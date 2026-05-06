// Task Manager router. Dispatches /api/v1/tm/* and /tm/* requests.
// Returns true once the response has been handled, false otherwise so the
// main server can fall through.

import { promises as fs } from 'node:fs';
import { join, dirname, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { gzipSync, brotliCompressSync, constants as zlibConst } from 'node:zlib';

import * as users from './users.js';
import * as projects from './projects.js';
import * as tasks from './tasks.js';
import * as dispatches from './dispatches.js';
import * as units from './units.js';
import * as assignments from './assignments.js';
import * as dss from './dss.js';
import * as audit from './audit.js';
import { FirestoreError } from './firestore.js';
import { ApiError, ScopeError, NotFoundError, ConflictError } from './_errors.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const WEB_DIR = process.env.WEB_DIR || join(__dirname, '..', '..', 'web');
const WEB_TM_DIR = join(WEB_DIR, 'tm');

const MAX_JSON_BODY = 256 * 1024;

function logJson(severity, fields) {
  const entry = { ts: new Date().toISOString(), severity, ...fields };
  process.stdout.write(JSON.stringify(entry) + '\n');
}

// ---------------------------------------------------------------------------
// Rate limit (per-IP) for /api/v1/tm/auth/*. 30 req/min, 200 req/day.
// In-memory; resets on cold start. Shape mirrors the triage limiter.
// ---------------------------------------------------------------------------
const authBuckets = new Map();
const AUTH_MAX_BUCKETS = 5000;
const AUTH_MIN = 30;
const AUTH_DAY = 200;

function checkAuthRate(ip) {
  const now = Date.now();
  let b = authBuckets.get(ip);
  if (!b) {
    if (authBuckets.size >= AUTH_MAX_BUCKETS) {
      const drop = Math.floor(AUTH_MAX_BUCKETS / 10);
      const it = authBuckets.keys();
      for (let i = 0; i < drop; i++) {
        const { value, done } = it.next();
        if (done) break;
        authBuckets.delete(value);
      }
    }
    b = { mTok: AUTH_MIN, mAt: now, dTok: AUTH_DAY, dAt: now };
    authBuckets.set(ip, b);
  }
  const mEl = (now - b.mAt) / 60_000;
  b.mTok = Math.min(AUTH_MIN, b.mTok + mEl * AUTH_MIN);
  b.mAt = now;
  const dEl = (now - b.dAt) / 86_400_000;
  b.dTok = Math.min(AUTH_DAY, b.dTok + dEl * AUTH_DAY);
  b.dAt = now;
  if (b.mTok < 1) return { ok: false, retryAfter: Math.max(1, Math.ceil((1 - b.mTok) * 60 / AUTH_MIN)), reason: 'minute' };
  if (b.dTok < 1) return { ok: false, retryAfter: 3600, reason: 'day' };
  b.mTok -= 1;
  b.dTok -= 1;
  return { ok: true };
}

// ---------------------------------------------------------------------------
// HTTP helpers.
// ---------------------------------------------------------------------------
function sendJson(res, status, obj, extraHeaders = {}) {
  if (res.writableEnded) return;
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    ...extraHeaders
  });
  res.end(body);
}

function sendError(res, status, code, message, extraHeaders = {}) {
  sendJson(res, status, { error: { code, message } }, extraHeaders);
}

// Forwards the rotated action key from a verified HMAC sig back to the
// client as response headers. The client swaps these in for the next
// request; old key has a 30s grace window on the server.
function nextKeyHeaders(verified) {
  if (!verified || !verified.next_action_key_b64) return {};
  return {
    'X-Next-Action-Key': verified.next_action_key_b64,
    'X-Next-Action-Key-Id': verified.next_action_key_id
  };
}

async function readJsonBody(req) {
  const lengthHeader = req.headers['content-length'];
  if (lengthHeader) {
    const len = parseInt(lengthHeader, 10);
    if (Number.isFinite(len) && len > MAX_JSON_BODY) {
      throw new ApiError('payload_too_large', 'Body exceeds 256 KB limit.', 413);
    }
  }
  let total = 0;
  const chunks = [];
  for await (const chunk of req) {
    total += chunk.length;
    if (total > MAX_JSON_BODY) {
      throw new ApiError('payload_too_large', 'Body exceeds 256 KB limit.', 413);
    }
    chunks.push(chunk);
  }
  if (total === 0) return {};
  const text = Buffer.concat(chunks, total).toString('utf8');
  try {
    const obj = JSON.parse(text);
    if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
      throw new ApiError('bad_request', 'JSON body must be an object.', 400);
    }
    return obj;
  } catch (e) {
    if (e instanceof ApiError) throw e;
    throw new ApiError('bad_json', 'Body is not valid JSON.', 400);
  }
}

function mapError(e) {
  if (e instanceof FirestoreError) {
    if (e.code === 'FS_NOT_FOUND') return { status: 404, code: 'not_found', message: 'Resource not found.' };
    if (e.code === 'FS_ALREADY_EXISTS') return { status: 409, code: 'conflict', message: 'Resource already exists.' };
    if (e.code === 'FS_PRECONDITION') return { status: 409, code: 'precondition_failed', message: 'Concurrent modification.' };
    if (e.code === 'FS_BAD_REQUEST') return { status: 400, code: 'bad_request', message: 'Invalid request.' };
    if (e.code === 'FS_UNAUTHORIZED') return { status: 503, code: 'service_unavailable', message: 'Backend authentication failed.' };
    if (e.code === 'FS_RATE_LIMITED') return { status: 503, code: 'service_unavailable', message: 'Storage rate limit hit.' };
    return { status: 502, code: 'storage_error', message: 'Storage temporarily unavailable.' };
  }
  if (e && e.name === 'AuthError') {
    return { status: e.status || 401, code: e.code || 'unauthorized', message: e.message || 'Unauthorized.' };
  }
  if (e && (e.name === 'AuditAccessError' || e.name === 'AuditWriteError')) {
    return { status: e.status || 403, code: e.code || 'forbidden', message: e.message || 'Forbidden.' };
  }
  if (e instanceof ScopeError) return { status: 403, code: e.code || 'forbidden', message: e.message || 'Forbidden.' };
  if (e instanceof NotFoundError) return { status: 404, code: e.code || 'not_found', message: e.message || 'Not found.' };
  if (e instanceof ConflictError) return { status: 409, code: e.code || 'conflict', message: e.message || 'Conflict.' };
  if (e instanceof ApiError) return { status: e.status || 400, code: e.code || 'bad_request', message: e.message || 'Bad request.' };
  return null;
}

function handleError(res, e, ctx) {
  const m = mapError(e);
  if (m) {
    if (m.status >= 500) {
      logJson('ERROR', { fn: 'router.handleError', requestId: ctx?.requestId, status: m.status, code: m.code, msg: m.message, err: String(e), stack: e?.stack });
    } else {
      logJson('WARNING', { fn: 'router.handleError', requestId: ctx?.requestId, status: m.status, code: m.code, msg: m.message });
    }
    sendError(res, m.status, m.code, m.message);
    return;
  }
  logJson('ERROR', { fn: 'router.handleError', requestId: ctx?.requestId, msg: 'unhandled', err: String(e), stack: e?.stack });
  sendError(res, 500, 'internal_error', 'Unexpected error.');
}

// ---------------------------------------------------------------------------
// Static file cache for /tm/* assets. Mirrors the main server's helper.
// ---------------------------------------------------------------------------
const fileCache = new Map();

async function loadStatic(absPath) {
  try {
    const stat = await fs.stat(absPath);
    const cached = fileCache.get(absPath);
    if (cached && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size) return cached;
    const buf = await fs.readFile(absPath);
    let gzBuf = null;
    let brBuf = null;
    try { gzBuf = await fs.readFile(absPath + '.gz'); } catch { /* none */ }
    try { brBuf = await fs.readFile(absPath + '.br'); } catch { /* none */ }
    if (!gzBuf) {
      try { gzBuf = gzipSync(buf, { level: 9 }); } catch { gzBuf = null; }
    }
    if (!brBuf) {
      try {
        brBuf = brotliCompressSync(buf, {
          params: {
            [zlibConst.BROTLI_PARAM_QUALITY]: 11,
            [zlibConst.BROTLI_PARAM_SIZE_HINT]: buf.length
          }
        });
      } catch { brBuf = null; }
    }
    const etag = '"' + createHash('sha1').update(buf).digest('base64').replace(/=+$/, '') + '"';
    const entry = { buf, gzBuf, brBuf, mtimeMs: stat.mtimeMs, size: stat.size, etag };
    fileCache.set(absPath, entry);
    return entry;
  } catch {
    return null;
  }
}

function pickEncoding(acceptEncoding, entry) {
  if (!acceptEncoding) return { enc: null, body: entry.buf };
  const ae = acceptEncoding.toLowerCase();
  if (entry.brBuf && ae.includes('br')) return { enc: 'br', body: entry.brBuf };
  if (entry.gzBuf && ae.includes('gzip')) return { enc: 'gzip', body: entry.gzBuf };
  return { enc: null, body: entry.buf };
}

function mimeFor(name) {
  if (name.endsWith('.html')) return 'text/html; charset=utf-8';
  if (name.endsWith('.js') || name.endsWith('.mjs')) return 'text/javascript; charset=utf-8';
  if (name.endsWith('.css')) return 'text/css; charset=utf-8';
  if (name.endsWith('.svg')) return 'image/svg+xml; charset=utf-8';
  if (name.endsWith('.json') || name.endsWith('.webmanifest')) return 'application/json; charset=utf-8';
  if (name.endsWith('.png')) return 'image/png';
  if (name.endsWith('.woff2')) return 'font/woff2';
  return 'application/octet-stream';
}

function safeJoinUnder(baseDir, relPath) {
  const joined = normalize(join(baseDir, relPath));
  const baseNorm = normalize(baseDir + '/');
  if (!joined.startsWith(baseNorm) && joined !== normalize(baseDir)) return null;
  return joined;
}

async function serveStaticFile(req, res, absPath, fallbackAbsPath) {
  let entry = await loadStatic(absPath);
  let chosen = absPath;
  if (!entry && fallbackAbsPath) {
    entry = await loadStatic(fallbackAbsPath);
    chosen = fallbackAbsPath;
  }
  if (!entry) {
    sendError(res, 404, 'not_found', 'No route matches.');
    return;
  }
  const inm = req.headers['if-none-match'];
  if (inm && inm === entry.etag) {
    res.writeHead(304, { ETag: entry.etag, 'Cache-Control': 'public, max-age=300, must-revalidate' });
    res.end();
    return;
  }
  const { enc, body } = pickEncoding(req.headers['accept-encoding'], entry);
  const headers = {
    'Content-Type': mimeFor(chosen),
    'Content-Length': body.length,
    'Cache-Control': 'public, max-age=300, must-revalidate',
    'ETag': entry.etag,
    'Vary': 'Accept-Encoding'
  };
  if (enc) headers['Content-Encoding'] = enc;
  res.writeHead(200, headers);
  if (req.method === 'HEAD') res.end(); else res.end(body);
}

// ---------------------------------------------------------------------------
// Auth bridge. The auth module is expected to expose the surface
// documented in tm/_iface.md (router section). Loaded lazily on first
// authenticated request so the file is optional during cold start.
// ---------------------------------------------------------------------------
let authModulePromise = null;

async function getAuth() {
  if (!authModulePromise) {
    authModulePromise = import('./auth.js').catch((e) => {
      authModulePromise = null;
      logJson('ERROR', { fn: 'getAuth', msg: 'auth_module_missing', err: String(e) });
      const err = new Error('Auth module is not yet available.');
      err.name = 'AuthError';
      err.code = 'auth_unavailable';
      err.status = 503;
      throw err;
    });
  }
  return authModulePromise;
}

async function authenticate(req) {
  const mod = await getAuth();
  if (typeof mod.authenticate !== 'function') {
    const err = new Error('Auth backend is incomplete.');
    err.name = 'AuthError';
    err.code = 'auth_unavailable';
    err.status = 503;
    throw err;
  }
  return mod.authenticate(req);
}

// ---------------------------------------------------------------------------
// Path matchers.
// ---------------------------------------------------------------------------
function matchTm(pathname) {
  if (pathname === '/api/v1/tm' || pathname === '/api/v1/tm/') return { kind: 'api_root' };
  if (pathname.startsWith('/api/v1/tm/')) return { kind: 'api', sub: pathname.slice('/api/v1/tm/'.length) };
  if (pathname === '/tm' || pathname === '/tm/') return { kind: 'web', sub: '' };
  if (pathname.startsWith('/tm/')) return { kind: 'web', sub: pathname.slice('/tm/'.length) };
  if (pathname.startsWith('/api/v1/internal/')) return { kind: 'internal', sub: pathname.slice('/api/v1/internal/'.length) };
  // phone-identity lane: SMS OTP + shortcode webhook routes. Public
  // facing (no bearer); rate-limited per IP and HMAC-gated where the
  // sender is a telco webhook.
  if (pathname.startsWith('/api/v1/sms/')) return { kind: 'sms', sub: pathname.slice('/api/v1/sms/'.length) };
  return null;
}

// ---------------------------------------------------------------------------
// API dispatch.
// ---------------------------------------------------------------------------
async function dispatchApi(req, res, sub, url, ctx) {
  const method = req.method || 'GET';

  // Public auth subroutes.
  if (sub.startsWith('auth/') || sub === 'server-pubkey') {
    // VAPID pubkey + push subscribe carve-outs sit under /auth/* but
    // need different gating. vapid_pubkey is fully public (it is the
    // public key, after all). push_subscribe is authenticated because
    // it ties a subscription to a uid; an unauthenticated subscribe
    // would let anyone pin notifications to any uid.
    if (sub === 'auth/vapid_pubkey') {
      if (method !== 'GET') return sendError(res, 405, 'method_not_allowed', 'Use GET.', { Allow: 'GET' });
      const m = await import('./notify.js');
      return sendJson(res, 200, { public_key_b64: m.getPublicKeyB64() });
    }
    // multi-device-keys lane.
    //
    // Device-list endpoints sit under /auth/* but require an authenticated
    // session (they tie to a uid). They share the public auth-rate bucket
    // with login/challenge/verify; per-action HMAC sig is enforced on the
    // revoke route via requireFreshHmacSigForDevice.
    if (sub === 'auth/devices') {
      const actorEarly = await authenticate(req);
      if (method !== 'GET') return sendError(res, 405, 'method_not_allowed', 'Use GET.', { Allow: 'GET' });
      const mod = await getAuth();
      if (typeof mod.handleDeviceList !== 'function') {
        return sendError(res, 503, 'service_unavailable', 'Devices endpoint not ready.');
      }
      return sendJson(res, 200, await mod.handleDeviceList(actorEarly, ctx));
    }
    if (sub === 'auth/devices/register') {
      const actorEarly = await authenticate(req);
      if (method !== 'POST') return sendError(res, 405, 'method_not_allowed', 'Use POST.', { Allow: 'POST' });
      const body = await readJsonBody(req);
      const mod = await getAuth();
      if (typeof mod.handleDeviceRegister !== 'function') {
        return sendError(res, 503, 'service_unavailable', 'Device-register endpoint not ready.');
      }
      return sendJson(res, 200, await mod.handleDeviceRegister(actorEarly, body, ctx));
    }
    {
      const revokeRe = /^auth\/devices\/([^\/]+)\/revoke$/;
      const matched = revokeRe.exec(sub);
      if (matched) {
        const actorEarly = await authenticate(req);
        if (method !== 'POST') return sendError(res, 405, 'method_not_allowed', 'Use POST.', { Allow: 'POST' });
        const deviceId = decodeURIComponent(matched[1]);
        const body = await readJsonBody(req);
        const sig = body?.signature_b64 || body?.action_signature_b64 || null;
        if (typeof sig !== 'string' || sig.length === 0) {
          return sendError(res, 400, 'bad_request', 'signature_b64 required.');
        }
        const mod = await getAuth();
        if (typeof mod.requireFreshHmacSigForDevice !== 'function' || typeof mod.handleDeviceRevoke !== 'function') {
          return sendError(res, 503, 'service_unavailable', 'Device-revoke endpoint not ready.');
        }
        const verified = await mod.requireFreshHmacSigForDevice(
          actorEarly, 'device.revoke', `device.revoke|${deviceId}`, req.headers
        );
        return sendJson(res, 200, await mod.handleDeviceRevoke(actorEarly, deviceId, sig, ctx), nextKeyHeaders(verified));
      }
    }
    if (sub === 'auth/push_subscribe') {
      // Authenticated. Skip the public auth-rate bucket so a logged-in
      // PWA does not share a budget with the login challenge flow.
      const actorEarly = await authenticate(req);
      const m = await import('./notify.js');
      if (method === 'POST') {
        const body = await readJsonBody(req);
        const sub2 = body && typeof body === 'object' ? body : null;
        if (!m.isValidSubscription(sub2)) {
          return sendError(res, 400, 'subscription_invalid', 'Subscription payload is malformed.');
        }
        await m.saveSubscription(actorEarly.uid, sub2);
        return sendJson(res, 200, { ok: true });
      }
      if (method === 'DELETE') {
        await m.deleteSubscription(actorEarly.uid);
        return sendJson(res, 200, { ok: true });
      }
      return sendError(res, 405, 'method_not_allowed', 'Use POST or DELETE.', { Allow: 'POST, DELETE' });
    }
    const rate = checkAuthRate(ctx.ip);
    if (!rate.ok) {
      sendError(res, 429, 'rate_limited', 'Too many auth requests.', { 'Retry-After': String(rate.retryAfter) });
      return;
    }
    if (sub === 'server-pubkey') {
      if (method !== 'GET') return sendError(res, 405, 'method_not_allowed', 'Use GET.', { Allow: 'GET' });
      const mod = await getAuth();
      const pub = typeof mod.getServerPubkeyB64 === 'function' ? await mod.getServerPubkeyB64() : null;
      if (!pub) return sendError(res, 503, 'service_unavailable', 'Server key not initialized.');
      return sendJson(res, 200, { pubkey_b64: pub, alg: 'ML-DSA-65' });
    }
    if (method !== 'POST') return sendError(res, 405, 'method_not_allowed', 'Use POST.', { Allow: 'POST' });
    const body = await readJsonBody(req);
    const mod = await getAuth();
    if (sub === 'auth/register') {
      if (typeof mod.handleRegister !== 'function') return sendError(res, 503, 'service_unavailable', 'Register endpoint not ready.');
      return sendJson(res, 200, await mod.handleRegister(body, ctx));
    }
    if (sub === 'auth/bootstrap') {
      if (typeof mod.handleBootstrap !== 'function') return sendError(res, 503, 'service_unavailable', 'Bootstrap endpoint not ready.');
      return sendJson(res, 200, await mod.handleBootstrap(body, ctx));
    }
    if (sub === 'auth/challenge') {
      if (typeof mod.handleChallenge !== 'function') return sendError(res, 503, 'service_unavailable', 'Challenge endpoint not ready.');
      return sendJson(res, 200, await mod.handleChallenge(body, ctx));
    }
    if (sub === 'auth/verify') {
      if (typeof mod.handleVerify !== 'function') return sendError(res, 503, 'service_unavailable', 'Verify endpoint not ready.');
      return sendJson(res, 200, await mod.handleVerify(body, ctx));
    }
    return sendError(res, 404, 'not_found', 'No such auth route.');
  }

  // Authenticated routes.
  const actor = await authenticate(req);

  // Presence heartbeat. Wave 2 watchdog reads tm_user_presence to detect
  // C2 compromise. bumpPresence is rate-limited per uid, so spamming
  // requests does not blow Firestore's free-tier write quota.
  if (actor && actor.uid) {
    users.bumpPresence(actor.uid).catch(() => { /* best-effort */ });
  }

  // Autonomous-mode clear. Any NDMA-tier authenticated call cancels the
  // watchdog's autonomous mode. Best-effort: never blocks the request.
  if (actor && Number(actor.tier) >= 100) {
    try {
      const watchdogMod = await import('./watchdog.js');
      if (typeof watchdogMod.clearAutonomousModeIfNdma === 'function') {
        watchdogMod.clearAutonomousModeIfNdma(actor);
      }
    } catch { /* swallow */ }
  }

  if (sub === 'me') {
    if (method !== 'GET') return sendError(res, 405, 'method_not_allowed', 'Use GET.', { Allow: 'GET' });
    return sendJson(res, 200, await users.getMe(actor));
  }

  if (sub === 'users') {
    if (method === 'GET') {
      const scope = url.searchParams.get('scope') || actor.scope_path;
      const limit = parseInt(url.searchParams.get('limit') || '0', 10) || undefined;
      return sendJson(res, 200, { users: await users.listUsers(actor, scope, limit) });
    }
    return sendError(res, 405, 'method_not_allowed', 'Use GET.', { Allow: 'GET' });
  }

  if (sub === 'users/invite') {
    if (method !== 'POST') return sendError(res, 405, 'method_not_allowed', 'Use POST.', { Allow: 'POST' });
    const body = await readJsonBody(req);
    const mod = await getAuth();
    const target = `invite|${body?.email || ''}|${body?.tier || ''}|${body?.parent_uid || ''}|${body?.scope_path || ''}`;
    const verified = await mod.requireFreshHmacSig(actor, 'user.invite', target, req.headers);
    return sendJson(res, 200, await users.inviteUser(actor, body, body?.signature_b64), nextKeyHeaders(verified));
  }

  if (sub.startsWith('users/')) {
    const rest = sub.slice('users/'.length);
    const slash = rest.indexOf('/');
    if (slash < 0) return sendError(res, 404, 'not_found', 'No such user route.');
    const uid = decodeURIComponent(rest.slice(0, slash));
    const action = rest.slice(slash + 1);
    if (action === 'delegate') {
      if (method !== 'POST') return sendError(res, 405, 'method_not_allowed', 'Use POST.', { Allow: 'POST' });
      const body = await readJsonBody(req);
      const newTier = Number(body?.new_tier);
      const sig = body?.signature_b64;
      const mod = await getAuth();
      const verified = await mod.requireFreshHmacSig(actor, 'user.delegate', `delegate|${uid}|${newTier}`, req.headers);
      return sendJson(res, 200, await users.delegate(actor, uid, newTier, sig), nextKeyHeaders(verified));
    }
    if (action === 'suspend') {
      if (method !== 'POST') return sendError(res, 405, 'method_not_allowed', 'Use POST.', { Allow: 'POST' });
      const body = await readJsonBody(req);
      const suspend = body?.suspend === true || body?.suspend === 'true';
      return sendJson(res, 200, await users.suspend(actor, uid, suspend));
    }
    if (action === 'escalation-policy') {
      if (method !== 'POST') return sendError(res, 405, 'method_not_allowed', 'Use POST.', { Allow: 'POST' });
      const body = await readJsonBody(req);
      const policy = String(body?.policy || '');
      return sendJson(res, 200, await users.setEscalationPolicy(actor, uid, policy));
    }
    if (action === '') {
      if (method !== 'GET') return sendError(res, 405, 'method_not_allowed', 'Use GET.', { Allow: 'GET' });
      return sendJson(res, 200, await users.getUser(actor, uid));
    }
    return sendError(res, 404, 'not_found', 'No such user route.');
  }

  if (sub === 'projects') {
    if (method === 'GET') {
      const includeArchived = url.searchParams.get('include_archived') === 'true';
      const limit = parseInt(url.searchParams.get('limit') || '0', 10) || undefined;
      return sendJson(res, 200, { projects: await projects.list(actor, { include_archived: includeArchived, limit }) });
    }
    if (method === 'POST') {
      const body = await readJsonBody(req);
      return sendJson(res, 201, await projects.create(actor, body));
    }
    return sendError(res, 405, 'method_not_allowed', 'Use GET or POST.', { Allow: 'GET, POST' });
  }

  if (sub.startsWith('projects/')) {
    const pid = decodeURIComponent(sub.slice('projects/'.length));
    if (!pid || pid.includes('/')) return sendError(res, 404, 'not_found', 'No such project route.');
    if (method === 'GET') return sendJson(res, 200, await projects.get(actor, pid));
    if (method === 'PATCH') {
      const body = await readJsonBody(req);
      return sendJson(res, 200, await projects.update(actor, pid, body));
    }
    if (method === 'DELETE') {
      const body = await readJsonBody(req).catch(() => ({}));
      const sig = body?.signature_b64;
      const mod = await getAuth();
      const verified = await mod.requireFreshHmacSig(actor, 'project.archive', `project.archive|${pid}`, req.headers);
      return sendJson(res, 200, await projects.archive(actor, pid, sig), nextKeyHeaders(verified));
    }
    return sendError(res, 405, 'method_not_allowed', 'Use GET, PATCH, or DELETE.', { Allow: 'GET, PATCH, DELETE' });
  }

  if (sub === 'tasks') {
    if (method === 'GET') {
      const filters = {
        project: url.searchParams.get('project'),
        assignee: url.searchParams.get('assignee'),
        status: url.searchParams.get('status'),
        overdue: url.searchParams.get('overdue') === 'true',
        limit: parseInt(url.searchParams.get('limit') || '0', 10) || undefined
      };
      return sendJson(res, 200, { tasks: await tasks.list(actor, filters) });
    }
    if (method === 'POST') {
      const body = await readJsonBody(req);
      return sendJson(res, 201, await tasks.create(actor, body));
    }
    return sendError(res, 405, 'method_not_allowed', 'Use GET or POST.', { Allow: 'GET, POST' });
  }

  if (sub.startsWith('tasks/')) {
    const tid = decodeURIComponent(sub.slice('tasks/'.length));
    if (!tid || tid.includes('/')) return sendError(res, 404, 'not_found', 'No such task route.');
    if (method === 'GET') return sendJson(res, 200, await tasks.get(actor, tid));
    if (method === 'PATCH') {
      const body = await readJsonBody(req);
      let sig = null;
      let verified = null;
      if (body?.assignee_uid !== undefined) {
        sig = body?.signature_b64 || null;
        const mod = await getAuth();
        verified = await mod.requireFreshHmacSig(actor, 'task.assign', `task.assign|${tid}|${body.assignee_uid || ''}`, req.headers);
      }
      return sendJson(res, 200, await tasks.update(actor, tid, body, sig), nextKeyHeaders(verified));
    }
    if (method === 'DELETE') {
      return sendJson(res, 200, await tasks.archive(actor, tid));
    }
    return sendError(res, 405, 'method_not_allowed', 'Use GET, PATCH, or DELETE.', { Allow: 'GET, PATCH, DELETE' });
  }

  if (sub === 'dashboard') {
    if (method !== 'GET') return sendError(res, 405, 'method_not_allowed', 'Use GET.', { Allow: 'GET' });
    return sendJson(res, 200, await tasks.dashboard(actor));
  }

  if (sub === 'dispatches') {
    if (method !== 'GET') return sendError(res, 405, 'method_not_allowed', 'Use GET.', { Allow: 'GET' });
    const limitRaw = parseInt(url.searchParams.get('limit') || '50', 10);
    const limit = Math.min(Math.max(Number.isFinite(limitRaw) ? limitRaw : 50, 1), 200);
    const mineParam = url.searchParams.get('mine');
    if (mineParam === 'only') {
      return sendJson(res, 200, { dispatches: await dispatches.listMine(actor, { limit }) });
    }
    const status = url.searchParams.get('status') || null;
    const requiresReview = url.searchParams.get('requires_review') === '1' || url.searchParams.get('requires_review') === 'true';
    const includeMine = mineParam === '1' || mineParam === 'true';
    // criticality-dedup lane: direct_only flag passed through to listTeam.
    const directOnly = url.searchParams.get('direct_only') === '1' || url.searchParams.get('direct_only') === 'true';
    return sendJson(res, 200, {
      dispatches: await dispatches.listTeam(actor, { limit, status, requires_review: requiresReview, mine: includeMine, direct_only: directOnly })
    });
  }

  // criticality-dedup lane: side-by-side criticality comparison endpoint.
  // Restricted to ddma+ (tier >= 60) so volunteers and field tiers cannot
  // bulk-pull dispatch summaries. listTeam already enforces scope, but
  // compare() runs scope checks per id as well.
  if (sub === 'dispatches/compare') {
    if (method !== 'GET') return sendError(res, 405, 'method_not_allowed', 'Use GET.', { Allow: 'GET' });
    if (Number(actor.tier) < 60) {
      return sendError(res, 403, 'forbidden', 'compare requires district tier or higher.');
    }
    const idsParam = url.searchParams.get('ids') || '';
    const ids = idsParam.split(',').map((s) => s.trim()).filter((s) => s.length > 0);
    return sendJson(res, 200, { dispatches: await dispatches.compare(actor, ids) });
  }

  if (sub.startsWith('dispatches/')) {
    const rest = sub.slice('dispatches/'.length);
    const slash = rest.indexOf('/');
    const did = decodeURIComponent(slash < 0 ? rest : rest.slice(0, slash));
    const action = slash < 0 ? '' : rest.slice(slash + 1);
    if (!did) return sendError(res, 404, 'not_found', 'No such dispatch route.');
    if (action === '') {
      if (method !== 'GET') return sendError(res, 405, 'method_not_allowed', 'Use GET.', { Allow: 'GET' });
      return sendJson(res, 200, await dispatches.get(actor, did));
    }
    if (action === 'escalate') {
      if (method !== 'POST') return sendError(res, 405, 'method_not_allowed', 'Use POST.', { Allow: 'POST' });
      const body = await readJsonBody(req);
      const sig = body?.action_signature_b64 || body?.signature_b64;
      const mod = await getAuth();
      const verified = await mod.requireFreshHmacSig(actor, 'dispatch.escalate', `dispatch.escalate|${did}`, req.headers);
      return sendJson(res, 200, await dispatches.escalate(actor, did, body, sig), nextKeyHeaders(verified));
    }
    if (action === 'review') {
      if (method !== 'POST') return sendError(res, 405, 'method_not_allowed', 'Use POST.', { Allow: 'POST' });
      const body = await readJsonBody(req).catch(() => ({}));
      const mod = await getAuth();
      const verified = await mod.requireFreshHmacSig(actor, 'dispatch.review', `dispatch.review|${did}`, req.headers);
      return sendJson(res, 200, await dispatches.markReviewed(actor, did, body), nextKeyHeaders(verified));
    }
    if (action === 'status') {
      if (method !== 'GET') return sendError(res, 405, 'method_not_allowed', 'Use GET.', { Allow: 'GET' });
      return sendJson(res, 200, await assignments.readWorkerStatus(actor, did));
    }
    if (action === 'suggestions') {
      if (method !== 'GET') return sendError(res, 405, 'method_not_allowed', 'Use GET.', { Allow: 'GET' });
      const dispatch = await dispatches.get(actor, did);
      const candidates = await units.listAvailableInScope(dispatch.caller_scope_path || actor.scope_path);
      const top = dss.suggest(dispatch, candidates, 3);
      return sendJson(res, 200, { suggestions: top });
    }
    if (action === 'assign') {
      if (method !== 'POST') return sendError(res, 405, 'method_not_allowed', 'Use POST.', { Allow: 'POST' });
      const body = await readJsonBody(req);
      const sig = body?.action_signature_b64 || body?.signature_b64;
      const mod = await getAuth();
      const verified = await mod.requireFreshHmacSig(actor, 'dispatch.assign', `dispatch.assign|${did}|${body?.unit_id || ''}`, req.headers);
      return sendJson(res, 200, await assignments.assignUnit(actor, did, body, sig), nextKeyHeaders(verified));
    }
    return sendError(res, 404, 'not_found', 'No such dispatch route.');
  }

  if (sub === 'units') {
    if (method === 'GET') {
      const opts = {
        status: url.searchParams.get('status') || null,
        type: url.searchParams.get('type') || null,
        limit: parseInt(url.searchParams.get('limit') || '0', 10) || undefined,
        include_archived: url.searchParams.get('include_archived') === 'true'
      };
      return sendJson(res, 200, { units: await units.list(actor, opts) });
    }
    if (method === 'POST') {
      const body = await readJsonBody(req);
      return sendJson(res, 201, await units.create(actor, body));
    }
    return sendError(res, 405, 'method_not_allowed', 'Use GET or POST.', { Allow: 'GET, POST' });
  }

  if (sub === 'units/bulk') {
    if (method !== 'POST') return sendError(res, 405, 'method_not_allowed', 'Use POST.', { Allow: 'POST' });
    const body = await readJsonBody(req);
    return sendJson(res, 200, await units.bulkCreate(actor, body));
  }

  if (sub.startsWith('units/')) {
    const uid = decodeURIComponent(sub.slice('units/'.length));
    if (!uid || uid.includes('/')) return sendError(res, 404, 'not_found', 'No such unit route.');
    if (method === 'GET') return sendJson(res, 200, await units.get(actor, uid));
    if (method === 'PATCH') {
      const body = await readJsonBody(req);
      const wantsSig = body?.scope_path !== undefined || body?.contact_phone !== undefined || body?.name !== undefined;
      let sig = null;
      let verified = null;
      if (wantsSig) {
        sig = body?.action_signature_b64 || body?.signature_b64 || null;
        const mod = await getAuth();
        verified = await mod.requireFreshHmacSig(actor, 'unit.update', `unit.update|${uid}`, req.headers);
      }
      return sendJson(res, 200, await units.update(actor, uid, body, sig), nextKeyHeaders(verified));
    }
    if (method === 'DELETE') {
      const body = await readJsonBody(req).catch(() => ({}));
      const sig = body?.action_signature_b64 || body?.signature_b64;
      const mod = await getAuth();
      const verified = await mod.requireFreshHmacSig(actor, 'unit.archive', `unit.archive|${uid}`, req.headers);
      return sendJson(res, 200, await units.archive(actor, uid, sig), nextKeyHeaders(verified));
    }
    return sendError(res, 405, 'method_not_allowed', 'Use GET, PATCH, or DELETE.', { Allow: 'GET, PATCH, DELETE' });
  }

  if (sub === 'audit/verify') {
    if (method !== 'GET') return sendError(res, 405, 'method_not_allowed', 'Use GET.', { Allow: 'GET' });
    const fromSeqRaw = parseInt(url.searchParams.get('from_seq') || '0', 10);
    const fromSeq = Number.isFinite(fromSeqRaw) && fromSeqRaw >= 0 ? fromSeqRaw : 0;
    const limitRaw = parseInt(url.searchParams.get('limit') || '1000', 10);
    const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(limitRaw, 1000) : 1000;
    return sendJson(res, 200, await audit.handleVerify(actor, { fromSeq, limit }));
  }

  if (sub === 'audit/list') {
    if (method !== 'GET') return sendError(res, 405, 'method_not_allowed', 'Use GET.', { Allow: 'GET' });
    const filters = {
      actor_uid: url.searchParams.get('actor_uid') || undefined,
      action: url.searchParams.get('action') || undefined,
      target_ref: url.searchParams.get('target_ref') || undefined,
      since: url.searchParams.get('since') || undefined,
      until: url.searchParams.get('until') || undefined
    };
    const limitRaw = parseInt(url.searchParams.get('limit') || '50', 10);
    const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(limitRaw, 200) : 50;
    const includeSig = url.searchParams.get('include_signatures') === '1' || url.searchParams.get('include_signatures') === 'true';
    return sendJson(res, 200, await audit.handleList(actor, filters, { limit, include_signatures: includeSig }));
  }

  if (sub.startsWith('assignments/')) {
    const aid = decodeURIComponent(sub.slice('assignments/'.length));
    if (!aid || aid.includes('/')) return sendError(res, 404, 'not_found', 'No such assignment route.');
    if (method === 'PATCH') {
      const body = await readJsonBody(req);
      const status = String(body?.status || '');
      const mod = await getAuth();
      const verified = await mod.requireFreshHmacSig(actor, 'assignment.update', `assignment.update|${aid}|${status}`, req.headers);
      return sendJson(res, 200, await assignments.updateAssignment(actor, aid, body), nextKeyHeaders(verified));
    }
    return sendError(res, 405, 'method_not_allowed', 'Use PATCH.', { Allow: 'PATCH' });
  }

  return sendError(res, 404, 'not_found', 'No such TM route.');
}

// ---------------------------------------------------------------------------
// Web dispatch. Serves /tm/* static and falls back to index.html for SPA
// routes (login, register, projects, users, dashboard).
// ---------------------------------------------------------------------------
async function dispatchWeb(req, res, sub) {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    sendError(res, 405, 'method_not_allowed', 'Use GET.', { Allow: 'GET, HEAD' });
    return;
  }
  if (sub === '' || sub === 'login' || sub === 'register' || sub === 'projects'
      || sub === 'users' || sub === 'dashboard' || sub === 'tasks'
      || sub === 'dispatches' || sub === 'units'
      || sub.startsWith('projects/') || sub.startsWith('users/')
      || sub.startsWith('dispatches/') || sub.startsWith('units/')) {
    await serveStaticFile(req, res, join(WEB_TM_DIR, 'index.html'), null);
    return;
  }
  const safe = safeJoinUnder(WEB_TM_DIR, sub);
  if (!safe) {
    sendError(res, 404, 'not_found', 'No such asset.');
    return;
  }
  await serveStaticFile(req, res, safe, join(WEB_TM_DIR, 'index.html'));
}

// ---------------------------------------------------------------------------
// Internal endpoints. /api/v1/internal/sla_tick is hit by Cloud Tasks
// after a watchdog timer fires. The body is HMAC-signed with
// WATCHDOG_HMAC_SECRET; auth bearer is NOT required because Cloud Tasks
// cannot mint a session.
// ---------------------------------------------------------------------------
async function dispatchInternal(req, res, sub, ctx) {
  if (sub === 'sla_tick') {
    if (req.method !== 'POST') {
      return sendError(res, 405, 'method_not_allowed', 'Use POST.', { Allow: 'POST' });
    }
    // Read raw body so HMAC verification runs against the exact bytes
    // the sender signed. JSON.parse afterwards.
    const lengthHeader = req.headers['content-length'];
    if (lengthHeader) {
      const len = parseInt(lengthHeader, 10);
      if (Number.isFinite(len) && len > 16384) {
        return sendError(res, 413, 'payload_too_large', 'Internal body too large.');
      }
    }
    let total = 0;
    const chunks = [];
    for await (const chunk of req) {
      total += chunk.length;
      if (total > 16384) {
        return sendError(res, 413, 'payload_too_large', 'Internal body too large.');
      }
      chunks.push(chunk);
    }
    const rawBody = Buffer.concat(chunks, total).toString('utf8');
    let watchdogMod;
    try {
      watchdogMod = await import('./watchdog.js');
    } catch (e) {
      logJson('ERROR', { fn: 'dispatchInternal', requestId: ctx?.requestId, msg: 'watchdog_import_failed', err: String(e) });
      return sendError(res, 503, 'service_unavailable', 'Watchdog module unavailable.');
    }
    const sig = req.headers['x-watchdog-sig'];
    if (typeof sig !== 'string' || sig.length === 0) {
      logJson('WARNING', { fn: 'dispatchInternal', requestId: ctx?.requestId, msg: 'sla_tick_missing_sig' });
      return sendError(res, 401, 'unauthorized', 'Missing watchdog signature.');
    }
    if (!watchdogMod.verifyCallbackSig(rawBody, sig)) {
      logJson('WARNING', { fn: 'dispatchInternal', requestId: ctx?.requestId, msg: 'sla_tick_bad_sig' });
      return sendError(res, 401, 'unauthorized', 'Watchdog signature invalid.');
    }
    let body;
    try {
      body = JSON.parse(rawBody);
    } catch {
      return sendError(res, 400, 'bad_json', 'sla_tick body is not valid JSON.');
    }
    const result = await watchdogMod.handleSlaTick(body);
    if (result?.ok === false) {
      return sendError(res, result.status || 500, result.code || 'sla_tick_failed', 'sla_tick rejected.');
    }
    return sendJson(res, 200, result || { ok: true });
  }
  return sendError(res, 404, 'not_found', 'No such internal route.');
}


// ---------------------------------------------------------------------------
// phone-identity lane: SMS OTP + shortcode webhook dispatch.
//
// /api/v1/sms/send_otp           1/min per IP, body {phone_e164, channel}
// /api/v1/sms/verify_otp         body {phone_e164, otp}
// /api/v1/sms/shortcode_webhook  HMAC-gated by SMS_WEBHOOK_HMAC env. The
//                                telco signs the raw body bytes and sends
//                                the base64 sig in X-Sms-Webhook-Sig.
// ---------------------------------------------------------------------------
const smsOtpBuckets = new Map();
const SMS_OTP_MAX_BUCKETS = 5000;

function checkSmsOtpRate(ip) {
  const now = Date.now();
  let b = smsOtpBuckets.get(ip);
  if (!b) {
    if (smsOtpBuckets.size >= SMS_OTP_MAX_BUCKETS) {
      const drop = Math.floor(SMS_OTP_MAX_BUCKETS / 10);
      const it = smsOtpBuckets.keys();
      for (let i = 0; i < drop; i++) {
        const { value, done } = it.next();
        if (done) break;
        smsOtpBuckets.delete(value);
      }
    }
    b = { lastAt: 0 };
    smsOtpBuckets.set(ip, b);
  }
  const elapsed = now - b.lastAt;
  if (elapsed < 60_000) {
    return { ok: false, retryAfter: Math.max(1, Math.ceil((60_000 - elapsed) / 1000)) };
  }
  b.lastAt = now;
  return { ok: true };
}

function timingSafeBufEq(a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b) || a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

async function readRawBody(req, max) {
  const lengthHeader = req.headers['content-length'];
  if (lengthHeader) {
    const len = parseInt(lengthHeader, 10);
    if (Number.isFinite(len) && len > max) {
      throw new ApiError('payload_too_large', `Body exceeds ${max} byte limit.`, 413);
    }
  }
  let total = 0;
  const chunks = [];
  for await (const chunk of req) {
    total += chunk.length;
    if (total > max) {
      throw new ApiError('payload_too_large', `Body exceeds ${max} byte limit.`, 413);
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, total);
}

async function dispatchSms(req, res, sub, ctx) {
  const method = req.method || 'GET';

  if (sub === 'send_otp') {
    if (method !== 'POST') return sendError(res, 405, 'method_not_allowed', 'Use POST.', { Allow: 'POST' });
    const rate = checkSmsOtpRate(ctx.ip);
    if (!rate.ok) {
      return sendError(res, 429, 'rate_limited', 'send_otp limited to 1 / min per IP.',
        { 'Retry-After': String(rate.retryAfter) });
    }
    const body = await readJsonBody(req);
    const phone = String(body?.phone_e164 || '').trim();
    const channel = String(body?.channel || 'auto');
    const sms = await import('./sms.js');
    return sendJson(res, 200, await sms.sendOtp(phone, channel));
  }

  if (sub === 'verify_otp') {
    if (method !== 'POST') return sendError(res, 405, 'method_not_allowed', 'Use POST.', { Allow: 'POST' });
    const body = await readJsonBody(req);
    const phone = String(body?.phone_e164 || '').trim();
    const otp = String(body?.otp || '').trim();
    const sms = await import('./sms.js');
    return sendJson(res, 200, await sms.verifyOtp(phone, otp));
  }

  if (sub === 'shortcode_webhook') {
    if (method !== 'POST') return sendError(res, 405, 'method_not_allowed', 'Use POST.', { Allow: 'POST' });
    const secret = String(process.env.SMS_WEBHOOK_HMAC || '').trim();
    if (secret.length === 0) {
      logJson('ERROR', { fn: 'tm.router.shortcode_webhook', msg: 'webhook_secret_unset' });
      return sendError(res, 503, 'service_unavailable', 'SMS webhook secret not configured.');
    }
    const sig = String(req.headers['x-sms-webhook-sig'] || '').trim();
    if (!sig) {
      return sendError(res, 401, 'unauthorized', 'Missing X-Sms-Webhook-Sig.');
    }
    const raw = await readRawBody(req, 16384);
    const expected = createHmac('sha256', secret).update(raw).digest('base64');
    let okSig;
    try {
      okSig = sig.length === expected.length
        && timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
    } catch { okSig = false; }
    if (!okSig) {
      logJson('WARNING', { fn: 'tm.router.shortcode_webhook', msg: 'bad_sig' });
      return sendError(res, 401, 'unauthorized', 'Webhook signature invalid.');
    }
    let body;
    try { body = JSON.parse(raw.toString('utf8')); } catch {
      return sendError(res, 400, 'bad_json', 'Webhook body is not valid JSON.');
    }
    const sms = await import('./sms.js');
    return sendJson(res, 200, await sms.handleShortcodeWebhook(body));
  }

  return sendError(res, 404, 'not_found', 'No such SMS route.');
}

// ---------------------------------------------------------------------------
// Public entry. Returns true if the request was handled.
// ---------------------------------------------------------------------------
export async function route(req, res, url, ctx) {
  const m = matchTm(url.pathname);
  if (!m) return false;

  try {
    if (m.kind === 'web') {
      await dispatchWeb(req, res, m.sub);
      return true;
    }
    if (m.kind === 'internal') {
      await dispatchInternal(req, res, m.sub, ctx);
      return true;
    }
    if (m.kind === 'sms') {
      await dispatchSms(req, res, m.sub, ctx);
      return true;
    }
    if (m.kind === 'api_root') {
      sendJson(res, 200, {
        service: 'tm',
        version: 'v1',
        endpoints: [
          // survivor-anon lane (handled in server.js, listed for discovery).
          'POST /api/v1/sos/anon',
          'POST /api/v1/sos/anon/audio',
          'GET /api/v1/tm/server-pubkey',
          'POST /api/v1/tm/auth/register',
          'POST /api/v1/tm/auth/bootstrap',
          'POST /api/v1/tm/auth/challenge',
          'POST /api/v1/tm/auth/verify',
          'GET /api/v1/tm/auth/vapid_pubkey',
          'POST|DELETE /api/v1/tm/auth/push_subscribe',
          'GET /api/v1/tm/auth/devices',
          'POST /api/v1/tm/auth/devices/register',
          'POST /api/v1/tm/auth/devices/:id/revoke',
          'GET /api/v1/tm/me',
          'GET|POST /api/v1/tm/users',
          'POST /api/v1/tm/users/invite',
          'POST /api/v1/tm/users/:uid/delegate',
          'POST /api/v1/tm/users/:uid/suspend',
          'GET|POST /api/v1/tm/projects',
          'GET|PATCH|DELETE /api/v1/tm/projects/:pid',
          'POST /api/v1/tm/users/:uid/escalation-policy',
          'GET|POST /api/v1/tm/tasks',
          'GET|PATCH|DELETE /api/v1/tm/tasks/:tid',
          'GET /api/v1/tm/dashboard',
          'GET /api/v1/tm/dispatches',
          'GET /api/v1/tm/dispatches/compare?ids=a,b,c',
          'GET /api/v1/tm/dispatches/:id',
          'POST /api/v1/tm/dispatches/:id/escalate',
          'POST /api/v1/tm/dispatches/:id/review',
          'GET /api/v1/tm/dispatches/:id/status',
          'GET /api/v1/tm/dispatches/:id/suggestions',
          'POST /api/v1/tm/dispatches/:id/assign',
          'GET|POST /api/v1/tm/units',
          'POST /api/v1/tm/units/bulk',
          'GET|PATCH|DELETE /api/v1/tm/units/:unit_id',
          'PATCH /api/v1/tm/assignments/:aid',
          'GET /api/v1/tm/audit/verify',
          'GET /api/v1/tm/audit/list',
          'POST /api/v1/sms/send_otp',
          'POST /api/v1/sms/verify_otp',
          'POST /api/v1/sms/shortcode_webhook'
        ]
      });
      return true;
    }
    await dispatchApi(req, res, m.sub, url, ctx);
    return true;
  } catch (e) {
    handleError(res, e, ctx);
    return true;
  }
}

export const _internal = {
  WEB_TM_DIR,
  checkAuthRate,
  matchTm,
  mapError
};
