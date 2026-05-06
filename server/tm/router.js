// Task Manager router. Dispatches /api/v1/tm/* and /tm/* requests.
// Returns true once the response has been handled, false otherwise so the
// main server can fall through.

import { promises as fs } from 'node:fs';
import { join, dirname, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
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
  return null;
}

// ---------------------------------------------------------------------------
// API dispatch.
// ---------------------------------------------------------------------------
async function dispatchApi(req, res, sub, url, ctx) {
  const method = req.method || 'GET';

  // Public auth subroutes.
  if (sub.startsWith('auth/') || sub === 'server-pubkey') {
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
    return sendJson(res, 200, {
      dispatches: await dispatches.listTeam(actor, { limit, status, requires_review: requiresReview, mine: includeMine })
    });
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
    if (m.kind === 'api_root') {
      sendJson(res, 200, {
        service: 'tm',
        version: 'v1',
        endpoints: [
          'GET /api/v1/tm/server-pubkey',
          'POST /api/v1/tm/auth/register',
          'POST /api/v1/tm/auth/bootstrap',
          'POST /api/v1/tm/auth/challenge',
          'POST /api/v1/tm/auth/verify',
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
          'GET /api/v1/tm/audit/list'
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
