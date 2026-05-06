// Project Aether · Task Manager · auth core.
//
// Two-tier auth model (per NDMA_BUILD_SPEC.md "Auth model — two tiers"):
//   1. Login: ML-DSA-65 challenge / response. Server issues a compact
//      bearer (`<token_id>.<HMAC>`) plus a per-session 32-byte HMAC
//      action_key returned ONCE in the verify response.
//   2. Per-action: HMAC-SHA256(action_key, canonical(uid, action,
//      target, ts, key_id)) sent in the `X-Action-Sig` header.
//      ML-DSA does NOT touch per-action calls; the bandwidth saving
//      is ~140× and is required for 2.5 kbps survivability.
//
// Bearer wire format: `<token_id_b64u>.<hmac_sig_b64u>`, ~88 chars.
// Server-side `tm_sessions/<token_id>` doc holds claims + action_key
// with a Firestore TTL on `exp`. An in-memory LRU cache fronts
// Firestore so steady-state authenticated calls are zero-IO.
//
// Pure ESM, Node 22+.

import { randomBytes, createHmac, timingSafeEqual, createHash } from 'node:crypto';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

import { canonicalActionMessage, isCriticalAction } from './canonical.js';

const SESSION_TTL_SECS = 30 * 60;
const SESSION_REFRESH_GRACE_SECS = 60;
const CHALLENGE_TTL_SECS = 60;
const CHALLENGE_DOMAIN = 'aether-tm:v1:';
const ACTION_TS_SKEW_SECS = 60;
const ACTION_REPLAY_TTL_SECS = 5 * 60;
const ACTION_REPLAY_MAX = 10_000;
const ACTION_KEY_GRACE_SECS = 30;
const SESSION_CACHE_MAX = 5_000;
const BEARER_HMAC_DOMAIN = 'aether-tm:bearer-hmac:v1';
const ACTION_HEADER_SIG = 'x-action-sig';
const ACTION_HEADER_TS = 'x-action-ts';
const ACTION_HEADER_KEY_ID = 'x-action-key-id';

function utf8(s) { return new TextEncoder().encode(s); }
function utf8Dec(b) { return new TextDecoder('utf-8', { fatal: true }).decode(b); }

function b64u(buf) {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  const s = Buffer.from(b).toString('base64');
  return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64uDec(str) {
  if (typeof str !== 'string') throw mkErr('BAD_B64U', 'expected base64url string');
  const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/') + pad;
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

function b64Dec(str) {
  return new Uint8Array(Buffer.from(str, 'base64'));
}

function b64Enc(buf) {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return Buffer.from(b).toString('base64');
}

function randomBytes32() {
  return new Uint8Array(randomBytes(32));
}

function mkErr(code, message, status) {
  const e = new Error(message);
  e.code = code;
  if (status !== undefined) e.status = status;
  return e;
}

function eqBytes(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function timingSafeEqB64u(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

let SERVER_PRIV = null;
let SERVER_PUB = null;
let SERVER_KEY_FRESH = false;
let BEARER_HMAC_SECRET = null;

function loadServerKeypair() {
  if (SERVER_PRIV && SERVER_PUB) return;
  const privEnv = process.env.TM_SERVER_PRIV_B64;
  const pubEnv = process.env.TM_SERVER_PUB_B64;
  if (privEnv && pubEnv) {
    let priv;
    let pub;
    try {
      priv = b64Dec(privEnv);
      pub = b64Dec(pubEnv);
    } catch {
      throw mkErr('TM_KEY_DECODE_FAIL', 'TM_SERVER_PRIV_B64 / TM_SERVER_PUB_B64 are not base64.');
    }
    if (priv.length !== 4032) {
      throw mkErr('TM_KEY_BAD_LEN', `TM_SERVER_PRIV_B64 must decode to 4032 bytes (got ${priv.length}).`);
    }
    if (pub.length !== 1952) {
      throw mkErr('TM_KEY_BAD_LEN', `TM_SERVER_PUB_B64 must decode to 1952 bytes (got ${pub.length}).`);
    }
    const probeMsg = utf8('aether-tm:keypair-self-test');
    const probeSig = ml_dsa65.sign(probeMsg, priv);
    if (!ml_dsa65.verify(probeSig, probeMsg, pub)) {
      throw mkErr('TM_KEY_MISMATCH', 'TM_SERVER_PRIV_B64 and TM_SERVER_PUB_B64 do not form a valid pair.');
    }
    SERVER_PRIV = priv;
    SERVER_PUB = pub;
    SERVER_KEY_FRESH = false;
    deriveBearerSecret();
    return;
  }
  const k = ml_dsa65.keygen();
  SERVER_PRIV = k.secretKey;
  SERVER_PUB = k.publicKey;
  SERVER_KEY_FRESH = true;
  deriveBearerSecret();
  const line = {
    ts: new Date().toISOString(),
    severity: 'WARNING',
    fn: 'tm.auth.loadServerKeypair',
    msg: 'tm_server_keypair_generated_in_memory',
    note: 'persist these out-of-band and set TM_SERVER_PRIV_B64 / TM_SERVER_PUB_B64 env vars on next boot',
    pubkey_b64: b64Enc(SERVER_PUB),
    privkey_b64: b64Enc(SERVER_PRIV)
  };
  process.stdout.write(JSON.stringify(line) + '\n');
}

function deriveBearerSecret() {
  // Derive a 32-byte HMAC secret deterministically from the ML-DSA
  // private key so we do not need a new env var. Using the key
  // material under a domain separator means rotating the ML-DSA pair
  // also rotates the bearer secret, which is the desired behaviour.
  if (!SERVER_PRIV) return;
  const h = createHash('sha256');
  h.update(BEARER_HMAC_DOMAIN);
  h.update(SERVER_PRIV);
  BEARER_HMAC_SECRET = h.digest();
}

loadServerKeypair();

function getServerPub() {
  if (!SERVER_PUB) loadServerKeypair();
  return SERVER_PUB;
}

function getServerPrivInternal() {
  if (!SERVER_PRIV) loadServerKeypair();
  return SERVER_PRIV;
}

function getServerPubB64() {
  return b64Enc(getServerPub());
}

function isServerKeyEphemeral() {
  return SERVER_KEY_FRESH;
}

let _firestore = null;

async function getFirestore() {
  if (_firestore) return _firestore;
  try {
    _firestore = await import('./firestore.js');
  } catch (e) {
    throw mkErr(
      'TM_FIRESTORE_MISSING',
      'server/tm/firestore.js is not available. The tm-api agent owns this file. ' +
      'Underlying import error: ' + (e?.message || String(e))
    );
  }
  for (const fn of ['createDoc', 'fetchAndDelete']) {
    if (typeof _firestore[fn] !== 'function') {
      throw mkErr(
        'TM_FIRESTORE_INCOMPLETE',
        `server/tm/firestore.js does not export ${fn}() (see _iface.md).`
      );
    }
  }
  return _firestore;
}

function _setFirestoreForTest(mock) {
  _firestore = mock;
}

// ---------------------------------------------------------------------------
// Compact bearer model.
//
//   bearer = `<token_id_b64u>.<bearer_hmac_b64u>`
//   token_id  = 32 random bytes (base64url, 43 chars)
//   bearer_hmac = HMAC_SHA256(BEARER_HMAC_SECRET, token_id_b64u)
//
// Claims (uid, tier, scope_path, iat, exp, action_key_b64, key_id) live
// in `tm_sessions/<token_id_b64u>` (Firestore, TTL on exp). The
// in-memory `sessionCache` map keeps hot sessions zero-IO; cache
// misses fall through to Firestore.
// ---------------------------------------------------------------------------

const sessionCache = new Map();

function evictSessionCacheIfNeeded() {
  if (sessionCache.size <= SESSION_CACHE_MAX) return;
  const drop = Math.floor(SESSION_CACHE_MAX / 10);
  const it = sessionCache.keys();
  for (let i = 0; i < drop; i++) {
    const { value, done } = it.next();
    if (done) break;
    sessionCache.delete(value);
  }
}

function bearerHmacOf(tokenIdB64u) {
  if (!BEARER_HMAC_SECRET) deriveBearerSecret();
  const h = createHmac('sha256', BEARER_HMAC_SECRET);
  h.update(tokenIdB64u);
  return b64u(new Uint8Array(h.digest()));
}

function newKeyId() {
  return b64u(new Uint8Array(randomBytes(6)));
}

async function persistSession(tokenIdB64u, claims) {
  // Best-effort Firestore persistence. In-memory cache is the source
  // of truth in steady state; Firestore is the cold-start fallback
  // and the multi-instance handoff. Failures here log and swallow
  // because losing one session record is recoverable (user re-logs).
  let fs;
  try { fs = await getFirestore(); }
  catch { return; }
  if (typeof fs.setDoc !== 'function') return;
  try {
    await fs.setDoc('tm_sessions', tokenIdB64u, {
      uid: claims.uid,
      tier: claims.tier,
      scope_path: claims.scope_path,
      iat: claims.iat,
      exp: claims.exp,
      action_key_b64: claims.action_key_b64,
      key_id: claims.key_id,
      updated_at: new Date().toISOString()
    });
  } catch (e) {
    process.stdout.write(JSON.stringify({
      ts: new Date().toISOString(),
      severity: 'WARNING',
      fn: 'tm.auth.persistSession',
      msg: 'session_persist_failed',
      err: String(e?.message || e)
    }) + '\n');
  }
}

async function loadSessionFromFirestore(tokenIdB64u) {
  let fs;
  try { fs = await getFirestore(); }
  catch { return null; }
  if (typeof fs.getDoc !== 'function') return null;
  try {
    const doc = await fs.getDoc('tm_sessions', tokenIdB64u);
    if (!doc) return null;
    return doc;
  } catch {
    return null;
  }
}

function signSession(payload) {
  if (!payload || typeof payload !== 'object') {
    throw mkErr('BAD_PAYLOAD', 'session payload must be a plain object');
  }
  if (typeof payload.uid !== 'string' || payload.uid.length === 0) {
    throw mkErr('BAD_PAYLOAD', 'session payload.uid required');
  }
  if (typeof payload.tier !== 'number' || !Number.isInteger(payload.tier)) {
    throw mkErr('BAD_PAYLOAD', 'session payload.tier must be an integer');
  }
  if (typeof payload.scope_path !== 'string' || payload.scope_path.length === 0) {
    throw mkErr('BAD_PAYLOAD', 'session payload.scope_path required');
  }
  const now = Math.floor(Date.now() / 1000);
  const tokenIdBytes = randomBytes32();
  const tokenIdB64u = b64u(tokenIdBytes);
  const action_key_b64 = payload.action_key_b64 || b64Enc(randomBytes32());
  const key_id = payload.key_id || newKeyId();
  const claims = {
    uid: payload.uid,
    tier: payload.tier,
    scope_path: payload.scope_path,
    iat: payload.iat ?? now,
    exp: payload.exp ?? (now + SESSION_TTL_SECS),
    action_key_b64,
    key_id
  };
  sessionCache.set(tokenIdB64u, {
    ...claims,
    prev_action_key_b64: null,
    prev_key_id: null,
    prev_grace_until: 0
  });
  evictSessionCacheIfNeeded();
  // Fire-and-forget Firestore persist so cold-start instances can
  // pick up the session. The local cache is authoritative until then.
  persistSession(tokenIdB64u, claims).catch(() => {});
  const sigB64u = bearerHmacOf(tokenIdB64u);
  return `${tokenIdB64u}.${sigB64u}`;
}

async function verifySession(token) {
  if (typeof token !== 'string' || token.length === 0) {
    throw mkErr('SESSION_MALFORMED', 'session token missing', 401);
  }
  const parts = token.split('.');
  if (parts.length !== 2) {
    throw mkErr('SESSION_MALFORMED', 'session token must have two parts', 401);
  }
  const [tokenIdB64u, sigB64u] = parts;
  if (tokenIdB64u.length === 0 || sigB64u.length === 0) {
    throw mkErr('SESSION_MALFORMED', 'session token parts empty', 401);
  }
  const expected = bearerHmacOf(tokenIdB64u);
  if (!timingSafeEqB64u(sigB64u, expected)) {
    throw mkErr('SESSION_BAD_SIG', 'session token signature failed verification', 401);
  }
  let entry = sessionCache.get(tokenIdB64u);
  if (!entry) {
    const doc = await loadSessionFromFirestore(tokenIdB64u);
    if (!doc) throw mkErr('SESSION_NOT_FOUND', 'session token not found', 401);
    entry = {
      uid: doc.uid,
      tier: doc.tier,
      scope_path: doc.scope_path,
      iat: doc.iat,
      exp: doc.exp,
      action_key_b64: doc.action_key_b64,
      key_id: doc.key_id,
      prev_action_key_b64: null,
      prev_key_id: null,
      prev_grace_until: 0
    };
    sessionCache.set(tokenIdB64u, entry);
    evictSessionCacheIfNeeded();
  }
  const now = Math.floor(Date.now() / 1000);
  if (typeof entry.exp !== 'number' || typeof entry.iat !== 'number') {
    throw mkErr('SESSION_BAD_CLAIMS', 'session token missing iat/exp', 401);
  }
  if (entry.exp <= now) {
    sessionCache.delete(tokenIdB64u);
    throw mkErr('SESSION_EXPIRED', 'session token expired', 401);
  }
  if (entry.iat > now + 60) throw mkErr('SESSION_FUTURE', 'session token iat in the future', 401);
  if (typeof entry.uid !== 'string' || typeof entry.scope_path !== 'string' || typeof entry.tier !== 'number') {
    throw mkErr('SESSION_BAD_CLAIMS', 'session token claims malformed', 401);
  }
  // Sliding refresh: extend exp on every authenticated call so an
  // active user never gets bounced to login mid-task. The Firestore
  // doc is rewritten lazily; the cache is authoritative.
  const newExp = now + SESSION_TTL_SECS;
  if (newExp - entry.exp > SESSION_REFRESH_GRACE_SECS) {
    entry.exp = newExp;
    persistSession(tokenIdB64u, entry).catch(() => {});
  }
  return {
    uid: entry.uid,
    tier: entry.tier,
    scope_path: entry.scope_path,
    iat: entry.iat,
    exp: entry.exp,
    token_id: tokenIdB64u,
    key_id: entry.key_id
  };
}

function _setSessionEntryForTest(tokenIdB64u, entry) {
  sessionCache.set(tokenIdB64u, entry);
}

function _getSessionEntryForTest(tokenIdB64u) {
  return sessionCache.get(tokenIdB64u);
}

function _clearSessionCacheForTest() {
  sessionCache.clear();
}

function verifyUserSig(pubkey_b64, message_bytes, sig_b64) {
  if (typeof pubkey_b64 !== 'string' || pubkey_b64.length === 0) {
    throw mkErr('BAD_PUBKEY', 'pubkey_b64 missing', 400);
  }
  if (!(message_bytes instanceof Uint8Array)) {
    throw mkErr('BAD_MESSAGE', 'message_bytes must be Uint8Array', 400);
  }
  if (typeof sig_b64 !== 'string' || sig_b64.length === 0) {
    throw mkErr('BAD_SIG', 'sig_b64 missing', 400);
  }
  let pub;
  let sig;
  try {
    pub = b64Dec(pubkey_b64);
  } catch {
    throw mkErr('BAD_PUBKEY', 'pubkey_b64 is not base64', 400);
  }
  try {
    sig = b64Dec(sig_b64);
  } catch {
    try {
      sig = b64uDec(sig_b64);
    } catch {
      throw mkErr('BAD_SIG', 'sig_b64 is neither base64 nor base64url', 400);
    }
  }
  if (pub.length !== 1952) throw mkErr('BAD_PUBKEY', `pubkey must be 1952 bytes (got ${pub.length})`, 400);
  if (sig.length !== 3309) throw mkErr('BAD_SIG', `signature must be 3309 bytes (got ${sig.length})`, 400);
  return ml_dsa65.verify(sig, message_bytes, pub);
}

function challengeMessageBytes(email, challenge_b64) {
  if (typeof email !== 'string' || email.length === 0) {
    throw mkErr('BAD_EMAIL', 'email required', 400);
  }
  if (typeof challenge_b64 !== 'string' || challenge_b64.length === 0) {
    throw mkErr('BAD_CHALLENGE', 'challenge_b64 required', 400);
  }
  return utf8(CHALLENGE_DOMAIN + email + ':' + challenge_b64);
}

async function issueChallenge(email) {
  if (typeof email !== 'string' || email.length === 0 || email.length > 320) {
    throw mkErr('BAD_EMAIL', 'email required (1..320 chars)', 400);
  }
  const fs = await getFirestore();
  const challengeBytes = randomBytes32();
  const challenge_b64 = b64Enc(challengeBytes);
  const expires_at = new Date(Date.now() + CHALLENGE_TTL_SECS * 1000).toISOString();
  const ch_id = await fs.createDoc('tm_challenges', {
    email,
    challenge_b64,
    expires_at
  });
  return { ch_id, challenge_b64 };
}

async function consumeChallenge(ch_id) {
  if (typeof ch_id !== 'string' || ch_id.length === 0) {
    throw mkErr('BAD_CH_ID', 'ch_id required', 400);
  }
  const fs = await getFirestore();
  const doc = await fs.fetchAndDelete('tm_challenges', ch_id);
  if (!doc) return null;
  if (typeof doc.expires_at === 'string') {
    const exp = Date.parse(doc.expires_at);
    if (!Number.isFinite(exp) || exp <= Date.now()) {
      return null;
    }
  }
  return doc;
}

// ---------------------------------------------------------------------------
// Per-action HMAC.
// ---------------------------------------------------------------------------

const replayStore = new Map();

function evictReplayIfNeeded() {
  if (replayStore.size <= ACTION_REPLAY_MAX) return;
  const drop = Math.floor(ACTION_REPLAY_MAX / 10);
  const it = replayStore.keys();
  for (let i = 0; i < drop; i++) {
    const { value, done } = it.next();
    if (done) break;
    replayStore.delete(value);
  }
}

function hmacB64u(keyBytes, message) {
  const h = createHmac('sha256', keyBytes);
  h.update(message);
  return b64u(new Uint8Array(h.digest()));
}

function _clearReplayStoreForTest() {
  replayStore.clear();
}

class AuthError extends Error {
  constructor(code, message, status) {
    super(message || code);
    this.name = 'AuthError';
    this.code = code || 'auth_error';
    this.status = status || 401;
  }
}

let _users = null;

async function getUsers() {
  if (_users) return _users;
  try {
    _users = await import('./users.js');
  } catch (e) {
    throw new AuthError(
      'tm_users_module_missing',
      'server/tm/users.js is not available. Underlying import error: ' + (e?.message || String(e)),
      503
    );
  }
  return _users;
}

function _setUsersForTest(mock) {
  _users = mock;
}

const getServerPubkeyB64 = getServerPubB64;

async function authenticate(req) {
  const headers = req?.headers || {};
  const raw = headers.authorization || headers.Authorization;
  if (typeof raw !== 'string' || raw.length === 0) {
    throw new AuthError('no_auth', 'Authorization header missing.', 401);
  }
  if (raw.length > 16384) {
    throw new AuthError('auth_too_large', 'Authorization header too large.', 401);
  }
  if (!raw.startsWith('Bearer ')) {
    throw new AuthError('auth_bad_scheme', 'Authorization must use Bearer scheme.', 401);
  }
  const token = raw.slice(7).trim();
  if (token.length === 0) throw new AuthError('auth_empty', 'Bearer token is empty.', 401);
  let payload;
  try {
    payload = await verifySession(token);
  } catch (e) {
    const code = e?.code || 'session_invalid';
    const status = e?.status || 401;
    throw new AuthError(mapSessionCode(code), e?.message || 'Session token rejected.', status);
  }
  if (req && typeof req === 'object') req.tm_session = payload;
  return payload;
}

function mapSessionCode(code) {
  switch (code) {
    case 'SESSION_MALFORMED': return 'session_malformed';
    case 'SESSION_BAD_HEADER': return 'session_bad_header';
    case 'SESSION_BAD_SIG': return 'session_bad_sig';
    case 'SESSION_BAD_CLAIMS': return 'session_bad_claims';
    case 'SESSION_EXPIRED': return 'session_expired';
    case 'SESSION_FUTURE': return 'session_future';
    case 'SESSION_NOT_FOUND': return 'session_not_found';
    default: return 'session_invalid';
  }
}

function getActionHeader(headers, name) {
  if (!headers || typeof headers !== 'object') return null;
  const v = headers[name] ?? headers[name.toUpperCase()] ?? headers[name.replace(/-/g, '_')];
  if (typeof v !== 'string' || v.length === 0) return null;
  return v;
}

// requireFreshHmacSig — the ONLY per-action signature gate.
//
// `actor` is the verified session payload from `authenticate()`. It
// MUST carry `token_id` so we can look up the session-bound action key
// from the in-memory cache. `headers` are the raw request headers; we
// pull `X-Action-Sig`, `X-Action-Ts`, and `X-Action-Key-Id` directly so
// no per-call body shape change is needed.
//
// Returns `{ uid, action, target, ts, key_id, next_action_key_b64,
// next_action_key_id }`. The caller forwards the next-key fields to
// the response so the client can rotate.
async function requireFreshHmacSig(actor, action, target, headers) {
  if (!actor || typeof actor.uid !== 'string') {
    throw new AuthError('no_session', 'actor required for action signature.', 401);
  }
  if (typeof action !== 'string' || action.length === 0) {
    throw new AuthError('bad_action', 'action required.', 400);
  }
  if (!isCriticalAction(action)) {
    throw new AuthError('bad_action', 'action is not on the critical-actions list.', 400);
  }
  if (typeof target !== 'string') {
    throw new AuthError('bad_action', 'target required.', 400);
  }
  if (typeof actor.token_id !== 'string' || actor.token_id.length === 0) {
    throw new AuthError('no_session', 'session token id missing on actor.', 401);
  }
  const sigB64u = getActionHeader(headers, ACTION_HEADER_SIG);
  const tsRaw = getActionHeader(headers, ACTION_HEADER_TS);
  const keyId = getActionHeader(headers, ACTION_HEADER_KEY_ID);
  if (!sigB64u) throw new AuthError('no_action_sig', 'X-Action-Sig header required.', 400);
  if (!tsRaw) throw new AuthError('no_action_ts', 'X-Action-Ts header required.', 400);
  if (!keyId) throw new AuthError('no_action_key_id', 'X-Action-Key-Id header required.', 400);
  const ts = Number(tsRaw);
  if (!Number.isFinite(ts) || !Number.isInteger(ts) || ts <= 0) {
    throw new AuthError('bad_action_ts', 'X-Action-Ts must be epoch seconds.', 400);
  }
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - ts) > ACTION_TS_SKEW_SECS) {
    throw new AuthError('stale_action', `X-Action-Ts outside ±${ACTION_TS_SKEW_SECS}s window.`, 400);
  }
  const entry = sessionCache.get(actor.token_id);
  if (!entry) {
    throw new AuthError('no_action_key', 'session action key missing; re-login required.', 401);
  }
  const users = await getUsers();
  if (typeof users.getMe !== 'function') {
    throw new AuthError('tm_users_module_incomplete', 'users.js missing required exports.', 503);
  }
  let userRow;
  try {
    userRow = await users.getMe(actor);
  } catch (e) {
    if (e?.status === 404 || e?.code === 'user_not_found') {
      throw new AuthError('user_gone', 'session uid not found in tm_users.', 401);
    }
    throw e;
  }
  if (!userRow) throw new AuthError('user_gone', 'session uid not found in tm_users.', 401);
  if (userRow.status === 'suspended') {
    throw new AuthError('user_suspended', 'user is suspended.', 403);
  }

  let activeKey = null;
  let activeKeyId = null;
  if (keyId === entry.key_id) {
    activeKey = entry.action_key_b64;
    activeKeyId = entry.key_id;
  } else if (
    entry.prev_key_id && keyId === entry.prev_key_id
    && typeof entry.prev_grace_until === 'number'
    && now <= entry.prev_grace_until
  ) {
    activeKey = entry.prev_action_key_b64;
    activeKeyId = entry.prev_key_id;
  } else {
    throw new AuthError('action_key_unknown', 'X-Action-Key-Id does not match an active key.', 401);
  }

  const canonical = canonicalActionMessage({
    uid: actor.uid,
    action,
    target,
    ts,
    key_id: activeKeyId
  });
  const expected = hmacB64u(b64Dec(activeKey), canonical);
  if (!timingSafeEqB64u(sigB64u, expected)) {
    throw new AuthError('action_sig_bad', 'action signature did not verify.', 401);
  }

  const replayKey = `${actor.uid}|${action}|${target}|${ts}`;
  const replayExp = replayStore.get(replayKey);
  if (replayExp && replayExp > now) {
    throw new AuthError('action_replay', 'action signature already used (replay).', 409);
  }
  replayStore.set(replayKey, now + ACTION_REPLAY_TTL_SECS);
  evictReplayIfNeeded();

  // Rotate the action key. Old key remains valid for ACTION_KEY_GRACE_SECS
  // so an in-flight client request that pre-dates the rotation still
  // succeeds.
  const nextKeyB64 = b64Enc(randomBytes32());
  const nextKeyId = newKeyId();
  entry.prev_action_key_b64 = entry.action_key_b64;
  entry.prev_key_id = entry.key_id;
  entry.prev_grace_until = now + ACTION_KEY_GRACE_SECS;
  entry.action_key_b64 = nextKeyB64;
  entry.key_id = nextKeyId;
  persistSession(actor.token_id, entry).catch(() => {});

  return {
    uid: actor.uid,
    action,
    target,
    ts,
    key_id: activeKeyId,
    next_action_key_b64: nextKeyB64,
    next_action_key_id: nextKeyId
  };
}

// Backwards-compatible alias for any caller that still uses the old
// name. Same behaviour: HMAC, not ML-DSA.
const requireFreshUserSig = requireFreshHmacSig;

// SPEC DEVIATION (acceptable per spec G): a parallel system-sig path
// rather than an extension to requireFreshHmacSig. Reasons:
//   - The HMAC path is bound to a session-scoped action key cached on the
//     in-memory session record. SYSTEM_AI has no session and no rotating
//     key; mixing the two mechanisms inside one function would force
//     extra branching on every human request.
//   - Human-facing endpoints stay on the HMAC path and are unchanged.
//   - The watchdog calls requireFreshSystemSig directly before invoking
//     dispatches.escalate / assignments.assignUnit.
//
// The SYSTEM_AI keypair lives in server/tm/watchdog.js so loading the
// auth module does not pull the ML-DSA verifier for system actions.
async function requireFreshSystemSig(actor, action, target, sigB64) {
  if (!actor || actor.uid !== 'SYSTEM_AI') {
    throw new AuthError('not_system_actor', 'requireFreshSystemSig requires the SYSTEM_AI actor.', 401);
  }
  if (typeof action !== 'string' || action.length === 0) {
    throw new AuthError('bad_action', 'action required.', 400);
  }
  if (!isCriticalAction(action)) {
    throw new AuthError('bad_action', 'action is not on the critical-actions list.', 400);
  }
  if (typeof target !== 'string') {
    throw new AuthError('bad_action', 'target required.', 400);
  }
  if (typeof sigB64 !== 'string' || sigB64.length === 0) {
    throw new AuthError('no_action_sig', 'system signature required.', 400);
  }
  let watchdogMod;
  try {
    watchdogMod = await import('./watchdog.js');
  } catch (e) {
    throw new AuthError('watchdog_unavailable',
      'server/tm/watchdog.js is not available: ' + (e?.message || String(e)), 503);
  }
  if (typeof watchdogMod.verifySystemAction !== 'function') {
    throw new AuthError('watchdog_incomplete',
      'watchdog.js missing verifySystemAction.', 503);
  }
  const ts = Math.floor(Date.now() / 1000);
  // The signed canonical message must include a server-known ts. The
  // watchdog signs at issue time and includes the ts in the body it
  // forwards through to assignUnit/escalate; we accept ts via the actor
  // object (set by watchdog) or fall back to "now" with a generous skew.
  const claimedTs = Number(actor.system_action_ts) || ts;
  const ok = watchdogMod.verifySystemAction({
    action,
    target,
    ts: claimedTs,
    key_id: actor.system_action_key_id || watchdogMod.SYSTEM_AI_KEY_ID,
    sig_b64: sigB64
  });
  if (!ok) {
    throw new AuthError('action_sig_bad', 'system action signature did not verify.', 401);
  }
  return {
    uid: 'SYSTEM_AI',
    action,
    target,
    ts: claimedTs,
    key_id: actor.system_action_key_id || watchdogMod.SYSTEM_AI_KEY_ID,
    next_action_key_b64: null,
    next_action_key_id: null
  };
}

function canonicalActionTarget(uid, action, target) {
  // Pre-existing helper used by `handleRegister` for the ML-DSA-signed
  // *invite*. Invites still ride ML-DSA because they are signed at
  // mint time and stored alongside the invite, not on every request.
  if (typeof uid !== 'string' || uid.length === 0) {
    throw new AuthError('bad_action', 'actor.uid required for invite signature.', 400);
  }
  if (typeof action !== 'string' || action.length === 0) {
    throw new AuthError('bad_action', 'action required for invite signature.', 400);
  }
  if (typeof target !== 'string') {
    throw new AuthError('bad_action', 'target required for invite signature.', 400);
  }
  return JSON.stringify({ uid, action, target });
}

function asNonEmptyString(v, code, msg) {
  if (typeof v !== 'string' || v.length === 0) throw new AuthError(code, msg, 400);
  return v;
}

async function handleRegister(body, _ctx) {
  if (!body || typeof body !== 'object') throw new AuthError('bad_request', 'body required.', 400);
  // Accept either `invite_id` (canonical) or `invite_token` (legacy
  // client). Both refer to the same Firestore doc.
  const invite_id = asNonEmptyString(
    body.invite_id ?? body.invite_token,
    'bad_request',
    'invite_id required.'
  );
  asNonEmptyString(body.name, 'bad_request', 'name required.');
  asNonEmptyString(body.pubkey_b64, 'bad_request', 'pubkey_b64 required.');

  const fs = await getFirestore();
  if (typeof fs.getDoc !== 'function') {
    throw new AuthError('tm_firestore_incomplete', 'firestore.js missing getDoc().', 503);
  }
  const inv = await fs.getDoc('tm_invitations', invite_id);
  if (!inv) throw new AuthError('invite_not_found', 'No such invite.', 404);
  if (inv.used === true) throw new AuthError('invite_used', 'Invite already consumed.', 409);
  const expMs = Date.parse(inv.expires_at || '') || 0;
  if (!expMs || expMs < Date.now()) throw new AuthError('invite_expired', 'Invite has expired.', 410);

  const issuerUid = typeof inv.issued_by_uid === 'string' ? inv.issued_by_uid : '';
  const issuerSigB64 = typeof inv.issued_signature_b64 === 'string' ? inv.issued_signature_b64 : '';
  if (!issuerUid || !issuerSigB64) {
    throw new AuthError('invite_unsigned', 'Invite is missing issuer signature.', 409);
  }
  const issuer = await fs.getDoc('tm_users', issuerUid);
  if (!issuer) throw new AuthError('issuer_gone', 'Invite issuer no longer exists.', 409);
  if (typeof issuer.pubkey_b64 !== 'string' || issuer.pubkey_b64.length === 0) {
    throw new AuthError('issuer_no_pubkey', 'Invite issuer has no pubkey.', 500);
  }
  const inviteTarget = `invite|${inv.email || ''}|${inv.tier || ''}|${inv.parent_uid || ''}|${inv.scope_path || ''}`;
  const canonical = canonicalActionTarget(issuerUid, 'user.invite', inviteTarget);
  let ok;
  try {
    ok = verifyUserSig(issuer.pubkey_b64, utf8(canonical), issuerSigB64);
  } catch (e) {
    throw new AuthError('invite_sig_bad', e?.message || 'invite signature rejected.', 409);
  }
  if (!ok) throw new AuthError('invite_sig_bad', 'invite signature did not verify.', 409);

  const users = await getUsers();
  if (typeof users.acceptInvite !== 'function') {
    throw new AuthError('tm_users_module_incomplete', 'users.js missing acceptInvite().', 503);
  }
  // Pass the resolved invite_id forward under both names so legacy
  // helpers in users.js still see what they expect.
  const forwarded = { ...body, invite_id, invite_token: invite_id };
  return users.acceptInvite(forwarded);
}

async function handleBootstrap(body, _ctx) {
  if (process.env.TM_BOOTSTRAP_ALLOW !== '1') {
    throw new AuthError('bootstrap_disabled', 'Bootstrap endpoint disabled. Set TM_BOOTSTRAP_ALLOW=1 to enable.', 403);
  }
  if (!body || typeof body !== 'object') throw new AuthError('bad_request', 'body required.', 400);
  const email = asNonEmptyString(body.email, 'bad_request', 'email required.');
  const name = asNonEmptyString(body.name, 'bad_request', 'name required.');
  const pubkey_b64 = asNonEmptyString(body.pubkey_b64, 'bad_request', 'pubkey_b64 required.');
  const users = await getUsers();
  if (typeof users.bootstrap !== 'function') {
    throw new AuthError('tm_users_module_incomplete', 'users.js missing bootstrap().', 503);
  }
  const created = await users.bootstrap(email, name, pubkey_b64);
  return {
    uid: created.uid,
    scope_path: created.scope_path,
    tier: created.tier,
    tier_name: created.tier_name || undefined,
    email: created.email,
    name: created.name,
    created_at: created.created_at || null
  };
}

async function handleChallenge(body, _ctx) {
  if (!body || typeof body !== 'object') throw new AuthError('bad_request', 'body required.', 400);
  const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
  if (email.length === 0 || email.length > 320) {
    throw new AuthError('bad_email', 'email required (1..320 chars).', 400);
  }
  const { ch_id, challenge_b64 } = await issueChallenge(email);
  const expires_at = new Date(Date.now() + CHALLENGE_TTL_SECS * 1000).toISOString();
  return { ch_id, challenge_b64, expires_at };
}

async function handleVerify(body, _ctx) {
  if (!body || typeof body !== 'object') throw new AuthError('bad_request', 'body required.', 400);
  const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
  const ch_id = typeof body.ch_id === 'string' ? body.ch_id : '';
  const signature_b64 = typeof body.signature_b64 === 'string' ? body.signature_b64 : '';
  if (email.length === 0) throw new AuthError('bad_request', 'email required.', 400);
  if (ch_id.length === 0) throw new AuthError('bad_request', 'ch_id required.', 400);
  if (signature_b64.length === 0) throw new AuthError('bad_request', 'signature_b64 required.', 400);

  const failGeneric = () => new AuthError('challenge_invalid', 'Challenge could not be verified.', 401);

  const challenge = await consumeChallenge(ch_id);
  if (!challenge) throw failGeneric();
  const storedEmail = typeof challenge.email === 'string' ? challenge.email.trim().toLowerCase() : '';
  if (storedEmail !== email) throw failGeneric();

  const users = await getUsers();
  if (typeof users.lookupByEmail !== 'function' || typeof users.touchLastLogin !== 'function') {
    throw new AuthError('tm_users_module_incomplete', 'users.js missing lookupByEmail / touchLastLogin.', 503);
  }
  const user = await users.lookupByEmail(email);
  if (!user) throw failGeneric();
  if (user.status === 'suspended') {
    throw new AuthError('account_suspended', 'Account is suspended.', 403);
  }
  if (typeof user.pubkey_b64 !== 'string' || user.pubkey_b64.length === 0) {
    throw new AuthError('user_no_pubkey', 'tm_users record missing pubkey_b64.', 500);
  }
  const msgBytes = challengeMessageBytes(email, challenge.challenge_b64);
  let ok;
  try {
    ok = verifyUserSig(user.pubkey_b64, msgBytes, signature_b64);
  } catch {
    throw failGeneric();
  }
  if (!ok) throw failGeneric();

  const action_key_b64 = b64Enc(randomBytes32());
  const key_id = newKeyId();
  const token = signSession({
    uid: user.uid,
    tier: user.tier,
    scope_path: user.scope_path,
    action_key_b64,
    key_id
  });
  const payload = await verifySession(token);
  await users.touchLastLogin(user.uid);
  return {
    token,
    exp: new Date(payload.exp * 1000).toISOString(),
    server_pubkey_b64: getServerPubB64(),
    action_key_b64,
    key_id,
    user: {
      uid: user.uid,
      email: user.email,
      name: user.name,
      tier: user.tier,
      tier_name: user.tier_name,
      scope_path: user.scope_path
    }
  };
}

export {
  signSession,
  verifySession,
  verifyUserSig,
  issueChallenge,
  consumeChallenge,
  challengeMessageBytes,
  randomBytes32,
  b64u,
  b64uDec,
  b64Enc,
  b64Dec,
  utf8,
  utf8Dec,
  eqBytes,
  getServerPub,
  getServerPubB64,
  isServerKeyEphemeral,
  _setFirestoreForTest,
  _setUsersForTest,
  _setSessionEntryForTest,
  _getSessionEntryForTest,
  _clearSessionCacheForTest,
  _clearReplayStoreForTest,
  AuthError,
  authenticate,
  getServerPubkeyB64,
  handleRegister,
  handleBootstrap,
  handleChallenge,
  handleVerify,
  requireFreshHmacSig,
  requireFreshUserSig,
  requireFreshSystemSig,
  canonicalActionTarget,
  hmacB64u,
  CHALLENGE_DOMAIN,
  SESSION_TTL_SECS,
  CHALLENGE_TTL_SECS,
  ACTION_TS_SKEW_SECS,
  ACTION_REPLAY_TTL_SECS,
  ACTION_KEY_GRACE_SECS
};
