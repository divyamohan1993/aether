// Project Aether · Task Manager · auth middleware.
//
// requireSession: extract Bearer token, verify, return decoded payload.
// requireFreshUserSig: verify a per-action ML-DSA-65 signature from the
// user's stored pubkey in `tm_users/{uid}`.

import {
  verifySession,
  verifyUserSig,
  utf8
} from './auth.js';

function mkErr(code, message, status) {
  const e = new Error(message);
  e.code = code;
  e.status = status;
  return e;
}

function extractBearer(headers) {
  const raw = headers?.authorization || headers?.Authorization;
  if (typeof raw !== 'string' || raw.length === 0) {
    throw mkErr('NO_AUTH', 'Authorization header missing', 401);
  }
  if (raw.length > 16384) {
    throw mkErr('AUTH_TOO_LARGE', 'Authorization header too large', 401);
  }
  if (!raw.startsWith('Bearer ')) {
    throw mkErr('AUTH_BAD_SCHEME', 'Authorization must use Bearer scheme', 401);
  }
  const tok = raw.slice(7).trim();
  if (tok.length === 0) throw mkErr('AUTH_EMPTY', 'Bearer token is empty', 401);
  return tok;
}

function requireSession(req, headers) {
  const hdrs = headers || req?.headers || {};
  const token = extractBearer(hdrs);
  let payload;
  try {
    payload = verifySession(token);
  } catch (e) {
    if (e && e.code && e.status) throw e;
    throw mkErr('SESSION_INVALID', e?.message || 'session token rejected', 401);
  }
  if (req && typeof req === 'object') {
    req.tm_session = payload;
  }
  return payload;
}

let _firestore = null;
async function getFirestore() {
  if (_firestore) return _firestore;
  try {
    _firestore = await import('./firestore.js');
  } catch (e) {
    throw mkErr(
      'TM_FIRESTORE_MISSING',
      'server/tm/firestore.js is not available. Underlying import error: ' + (e?.message || String(e)),
      500
    );
  }
  return _firestore;
}

function _setFirestoreForTest(mock) {
  _firestore = mock;
}

function canonicalActionMessage(uid, action, target, ts) {
  if (typeof uid !== 'string' || uid.length === 0) {
    throw mkErr('BAD_ACTION', 'action signature requires uid', 400);
  }
  if (typeof action !== 'string' || action.length === 0) {
    throw mkErr('BAD_ACTION', 'action signature requires action', 400);
  }
  if (typeof target !== 'string' || target.length === 0) {
    throw mkErr('BAD_ACTION', 'action signature requires target', 400);
  }
  if (typeof ts !== 'number' || !Number.isFinite(ts)) {
    throw mkErr('BAD_ACTION', 'action signature requires numeric ts (epoch seconds)', 400);
  }
  return JSON.stringify({ uid, action, target, ts });
}

async function requireFreshUserSig(req, body, payload) {
  if (!body || typeof body !== 'object') {
    throw mkErr('NO_BODY', 'request body required for re-sign', 400);
  }
  if (!payload || typeof payload.uid !== 'string') {
    throw mkErr('NO_SESSION', 'session payload required for re-sign', 401);
  }
  const sigB64 = body.action_signature_b64;
  const action = body.action;
  const target = body.target;
  const ts = typeof body.ts === 'number' ? body.ts : Number(body.ts);
  if (typeof sigB64 !== 'string' || sigB64.length === 0) {
    throw mkErr('NO_ACTION_SIG', 'body.action_signature_b64 required', 400);
  }
  const now = Math.floor(Date.now() / 1000);
  const skewSecs = 120;
  if (!Number.isFinite(ts) || ts < now - skewSecs || ts > now + skewSecs) {
    throw mkErr('STALE_ACTION', 'body.ts must be within 120 seconds of server time', 400);
  }
  const fs = await getFirestore();
  const user = await fs.getDoc('tm_users', payload.uid);
  if (!user) throw mkErr('USER_GONE', 'session uid not found in tm_users', 401);
  if (user.status === 'suspended') {
    throw mkErr('USER_SUSPENDED', 'user is suspended', 403);
  }
  if (typeof user.pubkey_b64 !== 'string' || user.pubkey_b64.length === 0) {
    throw mkErr('USER_NO_PUBKEY', 'tm_users record missing pubkey_b64', 500);
  }
  const message = canonicalActionMessage(payload.uid, action, target, ts);
  let ok;
  try {
    ok = verifyUserSig(user.pubkey_b64, utf8(message), sigB64);
  } catch (e) {
    if (e && e.status) throw e;
    throw mkErr('ACTION_SIG_BAD', e?.message || 'action signature rejected', 400);
  }
  if (!ok) throw mkErr('ACTION_SIG_BAD', 'action signature did not verify against user pubkey', 401);
  if (req && typeof req === 'object') {
    req.tm_action_verified = { action, target, ts };
  }
  return { uid: payload.uid, action, target, ts, message, signature_b64: sigB64 };
}

export {
  requireSession,
  requireFreshUserSig,
  extractBearer,
  canonicalActionMessage,
  _setFirestoreForTest
};
