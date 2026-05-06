// Project Aether · Task Manager · request middleware.
//
// Light wrappers around server/tm/auth.js. The auth module is the
// single source of truth for verification logic; this file exists so
// router and tests can use a consistent extraction surface (Bearer,
// session payload).
//
// The per-action signature path lives entirely in auth.js
// (`requireFreshHmacSig`). Re-exporting here lets older test imports
// keep working while the move is finished.

import {
  verifySession,
  requireFreshHmacSig
} from './auth.js';
import { canonicalActionMessage } from './canonical.js';

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

async function requireSession(req, headers) {
  const hdrs = headers || req?.headers || {};
  const token = extractBearer(hdrs);
  let payload;
  try {
    payload = await verifySession(token);
  } catch (e) {
    if (e && e.code && e.status) throw e;
    throw mkErr('SESSION_INVALID', e?.message || 'session token rejected', 401);
  }
  if (req && typeof req === 'object') {
    req.tm_session = payload;
  }
  return payload;
}

// Test seam kept for backwards compatibility with tests that wired a
// fake firestore through the middleware module. The real firestore
// hookup lives in auth.js; we forward there.
async function _setFirestoreForTest(mock) {
  const auth = await import('./auth.js');
  if (typeof auth._setFirestoreForTest === 'function') {
    auth._setFirestoreForTest(mock);
  }
}

export {
  requireSession,
  requireFreshHmacSig,
  extractBearer,
  canonicalActionMessage,
  _setFirestoreForTest
};
