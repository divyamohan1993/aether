// Project Aether · Task Manager · ML-DSA-65 auth core.
//
// Server-side helpers: server keypair custody, session token issue and
// verify, login challenge issue and consume, user signature verify.
// Pure ESM, Node 22+.

import { randomBytes } from 'node:crypto';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

const SESSION_TTL_SECS = 30 * 60;
const CHALLENGE_TTL_SECS = 60;
const CHALLENGE_DOMAIN = 'aether-tm:v1:';
const SESSION_HEADER = { alg: 'ML-DSA-65', typ: 'AETHER' };

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

let SERVER_PRIV = null;
let SERVER_PUB = null;
let SERVER_KEY_FRESH = false;

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
    return;
  }
  const k = ml_dsa65.keygen();
  SERVER_PRIV = k.secretKey;
  SERVER_PUB = k.publicKey;
  SERVER_KEY_FRESH = true;
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
  const full = {
    uid: payload.uid,
    tier: payload.tier,
    scope_path: payload.scope_path,
    iat: payload.iat ?? now,
    exp: payload.exp ?? (now + SESSION_TTL_SECS)
  };
  const headerB64 = b64u(utf8(JSON.stringify(SESSION_HEADER)));
  const payloadB64 = b64u(utf8(JSON.stringify(full)));
  const signingInput = utf8(headerB64 + '.' + payloadB64);
  const sig = ml_dsa65.sign(signingInput, getServerPrivInternal());
  const sigB64 = b64u(sig);
  return `${headerB64}.${payloadB64}.${sigB64}`;
}

function verifySession(token) {
  if (typeof token !== 'string' || token.length === 0) {
    throw mkErr('SESSION_MALFORMED', 'session token missing', 401);
  }
  const parts = token.split('.');
  if (parts.length !== 3) throw mkErr('SESSION_MALFORMED', 'session token must have three parts', 401);
  const [headerB64, payloadB64, sigB64] = parts;
  let header;
  let payload;
  try {
    header = JSON.parse(utf8Dec(b64uDec(headerB64)));
    payload = JSON.parse(utf8Dec(b64uDec(payloadB64)));
  } catch {
    throw mkErr('SESSION_MALFORMED', 'session token header or payload is not valid base64url JSON', 401);
  }
  if (!header || header.alg !== 'ML-DSA-65' || header.typ !== 'AETHER') {
    throw mkErr('SESSION_BAD_HEADER', 'session token header rejected', 401);
  }
  let sig;
  try {
    sig = b64uDec(sigB64);
  } catch {
    throw mkErr('SESSION_MALFORMED', 'session token signature not valid base64url', 401);
  }
  const signingInput = utf8(headerB64 + '.' + payloadB64);
  if (!ml_dsa65.verify(sig, signingInput, getServerPub())) {
    throw mkErr('SESSION_BAD_SIG', 'session token signature failed verification', 401);
  }
  if (typeof payload.exp !== 'number' || typeof payload.iat !== 'number') {
    throw mkErr('SESSION_BAD_CLAIMS', 'session token missing iat/exp', 401);
  }
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp <= now) throw mkErr('SESSION_EXPIRED', 'session token expired', 401);
  if (payload.iat > now + 60) throw mkErr('SESSION_FUTURE', 'session token iat in the future', 401);
  if (typeof payload.uid !== 'string' || typeof payload.scope_path !== 'string' || typeof payload.tier !== 'number') {
    throw mkErr('SESSION_BAD_CLAIMS', 'session token claims malformed', 401);
  }
  return payload;
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
// Router-facing handlers and AuthError. The router lazy-imports this module
// and calls these functions directly. They throw AuthError on failure; the
// router maps `name === 'AuthError'` to the supplied `status`.
// ---------------------------------------------------------------------------

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
    payload = verifySession(token);
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
    default: return 'session_invalid';
  }
}

function canonicalActionTarget(uid, action, target) {
  if (typeof uid !== 'string' || uid.length === 0) {
    throw new AuthError('bad_action', 'actor.uid required for re-sign.', 400);
  }
  if (typeof action !== 'string' || action.length === 0) {
    throw new AuthError('bad_action', 'action required for re-sign.', 400);
  }
  if (typeof target !== 'string') {
    throw new AuthError('bad_action', 'target required for re-sign.', 400);
  }
  return JSON.stringify({ uid, action, target });
}

// 4-arg form used by router.js. The canonical signed bytes are
// `JSON.stringify({uid: actor.uid, action, target})` as documented in
// _iface.md (router-call-site canonical action message format).
async function requireFreshUserSig(actor, action, target, signature_b64) {
  if (!actor || typeof actor.uid !== 'string') {
    throw new AuthError('no_session', 'actor required for re-sign.', 401);
  }
  if (typeof signature_b64 !== 'string' || signature_b64.length === 0) {
    throw new AuthError('no_action_sig', 'signature_b64 required.', 400);
  }
  const canonical = canonicalActionTarget(actor.uid, action, target);
  const users = await getUsers();
  if (typeof users.lookupByEmail !== 'function' || typeof users.getMe !== 'function') {
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
  if (typeof userRow.pubkey_b64 !== 'string' || userRow.pubkey_b64.length === 0) {
    throw new AuthError('user_no_pubkey', 'tm_users record missing pubkey_b64.', 500);
  }
  let ok;
  try {
    ok = verifyUserSig(userRow.pubkey_b64, utf8(canonical), signature_b64);
  } catch (e) {
    throw new AuthError('action_sig_bad', e?.message || 'action signature rejected.', 400);
  }
  if (!ok) throw new AuthError('action_sig_bad', 'action signature did not verify.', 401);
  return { uid: actor.uid, action, target, message: canonical, signature_b64 };
}

function asNonEmptyString(v, code, msg) {
  if (typeof v !== 'string' || v.length === 0) throw new AuthError(code, msg, 400);
  return v;
}

async function handleRegister(body, _ctx) {
  if (!body || typeof body !== 'object') throw new AuthError('bad_request', 'body required.', 400);
  const invite_id = asNonEmptyString(body.invite_id, 'bad_request', 'invite_id required.');
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
  return users.acceptInvite(body);
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

  const token = signSession({ uid: user.uid, tier: user.tier, scope_path: user.scope_path });
  const payload = verifySession(token);
  await users.touchLastLogin(user.uid);
  return {
    token,
    exp: new Date(payload.exp * 1000).toISOString(),
    server_pubkey_b64: getServerPubB64(),
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
  AuthError,
  authenticate,
  getServerPubkeyB64,
  handleRegister,
  handleBootstrap,
  handleChallenge,
  handleVerify,
  requireFreshUserSig,
  canonicalActionTarget,
  CHALLENGE_DOMAIN,
  SESSION_TTL_SECS,
  CHALLENGE_TTL_SECS
};
