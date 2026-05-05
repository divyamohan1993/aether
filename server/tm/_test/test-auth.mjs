// Project Aether · Task Manager · auth self-test.
//
// Run: `node server/tm/_test/test-auth.mjs`
// Exits 0 with `OK` on success. Exits 1 with a diagnostic on any failure.

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { randomUUID } from 'node:crypto';

import {
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
  _setFirestoreForTest as setAuthFirestore,
  CHALLENGE_TTL_SECS,
  SESSION_TTL_SECS,
  CHALLENGE_DOMAIN
} from '../auth.js';

import {
  requireSession,
  requireFreshUserSig,
  extractBearer,
  canonicalActionMessage,
  _setFirestoreForTest as setMwFirestore
} from '../middleware.js';

let failed = 0;
function ok(name, cond, detail) {
  if (cond) {
    process.stdout.write(`  PASS  ${name}\n`);
  } else {
    failed++;
    process.stdout.write(`  FAIL  ${name}${detail ? ' :: ' + detail : ''}\n`);
  }
}
function expectThrow(name, fn, codeWanted) {
  let caught = null;
  try { const r = fn(); if (r && typeof r.then === 'function') return r.then(() => ok(name, false, 'no throw'), e => ok(name, e?.code === codeWanted || codeWanted == null, `code=${e?.code} msg=${e?.message}`)); } catch (e) { caught = e; }
  ok(name, caught && (caught.code === codeWanted || codeWanted == null), caught ? `code=${caught.code} msg=${caught.message}` : 'no throw');
}

class FakeFs {
  constructor() {
    this.collections = new Map();
  }
  _col(name) {
    if (!this.collections.has(name)) this.collections.set(name, new Map());
    return this.collections.get(name);
  }
  async createDoc(collection, data) {
    const id = randomUUID();
    this._col(collection).set(id, JSON.parse(JSON.stringify(data)));
    return id;
  }
  async setDoc(collection, id, data) {
    this._col(collection).set(id, JSON.parse(JSON.stringify(data)));
  }
  async getDoc(collection, id) {
    const v = this._col(collection).get(id);
    return v ? JSON.parse(JSON.stringify(v)) : null;
  }
  async deleteDoc(collection, id) {
    this._col(collection).delete(id);
  }
  async fetchAndDelete(collection, id) {
    const col = this._col(collection);
    if (!col.has(id)) return null;
    const v = col.get(id);
    col.delete(id);
    return JSON.parse(JSON.stringify(v));
  }
}

const fakeFs = new FakeFs();
setAuthFirestore(fakeFs);
setMwFirestore(fakeFs);

// 1. Helpers round-trip.
{
  const r = randomBytes32();
  ok('randomBytes32 length', r.length === 32);
  const txt = 'aether-tm:keypair-self-test:' + 'अग्नि';
  const enc = utf8(txt);
  ok('utf8 round-trip', utf8Dec(enc) === txt);
  const bin = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
  ok('b64 round-trip', eqBytes(b64Dec(b64Enc(bin)), bin));
  ok('b64u round-trip', eqBytes(b64uDec(b64u(bin)), bin));
  ok('eqBytes mismatch', !eqBytes(new Uint8Array([1,2]), new Uint8Array([1,3])));
  ok('eqBytes match', eqBytes(new Uint8Array([1,2]), new Uint8Array([1,2])));
}

// 2. Server keypair loaded.
{
  const pub = getServerPub();
  ok('server pub length 1952', pub.length === 1952);
  ok('server pub b64 decodes', b64Dec(getServerPubB64()).length === 1952);
  ok('server key ephemeral flag is boolean', typeof isServerKeyEphemeral() === 'boolean');
}

// 3. Session sign + verify.
{
  const tok = signSession({ uid: 'u-123', tier: 80, scope_path: 'ndma/HP' });
  ok('session token has 3 dot-parts', tok.split('.').length === 3);
  const dec = verifySession(tok);
  ok('session decoded uid', dec.uid === 'u-123');
  ok('session decoded tier', dec.tier === 80);
  ok('session decoded scope', dec.scope_path === 'ndma/HP');
  ok('session iat is recent', Math.abs(dec.iat - Math.floor(Date.now() / 1000)) <= 5);
  ok('session exp = iat + TTL', dec.exp - dec.iat === SESSION_TTL_SECS);
  // tampered payload
  const [h, p, s] = tok.split('.');
  const badPayload = b64u(utf8(JSON.stringify({ uid: 'u-evil', tier: 100, scope_path: 'ndma', iat: dec.iat, exp: dec.exp })));
  expectThrow('verifySession tamper', () => verifySession(`${h}.${badPayload}.${s}`), 'SESSION_BAD_SIG');
  // expired
  const tokExp = signSession({ uid: 'u-1', tier: 20, scope_path: 'ndma', iat: 1, exp: 2 });
  expectThrow('verifySession expired', () => verifySession(tokExp), 'SESSION_EXPIRED');
  expectThrow('verifySession malformed', () => verifySession('a.b'), 'SESSION_MALFORMED');
  expectThrow('verifySession empty', () => verifySession(''), 'SESSION_MALFORMED');
}

// 4. User signature verify wrapper.
{
  const k = ml_dsa65.keygen();
  const pub_b64 = b64Enc(k.publicKey);
  const msg = utf8('hello aether');
  const sig = ml_dsa65.sign(msg, k.secretKey);
  ok('verifyUserSig good', verifyUserSig(pub_b64, msg, b64Enc(sig)) === true);
  ok('verifyUserSig wrong msg', verifyUserSig(pub_b64, utf8('hello other'), b64Enc(sig)) === false);
  expectThrow('verifyUserSig bad pubkey len', () => verifyUserSig(b64Enc(new Uint8Array(10)), msg, b64Enc(sig)), 'BAD_PUBKEY');
  expectThrow('verifyUserSig bad sig len', () => verifyUserSig(pub_b64, msg, b64Enc(new Uint8Array(10))), 'BAD_SIG');
}

// 5. Challenge issue + consume against fake Firestore.
{
  const email = 'commander@ndma.in';
  const { ch_id, challenge_b64 } = await issueChallenge(email);
  ok('challenge has ch_id', typeof ch_id === 'string' && ch_id.length > 0);
  ok('challenge_b64 decodes to 32 bytes', b64Dec(challenge_b64).length === 32);
  ok('challenge stored', fakeFs.collections.get('tm_challenges').size === 1);
  const msg = challengeMessageBytes(email, challenge_b64);
  ok('challenge prefix', utf8Dec(msg).startsWith(CHALLENGE_DOMAIN));
  const consumed = await consumeChallenge(ch_id);
  ok('challenge consumed returns doc', consumed && consumed.email === email);
  ok('challenge deleted after consume', fakeFs.collections.get('tm_challenges').size === 0);
  const second = await consumeChallenge(ch_id);
  ok('challenge single-use (null on replay)', second === null);
}

// 6. Challenge expiry path.
{
  const fakeId = await fakeFs.createDoc('tm_challenges', {
    email: 'old@x.in',
    challenge_b64: b64Enc(randomBytes32()),
    expires_at: new Date(Date.now() - 1000).toISOString()
  });
  const r = await consumeChallenge(fakeId);
  ok('expired challenge returns null', r === null);
}

// 7. End-to-end login: client signs, server verifies, server issues session.
{
  const userKey = ml_dsa65.keygen();
  const uid = 'u-' + randomUUID();
  const email = 'responder@hp.gov.in';
  await fakeFs.setDoc('tm_users', uid, {
    email,
    name: 'Asha Negi',
    tier: 40,
    parent_uid: null,
    scope_path: 'ndma/HP/Shimla',
    pubkey_b64: b64Enc(userKey.publicKey),
    status: 'active',
    created_at: new Date().toISOString(),
    last_login: null
  });

  const { ch_id, challenge_b64 } = await issueChallenge(email);
  const challengeMsg = challengeMessageBytes(email, challenge_b64);
  const userSig = ml_dsa65.sign(challengeMsg, userKey.secretKey);
  const userSigB64 = b64Enc(userSig);

  const consumed = await consumeChallenge(ch_id);
  ok('consumed during login', consumed && consumed.email === email);
  ok('verifyUserSig accepts client signature', verifyUserSig(b64Enc(userKey.publicKey), challengeMsg, userSigB64) === true);

  const token = signSession({ uid, tier: 40, scope_path: 'ndma/HP/Shimla' });
  const payload = verifySession(token);
  ok('issued session uid', payload.uid === uid);
  ok('issued session tier', payload.tier === 40);

  // Middleware Bearer extraction.
  const headers = { authorization: 'Bearer ' + token };
  const mwPayload = requireSession({}, headers);
  ok('requireSession returns payload', mwPayload.uid === uid);
  expectThrow('requireSession no header', () => requireSession({}, {}), 'NO_AUTH');
  expectThrow('requireSession bad scheme', () => requireSession({}, { authorization: 'Basic abc' }), 'AUTH_BAD_SCHEME');
  expectThrow('requireSession empty bearer', () => requireSession({}, { authorization: 'Bearer ' }), 'AUTH_EMPTY');

  // Re-sign action (e.g. role delegate).
  const ts = Math.floor(Date.now() / 1000);
  const action = 'user.delegate';
  const target = 'tm_users/' + uid;
  const canonical = canonicalActionMessage(uid, action, target, ts);
  ok('canonical message is JSON', JSON.parse(canonical).uid === uid);
  const actionSig = ml_dsa65.sign(utf8(canonical), userKey.secretKey);
  const body = {
    action,
    target,
    ts,
    action_signature_b64: b64Enc(actionSig)
  };
  const verified = await requireFreshUserSig({}, body, payload);
  ok('requireFreshUserSig accepts', verified.uid === uid && verified.action === action);

  const tampered = { ...body, target: 'tm_users/u-other' };
  let threw = null;
  try { await requireFreshUserSig({}, tampered, payload); } catch (e) { threw = e; }
  ok('requireFreshUserSig rejects tampered target', threw && threw.code === 'ACTION_SIG_BAD');

  const stale = { ...body, ts: ts - 600 };
  let threw2 = null;
  try { await requireFreshUserSig({}, stale, payload); } catch (e) { threw2 = e; }
  ok('requireFreshUserSig rejects stale ts', threw2 && threw2.code === 'STALE_ACTION');
}

// 8. extractBearer guards.
{
  expectThrow('extractBearer rejects oversize', () => extractBearer({ authorization: 'Bearer ' + 'a'.repeat(20000) }), 'AUTH_TOO_LARGE');
  ok('extractBearer accepts short token', extractBearer({ authorization: 'Bearer abc' }) === 'abc');
}

if (failed === 0) {
  process.stdout.write('OK\n');
  process.exit(0);
} else {
  process.stdout.write(`FAIL: ${failed} assertion(s) failed\n`);
  process.exit(1);
}
