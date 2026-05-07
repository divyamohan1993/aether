// Project Aether · Task Manager · auth self-test.
//
// Run: `node server/tm/_test/test-auth.mjs`
// Exits 0 with `OK` on success. Exits 1 with a diagnostic on any failure.
//
// Covers:
//   - low-level helpers (b64/utf8/eqBytes)
//   - compact bearer issue/verify (cache and Firestore paths)
//   - per-action HMAC sig: roundtrip, ts skew, replay, key rotation
//   - canonical message bytes: client (browser bundle) === server
//   - password login + register (scrypt hash + verify, timing mask)
//   - middleware façade (requireSession, extractBearer)

import { randomUUID, webcrypto } from 'node:crypto';

if (!globalThis.crypto) globalThis.crypto = webcrypto;

import {
  signSession,
  verifySession,
  randomBytes32,
  b64u,
  b64uDec,
  b64Enc,
  b64Dec,
  utf8,
  utf8Dec,
  eqBytes,
  hmacB64u,
  hashPassword,
  verifyPassword,
  handleLogin,
  handleRegister,
  handleBootstrap,
  requireFreshHmacSig,
  _setFirestoreForTest as setAuthFirestore,
  _setUsersForTest as setAuthUsers,
  _clearReplayStoreForTest,
  _clearSessionCacheForTest,
  _getSessionEntryForTest,
  SESSION_TTL_SECS,
  ACTION_TS_SKEW_SECS,
  ACTION_KEY_GRACE_SECS
} from '../auth.js';

import {
  requireSession,
  extractBearer
} from '../middleware.js';

import {
  canonicalActionMessage,
  isCriticalAction,
  CRITICAL_ACTIONS
} from '../canonical.js';

import {
  canonicalActionMessage as clientCanonical,
  hmacActionSig as clientHmacActionSig
} from '../../../web/tm/auth-client.js';

let failed = 0;
function ok(name, cond, detail) {
  if (cond) {
    process.stdout.write(`  PASS  ${name}\n`);
  } else {
    failed++;
    process.stdout.write(`  FAIL  ${name}${detail ? ' :: ' + detail : ''}\n`);
  }
}
async function expectThrow(name, fn, codeWanted) {
  let caught = null;
  try { const r = fn(); if (r && typeof r.then === 'function') await r; }
  catch (e) { caught = e; }
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
  ok('eqBytes mismatch', !eqBytes(new Uint8Array([1, 2]), new Uint8Array([1, 3])));
  ok('eqBytes match', eqBytes(new Uint8Array([1, 2]), new Uint8Array([1, 2])));
}

// 2. Password hash + verify roundtrip.
{
  const cred = hashPassword('aether-demo-2026');
  ok('hashPassword salt b64u 16 bytes', b64uDec(cred.saltB64u).length === 16);
  ok('hashPassword hash b64u 32 bytes', b64uDec(cred.hashB64u).length === 32);
  ok('verifyPassword good', verifyPassword('aether-demo-2026', cred.saltB64u, cred.hashB64u));
  ok('verifyPassword wrong', !verifyPassword('not-the-password', cred.saltB64u, cred.hashB64u));
  ok('verifyPassword empty', !verifyPassword('', cred.saltB64u, cred.hashB64u));
  ok('verifyPassword tampered hash', !verifyPassword('aether-demo-2026', cred.saltB64u, cred.hashB64u.slice(0, -1) + 'A'));
  // Two distinct hashes for the same password (different salts).
  const cred2 = hashPassword('aether-demo-2026');
  ok('hashPassword randomises salt', cred.saltB64u !== cred2.saltB64u);
  ok('hashPassword randomises hash', cred.hashB64u !== cred2.hashB64u);
  // Length bounds.
  expectThrow('hashPassword rejects too-short', () => hashPassword('1234567'), 'bad_password');
}

// 3. Compact bearer issue + verify.
{
  _clearSessionCacheForTest();
  const action_key_b64 = b64Enc(randomBytes32());
  const tok = signSession({ uid: 'u-123', tier: 80, scope_path: 'ndma/HP', action_key_b64, key_id: 'k0' });
  ok('compact bearer has 2 parts', tok.split('.').length === 2);
  ok('compact bearer fits within 200 chars', tok.length < 200, `len=${tok.length}`);
  const dec = await verifySession(tok);
  ok('session decoded uid', dec.uid === 'u-123');
  ok('session decoded tier', dec.tier === 80);
  ok('session decoded scope', dec.scope_path === 'ndma/HP');
  ok('session decoded token_id present', typeof dec.token_id === 'string' && dec.token_id.length > 0);
  ok('session decoded key_id present', dec.key_id === 'k0');
  // tampered HMAC byte
  const [tid, hmac] = tok.split('.');
  const flipped = hmac.slice(0, -1) + (hmac.slice(-1) === 'A' ? 'B' : 'A');
  await expectThrow('verifySession tamper', async () => verifySession(`${tid}.${flipped}`), 'SESSION_BAD_SIG');
  await expectThrow('verifySession malformed', async () => verifySession('abc'), 'SESSION_MALFORMED');
  await expectThrow('verifySession empty', async () => verifySession(''), 'SESSION_MALFORMED');
}

// 3b. Cache miss → Firestore lookup repopulates the cache.
{
  _clearSessionCacheForTest();
  const action_key_b64 = b64Enc(randomBytes32());
  const tok = signSession({ uid: 'u-fs', tier: 60, scope_path: 'ndma/HP/Shimla', action_key_b64, key_id: 'kfs' });
  // Wait briefly for the fire-and-forget Firestore write to land, then
  // wipe the in-memory cache and verify we recover from Firestore.
  await new Promise((r) => setTimeout(r, 10));
  _clearSessionCacheForTest();
  const dec = await verifySession(tok);
  ok('verifySession reloads from Firestore', dec.uid === 'u-fs');
  const tid = tok.split('.')[0];
  ok('Firestore-reloaded session repopulated cache', !!_getSessionEntryForTest(tid));
}

// 4. End-to-end password login.
{
  _clearSessionCacheForTest();
  const email = 'asha@hp.gov.in';
  const password = 'lotus-monsoon-72';
  const cred = hashPassword(password);
  const uid = 'u-' + randomUUID();
  await fakeFs.setDoc('tm_users', uid, {
    email, name: 'Asha Negi', tier: 40, parent_uid: null,
    scope_path: 'ndma/HP/Shimla', status: 'active',
    password_salt_b64u: cred.saltB64u,
    password_hash_b64u: cred.hashB64u,
    created_at: new Date().toISOString(), last_login: null
  });
  await fakeFs.setDoc('tm_user_emails', email, { uid });
  const fakeUsers = {
    async lookupByEmailRaw(e) {
      const idx = await fakeFs.getDoc('tm_user_emails', e);
      if (!idx) return null;
      const u = await fakeFs.getDoc('tm_users', idx.uid);
      return u ? { uid: idx.uid, ...u } : null;
    },
    async getMe(actor) {
      const u = await fakeFs.getDoc('tm_users', actor.uid);
      if (!u) throw Object.assign(new Error('not_found'), { code: 'user_not_found', status: 404 });
      return { uid: actor.uid, ...u };
    },
    async touchLastLogin() {},
    tierName: (t) => ({ 100: 'ndma', 80: 'sdma', 60: 'ddma', 40: 'subdivisional', 20: 'volunteer', 10: 'survivor' }[t] || 'unknown')
  };
  setAuthUsers(fakeUsers);

  const r = await handleLogin({ email, password });
  ok('handleLogin returns token', typeof r.token === 'string' && r.token.length > 0);
  ok('handleLogin returns user.uid', r.user.uid === uid);
  ok('handleLogin returns tier_name', r.user.tier_name === 'subdivisional');
  ok('handleLogin returns action_key_b64', typeof r.action_key_b64 === 'string' && b64Dec(r.action_key_b64).length === 32);

  // Round-trip through the bearer.
  const session = await verifySession(r.token);
  ok('login bearer verifies', session.uid === uid);

  // Wrong password.
  await expectThrow('handleLogin rejects wrong password', async () => {
    await handleLogin({ email, password: 'wrong-password' });
  }, 'bad_credentials');

  // Unknown email — same code, masks account existence.
  await expectThrow('handleLogin rejects unknown email', async () => {
    await handleLogin({ email: 'nobody@unknown.in', password });
  }, 'bad_credentials');

  // Suspended account.
  await fakeFs.setDoc('tm_users', uid, {
    ...(await fakeFs.getDoc('tm_users', uid)), status: 'suspended'
  });
  await expectThrow('handleLogin rejects suspended', async () => {
    await handleLogin({ email, password });
  }, 'account_suspended');
  // Reactivate for downstream tests.
  await fakeFs.setDoc('tm_users', uid, {
    ...(await fakeFs.getDoc('tm_users', uid)), status: 'active'
  });
}

// 5. canonical bytes parity: client bundle === server canonical.
{
  ok('CRITICAL_ACTIONS list non-empty', CRITICAL_ACTIONS.length === 10);
  ok('isCriticalAction recognises dispatch.assign', isCriticalAction('dispatch.assign'));
  ok('isCriticalAction rejects unknown', !isCriticalAction('not.an.action'));

  const ts = 1714900000;
  const cases = [
    { uid: 'u-1', action: 'user.invite', target: 'invite|new@x.in|40|p|ndma/HP', ts, key_id: 'k1' },
    { uid: 'u-2', action: 'user.delegate', target: 'delegate|u-x|60', ts, key_id: 'k1' },
    { uid: 'u-3', action: 'project.archive', target: 'project.archive|p1', ts, key_id: 'k1' },
    { uid: 'u-4', action: 'task.assign', target: 'task.assign|t1|u-9', ts, key_id: 'k1' },
    { uid: 'u-5', action: 'dispatch.escalate', target: 'dispatch.escalate|d1', ts, key_id: 'k1' },
    { uid: 'u-6', action: 'dispatch.assign', target: 'dispatch.assign|d1|unit-7', ts, key_id: 'k1' },
    { uid: 'u-7', action: 'dispatch.review', target: 'dispatch.review|d1', ts, key_id: 'k1' },
    { uid: 'u-8', action: 'unit.update', target: 'unit.update|unit-3', ts, key_id: 'k1' },
    { uid: 'u-9', action: 'unit.archive', target: 'unit.archive|unit-3', ts, key_id: 'k1' },
    { uid: 'u-10', action: 'assignment.update', target: 'assignment.update|a-1|en_route', ts, key_id: 'k1' },
    // unicode + reserved chars in target
    { uid: 'u-uni', action: 'user.invite', target: 'invite|अग्नि@x.in|40|p|ndma/HP', ts, key_id: 'kU' }
  ];
  let parity = true;
  for (const c of cases) {
    const a = canonicalActionMessage(c);
    const b = clientCanonical(c);
    if (a !== b) { parity = false; break; }
  }
  ok('canonical bytes parity (server === client) for all critical actions', parity);

  // Format spec: deterministic key order, no whitespace, JSON-escaped values.
  const fixed = canonicalActionMessage({ uid: 'u', action: 'a', target: 't', ts: 1, key_id: 'k' });
  ok('canonical fixed key order', fixed === '{"action":"a","key_id":"k","target":"t","ts":1,"uid":"u"}');

  await expectThrow('canonical rejects bad ts', () => canonicalActionMessage({ uid: 'u', action: 'a', target: 't', ts: 1.5, key_id: 'k' }), 'canonical_bad_ts');
  await expectThrow('canonical rejects empty action', () => canonicalActionMessage({ uid: 'u', action: '', target: 't', ts: 1, key_id: 'k' }), 'canonical_bad_action');
}

// 6. End-to-end HMAC roundtrip.
{
  _clearSessionCacheForTest();
  _clearReplayStoreForTest();

  const uid = 'u-' + randomUUID();
  await fakeFs.setDoc('tm_users', uid, {
    email: 'asha2@hp.gov.in', name: 'Asha Negi', tier: 40, parent_uid: null,
    scope_path: 'ndma/HP/Shimla', status: 'active',
    password_salt_b64u: 'AAAAAAAAAAAAAAAAAAAAAA',
    password_hash_b64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    created_at: new Date().toISOString(), last_login: null
  });
  setAuthUsers({
    async getMe(actor) {
      const u = await fakeFs.getDoc('tm_users', actor.uid);
      if (!u) throw Object.assign(new Error('not_found'), { code: 'user_not_found', status: 404 });
      return { uid: actor.uid, ...u };
    }
  });

  const action_key_bytes = randomBytes32();
  const action_key_b64 = b64Enc(action_key_bytes);
  const key_id = 'kE2E';
  const tok = signSession({ uid, tier: 40, scope_path: 'ndma/HP/Shimla', action_key_b64, key_id });
  const actor = await verifySession(tok);

  const ts = Math.floor(Date.now() / 1000);
  const action = 'dispatch.escalate';
  const target = 'dispatch.escalate|disp-42';
  const canonical = canonicalActionMessage({ uid, action, target, ts, key_id });
  const sig = hmacB64u(action_key_bytes, canonical);
  const headers = {
    [ 'x-action-sig' ]: sig,
    [ 'x-action-ts' ]: String(ts),
    [ 'x-action-key-id' ]: key_id
  };
  const verified = await requireFreshHmacSig(actor, action, target, headers);
  ok('requireFreshHmacSig accepts valid HMAC', verified.uid === uid && verified.action === action);
  ok('requireFreshHmacSig returns rotated next key', typeof verified.next_action_key_b64 === 'string' && b64Dec(verified.next_action_key_b64).length === 32);
  ok('requireFreshHmacSig returns rotated next key id', typeof verified.next_action_key_id === 'string' && verified.next_action_key_id !== key_id);

  // Replay: same (uid, action, target, ts) rejected.
  await expectThrow('replay rejected on second use', async () => {
    await requireFreshHmacSig(actor, action, target, headers);
  }, 'action_replay');

  // Tampered target → sig mismatch (tested before further rotations
  // evict the previous key from the grace window).
  const ts_t = Math.floor(Date.now() / 1000);
  const sig_for_clean_target = hmacB64u(action_key_bytes, canonicalActionMessage({ uid, action, target, ts: ts_t, key_id }));
  await expectThrow('tampered target rejected', async () => {
    await requireFreshHmacSig(actor, action, 'dispatch.escalate|tampered', {
      'x-action-sig': sig_for_clean_target,
      'x-action-ts': String(ts_t),
      'x-action-key-id': key_id
    });
  }, 'action_sig_bad');

  // Also using the verified-but-now-rotated old key should be permitted
  // within the grace window (covers in-flight client races).
  const ts2 = ts + 1;
  const canonical2 = canonicalActionMessage({ uid, action, target: target + 'X', ts: ts2, key_id });
  const sig2 = hmacB64u(action_key_bytes, canonical2);
  const verified2 = await requireFreshHmacSig(actor, action, target + 'X', {
    'x-action-sig': sig2,
    'x-action-ts': String(ts2),
    'x-action-key-id': key_id
  });
  ok('previous key honoured within grace window', verified2.key_id === key_id);

  // Unknown action rejected.
  await expectThrow('unknown action rejected', async () => {
    await requireFreshHmacSig(actor, 'not.real.action', 'x', headers);
  }, 'bad_action');

  // Skew: ts more than ±60 s out of range.
  const stale_ts = ts - (ACTION_TS_SKEW_SECS + 5);
  const canonicalStale = canonicalActionMessage({ uid, action, target: 'dispatch.escalate|d-skew', ts: stale_ts, key_id });
  const sigStale = hmacB64u(action_key_bytes, canonicalStale);
  await expectThrow('stale ts rejected', async () => {
    await requireFreshHmacSig(actor, action, 'dispatch.escalate|d-skew', {
      'x-action-sig': sigStale,
      'x-action-ts': String(stale_ts),
      'x-action-key-id': key_id
    });
  }, 'stale_action');

  // Missing headers.
  await expectThrow('missing X-Action-Sig rejected', async () => {
    await requireFreshHmacSig(actor, action, target, { 'x-action-ts': String(ts), 'x-action-key-id': key_id });
  }, 'no_action_sig');

  // Wrong key_id rejected.
  await expectThrow('unknown key_id rejected', async () => {
    await requireFreshHmacSig(actor, action, target, { ...headers, 'x-action-key-id': 'kBOGUS' });
  }, 'action_key_unknown');
}

// 7. Client bundle HMAC matches server hmac (parity at the byte level).
{
  const action_key_bytes = randomBytes32();
  const args = { uid: 'parity-uid', action: 'dispatch.assign', target: 'dispatch.assign|d|u', ts: 1714900042, key_id: 'kP' };
  const canonical = canonicalActionMessage(args);
  const serverSig = hmacB64u(action_key_bytes, canonical);
  const clientSig = await clientHmacActionSig(action_key_bytes, args);
  ok('client HMAC === server HMAC', serverSig === clientSig);
}

// 8. Middleware façade unchanged surface.
{
  await expectThrow('extractBearer rejects oversize', async () => {
    extractBearer({ authorization: 'Bearer ' + 'a'.repeat(20000) });
  }, 'AUTH_TOO_LARGE');
  ok('extractBearer accepts short token', extractBearer({ authorization: 'Bearer abc' }) === 'abc');

  _clearSessionCacheForTest();
  const action_key_b64 = b64Enc(randomBytes32());
  const tok = signSession({ uid: 'u-mw', tier: 100, scope_path: 'ndma', action_key_b64, key_id: 'kmw' });
  const headers = { authorization: 'Bearer ' + tok };
  const payload = await requireSession({}, headers);
  ok('requireSession returns payload', payload.uid === 'u-mw');
  await expectThrow('requireSession no header', async () => requireSession({}, {}), 'NO_AUTH');
  await expectThrow('requireSession bad scheme', async () => requireSession({}, { authorization: 'Basic abc' }), 'AUTH_BAD_SCHEME');
  await expectThrow('requireSession empty bearer', async () => requireSession({}, { authorization: 'Bearer ' }), 'AUTH_EMPTY');
}

// 9. ACTION_KEY_GRACE_SECS is the documented value (informational).
{
  ok('ACTION_KEY_GRACE_SECS is 30', ACTION_KEY_GRACE_SECS === 30);
  ok('SESSION_TTL_SECS is 1800', SESSION_TTL_SECS === 1800);
  ok('handleRegister is exported', typeof handleRegister === 'function');
  ok('handleBootstrap is exported', typeof handleBootstrap === 'function');
}

if (failed === 0) {
  process.stdout.write('OK\n');
  process.exit(0);
} else {
  process.stdout.write(`FAIL: ${failed} assertion(s) failed\n`);
  process.exit(1);
}
