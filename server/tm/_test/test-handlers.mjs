// Project Aether · Task Manager · auth handlers self-test.
//
// Mocks firestore + users and exercises the router-facing handler
// surface in auth.js: handleChallenge -> handleVerify, plus
// authenticate, requireFreshHmacSig (header-based), handleBootstrap,
// handleRegister (with invite_id and invite_token alias),
// getServerPubkeyB64.
//
// Run: `node server/tm/_test/test-handlers.mjs` -> prints OK.

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { randomUUID, webcrypto } from 'node:crypto';

if (!globalThis.crypto) globalThis.crypto = webcrypto;

import {
  authenticate,
  getServerPubkeyB64,
  handleRegister,
  handleBootstrap,
  handleChallenge,
  handleVerify,
  requireFreshHmacSig,
  requireFreshUserSig,
  canonicalActionTarget,
  signSession,
  challengeMessageBytes,
  utf8,
  b64Enc,
  b64Dec,
  hmacB64u,
  _setFirestoreForTest as setAuthFirestore,
  _setUsersForTest as setAuthUsers,
  _clearReplayStoreForTest,
  _clearSessionCacheForTest,
  _getSessionEntryForTest
} from '../auth.js';
import { canonicalActionMessage } from '../canonical.js';

let failed = 0;
function ok(name, cond, detail) {
  if (cond) {
    process.stdout.write(`  PASS  ${name}\n`);
  } else {
    failed++;
    process.stdout.write(`  FAIL  ${name}${detail ? ' :: ' + detail : ''}\n`);
  }
}
async function expectThrowAsync(name, fn, codeWanted) {
  try {
    await fn();
    ok(name, false, 'no throw');
  } catch (e) {
    ok(name, !codeWanted || e?.code === codeWanted, `code=${e?.code} status=${e?.status} msg=${e?.message}`);
  }
}

class FakeFs {
  constructor() { this.collections = new Map(); }
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
  async deleteDoc(collection, id) { this._col(collection).delete(id); }
  async fetchAndDelete(collection, id) {
    const col = this._col(collection);
    if (!col.has(id)) return null;
    const v = col.get(id);
    col.delete(id);
    return JSON.parse(JSON.stringify(v));
  }
}

function makeFakeUsers(fakeFs) {
  return {
    async lookupByEmail(email) {
      const norm = String(email || '').trim().toLowerCase();
      const idx = await fakeFs.getDoc('tm_user_emails', norm);
      if (!idx || !idx.uid) return null;
      const u = await fakeFs.getDoc('tm_users', idx.uid);
      if (!u) return null;
      return { uid: idx.uid, ...u, tier_name: tierName(u.tier) };
    },
    async getMe(actor) {
      const u = await fakeFs.getDoc('tm_users', actor.uid);
      if (!u) {
        const e = new Error('user not found'); e.code = 'user_not_found'; e.status = 404; throw e;
      }
      return { uid: actor.uid, ...u, tier_name: tierName(u.tier) };
    },
    async touchLastLogin(uid) {
      const u = await fakeFs.getDoc('tm_users', uid);
      if (!u) return;
      u.last_login = new Date().toISOString();
      await fakeFs.setDoc('tm_users', uid, u);
    },
    async acceptInvite(body) {
      const inv = await fakeFs.getDoc('tm_invitations', body.invite_id);
      if (!inv) { const e = new Error('invite_not_found'); e.code = 'invite_not_found'; e.status = 404; throw e; }
      const uid = randomUUID();
      const now = new Date().toISOString();
      await fakeFs.setDoc('tm_users', uid, {
        email: inv.email,
        name: body.name,
        tier: inv.tier,
        parent_uid: inv.parent_uid,
        scope_path: inv.scope_path,
        pubkey_b64: body.pubkey_b64,
        status: 'active',
        created_at: now,
        last_login: null
      });
      await fakeFs.setDoc('tm_user_emails', inv.email, { uid, created_at: now });
      inv.used = true;
      inv.used_at = now;
      inv.used_uid = uid;
      await fakeFs.setDoc('tm_invitations', body.invite_id, inv);
      return { uid, email: inv.email, name: body.name, tier: inv.tier, tier_name: tierName(inv.tier), scope_path: inv.scope_path, parent_uid: inv.parent_uid };
    },
    async bootstrap(email, name, pubkey_b64) {
      const uid = randomUUID();
      const now = new Date().toISOString();
      const norm = String(email).trim().toLowerCase();
      await fakeFs.setDoc('tm_users', uid, {
        email: norm, name, tier: 100, parent_uid: null, scope_path: 'ndma',
        pubkey_b64, status: 'active', created_at: now, last_login: null, bootstrapped: true
      });
      await fakeFs.setDoc('tm_user_emails', norm, { uid, created_at: now });
      return {
        uid, email: norm, name, tier: 100, tier_name: 'ndma',
        parent_uid: null, scope_path: 'ndma', pubkey_b64, status: 'active',
        created_at: now, last_login: null
      };
    }
  };
}

function tierName(t) {
  return ({ 100: 'ndma', 80: 'state', 60: 'district', 40: 'responder', 20: 'volunteer' })[t] || 'unknown';
}

const fakeFs = new FakeFs();
const fakeUsers = makeFakeUsers(fakeFs);
setAuthFirestore(fakeFs);
setAuthUsers(fakeUsers);

// 1. getServerPubkeyB64.
{
  const pub = await getServerPubkeyB64();
  ok('getServerPubkeyB64 returns base64 string', typeof pub === 'string' && pub.length > 100);
  ok('getServerPubkeyB64 decodes to 1952 bytes', b64Dec(pub).length === 1952);
}

// 2. Bootstrap → challenge → verify roundtrip.
{
  await expectThrowAsync(
    'handleBootstrap blocked when env not set',
    () => handleBootstrap({ email: 'a@b.in', name: 'Asha', pubkey_b64: 'x'.repeat(2604) }, {}),
    'bootstrap_disabled'
  );

  process.env.TM_BOOTSTRAP_ALLOW = '1';
  const userKey = ml_dsa65.keygen();
  const email = 'commander@ndma.in';
  const created = await handleBootstrap({
    email, name: 'NDMA Commander', pubkey_b64: b64Enc(userKey.publicKey)
  }, {});
  ok('handleBootstrap returned uid', typeof created.uid === 'string');
  ok('handleBootstrap returned tier 100', created.tier === 100);
  ok('handleBootstrap returned scope ndma', created.scope_path === 'ndma');
  delete process.env.TM_BOOTSTRAP_ALLOW;

  const ch = await handleChallenge({ email }, {});
  ok('handleChallenge ch_id', typeof ch.ch_id === 'string' && ch.ch_id.length > 0);
  ok('handleChallenge challenge_b64 length', b64Dec(ch.challenge_b64).length === 32);

  const msg = challengeMessageBytes(email, ch.challenge_b64);
  const sig = ml_dsa65.sign(msg, userKey.secretKey);

  const session = await handleVerify({
    email, ch_id: ch.ch_id, signature_b64: b64Enc(sig)
  }, {});
  ok('handleVerify returned compact token (2 parts)', typeof session.token === 'string' && session.token.split('.').length === 2);
  ok('handleVerify token under 200 chars', session.token.length < 200);
  ok('handleVerify exp ISO', !Number.isNaN(Date.parse(session.exp)));
  ok('handleVerify server_pubkey_b64 set', typeof session.server_pubkey_b64 === 'string' && session.server_pubkey_b64.length > 100);
  ok('handleVerify returned action_key_b64', typeof session.action_key_b64 === 'string' && b64Dec(session.action_key_b64).length === 32);
  ok('handleVerify returned key_id', typeof session.key_id === 'string' && session.key_id.length > 0);
  ok('handleVerify user.uid matches', session.user.uid === created.uid);

  const stored = await fakeFs.getDoc('tm_users', created.uid);
  ok('handleVerify bumped last_login', typeof stored.last_login === 'string' && stored.last_login.length > 0);

  await expectThrowAsync(
    'handleVerify replay rejected',
    () => handleVerify({ email, ch_id: ch.ch_id, signature_b64: b64Enc(sig) }, {}),
    'challenge_invalid'
  );

  const ch2 = await handleChallenge({ email }, {});
  const sig2 = ml_dsa65.sign(challengeMessageBytes(email, ch2.challenge_b64), userKey.secretKey);
  await expectThrowAsync(
    'handleVerify rejects mismatched email',
    () => handleVerify({ email: 'someone-else@x.in', ch_id: ch2.ch_id, signature_b64: b64Enc(sig2) }, {}),
    'challenge_invalid'
  );

  const ch3 = await handleChallenge({ email }, {});
  const wrongKey = ml_dsa65.keygen();
  const wrongSig = ml_dsa65.sign(challengeMessageBytes(email, ch3.challenge_b64), wrongKey.secretKey);
  await expectThrowAsync(
    'handleVerify rejects wrong signer',
    () => handleVerify({ email, ch_id: ch3.ch_id, signature_b64: b64Enc(wrongSig) }, {}),
    'challenge_invalid'
  );

  const ch4 = await handleChallenge({ email: 'ghost@nowhere.in' }, {});
  ok('handleChallenge always issues for unknown email', typeof ch4.ch_id === 'string');
  await expectThrowAsync(
    'handleVerify unknown email rejected',
    () => handleVerify({ email: 'ghost@nowhere.in', ch_id: ch4.ch_id, signature_b64: b64Enc(sig2) }, {}),
    'challenge_invalid'
  );

  globalThis.__seedAdminUid = created.uid;
  globalThis.__seedAdminKey = userKey;
  globalThis.__seedAdminSession = session;
}

// 3. authenticate(req).
{
  _clearSessionCacheForTest();
  // signSession primes the cache for the token we issued earlier.
  // Because the test cleared the cache we need a fresh login here so
  // the session is in the in-memory map.
  const seedUid = globalThis.__seedAdminUid;
  const seedKey = globalThis.__seedAdminKey;
  const ch = await handleChallenge({ email: 'commander@ndma.in' }, {});
  const sig = ml_dsa65.sign(challengeMessageBytes('commander@ndma.in', ch.challenge_b64), seedKey.secretKey);
  const session = await handleVerify({
    email: 'commander@ndma.in', ch_id: ch.ch_id, signature_b64: b64Enc(sig)
  }, {});
  globalThis.__seedAdminSession = session;

  const payload = await authenticate({ headers: { authorization: 'Bearer ' + session.token } });
  ok('authenticate returned uid', payload.uid === seedUid);
  ok('authenticate returned tier', payload.tier === 100);
  ok('authenticate returned scope', payload.scope_path === 'ndma');
  ok('authenticate exposes token_id', typeof payload.token_id === 'string' && payload.token_id.length > 0);
  ok('authenticate exposes key_id', payload.key_id === session.key_id);

  await expectThrowAsync('authenticate rejects missing header',
    () => authenticate({ headers: {} }), 'no_auth');
  await expectThrowAsync('authenticate rejects bad scheme',
    () => authenticate({ headers: { authorization: 'Basic abc' } }), 'auth_bad_scheme');
  await expectThrowAsync('authenticate rejects empty bearer',
    () => authenticate({ headers: { authorization: 'Bearer ' } }), 'auth_empty');
}

// 4. requireFreshHmacSig (header-based, HMAC-SHA256 over canonical).
{
  _clearReplayStoreForTest();
  const adminUid = globalThis.__seedAdminUid;
  const session = globalThis.__seedAdminSession;
  const actor = await authenticate({ headers: { authorization: 'Bearer ' + session.token } });
  const action_key_bytes = b64Dec(session.action_key_b64);

  const action = 'user.delegate';
  const target = `delegate|${randomUUID()}|40`;
  const ts = Math.floor(Date.now() / 1000);
  const canonical = canonicalActionMessage({ uid: adminUid, action, target, ts, key_id: session.key_id });
  const sig = hmacB64u(action_key_bytes, canonical);
  const headers = {
    'x-action-sig': sig,
    'x-action-ts': String(ts),
    'x-action-key-id': session.key_id
  };
  const verified = await requireFreshHmacSig(actor, action, target, headers);
  ok('requireFreshHmacSig accepts good sig', verified.uid === adminUid && verified.action === action);
  ok('next_action_key returned', typeof verified.next_action_key_b64 === 'string');
  ok('requireFreshUserSig is alias for requireFreshHmacSig', requireFreshUserSig === requireFreshHmacSig);

  // Tampered target with a sig over the CLEAN target (so HMAC fails).
  const ts2 = Math.floor(Date.now() / 1000);
  const cleanCanonical = canonicalActionMessage({ uid: adminUid, action, target: 'delegate|other|40', ts: ts2, key_id: session.key_id });
  const cleanSig = hmacB64u(action_key_bytes, cleanCanonical);
  await expectThrowAsync(
    'requireFreshHmacSig rejects tampered target',
    () => requireFreshHmacSig(actor, action, 'delegate|tampered|40', {
      'x-action-sig': cleanSig,
      'x-action-ts': String(ts2),
      'x-action-key-id': session.key_id
    }),
    'action_sig_bad'
  );

  await expectThrowAsync(
    'requireFreshHmacSig rejects missing sig',
    () => requireFreshHmacSig(actor, action, target, { 'x-action-ts': String(ts), 'x-action-key-id': session.key_id }),
    'no_action_sig'
  );

  // Suspended user. Re-authenticate to pick up the rotated active key.
  const stored = await fakeFs.getDoc('tm_users', adminUid);
  await fakeFs.setDoc('tm_users', adminUid, { ...stored, status: 'suspended' });
  const actor3 = await authenticate({ headers: { authorization: 'Bearer ' + session.token } });
  const cur = _getSessionEntryForTest(actor3.token_id);
  const curKey = b64Dec(cur.action_key_b64);
  const ts3 = Math.floor(Date.now() / 1000);
  const canon3 = canonicalActionMessage({ uid: adminUid, action, target, ts: ts3, key_id: cur.key_id });
  const sig3 = hmacB64u(curKey, canon3);
  await expectThrowAsync(
    'requireFreshHmacSig rejects suspended user',
    () => requireFreshHmacSig(actor3, action, target, {
      'x-action-sig': sig3,
      'x-action-ts': String(ts3),
      'x-action-key-id': cur.key_id
    }),
    'user_suspended'
  );
  await fakeFs.setDoc('tm_users', adminUid, { ...stored, status: 'active' });
}

// 5. handleRegister: invite minted off-band, accepts invite_id and the
//    legacy invite_token alias.
{
  const adminUid = globalThis.__seedAdminUid;
  const adminKey = globalThis.__seedAdminKey;

  const inviteId = randomUUID();
  const inviteEmail = 'rookie@hp.gov.in';
  const inviteTier = 40;
  const inviteParent = adminUid;
  const inviteScope = 'ndma/HP/Shimla';
  const inviteTarget = `invite|${inviteEmail}|${inviteTier}|${inviteParent}|${inviteScope}`;
  const inviteCanonical = canonicalActionTarget(adminUid, 'user.invite', inviteTarget);
  const inviteSig = b64Enc(ml_dsa65.sign(utf8(inviteCanonical), adminKey.secretKey));
  const expiresAt = new Date(Date.now() + 86_400_000).toISOString();
  await fakeFs.setDoc('tm_invitations', inviteId, {
    email: inviteEmail, tier: inviteTier, parent_uid: inviteParent, scope_path: inviteScope,
    issued_by_uid: adminUid, issued_signature_b64: inviteSig,
    expires_at: expiresAt, used: false, created_at: new Date().toISOString()
  });

  const newUserKey = ml_dsa65.keygen();
  const created = await handleRegister({
    invite_id: inviteId, name: 'Rookie Responder', pubkey_b64: b64Enc(newUserKey.publicKey)
  }, {});
  ok('handleRegister returned uid', typeof created.uid === 'string');
  ok('handleRegister returned matching email', created.email === inviteEmail);
  ok('handleRegister returned matching tier', created.tier === inviteTier);

  // Legacy `invite_token` alias works (this is what the web client posts).
  const inviteId4 = randomUUID();
  const inviteEmail4 = 'rookie4@hp.gov.in';
  const inviteTarget4 = `invite|${inviteEmail4}|40|${adminUid}|ndma/HP/Shimla`;
  const inviteSig4 = b64Enc(ml_dsa65.sign(utf8(canonicalActionTarget(adminUid, 'user.invite', inviteTarget4)), adminKey.secretKey));
  await fakeFs.setDoc('tm_invitations', inviteId4, {
    email: inviteEmail4, tier: 40, parent_uid: adminUid, scope_path: 'ndma/HP/Shimla',
    issued_by_uid: adminUid, issued_signature_b64: inviteSig4,
    expires_at: expiresAt, used: false, created_at: new Date().toISOString()
  });
  const newUserKey4 = ml_dsa65.keygen();
  const created4 = await handleRegister({
    invite_token: inviteId4, name: 'Rookie Four', pubkey_b64: b64Enc(newUserKey4.publicKey)
  }, {});
  ok('handleRegister accepts invite_token alias', typeof created4.uid === 'string' && created4.email === inviteEmail4);

  // Tampered invite (mutate stored signature).
  const inviteId2 = randomUUID();
  await fakeFs.setDoc('tm_invitations', inviteId2, {
    email: 'tamper@x.in', tier: 40, parent_uid: adminUid, scope_path: 'ndma/HP',
    issued_by_uid: adminUid, issued_signature_b64: inviteSig,
    expires_at: expiresAt, used: false, created_at: new Date().toISOString()
  });
  await expectThrowAsync(
    'handleRegister rejects tampered invite',
    () => handleRegister({ invite_id: inviteId2, name: 'X', pubkey_b64: b64Enc(newUserKey.publicKey) }, {}),
    'invite_sig_bad'
  );

  const inviteId3 = randomUUID();
  const goodTarget3 = `invite|t@x.in|40|${adminUid}|ndma/HP`;
  const goodSig3 = b64Enc(ml_dsa65.sign(utf8(canonicalActionTarget(adminUid, 'user.invite', goodTarget3)), adminKey.secretKey));
  await fakeFs.setDoc('tm_invitations', inviteId3, {
    email: 't@x.in', tier: 40, parent_uid: adminUid, scope_path: 'ndma/HP',
    issued_by_uid: adminUid, issued_signature_b64: goodSig3,
    expires_at: new Date(Date.now() - 1000).toISOString(),
    used: false, created_at: new Date().toISOString()
  });
  await expectThrowAsync(
    'handleRegister rejects expired invite',
    () => handleRegister({ invite_id: inviteId3, name: 'T', pubkey_b64: b64Enc(newUserKey.publicKey) }, {}),
    'invite_expired'
  );

  await expectThrowAsync(
    'handleRegister rejects unknown invite',
    () => handleRegister({ invite_id: 'no-such-id', name: 'T', pubkey_b64: b64Enc(newUserKey.publicKey) }, {}),
    'invite_not_found'
  );
}

// 6. handleChallenge / handleVerify input guards.
{
  await expectThrowAsync('handleChallenge rejects empty email',
    () => handleChallenge({ email: '' }, {}), 'bad_email');
  await expectThrowAsync('handleChallenge rejects missing body',
    () => handleChallenge(null, {}), 'bad_request');
  await expectThrowAsync('handleVerify rejects empty body',
    () => handleVerify({}, {}), 'bad_request');
}

// ---------------------------------------------------------------------------
// 7. Tier expansion: all 10 tiers exist, names match the GoI chain, legacy
//    aliases still resolve to the right code.
// ---------------------------------------------------------------------------
{
  const usersMod = await import('../users.js');
  const { TIER, tierName, isValidTier } = usersMod;

  const expectedNames = {
    100: 'ndma', 90: 'national_ops', 80: 'sdma', 70: 'state_ops',
    60: 'ddma', 50: 'district_ops', 40: 'subdivisional', 30: 'tehsil',
    20: 'volunteer', 10: 'survivor'
  };
  for (const [code, name] of Object.entries(expectedNames)) {
    ok(`tierName(${code}) is ${name}`, tierName(Number(code)) === name);
    ok(`isValidTier(${code}) true`, isValidTier(Number(code)));
  }
  ok('TIER.ndma is 100', TIER.ndma === 100);
  ok('TIER.national_ops is 90', TIER.national_ops === 90);
  ok('TIER.sdma is 80', TIER.sdma === 80);
  ok('TIER.state_ops is 70', TIER.state_ops === 70);
  ok('TIER.ddma is 60', TIER.ddma === 60);
  ok('TIER.district_ops is 50', TIER.district_ops === 50);
  ok('TIER.subdivisional is 40', TIER.subdivisional === 40);
  ok('TIER.tehsil is 30', TIER.tehsil === 30);
  ok('TIER.volunteer is 20', TIER.volunteer === 20);
  ok('TIER.survivor is 10', TIER.survivor === 10);

  // Legacy aliases still compile and map to the right code so existing
  // import sites do not break.
  ok('TIER.state alias = 80', TIER.state === 80);
  ok('TIER.district alias = 60', TIER.district === 60);
  ok('TIER.responder alias = 40', TIER.responder === 40);

  ok('isValidTier rejects 0', !isValidTier(0));
  ok('isValidTier rejects 25', !isValidTier(25));
  ok('isValidTier rejects "60"', !isValidTier('60'));
  ok('tierName(99) is unknown', tierName(99) === 'unknown');
}

// ---------------------------------------------------------------------------
// 8. SCOPE_RE: 12-segment depth, survivor root, cross-root prefix attacks.
// ---------------------------------------------------------------------------
{
  const { isValidScope, isInScope } = await import('../users.js');

  // 12 segments under ndma is now legal.
  const segs = ['HP', 'Shimla', 'Mashobra', 'Tehsil1', 'Village1',
    'Sub1', 'Block', 'Sector', 'Lane', 'House', 'Floor', 'Unit'];
  const path12 = 'ndma/' + segs.join('/');
  ok('SCOPE_RE accepts 12-segment scope', isValidScope(path12));
  ok('SCOPE_RE rejects 13-segment scope', !isValidScope(path12 + '/extra'));

  ok('SCOPE_RE accepts survivor/<fp>', isValidScope('survivor/fp1234567890'));
  ok('SCOPE_RE accepts survivor root', isValidScope('survivor'));
  ok('SCOPE_RE accepts demo root', isValidScope('demo'));
  ok('SCOPE_RE accepts ndma root', isValidScope('ndma'));

  // Cross-root prefix attacks: any root must have a slash boundary.
  ok('SCOPE_RE rejects ndmaplus', !isValidScope('ndmaplus'));
  ok('SCOPE_RE rejects ndma2', !isValidScope('ndma2'));
  ok('SCOPE_RE rejects survivors', !isValidScope('survivors'));
  ok('SCOPE_RE rejects demoabc/x', !isValidScope('demoabc/x'));
  ok('SCOPE_RE rejects empty', !isValidScope(''));
  ok('SCOPE_RE rejects double slash', !isValidScope('ndma//HP'));
  ok('SCOPE_RE rejects trailing slash', !isValidScope('ndma/HP/'));

  // Survivor and ndma roots are disjoint at the prefix level: a survivor
  // record is never reachable from any ndma actor's subtree, and vice versa.
  ok('isInScope(ndma/mh, survivor/x) is false', isInScope('ndma/mh', 'survivor/x') === false);
  ok('isInScope(survivor, ndma) is false', isInScope('survivor', 'ndma') === false);
  ok('isInScope(ndma, survivor) is false', isInScope('ndma', 'survivor') === false);
  ok('isInScope(survivor, survivor/abc) is true', isInScope('survivor', 'survivor/abc') === true);
}

// ---------------------------------------------------------------------------
// 9. Presence bump rate-limited to once per minute per uid.
// ---------------------------------------------------------------------------
{
  const { _shouldBumpPresence, _resetPresenceCacheForTest } = await import('../users.js');
  _resetPresenceCacheForTest();

  const t0 = 1_700_000_000_000;
  ok('first bump for uid-A returns true', _shouldBumpPresence('uid-A', t0) === true);
  ok('second bump 30s later returns false', _shouldBumpPresence('uid-A', t0 + 30_000) === false);
  ok('bump 59s later still returns false', _shouldBumpPresence('uid-A', t0 + 59_000) === false);
  ok('bump 61s later returns true', _shouldBumpPresence('uid-A', t0 + 61_000) === true);

  // Different uids tracked independently.
  ok('first bump for uid-B at 30s returns true', _shouldBumpPresence('uid-B', t0 + 30_000) === true);
  ok('second bump for uid-B at 31s returns false', _shouldBumpPresence('uid-B', t0 + 31_000) === false);

  // Bad input never bumps.
  ok('empty uid never bumps', _shouldBumpPresence('', t0) === false);
  ok('null uid never bumps', _shouldBumpPresence(null, t0) === false);

  _resetPresenceCacheForTest();
  ok('after reset, uid-A bumps again', _shouldBumpPresence('uid-A', t0 + 61_000) === true);
}

// ---------------------------------------------------------------------------
// 10. Bulk roster import. Mixed valid/invalid rows, idempotency on
//     (name, scope_path), tier gate.
// ---------------------------------------------------------------------------
{
  const units = await import('../units.js');
  const { TIER } = await import('../users.js');

  // Minimal in-memory Firestore. Supports queryDocs (range on
  // scope_path) + runTransaction (create with explicit id).
  class MockFs {
    constructor() { this.col = new Map(); }
    _c(name) { if (!this.col.has(name)) this.col.set(name, new Map()); return this.col.get(name); }
    async queryDocs(collection, filters, opts) {
      const c = this._c(collection);
      let lower = null, upper = null;
      for (const f of filters || []) {
        if (f.field === 'scope_path' && f.op === '>=') lower = f.value;
        if (f.field === 'scope_path' && f.op === '<=') upper = f.value;
      }
      const out = [];
      for (const [id, data] of c.entries()) {
        const sp = data.scope_path;
        if (lower !== null && (typeof sp !== 'string' || sp < lower)) continue;
        if (upper !== null && (typeof sp !== 'string' || sp > upper)) continue;
        out.push({ id, data: JSON.parse(JSON.stringify(data)) });
      }
      const lim = opts?.limit || 500;
      return out.slice(0, lim);
    }
    async runTransaction(fn) {
      const writes = [];
      const handle = {
        get: async (collection, id) => {
          const v = this._c(collection).get(id);
          return v ? JSON.parse(JSON.stringify(v)) : null;
        },
        create: (collection, data, explicitId) => {
          const id = explicitId || ('rand-' + Math.random().toString(16).slice(2));
          writes.push({ kind: 'create', collection, id, data: JSON.parse(JSON.stringify(data)) });
          return id;
        },
        set: () => { throw new Error('mock: set not implemented'); },
        update: () => { throw new Error('mock: update not implemented'); },
        delete: () => { throw new Error('mock: delete not implemented'); }
      };
      const result = await fn(handle);
      // Apply writes only on success.
      for (const w of writes) {
        if (w.kind === 'create') {
          const c = this._c(w.collection);
          if (c.has(w.id)) {
            const e = new Error('already exists'); e.code = 'FS_ALREADY_EXISTS'; throw e;
          }
          c.set(w.id, w.data);
        }
      }
      return result;
    }
  }
  const mockFs = new MockFs();
  const auditCalls = [];
  const mockAudit = {
    record: async (...args) => { auditCalls.push(args); return 'aid-' + auditCalls.length; }
  };
  units._setFirestoreForTest(mockFs);
  units._setAuditForTest(mockAudit);

  const ddma = { uid: 'admin-ddma', tier: TIER.ddma, scope_path: 'ndma/HP/Shimla' };

  // Tier gate.
  const tooLow = { uid: 'low', tier: TIER.tehsil, scope_path: 'ndma/HP/Shimla' };
  await expectThrowAsync(
    'bulkCreate rejects tier below ddma',
    () => units.bulkCreate(tooLow, { rows: [{ type: 'ambulance', name: 'X', contact_phone: '+91 111 222 3333', scope_path: 'ndma/HP/Shimla' }] }),
    'tier_too_low'
  );

  // Bad payload guards.
  await expectThrowAsync('bulkCreate rejects missing rows',
    () => units.bulkCreate(ddma, {}), 'bad_request');
  await expectThrowAsync('bulkCreate rejects empty rows',
    () => units.bulkCreate(ddma, { rows: [] }), 'bad_request');
  await expectThrowAsync('bulkCreate rejects > 1000 rows',
    () => units.bulkCreate(ddma, { rows: new Array(1001).fill({}) }), 'payload_too_large');

  // 100 rows, mixed valid + invalid.
  const rows = [];
  for (let i = 0; i < 90; i++) {
    rows.push({
      type: 'ambulance',
      name: `BULK-AMB-${String(i).padStart(3, '0')}`,
      contact_phone: '+91 11 5555 ' + String(1000 + i),
      scope_path: 'ndma/HP/Shimla',
      capacity: 4,
      lat: 31.10 + i * 0.001,
      lng: 77.17 + i * 0.001
    });
  }
  // Invalid: bad type.
  rows.push({ type: 'rocket', name: 'Bad-1', contact_phone: '+91 1', scope_path: 'ndma/HP/Shimla' });
  // Invalid: bad name (empty).
  rows.push({ type: 'ambulance', name: '', contact_phone: '+91 1 2 3 4', scope_path: 'ndma/HP/Shimla' });
  // Invalid: out-of-scope (UK is sibling of HP).
  rows.push({ type: 'ambulance', name: 'OUT-001', contact_phone: '+91 11 5555 9999', scope_path: 'ndma/UK/Dehradun' });
  // Invalid: bad capacity.
  rows.push({ type: 'ambulance', name: 'CAP-001', contact_phone: '+91 11 5555 9998', scope_path: 'ndma/HP/Shimla', capacity: 9999 });
  // Invalid: bad scope (wrong root).
  rows.push({ type: 'ambulance', name: 'ROOT-001', contact_phone: '+91 11 5555 9997', scope_path: 'foo/bar' });
  // Valid: deeper nested scope under actor.
  rows.push({ type: 'drone', name: 'DRN-NESTED', contact_phone: '+91 11 5555 9996', scope_path: 'ndma/HP/Shimla/responder1', capacity: 2 });
  // Duplicate-in-batch: same (name, scope_path) as row 0.
  rows.push({ type: 'ambulance', name: 'BULK-AMB-000', contact_phone: '+91 11 5555 0000', scope_path: 'ndma/HP/Shimla' });
  // Total: 90 + 5 invalid + 1 valid + 1 dup = 97 rows.

  const r1 = await units.bulkCreate(ddma, { rows });
  ok('bulkCreate response.rows length matches input', r1.rows.length === rows.length);
  ok('bulkCreate summary.created = 91', r1.summary.created === 91);
  ok('bulkCreate summary.invalid = 5', r1.summary.invalid === 5);
  ok('bulkCreate summary.duplicate_in_batch = 1', r1.summary.duplicate_in_batch === 1);
  ok('bulkCreate summary.total = 97', r1.summary.total === 97);

  // Spot-check per-row statuses.
  ok('row 0 created with unit_id', r1.rows[0].status === 'created' && typeof r1.rows[0].unit_id === 'string');
  ok('row 90 (bad type) invalid', r1.rows[90].status === 'invalid' && r1.rows[90].error === 'bad_type');
  ok('row 91 (empty name) invalid', r1.rows[91].status === 'invalid' && r1.rows[91].error === 'bad_name');
  ok('row 92 (out of scope) invalid', r1.rows[92].status === 'invalid' && r1.rows[92].error === 'out_of_scope');
  ok('row 93 (bad capacity) invalid', r1.rows[93].status === 'invalid' && r1.rows[93].error === 'bad_capacity');
  ok('row 94 (bad scope) invalid', r1.rows[94].status === 'invalid' && r1.rows[94].error === 'bad_scope');
  ok('row 95 (nested scope) created', r1.rows[95].status === 'created');
  ok('row 96 (dup in batch) flagged', r1.rows[96].status === 'duplicate_in_batch' && r1.rows[96].unit_id === r1.rows[0].unit_id);

  // Audit summary row was written.
  ok('bulk audit summary recorded', auditCalls.some((c) => c[1] === 'unit.bulk_summary'));

  // Idempotency: re-run the same valid 90-row block; all should report exists.
  const replay = rows.slice(0, 90);
  const r2 = await units.bulkCreate(ddma, { rows: replay });
  ok('replay summary.created = 0', r2.summary.created === 0);
  ok('replay summary.exists = 90', r2.summary.exists === 90);
  ok('replay row 0 status exists', r2.rows[0].status === 'exists');
  ok('replay row 0 unit_id matches first run', r2.rows[0].unit_id === r1.rows[0].unit_id);

  // Verify the in-memory store actually got 91 unit docs from the first
  // call plus 0 new docs on replay (sanity check on the test mock).
  const stored = mockFs._c('tm_units');
  ok('mock fs holds 91 unit docs', stored.size === 91);

  // Restore real modules so any later tests don't see the mock.
  units._setFirestoreForTest(null);
  units._setAuditForTest(null);
}

if (failed === 0) {
  process.stdout.write('OK\n');
  process.exit(0);
} else {
  process.stdout.write(`FAIL: ${failed} assertion(s) failed\n`);
  process.exit(1);
}
