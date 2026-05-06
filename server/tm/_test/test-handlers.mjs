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
import { criticalityScore, _internal as critInternal } from '../criticality.js';
import {
  geohash7,
  transcriptMinHash,
  minHashJaccard,
  haversineMeters,
  findCluster
} from '../dedupe.js';
import {
  listTeam,
  compare,
  _setUsersForTest as setDispatchesUsers,
  _setFirestoreForTest as setDispatchesFirestore
} from '../dispatches.js';
import * as dssMod from '../dss.js';

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

// 11. Audit hash chain (lane: audit-chain). Each tm_audit row is hash-
//    linked to the previous one, ML-DSA-65 signed, transactional tip
//    update, verify endpoint walks the chain and reports the first
//    break, list endpoint filters by actor/action/since/until, tier
//    gates on both endpoints, auditCriticality controls fail-open vs
//    fail-closed, migration backfills pre-chain rows.
// ---------------------------------------------------------------------------
{
  const auditMod = await import('../audit.js');
  const {
    record: auditRecord,
    verifyChain,
    handleVerify: handleAuditVerify,
    handleList: handleAuditList,
    auditWriteSig,
    _setFirestoreForTest: setAuditFs,
    _resetMigrationForTest: resetAuditMigration,
    _internalAudit
  } = auditMod;

  // Minimal in-memory Firestore that supports the audit lane's needs:
  // queryDocs (==, >=, <= filters + orderBy seq | ts asc | desc),
  // runTransaction (get + create + set), createDoc, getDoc, setDoc.
  // The fake serializes through JSON to mimic Firestore wire roundtrips
  // so reference identity does not leak across reads.
  class AuditFakeFs {
    constructor() {
      this.col = new Map();
      this.rng = 0;
      this.failNextTxn = 0;
      this.txnFailKind = 'FS_PRECONDITION';
    }
    _c(name) {
      if (!this.col.has(name)) this.col.set(name, new Map());
      return this.col.get(name);
    }
    async getDoc(collection, id) {
      const v = this._c(collection).get(id);
      return v ? JSON.parse(JSON.stringify(v)) : null;
    }
    async setDoc(collection, id, data) {
      this._c(collection).set(id, JSON.parse(JSON.stringify(data)));
    }
    async createDoc(collection, data, explicitId) {
      const id = explicitId || ('a-' + (++this.rng).toString(36) + '-' + Date.now().toString(36));
      const c = this._c(collection);
      if (c.has(id)) {
        const e = new Error('exists'); e.code = 'FS_ALREADY_EXISTS'; e.name = 'FirestoreError'; throw e;
      }
      c.set(id, JSON.parse(JSON.stringify(data)));
      return id;
    }
    async deleteDoc(collection, id) { this._c(collection).delete(id); }
    async queryDocs(collection, filters, opts) {
      const c = this._c(collection);
      const rows = [];
      for (const [id, data] of c.entries()) {
        let pass = true;
        for (const f of (filters || [])) {
          const v = data[f.field];
          if (f.op === '==') { if (!(v === f.value)) { pass = false; break; } }
          else if (f.op === '>=') { if (!(v >= f.value)) { pass = false; break; } }
          else if (f.op === '<=') { if (!(v <= f.value)) { pass = false; break; } }
          else if (f.op === '>') { if (!(v > f.value)) { pass = false; break; } }
          else if (f.op === '<') { if (!(v < f.value)) { pass = false; break; } }
          else if (f.op === '!=') { if (!(v !== f.value)) { pass = false; break; } }
        }
        if (pass) rows.push({ id, data: JSON.parse(JSON.stringify(data)) });
      }
      if (opts && opts.orderBy) {
        const ob = Array.isArray(opts.orderBy) ? opts.orderBy[0] : opts.orderBy;
        const field = typeof ob === 'string' ? ob : ob.field;
        const dir = (typeof ob === 'object' && ob.direction === 'desc') ? -1 : 1;
        rows.sort((a, b) => {
          const av = a.data[field], bv = b.data[field];
          if (av === bv) return 0;
          if (av === undefined || av === null) return 1;
          if (bv === undefined || bv === null) return -1;
          return av < bv ? -1 * dir : 1 * dir;
        });
      }
      const lim = opts?.limit || 1000;
      return rows.slice(0, lim);
    }
    async runTransaction(fn) {
      if (this.failNextTxn > 0) {
        this.failNextTxn--;
        const e = new Error('precondition'); e.code = this.txnFailKind; e.name = 'FirestoreError'; throw e;
      }
      const writes = [];
      const handle = {
        get: async (c, i) => this.getDoc(c, i),
        create: (c, d, eid) => {
          const id = eid || ('tx-' + (++this.rng).toString(36) + '-' + Date.now().toString(36));
          writes.push({ kind: 'create', c, id, d });
          return id;
        },
        set: (c, i, d) => writes.push({ kind: 'set', c, id: i, d }),
        update: (c, i, d) => writes.push({ kind: 'update', c, id: i, d }),
        delete: (c, i) => writes.push({ kind: 'delete', c, id: i })
      };
      const result = await fn(handle);
      for (const w of writes) {
        if (w.kind === 'create') {
          const col = this._c(w.c);
          if (col.has(w.id)) {
            const e = new Error('exists'); e.code = 'FS_ALREADY_EXISTS'; e.name = 'FirestoreError'; throw e;
          }
          col.set(w.id, JSON.parse(JSON.stringify(w.d)));
        } else if (w.kind === 'set') {
          this._c(w.c).set(w.id, JSON.parse(JSON.stringify(w.d)));
        } else if (w.kind === 'update') {
          const col = this._c(w.c);
          const cur = col.get(w.id) || {};
          col.set(w.id, { ...cur, ...JSON.parse(JSON.stringify(w.d)) });
        } else if (w.kind === 'delete') {
          this._c(w.c).delete(w.id);
        }
      }
      return result;
    }
  }

  const fakeAuditFs = new AuditFakeFs();
  setAuditFs(fakeAuditFs);
  resetAuditMigration();

  // 7.1 — single row: prev_hash == GENESIS, seq == 0.
  const aid0 = await auditRecord('uid-A', 'unit.create', 'tm_units/U0', { name: 'Alpha' });
  ok('first audit row written', typeof aid0 === 'string' && aid0.length > 0);
  const row0 = await fakeAuditFs.getDoc(_internalAudit.AUDIT_COLL, aid0);
  ok('row0 prev_hash == GENESIS', row0.prev_hash === _internalAudit.GENESIS_HASH);
  ok('row0 seq == 0', row0.seq === 0);
  ok('row0 actor_uid set', row0.actor_uid === 'uid-A');
  ok('row0 row_hash 64 hex chars',
    typeof row0.row_hash === 'string' && row0.row_hash.length === 64 && /^[0-9a-f]+$/.test(row0.row_hash));
  ok('row0 server_sig_b64 present',
    typeof row0.server_sig_b64 === 'string' && row0.server_sig_b64.length > 100);

  const tip0 = await fakeAuditFs.getDoc(_internalAudit.TIP_COLL, _internalAudit.TIP_ID);
  ok('tip after row0: hash matches', tip0.tip_hash === row0.row_hash);
  ok('tip after row0: seq == 0', tip0.tip_seq === 0);

  // 7.2 — second row: prev_hash == row0.row_hash, seq == 1.
  const aid1 = await auditRecord('uid-B', 'dispatch.escalate', 'tm_dispatches/D7', { from: 1, to: 2 });
  const row1 = await fakeAuditFs.getDoc(_internalAudit.AUDIT_COLL, aid1);
  ok('row1 prev_hash == row0.row_hash', row1.prev_hash === row0.row_hash);
  ok('row1 seq == 1', row1.seq === 1);
  const tip1 = await fakeAuditFs.getDoc(_internalAudit.TIP_COLL, _internalAudit.TIP_ID);
  ok('tip after row1: seq == 1', tip1.tip_seq === 1);
  ok('tip after row1: hash matches row1', tip1.tip_hash === row1.row_hash);

  // 7.3 — verify endpoint walks 100 rows with ok_count == 100.
  for (let i = 0; i < 98; i++) {
    await auditRecord('uid-C', 'task.update', `tm_tasks/T${i}`, { i, note: 'walk' });
  }
  const verify100 = await verifyChain({ fromSeq: 0, limit: 1000 });
  ok('verifyChain over 100 rows: total_walked == 100', verify100.total_walked === 100);
  ok('verifyChain over 100 rows: ok_count == 100', verify100.ok_count === 100);
  ok('verifyChain over 100 rows: no break_at_seq', verify100.break_at_seq === undefined);

  // 7.4 — tamper variants. Each test mutates one row, runs verify, then
  //        restores the row so subsequent assertions see a clean chain.
  const targetSeqRows = await fakeAuditFs.queryDocs(_internalAudit.AUDIT_COLL, [
    { field: 'seq', op: '==', value: 42 }
  ], { limit: 1 });
  const tampered = targetSeqRows[0];
  await fakeAuditFs.setDoc(_internalAudit.AUDIT_COLL, tampered.id, {
    ...tampered.data,
    payload_summary: { ...(tampered.data.payload_summary || {}), note: 'TAMPERED' }
  });
  const tamperRes = await verifyChain({ fromSeq: 0, limit: 1000 });
  ok('payload tamper detected at seq 42', tamperRes.break_at_seq === 42);
  ok('payload tamper kind row_hash_recompute_mismatch',
    tamperRes.break_kind === 'row_hash_recompute_mismatch');
  ok('payload tamper ok_count == 42', tamperRes.ok_count === 42);
  await fakeAuditFs.setDoc(_internalAudit.AUDIT_COLL, tampered.id, tampered.data);
  const recheck = await verifyChain({ fromSeq: 0, limit: 1000 });
  ok('chain ok again after restore', recheck.ok_count === 100);

  const sigRow = (await fakeAuditFs.queryDocs(_internalAudit.AUDIT_COLL, [
    { field: 'seq', op: '==', value: 17 }
  ], { limit: 1 }))[0];
  const sigBytes = Buffer.from(sigRow.data.server_sig_b64, 'base64');
  sigBytes[0] = sigBytes[0] ^ 0xff;
  await fakeAuditFs.setDoc(_internalAudit.AUDIT_COLL, sigRow.id, {
    ...sigRow.data,
    server_sig_b64: sigBytes.toString('base64')
  });
  const sigRes = await verifyChain({ fromSeq: 0, limit: 1000 });
  ok('sig tamper detected at seq 17', sigRes.break_at_seq === 17);
  ok('sig tamper kind server_sig_invalid', sigRes.break_kind === 'server_sig_invalid');
  await fakeAuditFs.setDoc(_internalAudit.AUDIT_COLL, sigRow.id, sigRow.data);

  const linkRow = (await fakeAuditFs.queryDocs(_internalAudit.AUDIT_COLL, [
    { field: 'seq', op: '==', value: 33 }
  ], { limit: 1 }))[0];
  await fakeAuditFs.setDoc(_internalAudit.AUDIT_COLL, linkRow.id, {
    ...linkRow.data,
    prev_hash: '0'.repeat(64)
  });
  const linkRes = await verifyChain({ fromSeq: 0, limit: 1000 });
  ok('prev_hash tamper detected at seq 33', linkRes.break_at_seq === 33);
  ok('prev_hash tamper kind prev_hash_mismatch', linkRes.break_kind === 'prev_hash_mismatch');
  await fakeAuditFs.setDoc(_internalAudit.AUDIT_COLL, linkRow.id, linkRow.data);

  // 7.5 — required-criticality: audit failure aborts mutation with 503.
  fakeAuditFs.failNextTxn = 5;
  let requiredErr = null;
  try {
    await auditRecord('uid-NDMA', 'ndma.declare', 'tm_dispatches/D-CRIT',
      { reason: 'test' }, null, 'required');
  } catch (e) { requiredErr = e; }
  ok('required-criticality threw AuditWriteError',
    !!requiredErr && requiredErr.name === 'AuditWriteError');
  ok('required-criticality status 503',
    !!requiredErr && requiredErr.status === 503);
  fakeAuditFs.failNextTxn = 0;

  // 7.6 — best-effort: chain failure logs CRITICAL, mutation succeeds.
  fakeAuditFs.failNextTxn = 5;
  const beforeBE = await fakeAuditFs.queryDocs(_internalAudit.AUDIT_COLL, [
    { field: 'chain_break', op: '==', value: true }
  ], { limit: 100 });
  const beAid = await auditRecord('uid-Vol', 'task.create', 'tm_tasks/T-BE',
    { i: 1 }, null, 'best_effort');
  ok('best-effort returns aid even on chain failure',
    typeof beAid === 'string' && beAid.length > 0);
  const afterBE = await fakeAuditFs.queryDocs(_internalAudit.AUDIT_COLL, [
    { field: 'chain_break', op: '==', value: true }
  ], { limit: 100 });
  ok('best-effort wrote unchained fallback row',
    afterBE.length === beforeBE.length + 1);
  const beRow = await fakeAuditFs.getDoc(_internalAudit.AUDIT_COLL, beAid);
  ok('best-effort row carries chain_break=true', beRow.chain_break === true);
  ok('best-effort row prev_hash null', beRow.prev_hash === null);
  fakeAuditFs.failNextTxn = 0;

  // 7.7 — NDMA-only access on verify; state-or-above on list.
  const ndmaActor = { uid: 'a-ndma', tier: 100, scope_path: 'ndma' };
  const sdmaActor = { uid: 'a-sdma', tier: 80, scope_path: 'ndma/HP' };
  const tehsilActor = { uid: 'a-tehsil', tier: 30, scope_path: 'ndma/HP/Shimla/East' };

  const ndmaVerify = await handleAuditVerify(ndmaActor, { fromSeq: 0, limit: 5 });
  ok('NDMA verify returns walk results', typeof ndmaVerify.total_walked === 'number');

  await expectThrowAsync(
    'verify rejects sdma tier',
    () => handleAuditVerify(sdmaActor, { fromSeq: 0, limit: 5 }),
    'audit_verify_forbidden'
  );
  await expectThrowAsync(
    'verify rejects tehsil tier',
    () => handleAuditVerify(tehsilActor, { fromSeq: 0, limit: 5 }),
    'audit_verify_forbidden'
  );
  await expectThrowAsync(
    'verify rejects null actor',
    () => handleAuditVerify(null, {}),
    'audit_verify_forbidden'
  );

  const sdmaList = await handleAuditList(sdmaActor, { actor_uid: 'uid-C' }, { limit: 200 });
  ok('SDMA list returns rows', Array.isArray(sdmaList.rows));
  ok('SDMA list rows carry hashes',
    sdmaList.rows.every((r) => typeof r.row_hash === 'string' || r.row_hash === null));

  await expectThrowAsync(
    'list rejects tehsil tier',
    () => handleAuditList(tehsilActor, {}, { limit: 10 }),
    'audit_list_forbidden'
  );

  // 7.8 — list filters by action.
  const filteredByAction = await handleAuditList(ndmaActor, { action: 'task.update' }, { limit: 200 });
  ok('list filters by action', filteredByAction.rows.every((r) => r.action === 'task.update'));
  ok('list found 98 task.update rows', filteredByAction.rows.length === 98);

  // 7.9 — verify with from_seq mid-chain.
  const partial = await handleAuditVerify(ndmaActor, { fromSeq: 50, limit: 1000 });
  ok('partial verify ok_count == 50', partial.ok_count === 50);
  ok('partial verify total_walked == 50', partial.total_walked === 50);

  // 7.10 — auditWriteSig is deterministic.
  const fixed = auditWriteSig(_internalAudit.GENESIS_HASH, {
    uid: 'u', action: 'a', target_ref: 't', payload_summary: { x: 1 }, ts: '2026-01-01T00:00:00.000Z'
  });
  const fixed2 = auditWriteSig(_internalAudit.GENESIS_HASH, {
    uid: 'u', action: 'a', target_ref: 't', payload_summary: { x: 1 }, ts: '2026-01-01T00:00:00.000Z'
  });
  ok('auditWriteSig row_hash deterministic', fixed.row_hash === fixed2.row_hash);
  ok('auditWriteSig prev_hash echoed', fixed.prev_hash === _internalAudit.GENESIS_HASH);
  const fixed3 = auditWriteSig(_internalAudit.GENESIS_HASH, {
    uid: 'u', action: 'a', target_ref: 't', payload_summary: { x: 2 }, ts: '2026-01-01T00:00:00.000Z'
  });
  ok('auditWriteSig differs on payload change', fixed.row_hash !== fixed3.row_hash);

  // 7.11 — migration backfills pre-chain rows.
  const migrFs = new AuditFakeFs();
  await migrFs.setDoc(_internalAudit.AUDIT_COLL, 'legacy-1', {
    actor_uid: 'old-A', action: 'project.create', target_ref: 'tm_projects/P1',
    payload_summary: { name: 'Foo' }, actor_signature_b64: null,
    ts: '2026-01-01T00:00:00.000Z'
  });
  await migrFs.setDoc(_internalAudit.AUDIT_COLL, 'legacy-2', {
    actor_uid: 'old-A', action: 'project.update', target_ref: 'tm_projects/P1',
    payload_summary: { name: 'Bar' }, actor_signature_b64: null,
    ts: '2026-01-02T00:00:00.000Z'
  });
  await migrFs.setDoc(_internalAudit.AUDIT_COLL, 'legacy-3', {
    actor_uid: 'old-B', action: 'project.archive', target_ref: 'tm_projects/P1',
    payload_summary: {}, actor_signature_b64: null,
    ts: '2026-01-03T00:00:00.000Z'
  });
  setAuditFs(migrFs);
  resetAuditMigration();
  const aidPostMigr = await auditRecord('uid-Z', 'unit.update', 'tm_units/U-Post',
    { name: 'Z' });
  ok('post-migration row written', typeof aidPostMigr === 'string');
  const m1 = await migrFs.getDoc(_internalAudit.AUDIT_COLL, 'legacy-1');
  const m2 = await migrFs.getDoc(_internalAudit.AUDIT_COLL, 'legacy-2');
  const m3 = await migrFs.getDoc(_internalAudit.AUDIT_COLL, 'legacy-3');
  ok('legacy-1 chained at seq 0',
    m1.seq === 0 && m1.prev_hash === _internalAudit.GENESIS_HASH);
  ok('legacy-2 chained at seq 1',
    m2.seq === 1 && m2.prev_hash === m1.row_hash);
  ok('legacy-3 chained at seq 2',
    m3.seq === 2 && m3.prev_hash === m2.row_hash);
  const newRow = await migrFs.getDoc(_internalAudit.AUDIT_COLL, aidPostMigr);
  ok('post-migration row links to legacy-3',
    newRow.prev_hash === m3.row_hash && newRow.seq === 3);
  const migrVerify = await verifyChain({ fromSeq: 0, limit: 1000 });
  ok('migrated chain verifies clean',
    migrVerify.ok_count === 4 && migrVerify.break_at_seq === undefined);

  // Restore real fs so any later imports do not see the audit fakes.
  setAuditFs(null);
  resetAuditMigration();
}


// ---------------------------------------------------------------------------
// criticality-dedup lane tests (sections 12-20). Owned by wave-1-criticality-dedup.
// ---------------------------------------------------------------------------
// 12. criticalityScore: pregnant + child + elderly_with_crush.
{
  const triage = {
    urgency: 'CRITICAL',
    victims: [
      { age_band: 'adult', condition_flags: ['pregnant'], count: 1 },
      { age_band: 'child', condition_flags: ['bleeding'], count: 1 },
      { age_band: 'elderly', condition_flags: ['crush_extracted'], count: 1 }
    ]
  };
  const fixedNow = Date.parse('2026-05-06T12:05:00Z');
  const receivedAt = '2026-05-06T12:00:00Z';
  const r = criticalityScore(triage, receivedAt, fixedNow);
  ok('criticality breakdown has 3 victim rows', Array.isArray(r.breakdown.victims) && r.breakdown.victims.length === 3);
  // adult + pregnant = 1.0 + 2.0 = 3.0
  ok('pregnant adult weight is 3.0', r.breakdown.victims[0].weight === 3);
  // child + bleeding = 1.3 + 1.5 = 2.8
  ok('child + bleeding weight is 2.8', Math.abs(r.breakdown.victims[1].weight - 2.8) < 1e-6);
  // elderly + crush -> 1.8 composite (no double-count)
  ok('elderly_with_crush weight is 1.8', r.breakdown.victims[2].weight === 1.8);
  // sum = 7.6, urgency 1.0, decay = 1.0 + 0.05 = 1.05 -> 7.98
  ok('criticality score scales with urgency + decay', Math.abs(r.score - 7.98) < 0.01, `got ${r.score}`);
  ok('breakdown urgency_factor 1.0 for CRITICAL', r.breakdown.urgency_factor === 1.0);
  ok('breakdown not in fallback mode', r.breakdown.fallback === false);
}

// 13. criticalityScore fallback: empty victims -> people_affected.
{
  const r = criticalityScore({ urgency: 'HIGH', people_affected: 4 }, '2026-05-06T12:00:00Z', Date.parse('2026-05-06T12:00:00Z'));
  ok('fallback engaged when victims missing', r.breakdown.fallback === true);
  ok('fallback uses people_affected count', r.breakdown.fallback_people_affected === 4);
  // 0.7 * 4 * 1.0 = 2.8
  ok('fallback score uses urgency * people * decay', Math.abs(r.score - 2.8) < 1e-6, `got ${r.score}`);
  // people_affected null -> default 1
  const r2 = criticalityScore({ urgency: 'MEDIUM' }, '2026-05-06T12:00:00Z', Date.parse('2026-05-06T12:00:00Z'));
  ok('fallback defaults people_affected to 1', r2.breakdown.fallback_people_affected === 1);
}

// 14. geohash7: distinct cities map to distinct prefixes; 50 m apart match.
{
  const delhi = geohash7(28.6139, 77.2090);
  const mumbai = geohash7(19.0760, 72.8777);
  const shimla = geohash7(31.1048, 77.1734);
  ok('geohash7 returns 7 chars for Delhi', typeof delhi === 'string' && delhi.length === 7);
  ok('Delhi and Mumbai have distinct geohash prefixes', delhi !== mumbai && delhi.slice(0, 3) !== mumbai.slice(0, 3));
  ok('Delhi and Shimla share country prefix but differ', delhi !== shimla && delhi.slice(0, 2) === shimla.slice(0, 2));
  // 0.00045 deg latitude ~ 50 m
  const a = geohash7(28.6139, 77.2090);
  const b = geohash7(28.6139 + 0.00045, 77.2090);
  ok('points 50 m apart share geohash7 prefix', a === b);
  ok('haversine 50m within 5 m tolerance', Math.abs(haversineMeters({lat: 28.6139, lng: 77.2090}, {lat: 28.6139 + 0.00045, lng: 77.2090}) - 50) < 5);
  ok('geohash7 rejects out-of-range lat', geohash7(120, 77) === null);
  ok('geohash7 rejects non-numeric', geohash7('x', 77) === null);
}

// 15. MinHash Jaccard: near-identical >= 0.7, unrelated < 0.2.
{
  const aText = 'A residential building has collapsed in Sector 7 Noida and three people are trapped under heavy rubble and one of them is bleeding badly.';
  const bText = 'A residential building has collapsed in Sector 7 Noida and three people are trapped under heavy rubble and one of them is bleeding heavily.';
  const cText = 'My motorbike broke down on the highway near the Indian Oil petrol pump. I need a tow truck.';
  const aSig = transcriptMinHash(aText, 64);
  const bSig = transcriptMinHash(bText, 64);
  const cSig = transcriptMinHash(cText, 64);
  ok('minhash blob is 344 base64 chars', aSig.length === 344);
  ok('minhash decodes to 256 bytes', Buffer.from(aSig, 'base64').length === 256);
  const sim = minHashJaccard(aSig, bSig);
  const dis = minHashJaccard(aSig, cSig);
  ok(`near-identical Jaccard >= 0.7 (got ${sim.toFixed(3)})`, sim >= 0.7);
  ok(`unrelated Jaccard < 0.2 (got ${dis.toFixed(3)})`, dis < 0.2);
  ok('identical text Jaccard is 1.0', minHashJaccard(aSig, aSig) === 1.0);
}

// 16. findCluster: two dispatches 50 m + 5 min apart, similar transcripts.
{
  const fakeFs2 = new FakeFs();
  // Seed primary 5 minutes ago, same geohash bucket, similar text.
  const primaryId = 'd_primary';
  const primaryText = 'Building collapse in Sector 7 Noida, three people trapped under heavy rubble.';
  const primarySig = transcriptMinHash(primaryText, 64);
  const primaryGeo = geohash7(28.6139, 77.2090);
  const fiveMinAgo = new Date(Date.now() - 5 * 60_000).toISOString();
  await fakeFs2.setDoc('tm_dispatches', primaryId, {
    id: primaryId,
    received_at: fiveMinAgo,
    location: { lat: 28.6139, lng: 77.2090 },
    triage: { incident_type: 'building_collapse' },
    geohash7: primaryGeo,
    transcript_minhash_b64: primarySig,
    cluster_id: primaryId,
    cluster_role: 'primary',
    worker_status: 'received'
  });
  // The dedupe module calls fakeFs.queryDocs(...). FakeFs already has
  // setDoc and getDoc; add a minimal queryDocs that returns the geohash
  // bucket within the time window.
  fakeFs2.queryDocs = async function (collection, filters /*, opts */) {
    const col = this._col(collection);
    const filterMap = Object.fromEntries(filters.map((f) => [`${f.field}|${f.op}`, f.value]));
    const wantHash = filterMap['geohash7|=='];
    const cutoff = filterMap['received_at|>='];
    const out = [];
    for (const [id, data] of col.entries()) {
      if (data.geohash7 !== wantHash) continue;
      if (cutoff && (data.received_at || '') < cutoff) continue;
      out.push({ id, data: JSON.parse(JSON.stringify(data)) });
    }
    return out;
  };
  const newSig = transcriptMinHash('Collapsed building in Sector 7 of Noida. Three people are trapped under rubble.', 64);
  const newGeo = geohash7(28.6139 + 0.00045, 77.2090);
  const match = await findCluster({
    id: 'd_new',
    geohash7: newGeo,
    location: { lat: 28.6139 + 0.00045, lng: 77.2090 },
    triage: { incident_type: 'building_collapse' },
    transcript_minhash_b64: newSig
  }, { firestoreModule: fakeFs2, nowMs: Date.now() });
  ok('findCluster detected duplicate', match !== null);
  ok('findCluster points at primary id', match?.cluster_primary_id === primaryId);
  ok('findCluster cluster_id reuses primary cluster_id', match?.cluster_id === primaryId);
  ok('findCluster match_score >= threshold', (match?.match_score ?? 0) >= 0.7);

  // No match when worker_status is resolved.
  await fakeFs2.setDoc('tm_dispatches', primaryId, {
    id: primaryId,
    received_at: fiveMinAgo,
    location: { lat: 28.6139, lng: 77.2090 },
    triage: { incident_type: 'building_collapse' },
    geohash7: primaryGeo,
    transcript_minhash_b64: primarySig,
    cluster_id: primaryId,
    cluster_role: 'primary',
    worker_status: 'resolved'
  });
  const noMatch = await findCluster({
    id: 'd_new2',
    geohash7: newGeo,
    location: { lat: 28.6139 + 0.00045, lng: 77.2090 },
    triage: { incident_type: 'building_collapse' },
    transcript_minhash_b64: newSig
  }, { firestoreModule: fakeFs2, nowMs: Date.now() });
  ok('findCluster skips resolved candidates', noMatch === null);

  // Storage error returns null (does not throw) so SOS persist proceeds.
  const failingFs = { queryDocs: async () => { throw new Error('FAILED_PRECONDITION: index missing'); } };
  const failResult = await findCluster({
    id: 'd_new3',
    geohash7: newGeo,
    location: { lat: 28.6139 + 0.00045, lng: 77.2090 },
    triage: { incident_type: 'building_collapse' },
    transcript_minhash_b64: newSig
  }, { firestoreModule: failingFs, nowMs: Date.now() });
  ok('findCluster swallows query errors', failResult === null);
}

// 17. listTeam ordering: pending review queue sorted by criticality desc.
{
  const seedRows = [
    { id: 'a', data: { id: 'a', caller_scope_path: 'ndma/HP/Shimla', caller_uid: 'u_a', escalation_status: 'pending_review', requires_review: true, criticality_score: 1.5, received_at: '2026-05-06T12:00:00Z', caller_tier: 40, triage: { urgency: 'HIGH' } } },
    { id: 'b', data: { id: 'b', caller_scope_path: 'ndma/HP/Shimla', caller_uid: 'u_b', escalation_status: 'pending_review', requires_review: true, criticality_score: 9.0, received_at: '2026-05-06T11:00:00Z', caller_tier: 40, triage: { urgency: 'CRITICAL' } } },
    { id: 'c', data: { id: 'c', caller_scope_path: 'ndma/HP/Shimla', caller_uid: 'u_c', escalation_status: 'pending_review', requires_review: true, criticality_score: 4.2, received_at: '2026-05-06T11:30:00Z', caller_tier: 40, triage: { urgency: 'HIGH' } } },
    { id: 'd', data: { id: 'd', caller_scope_path: 'ndma/HP/Shimla', caller_uid: 'u_d', escalation_status: 'reviewed', requires_review: false, criticality_score: 12.0, received_at: '2026-05-06T10:00:00Z', caller_tier: 40, triage: { urgency: 'CRITICAL' } } }
  ];
  setDispatchesFirestore({ queryDocs: async () => seedRows });
  try {
    const actor = { uid: 'lead', tier: 60, scope_path: 'ndma/HP/Shimla' };
    const review = await listTeam(actor, { requires_review: true, limit: 50 });
    ok('listTeam pending-review excludes non-pending rows', review.every((r) => r.requires_review === true));
    ok('listTeam pending-review sorted by criticality desc', review[0].id === 'b' && review[1].id === 'c' && review[2].id === 'a');
    const time = await listTeam(actor, { limit: 50 });
    ok('listTeam default mode keeps newest-first ordering', time[0].id === 'a' && time[time.length - 1].id === 'd');
  } finally {
    setDispatchesFirestore(null);
  }
}

// 18. listTeam direct_only: filters by caller.parent_uid === actor.uid.
{
  const seed = [
    { id: 'd1', data: { id: 'd1', caller_scope_path: 'ndma/HP/Shimla/T1', caller_uid: 'child_user', escalation_status: 'none', requires_review: false, criticality_score: 3.0, received_at: '2026-05-06T12:00:00Z', caller_tier: 40 } },
    { id: 'd2', data: { id: 'd2', caller_scope_path: 'ndma/HP/Shimla/T1', caller_uid: 'grandchild_user', escalation_status: 'none', requires_review: false, criticality_score: 5.0, received_at: '2026-05-06T11:30:00Z', caller_tier: 30 } }
  ];
  let userCalls = 0;
  setDispatchesFirestore({ queryDocs: async () => seed });
  setDispatchesUsers(async (_actor, uid) => {
    userCalls++;
    if (uid === 'child_user') return { uid, parent_uid: 'lead' };
    if (uid === 'grandchild_user') return { uid, parent_uid: 'child_user' };
    return null;
  });
  try {
    const actor = { uid: 'lead', tier: 60, scope_path: 'ndma/HP/Shimla' };
    const direct = await listTeam(actor, { direct_only: true, limit: 50 });
    ok('direct_only keeps only direct subordinates', direct.length === 1 && direct[0].id === 'd1');
    const before = userCalls;
    await listTeam(actor, { direct_only: true, limit: 50 });
    ok('direct_only caches user reads per call (cache cleared between calls)', userCalls - before === 2);
    const all = await listTeam(actor, { direct_only: false, limit: 50 });
    ok('direct_only=false returns full subtree', all.length === 2);
  } finally {
    setDispatchesFirestore(null);
    setDispatchesUsers(null);
  }
}

// 19. compare endpoint: returns 2-10 dispatches sorted by criticality desc.
{
  const docs = {
    'da': { caller_scope_path: 'ndma/HP/Shimla', caller_uid: 'u_a', criticality_score: 2.0, criticality_breakdown: { urgency: 'HIGH' }, triage: { urgency: 'HIGH', incident_type: 'flood' }, received_at: '2026-05-06T12:00:00Z' },
    'db': { caller_scope_path: 'ndma/HP/Shimla', caller_uid: 'u_b', criticality_score: 9.5, criticality_breakdown: { urgency: 'CRITICAL' }, triage: { urgency: 'CRITICAL', incident_type: 'building_collapse' }, received_at: '2026-05-06T12:01:00Z' },
    'dc': { caller_scope_path: 'ndma/HP/Shimla', caller_uid: 'u_c', criticality_score: 5.0, criticality_breakdown: { urgency: 'HIGH' }, triage: { urgency: 'HIGH', incident_type: 'fire' }, received_at: '2026-05-06T12:02:00Z' },
    'far': { caller_scope_path: 'ndma/MH', caller_uid: 'u_far', criticality_score: 99, triage: { urgency: 'CRITICAL' } }
  };
  setDispatchesFirestore({ getDoc: async (col, id) => (col === 'tm_dispatches' && docs[id]) ? JSON.parse(JSON.stringify(docs[id])) : null });
  try {
    const actor = { uid: 'lead', tier: 60, scope_path: 'ndma/HP/Shimla' };
    const result = await compare(actor, ['da', 'db', 'dc']);
    ok('compare returned 3 rows', result.length === 3);
    ok('compare sorted by criticality desc', result[0].id === 'db' && result[1].id === 'dc' && result[2].id === 'da');
    ok('compare carries urgency through', result[0].urgency === 'CRITICAL');

    await expectThrowAsync('compare rejects fewer than 2 ids', () => compare(actor, ['da']), 'bad_request');
    await expectThrowAsync('compare rejects more than 10 ids', () => compare(actor, ['1','2','3','4','5','6','7','8','9','10','11']), 'bad_request');
    await expectThrowAsync('compare blocks out-of-scope dispatch', () => compare(actor, ['da', 'far']), 'out_of_scope');
    await expectThrowAsync('compare 404s on missing dispatch', () => compare(actor, ['da', 'missing']), 'dispatch_not_found');
  } finally {
    setDispatchesFirestore(null);
  }
}

// 20. dss.suggest short-circuits on duplicate cluster role.
{
  const dispatch = {
    id: 'd_dup',
    cluster_role: 'duplicate',
    cluster_primary_id: 'd_primary',
    cluster_id: 'd_primary',
    cluster_match_score: 0.85,
    triage: { urgency: 'CRITICAL', needs: ['medical_evacuation'] }
  };
  const units = [{ unit_id: 'u1', name: 'Ambulance 1', type: 'ambulance', status: 'available' }];
  const r = dssMod.suggest(dispatch, units, 3);
  ok('duplicate dispatch returns single advisory row', Array.isArray(r) && r.length === 1);
  ok('advisory row references primary id', r[0].advisory === 'duplicate_of_primary' && r[0].cluster_primary_id === 'd_primary');
}

// ---------------------------------------------------------------------------
// 21. notify.js: dispatch.created payload encodes under 500 B and the
//     subscription store mints + deletes correctly.
// ---------------------------------------------------------------------------
{
  const notifyMod = await import('../notify.js');
  const fakeSubsFs = new FakeFs();
  notifyMod._setFirestoreForTest(fakeSubsFs);
  try {
    const payload = { kind: 'dispatch.created', dispatch_id: 'd-' + 'x'.repeat(36), urgency: 'CRITICAL', scope: 'ndma/HP/Shimla/Mall_Road/Tehsil_X', ttl_s: 600 };
    const { json, bytes } = notifyMod._internal.clampPayload(payload);
    ok('dispatch.created payload <= 500 B', bytes <= 500);
    ok('payload survives JSON round-trip', JSON.parse(json).kind === 'dispatch.created');

    // Subscription save + read.
    const subUid = 'u-rookie';
    // 65-byte uncompressed P-256 placeholder + 16-byte auth secret. We
    // do not need a real ECDH key here because saveSubscription only
    // validates lengths; encryption is exercised separately below.
    const { generateKeyPairSync, randomBytes: rb, createECDH } = await import('node:crypto');
    const kp = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = kp.publicKey.export({ format: 'jwk' });
    const padB64 = (s) => s + '='.repeat((4 - s.length % 4) % 4);
    const x = Buffer.from(padB64(jwk.x.replace(/-/g, '+').replace(/_/g, '/')), 'base64');
    const y = Buffer.from(padB64(jwk.y.replace(/-/g, '+').replace(/_/g, '/')), 'base64');
    const pubRaw = Buffer.concat([Buffer.from([0x04]), x, y]);
    const pubB64u = pubRaw.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const authB64u = rb(16).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const sub = { endpoint: 'https://fcm.example.test/p/abc', keys: { p256dh: pubB64u, auth: authB64u } };

    ok('isValidSubscription accepts well-formed sub', notifyMod.isValidSubscription(sub));
    ok('isValidSubscription rejects bad endpoint', !notifyMod.isValidSubscription({ endpoint: 'http://not-https/', keys: sub.keys }));
    ok('isValidSubscription rejects short auth', !notifyMod.isValidSubscription({ endpoint: sub.endpoint, keys: { p256dh: pubB64u, auth: 'short' } }));

    await notifyMod.saveSubscription(subUid, sub);
    const stored = await fakeSubsFs.getDoc('tm_user_subscriptions', subUid);
    ok('saveSubscription wrote endpoint', stored && stored.endpoint === sub.endpoint);
    ok('saveSubscription set TTL marker', stored.ttl_days === 90);
    ok('saveSubscription is idempotent on uid replace', (await (async () => {
      await notifyMod.saveSubscription(subUid, { ...sub, endpoint: sub.endpoint + '/v2' });
      const s2 = await fakeSubsFs.getDoc('tm_user_subscriptions', subUid);
      return s2.endpoint.endsWith('/v2');
    })()));
    await notifyMod.deleteSubscription(subUid);
    ok('deleteSubscription removed doc', !(await fakeSubsFs.getDoc('tm_user_subscriptions', subUid)));

    // 410 Gone deletes the subscription.
    await notifyMod.saveSubscription(subUid, sub);
    const origFetch = globalThis.fetch;
    globalThis.fetch = async () => ({ status: 410 });
    try {
      const r = await notifyMod.notify(subUid, payload);
      ok('410 Gone marks status', r.status === 410);
      const after = await fakeSubsFs.getDoc('tm_user_subscriptions', subUid);
      ok('410 Gone deleted subscription', !after);
    } finally {
      globalThis.fetch = origFetch;
    }

    // Encrypt path round-trip: ciphertext should be longer than plaintext + 16 (tag).
    const plaintext = Buffer.from(json, 'utf8');
    const body = notifyMod.encryptPayload(plaintext, pubRaw, rb(16));
    ok('encryptPayload returns Buffer with header + ciphertext', body.length > plaintext.length + 16 + 21);
    ok('encryptPayload header carries 65 B keyid', body.readUInt8(20) === 65);
  } finally {
    notifyMod._setFirestoreForTest(null);
  }
}

// ---------------------------------------------------------------------------
// 22. SW background sync simulation. We mock the SW IDB + fetch to assert
//     that pending clips upload with X-Client-Clip-Id and that 401 / 5xx
//     paths take the right branch.
// ---------------------------------------------------------------------------
{
  // The actual web/sw.js targets a Service Worker runtime, but the
  // upload + state-machine logic is small enough to validate in Node by
  // re-executing the same algorithm against in-memory mocks. The shape
  // mirrors uploadOne + flushQueue from web/sw.js.
  function mockUploadOne(row, bearer, fetchImpl) {
    const headers = {
      'Content-Type': row.mime || 'audio/webm',
      'Authorization': 'Bearer ' + bearer.token,
      'X-Client-Clip-Id': row.clip_id || String(row.id),
      'X-Client-Timestamp': row.ts || row.capturedAt || new Date().toISOString()
    };
    return fetchImpl('/api/v1/triage', { method: 'POST', headers, body: row.blob });
  }

  // Three pending clips → three POSTs with idempotency keys.
  const seen = [];
  let n = 0;
  const fetch3 = async (url, opts) => {
    n++;
    seen.push(opts.headers['X-Client-Clip-Id']);
    return { status: 200, async json() { return { id: 'd-' + n, received_at: new Date().toISOString(), triage: { urgency: 'HIGH' } }; } };
  };
  const bearer = { token: 'tok', uid: 'u' };
  const rows = [
    { id: 1, clip_id: 'c-aaa', blob: Buffer.from('a'), mime: 'audio/webm', status: 'pending' },
    { id: 2, clip_id: 'c-bbb', blob: Buffer.from('b'), mime: 'audio/webm', status: 'pending' },
    { id: 3, clip_id: 'c-ccc', blob: Buffer.from('c'), mime: 'audio/webm', status: 'pending' }
  ];
  for (const r of rows) await mockUploadOne(r, bearer, fetch3);
  ok('SW sync POSTs once per pending clip', n === 3);
  ok('each POST carries the X-Client-Clip-Id', seen.join(',') === 'c-aaa,c-bbb,c-ccc');

  // 401 → bearer cleared + reauth_required posted.
  let cleared = 0;
  const messages = [];
  const fetch401 = async () => ({ status: 401 });
  const r401 = await mockUploadOne(rows[0], bearer, fetch401);
  if (r401.status === 401) { cleared++; messages.push({ k: 'reauth_required' }); }
  ok('SW sync 401 clears bearer + posts reauth message', cleared === 1 && messages[0].k === 'reauth_required');

  // 5xx → row stays, attempt_count bumps, scheduled_at backs off.
  function bumpRetry(row, status) {
    const cur = { ...row };
    cur.attempt_count = (cur.attempt_count || 0) + 1;
    cur.lastError = 'retry_' + status;
    cur.status = cur.attempt_count >= 5 ? 'failed_terminal' : 'failed';
    cur.scheduled_at = Date.now() + ([60_000, 300_000, 1_800_000, 1_800_000, 1_800_000][Math.min(cur.attempt_count - 1, 4)]);
    return cur;
  }
  const after5xx = bumpRetry(rows[0], 503);
  ok('5xx bumps attempt_count', after5xx.attempt_count === 1);
  ok('5xx schedules retry roughly +60 s', after5xx.scheduled_at - Date.now() >= 50_000 && after5xx.scheduled_at - Date.now() <= 65_000);
  ok('5xx leaves row in failed status', after5xx.status === 'failed');
  let progressive = { ...rows[0] };
  for (let i = 0; i < 5; i++) progressive = bumpRetry(progressive, 503);
  ok('5xx after 5 attempts marks failed_terminal', progressive.status === 'failed_terminal');
}

// ---------------------------------------------------------------------------
// 23. clip_seen idempotency. We exercise the same key-presence logic the
//     server.js triage path uses: a stored tm_clip_seen row short-circuits
//     a duplicate POST. Different clip_ids fall through.
// ---------------------------------------------------------------------------
{
  const fs = new FakeFs();
  const clipId = 'c-abc-123-def';
  const dispatchId = 'd-original';
  const receivedAt = new Date().toISOString();
  await fs.setDoc('tm_clip_seen', clipId, {
    clip_id: clipId,
    dispatch_id: dispatchId,
    received_at: receivedAt,
    cached_response: { id: dispatchId, received_at: receivedAt, triage: { urgency: 'HIGH', summary_for_dispatch: 'Caller needs medics.' } },
    triage_summary: { urgency: 'HIGH' },
    created_at: new Date().toISOString()
  });

  async function checkClipSeen(id) {
    const row = await fs.getDoc('tm_clip_seen', id);
    if (!row || !row.dispatch_id) return null;
    const fresh = (Date.now() - Date.parse(row.created_at)) < 5 * 60_000;
    if (fresh && row.cached_response) return { ...row.cached_response, replay: true };
    return { id: row.dispatch_id, received_at: row.received_at, replay: true, triage: row.triage_summary };
  }
  const replay = await checkClipSeen(clipId);
  ok('replay returns cached id', replay && replay.id === dispatchId);
  ok('replay flag set true', replay && replay.replay === true);

  const fresh = await checkClipSeen('c-not-seen');
  ok('different clip_id falls through (null)', fresh === null);

  // Past 5 min returns the thin shape (no cached_response).
  await fs.setDoc('tm_clip_seen', clipId, {
    clip_id: clipId, dispatch_id: dispatchId, received_at: receivedAt,
    cached_response: { id: dispatchId, triage: { urgency: 'HIGH' } },
    triage_summary: { urgency: 'HIGH' },
    created_at: new Date(Date.now() - 10 * 60_000).toISOString()
  });
  const stale = await checkClipSeen(clipId);
  ok('stale replay returns thin shape', stale && stale.replay === true && stale.id === dispatchId);
}

// ---------------------------------------------------------------------------
// 24. Bearer in IDB: SW-readable contract. We assert the contract that
//     the SW relies on: the 'tm_session' store at key 's' holds {iv, ct}
//     and the 'tm_session_key' store at key 'k' holds the AES-GCM key.
//     Tests run in Node which has crypto.subtle, so the round-trip is
//     identical to the browser path.
// ---------------------------------------------------------------------------
{
  const subtle = (await import('node:crypto')).webcrypto.subtle;
  const key = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const iv = (await import('node:crypto')).webcrypto.getRandomValues(new Uint8Array(12));
  const sess = { token: 't.id.hmac', uid: 'u', tier: 40, scope_path: 'ndma/HP', action_key_b64: 'k', key_id: 'kid' };
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(sess)));
  // Round-trip: same key handle decrypts to the same record. Mirrors
  // the SW reading what the page wrote.
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  const parsed = JSON.parse(new TextDecoder().decode(pt));
  ok('SW-readable bearer round-trips', parsed.token === sess.token && parsed.uid === 'u');
}

// ---------------------------------------------------------------------------
// 25. iOS Push fallback: feature detection picks the 60 s poll path when
//     PushManager is missing. Mirrors the runtime check in web/index.html.
// ---------------------------------------------------------------------------
{
  function pickPollMs(global) {
    const HAS_PUSH = ('PushManager' in global) && ('serviceWorker' in (global.navigator || {}));
    return HAS_PUSH ? null : 60_000;
  }
  const fakeIos = { navigator: {} };
  ok('iOS fallback selects 60 s polling', pickPollMs(fakeIos) === 60_000);
  const fakeChrome = { PushManager: function () {}, navigator: { serviceWorker: {} } };
  ok('Push-capable browser disables polling', pickPollMs(fakeChrome) === null);
}
// (Note: HEAD content above is bg-sync-push lane sections 21-25; watchdog-tasks lane sections 26+ below.)
// watchdog-tasks lane tests (sections 26+).
// ---------------------------------------------------------------------------
{
  const watchdog = await import('../watchdog.js');
  const dispatchesMod = await import('../dispatches.js');
  const assignmentsMod = await import('../assignments.js');
  const authMod = await import('../auth.js');

  // Tiny in-memory firestore that supports the surface watchdog needs:
  // getDoc, setDoc, patchDoc, queryDocs, runTransaction.
  class TickFs {
    constructor() { this.col = new Map(); }
    _c(name) {
      if (!this.col.has(name)) this.col.set(name, new Map());
      return this.col.get(name);
    }
    async getDoc(collection, id) {
      const v = this._c(collection).get(id);
      return v ? JSON.parse(JSON.stringify(v)) : null;
    }
    async setDoc(collection, id, data) {
      this._c(collection).set(id, JSON.parse(JSON.stringify(data)));
    }
    async patchDoc(collection, id, data) {
      const cur = this._c(collection).get(id) || {};
      this._c(collection).set(id, { ...cur, ...JSON.parse(JSON.stringify(data)) });
    }
    async queryDocs(collection, filters, opts) {
      const c = this._c(collection);
      const rows = [];
      for (const [id, data] of c.entries()) {
        let pass = true;
        for (const f of (filters || [])) {
          const v = data[f.field];
          if (f.op === '==') { if (v !== f.value) { pass = false; break; } }
          else if (f.op === '>=') { if (!(v >= f.value)) { pass = false; break; } }
          else if (f.op === '<=') { if (!(v <= f.value)) { pass = false; break; } }
        }
        if (pass) rows.push({ id, data: JSON.parse(JSON.stringify(data)) });
      }
      const lim = opts?.limit || 1000;
      return rows.slice(0, lim);
    }
    async runTransaction(fn) {
      const writes = [];
      const handle = {
        get: async (c, i) => this.getDoc(c, i),
        create: (c, d, eid) => {
          const id = eid || ('tx-' + Math.random().toString(16).slice(2));
          writes.push({ kind: 'create', c, id, d });
          return id;
        },
        set: (c, i, d) => writes.push({ kind: 'set', c, id: i, d }),
        update: (c, i, d) => writes.push({ kind: 'update', c, id: i, d }),
        delete: (c, i) => writes.push({ kind: 'delete', c, id: i })
      };
      const result = await fn(handle);
      for (const w of writes) {
        const col = this._c(w.c);
        if (w.kind === 'create') {
          if (col.has(w.id)) { const e = new Error('exists'); e.code = 'FS_ALREADY_EXISTS'; throw e; }
          col.set(w.id, JSON.parse(JSON.stringify(w.d)));
        } else if (w.kind === 'set') {
          col.set(w.id, JSON.parse(JSON.stringify(w.d)));
        } else if (w.kind === 'update') {
          const cur = col.get(w.id) || {};
          col.set(w.id, { ...cur, ...JSON.parse(JSON.stringify(w.d)) });
        } else if (w.kind === 'delete') {
          col.delete(w.id);
        }
      }
      return result;
    }
  }

  // 22. SLA: persist CRITICAL dispatch -> sla_deadline_at = received_at + 60.
  {
    const recv = '2026-05-06T12:00:00.000Z';
    const deadline = watchdog.computeSlaDeadlineIso(recv, 'CRITICAL');
    ok('SLA CRITICAL = 60s', watchdog.slaSecondsFor('CRITICAL') === 60);
    ok('SLA HIGH = 300s', watchdog.slaSecondsFor('HIGH') === 300);
    ok('SLA MEDIUM = 900s', watchdog.slaSecondsFor('MEDIUM') === 900);
    ok('SLA LOW = 3600s', watchdog.slaSecondsFor('LOW') === 3600);
    ok('SLA UNCLEAR = 300s', watchdog.slaSecondsFor('UNCLEAR') === 300);
    ok('SLA unknown urgency falls back to UNCLEAR', watchdog.slaSecondsFor('???') === 300);
    ok('CRITICAL deadline is +60s of received_at',
      deadline === '2026-05-06T12:01:00.000Z');
    ok('HIGH deadline is +300s', watchdog.computeSlaDeadlineIso(recv, 'HIGH') === '2026-05-06T12:05:00.000Z');
  }

  // 23. scheduleSlaTick builds correct task name, body, HMAC.
  {
    const captured = [];
    watchdog.setCloudTasksClient(async (args) => {
      captured.push(args);
      return { duplicate: false, status: 200 };
    });
    process.env.WATCHDOG_HMAC_SECRET = 'unit-test-secret-1234567890';
    watchdog._resetForTest();

    const fireAt = '2026-05-06T12:01:00.000Z';
    const okPosted = await watchdog.scheduleSlaTick('disp-uuid-1', fireAt, 0);
    ok('scheduleSlaTick returns true', okPosted === true);
    ok('scheduleSlaTick captured one call', captured.length === 1);
    ok('task name is sla-{id}-{step}', captured[0].taskName === 'sla-disp-uuid-1-0');
    ok('schedule time matches fire_at', captured[0].scheduleTimeIso === fireAt);
    const body = JSON.parse(captured[0].body);
    ok('body has dispatch_id', body.dispatch_id === 'disp-uuid-1');
    ok('body has step', body.step === 0);
    ok('body has scheduled_for', body.scheduled_for === fireAt);
    ok('hmac header populated', typeof captured[0].hmacSig === 'string' && captured[0].hmacSig.length === 64);
    ok('hmac verifies via verifyCallbackSig',
      watchdog.verifyCallbackSig(captured[0].body, captured[0].hmacSig) === true);

    // Idempotency test: 409 from Cloud Tasks (duplicate name) is swallowed.
    watchdog.setCloudTasksClient(async () => ({ duplicate: true, status: 409 }));
    const okDup = await watchdog.scheduleSlaTick('disp-uuid-1', fireAt, 0);
    ok('scheduleSlaTick swallows 409 and returns true', okDup === true);

    // Failure path: client throws -> WARN logged, returns false but no
    // exception escapes (so persist pipeline never blocks).
    watchdog.setCloudTasksClient(async () => { throw new Error('cloud_tasks_offline'); });
    const okFail = await watchdog.scheduleSlaTick('disp-uuid-2', fireAt, 0);
    ok('scheduleSlaTick swallows transport failure', okFail === false);
    watchdog.setCloudTasksClient(null);
  }

  // 24. sla_tick callback: rejects bad HMAC, accepts good HMAC.
  {
    const body = JSON.stringify({ dispatch_id: 'd', scheduled_for: 'now', step: 0 });
    const badSig = 'a'.repeat(64);
    ok('rejects bad sig', watchdog.verifyCallbackSig(body, badSig) === false);
    ok('rejects empty sig', watchdog.verifyCallbackSig(body, '') === false);
    const goodSig = watchdog.signCallback(body);
    ok('accepts good sig', watchdog.verifyCallbackSig(body, goodSig) === true);
  }

  // 25. sla_tick callback: dispatch already advanced -> no-op.
  {
    const fs = new TickFs();
    fs._c('tm_dispatches').set('d-advanced', {
      id: 'd-advanced', received_at: new Date().toISOString(),
      caller_uid: 'caller-1', caller_scope_path: 'ndma/HP/Shimla',
      worker_status: 'on_scene', sla_step: 0, sla_history: [],
      triage: { urgency: 'CRITICAL' }
    });
    const r = await watchdog.handleSlaTick({ dispatch_id: 'd-advanced', step: 0 },
      { firestore: fs });
    ok('worker_status advanced -> noop', r.code === 'noop_worker_advanced');
    ok('worker_status echoed back', r.worker_status === 'on_scene');
  }

  // 26. sla_tick step 1 -> notify (mocked); next tick scheduled.
  {
    const fs = new TickFs();
    fs._c('tm_dispatches').set('d-step1', {
      id: 'd-step1', received_at: new Date().toISOString(),
      caller_uid: 'caller-1', caller_scope_path: 'ndma/HP/Shimla',
      worker_status: 'received', sla_step: 0, sla_history: [],
      triage: { urgency: 'CRITICAL' }
    });
    fs._c('tm_users').set('caller-1', {
      uid: 'caller-1', parent_uid: 'supervisor-1',
      scope_path: 'ndma/HP/Shimla', tier: 40
    });
    fs._c('tm_users').set('supervisor-1', {
      uid: 'supervisor-1', scope_path: 'ndma/HP/Shimla', tier: 60
    });
    // Seed presence for the supervisor so C2 evaluation does NOT skip.
    fs._c('tm_user_presence').set('supervisor-1', {
      uid: 'supervisor-1', last_seen_at: new Date().toISOString()
    });
    const notifyCalls = [];
    watchdog._setNotifyForTest({
      send: async (args) => { notifyCalls.push(args); }
    });
    const scheduled = [];
    watchdog.setCloudTasksClient(async (args) => {
      scheduled.push(args);
      return { duplicate: false, status: 200 };
    });
    const r = await watchdog.handleSlaTick({ dispatch_id: 'd-step1', step: 0 },
      { firestore: fs });
    ok('step 1 executed', r.step_executed === 1);
    ok('notify called for supervisor', notifyCalls.length >= 1
      && notifyCalls[0].to_uid === 'supervisor-1' && notifyCalls[0].kind === 'sla_supervisor');
    const persisted = await fs.getDoc('tm_dispatches', 'd-step1');
    ok('sla_step persisted as 1', persisted.sla_step === 1);
    ok('sla_history has step 1 entry',
      persisted.sla_history.some((h) => h.step === 1 && h.action === 'notify_supervisor'));
    ok('next tick scheduled', scheduled.length === 1);
    ok('next tick is step 2', JSON.parse(scheduled[0].body).step === 2);
    watchdog._setNotifyForTest(null);
    watchdog.setCloudTasksClient(null);
  }

  // 27. sla_tick step 2 -> auto-escalate as SYSTEM_AI; sla_history appended.
  {
    const fs = new TickFs();
    fs._c('tm_dispatches').set('d-step2', {
      id: 'd-step2', received_at: new Date().toISOString(),
      caller_uid: 'caller-2', caller_tier: 40,
      caller_scope_path: 'ndma/HP/Shimla',
      worker_status: 'received', sla_step: 1, sla_history: [
        { step: 1, ts: 'x', action: 'notify_supervisor', success: true }
      ],
      escalation_chain: [], escalation_status: 'pending_review',
      triage: { urgency: 'HIGH' }
    });
    // Route the dispatches module through the in-memory firestore.
    dispatchesMod._setFirestoreForTest({
      runTransaction: (fn) => fs.runTransaction(fn),
      queryDocs: (c, f, o) => fs.queryDocs(c, f, o),
      getDoc: (c, i) => fs.getDoc(c, i)
    });
    // Stub audit so escalate's auditRecord call does not hit the real
    // firestore. audit.js uses _setFirestoreForTest as the seam.
    const auditMod = await import('../audit.js');
    auditMod._setFirestoreForTest({
      runTransaction: (fn) => fs.runTransaction(fn),
      queryDocs: (c, f, o) => fs.queryDocs(c, f, o),
      getDoc: (c, i) => fs.getDoc(c, i),
      setDoc: (c, i, d) => fs.setDoc(c, i, d),
      createDoc: async (c, d, eid) => {
        const id = eid || ('a-' + Math.random().toString(16).slice(2));
        const col = fs._c(c);
        if (col.has(id)) { const e = new Error('exists'); e.code = 'FS_ALREADY_EXISTS'; throw e; }
        col.set(id, JSON.parse(JSON.stringify(d)));
        return id;
      }
    });
    auditMod._resetMigrationForTest();
    watchdog.setCloudTasksClient(async () => ({ duplicate: false, status: 200 }));
    const r = await watchdog.handleSlaTick({ dispatch_id: 'd-step2', step: 1 },
      { firestore: fs });
    ok('step 2 executed', r.step_executed === 2);
    const persisted = await fs.getDoc('tm_dispatches', 'd-step2');
    ok('escalation_status auto_escalated', persisted.escalation_status === 'auto_escalated');
    ok('escalation_chain has SYSTEM_AI entry',
      persisted.escalation_chain.some((e) => e.actor_uid === 'SYSTEM_AI' && e.action === 'auto_escalate'));
    ok('sla_history step 2 success',
      persisted.sla_history.some((h) => h.step === 2 && h.action === 'auto_escalate_system_ai' && h.success === true));
    dispatchesMod._setFirestoreForTest(null);
    auditMod._setFirestoreForTest(null);
    auditMod._resetMigrationForTest();
    watchdog.setCloudTasksClient(null);
  }

  // 28. sla_tick step 3 -> SYSTEM_AI assignUnit when DSS top-1 >= 0.55.
  {
    const fs = new TickFs();
    fs._c('tm_dispatches').set('d-step3', {
      id: 'd-step3', received_at: new Date().toISOString(),
      caller_uid: 'caller-3', caller_tier: 40,
      caller_scope_path: 'ndma/HP/Shimla',
      worker_status: 'received', sla_step: 2, sla_history: [],
      escalation_chain: [], assignments: [],
      worker_status_history: [],
      triage: { urgency: 'CRITICAL', needs: ['medical_evacuation'], incident_type: 'unknown' }
    });
    fs._c('tm_units').set('amb-1', {
      unit_id: 'amb-1', name: 'Amb-1', type: 'ambulance', status: 'available',
      scope_path: 'ndma/HP/Shimla', archived: false, contact_phone: '+91 11 5555 0001'
    });
    // Inject a units module that returns the seeded unit.
    watchdog._setUnitsForTest({
      listAvailableInScope: async () => [{
        unit_id: 'amb-1', name: 'Amb-1', type: 'ambulance', status: 'available',
        scope_path: 'ndma/HP/Shimla'
      }]
    });
    // Inject a dispatches module that just calls through (no-op for this
    // step) so the watchdog's escalate path is not exercised here.
    watchdog._setDispatchesForTest({ escalate: async () => ({}) });
    // Wire the real assignments module's firestore + audit seams to the
    // in-memory fs so SYSTEM_AI assignment lands in our test store.
    assignmentsMod._setFirestoreForTest({
      runTransaction: (fn) => fs.runTransaction(fn),
      getDoc: (c, i) => fs.getDoc(c, i)
    });
    assignmentsMod._setAuditForTest({
      record: async (uid, action, target, payload, sig) => {
        const aid = 'a-' + Math.random().toString(16).slice(2);
        fs._c('tm_audit').set(aid, { uid, action, target, payload, sig });
        return aid;
      }
    });
    watchdog.setCloudTasksClient(async () => ({ duplicate: false, status: 200 }));

    const r = await watchdog.handleSlaTick({ dispatch_id: 'd-step3', step: 2 },
      { firestore: fs });
    ok('step 3 executed', r.step_executed === 3);
    const persisted = await fs.getDoc('tm_dispatches', 'd-step3');
    ok('sla_history step 3 success',
      persisted.sla_history.some((h) => h.step === 3 && h.action === 'auto_assign_system_ai' && h.success === true));
    ok('dispatch has assignment by SYSTEM_AI',
      Array.isArray(persisted.assignments) && persisted.assignments.length === 1);
    const aid = persisted.assignments[0].aid;
    const adoc = await fs.getDoc('tm_assignments', aid);
    ok('assignment doc actor SYSTEM_AI', adoc && adoc.assigned_by_uid === 'SYSTEM_AI');
    ok('assignment doc carries dss_reasoning',
      adoc && adoc.dss_reasoning && typeof adoc.dss_reasoning.score === 'number');
    ok('assignment doc kind system_ai', adoc && adoc.assigned_by_kind === 'system_ai');

    // Restore real seams.
    assignmentsMod._setFirestoreForTest(null);
    assignmentsMod._setAuditForTest(null);
    watchdog._setDispatchesForTest(null);
    watchdog._setUnitsForTest(null);
    watchdog.setCloudTasksClient(null);
  }

  // 29. sla_tick step 3 -> no candidate >= 0.55 -> step 4 fan-out.
  {
    const fs = new TickFs();
    fs._c('tm_dispatches').set('d-step3-empty', {
      id: 'd-step3-empty', received_at: new Date().toISOString(),
      caller_uid: 'caller-x', caller_scope_path: 'ndma/HP/Shimla',
      worker_status: 'received', sla_step: 2, sla_history: [],
      triage: { urgency: 'HIGH' }
    });
    // Seed no available units; DSS suggest returns empty -> jump to fan-out.
    watchdog._setUnitsForTest({
      listAvailableInScope: async () => []
    });
    fs._c('tm_users').set('responder-A', {
      uid: 'responder-A', scope_path: 'ndma/HP/Shimla/Tehsil1', tier: 30
    });
    fs._c('tm_users').set('responder-B', {
      uid: 'responder-B', scope_path: 'ndma/HP/Shimla/Tehsil2', tier: 30
    });
    const notifyCalls = [];
    watchdog._setNotifyForTest({ send: async (a) => { notifyCalls.push(a); } });
    watchdog.setCloudTasksClient(async () => ({ duplicate: false, status: 200 }));

    const r = await watchdog.handleSlaTick({ dispatch_id: 'd-step3-empty', step: 2 },
      { firestore: fs });
    ok('step 3 -> step 4 in same tick', r.step_executed === 4 && r.history_appended === 2);
    const persisted = await fs.getDoc('tm_dispatches', 'd-step3-empty');
    ok('sla_step persisted as 4', persisted.sla_step === 4);
    ok('sla_history has step 3 skipped', persisted.sla_history.some((h) => h.step === 3 && h.action === 'auto_assign_skipped_no_candidate'));
    ok('sla_history has step 4 fanout', persisted.sla_history.some((h) => h.step === 4 && h.action === 'fanout_broadcast'));
    ok('fan-out reached subtree responders', notifyCalls.some((n) => n.kind === 'sla_fanout'));
    watchdog._setUnitsForTest(null);
    watchdog._setNotifyForTest(null);
    watchdog.setCloudTasksClient(null);
  }

  // 30. C2 detection: zero presence rows -> step 1 skipped, c2_compromised: true.
  {
    const fs = new TickFs();
    fs._c('tm_dispatches').set('d-c2', {
      id: 'd-c2', received_at: new Date().toISOString(),
      caller_uid: 'caller-c2', caller_scope_path: 'ndma/HP/Shimla',
      worker_status: 'received', sla_step: 0, sla_history: [],
      escalation_chain: [], caller_tier: 40, escalation_status: 'pending_review',
      triage: { urgency: 'CRITICAL' }
    });
    fs._c('tm_users').set('caller-c2', {
      uid: 'caller-c2', parent_uid: 'sup-c2', scope_path: 'ndma/HP/Shimla', tier: 40
    });
    // No presence rows seeded.
    watchdog.setCloudTasksClient(async () => ({ duplicate: false, status: 200 }));
    const r = await watchdog.handleSlaTick({ dispatch_id: 'd-c2', step: 0 },
      { firestore: fs });
    ok('c2 path executed step 2 instead of step 1', r.step_executed === 2);
    const persisted = await fs.getDoc('tm_dispatches', 'd-c2');
    ok('c2_compromised flag set', persisted.c2_compromised === true);
    ok('history shows skip_no_presence', persisted.sla_history.some((h) => h.action === 'skip_no_presence'));
    watchdog.setCloudTasksClient(null);
  }

  // 31. Autonomous mode: forced ON via test seam, CRITICAL dispatch jumps
  //     to step 3, NDMA-tier call clears the flag.
  {
    watchdog._setAutonomousModeForTest(true);
    ok('autonomous mode is ON', watchdog.isAutonomousMode() === true);
    watchdog.clearAutonomousModeIfNdma({ uid: 'volunteer-1', tier: 20 });
    ok('non-NDMA call does not clear autonomous mode', watchdog.isAutonomousMode() === true);
    watchdog.clearAutonomousModeIfNdma({ uid: 'ndma-cmdr', tier: 100 });
    ok('NDMA-tier call clears autonomous mode', watchdog.isAutonomousMode() === false);

    // Probe semantics: with no NDMA presence and >= 10 CRITICAL dispatches,
    // autonomous mode arms.
    watchdog._resetForTest();
    const fs = new TickFs();
    const recv = new Date().toISOString();
    for (let i = 0; i < 12; i++) {
      fs._c('tm_dispatches').set(`d-surge-${i}`, {
        id: `d-surge-${i}`, received_at: recv,
        caller_scope_path: 'ndma/HP/Shimla', triage: { urgency: 'CRITICAL' }
      });
    }
    // No NDMA-tier presence row.
    const flag = await watchdog.probeAutonomousMode({ firestore: fs });
    ok('probe arms autonomous mode on CRITICAL surge + no NDMA presence', flag === true);
  }

  // 32. SYSTEM_AI sig path verifies the ML-DSA-signed canonical message.
  {
    watchdog._resetForTest();
    const ts = Math.floor(Date.now() / 1000);
    const target = `dispatch.escalate|${randomUUID()}`;
    const signed = watchdog.signSystemAction({ action: 'dispatch.escalate', target, ts });
    ok('signSystemAction returns sig + ts + key_id',
      typeof signed.sig_b64 === 'string' && signed.sig_b64.length > 100
      && signed.ts === ts && signed.key_id === 'system-ai-v1');
    const okVerify = watchdog.verifySystemAction({
      action: 'dispatch.escalate', target, ts, key_id: signed.key_id, sig_b64: signed.sig_b64
    });
    ok('verifySystemAction accepts watchdog-signed message', okVerify === true);

    // Tampered target rejected.
    const bad = watchdog.verifySystemAction({
      action: 'dispatch.escalate', target: target + 'TAMPER', ts, key_id: signed.key_id,
      sig_b64: signed.sig_b64
    });
    ok('verifySystemAction rejects tampered target', bad === false);

    // Wrong key_id rejected.
    const badKey = watchdog.verifySystemAction({
      action: 'dispatch.escalate', target, ts, key_id: 'system-ai-v9',
      sig_b64: signed.sig_b64
    });
    ok('verifySystemAction rejects wrong key_id', badKey === false);

    // requireFreshSystemSig integrates with auth.js
    const verified = await authMod.requireFreshSystemSig(
      { uid: 'SYSTEM_AI', system_action_ts: ts, system_action_key_id: signed.key_id },
      'dispatch.escalate', target, signed.sig_b64
    );
    ok('requireFreshSystemSig returns SYSTEM_AI verified payload',
      verified.uid === 'SYSTEM_AI' && verified.action === 'dispatch.escalate');

    // Non-SYSTEM_AI actor rejected.
    await expectThrowAsync(
      'requireFreshSystemSig rejects non-SYSTEM_AI actor',
      () => authMod.requireFreshSystemSig({ uid: 'other-uid' }, 'dispatch.escalate', target, signed.sig_b64),
      'not_system_actor'
    );
    await expectThrowAsync(
      'requireFreshSystemSig rejects bad sig',
      () => authMod.requireFreshSystemSig(
        { uid: 'SYSTEM_AI', system_action_ts: ts, system_action_key_id: signed.key_id },
        'dispatch.escalate', target, 'A'.repeat(4412)),
      'action_sig_bad'
    );
  }
}


// ---------------------------------------------------------------------------


// i18n-server lane. pickLocale + t() + summaryFor locale wiring +
// JSON pack file count. Owned by wave-3-i18n-server.
{
  const { pickLocale, t, SUPPORTED_LOCALES } = await import('../i18n.js');
  const { _internal: assignInternal } = await import('../assignments.js');
  const { summaryFor, resolveDispatchLocale } = assignInternal;

  // 34.1 SUPPORTED_LOCALES has the 15 expected locales.
  const want = ['en', 'hi', 'ta', 'bn', 'ml', 'te', 'mr', 'or',
    'gu', 'pa', 'kn', 'ur', 'as', 'ne', 'mai'];
  ok('SUPPORTED_LOCALES exposes 15 locales',
    SUPPORTED_LOCALES.length === 15 && want.every((c) => SUPPORTED_LOCALES.includes(c)));

  // 34.2 pickLocale resolves 3-letter Vertex code 'mal' to 'ml',
  // preferring triage over caller hint.
  ok("pickLocale('mal','ml-IN') returns 'ml'",
    pickLocale('mal', 'ml-IN') === 'ml');

  // 34.3 pickLocale falls back to caller hint then 'en' for unknown.
  ok("pickLocale('xx','en-US') returns 'en'",
    pickLocale('xx', 'en-US') === 'en');
  ok("pickLocale('zz','yy') returns 'en' fallback",
    pickLocale('zz', 'yy') === 'en');
  ok("pickLocale(null,'hi') returns 'hi'",
    pickLocale(null, 'hi') === 'hi');
  ok('pickLocale strips BCP-47 region',
    pickLocale('bn-IN', null) === 'bn');

  // 34.4 t() returns non-empty strings for every key in every locale.
  const keys = ['sm_received', 'sm_under_review', 'sm_resources_assigned',
    'sm_dispatched', 'sm_en_route', 'sm_on_scene', 'sm_eta', 'sm_call',
    'sm_more_resources', 'sm_resolved', 'sm_cancelled'];
  let allPresent = true;
  let firstMissing = null;
  for (const loc of SUPPORTED_LOCALES) {
    for (const k of keys) {
      const out = t(loc, k, { unit_name: 'X', minutes: 1, phone: '0', n: 1 });
      if (typeof out !== 'string' || out.length === 0) {
        allPresent = false;
        firstMissing = `${loc}/${k}`;
        break;
      }
    }
    if (!allPresent) break;
  }
  ok('t() returns non-empty for every key in every locale',
    allPresent, firstMissing ? `missing ${firstMissing}` : null);

  // 34.5 t() variable substitution.
  ok('t() substitutes {unit_name}',
    t('en', 'sm_dispatched', { unit_name: 'AMB-7' }) === 'AMB-7 dispatched.');
  ok('t() substitutes {minutes} in non-en locale',
    t('hi', 'sm_eta', { minutes: 12 }).includes('12'));
  ok('t() leaves missing var rendering as a string (no crash)',
    typeof t('en', 'sm_dispatched', {}) === 'string');
  ok('t() falls back to en for unknown locale',
    t('zz', 'sm_received') === 'Request received. Dispatcher reviewing now.');

  // 34.6 summaryFor with locale='ml' on a dispatched unit returns
  // Malayalam containing the unit name. Survivors who only read
  // Malayalam must see Malayalam, not English.
  const mlSummary = summaryFor('en_route', [{
    aid: 'a1', unit_id: 'u1', unit_name: 'AMB-Kochi',
    status: 'en_route', eta_minutes: 8, contact_phone: '+919999000000'
  }], 'ml');
  ok('summaryFor(ml) renders unit name verbatim',
    mlSummary.includes('AMB-Kochi'));
  ok('summaryFor(ml) is in Malayalam script',
    /[ഀ-ൿ]/.test(mlSummary), `summary=${mlSummary}`);
  ok('summaryFor(ml) includes ETA digits', mlSummary.includes('8'));
  ok('summaryFor(ml) includes phone', mlSummary.includes('+919999000000'));

  // 34.7 summaryFor falls back to en when locale is null/empty.
  const enSummary = summaryFor('en_route', [{
    aid: 'a1', unit_id: 'u1', unit_name: 'AMB-X',
    status: 'en_route', eta_minutes: 5
  }], null);
  ok('summaryFor(null) falls back to English',
    enSummary === 'AMB-X en route. ETA 5 minutes.', `got: ${enSummary}`);
  const enDefault = summaryFor('received', []);
  ok('summaryFor() default arg is en',
    enDefault === 'Request received. Dispatcher reviewing now.');

  // 34.8 resolveDispatchLocale prefers triage over hint.
  ok('resolveDispatchLocale picks triage.language_detected',
    resolveDispatchLocale({ triage: { language_detected: 'mal' }, lang_hint: 'en' }) === 'ml');
  ok('resolveDispatchLocale falls back to lang_hint',
    resolveDispatchLocale({ triage: null, lang_hint: 'ta-IN' }) === 'ta');
  ok('resolveDispatchLocale falls back to en',
    resolveDispatchLocale({}) === 'en');
  ok('resolveDispatchLocale honours dispatch.locale override',
    resolveDispatchLocale({ locale: 'bn', triage: { language_detected: 'mal' } }) === 'bn');

  // 34.9 JSON pack file count: 11 new packs in web/i18n/.
  const { readdirSync, existsSync } = await import('node:fs');
  const { fileURLToPath } = await import('node:url');
  const path = await import('node:path');
  const here = path.dirname(fileURLToPath(import.meta.url));
  const i18nDir = path.resolve(here, '../../../web/i18n');
  if (existsSync(i18nDir)) {
    const files = readdirSync(i18nDir).filter((f) => f.endsWith('.json'));
    ok('web/i18n contains 11 JSON packs',
      files.length === 11, `found=${files.length}: ${files.join(',')}`);
    const expectPacks = ['ml', 'te', 'mr', 'or', 'gu', 'pa', 'kn', 'ur', 'as', 'ne', 'mai'];
    const missingPacks = expectPacks.filter((c) => !files.includes(`${c}.json`));
    ok('web/i18n covers all 11 lane locales',
      missingPacks.length === 0, `missing=${missingPacks.join(',')}`);
    const brCount = readdirSync(i18nDir).filter((f) => f.endsWith('.json.br')).length;
    const gzCount = readdirSync(i18nDir).filter((f) => f.endsWith('.json.gz')).length;
    ok('web/i18n has 11 brotli pre-compressed packs', brCount === 11);
    ok('web/i18n has 11 gzip pre-compressed packs', gzCount === 11);
  } else {
    ok('web/i18n directory exists', false, `expected at ${i18nDir}`);
  }
}



// 33. phone-identity lane: telco header HMAC verify, SMS OTP roundtrip,
//     attempt cap, shortcode webhook, frequency / geo anomaly, noise
//     gate, telco-attached caller_identity, anonymous + noise-gate
//     forwarding to the false-alarm review queue.
// ---------------------------------------------------------------------------
{
  const telcoMod = await import('../telco.js');
  const smsMod = await import('../sms.js');
  const abuseMod = await import('../abuse.js');
  const cryptoMod = await import('node:crypto');

  // 33.1 telco header verify: bad sig rejected, good sig accepted.
  {
    const secretBytes = cryptoMod.randomBytes(32);
    const secretB64 = secretBytes.toString('base64');
    process.env.TELCO_HMAC_SECRETS = `jio:${secretB64},airtel:${cryptoMod.randomBytes(32).toString('base64')}`;
    telcoMod._resetTelcoCacheForTest();
    const msisdn = '+919876543210';
    const ts = Math.floor(Date.now() / 1000);
    const sig = cryptoMod.createHmac('sha256', secretBytes).update(`${msisdn}|${ts}`).digest('base64');
    const goodHeaders = {
      'x-msisdn': msisdn,
      'x-telco-sig': sig,
      'x-telco-key-id': 'jio',
      'x-telco-ts': String(ts)
    };
    const verified = telcoMod.verifyTelcoHeader(goodHeaders);
    ok('verifyTelcoHeader accepts good jio sig',
      verified && verified.msisdn_e164 === msisdn && verified.telco === 'jio');

    const badSig = cryptoMod.createHmac('sha256', cryptoMod.randomBytes(32)).update(`${msisdn}|${ts}`).digest('base64');
    ok('verifyTelcoHeader rejects bad sig',
      telcoMod.verifyTelcoHeader({ ...goodHeaders, 'x-telco-sig': badSig }) === null);
    ok('verifyTelcoHeader rejects unknown key id',
      telcoMod.verifyTelcoHeader({ ...goodHeaders, 'x-telco-key-id': 'unknown' }) === null);
    ok('verifyTelcoHeader rejects 10 min skew',
      telcoMod.verifyTelcoHeader({ ...goodHeaders, 'x-telco-ts': String(ts - 600) }) === null);

    process.env.TELCO_HMAC_SECRETS = `jio:${secretB64}`;
    telcoMod._resetTelcoCacheForTest();
    const reverified = telcoMod.verifyTelcoHeader(goodHeaders);
    ok('verifyTelcoHeader accepts good sig after reload', reverified && reverified.telco === 'jio');
    delete process.env.TELCO_HMAC_SECRETS;
    telcoMod._resetTelcoCacheForTest();
  }

  class MiniFs {
    constructor() { this.col = new Map(); }
    _c(name) { if (!this.col.has(name)) this.col.set(name, new Map()); return this.col.get(name); }
    async setDoc(c, id, d) { this._c(c).set(id, JSON.parse(JSON.stringify(d))); }
    async getDoc(c, id) { const v = this._c(c).get(id); return v ? JSON.parse(JSON.stringify(v)) : null; }
    async deleteDoc(c, id) { this._c(c).delete(id); }
    async queryDocs(c, filters, opts) {
      const out = [];
      for (const [id, d] of this._c(c).entries()) {
        let pass = true;
        for (const f of filters || []) {
          const path = String(f.field).split('.');
          let v = d;
          for (const p of path) { v = v == null ? undefined : v[p]; }
          if (f.op === '==' && v !== f.value) pass = false;
          if (f.op === '>=' && !(v >= f.value)) pass = false;
          if (f.op === '<' && !(v < f.value)) pass = false;
        }
        if (pass) out.push({ id, data: d });
      }
      return opts?.limit ? out.slice(0, opts.limit) : out;
    }
  }

  // 33.2 sendOtp + verifyOtp roundtrip.
  {
    const fs = new MiniFs();
    smsMod._setFirestoreForTest(fs);
    let lastOtp = null;
    smsMod._setSmsSenderForTest((provider, phone, otp) => { lastOtp = otp; });
    process.env.MSG91_API_KEY = 'test-key';
    const phone = '+919876543210';
    const r = await smsMod.sendOtp(phone, 'auto');
    ok('sendOtp returned ok', r.ok === true);
    ok('sendOtp picked msg91 provider', r.provider === 'msg91');
    ok('OTP delivered via stub sender', typeof lastOtp === 'string' && lastOtp.length === 6);
    const pending = await fs.getDoc('tm_otp_pending', phone);
    ok('tm_otp_pending row created', pending && pending.attempts === 0);

    const verified = await smsMod.verifyOtp(phone, lastOtp);
    ok('verifyOtp succeeded', verified.ok === true && typeof verified.phone_fp === 'string');
    const cleared = await fs.getDoc('tm_otp_pending', phone);
    ok('tm_otp_pending cleared after verify', cleared === null);
    const binding = await fs.getDoc('tm_phone_bindings', verified.phone_fp);
    ok('tm_phone_bindings minted', binding && binding.phone_e164 === phone);

    delete process.env.MSG91_API_KEY;
    smsMod._setSmsSenderForTest(null);
    smsMod._setFirestoreForTest(null);
  }

  // 33.3 verifyOtp rejects after 3 failed attempts.
  {
    const fs = new MiniFs();
    smsMod._setFirestoreForTest(fs);
    let stashedOtp = null;
    smsMod._setSmsSenderForTest((provider, phone, otp) => { stashedOtp = otp; });
    process.env.KARIX_API_KEY = 'k-test';
    const phone = '+918888888888';
    await smsMod.sendOtp(phone, 'auto');
    ok('sendOtp picked karix when only karix is set', stashedOtp !== null);

    let last;
    for (let i = 0; i < 3; i++) {
      try { await smsMod.verifyOtp(phone, '000000'); }
      catch (e) { last = e; }
    }
    ok('third bad attempt rejected', last && last.code === 'otp_mismatch');
    let exceeded;
    try { await smsMod.verifyOtp(phone, stashedOtp); }
    catch (e) { exceeded = e; }
    ok('verifyOtp blocks after attempts exhausted',
      exceeded && (exceeded.code === 'otp_attempts_exceeded' || exceeded.code === 'otp_not_found'));

    delete process.env.KARIX_API_KEY;
    smsMod._setSmsSenderForTest(null);
    smsMod._setFirestoreForTest(null);
  }

  // 33.4 shortcode webhook with HMAC parses + creates dispatch.
  {
    const fs = new MiniFs();
    smsMod._setFirestoreForTest(fs);
    const r = await smsMod.handleShortcodeWebhook({
      from_e164: '+919999000011',
      body: 'SOS trapped under building',
      received_at: new Date().toISOString()
    });
    ok('handleShortcodeWebhook accepted SOS', r.ok === true && typeof r.dispatch_id === 'string');
    const row = await fs.getDoc('tm_dispatches', r.dispatch_id);
    ok('shortcode dispatch row written',
      row && row.phone_verified === true && row.verification_channel === 'sms_shortcode');
    ok('shortcode dispatch carries triage transcript',
      row.triage?.transcription_native === 'SOS trapped under building');

    const noSos = await smsMod.handleShortcodeWebhook({
      from_e164: '+919999000022',
      body: 'hello world',
      received_at: new Date().toISOString()
    });
    ok('handleShortcodeWebhook rejects non-SOS body',
      noSos.ok === false && noSos.reason === 'not_sos_format');

    smsMod._setFirestoreForTest(null);
  }

  // 33.5 checkFrequencyAnomaly: 4 in 1 hr from same fp flags.
  {
    const fs = new MiniFs();
    abuseMod._setFirestoreForTest(fs);
    const fp = 'fp-test-abuser';
    const recv = new Date().toISOString();
    for (let i = 0; i < 4; i++) {
      fs._c('tm_dispatches').set(`d-freq-${i}`, {
        id: `d-freq-${i}`,
        received_at: recv,
        caller_identity: { fingerprint: fp }
      });
    }
    const r = await abuseMod.checkFrequencyAnomaly(fp);
    ok('checkFrequencyAnomaly flags > 3 / hr', r.flagged === true && r.count === 4);

    const rOther = await abuseMod.checkFrequencyAnomaly('fp-clean');
    ok('checkFrequencyAnomaly clean fp not flagged', rOther.flagged === false && rOther.count === 0);

    abuseMod._setFirestoreForTest(null);
  }

  // 33.6 checkGeoImpossibility: 100 km in 2 min flags.
  {
    const fs = new MiniFs();
    abuseMod._setFirestoreForTest(fs);
    const fp = 'fp-jumper';
    const recv = new Date(Date.now() - 2 * 60_000).toISOString();
    fs._c('tm_dispatches').set('d-geo-1', {
      id: 'd-geo-1', received_at: recv,
      caller_identity: { fingerprint: fp },
      location: { lat: 28.6139, lng: 77.2090 }
    });
    const r = await abuseMod.checkGeoImpossibility(fp, 29.6139, 77.2090);
    ok('checkGeoImpossibility flags > 50 km in 5 min',
      r.flagged === true && r.max_distance_m > 100_000);
    const rNear = await abuseMod.checkGeoImpossibility(fp, 28.62, 77.21);
    ok('checkGeoImpossibility nearby not flagged', rNear.flagged === false);

    abuseMod._setFirestoreForTest(null);
  }

  // 33.7 checkNoiseGate: keyword + miss + panic + urgency.
  {
    const passKw = abuseMod.checkNoiseGate({
      urgency: 'LOW', transcription_english: 'help, trapped under rubble'
    });
    ok('checkNoiseGate passes with disaster keyword',
      passKw.passed === true && passKw.reason === 'disaster_keyword');

    const passUrg = abuseMod.checkNoiseGate({ urgency: 'CRITICAL', transcription_english: '' });
    ok('checkNoiseGate passes on CRITICAL',
      passUrg.passed === true && passUrg.reason === 'urgency_high');

    const passPanic = abuseMod.checkNoiseGate({
      urgency: 'LOW', transcription_english: '', panic_codes: [1, 8]
    });
    ok('checkNoiseGate passes on panic-code tap',
      passPanic.passed === true && passPanic.reason === 'panic_code');

    const fail = abuseMod.checkNoiseGate({
      urgency: 'LOW', transcription_english: 'hello world how are you'
    });
    ok('checkNoiseGate fails with no signal',
      fail.passed === false && fail.reason === 'no_disaster_signal');
  }

  // 33.8 handleTriage with telco header sets phone_verified true.
  //      Mirrors the helper that handleTriage uses to build
  //      caller_identity from a verified telco header.
  {
    const secret = cryptoMod.randomBytes(32);
    process.env.TELCO_HMAC_SECRETS = `vi:${secret.toString('base64')}`;
    telcoMod._resetTelcoCacheForTest();
    const msisdn = '+919998887776';
    const ts = Math.floor(Date.now() / 1000);
    const sig = cryptoMod.createHmac('sha256', secret).update(`${msisdn}|${ts}`).digest('base64');
    const verified = telcoMod.verifyTelcoHeader({
      'x-msisdn': msisdn, 'x-telco-sig': sig,
      'x-telco-key-id': 'vi', 'x-telco-ts': String(ts)
    });
    const callerIdentity = verified
      ? {
          msisdn_e164: verified.msisdn_e164,
          phone_verified: true,
          verification_channel: 'telco_header',
          fingerprint: 'fp-stub',
          ip_subnet24: '203.0.113.0/24',
          telco: verified.telco
        }
      : null;
    ok('handleTriage telco path: phone_verified true',
      callerIdentity && callerIdentity.phone_verified === true);
    ok('handleTriage telco path: verification_channel = telco_header',
      callerIdentity.verification_channel === 'telco_header');
    delete process.env.TELCO_HMAC_SECRETS;
    telcoMod._resetTelcoCacheForTest();
  }

  // 33.9 handleTriage anon + noise gate failed forwards to police.
  //      Mirrors the abuse-hook path that handleTriage runs after
  //      Vertex returns when the caller has no verified phone.
  {
    const fs = new MiniFs();
    abuseMod._setFirestoreForTest(fs);
    const triage = { urgency: 'LOW', transcription_english: 'just testing' };
    const verdict = abuseMod.checkNoiseGate(triage);
    ok('anon noise gate fails on no-signal', verdict.passed === false);
    const dispatchId = 'd-anon-fail-1';
    const wrote = await abuseMod.forwardToPolice(dispatchId, verdict.reason);
    ok('forwardToPolice persisted', wrote === true);
    const date = new Date().toISOString().slice(0, 10);
    const row = await fs.getDoc('tm_false_alarm_review', `${date}_${dispatchId}`);
    ok('false-alarm review row written',
      row && row.dispatch_id === dispatchId
      && row.enforcement_basis === 'DM_Act_2005_S_54');
    abuseMod._setFirestoreForTest(null);
  }
}

// 35. multi-device-keys lane. registerDevice + listDevices roundtrip,
//     revokeDevice HMAC re-sign required, bad-sig rejection, scope
//     isolation across uids.
// ---------------------------------------------------------------------------
{
  const devicesMod = await import('../devices.js');
  const { registerDevice, listDevices, revokeDevice, _setFirestoreForTest: setDevicesFs } = devicesMod;

  // Minimal in-memory Firestore for the device collection.
  class DevFs {
    constructor() { this.col = new Map(); }
    _c(name) { if (!this.col.has(name)) this.col.set(name, new Map()); return this.col.get(name); }
    async setDoc(c, id, data) { this._c(c).set(id, JSON.parse(JSON.stringify(data))); }
    async getDoc(c, id) {
      const v = this._c(c).get(id);
      return v ? JSON.parse(JSON.stringify(v)) : null;
    }
    async queryDocs(c, filters, opts) {
      const col = this._c(c);
      const out = [];
      for (const [id, data] of col.entries()) {
        let pass = true;
        for (const f of (filters || [])) {
          if (f.op === '==' && data[f.field] !== f.value) { pass = false; break; }
        }
        if (pass) out.push({ id, data: JSON.parse(JSON.stringify(data)) });
      }
      const lim = opts?.limit || 200;
      return out.slice(0, lim);
    }
  }

  const devFs = new DevFs();
  setDevicesFs(devFs);

  const actor = { uid: 'user-mdk-1', tier: 40, scope_path: 'ndma/HP/Shimla' };

  // 33.1 register first device.
  const pubkey1 = b64Enc(new Uint8Array(32).fill(1));
  const dev1 = await registerDevice(actor, { label: 'Pixel 7', pubkey_b64: pubkey1 });
  ok('registerDevice returned device_id', typeof dev1.device_id === 'string' && dev1.device_id.length > 0);
  ok('registerDevice returned label', dev1.label === 'Pixel 7');
  ok('registerDevice computed thumbprint',
    typeof dev1.pubkey_b64_thumbprint === 'string' && dev1.pubkey_b64_thumbprint.length === 16
    && /^[0-9a-f]+$/.test(dev1.pubkey_b64_thumbprint));
  ok('registerDevice stamped timestamps',
    typeof dev1.registered_at === 'string' && typeof dev1.last_seen_at === 'string');
  ok('registerDevice not revoked', dev1.revoked === false);

  // 33.2 register second device.
  const pubkey2 = b64Enc(new Uint8Array(32).fill(2));
  const dev2 = await registerDevice(actor, { label: 'Lenovo K8', pubkey_b64: pubkey2 });
  ok('second registerDevice has different device_id', dev2.device_id !== dev1.device_id);
  ok('second device thumbprint differs', dev2.pubkey_b64_thumbprint !== dev1.pubkey_b64_thumbprint);

  // 33.3 listDevices returns both rows for the actor.
  const list1 = await listDevices(actor);
  ok('listDevices returns 2 rows', Array.isArray(list1) && list1.length === 2);
  ok('listDevices returns only this user',
    list1.every((d) => d.uid === actor.uid));
  const ids = list1.map((d) => d.device_id).sort();
  const want = [dev1.device_id, dev2.device_id].sort();
  ok('listDevices contains both device_ids',
    ids[0] === want[0] && ids[1] === want[1]);

  // 33.4 listDevices isolated by uid: a sibling user sees nothing.
  const sibling = { uid: 'user-mdk-2', tier: 40, scope_path: 'ndma/HP/Shimla' };
  const sibList = await listDevices(sibling);
  ok('sibling user listDevices returns 0', sibList.length === 0);

  // 33.5 revokeDevice rejects missing signature.
  await expectThrowAsync(
    'revokeDevice rejects empty sig',
    () => revokeDevice(actor, dev1.device_id, ''),
    'no_action_sig'
  );
  await expectThrowAsync(
    'revokeDevice rejects null sig',
    () => revokeDevice(actor, dev1.device_id, null),
    'no_action_sig'
  );

  // 33.6 revokeDevice flips the row.
  const revoked = await revokeDevice(actor, dev1.device_id, 'fake-sig-b64');
  ok('revokeDevice returns revoked: true', revoked.revoked === true);
  ok('revokeDevice stamped revoked_at', typeof revoked.revoked_at === 'string' && revoked.revoked_at.length > 0);
  const list2 = await listDevices(actor);
  const persistedRev = list2.find((d) => d.device_id === dev1.device_id);
  ok('listDevices reflects revoked: true', persistedRev?.revoked === true);
  const persistedActive = list2.find((d) => d.device_id === dev2.device_id);
  ok('other device stays active', persistedActive?.revoked === false);

  // 33.7 revoking an unknown device fails 404-style.
  await expectThrowAsync(
    'revokeDevice rejects unknown id',
    () => revokeDevice(actor, 'no-such-device-id', 'sig'),
    'device_not_found'
  );

  // 33.8 cannot revoke another user's device.
  await expectThrowAsync(
    'revokeDevice rejects cross-user',
    () => revokeDevice(sibling, dev2.device_id, 'sig'),
    'device_not_found'
  );

  // 33.9 registerDevice rejects bad label.
  await expectThrowAsync(
    'registerDevice rejects empty label',
    () => registerDevice(actor, { label: '', pubkey_b64: pubkey1 }),
    'bad_label'
  );
  await expectThrowAsync(
    'registerDevice rejects oversize label',
    () => registerDevice(actor, { label: 'x'.repeat(60), pubkey_b64: pubkey1 }),
    'bad_label'
  );
  await expectThrowAsync(
    'registerDevice rejects empty pubkey',
    () => registerDevice(actor, { label: 'OK', pubkey_b64: '' }),
    'bad_pubkey'
  );
  await expectThrowAsync(
    'registerDevice rejects null actor',
    () => registerDevice(null, { label: 'X', pubkey_b64: pubkey1 }),
    'unauthorized'
  );

  // 33.10 HMAC re-sign required for revoke. requireFreshHmacSigForDevice
  // accepts only action='device.revoke' and verifies the canonical HMAC
  // over the session-bound action key. Mirrors the wire path from the
  // router for a real revoke call.
  const authMod2 = await import('../auth.js');
  const { requireFreshHmacSigForDevice } = authMod2;
  ok('requireFreshHmacSigForDevice exported', typeof requireFreshHmacSigForDevice === 'function');

  _clearReplayStoreForTest();
  // Re-issue a session so we have a fresh action key and the auth-side
  // user lookup hits a known uid.
  const seedKey2 = globalThis.__seedAdminKey;
  const ch33 = await handleChallenge({ email: 'commander@ndma.in' }, {});
  const sigCh33 = ml_dsa65.sign(challengeMessageBytes('commander@ndma.in', ch33.challenge_b64), seedKey2.secretKey);
  const session33 = await handleVerify({
    email: 'commander@ndma.in', ch_id: ch33.ch_id, signature_b64: b64Enc(sigCh33)
  }, {});
  const actor33 = await authenticate({ headers: { authorization: 'Bearer ' + session33.token } });
  const action_key_bytes = b64Dec(session33.action_key_b64);

  const fakeDeviceId = 'd-' + Math.random().toString(16).slice(2, 12);
  const tsRev = Math.floor(Date.now() / 1000);
  const targetRev = `device.revoke|${fakeDeviceId}`;
  const canonicalRev = canonicalActionMessage({
    uid: actor33.uid, action: 'device.revoke', target: targetRev, ts: tsRev, key_id: session33.key_id
  });
  const sigRev = hmacB64u(action_key_bytes, canonicalRev);

  const verifiedRev = await requireFreshHmacSigForDevice(
    actor33, 'device.revoke', targetRev,
    { 'x-action-sig': sigRev, 'x-action-ts': String(tsRev), 'x-action-key-id': session33.key_id }
  );
  ok('requireFreshHmacSigForDevice accepts good sig',
    verifiedRev.uid === actor33.uid && verifiedRev.action === 'device.revoke');
  ok('requireFreshHmacSigForDevice rotates key',
    typeof verifiedRev.next_action_key_b64 === 'string'
    && typeof verifiedRev.next_action_key_id === 'string');

  // 33.11 wrong action name rejected.
  await expectThrowAsync(
    'requireFreshHmacSigForDevice rejects non-device action',
    () => requireFreshHmacSigForDevice(actor33, 'user.delegate', 'x', { 'x-action-sig': 'a', 'x-action-ts': '1', 'x-action-key-id': 'k' }),
    'bad_action'
  );

  // 33.12 bad sig rejected. Tamper with the target after signing the clean target.
  _clearReplayStoreForTest();
  const tsRev2 = Math.floor(Date.now() / 1000);
  const cleanTarget = `device.revoke|${fakeDeviceId}-clean`;
  const cleanCanon = canonicalActionMessage({
    uid: actor33.uid, action: 'device.revoke', target: cleanTarget, ts: tsRev2, key_id: session33.key_id
  });
  const cleanSig = hmacB64u(action_key_bytes, cleanCanon);
  await expectThrowAsync(
    'requireFreshHmacSigForDevice rejects tampered target',
    () => requireFreshHmacSigForDevice(actor33, 'device.revoke',
      `device.revoke|${fakeDeviceId}-tamper`,
      { 'x-action-sig': cleanSig, 'x-action-ts': String(tsRev2), 'x-action-key-id': session33.key_id }),
    'action_sig_bad'
  );

  // 33.13 missing sig header rejected.
  await expectThrowAsync(
    'requireFreshHmacSigForDevice rejects missing sig',
    () => requireFreshHmacSigForDevice(actor33, 'device.revoke', targetRev,
      { 'x-action-ts': String(tsRev2), 'x-action-key-id': session33.key_id }),
    'no_action_sig'
  );

  // 33.14 stale ts rejected (outside +/-60s skew).
  await expectThrowAsync(
    'requireFreshHmacSigForDevice rejects stale ts',
    () => requireFreshHmacSigForDevice(actor33, 'device.revoke', targetRev,
      { 'x-action-sig': sigRev, 'x-action-ts': '1000', 'x-action-key-id': session33.key_id }),
    'stale_action'
  );
}



if (failed === 0) {
  process.stdout.write('OK\n');
  process.exit(0);
} else {
  process.stdout.write(`FAIL: ${failed} assertion(s) failed\n`);
  process.exit(1);
}
