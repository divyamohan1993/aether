// Project Aether · Task Manager · auth handlers self-test.
//
// Mocks firestore + users and exercises the router-facing handler
// surface added to auth.js: handleChallenge -> handleVerify, plus
// authenticate, requireFreshUserSig (4-arg), handleBootstrap,
// handleRegister, getServerPubkeyB64.
//
// Run: `node server/tm/_test/test-handlers.mjs` -> prints OK.

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { randomUUID } from 'node:crypto';

import {
  authenticate,
  getServerPubkeyB64,
  handleRegister,
  handleBootstrap,
  handleChallenge,
  handleVerify,
  requireFreshUserSig,
  canonicalActionTarget,
  signSession,
  challengeMessageBytes,
  utf8,
  b64Enc,
  b64Dec,
  _setFirestoreForTest as setAuthFirestore,
  _setUsersForTest as setAuthUsers
} from '../auth.js';

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

// ---------------------------------------------------------------------------
// Fakes.
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Wire fakes.
// ---------------------------------------------------------------------------
const fakeFs = new FakeFs();
const fakeUsers = makeFakeUsers(fakeFs);
setAuthFirestore(fakeFs);
setAuthUsers(fakeUsers);

// ---------------------------------------------------------------------------
// 1. getServerPubkeyB64 returns the same string as the existing alias.
// ---------------------------------------------------------------------------
{
  const pub = await getServerPubkeyB64();
  ok('getServerPubkeyB64 returns base64 string', typeof pub === 'string' && pub.length > 100);
  ok('getServerPubkeyB64 decodes to 1952 bytes', b64Dec(pub).length === 1952);
}

// ---------------------------------------------------------------------------
// 2. Round trip: register a user via bootstrap (env-gated), then run
//    challenge -> verify with their key.
// ---------------------------------------------------------------------------
{
  // Bootstrap disabled by default.
  await expectThrowAsync(
    'handleBootstrap blocked when env not set',
    () => handleBootstrap({ email: 'a@b.in', name: 'Asha', pubkey_b64: 'x'.repeat(2604) }, {}),
    'bootstrap_disabled'
  );

  process.env.TM_BOOTSTRAP_ALLOW = '1';
  const userKey = ml_dsa65.keygen();
  const email = 'commander@ndma.in';
  const created = await handleBootstrap({
    email,
    name: 'NDMA Commander',
    pubkey_b64: b64Enc(userKey.publicKey)
  }, {});
  ok('handleBootstrap returned uid', typeof created.uid === 'string');
  ok('handleBootstrap returned tier 100', created.tier === 100);
  ok('handleBootstrap returned scope ndma', created.scope_path === 'ndma');
  delete process.env.TM_BOOTSTRAP_ALLOW;

  // Challenge.
  const ch = await handleChallenge({ email }, {});
  ok('handleChallenge ch_id', typeof ch.ch_id === 'string' && ch.ch_id.length > 0);
  ok('handleChallenge challenge_b64 length', b64Dec(ch.challenge_b64).length === 32);
  ok('handleChallenge expires_at is ISO', !Number.isNaN(Date.parse(ch.expires_at)));
  ok('handleChallenge expiry roughly +60s', Date.parse(ch.expires_at) - Date.now() > 30_000 && Date.parse(ch.expires_at) - Date.now() < 90_000);

  // Sign challenge with user's private key.
  const msg = challengeMessageBytes(email, ch.challenge_b64);
  const sig = ml_dsa65.sign(msg, userKey.secretKey);

  // Verify.
  const session = await handleVerify({
    email,
    ch_id: ch.ch_id,
    signature_b64: b64Enc(sig)
  }, {});
  ok('handleVerify returned token (3 parts)', typeof session.token === 'string' && session.token.split('.').length === 3);
  ok('handleVerify exp ISO', !Number.isNaN(Date.parse(session.exp)));
  ok('handleVerify server_pubkey_b64 set', typeof session.server_pubkey_b64 === 'string' && session.server_pubkey_b64.length > 100);
  ok('handleVerify user.uid matches', session.user.uid === created.uid);
  ok('handleVerify user.tier matches', session.user.tier === 100);

  // last_login was bumped.
  const stored = await fakeFs.getDoc('tm_users', created.uid);
  ok('handleVerify bumped last_login', typeof stored.last_login === 'string' && stored.last_login.length > 0);

  // Replay should fail (challenge consumed).
  await expectThrowAsync(
    'handleVerify replay rejected',
    () => handleVerify({ email, ch_id: ch.ch_id, signature_b64: b64Enc(sig) }, {}),
    'challenge_invalid'
  );

  // Wrong email but correct ch_id (issue new ch, sign for different email).
  const ch2 = await handleChallenge({ email }, {});
  const sig2 = ml_dsa65.sign(challengeMessageBytes(email, ch2.challenge_b64), userKey.secretKey);
  await expectThrowAsync(
    'handleVerify rejects mismatched email',
    () => handleVerify({ email: 'someone-else@x.in', ch_id: ch2.ch_id, signature_b64: b64Enc(sig2) }, {}),
    'challenge_invalid'
  );

  // Bad signature.
  const ch3 = await handleChallenge({ email }, {});
  const wrongKey = ml_dsa65.keygen();
  const wrongSig = ml_dsa65.sign(challengeMessageBytes(email, ch3.challenge_b64), wrongKey.secretKey);
  await expectThrowAsync(
    'handleVerify rejects wrong signer',
    () => handleVerify({ email, ch_id: ch3.ch_id, signature_b64: b64Enc(wrongSig) }, {}),
    'challenge_invalid'
  );

  // Unknown email -> challenge issued but verify fails generically.
  const ch4 = await handleChallenge({ email: 'ghost@nowhere.in' }, {});
  ok('handleChallenge always issues for unknown email', typeof ch4.ch_id === 'string');
  await expectThrowAsync(
    'handleVerify unknown email -> challenge_invalid',
    () => handleVerify({ email: 'ghost@nowhere.in', ch_id: ch4.ch_id, signature_b64: b64Enc(sig2) }, {}),
    'challenge_invalid'
  );

  // Capture for the next block.
  globalThis.__seedAdminUid = created.uid;
  globalThis.__seedAdminKey = userKey;
}

// ---------------------------------------------------------------------------
// 3. authenticate(req): Bearer token in -> session payload out.
// ---------------------------------------------------------------------------
{
  const adminUid = globalThis.__seedAdminUid;
  const tok = signSession({ uid: adminUid, tier: 100, scope_path: 'ndma' });
  const payload = await authenticate({ headers: { authorization: 'Bearer ' + tok } });
  ok('authenticate returned uid', payload.uid === adminUid);
  ok('authenticate returned tier', payload.tier === 100);
  ok('authenticate returned scope', payload.scope_path === 'ndma');

  await expectThrowAsync('authenticate rejects missing header',
    () => authenticate({ headers: {} }), 'no_auth');
  await expectThrowAsync('authenticate rejects bad scheme',
    () => authenticate({ headers: { authorization: 'Basic abc' } }), 'auth_bad_scheme');
  await expectThrowAsync('authenticate rejects empty bearer',
    () => authenticate({ headers: { authorization: 'Bearer ' } }), 'auth_empty');
}

// ---------------------------------------------------------------------------
// 4. requireFreshUserSig (4-arg form). Canonical = JSON.stringify({uid,
//    action, target}).
// ---------------------------------------------------------------------------
{
  const adminUid = globalThis.__seedAdminUid;
  const adminKey = globalThis.__seedAdminKey;
  const actor = { uid: adminUid, tier: 100, scope_path: 'ndma' };
  const action = 'user.delegate';
  const target = `delegate|${randomUUID()}|40`;
  const canonical = canonicalActionTarget(adminUid, action, target);
  ok('canonical is JSON', JSON.parse(canonical).target === target);
  const sig = b64Enc(ml_dsa65.sign(utf8(canonical), adminKey.secretKey));
  const verified = await requireFreshUserSig(actor, action, target, sig);
  ok('requireFreshUserSig accepts good sig', verified.uid === adminUid && verified.action === action);

  // Tampered target.
  await expectThrowAsync(
    'requireFreshUserSig rejects tampered target',
    () => requireFreshUserSig(actor, action, target + 'x', sig),
    'action_sig_bad'
  );
  // Missing sig.
  await expectThrowAsync(
    'requireFreshUserSig rejects missing sig',
    () => requireFreshUserSig(actor, action, target, ''),
    'no_action_sig'
  );
  // Wrong signer.
  const wrongKey = ml_dsa65.keygen();
  const wrongSig = b64Enc(ml_dsa65.sign(utf8(canonical), wrongKey.secretKey));
  await expectThrowAsync(
    'requireFreshUserSig rejects wrong signer',
    () => requireFreshUserSig(actor, action, target, wrongSig),
    'action_sig_bad'
  );
  // Suspended user.
  const stored = await fakeFs.getDoc('tm_users', adminUid);
  await fakeFs.setDoc('tm_users', adminUid, { ...stored, status: 'suspended' });
  await expectThrowAsync(
    'requireFreshUserSig rejects suspended user',
    () => requireFreshUserSig(actor, action, target, sig),
    'user_suspended'
  );
  await fakeFs.setDoc('tm_users', adminUid, { ...stored, status: 'active' });
}

// ---------------------------------------------------------------------------
// 5. handleRegister: invite minted off-band, accept signs canonical
//    JSON.stringify({uid, action, target}) at mint time, register
//    verifies that signature against issuer pubkey.
// ---------------------------------------------------------------------------
{
  const adminUid = globalThis.__seedAdminUid;
  const adminKey = globalThis.__seedAdminKey;

  // Create an invite directly (bypassing users.inviteUser, which is owned
  // by tm-api). We sign the canonical the way the router would.
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
    email: inviteEmail,
    tier: inviteTier,
    parent_uid: inviteParent,
    scope_path: inviteScope,
    issued_by_uid: adminUid,
    issued_signature_b64: inviteSig,
    expires_at: expiresAt,
    used: false,
    created_at: new Date().toISOString()
  });

  const newUserKey = ml_dsa65.keygen();
  const created = await handleRegister({
    invite_id: inviteId,
    name: 'Rookie Responder',
    pubkey_b64: b64Enc(newUserKey.publicKey)
  }, {});
  ok('handleRegister returned uid', typeof created.uid === 'string');
  ok('handleRegister returned matching email', created.email === inviteEmail);
  ok('handleRegister returned matching tier', created.tier === inviteTier);

  // Tampered invite (mutate stored signature).
  const inviteId2 = randomUUID();
  await fakeFs.setDoc('tm_invitations', inviteId2, {
    email: 'tamper@x.in',
    tier: 40,
    parent_uid: adminUid,
    scope_path: 'ndma/HP',
    issued_by_uid: adminUid,
    issued_signature_b64: inviteSig, // signed for a different target
    expires_at: expiresAt,
    used: false,
    created_at: new Date().toISOString()
  });
  await expectThrowAsync(
    'handleRegister rejects tampered invite',
    () => handleRegister({ invite_id: inviteId2, name: 'X', pubkey_b64: b64Enc(newUserKey.publicKey) }, {}),
    'invite_sig_bad'
  );

  // Expired invite.
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

  // Missing invite.
  await expectThrowAsync(
    'handleRegister rejects unknown invite',
    () => handleRegister({ invite_id: 'no-such-id', name: 'T', pubkey_b64: b64Enc(newUserKey.publicKey) }, {}),
    'invite_not_found'
  );
}

// ---------------------------------------------------------------------------
// 6. handleChallenge / handleVerify input guards.
// ---------------------------------------------------------------------------
{
  await expectThrowAsync('handleChallenge rejects empty email',
    () => handleChallenge({ email: '' }, {}), 'bad_email');
  await expectThrowAsync('handleChallenge rejects missing body',
    () => handleChallenge(null, {}), 'bad_request');
  await expectThrowAsync('handleVerify rejects empty body',
    () => handleVerify({}, {}), 'bad_request');
}

if (failed === 0) {
  process.stdout.write('OK\n');
  process.exit(0);
} else {
  process.stdout.write(`FAIL: ${failed} assertion(s) failed\n`);
  process.exit(1);
}
