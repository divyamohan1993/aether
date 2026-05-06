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

// ---------------------------------------------------------------------------
// criticality-dedup lane tests (sections 11-18). Owned by wave-1-criticality-dedup.
// ---------------------------------------------------------------------------

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

// 11. criticalityScore: pregnant + child + elderly_with_crush.
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

// 12. criticalityScore fallback: empty victims -> people_affected.
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

// 13. geohash7: distinct cities map to distinct prefixes; 50 m apart match.
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

// 14. MinHash Jaccard: near-identical >= 0.7, unrelated < 0.2.
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

// 15. findCluster: two dispatches 50 m + 5 min apart, similar transcripts.
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

// 16. listTeam ordering: pending review queue sorted by criticality desc.
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

// 17. listTeam direct_only: filters by caller.parent_uid === actor.uid.
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

// 18. compare endpoint: returns 2-10 dispatches sorted by criticality desc.
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

// 19. dss.suggest short-circuits on duplicate cluster role.
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

if (failed === 0) {
  process.stdout.write('OK\n');
  process.exit(0);
} else {
  process.stdout.write(`FAIL: ${failed} assertion(s) failed\n`);
  process.exit(1);
}
