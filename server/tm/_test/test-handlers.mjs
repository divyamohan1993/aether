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
// 7. Audit hash chain (lane: audit-chain). Each tm_audit row is hash-
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

if (failed === 0) {
  process.stdout.write('OK\n');
  process.exit(0);
} else {
  process.stdout.write(`FAIL: ${failed} assertion(s) failed\n`);
  process.exit(1);
}
