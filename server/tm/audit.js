// Append-only, hash-chained audit log for the Task Manager module.
//
// Each tm_audit row carries:
//   - prev_hash: hex SHA-256 of the previous row's row_hash, or GENESIS
//                for seq=0.
//   - row_hash : hex SHA-256 of canonical-JSON
//                {action, payload_summary, prev_hash, target_ref, ts, uid}
//                with sorted keys.
//   - server_sig_b64: ML-DSA-65 signature over the row_hash bytes by the
//                     server keypair (same env-supplied keys that sign
//                     login session tokens; see auth.js).
//   - seq      : monotonic integer per chain. First row is 0.
//
// A single global tip doc tm_audit_tip/global pins the chain head. Tip and
// row write happen inside one Firestore optimistic transaction so two
// writers cannot fork the chain. On precondition failure the txn retries
// with jitter up to MAX_TXN_RETRIES; if all retries lose, the row is
// written unchained with chain_break:true so the action is still
// captured for post-incident review under DM Act 2005 § 54.
//
// Failure semantics depend on auditCriticality:
//   'best_effort' (default) — chain failure logs CRITICAL + the row falls
//                              through to an unchained write. Caller's
//                              mutation is not aborted.
//   'required'             — chain + fallback failure throws AuditWriteError
//                              with status 503. Used by NDMA-tier and
//                              SYSTEM_AI paths where an unauditable
//                              mutation must not land.

import { createHash } from 'node:crypto';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

import * as firestore from './firestore.js';
const { FirestoreError } = firestore;

const GENESIS_HASH = '0'.repeat(64);
const TIP_COLL = 'tm_audit_tip';
const TIP_ID = 'global';
const AUDIT_COLL = 'tm_audit';
const MAX_TXN_RETRIES = 3;
const MIGRATION_CAP = 10_000;
const SERVER_PRIV_LEN = 4032;
const SERVER_PUB_LEN = 1952;
const SERVER_SIG_LEN = 3309;

// ---------------------------------------------------------------------------
// Test seam. Tests inject a fake firestore facade that mirrors the real
// firestore.js exports. Production paths use the real module.
// ---------------------------------------------------------------------------
let _fs = firestore;

export function _setFirestoreForTest(mock) {
  _fs = mock || firestore;
}

function logJson(severity, fields) {
  const entry = { ts: new Date().toISOString(), severity, ...fields };
  process.stdout.write(JSON.stringify(entry) + '\n');
}

// ---------------------------------------------------------------------------
// Server keypair load. Mirrors the env-var contract in auth.js so when
// TM_SERVER_PRIV_B64 / TM_SERVER_PUB_B64 are set, both modules sign with
// identical keys. Without env vars an ephemeral keypair is generated; the
// chain remains internally verifiable via getAuditServerPubB64.
// ---------------------------------------------------------------------------
let _serverPriv = null;
let _serverPub = null;
let _serverKeyEphemeral = false;

function loadServerKey() {
  if (_serverPriv && _serverPub) return;
  const privEnv = process.env.TM_SERVER_PRIV_B64;
  const pubEnv = process.env.TM_SERVER_PUB_B64;
  if (privEnv && pubEnv) {
    try {
      const priv = new Uint8Array(Buffer.from(privEnv, 'base64'));
      const pub = new Uint8Array(Buffer.from(pubEnv, 'base64'));
      if (priv.length === SERVER_PRIV_LEN && pub.length === SERVER_PUB_LEN) {
        _serverPriv = priv;
        _serverPub = pub;
        _serverKeyEphemeral = false;
        return;
      }
    } catch { /* fall through to ephemeral */ }
  }
  const k = ml_dsa65.keygen();
  _serverPriv = k.secretKey;
  _serverPub = k.publicKey;
  _serverKeyEphemeral = true;
  logJson('WARNING', {
    fn: 'audit.loadServerKey',
    msg: 'audit_server_keypair_ephemeral',
    note: 'set TM_SERVER_PRIV_B64 / TM_SERVER_PUB_B64 so audit verify keys match auth across boots'
  });
}

export function getAuditServerPub() {
  loadServerKey();
  return _serverPub;
}

export function getAuditServerPubB64() {
  loadServerKey();
  return Buffer.from(_serverPub).toString('base64');
}

export function isAuditKeyEphemeral() {
  loadServerKey();
  return _serverKeyEphemeral;
}

// ---------------------------------------------------------------------------
// Canonical-JSON sort-keys serializer. The only stable cross-process form
// we trust for hash agreement.
// ---------------------------------------------------------------------------
function canonicalJson(v) {
  if (v === null || v === undefined) return 'null';
  if (typeof v === 'string') return JSON.stringify(v);
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) return 'null';
    return JSON.stringify(v);
  }
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (Array.isArray(v)) return '[' + v.map(canonicalJson).join(',') + ']';
  if (typeof v === 'object') {
    const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(v[k])).join(',') + '}';
  }
  return JSON.stringify(String(v));
}

function rowHashHex(rowDoc, prevHashHex) {
  const canonical = canonicalJson({
    action: rowDoc.action,
    payload_summary: rowDoc.payload_summary,
    prev_hash: prevHashHex,
    target_ref: rowDoc.target_ref,
    ts: rowDoc.ts,
    uid: rowDoc.uid
  });
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

function hexToBytes(h) {
  if (typeof h !== 'string' || (h.length & 1) !== 0) return new Uint8Array(0);
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(h.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) return new Uint8Array(0);
    out[i] = byte;
  }
  return out;
}

function summarize(payload) {
  if (!payload || typeof payload !== 'object') return {};
  const out = {};
  for (const [k, v] of Object.entries(payload)) {
    if (v === null || v === undefined) continue;
    if (k === 'pubkey_b64' || k === 'signature_b64' || k === 'action_signature' || k === 'passphrase') continue;
    if (typeof v === 'string') out[k] = v.length > 256 ? v.slice(0, 256) + '...' : v;
    else if (typeof v === 'number' || typeof v === 'boolean') out[k] = v;
    else if (Array.isArray(v)) out[k] = v.slice(0, 10).map((x) => typeof x === 'string' ? x.slice(0, 64) : x);
    else if (typeof v === 'object') out[k] = '[object]';
  }
  return out;
}

// ---------------------------------------------------------------------------
// Compute (row_hash, server_sig_b64) for an unwritten row. Wave-2 watchdog
// SYSTEM_AI auto-DSS rows call this when they need the signature
// pre-computed before scheduling the deferred write.
// ---------------------------------------------------------------------------
export function auditWriteSig(prevHashHex, rowDoc) {
  if (typeof prevHashHex !== 'string' || prevHashHex.length !== 64) {
    throw new Error('auditWriteSig: prevHashHex must be 64 hex chars');
  }
  if (!rowDoc || typeof rowDoc !== 'object') {
    throw new Error('auditWriteSig: rowDoc required');
  }
  const rh = rowHashHex(rowDoc, prevHashHex);
  loadServerKey();
  const sigBytes = ml_dsa65.sign(hexToBytes(rh), _serverPriv);
  return {
    prev_hash: prevHashHex,
    row_hash: rh,
    server_sig_b64: Buffer.from(sigBytes).toString('base64')
  };
}

// ---------------------------------------------------------------------------
// One-shot, idempotent migration of pre-chain rows. Capped at
// MIGRATION_CAP. For production-scale datasets a separate batch script is
// preferable; this in-process pass is sized for the hackathon dataset.
//
// On first record() / verify / list call after deploy, walk existing
// tm_audit rows in (ts asc) order and backfill prev_hash / row_hash /
// server_sig_b64 / seq. Already-chained rows are skipped and we resume
// from the highest seq to chain the un-chained tail. Then the tip is
// pinned to the last computed row_hash.
// ---------------------------------------------------------------------------
let _migrationPromise = null;

async function ensureMigration() {
  if (_migrationPromise) return _migrationPromise;
  _migrationPromise = (async () => {
    let tip = null;
    try { tip = await _fs.getDoc(TIP_COLL, TIP_ID); } catch (e) {
      if (!(e instanceof FirestoreError) || e.code !== 'FS_NOT_FOUND') {
        logJson('ERROR', { fn: 'audit.ensureMigration', msg: 'audit_migration_tip_read_failed', err: String(e) });
      }
    }
    let rows;
    try {
      rows = await _fs.queryDocs(AUDIT_COLL, [], { orderBy: 'ts', limit: MIGRATION_CAP });
    } catch (e) {
      logJson('ERROR', { fn: 'audit.ensureMigration', msg: 'audit_migration_query_failed', err: String(e) });
      return;
    }
    if (rows.length === 0 && !tip) return;
    let prevHash = GENESIS_HASH;
    let seq = 0;
    let lastHash = GENESIS_HASH;
    let migrated = 0;
    for (const r of rows) {
      const d = r.data || {};
      const tsIso = typeof d.ts === 'string' && d.ts.length > 0 ? d.ts : new Date().toISOString();
      if (typeof d.row_hash === 'string' && typeof d.prev_hash === 'string' && Number.isInteger(d.seq)) {
        prevHash = d.row_hash;
        lastHash = d.row_hash;
        seq = d.seq + 1;
        continue;
      }
      const baseRow = {
        uid: typeof d.actor_uid === 'string' ? d.actor_uid : 'unknown',
        action: typeof d.action === 'string' ? d.action : '',
        target_ref: typeof d.target_ref === 'string' ? d.target_ref : '',
        payload_summary: d.payload_summary && typeof d.payload_summary === 'object' ? d.payload_summary : {},
        ts: tsIso
      };
      const sig = auditWriteSig(prevHash, baseRow);
      const updated = {
        actor_uid: baseRow.uid,
        action: baseRow.action,
        target_ref: baseRow.target_ref,
        payload_summary: baseRow.payload_summary,
        actor_signature_b64: typeof d.actor_signature_b64 === 'string' ? d.actor_signature_b64 : null,
        ts: tsIso,
        prev_hash: sig.prev_hash,
        row_hash: sig.row_hash,
        server_sig_b64: sig.server_sig_b64,
        seq
      };
      try {
        await _fs.setDoc(AUDIT_COLL, r.id, updated);
        migrated++;
      } catch (e) {
        logJson('ERROR', { fn: 'audit.ensureMigration', msg: 'audit_migration_row_failed', id: r.id, err: String(e) });
        return;
      }
      prevHash = sig.row_hash;
      lastHash = sig.row_hash;
      seq++;
    }
    if (rows.length > 0) {
      try {
        await _fs.setDoc(TIP_COLL, TIP_ID, {
          tip_hash: lastHash,
          tip_seq: seq - 1,
          updated_at: new Date().toISOString(),
          migrated_count: migrated
        });
      } catch (e) {
        logJson('ERROR', { fn: 'audit.ensureMigration', msg: 'audit_migration_tip_failed', err: String(e) });
        return;
      }
    }
    if (migrated > 0) {
      logJson('NOTICE', { fn: 'audit.ensureMigration', msg: 'audit_migration_completed', migrated, tip_seq: seq - 1 });
    }
  })().catch((e) => {
    logJson('ERROR', { fn: 'audit.ensureMigration', msg: 'audit_migration_uncaught', err: String(e) });
  });
  return _migrationPromise;
}

export function _resetMigrationForTest() {
  _migrationPromise = null;
}

// ---------------------------------------------------------------------------
// AuditWriteError. Thrown only when criticality === 'required' and the
// chained + unchained writes both fail. Maps to 503.
// ---------------------------------------------------------------------------
export class AuditWriteError extends Error {
  constructor(code, message, status) {
    super(message || code);
    this.name = 'AuditWriteError';
    this.code = code || 'audit_write_failed';
    this.status = status || 503;
  }
}

// ---------------------------------------------------------------------------
// AuditAccessError. Thrown by handleVerify / handleList when the actor's
// tier is below the gate. Maps to 403.
// ---------------------------------------------------------------------------
export class AuditAccessError extends Error {
  constructor(code, message, status) {
    super(message || code);
    this.name = 'AuditAccessError';
    this.code = code || 'audit_forbidden';
    this.status = status || 403;
  }
}

function jitterMs() {
  return 5 + Math.floor(Math.random() * 50);
}

async function appendChained(rowBase) {
  let lastErr = null;
  for (let attempt = 0; attempt < MAX_TXN_RETRIES; attempt++) {
    try {
      const out = await _fs.runTransaction(async (tx) => {
        const tip = await tx.get(TIP_COLL, TIP_ID);
        const prevHash = tip && typeof tip.tip_hash === 'string' ? tip.tip_hash : GENESIS_HASH;
        const seq = tip && Number.isInteger(tip.tip_seq) ? tip.tip_seq + 1 : 0;
        const sig = auditWriteSig(prevHash, rowBase);
        const rowFull = {
          actor_uid: rowBase.uid,
          action: rowBase.action,
          target_ref: rowBase.target_ref,
          payload_summary: rowBase.payload_summary,
          actor_signature_b64: rowBase.actor_signature_b64 || null,
          ts: rowBase.ts,
          prev_hash: sig.prev_hash,
          row_hash: sig.row_hash,
          server_sig_b64: sig.server_sig_b64,
          seq
        };
        const aid = tx.create(AUDIT_COLL, rowFull);
        tx.set(TIP_COLL, TIP_ID, {
          tip_hash: sig.row_hash,
          tip_seq: seq,
          updated_at: new Date().toISOString()
        });
        return { aid, seq, row_hash: sig.row_hash };
      });
      return out;
    } catch (e) {
      lastErr = e;
      const code = e instanceof FirestoreError ? e.code : null;
      if (code === 'FS_PRECONDITION' || code === 'FS_ALREADY_EXISTS') {
        await new Promise((r) => setTimeout(r, jitterMs()));
        continue;
      }
      throw e;
    }
  }
  throw lastErr;
}

// ---------------------------------------------------------------------------
// record(). Public API preserved: existing callers pass five positional
// args. The optional sixth `auditCriticality` lets NDMA-tier and SYSTEM_AI
// paths upgrade to fail-closed semantics.
// ---------------------------------------------------------------------------
export async function record(actorUid, action, targetRef, payload, actorSignatureB64, auditCriticality) {
  const criticality = auditCriticality === 'required' ? 'required' : 'best_effort';
  const tsIso = new Date().toISOString();
  const rowBase = {
    uid: typeof actorUid === 'string' && actorUid.length > 0 ? actorUid : 'unknown',
    action: String(action || ''),
    target_ref: String(targetRef || ''),
    payload_summary: summarize(payload),
    actor_signature_b64: actorSignatureB64 || null,
    ts: tsIso
  };
  await ensureMigration();
  try {
    const result = await appendChained(rowBase);
    return result.aid;
  } catch (chainErr) {
    const code = chainErr instanceof FirestoreError ? chainErr.code : (chainErr?.code || 'UNKNOWN');
    logJson('CRITICAL', {
      fn: 'audit.record',
      msg: 'audit_chain_write_failed',
      action: rowBase.action,
      target_ref: rowBase.target_ref,
      actor_uid: rowBase.uid,
      criticality,
      code,
      err: String(chainErr)
    });
    if (criticality === 'required') {
      throw new AuditWriteError('audit_write_failed', 'Audit chain write failed and criticality=required.', 503);
    }
    try {
      const aid = await _fs.createDoc(AUDIT_COLL, {
        actor_uid: rowBase.uid,
        action: rowBase.action,
        target_ref: rowBase.target_ref,
        payload_summary: rowBase.payload_summary,
        actor_signature_b64: rowBase.actor_signature_b64,
        ts: rowBase.ts,
        prev_hash: null,
        row_hash: null,
        server_sig_b64: null,
        seq: null,
        chain_break: true,
        chain_break_reason: code
      });
      logJson('CRITICAL', {
        fn: 'audit.record',
        msg: 'audit_row_unchained',
        aid,
        action: rowBase.action,
        target_ref: rowBase.target_ref,
        actor_uid: rowBase.uid
      });
      return aid;
    } catch (fallbackErr) {
      logJson('CRITICAL', {
        fn: 'audit.record',
        msg: 'audit_row_lost',
        action: rowBase.action,
        target_ref: rowBase.target_ref,
        actor_uid: rowBase.uid,
        err: String(fallbackErr)
      });
      return null;
    }
  }
}

// ---------------------------------------------------------------------------
// verifyChain. Walks the chain from `fromSeq` forward up to `limit` rows,
// recomputes each row_hash, checks prev_hash linkage, and verifies the
// ML-DSA-65 server signature. On first break returns details. On full
// pass returns {total_walked, ok_count}.
// ---------------------------------------------------------------------------
export async function verifyChain({ fromSeq = 0, limit = 1000 } = {}) {
  await ensureMigration();
  const cap = Math.min(Math.max(1, Number.isInteger(limit) ? limit : 1000), 1000);
  const start = Math.max(0, Number.isInteger(fromSeq) ? fromSeq : 0);
  let rows;
  try {
    rows = await _fs.queryDocs(AUDIT_COLL, [
      { field: 'seq', op: '>=', value: start }
    ], { orderBy: 'seq', limit: cap });
  } catch (e) {
    if (e instanceof FirestoreError && e.code === 'FS_NOT_FOUND') {
      rows = [];
    } else {
      throw e;
    }
  }
  let prevHashExpect = GENESIS_HASH;
  if (start > 0) {
    try {
      const prior = await _fs.queryDocs(AUDIT_COLL, [
        { field: 'seq', op: '==', value: start - 1 }
      ], { limit: 1 });
      if (prior.length > 0 && typeof prior[0].data.row_hash === 'string') {
        prevHashExpect = prior[0].data.row_hash;
      } else {
        return {
          total_walked: 0,
          ok_count: 0,
          break_at_seq: start - 1,
          break_kind: 'missing_row',
          details: { reason: 'prior row not found for from_seq>0', expected_seq: start - 1 }
        };
      }
    } catch (e) {
      return {
        total_walked: 0,
        ok_count: 0,
        break_at_seq: start - 1,
        break_kind: 'missing_row',
        details: { reason: 'failed to read prior row', err: String(e) }
      };
    }
  }
  let okCount = 0;
  let totalWalked = 0;
  let expectedSeq = start;
  loadServerKey();
  for (const r of rows) {
    const d = r.data || {};
    totalWalked++;
    if (!Number.isInteger(d.seq) || d.seq !== expectedSeq) {
      return {
        total_walked: totalWalked,
        ok_count: okCount,
        break_at_seq: expectedSeq,
        break_kind: 'missing_row',
        details: { id: r.id, found_seq: d.seq ?? null, expected_seq: expectedSeq }
      };
    }
    if (typeof d.prev_hash !== 'string' || d.prev_hash !== prevHashExpect) {
      return {
        total_walked: totalWalked,
        ok_count: okCount,
        break_at_seq: d.seq,
        break_kind: 'prev_hash_mismatch',
        details: { id: r.id, prev_hash: d.prev_hash || null, expected_prev_hash: prevHashExpect }
      };
    }
    const recompute = rowHashHex({
      uid: d.actor_uid,
      action: d.action,
      target_ref: d.target_ref,
      payload_summary: d.payload_summary && typeof d.payload_summary === 'object' ? d.payload_summary : {},
      ts: d.ts
    }, d.prev_hash);
    if (recompute !== d.row_hash) {
      return {
        total_walked: totalWalked,
        ok_count: okCount,
        break_at_seq: d.seq,
        break_kind: 'row_hash_recompute_mismatch',
        details: { id: r.id, computed: recompute, stored: d.row_hash || null }
      };
    }
    let sigOk = false;
    try {
      const sigBuf = Buffer.from(d.server_sig_b64 || '', 'base64');
      const sig = new Uint8Array(sigBuf);
      const msg = hexToBytes(d.row_hash);
      sigOk = sig.length === SERVER_SIG_LEN && msg.length === 32 && ml_dsa65.verify(sig, msg, _serverPub);
    } catch { sigOk = false; }
    if (!sigOk) {
      return {
        total_walked: totalWalked,
        ok_count: okCount,
        break_at_seq: d.seq,
        break_kind: 'server_sig_invalid',
        details: { id: r.id }
      };
    }
    okCount++;
    prevHashExpect = d.row_hash;
    expectedSeq++;
  }
  return { total_walked: totalWalked, ok_count: okCount };
}

// ---------------------------------------------------------------------------
// listChain. Filtered read of audit rows for post-incident review. State
// tier (80) and above only; gating is enforced by handleList.
// ---------------------------------------------------------------------------
export async function listChain(filters = {}, opts = {}) {
  await ensureMigration();
  const limit = Math.min(Math.max(1, Number.isInteger(opts.limit) ? opts.limit : 50), 200);
  const queryFilters = [];
  if (typeof filters.actor_uid === 'string' && filters.actor_uid.length > 0) {
    queryFilters.push({ field: 'actor_uid', op: '==', value: filters.actor_uid });
  }
  if (typeof filters.action === 'string' && filters.action.length > 0) {
    queryFilters.push({ field: 'action', op: '==', value: filters.action });
  }
  if (typeof filters.target_ref === 'string' && filters.target_ref.length > 0) {
    queryFilters.push({ field: 'target_ref', op: '==', value: filters.target_ref });
  }
  if (typeof filters.since === 'string' && filters.since.length > 0) {
    queryFilters.push({ field: 'ts', op: '>=', value: filters.since });
  }
  if (typeof filters.until === 'string' && filters.until.length > 0) {
    queryFilters.push({ field: 'ts', op: '<=', value: filters.until });
  }
  let rows;
  try {
    rows = await _fs.queryDocs(AUDIT_COLL, queryFilters, {
      orderBy: { field: 'ts', direction: 'desc' },
      limit
    });
  } catch (e) {
    if (e instanceof FirestoreError && e.code === 'FS_NOT_FOUND') return { rows: [] };
    throw e;
  }
  const includeSig = opts.include_signatures === true;
  const out = rows.map((r) => {
    const d = r.data || {};
    const base = {
      id: r.id,
      seq: Number.isInteger(d.seq) ? d.seq : null,
      actor_uid: typeof d.actor_uid === 'string' ? d.actor_uid : null,
      action: typeof d.action === 'string' ? d.action : null,
      target_ref: typeof d.target_ref === 'string' ? d.target_ref : null,
      ts: typeof d.ts === 'string' ? d.ts : null,
      prev_hash: typeof d.prev_hash === 'string' ? d.prev_hash : null,
      row_hash: typeof d.row_hash === 'string' ? d.row_hash : null,
      chain_break: d.chain_break === true,
      payload_summary: d.payload_summary && typeof d.payload_summary === 'object' ? d.payload_summary : {}
    };
    if (includeSig) {
      base.server_sig_b64 = typeof d.server_sig_b64 === 'string' ? d.server_sig_b64 : null;
      base.actor_signature_b64 = typeof d.actor_signature_b64 === 'string' ? d.actor_signature_b64 : null;
    }
    return base;
  });
  return { rows: out };
}

// ---------------------------------------------------------------------------
// Router-facing handlers. Tier checks live here so the router stays slim.
// ---------------------------------------------------------------------------
export async function handleVerify(actor, opts = {}) {
  if (!actor || typeof actor.tier !== 'number' || actor.tier < 100) {
    throw new AuditAccessError('audit_verify_forbidden', 'NDMA tier required for audit verify.', 403);
  }
  return verifyChain(opts);
}

export async function handleList(actor, filters = {}, opts = {}) {
  if (!actor || typeof actor.tier !== 'number' || actor.tier < 80) {
    throw new AuditAccessError('audit_list_forbidden', 'State tier or above required for audit list.', 403);
  }
  return listChain(filters, opts);
}

// ---------------------------------------------------------------------------
// Test seam exports.
// ---------------------------------------------------------------------------
export const _internalAudit = Object.freeze({
  GENESIS_HASH,
  TIP_COLL,
  TIP_ID,
  AUDIT_COLL,
  MAX_TXN_RETRIES,
  rowHashHex,
  canonicalJson,
  summarize,
  hexToBytes,
  ensureMigration
});
