// Project Aether · Task Manager · auto-DSS-on-C2-fail watchdog.
//
// When a dispatch with escalation_policy=manual_review sits in
// pending_review past its SLA, this module climbs the ladder:
//
//   step 0 -> 1: notify direct supervisor                  (+1x SLA next)
//   step 1 -> 2: SYSTEM_AI auto-escalates one tier up       (+2x SLA next)
//   step 2 -> 3: SYSTEM_AI auto-assigns DSS top-1 (>= 0.55) (+ step 4 if no
//                candidate)
//   step 3 -> 4: fan-out broadcast to all in-scope responders (+4x SLA
//                final retry)
//
// Cloud Run scale-to-zero kills any in-process timer, so we delegate the
// timer to Cloud Tasks. Each persisted dispatch schedules a single
// `sla-{id}-0` task at sla_deadline_at; each ladder step schedules the
// next. Cloud Tasks rejects duplicate task names with 409 which makes
// the schedule idempotent.
//
// The HTTP target is `/api/v1/internal/sla_tick` on the same Cloud Run
// service. Body is HMAC-signed with WATCHDOG_HMAC_SECRET so a leaked
// task name cannot trigger an unauthorised tick.
//
// SYSTEM_AI sig path. The watchdog acts as a tier-100 pseudo-actor with
// a separate ML-DSA-65 keypair. Calls into dispatches.escalate and
// assignments.assignUnit go through auth.requireFreshSystemSig (the
// human-only HMAC path stays untouched). See SPEC DEVIATION in the
// module header in auth.js.
//
// Failure mode: if Cloud Tasks is unreachable, scheduleSlaTick logs a
// WARNING and returns; the dispatcher pipeline keeps working with no
// watchdog coverage. Lives are at stake; we never fail-closed on the
// scheduling side.

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { GoogleAuth } from 'google-auth-library';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

import { canonicalActionMessage } from './canonical.js';

const PROJECT_ID = process.env.GCP_PROJECT || 'dmjone';
// Cloud Tasks GA region nearest to Firestore Delhi (asia-south2).
// asia-south1 (Mumbai) has Cloud Tasks GA; asia-south2 does not.
const TASKS_LOCATION = process.env.CLOUD_TASKS_LOCATION || 'asia-south1';
const TASKS_QUEUE = process.env.CLOUD_TASKS_QUEUE || 'aether-watchdog';
const TASKS_HOST = 'cloudtasks.googleapis.com';
const TASK_HTTP_TARGET = process.env.WATCHDOG_TARGET_URL
  || 'https://aether.dmj.one/api/v1/internal/sla_tick';

const SLA_SECS = Object.freeze({
  CRITICAL: 60,
  HIGH: 300,
  MEDIUM: 900,
  LOW: 3600,
  UNCLEAR: 300
});

const STEP_MAX = 4;
const DSS_MIN_SCORE = 0.55;
const C2_PRESENCE_GRACE_MULT = 2;
const NDMA_PRESENCE_WINDOW_MS = 5 * 60_000;
const CRITICAL_SURGE_WINDOW_MS = 60_000;
const CRITICAL_SURGE_THRESHOLD = 10;

const SYSTEM_AI_UID = 'SYSTEM_AI';
const SYSTEM_AI_KEY_ID = 'system-ai-v1';
const SYSTEM_AI_TS_SKEW_SECS = 120;

// In-memory autonomous-mode flag. Cleared when any NDMA-tier user calls
// any authenticated endpoint. Survives only one Cloud Run instance; that
// is acceptable because the trigger condition (CRITICAL surge + no NDMA
// presence) recomputes on every SLA tick and re-arms the flag if still
// true.
let _autonomousMode = false;
let _autonomousModeEnteredAt = null;
let _autonomousModeLastProbeAt = 0;

let _systemPriv = null;
let _systemPub = null;
let _systemKeyEphemeral = false;
let _hmacSecret = null;

function logJson(severity, fields) {
  const entry = { ts: new Date().toISOString(), severity, ...fields };
  process.stdout.write(JSON.stringify(entry) + '\n');
}

function utf8(s) { return new TextEncoder().encode(s); }

function b64Dec(str) { return new Uint8Array(Buffer.from(str, 'base64')); }
function b64Enc(buf) {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return Buffer.from(b).toString('base64');
}

function loadSystemKeypair() {
  if (_systemPriv && _systemPub) return;
  const privEnv = process.env.SYSTEM_AI_PRIV_B64;
  const pubEnv = process.env.SYSTEM_AI_PUB_B64;
  if (privEnv && pubEnv) {
    let priv;
    let pub;
    try {
      priv = b64Dec(privEnv);
      pub = b64Dec(pubEnv);
    } catch {
      throw new Error('SYSTEM_AI_PRIV_B64 / SYSTEM_AI_PUB_B64 are not base64');
    }
    if (priv.length !== 4032) {
      throw new Error(`SYSTEM_AI_PRIV_B64 must decode to 4032 bytes (got ${priv.length})`);
    }
    if (pub.length !== 1952) {
      throw new Error(`SYSTEM_AI_PUB_B64 must decode to 1952 bytes (got ${pub.length})`);
    }
    const probe = utf8('aether-tm:system-ai:keypair-self-test');
    const sig = ml_dsa65.sign(probe, priv);
    if (!ml_dsa65.verify(sig, probe, pub)) {
      throw new Error('SYSTEM_AI_PRIV_B64 and SYSTEM_AI_PUB_B64 do not form a valid pair');
    }
    _systemPriv = priv;
    _systemPub = pub;
    _systemKeyEphemeral = false;
    return;
  }
  const k = ml_dsa65.keygen();
  _systemPriv = k.secretKey;
  _systemPub = k.publicKey;
  _systemKeyEphemeral = true;
  logJson('WARNING', {
    fn: 'tm.watchdog.loadSystemKeypair',
    msg: 'system_ai_keypair_generated_in_memory',
    note: 'persist out-of-band and set SYSTEM_AI_PRIV_B64 / SYSTEM_AI_PUB_B64 on next boot',
    pubkey_b64: b64Enc(_systemPub),
    privkey_b64: b64Enc(_systemPriv)
  });
}

function getSystemPub() {
  if (!_systemPub) loadSystemKeypair();
  return _systemPub;
}

function getSystemPubB64() {
  return b64Enc(getSystemPub());
}

function isSystemKeyEphemeral() {
  if (!_systemPriv) loadSystemKeypair();
  return _systemKeyEphemeral;
}

function loadHmacSecret() {
  if (_hmacSecret) return _hmacSecret;
  const env = process.env.WATCHDOG_HMAC_SECRET;
  if (typeof env === 'string' && env.length >= 16) {
    _hmacSecret = Buffer.from(env, 'utf8');
    return _hmacSecret;
  }
  _hmacSecret = randomBytes(32);
  logJson('WARNING', {
    fn: 'tm.watchdog.loadHmacSecret',
    msg: 'watchdog_hmac_secret_generated_in_memory',
    note: 'set WATCHDOG_HMAC_SECRET to a stable secret on next boot. Cross-instance ticks will be rejected until then.'
  });
  return _hmacSecret;
}

function _resetForTest() {
  _systemPriv = null;
  _systemPub = null;
  _systemKeyEphemeral = false;
  _hmacSecret = null;
  _autonomousMode = false;
  _autonomousModeEnteredAt = null;
  _autonomousModeLastProbeAt = 0;
}

const SYSTEM_AI_ACTOR = Object.freeze({
  uid: SYSTEM_AI_UID,
  tier: 100,
  scope_path: 'ndma',
  name: 'Aether Auto-DSS',
  email: 'system-ai@aether.local',
  isSystem: true
});

function systemActor() {
  return { ...SYSTEM_AI_ACTOR };
}

// Pluggable Cloud Tasks transport so tests can swap the network call
// for an in-memory recorder. Production binds to the GoogleAuth-backed
// REST client below.
let _cloudTasksClient = null;
let _googleAuth = null;

function getGoogleAuth() {
  if (_googleAuth) return _googleAuth;
  _googleAuth = new GoogleAuth({ scopes: ['https://www.googleapis.com/auth/cloud-platform'] });
  return _googleAuth;
}

async function defaultCloudTasksCreate({ taskName, scheduleTimeIso, body, hmacSig }) {
  const auth = getGoogleAuth();
  const token = await auth.getAccessToken();
  if (!token) throw new Error('cloud_tasks_no_token');
  const parent = `projects/${PROJECT_ID}/locations/${TASKS_LOCATION}/queues/${TASKS_QUEUE}`;
  const url = `https://${TASKS_HOST}/v2/${parent}/tasks`;
  const payload = {
    task: {
      name: `${parent}/tasks/${taskName}`,
      scheduleTime: scheduleTimeIso,
      httpRequest: {
        url: TASK_HTTP_TARGET,
        httpMethod: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Watchdog-Sig': hmacSig
        },
        body: Buffer.from(body, 'utf8').toString('base64')
      }
    }
  };
  const resp = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload)
  });
  if (resp.status === 409) {
    return { duplicate: true, status: 409 };
  }
  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    const err = new Error(`cloud_tasks_http_${resp.status}`);
    err.status = resp.status;
    err.body = text.slice(0, 1024);
    throw err;
  }
  return { duplicate: false, status: resp.status };
}

function setCloudTasksClient(fn) {
  _cloudTasksClient = (typeof fn === 'function') ? fn : null;
}

function getCloudTasksClient() {
  return _cloudTasksClient || defaultCloudTasksCreate;
}

// Sign the JSON body with WATCHDOG_HMAC_SECRET. The receiver MUST verify
// before parsing. Hex-encoded for ease of header transit.
function signCallback(bodyJson) {
  const sec = loadHmacSecret();
  const h = createHmac('sha256', sec);
  h.update(bodyJson);
  return h.digest('hex');
}

function verifyCallbackSig(bodyJson, sigHex) {
  if (typeof sigHex !== 'string' || sigHex.length === 0) return false;
  const expected = signCallback(bodyJson);
  if (expected.length !== sigHex.length) return false;
  try {
    return timingSafeEqual(Buffer.from(expected, 'utf8'), Buffer.from(sigHex, 'utf8'));
  } catch {
    return false;
  }
}

function slaSecondsFor(urgency) {
  const k = String(urgency || '').toUpperCase();
  return Object.prototype.hasOwnProperty.call(SLA_SECS, k) ? SLA_SECS[k] : SLA_SECS.UNCLEAR;
}

function computeSlaDeadlineIso(receivedAtIso, urgency) {
  const t = Date.parse(receivedAtIso || '');
  const base = Number.isFinite(t) ? t : Date.now();
  const secs = slaSecondsFor(urgency);
  return new Date(base + secs * 1000).toISOString();
}

function taskNameFor(dispatchId, step) {
  // Cloud Tasks task ID accepts only [A-Za-z0-9_-], 1..500 chars. UUID
  // dispatch ids fit. Step suffix keeps each rung idempotent.
  const safeId = String(dispatchId).replace(/[^A-Za-z0-9_-]/g, '-').slice(0, 400);
  return `sla-${safeId}-${step}`;
}

// Schedule one SLA tick. Idempotent on (dispatch_id, step). Failures log
// WARNING and resolve; the persist pipeline never blocks on this.
async function scheduleSlaTick(dispatchId, fireAtIso, step = 0) {
  if (typeof dispatchId !== 'string' || dispatchId.length === 0) return false;
  if (typeof step !== 'number' || step < 0 || step > STEP_MAX) return false;
  const taskName = taskNameFor(dispatchId, step);
  const body = JSON.stringify({
    dispatch_id: dispatchId,
    scheduled_for: fireAtIso,
    step
  });
  const hmacSig = signCallback(body);
  try {
    const r = await getCloudTasksClient()({
      taskName,
      scheduleTimeIso: fireAtIso,
      body,
      hmacSig
    });
    if (r && r.duplicate) {
      logJson('INFO', {
        fn: 'tm.watchdog.scheduleSlaTick',
        msg: 'cloud_tasks_duplicate_swallowed',
        dispatch_id: dispatchId, step, task_name: taskName
      });
      return true;
    }
    return true;
  } catch (e) {
    logJson('WARNING', {
      fn: 'tm.watchdog.scheduleSlaTick',
      msg: 'cloud_tasks_create_failed',
      dispatch_id: dispatchId, step, task_name: taskName,
      err: String(e?.message || e)
    });
    return false;
  }
}

// Resolve the firestore module lazily so tests can swap it.
let _firestore = null;
async function getFirestore() {
  if (_firestore) return _firestore;
  _firestore = await import('./firestore.js');
  return _firestore;
}

function _setFirestoreForTest(mock) { _firestore = mock; }

let _users = null;
async function getUsers() {
  if (_users) return _users;
  _users = await import('./users.js');
  return _users;
}
function _setUsersForTest(mock) { _users = mock; }

let _dispatchesMod = null;
async function getDispatches() {
  if (_dispatchesMod) return _dispatchesMod;
  _dispatchesMod = await import('./dispatches.js');
  return _dispatchesMod;
}
function _setDispatchesForTest(mock) { _dispatchesMod = mock; }

let _assignmentsMod = null;
async function getAssignments() {
  if (_assignmentsMod) return _assignmentsMod;
  _assignmentsMod = await import('./assignments.js');
  return _assignmentsMod;
}
function _setAssignmentsForTest(mock) { _assignmentsMod = mock; }

let _dssMod = null;
async function getDss() {
  if (_dssMod) return _dssMod;
  _dssMod = await import('./dss.js');
  return _dssMod;
}
function _setDssForTest(mock) { _dssMod = mock; }

let _unitsMod = null;
async function getUnits() {
  if (_unitsMod) return _unitsMod;
  _unitsMod = await import('./units.js');
  return _unitsMod;
}
function _setUnitsForTest(mock) { _unitsMod = mock; }

let _notifyMod = null;
let _notifyTried = false;
async function getNotify() {
  if (_notifyMod !== null) return _notifyMod;
  if (_notifyTried) return null;
  _notifyTried = true;
  try {
    _notifyMod = await import('./notify.js');
  } catch {
    _notifyMod = false;
  }
  return _notifyMod || null;
}
function _setNotifyForTest(mock) {
  _notifyMod = mock || false;
  _notifyTried = true;
}

// Sign a SYSTEM_AI canonical action message with the ML-DSA-65 priv key.
// The watchdog calls this before invoking dispatches.escalate /
// assignments.assignUnit; the sig is then verified by
// auth.requireFreshSystemSig.
function signSystemAction({ action, target, ts }) {
  loadSystemKeypair();
  const canon = canonicalActionMessage({
    uid: SYSTEM_AI_UID,
    action,
    target,
    ts,
    key_id: SYSTEM_AI_KEY_ID
  });
  const sig = ml_dsa65.sign(utf8(canon), _systemPriv);
  return { sig_b64: b64Enc(sig), key_id: SYSTEM_AI_KEY_ID, ts, canonical: canon };
}

function verifySystemAction({ action, target, ts, key_id, sig_b64 }) {
  if (typeof key_id !== 'string' || key_id !== SYSTEM_AI_KEY_ID) return false;
  if (typeof sig_b64 !== 'string' || sig_b64.length === 0) return false;
  const now = Math.floor(Date.now() / 1000);
  if (typeof ts !== 'number' || !Number.isInteger(ts) || ts <= 0) return false;
  if (Math.abs(now - ts) > SYSTEM_AI_TS_SKEW_SECS) return false;
  loadSystemKeypair();
  const canon = canonicalActionMessage({
    uid: SYSTEM_AI_UID,
    action,
    target,
    ts,
    key_id
  });
  let sig;
  try { sig = b64Dec(sig_b64); } catch { return false; }
  if (sig.length !== 3309) return false;
  try {
    return ml_dsa65.verify(sig, utf8(canon), _systemPub);
  } catch {
    return false;
  }
}

// Append a row to dispatch.sla_history. Caller patches
// tm_dispatches/{id} with the new sla_step + sla_history.
function appendSlaHistory(existing, entry) {
  const arr = Array.isArray(existing) ? existing.slice() : [];
  arr.push(entry);
  return arr;
}

// Read in-scope presence rows. Returns the count of users with
// last_seen_at >= cutoff inside the actor's subtree (or any if
// scopePath omitted). Failure paths return null so callers can
// distinguish "no presence" from "could not check".
async function readPresenceCount(scopePath, cutoffIso, opts) {
  try {
    const fs = opts?.firestore || await getFirestore();
    if (typeof fs.queryDocs !== 'function') return null;
    const rows = await fs.queryDocs('tm_user_presence', [
      { field: 'last_seen_at', op: '>=', value: cutoffIso }
    ], { limit: 50 });
    if (!Array.isArray(rows)) return 0;
    if (!scopePath) return rows.length;
    let count = 0;
    for (const r of rows) {
      const uid = r?.id || r?.data?.uid;
      if (!uid) continue;
      try {
        const u = await fs.getDoc('tm_users', uid);
        if (!u || typeof u.scope_path !== 'string') continue;
        if (u.scope_path === scopePath || u.scope_path.startsWith(scopePath + '/')
            || scopePath.startsWith(u.scope_path + '/') || scopePath === u.scope_path) {
          count++;
        }
      } catch { /* ignore individual lookup failures */ }
    }
    return count;
  } catch (e) {
    logJson('WARNING', {
      fn: 'tm.watchdog.readPresenceCount',
      msg: 'presence_query_failed',
      err: String(e?.message || e)
    });
    return null;
  }
}

async function readNdmaPresenceCount(opts) {
  try {
    const fs = opts?.firestore || await getFirestore();
    if (typeof fs.queryDocs !== 'function') return null;
    const cutoff = new Date(Date.now() - NDMA_PRESENCE_WINDOW_MS).toISOString();
    const rows = await fs.queryDocs('tm_user_presence', [
      { field: 'last_seen_at', op: '>=', value: cutoff }
    ], { limit: 100 });
    if (!Array.isArray(rows)) return 0;
    let count = 0;
    for (const r of rows) {
      const uid = r?.id || r?.data?.uid;
      if (!uid) continue;
      const u = await fs.getDoc('tm_users', uid);
      if (u && Number(u.tier) >= 100) count++;
    }
    return count;
  } catch {
    return null;
  }
}

async function readCriticalSurgeCount(opts) {
  try {
    const fs = opts?.firestore || await getFirestore();
    if (typeof fs.queryDocs !== 'function') return 0;
    const cutoff = new Date(Date.now() - CRITICAL_SURGE_WINDOW_MS).toISOString();
    const rows = await fs.queryDocs('tm_dispatches', [
      { field: 'received_at', op: '>=', value: cutoff }
    ], { limit: 100 });
    if (!Array.isArray(rows)) return 0;
    let count = 0;
    for (const r of rows) {
      const u = r?.data?.triage?.urgency;
      if (typeof u === 'string' && u.toUpperCase() === 'CRITICAL') count++;
    }
    return count;
  } catch {
    return 0;
  }
}

// Probe entry. Called from the SLA tick path on the first tick of each
// minute. Returns the autonomous-mode flag value AFTER recompute.
async function probeAutonomousMode(opts) {
  const now = Date.now();
  if (now - _autonomousModeLastProbeAt < CRITICAL_SURGE_WINDOW_MS && _autonomousMode === false) {
    // Only re-probe once per minute when not already in autonomous mode.
  } else if (now - _autonomousModeLastProbeAt < CRITICAL_SURGE_WINDOW_MS) {
    return _autonomousMode;
  }
  _autonomousModeLastProbeAt = now;
  const ndmaCount = await readNdmaPresenceCount(opts);
  const surge = await readCriticalSurgeCount(opts);
  const shouldArm = (ndmaCount === 0 || ndmaCount === null) && surge >= CRITICAL_SURGE_THRESHOLD;
  if (shouldArm && !_autonomousMode) {
    _autonomousMode = true;
    _autonomousModeEnteredAt = new Date().toISOString();
    logJson('CRITICAL', {
      fn: 'tm.watchdog.probeAutonomousMode',
      msg: 'autonomous_mode_engaged',
      ndma_presence: ndmaCount,
      critical_surge: surge,
      threshold: CRITICAL_SURGE_THRESHOLD
    });
    try {
      const auditMod = await import('./audit.js').catch(() => null);
      if (auditMod && typeof auditMod.record === 'function') {
        await auditMod.record(SYSTEM_AI_UID, 'system.autonomous_engage',
          'tm_watchdog/autonomous_mode',
          { ndma_presence: ndmaCount, critical_surge: surge },
          null, 'best_effort').catch(() => {});
      }
    } catch { /* swallow */ }
  } else if (!shouldArm && _autonomousMode) {
    // Do not auto-clear here; the spec requires NDMA to call to clear.
  }
  return _autonomousMode;
}

function isAutonomousMode() {
  return _autonomousMode;
}

// Hook called from router.js on every authenticated request. If the
// caller is at NDMA tier (>= 100) and autonomous mode is engaged, clear
// it and emit an audit row.
function clearAutonomousModeIfNdma(actor) {
  if (!_autonomousMode) return false;
  if (!actor || Number(actor.tier) < 100) return false;
  _autonomousMode = false;
  const enteredAt = _autonomousModeEnteredAt;
  _autonomousModeEnteredAt = null;
  logJson('INFO', {
    fn: 'tm.watchdog.clearAutonomousModeIfNdma',
    msg: 'autonomous_mode_cleared',
    cleared_by_uid: actor.uid,
    cleared_by_tier: actor.tier,
    entered_at: enteredAt
  });
  // Best-effort audit log; do not block the calling request.
  (async () => {
    try {
      const auditMod = await import('./audit.js').catch(() => null);
      if (auditMod && typeof auditMod.record === 'function') {
        await auditMod.record(actor.uid, 'system.autonomous_clear',
          'tm_watchdog/autonomous_mode',
          { entered_at: enteredAt }, null, 'best_effort').catch(() => {});
      }
    } catch { /* swallow */ }
  })();
  return true;
}

function _setAutonomousModeForTest(v) {
  _autonomousMode = v === true;
  _autonomousModeEnteredAt = _autonomousMode ? new Date().toISOString() : null;
  _autonomousModeLastProbeAt = Date.now();
}

// Send a notification through notify.js if available, otherwise log.
// Returns the success flag from the underlying call (true if delivered
// or logged-only).
async function safeNotify(args) {
  const notify = await getNotify();
  if (notify && typeof notify.send === 'function') {
    try {
      await notify.send(args);
      return true;
    } catch (e) {
      logJson('WARNING', {
        fn: 'tm.watchdog.safeNotify',
        msg: 'notify_send_failed',
        err: String(e?.message || e)
      });
      return false;
    }
  }
  // Fall back to a structured log line so the dispatcher feed in the
  // log explorer still surfaces the escalation.
  logJson('INFO', {
    fn: 'tm.watchdog.safeNotify',
    msg: 'notify_log_only',
    ...args
  });
  return true;
}

// Patch the dispatch with new sla_step / sla_history / optional flags.
async function patchSlaState(dispatchId, patch, opts) {
  const fs = opts?.firestore || await getFirestore();
  if (typeof fs.patchDoc === 'function') {
    await fs.patchDoc('tm_dispatches', dispatchId, patch);
    return;
  }
  if (typeof fs.setDoc === 'function' && typeof fs.getDoc === 'function') {
    const cur = (await fs.getDoc('tm_dispatches', dispatchId)) || {};
    await fs.setDoc('tm_dispatches', dispatchId, { ...cur, ...patch });
    return;
  }
  throw new Error('firestore_patch_unavailable');
}

// Build a full hop entry for sla_history. Always carries the action and
// success flag so audits can replay the ladder.
function makeHistoryEntry(step, action, success, extra) {
  return {
    step,
    ts: new Date().toISOString(),
    action,
    success: success === true,
    ...(extra && typeof extra === 'object' ? extra : {})
  };
}

// Step 1: notify direct supervisor.
async function runStep1(dispatch, opts) {
  const supervisorUid = await resolveSupervisorUid(dispatch, opts);
  let success = false;
  if (supervisorUid) {
    success = await safeNotify({
      kind: 'sla_supervisor',
      to_uid: supervisorUid,
      dispatch_id: dispatch.id,
      caller_uid: dispatch.caller_uid || null,
      urgency: dispatch?.triage?.urgency || null,
      sla_step: 1
    });
  } else {
    logJson('WARNING', {
      fn: 'tm.watchdog.runStep1',
      msg: 'supervisor_not_found',
      dispatch_id: dispatch.id, caller_uid: dispatch.caller_uid
    });
  }
  return makeHistoryEntry(1, 'notify_supervisor', success, {
    supervisor_uid: supervisorUid || null
  });
}

async function resolveSupervisorUid(dispatch, opts) {
  if (!dispatch || !dispatch.caller_uid) return null;
  try {
    const fs = opts?.firestore || await getFirestore();
    const u = await fs.getDoc('tm_users', dispatch.caller_uid);
    if (!u) return null;
    return typeof u.parent_uid === 'string' && u.parent_uid.length > 0 ? u.parent_uid : null;
  } catch {
    return null;
  }
}

// Step 2: SYSTEM_AI auto-escalates one tier up.
async function runStep2(dispatch, opts) {
  const dispatches = opts?.dispatchesModule || await getDispatches();
  const ts = Math.floor(Date.now() / 1000);
  const target = `dispatch.escalate|${dispatch.id}`;
  const { sig_b64 } = signSystemAction({ action: 'dispatch.escalate', target, ts });
  let success = false;
  let err = null;
  try {
    await dispatches.escalate(systemActor(), dispatch.id,
      { note: 'Auto-escalated by Aether watchdog: SLA exceeded.' }, sig_b64);
    success = true;
  } catch (e) {
    err = String(e?.message || e);
    logJson('WARNING', {
      fn: 'tm.watchdog.runStep2',
      msg: 'auto_escalate_failed',
      dispatch_id: dispatch.id, err
    });
  }
  // Notify next tier (best effort).
  await safeNotify({
    kind: 'sla_auto_escalate',
    dispatch_id: dispatch.id,
    urgency: dispatch?.triage?.urgency || null,
    sla_step: 2
  });
  return makeHistoryEntry(2, 'auto_escalate_system_ai', success,
    err ? { error: err } : {});
}

// Step 3: SYSTEM_AI auto-assigns DSS top-1 if score >= 0.55.
async function runStep3(dispatch, opts) {
  const units = opts?.unitsModule || await getUnits();
  const dss = opts?.dssModule || await getDss();
  const assignments = opts?.assignmentsModule || await getAssignments();

  const scope = dispatch.caller_scope_path || 'ndma';
  let candidates = [];
  try {
    if (typeof units.listAvailableInScope === 'function') {
      candidates = await units.listAvailableInScope(scope);
    }
  } catch (e) {
    logJson('WARNING', {
      fn: 'tm.watchdog.runStep3',
      msg: 'list_units_failed',
      dispatch_id: dispatch.id, err: String(e?.message || e)
    });
    candidates = [];
  }
  const top = (typeof dss.suggest === 'function' ? dss.suggest(dispatch, candidates, 1) : []) || [];
  const lead = top[0];
  if (!lead || typeof lead.score !== 'number' || lead.score < DSS_MIN_SCORE) {
    return makeHistoryEntry(3, 'auto_assign_skipped_no_candidate', false, {
      top_score: lead?.score ?? null,
      threshold: DSS_MIN_SCORE
    });
  }
  const ts = Math.floor(Date.now() / 1000);
  const target = `dispatch.assign|${dispatch.id}|${lead.unit_id}`;
  const { sig_b64 } = signSystemAction({ action: 'dispatch.assign', target, ts });
  let success = false;
  let err = null;
  try {
    await assignments.assignUnit(systemActor(), dispatch.id, {
      unit_id: lead.unit_id,
      eta_minutes: null,
      note: 'Auto-assigned by Aether watchdog. Top DSS candidate.',
      dss_reasoning: { score: lead.score, reason: lead.reason, distance_km: lead.distance_km }
    }, sig_b64);
    success = true;
  } catch (e) {
    err = String(e?.message || e);
    logJson('WARNING', {
      fn: 'tm.watchdog.runStep3',
      msg: 'auto_assign_failed',
      dispatch_id: dispatch.id, unit_id: lead.unit_id, err
    });
  }
  return makeHistoryEntry(3, 'auto_assign_system_ai', success, {
    unit_id: lead.unit_id,
    score: lead.score,
    reason: lead.reason,
    error: err
  });
}

// Step 4: fan-out broadcast to in-scope responders up to (and including)
// the NDMA tier. We use the dispatch's caller_scope_path subtree as the
// fan-out target. Notifications go through safeNotify.
async function runStep4(dispatch, opts) {
  const fs = opts?.firestore || await getFirestore();
  const scope = dispatch.caller_scope_path || 'ndma';
  let users = [];
  try {
    if (typeof fs.queryDocs === 'function') {
      const upper = scope + '/￿';
      users = await fs.queryDocs('tm_users', [
        { field: 'scope_path', op: '>=', value: scope },
        { field: 'scope_path', op: '<=', value: upper }
      ], { limit: 200 });
    }
  } catch (e) {
    logJson('WARNING', {
      fn: 'tm.watchdog.runStep4',
      msg: 'fanout_query_failed',
      dispatch_id: dispatch.id, err: String(e?.message || e)
    });
  }
  let sent = 0;
  for (const row of (users || [])) {
    const uid = row?.id || row?.data?.uid;
    if (!uid) continue;
    if (uid === dispatch.caller_uid) continue;
    const ok = await safeNotify({
      kind: 'sla_fanout',
      to_uid: uid,
      dispatch_id: dispatch.id,
      urgency: dispatch?.triage?.urgency || null,
      sla_step: 4
    });
    if (ok) sent++;
  }
  return makeHistoryEntry(4, 'fanout_broadcast', sent > 0, {
    recipients: sent,
    scope
  });
}

// Decide whether to skip step 1 and jump to step 2 because no in-scope
// supervisor presence exists. Returns { skip: bool, c2_compromised: bool,
// presence_count: number|null }.
async function evaluateC2(dispatch, opts) {
  const urgency = String(dispatch?.triage?.urgency || '').toUpperCase();
  const slaSecs = slaSecondsFor(urgency);
  const cutoff = new Date(Date.now() - slaSecs * 1000 * C2_PRESENCE_GRACE_MULT).toISOString();
  const scope = dispatch.caller_scope_path || 'ndma';
  const presence = await readPresenceCount(scope, cutoff, opts);
  if (presence === 0) {
    return { skip: true, c2_compromised: true, presence_count: 0 };
  }
  return { skip: false, c2_compromised: false, presence_count: presence };
}

// Compute the ISO timestamp at which the *next* tick should fire, given
// the just-completed step and the dispatch's urgency.
function nextFireAtIso(dispatch, justCompletedStep) {
  const secs = slaSecondsFor(dispatch?.triage?.urgency);
  const multiplier = (
    justCompletedStep === 1 ? 1 :
    justCompletedStep === 2 ? 2 :
    justCompletedStep === 3 ? 4 :
    1);
  const fireAtMs = Date.now() + secs * multiplier * 1000;
  return new Date(fireAtMs).toISOString();
}

// Main tick handler. Called by /api/v1/internal/sla_tick. Body shape:
//   { dispatch_id, scheduled_for, step }
// `opts` carries the optional firestore / module overrides for tests.
async function handleSlaTick(body, opts = {}) {
  if (!body || typeof body !== 'object') {
    return { ok: false, status: 400, code: 'bad_request' };
  }
  const dispatchId = String(body.dispatch_id || '');
  const step = Number(body.step);
  if (!dispatchId) return { ok: false, status: 400, code: 'bad_request' };
  if (!Number.isInteger(step) || step < 0 || step > STEP_MAX) {
    return { ok: false, status: 400, code: 'bad_step' };
  }

  const fs = opts.firestore || await getFirestore();
  const dispatch = await fs.getDoc('tm_dispatches', dispatchId);
  if (!dispatch) return { ok: false, status: 404, code: 'dispatch_not_found' };
  dispatch.id = dispatchId;

  // Bail out if the dispatch has moved past `received` (a human or a
  // prior SYSTEM_AI step has done the work).
  const workerStatus = String(dispatch.worker_status || 'received');
  if (workerStatus !== 'received' && workerStatus !== 'under_review') {
    return { ok: true, status: 200, code: 'noop_worker_advanced', worker_status: workerStatus };
  }

  // Probe / refresh autonomous-mode flag every minute.
  await probeAutonomousMode(opts);

  // Compute current step from history if disagreeing with body.step. The
  // body is the scheduled rung; the persisted sla_step is authoritative
  // when a parallel tick somehow arrived earlier.
  const persistedStep = Number(dispatch.sla_step) || 0;
  const targetStep = Math.max(persistedStep, step) + 1;
  if (targetStep > STEP_MAX) {
    return { ok: true, status: 200, code: 'noop_ladder_exhausted' };
  }

  let history = Array.isArray(dispatch.sla_history) ? dispatch.sla_history.slice() : [];
  let extraPatch = {};
  let actualStep = targetStep;

  // C2 detection only matters when stepping into rung 1.
  if (actualStep === 1) {
    const c2 = await evaluateC2(dispatch, opts);
    if (c2.c2_compromised) {
      history = appendSlaHistory(history, makeHistoryEntry(1, 'skip_no_presence', false, {
        presence_count: c2.presence_count
      }));
      extraPatch.c2_compromised = true;
      actualStep = 2;
    }
  }

  // Autonomous mode shortcut: jump to step 3 for CRITICAL dispatches.
  if (_autonomousMode && actualStep < 3
      && String(dispatch?.triage?.urgency || '').toUpperCase() === 'CRITICAL') {
    history = appendSlaHistory(history, makeHistoryEntry(actualStep, 'autonomous_mode_skip', false, {
      from_step: actualStep, to_step: 3
    }));
    actualStep = 3;
  }

  let entry;
  if (actualStep === 1) {
    entry = await runStep1(dispatch, opts);
  } else if (actualStep === 2) {
    entry = await runStep2(dispatch, opts);
  } else if (actualStep === 3) {
    entry = await runStep3(dispatch, opts);
    // Step 3 with no candidate -> immediately escalate to step 4 in the
    // same tick rather than waiting another SLA window.
    if (!entry.success && entry.action === 'auto_assign_skipped_no_candidate') {
      history = appendSlaHistory(history, entry);
      const nextEntry = await runStep4(dispatch, opts);
      history = appendSlaHistory(history, nextEntry);
      const finalPatch = {
        sla_step: 4,
        sla_history: history,
        ...extraPatch
      };
      await patchSlaState(dispatchId, finalPatch, opts);
      return { ok: true, status: 200, step_executed: 4, history_appended: 2, patch: finalPatch };
    }
  } else if (actualStep === 4) {
    entry = await runStep4(dispatch, opts);
  } else {
    entry = makeHistoryEntry(actualStep, 'unknown_step', false);
  }

  history = appendSlaHistory(history, entry);
  const patch = {
    sla_step: actualStep,
    sla_history: history,
    ...extraPatch
  };
  await patchSlaState(dispatchId, patch, opts);

  // Schedule the next tick for the next rung if we have not exhausted
  // the ladder. Step 4 schedules one final retry then stops.
  if (actualStep < STEP_MAX) {
    const fireAt = nextFireAtIso(dispatch, actualStep);
    await scheduleSlaTick(dispatchId, fireAt, actualStep + 1);
  }
  return { ok: true, status: 200, step_executed: actualStep, history_appended: 1, patch };
}

export {
  // Exported scheduling + SLA helpers.
  scheduleSlaTick,
  computeSlaDeadlineIso,
  slaSecondsFor,
  taskNameFor,
  signCallback,
  verifyCallbackSig,

  // Tick callback handler used by the router.
  handleSlaTick,

  // SYSTEM_AI sig path.
  signSystemAction,
  verifySystemAction,
  systemActor,
  getSystemPubB64,
  isSystemKeyEphemeral,
  SYSTEM_AI_UID,
  SYSTEM_AI_KEY_ID,

  // Autonomous-mode hooks.
  isAutonomousMode,
  probeAutonomousMode,
  clearAutonomousModeIfNdma,

  // Test seams.
  setCloudTasksClient,
  _setFirestoreForTest,
  _setUsersForTest,
  _setDispatchesForTest,
  _setAssignmentsForTest,
  _setDssForTest,
  _setUnitsForTest,
  _setNotifyForTest,
  _setAutonomousModeForTest,
  _resetForTest,

  // Constants for tests.
  SLA_SECS,
  DSS_MIN_SCORE,
  STEP_MAX
};
