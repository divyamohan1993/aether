// survivor-anon lane.
//
// Anonymous SOS pipeline for the rubble protocol. No login, no keypair,
// no challenge. A trapped survivor can post a heartbeat (panic codes,
// last-known geo, battery, signal, motion) and the server keeps the
// thread, escalates a tm_dispatches row when something changes, and
// rejects abuse with token-bucket caps per /24 subnet.
//
// Optional audio: a POST with Content-Type: audio/* runs through the
// same Vertex triage pipeline; the synthesized triage is then merged
// into the survivor thread.
//
// Wire format (heartbeat body, ~80-150 B JSON):
//   { fp, seq, ts, codes:[1..12], geo:[lat,lng,acc]|null,
//     bat, sig, rssi?, tap, motion }

import { createHash, createHmac, timingSafeEqual, randomUUID } from 'node:crypto';

import * as fsMod from './firestore.js';
import * as criticalityMod from './criticality.js';
import * as dedupeMod from './dedupe.js';

// ---------------------------------------------------------------------------
// Test injection seams. Production binds these to the live modules.
// ---------------------------------------------------------------------------
let _setDoc = (...a) => fsMod.setDoc(...a);
let _getDoc = (...a) => fsMod.getDoc(...a);
let _patchDoc = (...a) => fsMod.patchDoc(...a);

export function _setFirestoreForTest(stub) {
  if (stub && typeof stub === 'object') {
    if (typeof stub.setDoc === 'function') _setDoc = stub.setDoc.bind(stub);
    if (typeof stub.getDoc === 'function') _getDoc = stub.getDoc.bind(stub);
    if (typeof stub.patchDoc === 'function') _patchDoc = stub.patchDoc.bind(stub);
  } else {
    _setDoc = (...a) => fsMod.setDoc(...a);
    _getDoc = (...a) => fsMod.getDoc(...a);
    _patchDoc = (...a) => fsMod.patchDoc(...a);
  }
}

// ---------------------------------------------------------------------------
// Phone fingerprint. Stable per (UA, accept-language, permissions-policy).
// 10 hex chars (40 bits) is enough to keep collisions rare across the
// few-million-survivor scale of a single event without leaking identity.
// ---------------------------------------------------------------------------
const FP_NAMESPACE = 'aether-survivor-fp-v1';
const FP_PREFIX = 'survivor-';

export function phoneFingerprint(headers) {
  const h = headers || {};
  const ua = String(h['user-agent'] || h['User-Agent'] || '').slice(0, 512);
  const lang = String(h['accept-language'] || h['Accept-Language'] || '').slice(0, 256);
  const ppRaw = h['permissions-policy'] || h['Permissions-Policy'] || '';
  const ppHash = createHash('sha256').update(String(ppRaw)).digest('hex').slice(0, 16);
  const fp10 = createHash('sha256')
    .update(FP_NAMESPACE).update('|')
    .update(ua).update('|')
    .update(lang).update('|')
    .update(ppHash)
    .digest('hex')
    .slice(0, 10);
  return FP_PREFIX + fp10;
}

const FP_RE = /^survivor-[0-9a-f]{10}$/;
export function isValidFingerprint(fp) {
  return typeof fp === 'string' && FP_RE.test(fp);
}

// ---------------------------------------------------------------------------
// Body validator. Strict shape; reject anything off-script.
// ---------------------------------------------------------------------------
const SIG_VALUES = new Set(['slow-2g', '2g', '3g', '4g', '5g', 'wifi', 'unknown']);
const MAX_CODES_PER_BEAT = 24;
const MAX_TAP = 10000;
const MAX_MOTION = 200;
const MAX_TS_SKEW_S = 300;

export function validateAnonBody(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { ok: false, reason: 'body_not_object' };
  }
  if (!isValidFingerprint(body.fp)) return { ok: false, reason: 'fp_invalid' };
  if (!Number.isInteger(body.seq) || body.seq < 0 || body.seq > 1e9) {
    return { ok: false, reason: 'seq_invalid' };
  }
  if (!Number.isInteger(body.ts) || body.ts < 1700000000 || body.ts > 4102444800) {
    return { ok: false, reason: 'ts_invalid' };
  }
  // ts is wall-clock; the survivor's phone may have skewed clocks. We do
  // not reject on skew here so a stuck-at-boot phone can still send. The
  // server's own ts is the audit timestamp.
  if (!Array.isArray(body.codes) || body.codes.length > MAX_CODES_PER_BEAT) {
    return { ok: false, reason: 'codes_invalid' };
  }
  for (const c of body.codes) {
    if (!Number.isInteger(c) || c < 1 || c > 12) return { ok: false, reason: 'code_out_of_range' };
  }
  if (body.geo !== null && body.geo !== undefined) {
    if (!Array.isArray(body.geo) || body.geo.length !== 3) return { ok: false, reason: 'geo_shape' };
    const [la, ln, ac] = body.geo;
    if (typeof la !== 'number' || !Number.isFinite(la) || la < -90 || la > 90) return { ok: false, reason: 'lat_invalid' };
    if (typeof ln !== 'number' || !Number.isFinite(ln) || ln < -180 || ln > 180) return { ok: false, reason: 'lng_invalid' };
    if (typeof ac !== 'number' || !Number.isFinite(ac) || ac < 0 || ac > 100000) return { ok: false, reason: 'acc_invalid' };
  }
  if (!Number.isInteger(body.bat) || body.bat < 0 || body.bat > 100) {
    return { ok: false, reason: 'bat_invalid' };
  }
  if (typeof body.sig !== 'string' || !SIG_VALUES.has(body.sig)) {
    return { ok: false, reason: 'sig_invalid' };
  }
  if (body.rssi !== undefined && body.rssi !== null) {
    if (!Number.isInteger(body.rssi) || body.rssi < -150 || body.rssi > 0) {
      return { ok: false, reason: 'rssi_invalid' };
    }
  }
  if (!Number.isInteger(body.tap) || body.tap < 0 || body.tap > MAX_TAP) {
    return { ok: false, reason: 'tap_invalid' };
  }
  if (typeof body.motion !== 'number' || !Number.isFinite(body.motion) || body.motion < 0 || body.motion > MAX_MOTION) {
    return { ok: false, reason: 'motion_invalid' };
  }
  // Reject any field outside the documented set so a future schema bump
  // does not silently accept stale clients.
  const allowed = new Set(['fp', 'seq', 'ts', 'codes', 'geo', 'bat', 'sig', 'rssi', 'tap', 'motion']);
  for (const k of Object.keys(body)) {
    if (!allowed.has(k)) return { ok: false, reason: `unexpected_field_${k}` };
  }
  void MAX_TS_SKEW_S;
  return { ok: true };
}

// ---------------------------------------------------------------------------
// /24 subnet from IPv4 or IPv6. For IPv6 we use the /48 (the closest
// rough equivalent for abuse aggregation). Anything unparseable falls
// back to the raw string.
// ---------------------------------------------------------------------------
export function subnet24(ip) {
  if (typeof ip !== 'string' || ip.length === 0) return 'unknown';
  const v6map = ip.startsWith('::ffff:') ? ip.slice(7) : ip;
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(v6map)) {
    const parts = v6map.split('.');
    return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
  }
  if (ip.includes(':')) {
    const groups = ip.split(':').slice(0, 3).map((g) => g || '0');
    return `${groups.join(':')}::/48`;
  }
  return ip + '/?';
}

// ---------------------------------------------------------------------------
// NDMA event token. HMAC over `${zone_id}|${valid_until_iso}` using
// NDMA_EVENT_HMAC_SECRET. Token wire format (single base64url string):
//   base64url(`${zone_id}|${valid_until_iso}|${sig_b64u}`)
// Lifts caps to 200/min for the matching subnet.
// ---------------------------------------------------------------------------
function eventSecret() {
  return process.env.NDMA_EVENT_HMAC_SECRET || '';
}

export function mintEventToken(zoneId, validUntilIso) {
  const secret = eventSecret();
  if (!secret) throw new Error('NDMA_EVENT_HMAC_SECRET not set');
  const payload = `${zoneId}|${validUntilIso}`;
  const sig = createHmac('sha256', secret).update(payload).digest('base64')
    .replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  const wire = `${payload}|${sig}`;
  return Buffer.from(wire, 'utf8').toString('base64url');
}

export function verifyEventToken(token) {
  if (typeof token !== 'string' || token.length === 0 || token.length > 1024) return null;
  const secret = eventSecret();
  if (!secret) return null;
  let raw;
  try {
    raw = Buffer.from(token, 'base64url').toString('utf8');
  } catch {
    return null;
  }
  const parts = raw.split('|');
  if (parts.length !== 3) return null;
  const [zoneId, validUntilIso, sigB64u] = parts;
  if (!zoneId || zoneId.length > 128) return null;
  const validUntilMs = Date.parse(validUntilIso);
  if (!Number.isFinite(validUntilMs)) return null;
  if (Date.now() > validUntilMs) return null;
  const expect = createHmac('sha256', secret).update(`${zoneId}|${validUntilIso}`).digest();
  let got;
  try {
    const norm = sigB64u.replace(/-/g, '+').replace(/_/g, '/');
    got = Buffer.from(norm, 'base64');
  } catch {
    return null;
  }
  if (got.length !== expect.length) return null;
  if (!timingSafeEqual(got, expect)) return null;
  return { zone_id: zoneId, valid_until: validUntilIso };
}

// ---------------------------------------------------------------------------
// Rate limiter. Per /24 subnet. Token-bucket on three windows:
//   minute: 3 baseline, 200 with valid event token.
//   hour:   50 baseline.
//   day:    500 baseline.
// In-memory; resets per cold start. The map evicts the oldest 10% when
// it exceeds MAX_BUCKETS.
// ---------------------------------------------------------------------------
const MIN_BASE = 3;
const MIN_EVENT = 200;
const HOUR_BASE = 50;
const DAY_BASE = 500;
const MAX_BUCKETS = 50000;

const sosBuckets = new Map();

export function _resetRateLimitForTest() { sosBuckets.clear(); }

function evictIfNeeded() {
  if (sosBuckets.size < MAX_BUCKETS) return;
  const drop = Math.floor(MAX_BUCKETS / 10);
  const it = sosBuckets.keys();
  for (let i = 0; i < drop; i++) {
    const { value, done } = it.next();
    if (done) break;
    sosBuckets.delete(value);
  }
}

export function enforceRateLimit(ip, fp, opts) {
  const subnet = subnet24(ip);
  const now = Date.now();
  let b = sosBuckets.get(subnet);
  const minuteCap = opts?.eventToken ? MIN_EVENT : MIN_BASE;
  if (!b) {
    evictIfNeeded();
    b = { mTok: minuteCap, mAt: now, hTok: HOUR_BASE, hAt: now, dTok: DAY_BASE, dAt: now };
    sosBuckets.set(subnet, b);
  }
  // Refill.
  const mEl = (now - b.mAt) / 60_000;
  b.mTok = Math.min(minuteCap, b.mTok + mEl * minuteCap);
  b.mAt = now;
  const hEl = (now - b.hAt) / 3_600_000;
  b.hTok = Math.min(HOUR_BASE, b.hTok + hEl * HOUR_BASE);
  b.hAt = now;
  const dEl = (now - b.dAt) / 86_400_000;
  b.dTok = Math.min(DAY_BASE, b.dTok + dEl * DAY_BASE);
  b.dAt = now;
  if (b.mTok < 1) {
    return { ok: false, retryAfter: Math.max(1, Math.ceil((1 - b.mTok) * 60 / minuteCap)), reason: 'minute', subnet };
  }
  if (b.hTok < 1) return { ok: false, retryAfter: 600, reason: 'hour', subnet };
  if (b.dTok < 1) return { ok: false, retryAfter: 3600, reason: 'day', subnet };
  b.mTok -= 1;
  b.hTok -= 1;
  b.dTok -= 1;
  void fp;
  return { ok: true, subnet };
}

// ---------------------------------------------------------------------------
// Panic-code semantics. Each code maps to (urgency contribution, victim
// condition flags, optional people delta, environmental hazard flag).
// The synthesized triage feeds the existing criticality scorer so the
// dispatcher's pending-review queue surfaces survivor threads alongside
// authenticated ones.
// ---------------------------------------------------------------------------
const PANIC_CODES = {
  1:  { name: 'trapped_alive',        urgency: 'HIGH',     flags: [],                      people: 1, hazard: null },
  2:  { name: 'injured_conscious',    urgency: 'HIGH',     flags: ['conscious_ambulatory', 'bleeding'], people: 1, hazard: null },
  3:  { name: 'multiple_people',      urgency: 'HIGH',     flags: [],                      people: 3, hazard: null },
  4:  { name: 'cannot_move',          urgency: 'CRITICAL', flags: ['crush_extracted'],     people: 1, hazard: null },
  5:  { name: 'breathing_difficulty', urgency: 'CRITICAL', flags: ['breathing_difficulty'],people: 1, hazard: null },
  6:  { name: 'no_food_water',        urgency: 'MEDIUM',   flags: [],                      people: 1, hazard: null },
  7:  { name: 'need_medical',         urgency: 'HIGH',     flags: ['bleeding'],            people: 1, hazard: null },
  8:  { name: 'hear_rescuers',        urgency: 'MEDIUM',   flags: [],                      people: 1, hazard: null },
  9:  { name: 'building_stable',      urgency: 'LOW',      flags: [],                      people: 1, hazard: null },
  10: { name: 'building_failing',     urgency: 'CRITICAL', flags: [],                      people: 1, hazard: 'building_collapse' },
  11: { name: 'water_rising',         urgency: 'CRITICAL', flags: [],                      people: 1, hazard: 'flood' },
  12: { name: 'fire_nearby',          urgency: 'CRITICAL', flags: [],                      people: 1, hazard: 'fire' }
};

const URGENCY_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNCLEAR: 0 };

export function synthTriageFromCodes(codes, opts) {
  const seen = new Set();
  let urgency = 'UNCLEAR';
  let people = 1;
  const flags = new Set();
  let incidentType = 'unknown';
  const codeNames = [];
  for (const c of (codes || [])) {
    const meta = PANIC_CODES[c];
    if (!meta) continue;
    seen.add(c);
    codeNames.push(meta.name);
    if (URGENCY_ORDER[meta.urgency] > URGENCY_ORDER[urgency]) urgency = meta.urgency;
    if (meta.people > people) people = meta.people;
    for (const f of meta.flags) flags.add(f);
    if (meta.hazard && incidentType === 'unknown') incidentType = meta.hazard;
  }
  const langHint = opts?.lang_hint || null;
  const summaryParts = ['Anonymous survivor heartbeat.'];
  if (codeNames.length > 0) summaryParts.push('Codes: ' + codeNames.join(', ') + '.');
  if (opts?.audioTranscriptionEnglish) summaryParts.push(opts.audioTranscriptionEnglish);
  const triage = {
    urgency,
    language_detected: langHint || 'unknown',
    transcription_native: opts?.audioTranscriptionNative || '',
    transcription_english: opts?.audioTranscriptionEnglish || codeNames.join(' ') || 'panic codes only',
    people_affected: people,
    injuries: Array.from(flags),
    needs: ['search_and_rescue'],
    location_clues: [],
    ambient_audio: [],
    summary_for_dispatch: summaryParts.join(' ').slice(0, 480),
    confidence: opts?.confidence ?? 0.4,
    caller_state: 'panicked',
    incident_type: incidentType,
    victims: [{
      age_band: 'adult',
      condition_flags: Array.from(flags),
      count: people
    }]
  };
  return { triage, codeCount: seen.size };
}

// ---------------------------------------------------------------------------
// recordHeartbeat. Upsert tm_survivor_threads/{fp}.
// Returns { thread, isNew, statusChanged }.
// ---------------------------------------------------------------------------
const COLLECTION = 'tm_survivor_threads';
const MAX_HISTORY = 30;

function uniqueIntCodes(arr) {
  const out = [];
  const seen = new Set();
  for (const v of (arr || [])) {
    if (!Number.isInteger(v) || v < 1 || v > 12 || seen.has(v)) continue;
    seen.add(v);
    out.push(v);
  }
  return out;
}

function meaningfulChange(prev, next) {
  // First contact is always meaningful.
  if (!prev) return true;
  // New panic codes added.
  const before = new Set(prev.codes || []);
  for (const c of (next.codes || [])) {
    if (!before.has(c)) return true;
  }
  // Battery dropped below 5%.
  if (typeof next.bat === 'number' && next.bat <= 5
      && (typeof prev.bat !== 'number' || prev.bat > 5)) return true;
  // Geo moved more than 100 m.
  if (next.geo && prev.geo) {
    const d = dedupeMod.haversineMeters(
      { lat: next.geo[0], lng: next.geo[1] },
      { lat: prev.geo[0], lng: prev.geo[1] }
    );
    if (Number.isFinite(d) && d >= 100) return true;
  }
  // First geo fix arrived.
  if (next.geo && !prev.geo) return true;
  // Long heartbeat gap. The watchdog cares about presence; a renewed
  // beat after >5 min is notable.
  if (prev.last_seen_at) {
    const gap = Date.now() - Date.parse(prev.last_seen_at);
    if (gap > 5 * 60_000) return true;
  }
  return false;
}

export async function recordHeartbeat(fp, body, ip) {
  if (!isValidFingerprint(fp)) {
    throw new Error('fp_invalid');
  }
  const subnet = subnet24(ip);
  const nowIso = new Date().toISOString();
  const cleanCodes = uniqueIntCodes(body.codes);
  const prev = await _getDoc(COLLECTION, fp).catch(() => null);
  const next = {
    fp,
    last_seen_at: nowIso,
    last_seq: body.seq,
    codes: prev ? Array.from(new Set([...(prev.codes || []), ...cleanCodes])) : cleanCodes,
    geo: body.geo || prev?.geo || null,
    geo_at: body.geo ? nowIso : (prev?.geo_at || null),
    bat: body.bat,
    sig: body.sig,
    rssi: typeof body.rssi === 'number' ? body.rssi : null,
    tap_total: (prev?.tap_total || 0) + (Number.isInteger(body.tap) ? body.tap : 0),
    motion_last: body.motion,
    ip_subnet24: subnet,
    bat_history: (prev?.bat_history || []).concat([{ bat: body.bat, ts: nowIso }]).slice(-MAX_HISTORY),
    seq_count: (prev?.seq_count || 0) + 1,
    dispatch_id: prev?.dispatch_id || null
  };
  if (!prev) {
    next.created_at = nowIso;
  } else {
    next.created_at = prev.created_at || nowIso;
  }
  const statusChanged = meaningfulChange(prev, {
    codes: cleanCodes, bat: body.bat, geo: body.geo, last_seen_at: prev?.last_seen_at
  });
  await _setDoc(COLLECTION, fp, next);
  return { thread: next, isNew: !prev, statusChanged };
}

// ---------------------------------------------------------------------------
// escalateToDispatch. Reuses the dedup + criticality pipeline by calling
// directly into the same modules persistDispatch uses. Writes a
// tm_dispatches row tagged caller_tier 10, caller_scope_path
// `survivor/<fp>`, phone_verified false, confidence_band low.
// Returns the dispatch id (existing or newly minted).
// ---------------------------------------------------------------------------
function logJson(severity, fields) {
  const entry = { ts: new Date().toISOString(), severity, ...fields };
  process.stdout.write(JSON.stringify(entry) + '\n');
}

export async function escalateToDispatch(thread, opts) {
  if (!thread || !thread.fp) throw new Error('thread_invalid');
  if (thread.dispatch_id) return { id: thread.dispatch_id, reused: true };
  const id = randomUUID();
  const receivedAt = new Date().toISOString();
  const codes = thread.codes || [];
  const { triage } = synthTriageFromCodes(codes, {
    audioTranscriptionEnglish: opts?.audioTranscriptionEnglish,
    audioTranscriptionNative: opts?.audioTranscriptionNative,
    lang_hint: opts?.lang_hint,
    confidence: opts?.confidence
  });
  let location = null;
  if (Array.isArray(thread.geo) && thread.geo.length === 3) {
    location = { lat: thread.geo[0], lng: thread.geo[1], accuracy_m: thread.geo[2], source: 'cached' };
  }
  let geohash7 = null;
  let transcript_minhash_b64 = null;
  let cluster_id = id;
  let cluster_role = 'primary';
  let cluster_primary_id = null;
  let cluster_match_score = null;
  let cluster_match_reasons = null;
  try {
    if (location && Number.isFinite(location.lat) && Number.isFinite(location.lng)) {
      geohash7 = dedupeMod.geohash7(location.lat, location.lng);
    }
    transcript_minhash_b64 = dedupeMod.transcriptMinHash(triage.transcription_english || '', 64);
    if (geohash7) {
      const match = await dedupeMod.findCluster(
        { id, geohash7, location, triage, transcript_minhash_b64 },
        { firestoreModule: fsMod, nowMs: Date.now() }
      );
      if (match) {
        cluster_id = match.cluster_id;
        cluster_role = 'duplicate';
        cluster_primary_id = match.cluster_primary_id;
        cluster_match_score = match.match_score;
        cluster_match_reasons = match.match_reasons;
      }
    }
  } catch (e) {
    logJson('WARNING', { fn: 'anon.escalateToDispatch', msg: 'dedupe_failed', err: String(e), fp: thread.fp });
  }
  let criticality_score = 0;
  let criticality_breakdown = null;
  try {
    const r = criticalityMod.criticalityScore(triage, receivedAt, Date.now());
    criticality_score = r.score;
    criticality_breakdown = r.breakdown;
  } catch (e) {
    logJson('WARNING', { fn: 'anon.escalateToDispatch', msg: 'criticality_failed', err: String(e), fp: thread.fp });
  }
  const callerScopePath = `survivor/${thread.fp}`;
  const doc = {
    id,
    received_at: receivedAt,
    request_id: opts?.requestId || null,
    caller_uid: thread.fp,
    caller_parent_uid: null,
    caller_email: null,
    caller_name: null,
    caller_tier: 10,
    caller_scope_path: callerScopePath,
    caller_identity: {
      msisdn_e164: null,
      phone_verified: false,
      verification_channel: 'anon',
      fingerprint: thread.fp,
      ip_subnet24: thread.ip_subnet24 || null
    },
    phone_verified: false,
    confidence_band: 'low',
    location,
    triage,
    audio_bytes: opts?.audioBytes || 0,
    audio_mime: opts?.audioMime || null,
    network: thread.sig || null,
    battery: typeof thread.bat === 'number' ? thread.bat : null,
    client_timestamp: null,
    lang_hint: opts?.lang_hint || null,
    latency_ms: opts?.latencyMs || 0,
    ip: opts?.ip || null,
    escalation_status: 'pending_review',
    requires_review: true,
    escalation_chain: [],
    policy_at_capture: 'manual_review',
    assignments: [],
    worker_status: 'received',
    worker_status_history: [{ status: 'received', ts: receivedAt }],
    worker_summary_text: 'Anonymous survivor heartbeat. Dispatcher reviewing now.',
    criticality_score,
    criticality_breakdown,
    geohash7,
    transcript_minhash_b64,
    cluster_id,
    cluster_role,
    cluster_primary_id,
    cluster_match_score,
    cluster_match_reasons,
    sla_deadline_at: null,
    sla_seconds: null,
    sla_step: 0,
    sla_history: [],
    c2_compromised: false,
    panic_codes: codes.slice(),
    noise_gate: codes.length > 0 ? 'panic_code_pass' : 'failed',
    pattern_anomaly: false,
    geo_anomaly: false,
    created_at: new Date()
  };
  await _setDoc('tm_dispatches', id, doc);
  // Bind the dispatch back onto the thread so subsequent heartbeats
  // know not to mint a second row. patchDoc keeps the rest of the
  // thread intact.
  try {
    await _patchDoc(COLLECTION, thread.fp, { dispatch_id: id, escalated_at: receivedAt });
  } catch (e) {
    logJson('WARNING', { fn: 'anon.escalateToDispatch', msg: 'thread_bind_failed', err: String(e), fp: thread.fp });
  }
  return { id, reused: false, criticality_score, cluster_role, cluster_id };
}

// ---------------------------------------------------------------------------
// internals exposed for tests
// ---------------------------------------------------------------------------
export const _internal = {
  PANIC_CODES,
  COLLECTION,
  FP_PREFIX,
  MIN_BASE,
  MIN_EVENT,
  HOUR_BASE,
  DAY_BASE,
  meaningfulChange,
  uniqueIntCodes
};
