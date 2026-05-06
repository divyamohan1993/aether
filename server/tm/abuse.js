// phone-identity lane: misuse detection + DM Act § 54 forwarding.
//
// Aether never refuses to triage. Every SOS reaches Vertex; the cost
// of refusing a real SOS misclassified as fake outweighs the cost of
// triaging a fake. This module produces flags that the dispatcher UI
// surfaces and that flow to the daily false-alarm review queue.
//
// Flags:
//   frequency_anomaly  ->  same fingerprint > 3 / hour
//   geo_anomaly        ->  same fingerprint > 50 km within 5 min
//   noise_gate         ->  passed unless none of the disaster signals
//                          are present (keyword, audio energy, panic
//                          code, urgency >= HIGH)
//
// forwardToPolice writes one row to tm_false_alarm_review per
// (date, dispatch_id) pair. § 54 of the Disaster Management Act 2005
// vests the prosecution decision in the police, not in Aether.

import * as firestoreMod from './firestore.js';

const FREQ_WINDOW_DEFAULT_MS = 60 * 60 * 1000;
const FREQ_THRESHOLD = 3;
const GEO_WINDOW_MS = 5 * 60 * 1000;
const GEO_THRESHOLD_M = 50_000;

let _fs = firestoreMod;

export function _setFirestoreForTest(stub) { _fs = stub || firestoreMod; }

// Disaster keywords cleared for the noise gate. Matched as whole
// words against transcription_english. Case-insensitive.
const DISASTER_KEYWORDS = [
  'help', 'sos', 'trapped', 'stuck', 'fire', 'flood', 'flooding', 'landslide',
  'collapse', 'collapsed', 'drowning', 'drown', 'blood', 'bleeding', 'injured',
  'unconscious', 'rescue', 'evacuate', 'evacuation', 'emergency', 'crush',
  'crushed', 'rubble', 'debris', 'earthquake', 'tremor', 'cyclone', 'storm',
  'tsunami', 'flames', 'smoke', 'medical', 'ambulance', 'choking', 'breathing',
  'suffocating'
];

const KEYWORD_RE = new RegExp('\\b(' + DISASTER_KEYWORDS.join('|') + ')\\b', 'i');

function logJson(severity, fields) {
  const entry = { ts: new Date().toISOString(), severity, ...fields };
  process.stdout.write(JSON.stringify(entry) + '\n');
}

function haversineMeters(a, b) {
  const lat1 = Number(a?.lat); const lng1 = Number(a?.lng);
  const lat2 = Number(b?.lat); const lng2 = Number(b?.lng);
  if (!Number.isFinite(lat1) || !Number.isFinite(lng1)
      || !Number.isFinite(lat2) || !Number.isFinite(lng2)) return null;
  const R = 6371000;
  const toRad = (d) => d * Math.PI / 180;
  const dLat = toRad(lat2 - lat1);
  const dLng = toRad(lng2 - lng1);
  const s1 = Math.sin(dLat / 2);
  const s2 = Math.sin(dLng / 2);
  const h = s1 * s1 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * s2 * s2;
  return 2 * R * Math.asin(Math.min(1, Math.sqrt(h)));
}

export async function checkFrequencyAnomaly(fp, since_ms = FREQ_WINDOW_DEFAULT_MS) {
  if (typeof fp !== 'string' || fp.length === 0) {
    return { flagged: false, count: 0, threshold: FREQ_THRESHOLD, window_ms: since_ms, reason: 'no_fp' };
  }
  const sinceIso = new Date(Date.now() - since_ms).toISOString();
  let rows;
  try {
    rows = await _fs.queryDocs('tm_dispatches', [
      { field: 'caller_identity.fingerprint', op: '==', value: fp },
      { field: 'received_at', op: '>=', value: sinceIso }
    ], { limit: 50 });
  } catch (e) {
    logJson('WARNING', {
      fn: 'tm.abuse.checkFrequencyAnomaly',
      msg: 'query_failed', err: String(e?.message || e)
    });
    return { flagged: false, count: 0, threshold: FREQ_THRESHOLD, window_ms: since_ms, reason: 'query_error' };
  }
  const count = Array.isArray(rows) ? rows.length : 0;
  return {
    flagged: count > FREQ_THRESHOLD,
    count,
    threshold: FREQ_THRESHOLD,
    window_ms: since_ms
  };
}

export async function checkGeoImpossibility(fp, new_lat, new_lng) {
  if (typeof fp !== 'string' || fp.length === 0) {
    return { flagged: false, max_distance_m: 0, threshold_m: GEO_THRESHOLD_M, window_ms: GEO_WINDOW_MS, reason: 'no_fp' };
  }
  if (!Number.isFinite(new_lat) || !Number.isFinite(new_lng)) {
    return { flagged: false, max_distance_m: 0, threshold_m: GEO_THRESHOLD_M, window_ms: GEO_WINDOW_MS, reason: 'no_geo' };
  }
  const sinceIso = new Date(Date.now() - GEO_WINDOW_MS).toISOString();
  let rows;
  try {
    rows = await _fs.queryDocs('tm_dispatches', [
      { field: 'caller_identity.fingerprint', op: '==', value: fp },
      { field: 'received_at', op: '>=', value: sinceIso }
    ], { limit: 20 });
  } catch (e) {
    logJson('WARNING', {
      fn: 'tm.abuse.checkGeoImpossibility',
      msg: 'query_failed', err: String(e?.message || e)
    });
    return { flagged: false, max_distance_m: 0, threshold_m: GEO_THRESHOLD_M, window_ms: GEO_WINDOW_MS, reason: 'query_error' };
  }
  let maxDistance = 0;
  for (const r of rows || []) {
    const loc = r.data?.location;
    if (!loc) continue;
    const d = haversineMeters({ lat: new_lat, lng: new_lng }, loc);
    if (d !== null && d > maxDistance) maxDistance = d;
  }
  return {
    flagged: maxDistance > GEO_THRESHOLD_M,
    max_distance_m: Math.round(maxDistance),
    threshold_m: GEO_THRESHOLD_M,
    window_ms: GEO_WINDOW_MS
  };
}

// Synchronous: triage payload is already in memory.
export function checkNoiseGate(triage) {
  const t = triage || {};
  const urgency = String(t.urgency || '').toUpperCase();
  if (urgency === 'CRITICAL' || urgency === 'HIGH') {
    return { passed: true, reason: 'urgency_high' };
  }
  const text = String(t.transcription_english || '');
  if (KEYWORD_RE.test(text)) {
    return { passed: true, reason: 'disaster_keyword' };
  }
  if (Number(t.audio_energy_rms || 0) > 0.05) {
    return { passed: true, reason: 'audio_energy' };
  }
  if (Array.isArray(t.panic_codes) && t.panic_codes.length > 0) {
    return { passed: true, reason: 'panic_code' };
  }
  return { passed: false, reason: 'no_disaster_signal' };
}

// Daily review queue. The doc id is `<YYYY-MM-DD>_<dispatch_id>` so a
// single dispatch is forwarded at most once per day even if multiple
// callers fire-and-forget the same row.
export async function forwardToPolice(dispatch_id, reason) {
  if (typeof dispatch_id !== 'string' || dispatch_id.length === 0) return false;
  const date = new Date().toISOString().slice(0, 10);
  const docId = `${date}_${dispatch_id}`;
  try {
    await _fs.setDoc('tm_false_alarm_review', docId, {
      dispatch_id,
      date,
      reason: String(reason || 'noise_gate_failed'),
      created_at: new Date().toISOString(),
      enforcement_basis: 'DM_Act_2005_S_54'
    });
    return true;
  } catch (e) {
    logJson('WARNING', {
      fn: 'tm.abuse.forwardToPolice',
      msg: 'persist_failed', err: String(e?.message || e)
    });
    return false;
  }
}

export const _internal = {
  DISASTER_KEYWORDS, KEYWORD_RE, haversineMeters,
  FREQ_THRESHOLD, GEO_THRESHOLD_M, GEO_WINDOW_MS
};
