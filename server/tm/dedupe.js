// Dedup clustering for tm_dispatches.
//
// Three primitives:
//   geohash7(lat, lng)         -> 7-char standard geohash prefix
//   transcriptMinHash(text)    -> 64x32-bit MinHash on character bigrams,
//                                 packed as 256 bytes -> base64
//   findCluster(newDispatch)   -> queries recent dispatches in the same
//                                 geohash bucket, returns the best match
//                                 if composite score >= 0.7
//
// Match score: haversine <= 100 m -> 0.4, same incident_type -> 0.2,
// MinHash Jaccard >= 0.4 -> 0.4.

import { createHash } from 'node:crypto';

const GEOHASH_BASE32 = '0123456789bcdefghjkmnpqrstuvwxyz';
const GEOHASH_LEN = 7;

const MINHASH_LEN = 64;
const MINHASH_PRIME = 0xFFFFFFFB;
const MINHASH_MAX = 0xFFFFFFFF;

const MATCH_DISTANCE_M = 100;
const MATCH_INCIDENT = 0.2;
const MATCH_DISTANCE_BONUS = 0.4;
const MATCH_TEXT_BONUS = 0.4;
const MATCH_TEXT_THRESHOLD = 0.4;
const MATCH_THRESHOLD = 0.7;

const RECENT_WINDOW_MS = 15 * 60 * 1000;
const QUERY_LIMIT = 50;
const ACTIVE_WORKER_STATUSES_EXCLUDED = new Set(['resolved', 'cancelled']);

// ---------------------------------------------------------------------------
// Geohash. Standard interleave-bits-per-char encoder. Returns a 7-char
// string from the base32 ghs alphabet. Bounds-checked.
// ---------------------------------------------------------------------------
export function geohash7(lat, lng) {
  const la = Number(lat);
  const ln = Number(lng);
  if (!Number.isFinite(la) || !Number.isFinite(ln)) return null;
  if (la < -90 || la > 90 || ln < -180 || ln > 180) return null;
  let latLo = -90, latHi = 90, lngLo = -180, lngHi = 180;
  let bits = 0, bitCount = 0, even = true;
  let out = '';
  while (out.length < GEOHASH_LEN) {
    if (even) {
      const mid = (lngLo + lngHi) / 2;
      if (ln >= mid) { bits = (bits << 1) | 1; lngLo = mid; }
      else { bits = (bits << 1); lngHi = mid; }
    } else {
      const mid = (latLo + latHi) / 2;
      if (la >= mid) { bits = (bits << 1) | 1; latLo = mid; }
      else { bits = (bits << 1); latHi = mid; }
    }
    even = !even;
    bitCount++;
    if (bitCount === 5) {
      out += GEOHASH_BASE32[bits];
      bits = 0;
      bitCount = 0;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Haversine distance in meters between two {lat, lng} points.
// ---------------------------------------------------------------------------
export function haversineMeters(a, b) {
  const lat1 = Number(a?.lat), lng1 = Number(a?.lng);
  const lat2 = Number(b?.lat), lng2 = Number(b?.lng);
  if (!Number.isFinite(lat1) || !Number.isFinite(lng1) || !Number.isFinite(lat2) || !Number.isFinite(lng2)) return null;
  const R = 6371000;
  const toRad = (d) => d * Math.PI / 180;
  const dLat = toRad(lat2 - lat1);
  const dLng = toRad(lng2 - lng1);
  const s1 = Math.sin(dLat / 2);
  const s2 = Math.sin(dLng / 2);
  const h = s1 * s1 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * s2 * s2;
  return 2 * R * Math.asin(Math.min(1, Math.sqrt(h)));
}

// ---------------------------------------------------------------------------
// MinHash on character bigrams.
//
// Each token (a 2-character bigram of the lowercased, whitespace-collapsed
// English transcript) is hashed by a deterministic family of 64 hash
// functions: h_i(token) = (a_i * baseHash(token) + b_i) mod prime, where
// baseHash is the first 4 bytes of SHA-256(token) interpreted as a uint32
// and (a_i, b_i) are derived from SHA-256("minhash-coeff-<i>").
//
// The signature is the per-slot minimum across all tokens. Empty input
// produces a zero-filled signature (all zeros), which yields Jaccard 1.0
// against another empty signature and 0 against any non-empty signature.
// ---------------------------------------------------------------------------
const MINHASH_COEFFS = (() => {
  const a = new Uint32Array(MINHASH_LEN);
  const b = new Uint32Array(MINHASH_LEN);
  for (let i = 0; i < MINHASH_LEN; i++) {
    const h = createHash('sha256').update(`minhash-coeff-${i}`).digest();
    a[i] = (h.readUInt32BE(0) % (MINHASH_PRIME - 1)) + 1;
    b[i] = h.readUInt32BE(4) % MINHASH_PRIME;
  }
  return { a, b };
})();

function tokenize(text) {
  const s = String(text || '').toLowerCase().replace(/\s+/g, ' ').trim();
  if (s.length < 2) return [];
  const set = new Set();
  for (let i = 0; i < s.length - 1; i++) set.add(s.slice(i, i + 2));
  return Array.from(set);
}

function tokenHashU32(token) {
  const h = createHash('sha256').update(token).digest();
  return h.readUInt32BE(0);
}

// 32-bit safe (a*x + b) mod p without losing precision. Splits a into
// high and low 16-bit halves so the products stay below 2^53.
function modMulAdd(a, x, b, p) {
  const aHi = Math.floor(a / 65536);
  const aLo = a % 65536;
  const lo = (aLo * x) % p;
  const hi = ((aHi * x) % p) * 65536 % p;
  return (lo + hi + b) % p;
}

export function transcriptMinHash(text, numHashes) {
  const n = Number.isFinite(numHashes) ? Math.floor(numHashes) : MINHASH_LEN;
  if (n !== MINHASH_LEN) {
    // The wire format is fixed at 64 hashes (256 bytes). Refuse other
    // sizes so callers cannot accidentally produce incompatible blobs.
    throw new Error(`transcriptMinHash supports numHashes=${MINHASH_LEN} only`);
  }
  const sig = new Uint32Array(MINHASH_LEN);
  for (let i = 0; i < MINHASH_LEN; i++) sig[i] = MINHASH_MAX;
  const tokens = tokenize(text);
  if (tokens.length === 0) {
    const empty = Buffer.alloc(MINHASH_LEN * 4);
    return empty.toString('base64');
  }
  for (const tok of tokens) {
    const x = tokenHashU32(tok);
    for (let i = 0; i < MINHASH_LEN; i++) {
      const v = modMulAdd(MINHASH_COEFFS.a[i], x, MINHASH_COEFFS.b[i], MINHASH_PRIME);
      if (v < sig[i]) sig[i] = v;
    }
  }
  const buf = Buffer.alloc(MINHASH_LEN * 4);
  for (let i = 0; i < MINHASH_LEN; i++) buf.writeUInt32BE(sig[i], i * 4);
  return buf.toString('base64');
}

export function minHashJaccard(b64A, b64B) {
  if (typeof b64A !== 'string' || typeof b64B !== 'string') return 0;
  const a = Buffer.from(b64A, 'base64');
  const b = Buffer.from(b64B, 'base64');
  if (a.length !== MINHASH_LEN * 4 || b.length !== MINHASH_LEN * 4) return 0;
  let match = 0;
  for (let i = 0; i < MINHASH_LEN; i++) {
    if (a.readUInt32BE(i * 4) === b.readUInt32BE(i * 4)) match++;
  }
  return match / MINHASH_LEN;
}

// ---------------------------------------------------------------------------
// findCluster: scan recent neighbours in the same geohash bucket and
// return the best match if composite score >= 0.7.
//
// opts.firestoreModule is injected for tests; production passes the real
// firestore module from server/tm/firestore.js. opts.nowMs sets the
// reference time (defaults to Date.now()).
//
// Errors from the storage layer are swallowed and logged so an
// unprovisioned composite index never blocks SOS persistence.
// ---------------------------------------------------------------------------
function logJson(severity, fields) {
  const entry = { ts: new Date().toISOString(), severity, ...fields };
  process.stdout.write(JSON.stringify(entry) + '\n');
}

function scorePair(candidate, target) {
  const reasons = [];
  let total = 0;
  const dist = haversineMeters(target.location, candidate.location);
  if (Number.isFinite(dist) && dist <= MATCH_DISTANCE_M) {
    total += MATCH_DISTANCE_BONUS;
    reasons.push(`within ${Math.round(dist)} m`);
  }
  const tInc = String(target.incident_type || '');
  const cInc = String(candidate.incident_type || '');
  if (tInc && cInc && tInc === cInc && tInc !== 'unknown') {
    total += MATCH_INCIDENT;
    reasons.push(`same incident_type ${tInc}`);
  }
  let jaccard = 0;
  if (target.transcript_minhash_b64 && candidate.transcript_minhash_b64) {
    jaccard = minHashJaccard(target.transcript_minhash_b64, candidate.transcript_minhash_b64);
    if (jaccard >= MATCH_TEXT_THRESHOLD) {
      total += MATCH_TEXT_BONUS;
      reasons.push(`text similarity ${jaccard.toFixed(2)}`);
    }
  }
  return { score: Number(total.toFixed(4)), reasons, distance_m: Number.isFinite(dist) ? Math.round(dist) : null, jaccard: Number(jaccard.toFixed(3)) };
}

export async function findCluster(newDispatch, opts) {
  const fs = opts?.firestoreModule;
  if (!fs || typeof fs.queryDocs !== 'function') return null;
  if (!newDispatch?.geohash7 || typeof newDispatch.geohash7 !== 'string') return null;
  const nowMs = Number.isFinite(opts?.nowMs) ? opts.nowMs : Date.now();
  const cutoffIso = new Date(nowMs - RECENT_WINDOW_MS).toISOString();
  let rows;
  try {
    rows = await fs.queryDocs('tm_dispatches', [
      { field: 'geohash7', op: '==', value: newDispatch.geohash7 },
      { field: 'received_at', op: '>=', value: cutoffIso }
    ], { orderBy: [{ field: 'received_at', direction: 'desc' }], limit: QUERY_LIMIT });
  } catch (e) {
    logJson('WARNING', {
      fn: 'findCluster',
      msg: 'query_failed_returning_null',
      err: String(e),
      hint: 'Composite index (geohash7 ASC, received_at DESC) may not be provisioned yet'
    });
    return null;
  }
  if (!Array.isArray(rows) || rows.length === 0) return null;
  let best = null;
  for (const row of rows) {
    const data = row?.data || row;
    if (!data || data.id === newDispatch.id) continue;
    const ws = String(data.worker_status || '');
    if (ACTIVE_WORKER_STATUSES_EXCLUDED.has(ws)) continue;
    const candidate = {
      id: row.id || data.id,
      cluster_id: data.cluster_id || null,
      cluster_role: data.cluster_role || null,
      cluster_primary_id: data.cluster_primary_id || null,
      location: data.location || null,
      incident_type: data?.triage?.incident_type || null,
      transcript_minhash_b64: data.transcript_minhash_b64 || null
    };
    const target = {
      location: newDispatch.location,
      incident_type: newDispatch.triage?.incident_type || newDispatch.incident_type || null,
      transcript_minhash_b64: newDispatch.transcript_minhash_b64
    };
    const result = scorePair(candidate, target);
    if (result.score >= MATCH_THRESHOLD && (!best || result.score > best.result.score)) {
      best = { candidate, result };
    }
  }
  if (!best) return null;
  const primaryId = best.candidate.cluster_role === 'duplicate' && best.candidate.cluster_primary_id
    ? best.candidate.cluster_primary_id
    : best.candidate.id;
  const clusterId = best.candidate.cluster_id || best.candidate.id;
  return {
    cluster_id: clusterId,
    cluster_primary_id: primaryId,
    match_score: best.result.score,
    match_reasons: best.result.reasons,
    distance_m: best.result.distance_m,
    jaccard: best.result.jaccard
  };
}

export const _internal = {
  GEOHASH_BASE32,
  MINHASH_LEN,
  MATCH_THRESHOLD,
  MATCH_DISTANCE_M,
  scorePair,
  tokenize
};
