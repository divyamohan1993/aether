// Decision Support System for higher-tier dispatchers.
// Pure-rule scoring engine. Given a dispatch document and the candidate
// units inside its scope subtree, returns up to three best-fit unit
// suggestions ranked by total score.
//
// Scoring rules (all bounded; final score is capped at 1.0).
//
//   1. Urgency:
//        triage.urgency === 'CRITICAL' -> +0.40
//        triage.urgency === 'HIGH'     -> +0.25
//
//   2. Need-to-unit-type match (any one applies):
//        needs[] contains 'medical_evacuation' AND
//          unit.type in {ambulance, medical_team, helicopter}
//          -> +0.50
//        needs[] contains 'search_and_rescue' AND
//          unit.type in {sdrf_team, drone, helicopter}
//          -> +0.50
//
//   3. Incident-to-unit-type match:
//        incident_type === 'fire' AND unit.type === 'fire_engine'
//          -> +0.40
//        incident_type in {flood, landslide} AND
//          unit.type in {sdrf_team, helicopter, drone}
//          -> +0.30
//
//   4. Distance bonus:
//        if dispatch.location and unit.location both present
//          d_km = haversine(dispatch, unit)
//          bonus = 0.30 * max(0, 1 - d_km / 50)
//
//   5. Availability gate:
//        unit.status !== 'available' -> score forced to 0 (filtered out)
//
// Output: array of { unit_id, unit_name, unit_type, score, reason,
// distance_km } sorted by score descending. Returns at most three rows.

const NEED_MEDEVAC_TYPES = new Set(['ambulance', 'medical_team', 'helicopter']);
const NEED_SAR_TYPES = new Set(['sdrf_team', 'drone', 'helicopter']);
const FLOOD_LANDSLIDE_TYPES = new Set(['sdrf_team', 'helicopter', 'drone']);

function num(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function haversineKm(a, b) {
  const lat1 = num(a?.lat), lng1 = num(a?.lng);
  const lat2 = num(b?.lat), lng2 = num(b?.lng);
  if (lat1 === null || lng1 === null || lat2 === null || lng2 === null) return null;
  const R = 6371;
  const toRad = (d) => d * Math.PI / 180;
  const dLat = toRad(lat2 - lat1);
  const dLng = toRad(lng2 - lng1);
  const s1 = Math.sin(dLat / 2);
  const s2 = Math.sin(dLng / 2);
  const h = s1 * s1 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * s2 * s2;
  return 2 * R * Math.asin(Math.min(1, Math.sqrt(h)));
}

function arr(v) { return Array.isArray(v) ? v : []; }

export function score(dispatch, unit) {
  if (!dispatch || !unit) return { score: 0, reason: 'invalid input', distance_km: null };
  if (unit.status !== 'available') {
    return { score: 0, reason: 'unit not available', distance_km: null };
  }
  const triage = dispatch.triage || {};
  const urgency = String(triage.urgency || '').toUpperCase();
  const needs = arr(triage.needs).map((n) => String(n));
  const incident = String(triage.incident_type || '');
  const reasons = [];
  let total = 0;

  if (urgency === 'CRITICAL') { total += 0.40; reasons.push('critical urgency'); }
  else if (urgency === 'HIGH') { total += 0.25; reasons.push('high urgency'); }

  if (needs.includes('medical_evacuation') && NEED_MEDEVAC_TYPES.has(unit.type)) {
    total += 0.50; reasons.push('medical match');
  }
  if (needs.includes('search_and_rescue') && NEED_SAR_TYPES.has(unit.type)) {
    total += 0.50; reasons.push('search and rescue match');
  }

  if (incident === 'fire' && unit.type === 'fire_engine') {
    total += 0.40; reasons.push('fire match');
  }
  if ((incident === 'flood' || incident === 'landslide') && FLOOD_LANDSLIDE_TYPES.has(unit.type)) {
    total += 0.30; reasons.push(`${incident} match`);
  }

  let distance_km = null;
  if (dispatch.location && unit.location) {
    distance_km = haversineKm(dispatch.location, unit.location);
    if (distance_km !== null) {
      const bonus = 0.30 * Math.max(0, 1 - distance_km / 50);
      if (bonus > 0) {
        total += bonus;
        reasons.push(`${distance_km.toFixed(1)} km away`);
      }
    }
  }

  if (total > 1) total = 1;
  return {
    score: Number(total.toFixed(3)),
    reason: reasons.length ? reasons.join(', ') : 'no specific match',
    distance_km: distance_km === null ? null : Number(distance_km.toFixed(1))
  };
}

// Rank candidate units against a dispatch. Returns the top three by score.
// `units` must be the already scope-filtered list from server/tm/units.js.
export function suggest(dispatch, units, k = 3) {
  if (!Array.isArray(units) || units.length === 0) return [];
  const scored = [];
  for (const u of units) {
    const r = score(dispatch, u);
    if (r.score <= 0) continue;
    scored.push({
      unit_id: u.unit_id,
      unit_name: u.name,
      unit_type: u.type,
      score: r.score,
      reason: r.reason,
      distance_km: r.distance_km
    });
  }
  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, Math.max(1, Math.floor(k) || 3));
}

export const _internal = { haversineKm };
