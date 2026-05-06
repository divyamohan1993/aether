// DSS criticality scoring for tm_dispatches.
//
// Score = urgency_factor * sum(victim_weight * count) * time_decay.
// Per-victim weight is the SUM of every applicable flag weight plus the
// age_band base weight. The composite elderly_with_crush rule replaces
// the elderly base weight when crush_extracted is present.
//
// Floor at 0. No ceiling: a mass-casualty CRITICAL with multiple
// high-vulnerability victims must scale naturally so the sort surfaces it.
//
// Fallback when triage.victims is missing or empty: weight = 1.0 *
// (people_affected ?? 1). people_affected can be 0 when the model truly
// could not extract any count; treat that as 1 to avoid scoring zero on
// audio that mentions distress but no headcount.

const FLAG_WEIGHTS = Object.freeze({
  pregnant: 2.0,
  unresponsive: 2.0,
  crush_extracted: 1.5,
  bleeding: 1.5,
  breathing_difficulty: 0,
  conscious_ambulatory: 0
});

const AGE_BASE_WEIGHTS = Object.freeze({
  infant: 1.5,
  child: 1.3,
  adult: 1.0,
  elderly: 1.2
});

const URGENCY_FACTORS = Object.freeze({
  CRITICAL: 1.0,
  HIGH: 0.7,
  MEDIUM: 0.4,
  LOW: 0.2,
  UNCLEAR: 0.6
});

const ELDERLY_WITH_CRUSH = 1.8;

function urgencyFactor(urgency) {
  const key = String(urgency || '').toUpperCase();
  return Object.prototype.hasOwnProperty.call(URGENCY_FACTORS, key) ? URGENCY_FACTORS[key] : URGENCY_FACTORS.UNCLEAR;
}

function safeCount(c) {
  const n = Number(c);
  if (!Number.isFinite(n) || n < 1) return 1;
  return Math.floor(n);
}

function victimWeight(v) {
  const flags = Array.isArray(v?.condition_flags) ? v.condition_flags : [];
  const ageBand = String(v?.age_band || 'adult');
  const hasCrush = flags.includes('crush_extracted');
  const ageWeight = (ageBand === 'elderly' && hasCrush)
    ? ELDERLY_WITH_CRUSH
    : (AGE_BASE_WEIGHTS[ageBand] ?? AGE_BASE_WEIGHTS.adult);
  let flagWeight = 0;
  for (const f of flags) {
    if (Object.prototype.hasOwnProperty.call(FLAG_WEIGHTS, f)) flagWeight += FLAG_WEIGHTS[f];
  }
  if (ageBand === 'elderly' && hasCrush) {
    flagWeight -= FLAG_WEIGHTS.crush_extracted;
  }
  return ageWeight + flagWeight;
}

function timeDecay(receivedAtIso, nowMs) {
  if (!receivedAtIso) return 1.0;
  const t = Date.parse(receivedAtIso);
  if (!Number.isFinite(t)) return 1.0;
  const minutes = Math.max(0, (nowMs - t) / 60000);
  return 1.0 + 0.01 * minutes;
}

export function criticalityScore(triage, receivedAtIso, nowMs) {
  const now = Number.isFinite(nowMs) ? nowMs : Date.now();
  const factor = urgencyFactor(triage?.urgency);
  const decay = timeDecay(receivedAtIso, now);
  const breakdown = {
    urgency: String(triage?.urgency || 'UNCLEAR').toUpperCase(),
    urgency_factor: factor,
    time_decay: Number(decay.toFixed(4)),
    victims: [],
    fallback: false,
    sum_victim_weight: 0
  };
  let sum = 0;
  const victims = Array.isArray(triage?.victims) ? triage.victims : [];
  if (victims.length === 0) {
    const peopleRaw = Number(triage?.people_affected);
    const people = Number.isFinite(peopleRaw) && peopleRaw >= 1 ? Math.floor(peopleRaw) : 1;
    sum = 1.0 * people;
    breakdown.fallback = true;
    breakdown.fallback_people_affected = people;
    breakdown.sum_victim_weight = sum;
  } else {
    for (const v of victims) {
      const count = safeCount(v?.count);
      const weight = victimWeight(v);
      const contribution = weight * count;
      sum += contribution;
      breakdown.victims.push({
        age_band: String(v?.age_band || 'adult'),
        condition_flags: Array.isArray(v?.condition_flags) ? v.condition_flags.slice() : [],
        count,
        weight: Number(weight.toFixed(4)),
        contribution: Number(contribution.toFixed(4))
      });
    }
    breakdown.sum_victim_weight = Number(sum.toFixed(4));
  }
  const raw = factor * sum * decay;
  const score = raw > 0 ? Number(raw.toFixed(4)) : 0;
  return { score, breakdown };
}

export const _internal = { victimWeight, urgencyFactor, timeDecay, FLAG_WEIGHTS, AGE_BASE_WEIGHTS, URGENCY_FACTORS };
