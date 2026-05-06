// phone-identity lane: telco header HMAC enrichment.
//
// India telcos (Jio / Airtel / Vi / BSNL) inject `X-MSISDN` plus an
// HMAC-signed timestamp on traffic to aether.dmj.one so an SOS can
// be tied to a verified MSISDN with no client-side OTP. Each telco
// has its own key id sent in `X-Telco-Key-Id`. Secret material lives
// in env `TELCO_HMAC_SECRETS` as comma-separated `name:base64secret`
// pairs.
//
// HMAC input: `<msisdn>|<ts>` where ts is unix seconds. Skew window
// is +/- 60 s. On a valid sig, the caller (server.handleTriage) sets
// phone_verified=true and verification_channel='telco_header' on the
// dispatch row.

import { createHmac, timingSafeEqual } from 'node:crypto';

const SKEW_SECS = 60;
const E164_RE = /^\+?[1-9]\d{6,14}$/;

let _secretsCache = null;

export function loadTelcoSecrets() {
  if (_secretsCache !== null) return _secretsCache;
  const raw = String(process.env.TELCO_HMAC_SECRETS || '').trim();
  const out = new Map();
  if (raw.length === 0) {
    _secretsCache = out;
    return out;
  }
  for (const pair of raw.split(',')) {
    const colon = pair.indexOf(':');
    if (colon <= 0) continue;
    const name = pair.slice(0, colon).trim();
    const b64 = pair.slice(colon + 1).trim();
    if (!name || !b64) continue;
    let secret;
    try { secret = Buffer.from(b64, 'base64'); } catch { continue; }
    if (secret.length < 16) continue;
    out.set(name, secret);
  }
  _secretsCache = out;
  return out;
}

export function _resetTelcoCacheForTest() {
  _secretsCache = null;
}

function timingSafeStringEq(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

// Returns { msisdn_e164, telco, ts } on a valid signature, else null.
// Never throws.
export function verifyTelcoHeader(headers) {
  if (!headers || typeof headers !== 'object') return null;
  const msisdnRaw = String(headers['x-msisdn'] || '').trim();
  const sig = String(headers['x-telco-sig'] || '').trim();
  const keyId = String(headers['x-telco-key-id'] || '').trim();
  const tsRaw = String(headers['x-telco-ts'] || '').trim();
  if (!msisdnRaw || !sig || !keyId || !tsRaw) return null;
  if (!E164_RE.test(msisdnRaw)) return null;
  const ts = Number.parseInt(tsRaw, 10);
  if (!Number.isFinite(ts)) return null;
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - ts) > SKEW_SECS) return null;

  const secrets = loadTelcoSecrets();
  const secret = secrets.get(keyId);
  if (!secret) return null;
  const expected = createHmac('sha256', secret).update(`${msisdnRaw}|${ts}`).digest('base64');
  if (!timingSafeStringEq(sig, expected)) return null;
  const e164 = msisdnRaw.startsWith('+') ? msisdnRaw : '+' + msisdnRaw;
  return { msisdn_e164: e164, telco: keyId, ts };
}

export const _internal = { SKEW_SECS, E164_RE };
