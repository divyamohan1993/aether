// phone-identity lane: SMS OTP + shortcode webhook.
//
// Three jobs:
//   1. sendOtp(phone, channel)  ->  picks first configured provider
//      (msg91 / karix / twilio), stores tm_otp_pending/{phone} with
//      a 5 min TTL, sends SMS body via the chosen vendor.
//   2. verifyOtp(phone, otp)    ->  timing-safe compare; max 3
//      attempts; on success mints tm_phone_bindings/{fp} valid
//      30 days.
//   3. handleShortcodeWebhook(body)  ->  inbound SMS to one of the
//      shortcodes (1078, 112, state SDRF). Body matching /^\s*SOS\b/i
//      mints a phone-verified anonymous dispatch with the body as
//      transcription_native. The webhook is HMAC-gated by
//      SMS_WEBHOOK_HMAC at the router edge so a public POST cannot
//      forge an SOS.
//
// No new npm deps. Uses Node `node:crypto`.

import { randomBytes, createHash, timingSafeEqual, randomUUID } from 'node:crypto';
import * as firestoreMod from './firestore.js';

const OTP_TTL_SECS = 5 * 60;
const BINDING_TTL_SECS = 30 * 24 * 3600;
const OTP_MAX_ATTEMPTS = 3;
const OTP_LEN = 6;
const E164_RE = /^\+[1-9]\d{6,14}$/;

let _fs = firestoreMod;
let _smsSender = null;

export function _setFirestoreForTest(stub) { _fs = stub || firestoreMod; }
export function _setSmsSenderForTest(fn) { _smsSender = typeof fn === 'function' ? fn : null; }

function logJson(severity, fields) {
  const entry = { ts: new Date().toISOString(), severity, ...fields };
  process.stdout.write(JSON.stringify(entry) + '\n');
}

function nowSecs() { return Math.floor(Date.now() / 1000); }

function hashOtp(otp) {
  return createHash('sha256').update(`aether-otp:${otp}`).digest('base64');
}

function timingSafeStringEq(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

// Phone-fingerprint: SHA-256 of the E.164 number, base64url, first 24
// chars. Stable across binding renewals so a returning caller can be
// recognised without exposing the raw MSISDN to client code.
function fingerprintPhone(e164) {
  const h = createHash('sha256').update(`aether-phone:${e164}`).digest('base64');
  return h.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '').slice(0, 24);
}

function pickProvider(channel) {
  const want = channel || 'auto';
  if (want === 'msg91') return process.env.MSG91_API_KEY ? 'msg91' : null;
  if (want === 'karix') return process.env.KARIX_API_KEY ? 'karix' : null;
  if (want === 'twilio') {
    return (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_FROM)
      ? 'twilio' : null;
  }
  if (want === 'auto') {
    if (process.env.MSG91_API_KEY) return 'msg91';
    if (process.env.KARIX_API_KEY) return 'karix';
    if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_FROM) return 'twilio';
    return null;
  }
  return null;
}

// Rejection-sampled 6-digit OTP so digits are uniform in [0, 999999].
function generateOtp() {
  const max = 1_000_000;
  const limit = 0xFFFFFFFF - (0xFFFFFFFF % max);
  while (true) {
    const v = randomBytes(4).readUInt32BE(0);
    if (v >= limit) continue;
    return String(v % max).padStart(6, '0');
  }
}

async function defaultSender(provider, phone, otp) {
  const text = `Aether SOS verification code: ${otp}. Valid for 5 minutes.`;
  if (provider === 'msg91') {
    const url = process.env.MSG91_URL || 'https://api.msg91.com/api/v5/flow/';
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'authkey': process.env.MSG91_API_KEY },
      body: JSON.stringify({ mobiles: phone, message: text })
    });
    if (!r.ok) throw new Error(`msg91_send_${r.status}`);
    return;
  }
  if (provider === 'karix') {
    const url = process.env.KARIX_URL || 'https://api.karix.io/message/';
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${process.env.KARIX_API_KEY}` },
      body: JSON.stringify({
        destination: [phone], text, source: process.env.KARIX_SOURCE || 'AETHER'
      })
    });
    if (!r.ok) throw new Error(`karix_send_${r.status}`);
    return;
  }
  if (provider === 'twilio') {
    const sid = process.env.TWILIO_ACCOUNT_SID;
    const token = process.env.TWILIO_AUTH_TOKEN;
    const from = process.env.TWILIO_FROM;
    const url = `https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`;
    const auth = Buffer.from(`${sid}:${token}`).toString('base64');
    const params = new URLSearchParams({ From: from, To: phone, Body: text });
    const r = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${auth}`
      },
      body: params.toString()
    });
    if (!r.ok) throw new Error(`twilio_send_${r.status}`);
    return;
  }
  throw new Error('unknown_provider');
}

export async function sendOtp(phone_e164, channel = 'auto') {
  if (typeof phone_e164 !== 'string' || !E164_RE.test(phone_e164)) {
    const e = new Error('phone_invalid'); e.code = 'phone_invalid'; e.status = 400; throw e;
  }
  const provider = pickProvider(channel);
  if (!provider) {
    const e = new Error('sms_provider_unconfigured');
    e.code = 'sms_provider_unconfigured'; e.status = 503; throw e;
  }
  const otp = generateOtp();
  const otpHash = hashOtp(otp);
  const ttlAt = new Date((nowSecs() + OTP_TTL_SECS) * 1000).toISOString();
  await _fs.setDoc('tm_otp_pending', phone_e164, {
    phone_e164,
    otp_hash: otpHash,
    attempts: 0,
    provider,
    ttl_at: ttlAt,
    created_at: new Date().toISOString()
  });
  const sender = _smsSender || defaultSender;
  try {
    await sender(provider, phone_e164, otp);
  } catch (e) {
    logJson('WARNING', {
      fn: 'tm.sms.sendOtp', msg: 'send_failed',
      provider, err: String(e?.message || e)
    });
    const err = new Error('sms_send_failed');
    err.code = 'sms_send_failed'; err.status = 503; throw err;
  }
  return { ok: true, provider, ttl_seconds: OTP_TTL_SECS };
}

export async function verifyOtp(phone_e164, otp_input) {
  if (typeof phone_e164 !== 'string' || !E164_RE.test(phone_e164)) {
    const e = new Error('phone_invalid'); e.code = 'phone_invalid'; e.status = 400; throw e;
  }
  if (typeof otp_input !== 'string' || otp_input.length !== OTP_LEN) {
    const e = new Error('otp_invalid'); e.code = 'otp_invalid'; e.status = 400; throw e;
  }
  const pending = await _fs.getDoc('tm_otp_pending', phone_e164);
  if (!pending) {
    const e = new Error('otp_not_found'); e.code = 'otp_not_found'; e.status = 404; throw e;
  }
  if (Date.parse(pending.ttl_at || 0) < Date.now()) {
    await _fs.deleteDoc('tm_otp_pending', phone_e164).catch(() => {});
    const e = new Error('otp_expired'); e.code = 'otp_expired'; e.status = 410; throw e;
  }
  const attempts = Number(pending.attempts || 0);
  if (attempts >= OTP_MAX_ATTEMPTS) {
    await _fs.deleteDoc('tm_otp_pending', phone_e164).catch(() => {});
    const e = new Error('otp_attempts_exceeded');
    e.code = 'otp_attempts_exceeded'; e.status = 429; throw e;
  }
  const inputHash = hashOtp(otp_input);
  const matches = timingSafeStringEq(pending.otp_hash || '', inputHash);
  if (!matches) {
    const next = attempts + 1;
    if (next >= OTP_MAX_ATTEMPTS) {
      await _fs.deleteDoc('tm_otp_pending', phone_e164).catch(() => {});
    } else {
      await _fs.setDoc('tm_otp_pending', phone_e164, { ...pending, attempts: next });
    }
    const err = new Error('otp_mismatch');
    err.code = 'otp_mismatch'; err.status = 401;
    err.attempts_remaining = Math.max(0, OTP_MAX_ATTEMPTS - next);
    throw err;
  }
  await _fs.deleteDoc('tm_otp_pending', phone_e164).catch(() => {});
  const fp = fingerprintPhone(phone_e164);
  const expiresAt = new Date((nowSecs() + BINDING_TTL_SECS) * 1000).toISOString();
  await _fs.setDoc('tm_phone_bindings', fp, {
    phone_fp: fp,
    phone_e164,
    verification_channel: 'sms_otp',
    created_at: new Date().toISOString(),
    expires_at: expiresAt
  });
  return { ok: true, phone_fp: fp, expires_at: expiresAt };
}

// Inbound SMS shortcode webhook. Body shape:
//   { from_e164, body, received_at }
// On a body that starts with "SOS", a phone-verified anonymous
// dispatch is minted. Returns { ok: true, dispatch_id } on success
// or { ok: false, reason } when the message is not an SOS.
export async function handleShortcodeWebhook(body) {
  if (!body || typeof body !== 'object') {
    const e = new Error('bad_body'); e.code = 'bad_body'; e.status = 400; throw e;
  }
  const from = String(body.from_e164 || '').trim();
  const text = String(body.body || '').trim();
  const receivedAt = String(body.received_at || new Date().toISOString());
  if (!E164_RE.test(from)) {
    const e = new Error('from_invalid'); e.code = 'from_invalid'; e.status = 400; throw e;
  }
  if (!/^\s*SOS\b/i.test(text)) {
    return { ok: false, reason: 'not_sos_format' };
  }
  const dispatchId = randomUUID();
  const fp = fingerprintPhone(from);
  await _fs.setDoc('tm_dispatches', dispatchId, {
    id: dispatchId,
    received_at: receivedAt,
    caller_uid: null,
    caller_scope_path: `survivor/${fp}`,
    caller_phone_e164: from,
    phone_verified: true,
    verification_channel: 'sms_shortcode',
    caller_identity: {
      msisdn_e164: from,
      phone_verified: true,
      verification_channel: 'sms_shortcode',
      fingerprint: fp,
      ip_subnet24: null
    },
    triage: {
      urgency: 'HIGH',
      transcription_native: text,
      transcription_english: text,
      summary_for_dispatch: `SMS shortcode SOS from ${from}`,
      confidence: 0.6,
      incident_type: 'unknown'
    },
    worker_status: 'received',
    worker_status_history: [{ status: 'received', ts: receivedAt }],
    requires_review: true,
    escalation_status: 'pending_review',
    created_at: new Date()
  });
  return { ok: true, dispatch_id: dispatchId };
}

export const _internal = { hashOtp, fingerprintPhone, pickProvider, generateOtp, OTP_MAX_ATTEMPTS };
