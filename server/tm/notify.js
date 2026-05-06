// Project Aether · Task Manager · Web Push fan-out via VAPID.
//
// Replaces the 15 s status polling on the SOS PWA. Push delivery rides
// the OS push channel at near-zero bandwidth cost; polling at 2.5 kbps
// burned roughly 40 percent of the survivor budget for nothing.
//
// Wire:
//   POST   /api/v1/tm/auth/push_subscribe   stores one current sub per uid
//   DELETE /api/v1/tm/auth/push_subscribe   drops the current sub on logout
//   GET    /api/v1/tm/auth/vapid_pubkey     returns the public VAPID key
//
// The payload is encrypted per RFC 8291 (aes128gcm) using the
// subscriber's p256dh + auth secret, and signed with a VAPID JWT
// per RFC 8292. Zero new npm deps. All primitives come from Node's
// built-in crypto module.
//
// Storage:
//   tm_user_subscriptions/{uid}  one current subscription per user.
//     {endpoint, keys: {p256dh, auth}, last_seen_at, created_at}
//   Firestore TTL on last_seen_at expires the doc after 90 days so
//   stale subscriptions for retired devices do not accumulate.
//
// Failure semantics:
//   410 Gone         -> delete tm_user_subscriptions/{uid}
//   404 Not Found    -> delete (subscription was never registered upstream)
//   429 Too Many     -> log WARNING, leave subscription, caller sees void
//   any other 4xx    -> log WARNING, continue
//   5xx / network    -> log WARNING, continue
//
// Payload contract (≤ 500 B JSON, no PII):
//   { kind, dispatch_id, urgency, scope, ttl_s }
//
// Notes on RFC 8291 implementation:
//   - One ephemeral ECDH P-256 keypair per send.
//   - HKDF-SHA256 single-block expand because all derived keys are ≤ 32 B.
//   - One AES-128-GCM record. Padding delimiter 0x02 is appended.
//   - Header layout: salt(16) || rs(4) || idlen(1) || keyid(65).
//
// Pure ESM, Node 22+.

import {
  createECDH, createHmac, createPrivateKey, createPublicKey, createSign,
  createCipheriv, generateKeyPairSync, randomBytes
} from 'node:crypto';

import * as firestore from './firestore.js';

const SUBSCRIPTIONS_COLL = 'tm_user_subscriptions';
const TTL_DAYS = 90;
const MAX_PAYLOAD_BYTES = 500;
const RECORD_SIZE = 4096;

let _fs = firestore;

export function _setFirestoreForTest(mock) {
  _fs = mock || firestore;
}

let _vapidPriv = null;
let _vapidPubRaw = null;
let _vapidPrivKeyObj = null;
let _vapidSubject = null;
let _vapidEphemeral = false;

function logJson(severity, fields) {
  const entry = { ts: new Date().toISOString(), severity, ...fields };
  process.stdout.write(JSON.stringify(entry) + '\n');
}

function b64uEnc(buf) {
  const b = buf instanceof Uint8Array ? Buffer.from(buf) : Buffer.from(buf);
  return b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64uDec(s) {
  if (typeof s !== 'string') throw new Error('expected string');
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64');
}

function b64Dec(s) {
  if (typeof s !== 'string') throw new Error('expected string');
  return Buffer.from(s, 'base64');
}

// Decode the VAPID public key from raw 65-byte uncompressed form into
// the {x, y} JWK fields used by Node's createPublicKey.
function rawPubToJwkXY(raw) {
  if (raw.length !== 65 || raw[0] !== 0x04) {
    throw new Error('vapid_pub_must_be_65b_uncompressed');
  }
  return { x: b64uEnc(raw.subarray(1, 33)), y: b64uEnc(raw.subarray(33, 65)) };
}

// Build a Node KeyObject for the VAPID private key from raw bytes plus
// the matching uncompressed public key. The JWK form is the most
// portable across Node versions.
function buildPrivKeyObj(privBytes, pubRaw) {
  const xy = rawPubToJwkXY(pubRaw);
  return createPrivateKey({
    key: {
      kty: 'EC', crv: 'P-256',
      d: b64uEnc(privBytes),
      x: xy.x,
      y: xy.y,
      ext: true
    },
    format: 'jwk'
  });
}

function loadVapidKeys() {
  if (_vapidPrivKeyObj) return;
  const subjEnv = String(process.env.VAPID_SUBJECT || '').trim();
  _vapidSubject = subjEnv && /^(mailto:|https:\/\/)/.test(subjEnv)
    ? subjEnv
    : 'mailto:ops@aether.dmj.one';
  const privEnv = process.env.VAPID_PRIVATE_KEY_B64;
  const pubEnv = process.env.VAPID_PUBLIC_KEY_B64;
  if (privEnv && pubEnv) {
    try {
      const priv = b64uDec(privEnv);
      const pub = b64uDec(pubEnv);
      if (priv.length === 32 && pub.length === 65 && pub[0] === 0x04) {
        _vapidPriv = priv;
        _vapidPubRaw = pub;
        _vapidPrivKeyObj = buildPrivKeyObj(priv, pub);
        _vapidEphemeral = false;
        return;
      }
      logJson('WARNING', {
        fn: 'tm.notify.loadVapidKeys',
        msg: 'vapid_env_bad_lengths',
        priv_len: priv.length,
        pub_len: pub.length
      });
    } catch (e) {
      logJson('WARNING', {
        fn: 'tm.notify.loadVapidKeys',
        msg: 'vapid_env_decode_failed',
        err: String(e?.message || e)
      });
    }
  }
  // Ephemeral pair for cold start. Push will work for the lifetime of
  // this instance but every cold start invalidates client subscriptions
  // (the applicationServerKey will not match). Set the env vars before
  // production traffic.
  const kp = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = kp.privateKey.export({ format: 'jwk' });
  const x = b64uDec(jwk.x);
  const y = b64uDec(jwk.y);
  const pubRaw = Buffer.concat([Buffer.from([0x04]), x, y]);
  const privBytes = b64uDec(jwk.d);
  _vapidPriv = privBytes;
  _vapidPubRaw = pubRaw;
  _vapidPrivKeyObj = kp.privateKey;
  _vapidEphemeral = true;
  logJson('WARNING', {
    fn: 'tm.notify.loadVapidKeys',
    msg: 'vapid_keypair_generated_in_memory',
    note: 'set VAPID_PUBLIC_KEY_B64 / VAPID_PRIVATE_KEY_B64 / VAPID_SUBJECT before production',
    public_key_b64: b64uEnc(pubRaw),
    private_key_b64: b64uEnc(privBytes)
  });
}

export function getPublicKeyB64() {
  loadVapidKeys();
  return b64uEnc(_vapidPubRaw);
}

export function isEphemeral() {
  loadVapidKeys();
  return _vapidEphemeral;
}

// ---------------------------------------------------------------------------
// VAPID JWT (RFC 8292). aud = scheme://host of the push endpoint.
// ---------------------------------------------------------------------------
function vapidAudienceFromEndpoint(endpoint) {
  const u = new URL(endpoint);
  return `${u.protocol}//${u.host}`;
}

function signVapidJwt(audience) {
  loadVapidKeys();
  const header = { typ: 'JWT', alg: 'ES256' };
  const now = Math.floor(Date.now() / 1000);
  const payload = { aud: audience, exp: now + 12 * 3600, sub: _vapidSubject };
  const headerB64 = b64uEnc(Buffer.from(JSON.stringify(header), 'utf8'));
  const payloadB64 = b64uEnc(Buffer.from(JSON.stringify(payload), 'utf8'));
  const signingInput = `${headerB64}.${payloadB64}`;
  const sigRaw = createSign('SHA256').update(signingInput).sign({
    key: _vapidPrivKeyObj,
    dsaEncoding: 'ieee-p1363'
  });
  return `${signingInput}.${b64uEnc(sigRaw)}`;
}

// ---------------------------------------------------------------------------
// HKDF-SHA256 (single-block expand path is enough for our 12 / 16 / 32 byte
// outputs).
// ---------------------------------------------------------------------------
function hkdfExtract(salt, ikm) {
  return createHmac('sha256', salt).update(ikm).digest();
}

function hkdfExpand(prk, info, length) {
  if (length > 32) throw new Error('hkdf_expand_only_one_block_supported');
  const t = createHmac('sha256', prk)
    .update(Buffer.concat([info, Buffer.from([0x01])]))
    .digest();
  return t.subarray(0, length);
}

// ---------------------------------------------------------------------------
// RFC 8291 aes128gcm encryption of one record. Returns the wire body.
// ---------------------------------------------------------------------------
export function encryptPayload(plaintext, p256dhRaw, authSecret) {
  if (!(plaintext instanceof Uint8Array)) {
    plaintext = Buffer.from(plaintext);
  }
  if (p256dhRaw.length !== 65 || p256dhRaw[0] !== 0x04) {
    throw new Error('p256dh_must_be_65b_uncompressed');
  }
  if (authSecret.length !== 16) {
    throw new Error('auth_secret_must_be_16b');
  }

  const ecdh = createECDH('prime256v1');
  ecdh.generateKeys();
  const asPub = ecdh.getPublicKey();
  const sharedSecret = ecdh.computeSecret(p256dhRaw);
  const salt = randomBytes(16);

  // PRK_key = HMAC-SHA-256(auth_secret, ecdh_secret)
  const prkKey = hkdfExtract(authSecret, sharedSecret);
  // key_info = "WebPush: info\0" || ua_public || as_public
  const keyInfo = Buffer.concat([
    Buffer.from('WebPush: info\0', 'utf8'),
    p256dhRaw,
    asPub
  ]);
  // IKM = HMAC-SHA-256(PRK_key, key_info || 0x01) [first 32]
  const ikm = hkdfExpand(prkKey, keyInfo, 32);
  // PRK = HMAC-SHA-256(salt, IKM)
  const prk = hkdfExtract(salt, ikm);
  // CEK = HKDF(prk, "Content-Encoding: aes128gcm\0", 16)
  const cek = hkdfExpand(prk, Buffer.from('Content-Encoding: aes128gcm\0', 'utf8'), 16);
  // NONCE = HKDF(prk, "Content-Encoding: nonce\0", 12)
  const nonce = hkdfExpand(prk, Buffer.from('Content-Encoding: nonce\0', 'utf8'), 12);

  // Single record: data || 0x02 (last-record marker for aes128gcm).
  const record = Buffer.concat([plaintext, Buffer.from([0x02])]);
  const cipher = createCipheriv('aes-128-gcm', cek, nonce);
  const ct = Buffer.concat([cipher.update(record), cipher.final()]);
  const tag = cipher.getAuthTag();
  const cipherWithTag = Buffer.concat([ct, tag]);

  // Header: salt(16) || rs(4 BE) || idlen(1) || keyid(asPub 65 B).
  const header = Buffer.alloc(16 + 4 + 1 + asPub.length);
  salt.copy(header, 0);
  header.writeUInt32BE(RECORD_SIZE, 16);
  header.writeUInt8(asPub.length, 20);
  asPub.copy(header, 21);

  return Buffer.concat([header, cipherWithTag]);
}

// ---------------------------------------------------------------------------
// Subscription store.
// ---------------------------------------------------------------------------
function nowIso() { return new Date().toISOString(); }

export function isValidSubscription(sub) {
  if (!sub || typeof sub !== 'object') return false;
  if (typeof sub.endpoint !== 'string' || sub.endpoint.length === 0 || sub.endpoint.length > 2048) return false;
  if (!/^https:\/\//.test(sub.endpoint)) return false;
  if (!sub.keys || typeof sub.keys !== 'object') return false;
  if (typeof sub.keys.p256dh !== 'string' || sub.keys.p256dh.length === 0 || sub.keys.p256dh.length > 200) return false;
  if (typeof sub.keys.auth !== 'string' || sub.keys.auth.length === 0 || sub.keys.auth.length > 200) return false;
  try {
    const pub = b64uDec(sub.keys.p256dh);
    const auth = b64uDec(sub.keys.auth);
    if (pub.length !== 65 || pub[0] !== 0x04) return false;
    if (auth.length !== 16) return false;
  } catch {
    return false;
  }
  return true;
}

export async function saveSubscription(uid, sub) {
  if (typeof uid !== 'string' || uid.length === 0) throw new Error('uid_required');
  if (!isValidSubscription(sub)) throw new Error('subscription_invalid');
  const doc = {
    uid,
    endpoint: sub.endpoint,
    keys: { p256dh: sub.keys.p256dh, auth: sub.keys.auth },
    created_at: nowIso(),
    last_seen_at: nowIso(),
    ttl_days: TTL_DAYS
  };
  if (typeof _fs.setDoc === 'function') {
    await _fs.setDoc(SUBSCRIPTIONS_COLL, uid, doc);
  }
  return doc;
}

export async function deleteSubscription(uid) {
  if (typeof uid !== 'string' || uid.length === 0) return;
  if (typeof _fs.deleteDoc === 'function') {
    try { await _fs.deleteDoc(SUBSCRIPTIONS_COLL, uid); } catch { /* idempotent */ }
  }
}

export async function getSubscription(uid) {
  if (typeof uid !== 'string' || uid.length === 0) return null;
  if (typeof _fs.getDoc !== 'function') return null;
  try { return await _fs.getDoc(SUBSCRIPTIONS_COLL, uid); }
  catch { return null; }
}

// ---------------------------------------------------------------------------
// Send. Returns {ok, status} on every outcome. Never throws so notify
// hooks fire-and-forget without taking the caller's transaction down.
// ---------------------------------------------------------------------------
function clampPayload(obj) {
  const json = JSON.stringify(obj);
  const bytes = Buffer.byteLength(json, 'utf8');
  if (bytes > MAX_PAYLOAD_BYTES) {
    // Aggressively trim string fields if the payload exceeds the cap.
    // The contract is small enough that this should never trigger in
    // production; the guard keeps a future refactor honest.
    const trimmed = { kind: obj.kind || 'tm.event', dispatch_id: obj.dispatch_id || null, urgency: obj.urgency || null };
    return { json: JSON.stringify(trimmed), bytes: Buffer.byteLength(JSON.stringify(trimmed), 'utf8') };
  }
  return { json, bytes };
}

async function fetchPush(endpoint, headers, body) {
  // Node 22 has global fetch. Wrap once so tests can stub via global.
  const res = await fetch(endpoint, { method: 'POST', headers, body });
  return res;
}

export async function sendToSubscription(sub, payload, opts) {
  if (!isValidSubscription(sub)) {
    return { ok: false, status: 0, reason: 'invalid_subscription' };
  }
  const ttl = Number.isFinite(opts?.ttl_s) ? Math.max(0, Math.floor(opts.ttl_s)) : 60;
  const urgency = ['very-low', 'low', 'normal', 'high'].includes(opts?.urgency) ? opts.urgency : 'high';
  const { json, bytes } = clampPayload(payload);
  if (bytes > MAX_PAYLOAD_BYTES) {
    return { ok: false, status: 0, reason: 'payload_too_large', bytes };
  }
  let body;
  try {
    body = encryptPayload(
      Buffer.from(json, 'utf8'),
      b64uDec(sub.keys.p256dh),
      b64uDec(sub.keys.auth)
    );
  } catch (e) {
    logJson('WARNING', {
      fn: 'tm.notify.sendToSubscription',
      msg: 'encrypt_failed',
      err: String(e?.message || e)
    });
    return { ok: false, status: 0, reason: 'encrypt_failed' };
  }
  let aud;
  try { aud = vapidAudienceFromEndpoint(sub.endpoint); }
  catch { return { ok: false, status: 0, reason: 'bad_endpoint' }; }
  const jwt = signVapidJwt(aud);
  const auth = `vapid t=${jwt}, k=${getPublicKeyB64()}`;
  const headers = {
    'Authorization': auth,
    'TTL': String(ttl),
    'Urgency': urgency,
    'Content-Type': 'application/octet-stream',
    'Content-Encoding': 'aes128gcm',
    'Content-Length': String(body.length)
  };
  let res;
  try {
    res = await fetchPush(sub.endpoint, headers, body);
  } catch (e) {
    logJson('WARNING', {
      fn: 'tm.notify.sendToSubscription',
      msg: 'push_network_error',
      err: String(e?.message || e)
    });
    return { ok: false, status: 0, reason: 'network_error' };
  }
  return { ok: res.status >= 200 && res.status < 300, status: res.status, reason: null };
}

// ---------------------------------------------------------------------------
// Public fan-out helper. Looks up the user's current subscription, sends,
// and reaps stale subs on 410.
// ---------------------------------------------------------------------------
export async function notify(targetUid, payload, opts) {
  if (!targetUid || typeof targetUid !== 'string') return { ok: false, status: 0, reason: 'no_target' };
  const sub = await getSubscription(targetUid);
  if (!sub || !sub.endpoint) return { ok: false, status: 0, reason: 'no_subscription' };
  const r = await sendToSubscription({ endpoint: sub.endpoint, keys: sub.keys }, payload, opts);
  if (r.status === 410 || r.status === 404) {
    await deleteSubscription(targetUid);
    logJson('INFO', {
      fn: 'tm.notify.notify',
      msg: 'subscription_gone_deleted',
      uid: targetUid,
      status: r.status
    });
  } else if (!r.ok && r.status !== 0) {
    logJson('WARNING', {
      fn: 'tm.notify.notify',
      msg: 'push_non_2xx',
      uid: targetUid,
      status: r.status
    });
  }
  return r;
}

// ---------------------------------------------------------------------------
// Hook helpers used by the dispatch + assignment paths. Each function
// resolves the parent_uid via users.js and fires a single notify().
// All wrapped in try/catch so the underlying mutation never blocks on
// the side-effect.
// ---------------------------------------------------------------------------
async function getParentUid(uid) {
  if (!uid) return null;
  try {
    if (typeof _fs.getDoc !== 'function') return null;
    const u = await _fs.getDoc('tm_users', uid);
    return u?.parent_uid || null;
  } catch { return null; }
}

export async function notifyDispatchCreated(dispatch) {
  try {
    const callerUid = dispatch?.caller?.uid || dispatch?.caller_uid || null;
    if (!callerUid) return;
    const parentUid = await getParentUid(callerUid);
    if (!parentUid) return;
    await notify(parentUid, {
      kind: 'dispatch.created',
      dispatch_id: dispatch.id,
      urgency: dispatch?.triage?.urgency || 'UNCLEAR',
      scope: dispatch?.caller?.scope_path || dispatch?.caller_scope_path || null,
      ttl_s: 600
    }, { urgency: 'high', ttl_s: 600 });
  } catch (e) {
    logJson('WARNING', { fn: 'tm.notify.notifyDispatchCreated', err: String(e?.message || e) });
  }
}

export async function notifyDispatchEscalated(dispatch, actorUid) {
  try {
    if (!actorUid) return;
    const parentUid = await getParentUid(actorUid);
    if (!parentUid) return;
    await notify(parentUid, {
      kind: 'dispatch.escalated',
      dispatch_id: dispatch?.id || null,
      urgency: dispatch?.triage?.urgency || 'UNCLEAR',
      scope: dispatch?.caller_scope_path || null,
      ttl_s: 600
    }, { urgency: 'high', ttl_s: 600 });
  } catch (e) {
    logJson('WARNING', { fn: 'tm.notify.notifyDispatchEscalated', err: String(e?.message || e) });
  }
}

export async function notifyAssignmentCreated(dispatch, assignment) {
  try {
    const callerUid = dispatch?.caller_uid || null;
    const tasks = [];
    if (callerUid) {
      tasks.push(notify(callerUid, {
        kind: 'assignment.created',
        dispatch_id: dispatch?.id || null,
        urgency: dispatch?.triage?.urgency || dispatch?.worker_status || null,
        scope: dispatch?.caller_scope_path || null,
        ttl_s: 600
      }, { urgency: 'high', ttl_s: 600 }));
      const parentUid = await getParentUid(callerUid);
      if (parentUid) {
        tasks.push(notify(parentUid, {
          kind: 'assignment.created',
          dispatch_id: dispatch?.id || null,
          urgency: dispatch?.triage?.urgency || null,
          scope: dispatch?.caller_scope_path || null,
          ttl_s: 600
        }, { urgency: 'normal', ttl_s: 600 }));
      }
    }
    await Promise.allSettled(tasks);
  } catch (e) {
    logJson('WARNING', { fn: 'tm.notify.notifyAssignmentCreated', err: String(e?.message || e) });
  }
}

export async function notifyAssignmentUpdated(dispatch, assignment) {
  try {
    const callerUid = dispatch?.caller_uid || null;
    if (!callerUid) return;
    await notify(callerUid, {
      kind: 'assignment.updated',
      dispatch_id: dispatch?.id || null,
      urgency: dispatch?.triage?.urgency || dispatch?.worker_status || null,
      scope: dispatch?.caller_scope_path || null,
      ttl_s: 600
    }, { urgency: 'high', ttl_s: 600 });
  } catch (e) {
    logJson('WARNING', { fn: 'tm.notify.notifyAssignmentUpdated', err: String(e?.message || e) });
  }
}

export const _internal = {
  hkdfExtract,
  hkdfExpand,
  vapidAudienceFromEndpoint,
  signVapidJwt,
  clampPayload,
  MAX_PAYLOAD_BYTES,
  TTL_DAYS,
  SUBSCRIPTIONS_COLL
};
