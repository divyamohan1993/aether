// Project Aether · Task Manager · multi-device key sync (QR-bridge).
//
// multi-device-keys lane.
//
// A responder logging in on a new phone gets `T.err_nokey` because the
// ML-DSA-65 keypair only lives in the IDB of the original device. The
// QR-bridge transfers the encrypted keyring blob from the trusted
// device to the new device. The server's role is the device list:
//   - Each authenticated device registers a row in tm_user_devices/{uid}__{device_id}.
//   - The owner can list their devices and remotely revoke any of them.
//   - QR payload generation + unwrapping is browser-side; the wrap key
//     never leaves the user (4-word mnemonic).
//
// Pure ESM, Node 22+.

import { randomUUID, createHash } from 'node:crypto';

import * as _firestoreReal from './firestore.js';
import { ApiError, NotFoundError } from './_errors.js';

let _fsModule = _firestoreReal;
export function _setFirestoreForTest(mock) { _fsModule = mock || _firestoreReal; }

const COLLECTION = 'tm_user_devices';
const LABEL_RE = /^[A-Za-z0-9 .,'\-_/()]{1,40}$/;

function fs() { return _fsModule; }

function nowIso() { return new Date().toISOString(); }

function isValidLabel(s) {
  return typeof s === 'string' && LABEL_RE.test(s);
}

function isValidPubkeyB64(s) {
  if (typeof s !== 'string' || s.length === 0 || s.length > 4096) return false;
  return /^[A-Za-z0-9+/=]+$/.test(s);
}

// Short fingerprint of the registered pubkey. Stored on the device row
// so the dispatcher UI can surface "key thumbprint" without echoing the
// full 1952-byte ML-DSA pubkey. SHA-256 truncated to first 16 hex chars.
function pubkeyThumbprint(pubkeyB64) {
  const h = createHash('sha256');
  h.update(pubkeyB64);
  return h.digest('hex').slice(0, 16);
}

function projectDevice(row) {
  if (!row) return null;
  return {
    uid: row.uid,
    device_id: row.device_id,
    label: row.label,
    pubkey_b64_thumbprint: row.pubkey_b64_thumbprint,
    registered_at: row.registered_at,
    last_seen_at: row.last_seen_at,
    revoked: row.revoked === true,
    revoked_at: row.revoked_at || null
  };
}

// registerDevice — record a new device for the current user. The browser
// sends `{label, pubkey_b64}`. The server mints `device_id = randomUUID()`,
// computes the thumbprint, stamps timestamps, and stores the row keyed by
// `<uid>__<device_id>` so the device row collection is a flat keyspace
// (Firestore subcollections would force a different access pattern).
export async function registerDevice(actor, body) {
  if (!actor || typeof actor.uid !== 'string' || actor.uid.length === 0) {
    throw new ApiError('unauthorized', 'No session.', 401);
  }
  if (!body || typeof body !== 'object') {
    throw new ApiError('bad_request', 'body required.', 400);
  }
  const label = String(body.label || '').trim();
  if (!isValidLabel(label)) {
    throw new ApiError('bad_label', 'label must match /^[A-Za-z0-9 .,\\\'\\-_/()]{1,40}$/.', 400);
  }
  const pubkeyB64 = String(body.pubkey_b64 || '');
  if (!isValidPubkeyB64(pubkeyB64)) {
    throw new ApiError('bad_pubkey', 'pubkey_b64 must be a base64 string under 4 KB.', 400);
  }
  const device_id = randomUUID();
  const now = nowIso();
  const row = {
    uid: actor.uid,
    device_id,
    label,
    pubkey_b64_thumbprint: pubkeyThumbprint(pubkeyB64),
    registered_at: now,
    last_seen_at: now,
    revoked: false,
    revoked_at: null
  };
  const docId = `${actor.uid}__${device_id}`;
  await fs().setDoc(COLLECTION, docId, row);
  return projectDevice(row);
}

// listDevices — return the actor's own device rows. Filtered by `uid` so
// the browser never sees a sibling user's devices. Sorted newest-first
// by registered_at.
export async function listDevices(actor) {
  if (!actor || typeof actor.uid !== 'string' || actor.uid.length === 0) {
    throw new ApiError('unauthorized', 'No session.', 401);
  }
  const rows = await fs().queryDocs(COLLECTION, [
    { field: 'uid', op: '==', value: actor.uid }
  ], { limit: 200 }).catch(() => []);
  const out = [];
  for (const r of rows) {
    if (!r || !r.data) continue;
    if (r.data.uid !== actor.uid) continue;
    out.push(projectDevice(r.data));
  }
  out.sort((a, b) => {
    const ar = String(a.registered_at || '');
    const br = String(b.registered_at || '');
    if (ar === br) return 0;
    return ar < br ? 1 : -1;
  });
  return out;
}

// revokeDevice — flip the row to revoked. The router has already
// verified the per-action HMAC sig (action='device.revoke',
// target='device.revoke|<device_id>'); this function only persists the
// state change. `signatureB64` is captured on the row for post-incident
// audit so we can correlate the revoke with the action key id.
export async function revokeDevice(actor, deviceId, signatureB64) {
  if (!actor || typeof actor.uid !== 'string' || actor.uid.length === 0) {
    throw new ApiError('unauthorized', 'No session.', 401);
  }
  if (typeof deviceId !== 'string' || deviceId.length === 0) {
    throw new ApiError('bad_request', 'device_id required.', 400);
  }
  if (typeof signatureB64 !== 'string' || signatureB64.length === 0) {
    throw new ApiError('no_action_sig', 'action signature required.', 400);
  }
  const docId = `${actor.uid}__${deviceId}`;
  const existing = await fs().getDoc(COLLECTION, docId);
  if (!existing) {
    throw new NotFoundError('device_not_found', 'No such device for this user.');
  }
  if (existing.uid !== actor.uid) {
    throw new NotFoundError('device_not_found', 'No such device for this user.');
  }
  const now = nowIso();
  const updated = {
    ...existing,
    revoked: true,
    revoked_at: now,
    last_seen_at: now,
    revoke_signature_b64: signatureB64
  };
  await fs().setDoc(COLLECTION, docId, updated);
  return projectDevice(updated);
}

export const _internal = { COLLECTION, pubkeyThumbprint, isValidLabel, isValidPubkeyB64 };
