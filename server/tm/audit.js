// Append-only audit log for the Task Manager module.
// Every mutation routes here. Records carry the actor signature when one
// was required by the API contract (delegate, project archive, etc).

import { randomUUID } from 'node:crypto';
import { setDoc, FirestoreError } from './firestore.js';

function logJson(severity, fields) {
  const entry = { ts: new Date().toISOString(), severity, ...fields };
  process.stdout.write(JSON.stringify(entry) + '\n');
}

function summarize(payload) {
  if (!payload || typeof payload !== 'object') return {};
  const out = {};
  for (const [k, v] of Object.entries(payload)) {
    if (v === null || v === undefined) continue;
    if (k === 'pubkey_b64' || k === 'signature_b64' || k === 'action_signature' || k === 'passphrase') continue;
    if (typeof v === 'string') out[k] = v.length > 256 ? v.slice(0, 256) + '...' : v;
    else if (typeof v === 'number' || typeof v === 'boolean') out[k] = v;
    else if (Array.isArray(v)) out[k] = v.slice(0, 10).map((x) => typeof x === 'string' ? x.slice(0, 64) : x);
    else if (typeof v === 'object') out[k] = '[object]';
  }
  return out;
}

// Append an entry. Best-effort: failures are logged but never thrown to
// callers, since audit failure must not abort the requested mutation.
export async function record(actorUid, action, targetRef, payload, actorSignatureB64) {
  const aid = randomUUID();
  const data = {
    ts: new Date(),
    actor_uid: actorUid || 'unknown',
    action: String(action),
    target_ref: String(targetRef),
    payload_summary: summarize(payload),
    actor_signature_b64: actorSignatureB64 || null
  };
  try {
    await setDoc('tm_audit', aid, data);
    return aid;
  } catch (e) {
    const code = e instanceof FirestoreError ? e.code : 'UNKNOWN';
    logJson('ERROR', {
      fn: 'audit.record',
      msg: 'audit_write_failed',
      action,
      target_ref: String(targetRef),
      actor_uid: actorUid || null,
      code,
      err: String(e)
    });
    return null;
  }
}
