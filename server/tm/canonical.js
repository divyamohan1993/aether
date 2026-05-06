// Project Aether · Task Manager · canonical action message format.
//
// Single source of truth shared by server (HMAC verify) and browser
// (HMAC sign). Both sides MUST produce byte-identical output for the
// same inputs, so this module ships unchanged to the browser bundle
// (server/tm/_browser/auth-client.src.js inlines the same builder).
//
// The format is a hand-built JSON string with a fixed key order:
//   {"action":"...","key_id":"...","target":"...","ts":<int>,"uid":"..."}
// We do not rely on `JSON.stringify(object)` honouring insertion order;
// instead we emit each field in alphabetical order and let
// `JSON.stringify` handle string escaping. This keeps the encoding
// deterministic across Node, Chromium, WebKit, and Gecko.
//
// CRITICAL_ACTIONS lists the actions that must carry a fresh HMAC
// signature in the X-Action-Sig header. Routes outside this list are
// auth-only (bearer suffices). Adding a new mutating route means
// extending this list AND adding the call site in server/tm/router.js.

const CRITICAL_ACTIONS = Object.freeze([
  'user.invite',
  'user.delegate',
  'project.archive',
  'task.assign',
  'dispatch.escalate',
  'dispatch.assign',
  'dispatch.review',
  'unit.update',
  'unit.archive',
  'assignment.update'
]);

function _err(code) {
  const e = new Error(code);
  e.code = code;
  return e;
}

function canonicalActionMessage(args) {
  if (!args || typeof args !== 'object') throw _err('canonical_bad_args');
  const { uid, action, target, ts, key_id } = args;
  if (typeof uid !== 'string' || uid.length === 0 || uid.length > 256) throw _err('canonical_bad_uid');
  if (typeof action !== 'string' || action.length === 0 || action.length > 64) throw _err('canonical_bad_action');
  if (typeof target !== 'string' || target.length > 1024) throw _err('canonical_bad_target');
  if (typeof ts !== 'number' || !Number.isFinite(ts) || !Number.isInteger(ts) || ts < 0) throw _err('canonical_bad_ts');
  if (typeof key_id !== 'string' || key_id.length === 0 || key_id.length > 64) throw _err('canonical_bad_key_id');
  return '{"action":' + JSON.stringify(action)
    + ',"key_id":' + JSON.stringify(key_id)
    + ',"target":' + JSON.stringify(target)
    + ',"ts":' + ts
    + ',"uid":' + JSON.stringify(uid)
    + '}';
}

function isCriticalAction(action) {
  return typeof action === 'string' && CRITICAL_ACTIONS.includes(action);
}

export { canonicalActionMessage, isCriticalAction, CRITICAL_ACTIONS };
