// Project Aether · Task Manager · browser auth client (slim).
//
// Bundled to /web/tm/auth-client.js by tools/build-auth-client.mjs.
//
// MVP login posture: passphrases ride TLS to the server, server-side
// scrypt verifies them. The browser no longer runs ML-DSA-65 or
// Argon2id, so the bundle is a couple of KB instead of 14 KB brotli.
//
// What survives here is the per-action HMAC the server requires on
// critical mutating routes (delegate, archive, dispatch.escalate, etc.).
// SubtleCrypto handles the HMAC; canonicalActionMessage stays lock-step
// with server/tm/canonical.js so client + server hash byte-identical
// inputs.

import { canonicalActionMessage } from '../canonical.js';

function utf8(s) { return new TextEncoder().encode(s); }
function utf8Dec(b) { return new TextDecoder('utf-8', { fatal: true }).decode(b); }

function b64(buf) {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < b.length; i++) bin += String.fromCharCode(b[i]);
  return btoa(bin);
}

function b64Dec(str) {
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64u(buf) {
  return b64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64uDec(str) {
  const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
  return b64Dec(str.replace(/-/g, '+').replace(/_/g, '/') + pad);
}

function getCrypto() {
  const c = globalThis.crypto;
  if (!c || !c.subtle || typeof c.getRandomValues !== 'function') {
    throw new Error('TM_NO_WEBCRYPTO: this browser does not expose window.crypto.subtle');
  }
  return c;
}

// hmacActionSig — ~50 byte signature on critical mutating actions.
// Caller passes the session-bound action key (32 raw bytes, returned
// in the login response and rotated on every authenticated call) and
// the canonical args. Returns base64url over the 32-byte HMAC tag.
async function hmacActionSig(actionKeyBytes, args) {
  if (!(actionKeyBytes instanceof Uint8Array) || actionKeyBytes.length !== 32) {
    throw new Error('TM_BAD_ACTION_KEY: action key must be 32 bytes');
  }
  const message = canonicalActionMessage(args);
  const c = getCrypto();
  const key = await c.subtle.importKey(
    'raw',
    actionKeyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const tag = new Uint8Array(await c.subtle.sign('HMAC', key, utf8(message)));
  return b64u(tag);
}

export {
  hmacActionSig,
  canonicalActionMessage,
  b64,
  b64Dec,
  b64u,
  b64uDec,
  utf8,
  utf8Dec
};
