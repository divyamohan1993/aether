// Project Aether · Task Manager · browser auth client (source).
//
// Bundled to /web/tm/auth-client.js by tools/build-auth-client.mjs using
// esbuild. The bundle is what ships; this source is checked in for
// review and reproducibility. The browser cannot do bare ESM imports of
// npm packages, so the bundle is the only artifact loaded by the page.

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { argon2id } from '@noble/hashes/argon2.js';

const ARGON_T = 3;
const ARGON_M = 64 * 1024;
const ARGON_P = 1;
const ARGON_DK = 32;
const SALT_LEN = 16;
const IV_LEN = 12;

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

function generateKeypair() {
  const k = ml_dsa65.keygen();
  return { pub: k.publicKey, priv: k.secretKey };
}

function sign(priv, msgUtf8) {
  if (!(priv instanceof Uint8Array)) throw new Error('TM_BAD_PRIV: priv must be Uint8Array');
  const msg = msgUtf8 instanceof Uint8Array ? msgUtf8 : utf8(String(msgUtf8));
  const sig = ml_dsa65.sign(msg, priv);
  return b64u(sig);
}

async function deriveKey(passphrase, salt) {
  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    throw new Error('TM_BAD_PASSPHRASE: passphrase required');
  }
  const raw = argon2id(passphrase, salt, {
    t: ARGON_T,
    m: ARGON_M,
    p: ARGON_P,
    dkLen: ARGON_DK
  });
  const c = getCrypto();
  return c.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function encryptPriv(priv, passphrase) {
  if (!(priv instanceof Uint8Array)) throw new Error('TM_BAD_PRIV: priv must be Uint8Array');
  const c = getCrypto();
  const salt = c.getRandomValues(new Uint8Array(SALT_LEN));
  const iv = c.getRandomValues(new Uint8Array(IV_LEN));
  const key = await deriveKey(passphrase, salt);
  const ct = new Uint8Array(await c.subtle.encrypt({ name: 'AES-GCM', iv }, key, priv));
  return { saltB64: b64(salt), ivB64: b64(iv), ctB64: b64(ct) };
}

async function decryptPriv(saltB64, ivB64, ctB64, passphrase) {
  const salt = b64Dec(saltB64);
  const iv = b64Dec(ivB64);
  const ct = b64Dec(ctB64);
  if (salt.length !== SALT_LEN) throw new Error('TM_BAD_SALT: salt must be 16 bytes');
  if (iv.length !== IV_LEN) throw new Error('TM_BAD_IV: iv must be 12 bytes');
  const key = await deriveKey(passphrase, salt);
  let pt;
  try {
    pt = new Uint8Array(await getCrypto().subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));
  } catch {
    throw new Error('TM_DECRYPT_FAIL: wrong passphrase or corrupted ciphertext');
  }
  return pt;
}

export {
  generateKeypair,
  encryptPriv,
  decryptPriv,
  sign,
  b64,
  b64Dec,
  b64u,
  b64uDec,
  utf8,
  utf8Dec
};
