// Project Aether · Task Manager · browser auth client (source).
//
// Bundled to /web/tm/auth-client.js by `esbuild`. The bundle is what
// ships; this source is checked in for review and reproducibility.
//
// Two responsibilities live here:
//   1. ML-DSA-65 keypair gen + login challenge sign (one-shot at login).
//   2. HMAC-SHA256 per-action signature (every mutating call).
//
// `canonicalActionMessage` is imported from server/tm/canonical.js so
// the wire-format string is byte-identical to what the server
// canonicalises before HMAC verify. Drift between client and server
// canonicals is what broke the previous build; sharing the file makes
// it impossible.

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { argon2id } from '@noble/hashes/argon2.js';

import { canonicalActionMessage } from '../canonical.js';

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

// multi-device-keys lane.
//
// Word list for the 4-word mnemonic that wraps the keyring blob during
// device-to-device transfer. 256 short, common, distinguishable English
// words -> log2(256^4) = 32 bits per mnemonic, which is sufficient when
// paired with the 5-minute payload TTL and the offline (visual) channel.
// The list is intentionally inline so the browser bundle has zero
// network dependency for the QR bridge.
const MNEMONIC_WORDS = Object.freeze([
  'apple', 'arrow', 'autumn', 'azure', 'badge', 'baker', 'banjo', 'basil',
  'beach', 'beard', 'beast', 'beech', 'belly', 'berry', 'birch', 'bison',
  'black', 'blaze', 'bloom', 'blue', 'board', 'bonus', 'brace', 'brass',
  'brave', 'bread', 'brick', 'broom', 'brown', 'brush', 'buddy', 'bulb',
  'cabin', 'cable', 'cacao', 'cadet', 'cage', 'cairn', 'cake', 'calm',
  'camel', 'camp', 'canal', 'candy', 'cape', 'card', 'cargo', 'carve',
  'cedar', 'chalk', 'charm', 'chase', 'cheek', 'chef', 'chess', 'chest',
  'chime', 'chop', 'cider', 'cigar', 'cliff', 'climb', 'cloak', 'cloud',
  'clove', 'clown', 'coast', 'cocoa', 'coral', 'cosy', 'cotton', 'crab',
  'craft', 'crane', 'crash', 'crew', 'crisp', 'cross', 'crown', 'crumb',
  'cube', 'cup', 'curl', 'daily', 'daisy', 'dance', 'dawn', 'deer',
  'delta', 'desk', 'diary', 'diner', 'dish', 'ditch', 'dive', 'dock',
  'donor', 'door', 'dough', 'drive', 'drum', 'duck', 'dune', 'dusk',
  'eagle', 'earth', 'ebony', 'eddy', 'eight', 'elbow', 'elder', 'elite',
  'ember', 'emoji', 'empty', 'epoch', 'equal', 'event', 'extra', 'fable',
  'fade', 'fair', 'falcon', 'fancy', 'fawn', 'felt', 'fern', 'ferry',
  'field', 'fig', 'film', 'final', 'finch', 'fjord', 'flag', 'flame',
  'flask', 'flax', 'flint', 'float', 'flora', 'flock', 'foam', 'forge',
  'fox', 'frame', 'fresh', 'frog', 'frost', 'gaze', 'gear', 'gem',
  'ghost', 'giant', 'ginger', 'glade', 'glass', 'glide', 'globe', 'glow',
  'gold', 'grain', 'grape', 'grass', 'grid', 'grove', 'guide', 'gulf',
  'happy', 'hare', 'harp', 'haven', 'hawk', 'hazel', 'helm', 'heron',
  'hill', 'hint', 'hollow', 'honey', 'horn', 'hotel', 'house', 'human',
  'ice', 'igloo', 'image', 'inca', 'index', 'iron', 'island', 'ivory',
  'ivy', 'jade', 'jam', 'jar', 'jazz', 'jelly', 'jewel', 'joy',
  'judge', 'juice', 'kale', 'karma', 'kayak', 'kettle', 'kind', 'king',
  'kite', 'kiwi', 'knee', 'knot', 'koala', 'lake', 'lamp', 'land',
  'lane', 'larch', 'lark', 'lava', 'lawn', 'leaf', 'lemon', 'lens',
  'level', 'light', 'lilac', 'lily', 'lime', 'linen', 'lion', 'list',
  'llama', 'log', 'lotus', 'loyal', 'lucky', 'lunar', 'lyric', 'magic',
  'maple', 'march', 'marsh', 'mason', 'mate', 'meadow', 'melon', 'mesa',
  'mint', 'mist', 'moon', 'moss', 'motor', 'mouse', 'mud', 'muse'
]);

if (MNEMONIC_WORDS.length !== 256) {
  // Compile-time invariant. Keeping the assertion in shipped code is
  // cheap and guarantees the wrap-key derivation has the documented
  // 32 bits of entropy per mnemonic.
  throw new Error('TM_MNEMONIC_LIST_BAD_LEN');
}

const QR_PAYLOAD_VERSION = 1;
const QR_PAYLOAD_TTL_SECS = 5 * 60;
const QR_PAYLOAD_MAX_AGE_SECS = QR_PAYLOAD_TTL_SECS;
const QR_PAYLOAD_FUTURE_SKEW_SECS = 60;

function generateMnemonic(words = 4) {
  const n = Number(words);
  if (!Number.isFinite(n) || !Number.isInteger(n) || n < 1 || n > 12) {
    throw new Error('TM_BAD_MNEMONIC_LEN: words must be integer 1..12');
  }
  const c = getCrypto();
  const out = new Array(n);
  // Rejection-free draw: 256 is a power of 2 <= 256, so each random byte
  // maps to exactly one word with no modulo bias.
  const rand = c.getRandomValues(new Uint8Array(n));
  for (let i = 0; i < n; i++) out[i] = MNEMONIC_WORDS[rand[i]];
  return out.join(' ');
}

function normaliseMnemonic(mnemonic) {
  if (typeof mnemonic !== 'string') {
    throw new Error('TM_BAD_MNEMONIC: mnemonic must be a string');
  }
  const words = mnemonic.trim().toLowerCase().split(/\s+/).filter((w) => w.length > 0);
  if (words.length === 0) {
    throw new Error('TM_BAD_MNEMONIC: mnemonic is empty');
  }
  for (const w of words) {
    if (!MNEMONIC_WORDS.includes(w)) {
      throw new Error('TM_BAD_MNEMONIC: word not in list: ' + w);
    }
  }
  return words.join(' ');
}

async function deriveWrapKey(mnemonic, salt) {
  const norm = normaliseMnemonic(mnemonic);
  const raw = argon2id(norm, salt, {
    t: ARGON_T,
    m: ARGON_M,
    p: ARGON_P,
    dkLen: ARGON_DK
  });
  const c = getCrypto();
  return c.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

function _packKeyringBlob(rec) {
  if (!rec || typeof rec !== 'object') {
    throw new Error('TM_BAD_REC: keyring record must be an object');
  }
  const salt = typeof rec.salt === 'string' ? b64Dec(rec.salt) : rec.salt;
  const iv = typeof rec.iv === 'string' ? b64Dec(rec.iv) : rec.iv;
  const ct = typeof rec.ct === 'string' ? b64Dec(rec.ct) : rec.ct;
  if (!(salt instanceof Uint8Array) || salt.length !== SALT_LEN) {
    throw new Error('TM_BAD_REC: rec.salt must be 16 bytes');
  }
  if (!(iv instanceof Uint8Array) || iv.length !== IV_LEN) {
    throw new Error('TM_BAD_REC: rec.iv must be 12 bytes');
  }
  if (!(ct instanceof Uint8Array) || ct.length === 0 || ct.length > 8192) {
    throw new Error('TM_BAD_REC: rec.ct must be 1..8192 bytes');
  }
  // Fixed-layout container: [salt(16) | iv(12) | ct].
  const out = new Uint8Array(SALT_LEN + IV_LEN + ct.length);
  out.set(salt, 0);
  out.set(iv, SALT_LEN);
  out.set(ct, SALT_LEN + IV_LEN);
  return out;
}

function _unpackKeyringBlob(buf) {
  if (!(buf instanceof Uint8Array)) {
    throw new Error('TM_UNWRAP_FAIL: blob must be Uint8Array');
  }
  if (buf.length < SALT_LEN + IV_LEN + 1) {
    throw new Error('TM_UNWRAP_FAIL: blob too short');
  }
  const salt = buf.slice(0, SALT_LEN);
  const iv = buf.slice(SALT_LEN, SALT_LEN + IV_LEN);
  const ct = buf.slice(SALT_LEN + IV_LEN);
  return {
    salt: b64(salt),
    iv: b64(iv),
    ct: b64(ct)
  };
}

// wrapKeyringForExport — given the IDB keyring record `{salt, iv, ct}`
// (the ML-DSA private key already AES-GCM-sealed under the user's
// passphrase) and a 4-word mnemonic, returns a payload object with a
// fresh AES-GCM seal under a wrap-key derived from the mnemonic.
//
// The wrap is layered on top of the existing passphrase encryption so
// that even if the QR is captured the attacker still needs the user's
// passphrase to use the recovered keyring.
//
// Output:
//   { v, wrapped_b64, salt_b64, iv_b64, pubkey_b64, issued_at, expires_at }
async function wrapKeyringForExport(rec, mnemonic, opts) {
  const blob = _packKeyringBlob(rec);
  const c = getCrypto();
  const wrapSalt = c.getRandomValues(new Uint8Array(SALT_LEN));
  const wrapIv = c.getRandomValues(new Uint8Array(IV_LEN));
  const key = await deriveWrapKey(mnemonic, wrapSalt);
  const wrapped = new Uint8Array(await c.subtle.encrypt({ name: 'AES-GCM', iv: wrapIv }, key, blob));
  const issuedAt = Math.floor(Date.now() / 1000);
  const ttl = (opts && Number.isInteger(opts.ttl_secs) && opts.ttl_secs > 0)
    ? opts.ttl_secs : QR_PAYLOAD_TTL_SECS;
  const pubkeyB64 = (rec && typeof rec.pubkey_b64 === 'string') ? rec.pubkey_b64 : '';
  return {
    v: QR_PAYLOAD_VERSION,
    wrapped_b64: b64(wrapped),
    salt_b64: b64(wrapSalt),
    iv_b64: b64(wrapIv),
    pubkey_b64: pubkeyB64,
    issued_at: issuedAt,
    expires_at: issuedAt + ttl
  };
}

// unwrapKeyringFromImport — reverse of wrapKeyringForExport. Validates
// `expires_at` against the local clock with a small skew allowance so a
// captured QR cannot be replayed beyond the 5-minute TTL.
async function unwrapKeyringFromImport(qrPayload, mnemonic, opts) {
  if (!qrPayload || typeof qrPayload !== 'object') {
    throw new Error('TM_UNWRAP_BAD_PAYLOAD: qrPayload must be an object');
  }
  if (qrPayload.v !== QR_PAYLOAD_VERSION) {
    throw new Error('TM_UNWRAP_BAD_VERSION: payload v=' + qrPayload.v);
  }
  const issuedAt = Number(qrPayload.issued_at);
  const expiresAt = Number(qrPayload.expires_at);
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt)) {
    throw new Error('TM_UNWRAP_BAD_TS: issued_at/expires_at malformed');
  }
  const now = Math.floor((opts && typeof opts.now_secs === 'number' ? opts.now_secs : Date.now() / 1000));
  if (issuedAt > now + QR_PAYLOAD_FUTURE_SKEW_SECS) {
    throw new Error('TM_UNWRAP_FUTURE: issued_at is in the future');
  }
  if (expiresAt <= now) {
    throw new Error('TM_UNWRAP_EXPIRED: payload TTL elapsed');
  }
  if (expiresAt - issuedAt > QR_PAYLOAD_MAX_AGE_SECS + QR_PAYLOAD_FUTURE_SKEW_SECS) {
    throw new Error('TM_UNWRAP_BAD_TTL: payload TTL exceeds policy');
  }
  const wrapped = b64Dec(String(qrPayload.wrapped_b64 || ''));
  const wrapSalt = b64Dec(String(qrPayload.salt_b64 || ''));
  const wrapIv = b64Dec(String(qrPayload.iv_b64 || ''));
  if (wrapSalt.length !== SALT_LEN) throw new Error('TM_UNWRAP_BAD_SALT: salt must be 16 bytes');
  if (wrapIv.length !== IV_LEN) throw new Error('TM_UNWRAP_BAD_IV: iv must be 12 bytes');
  const key = await deriveWrapKey(mnemonic, wrapSalt);
  let pt;
  try {
    pt = new Uint8Array(await getCrypto().subtle.decrypt({ name: 'AES-GCM', iv: wrapIv }, key, wrapped));
  } catch {
    throw new Error('TM_UNWRAP_FAIL: wrong mnemonic or corrupted payload');
  }
  return _unpackKeyringBlob(pt);
}

// QR encode/decode. JSON -> base64url. Fits inside QR Version 25 (~2 KB).
function encodeQrPayload(obj) {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new Error('TM_QR_ENCODE_BAD: obj must be a plain object');
  }
  const json = JSON.stringify(obj);
  const bytes = utf8(json);
  const out = b64u(bytes);
  if (out.length > 2900) {
    // QR Version 25 (alphanumeric, ECC L) ~ 2953 chars; fail loudly so
    // the caller knows the payload will not fit instead of generating a
    // QR that some scanners truncate silently.
    throw new Error('TM_QR_ENCODE_TOO_LARGE: payload exceeds QR Version 25 capacity');
  }
  return out;
}

function decodeQrPayload(str) {
  if (typeof str !== 'string' || str.length === 0) {
    throw new Error('TM_QR_DECODE_EMPTY: input must be a non-empty string');
  }
  let bytes;
  try { bytes = b64uDec(str.trim()); }
  catch { throw new Error('TM_QR_DECODE_B64: not valid base64url'); }
  let json;
  try { json = utf8Dec(bytes); }
  catch { throw new Error('TM_QR_DECODE_UTF8: not valid utf-8'); }
  let obj;
  try { obj = JSON.parse(json); }
  catch { throw new Error('TM_QR_DECODE_JSON: not valid JSON'); }
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new Error('TM_QR_DECODE_SHAPE: payload must be a plain object');
  }
  return obj;
}

// hmacActionSig — ~50 byte equivalent of the old 3.3 KB ML-DSA per-action
// signature. Caller passes the session-bound action key (32 raw bytes,
// returned in the login response and rotated on every authenticated
// call) plus the canonical args. Returns base64url over 32-byte tag.
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
  generateKeypair,
  encryptPriv,
  decryptPriv,
  sign,
  hmacActionSig,
  canonicalActionMessage,
  wrapKeyringForExport,
  unwrapKeyringFromImport,
  generateMnemonic,
  encodeQrPayload,
  decodeQrPayload,
  MNEMONIC_WORDS,
  QR_PAYLOAD_VERSION,
  QR_PAYLOAD_TTL_SECS,
  b64,
  b64Dec,
  b64u,
  b64uDec,
  utf8,
  utf8Dec
};
