// Project Aether · Task Manager · multi-device-keys lane.
//
// Browser-side wrap/unwrap roundtrip + QR payload codec. The bundle
// targets the browser, but the source is plain ESM with `argon2id` from
// @noble/hashes and Web Crypto via globalThis.crypto. Node 22 ships
// node:crypto.webcrypto which satisfies the global, so we can exercise
// the same code in this test without spinning up a headless browser.
//
// Run: `node server/tm/_test/test-keywrap.mjs` -> prints OK.

import { webcrypto, randomBytes } from 'node:crypto';

if (!globalThis.crypto) globalThis.crypto = webcrypto;

import {
  wrapKeyringForExport,
  unwrapKeyringFromImport,
  generateMnemonic,
  encodeQrPayload,
  decodeQrPayload,
  MNEMONIC_WORDS,
  QR_PAYLOAD_VERSION,
  QR_PAYLOAD_TTL_SECS
} from '../_browser/auth-client.src.js';

let failed = 0;
function ok(name, cond, detail) {
  if (cond) {
    process.stdout.write(`  PASS  ${name}\n`);
  } else {
    failed++;
    process.stdout.write(`  FAIL  ${name}${detail ? ' :: ' + detail : ''}\n`);
  }
}

async function expectThrowAsync(name, fn, fragment) {
  try {
    await fn();
    ok(name, false, 'no throw');
  } catch (e) {
    const msg = String(e?.message || e);
    if (!fragment || msg.includes(fragment)) ok(name, true);
    else ok(name, false, `msg=${msg}`);
  }
}

function b64ToBytes(s) {
  return new Uint8Array(Buffer.from(s, 'base64'));
}
function bytesToB64(b) {
  return Buffer.from(b).toString('base64');
}

// Mock IDB keyring record. The blob represents an already-passphrase-
// sealed ML-DSA private key: { salt: 16B, iv: 12B, ct: <some bytes> }.
function makeKeyringRec() {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const ct = randomBytes(64); // representative inner ciphertext
  return {
    salt: bytesToB64(salt),
    iv: bytesToB64(iv),
    ct: bytesToB64(ct),
    pubkey_b64: bytesToB64(randomBytes(32))
  };
}

// 1. Mnemonic generator + word-list invariants.
{
  ok('MNEMONIC_WORDS has 256 entries', MNEMONIC_WORDS.length === 256);
  ok('MNEMONIC_WORDS all lowercase a-z',
    MNEMONIC_WORDS.every((w) => /^[a-z]+$/.test(w)));
  ok('MNEMONIC_WORDS all distinct',
    new Set(MNEMONIC_WORDS).size === 256);

  const m = generateMnemonic(4);
  const parts = m.split(' ');
  ok('generateMnemonic(4) yields 4 words', parts.length === 4);
  ok('generateMnemonic(4) words are in list',
    parts.every((w) => MNEMONIC_WORDS.includes(w)));

  const m6 = generateMnemonic(6);
  ok('generateMnemonic(6) yields 6 words', m6.split(' ').length === 6);

  // Bad inputs.
  let threw = false;
  try { generateMnemonic(0); } catch { threw = true; }
  ok('generateMnemonic(0) throws', threw);
  threw = false;
  try { generateMnemonic(13); } catch { threw = true; }
  ok('generateMnemonic(13) throws', threw);
  threw = false;
  try { generateMnemonic('four'); } catch { threw = true; }
  ok('generateMnemonic("four") throws', threw);
}

// 2. Wrap + unwrap roundtrip recovers the original keyring blob.
{
  const rec = makeKeyringRec();
  const mnemonic = generateMnemonic(4);
  const payload = await wrapKeyringForExport(rec, mnemonic);

  ok('wrap returns version 1', payload.v === QR_PAYLOAD_VERSION);
  ok('wrap returns wrapped_b64',
    typeof payload.wrapped_b64 === 'string' && payload.wrapped_b64.length > 0);
  ok('wrap returns 16-byte salt', b64ToBytes(payload.salt_b64).length === 16);
  ok('wrap returns 12-byte iv', b64ToBytes(payload.iv_b64).length === 12);
  ok('wrap echoes pubkey_b64', payload.pubkey_b64 === rec.pubkey_b64);
  ok('wrap stamps issued_at',
    Number.isInteger(payload.issued_at) && payload.issued_at > 0);
  ok('wrap stamps expires_at = issued_at + 300',
    payload.expires_at === payload.issued_at + QR_PAYLOAD_TTL_SECS);

  const restored = await unwrapKeyringFromImport(payload, mnemonic);
  ok('unwrap returns same salt', restored.salt === rec.salt);
  ok('unwrap returns same iv', restored.iv === rec.iv);
  ok('unwrap returns same ct', restored.ct === rec.ct);
}

// 3. Wrong mnemonic rejected.
{
  const rec = makeKeyringRec();
  const goodMnemonic = generateMnemonic(4);
  const payload = await wrapKeyringForExport(rec, goodMnemonic);

  let badMnemonic = generateMnemonic(4);
  // Belt-and-braces: ensure the second mnemonic differs from the first.
  while (badMnemonic === goodMnemonic) badMnemonic = generateMnemonic(4);

  await expectThrowAsync(
    'unwrap rejects wrong mnemonic',
    () => unwrapKeyringFromImport(payload, badMnemonic),
    'TM_UNWRAP_FAIL'
  );

  // Mnemonic with a word not in the list.
  await expectThrowAsync(
    'unwrap rejects mnemonic with foreign word',
    () => unwrapKeyringFromImport(payload, 'apple banana cherry doughnut'),
    'TM_BAD_MNEMONIC'
  );

  await expectThrowAsync(
    'unwrap rejects empty mnemonic',
    () => unwrapKeyringFromImport(payload, ''),
    'TM_BAD_MNEMONIC'
  );
}

// 4. Expired payload rejected.
{
  const rec = makeKeyringRec();
  const mnemonic = generateMnemonic(4);
  const payload = await wrapKeyringForExport(rec, mnemonic);

  // Pretend "now" is well past expires_at.
  const future = payload.expires_at + 60;
  await expectThrowAsync(
    'unwrap rejects expired payload',
    () => unwrapKeyringFromImport(payload, mnemonic, { now_secs: future }),
    'TM_UNWRAP_EXPIRED'
  );

  // Payload with manually backdated issued_at: future-skew check.
  const futurePayload = { ...payload, issued_at: payload.issued_at + 7200, expires_at: payload.expires_at + 7200 };
  await expectThrowAsync(
    'unwrap rejects payload with issued_at in the future',
    () => unwrapKeyringFromImport(futurePayload, mnemonic),
    'TM_UNWRAP_FUTURE'
  );

  // Bad version.
  const wrongVersion = { ...payload, v: 99 };
  await expectThrowAsync(
    'unwrap rejects wrong version',
    () => unwrapKeyringFromImport(wrongVersion, mnemonic),
    'TM_UNWRAP_BAD_VERSION'
  );
}

// 5. encode + decode QR payload roundtrip.
{
  const obj = { v: 1, hello: 'world', n: 42, arr: [1, 2, 3], nested: { a: 'b' } };
  const enc = encodeQrPayload(obj);
  ok('encodeQrPayload returns string', typeof enc === 'string' && enc.length > 0);
  ok('encodeQrPayload uses base64url alphabet',
    /^[A-Za-z0-9_-]+$/.test(enc));
  ok('encodeQrPayload omits padding', !enc.includes('='));

  const dec = decodeQrPayload(enc);
  ok('decodeQrPayload returns object', dec && typeof dec === 'object');
  ok('decodeQrPayload roundtrip equality',
    JSON.stringify(dec) === JSON.stringify(obj));

  // Real wrap payload roundtrip via QR codec.
  const rec = makeKeyringRec();
  const mnemonic = generateMnemonic(4);
  const payload = await wrapKeyringForExport(rec, mnemonic);
  const wire = encodeQrPayload(payload);
  ok('wrap payload encodes within QR Version 25 cap (< 2900 chars)', wire.length < 2900);
  const back = decodeQrPayload(wire);
  ok('wrap payload decodes byte-identical', JSON.stringify(back) === JSON.stringify(payload));
  const restored = await unwrapKeyringFromImport(back, mnemonic);
  ok('unwrap from decoded QR yields original blob',
    restored.salt === rec.salt && restored.iv === rec.iv && restored.ct === rec.ct);

  // Encode rejects non-objects.
  let threw = false;
  try { encodeQrPayload(null); } catch { threw = true; }
  ok('encodeQrPayload rejects null', threw);
  threw = false;
  try { encodeQrPayload([1, 2, 3]); } catch { threw = true; }
  ok('encodeQrPayload rejects array', threw);

  // Decode rejects garbage.
  threw = false;
  try { decodeQrPayload('not!base64!'); } catch { threw = true; }
  ok('decodeQrPayload rejects invalid base64', threw);
  threw = false;
  try { decodeQrPayload(''); } catch { threw = true; }
  ok('decodeQrPayload rejects empty', threw);
}

// 6. Mnemonic case + whitespace tolerated.
{
  const rec = makeKeyringRec();
  const mnemonic = 'apple arrow autumn azure';
  const payload = await wrapKeyringForExport(rec, mnemonic);
  const variants = [
    'APPLE ARROW AUTUMN AZURE',
    'apple   arrow  autumn  azure',
    '  apple arrow autumn azure  '
  ];
  for (const v of variants) {
    const restored = await unwrapKeyringFromImport(payload, v);
    ok(`unwrap accepts mnemonic variant: ${JSON.stringify(v)}`,
      restored.salt === rec.salt && restored.ct === rec.ct);
  }
}

if (failed === 0) {
  process.stdout.write('OK\n');
  process.exit(0);
} else {
  process.stdout.write(`FAIL: ${failed} assertion(s) failed\n`);
  process.exit(1);
}
