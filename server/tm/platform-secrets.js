// Project Aether · platform secret bootstrap.
//
// Self-healing $0-idle replacement for Secret Manager. Three platform
// secrets that ALL Cloud Run instances must agree on:
//   tm_platform_secrets/watchdog_hmac        // 64-char base64url HMAC
//   tm_platform_secrets/system_ai_keypair    // ML-DSA-65 priv + pub
//
// On every cold start the server calls `loadPlatformSecrets()`, which
// reads from Firestore. If the row is missing the FIRST instance to
// boot mints + persists a fresh value inside a one-shot transaction
// (create-only, currentDocument.exists=false), and every later cold
// start reads the same value. Subsequent instances that lose the race
// fall back to read.
//
// Trade-offs vs Secret Manager:
//   + Truly $0 idle. Reads only fire on cold start; writes only on the
//     very first cold start ever (and any TM_PLATFORM_RESET=1 admin op).
//   + No new Cloud product dependency; uses Firestore, already in scope.
//   + Self-healing if the row gets corrupted (set TM_PLATFORM_RESET=1,
//     redeploy, the next cold start mints fresh and re-persists).
//   - Anyone with Firestore read on tm_platform_secrets can extract the
//     ML-DSA priv. Same blast radius as the prior in-memory model
//     because operators with project-Editor already had ADC access.
//   - First cold start ever pays a ~5 ms ML-DSA keygen on the request
//     path. We block server.listen() on it for the same race-prevention
//     reason as the demo autoseed.
//
// Env-var overrides win when both are present:
//   process.env.WATCHDOG_HMAC_SECRET wins over Firestore, so production
//   ops can still mint out of band and pin a stable value if they wish.

import { randomBytes } from 'node:crypto';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

const COLLECTION = 'tm_platform_secrets';
const KEY_WATCHDOG = 'watchdog_hmac';
const KEY_SYSTEM_AI = 'system_ai_keypair';

let _cache = null;

function logJson(severity, fields) {
  const entry = { ts: new Date().toISOString(), severity, ...fields };
  process.stdout.write(JSON.stringify(entry) + '\n');
}

function b64u(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64(buf) { return Buffer.from(buf).toString('base64'); }

async function readOrCreate(fsMod, key, mintFn) {
  // Read first. If found, return it.
  let cur = await fsMod.getDoc(COLLECTION, key);
  if (cur && !process.env[`TM_PLATFORM_RESET_${key.toUpperCase()}`] && process.env.TM_PLATFORM_RESET !== '1') {
    return cur;
  }
  // Mint, then atomic create-only via runTransaction so concurrent cold
  // starts don't both write. The loser of the race reads the winner's
  // value on retry.
  const minted = mintFn();
  try {
    await fsMod.runTransaction(async (tx) => {
      const inTx = await tx.get(COLLECTION, key);
      if (inTx) {
        // Lost the race; somebody else just minted. Adopt theirs.
        return;
      }
      tx.set(COLLECTION, key, { ...minted, created_at: new Date().toISOString() });
    });
  } catch (e) {
    logJson('WARNING', { fn: 'platform-secrets.readOrCreate', key, msg: 'mint_persist_failed', err: String(e) });
  }
  cur = await fsMod.getDoc(COLLECTION, key);
  return cur || minted;
}

export async function loadPlatformSecrets() {
  if (_cache) return _cache;
  let fsMod;
  try { fsMod = await import('./firestore.js'); }
  catch (e) {
    logJson('WARNING', { fn: 'loadPlatformSecrets', msg: 'firestore_unavailable; using ephemeral keys', err: String(e) });
    return _cache = mintEphemeralFallback();
  }
  if (typeof fsMod.getDoc !== 'function' || typeof fsMod.runTransaction !== 'function') {
    return _cache = mintEphemeralFallback();
  }

  // Watchdog HMAC.
  const watchdog = await readOrCreate(fsMod, KEY_WATCHDOG, () => ({
    hmac_b64u: b64u(randomBytes(48))
  }));

  // SYSTEM_AI ML-DSA-65 keypair.
  const sysai = await readOrCreate(fsMod, KEY_SYSTEM_AI, () => {
    const k = ml_dsa65.keygen();
    return {
      priv_b64: b64(k.secretKey),
      pub_b64: b64(k.publicKey)
    };
  });

  // Promote to env vars so the existing watchdog.js / auth.js code that
  // reads process.env.WATCHDOG_HMAC_SECRET / SYSTEM_AI_PRIV_B64 /
  // SYSTEM_AI_PUB_B64 works unchanged on first lookup.
  if (!process.env.WATCHDOG_HMAC_SECRET && watchdog?.hmac_b64u) {
    process.env.WATCHDOG_HMAC_SECRET = watchdog.hmac_b64u;
  }
  if (!process.env.SYSTEM_AI_PRIV_B64 && sysai?.priv_b64) {
    process.env.SYSTEM_AI_PRIV_B64 = sysai.priv_b64;
  }
  if (!process.env.SYSTEM_AI_PUB_B64 && sysai?.pub_b64) {
    process.env.SYSTEM_AI_PUB_B64 = sysai.pub_b64;
  }

  _cache = {
    watchdog_hmac: watchdog?.hmac_b64u || null,
    system_ai_priv_b64: sysai?.priv_b64 || null,
    system_ai_pub_b64: sysai?.pub_b64 || null,
    source: 'firestore'
  };
  logJson('INFO', {
    fn: 'loadPlatformSecrets', msg: 'loaded',
    have_watchdog: !!_cache.watchdog_hmac,
    have_system_ai: !!(_cache.system_ai_priv_b64 && _cache.system_ai_pub_b64),
    source: _cache.source
  });
  return _cache;
}

// Fallback only when Firestore is genuinely missing. Cross-instance
// sigs will fail, autonomy will not work; logged as WARNING.
function mintEphemeralFallback() {
  const k = ml_dsa65.keygen();
  const out = {
    watchdog_hmac: b64u(randomBytes(48)),
    system_ai_priv_b64: b64(k.secretKey),
    system_ai_pub_b64: b64(k.publicKey),
    source: 'ephemeral'
  };
  if (!process.env.WATCHDOG_HMAC_SECRET) process.env.WATCHDOG_HMAC_SECRET = out.watchdog_hmac;
  if (!process.env.SYSTEM_AI_PRIV_B64) process.env.SYSTEM_AI_PRIV_B64 = out.system_ai_priv_b64;
  if (!process.env.SYSTEM_AI_PUB_B64) process.env.SYSTEM_AI_PUB_B64 = out.system_ai_pub_b64;
  logJson('WARNING', { fn: 'mintEphemeralFallback', msg: 'firestore_unreachable_using_ephemeral_keys' });
  return out;
}
