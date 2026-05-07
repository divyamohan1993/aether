// Project Aether · demo auto-reseed.
//
// Cold-start hook that ensures the published demo identities exist in
// Firestore with a freshly hashed copy of the published passphrase. The
// passphrase itself is public on /demo so this is purely a usability
// fix: every cold start guarantees a working demo login regardless of
// what state the prior revision left in Firestore (stale ML-DSA pubkey
// fields, missing password_salt_b64u, etc.).
//
// Gated by TM_AUTO_RESEED_DEMO=1 (set in deploy/deploy.sh). Real users
// in non-demo scopes are NEVER touched: only emails matching the
// allow-list below are upserted, and only docs whose existing
// scope_path either is missing or already starts with `demo`.
//
// Idempotent: if the existing doc already carries a verifying
// password_hash_b64u for the published passphrase, the upsert is
// skipped. This keeps Firestore writes near-zero on warm restarts.
//
// Production posture: leave TM_AUTO_RESEED_DEMO unset; this module
// becomes a no-op. The MLP deploy sets it to 1.

import { randomUUID } from 'node:crypto';
import { hashPassword, verifyPassword } from './auth.js';

const DEMO_PASSPHRASE = process.env.TM_DEMO_PASSPHRASE || 'aether-demo-2026';

// Mirrors server/tm/seed-demo.mjs SEEDS exactly. Adding a new demo
// account is a two-step change: extend this array AND extend the seed
// CLI list. The runtime never persists projects/tasks/units; if the
// dispatcher needs them, run `node server/tm/seed-demo.mjs` once with
// ADC.
const SEEDS = [
  {
    key: 'ndma',
    email: 'demo.ndma@aether.dmj.one',
    name: 'Demo NDMA Coordinator',
    tier: 100,
    scope_path: 'demo',
    parent_key: null
  },
  {
    key: 'sdma',
    email: 'demo.state@aether.dmj.one',
    name: 'Demo SDMA Officer',
    tier: 80,
    scope_path: 'demo/HP',
    parent_key: 'ndma'
  },
  {
    key: 'ddma',
    email: 'demo.district@aether.dmj.one',
    name: 'Demo DDMA Magistrate',
    tier: 60,
    scope_path: 'demo/HP/Shimla',
    parent_key: 'sdma'
  },
  {
    key: 'subdivisional',
    email: 'demo.responder@aether.dmj.one',
    name: 'Demo Subdivisional Officer',
    tier: 40,
    scope_path: 'demo/HP/Shimla/responder1',
    parent_key: 'ddma'
  },
  {
    key: 'volunteer',
    email: 'demo.volunteer@aether.dmj.one',
    name: 'Demo Volunteer',
    tier: 20,
    scope_path: 'demo/HP/Shimla/responder1/vol1',
    parent_key: 'subdivisional'
  }
];

function logJson(severity, fields) {
  const entry = { ts: new Date().toISOString(), severity, ...fields };
  process.stdout.write(JSON.stringify(entry) + '\n');
}

function isDemoScope(s) {
  return typeof s === 'string' && (s === 'demo' || s.startsWith('demo/'));
}

function normaliseEmail(e) {
  return String(e || '').trim().toLowerCase();
}

// Run once. Safe to call multiple times — every call re-hashes the
// passphrase against a fresh salt and overwrites the doc, so even if a
// previous revision wrote a corrupt hash the next cold start cleans it.
export async function autoReseedDemoIfEnabled() {
  if (process.env.TM_AUTO_RESEED_DEMO !== '1') return { ran: false, reason: 'flag_off' };
  let fsMod;
  try { fsMod = await import('./firestore.js'); }
  catch (e) {
    logJson('WARNING', { fn: 'autoReseedDemoIfEnabled', msg: 'firestore_unavailable', err: String(e) });
    return { ran: false, reason: 'firestore_load_failed' };
  }
  if (typeof fsMod.setDoc !== 'function' || typeof fsMod.getDoc !== 'function') {
    logJson('WARNING', { fn: 'autoReseedDemoIfEnabled', msg: 'firestore_incomplete' });
    return { ran: false, reason: 'firestore_incomplete' };
  }

  const ephemeral = typeof fsMod.isEphemeralMode === 'function' && fsMod.isEphemeralMode();
  const provisioned = {};
  let written = 0;
  let skipped = 0;

  for (const seed of SEEDS) {
    const email = normaliseEmail(seed.email);
    let parentUid = null;
    if (seed.parent_key && provisioned[seed.parent_key]) {
      parentUid = provisioned[seed.parent_key];
    }

    let uid = null;
    let existing = null;
    try {
      const idx = await fsMod.getDoc('tm_user_emails', email);
      if (idx && typeof idx.uid === 'string') {
        uid = idx.uid;
        existing = await fsMod.getDoc('tm_users', uid);
      }
    } catch (e) {
      logJson('WARNING', { fn: 'autoReseedDemoIfEnabled', email, msg: 'lookup_failed', err: String(e) });
    }

    // Only touch demo-scoped users. If a real user has this email and a
    // non-demo scope_path, refuse to overwrite. The published demo
    // emails are unique and shouldn't collide, but defence-in-depth.
    if (existing && existing.scope_path && !isDemoScope(existing.scope_path)) {
      logJson('WARNING', {
        fn: 'autoReseedDemoIfEnabled', email, uid, msg: 'skip_non_demo_scope',
        scope_path: existing.scope_path
      });
      continue;
    }

    // Idempotency: if the existing doc verifies the published
    // passphrase, skip the write. Saves a Firestore write on every
    // warm cold start of the same revision.
    if (existing
        && typeof existing.password_salt_b64u === 'string'
        && typeof existing.password_hash_b64u === 'string'
        && existing.status !== 'suspended'
        && existing.tier === seed.tier
        && existing.scope_path === seed.scope_path
        && verifyPassword(DEMO_PASSPHRASE, existing.password_salt_b64u, existing.password_hash_b64u)) {
      provisioned[seed.key] = uid;
      skipped++;
      continue;
    }

    if (!uid) uid = randomUUID();
    const cred = hashPassword(DEMO_PASSPHRASE);
    const now = new Date();
    const doc = {
      email,
      name: seed.name,
      tier: seed.tier,
      parent_uid: parentUid,
      scope_path: seed.scope_path,
      password_salt_b64u: cred.saltB64u,
      password_hash_b64u: cred.hashB64u,
      status: 'active',
      created_at: existing?.created_at || now,
      last_login: existing?.last_login || null,
      is_demo: true,
      auto_reseeded_at: now
    };
    try {
      await fsMod.setDoc('tm_users', uid, doc);
      await fsMod.setDoc('tm_user_emails', email, { uid, created_at: doc.created_at });
      provisioned[seed.key] = uid;
      written++;
      logJson('INFO', {
        fn: 'autoReseedDemoIfEnabled', email, uid,
        tier: seed.tier, scope_path: seed.scope_path,
        msg: existing ? 'demo_user_refreshed' : 'demo_user_created'
      });
    } catch (e) {
      logJson('ERROR', { fn: 'autoReseedDemoIfEnabled', email, msg: 'write_failed', err: String(e), stack: e?.stack });
    }
  }

  logJson('INFO', {
    fn: 'autoReseedDemoIfEnabled', msg: 'autoseed_complete',
    written, skipped, total: SEEDS.length, ephemeral
  });
  return { ran: true, written, skipped, total: SEEDS.length, ephemeral };
}
