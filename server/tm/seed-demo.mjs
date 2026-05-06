#!/usr/bin/env node
// Seed Project Aether's Task Manager with five demo accounts at every tier
// plus two demo projects and four demo tasks under demo/HP/Shimla.
//
// Usage:
//   node server/tm/seed-demo.mjs           # idempotent: skip existing demo users
//   node server/tm/seed-demo.mjs --force   # overwrite existing demo users
//
// Run from the repo root with ADC active. Requires GCP_PROJECT to point at
// the Firestore project. Outputs /web/demo/credentials.json which is the
// PUBLIC artefact the demo portal fetches.
//
// SECURITY MODEL.
// The credentials file is checked in and served publicly. Each
// encrypted_priv blob is AES-256-GCM ciphertext over the user's ML-DSA-65
// private key, with the key derived via Argon2id (t=3, m=64MB, p=1,
// dkLen=32) from the published demo passphrase. The blob is useless
// without that passphrase, but the passphrase is also published on
// /demo for educational purposes. These accounts must NEVER be used
// outside the public demo subtree (scope_path starts with `demo`).

import { promises as fs } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes, randomUUID, webcrypto } from 'node:crypto';

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { argon2id } from '@noble/hashes/argon2.js';

import { setDoc, getDoc, queryDocs } from './firestore.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..', '..');
const OUT_PATH = join(REPO_ROOT, 'web', 'demo', 'credentials.json');

const DEMO_PASSPHRASE = 'aether-demo-2026';
// MVP login posture: matches the browser bundle's reduced Argon2id
// (t=1, m=16 MiB). Demo decrypt then finishes in ~1 s on Android Go.
// Production should raise these.
const ARGON = { t: 1, m: 16 * 1024, p: 1, dkLen: 32 };
const SALT_LEN = 16;
const IV_LEN = 12;

const FORCE = process.argv.includes('--force');

const NOW = () => new Date();

const TIERS = Object.freeze({
  ndma: 100, sdma: 80, ddma: 60, subdivisional: 40, volunteer: 20
});
const TIER_NAME = Object.freeze({
  100: 'NDMA', 90: 'National Ops', 80: 'SDMA', 70: 'State Ops',
  60: 'DDMA', 50: 'District Ops', 40: 'Subdivisional', 30: 'Tehsil',
  20: 'Volunteer', 10: 'Survivor'
});

// Five demo users, parent_uid links resolved at run time.
const SEEDS = [
  {
    key: 'ndma',
    email: 'demo.ndma@aether.dmj.one',
    name: 'Demo NDMA Coordinator',
    tier: TIERS.ndma,
    scope_path: 'demo',
    parent: null,
    blurb: 'National view. Sees every state, district, responder and volunteer in the demo tree. Can delegate tier and archive any project.'
  },
  {
    key: 'sdma',
    email: 'demo.state@aether.dmj.one',
    name: 'Demo SDMA Officer',
    tier: TIERS.sdma,
    scope_path: 'demo/HP',
    parent: 'ndma',
    blurb: 'Himachal Pradesh SDMA subtree. Sees districts and field staff under HP. Can re-tier anyone below them.'
  },
  {
    key: 'ddma',
    email: 'demo.district@aether.dmj.one',
    name: 'Demo DDMA Magistrate',
    tier: TIERS.ddma,
    scope_path: 'demo/HP/Shimla',
    parent: 'sdma',
    blurb: 'Shimla DDMA. Owns demo projects and the team running them. Can edit any task in scope.'
  },
  {
    key: 'subdivisional',
    email: 'demo.responder@aether.dmj.one',
    name: 'Demo Subdivisional Officer',
    tier: TIERS.subdivisional,
    scope_path: 'demo/HP/Shimla/responder1',
    parent: 'ddma',
    blurb: 'Subdivisional officer. Owns assigned tasks fully. Sees only their own subtree.'
  },
  {
    key: 'volunteer',
    email: 'demo.volunteer@aether.dmj.one',
    name: 'Demo Volunteer',
    tier: TIERS.volunteer,
    scope_path: 'demo/HP/Shimla/responder1/vol1',
    parent: 'subdivisional',
    blurb: 'Read-only on assigned tasks. Status-only updates. Cannot create or delegate.'
  }
];

function log(msg, extra) {
  const entry = { ts: new Date().toISOString(), msg };
  if (extra) Object.assign(entry, extra);
  process.stdout.write(JSON.stringify(entry) + '\n');
}

function b64(buf) {
  return Buffer.from(buf instanceof Uint8Array ? buf : new Uint8Array(buf)).toString('base64');
}

function normalizeEmail(e) {
  return String(e || '').trim().toLowerCase();
}

async function deriveAesKey(passphrase, salt) {
  const raw = argon2id(passphrase, salt, ARGON);
  return webcrypto.subtle.importKey(
    'raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

async function encryptPrivKey(priv, passphrase) {
  if (!(priv instanceof Uint8Array)) throw new Error('priv must be Uint8Array');
  const salt = new Uint8Array(randomBytes(SALT_LEN));
  const iv = new Uint8Array(randomBytes(IV_LEN));
  const key = await deriveAesKey(passphrase, salt);
  const ct = new Uint8Array(await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, priv));
  return { saltB64: b64(salt), ivB64: b64(iv), ctB64: b64(ct) };
}

async function decryptPrivKey(saltB64, ivB64, ctB64, passphrase) {
  const salt = Buffer.from(saltB64, 'base64');
  const iv = Buffer.from(ivB64, 'base64');
  const ct = Buffer.from(ctB64, 'base64');
  const key = await deriveAesKey(passphrase, salt);
  return new Uint8Array(await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));
}

async function userExists(email) {
  const idx = await getDoc('tm_user_emails', email);
  if (!idx || !idx.uid) return null;
  const u = await getDoc('tm_users', idx.uid);
  if (!u) return null;
  return { uid: idx.uid, ...u };
}

async function writeUser(uid, email, doc) {
  await setDoc('tm_users', uid, doc);
  await setDoc('tm_user_emails', email, { uid, created_at: doc.created_at });
}

async function provisionUser(seed, parentUid) {
  const email = normalizeEmail(seed.email);
  const existing = await userExists(email);
  let uid;
  let pubB64;
  let encrypted;
  if (existing && !FORCE) {
    log('demo_user_exists_skip', { email, uid: existing.uid });
    if (!existing.demo_encrypted_priv) {
      throw new Error(
        `existing demo user ${email} has no demo_encrypted_priv field; run with --force to rewrite`
      );
    }
    return {
      uid: existing.uid,
      pubkey_b64: existing.pubkey_b64,
      encrypted_priv: existing.demo_encrypted_priv,
      reused: true
    };
  }
  uid = existing ? existing.uid : randomUUID();
  const kp = ml_dsa65.keygen();
  pubB64 = b64(kp.publicKey);
  encrypted = await encryptPrivKey(kp.secretKey, DEMO_PASSPHRASE);
  // Self-test: decrypt and round-trip sign+verify so we never ship a
  // cred that the browser cannot actually open.
  const recovered = await decryptPrivKey(
    encrypted.saltB64, encrypted.ivB64, encrypted.ctB64, DEMO_PASSPHRASE
  );
  if (recovered.length !== kp.secretKey.length) {
    throw new Error(`encryption round-trip failed for ${email}: length mismatch`);
  }
  const probe = new TextEncoder().encode('aether-demo-roundtrip:' + email);
  const sig = ml_dsa65.sign(probe, recovered);
  if (!ml_dsa65.verify(sig, probe, kp.publicKey)) {
    throw new Error(`encryption round-trip failed for ${email}: signature did not verify`);
  }
  const now = NOW();
  const doc = {
    email,
    name: seed.name,
    tier: seed.tier,
    parent_uid: parentUid || null,
    scope_path: seed.scope_path,
    pubkey_b64: pubB64,
    status: 'active',
    created_at: now,
    last_login: null,
    is_demo: true,
    demo_encrypted_priv: encrypted
  };
  await writeUser(uid, email, doc);
  log(existing ? 'demo_user_overwritten' : 'demo_user_created',
    { email, uid, tier: seed.tier, scope_path: seed.scope_path });
  return { uid, pubkey_b64: pubB64, encrypted_priv: encrypted, reused: false };
}

async function provisionProject(pid, name, description, ownerUid, scopePath) {
  const existing = await getDoc('tm_projects', pid);
  if (existing && !FORCE) {
    log('demo_project_exists_skip', { pid, name });
    return existing;
  }
  const now = NOW();
  const data = {
    name,
    description,
    scope_path: scopePath,
    owner_uid: ownerUid,
    status: 'active',
    created_at: now,
    updated_at: now,
    is_demo: true
  };
  await setDoc('tm_projects', pid, data);
  log(existing ? 'demo_project_overwritten' : 'demo_project_created', { pid, name });
  return data;
}

async function provisionUnit(unitId, doc) {
  const existing = await getDoc('tm_units', unitId);
  if (existing && !FORCE) {
    log('demo_unit_exists_skip', { unit_id: unitId, name: doc.name });
    return existing;
  }
  await setDoc('tm_units', unitId, doc);
  log(existing ? 'demo_unit_overwritten' : 'demo_unit_created',
    { unit_id: unitId, name: doc.name, type: doc.type, scope_path: doc.scope_path });
  return doc;
}

async function provisionTask(tid, projectId, title, description, scopePath, creatorUid, assigneeUid, priority, status, dueDays) {
  const existing = await getDoc('tm_tasks', tid);
  if (existing && !FORCE) {
    log('demo_task_exists_skip', { tid, title });
    return existing;
  }
  const now = NOW();
  const due = dueDays === null ? null : new Date(now.getTime() + dueDays * 86_400_000);
  const data = {
    project_id: projectId,
    title,
    description,
    scope_path: scopePath,
    assignee_uid: assigneeUid || null,
    creator_uid: creatorUid,
    status,
    priority,
    due_date: due,
    created_at: now,
    updated_at: now,
    is_demo: true
  };
  await setDoc('tm_tasks', tid, data);
  log(existing ? 'demo_task_overwritten' : 'demo_task_created', { tid, title, status });
  return data;
}

async function main() {
  if (!process.env.GCP_PROJECT) {
    log('warn_gcp_project_unset', { hint: 'firestore.js falls back to "dmjone"; set GCP_PROJECT to override' });
  }
  log('seed_demo_start', { force: FORCE, project: process.env.GCP_PROJECT || 'dmjone' });

  const provisioned = {};
  for (const seed of SEEDS) {
    const parentUid = seed.parent ? provisioned[seed.parent].uid : null;
    const out = await provisionUser(seed, parentUid);
    provisioned[seed.key] = out;
  }

  // Two demo projects scoped to demo/HP/Shimla, owned by the district user.
  const districtUid = provisioned.ddma.uid;
  const projectScope = 'demo/HP/Shimla';
  const proj1Id = 'demo-project-flood-2026';
  const proj2Id = 'demo-project-landslide-2026';
  await provisionProject(
    proj1Id,
    'Shimla flood response 2026',
    'Coordinated response to monsoon flooding in lower Shimla. Tracks evacuation routes, medical posts and supply convoys.',
    districtUid,
    projectScope
  );
  await provisionProject(
    proj2Id,
    'Kufri landslide stabilisation',
    'Geotech survey and slope stabilisation along the Kufri ridge. Vendor coordination and audit checkpoints.',
    districtUid,
    projectScope
  );

  // Four demo tasks across both projects with mixed priorities and statuses.
  const responderUid = provisioned.subdivisional.uid;
  const volunteerUid = provisioned.volunteer.uid;
  const taskScope = 'demo/HP/Shimla/responder1';
  await provisionTask(
    'demo-task-001', proj1Id,
    'Set up medical post at Devi temple junction',
    'Tent, oxygen kits, water purification. Reachable by 4x4 only.',
    taskScope, districtUid, responderUid, 'critical', 'in_progress', 1
  );
  await provisionTask(
    'demo-task-002', proj1Id,
    'Door-to-door welfare check, ward 7',
    'Confirm elderly residents have moved to higher ground. Update next-of-kin contact list.',
    taskScope, districtUid, volunteerUid, 'high', 'open', 2
  );
  await provisionTask(
    'demo-task-003', proj2Id,
    'Drone survey of Kufri ridge, sector 3',
    'Two passes at first light. Upload imagery to project drive.',
    taskScope, districtUid, responderUid, 'med', 'blocked', 3
  );
  await provisionTask(
    'demo-task-004', proj2Id,
    'Vendor sign-off on rockfall barrier specs',
    'Cross-check load tables against IS 14458. Three vendors. Compile note for SDMA.',
    taskScope, districtUid, null, 'low', 'done', null
  );

  // Six demo response units around Shimla. Lat/lng spread within a few
  // kilometres of the district HQ. All start available so the DSS UI has
  // something to suggest as soon as the demo loads.
  const unitScope = 'demo/HP/Shimla';
  const unitNow = NOW();
  const SEED_UNITS = [
    { unit_id: 'demo-unit-amb-047', type: 'ambulance',   name: 'AMB-047',       contact_phone: '+91 11 2345 6789', capacity: 4, lat: 31.1048, lng: 77.1734 },
    { unit_id: 'demo-unit-amb-052', type: 'ambulance',   name: 'AMB-052',       contact_phone: '+91 11 2345 6790', capacity: 4, lat: 31.1175, lng: 77.1658 },
    { unit_id: 'demo-unit-amb-061', type: 'ambulance',   name: 'AMB-061',       contact_phone: '+91 11 2345 6791', capacity: 4, lat: 31.0921, lng: 77.1812 },
    { unit_id: 'demo-unit-fe-12',   type: 'fire_engine', name: 'FE-12',         contact_phone: '+91 11 2345 6792', capacity: 8, lat: 31.1083, lng: 77.1701 },
    { unit_id: 'demo-unit-sdrf-a3', type: 'sdrf_team',   name: 'SDRF Alpha-3',  contact_phone: '+91 11 2345 6793', capacity: 8, lat: 31.1290, lng: 77.1530 },
    { unit_id: 'demo-unit-drn-04',  type: 'drone',       name: 'DRN-04',        contact_phone: '+91 11 2345 6794', capacity: 2, lat: 31.0850, lng: 77.1900 }
  ];
  for (const u of SEED_UNITS) {
    await provisionUnit(u.unit_id, {
      type: u.type,
      name: u.name,
      contact_phone: u.contact_phone,
      scope_path: unitScope,
      status: 'available',
      capacity: u.capacity,
      location: { lat: u.lat, lng: u.lng },
      last_status_at: unitNow,
      created_at: unitNow,
      created_by_uid: districtUid,
      archived: false,
      is_demo: true
    });
  }
  log('seed_units_complete', { N: SEED_UNITS.length, scope_path: unitScope });

  // Build the public credentials.json artefact.
  const credentials = SEEDS.map((seed) => {
    const p = provisioned[seed.key];
    return {
      email: seed.email,
      name: seed.name,
      tier: seed.tier,
      tier_name: TIER_NAME[seed.tier],
      scope_path: seed.scope_path,
      blurb: seed.blurb,
      pubkey_b64: p.pubkey_b64,
      encrypted_priv: p.encrypted_priv
    };
  });

  await fs.mkdir(dirname(OUT_PATH), { recursive: true });
  const json = JSON.stringify(credentials, null, 2) + '\n';
  await fs.writeFile(OUT_PATH, json, 'utf8');
  log('credentials_written', { path: OUT_PATH, bytes: Buffer.byteLength(json), users: credentials.length });

  // Final stdout summary line so deploy scripts can grep one machine-readable line.
  const summary = {
    summary: 'aether_demo_seed_complete',
    passphrase: DEMO_PASSPHRASE,
    emails: SEEDS.map((s) => s.email),
    credentials_path: OUT_PATH
  };
  process.stdout.write(JSON.stringify(summary) + '\n');
}

main().catch((e) => {
  log('seed_demo_fatal', { err: String(e), stack: e?.stack });
  process.exit(1);
});
