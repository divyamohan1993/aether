#!/usr/bin/env node
// Seed Project Aether's Task Manager with five demo accounts at every tier
// plus two demo projects, four demo tasks, and six demo response units
// under demo/HP/Shimla.
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
// Demo accounts share a published passphrase (DEMO_PASSPHRASE). They live
// strictly under scope_path "demo/..." and must never be reused outside
// this subtree. Server-side scrypt is the verifier; the credentials file
// only carries identity metadata and the published passphrase, never the
// hash or salt.

import { promises as fs } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes, randomUUID, scryptSync } from 'node:crypto';

import { setDoc, getDoc } from './firestore.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..', '..');
const OUT_PATH = join(REPO_ROOT, 'web', 'demo', 'credentials.json');

const DEMO_PASSPHRASE = 'aether-demo-2026';
// Server-side scrypt — must match server/tm/auth.js.
const SCRYPT_PARAMS = { N: 4096, r: 8, p: 1, maxmem: 32 * 1024 * 1024 };
const SCRYPT_DK_LEN = 32;
const PASSWORD_SALT_LEN = 16;

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

function b64u(buf) {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return Buffer.from(b).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function normalizeEmail(e) {
  return String(e || '').trim().toLowerCase();
}

function hashPassword(password) {
  const salt = new Uint8Array(randomBytes(PASSWORD_SALT_LEN));
  const dk = scryptSync(password, salt, SCRYPT_DK_LEN, SCRYPT_PARAMS);
  return {
    saltB64u: b64u(salt),
    hashB64u: b64u(new Uint8Array(dk))
  };
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
  if (existing && !FORCE) {
    if (!existing.password_salt_b64u || !existing.password_hash_b64u) {
      log('demo_user_missing_password', { email, hint: 'rerun with --force to install scrypt creds' });
      throw new Error(
        `existing demo user ${email} predates the password migration; run with --force to refresh`
      );
    }
    log('demo_user_exists_skip', { email, uid: existing.uid });
    return { uid: existing.uid, reused: true };
  }
  uid = existing ? existing.uid : randomUUID();
  const cred = hashPassword(DEMO_PASSPHRASE);
  const now = NOW();
  const doc = {
    email,
    name: seed.name,
    tier: seed.tier,
    parent_uid: parentUid || null,
    scope_path: seed.scope_path,
    password_salt_b64u: cred.saltB64u,
    password_hash_b64u: cred.hashB64u,
    status: 'active',
    created_at: now,
    last_login: null,
    is_demo: true
  };
  await writeUser(uid, email, doc);
  log(existing ? 'demo_user_overwritten' : 'demo_user_created',
    { email, uid, tier: seed.tier, scope_path: seed.scope_path });
  return { uid, reused: false };
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

  const unitScope = 'demo/HP/Shimla';
  const unitNow = NOW();
  const SEED_UNITS = [
    // Local first response (ambulance, fire, police, SDRF, drones)
    { unit_id: 'demo-unit-amb-047', type: 'ambulance',         name: 'AMB-047',          contact_phone: '+91 11 2345 6789', capacity: 4,  lat: 31.1048, lng: 77.1734 },
    { unit_id: 'demo-unit-amb-052', type: 'ambulance',         name: 'AMB-052',          contact_phone: '+91 11 2345 6790', capacity: 4,  lat: 31.1175, lng: 77.1658 },
    { unit_id: 'demo-unit-amb-061', type: 'ambulance',         name: 'AMB-061',          contact_phone: '+91 11 2345 6791', capacity: 4,  lat: 31.0921, lng: 77.1812 },
    { unit_id: 'demo-unit-fe-12',   type: 'fire_engine',       name: 'FE-12',            contact_phone: '+91 11 2345 6792', capacity: 8,  lat: 31.1083, lng: 77.1701 },
    { unit_id: 'demo-unit-frt-1',   type: 'fire_rescue_team',  name: 'FRT-Cobra-1',      contact_phone: '+91 11 2345 6795', capacity: 8,  lat: 31.1090, lng: 77.1700 },
    { unit_id: 'demo-unit-sdrf-a3', type: 'sdrf_team',         name: 'SDRF Alpha-3',     contact_phone: '+91 11 2345 6793', capacity: 8,  lat: 31.1290, lng: 77.1530 },
    { unit_id: 'demo-unit-drn-04',  type: 'drone',             name: 'DRN-04',           contact_phone: '+91 11 2345 6794', capacity: 2,  lat: 31.0850, lng: 77.1900 },
    { unit_id: 'demo-unit-pol-1',   type: 'police',            name: 'PCR-101',          contact_phone: '+91 11 2345 6796', capacity: 4,  lat: 31.1011, lng: 77.1750 },
    // National forces (NDRF, Army, IAF)
    { unit_id: 'demo-unit-ndrf-9b', type: 'ndrf_battalion',    name: 'NDRF 9 Bn (Bhatinda)', contact_phone: '+91 11 2345 6800', capacity: 45, lat: 31.1500, lng: 77.1300 },
    { unit_id: 'demo-unit-army-eng',type: 'army_engineer',     name: 'MEG Engineer Coy',  contact_phone: '+91 11 2345 6801', capacity: 30, lat: 31.1700, lng: 77.1100 },
    { unit_id: 'demo-unit-army-med',type: 'army_medical',      name: 'AMC Field Hosp 14', contact_phone: '+91 11 2345 6802', capacity: 50, lat: 31.1700, lng: 77.1100 },
    { unit_id: 'demo-unit-iaf-mi17',type: 'iaf_helicopter',    name: 'IAF Mi-17 Sarsawa', contact_phone: '+91 11 2345 6803', capacity: 24, lat: 31.2000, lng: 77.0800 },
    // Mountain / specialist
    { unit_id: 'demo-unit-itbp-1',  type: 'itbp_mountain',     name: 'ITBP Mountain Sqd 7', contact_phone: '+91 11 2345 6804', capacity: 12, lat: 31.1100, lng: 77.1900 },
    // Health facility surge
    { unit_id: 'demo-unit-igmc',    type: 'hospital_dsurge',   name: 'IGMC Shimla Surge', contact_phone: '+91 11 2345 6810', capacity: 30, lat: 31.1048, lng: 77.1734 },
    { unit_id: 'demo-unit-chc-mash',type: 'hospital_chc_slot', name: 'CHC Mashobra',      contact_phone: '+91 11 2345 6811', capacity: 30, lat: 31.1330, lng: 77.2310 },
    { unit_id: 'demo-unit-bld-1',   type: 'blood_unit',        name: 'IGMC Blood Bank',   contact_phone: '+91 11 2345 6812', capacity: 50, lat: 31.1048, lng: 77.1734 },
    // Comms / forecasting
    { unit_id: 'demo-unit-cow-1',   type: 'comms_cow',         name: 'BSNL COW Shimla',   contact_phone: '+91 11 2345 6820', capacity: 0,  lat: 31.1010, lng: 77.1700 },
    { unit_id: 'demo-unit-fcast',   type: 'forecast_cell',     name: 'IMD HP Forecast',   contact_phone: '+91 11 2345 6821', capacity: 0,  lat: 31.1004, lng: 77.1734 },
    // Transport / logistics / shelter
    { unit_id: 'demo-unit-bus-1',   type: 'bus_evac',          name: 'HRTC Volvo Evac-1', contact_phone: '+91 11 2345 6830', capacity: 60, lat: 31.1043, lng: 77.1689 },
    { unit_id: 'demo-unit-trk-1',   type: 'truck_relief',      name: 'Relief Truck-1',    contact_phone: '+91 11 2345 6831', capacity: 5000, lat: 31.1043, lng: 77.1689 },
    { unit_id: 'demo-unit-camp-1',  type: 'relief_camp',       name: 'Camp Lakkar Bazaar',contact_phone: '+91 11 2345 6840', capacity: 500, lat: 31.1056, lng: 77.1694 },
    // Volunteer
    { unit_id: 'demo-unit-irc-1',   type: 'ircs_team',         name: 'IRCS Shimla Team',  contact_phone: '+91 11 2345 6850', capacity: 12, lat: 31.1080, lng: 77.1720 },
    { unit_id: 'demo-unit-am-1',    type: 'aapda_mitra_squad', name: 'Aapda Mitra Sq A',  contact_phone: '+91 11 2345 6851', capacity: 12, lat: 31.1015, lng: 77.1740 },
    { unit_id: 'demo-unit-cd-1',    type: 'civil_defence_unit',name: 'Civil Defence Sq 1',contact_phone: '+91 11 2345 6852', capacity: 12, lat: 31.1015, lng: 77.1730 }
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

  const credentials = {
    passphrase: DEMO_PASSPHRASE,
    note: 'Demo passphrase. The same value works for every demo email below. Do not reuse outside the demo subtree.',
    users: SEEDS.map((seed) => ({
      email: seed.email,
      name: seed.name,
      tier: seed.tier,
      tier_name: TIER_NAME[seed.tier],
      scope_path: seed.scope_path,
      blurb: seed.blurb
    }))
  };

  await fs.mkdir(dirname(OUT_PATH), { recursive: true });
  const json = JSON.stringify(credentials, null, 2) + '\n';
  await fs.writeFile(OUT_PATH, json, 'utf8');
  const { gzipSync, brotliCompressSync, constants: zlibC } = await import('node:zlib');
  const buf = Buffer.from(json, 'utf8');
  await fs.writeFile(OUT_PATH + '.gz', gzipSync(buf, { level: 9 }));
  await fs.writeFile(OUT_PATH + '.br', brotliCompressSync(buf, {
    params: { [zlibC.BROTLI_PARAM_QUALITY]: 11, [zlibC.BROTLI_PARAM_SIZE_HINT]: buf.length }
  }));
  log('credentials_written', { path: OUT_PATH, bytes: Buffer.byteLength(json), users: credentials.users.length });

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
