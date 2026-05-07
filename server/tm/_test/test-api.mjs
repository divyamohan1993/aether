#!/usr/bin/env node
// Self-test for the TM Firestore + users module.
// Hits real Firestore via ADC. Uses a unique prefix per run so concurrent
// runs do not collide. Cleans up created docs at the end.
//
// Run:  node server/tm/_test/test-api.mjs
// Env:  GCP_PROJECT (default dmjone), FIRESTORE_DB (default "(default)").

import { randomUUID, randomBytes } from 'node:crypto';
import {
  getDoc, setDoc, deleteDoc, queryDocs, runTransaction,
  fetchAndDelete, encodeFields, decodeFields, value, parse,
  config, FirestoreError
} from '../firestore.js';
import {
  isInScope, isValidScope, isValidEmail,
  canActOn, TIER, normalizeEmail
} from '../users.js';

const RUN = randomUUID().slice(0, 8);
const PREFIX = `selftest-${RUN}`;

const created = []; // [{collection, id}]

function info(...args) { process.stdout.write(`[ok] ${args.join(' ')}\n`); }
function fail(msg, err) {
  process.stderr.write(`[FAIL] ${msg}\n`);
  if (err) process.stderr.write(`  ${err?.stack || err}\n`);
  cleanup().finally(() => process.exit(1));
}
function eq(a, b, label) {
  if (JSON.stringify(a) !== JSON.stringify(b)) {
    fail(`expected equal: ${label}\n  got: ${JSON.stringify(a)}\n  exp: ${JSON.stringify(b)}`);
  }
}
function truthy(v, label) { if (!v) fail(`expected truthy: ${label}`); }

async function cleanup() {
  for (const { collection, id } of created.reverse()) {
    try { await deleteDoc(collection, id); } catch { /* ignore */ }
  }
}

async function testValueCodec() {
  const sample = {
    name: 'Real Name',
    tier: TIER.responder,
    is_active: true,
    score: 3.14,
    parent_uid: null,
    tags: ['rescue', 'medical'],
    nested: { city: 'Shimla', alt: 2206 },
    created_at: new Date('2026-01-15T08:30:00.000Z'),
    expires_at: '2026-12-31T23:59:59Z'
  };
  const fields = encodeFields(sample);
  truthy(fields.tier && 'integerValue' in fields.tier, 'tier integerValue');
  truthy(fields.score && 'doubleValue' in fields.score, 'score doubleValue');
  truthy(fields.is_active && 'booleanValue' in fields.is_active, 'bool');
  truthy(fields.parent_uid && 'nullValue' in fields.parent_uid, 'null');
  truthy(fields.tags && 'arrayValue' in fields.tags, 'array');
  truthy(fields.nested && 'mapValue' in fields.nested, 'map');
  truthy(fields.created_at && 'timestampValue' in fields.created_at, 'date->ts');
  truthy(fields.expires_at && 'timestampValue' in fields.expires_at, 'iso str->ts via key');

  const back = decodeFields(fields);
  eq(back.name, sample.name, 'string roundtrip');
  eq(back.tier, sample.tier, 'int roundtrip');
  eq(back.is_active, true, 'bool roundtrip');
  eq(back.parent_uid, null, 'null roundtrip');
  eq(back.tags, sample.tags, 'array roundtrip');
  eq(back.nested.city, 'Shimla', 'nested map');
  truthy(typeof back.created_at === 'string' && back.created_at.startsWith('2026-01-15'), 'ts roundtrip');
  info('value codec roundtrip');

  eq(parse(value(0)), 0, 'parse(value(0))');
  eq(parse(value(-1)), -1, 'parse(value(-1))');
  eq(parse(value('')), '', 'parse(value(empty))');
}

async function testScopeHelpers() {
  truthy(isValidScope('ndma'), 'ndma scope');
  truthy(isValidScope('ndma/HP/Shimla'), 'deep scope');
  truthy(!isValidScope('foo'), 'reject non-ndma');
  truthy(!isValidScope('ndma/'), 'reject trailing slash');
  truthy(!isValidScope('ndma//HP'), 'reject double slash');
  truthy(isInScope('ndma', 'ndma/HP'), 'parent contains child');
  truthy(isInScope('ndma/HP', 'ndma/HP/Shimla'), 'state contains district');
  truthy(!isInScope('ndma/HP', 'ndma/UK'), 'siblings disjoint');
  truthy(!isInScope('ndma/HP', 'ndma/HPstate'), 'prefix not enough; needs slash boundary');
  truthy(isInScope('ndma/HP', 'ndma/HP'), 'equality is in scope');

  truthy(isValidEmail('a@b.co'), 'simple email');
  truthy(!isValidEmail('not-an-email'), 'reject bad email');
  eq(normalizeEmail('  Foo@BAR.com '), 'foo@bar.com', 'normalize email');

  const ndmaActor = { uid: 'a1', tier: TIER.ndma, scope_path: 'ndma' };
  const stateActor = { uid: 'a2', tier: TIER.state, scope_path: 'ndma/HP' };
  const districtUser = { uid: 'a3', tier: TIER.district, scope_path: 'ndma/HP/Shimla' };
  truthy(canActOn(ndmaActor, districtUser), 'ndma over district');
  truthy(canActOn(stateActor, districtUser), 'state over district');
  truthy(!canActOn(districtUser, stateActor), 'district cannot act on state');
  truthy(canActOn(districtUser, districtUser), 'self always ok');
  info('scope/email/canActOn helpers');
}

async function testCrud() {
  const id = `${PREFIX}-u1`;
  const data = {
    email: `${PREFIX}-u1@selftest.local`,
    name: 'Self Test User',
    tier: TIER.district,
    parent_uid: null,
    scope_path: 'ndma/HP/Shimla',
    password_salt_b64u: 'AAAAAAAAAAAAAAAAAAAAAA',
    password_hash_b64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    status: 'active',
    created_at: new Date(),
    last_login: null
  };
  await setDoc('tm_users', id, data);
  created.push({ collection: 'tm_users', id });

  const got = await getDoc('tm_users', id);
  truthy(got, 'getDoc returns');
  eq(got.email, data.email, 'email roundtrip');
  eq(got.tier, TIER.district, 'tier roundtrip');
  eq(got.scope_path, 'ndma/HP/Shimla', 'scope roundtrip');
  truthy(typeof got.created_at === 'string', 'created_at decoded as ISO string');

  // Missing doc returns null
  const miss = await getDoc('tm_users', `${PREFIX}-missing`);
  eq(miss, null, 'missing doc -> null');

  info('setDoc / getDoc / null on missing');
}

async function testQueryAndScopeFilter() {
  const ids = [];
  const mk = async (suffix, scope, tier) => {
    const id = `${PREFIX}-q-${suffix}`;
    await setDoc('tm_users', id, {
      email: `${PREFIX}-${suffix}@selftest.local`,
      name: `Q ${suffix}`,
      tier,
      parent_uid: null,
      scope_path: scope,
      password_salt_b64u: 'AAAAAAAAAAAAAAAAAAAAAA',
      password_hash_b64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      status: 'active',
      created_at: new Date(),
      last_login: null
    });
    ids.push(id);
    created.push({ collection: 'tm_users', id });
  };
  await mk('a', 'ndma/HP', TIER.state);
  await mk('b', 'ndma/HP/Shimla', TIER.district);
  await mk('c', 'ndma/UK', TIER.state);

  // Filter by exact email — exercises queryDocs.
  const rows = await queryDocs('tm_users',
    [{ field: 'email', op: '==', value: `${PREFIX}-a@selftest.local` }],
    { limit: 5 });
  truthy(rows.length === 1, 'queryDocs exact match');
  eq(rows[0].data.scope_path, 'ndma/HP', 'queryDocs returns expected doc');

  // Range query across the synthetic scope. We expect at least the two
  // HP-prefixed docs. Other selftest runs may contribute extras under
  // the same prefix — but `${PREFIX}-q-c` (UK) must NOT appear.
  const rangeRows = await queryDocs('tm_users', [
    { field: 'scope_path', op: '>=', value: 'ndma/HP' },
    { field: 'scope_path', op: '<=', value: 'ndma/HP/￿' }
  ], { orderBy: 'scope_path', limit: 50 });

  const idsSeen = new Set(rangeRows.map((r) => r.id));
  truthy(idsSeen.has(`${PREFIX}-q-a`), 'HP scope visible');
  truthy(idsSeen.has(`${PREFIX}-q-b`), 'HP/Shimla scope visible');
  truthy(!idsSeen.has(`${PREFIX}-q-c`), 'UK scope excluded');
  info('queryDocs + range scope filter');
}

async function testFetchAndDeleteOnce() {
  const id = `${PREFIX}-ch1`;
  await setDoc('tm_challenges', id, {
    email: `${PREFIX}-ch@selftest.local`,
    challenge_b64: 'TEST',
    expires_at: new Date(Date.now() + 60_000)
  });
  created.push({ collection: 'tm_challenges', id });

  const first = await fetchAndDelete('tm_challenges', id);
  truthy(first && first.email && first.email.startsWith(PREFIX), 'first fetchAndDelete returns data');
  const second = await fetchAndDelete('tm_challenges', id);
  eq(second, null, 'second fetchAndDelete returns null');

  // Already gone, so remove from cleanup list.
  const idx = created.findIndex((c) => c.collection === 'tm_challenges' && c.id === id);
  if (idx >= 0) created.splice(idx, 1);

  info('fetchAndDelete is single-use');
}

async function testTransaction() {
  const idA = `${PREFIX}-tx-a`;
  const idB = `${PREFIX}-tx-b`;
  const result = await runTransaction(async (tx) => {
    const before = await tx.get('tm_users', idA);
    eq(before, null, 'tx.get returns null for missing');
    tx.create('tm_users', {
      email: `${PREFIX}-tx-a@selftest.local`,
      name: 'TX A',
      tier: TIER.responder,
      parent_uid: null,
      scope_path: 'ndma/HP/Shimla',
      password_salt_b64u: 'AAAAAAAAAAAAAAAAAAAAAA',
      password_hash_b64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      status: 'active',
      created_at: new Date(),
      last_login: null
    }, idA);
    tx.create('tm_users', {
      email: `${PREFIX}-tx-b@selftest.local`,
      name: 'TX B',
      tier: TIER.responder,
      parent_uid: null,
      scope_path: 'ndma/HP/Shimla',
      password_salt_b64u: 'AAAAAAAAAAAAAAAAAAAAAA',
      password_hash_b64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      status: 'active',
      created_at: new Date(),
      last_login: null
    }, idB);
    return 'commit';
  });
  eq(result, 'commit', 'tx returns fn result');
  created.push({ collection: 'tm_users', id: idA });
  created.push({ collection: 'tm_users', id: idB });

  const a = await getDoc('tm_users', idA);
  const b = await getDoc('tm_users', idB);
  truthy(a && b, 'tx commit visible');

  // Rollback path
  let threw = false;
  try {
    await runTransaction(async (tx) => {
      tx.create('tm_users', {
        email: `${PREFIX}-tx-r@selftest.local`,
        name: 'TX R',
        tier: TIER.volunteer,
        parent_uid: null,
        scope_path: 'ndma/HP/Shimla',
        password_salt_b64u: 'AAAAAAAAAAAAAAAAAAAAAA',
      password_hash_b64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        status: 'active',
        created_at: new Date(),
        last_login: null
      }, `${PREFIX}-tx-r`);
      throw new Error('intentional');
    });
  } catch (e) {
    threw = e.message === 'intentional';
  }
  truthy(threw, 'tx rethrows fn error');
  const rolled = await getDoc('tm_users', `${PREFIX}-tx-r`);
  eq(rolled, null, 'tx rollback discarded write');
  info('transaction commit + rollback');
}

async function testCreateConflict() {
  const id = `${PREFIX}-conflict`;
  await setDoc('tm_users', id, {
    email: `${PREFIX}-conf@selftest.local`,
    name: 'Conflict',
    tier: TIER.volunteer,
    parent_uid: null,
    scope_path: 'ndma/HP/Shimla',
    password_salt_b64u: 'AAAAAAAAAAAAAAAAAAAAAA',
    password_hash_b64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    status: 'active',
    created_at: new Date(),
    last_login: null
  });
  created.push({ collection: 'tm_users', id });

  let caught = null;
  try {
    await runTransaction(async (tx) => {
      tx.create('tm_users', { email: 'x', tier: TIER.volunteer, scope_path: 'ndma/HP/Shimla' }, id);
    });
  } catch (e) { caught = e; }
  truthy(caught instanceof FirestoreError, 'conflict raises FirestoreError');
  info(`conflict surfaces as ${caught?.code}`);
}

async function main() {
  process.stdout.write(`Self-test starting. project=${config.projectId} db=${config.databaseId} prefix=${PREFIX}\n`);
  try {
    await testValueCodec();
    await testScopeHelpers();
    await testCrud();
    await testQueryAndScopeFilter();
    await testFetchAndDeleteOnce();
    await testTransaction();
    await testCreateConflict();
    process.stdout.write('OK\n');
  } catch (e) {
    fail('uncaught', e);
  } finally {
    await cleanup();
  }
}

main().catch((e) => fail('uncaught', e));
