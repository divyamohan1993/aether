// Resource registry for the dispatcher DSS. tm_units/{unit_id} stores
// ambulance, fire engine, SDRF, medical team, drone, helicopter, and
// police records. Units are scoped to a home base (scope_path) so that
// scope filtering reuses the existing isInScope semantics.

import { randomUUID } from 'node:crypto';
import * as _firestoreReal from './firestore.js';
import * as _auditReal from './audit.js';
import { getDoc, setDoc, queryDocs, runTransaction } from './firestore.js';
import { record as auditRecord } from './audit.js';
import { isInScope, isValidScope, TIER } from './users.js';
import { ApiError, ScopeError, NotFoundError, ConflictError } from './_errors.js';

// Test seams. Real callers see the real modules. Tests can swap in fakes
// to exercise bulkCreate without hitting Firestore.
let _fsModule = _firestoreReal;
let _auditModule = _auditReal;
export function _setFirestoreForTest(mock) { _fsModule = mock || _firestoreReal; }
export function _setAuditForTest(mock) { _auditModule = mock || _auditReal; }

export const UNIT_TYPES = Object.freeze([
  'ambulance', 'fire_engine', 'police', 'sdrf_team',
  'medical_team', 'drone', 'helicopter'
]);

export const UNIT_STATUSES = Object.freeze([
  'available', 'en_route', 'on_scene', 'returning', 'busy', 'offline'
]);

const NAME_RE = /^[A-Za-z0-9 .,'\-_/]{1,40}$/;
const PHONE_RE = /^\+?[0-9 \-]{6,24}$/;

function isValidName(n) { return typeof n === 'string' && NAME_RE.test(n); }
function isValidPhone(p) { return typeof p === 'string' && PHONE_RE.test(p); }
function isValidType(t) { return UNIT_TYPES.includes(t); }
function isValidStatus(s) { return UNIT_STATUSES.includes(s); }

function isValidLocation(loc) {
  if (loc === null) return true;
  if (!loc || typeof loc !== 'object') return false;
  const lat = Number(loc.lat), lng = Number(loc.lng);
  return Number.isFinite(lat) && Number.isFinite(lng)
    && Math.abs(lat) <= 90 && Math.abs(lng) <= 180;
}

function projectUnit(id, data) {
  return {
    unit_id: id,
    type: data.type,
    name: data.name,
    contact_phone: data.contact_phone,
    scope_path: data.scope_path,
    status: data.status,
    capacity: Number.isFinite(Number(data.capacity)) ? Number(data.capacity) : null,
    location: data.location || null,
    last_status_at: data.last_status_at || null,
    created_at: data.created_at || null,
    archived: data.archived === true
  };
}

function clampLimit(n, def) {
  const v = Number.isFinite(n) ? n : def;
  return Math.min(Math.max(Math.floor(v) || def, 1), 500);
}

function statusRank(s) {
  const order = { available: 0, en_route: 1, on_scene: 2, returning: 3, busy: 4, offline: 5 };
  return order[s] ?? 9;
}

// List units inside the actor's subtree. Filters: status, type, limit.
export async function list(actor, opts) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  const limit = clampLimit(opts?.limit, 200);
  const wantStatus = typeof opts?.status === 'string' && isValidStatus(opts.status) ? opts.status : null;
  const wantType = typeof opts?.type === 'string' && isValidType(opts.type) ? opts.type : null;
  const includeArchived = opts?.include_archived === true;
  const upper = actor.scope_path + '/￿';
  const rows = await queryDocs('tm_units', [
    { field: 'scope_path', op: '>=', value: actor.scope_path },
    { field: 'scope_path', op: '<=', value: upper }
  ], { orderBy: 'scope_path', limit: 500 }).catch(() => []);
  const out = [];
  for (const r of rows) {
    if (!isInScope(actor.scope_path, r.data.scope_path)) continue;
    if (!includeArchived && r.data.archived === true) continue;
    if (wantStatus && r.data.status !== wantStatus) continue;
    if (wantType && r.data.type !== wantType) continue;
    out.push(projectUnit(r.id, r.data));
  }
  out.sort((a, b) => {
    const sr = statusRank(a.status) - statusRank(b.status);
    if (sr !== 0) return sr;
    return String(a.name || '').localeCompare(String(b.name || ''));
  });
  return out.slice(0, limit);
}

export async function get(actor, unitId) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  if (typeof unitId !== 'string' || unitId.length === 0) {
    throw new ApiError('bad_request', 'unit_id required.', 400);
  }
  const doc = await getDoc('tm_units', unitId);
  if (!doc) throw new NotFoundError('unit_not_found', 'No such unit.');
  if (!isInScope(actor.scope_path, doc.scope_path)) {
    throw new ScopeError('out_of_scope', 'Unit is outside your subtree.');
  }
  return projectUnit(unitId, doc);
}

// Create a unit. District tier (60) and above only. Validates type,
// scope inside the actor's subtree, name uniqueness within that scope.
export async function create(actor, body) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  if (Number(actor.tier) < TIER.ddma) {
    throw new ScopeError('tier_too_low', 'Only ddma tier and above can create units.');
  }
  const type = String(body?.type || '');
  const name = String(body?.name || '').trim();
  const phone = String(body?.contact_phone || '').trim();
  const scopePath = String(body?.scope_path || actor.scope_path);
  const status = String(body?.status || 'available');
  const capacity = body?.capacity == null ? null : Number(body.capacity);
  const location = body?.location ?? null;

  if (!isValidType(type)) throw new ApiError('bad_type', 'Invalid type.', 400);
  if (!isValidName(name)) throw new ApiError('bad_name', 'Invalid name.', 400);
  if (!isValidPhone(phone)) throw new ApiError('bad_phone', 'Invalid contact phone.', 400);
  if (!isValidScope(scopePath)) throw new ApiError('bad_scope', 'Invalid scope_path.', 400);
  if (!isInScope(actor.scope_path, scopePath)) {
    throw new ScopeError('out_of_scope', 'Scope is outside your subtree.');
  }
  if (!isValidStatus(status)) throw new ApiError('bad_status', 'Invalid status.', 400);
  if (capacity !== null && (!Number.isFinite(capacity) || capacity < 0 || capacity > 500)) {
    throw new ApiError('bad_capacity', 'Capacity must be 0-500.', 400);
  }
  if (!isValidLocation(location)) throw new ApiError('bad_location', 'Invalid location.', 400);

  const upper = scopePath + '/￿';
  const dupRows = await queryDocs('tm_units', [
    { field: 'scope_path', op: '>=', value: scopePath },
    { field: 'scope_path', op: '<=', value: upper }
  ], { limit: 200 }).catch(() => []);
  for (const r of dupRows) {
    if (r.data.archived === true) continue;
    if (String(r.data.name || '').toLowerCase() === name.toLowerCase()
        && r.data.scope_path === scopePath) {
      throw new ConflictError('unit_name_taken', 'A unit with this name already exists in scope.');
    }
  }

  const unitId = randomUUID();
  const now = new Date();
  const doc = {
    type, name, contact_phone: phone, scope_path: scopePath,
    status, capacity: capacity === null ? null : Math.floor(capacity),
    location: location || null,
    last_status_at: now,
    created_at: now,
    created_by_uid: actor.uid,
    archived: false
  };
  await setDoc('tm_units', unitId, doc);
  await auditRecord(actor.uid, 'unit.create', `tm_units/${unitId}`,
    { type, name, scope_path: scopePath, status }, null);
  return projectUnit(unitId, doc);
}

// Update a unit. Status / location / capacity updates are low-risk.
// Re-sign required for scope or contact_phone changes.
export async function update(actor, unitId, body, signatureB64) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  if (typeof unitId !== 'string' || unitId.length === 0) {
    throw new ApiError('bad_request', 'unit_id required.', 400);
  }
  return runTransaction(async (tx) => {
    const doc = await tx.get('tm_units', unitId);
    if (!doc) throw new NotFoundError('unit_not_found', 'No such unit.');
    if (!isInScope(actor.scope_path, doc.scope_path)) {
      throw new ScopeError('out_of_scope', 'Unit is outside your subtree.');
    }
    const patch = { last_status_at: new Date() };
    let auditPayload = {};
    if (body?.status !== undefined) {
      if (!isValidStatus(body.status)) throw new ApiError('bad_status', 'Invalid status.', 400);
      patch.status = body.status;
      auditPayload.status = body.status;
    }
    if (body?.capacity !== undefined) {
      const cap = body.capacity == null ? null : Number(body.capacity);
      if (cap !== null && (!Number.isFinite(cap) || cap < 0 || cap > 500)) {
        throw new ApiError('bad_capacity', 'Capacity must be 0-500.', 400);
      }
      patch.capacity = cap === null ? null : Math.floor(cap);
      auditPayload.capacity = patch.capacity;
    }
    if (body?.location !== undefined) {
      if (!isValidLocation(body.location)) throw new ApiError('bad_location', 'Invalid location.', 400);
      patch.location = body.location || null;
    }
    if (body?.name !== undefined) {
      if (Number(actor.tier) < TIER.ddma) {
        throw new ScopeError('tier_too_low', 'Only ddma tier and above can rename units.');
      }
      const name = String(body.name || '').trim();
      if (!isValidName(name)) throw new ApiError('bad_name', 'Invalid name.', 400);
      patch.name = name;
      auditPayload.name = name;
    }
    if (body?.contact_phone !== undefined) {
      const phone = String(body.contact_phone || '').trim();
      if (!isValidPhone(phone)) throw new ApiError('bad_phone', 'Invalid contact phone.', 400);
      patch.contact_phone = phone;
      auditPayload.contact_phone = phone;
    }
    if (body?.scope_path !== undefined) {
      const scopePath = String(body.scope_path);
      if (!isValidScope(scopePath)) throw new ApiError('bad_scope', 'Invalid scope_path.', 400);
      if (!isInScope(actor.scope_path, scopePath)) {
        throw new ScopeError('out_of_scope', 'New scope is outside your subtree.');
      }
      patch.scope_path = scopePath;
      auditPayload.scope_path = scopePath;
    }
    tx.update('tm_units', unitId, patch);
    await auditRecord(actor.uid, 'unit.update', `tm_units/${unitId}`,
      auditPayload, signatureB64 || null);
    return projectUnit(unitId, { ...doc, ...patch });
  });
}

// Soft-delete a unit. Sets status='offline' and archived=true.
export async function archive(actor, unitId, signatureB64) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  if (Number(actor.tier) < TIER.ddma) {
    throw new ScopeError('tier_too_low', 'Only ddma tier and above can archive units.');
  }
  return runTransaction(async (tx) => {
    const doc = await tx.get('tm_units', unitId);
    if (!doc) throw new NotFoundError('unit_not_found', 'No such unit.');
    if (!isInScope(actor.scope_path, doc.scope_path)) {
      throw new ScopeError('out_of_scope', 'Unit is outside your subtree.');
    }
    tx.update('tm_units', unitId, {
      archived: true,
      status: 'offline',
      last_status_at: new Date()
    });
    await auditRecord(actor.uid, 'unit.archive', `tm_units/${unitId}`,
      { name: doc.name, type: doc.type }, signatureB64 || null);
    return { unit_id: unitId, archived: true };
  });
}

// Helper used by assignments.js + DSS: list units that cover a dispatch
// scope. A district unit covers every responder and volunteer below it,
// so candidates are units whose scope_path is the dispatch's scope or
// any ancestor of it (walk parents up to the scope root). Returns only
// available, non-archived units. Bounded read.
export async function listAvailableInScope(scopePath, limit = 200) {
  if (!isValidScope(scopePath)) return [];
  const parts = String(scopePath).split('/');
  const ancestors = [];
  for (let i = 1; i <= parts.length; i++) ancestors.push(parts.slice(0, i).join('/'));
  const cap = Math.min(Math.max(limit, 1), 500);
  const seen = new Set();
  const out = [];
  // Firestore '==' does the heavy lift; one round-trip per ancestor is
  // cheap because ancestor depth is bounded by tier count (5).
  const batches = await Promise.all(ancestors.map((sp) =>
    queryDocs('tm_units', [
      { field: 'scope_path', op: '==', value: sp }
    ], { limit: cap }).catch(() => [])
  ));
  for (const rows of batches) {
    for (const r of rows) {
      if (seen.has(r.id)) continue;
      seen.add(r.id);
      if (r.data.archived === true) continue;
      if (r.data.status !== 'available') continue;
      out.push(projectUnit(r.id, r.data));
    }
  }
  return out;
}

// Bulk roster import. NDMA/DDMA onboards 200+ SDRF responders, ambulances
// and drones in one operation when an event is declared. The single-row
// `create()` helper is too slow for that.
//
// Body: { rows: [{type, name, contact_phone, scope_path, capacity?, lat?, lng?}] }
// Returns: { summary, rows: [{row_index, status, unit_id?, error?}] }
//
// Status values per row:
//   created           -> new unit written
//   exists            -> active unit with same (name, scope_path) already present
//   duplicate_in_batch-> earlier row in this same upload already created it
//   invalid           -> validation failed; payload error in `error`
//
// Idempotent on (name, scope_path) within unarchived units. Capped at 1000
// rows per call. Tier requirement: ddma (60) and above.
const BULK_MAX_ROWS = 1000;
const BULK_CHUNK = 100;

function validateBulkRow(actor, row) {
  if (!row || typeof row !== 'object') {
    return { ok: false, code: 'bad_row', message: 'row must be an object' };
  }
  const type = String(row.type || '');
  const name = String(row.name || '').trim();
  const phone = String(row.contact_phone || '').trim();
  const scopePath = String(row.scope_path || actor.scope_path);
  const capacity = row.capacity == null ? null : Number(row.capacity);
  const hasLat = row.lat !== undefined && row.lat !== null;
  const hasLng = row.lng !== undefined && row.lng !== null;
  let location = null;
  if (hasLat || hasLng) {
    location = { lat: Number(row.lat), lng: Number(row.lng) };
  } else if (row.location && typeof row.location === 'object') {
    location = { lat: Number(row.location.lat), lng: Number(row.location.lng) };
  }

  if (!UNIT_TYPES.includes(type)) return { ok: false, code: 'bad_type', message: 'Invalid type.' };
  if (!isValidName(name)) return { ok: false, code: 'bad_name', message: 'Invalid name.' };
  if (!isValidPhone(phone)) return { ok: false, code: 'bad_phone', message: 'Invalid contact phone.' };
  if (!isValidScope(scopePath)) return { ok: false, code: 'bad_scope', message: 'Invalid scope_path.' };
  if (!isInScope(actor.scope_path, scopePath)) return { ok: false, code: 'out_of_scope', message: 'Scope is outside your subtree.' };
  if (capacity !== null && (!Number.isFinite(capacity) || capacity < 0 || capacity > 500)) {
    return { ok: false, code: 'bad_capacity', message: 'Capacity must be 0-500.' };
  }
  if (location !== null) {
    const lat = location.lat, lng = location.lng;
    if (!Number.isFinite(lat) || !Number.isFinite(lng) || Math.abs(lat) > 90 || Math.abs(lng) > 180) {
      return { ok: false, code: 'bad_location', message: 'Invalid location.' };
    }
  }
  return {
    ok: true,
    type,
    name,
    phone,
    scopePath,
    capacity: capacity === null ? null : Math.floor(capacity),
    location
  };
}

export async function bulkCreate(actor, body) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  if (Number(actor.tier) < TIER.ddma) {
    throw new ScopeError('tier_too_low', 'Only ddma tier and above can bulk import units.');
  }
  const rows = Array.isArray(body?.rows) ? body.rows : null;
  if (!rows) throw new ApiError('bad_request', 'rows[] required.', 400);
  if (rows.length === 0) throw new ApiError('bad_request', 'rows[] must contain at least one row.', 400);
  if (rows.length > BULK_MAX_ROWS) {
    throw new ApiError('payload_too_large', `rows[] capped at ${BULK_MAX_ROWS}.`, 413);
  }

  const fs = _fsModule;
  const audit = _auditModule;
  const results = new Array(rows.length);

  // Per-row validation up front. Invalid rows are recorded immediately
  // and skipped for the create phase.
  const validated = [];
  for (let i = 0; i < rows.length; i++) {
    const r = validateBulkRow(actor, rows[i]);
    if (!r.ok) {
      results[i] = { row_index: i, status: 'invalid', error: r.code, message: r.message };
    } else {
      validated.push({ index: i, ...r });
    }
  }

  // Pre-fetch active unit names per distinct target scope so we can
  // mark duplicates as `exists` without spending a transaction read on
  // each row.
  const scopes = new Set(validated.map((v) => v.scopePath));
  const existingByScope = new Map();
  for (const sp of scopes) {
    const upper = sp + '/￿';
    let rowsAt = [];
    try {
      rowsAt = await fs.queryDocs('tm_units', [
        { field: 'scope_path', op: '>=', value: sp },
        { field: 'scope_path', op: '<=', value: upper }
      ], { limit: 500 });
    } catch {
      rowsAt = [];
    }
    const m = new Map();
    for (const r of rowsAt) {
      if (r.data?.archived === true) continue;
      if (r.data?.scope_path !== sp) continue;
      const k = String(r.data?.name || '').toLowerCase();
      if (k) m.set(k, r.id);
    }
    existingByScope.set(sp, m);
  }

  // Decide per row + dedupe within the upload itself.
  const toCreate = [];
  const seenInBatch = new Map(); // `${scope}::${name}` -> unit_id
  for (const v of validated) {
    const existing = existingByScope.get(v.scopePath);
    const lname = v.name.toLowerCase();
    if (existing && existing.has(lname)) {
      results[v.index] = { row_index: v.index, status: 'exists', unit_id: existing.get(lname) };
      continue;
    }
    const batchKey = v.scopePath + '::' + lname;
    if (seenInBatch.has(batchKey)) {
      results[v.index] = { row_index: v.index, status: 'duplicate_in_batch', unit_id: seenInBatch.get(batchKey) };
      continue;
    }
    const unitId = randomUUID();
    seenInBatch.set(batchKey, unitId);
    toCreate.push({ ...v, unitId });
  }

  // Chunked transaction commits for the unit docs. Audit rows must flow
  // through audit.record() so the hash chain stays intact, so we collect
  // the per-row audit payloads and emit them after the unit txns commit.
  // Trade-off: a unit txn may succeed while a later audit.record() fails;
  // in that path audit-chain falls back to a chain_break:true row, which
  // verify will surface. Chain-break beats silent unchained writes.
  const now = new Date();
  const auditQueue = [];
  for (let i = 0; i < toCreate.length; i += BULK_CHUNK) {
    const chunk = toCreate.slice(i, i + BULK_CHUNK);
    await fs.runTransaction(async (tx) => {
      for (const c of chunk) {
        const doc = {
          type: c.type,
          name: c.name,
          contact_phone: c.phone,
          scope_path: c.scopePath,
          status: 'available',
          capacity: c.capacity,
          location: c.location,
          last_status_at: now,
          created_at: now,
          created_by_uid: actor.uid,
          archived: false
        };
        tx.create('tm_units', doc, c.unitId);
        auditQueue.push({
          unitId: c.unitId,
          payload: { type: c.type, name: c.name, scope_path: c.scopePath, status: 'available' }
        });
        results[c.index] = { row_index: c.index, status: 'created', unit_id: c.unitId };
      }
    });
  }
  for (const a of auditQueue) {
    try {
      await audit.record(actor.uid, 'unit.bulk_create', `tm_units/${a.unitId}`, a.payload, null);
    } catch (e) {
      /* audit.record() best-effort fallback already wrote chain_break */
    }
  }

  const summary = {
    total: rows.length,
    created: results.filter((r) => r && r.status === 'created').length,
    exists: results.filter((r) => r && r.status === 'exists').length,
    duplicate_in_batch: results.filter((r) => r && r.status === 'duplicate_in_batch').length,
    invalid: results.filter((r) => r && r.status === 'invalid').length
  };

  // One summary audit row for the whole upload. Best-effort.
  try {
    await audit.record(actor.uid, 'unit.bulk_summary', `tm_units/bulk:${randomUUID()}`,
      summary, body?.signature_b64 || null);
  } catch {
    /* swallowed; per-row audits already captured */
  }

  return { summary, rows: results };
}

export const _internal = { projectUnit, statusRank, isValidName, isValidPhone, validateBulkRow };
