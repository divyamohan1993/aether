// Firestore REST client. Zero deps beyond google-auth-library.
// Forces HTTP/1.1 via node:https + keep-alive Agent because HTTP/2 streams
// have been observed to stall against firestore.googleapis.com from this
// environment.

import { randomUUID } from 'node:crypto';
import { request as httpsRequest, Agent as HttpsAgent } from 'node:https';
import { GoogleAuth } from 'google-auth-library';

const PROJECT_ID = process.env.GCP_PROJECT || 'dmjone';
const DB_ID = process.env.FIRESTORE_DB || '(default)';
const HOST = 'firestore.googleapis.com';
const BASE = `/v1/projects/${PROJECT_ID}/databases/${encodeURIComponent(DB_ID)}/documents`;

const agent = new HttpsAgent({ keepAlive: true, maxSockets: 32, keepAliveMsecs: 30_000 });
const auth = new GoogleAuth({ scopes: ['https://www.googleapis.com/auth/datastore'] });

function logJson(severity, fields) {
  const entry = { ts: new Date().toISOString(), severity, ...fields };
  process.stdout.write(JSON.stringify(entry) + '\n');
}

export class FirestoreError extends Error {
  constructor(code, message, status, raw) {
    super(message);
    this.name = 'FirestoreError';
    this.code = code;
    this.status = status || 0;
    this.raw = raw;
  }
}

let cachedToken = null;
let cachedTokenAt = 0;

async function getAccessToken() {
  const now = Date.now();
  if (cachedToken && (now - cachedTokenAt) < 240_000) return cachedToken;
  const t = await auth.getAccessToken();
  if (!t) throw new FirestoreError('FS_AUTH', 'No ADC token available', 0, null);
  cachedToken = t;
  cachedTokenAt = now;
  return t;
}

function fsRequest(method, urlPath, body) {
  return new Promise(async (resolve, reject) => {
    let token;
    try { token = await getAccessToken(); } catch (e) { reject(e); return; }
    const data = body ? Buffer.from(JSON.stringify(body), 'utf8') : null;
    const req = httpsRequest({
      hostname: HOST,
      port: 443,
      path: urlPath,
      method,
      agent,
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-Goog-User-Project': PROJECT_ID,
        'Content-Length': data ? data.length : 0
      }
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        const status = res.statusCode || 0;
        let parsed = null;
        if (raw.length > 0) {
          try { parsed = JSON.parse(raw); } catch { parsed = null; }
        }
        if (status >= 200 && status < 300) {
          resolve({ status, body: parsed });
          return;
        }
        const errMsg = parsed?.error?.message || raw.slice(0, 512) || `http_${status}`;
        const errStatus = parsed?.error?.status || '';
        let code = 'FS_TRANSPORT';
        if (status === 400) code = 'FS_BAD_REQUEST';
        else if (status === 401 || status === 403) code = 'FS_UNAUTHORIZED';
        else if (status === 404) code = 'FS_NOT_FOUND';
        else if (status === 409 || errStatus === 'ALREADY_EXISTS') code = 'FS_ALREADY_EXISTS';
        else if (status === 412 || errStatus === 'FAILED_PRECONDITION') code = 'FS_PRECONDITION';
        else if (status === 429) code = 'FS_RATE_LIMITED';
        // 404 is the normal "doc absent" path; let callers decide whether
        // to surface it. Any other non-2xx is logged for observability.
        if (status !== 404) {
          const sev = status >= 500 ? 'ERROR' : 'WARNING';
          logJson(sev, { fn: 'fsRequest', msg: 'firestore_http_error', method, path: urlPath, status, errStatus, errMsg: errMsg.slice(0, 256) });
        }
        reject(new FirestoreError(code, errMsg, status, parsed));
      });
    });
    req.on('error', (e) => {
      logJson('ERROR', { fn: 'fsRequest', msg: 'firestore_transport_error', method, path: urlPath, err: String(e) });
      reject(new FirestoreError('FS_TRANSPORT', String(e), 0, null));
    });
    req.setTimeout(20_000, () => {
      req.destroy(new Error('firestore_timeout'));
    });
    if (data) req.write(data);
    req.end();
  });
}

const TIMESTAMP_KEY = /(_at|_login|_date)$/;

function isIsoLike(s) {
  return typeof s === 'string'
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(s)
    && !Number.isNaN(Date.parse(s));
}

export function value(v, key) {
  if (v === null || v === undefined) return { nullValue: null };
  if (v instanceof Date) return { timestampValue: v.toISOString() };
  if (typeof v === 'boolean') return { booleanValue: v };
  if (typeof v === 'number') {
    if (Number.isFinite(v) && Number.isInteger(v)) return { integerValue: String(v) };
    return { doubleValue: v };
  }
  if (typeof v === 'bigint') return { integerValue: String(v) };
  if (typeof v === 'string') {
    if (key && TIMESTAMP_KEY.test(key) && isIsoLike(v)) return { timestampValue: v };
    return { stringValue: v };
  }
  if (Array.isArray(v)) {
    return { arrayValue: { values: v.map((x) => value(x, null)) } };
  }
  if (typeof v === 'object') {
    return { mapValue: { fields: encodeFields(v) } };
  }
  return { stringValue: String(v) };
}

export function parse(v) {
  if (!v || typeof v !== 'object') return null;
  if ('nullValue' in v) return null;
  if ('booleanValue' in v) return v.booleanValue;
  if ('integerValue' in v) {
    const n = Number(v.integerValue);
    return Number.isSafeInteger(n) ? n : v.integerValue;
  }
  if ('doubleValue' in v) return Number(v.doubleValue);
  if ('stringValue' in v) return v.stringValue;
  if ('timestampValue' in v) return v.timestampValue;
  if ('bytesValue' in v) return v.bytesValue;
  if ('referenceValue' in v) return v.referenceValue;
  if ('arrayValue' in v) return (v.arrayValue.values || []).map(parse);
  if ('mapValue' in v) return decodeFields(v.mapValue.fields || {});
  if ('geoPointValue' in v) return v.geoPointValue;
  return null;
}

export function encodeFields(obj) {
  const fields = {};
  if (!obj) return fields;
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined) continue;
    fields[k] = value(v, k);
  }
  return fields;
}

export function decodeFields(fields) {
  const out = {};
  if (!fields) return out;
  for (const [k, v] of Object.entries(fields)) {
    out[k] = parse(v);
  }
  return out;
}

export function serverTime() {
  return new Date().toISOString();
}

export function now() {
  return { timestampValue: new Date().toISOString() };
}

export function dbPath() {
  return BASE;
}

export function docName(collection, id) {
  return `${BASE}/${collection}/${encodeURIComponent(id)}`;
}

export function usersPath(uid) { return docName('tm_users', uid); }
export function projectsPath(pid) { return docName('tm_projects', pid); }
export function tasksPath(tid) { return docName('tm_tasks', tid); }
export function challengesPath(cid) { return docName('tm_challenges', cid); }
export function invitationsPath(iid) { return docName('tm_invitations', iid); }
export function auditPath(aid) { return docName('tm_audit', aid); }
export function userEmailPath(emailNorm) { return docName('tm_user_emails', emailNorm); }

// Read by ID. Returns decoded data or null if not found.
export async function getDoc(collection, id) {
  if (typeof id !== 'string' || id.length === 0) {
    throw new FirestoreError('FS_BAD_REQUEST', 'id is required', 0, null);
  }
  try {
    const { body } = await fsRequest('GET', `${BASE}/${collection}/${encodeURIComponent(id)}`, null);
    return decodeFields(body?.fields || {});
  } catch (e) {
    if (e instanceof FirestoreError && e.code === 'FS_NOT_FOUND') return null;
    throw e;
  }
}

// Create or overwrite a document at an explicit ID.
export async function setDoc(collection, id, data) {
  const fields = encodeFields(data);
  const path = `${BASE}/${collection}/${encodeURIComponent(id)}`;
  await fsRequest('PATCH', path, { fields });
}

// Create with auto-generated ID. Returns the assigned ID.
export async function createDoc(collection, data, explicitId) {
  const id = explicitId || randomUUID();
  const fields = encodeFields(data);
  const path = `${BASE}/${collection}/${encodeURIComponent(id)}`;
  // currentDocument.exists=false ensures create-only semantics.
  await fsRequest('PATCH', path + '?currentDocument.exists=false', { fields });
  return id;
}

// Patch only provided fields. The list of paths is computed from the
// top-level keys of `data`. Caller is responsible for splitting nested
// updates if needed.
export async function patchDoc(collection, id, data) {
  const fields = encodeFields(data);
  const fieldPaths = Object.keys(fields);
  if (fieldPaths.length === 0) return;
  const qs = fieldPaths.map((p) => 'updateMask.fieldPaths=' + encodeURIComponent(p)).join('&');
  const path = `${BASE}/${collection}/${encodeURIComponent(id)}?${qs}`;
  await fsRequest('PATCH', path, { fields });
}

// Delete by ID. No-op on 404.
export async function deleteDoc(collection, id) {
  try {
    await fsRequest('DELETE', `${BASE}/${collection}/${encodeURIComponent(id)}`, null);
  } catch (e) {
    if (e instanceof FirestoreError && e.code === 'FS_NOT_FOUND') return;
    throw e;
  }
}

// Atomic fetch-and-delete. Used for one-shot challenge consumption.
export async function fetchAndDelete(collection, id) {
  const beg = await fsRequest('POST', `${BASE}:beginTransaction`, { options: { readWrite: {} } });
  const tx = beg.body?.transaction;
  if (!tx) throw new FirestoreError('FS_TRANSPORT', 'no transaction id returned', 0, null);
  let docData = null;
  try {
    const url = `${BASE}/${collection}/${encodeURIComponent(id)}?transaction=${encodeURIComponent(tx)}`;
    try {
      const got = await fsRequest('GET', url, null);
      docData = decodeFields(got.body?.fields || {});
    } catch (e) {
      if (e instanceof FirestoreError && e.code === 'FS_NOT_FOUND') {
        docData = null;
      } else {
        throw e;
      }
    }
    const writes = docData
      ? [{ delete: `projects/${PROJECT_ID}/databases/${DB_ID}/documents/${collection}/${id}` }]
      : [];
    await fsRequest('POST', `${BASE}:commit`, { writes, transaction: tx });
    return docData;
  } catch (e) {
    try { await fsRequest('POST', `${BASE}:rollback`, { transaction: tx }); } catch { /* swallow */ }
    throw e;
  }
}

const OP_MAP = {
  '==': 'EQUAL',
  '!=': 'NOT_EQUAL',
  '<': 'LESS_THAN',
  '<=': 'LESS_THAN_OR_EQUAL',
  '>': 'GREATER_THAN',
  '>=': 'GREATER_THAN_OR_EQUAL',
  'array-contains': 'ARRAY_CONTAINS',
  'in': 'IN',
  'not-in': 'NOT_IN'
};

function buildStructuredQuery(collection, filters, opts) {
  const sq = { from: [{ collectionId: collection }] };
  const fieldFilters = (filters || []).map((f) => {
    const op = OP_MAP[f.op];
    if (!op) throw new FirestoreError('FS_BAD_REQUEST', `unsupported op ${f.op}`, 0, null);
    return { fieldFilter: { field: { fieldPath: f.field }, op, value: value(f.value, f.field) } };
  });
  if (fieldFilters.length === 1) sq.where = fieldFilters[0];
  else if (fieldFilters.length > 1) sq.where = { compositeFilter: { op: 'AND', filters: fieldFilters } };
  if (opts?.orderBy) {
    const ob = Array.isArray(opts.orderBy) ? opts.orderBy : [opts.orderBy];
    sq.orderBy = ob.map((o) => {
      if (typeof o === 'string') return { field: { fieldPath: o }, direction: 'ASCENDING' };
      return { field: { fieldPath: o.field }, direction: o.direction === 'desc' ? 'DESCENDING' : 'ASCENDING' };
    });
  }
  if (typeof opts?.limit === 'number' && opts.limit > 0) sq.limit = Math.floor(opts.limit);
  if (opts?.offset && opts.offset > 0) sq.offset = Math.floor(opts.offset);
  if (opts?.select && Array.isArray(opts.select)) {
    sq.select = { fields: opts.select.map((f) => ({ fieldPath: f })) };
  }
  return sq;
}

// Run a structured query. `parent` is the parent document path (or empty
// to scope to the database root). Returns the decoded array of documents.
export async function runQuery(parent, structuredQuery) {
  const path = (parent && parent.length > 0 ? parent : BASE) + ':runQuery';
  const { body } = await fsRequest('POST', path, { structuredQuery });
  if (!Array.isArray(body)) return [];
  const out = [];
  for (const row of body) {
    if (!row || !row.document) continue;
    const name = row.document.name || '';
    const id = name.split('/').pop();
    out.push({ id, name, data: decodeFields(row.document.fields || {}) });
  }
  return out;
}

// Convenience query. Returns [{id, data}].
export async function queryDocs(collection, filters, opts) {
  const sq = buildStructuredQuery(collection, filters, opts);
  const rows = await runQuery(BASE, sq);
  return rows.map((r) => ({ id: r.id, data: r.data }));
}

// Aggregation count for a structured query. Returns integer.
export async function countQuery(collection, filters) {
  const sq = buildStructuredQuery(collection, filters, null);
  const path = `${BASE}:runAggregationQuery`;
  const aggReq = {
    structuredAggregationQuery: {
      structuredQuery: sq,
      aggregations: [{ alias: 'cnt', count: {} }]
    }
  };
  const { body } = await fsRequest('POST', path, aggReq);
  if (!Array.isArray(body) || body.length === 0) return 0;
  const cnt = body[0]?.result?.aggregateFields?.cnt;
  if (!cnt) return 0;
  if ('integerValue' in cnt) return Number(cnt.integerValue);
  if ('doubleValue' in cnt) return Number(cnt.doubleValue);
  return 0;
}

// Run a function inside a transaction. The handle exposes immediate
// reads (transaction-bound) and queued writes (committed on success).
export async function runTransaction(fn) {
  const beg = await fsRequest('POST', `${BASE}:beginTransaction`, { options: { readWrite: {} } });
  const tx = beg.body?.transaction;
  if (!tx) throw new FirestoreError('FS_TRANSPORT', 'no transaction id returned', 0, null);
  const writes = [];
  const fullDocName = (coll, id) =>
    `projects/${PROJECT_ID}/databases/${DB_ID}/documents/${coll}/${id}`;
  const handle = {
    async get(collection, id) {
      try {
        const url = `${BASE}/${collection}/${encodeURIComponent(id)}?transaction=${encodeURIComponent(tx)}`;
        const r = await fsRequest('GET', url, null);
        return decodeFields(r.body?.fields || {});
      } catch (e) {
        if (e instanceof FirestoreError && e.code === 'FS_NOT_FOUND') return null;
        throw e;
      }
    },
    create(collection, data, explicitId) {
      const id = explicitId || randomUUID();
      writes.push({
        update: { name: fullDocName(collection, id), fields: encodeFields(data) },
        currentDocument: { exists: false }
      });
      return id;
    },
    set(collection, id, data) {
      writes.push({
        update: { name: fullDocName(collection, id), fields: encodeFields(data) }
      });
    },
    update(collection, id, data) {
      const fields = encodeFields(data);
      const fieldPaths = Object.keys(fields);
      writes.push({
        update: { name: fullDocName(collection, id), fields },
        updateMask: { fieldPaths },
        currentDocument: { exists: true }
      });
    },
    delete(collection, id) {
      writes.push({ delete: fullDocName(collection, id) });
    }
  };
  try {
    const result = await fn(handle);
    await fsRequest('POST', `${BASE}:commit`, { writes, transaction: tx });
    return result;
  } catch (e) {
    try { await fsRequest('POST', `${BASE}:rollback`, { transaction: tx }); } catch { /* swallow */ }
    throw e;
  }
}

export const config = Object.freeze({
  projectId: PROJECT_ID,
  databaseId: DB_ID,
  host: HOST
});
