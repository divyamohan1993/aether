// Task CRUD and dashboard aggregation.

import { randomUUID } from 'node:crypto';
import {
  getDoc, setDoc, queryDocs, runTransaction, countQuery
} from './firestore.js';
import { record as auditRecord } from './audit.js';
import { isInScope, isValidScope } from './users.js';
import { ApiError, ScopeError, NotFoundError } from './_errors.js';

const STATUS_VALUES = new Set(['open', 'in_progress', 'blocked', 'done', 'cancelled']);
const PRIORITY_VALUES = new Set(['low', 'med', 'high', 'critical']);

const TITLE_RE = /^[\p{L}\p{N} .,'\-_/()&!?:;@#%]{1,160}$/u;

function isValidTitle(t) { return typeof t === 'string' && TITLE_RE.test(t); }

function isIso(s) {
  return typeof s === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(s) && !Number.isNaN(Date.parse(s));
}

function publicTask(t) {
  if (!t) return null;
  return {
    tid: t.tid,
    project_id: t.project_id,
    title: t.title,
    description: t.description || '',
    scope_path: t.scope_path,
    assignee_uid: t.assignee_uid || null,
    creator_uid: t.creator_uid,
    status: t.status,
    priority: t.priority,
    due_date: t.due_date || null,
    created_at: t.created_at,
    updated_at: t.updated_at || t.created_at
  };
}

function canRead(actor, task) {
  if (!actor || !task) return false;
  return isInScope(actor.scope_path, task.scope_path);
}

// Volunteers: status updates only, on tasks they are assigned to.
// Responders: own assigned tasks fully; cannot edit unassigned.
// District+: edit any task in scope.
function canEditFully(actor, task) {
  if (!canRead(actor, task)) return false;
  if (actor.tier >= 60) return true;
  if (actor.tier === 40 && task.assignee_uid === actor.uid) return true;
  return false;
}

function canEditStatus(actor, task) {
  if (canEditFully(actor, task)) return true;
  if (actor.tier === 20 && task.assignee_uid === actor.uid) return true;
  return false;
}

export async function list(actor, filters) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  const cap = Math.min(Math.max(filters?.limit || 200, 1), 500);
  const upper = actor.scope_path + '/￿';
  const fs = [
    { field: 'scope_path', op: '>=', value: actor.scope_path },
    { field: 'scope_path', op: '<=', value: upper }
  ];
  if (filters?.project) fs.push({ field: 'project_id', op: '==', value: String(filters.project) });
  if (filters?.assignee) fs.push({ field: 'assignee_uid', op: '==', value: String(filters.assignee) });
  if (filters?.status) {
    const s = String(filters.status);
    if (!STATUS_VALUES.has(s)) throw new ApiError('bad_status', 'Invalid status.', 400);
    fs.push({ field: 'status', op: '==', value: s });
  }
  const rows = await queryDocs('tm_tasks', fs, { orderBy: 'scope_path', limit: cap });
  const overdueCutoff = new Date().toISOString();
  const overdueOnly = filters?.overdue === true || filters?.overdue === 'true';
  const out = [];
  for (const r of rows) {
    const sp = r.data.scope_path;
    if (sp !== actor.scope_path && !sp.startsWith(actor.scope_path + '/')) continue;
    if (overdueOnly) {
      const dd = r.data.due_date;
      if (!dd || dd >= overdueCutoff) continue;
      if (r.data.status === 'done' || r.data.status === 'cancelled') continue;
    }
    out.push(publicTask({ tid: r.id, ...r.data }));
  }
  return out;
}

export async function get(actor, tid) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  const doc = await getDoc('tm_tasks', tid);
  if (!doc) throw new NotFoundError('task_not_found', 'No such task.');
  if (!canRead(actor, doc)) throw new ScopeError('out_of_scope', 'Task is out of scope.');
  return publicTask({ tid, ...doc });
}

export async function create(actor, body) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  if (actor.tier < 40) throw new ScopeError('tier_too_low', 'Volunteers cannot create tasks.');
  const projectId = String(body?.project_id || '');
  if (!projectId) throw new ApiError('bad_request', 'project_id required.', 400);
  const project = await getDoc('tm_projects', projectId);
  if (!project) throw new NotFoundError('project_not_found', 'No such project.');
  if (!isInScope(actor.scope_path, project.scope_path)) {
    throw new ScopeError('out_of_scope', 'Project is out of scope.');
  }
  if (project.status === 'archived') {
    throw new ApiError('project_archived', 'Project is archived.', 409);
  }
  const title = String(body?.title || '').trim();
  if (!isValidTitle(title)) throw new ApiError('bad_title', 'Invalid title.', 400);
  const description = String(body?.description || '').trim().slice(0, 8000);
  const priority = String(body?.priority || 'med');
  if (!PRIORITY_VALUES.has(priority)) throw new ApiError('bad_priority', 'Invalid priority.', 400);
  let assigneeUid = body?.assignee_uid ? String(body.assignee_uid) : null;
  if (assigneeUid) {
    const u = await getDoc('tm_users', assigneeUid);
    if (!u) throw new NotFoundError('assignee_not_found', 'Assignee does not exist.');
    if (!isInScope(actor.scope_path, u.scope_path)) {
      throw new ScopeError('assignee_out_of_scope', 'Assignee is outside your subtree.');
    }
  }
  let dueDate = null;
  if (body?.due_date) {
    if (!isIso(body.due_date)) throw new ApiError('bad_due_date', 'due_date must be ISO 8601.', 400);
    dueDate = new Date(body.due_date);
  }

  const tid = randomUUID();
  const now = new Date();
  const data = {
    project_id: projectId,
    title,
    description,
    scope_path: project.scope_path,
    assignee_uid: assigneeUid,
    creator_uid: actor.uid,
    status: 'open',
    priority,
    due_date: dueDate,
    created_at: now,
    updated_at: now
  };
  await setDoc('tm_tasks', tid, data);
  await auditRecord(actor.uid, 'task.create', `tm_tasks/${tid}`,
    { project_id: projectId, title, priority, assignee_uid: assigneeUid }, null);
  return publicTask({
    tid,
    project_id: projectId,
    title,
    description,
    scope_path: project.scope_path,
    assignee_uid: assigneeUid,
    creator_uid: actor.uid,
    status: 'open',
    priority,
    due_date: dueDate ? dueDate.toISOString() : null,
    created_at: now.toISOString(),
    updated_at: now.toISOString()
  });
}

export async function update(actor, tid, body, actorSignatureB64) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  return runTransaction(async (tx) => {
    const doc = await tx.get('tm_tasks', tid);
    if (!doc) throw new NotFoundError('task_not_found', 'No such task.');
    if (!canRead(actor, doc)) throw new ScopeError('out_of_scope', 'Task is out of scope.');
    const wantsFull = (body?.title !== undefined) || (body?.description !== undefined)
      || (body?.priority !== undefined) || (body?.assignee_uid !== undefined)
      || (body?.due_date !== undefined);
    if (wantsFull && !canEditFully(actor, doc)) {
      throw new ScopeError('forbidden', 'You may only update status on this task.');
    }
    if (!wantsFull && body?.status !== undefined && !canEditStatus(actor, doc)) {
      throw new ScopeError('forbidden', 'You cannot update this task.');
    }
    const patch = {};
    if (body?.title !== undefined) {
      const title = String(body.title).trim();
      if (!isValidTitle(title)) throw new ApiError('bad_title', 'Invalid title.', 400);
      patch.title = title;
    }
    if (body?.description !== undefined) {
      patch.description = String(body.description).trim().slice(0, 8000);
    }
    if (body?.priority !== undefined) {
      const p = String(body.priority);
      if (!PRIORITY_VALUES.has(p)) throw new ApiError('bad_priority', 'Invalid priority.', 400);
      patch.priority = p;
    }
    if (body?.status !== undefined) {
      const s = String(body.status);
      if (!STATUS_VALUES.has(s)) throw new ApiError('bad_status', 'Invalid status.', 400);
      patch.status = s;
    }
    if (body?.assignee_uid !== undefined) {
      const a = body.assignee_uid === null ? null : String(body.assignee_uid);
      if (a) {
        const u = await tx.get('tm_users', a);
        if (!u) throw new NotFoundError('assignee_not_found', 'Assignee does not exist.');
        if (!isInScope(actor.scope_path, u.scope_path)) {
          throw new ScopeError('assignee_out_of_scope', 'Assignee is outside your subtree.');
        }
      }
      patch.assignee_uid = a;
    }
    if (body?.due_date !== undefined) {
      if (body.due_date === null) patch.due_date = null;
      else {
        if (!isIso(body.due_date)) throw new ApiError('bad_due_date', 'due_date must be ISO 8601.', 400);
        patch.due_date = new Date(body.due_date);
      }
    }
    if (Object.keys(patch).length === 0) {
      return publicTask({ tid, ...doc });
    }
    patch.updated_at = new Date();
    tx.update('tm_tasks', tid, patch);
    const action = (Object.keys(patch).length === 2 && 'status' in patch) ? 'task.status' : 'task.update';
    await auditRecord(actor.uid, action, `tm_tasks/${tid}`, patch, actorSignatureB64 || null);
    const merged = { ...doc, ...patch };
    if (merged.due_date instanceof Date) merged.due_date = merged.due_date.toISOString();
    if (merged.updated_at instanceof Date) merged.updated_at = merged.updated_at.toISOString();
    return publicTask({ tid, ...merged });
  });
}

export async function archive(actor, tid) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  return runTransaction(async (tx) => {
    const doc = await tx.get('tm_tasks', tid);
    if (!doc) throw new NotFoundError('task_not_found', 'No such task.');
    if (!canEditFully(actor, doc)) throw new ScopeError('forbidden', 'You cannot archive this task.');
    if (doc.status === 'cancelled') return publicTask({ tid, ...doc });
    const updatedAt = new Date();
    tx.update('tm_tasks', tid, { status: 'cancelled', updated_at: updatedAt });
    await auditRecord(actor.uid, 'task.archive', `tm_tasks/${tid}`,
      { title: doc.title, project_id: doc.project_id }, null);
    return publicTask({ tid, ...doc, status: 'cancelled', updated_at: updatedAt.toISOString() });
  });
}

// Aggregate dashboard for the actor's subtree. Counts use
// runAggregationQuery so we only pay for the totals, not the documents.
export async function dashboard(actor) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  const upper = actor.scope_path + '/￿';
  const scopeFilters = [
    { field: 'scope_path', op: '>=', value: actor.scope_path },
    { field: 'scope_path', op: '<=', value: upper }
  ];

  const statuses = ['open', 'in_progress', 'blocked', 'done', 'cancelled'];
  const priorities = ['low', 'med', 'high', 'critical'];

  const counts = { by_status: {}, by_priority: {}, total: 0, overdue: 0 };
  const runs = [];

  runs.push(countQuery('tm_tasks', scopeFilters)
    .then((n) => { counts.total = n; })
    .catch(() => { counts.total = 0; }));
  for (const s of statuses) {
    counts.by_status[s] = 0;
    runs.push(countQuery('tm_tasks', [...scopeFilters,
      { field: 'status', op: '==', value: s }])
      .then((n) => { counts.by_status[s] = n; })
      .catch(() => {}));
  }
  for (const p of priorities) {
    counts.by_priority[p] = 0;
    runs.push(countQuery('tm_tasks', [...scopeFilters,
      { field: 'priority', op: '==', value: p }])
      .then((n) => { counts.by_priority[p] = n; })
      .catch(() => {}));
  }
  runs.push(countQuery('tm_tasks', [...scopeFilters,
    { field: 'due_date', op: '<', value: new Date() },
    { field: 'status', op: '!=', value: 'done' }
  ]).then((n) => { counts.overdue = n; }).catch(() => { counts.overdue = 0; }));

  const rowsForAssignees = queryDocs('tm_tasks',
    [...scopeFilters, { field: 'status', op: '!=', value: 'done' }],
    { orderBy: 'status', limit: 500 }
  ).then((rows) => {
    const m = new Map();
    for (const r of rows) {
      const sp = r.data.scope_path;
      if (sp !== actor.scope_path && !sp.startsWith(actor.scope_path + '/')) continue;
      const a = r.data.assignee_uid;
      if (!a) continue;
      m.set(a, (m.get(a) || 0) + 1);
    }
    return [...m.entries()]
      .sort((x, y) => y[1] - x[1])
      .slice(0, 5)
      .map(([uid, n]) => ({ uid, open_count: n }));
  }).catch(() => []);

  const projectsCount = countQuery('tm_projects', [
    ...scopeFilters,
    { field: 'status', op: '==', value: 'active' }
  ]).catch(() => 0);

  await Promise.all(runs);
  const top = await rowsForAssignees;
  const projects_active = await projectsCount;

  return {
    scope_path: actor.scope_path,
    tier: actor.tier,
    tasks: counts,
    projects_active,
    top_assignees: top
  };
}
