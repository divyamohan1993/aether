// Project CRUD for the Task Manager module.
// Visibility is scope-driven: a caller sees a project iff its scope_path
// is equal to or a descendant of the caller's scope_path.

import { randomUUID } from 'node:crypto';
import {
  getDoc, setDoc, queryDocs, patchDoc, runTransaction
} from './firestore.js';
import { record as auditRecord } from './audit.js';
import { isInScope, isValidScope } from './users.js';
import { ApiError, ScopeError, NotFoundError } from './_errors.js';

const NAME_RE = /^[\p{L}\p{N} .,'\-_/()&]{1,120}$/u;

function isValidName(n) {
  return typeof n === 'string' && NAME_RE.test(n);
}

function publicProject(p) {
  if (!p) return null;
  return {
    pid: p.pid,
    name: p.name,
    description: p.description || '',
    scope_path: p.scope_path,
    owner_uid: p.owner_uid,
    status: p.status,
    created_at: p.created_at,
    updated_at: p.updated_at || p.created_at
  };
}

function canRead(actor, project) {
  if (!actor || !project) return false;
  return isInScope(actor.scope_path, project.scope_path);
}

function canWrite(actor, project) {
  if (!canRead(actor, project)) return false;
  if (actor.uid === project.owner_uid) return true;
  return actor.tier >= 60; // district and above can edit any project in scope
}

export async function list(actor, opts) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  const cap = Math.min(Math.max(opts?.limit || 200, 1), 500);
  const includeArchived = opts?.include_archived === true;
  const upper = actor.scope_path + '/￿';
  const filters = [
    { field: 'scope_path', op: '>=', value: actor.scope_path },
    { field: 'scope_path', op: '<=', value: upper }
  ];
  const rows = await queryDocs('tm_projects', filters, { orderBy: 'scope_path', limit: cap });
  const out = [];
  for (const r of rows) {
    const sp = r.data.scope_path;
    if (sp !== actor.scope_path && !sp.startsWith(actor.scope_path + '/')) continue;
    if (!includeArchived && r.data.status === 'archived') continue;
    out.push(publicProject({ pid: r.id, ...r.data }));
  }
  return out;
}

export async function get(actor, pid) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  const doc = await getDoc('tm_projects', pid);
  if (!doc) throw new NotFoundError('project_not_found', 'No such project.');
  if (!canRead(actor, doc)) throw new ScopeError('out_of_scope', 'Project is out of scope.');
  return publicProject({ pid, ...doc });
}

export async function create(actor, body) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  if (actor.tier < 60) throw new ScopeError('tier_too_low', 'Only district tier and above can create projects.');
  const name = String(body?.name || '').trim();
  const description = String(body?.description || '').trim().slice(0, 4000);
  const scopePath = String(body?.scope_path || actor.scope_path);
  if (!isValidName(name)) throw new ApiError('bad_name', 'Invalid project name.', 400);
  if (!isValidScope(scopePath)) throw new ApiError('bad_scope', 'Invalid scope_path.', 400);
  if (!isInScope(actor.scope_path, scopePath)) throw new ScopeError('out_of_scope', 'Scope is outside your subtree.');

  const pid = randomUUID();
  const now = new Date();
  const data = {
    name,
    description,
    scope_path: scopePath,
    owner_uid: actor.uid,
    status: 'active',
    created_at: now,
    updated_at: now
  };
  await setDoc('tm_projects', pid, data);
  await auditRecord(actor.uid, 'project.create', `tm_projects/${pid}`,
    { name, scope_path: scopePath }, null);
  return publicProject({
    pid,
    name,
    description,
    scope_path: scopePath,
    owner_uid: actor.uid,
    status: 'active',
    created_at: now.toISOString(),
    updated_at: now.toISOString()
  });
}

export async function update(actor, pid, body) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  return runTransaction(async (tx) => {
    const doc = await tx.get('tm_projects', pid);
    if (!doc) throw new NotFoundError('project_not_found', 'No such project.');
    if (!canWrite(actor, doc)) throw new ScopeError('forbidden', 'You cannot edit this project.');
    const patch = {};
    if (body && typeof body.name === 'string') {
      const name = body.name.trim();
      if (!isValidName(name)) throw new ApiError('bad_name', 'Invalid project name.', 400);
      patch.name = name;
    }
    if (body && typeof body.description === 'string') {
      patch.description = body.description.trim().slice(0, 4000);
    }
    if (Object.keys(patch).length === 0) {
      return publicProject({ pid, ...doc });
    }
    patch.updated_at = new Date();
    tx.update('tm_projects', pid, patch);
    await auditRecord(actor.uid, 'project.update', `tm_projects/${pid}`, patch, null);
    return publicProject({ pid, ...doc, ...patch, updated_at: patch.updated_at.toISOString() });
  });
}

// Archive (soft delete) a project. The spec maps DELETE /projects/:pid
// to archive and requires a fresh user signature. Auth.js verifies the
// signature before this runs; we record it in the audit entry.
export async function archive(actor, pid, actorSignatureB64) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  return runTransaction(async (tx) => {
    const doc = await tx.get('tm_projects', pid);
    if (!doc) throw new NotFoundError('project_not_found', 'No such project.');
    if (!canWrite(actor, doc)) throw new ScopeError('forbidden', 'You cannot archive this project.');
    if (doc.status === 'archived') {
      return publicProject({ pid, ...doc });
    }
    const updatedAt = new Date();
    tx.update('tm_projects', pid, { status: 'archived', updated_at: updatedAt });
    await auditRecord(actor.uid, 'project.archive', `tm_projects/${pid}`,
      { name: doc.name, scope_path: doc.scope_path }, actorSignatureB64 || null);
    return publicProject({ pid, ...doc, status: 'archived', updated_at: updatedAt.toISOString() });
  });
}
