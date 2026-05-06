// Resource assignments: links a unit to a dispatch and back-channels
// status to the field worker who filed the SOS. Each assignment lives at
// tm_assignments/{aid}; the parent dispatch carries a denormalised
// mirror of the assignment so the SOS PWA poll fetches one document.

import { randomUUID } from 'node:crypto';
import { runTransaction, getDoc } from './firestore.js';
import { record as auditRecord } from './audit.js';
import { ApiError, ScopeError, NotFoundError } from './_errors.js';

const ASSIGNMENT_STATUSES = new Set(['assigned', 'en_route', 'on_scene', 'completed', 'cancelled']);

const WORKER_STATUSES = Object.freeze([
  'received', 'under_review', 'resources_assigned', 'en_route',
  'on_scene', 'resolved', 'cancelled'
]);

function inActorSubtree(actorScope, callerScope) {
  if (typeof callerScope !== 'string') return false;
  return callerScope === actorScope || callerScope.startsWith(actorScope + '/');
}

function fmtEta(eta) {
  const n = Number(eta);
  if (!Number.isFinite(n) || n < 0) return null;
  return Math.floor(n);
}

function fmtPhone(p) {
  return typeof p === 'string' ? p : '';
}

// Worker-facing English summary. Re-generated every time a status moves.
// Localising to other languages is deferred; the field is structured so
// future locales can be added without breaking polls.
export function summaryFor(workerStatus, assignments) {
  const active = (assignments || []).filter((a) =>
    a && a.status !== 'completed' && a.status !== 'cancelled');
  const lead = active[0] || null;
  if (workerStatus === 'received') {
    return 'Request received. Dispatcher reviewing now.';
  }
  if (workerStatus === 'under_review') {
    return 'Dispatcher is matching the right responders to your case.';
  }
  if (workerStatus === 'cancelled') {
    return 'Request cancelled. If you still need help, raise a fresh SOS.';
  }
  if (workerStatus === 'resolved') {
    return 'Responders have closed this case. Stay safe.';
  }
  if (!lead) return 'Resources are being arranged. Hold on.';
  const parts = [];
  const name = lead.unit_name || 'Unit';
  if (workerStatus === 'on_scene' || lead.status === 'on_scene') {
    parts.push(`${name} on scene.`);
  } else if (workerStatus === 'en_route' || lead.status === 'en_route') {
    parts.push(`${name} en route.`);
  } else {
    parts.push(`${name} dispatched.`);
  }
  if (Number.isFinite(Number(lead.eta_minutes))) {
    parts.push(`ETA ${Math.max(0, Math.floor(Number(lead.eta_minutes)))} minutes.`);
  }
  if (lead.contact_phone) {
    parts.push(`Call ${lead.contact_phone}.`);
  }
  if (active.length > 1) {
    parts.push(`+${active.length - 1} more resources tasked.`);
  }
  return parts.join(' ');
}

function denormaliseAssignment(aid, a) {
  return {
    aid,
    unit_id: a.unit_id,
    unit_name: a.unit_name,
    unit_type: a.unit_type,
    status: a.status,
    assigned_at: a.assigned_at,
    eta_minutes: a.eta_minutes ?? null,
    contact_phone: a.unit_contact_phone || ''
  };
}

function appendHistory(arr, entry) {
  const a = Array.isArray(arr) ? arr.slice() : [];
  a.push(entry);
  return a;
}

// POST /api/v1/tm/dispatches/:id/assign
// body: { unit_id, eta_minutes?, note? }
// signatureB64 is verified by the router via requireFreshUserSig.
export async function assignUnit(actor, dispatchId, body, signatureB64) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  const unitId = String(body?.unit_id || '');
  if (!unitId) throw new ApiError('bad_request', 'unit_id required.', 400);
  const eta = fmtEta(body?.eta_minutes);
  const note = typeof body?.note === 'string' && body.note.length <= 500 ? body.note : null;

  return runTransaction(async (tx) => {
    const dispatch = await tx.get('tm_dispatches', dispatchId);
    if (!dispatch) throw new NotFoundError('dispatch_not_found', 'No such dispatch.');
    if (!inActorSubtree(actor.scope_path, dispatch.caller_scope_path)) {
      throw new ScopeError('out_of_scope', 'Dispatch is outside your subtree.');
    }
    if (dispatch.worker_status === 'resolved' || dispatch.worker_status === 'cancelled') {
      throw new ApiError('dispatch_closed', 'Dispatch is already closed.', 409);
    }
    const unit = await tx.get('tm_units', unitId);
    if (!unit) throw new NotFoundError('unit_not_found', 'No such unit.');
    if (unit.archived === true) throw new ApiError('unit_archived', 'Unit is archived.', 409);
    if (!inActorSubtree(actor.scope_path, unit.scope_path)) {
      throw new ScopeError('out_of_scope', 'Unit is outside your subtree.');
    }
    if (unit.status !== 'available') {
      throw new ApiError('unit_unavailable', `Unit is ${unit.status}.`, 409);
    }

    const aid = randomUUID();
    const now = new Date();
    const nowIso = now.toISOString();
    const initialStatus = 'assigned';
    const assignmentDoc = {
      dispatch_id: dispatchId,
      unit_id: unitId,
      unit_name: unit.name,
      unit_type: unit.type,
      unit_contact_phone: fmtPhone(unit.contact_phone),
      assigned_by_uid: actor.uid,
      assigned_by_name: actor.name || null,
      assigned_at: now,
      eta_minutes: eta,
      note,
      status: initialStatus,
      status_history: [{ status: initialStatus, ts: nowIso, note: note || null }],
      completed_at: null
    };

    tx.set('tm_assignments', aid, assignmentDoc);
    tx.update('tm_units', unitId, {
      status: 'busy',
      last_status_at: now
    });

    const denorm = denormaliseAssignment(aid, assignmentDoc);
    const assignments = Array.isArray(dispatch.assignments) ? dispatch.assignments.slice() : [];
    assignments.push(denorm);

    const nextWorkerStatus = eta !== null ? 'en_route' : 'resources_assigned';
    const workerHist = appendHistory(dispatch.worker_status_history, {
      status: nextWorkerStatus,
      ts: nowIso,
      by_uid: actor.uid,
      note: note || null
    });
    const summary = summaryFor(nextWorkerStatus, assignments);

    tx.update('tm_dispatches', dispatchId, {
      assignments,
      worker_status: nextWorkerStatus,
      worker_status_history: workerHist,
      worker_summary_text: summary,
      updated_at: now
    });

    await auditRecord(actor.uid, 'dispatch.assign', `tm_dispatches/${dispatchId}`,
      { aid, unit_id: unitId, unit_name: unit.name, eta, note }, signatureB64 || null);

    const result = {
      aid,
      dispatch_id: dispatchId,
      unit_id: unitId,
      unit_name: unit.name,
      unit_type: unit.type,
      status: initialStatus,
      eta_minutes: eta,
      worker_status: nextWorkerStatus,
      worker_summary_text: summary,
      assignments
    };
    // Push notify the dispatch caller (their PWA used to poll every
    // 15 s; this replaces the polling) AND the caller's parent so
    // the supervising tier sees movement on the dispatch without a
    // refresh.
    import('./notify.js').then((m) => {
      if (typeof m.notifyAssignmentCreated === 'function') {
        return m.notifyAssignmentCreated({
          id: dispatchId,
          caller_uid: dispatch.caller_uid || null,
          caller_scope_path: dispatch.caller_scope_path || null,
          worker_status: nextWorkerStatus,
          triage: dispatch.triage || null
        }, result);
      }
    }).catch(() => { /* notify is best-effort */ });
    return result;
  });
}

// PATCH /api/v1/tm/assignments/:aid
// body: { status?, eta_minutes?, note? }
export async function updateAssignment(actor, aid, body) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  if (typeof aid !== 'string' || aid.length === 0) {
    throw new ApiError('bad_request', 'aid required.', 400);
  }
  const wantStatus = body?.status !== undefined ? String(body.status) : null;
  if (wantStatus !== null && !ASSIGNMENT_STATUSES.has(wantStatus)) {
    throw new ApiError('bad_status', 'Invalid status.', 400);
  }
  const wantEta = body?.eta_minutes !== undefined ? fmtEta(body.eta_minutes) : undefined;
  const note = typeof body?.note === 'string' && body.note.length <= 500 ? body.note : null;

  return runTransaction(async (tx) => {
    const a = await tx.get('tm_assignments', aid);
    if (!a) throw new NotFoundError('assignment_not_found', 'No such assignment.');
    const dispatch = await tx.get('tm_dispatches', a.dispatch_id);
    if (!dispatch) throw new NotFoundError('dispatch_not_found', 'No such dispatch.');
    if (!inActorSubtree(actor.scope_path, dispatch.caller_scope_path)) {
      throw new ScopeError('out_of_scope', 'Dispatch is outside your subtree.');
    }

    const now = new Date();
    const nowIso = now.toISOString();
    const patch = {};
    let nextStatus = a.status;
    if (wantStatus !== null && wantStatus !== a.status) {
      nextStatus = wantStatus;
      patch.status = nextStatus;
    }
    if (wantEta !== undefined) {
      patch.eta_minutes = wantEta;
    }
    const histEntry = { status: nextStatus, ts: nowIso, note: note || null };
    const history = appendHistory(a.status_history, histEntry);
    patch.status_history = history;
    if (nextStatus === 'completed' || nextStatus === 'cancelled') {
      patch.completed_at = now;
    }
    tx.update('tm_assignments', aid, patch);

    if (nextStatus === 'completed' || nextStatus === 'cancelled') {
      tx.update('tm_units', a.unit_id, { status: 'available', last_status_at: now });
    } else if (nextStatus === 'en_route') {
      tx.update('tm_units', a.unit_id, { status: 'en_route', last_status_at: now });
    } else if (nextStatus === 'on_scene') {
      tx.update('tm_units', a.unit_id, { status: 'on_scene', last_status_at: now });
    }

    const assignments = Array.isArray(dispatch.assignments)
      ? dispatch.assignments.map((x) => x.aid === aid
          ? { ...x, status: nextStatus, eta_minutes: wantEta !== undefined ? wantEta : x.eta_minutes }
          : x)
      : [];
    const active = assignments.filter((x) => x.status !== 'completed' && x.status !== 'cancelled');

    let workerStatus = dispatch.worker_status || 'received';
    if (active.length === 0 && assignments.length > 0) {
      workerStatus = 'resolved';
    } else if (active.some((x) => x.status === 'on_scene')) {
      workerStatus = 'on_scene';
    } else if (active.some((x) => x.status === 'en_route')) {
      workerStatus = 'en_route';
    } else if (active.length > 0) {
      workerStatus = 'resources_assigned';
    }

    const workerHist = workerStatus !== dispatch.worker_status
      ? appendHistory(dispatch.worker_status_history, {
          status: workerStatus, ts: nowIso, by_uid: actor.uid, note: note || null
        })
      : (Array.isArray(dispatch.worker_status_history) ? dispatch.worker_status_history : []);
    const summary = summaryFor(workerStatus, assignments);

    tx.update('tm_dispatches', a.dispatch_id, {
      assignments,
      worker_status: workerStatus,
      worker_status_history: workerHist,
      worker_summary_text: summary,
      updated_at: now,
      ...(workerStatus === 'resolved' ? { resolved_at: now } : {})
    });

    await auditRecord(actor.uid, 'assignment.update', `tm_assignments/${aid}`,
      { dispatch_id: a.dispatch_id, status: nextStatus, eta_minutes: wantEta, note }, null);

    const result = {
      aid,
      dispatch_id: a.dispatch_id,
      status: nextStatus,
      eta_minutes: wantEta !== undefined ? wantEta : a.eta_minutes,
      worker_status: workerStatus,
      worker_summary_text: summary,
      assignments
    };
    // Push notify the dispatch caller on every assignment status
    // change so the SOS PWA updates without a poll.
    import('./notify.js').then((m) => {
      if (typeof m.notifyAssignmentUpdated === 'function') {
        return m.notifyAssignmentUpdated({
          id: a.dispatch_id,
          caller_uid: dispatch.caller_uid || null,
          caller_scope_path: dispatch.caller_scope_path || null,
          worker_status: workerStatus,
          triage: dispatch.triage || null
        }, result);
      }
    }).catch(() => { /* notify is best-effort */ });
    return result;
  });
}

// GET /api/v1/tm/dispatches/:id/status
// Caller-permitted read used by the SOS PWA. The dispatch's caller can
// always read its own status; subtree actors can read any dispatch in
// scope. Returns only fields the worker needs to render.
export async function readWorkerStatus(actor, dispatchId) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  const doc = await getDoc('tm_dispatches', dispatchId);
  if (!doc) throw new NotFoundError('dispatch_not_found', 'No such dispatch.');
  const isCaller = doc.caller_uid && doc.caller_uid === actor.uid;
  const inScope = inActorSubtree(actor.scope_path, doc.caller_scope_path);
  if (!isCaller && !inScope) {
    throw new ScopeError('out_of_scope', 'Dispatch is outside your subtree.');
  }
  return {
    id: dispatchId,
    worker_status: doc.worker_status || 'received',
    worker_summary_text: doc.worker_summary_text || '',
    assignments: Array.isArray(doc.assignments) ? doc.assignments : [],
    received_at: doc.received_at || null,
    updated_at: doc.updated_at || doc.received_at || null
  };
}

export const VALID_WORKER_STATUSES = WORKER_STATUSES;
export const _internal = { summaryFor, ASSIGNMENT_STATUSES };
