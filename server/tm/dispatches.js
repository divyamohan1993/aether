// Dispatch escalation pipeline. Reads + mutates tm_dispatches/{id}.
// Scope rules: an actor sees every dispatch whose caller_scope_path is a
// prefix of their own scope_path. They can act (escalate / mark reviewed)
// only when the caller is at a strictly lower tier in their subtree.

import * as fsMod from './firestore.js';
import * as usersMod from './users.js';
import { record as auditRecord } from './audit.js';
import { ApiError, ScopeError, NotFoundError } from './_errors.js';

// Test injection seams. Production binds these to firestore.js and
// users.js directly; tests can swap any of them to keep the run
// in-process. Lightweight and limited to read paths.
let _getUser = (actor, uid) => usersMod.getUser(actor, uid);
let _queryDocs = (...args) => fsMod.queryDocs(...args);
let _getDoc = (...args) => fsMod.getDoc(...args);
let _runTransaction = (fn) => fsMod.runTransaction(fn);

export function _setUsersForTest(stub) {
  _getUser = typeof stub === 'function' ? stub : (actor, uid) => usersMod.getUser(actor, uid);
}
export function _setFirestoreForTest(stub) {
  if (stub && typeof stub === 'object') {
    if (typeof stub.queryDocs === 'function') _queryDocs = stub.queryDocs.bind(stub);
    if (typeof stub.getDoc === 'function') _getDoc = stub.getDoc.bind(stub);
    if (typeof stub.runTransaction === 'function') _runTransaction = stub.runTransaction.bind(stub);
  } else {
    _queryDocs = (...args) => fsMod.queryDocs(...args);
    _getDoc = (...args) => fsMod.getDoc(...args);
    _runTransaction = (fn) => fsMod.runTransaction(fn);
  }
}

const STATUS_VALUES = new Set(['none', 'pending_review', 'escalated', 'auto_escalated', 'reviewed']);

function clampLimit(n, def) {
  const v = Number.isFinite(n) ? n : def;
  return Math.min(Math.max(Math.floor(v) || def, 1), 200);
}

function projectDispatch(id, data) {
  return { id, ...data };
}

function inActorSubtree(actorScope, callerScope) {
  if (typeof callerScope !== 'string') return false;
  return callerScope === actorScope || callerScope.startsWith(actorScope + '/');
}

// All dispatches filed by the actor.
export async function listMine(actor, opts) {
  if (!actor || !actor.uid) throw new ApiError('unauthorized', 'No session.', 401);
  const limit = clampLimit(opts?.limit, 50);
  const rows = await _queryDocs('tm_dispatches', [
    { field: 'caller_uid', op: '==', value: actor.uid }
  ], { limit }).catch(() => []);
  const out = rows.map((r) => projectDispatch(r.id, r.data));
  out.sort((a, b) => (b.received_at || '').localeCompare(a.received_at || ''));
  return out;
}

// Subtree feed. Excludes the actor's own dispatches unless mine=true.
// Optional status filter, applied in memory because Firestore composite
// indexes are not pre-declared for this collection.
//
// When opts.requires_review === true, the result is sorted by
// criticality_score desc with received_at asc as the tiebreaker so the
// dispatcher's pending-review queue surfaces life-threat first. All
// other modes keep the existing newest-first time order.
//
// opts.direct_only === true filters to dispatches whose caller is a
// direct subordinate of the actor (caller.parent_uid === actor.uid).
// Caches per-call user reads in a Map to avoid N+1 lookups.
export async function listTeam(actor, opts) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  const limit = clampLimit(opts?.limit, 50);
  const includeMine = !!opts?.mine;
  const status = typeof opts?.status === 'string' && STATUS_VALUES.has(opts.status) ? opts.status : null;
  const requiresReview = opts?.requires_review === true;
  const directOnly = opts?.direct_only === true;
  const upper = actor.scope_path + '/￿';
  const rows = await _queryDocs('tm_dispatches', [
    { field: 'caller_scope_path', op: '>=', value: actor.scope_path },
    { field: 'caller_scope_path', op: '<=', value: upper }
  ], { orderBy: 'caller_scope_path', limit: 200 }).catch(() => []);
  const userCache = new Map();
  const out = [];
  for (const r of rows) {
    const sp = r.data.caller_scope_path;
    if (!inActorSubtree(actor.scope_path, sp)) continue;
    if (!includeMine && r.data.caller_uid === actor.uid) continue;
    if (status && r.data.escalation_status !== status) continue;
    if (requiresReview && r.data.requires_review !== true) continue;
    if (directOnly) {
      const callerUid = r.data.caller_uid;
      if (!callerUid) continue;
      let parentUid = userCache.get(callerUid);
      if (parentUid === undefined) {
        try {
          const u = await _getUser(actor, callerUid);
          parentUid = u?.parent_uid || null;
        } catch {
          parentUid = null;
        }
        userCache.set(callerUid, parentUid);
      }
      if (parentUid !== actor.uid) continue;
    }
    out.push(projectDispatch(r.id, r.data));
  }
  if (requiresReview) {
    out.sort((a, b) => {
      const ca = Number(a.criticality_score) || 0;
      const cb = Number(b.criticality_score) || 0;
      if (cb !== ca) return cb - ca;
      return (a.received_at || '').localeCompare(b.received_at || '');
    });
  } else {
    out.sort((a, b) => (b.received_at || '').localeCompare(a.received_at || ''));
  }
  return out.slice(0, limit);
}

export async function get(actor, id) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  if (typeof id !== 'string' || id.length === 0) {
    throw new ApiError('bad_request', 'id required.', 400);
  }
  const doc = await _getDoc('tm_dispatches', id);
  if (!doc) throw new NotFoundError('dispatch_not_found', 'No such dispatch.');
  if (!inActorSubtree(actor.scope_path, doc.caller_scope_path)) {
    throw new ScopeError('out_of_scope', 'Dispatch is outside your subtree.');
  }
  return projectDispatch(id, doc);
}

function appendChain(existing, entry) {
  const arr = Array.isArray(existing) ? existing.slice() : [];
  arr.push(entry);
  return arr;
}

// Escalate: actor must outrank caller AND must have at least one parent
// (cannot escalate from NDMA root). Re-sign verified by router.
export async function escalate(actor, id, body, signatureB64) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  if (Number(actor.tier) >= 100) {
    throw new ScopeError('no_supervisor', 'You are at the top of the chain.');
  }
  return _runTransaction(async (tx) => {
    const doc = await tx.get('tm_dispatches', id);
    if (!doc) throw new NotFoundError('dispatch_not_found', 'No such dispatch.');
    if (!inActorSubtree(actor.scope_path, doc.caller_scope_path)) {
      throw new ScopeError('out_of_scope', 'Dispatch is outside your subtree.');
    }
    const callerTier = Number(doc.caller_tier);
    if (Number.isFinite(callerTier) && callerTier >= actor.tier) {
      throw new ScopeError('caller_at_or_above_actor', 'Cannot escalate a dispatch from your peer or superior.');
    }
    const note = typeof body?.note === 'string' && body.note.length <= 500 ? body.note : null;
    const entry = {
      actor_uid: actor.uid,
      actor_tier: actor.tier,
      action: 'escalate',
      target_tier: actor.tier,
      ts: new Date().toISOString()
    };
    if (note) entry.note = note;
    const chain = appendChain(doc.escalation_chain, entry);
    tx.update('tm_dispatches', id, {
      escalation_chain: chain,
      escalation_status: 'escalated',
      requires_review: false,
      updated_at: new Date()
    });
    await auditRecord(actor.uid, 'dispatch.escalate', `tm_dispatches/${id}`,
      { caller_uid: doc.caller_uid, caller_tier: callerTier, note }, signatureB64 || null);
    const projected = projectDispatch(id, { ...doc, escalation_chain: chain, escalation_status: 'escalated', requires_review: false });
    // Push notify the actor's parent_uid so the next tier sees the
    // escalation without polling. Fire-and-forget; the caller path is
    // not blocked on the OS push channel.
    import('./notify.js').then((m) => {
      if (typeof m.notifyDispatchEscalated === 'function') {
        return m.notifyDispatchEscalated(projected, actor.uid);
      }
    }).catch(() => { /* notify is best-effort */ });
    return projected;
  });
}

// Mark a dispatch as reviewed. No re-sign required; this is a low-risk
// triage action and the audit record carries the actor uid.
export async function markReviewed(actor, id, body) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  return _runTransaction(async (tx) => {
    const doc = await tx.get('tm_dispatches', id);
    if (!doc) throw new NotFoundError('dispatch_not_found', 'No such dispatch.');
    if (!inActorSubtree(actor.scope_path, doc.caller_scope_path)) {
      throw new ScopeError('out_of_scope', 'Dispatch is outside your subtree.');
    }
    const callerTier = Number(doc.caller_tier);
    if (Number.isFinite(callerTier) && callerTier >= actor.tier) {
      throw new ScopeError('caller_at_or_above_actor', 'Cannot review a dispatch from your peer or superior.');
    }
    const note = typeof body?.note === 'string' && body.note.length <= 500 ? body.note : null;
    const entry = {
      actor_uid: actor.uid,
      actor_tier: actor.tier,
      action: 'reviewed',
      ts: new Date().toISOString()
    };
    if (note) entry.note = note;
    const chain = appendChain(doc.escalation_chain, entry);
    const nextStatus = doc.escalation_status === 'escalated' || doc.escalation_status === 'auto_escalated'
      ? doc.escalation_status
      : 'reviewed';
    tx.update('tm_dispatches', id, {
      escalation_chain: chain,
      escalation_status: nextStatus,
      requires_review: false,
      reviewed_at: new Date(),
      reviewed_by_uid: actor.uid
    });
    await auditRecord(actor.uid, 'dispatch.review', `tm_dispatches/${id}`,
      { caller_uid: doc.caller_uid, note }, null);
    return projectDispatch(id, {
      ...doc,
      escalation_chain: chain,
      escalation_status: nextStatus,
      requires_review: false
    });
  });
}

// Side-by-side comparison surface. Loads each dispatch by id, enforces
// scope, and returns a slim payload with the persisted criticality
// breakdown plus a few fields a dispatcher needs to choose between
// pending dispatches at a glance. Sorted by criticality_score desc.
//
// Caller is responsible for tier gating (ddma+, tier >= 60). The route
// in router.js applies the gate; this function is callable in tests
// without one.
export async function compare(actor, ids) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  if (!Array.isArray(ids)) throw new ApiError('bad_request', 'ids must be an array.', 400);
  if (ids.length < 2 || ids.length > 10) {
    throw new ApiError('bad_request', 'compare accepts 2 to 10 dispatch ids.', 400);
  }
  const seen = new Set();
  const docs = [];
  for (const raw of ids) {
    const id = typeof raw === 'string' ? raw.trim() : '';
    if (!id || seen.has(id)) continue;
    seen.add(id);
    const doc = await _getDoc('tm_dispatches', id);
    if (!doc) throw new NotFoundError('dispatch_not_found', `No such dispatch ${id}.`);
    if (!inActorSubtree(actor.scope_path, doc.caller_scope_path)) {
      throw new ScopeError('out_of_scope', `Dispatch ${id} is outside your subtree.`);
    }
    docs.push({
      id,
      received_at: doc.received_at || null,
      caller_uid: doc.caller_uid || null,
      caller_name: doc.caller_name || null,
      caller_tier: doc.caller_tier ?? null,
      caller_scope_path: doc.caller_scope_path || null,
      urgency: doc?.triage?.urgency || null,
      incident_type: doc?.triage?.incident_type || null,
      summary_for_dispatch: doc?.triage?.summary_for_dispatch || null,
      criticality_score: Number(doc.criticality_score) || 0,
      criticality_breakdown: doc.criticality_breakdown || null,
      cluster_id: doc.cluster_id || null,
      cluster_role: doc.cluster_role || null,
      cluster_primary_id: doc.cluster_primary_id || null,
      requires_review: doc.requires_review === true,
      escalation_status: doc.escalation_status || null
    });
  }
  docs.sort((a, b) => b.criticality_score - a.criticality_score);
  return docs;
}
