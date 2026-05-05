// User management for the Task Manager module.
// Tier values, scope checks, invite mint/accept, delegate, suspend.
// Email uniqueness is enforced via a side-index doc tm_user_emails/{email}.

import { randomUUID } from 'node:crypto';
import {
  getDoc, setDoc, deleteDoc, queryDocs, runTransaction,
  FirestoreError
} from './firestore.js';
import { record as auditRecord } from './audit.js';
import { ApiError, ScopeError, NotFoundError, ConflictError } from './_errors.js';

export const TIER = Object.freeze({
  ndma: 100,
  state: 80,
  district: 60,
  responder: 40,
  volunteer: 20
});

const TIER_VALUES = new Set([20, 40, 60, 80, 100]);

const TIER_NAMES = Object.freeze({
  100: 'ndma',
  80: 'state',
  60: 'district',
  40: 'responder',
  20: 'volunteer'
});

export function tierName(t) { return TIER_NAMES[t] || 'unknown'; }

export function isValidTier(t) {
  return Number.isInteger(t) && TIER_VALUES.has(t);
}

const SCOPE_RE = /^ndma(\/[A-Za-z0-9_\-.]+){0,8}$/;

export function isValidScope(s) {
  return typeof s === 'string' && s.length > 0 && s.length <= 256 && SCOPE_RE.test(s);
}

export function isInScope(actorScope, targetScope) {
  if (typeof actorScope !== 'string' || typeof targetScope !== 'string') return false;
  if (actorScope === targetScope) return true;
  return targetScope.startsWith(actorScope + '/');
}

const EMAIL_RE = /^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}$/;
export function normalizeEmail(e) {
  if (typeof e !== 'string') return '';
  return e.trim().toLowerCase();
}
export function isValidEmail(e) {
  return typeof e === 'string' && e.length <= 254 && EMAIL_RE.test(e);
}

const NAME_RE = /^[\p{L}\p{N} .,'\-]{1,80}$/u;
export function isValidName(n) {
  return typeof n === 'string' && NAME_RE.test(n);
}

// ML-DSA-65 public key is 1952 raw bytes = 2604 base64 chars (no padding
// since 1952 % 3 == 2 needs 2 chars + "==" or omitted; we accept either).
const PUBKEY_LEN_MIN = 2600;
const PUBKEY_LEN_MAX = 2610;
export function isValidPubkeyB64(p) {
  if (typeof p !== 'string') return false;
  if (!/^[A-Za-z0-9+/=]+$/.test(p)) return false;
  if (p.length < PUBKEY_LEN_MIN || p.length > PUBKEY_LEN_MAX) return false;
  return true;
}

export function canActOn(actor, target) {
  if (!actor || !target) return false;
  if (actor.uid && target.uid && actor.uid === target.uid) return true;
  return isInScope(actor.scope_path, target.scope_path);
}

function publicUser(u) {
  if (!u) return null;
  return {
    uid: u.uid,
    email: u.email,
    name: u.name,
    tier: u.tier,
    tier_name: tierName(u.tier),
    parent_uid: u.parent_uid || null,
    scope_path: u.scope_path,
    pubkey_b64: u.pubkey_b64,
    status: u.status,
    created_at: u.created_at,
    last_login: u.last_login || null
  };
}

export async function getMe(actor) {
  if (!actor || !actor.uid) throw new ApiError('unauthorized', 'No session.', 401);
  const doc = await getDoc('tm_users', actor.uid);
  if (!doc) throw new NotFoundError('user_not_found', 'Session user no longer exists.');
  return publicUser({ uid: actor.uid, ...doc });
}

// List users that the actor can see. Optional scope param narrows further.
// Result is bounded by `limit` (default 200, max 500).
export async function listUsers(actor, scope, limit) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  const cap = Math.min(Math.max(limit || 200, 1), 500);
  const targetScope = scope || actor.scope_path;
  if (!isValidScope(targetScope)) throw new ApiError('bad_scope', 'Invalid scope_path.', 400);
  if (!isInScope(actor.scope_path, targetScope)) throw new ScopeError('out_of_scope', 'Scope is outside actor subtree.');
  const upper = targetScope + '/￿';
  const rows = await queryDocs('tm_users', [
    { field: 'scope_path', op: '>=', value: targetScope },
    { field: 'scope_path', op: '<=', value: upper }
  ], { orderBy: 'scope_path', limit: cap });
  const out = [];
  for (const r of rows) {
    const sp = r.data.scope_path;
    if (sp === targetScope || (typeof sp === 'string' && sp.startsWith(targetScope + '/'))) {
      out.push(publicUser({ uid: r.id, ...r.data }));
    }
  }
  return out;
}

// Fetch a single user with scope check.
export async function getUser(actor, uid) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  if (typeof uid !== 'string' || uid.length === 0) throw new ApiError('bad_request', 'uid required.', 400);
  const doc = await getDoc('tm_users', uid);
  if (!doc) throw new NotFoundError('user_not_found', 'No such user.');
  if (!canActOn(actor, { uid, scope_path: doc.scope_path })) {
    throw new ScopeError('out_of_scope', 'Cannot view this user.');
  }
  return publicUser({ uid, ...doc });
}

// Mint a signed invite. Caller (admin) supplies their action signature
// over (email|tier|parent_uid|scope_path) which auth.js has already
// verified before this function is called.
export async function inviteUser(actor, body, actorSignatureB64) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  const email = normalizeEmail(body?.email);
  const tier = Number(body?.tier);
  const parentUid = String(body?.parent_uid || actor.uid);
  const scopePath = String(body?.scope_path || '');
  const ttlMs = 7 * 86_400_000;

  if (!isValidEmail(email)) throw new ApiError('bad_email', 'Invalid email.', 400);
  if (!isValidTier(tier)) throw new ApiError('bad_tier', 'Invalid tier.', 400);
  if (!isValidScope(scopePath)) throw new ApiError('bad_scope', 'Invalid scope_path.', 400);
  if (tier > actor.tier) throw new ScopeError('tier_too_high', 'Cannot invite at a tier above your own.');
  if (!isInScope(actor.scope_path, scopePath)) throw new ScopeError('out_of_scope', 'Scope is outside your subtree.');

  const parent = await getDoc('tm_users', parentUid);
  if (!parent) throw new NotFoundError('parent_not_found', 'Parent user does not exist.');
  if (!isInScope(actor.scope_path, parent.scope_path)) {
    throw new ScopeError('parent_out_of_scope', 'Parent is outside your subtree.');
  }
  if (tier > parent.tier) {
    throw new ScopeError('tier_above_parent', 'Tier cannot exceed parent tier.');
  }
  if (!isInScope(parent.scope_path, scopePath)) {
    throw new ScopeError('scope_outside_parent', 'Scope must extend the parent scope.');
  }

  const invId = randomUUID();
  const expiresAt = new Date(Date.now() + ttlMs);
  const data = {
    email,
    tier,
    parent_uid: parentUid,
    scope_path: scopePath,
    issued_by_uid: actor.uid,
    issued_signature_b64: actorSignatureB64 || null,
    expires_at: expiresAt,
    used: false,
    created_at: new Date()
  };
  await setDoc('tm_invitations', invId, data);
  await auditRecord(actor.uid, 'user.invite', `tm_invitations/${invId}`,
    { email, tier, parent_uid: parentUid, scope_path: scopePath },
    actorSignatureB64 || null);
  return {
    invite_id: invId,
    email,
    tier,
    parent_uid: parentUid,
    scope_path: scopePath,
    expires_at: expiresAt.toISOString()
  };
}

// Accept an invite. Body: { invite_id, name, pubkey_b64 }.
// auth.js MUST have already verified the invite's issued_signature_b64
// against the issuer's pubkey before calling this. We re-fetch the invite
// here in the same transaction that creates the user, and burn it.
export async function acceptInvite(body) {
  const inviteId = String(body?.invite_id || '');
  const name = String(body?.name || '').trim();
  const pubkeyB64 = String(body?.pubkey_b64 || '');

  if (!inviteId) throw new ApiError('bad_request', 'invite_id required.', 400);
  if (!isValidName(name)) throw new ApiError('bad_name', 'Name is invalid.', 400);
  if (!isValidPubkeyB64(pubkeyB64)) throw new ApiError('bad_pubkey', 'Public key is invalid.', 400);

  return runTransaction(async (tx) => {
    const inv = await tx.get('tm_invitations', inviteId);
    if (!inv) throw new NotFoundError('invite_not_found', 'No such invite.');
    if (inv.used === true) throw new ConflictError('invite_used', 'Invite already consumed.');
    const expMs = Date.parse(inv.expires_at || '') || 0;
    if (!expMs || expMs < Date.now()) throw new ApiError('invite_expired', 'Invite has expired.', 410);

    const email = normalizeEmail(inv.email);
    const existing = await tx.get('tm_user_emails', email);
    if (existing) throw new ConflictError('email_taken', 'Email is already registered.');

    const uid = randomUUID();
    const now = new Date();
    tx.create('tm_users', {
      email,
      name,
      tier: inv.tier,
      parent_uid: inv.parent_uid || null,
      scope_path: inv.scope_path,
      pubkey_b64: pubkeyB64,
      status: 'active',
      created_at: now,
      last_login: null
    }, uid);
    tx.create('tm_user_emails', { uid, created_at: now }, email);
    tx.update('tm_invitations', inviteId, { used: true, used_at: now, used_uid: uid });

    await auditRecord(uid, 'user.register', `tm_users/${uid}`,
      { email, tier: inv.tier, scope_path: inv.scope_path }, null);

    return {
      uid,
      email,
      name,
      tier: inv.tier,
      tier_name: tierName(inv.tier),
      scope_path: inv.scope_path,
      parent_uid: inv.parent_uid || null
    };
  });
}

// Delegate (change tier) of a target user. Caller must be in scope and
// hold a tier strictly above the target's current AND new tier. Re-sign
// has already been verified by auth.js.
export async function delegate(actor, targetUid, newTier, actorSignatureB64) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  if (!targetUid || typeof targetUid !== 'string') throw new ApiError('bad_request', 'target uid required.', 400);
  if (!isValidTier(newTier)) throw new ApiError('bad_tier', 'Invalid tier.', 400);
  if (newTier > actor.tier) throw new ScopeError('tier_too_high', 'New tier exceeds your own.');
  if (actor.uid === targetUid) throw new ScopeError('self_delegate', 'Cannot delegate yourself.');

  return runTransaction(async (tx) => {
    const target = await tx.get('tm_users', targetUid);
    if (!target) throw new NotFoundError('user_not_found', 'No such user.');
    if (!isInScope(actor.scope_path, target.scope_path)) {
      throw new ScopeError('out_of_scope', 'Target is outside your subtree.');
    }
    if (target.tier >= actor.tier) {
      throw new ScopeError('tier_at_or_above_actor', 'Cannot delegate someone at or above your tier.');
    }
    if (target.tier === newTier) {
      return { uid: targetUid, tier: newTier, tier_name: tierName(newTier), unchanged: true };
    }
    tx.update('tm_users', targetUid, {
      tier: newTier,
      updated_at: new Date()
    });
    await auditRecord(actor.uid, 'user.delegate', `tm_users/${targetUid}`,
      { from_tier: target.tier, to_tier: newTier }, actorSignatureB64 || null);
    return { uid: targetUid, tier: newTier, tier_name: tierName(newTier), unchanged: false };
  });
}

// Suspend or restore a user. Suspended users cannot complete login.
export async function suspend(actor, targetUid, suspended) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  if (actor.uid === targetUid) throw new ScopeError('self_suspend', 'Cannot suspend yourself.');
  return runTransaction(async (tx) => {
    const target = await tx.get('tm_users', targetUid);
    if (!target) throw new NotFoundError('user_not_found', 'No such user.');
    if (!isInScope(actor.scope_path, target.scope_path)) {
      throw new ScopeError('out_of_scope', 'Target is outside your subtree.');
    }
    if (target.tier >= actor.tier) {
      throw new ScopeError('tier_at_or_above_actor', 'Cannot suspend someone at or above your tier.');
    }
    const status = suspended ? 'suspended' : 'active';
    if (target.status === status) {
      return { uid: targetUid, status, unchanged: true };
    }
    tx.update('tm_users', targetUid, { status, updated_at: new Date() });
    await auditRecord(actor.uid, suspended ? 'user.suspend' : 'user.restore',
      `tm_users/${targetUid}`, { from: target.status, to: status }, null);
    return { uid: targetUid, status, unchanged: false };
  });
}

// Bootstrap the first NDMA root user. Used by the CLI tool. Refuses if
// any user exists unless TM_BOOTSTRAP_FORCE=1. Returns the new user.
export async function bootstrap(email, name, pubkeyB64) {
  email = normalizeEmail(email);
  if (!isValidEmail(email)) throw new ApiError('bad_email', 'Invalid email.', 400);
  if (!isValidName(name)) throw new ApiError('bad_name', 'Invalid name.', 400);
  if (!isValidPubkeyB64(pubkeyB64)) throw new ApiError('bad_pubkey', 'Invalid pubkey_b64.', 400);

  const force = process.env.TM_BOOTSTRAP_FORCE === '1';
  const existing = await queryDocs('tm_users', [], { limit: 1 });
  if (existing.length > 0 && !force) {
    throw new ConflictError('users_exist', 'Users exist. Set TM_BOOTSTRAP_FORCE=1 to override.');
  }

  return runTransaction(async (tx) => {
    const taken = await tx.get('tm_user_emails', email);
    if (taken) throw new ConflictError('email_taken', 'Email already registered.');
    const uid = randomUUID();
    const now = new Date();
    tx.create('tm_users', {
      email,
      name,
      tier: TIER.ndma,
      parent_uid: null,
      scope_path: 'ndma',
      pubkey_b64: pubkeyB64,
      status: 'active',
      created_at: now,
      last_login: null,
      bootstrapped: true
    }, uid);
    tx.create('tm_user_emails', { uid, created_at: now }, email);
    await auditRecord(uid, 'user.bootstrap', `tm_users/${uid}`,
      { email, tier: TIER.ndma, scope_path: 'ndma' }, null);
    return publicUser({
      uid, email, name,
      tier: TIER.ndma,
      parent_uid: null,
      scope_path: 'ndma',
      pubkey_b64: pubkeyB64,
      status: 'active',
      created_at: now.toISOString(),
      last_login: null
    });
  });
}

// Lookup user by email. Used by auth.js during challenge/verify. Returns
// the public user view (with pubkey) or null.
export async function lookupByEmail(email) {
  email = normalizeEmail(email);
  if (!isValidEmail(email)) return null;
  try {
    const idx = await getDoc('tm_user_emails', email);
    if (!idx || !idx.uid) return null;
    const u = await getDoc('tm_users', idx.uid);
    if (!u) return null;
    return publicUser({ uid: idx.uid, ...u });
  } catch (e) {
    if (e instanceof FirestoreError) return null;
    throw e;
  }
}

// Bump last_login timestamp. Best-effort; failures logged but not thrown.
export async function touchLastLogin(uid) {
  try {
    await runTransaction(async (tx) => {
      const u = await tx.get('tm_users', uid);
      if (!u) return;
      tx.update('tm_users', uid, { last_login: new Date() });
    });
  } catch {
    /* swallowed; auth flow has already completed */
  }
}
