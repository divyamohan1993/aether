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

// Real Government of India disaster-response chain. Codes match the
// hierarchy mandated by the build spec. Old names (state, district,
// responder) are kept as aliases so callers that imported them continue
// to compile until they are migrated.
export const TIER = Object.freeze({
  ndma: 100,
  national_ops: 90,
  sdma: 80,
  state_ops: 70,
  ddma: 60,
  district_ops: 50,
  subdivisional: 40,
  tehsil: 30,
  volunteer: 20,
  survivor: 10,
  // Aliases for legacy import sites.
  state: 80,
  district: 60,
  responder: 40
});

const TIER_VALUES = new Set([10, 20, 30, 40, 50, 60, 70, 80, 90, 100]);

const TIER_NAMES = Object.freeze({
  100: 'ndma',
  90: 'national_ops',
  80: 'sdma',
  70: 'state_ops',
  60: 'ddma',
  50: 'district_ops',
  40: 'subdivisional',
  30: 'tehsil',
  20: 'volunteer',
  10: 'survivor'
});

export function tierName(t) { return TIER_NAMES[t] || 'unknown'; }

export function isValidTier(t) {
  return Number.isInteger(t) && TIER_VALUES.has(t);
}

// Three disjoint roots: `ndma` (operational), `demo` (public demo subtree),
// and `survivor` (anonymous tier-10 records). Up to 12 path segments to
// fit ndma/<state>/<district>/<sd>/<tehsil>/<village>/<sub-village>/ops/<unit>.
// Each segment must include at least one alphanumeric so that path-
// traversal markers like ".." or "." cannot pass through.
const SCOPE_RE = /^(ndma|demo|survivor)(\/(?=[^/]*[A-Za-z0-9])[A-Za-z0-9_.\-]+){0,12}$/;

export function isValidScope(s) {
  if (typeof s !== 'string' || s.length === 0 || s.length > 256) return false;
  if (!SCOPE_RE.test(s)) return false;
  // Belt-and-braces: reject `..`/`.` segments even if a future regex
  // change accidentally allows them.
  return !s.split('/').some((seg) => seg === '..' || seg === '.');
}

export function isInScope(actorScope, targetScope) {
  if (typeof actorScope !== 'string' || typeof targetScope !== 'string') return false;
  if (actorScope === targetScope) return true;
  return targetScope.startsWith(actorScope + '/');
}

// Email regex with stricter domain. Each domain label starts and ends
// with alphanumeric (RFC 1035), labels are separated by single dots, and
// the TLD is 2-24 letters. Rules out 'a@b..in' (consecutive dots), and
// 'a@-b.in' (label starts with '-').
const EMAIL_LOCAL = '[A-Za-z0-9._%+\\-]+';
const EMAIL_LABEL = '[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?';
const EMAIL_RE = new RegExp(`^${EMAIL_LOCAL}@${EMAIL_LABEL}(?:\\.${EMAIL_LABEL})*\\.[A-Za-z]{2,24}$`);
export function normalizeEmail(e) {
  if (typeof e !== 'string') return '';
  return e.trim().toLowerCase();
}
export function isValidEmail(e) {
  return typeof e === 'string' && e.length <= 254 && EMAIL_RE.test(e);
}

// Name regex covers Unicode letters, marks (combining), digits, and the
// usual punctuation found in proper names across Indic + Latin scripts.
// `\p{M}` is essential for Devanagari/Bengali/Tamil composition.
const NAME_RE = /^[\p{L}\p{M}\p{N} .,'\-]{1,80}$/u;
export function isValidName(n) {
  return typeof n === 'string' && NAME_RE.test(n);
}

// scrypt-derived password material lives in two base64url fields on the
// user doc. Both must round-trip cleanly; the auth module is the only
// component that ever reads them.
const _B64U_RE = /^[A-Za-z0-9_\-]+$/;
function _isValidB64u(s, minLen, maxLen) {
  if (typeof s !== 'string') return false;
  if (s.length < minLen || s.length > maxLen) return false;
  return _B64U_RE.test(s);
}
export function isValidPasswordSaltB64u(s) {
  return _isValidB64u(s, 16, 128);
}
export function isValidPasswordHashB64u(s) {
  return _isValidB64u(s, 32, 128);
}

export function canActOn(actor, target) {
  if (!actor || !target) return false;
  if (actor.uid && target.uid && actor.uid === target.uid) return true;
  return isInScope(actor.scope_path, target.scope_path);
}

export const ESCALATION_POLICIES = Object.freeze(['auto', 'manual_review', 'none']);
export const DEFAULT_ESCALATION_POLICY = 'manual_review';

export function isValidEscalationPolicy(p) {
  return typeof p === 'string' && ESCALATION_POLICIES.includes(p);
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
    status: u.status,
    escalation_policy: isValidEscalationPolicy(u.escalation_policy) ? u.escalation_policy : DEFAULT_ESCALATION_POLICY,
    created_at: u.created_at,
    last_login: u.last_login || null
  };
}

// Best-effort lookup. Returns the policy value or DEFAULT_ESCALATION_POLICY
// on any error so persistDispatch never blocks on this side-channel read.
export async function getEscalationPolicy(uid) {
  if (typeof uid !== 'string' || uid.length === 0) return DEFAULT_ESCALATION_POLICY;
  try {
    const doc = await getDoc('tm_users', uid);
    if (!doc) return DEFAULT_ESCALATION_POLICY;
    return isValidEscalationPolicy(doc.escalation_policy) ? doc.escalation_policy : DEFAULT_ESCALATION_POLICY;
  } catch {
    return DEFAULT_ESCALATION_POLICY;
  }
}

// Set escalation_policy on a target user. Actor must be strictly higher
// tier and contain the target's scope. NDMA can set anyone below them.
export async function setEscalationPolicy(actor, targetUid, policy) {
  if (!actor) throw new ApiError('unauthorized', 'No session.', 401);
  if (typeof targetUid !== 'string' || targetUid.length === 0) {
    throw new ApiError('bad_request', 'target uid required.', 400);
  }
  if (!isValidEscalationPolicy(policy)) {
    throw new ApiError('bad_policy', 'policy must be auto, manual_review, or none.', 400);
  }
  return runTransaction(async (tx) => {
    const target = await tx.get('tm_users', targetUid);
    if (!target) throw new NotFoundError('user_not_found', 'No such user.');
    if (!isInScope(actor.scope_path, target.scope_path)) {
      throw new ScopeError('out_of_scope', 'Target is outside your subtree.');
    }
    if (target.tier >= actor.tier) {
      throw new ScopeError('tier_at_or_above_actor', 'Cannot set policy for someone at or above your tier.');
    }
    const prev = isValidEscalationPolicy(target.escalation_policy) ? target.escalation_policy : DEFAULT_ESCALATION_POLICY;
    if (prev === policy) {
      return publicUser({ uid: targetUid, ...target, escalation_policy: policy });
    }
    tx.update('tm_users', targetUid, { escalation_policy: policy, updated_at: new Date() });
    await auditRecord(actor.uid, 'user.escalation_policy', `tm_users/${targetUid}`,
      { from: prev, to: policy }, null);
    return publicUser({ uid: targetUid, ...target, escalation_policy: policy });
  });
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

// Accept an invite with a server-hashed password.
// Body: { invite_id, name, password_salt_b64u, password_hash_b64u }.
// auth.handleRegister hashes the plaintext password before calling here.
export async function acceptInviteWithPassword(body) {
  const inviteId = String(body?.invite_id || body?.invite_token || '');
  const name = String(body?.name || '').trim();
  const saltB64u = String(body?.password_salt_b64u || '');
  const hashB64u = String(body?.password_hash_b64u || '');

  if (!inviteId) throw new ApiError('bad_request', 'invite_id required.', 400);
  if (!isValidName(name)) throw new ApiError('bad_name', 'Name is invalid.', 400);
  if (!isValidPasswordSaltB64u(saltB64u)) throw new ApiError('bad_password', 'Password salt invalid.', 400);
  if (!isValidPasswordHashB64u(hashB64u)) throw new ApiError('bad_password', 'Password hash invalid.', 400);

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
      password_salt_b64u: saltB64u,
      password_hash_b64u: hashB64u,
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

// Bootstrap the first NDMA root user with a password. Used by the CLI
// tool and the demo seed. Refuses if any user exists unless
// TM_BOOTSTRAP_FORCE=1. auth.handleBootstrap pre-hashes the password.
export async function bootstrapWithPassword(email, name, saltB64u, hashB64u) {
  email = normalizeEmail(email);
  if (!isValidEmail(email)) throw new ApiError('bad_email', 'Invalid email.', 400);
  if (!isValidName(name)) throw new ApiError('bad_name', 'Invalid name.', 400);
  if (!isValidPasswordSaltB64u(saltB64u)) throw new ApiError('bad_password', 'Password salt invalid.', 400);
  if (!isValidPasswordHashB64u(hashB64u)) throw new ApiError('bad_password', 'Password hash invalid.', 400);

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
      password_salt_b64u: saltB64u,
      password_hash_b64u: hashB64u,
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
      status: 'active',
      created_at: now.toISOString(),
      last_login: null
    });
  });
}

// Lookup user by email. Returns the public-shaped user view (no password
// material). Used by routes that present user identity to the client.
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

// Lookup user by email with the raw doc fields. ONLY auth.handleLogin
// should call this; it is the only path that needs the stored
// password_salt_b64u / password_hash_b64u columns.
export async function lookupByEmailRaw(email) {
  email = normalizeEmail(email);
  if (!isValidEmail(email)) return null;
  try {
    const idx = await getDoc('tm_user_emails', email);
    if (!idx || !idx.uid) return null;
    const u = await getDoc('tm_users', idx.uid);
    if (!u) return null;
    return { uid: idx.uid, ...u };
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

// Presence heartbeat. Every authenticated request bumps
// tm_user_presence/{uid}.last_seen_at. The Wave 2 watchdog reads this to
// detect C2 compromise. Writes are throttled per uid to one bump per
// PRESENCE_THROTTLE_MS so an active session does not exceed Firestore
// free-tier write quota under heavy polling.
const PRESENCE_THROTTLE_MS = 60_000;
const PRESENCE_CACHE_MAX = 10_000;
const _presenceLastBump = new Map();

export function _shouldBumpPresence(uid, nowMs) {
  if (typeof uid !== 'string' || uid.length === 0) return false;
  const t = typeof nowMs === 'number' ? nowMs : Date.now();
  const last = _presenceLastBump.get(uid);
  if (typeof last === 'number' && t - last < PRESENCE_THROTTLE_MS) return false;
  if (_presenceLastBump.size >= PRESENCE_CACHE_MAX) {
    const drop = Math.floor(PRESENCE_CACHE_MAX / 10);
    const it = _presenceLastBump.keys();
    for (let i = 0; i < drop; i++) {
      const { value, done } = it.next();
      if (done) break;
      _presenceLastBump.delete(value);
    }
  }
  _presenceLastBump.set(uid, t);
  return true;
}

export function _resetPresenceCacheForTest() {
  _presenceLastBump.clear();
}

export async function bumpPresence(uid) {
  if (typeof uid !== 'string' || uid.length === 0) return false;
  if (!_shouldBumpPresence(uid)) return false;
  try {
    await setDoc('tm_user_presence', uid, { uid, last_seen_at: new Date() });
    return true;
  } catch {
    return false;
  }
}
