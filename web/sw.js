// Aether Service Worker v3.
//
// Owns the offline queue end-to-end. The previous v2 only nudged open
// tabs; if the tab was memory-killed or the user closed the PWA, the
// pending clip pile sat there until manual reopen. v3 reads the queue
// itself, ships the bytes, and writes status into IDB so a returning
// user sees real progress.
//
// Background sync: 'sync' tag 'flush-clips' triggered on enqueue + on
// 'online'. 'periodicsync' tag 'periodic-flush' triggered roughly every
// 12 h on installed Chromium PWAs. Push (RFC 8030 + RFC 8291) replaces
// the 15 s status polling; payload arrives encrypted, we decrypt via
// the OS push agent's normal handling, parse JSON, and either show a
// native notification or post a 'status_update' message to live tabs.
//
// IDB layout:
//   db 'a' v3:
//     q       audio queue rows {id, clip_id, status, blob, mime, capturedAt, attempt_count, ...}
//     tracked dispatch progress {id, lastStatus, summary, assignments, lastUpdatedAt}
//   db 'aether-tm' v2:
//     keyrings        {email, salt, iv, ct, pubkey_b64, ...}
//     tm_session      {iv, ct} encrypted bearer record at key 's'
//     tm_session_key  AES-GCM CryptoKey at key 'k'

const V = 'aether-v3';
const PRECACHE = [
  '/',
  '/sw.js',
  '/manifest.webmanifest',
  '/favicon.svg',
  '/icon-192.png',
  '/icon-512.png',
  '/tm/',
  '/tm/tm.css',
  '/tm/tm.js',
  '/tm/auth-client.js',
  // survivor-anon lane: /sos shell precache so a survivor who has visited
  // once can re-open even when the network is fully gone.
  '/sos-shell.html',
  '/sos'
];

const QDB = 'a';
// survivor-anon lane: db version bumped to 4 to add q_anon, survivor_geo,
// survivor_meta object stores. Existing q + tracked stores are kept.
const QDB_V = 4;
const SDB = 'aether-tm';
const SDB_V = 2;

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(V).then((c) => c.addAll(PRECACHE).catch(() => {})).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((ks) => Promise.all(ks.filter((k) => k !== V).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  const r = e.request;
  if (r.method !== 'GET') return;
  const u = new URL(r.url);
  if (u.pathname.startsWith('/api/')) return;
  e.respondWith(
    caches.match(r).then((c) => c || fetch(r).then((res) => {
      if (res.ok && u.origin === location.origin) {
        const cl = res.clone();
        caches.open(V).then((ca) => ca.put(r, cl));
      }
      return res;
    }).catch(() => caches.match('/')))
  );
});

// ---------------------------------------------------------------------------
// IDB helpers. Promise-wrapped wrappers around the existing DB layout.
// ---------------------------------------------------------------------------
function openQDb() {
  return new Promise((res, rej) => {
    const o = indexedDB.open(QDB, QDB_V);
    o.onupgradeneeded = (e) => {
      const d = e.target.result;
      if (!d.objectStoreNames.contains('q')) d.createObjectStore('q', { keyPath: 'id', autoIncrement: true });
      if (!d.objectStoreNames.contains('tracked')) d.createObjectStore('tracked', { keyPath: 'id' });
      // survivor-anon lane: anonymous heartbeat queue + last-known geo + meta.
      if (!d.objectStoreNames.contains('q_anon')) d.createObjectStore('q_anon', { keyPath: 'id', autoIncrement: true });
      if (!d.objectStoreNames.contains('survivor_geo')) d.createObjectStore('survivor_geo', { keyPath: 'ts' });
      if (!d.objectStoreNames.contains('survivor_meta')) d.createObjectStore('survivor_meta');
    };
    o.onsuccess = (e) => res(e.target.result);
    o.onerror = () => rej(o.error);
  });
}

function openSDb() {
  return new Promise((res, rej) => {
    const o = indexedDB.open(SDB, SDB_V);
    o.onupgradeneeded = (e) => {
      const d = e.target.result;
      if (!d.objectStoreNames.contains('keyrings')) d.createObjectStore('keyrings', { keyPath: 'email' });
      if (!d.objectStoreNames.contains('tm_session')) d.createObjectStore('tm_session');
      if (!d.objectStoreNames.contains('tm_session_key')) d.createObjectStore('tm_session_key');
    };
    o.onsuccess = (e) => res(e.target.result);
    o.onerror = () => rej(o.error);
  });
}

function txAll(db, store) {
  return new Promise((res, rej) => {
    const out = [];
    const tx = db.transaction(store, 'readonly').objectStore(store).openCursor();
    tx.onsuccess = (e) => {
      const c = e.target.result;
      if (c) { out.push(c.value); c.continue(); } else res(out);
    };
    tx.onerror = () => rej(tx.error);
  });
}

function txGet(db, store, key) {
  return new Promise((res, rej) => {
    const t = db.transaction(store, 'readonly').objectStore(store).get(key);
    t.onsuccess = () => res(t.result || null);
    t.onerror = () => rej(t.error);
  });
}

function txPut(db, store, value, key) {
  return new Promise((res, rej) => {
    const objStore = db.transaction(store, 'readwrite').objectStore(store);
    const t = key === undefined ? objStore.put(value) : objStore.put(value, key);
    t.onsuccess = () => res(t.result);
    t.onerror = () => rej(t.error);
  });
}

function txDelete(db, store, key) {
  return new Promise((res, rej) => {
    const t = db.transaction(store, 'readwrite').objectStore(store).delete(key);
    t.onsuccess = () => res();
    t.onerror = () => rej(t.error);
  });
}

// ---------------------------------------------------------------------------
// Bearer read. Returns null when no session is present or decryption
// fails; the page redirects to /login in either case.
// ---------------------------------------------------------------------------
async function readBearer() {
  try {
    const db = await openSDb();
    const k = await txGet(db, 'tm_session_key', 'k');
    const rec = await txGet(db, 'tm_session', 's');
    if (!k || !rec || !rec.iv || !rec.ct) return null;
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: rec.iv }, k, rec.ct);
    const obj = JSON.parse(new TextDecoder().decode(pt));
    return obj && obj.token ? obj : null;
  } catch {
    return null;
  }
}

async function clearBearer() {
  try {
    const db = await openSDb();
    await txDelete(db, 'tm_session', 's');
  } catch { /* idempotent */ }
}

// ---------------------------------------------------------------------------
// Backoff schedule (ms). 60 s, 5 min, 30 min. After the fifth attempt
// the row flips to 'failed_terminal' so it stops eating sync slots.
// ---------------------------------------------------------------------------
const BACKOFF_MS = [60_000, 5 * 60_000, 30 * 60_000, 30 * 60_000, 30 * 60_000];

function nextRetryAt(attempt) {
  const i = Math.min(Math.max(attempt - 1, 0), BACKOFF_MS.length - 1);
  return Date.now() + BACKOFF_MS[i];
}

async function postClients(msg) {
  const cs = await self.clients.matchAll({ includeUncontrolled: true, type: 'window' });
  for (const c of cs) {
    try { c.postMessage(msg); } catch { /* drop dead clients */ }
  }
}

// ---------------------------------------------------------------------------
// uploadOne: ship one queued clip. Returns one of
//   'sent' | 'auth_lost' | 'transient' | 'permanent'
// The caller writes the matching state back to IDB.
// ---------------------------------------------------------------------------
async function uploadOne(row, bearer) {
  const headers = {
    'Content-Type': row.mime || 'audio/webm',
    'Authorization': 'Bearer ' + bearer.token,
    'X-Client-Clip-Id': row.clip_id || String(row.id),
    'X-Client-Timestamp': row.ts || row.capturedAt || new Date().toISOString()
  };
  if (row.lang) headers['X-Client-Lang'] = row.lang;
  if (row.geo) {
    headers['X-Client-Geo'] = row.geo;
    if (row.geoAcc != null) headers['X-Client-Geo-Accuracy'] = String(Math.round(row.geoAcc));
    if (row.geoSrc) headers['X-Client-Geo-Source'] = row.geoSrc;
  }
  if (row.bat != null) headers['X-Client-Battery'] = String(row.bat);
  if (row.net) headers['X-Client-Network'] = row.net;
  let res;
  try {
    res = await fetch('/api/v1/triage', { method: 'POST', headers, body: row.blob });
  } catch {
    return { kind: 'transient' };
  }
  if (res.status === 401) return { kind: 'auth_lost' };
  if (res.status === 200) {
    let body = null;
    try { body = await res.json(); } catch { /* tolerate empty */ }
    return { kind: 'sent', body };
  }
  if (res.status >= 500 || res.status === 429 || res.status === 408) {
    return { kind: 'transient', status: res.status };
  }
  return { kind: 'permanent', status: res.status };
}

async function trackAddOrUpdate(db, body) {
  if (!body || !body.id) return;
  const cur = (await txGet(db, 'tracked', body.id)) || { id: body.id, capturedAt: body.received_at || new Date().toISOString() };
  cur.lastStatus = body.replay ? (cur.lastStatus || 'received') : 'received';
  cur.summary = (body.triage && body.triage.summary_for_dispatch) || cur.summary || 'Request received. Dispatcher reviewing.';
  cur.lastUpdatedAt = Date.now();
  cur.assignments = cur.assignments || [];
  await txPut(db, 'tracked', cur);
}

// ---------------------------------------------------------------------------
// flushQueue: walk the pending + failed rows and ship them. Honors
// the per-row scheduled_at so backoff actually backs off.
// ---------------------------------------------------------------------------
let _flushing = false;

async function flushQueue() {
  if (_flushing) return;
  _flushing = true;
  try {
    const bearer = await readBearer();
    if (!bearer || !bearer.token) {
      await postClients({ k: 'reauth_required' });
      return;
    }
    const qdb = await openQDb();
    const rows = (await txAll(qdb, 'q'))
      .filter((r) => r.status === 'pending' || r.status === 'failed')
      .filter((r) => !r.scheduled_at || r.scheduled_at <= Date.now())
      .sort((a, b) => (a.id || 0) - (b.id || 0));
    for (const r of rows) {
      r.status = 'sending';
      r.lastError = '';
      await txPut(qdb, 'q', r);
      await postClients({ k: 'queue_progress', clip_id: r.clip_id, status: 'sending' });
      const result = await uploadOne(r, bearer);
      if (result.kind === 'sent') {
        await txDelete(qdb, 'q', r.id);
        await trackAddOrUpdate(qdb, result.body);
        await postClients({ k: 'queue_progress', clip_id: r.clip_id, status: 'sent', dispatch_id: result.body && result.body.id });
        continue;
      }
      if (result.kind === 'auth_lost') {
        const reset = (await txGet(qdb, 'q', r.id)) || r;
        reset.status = 'pending';
        reset.lastError = 'auth';
        await txPut(qdb, 'q', reset);
        await clearBearer();
        await postClients({ k: 'reauth_required' });
        return;
      }
      // transient or permanent: bump attempt + schedule retry
      const cur = (await txGet(qdb, 'q', r.id)) || r;
      cur.attempt_count = (cur.attempt_count || 0) + 1;
      cur.lastError = result.kind === 'permanent' ? ('http_' + (result.status || '4xx')) : ('retry_' + (result.status || 'net'));
      if (result.kind === 'permanent' || cur.attempt_count >= 5) {
        cur.status = 'failed_terminal';
      } else {
        cur.status = 'failed';
        cur.scheduled_at = nextRetryAt(cur.attempt_count);
      }
      await txPut(qdb, 'q', cur);
      await postClients({ k: 'queue_progress', clip_id: cur.clip_id, status: cur.status, error: cur.lastError });
      if (result.kind === 'transient') break;
    }
  } catch {
    /* swallow; the next sync tick or online event re-tries */
  } finally {
    _flushing = false;
  }
}

// ---------------------------------------------------------------------------
// survivor-anon lane: drain queued anonymous heartbeats. The sos-shell
// posts beats to /api/v1/sos/anon directly when online; this handler
// catches the offline tail. Beats are not idempotent on the server (each
// is a state delta) so we only retry rows whose previous attempt was
// transient. Permanent rejections drop the row.
// ---------------------------------------------------------------------------
const ANON_BACKOFF_MS = [60_000, 5 * 60_000, 30 * 60_000, 30 * 60_000, 30 * 60_000];

function nextAnonRetryAt(attempt) {
  const i = Math.min(Math.max(attempt - 1, 0), ANON_BACKOFF_MS.length - 1);
  return Date.now() + ANON_BACKOFF_MS[i];
}

let _flushingAnon = false;

async function flushAnonQueue() {
  if (_flushingAnon) return;
  _flushingAnon = true;
  try {
    const qdb = await openQDb();
    const rows = (await txAll(qdb, 'q_anon'))
      .filter((r) => !r.scheduled_at || r.scheduled_at <= Date.now())
      .sort((a, b) => (a.id || 0) - (b.id || 0));
    for (const r of rows) {
      let res;
      try {
        res = await fetch('/api/v1/sos/anon', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(r.body || {}),
          keepalive: true
        });
      } catch {
        // Network error. Bump attempt + backoff.
        r.attempt_count = (r.attempt_count || 0) + 1;
        r.scheduled_at = nextAnonRetryAt(r.attempt_count);
        r.lastError = 'net';
        if (r.attempt_count >= 5) {
          await txDelete(qdb, 'q_anon', r.id);
        } else {
          await txPut(qdb, 'q_anon', r);
        }
        break;
      }
      if (res.status === 200) {
        await txDelete(qdb, 'q_anon', r.id);
        continue;
      }
      if (res.status >= 500 || res.status === 429 || res.status === 408) {
        r.attempt_count = (r.attempt_count || 0) + 1;
        r.scheduled_at = nextAnonRetryAt(r.attempt_count);
        r.lastError = 'http_' + res.status;
        if (r.attempt_count >= 5) await txDelete(qdb, 'q_anon', r.id);
        else await txPut(qdb, 'q_anon', r);
        break;
      }
      // Permanent (400, 413, 415). Drop the row; survivor will resend
      // on next interaction with up-to-date fingerprint and shape.
      await txDelete(qdb, 'q_anon', r.id);
    }
  } catch {
    /* swallow; next sync tick re-tries */
  } finally {
    _flushingAnon = false;
  }
}

self.addEventListener('sync', (e) => {
  if (e.tag === 'flush-clips') e.waitUntil(flushQueue());
  // survivor-anon lane: separate sync tag so an authenticated flush
  // does not block on a survivor heartbeat retry and vice versa.
  if (e.tag === 'flush-anon') e.waitUntil(flushAnonQueue());
});

self.addEventListener('periodicsync', (e) => {
  if (e.tag === 'periodic-flush') e.waitUntil(Promise.all([flushQueue(), flushAnonQueue()]));
});

self.addEventListener('online', () => {
  flushQueue();
  flushAnonQueue();
});

self.addEventListener('message', (e) => {
  const d = e.data || {};
  if (d.k === 'flush' || d.k === 'nudge') e.waitUntil(flushQueue());
  // survivor-anon lane: explicit nudge from the /sos shell.
  if (d.k === 'flush_anon') e.waitUntil(flushAnonQueue());
});

// ---------------------------------------------------------------------------
// Push handler. Payload contract: {kind, dispatch_id, urgency, scope, ttl_s}.
// Localised title strings cover en/hi/ta/bn for now; the i18n lane will
// extend the table without touching this code.
// ---------------------------------------------------------------------------
const PUSH_TITLES = {
  en: {
    'dispatch.created': 'New dispatch in your area',
    'dispatch.escalated': 'Dispatch escalated to you',
    'assignment.created': 'Help is on the way',
    'assignment.updated': 'Dispatch update',
    default: 'Aether update'
  },
  hi: {
    'dispatch.created': 'आपके क्षेत्र में नया मामला',
    'dispatch.escalated': 'मामला आपको सौंपा गया',
    'assignment.created': 'मदद रवाना',
    'assignment.updated': 'मामले की नई स्थिति',
    default: 'Aether सूचना'
  },
  ta: {
    'dispatch.created': 'உங்கள் பகுதியில் புதிய அழைப்பு',
    'dispatch.escalated': 'வழக்கு உங்களுக்கு உயர்த்தப்பட்டது',
    'assignment.created': 'உதவி வருகிறது',
    'assignment.updated': 'வழக்கு புதுப்பிப்பு',
    default: 'Aether செய்தி'
  },
  bn: {
    'dispatch.created': 'আপনার এলাকায় নতুন কেস',
    'dispatch.escalated': 'কেস আপনাকে পাঠানো হয়েছে',
    'assignment.created': 'সাহায্য আসছে',
    'assignment.updated': 'কেস আপডেট',
    default: 'Aether নোটিস'
  }
};

function localizedTitle(kind) {
  const lang = (self.navigator?.language || 'en').slice(0, 2);
  const table = PUSH_TITLES[lang] || PUSH_TITLES.en;
  return table[kind] || table.default;
}

self.addEventListener('push', (e) => {
  let payload = null;
  try {
    if (e.data) payload = e.data.json();
  } catch { /* malformed payload; show default */ }
  payload = payload || {};
  const kind = payload.kind || 'default';
  const dispatchId = payload.dispatch_id || null;
  const title = localizedTitle(kind);
  const body = payload.urgency
    ? `${payload.urgency} urgency`
    : 'Tap to open the dispatch board.';
  const tag = dispatchId ? `aether-${dispatchId}` : `aether-${kind}`;
  const data = { kind, dispatch_id: dispatchId, urgency: payload.urgency || null };

  // Translate the push into an in-page status_update for any open tab
  // so the UI updates immediately without a refresh.
  const liveUpdate = postClients({ k: 'status_update', kind, dispatch_id: dispatchId, urgency: payload.urgency || null, scope: payload.scope || null });

  e.waitUntil(Promise.all([
    liveUpdate,
    self.registration.showNotification(title, {
      body,
      tag,
      renotify: true,
      requireInteraction: kind === 'dispatch.escalated',
      icon: '/icon-192.png',
      badge: '/icon-192.png',
      data
    })
  ]));
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const dispatchId = e.notification?.data?.dispatch_id;
  const url = dispatchId ? '/tm/#/dispatches/' + encodeURIComponent(dispatchId) : '/tm/';
  e.waitUntil((async () => {
    const cs = await self.clients.matchAll({ includeUncontrolled: true, type: 'window' });
    for (const c of cs) {
      try {
        const u = new URL(c.url);
        if (u.origin === self.location.origin) {
          await c.focus();
          c.postMessage({ k: 'open_dispatch', dispatch_id: dispatchId });
          return;
        }
      } catch { /* unfocusable client */ }
    }
    await self.clients.openWindow(url);
  })());
});
