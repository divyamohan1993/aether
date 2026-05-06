// Aether · Cloud Run entry. Stateless triage proxy in front of Vertex AI Gemini 2.5 Flash.

import { createServer } from 'node:http';
import { randomUUID, createHash } from 'node:crypto';
import { promises as fs, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync, brotliCompressSync, constants as zlibConst } from 'node:zlib';
import { GoogleAuth } from 'google-auth-library';

const __dirname = dirname(fileURLToPath(import.meta.url));

const PORT = parseInt(process.env.PORT || '8080', 10);
const PROJECT_ID = process.env.GCP_PROJECT || 'dmjone';
const REGION = process.env.VERTEX_REGION || 'us-central1';
const MODEL_ID = process.env.VERTEX_MODEL || 'gemini-2.5-flash';
const VERTEX_URL = `https://${REGION}-aiplatform.googleapis.com/v1/projects/${PROJECT_ID}/locations/${REGION}/publishers/google/models/${MODEL_ID}:generateContent`;

const WEB_DIR = process.env.WEB_DIR || join(__dirname, '..', 'web');
const MAX_BODY = 512 * 1024;
const MAX_HEADER_LEN = 256;
const ALLOWED_ORIGINS = new Set(['https://dmj.one', 'https://aether.dmj.one']);

const auth = new GoogleAuth({ scopes: 'https://www.googleapis.com/auth/cloud-platform' });

let _tmRouter = null;
async function loadTmRouter() {
  if (_tmRouter) return _tmRouter;
  _tmRouter = await import('./tm/router.js');
  return _tmRouter;
}

// Triage response schema enforced by Gemini structured output.
const TRIAGE_SCHEMA = {
  type: 'OBJECT',
  properties: {
    urgency: { type: 'STRING', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNCLEAR'] },
    language_detected: { type: 'STRING' },
    transcription_native: { type: 'STRING' },
    transcription_english: { type: 'STRING' },
    people_affected: { type: 'INTEGER' },
    injuries: { type: 'ARRAY', items: { type: 'STRING' } },
    needs: { type: 'ARRAY', items: { type: 'STRING' } },
    location_clues: { type: 'ARRAY', items: { type: 'STRING' } },
    ambient_audio: { type: 'ARRAY', items: { type: 'STRING' } },
    summary_for_dispatch: { type: 'STRING' },
    confidence: { type: 'NUMBER' },
    caller_state: { type: 'STRING', enum: ['calm', 'panicked', 'injured', 'unresponsive_likely'] },
    incident_type: { type: 'STRING', enum: ['flood', 'landslide', 'earthquake', 'fire', 'building_collapse', 'unknown'] },
    victims: {
      type: 'ARRAY',
      items: {
        type: 'OBJECT',
        properties: {
          age_band: { type: 'STRING', enum: ['infant', 'child', 'adult', 'elderly'] },
          condition_flags: {
            type: 'ARRAY',
            items: {
              type: 'STRING',
              enum: ['pregnant', 'crush_extracted', 'unresponsive', 'bleeding', 'breathing_difficulty', 'conscious_ambulatory']
            }
          },
          count: { type: 'INTEGER' }
        },
        required: ['age_band', 'condition_flags', 'count']
      }
    }
  },
  required: [
    'urgency', 'language_detected', 'transcription_native', 'transcription_english',
    'people_affected', 'injuries', 'needs', 'location_clues', 'ambient_audio',
    'summary_for_dispatch', 'confidence', 'caller_state', 'incident_type'
  ]
};

const SYSTEM_PROMPT = [
  'You are Aether, a multimodal disaster-response triage model serving the State Disaster Response Force (SDRF) in India.',
  '',
  'Task: listen to one short audio clip recorded by a survivor or first responder in a degraded environment (heavy static, wind, rain, panic, code-switched Hindi or regional dialect, possibly partial or unintelligible). Return one strict JSON object that matches the response schema exactly.',
  '',
  'Rules.',
  '1. Output JSON only. No prose, no markdown, no commentary outside JSON.',
  '2. The audio is the primary evidence. Do not invent names, casualty counts, locations, or facts not directly evident in the audio.',
  '3. transcription_native preserves the original language(s) and code-switching verbatim. transcription_english is a careful English translation of the same content.',
  '4. If the audio is mostly unintelligible, set urgency to "UNCLEAR", lower confidence, and use summary_for_dispatch to state what you could extract and what was lost.',
  '5. Be conservative with confidence (0..1). Lower it for short audio, masked speech, ambiguous accents, or contradictory cues.',
  '6. Use enum values exactly as listed in the schema. For incident_type, use "unknown" when not determinable; never null.',
  '7. needs[] uses these canonical tokens when applicable: medical_evacuation, food, water, shelter, search_and_rescue. Other short snake_case tokens are allowed only when clearly needed.',
  '8. The X-Client-Lang hint in the user message is a tie-breaker for ambiguous dialect, not a hard constraint. The audio always wins.',
  '9. ambient_audio[] should capture cues that change rescue tactics (rushing water, structural collapse, screams, traffic, sirens, machinery, gunfire, animals, vehicles).',
  '10. summary_for_dispatch is one or two sentences, English only, written for an SDRF officer to act on immediately.',
  '11. victims[] is OPTIONAL. Populate only when the audio gives clear cues about specific people in distress. Use age_band buckets: infant (under 1 year), child (1 to 12), adult (13 to 60), elderly (over 60). condition_flags use the listed tokens with these meanings: pregnant (visibly or stated pregnant), crush_extracted (just removed from rubble or pinned weight), unresponsive (no response to voice or shake), bleeding (active visible blood loss), breathing_difficulty (labored or gasping), conscious_ambulatory (awake and able to move). count is the number of victims sharing the same age_band and condition_flags; default to 1; combine identical victims into one row with higher count.'
].join('\n');

// In-memory token-bucket rate limiter. Resets per cold start, which is acceptable.
const buckets = new Map();
const MAX_BUCKETS = 10000;
const MIN_LIMIT = 10;
const DAY_LIMIT = 200;

function checkRate(ip) {
  const now = Date.now();
  let b = buckets.get(ip);
  if (!b) {
    if (buckets.size >= MAX_BUCKETS) {
      const drop = Math.floor(MAX_BUCKETS / 10);
      const it = buckets.keys();
      for (let i = 0; i < drop; i++) {
        const { value, done } = it.next();
        if (done) break;
        buckets.delete(value);
      }
    }
    b = { mTok: MIN_LIMIT, mAt: now, dTok: DAY_LIMIT, dAt: now };
    buckets.set(ip, b);
  }
  const mEl = (now - b.mAt) / 60000;
  b.mTok = Math.min(MIN_LIMIT, b.mTok + mEl * MIN_LIMIT);
  b.mAt = now;
  const dEl = (now - b.dAt) / 86400000;
  b.dTok = Math.min(DAY_LIMIT, b.dTok + dEl * DAY_LIMIT);
  b.dAt = now;
  if (b.mTok < 1) return { ok: false, retryAfter: Math.max(1, Math.ceil((1 - b.mTok) * 60 / MIN_LIMIT)), reason: 'minute' };
  if (b.dTok < 1) return { ok: false, retryAfter: 3600, reason: 'day' };
  b.mTok -= 1;
  b.dTok -= 1;
  return { ok: true };
}

function logJson(severity, fields) {
  const entry = { ts: new Date().toISOString(), severity, ...fields };
  process.stdout.write(JSON.stringify(entry) + '\n');
}

function clientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length > 0) return xff.split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}

// Drop control bytes (U+0000-U+001F and U+007F), cap to MAX_HEADER_LEN, trim.
function sanitizeHeader(v) {
  if (typeof v !== 'string' || v.length === 0) return null;
  const limit = Math.min(v.length, MAX_HEADER_LEN);
  let out = '';
  for (let i = 0; i < limit; i++) {
    const c = v.charCodeAt(i);
    if (c >= 32 && c !== 127) out += v[i];
  }
  out = out.trim();
  return out.length > 0 ? out : null;
}

const SECURITY_HEADERS = {
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; media-src 'self' blob:; worker-src 'self'; manifest-src 'self'; base-uri 'none'; frame-ancestors 'none'",
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'Permissions-Policy': 'geolocation=(self), microphone=(self), camera=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin'
};

function applySecurityHeaders(res) {
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, v);
}

function applyCors(req, res) {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Client-Id, X-Client-Lang, X-Client-Geo, X-Client-Battery, X-Client-Network, X-Client-Timestamp');
    res.setHeader('Access-Control-Max-Age', '86400');
  }
}

function sendJson(res, status, obj, extraHeaders = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    ...extraHeaders
  });
  res.end(body);
}

function sendError(res, status, code, message, extraHeaders = {}) {
  sendJson(res, status, { error: { code, message } }, extraHeaders);
}

// First-bytes audio sniff. Detects Ogg/Opus, WebM/Matroska, WAV/RIFF, MP4/ISO-BMFF.
function sniffAudio(buf) {
  if (!buf || buf.length < 12) return null;
  // OggS
  if (buf[0] === 0x4f && buf[1] === 0x67 && buf[2] === 0x67 && buf[3] === 0x53) return 'audio/ogg';
  // EBML (WebM/Matroska)
  if (buf[0] === 0x1a && buf[1] === 0x45 && buf[2] === 0xdf && buf[3] === 0xa3) return 'audio/webm';
  // RIFF....WAVE
  if (buf[0] === 0x52 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x46
      && buf[8] === 0x57 && buf[9] === 0x41 && buf[10] === 0x56 && buf[11] === 0x45) return 'audio/wav';
  // ISO-BMFF / MP4: bytes 4..7 == "ftyp"
  if (buf[4] === 0x66 && buf[5] === 0x74 && buf[6] === 0x79 && buf[7] === 0x70) return 'audio/mp4';
  return null;
}

async function readBody(req, cap) {
  const lengthHeader = req.headers['content-length'];
  if (lengthHeader) {
    const len = parseInt(lengthHeader, 10);
    if (Number.isFinite(len) && len > cap) {
      const err = new Error('payload_too_large');
      err.code = 'PAYLOAD_TOO_LARGE';
      throw err;
    }
  }
  let total = 0;
  const chunks = [];
  for await (const chunk of req) {
    total += chunk.length;
    if (total > cap) {
      const err = new Error('payload_too_large');
      err.code = 'PAYLOAD_TOO_LARGE';
      throw err;
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, total);
}

// File cache for static assets. Reads disk on cold miss; precompresses gzip/brotli once.
const fileCache = new Map();

async function loadStatic(absPath) {
  try {
    const stat = await fs.stat(absPath);
    const cached = fileCache.get(absPath);
    if (cached && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size) return cached;
    const buf = await fs.readFile(absPath);
    let gzBuf = null;
    let brBuf = null;
    try { gzBuf = await fs.readFile(absPath + '.gz'); } catch { /* none */ }
    try { brBuf = await fs.readFile(absPath + '.br'); } catch { /* none */ }
    if (!gzBuf) {
      try { gzBuf = gzipSync(buf, { level: 9 }); } catch { gzBuf = null; }
    }
    if (!brBuf) {
      try {
        brBuf = brotliCompressSync(buf, {
          params: {
            [zlibConst.BROTLI_PARAM_QUALITY]: 11,
            [zlibConst.BROTLI_PARAM_SIZE_HINT]: buf.length
          }
        });
      } catch { brBuf = null; }
    }
    const etag = '"' + createHash('sha1').update(buf).digest('base64').replace(/=+$/, '') + '"';
    const entry = { buf, gzBuf, brBuf, mtimeMs: stat.mtimeMs, size: stat.size, etag };
    fileCache.set(absPath, entry);
    return entry;
  } catch {
    return null;
  }
}

function pickEncoding(acceptEncoding, entry) {
  if (!acceptEncoding) return { enc: null, body: entry.buf };
  const ae = acceptEncoding.toLowerCase();
  if (entry.brBuf && ae.includes('br')) return { enc: 'br', body: entry.brBuf };
  if (entry.gzBuf && ae.includes('gzip')) return { enc: 'gzip', body: entry.gzBuf };
  return { enc: null, body: entry.buf };
}

const STATIC_ROUTES = {
  '/': { file: 'index.html', mime: 'text/html; charset=utf-8' },
  '/index.html': { file: 'index.html', mime: 'text/html; charset=utf-8' },
  '/sw.js': { file: 'sw.js', mime: 'text/javascript; charset=utf-8' },
  '/manifest.webmanifest': { file: 'manifest.webmanifest', mime: 'application/manifest+json; charset=utf-8' },
  '/favicon.svg': { file: 'favicon.svg', mime: 'image/svg+xml; charset=utf-8' },
  '/icon-192.png': { file: 'icon-192.png', mime: 'image/png' },
  '/icon-512.png': { file: 'icon-512.png', mime: 'image/png' },
  '/robots.txt': { file: 'robots.txt', mime: 'text/plain; charset=utf-8' },
  '/pitch': { file: 'pitch/index.html', mime: 'text/html; charset=utf-8' },
  '/pitch/': { file: 'pitch/index.html', mime: 'text/html; charset=utf-8' },
  '/pitch/index.html': { file: 'pitch/index.html', mime: 'text/html; charset=utf-8' },
  '/docs': { file: 'docs/index.html', mime: 'text/html; charset=utf-8' },
  '/docs/': { file: 'docs/index.html', mime: 'text/html; charset=utf-8' },
  '/docs/index.html': { file: 'docs/index.html', mime: 'text/html; charset=utf-8' },
  '/demo': { file: 'demo/index.html', mime: 'text/html; charset=utf-8' },
  '/demo/': { file: 'demo/index.html', mime: 'text/html; charset=utf-8' },
  '/demo/index.html': { file: 'demo/index.html', mime: 'text/html; charset=utf-8' },
  '/demo/credentials.json': { file: 'demo/credentials.json', mime: 'application/json; charset=utf-8' }
};

async function serveStatic(req, res, route, requestId) {
  const absPath = join(WEB_DIR, route.file);
  const entry = await loadStatic(absPath);
  if (!entry) {
    logJson('WARNING', { fn: 'serveStatic', requestId, msg: 'static_missing', path: absPath });
    sendError(res, 503, 'service_initializing', 'Static asset not built yet. Try again shortly.');
    return;
  }
  const inm = req.headers['if-none-match'];
  if (inm && inm === entry.etag) {
    res.writeHead(304, { ETag: entry.etag, 'Cache-Control': 'public, max-age=300, must-revalidate' });
    res.end();
    return;
  }
  const { enc, body } = pickEncoding(req.headers['accept-encoding'], entry);
  const headers = {
    'Content-Type': route.mime,
    'Content-Length': body.length,
    'Cache-Control': 'public, max-age=300, must-revalidate',
    'ETag': entry.etag,
    'Vary': 'Accept-Encoding'
  };
  if (enc) headers['Content-Encoding'] = enc;
  res.writeHead(200, headers);
  if (req.method === 'HEAD') res.end(); else res.end(body);
}

async function getAccessToken() {
  const t = await auth.getAccessToken();
  if (!t) throw new Error('access_token_missing');
  return t;
}

async function persistDispatch(d) {
  const fs = await import('./tm/firestore.js').catch(() => null);
  if (!fs || typeof fs.setDoc !== 'function') return;
  let policy = 'manual_review';
  try {
    const usersMod = await import('./tm/users.js');
    if (typeof usersMod.getEscalationPolicy === 'function' && d.caller?.uid) {
      policy = await usersMod.getEscalationPolicy(d.caller.uid);
    }
  } catch { /* fall through with default */ }
  const escalationStatus = policy === 'auto'
    ? 'auto_escalated'
    : policy === 'manual_review' ? 'pending_review' : 'none';
  const requiresReview = policy === 'manual_review';
  const escalationChain = policy === 'auto'
    ? [{ actor_uid: d.caller?.uid || null, actor_tier: d.caller?.tier ?? null, action: 'auto_escalated', ts: d.receivedAt }]
    : [];
  const workerStatus = 'received';
  const workerHistory = [{ status: workerStatus, ts: d.receivedAt }];
  const workerSummary = 'Request received. Dispatcher reviewing now.';
  // Criticality + dedup. Failures here log a warning and proceed with
  // sane defaults so a single broken pipeline cannot drop a dispatch.
  let criticality_score = 0;
  let criticality_breakdown = null;
  try {
    const critMod = await import('./tm/criticality.js');
    const r = critMod.criticalityScore(d.triage || {}, d.receivedAt, Date.now());
    criticality_score = r.score;
    criticality_breakdown = r.breakdown;
  } catch (e) {
    logJson('WARNING', { fn: 'persistDispatch', requestId: d.requestId, msg: 'criticality_failed', err: String(e) });
  }
  let geohash7 = null;
  let transcript_minhash_b64 = null;
  let cluster_id = null;
  let cluster_role = 'primary';
  let cluster_primary_id = null;
  let cluster_match_score = null;
  let cluster_match_reasons = null;
  try {
    const dedupeMod = await import('./tm/dedupe.js');
    if (d.location && Number.isFinite(d.location.lat) && Number.isFinite(d.location.lng)) {
      geohash7 = dedupeMod.geohash7(d.location.lat, d.location.lng);
    }
    const transcriptText = d.triage?.transcription_english || '';
    transcript_minhash_b64 = dedupeMod.transcriptMinHash(transcriptText, 64);
    if (geohash7) {
      const match = await dedupeMod.findCluster(
        { id: d.id, geohash7, location: d.location, triage: d.triage, transcript_minhash_b64 },
        { firestoreModule: fs, nowMs: Date.now() }
      );
      if (match) {
        cluster_id = match.cluster_id;
        cluster_role = 'duplicate';
        cluster_primary_id = match.cluster_primary_id;
        cluster_match_score = match.match_score;
        cluster_match_reasons = match.match_reasons;
      }
    }
  } catch (e) {
    logJson('WARNING', { fn: 'persistDispatch', requestId: d.requestId, msg: 'dedupe_failed', err: String(e) });
  }
  if (!cluster_id) cluster_id = d.id;
  const doc = {
    id: d.id,
    received_at: d.receivedAt,
    request_id: d.requestId,
    caller_uid: d.caller?.uid || null,
    caller_email: d.caller?.email || null,
    caller_name: d.caller?.name || null,
    caller_tier: d.caller?.tier ?? null,
    caller_scope_path: d.caller?.scope_path || null,
    location: d.location || null,
    triage: d.triage || null,
    audio_bytes: d.audioBytes,
    audio_mime: d.audioMime,
    network: d.network || null,
    battery: d.battery && Number.isFinite(Number(d.battery)) ? Number(d.battery) : null,
    client_timestamp: d.clientTs || null,
    lang_hint: d.langHint || null,
    latency_ms: d.latencyMs,
    ip: d.ip || null,
    escalation_status: escalationStatus,
    requires_review: requiresReview,
    escalation_chain: escalationChain,
    policy_at_capture: policy,
    assignments: [],
    worker_status: workerStatus,
    worker_status_history: workerHistory,
    worker_summary_text: workerSummary,
    criticality_score,
    criticality_breakdown,
    geohash7,
    transcript_minhash_b64,
    cluster_id,
    cluster_role,
    cluster_primary_id,
    cluster_match_score,
    cluster_match_reasons,
    created_at: new Date()
  };
  await fs.setDoc('tm_dispatches', d.id, doc);
}

async function callVertex({ audioBuf, audioMime, langHint, geoHint, caller, location, requestId }) {
  const token = await getAccessToken();
  const callerLine = caller
    ? `Caller is identified: name "${caller.name || 'unknown'}", email ${caller.email || 'unknown'}, tier ${caller.tier_name || caller.tier}, scope ${caller.scope_path || 'unknown'}.`
    : 'Caller identity: anonymous.';
  const locationLine = location
    ? `Caller GPS: ${location.lat.toFixed(6)}, ${location.lng.toFixed(6)} (accuracy ${location.accuracy_m ? Math.round(location.accuracy_m) + ' m' : 'unknown'}, source ${location.source}). Treat this as the canonical location. Do not ask the speaker to state where they are.`
    : 'Caller GPS: unavailable. Listen for landmarks or place names in the audio.';
  const userText = [
    callerLine,
    locationLine,
    `X-Client-Lang hint: ${langHint || 'none'}`,
    `X-Client-Geo hint: ${geoHint || 'none'}`,
    'Triage the attached audio per the schema. The speaker is a known responder calling about a situation; capture only the situation, casualties, needs, and ambient cues. Do not echo the caller name or coordinates back into the JSON.'
  ].join('\n');
  const reqBody = {
    systemInstruction: { parts: [{ text: SYSTEM_PROMPT }] },
    contents: [{
      role: 'user',
      parts: [
        { text: userText },
        { inlineData: { mimeType: audioMime, data: audioBuf.toString('base64') } }
      ]
    }],
    generationConfig: {
      responseMimeType: 'application/json',
      responseSchema: TRIAGE_SCHEMA,
      temperature: 0.1,
      maxOutputTokens: 1024,
      thinkingConfig: { thinkingBudget: 0 }
    },
    safetySettings: [
      { category: 'HARM_CATEGORY_HARASSMENT', threshold: 'BLOCK_NONE' },
      { category: 'HARM_CATEGORY_HATE_SPEECH', threshold: 'BLOCK_NONE' },
      { category: 'HARM_CATEGORY_SEXUALLY_EXPLICIT', threshold: 'BLOCK_NONE' },
      { category: 'HARM_CATEGORY_DANGEROUS_CONTENT', threshold: 'BLOCK_NONE' }
    ]
  };
  const startedAt = Date.now();
  const resp = await fetch(VERTEX_URL, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
      'x-goog-user-project': PROJECT_ID
    },
    body: JSON.stringify(reqBody)
  });
  const modelLatencyMs = Date.now() - startedAt;
  if (!resp.ok) {
    const errText = await resp.text().catch(() => '');
    logJson('ERROR', { fn: 'callVertex', requestId, msg: 'vertex_http_error', status: resp.status, body: errText.slice(0, 4096), modelLatencyMs });
    const err = new Error('vertex_error');
    err.code = 'VERTEX_ERROR';
    err.status = resp.status;
    throw err;
  }
  const data = await resp.json();
  const finishReason = data?.candidates?.[0]?.finishReason;
  const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!text || typeof text !== 'string') {
    logJson('ERROR', { fn: 'callVertex', requestId, msg: 'vertex_empty_text', finishReason, raw: JSON.stringify(data).slice(0, 4096), modelLatencyMs });
    const err = new Error('vertex_empty');
    err.code = 'VERTEX_EMPTY';
    throw err;
  }
  let triage;
  try {
    triage = JSON.parse(text);
  } catch {
    logJson('ERROR', { fn: 'callVertex', requestId, msg: 'vertex_invalid_json', text: text.slice(0, 4096), modelLatencyMs });
    const err = new Error('vertex_invalid_json');
    err.code = 'VERTEX_INVALID_JSON';
    throw err;
  }
  return { triage, modelLatencyMs };
}

async function handleTriage(req, res, ctx) {
  if (req.method !== 'POST') {
    sendError(res, 405, 'method_not_allowed', 'Use POST.', { 'Allow': 'POST, OPTIONS' });
    return;
  }
  const rate = checkRate(ctx.ip);
  if (!rate.ok) {
    logJson('WARNING', { fn: 'handleTriage', requestId: ctx.requestId, ip: ctx.ip, msg: 'rate_limited', reason: rate.reason });
    sendError(res, 429, 'rate_limited', 'Too many requests. Slow down.', { 'Retry-After': String(rate.retryAfter) });
    return;
  }
  // Authentication is required for triage so every dispatch is signed by a
  // known responder and the model can skip identity questions entirely.
  let caller = null;
  try {
    const authMod = await import('./tm/auth.js');
    const session = await authMod.authenticate({ headers: req.headers });
    const usersMod = await import('./tm/users.js');
    const u = await usersMod.getUser(session, session.uid).catch(() => null);
    caller = {
      uid: session.uid,
      tier: session.tier,
      tier_name: u?.tier_name || null,
      scope_path: session.scope_path,
      email: u?.email || null,
      name: u?.name || null
    };
  } catch (e) {
    logJson('WARNING', { fn: 'handleTriage', requestId: ctx.requestId, ip: ctx.ip, msg: 'auth_required', err: e?.message || String(e) });
    const status = e?.status === 401 ? 401 : 401;
    sendError(res, status, 'auth_required', 'Triage requires a Task Manager session. Sign in at /tm/.');
    return;
  }
  let body;
  try {
    body = await readBody(req, MAX_BODY);
  } catch (e) {
    if (e.code === 'PAYLOAD_TOO_LARGE') {
      sendError(res, 413, 'payload_too_large', 'Audio exceeds 512 KB limit.');
      return;
    }
    logJson('ERROR', { fn: 'handleTriage', requestId: ctx.requestId, ip: ctx.ip, msg: 'body_read_error', err: String(e) });
    sendError(res, 400, 'bad_request', 'Failed to read body.');
    return;
  }
  if (body.length === 0) {
    sendError(res, 400, 'empty_body', 'Audio body is empty.');
    return;
  }
  const sniffed = sniffAudio(body);
  if (!sniffed) {
    logJson('WARNING', { fn: 'handleTriage', requestId: ctx.requestId, ip: ctx.ip, msg: 'mime_reject', firstBytesHex: body.subarray(0, 16).toString('hex') });
    sendError(res, 415, 'unsupported_media_type', 'Body must be Opus/Ogg, WebM, MP4, or WAV audio.');
    return;
  }
  const langHint = sanitizeHeader(req.headers['x-client-lang']);
  const geoHint = sanitizeHeader(req.headers['x-client-geo']);
  const geoSource = sanitizeHeader(req.headers['x-client-geo-source']);
  const geoAccuracy = sanitizeHeader(req.headers['x-client-geo-accuracy']);
  const clientId = sanitizeHeader(req.headers['x-client-id']) || null;
  const battery = sanitizeHeader(req.headers['x-client-battery']);
  const network = sanitizeHeader(req.headers['x-client-network']);
  const clientTs = sanitizeHeader(req.headers['x-client-timestamp']);
  const id = randomUUID();
  const receivedAt = new Date().toISOString();
  let location = null;
  if (geoHint) {
    const m = /^(-?\d{1,3}(?:\.\d+)?),(-?\d{1,3}(?:\.\d+)?)$/.exec(geoHint);
    if (m) {
      const lat = Number(m[1]);
      const lng = Number(m[2]);
      if (Math.abs(lat) <= 90 && Math.abs(lng) <= 180) {
        location = {
          lat,
          lng,
          accuracy_m: geoAccuracy && Number.isFinite(Number(geoAccuracy)) ? Number(geoAccuracy) : null,
          source: (geoSource === 'gps' || geoSource === 'wifi' || geoSource === 'ip') ? geoSource : 'browser'
        };
      }
    }
  }
  try {
    const { triage, modelLatencyMs } = await callVertex({
      audioBuf: body,
      audioMime: sniffed,
      langHint,
      geoHint,
      caller,
      location,
      requestId: ctx.requestId
    });
    const latencyMs = Date.now() - ctx.startedAt;
    logJson('INFO', {
      fn: 'handleTriage',
      requestId: ctx.requestId,
      clientId,
      callerUid: caller?.uid,
      callerEmail: caller?.email,
      ip: ctx.ip,
      msg: 'triage_ok',
      audioBytes: body.length,
      audioMime: sniffed,
      langHint,
      battery,
      network,
      clientTs,
      hasLocation: !!location,
      urgency: triage?.urgency,
      confidence: triage?.confidence,
      modelLatencyMs,
      latencyMs
    });
    persistDispatch({
      id, receivedAt, caller, location, triage, latencyMs,
      audioBytes: body.length, audioMime: sniffed, network, battery,
      clientTs, langHint, ip: ctx.ip, requestId: ctx.requestId
    }).catch((err) => logJson('WARNING', {
      fn: 'persistDispatch', requestId: ctx.requestId, msg: 'dispatch_persist_failed', err: String(err)
    }));
    sendJson(res, 200, {
      id,
      received_at: receivedAt,
      model: MODEL_ID,
      latency_ms: latencyMs,
      caller,
      location,
      triage
    });
  } catch (e) {
    const latencyMs = Date.now() - ctx.startedAt;
    logJson('ERROR', {
      fn: 'handleTriage',
      requestId: ctx.requestId,
      clientId,
      ip: ctx.ip,
      msg: 'triage_failed',
      audioBytes: body.length,
      audioMime: sniffed,
      err: String(e),
      stack: e?.stack,
      latencyMs
    });
    sendError(res, 502, 'upstream_error', 'Triage model is temporarily unavailable. Retry shortly.');
  }
}

async function handleRequest(req, res) {
  const startedAt = Date.now();
  const requestId = randomUUID();
  const ip = clientIp(req);
  res.setHeader('X-Request-Id', requestId);
  applySecurityHeaders(res);
  applyCors(req, res);

  if (req.method === 'OPTIONS') {
    res.writeHead(204, { 'Content-Length': '0' });
    res.end();
    return;
  }

  let url;
  try {
    url = new URL(req.url, 'http://localhost');
  } catch {
    sendError(res, 400, 'bad_request', 'Malformed URL.');
    return;
  }
  const pathname = url.pathname;

  logJson('INFO', { fn: 'handleRequest', requestId, ip, msg: 'request_start', method: req.method, path: pathname, ua: sanitizeHeader(req.headers['user-agent']) });

  try {
    if (pathname === '/healthz' || pathname === '/api/healthz') {
      sendJson(res, 200, { ok: true });
      return;
    }
    if (pathname === '/api/v1/triage') {
      await handleTriage(req, res, { ip, requestId, startedAt });
      return;
    }
    if (pathname === '/tm' || pathname.startsWith('/tm/')
        || pathname === '/api/v1/tm' || pathname.startsWith('/api/v1/tm/')) {
      const tm = await loadTmRouter();
      const handled = await tm.route(req, res, url, { requestId, ip, startedAt });
      if (handled) return;
    }
    const route = STATIC_ROUTES[pathname];
    if (route && (req.method === 'GET' || req.method === 'HEAD')) {
      await serveStatic(req, res, route, requestId);
      return;
    }
    sendError(res, 404, 'not_found', 'No route matches.');
  } catch (e) {
    logJson('ERROR', { fn: 'handleRequest', requestId, ip, msg: 'unhandled', err: String(e), stack: e?.stack });
    if (!res.headersSent) sendError(res, 500, 'internal_error', 'Unexpected error.');
    else res.end();
  } finally {
    const latencyMs = Date.now() - startedAt;
    logJson('INFO', { fn: 'handleRequest', requestId, ip, msg: 'request_end', method: req.method, path: pathname, status: res.statusCode, latencyMs });
  }
}

const server = createServer(handleRequest);
server.requestTimeout = 30_000;
server.headersTimeout = 10_000;
server.keepAliveTimeout = 65_000;
server.maxHeadersCount = 64;

server.listen(PORT, '0.0.0.0', () => {
  logJson('INFO', {
    fn: 'main',
    msg: 'server_listening',
    port: PORT,
    project: PROJECT_ID,
    region: REGION,
    model: MODEL_ID,
    webDir: WEB_DIR,
    webDirExists: existsSync(WEB_DIR)
  });
});

function shutdown(signal) {
  logJson('INFO', { fn: 'shutdown', msg: 'signal_received', signal });
  server.close(() => {
    logJson('INFO', { fn: 'shutdown', msg: 'server_closed' });
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('unhandledRejection', (reason) => {
  logJson('ERROR', { fn: 'unhandledRejection', msg: 'unhandled_rejection', reason: String(reason) });
});
process.on('uncaughtException', (err) => {
  logJson('ERROR', { fn: 'uncaughtException', msg: 'uncaught_exception', err: String(err), stack: err?.stack });
});
