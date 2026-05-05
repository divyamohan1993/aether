# Aether

Edge AI for disaster response. A 40 KB SOS payload, zero Speech-to-Text, Gemini 2.5 Flash hearing the panic, the dialect, and the river behind the door, returning a strict-schema dispatch brief for the State Disaster Response Force in under two seconds.

Built end-to-end as a 24-hour assessment for **Ethara.AI · AI/LLM Operations** · Round 1.

Live: https://aether.dmj.one
Showcase: https://dmj.one/products/aether.html

## Why this exists

In the first 24 hours of a flood or landslide, optical fibre and cell towers collapse. Survivors fall back to crackly HAM radio, walkie-talkies, or panicked voice notes shoved through brief 2G windows. Standard Speech-to-Text shatters under static, wind, and a panicked mix of dialects. Aether bypasses the STT layer entirely and lets Gemini's native audio modality do the listening.

## Architecture

```
[ EXTREME-EDGE CLIENT ]   battery < 10%, 1-bar 2G
   |  Audio capture · pure-black OLED UI · hardware key bind
   |  Compression · Opus 12 kbps mono 16 kHz · ~40 KB / 15 s
   |  Store-and-Forward · IndexedDB queue + ServiceWorker
   v
[ INTERMITTENT 2G NETWORK ]  one 1.5 s burst is enough
   v
[ CLOUD RUN · stateless container ]   us-central1
   |  IP token bucket · 10 req/min, 200 req/day
   |  512 KB payload cap · MIME sniff · header sanitise
   |  ADC · service account `aether-vertex-sa`
   v
[ VERTEX AI · Gemini 2.5 Flash ]   us-central1
   |  No STT layer
   |  responseSchema enforced · no hallucinated keys
   |  thinkingBudget: 0 · sub-second model latency
   v
[ TRIAGE JSON ]   urgency, location clues, casualties, summary, confidence
   v
[ SDRF DISPATCH ]
```

## Live demo

1. Open https://aether.dmj.one on a phone.
2. Hold the SOS button. Speak. Release.
3. Receive a structured dispatch brief in under two seconds.

The browser never holds a Vertex AI key. The Cloud Run container authenticates via Application Default Credentials backed by a least-privilege service account. The service account has `roles/aiplatform.user`, `roles/logging.logWriter`, `roles/cloudtrace.agent` and nothing else.

## Repo layout

```
.
├─ server/             Node.js 22 · ESM · zero deps except google-auth-library
│  ├─ server.js        single-file HTTP server
│  ├─ package.json
│  ├─ Dockerfile       multi-stage, node:22-alpine, non-root, tini
│  └─ README.md
├─ web/                edge client PWA
│  ├─ index.html       12 KB raw · 4.5 KB brotli · OLED black, hold-to-record
│  ├─ index.html.gz    pre-compressed (gzip -9)
│  ├─ index.html.br    pre-compressed (brotli q=11)
│  ├─ sw.js            offline shell + IndexedDB queue
│  ├─ manifest.webmanifest
│  ├─ favicon.svg
│  ├─ icon-192.png
│  └─ icon-512.png
├─ deploy/
│  └─ deploy.sh        gcloud-driven Cloud Run deploy
├─ test/
│  └─ smoke.sh         end-to-end smoke test against a deployed URL
├─ Dockerfile          repo-root build context
└─ .dockerignore
```

## Endpoints

`GET /` · serves the PWA (gzip + brotli aware)
`GET /sw.js`, `/manifest.webmanifest`, `/favicon.svg`, `/icon-192.png`, `/icon-512.png`
`POST /api/v1/triage` · multipart of audio bytes · returns strict JSON
`OPTIONS /api/v1/triage` · CORS preflight

### POST /api/v1/triage

Accepts `audio/webm`, `audio/ogg`, `audio/mp4`, or `audio/wav` up to 512 KB. Optional headers:

- `X-Client-Id` · UUIDv4 persisted on the device
- `X-Client-Lang` · BCP-47 hint (`hi-IN`, `en-IN`, `ta-IN`, `bn-IN`)
- `X-Client-Geo` · `lat,lng` best effort
- `X-Client-Battery` · 0..100
- `X-Client-Network` · `2g|3g|4g|wifi`
- `X-Client-Timestamp` · ISO 8601

Response:

```json
{
  "id": "<uuid>",
  "received_at": "2026-05-05T11:13:55.603Z",
  "model": "gemini-2.5-flash",
  "latency_ms": 1777,
  "triage": {
    "urgency": "CRITICAL|HIGH|MEDIUM|LOW|UNCLEAR",
    "language_detected": "hi-IN",
    "transcription_native": "...",
    "transcription_english": "...",
    "people_affected": 3,
    "injuries": ["blunt trauma"],
    "needs": ["medical_evacuation","search_and_rescue"],
    "location_clues": ["near Devi temple"],
    "ambient_audio": ["rushing water","wind"],
    "summary_for_dispatch": "Three people trapped near Devi temple after landslide. Send rescue and medical.",
    "confidence": 0.82,
    "caller_state": "panicked",
    "incident_type": "landslide"
  }
}
```

## Deploy

```bash
PROJECT_ID=dmjone REGION=us-central1 ./deploy/deploy.sh
```

Defaults bake in:

- Cloud Run service `aether` in `us-central1`, `--allow-unauthenticated`
- Vertex AI Gemini 2.5 Flash in `us-central1`
- Service account `aether-vertex-sa` with three least-privilege roles
- Artifact Registry repo `aether-images`
- 512 Mi memory · 1 vCPU · scale-to-zero · max 10 instances · 40 concurrency

## Smoke test

```bash
bash test/smoke.sh https://your-cloud-run-url
```

The smoke test synthesises a 5 s WAV, posts it to `/api/v1/triage`, and prints the structured response. With a tone-only payload Gemini correctly returns `urgency: "UNCLEAR"` and `confidence: 0.1` rather than hallucinating an event. That is the point of the strict response schema.

## Misuse prevention

- Vertex AI key never reaches the browser. Server uses ADC → least-privilege service account.
- IP token bucket: 10 requests per minute, 200 per day, in-memory per Cloud Run instance.
- Body cap 512 KB, enforced on `Content-Length` and again on the body stream.
- MIME sniffer rejects anything that does not look like Opus/Ogg/WebM/MP4/WAV.
- Header sanitiser strips control characters and caps every `X-Client-*` value at 256 chars.
- All responses ship HSTS preload, strict CSP, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, locked Permissions-Policy.
- Strict `responseSchema` on the model prevents hallucinated keys.

## Tech stack

- Vertex AI · Gemini 2.5 Flash · `thinkingBudget: 0` for sub-second latency
- Cloud Run · single container · `gen2` · scale-to-zero
- Node.js 22 · ESM · zero deps except `google-auth-library`
- IAM service account with `roles/aiplatform.user`, `roles/logging.logWriter`, `roles/cloudtrace.agent`
- MediaRecorder + Opus codec, IndexedDB queue, ServiceWorker for offline
- WCAG 2.2 AAA · pure-black OLED UI · `prefers-reduced-motion`

## Languages

The PWA auto-detects from `navigator.language` and ships native-script strings for:

- `en-IN` · English (India)
- `hi-IN` · Hindi
- `ta-IN` · Tamil
- `bn-IN` · Bengali

## Task Manager (`/tm/`)

A second module ships in the same Cloud Run service: a hierarchical task tracker for the NDMA chain of command (NDMA → SDMA → DDMO → Responder → Volunteer). It is the team layer that turns a triage brief into accountable action.

### Post-quantum, unspoofable

Authentication is **ML-DSA-65** (NIST FIPS 204). No password ever crosses the wire. Each user generates a keypair on registration; the private key is encrypted with the user's passphrase via Argon2id and lives only in their browser's IndexedDB. Login is a challenge-response: the server issues 32 random bytes, the user signs them with their private key, the server verifies against the stored public key. Even the server operator cannot impersonate a user.

Sessions are short-lived bearer tokens signed by the **server's** ML-DSA-65 keypair (kept in Secret Manager, mounted by Cloud Run via least-privilege binding). Critical actions (role delegation, project archive, task reassignment) require a fresh per-action signature on top of the bearer.

### Hierarchy

| Tier | Code | Authority |
|---|---|---|
| `ndma`      | 100 | National. Sees all. Delegates to anyone. |
| `state`     |  80 | One state's subtree. |
| `district`  |  60 | One district's subtree. |
| `responder` |  40 | Field staff. Owns assigned tasks. |
| `volunteer` |  20 | Read-only on assigned tasks; status-only updates. |

A user can read, update, and delegate any user, project, or task whose `scope_path` is a prefix of their own. Two-click delegation: pick user, pick new tier, server validates and writes atomically into an audited Firestore transaction.

### Data store

Firestore Native, `(default)` database, free-tier friendly. Collections:

- `tm_users`       email-addressable, ML-DSA-65 public key, tier, scope_path, parent_uid
- `tm_projects`    name, description, scope_path, owner, status
- `tm_tasks`       project_id, title, assignee, status, priority, due_date, scope_path
- `tm_challenges`  TTL-cleaned login nonces (60 s)
- `tm_invitations` TTL-cleaned signed invites (7 days)
- `tm_audit`       append-only signed mutation log

### Endpoints

- `GET  /tm/`                              SPA shell · login + dashboard + projects + tasks + users
- `GET  /api/v1/tm/server-pubkey`          server's ML-DSA-65 public key, for offline session validation
- `POST /api/v1/tm/auth/challenge`         issue 32-byte challenge bound to email
- `POST /api/v1/tm/auth/verify`            consume challenge, return signed session token
- `POST /api/v1/tm/auth/register`          accept signed invite, create user
- `POST /api/v1/tm/auth/bootstrap`         one-time NDMA root creation, env-gated
- `GET  /api/v1/tm/me`
- `GET  /api/v1/tm/users`                  scope-filtered
- `POST /api/v1/tm/users/invite`           mint signed invite for an email
- `POST /api/v1/tm/users/:uid/delegate`    re-sign required
- `POST /api/v1/tm/users/:uid/suspend`
- `GET  /api/v1/tm/projects`               scope-filtered
- `POST /api/v1/tm/projects`
- `GET  /api/v1/tm/projects/:pid`
- `PATCH /api/v1/tm/projects/:pid`
- `DELETE /api/v1/tm/projects/:pid`        re-sign required
- `GET  /api/v1/tm/tasks`                  filter by project, assignee, status, overdue
- `POST /api/v1/tm/tasks`
- `PATCH /api/v1/tm/tasks/:tid`            volunteers status-only, responders own assigned, district+ edit any in scope
- `DELETE /api/v1/tm/tasks/:tid`
- `GET  /api/v1/tm/dashboard`              counts by status, priority, overdue, top assignees, projects active

### Bootstrap

```bash
# generate the operator's ML-DSA-65 keypair locally
node -e "import('@noble/post-quantum/ml-dsa.js').then(m=>{const k=m.ml_dsa65.keygen();require('fs').writeFileSync('pub.b64',Buffer.from(k.publicKey).toString('base64'));require('fs').writeFileSync('priv.b64',Buffer.from(k.secretKey).toString('base64'))})"
gcloud run services update aether --project=dmjone --region=us-central1 --update-env-vars=TM_BOOTSTRAP_ALLOW=1
curl -X POST -H "Content-Type: application/json" \
  -d "$(jq -n --arg email 'ops@example.com' --arg name 'Ops' --arg pub "$(cat pub.b64)" '{email:$email,name:$name,pubkey_b64:$pub}')" \
  https://aether.dmj.one/api/v1/tm/auth/bootstrap
gcloud run services update aether --project=dmjone --region=us-central1 --update-env-vars=TM_BOOTSTRAP_ALLOW=0
```

Keep `priv.b64` offline. Lose it and the account is unrecoverable by design.

### Cost shape

- **Cloud Run** scale-to-zero with `min-instances=0` · $0 idle.
- **Vertex AI** pay-per-token · $0 idle.
- **Firestore Native** within free tier (1 GB stored, 50K reads/day, 20K writes/day) for an MVP · $0.
- **Secret Manager** 2 secret versions, well within the 6-version free tier · $0.
- **Artifact Registry** image well under the 0.5 GB free tier · $0.
- **Cloud Build** under the 120 build-minutes/day free tier · $0.

The whole system runs at $0 when no one is using it. That is the design.

## License

Apache 2.0 · Copyright 2026 Divya Mohan · dmj.one
