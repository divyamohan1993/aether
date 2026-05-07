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

A second module ships in the same Cloud Run service: an NDMA chain-of-command coordinator. It is the team layer that turns a triage brief into accountable action across every legally empowered Indian disaster-response agency.

### Auth posture (MLP)

Login is email + password over TLS 1.3. The server runs scrypt (N=4096, r=8, p=1) — ~13 ms per verify, brute-force is CPU-bound. The plaintext password never reaches storage; only the salt+hash live in Firestore.

Sessions are compact HMAC-signed bearer tokens (`token_id.hmac`, ~88 chars). Critical actions (delegate, archive, dispatch escalate, dispatch assign) carry a fresh HMAC-SHA256 signature over a session-bound 32-byte action key. The action key rotates on every authenticated mutation; old keys remain valid for 30 s to absorb in-flight client races. Replay store rejects any (uid, action, target, ts) tuple seen in the last 5 minutes.

The bundle the survivor downloads is **20.6 KB brotli end-to-end** (was 36.8 KB on the original ML-DSA-65 design). Login on a Rs 2000 phone over 1-bar 2G completes in ~6 seconds. On 5G/wifi the same flow is ~1 second. Slow-2g (effectiveType `slow-2g`) automatically routes to text-only `/api/v1/sos/anon` heartbeats; audio is held until network grade improves.

Production hardening (post-MLP) re-introduces ML-DSA-65 server-side bearer signing, Secret Manager–mounted server keypair, and persistent VAPID. The migration is documented in `deploy/deploy.sh`.

### Chain-of-command tier ladder (DM Act 2005)

The model faithfully follows the cascade of authority in the Disaster Management Act 2005:

| Tier | Code | Authority |
|---|---|---|
| 100 | `ndma`         | National Disaster Management Authority. PM-chaired. Sees all. |
| 90  | `national_ops` | NDMA Secretariat, NDRF DG, MHA NDM Division. |
| 80  | `sdma`         | State Disaster Management Authority. CM-chaired. |
| 70  | `state_ops`    | State EOC, SDRF DG, state cabinet-level operations. |
| 60  | `ddma`         | District Disaster Management Authority. DC/DM-chaired. |
| 50  | `district_ops` | ADM (Disaster), district control room. |
| 40  | `subdivisional`| Sub-Divisional Magistrate. |
| 30  | `tehsil`       | Tehsildar, Block Development Officer. |
| 20  | `volunteer`    | Civil Defence, Aapda Mitra, NCC, NSS, IRCS. |
| 10  | `survivor`     | Anonymous distress source (read-only). |

A user can read, update, and delegate any record whose `scope_path` is a prefix of their own. Two-click delegation: pick user, pick new tier, server validates and writes atomically inside a Firestore transaction with an audit-chain entry.

### Inter-agency framework (`server/tm/taxonomy.js`)

`taxonomy.js` is the single source of truth for the response ecosystem:

- **77 agencies** across national, state, district, local, facility, and utility levels — NDMA, PMO, MHA NDM, NDRF, NIDM; IMD, CWC, GSI, INCOIS, ISRO; Army (Engineers, Infantry, Signals, Medical Corps), Navy (dive, ships), IAF (Mi-17/C-17), Coast Guard; CRPF, BSF, ITBP, SSB, CISF, Assam Rifles; SDMA / SEC / SDRF / state EOC + every line department; DDMA / district EOC / district police / district health / SDM / BDO / Tehsildar / Patwari; municipal corps, panchayats, ward offices; AIIMS / state hospital / district hospital / CHC / PHC / private hospital MoUs / blood banks / 108 / fire stations / police stations; telecom / power / water utilities and Indian Railways; IRCS, Civil Defence, NCC, NSS, Aapda Mitra, Bharat Scouts and Guides, Sphere India, registered relief NGOs.
- **45 unit types** with statutory references — ambulance, fire engine, police patrol, SDRF/NDRF battalion, mobile medical team, drone, helicopter, IAF rotary/fixed-wing, navy dive/ship, coast guard boat/heli, ITBP mountain, BSF water wing, CRPF QRT, CISF industrial cell, hospital surge slots (AIIMS / district / CHC / PHC), blood unit, fire aerial platform, fire rescue team (Cobra), DISCOM crew, water tanker, RO unit, COW (cell-on-wheels), satellite imagery, forecast cell, evacuation bus, relief train, relief truck, relief camp, IRCS / civil defence / NCC / NSS / Aapda Mitra / Scouts squads.
- **22 capability categories** (rescue water/air/high-altitude/collapse/fire/general, medical pre/field/facility/blood, security armed, comms, power, engineering, logistics, evacuation transport, shelter, forecasting, civil society).
- **143 mutual-aid edges** describing who can task whom — NDMA → NDRF / SDMA / MHA NDM / MoD; MoD → Army / Navy / IAF / Coast Guard; SDMA → SDRF / state line departments; DDMA → district police / district health / SDM / BDO / municipal / panchayat; etc. The directed edge `from → to` enforces "request support" affordances; reverse traffic is reporting-only.
- **10 incident playbooks** map `flood / landslide / earthquake / fire / building_collapse / cyclone / tsunami / industrial / cbrn / unknown` to recommended capability categories so the DSS suggests the right unit short-list.

Adding a new agency or unit type is additive: extend `taxonomy.js`, redeploy, the dispatcher renders it. No schema migration.

### Data store

Firestore Native, `(default)` database, free-tier friendly. Collections:

- `tm_users`        email-addressable, scrypt salt+hash, tier, scope_path, parent_uid
- `tm_projects`     name, description, scope_path, owner, status
- `tm_tasks`        project_id, title, assignee, status, priority, due_date, scope_path
- `tm_dispatches`   triage payload, location + altitude + pressure + motion + bluetooth peers, location_confidence + depth_estimate_m, criticality_score, escalation chain
- `tm_invitations`  TTL-cleaned signed invites (7 days)
- `tm_audit`        append-only SHA-256-chained mutation log (tamper-evident, verified by a supervising tier)
- `tm_sessions`     bearer claims (TTL on `exp`)
- `tm_clip_seen`    24-hour idempotency markers for queued audio clips
- `tm_units`        agency-tagged unit roster with type, capacity, location, status
- `tm_assignments`  unit ↔ dispatch links, ETA, worker status

### Endpoints

- `GET  /tm/`                              SPA shell — login + dashboard + tasks + dispatches + units + users
- `POST /api/v1/tm/auth/login`             email + password → bearer token + action key
- `POST /api/v1/tm/auth/register`          accept invite, create user with password
- `POST /api/v1/tm/auth/bootstrap`         env-gated NDMA root creation
- `GET  /api/v1/tm/me`
- `GET  /api/v1/tm/users`                  scope-filtered
- `POST /api/v1/tm/users/invite`           per-action HMAC sig required
- `POST /api/v1/tm/users/:uid/delegate`    per-action HMAC sig required
- `POST /api/v1/tm/users/:uid/suspend`
- `GET  /api/v1/tm/projects`, `POST`
- `GET|PATCH|DELETE /api/v1/tm/projects/:pid`     archive needs HMAC sig
- `GET|POST /api/v1/tm/tasks`
- `GET|PATCH|DELETE /api/v1/tm/tasks/:tid`        reassign needs HMAC sig
- `GET  /api/v1/tm/dispatches`             scope-filtered
- `POST /api/v1/tm/dispatches/:id/assign`  HMAC sig + DSS-suggested unit
- `POST /api/v1/tm/dispatches/:id/escalate` HMAC sig
- `GET  /api/v1/tm/units`, `POST`, `PATCH`, `DELETE`
- `GET  /api/v1/tm/dashboard`              counts by status, priority, overdue, top assignees
- `GET  /legal`                            DPDPA + IT Act + Disaster Management Act notice

### Survivor telemetry (`/api/v1/triage`)

Audio + structured headers feed the dispatcher's location confidence and depth estimate:

| header | source | role |
|---|---|---|
| `X-Client-Geo`, `X-Client-Geo-Accuracy`, `X-Client-Geo-Source` | browser geolocation | base lat/lng |
| `X-Client-Altitude`, `X-Client-Altitude-Accuracy` | geolocation API | depth ground-truth |
| `X-Client-Heading`, `X-Client-Speed` | geolocation API | moving caller |
| `X-Client-Pressure`, `X-Client-Pressure-Baseline` | Generic Sensor API barometer | depth from baseline |
| `X-Client-Motion-Peak`, `X-Client-Motion-Rms` | DeviceMotion accelerometer | impact / activity |
| `X-Client-Bt-Peers` | Web Bluetooth scan (opt-in) | rescuer-phone proximity |
| `X-Client-Battery`, `X-Client-Network` | Battery + Network Info APIs | survivability + bandwidth-shaping |
| `X-Client-Lang` | navigator.language | Gemini lang hint |

Server fuses these into `location_confidence` ∈ [0,1] (weighted by source quality) and `depth_estimate_m` from pressure delta (~12 Pa per metre standard atmosphere). Buried scenario validated in `test-stress.mjs`: 50 hPa delta → 416 m below baseline.

### Bootstrap

```bash
# Plain email + password is the operator credential now. No keypair to manage.
gcloud run services update aether --project=dmjone --region=us-central1 --update-env-vars=TM_BOOTSTRAP_ALLOW=1
curl -X POST -H "Content-Type: application/json" \
  -d '{"email":"ops@example.com","name":"Ops","password":"<strong-password>"}' \
  https://aether.dmj.one/api/v1/tm/auth/bootstrap
gcloud run services update aether --project=dmjone --region=us-central1 --update-env-vars=TM_BOOTSTRAP_ALLOW=0
```

Forgotten password → re-bootstrap with `TM_BOOTSTRAP_FORCE=1`.

### Test surface

```bash
node server/tm/_test/test-auth.mjs       # 56 assertions: bearer, HMAC, password
node server/tm/_test/test-vad.mjs        # 5  assertions: VAD, MFCC, adaptive bitrate
TM_EPHEMERAL_MODE=1 node server/tm/_test/test-stress.mjs  # 60+ adversarial assertions
```

`test-stress.mjs` exercises: 50× scrypt volume, 20 concurrent logins, 200 brute-force attempts (CPU-bound), 100× replay rejection, timing mask, header injection, oversize-payload, validator fuzz (Devanagari names, path-traversal scopes, RFC 1035 emails), 6000-session cache eviction, triangulation fusion edge cases, adaptive bitrate / verbosity, ts skew envelope, audit chain tamper detection, bearer format hardening, end-to-end loop, suspended account block.

### MLP / fresh-each-run mode

`TM_EPHEMERAL_MODE=1` routes every Firestore call (`getDoc`, `setDoc`, `createDoc`, `patchDoc`, `deleteDoc`, `fetchAndDelete`, `queryDocs`, `countQuery`, `runTransaction`) through an in-process Map. No network, no persistence, no idle quota burn. Production deploy leaves it unset and the real Firestore client takes over. Same exported surface, same semantics.

### Cost shape

- **Cloud Run** scale-to-zero with `min-instances=0` · $0 idle.
- **Vertex AI** pay-per-token · $0 idle.
- **Firestore Native** within free tier (1 GB stored, 50K reads/day, 20K writes/day) for an MVP · $0.
- **Secret Manager** unused in MLP posture · $0.
- **Artifact Registry** image well under the 0.5 GB free tier · $0.
- **Cloud Build** under the 120 build-minutes/day free tier · $0.

The whole system runs at $0 when no one is using it. That is the design.

### Indian-law alignment

- **DM Act 2005** ss. 6, 14, 25, 35 — tier ladder follows the legal cascade of authority.
- **DPDPA 2023** s. 7 — disaster response is a recognised legitimate-use ground; data minimised, retention published at `/legal`.
- **IT Act 2000** s. 79 — Aether operates as an intermediary; due diligence + grievance redressal at `/legal`.
- **Bharatiya Nyaya Sanhita 2023** ss. 217, 230 — false reporting penalties surfaced in the legal notice.
- **Section 91 CrPC** — police hand-off only on magistrate-compelled disclosure; otherwise survivor location is redacted.

## License

Apache 2.0 · Copyright 2026 Divya Mohan · dmj.one
