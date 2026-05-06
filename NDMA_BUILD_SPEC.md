# Aether → NDMA Disaster Response DSS — Build Spec

Single source of truth for the build phase. Every agent reads this first.

## North star

A first-72-hour disaster response platform for India that:

1. Survives 1-bar 2G at 2.5 kbps, dying battery, no GPS in rubble.
2. Lets a trapped survivor with one moving finger or only a voice get help, with no prior account.
3. Runs the real NDMA command chain end-to-end with auto-DSS fallback when C2 is compromised.
4. Stays $0 idle. WCAG AAA. No banned words. No emojis. Pure black background.
5. Multilingual to the 22 Indian languages where reach is realistic, with Hindi + English + survivor's local language as floor.

Trade-offs the user has authorized:

- Reduce per-action signature strength when bandwidth is the limiting factor. ML-DSA stays at login and at the audit boundary; HMAC over server-issued nonce replaces ML-DSA on per-action calls.
- Survivor mode is anonymous. No login. No registration. Heavy rate-limit + fingerprint + post-event audit instead.

## Bandwidth budget

| Persona | Network floor | Per-action overhead target | Audio target |
|---|---|---|---|
| Survivor anon | 1-bar 2G, 2.5 kbps | ≤ 100 B | optional (panic-code primary) |
| Survivor with voice | 2G, 10 kbps | ≤ 500 B | Opus 4 kbps, 10 s max |
| Field responder | 2G/3G | ≤ 500 B | Opus 6-12 kbps adaptive |
| Field VAD-mode | 3G+ | ≤ 1 KB per phrase | Opus 12 kbps |
| Dispatcher / NDMA | reliable | n/a | n/a |

Today's per-action overhead (broken): ~7 KB. Target: ~50-500 B. **140× compression** by replacing ML-DSA per-action with HMAC.

## Real NDMA command chain (replaces toy 5-tier)

| Code | Tier | Authority | Scope |
|---|---|---|---|
| 100 | `ndma` | NDMA. PMO chair. MHA-DM Division. NDRF HQ. | `ndma` |
| 90 | `national_ops` | NDRF battalions. Army DGMO / IAF / Navy liaison. Cabinet Sec. | `ndma/ops/<unit>` |
| 80 | `sdma` | SDMA. CM chair. Chief Sec. Relief Commissioner. | `ndma/<state>` |
| 70 | `state_ops` | SDRF. State Health DGP. Police DGP. Forest. | `ndma/<state>/ops/<unit>` |
| 60 | `ddma` | DDMA. DM/DC. SP. CMHO. | `ndma/<state>/<district>` |
| 50 | `district_ops` | DSP. Civil Surgeon. | `ndma/<state>/<district>/ops/<unit>` |
| 40 | `subdivisional` | SDM. BDO. ACMO. | `ndma/<state>/<district>/<sd>` |
| 30 | `tehsil` | Tehsildar. SHO. ASHA supervisor. | `ndma/<state>/<district>/<sd>/<tehsil>` |
| 20 | `volunteer` | ASHA. ANM. Anganwadi. NCC. NSS. Civil Defence. Home Guards. Panchayat. | `ndma/<state>/<district>/<sd>/<tehsil>/<village>` |
| 10 | `survivor` | Anonymous. Rate-limited. Cannot mutate anything besides own SOS thread. | `survivor/<fp>` |

Operational forces (NDRF, SDRF, Army, IAF, Navy, Coast Guard, Fire, Police, Civil Defence, Health, Forest, NGO partners) remain `tm_units` rows with proper `type` and `parent_org` enums.

`SCOPE_RE` extends to allow up to 12 path segments (was 8) plus the `survivor/` root.

## Survivor mode (rubble protocol)

The survivor is the design center. Everything else serves them.

Reality a trapped survivor faces:

- No GPS lock. Sky view blocked. Last cached fix is the only fix.
- 1-bar 2G if the cell tower stayed up. Often dropping.
- Dying battery. Each unnecessary CPU cycle costs life.
- One moving finger or only voice. Maybe not even that for stretches.
- Cannot register. Cannot type a passphrase. Cannot wait 8 seconds for Argon2id.

### Survivor surfaces

- `/sos` — ultra-light shell. ≤ 3 KB brotli total. Single screen. Big red button. Panic-code icons.
- No login. No registration. No keypair generation.
- Phone fingerprint = SHA-256(UA + screen W×H + tz + lang + canvas FP) → `survivor-<fp10>` valid 7 days, auto-renewed on each request.

### Inputs (survivor can use any)

- Tap big SOS button.
- Triple-tap anywhere on the screen.
- Volume button combo (where browser allows in PWA standalone).
- Shake gesture (`devicemotion` accelerometer threshold 1.5 g, 3 shakes in 2 s).
- Voice activity (after first ack, app stays in trapped-mode listening).

### Panic codes

12 fixed codes survivor can tap as supplements / sole input when audio is too costly:

```
01 trapped_alive          07 need_medical
02 injured_conscious      08 hear_rescuers
03 multiple_people        09 building_stable
04 cannot_move            10 building_failing
05 breathing_difficulty   11 water_rising
06 no_food_water          12 fire_nearby
```

Each tap → 1 byte code in the heartbeat.

### Heartbeat protocol

After first SOS, app enters trapped mode and emits a heartbeat every 60 s:

```
{
  fp: "survivor-fp10",
  seq: 42,
  ts: 1714900000,
  codes: [1, 8],            // panic codes since last beat
  geo: [12.345, 75.678, 22], // last-known lat, lng, accuracy_m (or null)
  bat: 12,                   // percent
  sig: "2g",                 // effectiveType
  rssi: -103,                // signal in dBm if available
  tap: 4,                    // taps since last beat
  motion: 0.05               // RMS accel since last beat
}
```

JSON serialized, ~80-150 B. With brotli at the body level (Cloud Run supports `Content-Encoding: br` on requests via gzip/brotli stream): ~50-90 B on wire. At 2.5 kbps that is ~150-300 ms upload. Survives.

### Last-known GPS persistence

- `watchPosition` writes every successful fix to IDB `survivor_geo` store with timestamp.
- When the app cannot get a current fix, it ships the most recent stored fix flagged `stale_seconds: <n>`.
- Cell-tower hint: server-side IP geo via Cloud Load Balancer's `X-Geo-*` headers (or fallback Maxmind). Better than 1 km in most Indian metros, ~5 km in rural.

### Dedup

Server clusters survivor SOS by `(geohash7, time_bucket_10min, panic_code_class)`. A whole apartment block reporting the same building collapse merges into one cluster with `+N reporters`.

### Audio in survivor mode

- Default off in panic-code-only path.
- If the user holds the SOS button, MediaRecorder captures Opus at adaptive bitrate:
  - `effectiveType === '4g'` → 12 kbps
  - `'3g'` → 8 kbps
  - `'2g'` or unknown → 4 kbps, max 10 s
  - `'slow-2g'` → audio off, panic codes only.
- 5-10 s clip at 4 kbps = 2.5-5 KB. At 2.5 kbps that's 8-16 s upload. Acceptable in extremis.

### Anti-abuse

- 3 SOS / minute per /24 subnet. 50 / hour. 500 / day.
- Override via NDMA-issued event token (HMAC) for confirmed disaster zones — caps lift to 200/min/subnet.
- Anonymous SOS dispatches carry `confidence: low`. Dispatcher sees a "anon" badge. Vertex must extract disaster keywords or audio energy threshold to clear noise gate; otherwise queued at lower priority.

## Phone identity + misuse prevention

The user's mandate: identify the phone behind every SOS where possible, deter false reports during high-stakes events.

Reality: browsers do not expose `MSISDN` directly. We use four cooperating channels.

### 1. Telco header enrichment (best path)

NDMA partners with Jio / Airtel / Vi / BSNL to inject `X-MSISDN` (or `X-Up-Calling-Line-ID` on legacy WAP gateways) for traffic to `aether.dmj.one`. Telco signs the header with a shared secret. Server validates `HMAC-SHA256(telco_secret, msisdn|ts)` → `verified_msisdn`. Stored on the dispatch as `caller_phone_e164` with `phone_verified: true`.

This is the same primitive that powers Truecaller's SIM-based verification and BSNL's e-KYC pipeline. Costs nothing per-call, requires partnership.

### 2. SMS OTP fallback (when telco enrichment is off)

- Client posts `phone_e164` to `/api/v1/sos/verify_phone`.
- Server sends 6-digit OTP via MSG91 / Karix / Twilio India.
- Client uses Web OTP API (`navigator.credentials.get({otp:{transport:['sms']}})`) to auto-read on Android Chrome. iOS Safari falls back to manual paste.
- Verified phone bound to phone fingerprint for 30 days in `tm_phone_bindings` (TTL 30 d).

OTP cost: ₹0.15-0.25 per send. Acceptable. Disabled at survivor extreme-rate-limit tier (the rubble case skips OTP).

### 3. SMS shortcode SOS (zero-data fallback)

When the survivor cannot load the PWA at all, they SMS one of:
- `1078` — National Emergency Operations Centre (NDMA)
- `112` — pan-India ERSS (NDMA can subscribe to feed)
- `<state>-SDRF-shortcode` (state-specific, e.g. 1077)

Format: `SOS <free text>`. Telco delivers SMS with the survivor's MSISDN to a webhook on `aether.dmj.one`. Server creates a phone-verified anonymous dispatch with the SMS body as `transcription_native`. Vertex skipped (no audio); urgency defaults to HIGH unless the body contains explicit non-emergency keywords.

### 4. Anonymous fallback (only path when none of the above)

- No `X-MSISDN`, no OTP, no SMS gateway → phone fingerprint based identity (`survivor-<fp10>`).
- Dispatch carries `phone_verified: false` and `confidence: low`.
- Heavy rate limit (3/min per /24, 50/hr).
- Dispatcher UI shows an "anonymous" badge — handled with same care but lower auto-priority unless content indicates clear emergency.

### Phone-identity surfacing

Every dispatch carries:
```
caller_identity: {
  msisdn_e164: "+919876543210" | null,
  phone_verified: true | false,
  verification_channel: "telco_header" | "sms_otp" | "sms_shortcode" | "anon",
  fingerprint: "fp10",
  ip_subnet24: "203.0.113.0/24"
}
```

Dispatcher UI badge:
- ✓ Verified phone (telco)
- ✓ SMS OTP verified
- 📱 SMS shortcode (telco-side identity)
- ⚠ Anonymous

(Above icons in the spec only — UI uses text labels per no-emoji rule.)

### Misuse prevention

The Disaster Management Act 2005 § 54 prescribes imprisonment up to 1 year and/or fine for false alarms. Indian Penal Code § 177, § 182 cover false information to public servant. Aether's role: capture, audit, and forward.

Mechanisms:

1. **Vertex disaster-keyword + audio-energy gate.** Anonymous + low-confidence dispatches must clear at least one of: disaster keyword in transcription, audio RMS energy above panic threshold, or explicit panic-code tap. Otherwise queued at lowest priority and flagged `noise_gate: failed`.

2. **Frequency anomaly detection.** Same fingerprint + same SOS pattern repeated > 3 times in 1 hour → auto-flag `pattern_anomaly: true`. Dispatcher sees a banner.

3. **Geo-impossibility detection.** Same fingerprint reporting from > 50 km apart within 5 min → flag `geo_anomaly: true`.

4. **Cross-check with 112 ERSS feed.** When NDMA enables ERSS integration, Aether queries the same incident in 112's database. Match raises confidence; absence does not lower it (112 may have missed it).

5. **Audit chain forwarding.** Every dispatch with `phone_verified: false` and `noise_gate: failed` flows to a daily report to the district SP for false-alarm review. § 54 DM Act prosecution decisions sit with the police, not Aether.

6. **No false-report blocking pre-Vertex.** We never refuse to triage. We only mark and prioritise. The cost of refusing a real SOS misclassified as fake > the cost of triaging a fake.

### Code surface

- `server/server.js`: `X-MSISDN` validation against telco HMAC.
- `server/tm/anon.js`: phone-identity record + verification channel + noise-gate.
- `server/tm/sms.js`: NEW. Outbound OTP, inbound shortcode webhook, MSG91/Karix adapters.
- `server/tm/abuse.js`: NEW. Pattern-anomaly + geo-anomaly + § 54 forward.
- `web/index.html`: SMS OTP flow, Web OTP auto-read, phone field on first survivor SOS where bandwidth permits.

### Budget

- SMS OTP: ₹50 per 1000 sends. NDMA absorbs.
- Telco header enrichment: zero per-call after partnership setup.
- SMS shortcode: telco interconnect cost (NDMA-borne).
- Anonymous: zero, infinite scale.

## Auth model — two tiers

### Login (ML-DSA-65 stays)

Unchanged for responders + dispatchers + NDMA chain. Keypair in IDB, Argon2id 64 MiB → AES-GCM, server challenge / response, signed bearer.

**Argon2id moved to a Web Worker** so the main thread does not freeze during the 8-15 s key derivation on Android Go.

**Bearer compaction**: bearer becomes `<32B-random>.<32B-HMAC-SHA256-of-claims>` instead of a JSON+ML-DSA-signed JWT. Server-side `tm_sessions/{token_id}` doc (TTL 30 min) holds the claims. Saves ~3 KB per request. Sliding refresh on every authenticated call. No need to re-login at 30 min unless idle for that long.

### Per-action signature (HMAC, not ML-DSA)

Replaces every `requireFreshUserSig` ML-DSA path.

Flow:
1. On login, server issues a per-session `action_key_b64` (32 B) bound to the session token. Cached server-side, never re-sent.
2. Client signs `HMAC-SHA256(action_key, canonical(uid, action, target, ts))` and sends in `X-Action-Sig` header. ts ±60 s window. Server keeps a 5-min nonce store keyed by `(uid, action, target, ts)` to block replay.

Trade-off acknowledged: a stolen session key allows action forgery. Mitigation:
- Action key never leaves IDB on the client and never touches the wire after issuance.
- Session key rotates on every authenticated call (server returns a new key in `X-Next-Action-Key`); previous key valid for 30 s overlap.
- Audit row carries the HMAC and the action key id; post-incident inquiry can detect anomalous keys via the chain.

**Crucially: client and server canonical formats are now defined in one shared file (`server/tm/canonical.js` re-exported as `web/tm/canonical-shared.js` via build) so they cannot drift again.**

### Survivor mode — no auth

Anonymous. Heavy rate-limit. Server-issued daily HMAC `event_key` for confirmed-zone caps lift; obtained via NDMA dashboard and propagated to a public endpoint.

## Watchdog (Cloud Tasks ladder)

Per the auto-DSS-on-C2-fail design from earlier conversation. Implemented via Cloud Tasks queues in `dmjone-asia-south2` region (closer to Firestore Delhi), HMAC-signed callbacks to internal endpoints.

SLA per urgency: CRITICAL=60s, HIGH=300s, MEDIUM=900s, LOW=3600s, UNCLEAR=300s.

Step ladder:
1. Notify direct supervisor (push).
2. Auto-escalate one tier up + notify.
3. SYSTEM_AI auto-assigns DSS top-1 if score ≥ 0.55.
4. Fan-out broadcast to all in-scope responders.

C2-compromise detection via `tm_user_presence` (TTL 5 min) heartbeat on every authenticated call. If no in-scope user has presence in 2× SLA, skip the manual rungs.

## DSS criticality (extends Vertex schema)

`TRIAGE_SCHEMA` adds:
```
victims: ARRAY of {
  age_band: enum [infant, child, adult, elderly],
  condition_flags: ARRAY of [pregnant, crush_extracted, unresponsive,
                             bleeding, breathing_difficulty, conscious_ambulatory],
  count: INTEGER (default 1)
}
```

`tm_dispatches` gains computed `criticality_score` at persist time:

```
criticality = urgency_factor × Σ(victim_weight × victim_count) × time_decay

victim_weight:
  pregnant: 2.0
  unresponsive: 2.0
  crush_extracted: 1.5
  bleeding: 1.5
  infant: 1.5
  elderly_with_crush: 1.8
  child <5y: 1.3
  elderly: 1.2
  adult: 1.0

urgency_factor:
  CRITICAL: 1.0
  HIGH: 0.7
  MEDIUM: 0.4
  LOW: 0.2

time_decay:
  1.0 + 0.01 × minutes_since_received
```

`listTeam` for `requires_review` orders by `criticality_score` desc. DSS unit-suggestion stays as is for unit-side scoring; new `multi_dispatch_compare` endpoint surfaces side-by-side criticality when one unit must serve multiple pending dispatches.

## Dedup clustering

`tm_dispatches` adds `geohash7`, `transcript_minhash_b64`, `cluster_id`, `cluster_role`. On persist, server queries (geohash7, last 15 min, not-resolved) and computes match score. If ≥ 0.7, link as duplicate to existing primary.

For survivor anon: cluster also keys on phone fingerprint (same survivor reporting twice) plus geohash + time bucket.

## Background sync + Web Push

Replaces 15 s status polling.

- SW v3 owns the queue: reads pending clips from IDB, calls `/api/v1/triage` (or `/api/v1/sos/anon`), retries with exponential backoff. `sync` + `periodicsync` events.
- Bearer cached encrypted in IDB so SW can read it.
- Idempotency keys (`X-Client-Clip-Id`) with 24 h server-side `tm_clip_seen` TTL store.
- Web Push via VAPID. Supervisor of the dispatch caller gets notified, not the whole subtree. Push payload ≤ 500 B.
- iOS Safari: degrade gracefully to `pageshow` + `online` listeners.

## Audio adaptive cascade

At [index.html record path]:
```
const conn = navigator.connection;
const eff = conn?.effectiveType || '4g';
const audioBitrate = {
  'slow-2g': 0,         // no audio; panic codes only
  '2g': 4000,
  '3g': 8000,
  '4g': 12000
}[eff] ?? 12000;
const maxClipMs = eff === '2g' ? 10_000 : 30_000;
```

If `audioBitrate === 0`, the SOS button toggles panic-code-mode UI: 12 large icons in a 3×4 grid. Tap = code added to next heartbeat.

## i18n expansion

Add 11 languages on top of existing en/hi/ta/bn:
- `ml` Malayalam, `te` Telugu, `mr` Marathi, `or` Odia, `gu` Gujarati,
- `pa` Punjabi, `kn` Kannada, `ur` Urdu, `as` Assamese, `ne` Nepali, `mai` Maithili.

Strings split by surface:
- Survivor shell: 18 strings × 15 langs × ~20 chars × 2 bytes ≈ 11 KB raw, ~3 KB brotli.
- Login: 30 strings.
- Dashboard: 200 strings.

Worker summary text: at status-change, server picks template by `triage.language_detected` if present in supported set, else `caller_lang_hint`, else `en`. New `server/tm/i18n.js` carries the templates.

## Audit hash chain

`tm_audit` rows gain:
- `prev_hash`: SHA-256 of previous row's `row_hash`.
- `row_hash`: SHA-256 of canonical `(uid, action, target_ref, payload_summary, ts, prev_hash)`.
- `server_sig_b64`: ML-DSA-65 sig over `row_hash` by server key.

`/api/v1/tm/audit/verify` walks chain, returns first break + index. Available to NDMA tier only.

## Multi-device key sync (QR-bridge)

Device 1 → "Add another device" → generates 30-second QR with:
- Encrypted private key blob (existing IDB)
- Random 16-byte one-time wrap key (shown to user as 4-word mnemonic)

Device 2 → scans QR + types mnemonic → unwraps + stores in own IDB. Same pubkey on both devices. Original device tracks all known devices; can remotely revoke any.

## Bulk roster import

NDMA / state tier opens upload UI → CSV with columns `name,type,phone,scope_path,capacity,lat,lng`. Server validates row-by-row in a single transaction, idempotent on `(name, scope_path)`. Reports per-row errors. Caps at 1000 rows per upload.

## File-by-file change plan

### server/

- `server.js`: `/api/v1/sos/anon` route, `X-Action-Sig` header, idempotency key handling, audio bitrate hint header.
- `server/tm/auth.js`: bearer compaction, session/action key model, drop ML-DSA per-action (keep at login + audit), Web Worker note.
- `server/tm/canonical.js`: NEW. Single source of canonical action message format. Re-exported to client via build.
- `server/tm/users.js`: tier expansion, scope_re, presence heartbeat, escalation policy ladder.
- `server/tm/dispatches.js`: criticality_score, listTeam ordering, direct_only filter, multi_dispatch_compare.
- `server/tm/dss.js`: criticality computation alongside unit score.
- `server/tm/dedupe.js`: NEW. geohash + minhash + cluster.
- `server/tm/watchdog.js`: NEW. Cloud Tasks integration + SLA ladder + SYSTEM_AI assigner.
- `server/tm/notify.js`: NEW. Web Push fan-out via VAPID.
- `server/tm/audit.js`: hash chain + per-row sig + verify endpoint.
- `server/tm/units.js`: bulk roster import.
- `server/tm/i18n.js`: NEW. Language templates for worker_summary.
- `server/tm/anon.js`: NEW. Survivor anonymous SOS pipeline + heartbeat aggregation.
- `server/tm/router.js`: route table updates.

### web/

- `web/index.html`: survivor anon mode, panic-code grid, adaptive bitrate, last-GPS persistence, shake/triple-tap/volume listeners, replace polling with push, 4-word mnemonic UI.
- `web/sw.js`: full rewrite for real bg sync + push handler + idempotency replay.
- `web/sos-shell.html`: NEW. Ultra-light ≤ 3 KB survivor entry.
- `web/i18n/{lang}.json`: NEW. 11 new language packs.
- `web/tm/tm.js`: HMAC action sig, push subscribe, scoped notification feed, multi-device key sync UI, bulk roster UI, criticality column, NDMA tier mapping.
- `web/tm/auth-client.js`: Argon2id Worker mode, HMAC action sig, multi-device key bridge.

### deploy/

- `deploy/deploy.sh`: VAPID secret, Cloud Tasks queue create, additional Firestore composite indexes.

## Build waves

Each agent works in its own git worktree branch named `wave-N-<lane>`. After agent commits, lead merges.

### Wave 1 — bones
- `canonical-and-bearer`: shared canonical + HMAC action sig + bearer compaction + register field rename.
- `ndma-tiers`: tier expansion + scope_re + presence + bulk roster.
- `criticality-dedup`: Vertex schema extension + criticality + geohash + minhash + cluster.
- `audit-chain`: hash chain + per-row sig + verify endpoint.

### Wave 2 — transport
- `bg-sync-push`: SW v3 + idempotency + VAPID + scoped push + replace polling.
- `watchdog-tasks`: Cloud Tasks + SLA ladder + SYSTEM_AI auto-assigner.

### Wave 3 — survivor + field + i18n
- `survivor-anon`: /sos shell + anon endpoint + panic codes + heartbeat + rubble protocol.
- `field-vad`: VAD + speaker gate + field mode + adaptive bitrate.
- `i18n-expand`: 11 new languages + worker_summary localization + multi-device QR sync.

### Wave 4 — integration + deploy
- `merge-and-test`: merge all branches, integration tests, deploy.

## Constraints non-negotiable

- WCAG 2.2 AAA. Tap targets ≥ 44 px. Contrast ≥ 7:1 normal text. Reduced motion. Keyboard nav. Screen reader labels.
- No banned words anywhere (delve, leverage, utilize, streamline, robust, seamless, cutting-edge, game-changing, innovative, revolutionize, empower, harness, elevate, spearhead, holistic, synergy, paradigm, ecosystem, comprehensive, deep-dive, furthermore, additionally, notably, essentially, fundamentally, in-conclusion).
- No em dashes. Plain words. Short sentences.
- No emojis.
- Pure black `#000000` background.
- WCAG colour contrast verified per element with the contrast pair documented in CSS comments.
- Brotli pre-compression on every static asset.
- $0 idle: scale-to-zero, TTL on transient collections, cleanup policies on AR/GCS/CloudBuild.

## Voice + style enforcement

Every PR description, every commit message, every comment, every UI string. No exceptions. Run a banned-word check pre-commit.
