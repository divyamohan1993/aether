================================================================================
AETHER · NDMA-grade disaster response decision support system for India
================================================================================

A first-72-hour disaster response platform built for the National Disaster
Management Authority of India and the State Disaster Response Forces of every
state. Survives 1-bar 2G at 2.5 kbps. Lets a survivor trapped under rubble
with one moving finger get help. Runs the real Government of India command
chain from Prime Minister's Office down to the village volunteer. Falls open
when command and control is compromised: the AI takes over, with full audit
and one-tap human override.

Open source. Apache 2.0. Built end-to-end as a single $0-idle Cloud Run
service.

================================================================================
The problem
================================================================================

In the first 24 hours of an Indian disaster:

  - Cell towers fall. The ones that survive run on backup batteries that
    last hours, not days.
  - Survivors do not have prior accounts in any specific app. They cannot
    register, type a passphrase, or wait for an 8-second key derivation.
  - GPS does not lock from inside a collapsed building. Sky view blocked.
  - Many speak languages that English-only or Hindi-only apps ignore:
    Malayalam, Telugu, Marathi, Odia, Gujarati, Kannada, Punjabi, Urdu,
    Assamese, plus dozens of regional and tribal languages.
  - Dispatchers drown in panicked, code-switched audio that no IVR script
    can parse.
  - Command and control itself can fail. The on-call dispatcher's phone
    dies. The district commander is asleep. Nothing pages anyone.
  - False alarms compete with real ones. Misuse during high-stakes events
    has real cost in misallocated rescue capacity.

Existing systems handle parts of this. Few handle all of it. None ship at
$0 idle cost so a state can deploy without budget approval.

================================================================================
The solution shape
================================================================================

One Cloud Run service. Three personas. One survivor edge.

  Survivor edge          Anonymous, 1-bar 2G capable, voice or single-button
                         or shake or volume-button input, panic codes for
                         sub-50-byte heartbeats, last-known GPS, cell-tower
                         hint, multilingual.

  Field responder        Per-tier ML-DSA signed login. HMAC per-action sig
                         to fit 2.5 kbps. Voice-activated dispatch after a
                         single toggle. Speaker-gated so bystanders are
                         not dispatched. Offline write queue with real
                         background sync.

  Dispatcher and command Pending-review queue ranked by criticality, not
                         time. Dedup'd so two volunteers reporting the
                         same survivor surface as one cluster. Decision
                         support that scores units against patient profile
                         (pregnancy, crush extraction, paediatric, elderly).
                         Watchdog escalates if no human acts within the
                         SLA for that urgency. AI takes over at the top
                         of the ladder when nobody is there to act.

================================================================================
Real Government of India command chain
================================================================================

Ten tiers, mapping the actual chain. Authority decreases left to right.

  100 ndma           National Disaster Management Authority
                     PMO chair, MHA Disaster Management Division, NDRF HQ
   90 national_ops   NDRF battalions, Army DGMO, IAF, Navy liaison,
                     Cabinet Secretariat
   80 sdma           State Disaster Management Authority
                     CM chair, Chief Secretary, Relief Commissioner
   70 state_ops      SDRF battalions, State Health DGP, Police DGP, Forest
   60 ddma           District Disaster Management Authority
                     DM/DC, SP, CMHO
   50 district_ops   DSP, Civil Surgeon
   40 subdivisional  SDM, BDO, ACMO
   30 tehsil         Tehsildar, SHO, ASHA supervisor
   20 volunteer      ASHA, ANM, Anganwadi worker, NCC, NSS,
                     Civil Defence, Home Guards, Panchayat member
   10 survivor       Anonymous. Rate-limited. Cannot mutate beyond own
                     SOS thread.

Scope paths follow Indian administrative geography:
ndma/<state>/<district>/<sub-division>/<tehsil>/<village>

Operational forces are tracked as units rather than tiers:
NDRF, SDRF, Indian Army (Aid to Civil Authority u/s 130/131 CrPC,
requested via DM), IAF, Indian Navy, Coast Guard, Fire and Emergency
Services, State and Central Police, GRP, RPF, Civil Defence, Health
Department, Forest Department, NGO partners.

================================================================================
Survivor mode (rubble protocol)
================================================================================

The trapped survivor is the design center. Everything else serves them.

Reality:
  - No GPS lock from inside rubble.
  - 1-bar 2G if the cell tower stayed up. Dropping.
  - Dying battery.
  - Maybe one finger or only voice.
  - No prior account.

Inputs (any of these works):
  - Tap a big red button.
  - Triple-tap anywhere on the screen.
  - Volume button combo where the browser allows.
  - Shake gesture, three shakes in two seconds.
  - Voice activity, after the first ack the app stays in trapped mode.

Twelve panic codes. One byte each. Tap an icon if you cannot speak:
  trapped_alive, injured_conscious, multiple_people, cannot_move,
  breathing_difficulty, no_food_water, need_medical, hear_rescuers,
  building_stable, building_failing, water_rising, fire_nearby.

Heartbeat protocol (every 60 seconds, ~50 to 90 bytes on wire after
brotli):
  fingerprint, sequence, timestamp, panic codes since last beat,
  last-known GPS with stale-seconds, battery, signal strength, taps,
  motion RMS.

Last-known GPS persists in IndexedDB for seven days. When the current
fix is unavailable, the most recent stored fix ships with a stale flag.

Cell-tower hint via the Cloud load balancer's geo headers. Better than
1 km in most Indian metros, ~5 km in rural.

Anti-abuse: heavy rate limit per /24 subnet (3 per minute, 50 per hour,
500 per day). NDMA can mint event tokens that lift caps in confirmed
disaster zones.

================================================================================
Phone identity (four cooperating channels)
================================================================================

Browsers do not expose MSISDN directly. We use four channels in priority.

  1. Telco header enrichment. Jio, Airtel, Vi, BSNL inject an
     HMAC-signed X-MSISDN header on traffic to the NDMA endpoint.
     Verified phone, zero per-call cost. Best path. Requires partnership.

  2. SMS OTP. Standard MSG91/Karix/Twilio pipeline. Web OTP API
     auto-reads on Android Chrome. iOS Safari falls back to manual paste.
     30-day binding to phone fingerprint.

  3. SMS shortcode. Survivor texts SOS to 1078 (national EOC), 112
     (pan-India ERSS), or a state-SDRF shortcode. Telco delivers SMS
     with caller MSISDN to a webhook.

  4. Anonymous fallback. Phone fingerprint only. Heavy rate limit.
     Confidence flagged low at the dispatcher UI.

Misuse prevention:
  - Vertex disaster-keyword and audio-energy noise gate.
  - Frequency anomaly: same fingerprint reporting more than 3 times
    in an hour.
  - Geo-impossibility: same fingerprint reporting from points more
    than 50 km apart within 5 minutes.
  - 112 ERSS cross-check when integrated.
  - Audit forwarding to district SP for false-alarm review under
    Disaster Management Act 2005 section 54.
  - The system never refuses to triage. It only marks and prioritises.
    The cost of refusing a real SOS misclassified as fake exceeds the
    cost of triaging a fake.

================================================================================
Bandwidth budget (2.5 kbps survivable)
================================================================================

Persona              Network floor    Per-action overhead    Audio target
Survivor anon        1-bar 2G          <= 100 B                Optional
Survivor with voice  2G, 10 kbps       <= 500 B                Opus 4 kbps, 10s
Field responder      2G/3G             <= 500 B                Opus 6-12 kbps
Field VAD-mode       3G+               <= 1 KB per phrase      Opus 12 kbps
Dispatcher / NDMA    Reliable          n/a                    n/a

Achieved by:
  - Replacing per-action ML-DSA-65 (~3.3 KB sig) with HMAC-SHA256 over
    a server-issued nonce (~32 B). 140x wire reduction.
  - Compacting the bearer to <token-id>.<HMAC-of-claims>; claims live
    server-side in a TTL'd session doc. Saves ~3 KB per request.
  - Adaptive Opus bitrate that shrinks on slow 2G; falls back to
    panic-code-only on slow-2G.
  - Service worker caches the entire shell.
  - Brotli pre-compression on every static asset.
  - Replacing 15-second status polling with Web Push delivered through
    the OS push channel.

ML-DSA-65 stays at the boundaries that matter:
  - Login challenge and response.
  - Audit chain row signatures.

================================================================================
Decision intelligence (criticality + DSS + dedup)
================================================================================

Vertex AI Gemini 2.5 Flash transcribes and triages each clip in under
two seconds. Strict-schema response so the server cannot drift on
malformed JSON. Schema includes:

  urgency, language_detected, transcription_native, transcription_english,
  people_affected, injuries, needs, location_clues, ambient_audio,
  summary_for_dispatch, confidence, caller_state, incident_type,
  victims (per-victim age band and condition flags)

Criticality score (computed at persist time, sorts the dispatcher feed):
  urgency_factor x sum(victim_weight x count) x time_decay

Per-victim weights:
  pregnant 2.0, unresponsive 2.0, crush_extracted 1.5, bleeding 1.5,
  infant 1.5, elderly_with_crush_extracted 1.8, child <5y 1.3,
  elderly 1.2, adult 1.0

Unit-side DSS scores ambulances, fire engines, SDRF teams, drones,
helicopters, medical teams against urgency, need-to-type match, incident
match, and haversine distance.

Cross-volunteer dedup: every dispatch carries a 7-character geohash
(~150 m precision) and a 64-hash MinHash of its English transcription.
Server queries (geohash, last 15 minutes, not-resolved). Match score
combines distance, incident type, and Jaccard. Above 0.7 the new
dispatch joins the existing cluster as a duplicate. The dispatcher feed
shows a cluster as one row with a "+N reporters" badge.

================================================================================
Watchdog (auto-DSS at C2 failure)
================================================================================

Cloud Run scales to zero between requests, so no in-process timer can
work. Cloud Tasks schedules a callback per dispatch at the SLA deadline.

SLA per urgency:
  CRITICAL 60 s, HIGH 5 min, MEDIUM 15 min, LOW 1 hr, UNCLEAR 5 min.

Step ladder (each rung idempotent, signed by SYSTEM_AI key):
  Step 1 (1x SLA)  Push to direct supervisor
  Step 2 (2x SLA)  Auto-escalate one tier up
  Step 3 (3x SLA)  SYSTEM_AI auto-assigns DSS top-1 if score >= 0.55
  Step 4 (4x SLA)  Fan-out broadcast to all in-scope responders

C2-compromise detection from a 5-minute presence TTL on each tier. If
no in-scope user has hit the API within 2x SLA, the manual rungs are
skipped. If the NDMA tier itself has no presence during a CRITICAL
surge (>= 10 CRITICAL dispatches in 60 s), autonomous mode activates:
new CRITICAL dispatches go straight to step 3 plus a parallel SMS
broadcast.

Reversibility:
  - Every SYSTEM_AI assignment carries the full DSS reasoning blob.
  - Any human in scope can cancel and reassign at any time.
  - Post-incident report at NDMA tier enumerates every actor=SYSTEM_AI
    row.

================================================================================
Auth (post-quantum, two-tier)
================================================================================

Login layer (full ML-DSA-65, NIST FIPS 204):
  - User keypair generated in browser at registration.
  - Private key encrypted with passphrase via Argon2id (t=3, m=64 MiB,
    p=1, dkLen=32) and AES-256-GCM. Lives only in IndexedDB. Argon2id
    runs in a Web Worker so the main thread stays responsive on
    Android Go.
  - Server issues a 32-byte challenge; browser signs locally; server
    verifies against stored public key.
  - Server's own ML-DSA-65 keypair lives in Secret Manager with
    least-privilege binding.

Per-action layer (HMAC for bandwidth):
  - Server mints a 32-byte action_key at login, returned once in the
    verify response.
  - Client signs each mutating call with HMAC-SHA256(action_key,
    canonical(uid, action, target, ts)) sent in X-Action-Sig.
  - Server verifies HMAC, ts within +/- 60 s, blocks replay via a
    5-minute nonce cache.
  - Sliding key rotation: each authenticated response carries
    X-Next-Action-Key. Old key honoured for 30 s overlap.
  - Canonical message format defined once in server/tm/canonical.js
    and bundled to the browser, so client and server bytes cannot
    drift.

Multi-device key sync via QR-bridge (planned in Wave 3). Forgotten
passphrase still means re-invitation by the user's parent in the
hierarchy.

================================================================================
Audit (tamper-evident hash chain)
================================================================================

Every mutation writes one tm_audit row. Each row carries:
  - prev_hash, the SHA-256 of the previous row's row_hash
  - row_hash, SHA-256 of canonical (uid, action, target, payload, ts)
  - server_sig_b64, ML-DSA-65 over row_hash by the server key
  - seq, monotonic per chain

Tip pointer at tm_audit_tip/global, updated inside the same Firestore
transaction as the row. Three retries with jitter on contention; on
exhaustion falls back to chain_break:true and CRITICAL log.

NDMA-tier-only verify endpoint walks the chain and reports the first
break. State+ list endpoint filters by actor, action, target, time
range.

Pre-existing audit rows migrate lazily on first call. Capped at 10K
rows per migration; production runs a separate batch script.

================================================================================
Internationalisation
================================================================================

Currently shipping: English, Hindi, Tamil, Bengali.

Planned in Wave 3: Malayalam, Telugu, Marathi, Odia, Gujarati, Punjabi,
Kannada, Urdu, Assamese, Nepali, Maithili.

Worker-summary text (the one survivor-facing string) is templated and
selected per dispatch's language_detected, falling back to caller's
language hint, falling back to English. Dispatcher feed labels follow
the user's browser language.

================================================================================
Tech stack
================================================================================

Runtime         Cloud Run, Node 22, scale-to-zero, min-instances=0
Database        Firestore Native, multi-region, free tier
AI              Vertex AI Gemini 2.5 Flash, structured output
Auth            ML-DSA-65 (FIPS 204) at boundaries, HMAC-SHA256
                between, Argon2id (RFC 9106) for passphrase derivation
Notifications   Web Push (RFC 8030, RFC 8291) via VAPID
Background      Service Worker v3 with sync and periodicsync
Storage         IndexedDB on the client, Firestore on the server
Compression     Brotli quality 11, gzip -9, pre-compressed at build
Build           Pure ESM, no bundler for server, esbuild for the
                browser auth client
Testing         Pure-Node test suites, no test framework dependency

Zero npm dependencies on the server beyond google-auth-library and
@noble/post-quantum. Zero npm dependencies on the browser beyond
the auth-client bundle.

================================================================================
What this is not
================================================================================

  - Not a replacement for 112 ERSS. It complements ERSS by taking
    multimodal voice input that ERSS cannot parse and routing through
    the NDMA hierarchy.
  - Not a personal-emergency app for everyday use. The survivor edge
    activates in declared disaster zones.
  - Not a cryptographic identity system. Speaker matching gates
    bystander voices in field mode but is not biometric proof.
  - Not a forensic-grade witness platform. The audit chain is
    tamper-evident, but full evidentiary handling for criminal
    prosecution sits with the police chain.

================================================================================
Constraints, non-negotiable
================================================================================

  - $0 idle cost. Cloud Run min-instances=0, Firestore TTL on transient
    collections, cleanup policies on Artifact Registry, GCS, Cloud Build.
  - WCAG 2.2 AAA. Tap targets >= 44 px. Contrast >= 7:1 normal text.
    Reduced motion respected. Keyboard navigation. Screen reader labels.
  - Pure black background for OLED zero-power.
  - No banned words anywhere in code, comments, UI, or commit
    messages.
  - No emojis. Plain words. Short sentences.
  - Pre-compress every static asset.

================================================================================
Public surfaces
================================================================================

  Live SOS PWA + Task Manager   <redacted custom domain>
  Demo portal (one-click login) <redacted>/demo
  Documentation                 <redacted>/docs
  Pitch deck                    <redacted>/pitch
  GitHub                        <redacted org / repo>
  Showcase                      <redacted portfolio site>

Demo accounts (passphrase published on /demo, ciphertext blobs in
web/demo/credentials.json): NDMA, SDMA, DDMA, subdivisional, volunteer
tier across the demo scope. Real production accounts live under the
ndma scope and never reuse demo credentials.

================================================================================
License
================================================================================

Apache License 2.0. See LICENSE for the full text.

The phone identity, watchdog, and SYSTEM_AI components require
credentials that are not in the repository. Operators must mint their
own keypairs and configure their own telco partnerships before any
deployment to a live network.

================================================================================
Acknowledgements
================================================================================

This system is built around the codified disaster response chain
under the Disaster Management Act 2005 and the operational doctrines
of the National Disaster Management Authority, the National Disaster
Response Force, the Indian Armed Forces' Aid to Civil Authority
provisions, the National Emergency Response Support System (112), and
the state-level SDRF and SDMA mandates.

The product positioning targets the first 72 hours of an Indian
disaster, when the people who need help most are the ones least able
to ask for it.

================================================================================
