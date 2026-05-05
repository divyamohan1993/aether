# aether-server

Stateless Cloud Run service for Project Aether. Receives short audio (Opus/WebM/MP4/WAV, max 512 KB), forwards it to Vertex AI Gemini 2.5 Flash in `us-central1`, and returns SDRF-ready triage JSON. Also serves the survivor PWA from `/app/web/`.

Zero npm deps except `google-auth-library` (for ADC + access token to Vertex AI). Pure `node:http` server. Cold start under 1.5s.

## Routes

- `GET /` and `GET /index.html` · survivor PWA shell
- `GET /sw.js`, `GET /manifest.webmanifest`, `GET /favicon.svg`, `GET /robots.txt`
- `POST /api/v1/triage` · primary endpoint (see `../SHARED_SPEC.md`)
- `GET /healthz` · `{"ok":true}`

Static assets are served from `WEB_DIR` (default `../web/` locally, `/app/web/` in the container). Pre-built `*.gz` and `*.br` are honored if present; otherwise compression is generated once and cached.

## Local dev

```sh
# Install deps once.
npm install

# ADC for Vertex AI. Either is fine.
gcloud auth application-default login
# or
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa-key.json

# Start.
PORT=8080 npm start
```

The frontend agent writes its build into `../web/`. The server reads from disk lazily, so you can rebuild the frontend while the server keeps running.

## Env vars

| Var | Default | Notes |
|---|---|---|
| `PORT` | `8080` | Cloud Run injects this. |
| `GCP_PROJECT` | `dmjone` | Used for the Vertex URL and quota project. |
| `VERTEX_REGION` | `us-central1` | Iowa. |
| `VERTEX_MODEL` | `gemini-2.5-flash` | |
| `WEB_DIR` | `../web` (dev), `/app/web` (image) | Where static assets live. |

## Deploy

The deploy script (`/mnt/experiments/aether/deploy/`) builds with the Dockerfile here, pushes to Artifact Registry, and runs `gcloud run deploy aether` against project `dmjone`, region `us-central1`, with service account `aether-vertex-sa@dmjone.iam.gserviceaccount.com` (roles: `aiplatform.user`, `logging.logWriter`, `cloudtrace.agent`).

The container expects:
- ADC available via the runtime SA (no key files in image).
- Cloud Run min-instances `0`, max-instances modest (e.g. 5). Cold start budget is met.
- Cloud Run's request concurrency default is fine. Token-bucket rate limit is per-instance per-IP and resets on cold start; that's an additional friction layer, not a hard guarantee. Add Cloud Armor / IAP if you need a hard floor.

## Build

```sh
# From repo root (../):
docker build -f server/Dockerfile -t aether:local .
docker run --rm -p 8080:8080 \
  -v "$HOME/.config/gcloud:/home/node/.config/gcloud:ro" \
  -e GOOGLE_APPLICATION_CREDENTIALS=/home/node/.config/gcloud/application_default_credentials.json \
  aether:local
```

## Logs

Structured JSON to stdout. Cloud Logging will index `severity`, `requestId`, `clientId`, `ip`, `urgency`, `latencyMs`, `modelLatencyMs`. Errors include stack traces. The client never sees internal error detail; check Cloud Logging when triage fails.
