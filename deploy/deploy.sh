#!/usr/bin/env bash
# Project Aether · one-shot Cloud Run deploy.
#
#   ./deploy.sh                 # defaults: project=dmjone, region=us-central1
#   PROJECT_ID=foo REGION=us-central1 VERTEX_REGION=us-central1 ./deploy.sh
#
# What this does:
#   1. Verifies gcloud auth and required APIs.
#   2. Ensures Artifact Registry repo `aether-images` exists in REGION.
#   3. Ensures runtime SA `aether-vertex-sa` exists with least-privilege roles.
#   4. Builds the container from the repo root (server + web baked in).
#   5. Deploys to Cloud Run with min-instances=0 (scale-to-zero, $0 idle).
#   6. Prints the URL.

set -euo pipefail

PROJECT_ID="${PROJECT_ID:-dmjone}"
REGION="${REGION:-us-central1}"
VERTEX_REGION="${VERTEX_REGION:-us-central1}"
VERTEX_MODEL="${VERTEX_MODEL:-gemini-2.5-flash}"
SERVICE="${SERVICE:-aether}"
REPO="${REPO:-aether-images}"
SA_NAME="aether-vertex-sa"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

log()  { printf '\033[1;34m[aether]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[aether]\033[0m %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "Required command '$1' not found."; }

need gcloud
need docker

ACTIVE_ACCOUNT="$(gcloud auth list --filter=status:ACTIVE --format='value(account)' || true)"
[[ -n "${ACTIVE_ACCOUNT}" ]] || die "Run 'gcloud auth login' first."
log "Active account: ${ACTIVE_ACCOUNT}"
log "Project: ${PROJECT_ID} · Cloud Run: ${REGION} · Vertex AI: ${VERTEX_REGION} · Model: ${VERTEX_MODEL}"

gcloud config set project "${PROJECT_ID}" >/dev/null

log "Ensuring required APIs are enabled"
gcloud services enable \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  aiplatform.googleapis.com \
  logging.googleapis.com \
  cloudtrace.googleapis.com \
  cloudtasks.googleapis.com \
  secretmanager.googleapis.com \
  --project="${PROJECT_ID}" >/dev/null

# Watchdog Cloud Tasks queue. asia-south1 (Mumbai) is the closest GA
# region to Firestore Delhi (asia-south2 has no Cloud Tasks GA at the
# time of writing). Idempotent: describe first, create only on miss.
TASKS_LOCATION="${CLOUD_TASKS_LOCATION:-asia-south1}"
TASKS_QUEUE="${CLOUD_TASKS_QUEUE:-aether-watchdog}"
log "Ensuring Cloud Tasks queue ${TASKS_QUEUE} in ${TASKS_LOCATION}"
if ! gcloud tasks queues describe "${TASKS_QUEUE}" --location="${TASKS_LOCATION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud tasks queues create "${TASKS_QUEUE}" \
    --location="${TASKS_LOCATION}" \
    --project="${PROJECT_ID}" \
    --max-attempts=3 \
    --max-dispatches-per-second=10 \
    --max-concurrent-dispatches=20
fi

# Watchdog HMAC secret. Generated once and stored in Secret Manager so
# MVP posture: secret auto-creation skipped to keep Secret Manager at
# $0 idle. Production must mint the secrets enumerated near --set-secrets
# below. Re-enable this block by removing the early return guard.
#
# Production block (commented for MVP):
# log "Ensuring Secret Manager secret aether-watchdog-hmac"
# if ! gcloud secrets describe aether-watchdog-hmac --project="${PROJECT_ID}" >/dev/null 2>&1; then
#   gcloud secrets create aether-watchdog-hmac \
#     --replication-policy=automatic \
#     --project="${PROJECT_ID}" >/dev/null
#   python3 -c 'import secrets,sys; sys.stdout.write(secrets.token_urlsafe(48))' \
#     | gcloud secrets versions add aether-watchdog-hmac \
#         --data-file=- --project="${PROJECT_ID}" >/dev/null
#   log "  generated initial WATCHDOG_HMAC_SECRET version"
# fi
# log "Ensuring Secret Manager secrets tm-system-ai-priv / tm-system-ai-pub"
# for secret in tm-system-ai-priv tm-system-ai-pub; do
#   if ! gcloud secrets describe "${secret}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
#     gcloud secrets create "${secret}" \
#       --replication-policy=automatic \
#       --project="${PROJECT_ID}" >/dev/null
#     log "  TODO: mint ML-DSA-65 keypair offline, then versions add"
#   fi
# done

log "Ensuring Artifact Registry repo ${REPO}"
if ! gcloud artifacts repositories describe "${REPO}" --location="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud artifacts repositories create "${REPO}" \
    --repository-format=docker \
    --location="${REGION}" \
    --description="Project Aether container images" \
    --project="${PROJECT_ID}"
fi

log "Ensuring service account ${SA_EMAIL}"
if ! gcloud iam service-accounts describe "${SA_EMAIL}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud iam service-accounts create "${SA_NAME}" \
    --display-name="Project Aether Vertex AI SA" \
    --description="Least-privilege identity for SOS triage. roles/aiplatform.user only." \
    --project="${PROJECT_ID}"
fi

log "Granting least-privilege roles to ${SA_EMAIL}"
for role in roles/aiplatform.user roles/logging.logWriter roles/cloudtrace.agent roles/cloudtasks.enqueuer roles/secretmanager.secretAccessor; do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="${role}" \
    --condition=None --quiet >/dev/null
done

IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO}/${SERVICE}:$(date -u +%Y%m%d-%H%M%S)"

log "Building image ${IMAGE} via Cloud Build"
( cd "${ROOT}" && gcloud builds submit \
    --project="${PROJECT_ID}" \
    --tag="${IMAGE}" \
    --timeout=900s \
    --machine-type=e2-medium \
    . )

log "Deploying ${SERVICE} to Cloud Run (${REGION})"
gcloud run deploy "${SERVICE}" \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --image="${IMAGE}" \
  --service-account="${SA_EMAIL}" \
  --allow-unauthenticated \
  --memory=512Mi \
  --cpu=1 \
  --min-instances=0 \
  --max-instances=10 \
  --concurrency=40 \
  --timeout=60 \
  --port=8080 \
  --execution-environment=gen2 \
  --set-env-vars="GCP_PROJECT=${PROJECT_ID},VERTEX_REGION=${VERTEX_REGION},VERTEX_MODEL=${VERTEX_MODEL},NODE_ENV=production,LOG_LEVEL=info,FIRESTORE_DB=(default),TM_BOOTSTRAP_ALLOW=${TM_BOOTSTRAP_ALLOW:-0},VAPID_SUBJECT=${VAPID_SUBJECT:-mailto:ops@aether.dmj.one},CLOUD_TASKS_QUEUE=${TASKS_QUEUE},CLOUD_TASKS_LOCATION=${TASKS_LOCATION},MSG91_API_KEY=${MSG91_API_KEY:-},KARIX_API_KEY=${KARIX_API_KEY:-},TWILIO_ACCOUNT_SID=${TWILIO_ACCOUNT_SID:-},TWILIO_AUTH_TOKEN=${TWILIO_AUTH_TOKEN:-},TWILIO_FROM=${TWILIO_FROM:-}"
# MVP posture: NO Secret Manager bindings (zero idle Secret Manager cost).
# Runtime modules fall back to in-memory ephemeral keys / no telco / no SMS
# webhook on every cold start. Existing sessions die when Cloud Run scales
# out or restarts. Audit chain cannot verify across cold starts. Web Push
# subscriptions invalidate when VAPID rotates. Cloud Tasks callbacks fail
# HMAC across instances. All acceptable for demo. NOT acceptable for any
# live NDMA / SDRF disaster response deployment.
#
# Production requires these secrets, minted out of band, and the bindings
# below uncommented:
#   TM_SERVER_PUB_B64       tm-server-pub
#   TM_SERVER_PRIV_B64      tm-server-priv
#   VAPID_PUBLIC_KEY_B64    vapid-pub
#   VAPID_PRIVATE_KEY_B64   vapid-priv
#   WATCHDOG_HMAC_SECRET    aether-watchdog-hmac
#   SYSTEM_AI_PRIV_B64      tm-system-ai-priv
#   SYSTEM_AI_PUB_B64       tm-system-ai-pub
#   TELCO_HMAC_SECRETS      aether-telco-hmac
#   SMS_WEBHOOK_HMAC        aether-sms-webhook-hmac
#
# --set-secrets="TM_SERVER_PUB_B64=tm-server-pub:latest,TM_SERVER_PRIV_B64=tm-server-priv:latest,VAPID_PUBLIC_KEY_B64=vapid-pub:latest,VAPID_PRIVATE_KEY_B64=vapid-priv:latest,WATCHDOG_HMAC_SECRET=aether-watchdog-hmac:latest,SYSTEM_AI_PRIV_B64=tm-system-ai-priv:latest,SYSTEM_AI_PUB_B64=tm-system-ai-pub:latest,TELCO_HMAC_SECRETS=aether-telco-hmac:latest,SMS_WEBHOOK_HMAC=aether-sms-webhook-hmac:latest"

URL="$(gcloud run services describe "${SERVICE}" --project="${PROJECT_ID}" --region="${REGION}" --format='value(status.url)')"

log "Deployed: ${URL}"

# Wave 2 (bg-sync-push) secret refs.
#
# VAPID keys for Web Push (RFC 8292). Used by server/tm/notify.js to
# sign the VAPID JWT and by the PWA to subscribe via pushManager. The
# subject is just a contact mailto so push providers can reach an
# operator on policy questions; it is not secret.
#
#   gcloud secrets create vapid-pub  --replication-policy=automatic
#   gcloud secrets create vapid-priv --replication-policy=automatic
#   # one-shot keypair generator (run locally, then load into Secret Manager):
#   node -e "const c=require('crypto');const k=c.generateKeyPairSync('ec',{namedCurve:'P-256'});const j=k.privateKey.export({format:'jwk'});const u=s=>Buffer.from(s,'base64url');const x=u(j.x),y=u(j.y),d=u(j.d);const pub=Buffer.concat([Buffer.from([0x04]),x,y]).toString('base64url');console.log('VAPID_PUB:',pub);console.log('VAPID_PRIV:',d.toString('base64url'))"
#   echo -n "$VAPID_PUB"  | gcloud secrets versions add vapid-pub  --data-file=-
#   echo -n "$VAPID_PRIV" | gcloud secrets versions add vapid-priv --data-file=-
#   gcloud secrets add-iam-policy-binding vapid-pub  --member="serviceAccount:${SA_EMAIL}" --role=roles/secretmanager.secretAccessor
#   gcloud secrets add-iam-policy-binding vapid-priv --member="serviceAccount:${SA_EMAIL}" --role=roles/secretmanager.secretAccessor
#
# Without these secrets the runtime generates an ephemeral pair on
# cold start and logs a WARNING; push will work for the lifetime of
# the instance only.

# Wave 2 (bg-sync-push) Firestore TTL setup.
#
# tm_clip_seen rows expire 24 h after creation. The collection is
# created lazily; provision the TTL policy once via:
#   gcloud firestore fields ttls update created_at \
#     --collection-group=tm_clip_seen \
#     --enable-ttl --project="${PROJECT_ID}" --database='(default)'
#
# tm_user_subscriptions rows expire 90 d after last_seen_at:
#   gcloud firestore fields ttls update last_seen_at \
#     --collection-group=tm_user_subscriptions \
#     --enable-ttl --project="${PROJECT_ID}" --database='(default)'

# TODO(criticality-dedup): provision Firestore composite index for
# tm_dispatches on (geohash7 ASC, received_at DESC). The dedup cluster
# scan in server/tm/dedupe.js queries by geohash bucket within a 15 min
# window and needs this composite to run efficiently. Until the index
# exists, findCluster catches the missing-index error and returns null
# so SOS persistence keeps working without dedup. Add via:
#   gcloud firestore indexes composite create \
#     --collection-group=tm_dispatches \
#     --field-config=field-path=geohash7,order=ascending \
#     --field-config=field-path=received_at,order=descending \
#     --project="${PROJECT_ID}" --database='(default)'

# Idle cost discipline: delete superseded Cloud Run revisions so we never
# accumulate billable references to old container images. Cloud Run does
# not bill inactive revisions, but they pin Artifact Registry image
# digests and prevent the cleanup policy from collecting them.
ACTIVE_REV="$(gcloud run services describe "${SERVICE}" --project="${PROJECT_ID}" --region="${REGION}" --format='value(status.traffic[0].revisionName)')"
log "Active revision: ${ACTIVE_REV}; cleaning up older revisions"
gcloud run revisions list --service="${SERVICE}" --project="${PROJECT_ID}" --region="${REGION}" --format='value(metadata.name)' \
  | grep -v "^${ACTIVE_REV}$" \
  | while read -r rev; do
      [[ -n "${rev}" ]] || continue
      gcloud run revisions delete "${rev}" --project="${PROJECT_ID}" --region="${REGION}" --quiet >/dev/null 2>&1 \
        && log "  deleted ${rev}" || true
    done

log "Smoke test: bash test/smoke.sh ${URL}"
echo "${URL}"

# Wave 3 (phone-identity) secret refs.
#
# TELCO_HMAC_SECRETS: comma-separated `name:base64secret` pairs the
# server uses to verify X-Telco-Sig headers (one secret per partner
# telco: Jio, Airtel, Vi, BSNL). Stored as a single Secret Manager
# blob so rotation hits all telcos in lockstep.
#
#   gcloud secrets create aether-telco-hmac --replication-policy=automatic
#   echo -n "jio:$JIO_B64,airtel:$AIRTEL_B64,vi:$VI_B64,bsnl:$BSNL_B64" \
#     | gcloud secrets versions add aether-telco-hmac --data-file=-
#   gcloud secrets add-iam-policy-binding aether-telco-hmac \
#     --member="serviceAccount:${SA_EMAIL}" --role=roles/secretmanager.secretAccessor
#
# SMS_WEBHOOK_HMAC: shared secret with the inbound shortcode webhook
# sender. The telco / aggregator computes HMAC-SHA256(secret, body)
# and sends the base64 sig in X-Sms-Webhook-Sig.
#
#   gcloud secrets create aether-sms-webhook-hmac --replication-policy=automatic
#   python3 -c "import secrets,sys; sys.stdout.write(secrets.token_urlsafe(48))" \
#     | gcloud secrets versions add aether-sms-webhook-hmac --data-file=-
#
# OTP provider keys (env-only; rotates outside the deploy cadence):
#   MSG91_API_KEY, KARIX_API_KEY,
#   TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM
# Pass these on the command line of deploy.sh to enable each provider.
#
# tm_otp_pending TTL (5 min): row ttl_at field is enforced by Firestore TTL.
#   gcloud firestore fields ttls update ttl_at \
#     --collection-group=tm_otp_pending \
#     --enable-ttl --project="${PROJECT_ID}" --database='(default)'
#
# tm_phone_bindings TTL (30 d): expires_at field.
#   gcloud firestore fields ttls update expires_at \
#     --collection-group=tm_phone_bindings \
#     --enable-ttl --project="${PROJECT_ID}" --database='(default)'
