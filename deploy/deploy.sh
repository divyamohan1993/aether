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
  --project="${PROJECT_ID}" >/dev/null

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
for role in roles/aiplatform.user roles/logging.logWriter roles/cloudtrace.agent; do
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
  --set-env-vars="GCP_PROJECT=${PROJECT_ID},VERTEX_REGION=${VERTEX_REGION},VERTEX_MODEL=${VERTEX_MODEL},NODE_ENV=production,LOG_LEVEL=info,FIRESTORE_DB=(default),TM_BOOTSTRAP_ALLOW=${TM_BOOTSTRAP_ALLOW:-0}" \
  --set-secrets="TM_SERVER_PUB_B64=tm-server-pub:latest,TM_SERVER_PRIV_B64=tm-server-priv:latest"

URL="$(gcloud run services describe "${SERVICE}" --project="${PROJECT_ID}" --region="${REGION}" --format='value(status.url)')"

log "Deployed: ${URL}"

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
