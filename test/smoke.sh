#!/usr/bin/env bash
# Aether end-to-end smoke test against a deployed Cloud Run URL.
# Generates a 5-second WAV with synthesized speech (or a tone fallback),
# uploads it to /api/v1/triage, and prints the structured triage response.
set -euo pipefail

URL="${1:-${URL:-}}"
[[ -n "$URL" ]] || { echo "Usage: $0 <cloud-run-url>"; exit 1; }
URL="${URL%/}"

log()  { printf '\033[1;34m[smoke]\033[0m %s\n' "$*"; }

log "GET ${URL}/healthz"
curl -fsS "${URL}/healthz" && echo

log "GET ${URL}/ (home)"
curl -fsS -I "${URL}/" | head -10

log "Generating 5s test audio (16kHz mono WAV, simulated panic tone)"
TMP="$(mktemp /tmp/aether-XXXX.wav)"
trap 'rm -f "$TMP"' EXIT
python3 - "$TMP" <<'PY'
import struct, math, sys, random
sr=16000; dur=5; n=sr*dur
fp=open(sys.argv[1],'wb')
fp.write(b'RIFF'+struct.pack('<I',36+n*2)+b'WAVE')
fp.write(b'fmt '+struct.pack('<IHHIIHH',16,1,1,sr,sr*2,2,16))
fp.write(b'data'+struct.pack('<I',n*2))
random.seed(42)
for i in range(n):
    t=i/sr
    base=0.4*math.sin(2*math.pi*220*t)*math.exp(-2*((t%1)-0.5)**2)
    formant=0.2*math.sin(2*math.pi*880*t)*math.sin(2*math.pi*4*t)
    noise=0.05*(random.random()*2-1)
    s=int(max(-1,min(1,base+formant+noise))*32767)
    fp.write(struct.pack('<h',s))
fp.close()
PY

log "POST ${URL}/api/v1/triage (audio/wav)"
RESP="$(mktemp /tmp/aether-resp-XXXX.json)"
HTTP_CODE=$(curl -sS -o "$RESP" -w '%{http_code}' \
  -X POST "${URL}/api/v1/triage" \
  -H "Content-Type: audio/wav" \
  -H "X-Client-Id: smoke-$(date +%s)" \
  -H "X-Client-Lang: en-IN" \
  -H "X-Client-Network: 2g" \
  --data-binary "@${TMP}")

log "HTTP ${HTTP_CODE}"
if command -v jq >/dev/null 2>&1; then
  jq . "$RESP" || cat "$RESP"
else
  cat "$RESP"; echo
fi
rm -f "$RESP"

[[ "$HTTP_CODE" == "200" ]] || { echo "Smoke test failed."; exit 1; }
log "OK"
