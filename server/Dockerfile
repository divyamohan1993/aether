# Aether · Cloud Run runtime image. Multi-stage to keep prod layers tiny.
# syntax=docker/dockerfile:1.7

FROM node:22-alpine AS deps
WORKDIR /app
COPY server/package.json ./package.json
RUN npm install --omit=dev --no-audit --no-fund --no-package-lock \
 && rm -rf /root/.npm /tmp/* \
 && find node_modules -name "*.md" -delete \
 && find node_modules -name "*.ts" -delete \
 && find node_modules -name "*.map" -delete \
 && find node_modules -type d -name "test" -exec rm -rf {} + 2>/dev/null || true \
 && find node_modules -type d -name "tests" -exec rm -rf {} + 2>/dev/null || true \
 && find node_modules -type d -name "__tests__" -exec rm -rf {} + 2>/dev/null || true \
 && find node_modules -type d -name "docs" -exec rm -rf {} + 2>/dev/null || true \
 && find node_modules -type d -name "examples" -exec rm -rf {} + 2>/dev/null || true

FROM node:22-alpine AS runtime
ENV NODE_ENV=production \
    NODE_OPTIONS="--enable-source-maps=false" \
    PORT=8080 \
    GCP_PROJECT=dmjone \
    VERTEX_REGION=us-central1 \
    VERTEX_MODEL=gemini-2.5-flash \
    WEB_DIR=/app/web

RUN apk add --no-cache tini \
 && mkdir -p /app/web \
 && chown -R node:node /app

WORKDIR /app
COPY --chown=node:node --from=deps /app/node_modules ./node_modules
COPY --chown=node:node server/server.js ./server.js
COPY --chown=node:node server/package.json ./package.json
COPY --chown=node:node web/ ./web/

USER node
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/sbin/tini","--"]
CMD ["node","server.js"]
