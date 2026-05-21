# syntax=docker/dockerfile:1.7
# USG SBC operator dashboard — nginx-served React SPA.
#
# Runs in its own Deployment so dashboard releases roll independently of the
# SBC daemon (and therefore do not interrupt SIP / RTP). The nginx config
# proxies /api/* and /provision/* upstream to the daemon's in-cluster
# ClusterIP Service, so the browser sees a single origin.
#
# Build (from repo root):
#   docker build -t sbc-frontend:local -f crates/sbc/sbc-dashboard/Dockerfile crates/sbc/sbc-dashboard/

# =============================================================================
# Stage 1: Build the SPA bundle.
# =============================================================================
FROM node:22-bookworm-slim AS build

WORKDIR /app
COPY package.json package-lock.json* ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --prefer-offline
COPY . .
RUN npm run build

# =============================================================================
# Stage 2: Runtime — nginx serving the static bundle and proxying API paths.
# =============================================================================
FROM nginxinc/nginx-unprivileged:1.27-alpine AS runtime

# Template, not final config — entrypoint envsubst's $SBC_API_UPSTREAM in
# at container start so the upstream Service name can be set per-deploy
# (typically the Helm-rendered "<release>-api" ClusterIP Service).
COPY nginx.conf.template /etc/nginx/templates/default.conf.template

COPY --from=build /app/dist/sbc-dashboard/browser /usr/share/nginx/html

# nginx-unprivileged listens on 8080 by default (non-root). The Helm Service
# maps external 80 -> targetPort 8080.
EXPOSE 8080

# nginx-unprivileged base image already sets USER nginx (uid 101).
