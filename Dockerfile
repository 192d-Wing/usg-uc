# syntax=docker/dockerfile:1.7
# USG Unified Communications SBC - Multi-stage Dockerfile
#
# Optimized for fast incremental rebuilds:
#  - cargo-chef separates dependency compilation from workspace compilation,
#    so source-only changes don't re-build crates.io deps.
#  - BuildKit cache mounts on /usr/local/cargo/registry and /app/target
#    persist Rust build artifacts across builds.
#
# Build: docker build -t sbc-daemon:latest .  (or: podman build ...)
# Run:   docker run -p 5060:5060/udp -p 80:80 sbc-daemon:latest
#
# ## NIST 800-53 Rev5 Controls
# - **CM-2**: Baseline Configuration - Minimal base image with defined packages
# - **CM-7**: Least Functionality - Only required binaries installed
# - **SC-28**: Protection of Information at Rest - No secrets in image

# =============================================================================
# Stage 1: Build dashboard (Vite + React, output to dist/sbc-dashboard/browser
# to match the path baked into sbc-daemon's include_dir!).
# =============================================================================
FROM node:22-bookworm-slim AS dashboard

WORKDIR /app
COPY crates/sbc/sbc-dashboard/package.json crates/sbc/sbc-dashboard/package-lock.json* ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --prefer-offline
COPY crates/sbc/sbc-dashboard/ ./
RUN npm run build

# =============================================================================
# Stage 2a: Rust toolchain + build-deps + cargo-chef. Shared base for the
# planner / cacher / builder stages so the apt-install + cargo-install
# layers cache once.
# =============================================================================
FROM rust:1.85-bookworm AS chef

# Install build dependencies (Go required for aws-lc-fips-sys)
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    pkg-config \
    libssl-dev \
    golang \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo install --locked cargo-chef

WORKDIR /app

# =============================================================================
# Stage 2b: Compute a dependency-only recipe from Cargo.toml + Cargo.lock.
# Any workspace source change still produces the same recipe.json, so the
# downstream cacher stage stays cached.
# =============================================================================
FROM chef AS planner

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/

RUN cargo chef prepare --recipe-path recipe.json

# =============================================================================
# Stage 2c: Cook (= compile) just the dependencies. This layer is reused on
# every rebuild where Cargo.lock + crate manifests are unchanged.
# =============================================================================
FROM chef AS cacher

COPY --from=planner /app/recipe.json recipe.json

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo chef cook --release --recipe-path recipe.json \
        --package sbc-daemon --package sbc-cli

# =============================================================================
# Stage 2d: Build the workspace binaries. With cached deps in /app/target,
# source-only changes recompile only the changed crates.
# =============================================================================
FROM chef AS builder

# Bring the cooked target tree forward. The cache mount below keeps fingerprints
# fresh on rebuilds, but the COPY ensures we have a non-cache baseline so the
# binaries can be extracted in the final stage even when BuildKit cache misses.
COPY --from=cacher /app/target /app/target

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
COPY audio_files/ audio_files/

# Copy built dashboard into the location include_dir! expects.
COPY --from=dashboard /app/dist/ crates/sbc/sbc-dashboard/dist/

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target,sharing=locked \
    cargo build --release --package sbc-daemon --package sbc-cli \
    && cp target/release/sbc-daemon /tmp/sbc-daemon \
    && cp target/release/sbc-cli /tmp/sbc-cli

# =============================================================================
# Stage 3: Runtime
# =============================================================================
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies. libcap2-bin provides `setcap` so the
# non-root daemon can bind to privileged ports (e.g. HTTP :80).
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN groupadd --gid 1000 sbc \
    && useradd --uid 1000 --gid sbc --shell /bin/bash --create-home sbc

# Create directories
RUN mkdir -p /etc/sbc /var/lib/sbc /var/log/sbc \
    && chown -R sbc:sbc /etc/sbc /var/lib/sbc /var/log/sbc

# Copy binaries from builder (we cp'd them out of the cache-mounted target dir
# in the builder stage so this COPY survives cache misses).
COPY --from=builder /tmp/sbc-daemon /usr/local/bin/
COPY --from=builder /tmp/sbc-cli /usr/local/bin/

# Copy default configuration
COPY deploy/config/config.toml /etc/sbc/config.toml

# Set ownership and grant CAP_NET_BIND_SERVICE as a file capability so the
# non-root user (UID 1000) can bind to privileged ports without needing
# ambient capabilities at the pod level.
RUN chown -R sbc:sbc /usr/local/bin/sbc-daemon /usr/local/bin/sbc-cli \
    && setcap 'cap_net_bind_service=+ep' /usr/local/bin/sbc-daemon

# Switch to non-root user
USER sbc

# Expose ports
# Signaling interface:
EXPOSE 5060/udp
EXPOSE 5060/tcp
EXPOSE 5061/tcp
EXPOSE 80/tcp
EXPOSE 443/tcp
EXPOSE 9090/tcp
# Media interface (RTP/SRTP):
EXPOSE 16384-32768/udp

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/sbc-cli", "health", "--quiet"] || exit 1

# Set working directory
WORKDIR /var/lib/sbc

# Default command
ENTRYPOINT ["/usr/local/bin/sbc-daemon"]
CMD ["-c", "/etc/sbc/config.toml", "-f"]
