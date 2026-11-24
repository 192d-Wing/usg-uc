# syntax=docker/dockerfile:1.7
# sbc-config-sync — the per-site agent that pulls its shard from the central
# config plane and applies it into the site-local Postgres (and refreshes the
# daemon over gRPC). Runs as a sidecar/Deployment at each base.
#
# Connects outbound only (HTTPS to central, gRPC to the local daemon,
# Postgres to the local shard); binds no listening port.
#
# Builder and runtime follow the root Dockerfile: glibc (Debian) with Go,
# because the binary links the FIPS-validated aws-lc module and
# aws-lc-fips-sys does not build on musl. Do NOT change to Alpine;
# ci/check-dockerfiles-fips.sh fails CI on an Alpine/musl Rust builder.
#
# Build (from repo root):
#   docker build -t usg-sbc-config-sync:local -f crates/sbc/sbc-config-sync/Dockerfile .

# =============================================================================
# Stage 1: Rust toolchain + build-deps + cargo-chef.
# =============================================================================
FROM rust:1-bookworm AS chef

# cmake + Go for aws-lc-fips-sys (the FIPS module build needs both);
# pkg-config for native build scripts.
# protobuf for the tonic/prost gRPC codegen.
# No openssl: the binary is rustls-only.
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    golang \
    libprotobuf-dev \
    pkg-config \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo install --locked cargo-chef

WORKDIR /app

# =============================================================================
# Stage 2: Cook just the deps the sbc-config-sync binary needs.
# =============================================================================
FROM chef AS planner

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
# central-config-store (a dependency) embeds these via sqlx::migrate!.
COPY deploy/central-db deploy/central-db

RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS cacher

COPY --from=planner /app/recipe.json recipe.json

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo chef cook --release --recipe-path recipe.json \
        --package sbc-config-sync

# =============================================================================
# Stage 3: Build the binary against the cooked deps.
# =============================================================================
FROM chef AS builder

COPY --from=cacher /app/target /app/target

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
# central-config-store (a dependency) embeds these via sqlx::migrate!.
COPY deploy/central-db deploy/central-db

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build --release --package sbc-config-sync \
    && cp target/release/sbc-config-sync /tmp/sbc-config-sync

# =============================================================================
# Stage 4: Runtime — same pinned Debian trixie-slim as the root Dockerfile.
# ca-certificates: outbound HTTPS clients verify against the OS roots.
# =============================================================================
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS runtime

# NB: the user/group is not 'sync': that is a reserved system account in
# Debian (and Alpine).
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean \
    && groupadd --gid 1000 configsync \
    && useradd --uid 1000 --gid configsync --shell /usr/sbin/nologin --no-create-home configsync

COPY --from=builder /tmp/sbc-config-sync /usr/local/bin/sbc-config-sync

USER configsync

ENTRYPOINT ["/usr/local/bin/sbc-config-sync"]
