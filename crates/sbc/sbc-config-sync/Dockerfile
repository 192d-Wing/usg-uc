# syntax=docker/dockerfile:1.7
# sbc-config-sync — the per-site agent that pulls its shard from the central
# config plane and applies it into the site-local Postgres (and refreshes the
# daemon over gRPC). Runs as a sidecar/Deployment at each base.
#
# Connects outbound only (HTTPS to central, gRPC to the local daemon,
# Postgres to the local shard); binds no listening port.
#
# Build (from repo root):
#   docker build -t usg-sbc-config-sync:local -f crates/sbc/sbc-config-sync/Dockerfile .

# =============================================================================
# Stage 1: Rust toolchain + build-deps + cargo-chef.
# =============================================================================
FROM rust:1-alpine AS chef

# build-base = gcc/make/musl-dev; cmake + perl for aws-lc-sys; protobuf for
# the daemon gRPC client (tonic/prost codegen). No openssl: rustls-only.
RUN apk add --no-cache \
    build-base \
    cmake \
    perl \
    pkgconfig \
    protobuf \
    protobuf-dev

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
# Stage 4: Runtime — alpine with the bare libs the binary needs.
# =============================================================================
FROM alpine:3.21 AS runtime

# NB: user/group must not be 'sync' — that's a reserved Alpine system
# account and `adduser sync` fails.
RUN apk add --no-cache ca-certificates \
    && addgroup -g 1000 configsync \
    && adduser -D -u 1000 -G configsync -s /bin/sh configsync

COPY --from=builder /tmp/sbc-config-sync /usr/local/bin/sbc-config-sync

USER configsync

ENTRYPOINT ["/usr/local/bin/sbc-config-sync"]
