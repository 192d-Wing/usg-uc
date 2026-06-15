# syntax=docker/dockerfile:1.7
# central-config-import — one-shot site onboarding tool. Registers a site in
# the central config DB and imports its existing site-local Postgres config
# into the central shard. Run as a Kubernetes Job, not a long-lived service.
#
# Build (from repo root):
#   docker build -t usg-central-config-import:local -f crates/sbc/central-config-import/Dockerfile .

# =============================================================================
# Stage 1: Rust toolchain + build-deps + cargo-chef.
# =============================================================================
FROM rust:1-alpine AS chef

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
# Stage 2: Cook just the deps the central-config-import binary needs.
# =============================================================================
FROM chef AS planner

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
# central-config-store embeds these via sqlx::migrate! at compile time.
COPY deploy/central-db deploy/central-db

RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS cacher

COPY --from=planner /app/recipe.json recipe.json

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo chef cook --release --recipe-path recipe.json \
        --package central-config-import

# =============================================================================
# Stage 3: Build the binary against the cooked deps.
# =============================================================================
FROM chef AS builder

COPY --from=cacher /app/target /app/target

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
# central-config-store embeds these via sqlx::migrate! at compile time.
COPY deploy/central-db deploy/central-db

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build --release --package central-config-import \
    && cp target/release/central-config-import /tmp/central-config-import

# =============================================================================
# Stage 4: Runtime — alpine with the bare libs the binary needs.
# =============================================================================
FROM alpine:3.21 AS runtime

RUN apk add --no-cache ca-certificates \
    && addgroup -g 1000 importer \
    && adduser -D -u 1000 -G importer -s /bin/sh importer

COPY --from=builder /tmp/central-config-import /usr/local/bin/central-config-import

USER importer

ENTRYPOINT ["/usr/local/bin/central-config-import"]
