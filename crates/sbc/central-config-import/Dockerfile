# syntax=docker/dockerfile:1.7
# central-config-import — one-shot site onboarding tool. Registers a site in
# the central config DB and imports its existing site-local Postgres config
# into the central shard. Run as a Kubernetes Job, not a long-lived service.
#
# Builder and runtime follow the root Dockerfile: glibc (Debian) with Go.
# This binary does not link aws-lc-fips today; the shared toolchain keeps a
# FIPS crypto dependency buildable here (aws-lc-fips-sys does not build on
# musl). Do NOT change to Alpine;
# ci/check-dockerfiles-fips.sh fails CI on an Alpine/musl Rust builder.
#
# Build (from repo root):
#   docker build -t usg-central-config-import:local -f crates/sbc/central-config-import/Dockerfile .

# =============================================================================
# Stage 1: Rust toolchain + build-deps + cargo-chef.
# =============================================================================
FROM rust:1-bookworm AS chef

# cmake + Go for aws-lc-fips-sys (the FIPS module build needs both);
# pkg-config for native build scripts.
# No openssl: the binary is rustls-only.
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    pkg-config \
    golang \
    && rm -rf /var/lib/apt/lists/*

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
# Stage 4: Runtime — same pinned Debian trixie-slim as the root Dockerfile.
# ca-certificates: outbound HTTPS clients verify against the OS roots.
# =============================================================================
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean \
    && groupadd --gid 1000 importer \
    && useradd --uid 1000 --gid importer --shell /usr/sbin/nologin --no-create-home importer

COPY --from=builder /tmp/central-config-import /usr/local/bin/central-config-import

USER importer

ENTRYPOINT ["/usr/local/bin/central-config-import"]
