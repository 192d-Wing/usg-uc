# syntax=docker/dockerfile:1.7
# central-config-api — the fleet's central configuration plane.
#
# Stateless HTTP service: operator write surface + per-site sync read
# surface over the central, site_code-sharded Postgres. Same cargo-chef
# shape as the other SBC binaries, scoped to this one package.
#
# Builder and runtime follow the root Dockerfile: glibc (Debian) with Go,
# because the binary links the FIPS-validated aws-lc module and
# aws-lc-fips-sys does not build on musl. Do NOT change to Alpine;
# ci/check-dockerfiles-fips.sh fails CI on an Alpine/musl Rust builder.
#
# Build (from repo root):
#   docker build -t usg-central-config-api:local -f crates/sbc/central-config-api/Dockerfile .

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
# Stage 2: Cook just the deps the central-config-api binary needs.
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
        --package central-config-api

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
    cargo build --release --package central-config-api \
    && cp target/release/central-config-api /tmp/central-config-api

# =============================================================================
# Stage 4: Runtime — same pinned Debian trixie-slim as the root Dockerfile.
# ca-certificates: outbound HTTPS clients verify against the OS roots.
# =============================================================================
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean \
    && groupadd --gid 1000 central \
    && useradd --uid 1000 --gid central --shell /usr/sbin/nologin --no-create-home central

COPY --from=builder /tmp/central-config-api /usr/local/bin/central-config-api

# CAP_NET_BIND_SERVICE so the non-root user can bind to :80
# (CENTRAL_API_LISTEN_ADDR defaults to 0.0.0.0:80).
# libcap2-bin is only needed for setcap; it is purged in the same layer.
RUN chown central:central /usr/local/bin/central-config-api \
    && setcap 'cap_net_bind_service=+ep' /usr/local/bin/central-config-api \
    && apt-get purge -y --auto-remove libcap2-bin \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb

USER central

EXPOSE 80/tcp

ENTRYPOINT ["/usr/local/bin/central-config-api"]
