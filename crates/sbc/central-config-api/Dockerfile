# syntax=docker/dockerfile:1.7
# central-config-api — the fleet's central configuration plane.
#
# Stateless HTTP service: operator write surface + per-site sync read
# surface over the central, site_code-sharded Postgres. Same cargo-chef
# shape as the other SBC binaries, scoped to this one package.
#
# Build (from repo root):
#   docker build -t usg-central-config-api:local -f crates/sbc/central-config-api/Dockerfile .

# =============================================================================
# Stage 1: Rust toolchain + build-deps + cargo-chef.
# =============================================================================
FROM rust:1-alpine AS chef

# build-base = gcc/make/musl-dev; cmake + perl for aws-lc-sys; protobuf for
# any tonic/prost codegen pulled transitively. No openssl: rustls-only.
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
# Stage 4: Runtime — alpine with the bare libs the binary needs.
# =============================================================================
FROM alpine:3.21 AS runtime

RUN apk add --no-cache ca-certificates libcap \
    && addgroup -g 1000 central \
    && adduser -D -u 1000 -G central -s /bin/sh central

COPY --from=builder /tmp/central-config-api /usr/local/bin/central-config-api

# CAP_NET_BIND_SERVICE so the non-root user can bind to :80
# (CENTRAL_API_LISTEN_ADDR defaults to 0.0.0.0:80).
RUN chown central:central /usr/local/bin/central-config-api \
    && setcap 'cap_net_bind_service=+ep' /usr/local/bin/central-config-api

USER central

EXPOSE 80/tcp

ENTRYPOINT ["/usr/local/bin/central-config-api"]
