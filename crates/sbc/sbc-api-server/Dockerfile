# syntax=docker/dockerfile:1.7
# sbc-api-server — REST front-door pod for the USG SBC.
#
# Built standalone so it can roll independently of the daemon image.
# Same cargo-chef shape as the daemon's Dockerfile, scoped to one
# binary so the dependency-cooking layer is much smaller.
#
# Build (from repo root):
#   docker build -t usg-sbc-api-server:local -f crates/sbc/sbc-api-server/Dockerfile .

# =============================================================================
# Stage 1: Rust toolchain + build-deps + cargo-chef.
# =============================================================================
FROM rust:1-alpine AS chef

# build-base = gcc/make/musl-dev (native build deps); cmake + perl for
# aws-lc-sys; protobuf for the daemon gRPC client (tonic/prost codegen).
# No openssl: the binary is rustls-only.
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
# Stage 2: Cook just the deps the sbc-api-server binary needs.
# =============================================================================
FROM chef AS planner

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/

RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS cacher

COPY --from=planner /app/recipe.json recipe.json

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo chef cook --release --recipe-path recipe.json \
        --package sbc-api-server

# =============================================================================
# Stage 3: Build the binary against the cooked deps.
# =============================================================================
FROM chef AS builder

COPY --from=cacher /app/target /app/target

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build --release --package sbc-api-server \
    && cp target/release/sbc-api-server /tmp/sbc-api-server

# =============================================================================
# Stage 4: Runtime — alpine with the bare libs the binary needs.
# =============================================================================
FROM alpine:3.21 AS runtime

RUN apk add --no-cache ca-certificates libcap \
    && addgroup -g 1000 sbc \
    && adduser -D -u 1000 -G sbc -s /bin/sh sbc

COPY --from=builder /tmp/sbc-api-server /usr/local/bin/sbc-api-server

# CAP_NET_BIND_SERVICE so the non-root user can bind to :80 (the
# default SBC_API_LISTEN_ADDR matches the daemon's old API port, so the
# nginx upstream stays the same shape post-cutover).
RUN chown sbc:sbc /usr/local/bin/sbc-api-server \
    && setcap 'cap_net_bind_service=+ep' /usr/local/bin/sbc-api-server

USER sbc

EXPOSE 80/tcp

ENTRYPOINT ["/usr/local/bin/sbc-api-server"]
