# syntax=docker/dockerfile:1.7
# sbc-provision-server — phone provisioning HTTP pod.
#
# Builds standalone so phone-provisioning rolls and recovers
# independently of the daemon and sbc-api. Same cargo-chef shape as
# sbc-api-server's Dockerfile.
#
# Build (from repo root):
#   docker build -t usg-sbc-provision-server:local \
#     -f crates/sbc/sbc-provision-server/Dockerfile .

FROM rust:1-alpine AS chef

# build-base = gcc/make/musl-dev (native build deps); cmake + perl for
# aws-lc-sys. No openssl: the binary is rustls-only.
RUN apk add --no-cache \
    build-base \
    cmake \
    perl \
    pkgconfig

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo install --locked cargo-chef

WORKDIR /app

FROM chef AS planner

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/

RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS cacher

COPY --from=planner /app/recipe.json recipe.json

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo chef cook --release --recipe-path recipe.json \
        --package sbc-provision-server

FROM chef AS builder

COPY --from=cacher /app/target /app/target

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build --release --package sbc-provision-server \
    && cp target/release/sbc-provision-server /tmp/sbc-provision-server

FROM alpine:3.21 AS runtime

RUN apk add --no-cache ca-certificates libcap \
    && addgroup -g 1000 sbc \
    && adduser -D -u 1000 -G sbc -s /bin/sh sbc

COPY --from=builder /tmp/sbc-provision-server /usr/local/bin/sbc-provision-server

# CAP_NET_BIND_SERVICE for binding :80 as a non-root user.
RUN chown sbc:sbc /usr/local/bin/sbc-provision-server \
    && setcap 'cap_net_bind_service=+ep' /usr/local/bin/sbc-provision-server

USER sbc

EXPOSE 80/tcp

ENTRYPOINT ["/usr/local/bin/sbc-provision-server"]
