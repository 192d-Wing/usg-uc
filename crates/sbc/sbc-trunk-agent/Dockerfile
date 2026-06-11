# syntax=docker/dockerfile:1.7
# sbc-trunk-agent — trunk maintenance pod.
#
# Runs the SIP OPTIONS health monitor and outbound carrier-registration
# loops outside the daemon (daemon runs with SBC_TRUNK_SERVICES=external).
# Reads trunk configuration from Postgres and publishes status snapshots
# to the daemon's gRPC TrunkStatusPublishService. Deploy exactly ONE
# replica: two agents would double-REGISTER to carriers.
#
# Build (from repo root):
#   docker build -t usg-sbc-trunk-agent:local \
#     -f crates/sbc/sbc-trunk-agent/Dockerfile .

FROM rust:1-alpine AS chef

# build-base = gcc/make/musl-dev — aws-lc-sys (the non-FIPS aws-lc-rs
# backend behind rustls/tonic TLS) compiles C and needs cmake; perl for
# its assembly generation; protobuf for the gRPC codegen in sbc-grpc-api.
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

FROM chef AS planner

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/

RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS cacher

COPY --from=planner /app/recipe.json recipe.json

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo chef cook --release --recipe-path recipe.json \
    --package sbc-trunk-agent

FROM chef AS builder

COPY --from=cacher /app/target /app/target

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build --release --package sbc-trunk-agent \
    && cp target/release/sbc-trunk-agent /tmp/sbc-trunk-agent

FROM alpine:3.21 AS runtime

RUN apk add --no-cache ca-certificates libcap \
    && addgroup -g 1000 sbc \
    && adduser -D -u 1000 -G sbc -s /bin/sh sbc

COPY --from=builder /tmp/sbc-trunk-agent /usr/local/bin/sbc-trunk-agent

# CAP_NET_BIND_SERVICE: the registrar/monitor bind local UDP :5060 when
# SBC_TRUNK_BIND_IP is set, so the carrier's NAT mapping matches.
RUN chown sbc:sbc /usr/local/bin/sbc-trunk-agent \
    && setcap 'cap_net_bind_service=+ep' /usr/local/bin/sbc-trunk-agent

USER sbc

# gRPC health probes.
EXPOSE 9096/tcp

ENTRYPOINT ["/usr/local/bin/sbc-trunk-agent"]
