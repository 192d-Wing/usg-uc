# syntax=docker/dockerfile:1.7
# sbc-announcement-server — announcement playback pod.
#
# Hosts the gRPC AnnouncementService: the daemon delegates announcement
# media here (SBC_ANNOUNCEMENT_URL); the pod binds the RTP socket,
# streams the PCMU announcement to the caller, and reports completion.
# Stateless; the daemon falls back to in-process playback when this pod
# is unreachable. Same cargo-chef shape as sbc-client-config-server's
# Dockerfile, plus protobuf for tonic/prost codegen (sbc-grpc-api).
#
# Build (from repo root):
#   docker build -t usg-sbc-announcement-server:local \
#     -f crates/sbc/sbc-announcement-server/Dockerfile .

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
COPY audio_files/ audio_files/

RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS cacher

COPY --from=planner /app/recipe.json recipe.json

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo chef cook --release --recipe-path recipe.json \
    --package sbc-announcement-server

FROM chef AS builder

COPY --from=cacher /app/target /app/target

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
# Embedded announcement audio (include_dir in sbc-announcement).
COPY audio_files/ audio_files/

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build --release --package sbc-announcement-server \
    && cp target/release/sbc-announcement-server /tmp/sbc-announcement-server

FROM alpine:3.21 AS runtime

RUN apk add --no-cache ca-certificates \
    && addgroup -g 1000 sbc \
    && adduser -D -u 1000 -G sbc -s /bin/sh sbc

COPY --from=builder /tmp/sbc-announcement-server /usr/local/bin/sbc-announcement-server

USER sbc

# gRPC control plane; RTP uses ephemeral UDP ports unless
# SBC_ANN_RTP_PORT_MIN/MAX pins a range (expose that range in k8s).
EXPOSE 9095/tcp

ENTRYPOINT ["/usr/local/bin/sbc-announcement-server"]
