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
# Builder and runtime follow the root Dockerfile: glibc (Debian) with Go,
# because the binary links the FIPS-validated aws-lc module and
# aws-lc-fips-sys does not build on musl. Do NOT change to Alpine;
# ci/check-dockerfiles-fips.sh fails CI on an Alpine/musl Rust builder.
#
# Build (from repo root):
#   docker build -t usg-sbc-announcement-server:local -f crates/sbc/sbc-announcement-server/Dockerfile .

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
    pkg-config \
    golang \
    protobuf-compiler \
    libprotobuf-dev \
    && rm -rf /var/lib/apt/lists/*

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo install --locked cargo-chef

WORKDIR /app

# =============================================================================
# Stage 2: Cook just the deps the sbc-announcement-server binary needs.
# =============================================================================
FROM chef AS planner

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
# Embedded announcement audio (include_dir in sbc-announcement).
COPY audio_files/ audio_files/

RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS cacher

COPY --from=planner /app/recipe.json recipe.json

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo chef cook --release --recipe-path recipe.json \
        --package sbc-announcement-server

# =============================================================================
# Stage 3: Build the binary against the cooked deps.
# =============================================================================
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

# =============================================================================
# Stage 4: Runtime — same pinned Debian trixie-slim as the root Dockerfile.
# ca-certificates: outbound HTTPS clients verify against the OS roots.
# =============================================================================
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean \
    && groupadd --gid 1000 sbc \
    && useradd --uid 1000 --gid sbc --shell /usr/sbin/nologin --no-create-home sbc

COPY --from=builder /tmp/sbc-announcement-server /usr/local/bin/sbc-announcement-server

USER sbc

# gRPC control plane; RTP uses ephemeral UDP ports unless
# SBC_ANN_RTP_PORT_MIN/MAX pins a range (expose that range in k8s).
EXPOSE 9095/tcp

ENTRYPOINT ["/usr/local/bin/sbc-announcement-server"]
