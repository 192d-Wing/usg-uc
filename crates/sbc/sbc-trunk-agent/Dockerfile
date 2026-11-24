# syntax=docker/dockerfile:1.7
# sbc-trunk-agent — trunk maintenance pod.
#
# Runs the SIP OPTIONS health monitor and outbound carrier-registration
# loops outside the daemon (daemon runs with SBC_TRUNK_SERVICES=external).
# Reads trunk configuration from Postgres and publishes status snapshots
# to the daemon's gRPC TrunkStatusPublishService. Deploy exactly ONE
# replica: two agents would double-REGISTER to carriers.
#
# Builder and runtime follow the root Dockerfile: glibc (Debian) with Go,
# because the binary links the FIPS-validated aws-lc module and
# aws-lc-fips-sys does not build on musl. Do NOT change to Alpine;
# ci/check-dockerfiles-fips.sh fails CI on an Alpine/musl Rust builder.
#
# Build (from repo root):
#   docker build -t usg-sbc-trunk-agent:local -f crates/sbc/sbc-trunk-agent/Dockerfile .

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
# Stage 2: Cook just the deps the sbc-trunk-agent binary needs.
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
        --package sbc-trunk-agent

# =============================================================================
# Stage 3: Build the binary against the cooked deps.
# =============================================================================
FROM chef AS builder

COPY --from=cacher /app/target /app/target

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build --release --package sbc-trunk-agent \
    && cp target/release/sbc-trunk-agent /tmp/sbc-trunk-agent

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
    && groupadd --gid 1000 sbc \
    && useradd --uid 1000 --gid sbc --shell /usr/sbin/nologin --no-create-home sbc

COPY --from=builder /tmp/sbc-trunk-agent /usr/local/bin/sbc-trunk-agent

# CAP_NET_BIND_SERVICE: the registrar/monitor bind local UDP :5060 when
# SBC_TRUNK_BIND_IP is set, so the carrier's NAT mapping matches.
# libcap2-bin is only needed for setcap; it is purged in the same layer.
RUN chown sbc:sbc /usr/local/bin/sbc-trunk-agent \
    && setcap 'cap_net_bind_service=+ep' /usr/local/bin/sbc-trunk-agent \
    && apt-get purge -y --auto-remove libcap2-bin \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb

USER sbc

# gRPC health probes.
EXPOSE 9096/tcp

ENTRYPOINT ["/usr/local/bin/sbc-trunk-agent"]
