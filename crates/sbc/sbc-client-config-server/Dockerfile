# syntax=docker/dockerfile:1.7
# sbc-client-config-server — soft-client discovery + provisioning pod.
#
# Serves /.well-known/sip-client-config and /v1/client-config (OIDC
# bearer-token authorized). Stateless; builds standalone so soft-client
# sign-in rolls and recovers independently of the daemon. Same
# cargo-chef shape as sbc-provision-server's Dockerfile.
#
# Builder and runtime follow the root Dockerfile: glibc (Debian) with Go.
# This binary does not link aws-lc-fips today; the shared toolchain keeps a
# FIPS crypto dependency buildable here (aws-lc-fips-sys does not build on
# musl). Do NOT change to Alpine;
# ci/check-dockerfiles-fips.sh fails CI on an Alpine/musl Rust builder.
#
# Build (from repo root):
#   docker build -t usg-sbc-client-config-server:local -f crates/sbc/sbc-client-config-server/Dockerfile .

# =============================================================================
# Stage 1: Rust toolchain + build-deps + cargo-chef.
# =============================================================================
FROM rust:1-bookworm AS chef

# cmake + Go for aws-lc-fips-sys (the FIPS module build needs both);
# pkg-config for native build scripts.
# No openssl: the binary is rustls-only.
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    golang \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo install --locked cargo-chef

WORKDIR /app

# =============================================================================
# Stage 2: Cook just the deps the sbc-client-config-server binary needs.
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
        --package sbc-client-config-server

# =============================================================================
# Stage 3: Build the binary against the cooked deps.
# =============================================================================
FROM chef AS builder

COPY --from=cacher /app/target /app/target

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build --release --package sbc-client-config-server \
    && cp target/release/sbc-client-config-server /tmp/sbc-client-config-server

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

COPY --from=builder /tmp/sbc-client-config-server /usr/local/bin/sbc-client-config-server

# CAP_NET_BIND_SERVICE for binding :80 as a non-root user.
# libcap2-bin is only needed for setcap; it is purged in the same layer.
RUN chown sbc:sbc /usr/local/bin/sbc-client-config-server \
    && setcap 'cap_net_bind_service=+ep' /usr/local/bin/sbc-client-config-server \
    && apt-get purge -y --auto-remove libcap2-bin \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb

USER sbc

EXPOSE 80/tcp

ENTRYPOINT ["/usr/local/bin/sbc-client-config-server"]
