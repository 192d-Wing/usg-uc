# syntax=docker/dockerfile:1.7
# sbc-api-server — REST front-door pod for the USG SBC.
#
# Built standalone so it can roll independently of the daemon image.
# Same cargo-chef shape as the daemon's Dockerfile, scoped to one
# binary so the dependency-cooking layer is much smaller.
#
# Builder and runtime follow the root Dockerfile: glibc (Debian) with Go,
# because the binary links the aws-lc FIPS module and
# aws-lc-fips-sys does not build on musl. Do NOT change to Alpine;
# ci/check-dockerfiles-fips.sh fails CI on an Alpine/musl Rust builder.
#
# Build (from repo root):
#   docker build -t usg-sbc-api-server:local -f crates/sbc/sbc-api-server/Dockerfile .

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

COPY --from=builder /tmp/sbc-api-server /usr/local/bin/sbc-api-server

# CAP_NET_BIND_SERVICE so the non-root user can bind to :80 (the
# default SBC_API_LISTEN_ADDR matches the daemon's old API port, so the
# nginx upstream stays the same shape post-cutover).
# libcap2-bin is only needed for setcap; it is purged in the same layer.
RUN chown sbc:sbc /usr/local/bin/sbc-api-server \
    && setcap 'cap_net_bind_service=+ep' /usr/local/bin/sbc-api-server \
    && apt-get purge -y --auto-remove libcap2-bin \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb

# No secrets are baked in. SBC_USER_HA1_KEY_FILE (required) must point at a
# mounted 64-hex-char key file, mode 0400, owned by uid 1000, e.g.
#   -v ./ha1-key:/run/secrets/sbc-ha1-key:ro -e SBC_USER_HA1_KEY_FILE=/run/secrets/sbc-ha1-key
USER sbc

EXPOSE 80/tcp

ENTRYPOINT ["/usr/local/bin/sbc-api-server"]
