# USG Unified Communications SBC - Multi-stage Dockerfile (Iron Bank base)
#
# Builds an optimized, hardened container image for the SBC daemon. All stages
# derive from the Iron Bank (Platform One) hardened Alpine base; pulling it
# requires authenticating to registry1.dso.mil (the release workflow does this
# with the org secrets REPO1_USER / REPO1).
#
# Build (CI handles registry auth):
#   docker build -t sbc-daemon:latest .
# Run:
#   docker run -p 5060:5060/udp -p 8443:8443 sbc-daemon:latest
#
# Alpine => musl. The Rust binaries are built statically against musl on the
# same architecture as the target (the release workflow builds each arch on a
# native runner), so no cross-compilation is involved.
#
# NOTE on FIPS: uc-crypto enables aws-lc-rs/fips by default, which compiles
# aws-lc-fips-sys from source (needs go + cmake + perl + a C toolchain). If the
# FIPS backend ever fails to build on musl, build with FIPS disabled by adding
# `--no-default-features` handling to uc-crypto, or switch the runtime to a
# hardened glibc Iron Bank base (e.g. ubi9-micro). A from-source rebuild is not
# itself FIPS-validated regardless of base.
#
# ## NIST 800-53 Rev5 Controls
# - **CM-2**: Baseline Configuration - Iron Bank hardened base image
# - **CM-7**: Least Functionality - Only required binaries installed
# - **SC-28**: Protection of Information at Rest - No secrets in image

ARG IRONBANK_ALPINE=registry1.dso.mil/ironbank/opensource/alpinelinux/alpine:3.24

# =============================================================================
# Stage 1: Build dashboard (Vite + React -> dist/sbc-dashboard/browser, the
# path baked into sbc-daemon's include_dir!).
# =============================================================================
FROM ${IRONBANK_ALPINE} AS dashboard

RUN apk add --no-cache nodejs npm
WORKDIR /app
COPY crates/sbc/sbc-dashboard/package.json crates/sbc/sbc-dashboard/package-lock.json* ./
RUN npm ci --prefer-offline --no-audit --no-fund
COPY crates/sbc/sbc-dashboard/ ./
RUN npm run build

# =============================================================================
# Stage 2: Build Rust binaries (static musl)
# =============================================================================
FROM ${IRONBANK_ALPINE} AS builder

# Toolchain + build deps. go/cmake/perl/clang are required by aws-lc-fips-sys;
# build-base/musl-dev provide the C/C++ toolchain; protoc for the gRPC build.rs.
RUN apk add --no-cache \
    rustup \
    build-base \
    musl-dev \
    linux-headers \
    cmake \
    make \
    perl \
    go \
    clang \
    protoc \
    protobuf-dev \
    pkgconf \
    openssl-dev \
    git

WORKDIR /app

# Install the toolchain pinned by rust-toolchain.toml on the musl host triple.
COPY rust-toolchain.toml ./
RUN rustup-init -y --no-modify-path --profile minimal \
    && . "$HOME/.cargo/env" \
    && rustup show
ENV PATH="/root/.cargo/bin:${PATH}"

# Copy workspace and build.
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY audio_files/ audio_files/
COPY --from=dashboard /app/dist/ crates/sbc/sbc-dashboard/dist/

# Build the release binaries. The musl host target links the C runtime
# statically; aws-lc is built from source via the deps installed above.
RUN cargo build --release --package sbc-daemon --package sbc-cli

# =============================================================================
# Stage 3: Runtime
# =============================================================================
FROM ${IRONBANK_ALPINE} AS runtime

# Runtime deps: ca-certificates for TLS trust; libcap for setcap (privileged
# port binding when the API runs on :80); libgcc/libstdc++ for aws-lc's C++
# runtime; curl for the health check.
RUN apk add --no-cache \
    ca-certificates \
    libcap \
    libgcc \
    libstdc++ \
    curl

# Non-root user (busybox adduser/addgroup).
RUN addgroup -g 1000 sbc \
    && adduser -u 1000 -G sbc -D -s /bin/sh sbc \
    && mkdir -p /etc/sbc /var/lib/sbc /var/log/sbc \
    && chown -R sbc:sbc /etc/sbc /var/lib/sbc /var/log/sbc

# Binaries + default config.
COPY --from=builder /app/target/release/sbc-daemon /usr/local/bin/
COPY --from=builder /app/target/release/sbc-cli /usr/local/bin/
COPY deploy/config/config.toml /etc/sbc/config.toml

# Grant CAP_NET_BIND_SERVICE as a file capability so the non-root user can bind
# privileged ports (e.g. the API on :80 in the provisioning configuration)
# without ambient pod capabilities.
RUN chown sbc:sbc /usr/local/bin/sbc-daemon /usr/local/bin/sbc-cli \
    && setcap 'cap_net_bind_service=+ep' /usr/local/bin/sbc-daemon

USER sbc

# Signaling: SIP UDP/TCP 5060, TLS 5061. Management: API HTTPS 8443 (default),
# HTTP 80 only when api.insecure_http is opted in (e.g. phone provisioning).
EXPOSE 5060/udp
EXPOSE 5060/tcp
EXPOSE 5061/tcp
EXPOSE 80/tcp
EXPOSE 8443/tcp
# Media (RTP/SRTP):
EXPOSE 16384-32768/udp

# Health check hits the unauthenticated /healthz over the default HTTPS API
# (self-signed bootstrap cert -> -k). The old `sbc-cli health` check no longer
# works: the CLI now requires an authenticated daemon connection.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsSk https://127.0.0.1:8443/healthz || exit 1

WORKDIR /var/lib/sbc

ENTRYPOINT ["/usr/local/bin/sbc-daemon"]
CMD ["-c", "/etc/sbc/config.toml", "-f"]
