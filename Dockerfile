# USG Unified Communications SBC - Multi-stage Dockerfile
#
# This Dockerfile builds an optimized container image for the SBC daemon.
# It uses a multi-stage build to minimize the final image size.
#
# Build: docker build -t sbc-daemon:latest .
# Run:   docker run -p 5060:5060/udp -p 8080:8080 sbc-daemon:latest
#
# ## NIST 800-53 Rev5 Controls
# - **CM-2**: Baseline Configuration - Minimal base image with defined packages
# - **CM-7**: Least Functionality - Only required binaries installed
# - **SC-28**: Protection of Information at Rest - No secrets in image

# =============================================================================
# Stage 1: Build Angular dashboard
# =============================================================================
FROM node:22-bookworm-slim AS dashboard

WORKDIR /app
COPY crates/sbc/sbc-dashboard/package.json crates/sbc/sbc-dashboard/package-lock.json* ./
RUN npm ci --prefer-offline
COPY crates/sbc/sbc-dashboard/ ./
RUN npx ng build --configuration=production

# =============================================================================
# Stage 2: Build Rust binaries
# =============================================================================
FROM rust:1.85-bookworm AS builder

# Install build dependencies (Go required for aws-lc-fips-sys)
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    pkg-config \
    libssl-dev \
    golang \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy workspace files
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/

# Copy built Angular dashboard into the location include_dir! expects
COPY --from=dashboard /app/dist/ crates/sbc/sbc-dashboard/dist/

# Build release binary (dashboard is embedded via include_dir!)
RUN cargo build --release --package sbc-daemon --package sbc-cli

# =============================================================================
# Stage 2: Runtime
# =============================================================================
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN groupadd --gid 1000 sbc \
    && useradd --uid 1000 --gid sbc --shell /bin/bash --create-home sbc

# Create directories
RUN mkdir -p /etc/sbc /var/lib/sbc /var/log/sbc \
    && chown -R sbc:sbc /etc/sbc /var/lib/sbc /var/log/sbc

# Copy binaries from builder
COPY --from=builder /app/target/release/sbc-daemon /usr/local/bin/
COPY --from=builder /app/target/release/sbc-cli /usr/local/bin/

# Copy default configuration
COPY deploy/config/config.toml /etc/sbc/config.toml

# Set ownership
RUN chown -R sbc:sbc /usr/local/bin/sbc-daemon /usr/local/bin/sbc-cli

# Switch to non-root user
USER sbc

# Expose ports
# Signaling interface:
EXPOSE 5060/udp
EXPOSE 5060/tcp
EXPOSE 5061/tcp
EXPOSE 8080/tcp
EXPOSE 8443/tcp
# Media interface (RTP/SRTP):
EXPOSE 16384-32768/udp

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/sbc-cli", "health", "--quiet"] || exit 1

# Set working directory
WORKDIR /var/lib/sbc

# Default command
ENTRYPOINT ["/usr/local/bin/sbc-daemon"]
CMD ["-c", "/etc/sbc/config.toml", "-f"]
