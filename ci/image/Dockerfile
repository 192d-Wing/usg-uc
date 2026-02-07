# GitLab CI Docker Image for USG Unified Communications
#
# This image includes all dependencies required for CI/CD pipeline:
# - Rust toolchain
# - Go (required for FIPS)
# - cmake (required for build)
# - Common cargo tools pre-installed
#
# Build: docker build -t registry.gitlab.com/<your-group>/<your-project>/ci-image:latest .
# Push:  docker push registry.gitlab.com/<your-group>/<your-project>/ci-image:latest

FROM rust:1.93-trixie

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive \
    GO_VERSION=1.25.7 \
    CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build essentials
    build-essential \
    cmake \
    pkg-config \
    # SSL/TLS libraries
    libssl-dev \
    ca-certificates \
    # Utilities
    curl \
    git \
    # Clean up
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Install Go (required for FIPS)
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o go.tar.gz \
    && tar -C /usr/local -xzf go.tar.gz \
    && rm go.tar.gz

# Add Go to PATH
ENV PATH="/usr/local/go/bin:${PATH}" \
    GOPATH="/go" \
    GOCACHE="/go/cache"

# Create Go workspace
RUN mkdir -p /go/bin /go/cache && chmod -R 777 /go

# Install Rust components
RUN rustup component add \
    rustfmt \
    clippy \
    llvm-tools-preview

# Pre-install common cargo tools (speeds up CI runs)
RUN cargo install --locked \
    cargo-audit \
    cargo-llvm-cov \
    && rm -rf ${CARGO_HOME}/registry/cache \
    && rm -rf ${CARGO_HOME}/git/db

# Verify installations
RUN echo "=== Rust ===" && rustc --version && cargo --version \
    && echo "=== Go ===" && go version \
    && echo "=== cmake ===" && cmake --version \
    && echo "=== rustfmt ===" && rustfmt --version \
    && echo "=== clippy ===" && cargo clippy --version \
    && echo "=== cargo-audit ===" && cargo audit --version \
    && echo "=== cargo-llvm-cov ===" && cargo llvm-cov --version

# Set working directory
WORKDIR /builds

# Default command
CMD ["/bin/bash"]
