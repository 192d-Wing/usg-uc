# GitLab CI Docker Image

This directory contains the custom Docker image used for GitLab CI/CD pipelines.

## Contents

The image includes:

- **Rust 1.93** (Debian Bookworm base)
- **Go 1.25.7** (required for FIPS)
- **cmake** (required for building)
- **Pre-installed tools:**
  - rustfmt, clippy, llvm-tools-preview
  - cargo-audit, cargo-llvm-cov

## Building the Image

### Local Build

```bash
cd ci/image
docker build -t usg-uc-ci:latest .
```

### Build for GitLab Container Registry

```bash
cd ci/image
docker build -t registry.gitlab.com/<your-group>/<your-project>/ci-image:latest .
docker push registry.gitlab.com/<your-group>/<your-project>/ci-image:latest
```

Or use the build script:

```bash
./build.sh
```

## Using in GitLab CI

Update `.gitlab-ci.yml` to use the custom image:

```yaml
.rust-base:
  image: registry.gitlab.com/<your-group>/<your-project>/ci-image:latest
  # ... rest of config
```

## Updating Dependencies

### Update Go Version

Edit the `GO_VERSION` environment variable in the Dockerfile:

```dockerfile
ENV GO_VERSION=1.23.0
```

### Update Rust Version

Change the base image:

```dockerfile
FROM rust:1.86-bookworm
```

### Add New Tools

Add to the `cargo install` command:

```dockerfile
RUN cargo install --locked \
    cargo-audit \
    cargo-llvm-cov \
    your-new-tool \
    && ...
```

## Maintenance

Rebuild and push the image whenever:

- Go version needs updating for FIPS compliance
- Rust version is updated
- New cargo tools are needed in CI
- System dependencies change

## Troubleshooting

### Image Build Fails

- Check Docker daemon is running
- Ensure you have internet connectivity
- Verify Go version exists at go.dev

### CI Jobs Failing

- Ensure image is pushed to registry
- Check registry authentication
- Verify image tag matches `.gitlab-ci.yml`

## License

Same as parent project.
