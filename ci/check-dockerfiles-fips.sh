#!/usr/bin/env bash
# Fails if a Dockerfile that builds Rust uses an Alpine or musl builder.
# aws-lc-fips-sys (the FIPS module behind uc-crypto and rustls `fips`)
# does not build on musl, and a musl build cannot carry the FIPS module.
#
# NIST 800-53 Rev5: SC-13, CM-2, CM-6
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

status=0
while IFS= read -r f; do
    # Only Dockerfiles with a Rust toolchain stage.
    grep -qiE '^FROM[[:space:]]+([^[:space:]]*/)?rust:' "$f" || continue
    if grep -nE '^FROM[[:space:]]' "$f" | grep -iE 'alpine|musl'; then
        echo "error: $f: Alpine/musl base in a Rust image (aws-lc FIPS needs glibc)" >&2
        status=1
    fi
    if grep -nE '^[^#]*(musl|--target[= ][^[:space:]]*musl)' "$f"; then
        echo "error: $f: musl target in a Rust image (aws-lc FIPS needs glibc)" >&2
        status=1
    fi
done < <(git ls-files | grep -E '(^|/)Dockerfile[^/]*$')

if [[ "$status" -eq 0 ]]; then
    echo "ok: no Rust Dockerfile uses an Alpine or musl builder"
fi
exit "$status"
