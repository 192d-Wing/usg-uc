#!/usr/bin/env bash
# Builds ClientFFI.xcframework and regenerates the Swift bindings for the
# UsgSipClient Swift package.
#
# Usage: ./build-xcframework.sh [--release] [--skip-ios]
#   --release   build optimized libraries (slow: workspace uses fat LTO)
#   --skip-ios  macOS slice only (faster iteration on the desktop app)
#
# Output:
#   UsgSipClient/Frameworks/ClientFFI.xcframework
#   UsgSipClient/Sources/UsgSipClient/ClientFFI.swift (generated bindings)

set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(git rev-parse --show-toplevel)"
PKG_DIR="$PWD/UsgSipClient"
TARGET_DIR="$(cargo metadata --format-version 1 --no-deps --manifest-path "$REPO_ROOT/Cargo.toml" 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"

PROFILE=debug
# digest-auth: password-based SIP auth for commercial-provider interop testing
# (BulkVS). Production government builds are mTLS-only — drop the feature then.
CARGO_FLAGS=(--features digest-auth)
SKIP_IOS=0
for arg in "$@"; do
    case "$arg" in
        --release) PROFILE=release; CARGO_FLAGS+=(--release) ;;
        --skip-ios) SKIP_IOS=1 ;;
        *) echo "unknown flag: $arg" >&2; exit 2 ;;
    esac
done

TARGETS=(aarch64-apple-darwin)
if [[ "$SKIP_IOS" -eq 0 ]]; then
    TARGETS+=(aarch64-apple-ios aarch64-apple-ios-sim)
fi

echo "==> Building client-ffi staticlibs (${PROFILE}) for: ${TARGETS[*]}"
for target in "${TARGETS[@]}"; do
    cargo build -p client-ffi --target "$target" ${CARGO_FLAGS[@]+"${CARGO_FLAGS[@]}"} \
        --manifest-path "$REPO_ROOT/Cargo.toml"
done

echo "==> Generating Swift bindings"
# Bindings come from the host dylib; any slice works, the host one is cheapest.
cargo build -p client-ffi --manifest-path "$REPO_ROOT/Cargo.toml" ${CARGO_FLAGS[@]+"${CARGO_FLAGS[@]}"}
BINDINGS_DIR="$(mktemp -d)"
cargo run -p client-ffi --features bindgen --bin uniffi-bindgen \
    --manifest-path "$REPO_ROOT/Cargo.toml" ${CARGO_FLAGS[@]+"${CARGO_FLAGS[@]}"} -- \
    generate --library "$TARGET_DIR/$PROFILE/libclient_ffi.dylib" \
    --language swift --out-dir "$BINDINGS_DIR"

HEADERS_DIR="$BINDINGS_DIR/headers"
mkdir -p "$HEADERS_DIR"
mv "$BINDINGS_DIR/client_ffiFFI.h" "$HEADERS_DIR/"
# xcodebuild requires the modulemap to be named module.modulemap.
mv "$BINDINGS_DIR/client_ffiFFI.modulemap" "$HEADERS_DIR/module.modulemap"

mkdir -p "$PKG_DIR/Sources/UsgSipClient"
mv "$BINDINGS_DIR/client_ffi.swift" "$PKG_DIR/Sources/UsgSipClient/ClientFFI.swift"

echo "==> Staging the FIPS crypto module"
# A cargo staticlib contains only Rust objects. The one native library the
# core needs is the aws-lc FIPS module, which is a DYLIB by design (the FIPS
# boundary requires a shared library): staged under Frameworks/native/<target>/
# and linked + rpath'd by Package.swift. The macOS demo loads it from there;
# the iOS app must embed it in its bundle.
for target in "${TARGETS[@]}"; do
    mkdir -p "$PKG_DIR/Frameworks/native/$target"
    find "$TARGET_DIR/$target/$PROFILE/build" -path "*/artifacts/*" \
        -name "libaws_lc_fips_*_crypto.dylib" \
        -exec cp {} "$PKG_DIR/Frameworks/native/$target/" \; 2>/dev/null
done

echo "==> Assembling ClientFFI.xcframework"
XCF_ARGS=()
for target in "${TARGETS[@]}"; do
    XCF_ARGS+=(-library "$TARGET_DIR/$target/$PROFILE/libclient_ffi.a" -headers "$HEADERS_DIR")
done
rm -rf "$PKG_DIR/Frameworks/ClientFFI.xcframework"
mkdir -p "$PKG_DIR/Frameworks"
xcodebuild -create-xcframework "${XCF_ARGS[@]}" \
    -output "$PKG_DIR/Frameworks/ClientFFI.xcframework"

rm -rf "$BINDINGS_DIR"
echo "==> Done: $PKG_DIR/Frameworks/ClientFFI.xcframework"
