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
CARGO_FLAGS=()
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

echo "==> Bundling native libraries"
# A cargo staticlib contains only Rust objects; native libraries compiled by
# build scripts must be carried separately:
#  - aws-lc-sys (non-FIPS, used by rustls) emits a static archive -> merge it
#    into the slice with libtool so the xcframework is self-contained
#  - aws-lc-fips-sys emits a DYLIB (the FIPS module boundary requires a shared
#    library) -> staged under Frameworks/native/<target>/ and linked+rpath'd
#    by Package.swift
MERGED_DIR="$(mktemp -d)"
for target in "${TARGETS[@]}"; do
    build_dir="$TARGET_DIR/$target/$PROFILE/build"
    mkdir -p "$MERGED_DIR/$target" "$PKG_DIR/Frameworks/native/$target"

    static_extras=()
    while IFS= read -r lib; do
        static_extras+=("$lib")
    done < <(find "$build_dir" -path "*/out/*" -name "libaws_lc_*_crypto.a" 2>/dev/null)

    libtool -static -o "$MERGED_DIR/$target/libclient_ffi.a" \
        "$TARGET_DIR/$target/$PROFILE/libclient_ffi.a" \
        ${static_extras[@]+"${static_extras[@]}"}

    find "$build_dir" -path "*/artifacts/*" -name "libaws_lc_fips_*_crypto.dylib" \
        -exec cp {} "$PKG_DIR/Frameworks/native/$target/" \; 2>/dev/null
done

echo "==> Assembling ClientFFI.xcframework"
XCF_ARGS=()
for target in "${TARGETS[@]}"; do
    XCF_ARGS+=(-library "$MERGED_DIR/$target/libclient_ffi.a" -headers "$HEADERS_DIR")
done
rm -rf "$PKG_DIR/Frameworks/ClientFFI.xcframework"
mkdir -p "$PKG_DIR/Frameworks"
xcodebuild -create-xcframework "${XCF_ARGS[@]}" \
    -output "$PKG_DIR/Frameworks/ClientFFI.xcframework"

rm -rf "$BINDINGS_DIR" "$MERGED_DIR"
echo "==> Done: $PKG_DIR/Frameworks/ClientFFI.xcframework"
