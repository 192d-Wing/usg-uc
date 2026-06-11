#!/usr/bin/env bash
# Cross-compiles client-ffi into Android .so libraries and stages them under the
# app module's jniLibs, then (re)generates the UniFFI Kotlin bindings from the
# host build. Mirrors clients/apple/build-xcframework.sh but for Android/NDK.
#
# Usage: ./build-rust.sh [--debug] [--no-bindings]
#   --debug         build unoptimized libraries (fast iteration; default is --release)
#   --no-bindings   skip Kotlin binding regeneration (only rebuild the .so files)
#
# Output:
#   app/src/main/jniLibs/arm64-v8a/libclient_ffi.so   (physical devices)
#   app/src/main/jniLibs/x86_64/libclient_ffi.so      (emulator)
#   app/src/main/java/uniffi/client_ffi/client_ffi.kt (generated bindings)
#
# Requirements: cargo-ndk, the Android NDK, and the aarch64-/x86_64-linux-android
# Rust targets (`rustup target add aarch64-linux-android x86_64-linux-android`).

set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(git rev-parse --show-toplevel)"
APP_DIR="$PWD/app"

# cargo-ndk auto-detects the NDK from ANDROID_NDK_HOME (or ANDROID_HOME's ndk/).
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$HOME/Library/Android/sdk/ndk/27.2.12479018}"
# aws-lc-fips-sys builds a FIPS module via its own CMake invocation, and CMake's
# Android-Determine.cmake locates the toolchain through ANDROID_NDK_ROOT /
# ANDROID_NDK (NOT ANDROID_NDK_HOME). Export both so the FIPS CMake step finds
# the NDK; without them the build dies with "Neither the NDK or a standalone
# toolchain was found."
export ANDROID_NDK_ROOT="$ANDROID_NDK_HOME"
export ANDROID_NDK="$ANDROID_NDK_HOME"

PROFILE_FLAG="--release"
PROFILE_DIR="release"
GEN_BINDINGS=1
# digest-auth: password-based SIP auth for commercial-provider interop testing
# (BulkVS). Production government builds are mTLS-only — drop the feature then.
CARGO_FEATURES=(--features digest-auth)
for arg in "$@"; do
    case "$arg" in
        --debug) PROFILE_FLAG=""; PROFILE_DIR="debug" ;;
        --no-bindings) GEN_BINDINGS=0 ;;
        *) echo "unknown flag: $arg" >&2; exit 2 ;;
    esac
done

echo "==> NDK: $ANDROID_NDK_HOME"
if [[ ! -d "$ANDROID_NDK_HOME" ]]; then
    echo "error: NDK not found at ANDROID_NDK_HOME=$ANDROID_NDK_HOME" >&2
    exit 1
fi

echo "==> Building libclient_ffi.so for arm64-v8a + x86_64 (${PROFILE_DIR})"
# -t arm64-v8a: physical Android devices.  -t x86_64: the SDK emulator.
# -P 29: link against the API-29 sysroot. The Oboe backend in client-audio
# links -laaudio, which the NDK ships only for API >= 26; cargo-ndk otherwise
# defaults to API 21 and the link fails with "unable to find library -laaudio".
# Keep this in sync with app/build.gradle.kts minSdk. (Capital -P / --platform;
# lowercase -p is cargo's --package and would error.)
# -o stages the per-ABI .so into the jniLibs tree the Gradle build packages.
cargo ndk \
    -t arm64-v8a \
    -t x86_64 \
    -P 29 \
    -o "$APP_DIR/src/main/jniLibs" \
    build -p client-ffi ${PROFILE_FLAG:+$PROFILE_FLAG} \
    "${CARGO_FEATURES[@]}" \
    --manifest-path "$REPO_ROOT/Cargo.toml"

# Stage the aws-lc FIPS crypto module next to libclient_ffi.so. A cargo cdylib
# contains only Rust objects; the one native library the core needs is the
# aws-lc FIPS module, which is a DYLIB by design (the FIPS boundary requires a
# shared library). libclient_ffi.so carries a NEEDED entry for it, so it must
# sit in the same jniLibs/<abi>/ dir or the app dlopen()s fail at launch. (The
# Apple build stages the equivalent .dylib under Frameworks/native/<target>/.)
echo "==> Staging the aws-lc FIPS crypto module"
TARGET_ROOT="$(cargo metadata --format-version 1 --no-deps \
    --manifest-path "$REPO_ROOT/Cargo.toml" 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
# macOS ships bash 3.2 (no associative arrays); map ABI -> triple with a case.
for abi in arm64-v8a x86_64; do
    case "$abi" in
        arm64-v8a) triple=aarch64-linux-android ;;
        x86_64)    triple=x86_64-linux-android ;;
    esac
    crypto_so="$(find "$TARGET_ROOT/$triple/$PROFILE_DIR/build" -path '*/artifacts/*' \
        -name 'libaws_lc_fips_*_crypto.so' 2>/dev/null | head -1)"
    if [[ -n "$crypto_so" ]]; then
        cp "$crypto_so" "$APP_DIR/src/main/jniLibs/$abi/"
        echo "    $abi: $(basename "$crypto_so")"
    else
        echo "    warning: no FIPS crypto .so found for $abi" >&2
    fi
done

if [[ "$GEN_BINDINGS" -eq 1 ]]; then
    # Bindings come from a host dylib (see generate-bindings.sh); the android
    # Oboe backend is cfg-gated out of the host build, so the FFI surface is
    # complete there even while the cross-compiled .so is in flux.
    ./generate-bindings.sh
fi

echo "==> Done."
ls -R "$APP_DIR/src/main/jniLibs"
