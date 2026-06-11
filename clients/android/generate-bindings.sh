#!/usr/bin/env bash
# Regenerates the UniFFI Kotlin bindings into app/src/main/java/uniffi/ from a
# host build of libclient_ffi. This is the Android counterpart of the Swift
# binding generation in clients/apple/build-xcframework.sh, using the same
# uniffi-bindgen with --language kotlin.
#
# Bindings are host-target only (no NDK needed): the android-specific Oboe
# module is #[cfg(target_os = "android")]-gated, so the host dylib still exports
# the full FFI surface. build-rust.sh calls this after building the .so files;
# run it standalone when only the bindings changed.

set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(git rev-parse --show-toplevel)"
# digest-auth: mirrors the Swift/iOS build; production mTLS builds drop it.
CARGO_FEATURES=(--features digest-auth)

echo "==> Building host libclient_ffi (for bindgen)"
cargo build -p client-ffi "${CARGO_FEATURES[@]}" \
    --manifest-path "$REPO_ROOT/Cargo.toml"

TARGET_DIR="$(cargo metadata --format-version 1 --no-deps \
    --manifest-path "$REPO_ROOT/Cargo.toml" 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"

DYLIB="$TARGET_DIR/debug/libclient_ffi.dylib"
[[ -f "$DYLIB" ]] || DYLIB="$TARGET_DIR/debug/libclient_ffi.so"

BINDINGS_OUT="$PWD/app/src/main/java"
echo "==> Generating Kotlin bindings into $BINDINGS_OUT/uniffi/"
rm -rf "$BINDINGS_OUT/uniffi"
cargo run -p client-ffi --features bindgen,digest-auth --bin uniffi-bindgen \
    --manifest-path "$REPO_ROOT/Cargo.toml" -- \
    generate --library "$DYLIB" \
    --language kotlin --out-dir "$BINDINGS_OUT"

GENERATED="$BINDINGS_OUT/uniffi/client_ffi/client_ffi.kt"

# Patch a UniFFI Kotlin codegen collision: ClientError's variants carry a field
# literally named `message`, and the generator emits BOTH a constructor
# `val \`message\`` AND a synthesized `override val message` getter — which the
# Kotlin compiler rejects ("hides member of supertype Throwable / conflicting
# declarations"). The fix flattens each error variant to a single
# `override val \`message\`` constructor property and drops the synthesized
# getter. The FfiConverter still reads/writes `value.\`message\`` positionally,
# so behavior is unchanged. (The FFI `ClientError` field name lives in
# crates/client/client-ffi; this shell owns only the generated Android copy.)
python3 - "$GENERATED" <<'PY'
import re, sys
path = sys.argv[1]
src = open(path).read()
pattern = re.compile(
    r"val `message`: kotlin\.String\n"
    r"(\s*)\) : ClientException\(\) \{\n"
    r"\s*override val message\n"
    r"\s*get\(\) = \"message=\$\{ `message` \}\"\n"
    r"\s*\}",
)
replacement = r"override val `message`: kotlin.String\n\1) : ClientException() {}"
new, n = pattern.subn(replacement, src)
if n == 0:
    print("warning: ClientException message-collision patch matched 0 sites "
          "(upstream codegen may have changed)", file=sys.stderr)
open(path, "w").write(new)
print(f"==> Patched {n} ClientException variant(s) for the message collision")
PY

echo "==> Done: $GENERATED"
