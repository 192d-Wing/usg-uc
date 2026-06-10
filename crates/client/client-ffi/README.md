# client-ffi

UniFFI bindings layer for the SIP Soft Client — the single API surface
consumed by the three native shells (SwiftUI for iOS/macOS, Kotlin/Compose for
Android, WinUI 3/C# for Windows). See `docs/CLIENT-NATIVE-MIGRATION-PLAN.md`.

## Generating bindings

Build the library, then run the bundled generator against it:

```sh
cargo build -p client-ffi
cargo run -p client-ffi --features bindgen --bin uniffi-bindgen -- \
    generate --library <target-dir>/debug/libclient_ffi.dylib \
    --language swift --out-dir out/swift
```

`--language kotlin` for Android. C# uses `uniffi-bindgen-cs` (separate tool).

## Cross-compiling

### iOS (from macOS)

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
cargo check -p client-ffi --target aarch64-apple-ios
```

Works out of the box with Xcode installed.

### Android (from macOS)

Requires an NDK (Android Studio: SDK Manager → NDK, or
`sdkmanager --install "ndk;27.2.12479018"`), plus `cmake` and `go` on PATH
(the FIPS crypto build needs them).

```sh
rustup target add aarch64-linux-android
NDK="$HOME/Library/Android/sdk/ndk/27.2.12479018"
PREBUILT="$NDK/toolchains/llvm/prebuilt/darwin-x86_64"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$PREBUILT/bin/aarch64-linux-android26-clang"
export CC_aarch64_linux_android="$PREBUILT/bin/aarch64-linux-android26-clang"
export CXX_aarch64_linux_android="$PREBUILT/bin/aarch64-linux-android26-clang++"
export AR_aarch64_linux_android="$PREBUILT/bin/llvm-ar"
# aws-lc-(fips-)sys runs host libclang for bindgen; without the sysroot it
# fails with: fatal error: 'stdlib.h' file not found
export BINDGEN_EXTRA_CLANG_ARGS_aarch64_linux_android="--sysroot=$PREBUILT/sysroot --target=aarch64-linux-android26"
export ANDROID_NDK_ROOT="$NDK"
cargo check -p client-ffi --target aarch64-linux-android
```

CI runs all of these checks per push (`client-cross` job in
`.github/workflows/ci.yml`).
