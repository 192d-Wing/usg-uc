# USG SIP Client — Android (Kotlin + Jetpack Compose)

A Jetpack Compose front end for the SIP soft-client Rust core, reusing
`crates/client/client-ffi` through **UniFFI Kotlin bindings** — the same FFI
surface the macOS/iOS SwiftUI app (`clients/apple/`) consumes, only generated
with `--language kotlin` instead of `--language swift`.

The UX is a port of the SwiftUI app: a bottom nav (Dialpad / Contacts / Recents
/ Settings), a full-screen in-call overlay (answer/reject/hangup/mute/hold/DTMF
keypad), classification banner strips top and bottom, and a settings screen with
the SIP account form, register/unregister, and audio preferences.

## Layout

```text
clients/android/
├── build-rust.sh            # cargo-ndk → libclient_ffi.so into app/src/main/jniLibs
├── generate-bindings.sh     # uniffi-bindgen → app/src/main/java/uniffi/ (Kotlin)
├── settings.gradle.kts
├── build.gradle.kts         # root: plugin versions
├── gradle.properties
├── gradlew / gradle/wrapper # Gradle 8.9 wrapper
└── app/
    ├── build.gradle.kts     # compileSdk 35, minSdk 29, targetSdk 35, Compose
    └── src/main/
        ├── AndroidManifest.xml
        ├── assets/DevSeed.json          # gitignored dev account seed (optional)
        ├── jniLibs/<abi>/libclient_ffi.so   # generated (gitignored)
        ├── java/uniffi/…                # generated UniFFI bindings (gitignored)
        └── java/org/usg/sipclient/
            ├── MainActivity.kt          # ComponentActivity; mic permission; audio mode
            ├── AppViewModel.kt          # port of AppModel.swift (FFI off-main, events→main)
            ├── DevSeed.kt               # DEBUG-only account seeding from assets/DevSeed.json
            └── ui/                      # RootScreen, Dialpad, Contacts, Recents, Settings,
                                         #   CallOverlay, DtmfPad, Helpers, Theme
```

## Prerequisites

- **Android SDK** at `$ANDROID_HOME` (or `$HOME/Library/Android/sdk`), with
  `platforms;android-35` and recent `build-tools`.
- **NDK** `27.2.12479018` (under `$SDK/ndk/`).
- **JDK 17** (e.g. `/opt/homebrew/opt/openjdk@17`) — set `JAVA_HOME`.
- **Rust** with the Android targets and cargo-ndk:
  ```sh
  rustup target add aarch64-linux-android x86_64-linux-android
  cargo install cargo-ndk
  ```
- `app/local.properties` (gitignored) with `sdk.dir=…` — Gradle writes this
  automatically on first sync, or create it by hand.

## Build & run

```sh
# 1. Cross-compile the Rust core into per-ABI .so files AND (re)generate the
#    Kotlin bindings. arm64-v8a = physical devices, x86_64 = Intel emulator.
#    (Apple-Silicon emulators use the arm64-v8a slice; add it here if needed.)
./build-rust.sh                 # release; --debug for fast iteration

# 2. Build the debug APK.
JAVA_HOME=/opt/homebrew/opt/openjdk@17 ./gradlew :app:assembleDebug
#    → app/build/outputs/apk/debug/app-debug.apk

# 3. Install + launch on a running device/emulator.
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n org.usg.sipclient/.MainActivity
adb logcat | grep -E 'UsgSipClient|client_core'   # watch the Rust core logs
```

`build-rust.sh` exports `ANDROID_NDK_HOME`/`ANDROID_NDK_ROOT`/`ANDROID_NDK` for
the NDK; the last two are required by **aws-lc-fips-sys**, whose CMake step
locates the toolchain through `ANDROID_NDK_ROOT` (not `ANDROID_NDK_HOME`).

The bindings are generated from a **host** build of `libclient_ffi` (the
Android-only Oboe backend is `#[cfg(target_os = "android")]`-gated, so the host
dylib still exports the full FFI surface). `generate-bindings.sh` also applies a
small post-generation patch to the generated `client_ffi.kt`: UniFFI's Kotlin
codegen emits a `message`-property collision on the `ClientError` variants
(`hides member of supertype Throwable`); the patch flattens each variant to a
single `override val \`message\``.

## FFI configuration notes

- **Storage paths**: Android has no directories-crate default, so `AppViewModel`
  passes `configDir`/`dataDir` explicitly from `context.filesDir`
  (`…/config`, `…/data`). Without them the core errors on construction.
- **Threading**: every FFI call blocks on the Rust runtime and runs on
  `Dispatchers.IO`; the `EventListener` callback hops to `Dispatchers.Main`
  before touching `StateFlow` — a direct port of `AppModel.swift`'s contract.
- **digest-auth**: both build scripts pass `--features digest-auth` (BulkVS-style
  password auth for commercial interop). Production mTLS-only builds drop it.
- **DevSeed** (optional, DEBUG only): drop a gitignored
  `app/src/main/assets/DevSeed.json` (same schema as the Apple app's) and the
  ViewModel seeds + registers a dev account on a fresh install. Absent → skipped.

## Current status / gaps

- **APK builds, installs, launches, and the Rust core initializes.** Verified on
  an `android-35` arm64-v8a emulator: `adb logcat` shows
  `client_core::app: Application initialization complete`, the UDP SIP socket
  binds, and the process stays alive. The Compose UI, navigation, and FFI wiring
  are complete.
- **The `.so` links against a FIPS crypto dylib.** `libclient_ffi.so` has a
  `NEEDED` entry for `libaws_lc_fips_<ver>_crypto.so`; `build-rust.sh` stages
  that dylib into each `jniLibs/<abi>/` (the Apple build does the same under
  `Frameworks/native/`). Both `.so` files are packaged in the APK.
- **Audio does not work yet (expected).** The Android **Oboe** backend in
  `crates/client/client-audio` is still landing (concurrent work). At runtime its
  worker threads panic with `ndk-context: android context was not initialized`
  (non-fatal — the app stays up): the FFI does not yet hand the Rust core the
  JavaVM/Android `Context` that `ndk_context` needs. Until that wiring lands:
  - SIP signaling (register, INVITE/BYE) works, but no media flows.
    `MainActivity` already toggles `AudioManager.MODE_IN_COMMUNICATION` around
    calls in preparation.
  - Audio-device enumeration (`listInputDevices`/`listOutputDevices`) has no
    Android CPAL backend and returns empty; the Settings pickers degrade to
    "System Default" (the ViewModel swallows the error).
