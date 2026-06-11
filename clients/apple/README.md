# Apple client (iOS + macOS)

Phase 1 of `docs/CLIENT-NATIVE-MIGRATION-PLAN.md`: the SwiftUI shell over the
shared Rust core, consumed through the `client-ffi` UniFFI layer.

## Layout

- `build-xcframework.sh` — builds `client-ffi` staticlibs (macOS arm64, iOS,
  iOS simulator), generates the Swift bindings, and assembles
  `ClientFFI.xcframework` into the Swift package. Run this first; the
  framework and `ClientFFI.swift` are generated, not committed.
- `UsgSipClient/` — Swift package:
  - `UsgSipClient` library target: generated bindings + the Rust binary target
  - `SipClientDemo` executable: minimal SwiftUI smoke-test app (macOS)

## Quick start

```sh
./build-xcframework.sh            # add --release for optimized core
cd UsgSipClient
swift build                       # link check
swift run SipClientDemo           # macOS smoke-test UI
```

The demo reads the same `settings.toml` as the desktop client
(`~/Library/Application Support/com.usg.sip-client/`), so an account
configured there auto-registers on launch.

Microphone permission for `swift run` is inherited from the terminal app
(System Settings → Privacy & Security → Microphone), same as `cargo run`.

## Status

- [x] XCFramework + Swift package pipeline
- [x] macOS smoke-test shell (register, dial, answer, hang up, DTMF, mute)
- [ ] Real SwiftUI app (contacts, history, settings, cert/PIN flow)
- [ ] iOS app target (AVAudioSession + VPIO backend, CallKit, PushKit)
