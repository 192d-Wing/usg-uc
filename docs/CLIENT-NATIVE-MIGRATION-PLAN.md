# Native Client Migration Plan

**Goal:** Migrate `crates/client` from a single Tauri 2.0 desktop app to **three maintained clients** sharing one Rust core:

| Client | Platforms | UI stack | Bridge |
|--------|-----------|----------|--------|
| **Apple** | iOS + macOS (one Xcode multiplatform target) | SwiftUI | UniFFI → Swift package |
| **Android** | Android 10+ (API 29+) | Kotlin + Jetpack Compose | UniFFI → Kotlin/JNA (or JNI) |
| **Windows** | Windows 10/11 | WinUI 3 (C#) | `uniffi-bindgen-cs` → .NET bindings |

The existing Tauri client stays alive as the reference implementation until the Windows native client reaches parity, then is retired (or kept as the Linux client — decision deferred to Phase 5).

---

## 1. Current state (what we're starting from)

~39K LOC across `crates/client/`:

- **`client-types`** (2.2K) — pure shared types, zero platform code. Ships as-is.
- **`client-sip-ua`** (4.7K) — SIP signaling (REGISTER/INVITE/BYE, ICE, DTLS-SRTP). Platform-agnostic, tokio-based. Ships as-is.
- **`client-audio`** (15K) — RTP/SRTP pipeline, codecs, jitter buffer, AEC/AGC/VAD/PLC, resampler. Real-time path is **tokio-free `std::thread`s** (I/O thread + decode thread, lock-free ring buffer to the CPAL callback). Device I/O goes through CPAL; macOS hardware AEC via VPIO (`vpio.rs`); thread priority via pthread QoS (`thread_priority.rs`).
- **`client-core`** (11.7K) — `ClientApp` coordinator, `CallManager`, settings/contacts persistence, cert store (Windows CryptoAPI / macOS Keychain / PKCS#11). Event-driven via `AppEvent` mpsc channels; GUI consumes via 20ms `poll_events()` (a Tauri workaround, not a core requirement).
- **`client-gui-tauri`** (1.8K Rust + 3K JS) — thin command/event bridge + vanilla-JS UI. This is the only layer being replaced.

**Why this migration is tractable:** the core is already GUI-agnostic and event-driven; the only desktop-only assumptions are CPAL device I/O, the Tauri polling loop, `directories`-based config paths, and desktop cert stores — all of which sit behind existing module boundaries.

---

## 2. Target architecture

```
crates/client/
  client-types/            # unchanged — shared types
  client-sip-ua/           # unchanged — SIP signaling
  client-audio/            # core DSP/RTP unchanged; device I/O behind a trait
  client-core/             # ClientApp; platform services behind traits
  client-ffi/              # NEW — UniFFI interface crate (the ONE public API)
  client-gui-tauri/        # legacy, retired after Windows-native parity
clients/                   # NEW — native app shells (not in cargo workspace)
  apple/                   # Xcode project: iOS + macOS SwiftUI app
  android/                 # Gradle project: Kotlin/Compose app
  windows/                 # WinUI 3 (C#) solution
```

### 2.1 The FFI boundary: `client-ffi` (UniFFI)

One crate defines the entire surface the three shells consume. UniFFI generates Swift and Kotlin bindings; the community-maintained `uniffi-bindgen-cs` (NordSecurity) generates C# for Windows. This keeps **one** interface definition for all three clients.

API shape (mirrors today's Tauri commands + events):

```
interface SipClient {
  constructor(config: ClientConfig, platform: PlatformServices);
  initialize(), shutdown()
  make_call(uri), answer_call(id), end_call(id), hold_call(id), resume_call(id)
  send_dtmf(id, digit), set_muted(bool), set_moh_active(bool)
  registration_status(), call_status(id), list_audio_devices(), select_audio_device(id)
  list_certificates(), select_certificate(id), enter_pin(pin)
  settings get/update, contacts CRUD, call history
}
callback interface EventListener {
  on_event(event: AppEvent)   // push-based — replaces the 20ms poll loop
}
callback interface PlatformServices {
  data_dir(), cache_dir()           // replaces `directories` on mobile
  // audio + cert callbacks per §2.2 / §2.3
}
```

Key changes inside `client-core` to support this:

1. **Replace polling with push.** `poll_events()` exists only because of a Tauri/tokio interaction. Add `ClientApp::subscribe(listener)` that forwards `AppEvent`s directly from the mpsc receiver on a tokio task. Tauri shell can keep polling during transition; native shells use push from day one.
2. **Inject paths.** Replace direct `directories` calls with a `Paths` provider passed at construction (desktop default = `directories`; mobile = sandbox dirs handed in from the shell).
3. **Runtime ownership.** `client-ffi` owns a multi-thread tokio runtime; all UniFFI entry points dispatch onto it. This deletes the `tauri::async_runtime::spawn` workaround class of problems entirely.

### 2.2 Audio device abstraction

The DSP core (codecs, jitter buffer, AEC, resampler, PLC, DTMF — ~13K of the 15K LOC) is pure computation and ports untouched. Only device I/O changes. Introduce in `client-audio`:

```rust
trait AudioBackend: Send {
    fn start_capture(&mut self, cfg: StreamConfig, sink: CaptureSink) -> Result<...>;
    fn start_playback(&mut self, cfg: StreamConfig, source: PlaybackSource) -> Result<...>;
    fn enumerate_devices(&self) -> Vec<AudioDevice>;
    // route-change / device-default-change notifications
}
```

Per platform:

| Platform | Backend | Notes |
|----------|---------|-------|
| macOS | Existing CPAL + **VPIO** path | unchanged |
| Windows | Existing CPAL (WASAPI) | unchanged; software AEC as today |
| iOS | **AudioUnit VPIO** (`kAudioUnitSubType_VoiceProcessingIO`) — same family as `vpio.rs` | gives hardware AEC + correct VoIP ducking. Plus **AVAudioSession** management (`.playAndRecord`, `.voiceChat` mode, route changes, interruption handling — phone calls, Siri) driven from the Swift shell via `PlatformServices`. |
| Android | **Oboe/AAudio** via `oboe-rs`, low-latency callback API | plus `AudioManager` mode `MODE_IN_COMMUNICATION`, audio focus, and `AcousticEchoCanceler` where available (software AEC fallback — already have one). |

The existing I/O-thread/decode-thread model is kept everywhere; on iOS/Android the OS audio callback replaces the CPAL callback at the same ring-buffer boundary. The pthread-QoS code in `thread_priority.rs` already works on iOS; Android needs `setThreadPriority(THREAD_PRIORITY_URGENT_AUDIO)` via JNI (small addition behind the same module).

**Known risk carried forward:** Bluetooth capture/playback rate mismatch and exact-count resampling lessons from desktop apply doubly on mobile (HFP 16kHz vs A2DP 44.1/48kHz). The sinc resampler and drift compensator port as-is.

### 2.3 Certificates & credentials

`cert_store.rs` is already per-platform behind `cfg`. Formalize it as a `CertProvider` trait with implementations:

- **Windows:** existing CryptoAPI store + smart-card logon EKU (unchanged).
- **macOS:** existing Keychain + PKCS#11/YubiKey (unchanged).
- **iOS:** Keychain / Secure Enclave via Security.framework, surfaced through `PlatformServices`. For CAC/PIV, mobile has no reader — plan for **derived credentials** (DoD Purebred-style: cert + key provisioned into the Keychain/KeyStore) as the mTLS identity source.
- **Android:** Android KeyStore via `KeyChain.choosePrivateKeyAlias` / hardware-backed keys, same derived-credential model.
- `keyring` (digest-auth credential storage) has no mobile backends → on mobile, route credential storage through `PlatformServices` (iOS Keychain / Android EncryptedSharedPreferences-or-KeyStore).

### 2.4 Mobile call lifecycle (net-new functionality, biggest non-port work)

Desktop assumes the process is always running with an open socket. Mobile does not:

- **iOS:** **CallKit** integration (system call UI, audio session activation, hold/mute coordination) + **PushKit VoIP push** to wake the app for incoming INVITEs. Without PushKit, incoming calls only work foregrounded. This requires server-side support: a push notification service that the SBC/registrar signals on inbound calls (new component or BulkVS-style provider hook — flagged as a **server-side dependency**, scoped in Phase 3).
- **Android:** **ConnectionService** (self-managed) for system call integration + **FCM high-priority push** for wake-up, plus a foreground service with `microphone|phoneCall` type during active calls.
- Registration strategy on mobile shifts from "always registered" to "register on launch/push"; `client-sip-ua`'s registration agent already supports explicit register/unregister so this is shell-level policy.

macOS/Windows keep the always-running model (menu bar / tray).

---

## 3. Phases

### Phase 0 — Core refactor (no new clients yet) ~2-3 weeks
1. Create `client-ffi` crate; define UniFFI interface mirroring today's Tauri commands/events.
2. `client-core`: push-based `subscribe()`, injected `Paths`, owned tokio runtime, remove Tauri-specific workarounds from core (leave shims in `client-gui-tauri`).
3. `client-audio`: extract `AudioBackend` trait; move CPAL behind `backend_cpal` (default feature), VPIO stays macOS-gated.
4. `client-core`: extract `CertProvider` trait over existing `cfg` blocks.
5. CI: add `cargo check` for `aarch64-apple-ios`, `aarch64-linux-android`, `x86_64-pc-windows-msvc` targets of the core crates to lock in portability.
6. **Exit criteria:** Tauri client still fully functional, now running through `client-ffi`-shaped APIs internally; core crates compile for all five targets.

### Phase 1 — Apple client (macOS first, then iOS) ~6-8 weeks
1. XCFramework build of `client-ffi` (ios + ios-sim + macos slices); Swift package with generated bindings; SPM integration.
2. SwiftUI multiplatform app: registration, dialpad, in-call UI, call history, contacts, settings, cert/PIN flow. macOS gets menu-bar presence.
3. **macOS milestone:** feature parity with Tauri client using the existing CPAL/VPIO backend — proves the FFI layer with zero new audio code.
4. iOS: AVAudioSession + AudioUnit-VPIO backend, CallKit, mic permission flow, background audio entitlement.
5. PushKit incoming-call path (depends on server-side push service — see Phase 3 dependency; foreground-only incoming calls are the interim milestone).

### Phase 2 — Android client ~6-8 weeks (can overlap Phase 1 after its step 1)
1. `cargo-ndk` build for arm64-v8a (+ x86_64 for emulator); Gradle module with UniFFI Kotlin bindings.
2. Oboe `AudioBackend` + `AudioManager` communication-mode handling.
3. Compose UI to parity; ConnectionService + foreground service; FCM wake-up path.

### Phase 3 — Push/wake server support ~3-4 weeks (parallel with 1/2)
- SBC/registrar-side push gateway: on inbound INVITE for a mobile registration, fire APNs VoIP push / FCM, hold the INVITE per RFC 3261 timers until the device re-registers. Scope and design doc is its own deliverable (touches `crates/sbc/*`, outside `crates/client`).

### Phase 4 — Windows native client ~5-6 weeks
1. `uniffi-bindgen-cs` C# bindings; `client-ffi` as cdylib in a NuGet-able package.
2. WinUI 3 app to parity (existing CPAL/WASAPI backend and Windows cert store reused unchanged — this client is almost entirely UI work).
3. MSIX packaging, tray icon, autostart.

### Phase 5 — Retire/repurpose Tauri ~1-2 weeks
- Once Windows-native passes the integration suite, either delete `client-gui-tauri` or strip it to a Linux-only client. Remove poll-based event path from core.

---

## 4. Testing strategy

- **`client-integration-tests` stays the source of truth** for core behavior (cert, registration, call flow, two-client) — it tests below the FFI line and runs unchanged in CI for all target triples (host-runnable subsets).
- Add an **FFI smoke layer**: a headless harness per binding (Swift XCTest, Kotlin instrumented test, C# xunit) that registers + completes one loopback call against the test SBC, run in CI on macOS runners, Android emulator, and Windows runners.
- Audio DSP unit tests (resampler, jitter buffer, PLC) are platform-independent and already exist — gate them on all targets.
- Manual device matrix per release: BT headset, wired, built-in, speaker — on at least one device per platform (the Bluetooth rate-mismatch class of bugs does not reproduce in CI).

## 5. CI / release

Extend the existing release pipeline (`.github/workflows/release.yml` currently covers SBC images):
- Rust core: build + clippy + test matrix for the 5 triples (mac runners cover apple targets, ubuntu + NDK for Android, windows runner for MSVC).
- Artifacts: XCFramework (Apple), `.aar` (Android), NuGet (Windows) — versioned with the workspace.
- App shells build in their own jobs; distribution is MDM/TestFlight/internal (government context — App Store/Play submission and NIAP/STIG evaluation tracked separately under `stigs/`).

## 6. Risks & mitigations

| Risk | Mitigation |
|------|------------|
| iOS background/incoming calls require server push (new infra) | Phase 3 scoped early, runs parallel; foreground-only is an explicit interim milestone |
| `uniffi-bindgen-cs` is community-maintained | Windows is last; fallback is a hand-written C ABI + P/Invoke layer over `client-ffi` (surface is small) |
| Mobile audio edge cases (BT, interruptions, route changes) | Reuse desktop lessons (exact-count resampling, capture-rate sizing); device test matrix; VPIO/Oboe are the platform-blessed low-latency paths |
| CAC/PIV has no mobile reader | Derived credentials (Purebred model) into Keychain/KeyStore; mTLS code path unchanged |
| Three UIs drift apart | All behavior lives below `client-ffi`; UI shells are intentionally thin (today's Tauri JS is only 3K LOC — that's the per-platform budget) |
| `edition 2024` / aws-lc-rs on iOS/Android | Phase 0 step 5 (cross-target `cargo check` in CI) surfaces this in week 1, not month 3 |

## 7. Explicit non-goals

- No UI framework unification (no Flutter/React Native/shared egui) — "3 native clients" is the requirement.
- No Linux-native client commitment (Tauri may remain for Linux; decide at Phase 5).
- No video, no messaging — voice parity only.
