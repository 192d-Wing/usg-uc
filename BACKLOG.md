# Backlog

Deferred work, roughly prioritized. Native-client items reference
[docs/CLIENT-NATIVE-MIGRATION-PLAN.md](docs/CLIENT-NATIVE-MIGRATION-PLAN.md).
Done so far: Phase 0 (shared `client-ffi` core, `AudioBackend` trait, FIPS,
cross-target CI), the macOS SwiftUI client (live-validated + full SIP/RTP RFC
compliance pass — see [docs/CLIENT_RFC_COMPLIANCE_AUDIT.md](docs/CLIENT_RFC_COMPLIANCE_AUDIT.md)),
and the iOS app target (AudioUnit-VPIO backend; builds, registers against
BulkVS in the Simulator).

## iOS on-device

The Simulator proves signaling but not real audio (its audio stack can't
exercise VPIO hardware AEC) and can't host CallKit/PushKit. These need a real
device and Apple code-signing.

- [ ] **Code signing / provisioning** — Apple Developer team in the xcodegen
  project (`clients/apple/ios/project.yml`); provisioning profile; deploy to a
  device. Prerequisite for everything below.
- [ ] **Real-call audio validation** — exercise the iOS AudioUnit
  VoiceProcessingIO duplex backend (`crates/client/client-audio/src/ios_vpio.rs`)
  on-device: bidirectional audio, hardware AEC, the Bluetooth HFP/A2DP
  rate-mismatch class of bugs, route changes, interruptions (Siri, phone
  calls). The Swift shell already sets AVAudioSession `.playAndRecord` /
  `.voiceChat`.
- [ ] **CallKit** — system call UI, audio-session activation handshake,
  hold/mute coordination, call history integration. Replaces the in-app call
  overlay as the OS-level call surface.
- [ ] **PushKit (VoIP push)** — wake the app for incoming INVITEs in the
  background. Without it, inbound calls only work foregrounded. Depends on the
  server-side push gateway below.
- [ ] **Server-side push gateway** (touches `crates/sbc/*`, not the client) —
  on an inbound INVITE for a mobile registration, fire an APNs VoIP push and
  hold the INVITE per RFC 3261 timers until the device re-registers. Its own
  scope/design doc; the migration plan flags this as Phase 3. Android FCM
  shares this component.
- [ ] **iOS Keychain `CertProvider`** — replace the DEBUG dev-seed +
  encrypted-file credential store with Secure Enclave / Keychain and
  CAC/PIV-derived credentials (Purebred-style) for production mTLS. The
  dev-seed (`DevSeed.swift`, DEBUG-only) is a test stopgap.
- [ ] **App distribution** — TestFlight / MDM; NIAP/STIG evaluation tracked
  under `stigs/`.

## Other native clients

- [ ] **Android client** — Oboe/AAudio backend into the existing
  `create_capture`/`create_playback` factory (same seam iOS uses), Kotlin/
  Compose UI reusing the FFI, `AudioManager` `MODE_IN_COMMUNICATION`,
  ConnectionService + FCM wake-up, Android KeyStore `CertProvider`.
- [ ] **Windows-native client** — `uniffi-bindgen-cs` C# bindings + WinUI 3.
  Lightest lift: CPAL/WASAPI audio and the Windows cert store are reused
  unchanged, so it's mostly UI. Retire or Linux-ify the Tauri client once it
  reaches parity (migration plan Phase 5).

## RFC compliance — accepted limitations

From the compliance audit; revisit if a deployment requires them.

- [ ] SRTP ROC preservation across DTLS renegotiation (RFC 3711 §3.2.1).
- [ ] Early-media start on 183+SDP (RFC 3960) — currently no audio before answer.
- [ ] ICE candidate trickling (RFC 8838) — full-gathering-before-offer only.

## Housekeeping

- [ ] v0.2.0 workspace version bumps are parked in a `git stash` (release work);
  land them on the release branch when cutting v0.2.0.
