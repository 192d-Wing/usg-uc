# Architecture Overview

The workspace is organized in layers. Lower layers have no knowledge of
the applications built on top of them, so the protocol and UC crates are
reusable outside the SBC and clients.

``` mermaid
flowchart TB
    subgraph apps["Applications"]
        sbc["SBC<br>(sbc-*)"]
        clients["Soft clients<br>(client-*)"]
    end
    uc["UC infrastructure (uc-*)<br>routing, policy, media engine, AAA, clustering…"]
    proto["Protocol core (proto-*)<br>SIP, SDP, RTP/SRTP, DTLS, STUN/TURN/ICE…"]
    found["Foundation<br>uc-types, uc-crypto, uc-audit, uc-transport"]
    sbc --> uc
    clients --> uc
    uc --> proto
    proto --> found
```

## Crate layers

| Layer | Crates | Purpose |
| --- | --- | --- |
| 0 — Foundation | `uc-types`, `uc-crypto`, `uc-audit` | Shared types, CNSA 2.0 cryptography (aws-lc-rs / FIPS), audit logging |
| 1 — Transport | `uc-transport` | UDP/TCP/TLS transport for SIP |
| 2 — Protocol core | `proto-sip`, `proto-transaction`, `proto-dialog`, `proto-b2bua`, `proto-registrar`, `proto-sdp`, `proto-rtp`, `proto-srtp`, `proto-dtls`, `proto-stun`, `proto-turn`, `proto-ice`, `proto-stir-shaken` | RFC protocol implementations |
| 3 — Media engine | `uc-codecs`, `uc-media-engine` | Codec encode/decode (G.711 et al.), transcoding, media relay |
| 4 — Security | `uc-acl`, `uc-auth`, `uc-dos-protection` | Access control, digest auth, rate limiting |
| 5 — Orchestration | `uc-policy`, `uc-routing`, `uc-cdr` | Policy, dial-plan routing, call detail records |
| 6 — Recording | `uc-siprec` | SIPREC call recording |
| 7 — Management | `uc-api`, `uc-metrics`, `uc-health`, `uc-telemetry` | Management APIs and observability |
| 8 — HA & clustering | `uc-cluster`, `uc-discovery`, `uc-storage`, `uc-state-sync`, `uc-aaa`, `uc-user-mgmt`, `uc-phone-mgmt`, `uc-snmp`, `uc-syslog` | Cluster membership, state replication, user/phone management |
| 9 — WebRTC | `uc-webrtc` | WebRTC interop |
| 10 — Specialized | `uc-t38` | T.38 fax relay |
| 11 — DNS | `uc-dns` | DNS (NAPTR/SRV) integration |

## Applications

### SBC (`crates/sbc/`)

`sbc-daemon` is the main binary; it wires the B2BUA, registrar, routing,
and media relay together. Supporting crates:

- `sbc-config`, `sbc-config-store` — configuration model and persistence
- `sbc-grpc-api`, `sbc-api-server` — gRPC management API and REST server
- `sbc-provision-server`, `sbc-client-config-server` — device and client
  provisioning endpoints
- `sbc-cli` — operator command-line tool
- `sbc-dashboard` — web dashboard

Operational details live in the [Administrator Guide](SBC-ADMIN-GUIDE.md),
[Clustering](CLUSTERING.md), and [Storage Backends](STORAGE-BACKENDS.md).

### Soft clients (`crates/client/`)

One Rust core serves all platforms:

- `client-types` — shared types
- `client-sip-ua` — SIP user agent (INVITE/BYE/CANCEL/ACK, registration)
- `client-audio` — capture/playback, resampling, jitter buffer, RTP
- `client-core` — call lifecycle, SDP handling, audio session management
- `client-ffi` — C FFI surface for the native mobile apps
- `client-gui-tauri` — Tauri 2.0 desktop app

Platform shells live under `clients/android/` and `clients/apple/`. The
direction of travel is described in the
[Native Client Migration Plan](CLIENT-NATIVE-MIGRATION-PLAN.md).

## Security posture

Cryptography is CNSA 2.0 compliant: all TLS and SRTP key material flows
through `uc-crypto` backed by the AWS-LC FIPS module, and rustls is built
with its FIPS posture enabled. See
[CNSA 2.0 Compliance](CNSA-2-COMPLIANCE.md) and the
[NIST 800-53 control matrix](NIST-800-53-CONTROLS.md) for the full
mapping, and the RFC compliance pages for protocol conformance status.
