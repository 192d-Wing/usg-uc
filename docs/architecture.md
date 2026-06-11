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
- `sbc-announcement` (lib), `sbc-announcement-server` (pod) —
  announcement playback engine and the gRPC-fronted pod that streams
  announcements ("number not in service", "all circuits busy") on the
  daemon's behalf
- `sbc-trunk-services` (lib), `sbc-trunk-agent` (pod) — OPTIONS trunk
  health monitoring and outbound carrier registration, runnable
  in-process or as a dedicated single-replica pod
- `sbc-cli` — operator command-line tool
- `sbc-dashboard` — web dashboard

### SBC container topology

The SBC ships as one image per concern. Pods marked *optional* have an
in-daemon fallback: when the pod (or its env var switch) is absent, the
daemon runs that subsystem in-process, preserving single-pod deploys.

``` mermaid
flowchart LR
    carriers["Carriers / Phones"]
    subgraph cluster["SBC deployment"]
        daemon["sbc-daemon<br>SIP B2BUA, routing, registrar,<br>RTP relay (5060/5061, 16384-32768/udp)"]
        api["sbc-api-server<br>REST config CRUD"]
        prov["sbc-provision-server<br>phone provisioning"]
        ccfg["sbc-client-config-server<br>soft-client OIDC config"]
        ann["sbc-announcement-server*<br>announcement RTP playback"]
        trunk["sbc-trunk-agent*<br>OPTIONS pings + carrier REGISTER<br>(single replica)"]
        pg[("PostgreSQL")]
    end
    carriers <-->|"SIP + RTP"| daemon
    carriers <-->|"announcement RTP"| ann
    carriers <-->|"OPTIONS / REGISTER"| trunk
    daemon -->|"gRPC AnnouncementService<br>(SBC_ANNOUNCEMENT_URL)"| ann
    trunk -->|"gRPC TrunkStatusPublishService<br>(daemon: SBC_TRUNK_SERVICES=external)"| daemon
    api -->|"gRPC sync services :9091"| daemon
    api --> pg
    prov --> pg
    trunk -->|"trunk config"| pg
    daemon --> pg
```

\* optional pods with in-daemon fallback. `sbc-trunk-agent` must run as
exactly one replica (a second agent would double-REGISTER to carriers);
the daemon must then run with `SBC_TRUNK_SERVICES=external`.

A further decomposition of the daemon itself (signaling pod + N media
relay pods) is explored in
[Signaling / Media Split](SIGNALING-MEDIA-SPLIT.md).

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
