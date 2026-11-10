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

> **Egress flow layer (sbc-daemon):** each `ProcessResult` carries a `Flow` (the leg's transport plus, for a trunk, the right to dial it with a configured TLS name). `FlowTable` turns it into the UDP socket, the accepted connection, or a cached, certificate-verified trunk connection with its own reader task. The SIPREC recorder has a third TLS client profile (`FlowProfile::Recorder`: SRS CA only, TLS 1.3) keyed apart from trunk flows, so its connection is never shared with a trunk at the same address. Requests are never written to the connection they were triggered from unless that is the target leg.
| 2 — Protocol core | `proto-sip`, `proto-transaction`, `proto-dialog`, `proto-b2bua`, `proto-registrar`, `proto-sdp`, `proto-rtp`, `proto-srtp`, `proto-dtls`, `proto-stun`, `proto-turn`, `proto-ice`, `proto-stir-shaken` | RFC protocol implementations |
| 3 — Media engine | `uc-codecs`, `uc-media-engine` | Codec encode/decode (G.711 et al.), transcoding, media relay |
| 4 — Security | `uc-acl`, `uc-auth`, `uc-dos-protection` | Access control, digest auth, rate limiting |
| 5 — Orchestration | `uc-policy`, `uc-routing`, `uc-cdr`, `uc-sti` | Policy, dial-plan routing, call detail records, STIR/SHAKEN services (x5u cert cache, trust anchors, attestation policy, signing key) |
| 6 — Recording | `uc-siprec` | SIPREC call recording (partial; wired through `sbc-daemon` since phase 3, off by default). `uc-siprec` holds the RFC 7865 metadata serializer, the RFC 7866 RS-offer body builder (SRTP / SDES) and the SRS answer validator. The session recording client itself is in `sbc-daemon` (`recording.rs`: trigger, policy, RS messages, answer validation, `max_sessions` slot; `sip_stack/recording_session.rs`: stack glue) and the media fork in `sbc-media-core` (`recording_fork.rs`, driven through `MediaController::{prepare,activate,stop}_recording_fork`; in-process `MediaPipeline` only, remote gRPC media nodes return `RecordingUnsupported`). The recorder is reached on its own TLS flow profile (`flow.rs` `FlowProfile::Recorder`). Open: POA&M-300, -301, -303, -304, -305, -307, -308 |
| 7 — Management | `uc-api`, `uc-metrics`, `uc-health`, `uc-telemetry` | Management APIs and observability |
| 8 — HA & clustering | `uc-cluster`, `uc-discovery`, `uc-storage`, `uc-state-sync`, `uc-aaa`, `uc-user-mgmt`, `uc-phone-mgmt`, `uc-snmp`, `uc-syslog` | Cluster membership, state replication, user/phone management |
| 9 — WebRTC | `uc-webrtc` | WebRTC interop |
| 10 — Specialized | `uc-t38` | T.38 fax relay (partial, dormant, not interoperable: UDPTL/IFP encoding is project-specific, not ITU-T T.38 ASN.1 PER; POA&M-204). The SBC relays UDPTL opaquely and does not use this crate. |
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

**T.38 fax.** The B2BUA switches a call between audio and T.38
(`m=image udptl t38`) on re-INVITE. `proto-sdp::t38` parses the T.38 Annex D
attributes, `proto-b2bua` selects the one anchored m-line, and `sbc-daemon`
(`t38.rs`, `sip_stack.rs`) applies the `[media.t38]` policy: 488 for refused
offers, clamped capacity attributes, and the relay moved only on the far
side's 2xx. The `sbc-media-core` relay forwards UDPTL opaquely on the call's
existing ports and re-latches to the gateways' new source ports. The SBC does
not use `uc-t38` (POA&M-290..294).

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

### CDR data flow

``` mermaid
flowchart LR
    sip["sip_stack.rs<br>call end / reject"]
    emit["CdrEmitter<br>(uc-cdr, bounded queue,<br>try_send)"]
    writer["writer thread<br>PII policy, sequence,<br>SHA-384 chain"]
    file[("rotated JSONL/CSV files<br>+ .sha384 sidecars<br>(cdr.directory)")]
    ring["in-memory ring<br>(ring_capacity)"]
    sys["syslog sink thread<br>RFC 5424 over RFC 5425 TLS<br>(optional)"]
    audit["uc-audit<br>CdrFileRotated, CdrSinkFailure"]
    svc["gRPC CdrService<br>(mTLS or loopback only)"]
    api["sbc-api-server<br>/api/v1/cdrs* (cdr:read / cdr:export)"]
    cli["sbc-cli cdrs<br>list/show/export (gRPC)<br>verify (offline, files)"]
    dash["sbc-dashboard Cdrs page"]
    sip --> emit --> writer
    writer --> file
    writer --> ring
    writer -->|"own queue"| sys
    writer --> audit
    ring --> svc
    svc -->|"mTLS, client-cert allow-list"| api
    svc -->|"loopback"| cli
    api --> dash
    file --> cli
```

Each daemon node writes its own CDRs; `node_id` and `sequence` identify the
source. The files are the durable record. The API, CLI and dashboard read
only the node's in-memory ring. The chain and sidecars are tamper-evident
only; they are anchored by uc-audit or syslog, not signed. The daemon has
no dialog-takeover path, so a call lost in a node crash produces no CDR.
Configuration and limits are in the
[Administrator Guide](SBC-ADMIN-GUIDE.md#call-detail-records) and the
POA&M in the [NIST control matrix](NIST-800-53-CONTROLS.md).

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

Cryptography targets CNSA 2.0: TLS and SRTP use the AWS-LC FIPS module
(`uc-crypto`, rustls with its FIPS posture enabled). Not every TLS channel
restricts its suites to CNSA 2.0. The daemon gRPC / sbc-api channel uses
tonic's default suites, and the SIP-TLS and CDR syslog configs pin the TLS
version but not the suites. These gaps are tracked in the CNSA and NIST
documents. See
[CNSA 2.0 Compliance](CNSA-2-COMPLIANCE.md) and the
[NIST 800-53 control matrix](NIST-800-53-CONTROLS.md) for the full
mapping, and the RFC compliance pages for protocol conformance status.
