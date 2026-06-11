# USG Unified Communications

USG UC is a unified communications platform written in Rust. It pairs a
SIP **Session Border Controller** (SBC) with native **soft clients**
(desktop and mobile) built on a shared protocol and media core, with
CNSA 2.0–compliant cryptography throughout.

## Components

- **Session Border Controller** — B2BUA call control, SIP registration with
  digest authentication, dial-plan routing, RTP/SRTP media relay with
  transcoding, topology hiding, DoS protection, and a gRPC management API.
  Optional high-availability clustering replicates state via Redis or
  PostgreSQL.
- **Soft clients** — A Tauri 2.0 desktop client plus Android and Apple
  clients sharing one Rust core (`client-core`, `client-sip-ua`,
  `client-audio`) over FFI.
- **Protocol stack** — Standalone `proto-*` crates implementing SIP,
  SDP, RTP/SRTP, DTLS, STUN/TURN/ICE, and STIR/SHAKEN.
- **UC infrastructure** — Reusable `uc-*` crates for transport, codecs,
  media, AAA, routing, CDR, recording (SIPREC), clustering, and
  observability.

## Where to start

- New to the codebase? Read the [Architecture overview](architecture.md).
- Deploying or operating the SBC? Start with the
  [Administrator Guide](SBC-ADMIN-GUIDE.md), then see
  [Clustering](CLUSTERING.md) and [Storage Backends](STORAGE-BACKENDS.md).
- Configuring call routing? See the
  [Route Pattern Reference](route-patterns.md).
- Integrating against the management plane? See the
  [REST API Reference](API-REFERENCE.md).
- Working on the clients? See the
  [Native Client Migration Plan](CLIENT-NATIVE-MIGRATION-PLAN.md) and the
  [Provisioning & OIDC design](CLIENT-PROVISIONING-OIDC.md).
- Security and standards posture? See
  [CNSA 2.0 Compliance](CNSA-2-COMPLIANCE.md) and the
  [NIST 800-53 control matrix](NIST-800-53-CONTROLS.md).

## Building the project

```bash
# SBC daemon
cargo build --release --bin sbc-daemon

# Desktop soft client (BulkVS-style digest auth)
cargo run -p client-gui-tauri --features digest-auth
```

See the [Administrator Guide](SBC-ADMIN-GUIDE.md) for full installation,
configuration, and deployment instructions (including Helm charts under
`deploy/helm/`).

## Working on this documentation

The site is generated with [Zensical](https://zensical.org/). Content is
the Markdown in `docs/`; configuration is `zensical.toml` at the repo root.

```bash
uvx zensical serve   # live preview at http://localhost:8000
uvx zensical build   # static site in site/
```
