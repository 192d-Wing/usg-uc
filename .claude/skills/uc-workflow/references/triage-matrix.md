# Triage Matrix — which roles run

When in doubt, include the reviewer: a skipped reviewer is a silent gap in ATO
evidence, an extra one costs only tokens.

## Always-on for any code change

- `qa-engineer`
- `security-reviewer`
- `nist-800-53-reviewer`
- `compliance-scribe`

## Path-triggered roles

| Touched path / topic | Add |
|----------------------|-----|
| `crates/proto/proto-sip`, `proto-transaction`, `proto-dialog`, `proto-b2bua`, `proto-registrar` | `rfc-conformance-reviewer`, `performance-reviewer` |
| `crates/proto/proto-sdp` | `rfc-conformance-reviewer` |
| `crates/proto/proto-rtp`, `proto-srtp`, `proto-dtls`, `proto-ice`, `proto-stun`, `proto-turn` | `rfc-conformance-reviewer`, `performance-reviewer`; flag SC-8/SC-13/CNSA |
| `crates/proto/proto-stir-shaken`, `proto-jwt`, `uc-auth`, `uc-aaa`, `uc-crypto` | `rfc-conformance-reviewer`; flag IA-*/SC-12/SC-13/CNSA |
| `uc-transport`, `uc-media-engine`, `uc-codecs`, `sbc-media*` | `performance-reviewer` (+ `rfc-conformance-reviewer` for codecs/T.38/WebRTC) |
| `uc-acl`, `uc-dos-protection`, `uc-policy`, `uc-routing` | flag SC-5/SC-7/AC-4 focus; `performance-reviewer` |
| `uc-audit`, `uc-syslog`, `uc-cdr`, `uc-siprec` | `performance-reviewer` (back-pressure); flag AU-4/AU-5/AU-9; `release-engineer` on schema change |
| `uc-cluster`, `uc-state-sync`, `uc-storage`, `uc-discovery` | `performance-reviewer`; flag CP-10 |
| `sbc-daemon` | `performance-reviewer` |
| `sbc-api-server`, `sbc-grpc-api`, `sbc-dashboard`, `central-config-*`, `sbc-provision-server`, `sbc-client-config-server` | flag AC-3/IA-2/SC-8 focus; `release-engineer` on API change |
| `sbc-config`, `sbc-config-store`, `sbc-config-sync` | `release-engineer` (config schema); flag CM-6/CM-7 |
| `crates/client/**` | `rfc-conformance-reviewer` (client-sip-ua); flag CNSA (client); `unsafe` focus for client-ffi/client-audio; `release-engineer` for installer/GUI |
| `Cargo.toml`, `Cargo.lock`, `.cargo/audit.toml` | `release-engineer` |
| `Dockerfile`, `deploy/**`, `sidecar/**` | `release-engineer` |
| `.github/workflows/**`, `ci/**` | `release-engineer` |
| `tests/**`, `benches/**`, `*-integration-tests` only | `qa-engineer` only (+ `performance-reviewer` for benches) |

## Phase skips

| Situation | Skip |
|-----------|------|
| Docs / comments only | Phases 1–4; run scribe + `markdownlint` only |
| Bug fix with an obvious one-file cause | Phase 1 may be a short inline plan by the orchestrator |
| Internal refactor, no behaviour/API change | Phase 6 (but still run benches if a hot path is touched) |
| `review` mode | Phases 1–2 |

Record every skipped role or phase, with the reason, in `brief.md`.
