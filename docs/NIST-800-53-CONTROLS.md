# NIST 800-53 Rev5 Control Implementation Matrix

This document maps NIST 800-53 Rev5 security controls to their implementations in the USG SBC codebase.

> **Status legend.** *Wired (sbc-daemon | sbc-media-core | soft client)* — a shipped binary has a call site for this (the binary is named). *Library-only* — implemented and tested in a `proto-*`/`uc-*` crate, but no shipped binary calls it. *Planned* — not implemented. A row that says only "Full"/"Complete" describes crate-level capability; the wiring column/annotation says what the running SBC actually does.

Crate names below are the real workspace crates (`crates/uc/uc-*`, `crates/proto/proto-*`, `crates/sbc/*`). There are no `sbc-crypto`, `sbc-audit`, `sbc-acl`, `sbc-registrar` or similar crates.

## Control Families

### AC - Access Control

| Control | Title | Status | Implementation |
|---------|-------|--------|----------------|
| AC-3 | Access Enforcement | **Wired (sbc-daemon)** | INVITE source admission: the source IP must belong to a configured trunk or an active registration contact (`sbc-daemon/src/sip_stack.rs`, `is_admitted_source`). The `uc-acl` crate is Library-only (no shipped binary depends on it). |
| AC-6 | Least Privilege | Planned | `uc-acl` crate exists (Library-only); not wired into any binary. |

### AU - Audit and Accountability

| Control | Title | Status | Implementation |
|---------|-------|--------|----------------|
| AU-2 | Event Logging | Library-only | `uc-audit::event` defines auditable events. No `crates/sbc` binary depends on `uc-audit`; the daemon emits `tracing` logs only. `logging.audit_enabled` / `logging.audit_path` are parsed by `sbc-config` but not read by `sbc-daemon`. |
| AU-3 | Content of Audit Records | Library-only | `uc-audit::record` structured records; not wired. |
| AU-4 | Audit Log Storage Capacity | Library-only | `uc-audit::sink` configurable sinks; not wired. |
| AU-8 | Time Stamps | Library-only | `uc-audit::record` UTC timestamps; not wired. |
| AU-9 | Protection of Audit Information | Library-only | `uc-audit::record` SHA-384 hash chain; not wired. |
| AU-10 | Non-repudiation | Planned | Cryptographic signing of audit records |

### CM - Configuration Management

| Control | Title | Status | Implementation |
|---------|-------|--------|----------------|
| CM-2 | Baseline Configuration | **Wired (sbc-daemon)** | `sbc-config::schema` typed configuration, loaded at startup (`sbc-daemon/src/runtime.rs`, `load_config`). |
| CM-6 | Configuration Settings | **Wired (sbc-daemon)** | `sbc-config::validate::validate_config` runs on load and via gRPC `ConfigService.ValidateConfig`. |

### IA - Identification and Authentication

| Control | Title | Status | Implementation |
|---------|-------|--------|----------------|
| IA-2 | Identification and Authentication | **Wired (sbc-daemon), off by default** | REGISTER authorization via `proto-registrar`: RFC 8898 Bearer tokens (`sbc-daemon/src/server.rs`, `build_bearer_authenticator`) are enabled only with `SBC_AUTH_MODE=bearer` + `SBC_OIDC_ISSUER`. Digest auth (`AuthenticatedRegistrar`) is compiled in but `require_auth`/`auth_credentials` are never set from configuration; without the env var the daemon logs "REGISTER is UNAUTHENTICATED". |
| IA-5 | Authenticator Management | Library-only | `proto-registrar` digest credential store; no TOML/env path populates it. |
| IA-9 | Service Identification | Library-only | `proto-stir-shaken` (ES384-only PASSporT verification). Not a dependency of any `crates/sbc` binary; the `[stir_shaken]` config section is parsed but unused. |

### SC - System and Communications Protection

| Control | Title | Status | Implementation |
|---------|-------|--------|----------------|
| SC-5 | Denial of Service Protection | **Wired (sbc-daemon)** | `uc-dos-protection::RateLimiter` per-source-IP and global limiters (`sbc-daemon/src/server.rs`); `general.max_calls` admission control (503) in `sip_stack.rs`. `rate_limit.per_user_rps` is parsed but not applied. |
| SC-7 | Boundary Protection | **Wired (sbc-daemon)** | `proto-sip::TopologyHider` initialised from `[topology_hiding]` and applied to external B-legs (`sbc-daemon/src/sip_stack.rs`). |
| SC-8 | Transmission Confidentiality | **Wired (sbc-daemon, sbc-media-core)** | SIP-over-TLS listeners use `uc-transport::tls::create_server_config` (TLS 1.3 only); listeners are skipped with a warning when `security.tls_cert_path` is unset. SRTP relay/termination accepts only `AEAD_AES_256_GCM` (`sbc-media-core/src/srtp_relay.rs`, `dtls_relay.rs`). The REST HTTPS listener (`api_server.rs`) uses rustls defaults (TLS 1.2 permitted). |
| SC-12 | Cryptographic Key Establishment | Library-only (`uc-crypto::ecdh`, `uc-crypto::hkdf`) | No shipped binary or `proto-*` crate calls the ECDH/HKDF helpers. Key establishment in the shipped path is TLS 1.3 (rustls) and DTLS-SRTP performed by the external Go DTLS sidecar (`sbc-media-core/src/dtls_sidecar.rs`). |
| SC-13 | Cryptographic Protection | **Wired (sbc-daemon, sbc-media-core)** | rustls aws-lc-rs FIPS provider installed at startup (`sbc-daemon/src/main.rs`; workspace `rustls` features `fips`). `uc-crypto` exposes only SHA-384/512, AES-256, P-384 and is used by `proto-srtp`/`proto-dtls`. |
| SC-23 | Session Authenticity | Partial | TLS 1.3 SIP listeners wired (see SC-8). STIR/SHAKEN (`proto-stir-shaken`) is Library-only. |

### SI - System and Information Integrity

| Control | Title | Status | Implementation |
|---------|-------|--------|----------------|
| SI-3 | Malicious Code Protection | Planned | Input validation |
| SI-4 | System Monitoring | **Wired (sbc-daemon, sbc-api-server)** | `uc-metrics::SbcMetrics` registry in the daemon; Prometheus text served by `sbc-api-server` at `/api/v1/system/metrics`. |
| SI-11 | Error Handling | **Wired** | `uc-types::error` structured errors without info leakage |

### SA - System and Services Acquisition

| Control | Title | Status | Implementation |
|---------|-------|--------|----------------|
| SA-11 | Developer Testing | In Progress | Unit tests with assertions |

## Implementation Notes

### Documenting Controls in Code

All security-relevant code includes NIST control references in doc comments:

```rust
/// NIST 800-53 Rev5: SC-13 (Cryptographic Protection)
///
/// Computes SHA-384 hash of the input data.
pub fn sha384(data: &[u8]) -> [u8; 48] {
    // ...
}
```

### Verification

Control implementations are verified through:

1. **Unit Tests**: Each module has tests validating correct behavior (e.g. `sbc-config/src/validate.rs`, `sbc-daemon/src/sip_stack.rs` admission tests).
2. **Integration Tests**: `crates/sbc/sbc-integration-tests`. There is no `tests/compliance/` directory.
3. **Audit Logging**: Planned. No audit sink is wired into a shipped binary (see AU-2); security events are currently visible only in `tracing` output.

## References

- [NIST SP 800-53 Rev5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [NIST SP 800-53B](https://csrc.nist.gov/publications/detail/sp/800-53b/final) - Control Baselines
