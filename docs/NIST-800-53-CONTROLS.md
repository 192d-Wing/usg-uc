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
| AU-2 | Event Logging | **Wired (sbc-daemon)**, opt-in | With `logging.audit_enabled`, `sbc-daemon` initialises `uc-audit` (`runtime.rs`) and records startup/shutdown, REGISTER authentication outcomes, INVITE admission/VPS rejections, call establishment/termination and rate-limit rejections (`sip_stack.rs`, `server.rs`). Off by default. |
| AU-3 | Content of Audit Records | **Wired (sbc-daemon)**, opt-in | `uc-audit::record` structured records (sequence, UTC timestamp, typed event, hash chain) written for every event above. |
| AU-4 | Audit Log Storage Capacity | **Wired (sbc-daemon)**, opt-in | `uc-audit::sink::FileSink` appends JSON lines to `logging.audit_path`; without a path records go to the tracing output (target `audit`). Rotation/retention is the platform's. |
| AU-8 | Time Stamps | **Wired (sbc-daemon)**, opt-in | `uc-audit::record` UTC timestamps on every record. |
| AU-9 | Protection of Audit Information | **Wired (sbc-daemon)**, opt-in | `uc-audit::record` SHA-384 hash chain across records (`AuditRecord::verify`); file permissions are the platform's. |
| AU-10 | Non-repudiation | Planned | Cryptographic signing of audit records |

### CM - Configuration Management

| Control | Title | Status | Implementation |
|---------|-------|--------|----------------|
| CM-2 | Baseline Configuration | **Wired (sbc-daemon)** | `sbc-config::schema` typed configuration, loaded at startup (`sbc-daemon/src/runtime.rs`, `load_config`). |
| CM-6 | Configuration Settings | **Wired (sbc-daemon)** | `sbc-config::validate::validate_config` runs on load and via gRPC `ConfigService.ValidateConfig`. Since this change `validate_config` also rejects: `media.default_mode` other than `Relay`, any non-empty `media.realm_modes`, `media.codecs` that is not the default set (order-insensitive), `general.max_registrations = 0`, trunk `max_calls = 0` / `max_failures = 0`, and `options_ping_interval_secs` outside 5..=3600 when `options_ping_enabled` (`sbc-config/src/validate.rs`; tests `test_media_default_mode_must_be_relay`, `test_media_realm_modes_rejected`, `test_media_codecs_must_equal_default_set`, `test_trunk_limits_must_be_positive`, `test_trunk_options_ping_interval_bounds`, `qa_media_default_mode_non_relay_rejected`, `qa_media_realm_modes_rejected_even_when_relay`, `qa_media_codecs_only_default_set_accepted`, `qa_general_max_registrations_zero_rejected`, `qa_trunk_limit_keys_enforced_or_rejected`, `qa_trunk_options_ping_keys_bounds`). Trunk `cooldown_secs` and `max_failures` now reach the router's `TrunkConfig` (test `qa_config_cooldown_and_max_failures_reach_router`). `sbc-media` accepts only `SBC_MEDIA_DEFAULT_MODE=relay` and fails at startup otherwise (`sbc-media/src/main.rs` `parse_default_mode`; test `default_mode_only_accepts_relay`). |
| CM-7 | Least Functionality | **Wired (sbc-daemon, sbc-media)** | Configuration for functions the live relay does not provide (pass-through/signaling-only media, per-realm modes, codec lists that would imply transcoding) is rejected instead of silently ignored; see CM-6 for code and tests. |

### CP - Contingency Planning

| Control | Title | Status | Implementation |
|---------|-------|--------|----------------|
| CP-8 | Telecommunications Services | **Wired (sbc-daemon)**, partial | Trunk failover within the selected route groups (`sbc-daemon/src/sip_stack.rs` `is_failover_status`, `try_failover`; `uc-routing/src/router.rs` `route_to_groups`, capped by `routing.max_failover_attempts`). Triggers: 408, Timer B, 500, 502, 503, 504, and a trunk URI that does not resolve. No failover on other 4xx or 6xx, or after a 2xx or a reliable 18x carrying SDP has been relayed. A 503 also puts the trunk into `cooldown_secs` cooldown (the trunk's own Retry-After is ignored). Trunks marked down by OPTIONS health (config-file trunks with `options_ping_enabled`, and API trunks) are skipped (`runtime.rs` `start_config_trunk_monitors`, `spawn_trunk_health_feed`). Tests: `failover_on_503_retries_next_trunk_with_same_sdp`, `failover_exhausted_relays_last_error_and_releases`, `timer_b_fails_over_then_408_when_exhausted`, `qa_every_failover_status_moves_call_to_second_trunk`, `qa_client_and_global_errors_never_fail_over`, `qa_failover_still_happens_after_unreliable_or_sdp_less_18x`, `no_failover_after_reliable_early_media`, `options_down_trunk_is_skipped`, `qa_trunk_marked_down_mid_call_then_up`. **Not implemented:** failover on B-leg transport send errors (POA&M-2). The runtime health-feed task has no test. |

### IA - Identification and Authentication

| Control | Title | Status | Implementation |
|---------|-------|--------|----------------|
| IA-2 | Identification and Authentication | **Wired (sbc-daemon), off by default** | REGISTER authorization via `proto-registrar`: RFC 8898 Bearer tokens (`sbc-daemon/src/server.rs`, `build_bearer_authenticator`) are enabled only with `SBC_AUTH_MODE=bearer` + `SBC_OIDC_ISSUER`. Digest auth (`AuthenticatedRegistrar`) is compiled in but `require_auth`/`auth_credentials` are never set from configuration; without the env var the daemon logs "REGISTER is UNAUTHENTICATED". |
| IA-5 | Authenticator Management | Library-only | `proto-registrar` digest credential store; no TOML/env path populates it. |
| IA-9 | Service Identification | Library-only | `proto-stir-shaken` (ES384-only PASSporT verification). Not a dependency of any `crates/sbc` binary; the `[stir_shaken]` config section is parsed but unused. |

### SC - System and Communications Protection

| Control | Title | Status | Implementation |
|---------|-------|--------|----------------|
| SC-5 | Denial of Service Protection | **Wired (sbc-daemon)** | `uc-dos-protection::RateLimiter` per-source-IP and global limiters (`sbc-daemon/src/server.rs`); `general.max_calls` admission control (503) in `sip_stack.rs`; `rate_limit.per_user_rps` per-user limiter (`server.rs`, test `per_user_rate_limit_answers_503_with_retry_after`). Per-trunk `max_calls`: a trunk at capacity is skipped; when every trunk in the route is full or down the caller gets 503 `Retry-After: 5` (`uc-routing/src/router.rs` `acquire_trunk`/`release_trunk`; tests `trunk_at_max_calls_is_skipped_then_503_when_all_full`, `test_route_skips_full_trunk_then_errors_when_all_full`, `qa_bye_cancel_race_releases_exactly_once`). `vps.per_callee_max_concurrent` keyed on the dialed (pre-translation) number (`uc-vps/src/engine.rs` `screen_and_reserve`; tests `per_callee_max_concurrent_rejects_the_next_call`, `all_trunks_down_503_releases_vps_slot`). `general.max_registrations` counts bindings by the registrar's binding key (instance-id:reg-id per RFC 5626, else contact URI), checked after authentication under the registrar lock; over the cap REGISTER gets 503 `Retry-After: 60` and nothing is stored (`proto-registrar/src/registrar.rs` `process_register_with_admission`, `new_binding_count`; tests `max_registrations_rejects_new_bindings_but_allows_refresh`, `qa_max_registrations_counts_bindings_and_allows_deregistration_forms`, `qa_max_registrations_allows_rebooted_phone_same_contact_new_call_id`, `max_registrations_counts_multi_contact_register_after_dedup`, `test_admission_runs_after_auth_and_stores_nothing_when_refused`, `test_admission_same_uri_new_instance_at_cap_is_refused`, `test_admission_same_instance_new_uri_at_cap_is_accepted`). gRPC `PublishTrunkStatus` rejects more than 4096 health or registration entries per publish with `InvalidArgument` and ignores unknown trunk IDs (`grpc_server/trunk_status_publish_service.rs`, `MAX_PUBLISHED_TRUNKS`; no test asserts the 4096 cap). All three caps (trunk `max_calls`, per-callee, `max_registrations`) are **per node** — see POA&M-1. |
| SC-7 | Boundary Protection | **Wired (sbc-daemon)** | `proto-sip::TopologyHider` initialised from `[topology_hiding]` and applied to external B-legs (`sbc-daemon/src/sip_stack.rs`). |
| SC-8 | Transmission Confidentiality | **Wired (sbc-daemon, sbc-media-core)** | SIP-over-TLS listeners use `uc-transport::tls::create_server_config_with` (TLS 1.3 only by default; `security.min_tls_version = "1.2"` admits 1.2; `security.require_mtls` + `tls_ca_path` requires client certificates); listeners are skipped with a warning when `security.tls_cert_path` is unset. SRTP relay/termination accepts only `AEAD_AES_256_GCM` (`sbc-media-core/src/srtp_relay.rs`, `dtls_relay.rs`). The REST HTTPS listener (`api_server.rs`) uses rustls defaults (TLS 1.2 permitted). |
| SC-12 | Cryptographic Key Establishment | Library-only (`uc-crypto::ecdh`, `uc-crypto::hkdf`) | No shipped binary or `proto-*` crate calls the ECDH/HKDF helpers. Key establishment in the shipped path is TLS 1.3 (rustls) and DTLS-SRTP performed by the external Go DTLS sidecar (`sbc-media-core/src/dtls_sidecar.rs`). |
| SC-13 | Cryptographic Protection | **Wired (sbc-daemon, sbc-media-core)** | rustls aws-lc-rs FIPS provider installed at startup (`sbc-daemon/src/main.rs`; workspace `rustls` features `fips`). `uc-crypto` exposes only SHA-384/512, AES-256, P-384 and is used by `proto-srtp`/`proto-dtls`. |
| SC-23 | Session Authenticity | Partial | TLS 1.3 SIP listeners wired (see SC-8). STIR/SHAKEN (`proto-stir-shaken`) is Library-only. |

### SI - System and Information Integrity

| Control | Title | Status | Implementation |
|---------|-------|--------|----------------|
| SI-3 | Malicious Code Protection | Planned | Input validation |
| SI-4 | System Monitoring | **Wired (sbc-daemon, sbc-api-server)** | `uc-metrics::SbcMetrics` registry in the daemon; Prometheus text served by `sbc-api-server` at `/api/v1/system/metrics`. |
| SI-10 | Information Input Validation | **Wired (sbc-daemon)** | The translated number (SBC router / dial plan) is validated before it is placed in the B-leg Request-URI user and To: RFC 3261 §25.1 unreserved/user-unreserved characters only (no `;`, `?`, `%`, `@`, CR/LF, space, `<`/`>`), at most 64 characters; otherwise the caller gets 500 and nothing is sent (`sip_stack.rs`, `is_safe_b_leg_user`, `MAX_B_LEG_USER_LEN`; tests `translated_number_is_on_b_leg_request_uri_and_to`, `unsafe_translation_is_rejected_with_500_and_nothing_sent`, `safe_b_leg_user_charset`, `qa_header_injection_in_translated_number_is_rejected`, `qa_translated_number_on_failover_invite_wire_bytes`). |
| SI-11 | Error Handling | **Wired** | `uc-types::error` structured errors without info leakage |

### SA - System and Services Acquisition

| Control | Title | Status | Implementation |
|---------|-------|--------|----------------|
| SA-11 | Developer Testing | In Progress | Unit tests with assertions |

## Plan of Action and Milestones (POA&M)

Open items from the dead-config-features change (each has a `// POAM:` in code where noted).

| ID | Control | Item | Location |
|----|---------|------|----------|
| POA&M-1 | SC-5 | Trunk `max_calls`, `per_callee_max_concurrent` and `max_registrations` are counted per node; a cluster of N nodes admits N x cap. Cluster-wide counting is a follow-up (uc-state-sync). | `// POAM:` in `uc-routing/src/router.rs` (`select_trunk_from_group`, `acquire_trunk`), `uc-vps/src/engine.rs` (`screen_and_reserve`) |
| POA&M-2 | CP-8 | B-leg transport send errors do not trigger failover (RFC 3263 §4.3); only an unresolvable trunk URI does. | `// POAM:` at `is_failover_status`, `sbc-daemon/src/sip_stack.rs` |
| POA&M-3 | AU-2 | Trunk failover and trunk reachability changes are logged only; no `uc-audit` event type. | `// POAM:` in `sip_stack.rs` (failover) and `runtime.rs` (reachability) |
| POA&M-4 | AU-3 | New denial records (`no-usable-trunk`, `number-translation-invalid`, `max-registrations`) carry no source IP, and no test asserts these audit events. | `sip_stack.rs` |
| POA&M-5 | SC-8 | Failover INVITE keeps the original R-URI scheme/host and the hard-coded UDP Via transport; not derived from the target trunk. | `// POAM:` above `try_failover`, `sip_stack.rs` |
| POA&M-6 | SC-5 | Trunk host resolution uses blocking `to_socket_addrs` on the async path, now once per failover hop (SEC-003). | `sip_stack.rs` |
| POA&M-7 | SC-5 / CP-8 | `per_callee_max_concurrent` also applies to emergency numbers (911/933); exemption or confirmation that emergency routing bypasses VPS is needed (SEC-004). | `uc-vps/src/engine.rs` |
| POA&M-8 | SC-5 | The B-leg INVITE is deep-cloned as the failover template on every call that has failover targets (PERF-002); fix needs `ProcessResult::Forward` to carry `Arc<SipRequest>` or bytes. | `sip_stack.rs` |
| POA&M-9 | SI-10 / SC-5 | Pre-existing registrar issues: RFC-R1-01 REGISTER processing is not atomic; RFC-R1-02 a duplicate contact yields 500; RFC-R1-03 (remaining half) plain `expires=0` removal has no Call-ID/CSeq ordering check (key-based removal and the moved-flow ordering check are fixed: tests `expires_zero_plain_removes_only_plain`, `moved_flow_with_stale_cseq_is_rejected`); RFC-R1-04 `TooManyContacts` yields 500. | `crates/proto/proto-registrar` |

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
3. **Audit Logging**: Wired, opt-in via `logging.audit_enabled` (see AU-2). Without it, security events are visible only in `tracing` output.

## References

- [NIST SP 800-53 Rev5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [NIST SP 800-53B](https://csrc.nist.gov/publications/detail/sp/800-53b/final) - Control Baselines
