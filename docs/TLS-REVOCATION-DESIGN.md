# TLS Certificate Revocation (CRL) Design

Status: **phase (a) implemented (2026-11-27); phase (b) open.** Tracked as
POA&M-401 in [NIST 800-53 Controls](NIST-800-53-CONTROLS.md). Decisions D1-D6
below were accepted on 2026-11-25. Operator documentation: SBC admin guide,
"Certificate revocation (CRL files)".

## Phase (a) as built

- `uc-transport/src/revocation.rs`: `CrlSet` (loader, caps, DER walk,
  duplicate-issuer check), `Revocation` (policy plus CRLs; builds the client
  and server verifiers), `classify` / `classify_io`. Handshake failures with a
  revocation cause come back as `TransportError::TlsPeerCertificateRejected`.
- The options structs are unchanged. The CRL-checking configs come from new
  builders, `create_server_config_with_revocation` and
  `create_client_config_verified`; with no CRL the old builders run, so
  behaviour without a CRL is unchanged.
- Directory loading follows a symlink only when its target is a regular file
  inside the directory, so ConfigMap and Secret volumes (keys are symlinks
  into `..data/`) load; a symlink out of the directory and a symlinked top
  path are refused.
- `sbc-daemon/src/tls_revocation.rs`: per-role loading, startup audit,
  aggregated rejection audit, metrics. A CRL past `nextUpdate` at startup
  does not stop the daemon (D1); with `expired_crl = "reject"` rustls fails
  each handshake that needs that CRL.
- The `client_unknown = "allow"` warning is logged by the daemon at startup
  (sbc-config has no logger).
- Session resumption: a resumed TLS session skips certificate verification
  and so the CRL check. Phase (a) loads CRLs once, and session caches are in
  memory, so every resumable session was checked against the current CRLs.
  b1 (reload) must clear or bypass session caches when CRLs change. A
  session resumed after a CRL's `nextUpdate` is not re-verified either, so
  `expired_crl = "reject"` holds for full handshakes only (b2).
- A directory with any file name other than `*.pem`, `*.crl`, `*.der` (or a
  dotfile) is refused rather than skipped. A CRL set above 8 MiB is logged
  as a warning (per-handshake cost, SC-5).
- Bench (`uc-transport` `crl_handshake`, in-memory TLS 1.3, resumption off,
  local run): 0.51 ms without a CRL, 0.67 ms with 1k entries, 2.0 ms with
  100k entries (2.1 MB).

Versions checked: rustls 0.23.46, rustls-webpki 0.103.16, rustls-pki-types
1.15.1, tonic 0.14.6.

## Call sites

Line numbers are against the commit that adds this document.

| # | Path | Verifier build site | Config |
|---|---|---|---|
| V1 | SIP-TLS listener, mTLS client certificates | `crates/uc/uc-transport/src/tls.rs:166-178` `create_server_config_with` (`WebPkiClientVerifier::builder_with_provider(..).build()`); caller `crates/sbc/sbc-daemon/src/server.rs:1733` `bind_tls_listeners` | `security.require_mtls`, `security.tls_ca_path` |
| V2 | Trunk egress TLS | `tls.rs:289` `create_client_config_with` (`with_root_certificates`); caller `server.rs:1577` `load_trunk_tls_clients`, then `sbc-daemon/src/flows.rs:282` `set_tls_clients` | `security.trunk_tls_ca_path` |
| V3 | Trunk egress mTLS (`tls_client_cert = true`) | as V2; second caller in `load_trunk_tls_clients` (`server.rs:1618`) | as V2, plus `security.tls_cert_path` / `tls_key_path` |
| V4 | SIPREC recorder (SRS) TLS | as V2; caller `server.rs:1440` `wire_recording`, then `flows.rs:299` `set_recorder_tls_client` | `recording.srs_tls_ca_file` |
| V5 | CDR syslog (RFC 5425) | `tls.rs:224-235` `create_client_config` (TLS 1.3); caller `sbc-daemon/src/cdr.rs:863` `TlsSyslogConnector::new`, from `cdr.rs:1052-1059` | `cdr.syslog.ca_path`, else `security.tls_ca_path` |

Related paths, outside phase (a):

- `uc-syslog` forwarder (`crates/uc/uc-syslog/src/forwarder.rs`): library only,
  not wired in the daemon (POA&M-195). Phase (a) adds a `crl_file` field to
  `SyslogTlsConfig` and nothing more.
- STIR `x5u` fetch (`uc-sti/src/fetch.rs`): public Web PKI roots. It gets no CRL
  support. STI certificate revocation is POA&M-28.
- Daemon and sbc-media gRPC mTLS (`grpc_server/mod.rs`, `sbc-media/src/grpc_tls.rs`):
  tonic 0.14 `ServerTlsConfig` has no CRL hook. Revocation there needs
  `serve_with_incoming` with a uc-transport acceptor (item b7).
- REST HTTPS: no client certificates, so not applicable.

## rustls / webpki behaviour

API (both `WebPkiClientVerifier` and `WebPkiServerVerifier` builders):

- `with_crls(iter of CertificateRevocationListDer)` (appends),
  `only_check_end_entity_revocation()`, `allow_unknown_revocation_status()`,
  `enforce_revocation_expiration()`, then `build()`. `build()` fails with
  `VerifierBuilderError::InvalidCrl` for a CRL it cannot parse.
- Defaults once CRLs are given: depth = whole chain, unknown status = deny,
  expired CRL = ignored.
- Client side: build a `WebPkiServerVerifier` and pass it to
  `with_webpki_verifier` (not the `dangerous()` API). With no CRL configured,
  keep `with_root_certificates`, so behaviour without CRLs is unchanged.
- PEM CRLs load with `CertificateRevocationListDer::pem_file_iter` /
  `pem_slice_iter` (label `X509 CRL`); DER files are used as-is.
- FIPS status (`ClientConfig::fips()`, `ServerConfig::fips()`) does not depend
  on the verifier. CRL signatures are verified with the aws-lc FIPS provider's
  algorithms. A CRL signed with SHA-1 is rejected (fails closed).

Behaviour the design has to handle:

1. webpki uses the **first** authoritative CRL for an issuer. Two CRLs from the
   same issuer can make the older one win. The loader rejects duplicate issuers.
2. The CRL signature is verified on **every handshake**, per checked chain
   element. Cost is linear in CRL size (about 0.1 ms for 100 KB, 7-10 ms for
   10 MB). A large CRL amplifies a handshake flood.
3. Unknown status means no CRL from the certificate's issuer with a matching
   scope. With deny and chain depth, every non-anchor CA in the chain needs a CRL
   from its issuer (the root's ARL for intermediates).
4. Delta and indirect CRLs are not supported; `build()` fails, so this is a
   startup error.
5. `nextUpdate` is not exposed. Expiry monitoring needs a bounded DER walk of
   `TBSCertList` in our code (no new dependency).
6. With expiry enforced, `now >= nextUpdate` fails the handshake. There is no
   grace period setting.
7. rustls does not validate OCSP. A stapled response from a server is logged at
   trace level only.

## Proposed configuration

```toml
[security]
tls_crl_path       = "/etc/sbc/client-crl"   # V1; needs require_mtls and tls_ca_path
trunk_tls_crl_path = "/etc/sbc/trunk-crl"    # V2, V3; needs trunk_tls_ca_path

[security.revocation]            # one policy for all paths (D6)
check_depth    = "chain"         # "chain" | "end_entity"      (D4)
client_unknown = "deny"          # V1: "deny" | "allow"
server_unknown = "deny"          # V2-V5: "deny" | "allow"     (D2)
expired_crl    = "reject"        # "reject" | "ignore"         (D1)
require        = false           # true: every enabled TLS path needs a CRL path (D3)

[recording]
srs_tls_crl_file = "/etc/sbc/srs-crl.pem"    # V4

[cdr.syslog]
crl_path = "/etc/sbc/syslog-crl"             # V5
```

- A CRL path is a PEM or DER file, or a directory of `*.pem`, `*.crl`, `*.der`
  regular files (symlinks not followed). Caps: 256 files, 64 MiB per file,
  256 MiB total. A configured path that yields no CRL is an error.
- `[security.revocation]` rejects unknown keys.
- Validation: CRL paths must be absolute; a CRL path without its CA path or
  without its feature enabled is an error; `require = true` with an enabled TLS
  path that has no CRL path is an error; `client_unknown = "allow"` with
  `require_mtls` logs a warning.
- File contents are checked at startup. A bad CRL fails that TLS path the same
  way a bad CA bundle does today.
- Audit events: `TlsRevocationListLoaded` (Configuration, per role at startup)
  and `TlsPeerCertificateRejected` (Security; reason `revoked`,
  `unknown_status`, `crl_expired` or `crl_invalid`; aggregated per role and
  reason over 60 s).
- Metrics: `tls_revocation_rejections_total{role,reason}`,
  `tls_revocation_enabled{role}`, `tls_crl_next_update_seconds{role}`.
- Helm: optional ConfigMap or Secret mounted as a directory (no `subPath`) at
  `/etc/sbc/trunk-crl`.
- Cluster: CRLs are node-local files. Every node needs the same CRL set.

## Phase (a): minimal CRL-file support

One PR, about 16 files (2 new), about 1,800 changed lines, most of them tests.

| Unit | Scope | Est. LOC (src / tests) |
|---|---|---|
| A | `uc-transport`: new `revocation.rs` (policy, CRL loader, DER metadata walk, caps, duplicate-issuer check, error classifier); revocation fields on `TlsServerOptions` / `TlsClientOptions`; one shared server verifier for V2 and V3 | 320 / 330 |
| B | `uc-audit` events; `sbc-config` schema keys and validation | 150 / 180 |
| C | `uc-syslog` `SyslogTlsConfig.crl_file` | 20 / 60 |
| D | `sbc-daemon`: wire V1-V5, classify handshake failures, metrics, startup audit | 260 / 300 |
| E | Helm values and templates, example `config.toml` | 40 |
| F | Admin guide, NIST matrix, CNSA doc, changelog | 120 |

CRLs are loaded once at startup. Changing a CRL needs a restart in phase (a).

## Phase (b): follow-ups

Separate PRs, each mergeable after (a).

| Item | Scope | Est. LOC (src / tests) |
|---|---|---|
| b1 | Reload on SIGHUP, file poll and gRPC `ReloadTls`, through `ArcSwap` verifier delegates; a failed reload keeps the previous verifier | 550 / 450 |
| b1' | Re-check live trunk, SRS and inbound mTLS connections when a CRL changes | 250 / 200 |
| b2 | Expiry monitoring (gauges, warning window, audit, health) and an optional grace period | 300 / 250 |
| b3 | Load-time checks: CRL signature against its issuer in the CA bundle, issuer must be in the bundle, keep newest per issuer | 250 / 250 |
| b4 | OCSP stapling of the SBC's own SIP-TLS certificate; also addresses POA&M-194 | 400 / 300 |
| b5 | OCSP client validation (peer staple and AIA fetch) | 1,500-2,500 |
| b6 | CRL fetch from CDP: sample CronJob / systemd timer that writes the files | about 80 |
| b7 | Management-plane gRPC mTLS (daemon, sbc-media) with CRLs | about 400 |

## Deliberately not built

- A custom certificate verifier. rustls' built-in CRL path is used; phase (b)
  only adds a thin reload delegate.
- OCSP client validation (b5): no rustls support and no OCSP crate in the tree.
  Stays on POA&M-401 unless D5 says otherwise.
- In-daemon CRL download from CDP URLs (b6 is out of process).
- CRL checking for the STIR `x5u` fetch (public Web PKI; POA&M-28).
- Delta and indirect CRLs.

## Tests (phase a)

- `uc-transport`: loader (PEM, DER, multi-PEM, directory; rejects empty,
  oversize, symlink, delta, indirect, garbage, duplicate issuer); DER metadata
  walker (truncated, over-length, wrong tags; random input never panics);
  loopback handshakes for V1 and V2: revoked leaf rejected, good leaf accepted,
  unknown issuer under deny and allow, expired CRL under reject and ignore,
  revoked intermediate under chain and end-entity depth, `fips()` still true.
  CRLs generated with rcgen 0.13 `CertificateRevocationListParams`.
- No-CRL configurations: existing tests unchanged.
- `sbc-config`: every validation rule, positive and negative; TOML round trip;
  unknown keys rejected.
- `uc-syslog`: revoked collector fails to connect.
- `sbc-daemon`: revoked trunk and SRS certificates fail closed with no
  downgrade; SIP mTLS listener rejects a revoked client certificate; reject
  audit aggregated with a count; metric incremented; bad CRL file fails
  `bind_tls_listeners`; revoked syslog collector not connected; startup audit
  per role.
- Integration: REGISTER over TLS with a revoked certificate never reaches the
  registrar; INVITE to a TLS trunk with a revoked certificate fails with no UDP
  fallback.
- Bench: TLS handshake with 0, 1k and 100k CRL entries.

## Decisions

Accepted 2026-11-25 as recommended. Each changes runtime behaviour.

| # | Question | Decision |
|---|---|---|
| D1 | Expired CRL (`now >= nextUpdate`): reject (fail closed) or ignore (fail open, logged)? At startup, refuse to start or fail only that path? | `reject`. At startup, start, log, audit and fail only that TLS path closed. Until b1 ships, a fresh CRL needs a restart, or b1 is pulled into the first PR. |
| D2 | Unknown status for server certificates (trunk, SRS, syslog): deny or allow? | `deny` for SRS and syslog; explicit operator setting for trunks, default `deny`. Clients (V1): `deny`. |
| D3 | CRL mandatory whenever a TLS path is enabled, or optional? | Optional, plus `security.revocation.require = true` as the hardening switch. |
| D4 | Check depth: whole chain or end entity only? | `chain` (RFC 5280 path validation). |
| D5 | First PR scope: (a) alone or (a)+b1? Is b5 (OCSP client) permanently out? Is b6 out of process? | (a) alone; b5 stays on POA&M-401; b6 out of process. |
| D6 | One revocation policy for all paths, or per-path overrides? | One `[security.revocation]` table with split `client_unknown` / `server_unknown`; per-path overrides only if D2 differs per path. |
