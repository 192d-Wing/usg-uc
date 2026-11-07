# Changelog

All notable changes to the USG Unified Communications SBC project will be documented in this file.

The format is based on [Keep a Changelog v1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Planned SBC 0.11.0. The proto-sip hardening below also affects the soft client.

### BREAKING (SBC storage, dormant data-plane batch POA&M-230..237)

- **SBC: `uc-storage` now fails closed on insecure transport.** (SC-8,
  SC-13, SI-10; POA&M-230) Postgres `ssl_mode` now defaults to
  `verify-full` (it used to be `prefer`). `disable`, `prefer` and `require`
  are rejected at startup unless `allow_insecure_transport = true` is set.
  `require` is included because it does not authenticate the server.
  Redis `redis://` and `unix://` URLs need the same opt-in. These are always
  rejected, opt-in or not: `tls.verify_certificate = false`, an `#insecure`
  URL fragment, a client cert without its key (or a key without its cert),
  and a `tls` block on a non-`rediss://` URL. A URL `sslmode=` can no longer
  downgrade the configured `ssl_mode`. When the opt-in is used, a `warn!` is
  logged. New keys: `postgres.ssl_root_cert`,
  `postgres.allow_insecure_transport`, `redis.allow_insecure_transport`.
  **Upgrade:** use `verify-ca`/`verify-full` and `rediss://` (setting
  `ssl_root_cert` if needed), or set `allow_insecure_transport` on purpose.
  The negotiated suites are the aws-lc-rs defaults and are not yet pinned to
  CNSA (POA&M-230).
- **SBC: Redis `cluster_mode = true` is now rejected.** (CM-6, SI-10) It was
  never implemented and used to be ignored without any warning.
- **Library API:** `StorageError::InsecureTransport`,
  `ClusterError::AuthenticationFailed` and
  `StateSyncError::AuthenticationFailed` are new variants. `ClusterMembership::handle_heartbeat` is now `pub(crate)`; use
  `handle_authenticated_heartbeat` instead.
  `SnapshotReader::add_chunk` now returns `StateSyncResult<()>`.
  `SyslogTransport::Tls` is new.

### Security

- **uc-cluster / uc-state-sync: authenticated peer envelopes.** (IA-3,
  SC-8, SC-23; POA&M-231, -232) Heartbeats and replication messages are
  sealed with HMAC-SHA-384 (key at least 48 bytes, compared in constant
  time). Messages are checked against the configured peer list, a 30 s
  timestamp window, and a generation/sequence replay window. Snapshot
  reassembly is bounded (65,536 chunks, 256 MiB) and rejects duplicate and
  out-of-range chunks. This is library-only for now: there is no transport,
  key distribution or rotation (POA&M-231) and no split-brain fencing
  (POA&M-232). sbc-config and sbc-daemon still need to wire `cluster.auth`.
- **uc-user-mgmt: `PkiValidator` now always rejects.** (IA-2(12), IA-5(2);
  POA&M-233) The old substring CN/EDIPI parser did not validate the
  certificate chain, so it has been removed. Every certificate gets
  `CertificateValidationFailed` until validation with webpki, a client-auth
  EKU check and a CRL check is in place.
- **uc-api: routes are denied by default.** (AC-3, AC-6; POA&M-234) A route
  must have a permission or be marked `public()`. Every SBC route now has a
  `*:read`/`*:admin` permission. `/config` needs `config:read` for GET and
  `config:admin` for PUT. Only the health check is public. Library-only:
  sbc-daemon must call `Router::authorize`.
- **uc-storage:** passwords are redacted in `Debug` output, logs and driver
  errors. This covers URL userinfo, query parameters and quoted libpq DSNs.
  Serialize still emits the password (POA&M-237). Redis `KEYS` is replaced
  by a capped `SCAN` (COUNT 1000, at most 100,000 results), and pooled Redis
  connections are marked broken after fatal I/O errors.
- **uc-syslog: RFC 5425 TLS transport.** (AU-9, SC-8, SC-13; POA&M-235)
  `transport = "tls"` (default port 6514) uses the CNSA 2.0 provider
  (TLS 1.3 only, or 1.2 with CNSA suites if `allow_tls12` is set), supports
  optional mTLS, and uses octet-counted framing. `close()` sends
  close_notify. Startup fails if the `tls` block is missing or incomplete,
  if a `tls` block is set on udp/tcp, or if `use_rfc5424 = false`.
  Delivery is at-least-once and messages are not buffered while the
  collector is down. Certificate-fingerprint pinning is not implemented
  (POA&M-235). Library-only. SNMP is unchanged (POA&M-236).

### Changed

- **Dependencies (SBC):** `bb8-redis` has been removed and replaced by a
  local bb8 manager. New feature flags: `redis/tokio-rustls-comp` and
  `sqlx/tls-rustls-aws-lc-rs` (`tls-rustls-insecure` is not enabled).
  `uc-cluster` now uses `uc-crypto` and `zeroize`. `uc-syslog` now uses
  `uc-transport` and `tokio-rustls`, with dev-dependencies `rcgen`,
  `tempfile` and `serde_json`. No new third-party runtime crates: the lock
  only adds a `webpki-roots` 0.26 compatibility shim, which comes in through
  the sqlx TLS feature and is not in the active build.

### BREAKING (SBC config, live batch POA&M-190..192, 166)

- **SBC: `[monitoring]` and `[telemetry.otlp]` are now rejected at config
  load.** (CM-6, CM-7, SI-10; POA&M-191) Before, both tables were parsed and
  silently ignored: no metrics exporter, SNMP, syslog or OTLP exporter
  read them. This covers every `[monitoring]` key, including
  `[monitoring.snmp]` and `[monitoring.syslog]` (`[cdr.syslog]` is a
  different table, still supported, and not affected). **We chose to reject
  rather than warn.** A setting that loads and is then ignored makes
  operators and assessors think monitoring or OTLP export is running when it
  is not. A log warning is easy to miss, and a failed start is not.
  **Upgrade:** remove these tables from `sbc.toml` before upgrading. In a
  mixed-version cluster, old nodes still accept the tables and new nodes
  refuse them, so remove them from the shared config first.
- **SBC: the TLS private key must match `security.curve`.** (SC-12, SC-13;
  POA&M-166) The SIP-TLS listener key and the trunk mTLS client key are
  loaded pinned to the configured curve. A P-521 key with
  `curve = "P-384"` (or the reverse) now stops startup.
- **SBC: new `stir_shaken.verification.max_fetches_per_source` key
  (default 4; must be in `1..=max_concurrent_fetches`).** (SC-5; POA&M-190)
  This caps concurrent x5u certificate fetches per source (IPv4 address or
  IPv6 /64). Sources that can't be identified share one budget. **Upgrade:**
  if you set `max_concurrent_fetches` below 4, also set
  `max_fetches_per_source` to that value or lower, or config load fails.
  When verification is on and `x5u_allow_hosts` is empty, startup logs a
  warning.
- **Helm (`deploy/helm/sbc`): `[monitoring]` is no longer rendered into
  `sbc.toml`.** `sbcDaemon.config.metrics_listen` is kept but reserved.
  `services.metrics.enabled` now defaults to `false`, because the
  `<release>-metrics` Service pointed at port 9090 and nothing listens
  there. Before re-enabling it, check whether anything scrapes it.

### Added

- **SBC audit schema (additive):** `CryptoKeyOperation` events gain
  `outcome` (`failure`) and `reason` (sanitised, at most 256 bytes, file
  names only). Both fields are omitted on success, so success records are
  byte-identical to before. SIEM parsers should treat both as optional. TLS
  key load at startup and gRPC `ReloadTls` now emit these events (AU-2,
  AU-3, SC-12; POA&M-166).

### Changed

- **SBC routing:** partition-scoped route lookups use a per-partition index.
  Results and ordering are unchanged (POA&M-192).

### Security

- **SBC: management-API hardening (BREAKING for admin sessions,
  provisioning URLs and REST TLS).** (NIST 800-53 Rev5: IA-2, IA-5, SC-8,
  SC-12, SC-13, SC-5, SC-23; POA&M-210..214) **Upgrade notes:**
  - Admin tokens are now `v2.` HMAC-SHA-384 with `aud=sbc-api`. v1 tokens
    are rejected with no fallback; operators must log in again after
    upgrade.
  - `SBC_AUTH_SIGNING_KEY` (if set) must be hex and decode to at least 32
    bytes (48 recommended; shorter keys log a warning). Empty, non-hex or
    short keys stop startup. `SBC_AUTH_TOKEN_TTL_SECS` must be within 60..=86400.
    New Helm installs generate a 48-byte hex key; existing 32-byte keys are
    kept and still load.
  - Provisioning tokens are now HMAC-SHA-384 (96 hex chars). When
    `SBC_PROVISION_SECRET` is set it must be hex and decode to at least 32
    bytes (`openssl rand -hex 48`). Existing `?token=` URLs return 403 until
    re-minted with `sbc-provision-server --mint-token <MAC>`. Deployments
    that rely only on `allowedSourceCidrs` are unaffected.
  - The REST HTTPS listener uses the CNSA provider, TLS 1.3 only (whatever
    `security.min_tls_version` says) and HTTP/1.1 only. It applies the
    checked key load and curve enforcement, fails closed when no acceptor
    is configured, caps connections at 256, and sets a 10 s handshake
    timeout, a 10 s idle/header timeout and a 300 s maximum connection age.
    The cert and key are reloaded within 30 s of changing on disk.
  - `SBC_API_TOKEN` is compared in constant time.
  - New metrics: `sbc_api_tls_handshake_timeouts_total`,
    `sbc_api_tls_connections_rejected_total`,
    `sbc_api_tls_cert_reloads_total`,
    `sbc_api_tls_cert_reload_failures_total`.

- **SBC: TLS private key files are checked at load and the key curve is
  enforced (BREAKING, SEC-001).** (NIST 800-53 Rev5: SC-12, SC-13, SC-28,
  SC-4) **Upgrade note:** the SIP-TLS listeners, the trunk client key and
  the REST HTTPS listener now refuse to start, or keep the old key on
  reload, when the key file is a symlink, is not a regular file, is group-
  or world-readable (any `0o077` bit), is not owned by the SBC's effective
  user, or exceeds 64 KiB. RSA and P-256 keys are rejected; only ECDSA
  P-384 or P-521 are accepted. Before upgrading, `chmod 0600` (or `0400`)
  the key, `chown` it to the SBC user, and reissue any RSA or P-256
  certificates on P-384. In `uc-crypto`, AES-256-GCM and P-384 PKCS#8 key
  bytes are now wiped on drop, and the `open()` buffer is wiped when the
  tag check fails (POA&M-160..164).

- **SBC: topology hiding covers the whole dialog, both directions
  (peer-visible).** (NIST 800-53 Rev5: SC-7, AC-4, SI-17, SI-11, AU-12, SI-4;
  RFC 3261 §8.2.6.2, §18.2.2; POA&M-155, POA&M-156) With
  `topology_hiding.enabled`, every request and response the SBC sends toward
  a hidden leg is rewritten, not only the B-leg initial INVITE: 1xx/2xx and
  error relays, ACK, re-INVITE, UPDATE, BYE, CANCEL, the local 405 to
  in-dialog PRACK/INFO/MESSAGE/NOTIFY (not relayed yet, POA&M-182),
  out-of-dialog responses (OPTIONS, REGISTER, 405, 481),
  timer 408/BYE, failover INVITEs, media-failure BYEs and the
  post-announcement BYE. Retransmissions resend the hidden bytes.
  - **Upgrade note:** the caller-facing leg is now hidden when the caller is
    an inbound trunk or outside `topology_hiding.internal_networks`, so
    inbound trunk calls see `external_host` in the SBC's Via/Contact/
    Record-Route. `external_host` must route back to the SBC. The callee
    leg is likewise hidden toward a trunk or any destination outside
    `internal_networks` (e.g. a remote registered endpoint).
  - **3xx Contacts:** in redirect responses only Contacts with an internal
    host are rewritten to `external_host`; external redirect targets pass
    unchanged (RFC 3261 §8.1.3.4, §21.3).
  - **rport:** the SBC's own (rewritten) Via keeps a bare `;rport` flag
    (RFC 3581) instead of dropping it; the B-leg initial INVITE on UDP now
    carries `;rport` too, so CANCEL and non-2xx ACK Vias equal the INVITE's
    (RFC 3261 §9.1, §17.1.1.3).
  - Response Via stacks are never rewritten (new
    `TopologyHider::hide_b2bua_response`); the hider no longer clones the
    header map per call.
  - Fail closed: a message that cannot be hidden is never sent raw. A
    relayed request is dropped and its sender gets 500; a final response
    becomes a bare 500 and an unreliable 1xx is dropped; a reliable
    (`Require: 100rel`) 1xx becomes 500 and the unanswered call is
    CANCELed (on a re-INVITE both legs are BYEd, so no late final is
    relayed after the 500); a 2xx to INVITE becomes 500 and the other leg is BYEd
    (peer-induced teardowns audited as `PolicyTerminated`); a failover
    INVITE fails the call with 503. Each failure is audited as
    `sip.topology_hiding.failed:<Header>`, naming the peer whose message
    failed; the warning log is sampled, the counter and audit are not.
  - New counters `topology_hiding_failures` and
    `header_manipulation_failures` (to be exported as
    `sbc_topology_hiding_failures_total` /
    `sbc_header_manipulation_failures_total`; counted, export deferred to
    POA&M-180).

- **proto-sip / SBC: SIP URI parser, topology hiding and header manipulation
  (BREAKING for some configs and malformed peers).** (NIST 800-53 Rev5: SI-10,
  SC-7, SC-8, SC-5, SC-30, AC-4, CM-6, SI-17; POA&M-150..152)
  - URIs are parsed per the RFC 3261 §25 grammar. The userinfo delimiter is
    the last `@`, so `sip:victim;x=@evil.com` now resolves to host
    `evil.com`. Illegal characters, bad `%` escapes, invalid ports (`:0`,
    `:70000`, `:abc`) and duplicate `transport`/`user`/`ttl`/`method`/
    `maddr`/`lr` parameters are rejected instead of being dropped or
    accepted. URI headers in a Request-URI are rejected. New
    `SipUri::equivalent` (§19.1.4) and generic `Uri` (`sip`/`tel`/other).
  - A Request-URI with a non-SIP scheme (`tel:`, `urn:` ...) is answered
    **416 Unsupported URI Scheme** instead of being dropped.
  - Topology hiding matches internal hosts by CIDR / DNS label, not string
    prefix, and covers 100.64/10, 127/8, 169.254/16, IPv6 ULA, link-local
    and IPv4-mapped IPv6. On the B-leg initial INVITE toward an external
    (trunk) zone, every Via/Contact/Record-Route instance and comma-folded
    element is rewritten, and an element that cannot be parsed rejects the
    call (400 plus audit record `sip.topology_hiding.failed:<header>`)
    instead of being forwarded. Responses relayed back to the caller and
    in-dialog requests were not hidden by this change (POA&M-155, since closed; see above). An invalid
    `internal_networks`/`internal_domains` entry now stops the SBC at
    startup instead of being skipped. Contact rewrites keep
    `transport=tls` / `sips:` and use the new
    `topology_hiding.external_tls_port` (default 5061). New keys
    `topology_hiding.internal_networks` and `internal_domains` add to the
    built-in list. `full` mode is the recommended mode: it hides every host
    that is not `external_host`. `signaling_only` (basic) is best effort and
    leaves public hostnames alone. Call-ID obfuscation uses random tokens in
    a bounded map.
  - Replace/regex-replace/prepend/append results longer than the 8 KiB
    header bound are refused before the value is built (SC-5).
  - Header manipulation now acts on every instance of a header, and
    conditions match if any instance matches. `set` still collapses to one
    instance. Output is validated (no CR/LF/CTL, From/To/Contact/Route/CSeq
    grammar, single From/To/Call-ID/CSeq). An invalid result leaves the
    headers untouched and the SBC rejects the INVITE with 500 and an audit
    record (`sip.header_manipulation.failed:<rule>`).
  - **Config break:** `header_manipulation` rules that target `Via`,
    `Content-Length`, `CSeq` or `Call-ID` (including compact forms) are
    refused at load.
  - **SIEM/alerting:** these failures are written as the existing
    `AuthorizationDecision` event (granted=false). The schema is unchanged.
    The new policy values are `sip.header_manipulation.failed:<rule>` and
    `sip.topology_hiding.failed:<header>`. No Prometheus failure metrics yet
    (counters added under POA&M-156; export is POA&M-180), so alert from audit records.
  - **proto-sip API (client/library consumers):** `obfuscate_call_id`
    returns `SipResult<String>`. `with_internal_network` was removed (use
    `try_with_internal_network`). `SipError` gains `UnsupportedUriScheme`,
    `TopologyHiding` and `ManipulationInvalid`, which breaks exhaustive matches.
  - Helm: `sbcDaemon.topologyHiding.externalTlsPort`, `internalNetworks`
    and `internalDomains` are exposed.
- **Client: SIP-TLS and provisioning HTTPS use the CNSA 2.0 provider.** The
  soft client's SIP-TLS transport (client-core) and the provisioning HTTPS client
  (client-provisioning, which gets a preconfigured rustls config passed to
  reqwest) now build rustls from `uc_transport::tls::cnsa_provider()`, which
  allows TLS 1.3 only with the CNSA suites and key-exchange groups. Before this
  they used the default aws-lc provider. Servers that only offer TLS 1.2 or
  non-CNSA suites now fail the handshake. (NIST 800-53 Rev5: SC-8, SC-13;
  POA&M-173 tracks the residual CM-2 item)

- **SBC: audit trail integrity (uc-audit) (BREAKING for SIEM parsers and
  alerting).** (NIST 800-53 Rev5: AU-5, AU-9, AU-10, AU-8, SI-10)
  - Audit sink writes can now fail and are counted. A write error (for
    example ENOSPC) no longer drops records silently. New gauge
    `sbc_audit_write_failures`, and the `audit` health component reports
    Unhealthy while the sink is failing. **Alert change:**
    `sbc_audit_records_dropped` now counts queue drops plus sink write
    failures, so existing thresholds may fire more often.
  - The hash chain resumes from the last complete record on restart instead
    of starting again at sequence 0. An unterminated tail is truncated and a
    marker is chained. A file that holds only a torn fragment, or that has no
    parsable record, is refused and left untouched.
  - Audit files are created with mode 0640 (existing looser files are
    tightened) and missing directories with 0750. Symlinks, non-regular files
    and group- or world-writable parent directories are refused.
  - New event type `audit_records_dropped` (`count`, `total`, `reason`:
    queue full, sink write failed, torn tail). SIEM parsers must accept it.
  - The record timestamp is now taken on the writer thread.
  - New `sbc-cli audit verify <FILE>... [--require-anchor]`. It checks the
    chain against canonical record bytes, so reordered, extra or re-encoded
    fields count as tampering. Unanchored first files give a warning, or exit 1
    with `--require-anchor`.
  - `sbc-api-server` (`SBC_API_AUDIT_PATH`) and `central-config-api`
    (`CENTRAL_API_AUDIT_PATH`) can write a hash-chained audit file (absolute
    path; unset or empty means tracing only). When it is set, startup fails
    closed (exit 5 / exit 6) if the file cannot be opened, and `/readyz`
    reports not-ready while the sink is failing. Helm: optional
    `sbcApi.auditPath` / `api.auditPath`, unset by default, and the path must
    be on a writable volume. **BREAKING for deployments with an unwritable
    `logging.audit_path`:** sbc-daemon now fails closed and exits with code 3
    when `logging.audit_path` is set but the file cannot be opened or resumed
    (including refused files); the tracing fallback is removed. Unset
    `audit_path` is unchanged (tracing only).
  - Dependency: workspace `hex = "0.4"` (already in the lock tree, 0.4.3; not
    a crypto dependency). Replaces hand-written hex decoding that could panic.
  - Open items: POA&M-130 (keyed chain, HMAC-SHA-384 or ML-DSA-87),
    POA&M-131 (residual O_NOFOLLOW open race), POA&M-133 (audit file rotation and retention; capacity is the platform's job).

- **SBC: phone-config output escaping for all vendors.** `uc-phone-mgmt`
  now escapes every operator-supplied string in Polycom VVX, Poly Edge,
  Cisco MPP, Cisco 9800 and Teo configs (XML text, attribute, comment and
  MPP key/value contexts). Benign output is byte-identical. (SI-15, SI-10;
  POA&M-122: Cisco MPP `$VAR` macros are not escaped yet, pending firmware
  confirmation)
- **SBC: provisioning token no longer in request logs.**
  `sbc-provision-server` request spans record only method and path, so the
  `?token=` query string is never logged. The token design itself is still
  open as POA&M-120. (IA-5, AU-9)
- **SBC: user HA1 digests encrypted at rest; key required (BREAKING, fail closed).**
  `sbc-api-server` now refuses to start without `SBC_USER_HA1_KEY_FILE`
  (64 hex chars, mode 0400, owned by uid 1000). On first start it re-encrypts
  existing plaintext `digest_ha1` rows once (Postgres advisory lock, 60 s
  timeout; a lost row race is retried next start). Helm now requires
  `sbcApi.ha1Key.existingSecret`; default values fail to render.
  `sbcApi.ha1Key.generate=true` is for disposable labs only. No mixed-version
  rollout: stop every old sbc-api replica before starting the new one, because
  old binaries cannot read encrypted rows. Recovery for malformed rows is in
  RUNBOOK.md. (NIST 800-53 Rev5: IA-5(1), SC-28, SC-12)
- **SBC: `/users` requires `users:read` / `users:admin` (BREAKING).** New
  Keycloak roles `users-reader` and `users-admin`. Existing API clients need the
  new roles before upgrade (see deploy/keycloak/central-config-clients.md).
  (AC-3, AC-6)
- **SBC: new `AccountManagement` audit event (SIEM schema addition).** It records
  user create/update/delete and rejected request bodies, with `actor_issuer` and
  `changed` (field-group names only). SIEM parsers must accept the new event
  type. (AC-2(4), AU-2, AU-3)

- **SBC: dormant AAA, policy-regex, dial-plan-regex and T.38 paths fail
  closed.** (NIST 800-53 Rev5: AC-3, IA-2, SI-10, CM-6; POA&M-200..206)
  None of these paths is wired by default. The Diameter Cx stubs
  (UAR/MAR/SAR, `authenticate`, `account`) now return `DiameterError`
  instead of accepting (POA&M-200). Policy `StringMatch::Regex` now
  evaluates a compiled, size-bounded regex (1 KiB pattern, 1 MiB compiled
  limit) instead of always matching; an invalid pattern cannot be
  constructed (POA&M-201). Dial-plan `DialPattern::Regex` is compiled once,
  an invalid pattern never matches, and `DialPattern::validate` /
  `DialPlan::try_add_entry` reject it (POA&M-205). **Upgrade note:** a
  policy or dial-plan regex that was silently accepted before may now fail
  to load or stop matching. UDPTL/IFP decoding in `uc-t38` is
  bounds-checked, with new cargo-fuzz targets (POA&M-202/203). `uc-t38` is
  now documented as a non-interoperable T.38-style encoding, not ITU-T T.38
  PER (POA&M-204). `uc-policy` now depends on `regex` (already in the
  workspace; no new crate in `Cargo.lock`).

### Changed

- **SBC + client: uc-dns uses the system DNS configuration and has no public
  fallback (behaviour change).** `SipResolver::new` and the client call agent
  now build a hickory resolver from the host config (`/etc/resolv.conf` or the
  OS equivalent). The resolver no longer falls back to public resolvers. All
  `SipResolver::new` callers are affected, including the SBC: hosts with no
  usable system DNS config get a resolver-init error. `DnsConfig::default()`
  now has an empty `servers` list, which means "use system config". Set
  `servers` explicitly if you relied on the old defaults. (CM-7; POA&M-172 and
  POA&M-174 track the residual items)
- **SBC + client: real RFC 3263 NAPTR/SRV resolution.** NAPTR and SRV are now
  queried. SRV targets are chosen by RFC 2782 weighted-random selection; before
  this the median was always picked. "." targets are filtered out, and
  unresolvable targets are skipped. A `sips` lookup never downgrades to a
  non-TLS target.
- **uc-dns: cache eviction is O(log n).** Eviction no longer does an O(n) scan
  on every insert. Each `put` evicts at most 32 expired entries.
- **Client:** the call agent initializes its resolver lazily (OnceCell built
  on a blocking task).

- **SBC: config-store write validation (operator-visible).** Phone and
  directory-number upserts are validated first and fail with the new
  `ConfigStoreError::Invalid { field, reason }`. Rows that used to be accepted
  are now rejected: control characters, oversize fields, bad charsets. Dial
  strings must be ASCII alphanumerics plus `*#+,.-_`. Re-check existing
  provisioning data before upgrade. Known gaps: sbc-api-server still returns
  500 for `Invalid` instead of 400 and emits no audit event for the reject (POA&M-123), and `sbc-config-sync` apply bypasses
  validation (POA&M-121). (SI-10)
- **SBC: transport is case-insensitive on Cisco MPP/9800 and Teo.** A stored
  `"TLS"`/`"TCP"` used to render `UDP` on MPP/9800. It now renders TLS/TCP,
  so affected phones change transport on their next resync.
- **SBC: `SBC_PROVISION_HOST` must be `host[:port]`.** Any other value makes
  `sbc-provision-server` refuse to start. (CM-6)
- **SBC: `/users` API semantics (BREAKING for API clients).** PUT/DELETE
  return real status codes (404 etc.) instead of blanket success. A duplicate
  POST returns 409. `GET /users` is paged (`limit` default 100, max 1000;
  `offset`), and the response includes `limit` and `offset`. Ansible
  `configure-sbc.yml` treats 409 as already-present.

### Security

- **SBC: transport-level DoS hardening for TCP/TLS/WebSocket (SC-5, SC-7, SC-10).**
  Each stream listener now has its own connection pool. There is also a
  node-wide ceiling and a per-source cap; a source is one IPv4 address or one
  IPv6 prefix (`rate_limit.ipv6_prefix_len`). Admission checks the per-source
  cap first, then the listener pool, then the total. TLS and WebSocket
  handshakes run under `handshake_timeout_secs`. A new connection must send an
  accepted SIP message within `first_message_timeout_secs`; CRLF keep-alives
  and frames the parser rejects do not count. After that, idle time is
  measured by the wall clock, so dripping one byte at a time no longer keeps
  a connection open. Stream framing uses the same Content-Length rules as the
  parser (#167). A bad frame gets a sanitized 400 and the connection closes.
  On TCP/TLS, RFC 5626 CRLFCRLF pings get a single CRLF pong. WebSocket
  messages are capped at 65,535 bytes, and a truncated WS message is
  discarded instead of being joined to the next one.
- **SBC: per-source rate-limiter state is bounded (SC-5).** In global mode the
  limiter never blocks. Per-source buckets are capped at
  `max_tracked_sources`. Once the cap is reached, new sources share an
  overflow bucket. Blocked sources are capped at `max_blocked_sources`.
  Expired state is cleared by a periodic sweep. Known gaps: blocks are not
  replicated across the cluster (POA&M-90), and rotating through /48
  prefixes is bounded only by the overflow bucket (POA&M-91).
- **SBC: API-synced trunks now use their configured transport (behaviour change).**
  Trunk groups created over the REST API, TrunkSync, the config store or
  central config used to be sent over UDP whatever the trunk said. The daemon
  now reads the trunk's `protocol`, or `transport` if `protocol` is absent
  (`udp`/`tcp`/`tls`, case-insensitive; absent = `udp`). A row that already
  says `"transport": "tls"` switches to TLS on upgrade and needs
  `security.trunk_tls_ca_path`; without it the trunk fails closed. An unknown
  value now skips the trunk with a warning instead of falling back to UDP.
  `tls_server_name` and `tls_client_cert` are read for TLS trunks.
  (NIST 800-53 Rev5: SC-8)
- **SBC: API/synced trunk ports follow the transport (behaviour change).** A
  TLS trunk with no `port` now dials 5061 (was 5060). A port of 0, above
  65535 or non-integer is rejected with 400 by sbc-api-server and
  central-config-api, and skipped with a warning by the daemon; it is never
  truncated.

### Added

- **SBC: new `[transport]` keys** (defaults; valid range):
  `max_connections_per_listener` (10000; 1..=1,000,000),
  `max_connections_total` (20000; 1..=4,000,000),
  `max_connections_per_source` (128; 1..=`max_connections_per_listener`;
  raise it for large enterprise NATs with many TLS phones),
  `handshake_timeout_secs` (10; 1..=60),
  `first_message_timeout_secs` (30; 1..=`tcp_idle_timeout_secs`),
  `ws_require_sip_subprotocol` (true).
- **SBC: new `[rate_limit]` keys** (defaults; valid range):
  `ipv6_prefix_len` (64; 32..=128, checked even when rate limiting is
  disabled), `max_tracked_sources` (65536; 1024..=4,194,304),
  `max_blocked_sources` (16384; 1..=`max_tracked_sources`),
  `overflow_rps` (0 = auto, which is 1000 clamped into
  `per_ip_rps..=global_rps`; a non-zero value must be in that range),
  `block_duration_secs` (60; 1..=86400), `sweep_interval_secs` (10; 1..=300),
  `audit_interval_secs` (60; 1..=3600),
  `audit_max_records_per_interval` (1024; 1..=65536).
  Existing configs that omit these keys still load and get the defaults.
- **SBC: `require_tls` trunk-group policy (POA&M-48, SC-8).** `require_tls = true`
  on a `[[trunk_groups]]` entry (or `"require_tls": true` in the API/central
  body) limits primary selection and every failover hop to TLS trunks. If no
  TLS trunk is usable the INVITE gets 503 and is never sent over UDP/TCP (a
  policy refusal carries `Reason: Q.850;cause=79;text="no TLS trunk"` and no
  Retry-After). A `sips:` Request-URI makes the call TLS-only in every group
  on its route, failover included. `security.require_tls_trunks = true` (Helm
  `sbcDaemon.trunkTls.requireTlsTrunks`) applies this to every group, and
  groups cannot opt out. Refusals are audited as `InviteDenied` with reason
  `no-tls-trunk` and counted in `routing_tls_required_skips` and
  `routing_tls_required_rejects`.
  - Validation: a config file with a TLS-only group that has no TLS trunk
    fails to load.
  - REST API: a non-bool `require_tls` or an unknown protocol returns 400. A
    TLS-only group that has trunks but none of them TLS returns 422; nothing
    is stored. An empty TLS-only group is accepted with a `warnings` entry.
  - Central config returns 422 for any TLS-only group without a TLS trunk.
    Trunk-group upserts and deletes that change transport policy write a
    `ConfigurationChange` audit record. `central-config-api` now exits with
    code 6 if audit init fails (server errors keep code 5).
  - The dashboard has a "Require TLS" checkbox and a "TLS only" badge.
  - Policy is per group. A route that lists a TLS-only group and then a plain
    group can still fail over to the plain group: set the flag on every
    group in the route, or use the global key.
  - Covers signaling only; it does not require SRTP.
  - Takes effect on restart only; a reload reports it as `restart_required`.
  - `require_tls` and trunk-protocol changes made through sbc-api-server or
    central config are audited as `ConfigurationChange`.
  - API/synced trunks without a `port` default to 5061 for TLS (was 5060);
    an out-of-range port is rejected (400) or skipped, never truncated.
  - **Upgrade all nodes before enabling it.** Older nodes ignore the flag.

### Changed

- **SBC: `transport.tcp_idle_timeout_secs` is now enforced (behaviour
  change).** The key used to be accepted and ignored. It is now the idle
  timeout for TCP, TLS and WS connections after their first message, and it
  must be 30..=3600. A config outside that range now fails to load. The
  default of 300 is unchanged.
- **SBC: WebSocket upgrades must offer the `sip` subprotocol (behaviour
  change, RFC 7118 §4).** An upgrade that does not offer `sip` is refused
  with 400. Setting `transport.ws_require_sip_subprotocol = false` admits
  upgrades that send no `Sec-WebSocket-Protocol` header, but that is
  non-conformant with RFC 7118. An offer that lists only other subprotocols
  is refused either way.
- **SBC: rate-limit audit records changed (SIEM parsers: action needed).**
  - Rate-limit rejections are no longer logged one record per packet. They
    are summed per source and per `limit_name` every
    `audit_interval_secs`, with at most `audit_max_records_per_interval`
    records per interval. Anything over that cap goes into one
    `per_ip_rps_suppressed` record.
  - New `limit_name` values: `per_ip_rps_suppressed`,
    `per_ip_blocked_drops`, `listener_conn`, `total_conn` and `framing`.
    Global, overflow and pool records use the placeholder source `0.0.0.0`
    (POA&M-92).
  - `per_ip_block` is written once, when the block starts. Its `limit_name`
    is now `per_ip_block:/<prefix>:<secs>s` (for example
    `per_ip_block:/32:60s`). Its source is the blocked address or IPv6
    network, `request_count` is 0, and the threshold is `per_ip_rps`.
  - **SIEM rules that match `limit_name == "per_ip_block"` exactly must
    switch to a prefix match on `per_ip_block:`.**
  - The audit control tag is now `AU-4, AU-12, SC-5`.
  - The new server counters (`framing_errors`, `conn_rejected_per_source`,
    `ws_handshake_failures`, `handshake_timeouts`) are not yet exported by
    the API (POA&M-93).
- **BREAKING (SBC operators): `central-config-api` audit init is fail-closed.**
  It now depends on `sbc-config-store` and `uc-audit` at runtime and exits
  with code 6 if audit logging cannot start (server errors keep code 5).
  Supervisors and alerting that match exit codes must know code 6.
- **SBC: config reload reports `require_tls` changes as `restart_required`.**
  `security.require_tls_trunks`, `trunk_groups.require_tls` and
  `trunk_groups` changes are logged and returned as needing a restart.
- **SBC: new audit records.** Trunk-group transport-policy changes emit the
  existing `ConfigurationChange` event (change type `Modified`, also for a
  central delete). The audit schema is unchanged; SIEM parsers see more
  records of an existing type. The CDR schema is unchanged.
- **SBC: mixed-version cluster rollout.** Nodes older than this release ignore
  `require_tls` and keep sending API trunks over UDP. Upgrade every node
  (and central-config-api) before setting the flag or the global key, or
  calls routed by old nodes still leave in clear text.
- **BREAKING (trunk TLS, CDR syslog, STIR/SHAKEN x5u fetch, SIP-TLS listeners):**
  TLS is now limited to CNSA 2.0 algorithms through the new shared
  `uc_transport::tls::cnsa_provider()` (POA&M-26, POA&M-40). TLS 1.3 offers
  only `TLS_AES_256_GCM_SHA384`; where TLS 1.2 is allowed
  (`security.min_tls_version = "1.2"`, and always for x5u fetches) only
  `ECDHE-ECDSA-AES256-GCM-SHA384`. Key exchange is ML-KEM-1024 (preferred)
  or P-384; X25519, P-256 and the ML-KEM-768 hybrids are gone. Peers that
  will stop connecting:
  - SIP trunks and SIP-TLS clients (phones) that support only AES-128-GCM,
    ChaCha20-Poly1305, X25519 or P-256, or that use TLS 1.2 with an RSA
    certificate.
  - RFC 5425 syslog collectors (`cdr.syslog`) with the same limits.
  - STIR/SHAKEN certificate repositories (`x5u` hosts) with the same limits;
    calls signed with their certificates then fail verification.

  Check a peer with
  `openssl s_client -connect host:port -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384 -groups secp384r1`.
  The REST HTTPS listener, daemon gRPC and the soft client are unchanged.

- **SBC, STIR/SHAKEN (behaviour change):** attestation A for a registered
  endpoint is now tied to the TCP/TLS connection that carried its REGISTER,
  not to the source `ip:port`. When that connection closes, the binding is
  dropped. A new connection from the same address (CGNAT port reuse) no
  longer gets A (POA&M-36). What operators will see:
  - Phones that reconnect get B until they re-REGISTER on the new connection.
  - A de-REGISTER only removes the binding when it arrives on the connection
    that owns it.
  - UDP is unchanged and stays at B.

  There are no config or schema changes. TLS peer-certificate binding is
  still open as POA&M-70.

### Fixed

- **Route-pattern digit manipulation reaches the daemon** — route patterns created or updated through the REST API accept `transform_type` / `transform_value` (`strip_prefix`, `add_prefix`, `replace_prefix`, `replace`, same spelling as dial-plan entries), the API rejects malformed values with 400, the daemon's sync path sets the transform on the `SbcRouter` pattern, and the dashboard form exposes it. Previously the field was dropped and every API-created pattern routed with no transform (`sbc-daemon`, `sbc-api-server`, `sbc-dashboard`, closes #144)
- **SBC:** at registration capacity, the full STIR flow-table sweep is now
  rate-limited to once per second. Before, it ran under the location write
  lock on every new-flow REGISTER (POA&M-35).

### Security (SBC, call-path routing and number normalisation)

- **SBC: blocked route patterns fail closed (behaviour change).** A call that
  matches a `blocked` route pattern now gets `403 Forbidden` and does not fall
  back to a later partition, the dial plan or `default_trunk_group`. A block is
  also tested against the dialled number with `+` stripped, so a `1900` block
  catches `+1-900-…`. A block written as `+1900` does not catch the national
  form `1900…`, so write blocks without `+`. Audited as `route:blocked`; new
  metric `sbc_route_blocked_total`. (AC-3, AC-4)
- **SBC: `routing.default_trunk_group` is outbound-only (behaviour change).**
  Inbound calls that match nothing get 404 and are no longer sent to the
  default group. Deployments that relied on inbound catch-all through the
  default group need an explicit dial-plan entry with `direction = "inbound"`
  or `"both"`. (AC-4)
- **SBC: dial-plan `direction`, `source_trunk` and `domain_pattern` are
  enforced (behaviour change).** They were parsed but ignored before.
  `domain_pattern` now matches on a label boundary and ignores ASCII case
  (`*.mil` no longer matches `evilmil`). API/JSON dial plans still carry only
  the pattern kind. (AC-4)
- **SBC: unknown `pattern_type` is rejected (behaviour change).** Only
  `exact|prefix|wildcard|any` (case-sensitive) are accepted. Config load fails
  validation. Daemon seed and gRPC sync skip the row with a warning
  (`sbc_route_pattern_rejected_total`). REST POST/PUT `/route-patterns`
  returns 400 for an unknown or non-string value. Seeded `blocked` and
  `priority` are now honoured. (SI-10, CM-6)
- **SBC: canonical dialled-number handling (behaviour change).** R-URI users
  are canonicalised once (`uc_types::DialedNumber`: separators, percent
  decoding, `tel:`/`sip:` forms) before routing, VPS screening, blocklist and
  emergency matching. A numeric-looking user that is not canonical (for
  example `+19005551234x`), an empty user or a user over 256 bytes is never
  routed and gets 404, including against `any` catch-alls and the default
  group. Alias users such as `alice` still route. `;phone-context` is dropped,
  not applied (POA&M-100). (SI-10)
- **SBC: per-user INVITE/REGISTER limiter rekeyed (behaviour change).**
  Buckets are keyed on the authenticated AOR when the request arrives on a
  flow bound by an authenticated REGISTER, and otherwise on
  `(source /32 or /64, From user)`, so a spoofed `From` from another network
  cannot drain a victim's bucket. More than 64 unauthenticated users per
  network share one bucket. Trunk sources are exempt (bounded by trunk
  `max_calls` and VPS caps). Emergency INVITEs bypass the limiter. Overflow of
  the key table is allowed, not rejected. Burst is fixed at `rps x 2` and
  `rate_limit.burst_multiplier` is ignored for this limiter (POA&M-101).
  Audit `limit_name` is now `per_user_rps:auth:…` or
  `per_user_rps:unauth:<net>`, which affects SIEM parsers. New metrics
  `sbc_user_limiter_overflow_total` and
  `sbc_user_limiter_emergency_bypass_total`. (SC-5)
- **SBC: emergency calls (behaviour change).** Emergency numbers are
  canonicalised (`9-1-1` and `%39%311` match `911`). They are force-routed to
  the new optional `routing.emergency_trunk_group` when it is set, and a
  matching block is ignored and audited (`route:blocked-ignored`). An emergency
  call with no route gets 503 without `Retry-After` and is audited as
  `emergency_unrouted`. Routability is checked at startup only. New metrics
  `sbc_emergency_force_routed_emergency_trunk_total`,
  `sbc_emergency_force_routed_blocked_ignored_total` and
  `sbc_emergency_unrouted_total`. Route audit subjects are now
  `trunk_group:<tg>`, the flow-bound AOR, or `unverified:<From URI>`.
  (CP-8, CM-6, AU-3; 47 CFR 9.16)
- POA&M-100 to POA&M-103 record the deferred items from this work, including
  phone-context-aware normalisation (POA&M-100) and `burst_multiplier` for
  the per-user limiter (POA&M-101). See `docs/NIST-800-53-CONTROLS.md`.

### Changed (SBC, call-path routing)

- **Breaking API (library): `uc_routing::SbcRouter::route` now returns
  `SbcRouteOutcome { Routed, Blocked { pattern_id, partition_id }, NoMatch }`**
  instead of an `Option`. Use `routed()` and `is_blocked()` for the old shape.
  `Router::route_call` takes a `CallRouteContext` and uses
  `DialPlan::match_extended`. `route`/`route_for`/`route_for_tls` keep their
  old semantics and are documented as legacy.
- **VPS: canonical comparisons.** Blocklist rule names are canonical
  (`blocklist:1900`, was `blocklist:+1900`) and the reserved callee key is
  canonical (`12135552000`). Update any SIEM rules that match these strings.
  CDR causes are unchanged: a blocked route records `PolicyDenied` and an
  unrouted emergency call records `NoRoute`.
- `uc-vps` now depends on `uc-types` (workspace crate). `uc-types` gains
  `proptest` as a dev-dependency only. No new third-party runtime
  dependencies.

### Changed (SBC and client, proto-sip message-layer hardening, Phase 1)

- **SIP parsing is strict.** Messages with bare CR or LF line ends, header
  names that are not tokens, control characters (other than HTAB) in header
  values, malformed or duplicate Content-Length (`+5`, `-1`, `l:` plus
  `Content-Length:`), duplicate Call-ID/To/From/CSeq/Max-Forwards, CSeq of
  2^31 or more, a CSeq method that differs from the request method, or
  Max-Forwards above 255 are now rejected, as is a header section without
  its terminating empty line (missing final CRLF). Peers that send LF-only
  messages no longer interoperate; there is no compatibility switch.
- Over UDP, bytes after Content-Length are discarded (RFC 3261 §18.3). The
  soft client requires Content-Length on TCP/TLS, and its stream framer now
  applies the parser's Content-Length rules: a missing, duplicate or
  non-numeric Content-Length closes the connection instead of framing as 0.
  WS/WSS/SCTP use a new `Framing::Message` mode: Content-Length optional,
  exact if present (RFC 7118 §5, RFC 4168).
- **SIP methods are case-sensitive** (RFC 3261 §7.1). `invite` is now an
  extension method, not INVITE, and extension methods keep the case they
  were received in. `CSeq: 1 invite` on an INVITE is rejected.
- Binary message bodies are no longer dropped on re-serialization.
- Header names compare case-insensitively everywhere (custom spellings of
  known headers such as `Min-Expires` and `Accept` now match). New compact
  forms: `e`, `x`, `b`, `y`, `a`, `j`, `d`.
- Per-message limits: 256 header fields, 8 KiB per header and start line,
  4 KiB URIs, 64 parameters, 64 list elements.
- Fixed a panic in Route/Contact list splitting with non-ASCII display names.
- Known gap (SBC): sbc-daemon still frames TCP/TLS with datagram rules and
  does not yet use the stream framer (POA&M-64, deferred).
- Dev only: proptest and criterion dev-dependencies and a standalone
  cargo-fuzz crate (`crates/proto/proto-sip/fuzz`, excluded from the
  workspace). No runtime dependency or config/CDR/audit schema change.

### Fixed (client, media audit 2026-11-06)

- **Client: Opus FEC/PLC no longer drifts 60 ms per lost 20 ms frame.**
  A lost frame used to be concealed into a 2880-sample (60 ms) buffer, so
  playout drifted on every loss. Now each lost frame produces exactly one
  ptime: in-band FEC from packet N+1 (when its TOC can carry LBRR), then
  Opus native PLC, then WSOLA. `fec_recovered` / `fec_recovered_frames`
  count FEC-path decodes only. They do not confirm that LBRR was present
  (POA&M-141). The hot path does not allocate on loss.

### Fixed (SBC / uc-codecs, media audit 2026-11-06)

- **G.722 level fix.** Input at -3 dBFS used to clip at -6 dBFS (-1.8 dB
  gain, rail hits). The QMF scaling now follows the ITU-T G.191 STL / spandsp
  16-bit convention, and the -3 and -10 dBFS level tests both show 0.00 dB.
  Transcoded G.722 audio is louder near full scale than before. Only a
  self-generated regression vector is used, not the official ITU vectors
  (POA&M-140).
- **G.722 encode/decode return errors instead of `Ok(0)`.** Odd PCM length
  gives `CodecError::InvalidInput` and a short output buffer gives
  `CodecError::BufferTooSmall`. sbc-media-core transcoder callers map these
  to the existing `DecryptionFailed`/`EncryptionFailed`. (SI-10)
- **Codec negotiation hardened (library only, NOT wired in sbc-daemon).**
  `CodecRegistry::negotiate` now matches channel count. Opus is exempt per
  RFC 7587 §7. It adopts the remote PT for any non-reserved PT and rejects
  reserved PTs (72-76, >127) and conflicting PT bindings. It caps remote
  entries at 64. The answer gives local Opus fmtp (minptime is reconciled)
  and keeps the peer's parsed fmtp in `CodecCapability::remote_fmtp`.
  telephone-event events are intersected (RFC 4733). Remote fmtp that is
  oversize or contains control characters is rejected. telephone-event at
  8 kHz (PT 101) and 48 kHz (PT 110) is in the default registry. The
  transcoder refuses telephone-event/CN legs. `MediaSession::negotiate_codecs`
  now delegates to the registry. **These code paths are reached only from
  tests today. The live sbc-daemon SDP answer path does not use them, so this
  gives no production protection yet (POA&M-142).** PTs 64-95 are still adopted
  under rtcp-mux (POA&M-143).

### Changed (BREAKING, uc-codecs / uc-media-engine library API)

- `AudioCodec::decode_fec` now takes `(next_packet, output)` and sizes the
  output to the lost frame. New trait methods `conceal(output)` and
  `supports_plc()` have defaults. External `AudioCodec` implementors must
  update.
- New `CodecError` variants: `InvalidInput { reason }` and
  `LossRecoveryFailed { reason: &'static str }`. Exhaustive matches must
  handle them. `G722Encoder::encode`/`G722Decoder::decode` return
  `CodecResult<usize>`. `PayloadType::is_dynamic` now uses the RFC 3551
  ranges, so `Dynamic(72)` returns false.
- New public field `CodecCapability::remote_fmtp` and new modules `fmtp` and
  `opus_toc`.
- uc-media-engine: removed `StreamStats::{packets_lost, jitter_ms, rtt_ms}`
  (they were always 0). Crate docs no longer claim RTP/RTCP/SRTP/transcoding.
- Client: `AudioError::LossRecovery` variant and
  `JitterBufferResult::Lost { fec_source }` field added.
- No config, CDR, audit or gRPC schema change. Dev only: `criterion`
  (workspace 0.8) dev-dependency and `benches/codecs.rs` in uc-codecs. No new
  runtime or crypto dependency.

## [0.10.0] — 2026-11-06

SBC release with three operator-breaking changes: call detail records,
STIR/SHAKEN, and SIP transport on every leg (POA&M-5). The client is not
released with this version; client crates share the workspace version
number only.

### Upgrade checklist (operators)

1. **CDRs are on by default.** Make sure the CDR directory is writable (Helm
   gives it its own PVC). The daemon refuses to start if it isn't, or if none
   of the newest CDR files holds a complete record.
2. **CDR access moved.** OIDC `config-admin` alone no longer reads CDRs; grant
   `cdr:read` / `cdr:export`. In Helm, `/api/v1/cdrs` returns 503 until
   `sbcDaemon.grpcMtls` is configured. sbc-api exits with code 5 if audit
   logging can't start.
3. **CDR schema is v2** (STIR fields added). Readers must accept v1 and v2;
   a file mixing both is rejected by `sbc-cli cdrs verify`.
4. **STIR/SHAKEN config is nested.** `[stir_shaken]` now has
   `signing` / `attestation` / `verification` tables and rejects unknown keys;
   the old flat keys still parse for this release with a warning.
   `verification_enabled` now defaults to false and the default attestation
   is C. Helm: `sbcDaemon.stirShaken`.
5. **TLS trunks need trust anchors and a listener.** Set
   `security.trunk_tls_ca_path` (Helm: `sbcDaemon.trunkTls.caConfigMap` or
   `caSecretName`) and `tls_listen`; TCP trunks need `tcp_listen`. Without the
   CA a TLS trunk fails closed.
6. **Trunk Request-URI uses the trunk host:port**, not the dialled host; the
   CDR destination host can change accordingly.
7. **Registered phones are reached only on the connection they registered
   on.** A phone registered over TLS whose connection is gone gets 503, never
   UDP.

### Changed (release)

- Workspace version 0.9.0 → 0.10.0; Helm chart version and appVersion
  0.8.0 → 0.10.0.
- tokio 1.53.2 → 1.54.1, fixing RUSTSEC-2026-0386 (`AsyncFd` I/O-safety
  unsoundness).
- New `deny.toml`: `cargo deny check` (licenses, advisories, bans, sources)
  now passes. Licenses are an explicit permissive allow-list; git sources are
  limited to the first-party RADIUS crate (NIST 800-53 SR-3, SR-4, CM-10).
- `client-gui-tauri` now inherits the workspace license (Apache-2.0).
- `security.trunk_tls_ca_path` is accepted with no TLS trunk in the config
  file, so TLS trunks synced over the API (as in Helm) can connect.

### Added (deploy)

- Helm `sbcDaemon.trunkTls` (trunk CA bundle from a ConfigMap or Secret,
  mounted at `/etc/sbc/trunk-ca`).
- Helm `sbcDaemon.stirShaken`: verification with an STI-CR anchors ConfigMap,
  and signing with a Secret. The init container copies the signing key to a
  memory-backed volume owned by the daemon uid at mode 0400, as the signer
  requires. Per-trunk sign/verify still come only from `[[trunk_groups]]` in
  the config file (POA&M-34).

### Fixed (SBC, Security, POA&M-5 / SC-8)

- **Requests go out on the target leg's transport.** Before this fix, a B-leg INVITE, BYE or CANCEL triggered by a TCP/TLS caller was written back down the *caller's* connection. That was a misroute, and it leaked trunk routing and the STIR Identity to the caller. Timer-driven sends (retransmissions, failover INVITEs, BYEs, 408s) all went out on the UDP socket. Now every message carries an explicit flow: the caller's transport for the A-leg, and the trunk's `protocol` for the B-leg. The daemon opens outbound TCP/TLS connections to trunks, reuses them, and reads trunk responses from them (`sbc-daemon`)
- **Failover follows the next trunk.** The retried INVITE gets that trunk's Request-URI (`sips:` for TLS, `;transport=tcp` for TCP), a Via with the matching transport and listener port, a matching Contact, and a transaction with that transport's timers. STIR re-signing on failover is unchanged (`sbc-daemon`)
- **No plaintext fallback.** Trunk TLS always verifies the server certificate. A connect, handshake or verification failure fails the attempt over to the next trunk, or returns 503 (`sbc-daemon`)
- **CANCEL uses the B-leg INVITE's Request-URI** (RFC 3261 §9.1) and goes out on the B-leg flow, not the dialled R-URI over UDP (`sbc-daemon`)
- **Phones registered over TLS/TCP were reached over UDP.** Requests to a registered contact now go on the flow the REGISTER arrived on (`sbc-daemon`, `proto-registrar`)
- **TCP/TLS transports split read and write halves**, so a send no longer waits behind a pending receive on the same connection (`uc-transport`)

### Added (SBC, config)

- `security.trunk_tls_ca_path` sets the trust anchors for trunk server certificates. It is required when any trunk in the config file uses `protocol = "tls"`, and may also be set with no TLS trunk in the file so that TLS trunks synced over the API can connect. Per-trunk `tls_server_name` and `tls_client_cert` (mTLS to the trunk, default off) are TLS-only (`sbc-config`, `uc-routing`)
- Flow metrics on `/metrics`: `sip_egress_connections`, `sip_egress_connect_failures_total`, `sip_egress_dial_backoff_total`, `sip_send_no_connection_total`, `sip_stream_write_timeouts_total`, `sip_send_lane_dropped_total`, `sip_send_lane_overflow_total` (`sbc-daemon`)
- Via `rport` (RFC 3581) on SBC-originated UDP requests (`sbc-daemon`)
- `uc_transport::tls::create_client_config_with(TlsClientOptions)` takes extra roots, a minimum TLS version and an optional client certificate (`uc-transport`)

### Changed (BREAKING, SBC config)

- A config with a `protocol = "tls"` trunk now fails validation unless `security.trunk_tls_ca_path` is set. Operators must mount the trunk CA bundle before upgrading (Helm: `sbcDaemon.trunkTls`)
- A `protocol = "tcp"` or `"tls"` trunk now requires a matching listener of that transport; configs without one fail validation
- B-leg INVITEs to trunks now use the trunk's host and port in the Request-URI instead of the dialled host. Trunks or downstream parsers matching on the dialled host must be updated
- Registered phones are reached only on their registration flow. A UDP caller calling a TLS-registered phone whose connection has closed gets 503 (no UDP fallback, SC-8)
- B-leg transaction timers follow the trunk transport (Timer A not used on TCP/TLS, RFC 3261 §17.1.2.2), changing retransmission and failover timing on stream trunks
- `proto_registrar::Binding` gains a `source_transport` field; struct-literal constructors must set it (`proto-registrar`, internal API)

### Added (SBC, STIR/SHAKEN)

- **STIR/SHAKEN verification and signing in the call path** — inbound INVITEs are verified (RFC 8224/8225/8588, ATIS-1000074) after Max-Forwards and before VPS. The verstat result is written into From/P-Asserted-Identity and fed to VPS enforcement. Outbound INVITEs to trunks with `sign = true` are signed at egress after manipulation and topology hiding, and any inbound Identity is stripped unless the trunk is trusted. Failures follow `verification.failure_policy` (`pass-through` | `mark` | `reject`). Rejects carry a `Reason: SIP;cause=N` header and produce a PolicyDenied CDR (`sbc-daemon`, `proto-sip`)
- **New crate `uc-sti`** — STI certificate fetch over HTTPS with SSRF protection (all resolved addresses are vetted, no redirects, body cap, timeout), a bounded single-flight certificate cache, trust anchors reloaded on SIGHUP and on a timer, the A/B/C attestation policy, and a file signing key (opened `O_NOFOLLOW`, mode 0600/0400, owned by the daemon user, zeroized) (`uc-sti`)
- **ES256 and STI certificate validation in `uc-crypto`** — behind the new `stir-shaken-es256` feature: `interop::ecdsa_p256` and `x509::verify_sti_chain` (rustls-webpki on aws-lc-rs FIPS, TNAuthList per RFC 8226). This is a documented **CNSA 2.0 exception**: ATIS-1000074 requires ES256 (P-256) (`uc-crypto`)
- **SIP response codes** — 428 Use Identity Header, 436 Bad Identity Info, 437 Unsupported Credential, 438 Invalid Identity Header. A stale or future `iat` gets **403 Stale Date** (RFC 8224 §6.2.2) (`proto-sip`, `proto-stir-shaken`)
- **Per-trunk switches** — `stir_shaken = { sign, verify, strip_inbound_identity }` on a trunk. They need the matching global switch (`sbc-config`)
- **Audit events, for SIEM parsers** — `StirSignFailure`, `StirVerifyFailure` (aggregated per trunk and reason, with `count`, last `source_ip` and Call-ID hash), `StirTrustAnchorsReloaded`, `StirTrustAnchorReloadFailed`, `StirKeyLoaded`, and `StirAuditEventsDropped` (Security, `count`/`total`, AU-5) when the aggregator drops events. Strict-schema parsers must accept them (`uc-audit`, `sbc-daemon`)
- **gRPC** — `CallInfo.verstat` (field 15); `CdrRecord` fields 42-45 for the STIR CDR fields. The CDR attestation mapping uses stable strings instead of debug formatting (`sbc-grpc-api`)
- **Metrics** — STIR gauges and counters on the daemon metrics endpoint (`sbc-daemon`)

### Changed (BREAKING, SBC, STIR/SHAKEN)

- **`stir_shaken.verification_enabled` now defaults to `false`** — before this release it defaulted to `true` but did not verify anything. With verification on, `verification.trust_anchors_path` (STI-CR bundle, file or directory) is required, and the daemon refuses to start without it. The shipped `deploy/config/config.toml` used to set `verification_enabled = true` with no anchors, and would fail validation now. It has been migrated
- **Default attestation is now `C`** (was `B`). Set `stir_shaken.attestation.default` and `owned_numbers` to get A/B
- **`[stir_shaken]` is nested and strict** — new `[stir_shaken.signing]`, `[stir_shaken.attestation]` and `[stir_shaken.verification]` sections with `deny_unknown_fields`, so a misspelled key now stops startup. The old flat keys (`default_attestation`, `certificate_path`, `private_key_path`, `certificate_url`, `max_passport_age_secs`, `ca_bundle_path`) are **deprecated aliases**: still accepted, with a startup warning. Setting an old key and its new key together is an error. `certificate_url` must be `https`, and `pkcs11` keys are rejected
- **Attestation A needs a TCP/TLS REGISTER flow** — an endpoint INVITE gets A only on the connection flow its REGISTER came in on. Bindings created another way (API, replication) are not attested. **For UDP endpoints the most you get is B**
- **CDR schema v2** — `schema_version = 2` adds `stir_verstat`, `stir_verify_reason`, `stir_inbound_attestation` and `stir_x5u_host` (JSONL fields and CSV columns). When these fields are absent, v1 records serialise exactly as before, and existing v1 files still verify. The verifier rejects a file that mixes v1 and v2 records. Billing/SIEM parsers must accept v2 and the wider CSV
- **`proto-stir-shaken` API rewritten** — the structural-only `verify_identity` and the hand-written base64 are gone. They are replaced by `IdentityHeader::parse`, the `Signer`/`VerifyingKey`/`KeyResolver` traits and the two-stage `Verifier::prepare`/`verify`. `KeyResolver::cached` returns `Option<Arc<VerifiedKey>>`. `Attestation` is now an alias for `uc_types::AttestationLevel`. Code that uses the crate must be ported
- **Audit event set grows** — see the new `Stir*` events above

### Added (SBC, CDR)

- **Call Detail Records (schema v1)** — the daemon writes one CDR per INVITE that reaches admission through a bounded queue to a dedicated writer thread (emits never block signalling; overflow is dropped and counted). Records are SHA-384 hash-chained with a per-file `.sha384` sidecar, rotated by size/interval and pruned by `retention_files`/`retention_days`. PII handling is `full`, `mask_caller` or `hash` (HMAC with `pii_hash_key_file`, opened `O_NOFOLLOW`, must be a 0400/0600 regular file >= 48 bytes). CSV output guards against formula injection by prefixing `'`, which also applies to E.164 numbers such as `'+15551234567` (NIST AU-2/AU-3/AU-9/AU-12) (`uc-cdr`, `sbc-daemon`)
- **CDR sinks** — a local file sink (`jsonl` or `csv`, directory 0750, files 0640) and an optional RFC 5425 syslog-over-TLS sink (`[cdr.syslog]`, TLS only), plus an in-memory ring of recent CDRs for the API (`uc-cdr`, `sbc-daemon`)
- **gRPC `CdrService`** — list, get, stats and streaming export of CDRs (`proto/cdr.proto`). The new `grpc.allowed_client_names` restricts daemon gRPC callers by client-certificate name when mTLS is on (`sbc-grpc-api`, `sbc-daemon`, `sbc-config`)
- **REST CDR API** — `GET /api/v1/cdrs`, `/api/v1/cdrs/{record_id}`, `/api/v1/cdrs/stats` and `/api/v1/cdrs/export` (JSONL/CSV) on `sbc-api`, served from the daemon `CdrService` (`sbc-api-server`)
- **CLI** — `sbc-cli cdrs list|get|stats|export|verify`. `verify` checks the hash chain and sidecars of CDR files offline (`sbc-cli`)
- **Dashboard** — the CDRs page reads the real API, with filters and export (`sbc-dashboard`)
- **Config keys** — `[cdr]`: `enabled`, `format`, `directory`, `node_id`, `rotate_size_mb`, `rotate_interval`, `retention_files`, `retention_days`, `fsync_interval_ms`, `queue_capacity`, `ring_capacity`, `hash_chain`, `record_unanswered`, `record_auth_challenges`, `pii`, `pii_hash_key_file`, `on_failure` (`continue` | `reject_new_calls`, emergency calls are always admitted); `[cdr.syslog]`: `enabled`, `target`, `ca_path`, `facility`; `grpc.allowed_client_names`. See `deploy/config/config.toml` and `docs/SBC-ADMIN-GUIDE.md` "Call Detail Records" (`sbc-config`)
- **Metrics** — `sbc_cdr_emitted_total`, `sbc_cdr_dropped_queue_full_total`, `sbc_cdr_dropped_writer_dead_total`, `sbc_cdr_write_errors_total`, `sbc_cdr_rotations_total`, `sbc_cdr_syslog_dropped_total`, `sbc_cdr_queue_depth`, `sbc_cdr_writer_alive`, `sbc_cdr_last_write_timestamp_seconds`. A new `cdr` health component reports degraded on drops and unhealthy when the writer has exited. Operators should alert on the drop counters and `sbc_cdr_writer_alive` (`sbc-daemon`)
- **Audit events, for SIEM parsers** — `CdrSinkFailure` and `CdrFileRotated` (System), and `CdrExport` (Authorization) with fields `user`, `on_behalf_of`, `filter`, `count`, `format`, written for every CDR read or export through `sbc-api`. Strict-schema parsers must accept the new event types (`uc-audit`, `sbc-daemon`, `sbc-api-server`)
- **Deploy assets** — the Dockerfile creates `/var/lib/usg-sbc/cdr` (0750, owned by `sbc`); the Helm chart adds `sbcDaemon.cdr.*` values, a dedicated CDR PVC (`<fullname>-cdr`, kept apart from the data volume, AU-4) and an optional daemon gRPC mTLS template (`26-sbc-grpc-mtls.yaml`); Ansible creates the CDR directory when `sbc_host_install=true`

### Changed (BREAKING, SBC operators and integrators)

- **CDRs are on by default and need a writable directory** — `cdr.enabled` defaults to `true`, and the daemon refuses to start if `cdr.directory` (default `/var/lib/usg-sbc/cdr`) cannot be created or written. The container image, Helm chart and Ansible playbook (with `sbc_host_install=true`) create it. Bare-metal installs must create it for the daemon user, or set `cdr.enabled = false`
- **Daemon refuses to start on unrecoverable CDR files** — if no resume point can be found in the newest CDR files (a broken chain or foreign content), startup fails rather than reusing record IDs. Move the affected files aside and check them with `sbc-cli cdrs verify`
- **`uc-cdr` API replaced** — the old `uc-cdr` types, writer and format API are gone, replaced by the schema v1 record, sink, chain and ring API. The crate now depends on `uc-crypto`, not `uc-types`. Downstream code that uses `uc-cdr` must be ported
- **Daemon `/cdrs` REST stub removed** — the daemon's own placeholder `/cdrs` endpoint no longer exists. Use `sbc-api` `/api/v1/cdrs` or gRPC `CdrService`
- **CDR read access needs a CDR role** — OIDC `config-admin` alone can no longer read CDRs. Grant `cdr-reader`, `auditor`, `cdr-exporter` or `fleet-admin`, or the `cdr:read` / `cdr:export` scopes (export needs `cdr-exporter`/`fleet-admin` or `cdr:export`) (AC-3, AC-6)
- **Helm: `/api/v1/cdrs` returns 503 until daemon gRPC mTLS is set up** — with default values `sbc-api` does not send CDRs over plaintext gRPC. Configure `sbcDaemon.grpcMtls`. `grpcMtls` cannot be combined with `sbcTrunkAgent`, and the chart fails to render if both are set
- **New `sbc-api` environment variables** — `SBC_DAEMON_GRPC_TLS_CA_FILE`, `SBC_DAEMON_GRPC_TLS_CERT_FILE`, `SBC_DAEMON_GRPC_TLS_KEY_FILE` (set all three or none) enable mTLS to the daemon
- **`sbc-api` exits with code 5 if audit init fails** — supervisors and health probes that treat specific exit codes must account for it (AU-5)
- **CDR and audit schemas for billing/SIEM parsers** — CDR schema v1 is new (JSONL/CSV, `schema_version` field). `CdrExport`, `CdrSinkFailure` and `CdrFileRotated` are new audit event types

### Added (SBC)

- **Emergency calls get reserved headroom** — calls to a number in `vps.emergency_numbers` (default `["911", "933", "112"]`, exact match on the dialed user part; at most 32 entries of up to 32 characters each, and an entry like `9-1-1` is rejected) are admitted past `general.max_calls` and trunk `max_calls` up to a bounded reserve: `general.emergency_reserve_calls`, and the per-trunk `emergency_reserve_calls` (each defaults to 10% of the matching `max_calls`, minimum 1; valid range 1–`max_calls`). Once the reserve is used up, emergency calls get 503 too, and normal calls never use it. Emergency calls skip VPS number/caller deny rules, but these still apply: operator source-IP blocklist entries, ACLs, authentication and the source-IP flood limiter. Each bypass is audited as `emergency-bypass` with `source_ip`. STIR/SHAKEN attestation is **not** checked for emergency calls (accepted deviation SEC-003 / NIST-002). New metric `sbc_emergency_calls_admitted` (`sbc-config`, `sbc-daemon`, `uc-vps`, `uc-routing`)
- **Trunk `Retry-After` honoured** — a 503 from a trunk that carries `Retry-After` puts that trunk in cooldown for the given time, capped by `general.trunk_retry_after_max_secs` (default 300, valid 1–3600) (`sbc-daemon`, `uc-routing`, `sbc-config`)
- **Immediate failover on transport errors** — if sending the first B-leg INVITE fails with a transport error, the SBC moves to the next trunk right away instead of waiting for Timer B (`sbc-daemon`)
- **New audit events, for SIEM parsers** — `TrunkFailover` and `TrunkReachabilityChanged`. `AuthorizationDecision` gains a `source_ip` field (additive). It is filled in on the `no-usable-trunk`, `number-translation-invalid`, `max-registrations` and `emergency-bypass` decisions, and anywhere else the source address is known. Strict-schema parsers must accept the new event types and field (`uc-audit`, `sbc-daemon`)

### Changed (SBC)

- **Audit writes no longer block signalling** — records go on a bounded queue to a dedicated writer thread, which hash-chains and writes them in queue order. The hash chain still covers every record that is written. When the queue is full or the writer has died, the record is **dropped and counted** rather than holding up the caller, and the loss is logged at error level, rate limited (AU-5). The queue is flushed with a timeout at shutdown. A new `audit` health component reports degraded when records have been dropped and unhealthy when the writer thread has exited. New metrics: `sbc_audit_records_dropped` and `sbc_audit_writer_alive`. Operators should alert on both. A gap in the written sequence now means records were dropped, not that the chain was tampered with: compare it against `sbc_audit_records_dropped` (`uc-audit`, `sbc-daemon`)

- **Audit health recovers after drops (operator-visible)** — the `audit` health component now reports degraded only for 60 s after the most recent dropped record, then returns to healthy; it is still unhealthy while the writer thread has exited. `sbc_audit_records_dropped` stays cumulative and never resets. Operators who relied on health staying degraded must alert on the **rate** of `sbc_audit_records_dropped` (e.g. `increase(...) > 0`) instead (POA&M-12, AU-5) (`uc-audit`, `sbc-daemon`)

### Fixed (SBC)

- **No SIP retransmissions over reliable transports** — client and server transactions on TCP, TLS, WS, WSS and SCTP are now built as reliable: Timers A, E and G no longer fire, and Timers I, J and K are zero (RFC 3261 §17.1.1.2, §17.1.2.2, §17.2.1, §17.2.2). Timers B, F and H are still armed. UDP is unchanged. Requests and responses sent from the timer loop (failover INVITEs, BYEs, 408s) still go out on the UDP timer socket and are tracked as UDP until POA&M-5 (POA&M-10) (`sbc-daemon`)
- **`max_calls` admission is atomic** — the call-slot check and reservation are a single atomic step, so concurrent INVITEs can no longer push active calls past `general.max_calls`. The slot is released on every reject and teardown path. Emergency reserve behaviour (`emergency_reserve_calls`) is unchanged (POA&M-11, SC-5) (`sbc-daemon`)

### Changed (BREAKING, SBC operators)

- **Configuration keys the SBC accepted but ignored are now rejected by `validate_config`** — the daemon refuses to start (CM-6/CM-7) when: `media.default_mode` is anything other than `Relay` (there is no media bypass); `media.realm_modes` has any entries; `media.codecs` differs from the default set `["Opus", "G722", "G711Ulaw", "G711Alaw"]` (order ignored; there is no SDP codec filtering or transcoding); a trunk has `max_calls = 0` or `max_failures = 0`; or `options_ping_interval_secs` is outside 5–3600 while `options_ping_enabled = true`. `sbc-media` exits at startup if `SBC_MEDIA_DEFAULT_MODE` is not `relay`. The `codecs` line was removed from `deploy/test/sbc-test.toml`. Remove or fix these keys before upgrading (`sbc-config`, `sbc-media`)

### Fixed

- **SBC features that could be configured but had no effect now work** — the SBC-router and dial-plan number translation is written into the B-leg Request-URI/To user part; trunk failover is filled in from the remaining trunks in the selected trunk group/route group, and `TrunkMonitor` OPTIONS health drives trunk selection so a down trunk is skipped (new config-file trunk keys `options_ping_enabled` / `options_ping_interval_secs`); per-trunk `max_calls`, `cooldown_secs` and `max_failures` are enforced; VPS `per_callee_max_concurrent` is enforced; `general.max_registrations` is enforced after authentication; the trunk-status publish service is bounded. Call counts are released on every teardown path (failure, CANCEL, timeout, BYE from either side) (`sbc-daemon`, `sbc-config`, `sbc-trunk-services`, `uc-routing`, `uc-vps`, `proto-registrar`)

### Added

- **Mid-dialog re-INVITE and UPDATE relay** — the daemon now relays re-INVITE (RFC 3261 §14) and UPDATE (RFC 3311) across both legs of a B2BUA call, re-anchoring the new offer and answer through the media relay and following each leg's new RTP address, so hold/resume, codec changes and RFC 4028 session refreshes work end to end. Body-less refreshes are answered locally; a second change while one is in flight gets 491; `Supported: timer`, `Session-Expires` and `Min-SE` are carried through the initial INVITE and the 2xx (`sbc-daemon`, closes #117)

### Added

- **SIP over WebSocket listeners** — `transport.ws_listen` now binds RFC 7118 WebSocket listeners (plain `ws`); `wss_listen` is rejected by `validate_config` because the WebSocket transport does not terminate TLS (`sbc-daemon`, `sbc-config`)
- **Audit trail** — `logging.audit_enabled` starts the `uc-audit` logger (hash-chained JSON lines at `logging.audit_path`, or the tracing output); the daemon records startup/shutdown, REGISTER authentication outcomes, INVITE admission and VPS rejections, call establishment/termination with duration, and rate-limit rejections (NIST AU-2/AU-3/AU-9) (`sbc-daemon`, `uc-audit`)

### Fixed

- **Configuration keys that were parsed but ignored are now enforced** — `security.min_tls_version` and `security.require_mtls` (with the new `security.tls_ca_path`) are applied to SIP-TLS listeners via `uc-transport::tls::create_server_config_with`; `rate_limit.per_user_rps` limits requests per From user after parsing (503 + `Retry-After`); `logging.level`/`format`/`output` configure the tracing subscriber (json/text, stdout/stderr/file). `validate_config` rejects `require_mtls` without certificate and CA paths and malformed `[logging]` values (`sbc-daemon`, `sbc-config`, `uc-transport`, `uc-dos-protection`, closes #145)
- **ICE connectivity checks run in the soft client** — `IceHandler::start_checks` now drives RFC 8445 checks on the media socket: priority-ordered checks paced by Ta, retransmission, role-conflict handling, regular and aggressive nomination, and answering the peer's checks; the media session falls back to the SDP `c=`/`m=` address on ICE mismatch (RFC 8445 §5.1.1, e.g. through a B2BUA) or check failure. STUN servers and the nomination mode come from `[network]` settings (`client-sip-ua`, `client-core`, closes #142)
- **Dead ICE module removed from sbc-daemon** — `ice_agent.rs` was never constructed; the SBC anchors media with symmetric latching and does not run ICE. `proto-ice` and `proto-turn` are no longer daemon dependencies (`sbc-daemon`)
- **Compliance documents reconciled with what ships** — `PROTO_RFC_COMPLIANCE.md`, `docs/RFC_COMPLIANCE_GAPS.md`, `docs/NIST-800-53-CONTROLS.md`, `docs/CNSA-2-COMPLIANCE.md`, `docs/CLUSTERING.md`, `docs/route-patterns.md`, `docs/SBC-ADMIN-GUIDE.md` and `ROADMAP.md` now label every "Full"/"Complete"/"Implemented" entry as *Wired* (naming the binary), *Library-only* or *Planned*, use the real `proto-*`/`uc-*` crate names, and correct config keys and enum spellings that did not match `sbc-config` (closes #118)
- **SIP transaction layer is driven** — the daemon now steps the `proto-transaction` state machines it creates: a timer task retransmits forwarded INVITEs (Timer A), non-2xx finals toward the caller (Timer G) and 2xx responses until ACKed (RFC 3261 §13.3.1.4); an unanswered B-leg INVITE fails the call with 408 (Timer B); retransmitted requests are answered from the stored response instead of being re-processed; every non-2xx final from the far end is ACKed (§17.1.1.3) and retransmitted finals are absorbed, so a lost ACK no longer leaves the far end retransmitting for 32 s or restarts the media relay (`sbc-daemon`)
- **481 for unmatched in-dialog requests** — BYE, re-INVITE, UPDATE and other tagged requests for a dialog the SBC does not have, and CANCEL for an unknown INVITE, now get 481 Call/Transaction Does Not Exist instead of 200 OK or 405 (RFC 3261 §9.2, §12.2.2, §15.1.2) (`sbc-daemon`)

### Security

- **No untrusted-CA override in release builds** — the provisioning HTTP client's accept-any-certificate mode (`CaTrust::Insecure`) and the sign-in "continue anyway" prompt now exist only under `debug_assertions`, matching the SIP TLS transport. Release clients must install a private CA via `[provisioning] extra_ca_cert_file` (`client-provisioning`, `client-gui-tauri`)
- **Security Audit is blocking** — the `cargo audit` job is part of the `CI OK` gate
- **Opus binding → `opusic-c`** — the `opus-ffi` feature now uses the maintained `opusic-c` 1.6 binding (bundled libopus 1.6.1, CMake 4 compatible) instead of the unmaintained `audiopus`/`audiopus_sys` (RUSTSEC-2026-0150). No system libopus needed; the audit ignore is removed (`uc-codecs`)
- **cryptoki 0.7 → 0.12** — fixes RUSTSEC-2026-0286 (out-of-bounds read decoding `CKA_ALLOWED_MECHANISMS`) in the PKCS#11 smart-card certificate enumeration (`client-core`). Also drops the unmaintained `paste` crate from the lockfile
- **cargo-audit clean** — CI installs `libopus-dev` so the `opus-ffi` feature links the system libopus instead of running `audiopus_sys`'s unmaintained source build; `.cargo/audit.toml` documents the remaining GTK3-pinned advisories

### Changed

- **Path-scoped CI** — PRs lint/test only the crate groups they touch (`crates/sbc`, `crates/client`); changes to the shared `uc-*`/`proto-*` core, workspace manifests, or the workflow widen to the full workspace, and pushes to `main` always run everything. A single `CI OK` status gates the result (`.github/workflows/ci.yml`)
- **Independent release tags** — SBC images are cut from `sbc-v*` (`release-sbc.yml`, formerly `release.yml` on `v*`); a new `release-client.yml` builds the soft-client desktop binaries and `client-ffi` libraries from `client-v*`. Bare `v*` tags no longer trigger a release
- **Integration tests** no longer run for client-only PRs (`integration.yml`)

## [0.9.0] — 2026-07-19

### Security

- **Path traversal rejection** — reverse-proxy catch-all now rejects dot-segment (`..`/`.`) paths (`sbc-api-server`)
- **Error detail suppression** — proxy upstream-failure responses no longer leak internal error strings
- **IP source validation** — provision server falls back to `ConnectInfo` peer address when `X-Forwarded-For` is absent
- **OIDC session check** — `/api/v1/auth/session` now validates OIDC bearer tokens alongside legacy HMAC, so Keycloak SSO users see correct authentication status

### Fixed

- **Regex dial-plan matching** — replaced `true` stub with real `regex::Regex` evaluation in `DialPattern::Regex` (`uc-routing`)
- **UTF-8 panic in number transforms** — `StripDigits` and `ReplacePrefix` now use `char_indices` instead of byte-index slicing (`uc-routing`)
- **Blocked route patterns** — blocked patterns now reject calls outright instead of being silently skipped, matching expected telecom semantics (`uc-routing`)
- **Via header copy** — SIP responses now copy all Via headers per RFC 3261, not just the first (`sbc-daemon`)
- **NaN/Infinity guard** — `burst_multiplier` validation rejects non-finite floats (`sbc-config`)
- **Keycloak `basic` scope** — OIDC client config now includes the `basic` scope so operator tokens carry the `sub` claim

### Changed

- **RTP port allocation** — replaced hardcoded port 20000 with an atomic wrap-around allocator (20000–40000 range) (`sbc-daemon`)
- **TCP/TLS connection cap** — accept loops bounded by a shared `Semaphore(10_000)` to prevent resource exhaustion (`sbc-daemon`)
- **Blocking DNS** — `to_socket_addrs()` moved off the async executor via `block_in_place` (`sbc-daemon`)
- **Config sync TOCTOU guard** — `restamp_uploaded` uses a `collected_at` timestamp so concurrent local edits during the upload round-trip are not clobbered (`sbc-config-sync`)
- **Config reload warning** — SIGHUP handler now logs that live Server/SipStack retain their original config snapshots (`sbc-daemon`)
- **Postgres sslmode** — DSN `sslmode` is now configurable via `values.yaml` instead of being hardcoded to `disable` (`deploy/helm`)

### Added

#### Enterprise Management Features (In Progress)

**Multi-Format Configuration Support** (`sbc-config`)

- Added `serde_yaml_ng` dependency for YAML configuration parsing
- New `ConfigFormat` enum with `Toml` and `Yaml` variants
- `ConfigFormat::from_extension()` for automatic format detection from file extension
- `load_from_file_with_format()` for explicit format loading
- `load_from_str_with_format()` for parsing configuration strings
- Auto-detection: `.yaml`/`.yml` files parse as YAML, all others as TOML
- Backward compatible: existing TOML workflows unchanged
- 20 tests passing for configuration crate

**gRPC Management API** (`sbc-grpc-api` new crate)

- New Protocol Buffer definitions for enterprise management
- Services: ConfigService, CallService, RegistrationService, SystemService, HealthService, ClusterService
- Proto files: config.proto, call.proto, registration.proto, system.proto, health.proto, cluster.proto
- Built with tonic 0.14 and prost 0.14
- Standard gRPC health checking protocol (grpc.health.v1)
- Cluster service feature-gated behind `cluster` feature flag
- 4 tests passing for gRPC API crate

**gRPC Server Implementation** (`sbc-daemon`)

- New `grpc_server` module with service implementations
- `GrpcServer` struct for managing gRPC server lifecycle
- `ConfigServiceImpl`: GetConfig, UpdateConfig, ValidateConfig, ReloadConfig RPCs
- `SystemServiceImpl`: GetVersion, GetStats, GetMetrics, ReloadTls, GetTlsStatus, Shutdown RPCs
- `HealthServiceImpl`: Standard gRPC health Check and Watch RPCs
- `CallServiceImpl`: ListCalls, GetCall, TerminateCall, GetCallStats, WatchCalls RPCs
- `RegistrationServiceImpl`: ListRegistrations, GetRegistration, DeleteRegistration, GetRegistrationStats RPCs
- `ClusterServiceImpl`: GetClusterStatus, ListNodes, GetNodeStatus, DrainNode, WatchCluster RPCs (cluster feature)
- ClusterService maps internal NodeRole/NodeState to protobuf enums
- ClusterService aggregates health from storage, discovery, and location services
- `GrpcConfig` schema in sbc-config for server configuration
- Feature-gated behind `grpc` feature flag (ClusterService also requires `cluster` feature)
- Integrated into Runtime with graceful shutdown support
- Runtime passes ClusterManager to GrpcServer when cluster feature enabled
- Default port 9090 (alongside REST API on 8080)
- TLS/mTLS support via `ServerTlsConfig` with certificate and CA configuration
- 61 tests passing for daemon crate (with cluster feature)

**Configuration Schema** (`sbc-config/schema.rs`)

- `GrpcConfig` struct with comprehensive options:
  - `enabled`: Enable/disable gRPC server
  - `listen_addr`: Bind address (default: 0.0.0.0:9090)
  - `tls_cert_path`, `tls_key_path`, `tls_ca_path`: TLS configuration
  - `require_mtls`: Mutual TLS requirement
  - `max_connections`: Connection limit
  - `request_timeout_secs`: Request timeout
  - `enable_reflection`: gRPC reflection service

**gRPC Reflection Service** (`sbc-grpc-api`, `sbc-daemon`)

- Added `tonic-reflection` v0.14 dependency to workspace
- Build script generates file descriptor set (`sbc_descriptor.bin`) for reflection
- `FILE_DESCRIPTOR_SET` constant exported from sbc-grpc-api (feature-gated behind `reflection`)
- New `grpc-reflection` feature flag in sbc-daemon enables reflection support
- Reflection service enabled at runtime via `enable_reflection` config option
- Allows service discovery via `grpcurl -plaintext localhost:9090 list`
- Compatible with all feature combinations (grpc, cluster, grpc-reflection)

**gRPC Integration Tests** (`sbc-integration-tests`)

- New `grpc_tests` module with comprehensive test coverage
- Proto message tests: Health, Config, System, Call, Registration services
- Cluster service tests (feature-gated behind `grpc-cluster`)
- Reflection service tests verifying FILE_DESCRIPTOR_SET
- Prelude export tests ensuring all types accessible
- Service trait tests with mock Health service implementation
- Message serialization tests using prost encode/decode
- New feature flags: `grpc`, `grpc-reflection`, `grpc-cluster`
- 35 gRPC-specific tests, 82 total tests with all features enabled

#### Phase 24.38: Button Event Handlers & Custom Dialogs (Completed)

**Button Event Handlers** (`client-gui-windows/src/views/*.rs`)

- Dialer view: Dialpad digits (0-9, *, #), Call, Clear, Backspace buttons
- Call view: Mute, Hold, Transfer, Hangup, Keypad buttons, audio device selection
- Contacts view: Add, Call, Edit, Favorite, Delete buttons, search text filtering
- Settings view: Register, Unregister, Refresh Certs, Use Cert, Save, Discard buttons

**Custom Dialogs Module** (`client-gui-windows/src/dialogs/`)

- `TransferDialog`: Modal dialog for call transfer with SIP URI input
- `ContactDialog`: Add/edit contact dialog with name, SIP URI, favorite checkbox
- `PinDialog`: Masked PIN entry dialog for smart card authentication
- `DtmfDialog`: Non-modal DTMF dialpad for sending tones during active calls

**App Handler Methods** (`client-gui-windows/src/app.rs`)

- Dialer handlers: `on_dialer_digit()`, `on_dialer_call()`, `on_dialer_clear()`, `on_dialer_backspace()`
- Call handlers: `on_call_mute()`, `on_call_hold()`, `on_call_transfer()`, `on_call_hangup()`, `on_call_keypad()`
- Contact handlers: `on_contact_add()`, `on_contact_call()`, `on_contact_edit()`, `on_contact_favorite()`, `on_contact_delete()`, `on_contact_search()`
- Settings handlers: `on_settings_register()`, `on_settings_unregister()`, `on_settings_refresh_certs()`, `on_settings_use_cert()`, `on_settings_save()`, `on_settings_discard()`
- DTMF support: `show_dtmf_dialog()`, `send_dtmf()` for RFC 4733 telephone events
- Transfer support: `show_transfer_dialog()`, `transfer_call()` for RFC 3515 REFER

#### Phase 24.37: Native Windows GUI Migration (Completed)

**Migration from egui/eframe to native-windows-gui**

- Replaced egui/eframe with native-windows-gui (NWG) 1.0 for true Windows native appearance
- Removed `tray-icon` dependency in favor of NWG's built-in `TrayNotification`
- Kept `winrt-notification` for Windows toast notifications (works independently of GUI)

**Main Application Window** (`client-gui-windows/src/app.rs`)

- `nwg::Window` as main application container (420x640)
- `nwg::TabsContainer` for view navigation (Dialer, Call, Contacts, Settings)
- `nwg::StatusBar` for status messages
- `nwg::AnimationTimer` (100ms) for SIP event polling
- RefCell-based interior mutability for NWG's event-driven model
- Rc-based app sharing across event handlers

**View Implementations**

- `DialerView`: TextInput, 12 dialpad buttons, Call/Clear/Backspace actions
- `CallView`: Labels for caller/status/duration, Mute/Hold/Transfer/Hangup buttons, audio device ComboBoxes
- `ContactsView`: ListBox with search filtering, CRUD action buttons, favorite indicators
- `SettingsView`: Account form fields, certificate ListBox, Register/Unregister buttons

**System Tray** (`client-gui-windows/src/tray.rs`)

- `nwg::TrayNotification` for system tray icon
- `nwg::Menu` with popup context menu (Show, Hide, Exit)
- Event handlers for tray icon click and menu selection
- Tray icon click shows main window

**Styling** (`client-gui-windows/src/style.rs`)

- Simplified to color constants (RGB tuples) and size definitions
- Removed egui-specific styling helpers
- Windows system theming handles most visual styling

#### Phase 15: Production Hardening (Completed)

**New Crate**: `uc-telemetry`

- OpenTelemetry distributed tracing integration
  - `TelemetryConfig` with builder pattern for traces, metrics, OTLP
  - `TelemetryProvider` managing tracer and meter providers
  - `SpanContext` with W3C Trace Context (traceparent) support
  - Standard SIP/VoIP span attributes (call_id, sip_method, etc.)
  - OTLP exporter support (optional `otlp` feature)
  - Tracing crate integration (optional `tracing` feature)
  - 18 tests passing

**TLS Certificate Rotation** (`uc-transport/cert_reload.rs`)

- `ReloadableTlsAcceptor` for hot certificate reloading
  - Uses `arc-swap` for lock-free atomic acceptor swapping
  - New connections use updated certificates
  - Existing connections continue with original certificates
  - `reload()` method for programmatic reload
  - `try_reload()` for signal handler use (logs errors)
  - Reload metrics: count and timestamp tracking
  - `CertReloadStats` for monitoring
  - 7 tests passing

#### Phase 25: SCTP RFC 9260 Full Compliance - Critical Items (Completed)

**Verification Tag Validation** (`uc-transport/sctp/association.rs`)

- RFC 9260 §8.5.1 compliant verification tag validation
  - `VerificationTagError` enum with variants: `InitNonZero`, `Mismatch`, `AbortTBitMismatch`, `ShutdownCompleteTBitMismatch`
  - `validate_verification_tag()` method checks V-tag on all received packets
  - INIT must have V-tag = 0, ABORT/SHUTDOWN-COMPLETE handle T-bit flag
  - Rejects packets with incorrect V-tag (silently drops or sends ABORT)

**Cookie Security Hardening** (`uc-transport/sctp/cookie.rs`)

- RFC 9260 §5.1.3 compliant cookie authentication (CNSA 2.0)
  - HMAC-SHA384 for cookie MAC (upgraded from placeholder)
  - 48-byte cryptographically secure random secret key
  - Cookie lifespan enforcement with expiration checking
  - Stale cookie detection via timestamp validation

**ERROR Chunk Handling** (`uc-transport/sctp/association.rs`)

- RFC 9260 §3.3.10 compliant error processing
  - `process_error_chunk()` handles all 14 error cause codes
  - Error causes: InvalidStreamIdentifier, MissingMandatoryParameter, StaleCookieError, OutOfResource, UnresolvableAddress, UnrecognizedChunkType, InvalidMandatoryParameter, UnrecognizedParameters, NoUserData, CookieReceivedWhileShuttingDown, RestartWithNewAddresses, UserInitiatedAbort, ProtocolViolation, Unknown
  - Graceful degradation - non-fatal errors don't abort association

**ECN Integration** (`uc-transport/sctp/congestion.rs`)

- RFC 9260 §7.2.5 compliant Explicit Congestion Notification
  - `on_ecn_ce_received()` method in CongestionController
  - Reduces cwnd to ssthresh (less aggressive than timeout)
  - Prevents double-reduction during fast recovery
  - `process_ecne()` handles ECNE chunks and sends CWR response
  - `process_cwr()` acknowledges peer's cwnd reduction
  - 3 new ECN tests (reduction, no-double-reduce, ecn-vs-timeout)

**Per-Path Congestion Control** (`uc-transport/sctp/path.rs`)

- RFC 9260 §7.1 compliant multi-homed congestion management
  - Each `Path` has dedicated `CongestionController` instance
  - Path-specific cwnd, ssthresh, flight_size tracking
  - `RtoCalculator` per path for RTT estimation
  - `PathManager` handles path selection and failover
  - Error counting and automatic path deactivation

**Tests**: 169 tests passing (76 RFC 9260 compliance + 9 integration + 84 unit)

#### Phase 25: SCTP RFC 9260 Full Compliance - Medium Priority (Completed)

**ASCONF Chunks** (`uc-transport/sctp/chunk.rs`, `association.rs`)

- RFC 5061 compliant Address Configuration Change support
  - `AsconfChunk` with ADD-IP, DELETE-IP, SET-PRIMARY-ADDRESS parameters
  - `AsconfAckChunk` for ASCONF response with success/error codes
  - `AsconfParam` enum: AddIp, DeleteIp, SetPrimaryAddress
  - `AsconfAckParam` with success/error correlation IDs
  - Multi-homing address management infrastructure
  - Serial number tracking for ASCONF request/response correlation

**Forward TSN / Partial Reliability** (`uc-transport/sctp/chunk.rs`, `association.rs`)

- RFC 3758 compliant PR-SCTP extension support
  - `ForwardTsnChunk` with new cumulative TSN and stream info
  - `ForwardTsnStream` struct for per-stream sequence number updates
  - Enables timed reliability and limited retransmission policies
  - Stream sequence number advancement for skipped chunks

**Stream Reset / RE-CONFIG** (`uc-transport/sctp/chunk.rs`, `association.rs`)

- RFC 6525 compliant stream reconfiguration support
  - `ReConfigChunk` for reconfiguration requests/responses
  - `ReConfigParam` enum: OutgoingSsnReset, IncomingSsnReset, SsnTsnReset, AddOutgoingStreams, AddIncomingStreams, Response
  - `ReConfigResult` enum: Success, Denied, WrongSsn, AlreadyInProgress, BadSequence, InProgress
  - Request/response sequence number tracking
  - Dynamic stream addition and SSN reset

**Full INIT Parameter Validation** (`uc-transport/sctp/association.rs`)

- RFC 9260 §5.1.2 compliant INIT/INIT-ACK validation
  - `InitValidationError` enum: InvalidInitiateTag, InvalidInboundStreams, InvalidOutboundStreams
  - Validates Initiate Tag MUST NOT be 0
  - Validates Number of Inbound/Outbound Streams MUST NOT be 0
  - Warns if A-RWND below minimum 1500 bytes
  - Applied to both `process_init()` and `process_init_ack()`

**Duplicate TSN Detection** (`uc-transport/sctp/association.rs`)

- RFC 9260 §6.2 compliant duplicate tracking
  - `received_tsns: HashSet<u32>` for gap tracking
  - `duplicate_tsns: Vec<u32>` for SACK duplicate reports
  - Duplicate TSNs reported in next SACK
  - Prevents replay attacks and handles network duplicates

**Immediate Flag Handling** (`uc-transport/sctp/association.rs`)

- RFC 9260 §6.8 compliant I-bit processing
  - `sack_immediately: bool` flag set on I-bit receipt
  - Triggers immediate SACK generation without delay
  - Supports low-latency signaling applications

**Multi-homing Infrastructure** (`uc-transport/sctp/association.rs`)

- RFC 9260 compliant multi-address support
  - `local_addresses: HashSet<SocketAddr>` for local addresses
  - `peer_addresses: HashSet<SocketAddr>` for peer addresses
  - ASCONF serial number tracking for dynamic updates
  - RE-CONFIG sequence number management

#### Phase 25: SCTP RFC 9260 Full Compliance - Lower Priority (Completed)

**PAD Chunk Support** (`uc-transport/sctp/chunk.rs`)

- RFC 4820 / RFC 9260 §3.3.14 compliant padding chunk
  - `PadChunk` struct for PMTU probing
  - `new(size)` and `from_bytes(padding)` constructors
  - `chunk_size()` helper for total size calculation
  - Encode/decode with proper 4-byte alignment

**AUTH Chunk Support** (`uc-transport/sctp/chunk.rs`)

- RFC 4895 compliant SCTP authentication chunk
  - `AuthChunk` struct with shared key ID, HMAC ID, and HMAC value
  - `HmacId` enum: Reserved, Sha1 (20 bytes), Sha256 (32 bytes)
  - `hmac_algorithm()` and `hmac_length()` helpers
  - Encode/decode roundtrip verified

**SACK Bundling Optimization** (`uc-transport/sctp/association.rs`)

- RFC 9260 §6.2 compliant delayed/bundled SACK
  - `on_data_received()` tracks DATA chunks since last SACK
  - `should_send_sack()` checks timer, every-other-DATA rule, and I-bit
  - `try_bundle_sack()` for bundling SACK with outgoing DATA
  - T4-sack timer (200ms) for delayed SACK generation
  - Immediate SACK on second DATA chunk per RFC requirement

**Heartbeat Bundling** (`uc-transport/sctp/association.rs`)

- RFC 9260 §8.3 compliant heartbeat optimization
  - `should_send_heartbeat()` checks idle paths and timer
  - `restart_heartbeat_timer()` tracks last data sent time
  - Heartbeat bundling with DATA chunks reduces overhead

**Path MTU Discovery** (`uc-transport/sctp/association.rs`)

- RFC 9260 §8.4 compliant PMTU probing
  - `path_mtu()` returns current discovered MTU
  - `start_pmtu_probe()` sends PAD chunks to probe larger MTU
  - `on_pmtu_probe_success()` updates MTU on successful probe
  - `on_pmtu_probe_failure()` handles ICMP Packet Too Big
  - Configurable PMTU min (576 IPv4 / 1280 IPv6) and max bounds

**T2-Shutdown Timer** (`uc-transport/sctp/timer.rs`)

- RFC 9260 §9.2 compliant shutdown retransmission timer
  - Already implemented as T2-shutdown in TimerManager
  - Handles SHUTDOWN-ACK retransmission timing
  - Proper state machine integration

**Tests**: 240 unit tests + 76 RFC compliance tests + 9 integration tests

#### Phase 22: High Availability - Storage Backends (Completed)

**Redis Backend** (`uc-storage/redis.rs`)

- Full `StorageBackend` implementation with bb8 connection pooling
  - All trait methods: get, set, delete, keys, increment
  - Extended methods: exists, set_nx, mget, mset, mdelete, ttl, expire, persist
  - Connection pool configuration (max size, idle timeout)
  - Health check via PING command
  - 20 tests (11 require running Redis server)

**PostgreSQL Backend** (`uc-storage/postgres.rs`)

- Full `StorageBackend` implementation with sqlx
  - Auto-migration: creates `kv_store` and `kv_counters` tables
  - TTL via `expires_at` TIMESTAMPTZ column
  - Pattern matching via `glob_to_like()` conversion
  - Connection pool configuration via `PgPoolOptions`
  - Health check via connection acquisition
  - 21 tests (11 require running PostgreSQL server)

**DNS-based Service Discovery** (`uc-discovery/dns.rs`)

- `DnsDiscovery` provider using hickory-resolver
  - SRV record lookup with address resolution
  - A/AAAA record lookup for simple discovery
  - `sort_peers()` for priority/weight ordering
  - `select_weighted_peer()` per RFC 2782
  - Health check via localhost resolution
  - Integration with `uc-dns` crate
  - 8 tests (2 require network)

**Kubernetes Service Discovery** (`uc-discovery/kubernetes.rs`)

- `KubernetesDiscovery` provider using kube-rs
  - In-cluster and kubeconfig client initialization
  - Kubernetes Endpoints API for service discovery
  - Named port and numeric port resolution
  - Metadata enrichment (pod name, node name, namespace, service)
  - Ready/not-ready endpoint distinction with priority weighting
  - Health check via namespace list API
  - 7 unit tests + integration tests (require K8s cluster)

**Registrar Storage Integration** (`proto-registrar`)

- `StorableBinding` DTO for serializing SIP bindings
  - Converts `std::time::Instant` to Unix timestamps
  - Full round-trip support with `to_binding()` conversion
  - Serializable binding state for external storage
- `AsyncLocationService` cache-aside wrapper
  - Wraps synchronous `LocationService` for async storage access
  - Cache-first reads with storage fallback
  - Write-through to storage with TTL (expires + 60s buffer)
  - Key format: `sip:binding:{aor}:{binding_key}`
  - `sync_cache()` for cache warming from storage
  - Health check via storage backend ping
  - Storage feature flag (`storage`) for optional dependency
  - 6 tests for StorableBinding + AsyncLocationService

**Cluster Integration Tests** (`sbc-integration-tests`)

- Comprehensive integration test suite for clustering infrastructure
  - Storage tests: basic operations, TTL, keys pattern, increment, health check
  - Discovery tests: static discovery, empty peers, health check, peer metadata
  - Membership tests: creation, add/remove node, get node, view version
  - Registrar tests: AsyncLocationService CRUD, cache reload, health check
  - End-to-end tests: cluster formation, registration flow, shared storage
  - 23 integration tests total
  - Feature flags: `cluster`, `redis`, `postgres`

**Dependencies Added**

- `arc-swap` 1.7: Lock-free atomic pointer swapping
- `chrono` 0.4: Timestamp handling for PostgreSQL TTL
- `bb8` 0.8: Connection pooling for Redis
- `bb8-redis` 0.18: Redis backend for bb8
- `redis` 0.27: Redis client
- `sqlx` 0.8: PostgreSQL async driver

#### Phase 24: SIP Soft Client (In Progress)

**New Crates** (`crates/client/`)

- `client-types`: Shared types for SIP soft client
  - `CallState` enum with full call lifecycle (Idle → Dialing → Ringing → Connected → Terminated)
  - `CallInfo` and `CallHistoryEntry` for call tracking and persistence
  - `CallFailureReason` and `CallEndReason` for detailed call disposition
  - `SipAccount` with smart card certificate configuration (NO password fields)
  - `CertificateConfig` for smart card (CAC/PIV) certificate selection
  - `CertificateSelectionMode`: PromptUser, SpecificCertificate, AutoSelect
  - `CertificateInfo` for certificate details (thumbprint, subject, issuer, validity)
  - `RegistrationState` with smart card states (WaitingForPin, SmartCardNotPresent, CertificateInvalid)
  - `TransportPreference::TlsOnly` (CNSA 2.0 - no UDP/TCP fallback)
  - `AudioConfig` with device selection and jitter buffer settings
  - `AudioDevice` and `AudioStatistics` for audio monitoring
  - `CodecPreference` enum: Opus, G722, G711Ulaw, G711Alaw
  - `Contact` and `PhoneNumber` types for contact management
  - `ClientError` and `ClientResult` error handling

- `client-audio`: Audio pipeline skeleton (CPAL integration planned)
  - `AudioError` and `AudioResult` types

- `client-sip-ua`: SIP User Agent implementation
  - `SipUaError` with smart card error types (SmartCardNotPresent, CertificateError)
  - `SipUaResult` type
  - `RegistrationAgent` for SIP REGISTER transactions
    - State management: Unregistered → Registering → Registered
    - Handles 200 OK, 401/407 rejection (mTLS only), 403, 423 responses
    - Registration refresh before expiry
    - `RegistrationEvent` for state changes and request sending
  - `CallAgent` for INVITE/BYE/CANCEL/ACK transactions
    - Outbound call flow: make_call → Dialing → Ringing → Connected
    - Hangup: CANCEL for pending calls, BYE for connected
    - SDP offer/answer event emission
    - Response handling for 1xx, 2xx, 3xx, 4xx-6xx status codes
    - Proper ACK generation for all final responses
    - `CallEvent` for state changes, SDP handling, request sending
  - `IceHandler` for ICE candidate gathering
    - Host, server-reflexive (STUN), and relay (TURN) candidates
    - SDP candidate formatting using `Candidate::to_sdp()`
    - SDP candidate parsing using `Candidate::from_sdp()`
    - ICE role handling (controlling/controlled)
    - `IceEvent` for state changes, candidates, connectivity
  - `DtlsHandler` for DTLS handshake
    - SRTP key derivation via DTLS-SRTP
    - Certificate fingerprint handling for SDP
    - Support for client and server roles
    - `DtlsEvent` for state changes, handshake completion
  - `MediaSession` coordinated secure media pipeline
    - Orchestrates ICE + DTLS + SRTP setup
    - `MediaSessionState`: New, Gathering, Connecting, Securing, Active, Closing, Closed, Failed
    - RtpPacket encryption via `SrtpProtect`
    - RtpPacket decryption via `SrtpUnprotect`
    - UDP socket management for media
    - `MediaSessionEvent` for state changes, candidates, credentials, ready notification

- `client-core`: Application core (Phase 24.4 Complete)
  - `settings.rs`: TOML-based settings persistence
    - `Settings`, `GeneralSettings`, `NetworkSettings`, `UiSettings` structs
    - `SettingsManager` with atomic save (temp file + rename)
    - Platform-specific paths via `directories` crate
    - Account management with set/get/remove operations
    - 6 tests passing
  - `contact_manager.rs`: JSON-based contact and call history storage
    - `ContactStore` with HashMap-based contact storage
    - `ContactManager` with CRUD operations
    - Contact search by name, phone number, or SIP URI
    - Partial phone number matching (suffix matching)
    - Call history with automatic trimming (max 1000 entries)
    - 8 tests passing
  - `call_manager.rs`: Call coordination between SIP UA and media
    - `CallManager` bridging CallAgent, MediaSession, and ContactManager
    - make_call/hangup with proper state tracking
    - SDP offer generation with ICE credentials
    - ICE credential parsing from SDP answers
    - Call history integration
    - Mute toggle support
    - 5 tests passing
  - `app.rs`: Main application coordinator
    - `ClientApp` managing registration, calls, settings, contacts
    - `AppState`: Starting, Ready, Registering, Registered, InCall, ShuttingDown
    - `AppEvent`: RegistrationStateChanged, CallStateChanged, IncomingCall, CallEnded, Error
    - Account registration via RegistrationAgent
    - Event broadcasting to GUI
    - Graceful shutdown with state persistence
  - `AppError` and `AppResult` types

- `client-gui`: Windows GUI implementation (Phase 24.5 Complete)
  - Main window with dark theme and navigation bar (Dialer, Call, Contacts, Settings)
  - `app.rs`: Main GUI application coordinator
    - `SipClientApp` implementing `eframe::App`
    - `ActiveView` enum for navigation state
    - Event-driven architecture connecting to client-core
    - Registration status indicator in navigation bar
    - Error dialog for user notifications
  - `views/dialer.rs`: Phone dialer view
    - Number pad with digits 0-9, *, #
    - URI input field with backspace and clear
    - Auto-formatting for sips: URIs
    - `DialerAction::Call(String)` for call initiation
  - `views/call.rs`: Active call view
    - Duration timer with mm:ss display
    - Remote party info display
    - Mute/Hold/Hangup button controls
    - `CallAction` enum: Hangup, Mute, Hold
    - Visual call state feedback
  - `views/contacts.rs`: Contacts list view
    - Search filtering by name or SIP URI
    - Favorites section with star indicators
    - Avatar initials display
    - Context menu with call/edit/delete options
    - `ContactsAction` enum: Call, Edit, Delete
  - `views/settings.rs`: Settings view
    - Tabbed interface: Account, Audio, General, About
    - Account configuration with smart card info
    - Audio device selection (input/output)
    - General settings (startup behavior, audio preferences)
    - About tab with version info
    - `SettingsAction` enum: Save, Register, Unregister
  - `tray.rs`: System tray integration
    - `SystemTray` with tray-icon crate
    - Menu items: Show window, Exit
    - `TrayAction` enum for event handling
    - Icon generation for tray display
  - `notifications.rs`: Windows toast notifications (Phase 24.6)
    - `NotificationManager` for toast notifications
    - `NotificationType` enum: IncomingCall, MissedCall, CallEnded, Error, RegistrationChanged
    - Uses `winrt-notification` on Windows
    - Integrated with app event handling

- `client-core`: Certificate store and security (Phase 24.6)
  - `cert_store.rs`: Certificate store access
    - `CertificateStore` for Windows Certificate Store
    - `CertStoreError` error types
    - Auto-select prefers ECDSA P-384 (CNSA 2.0)
    - Find by thumbprint, list, refresh operations
    - Stub data for cross-platform development
    - 8 tests for certificate operations

- `client-types`: Sensitive data types (Phase 24.6)
  - `sensitive.rs`: Memory-safe credential storage
    - `SmartCardPin` with zeroize-on-drop
    - `SessionToken` for SRTP/session secrets
    - `SrtpKeyMaterial` for SRTP master keys
    - `SensitiveString` for general sensitive data
    - All types implement Debug with [REDACTED]
    - 7 tests for sensitive types

**Phase 24.7: Deployment & Packaging**

- `crates/client/installer/` directory for Windows packaging
  - `usg-sip-client.wxs` - WiX v4.x MSI installer configuration
    - Program Files installation with proper permissions
    - Start Menu and Desktop shortcuts
    - Registry entries for uninstall
    - SIP/SIPS URI handler registration for click-to-call
    - Upgrade support via UpgradeCode
  - `build-installer.ps1` - PowerShell build script
    - Debug and Release build modes
    - CNSA 2.0 compliant code signing (SHA-384)
    - MSI creation via WiX Toolset
    - Portable ZIP package creation
  - `resources/license.rtf` - License agreement for installer
  - `resources/default-settings.toml` - Default configuration
  - `README.md` - Installer documentation

- `crates/client/client-gui/` Windows integration
  - `app.manifest` - Windows application manifest
    - UAC settings (asInvoker - no elevation required)
    - DPI awareness (Per-Monitor V2)
    - Visual styles (Common Controls 6)
    - Windows version compatibility (Windows 7+)
  - `build.rs` - Build script for Windows resources
    - Version info resource generation
    - Manifest embedding
    - Icon embedding support

**CNSA 2.0 Compliance Documentation**

- `CNSA_COMPLIANCE.md` in crates/client/
  - Algorithm restrictions (AES-256, P-384, SHA-384)
  - Crate-by-crate compliance status
  - Smart card authentication requirements
  - Key management practices

**Phase 24.8: Audio Pipeline**

- `client-audio` crate fully implemented
  - `device.rs`: Audio device enumeration and management (CPAL 0.17)
    - Cross-platform input/output device listing via `DeviceManager`
    - Device selection by name with fallback to default
    - Stream configuration for 8/16/48 kHz sample rates
    - Deprecated CPAL API workarounds
  - `jitter_buffer.rs`: Adaptive jitter buffer for RTP reordering
    - BTreeMap-based packet ordering by sequence number
    - `BufferedPacket` with sequence, timestamp, payload type, and data
    - Adaptive depth adjustment (40-200ms min/max)
    - Packet loss detection with `JitterBufferResult::Lost`
    - Jitter calculation per RFC 3550
    - `JitterBufferStats` for monitoring
  - `stream.rs`: CPAL audio capture/playback streams
    - `CaptureStream` for microphone input
    - `PlaybackStream` for speaker output
    - Ring buffer-based producer/consumer (ringbuf 0.4)
    - Support for i16 and f32 sample formats
    - Automatic mono mixdown from stereo
    - Non-blocking read/write operations
  - `codec.rs`: Codec encode/decode pipeline
    - `CodecPipeline` wrapper for G.711, G.722, Opus
    - Codec negotiation via `negotiate_codec()`
    - Payload type mapping and SDP capability generation
    - PLC (packet loss concealment) via silence generation
  - `rtp_handler.rs`: RTP packet send/receive
    - `RtpTransmitter` with sequence number and timestamp management
    - `RtpReceiver` with jitter buffer integration
    - SRTP encryption via `SrtpProtect` wrapper
    - SRTP decryption via `SrtpUnprotect` wrapper
    - Separate TX/RX contexts (different SSRCs and directions)
    - `RtpStats` for packet and byte counting
  - `pipeline.rs`: Main audio pipeline coordinator
    - `AudioPipeline` orchestrating full audio path
    - Capture → Encode → RTP TX / RTP RX → Decode → Playback
    - `PipelineConfig` for codec, port, SRTP keys, mute settings
    - `PipelineState`: Stopped, Starting, Running, Stopping
    - SRTP context setup with `SrtpKeyMaterial`
    - Mute control and pipeline statistics aggregation

**Phase 24.9: Audio Integration**

- `client-core` audio session management
  - `audio_session.rs`: Bridge between MediaSession and AudioPipeline
    - `AudioSession` coordinates SRTP keys with audio pipeline
    - `AudioSessionConfig` for flexible configuration
    - `AudioSessionConfigBuilder` for fluent API
    - 20ms audio processing loop via `tokio::time::interval`
    - Proper tick behavior (`MissedTickBehavior::Skip`)
    - Statistics reporting every 5 seconds
    - `AudioSessionEvent`: Started, Stopped, StatsUpdate, Error
  - `CallManager` audio integration
    - Audio session starts on `CallState::Connected`
    - Audio session stops on `CallState::Terminated`
    - `toggle_mute()` propagates to audio session
    - `audio_stats()` for real-time pipeline statistics
    - `set_preferred_codec()` for codec selection
  - 4 new tests for AudioSession

**Phase 24.10: Windows CryptoAPI Integration**

- `client-core` certificate store implementation
  - `cert_store.rs`: Full Windows CryptoAPI integration
    - `CertificateStore` for managing certificates from Windows Certificate Store
    - `CertificateInfo` with subject, issuer, validity dates, thumbprint, key algorithm
    - `CertOpenStore` for MY (Personal) certificate store access
    - `CertEnumCertificatesInStore` for certificate enumeration
    - `CertGetNameStringW` / `CertNameToStrW` for name extraction
    - `CertGetCertificateContextProperty` for smart card detection
    - `CertVerifyTimeValidity` for validity checking
    - EC curve OID parsing (P-256, P-384, P-521 detection)
    - Smart card reader detection via `CERT_KEY_PROV_INFO_PROP_ID`
    - CNSA 2.0 preference: prioritizes P-384 certificates
  - Cross-platform support
    - Full Windows implementation with `#[cfg(windows)]`
    - Stub certificate data for non-Windows platforms (development/testing)
    - `list_smart_card_readers()` returns detected readers on Windows
  - 7 tests for certificate store functionality

**Phase 24.11: Certificate Selection UI**

- `client-gui` security settings implementation
  - `settings.rs`: New Security tab in Settings view
    - Smart card reader detection and display
    - Certificate list with detailed information
    - Key algorithm badges (P-384 green, P-256 yellow, RSA red)
    - Smart card indicator for certificates on hardware tokens
    - Validity status indicators (valid/expired)
  - Certificate selection functionality
    - Manual certificate selection by thumbprint
    - Auto-select mode toggle (prefers ECDSA P-384)
    - Refresh certificates button with loading spinner
  - Certificate information display
    - Subject CN and issuer CN
    - Validity period (not before/not after)
    - Reader name for smart card certificates
- `client-core` certificate store updates
  - `list_smart_card_readers()` method for reader enumeration
- `app.rs` integration
  - `RefreshCertificates` and `SelectCertificate` actions
  - Real-time certificate loading from CertificateStore
  - Error handling with status message display

**Phase 24.12: Certificate Authentication Integration**

- `client-core` certificate export functionality
  - `cert_store.rs`: Certificate chain export methods
    - `get_certificate_chain()` retrieves DER-encoded certificates
    - `has_private_key()` verifies private key availability
    - Windows: extracts raw bytes from CERT_CONTEXT
    - Non-Windows: stub certificate for testing
  - `app.rs`: Certificate authentication support
    - `set_client_certificate()` for mTLS configuration
    - `client_certificate_thumbprint()` accessor
    - `has_client_certificate()` check
    - Certificate chain passed to CallManager
- `client-gui` certificate usage
  - `settings.rs`: UseCertificate action
    - "Use Selected Certificate" button
    - Private key verification before use
    - Status message feedback
  - `app.rs`: Certificate configuration flow
    - Pending certificate storage for delayed init
    - Certificate chain retrieval and validation

**Phase 24.13: PIN Entry UI**

- `client-gui` PIN dialog implementation
  - `app.rs`: Modal PIN dialog for smart card authentication
    - Masked password input field
    - Lock icon with clear visual styling
    - PIN attempt counter with lockout warning (max 3 attempts)
    - Enter key submission support
    - Focus management for keyboard-first input
    - Cancel button for user abort
  - `PinOperation` enum for tracking PIN context
    - `UseCertificate { thumbprint }` - certificate selection
    - `Register { account_id }` - SIP registration signing
    - `SignCall { call_id }` - DTLS call establishment
  - PIN dialog state management
    - `show_pin_dialog`, `pin_input`, `pin_error` fields
    - `pin_operation` for operation context
    - `pin_attempts` for retry tracking
  - Methods: `show_pin_dialog_for()`, `submit_pin()`, `cancel_pin()`, `use_certificate_with_pin()`
- `client-gui` Settings integration
  - `settings.rs`: `SettingsAction::PinRequired { thumbprint }` variant
- `client-core` async event support
  - `app.rs`: PIN-related AppEvent variants
    - `PinRequired { operation, thumbprint }` - trigger PIN dialog
    - `PinCompleted { success, error }` - report PIN result
  - `PinOperationType` enum: CertificateSelection, Registration, CallEstablishment
  - Exported in `lib.rs` for GUI access
- Integration with CertStoreError
  - Automatic PIN dialog on `CertStoreError::PinRequired`
  - Handles `CertStoreError::PinIncorrect` with error display
  - Smart card not present detection via `CertStoreError::SmartCardNotPresent`

**Phase 24.14: SIP Transport Layer**

- `client-core/sip_transport.rs` - SIP over TLS transport implementation
  - `SipTransport` struct for managing TLS connections
    - Connection pooling by peer SocketAddr
    - Automatic reconnection on connection loss
    - TLS 1.3 only (CNSA 2.0 compliance)
    - `send_request()` for sending SIP requests
    - `shutdown()` for graceful cleanup
  - `TlsConnection` for individual connection management
    - Async send/receive using tokio-rustls
    - BytesMut buffer for message reassembly
    - SIP message framing with Content-Length
  - `TransportEvent` enum for event-driven architecture
    - `ResponseReceived { response, source }` - incoming SIP response
    - `RequestReceived { request, source }` - incoming SIP request
    - `Connected { peer }` - TLS connection established
    - `Disconnected { peer, reason }` - connection lost
    - `Error { message }` - transport-level error
  - `InsecureCertVerifier` for development
    - Accepts all certificates during development
    - Production requires proper CA validation
  - Helper functions: `find_header_end()`, `extract_content_length()`
- `client-core/app.rs` - Transport integration
  - `sip_transport` and `transport_event_rx` fields
  - `poll_events()` for event-driven processing
  - `handle_transport_event()` for response routing
  - `handle_registration_event()` wired to transport
- Unit tests: 14 new tests for transport functionality
  - Header parsing tests
  - Content-Length extraction (standard and compact forms)
  - Transport creation and shutdown
  - Event serialization

**Phase 24.15: Call Signaling Integration**

- `client-core/call_manager.rs` - Call signaling wiring
  - `call_event_rx` field to receive CallAgent events
  - `poll_call_events()` to collect pending call events
  - `handle_sip_response()` for routing responses to CallAgent
  - `handle_sip_request()` for routing incoming requests
  - `handle_incoming_invite()`, `handle_incoming_bye()`, `handle_incoming_cancel()`
  - `find_call_by_sip_id()` for SIP Call-ID to app call ID mapping
- `client-core/app.rs` - Call event routing
  - `handle_call_agent_event()` for processing CallAgent events
  - Routes `SendRequest` events to SipTransport
  - CSeq-based response routing (REGISTER vs INVITE/BYE/CANCEL)
  - Incoming request routing to CallManager
- `client-sip-ua/call_agent.rs` - SIP Call-ID lookup
  - `find_call_by_sip_id()` method for call correlation
- Full call signaling path:
  - Outbound: CallAgent → CallEvent::SendRequest → SipTransport
  - Inbound: SipTransport → TransportEvent → CallManager → CallAgent

**Phase 24.16: Production Certificate Validation & mTLS**

- `client-core/sip_transport.rs` - Certificate verification and mTLS
  - `CertVerificationMode` enum with three modes:
    - `Insecure` - Accept all certificates (development only, with warnings)
    - `System` - Use OS trusted CA store (default for production)
    - `Custom` - Use user-provided CA certificates
  - `load_system_root_certs()` - Platform-specific CA loading
    - Windows: Windows Certificate Store (ROOT store)
    - macOS: Keychain
    - Linux: /etc/ssl/certs via rustls-native-certs
    - Graceful handling of partial load errors
  - `load_custom_root_certs()` - Custom CA certificate loading
    - Validates at least one cert is successfully added
  - `ClientCertResolver` for mTLS client authentication
    - Implements `ResolvesClientCert` trait
    - Provides certificate chain during TLS handshake
  - `TransportConfig` for builder-pattern configuration
    - `with_verification_mode()` - set verification mode
    - `with_client_certificate()` - configure client cert and optional private key
  - `SipTransport` updates:
    - `with_config()` - create transport with custom config
    - `set_verification_mode()` - change mode at runtime
    - `set_client_certificate()` - configure mTLS credentials
    - Hot-reload: closes existing connections on config change
- `client-core/app.rs` - ClientApp integration
  - `set_client_certificate()` - configure cert chain for DTLS
  - `set_client_certificate_with_key()` - full mTLS with private key
  - `set_verification_mode()` - change transport verification
  - `set_trusted_ca_certs()` - configure custom CAs
- `client-core/lib.rs` - Export new types
  - `CertVerificationMode`, `TransportConfig` exported for external use
- Unit tests: 10 new tests
  - Verification mode default and debug
  - Config builder pattern
  - Transport with insecure/system modes
  - Runtime verification mode change
  - System root cert loading
  - Custom root cert validation

**Phase 24.17: Response Sending for Incoming Calls**

- `client-core/sip_transport.rs` - Response sending capability
  - `send_response()` - Send SIP responses over existing TLS connections
  - `build_response_from_request()` - RFC 3261 §8.2.6 compliant response building
    - Copy Via headers (all, in order)
    - Copy From header unchanged
    - Copy To header with optional tag
    - Copy Call-ID and CSeq headers
    - Add Content-Length: 0 if no body
  - `generate_tag()` - Unique dialog tag generation
- `client-core/call_manager.rs` - Incoming call handling
  - `IncomingCallInfo` struct for tracking pending incoming calls
  - `handle_incoming_invite_from()` - Process incoming INVITE with source address
    - Automatic 100 Trying response (per RFC 3261 §8.2.6)
    - Automatic 180 Ringing response with To-tag
    - 486 Busy Here when already in a call
  - `accept_incoming_call()` - Accept with 200 OK and SDP answer
  - `reject_incoming_call()` - Reject with 486 Busy or 603 Decline
  - `has_incoming_call()` and `incoming_calls()` accessors
  - Helper functions: `parse_from_header()`, `extract_username_from_sip_uri()`
- `client-core/app.rs` - Transport integration
  - Handle `CallManagerEvent::SendResponse` to forward responses to transport
- `client-types/call.rs` - New end reason
  - `CallEndReason::LocalReject` for rejected incoming calls
- Unit tests: 11 new tests (66 total in client-core)

**Phase 24.18: Incoming Call UI**

- `client-gui/src/views/call.rs` - New call actions
  - `CallAction::Accept { call_id }` - Accept incoming call
  - `CallAction::Reject { call_id }` - Reject incoming call
- `client-gui/src/app.rs` - Incoming call dialog
  - `IncomingCallAlert` struct for tracking pending calls
  - `render_incoming_call_dialog()` - Modal dialog with caller info
  - Green Accept button and Red Reject button
  - Dialog shows on `AppEvent::IncomingCall`
  - Dialog clears on `AppEvent::CallEnded`
  - Handle Accept/Reject in `handle_call_action()`
- `client-core/app.rs` - ClientApp methods
  - `accept_incoming_call()` - Accept and transition to InCall
  - `reject_incoming_call()` - Reject with 486 Busy Here

**Phase 24.19: Full End-to-End Call Testing**

- `client-integration-tests/src/test_utils.rs` - Enhanced mock server
  - `create_invite_request()` - Generate INVITE requests for testing
  - `basic_sdp_offer()` - Generate test SDP offers with ICE/DTLS
  - `invite_100_trying()` - Generate 100 Trying responses
  - `invite_486_busy()` - Generate 486 Busy Here responses
  - `invite_603_decline()` - Generate 603 Decline responses
  - `create_bye_request()` - Generate BYE requests for call termination
  - `bye_200_ok()` - Generate 200 OK for BYE
  - `send_incoming_invite()` - Helper to simulate incoming calls
  - `generate_test_id()` - Unique ID generation for test branches/tags
- `client-integration-tests/src/call_flow_tests.rs` - Incoming call tests
  - `incoming_call_tests` module with 6 new tests:
    - `test_handle_incoming_invite` - INVITE handling with provisional responses
    - `test_accept_incoming_call` - Call acceptance with 200 OK
    - `test_reject_incoming_call` - Call rejection with 486 Busy
    - `test_accept_nonexistent_call_fails` - Error handling
    - `test_reject_nonexistent_call_fails` - Error handling
    - `test_incoming_calls_list` - Incoming call tracking
  - `mock_server_invite_tests` module with 7 tests:
    - Tests for INVITE, SDP, 100/486/603 responses, BYE
  - Helper function `parse_invite()` for parsing SIP messages
- `client-core/src/lib.rs` - Export `IncomingCallInfo` for tests
- Total: 54 integration tests passing

**Phase 24.20: Audio Pipeline Activation**

- `client-sip-ua/src/media_session.rs` - New accessors for audio integration
  - `remote_addr()` - Get remote media address after ICE establishment
  - `local_addr()` - Get local media address
  - `is_ready()` - Check if session is Active with SRTP ready
  - `srtp_contexts()` - Get outbound/inbound SRTP context references
- `client-core/src/call_manager.rs` - Improved audio lifecycle
  - Use real remote address from MediaSession when starting audio
  - Check `session.is_ready()` before extracting remote address
  - Log warning if media not ready (fallback to local address)
  - Audio starts on `CallState::Connected`, stops on `CallState::Terminated`
- New unit tests for MediaSession accessors (22 tests in client-sip-ua)

**Phase 24.21: GUI Certificate Verification Mode**

- `client-types/src/account.rs` - New `ServerCertVerificationMode` type
  - `System` (default) - Use OS trusted CA store
  - `Custom { ca_file_path }` - Use custom CA certificate file (PEM)
  - `Insecure` - Accept all certificates (DEVELOPMENT ONLY)
  - Serializable with serde for settings persistence
  - Helper methods: `label()`, `is_insecure()`, `custom_ca_path()`, `all_modes()`
- `client-core/src/settings.rs` - Added `server_cert_verification` to `NetworkSettings`
  - Persisted in settings.toml
  - Defaults to System (OS CA store)
- `client-gui/src/views/settings.rs` - Security tab UI enhancements
  - Verification mode dropdown (System/Custom/Insecure)
  - Custom CA file path input with Browse button
  - Insecure mode confirmation dialog with security warning
  - Visual warning banner when insecure mode is active
- `client-gui/src/app.rs` - New actions and handlers
  - `SetVerificationMode` - Apply verification mode change
  - `BrowseForCaFile` - Trigger file browser
  - `ConfirmInsecureMode` - User confirmation for insecure mode
- Total: 94 tests passing (28 client-types, 66 client-core)

#### Phase 24.22: Hold/Resume

- `client-sip-ua/src/call_agent.rs` - SIP re-INVITE for hold/resume
  - `hold_call()` - Put call on hold via re-INVITE with `a=sendonly` SDP
  - `resume_call()` - Resume held call via re-INVITE with `a=sendrecv` SDP
  - `send_reinvite()` - Shared helper for building and sending re-INVITE
  - `build_reinvite_request_static()` - Constructs re-INVITE SIP request
  - ClientInviteTransaction for tracking re-INVITE responses
- `client-core/src/call_manager.rs` - High-level hold/resume API
  - `hold_call()` - Generates hold SDP, sends re-INVITE, pauses audio
  - `resume_call()` - Generates resume SDP, sends re-INVITE, restores audio
  - `toggle_hold()` - Switches between Connected and OnHold states
  - `generate_hold_sdp()` / `generate_resume_sdp()` - SDP direction helpers
  - `generate_sdp_with_direction()` - Common SDP generation with configurable direction
- `client-core/src/app.rs` - Expose hold toggle to GUI
  - `toggle_hold()` - Returns true if now on hold, false if resumed
- `client-gui/src/app.rs` - Handle Hold action from UI
  - CallAction::Hold handler calls toggle_hold() and displays status
- Total: 88 tests passing (22 client-sip-ua, 66 client-core)

#### Phase 24.23: Future Enhancements (Hold UI, Multi-Call, MOH)

- `client-gui/src/views/call.rs` - Visual hold indicator
  - Prominent orange hold banner with pause icon (⏸) and "CALL ON HOLD" text
  - Orange duration text styling when on hold
  - `CallAction::SwitchTo { call_id }` for multi-call switching
- `client-types/src/call.rs` - Multi-call state tracking
  - `CallFocus` enum: Active, Held, Ringing
  - Exported from lib.rs for use across crates
- `client-core/src/call_manager.rs` - Multiple held calls support
  - Replace `active_call_id` with `focused_call_id` + `active_calls: Vec<String>`
  - `max_concurrent_calls` configuration (default: 2 for call waiting)
  - `switch_to_call()` - Hold current, resume target call
  - `all_call_ids()` / `all_call_info()` - Accessors for all active calls
  - Auto-hold current call when making/accepting second call
  - `hold_call_by_id()` / `resume_call_by_id()` - Direct call manipulation
  - MOH activation on hold, deactivation on resume
- `client-gui/src/app.rs` - Multi-call UI
  - `all_calls: Vec<CallInfo>` tracking for GUI state
  - `render_call_tabs()` - Tabs showing all active calls
  - Tab colors: green=focused, orange=held
  - Click to switch between calls
  - `SwitchTo` handler calling `switch_to_call()`
- `client-audio/src/file_source.rs` - NEW file for MOH audio
  - `FileAudioSource` for WAV file loading
  - Automatic mono conversion from stereo
  - Linear resampling to target sample rate
  - Continuous looping playback for MOH
  - 8 tests for file source operations
- `client-audio/src/pipeline.rs` - MOH integration
  - `moh_source: Option<FileAudioSource>` field
  - `moh_active: AtomicBool` for hold state
  - `set_moh_active()` / `is_moh_active()` / `has_moh()` accessors
  - `process_moh_frame()` - Send MOH audio instead of microphone
  - MOH loaded during pipeline start if configured
- `client-core/src/audio_session.rs` - MOH control
  - `moh_file_path` in AudioSessionConfig
  - `set_moh_active()` / `is_moh_active()` / `has_moh()` async methods
  - Audio processing loop uses MOH when active instead of capture
- `client-types/src/audio.rs` - MOH configuration
  - `moh_file_path: Option<String>` in AudioConfig (serde-serializable)
  - User-configurable MOH file path

#### Phase 24.24: Audio Ringtone & Auto-Answer

- `client-audio/src/ringtone.rs` - NEW file for ringtone playback
  - `RingtonePlayer` struct for incoming call audio
  - WAV file loading via `FileAudioSource` with resampling
  - Default dual-tone generator (440Hz + 480Hz, standard phone ring)
  - Ring buffer-based audio streaming to output device
  - Configurable ring device (separate from speaker output)
  - `start()` / `stop()` / `process_frame()` for playback control
  - Volume control and device selection
  - 4 tests for ringtone operations
- `client-audio/src/device.rs` - Ring device support
  - `get_output_device_by_name()` for ring device selection
- `client-types/src/audio.rs` - Ringtone configuration
  - `ringtone_file_path: Option<String>` in AudioConfig
- `client-core/src/settings.rs` - Auto-answer settings
  - `auto_answer_enabled: bool` in GeneralSettings
  - `auto_answer_delay_secs: u32` with default of 3 seconds
- `client-gui/src/app.rs` - Ringtone and auto-answer integration
  - `RingtonePlayer` field in SipClientApp
  - `auto_answer_timer: Option<(String, Instant)>` for delayed answer
  - `start_ringtone()` / `stop_ringtone()` / `check_auto_answer()` methods
  - `process_auto_answer()` called in update loop
  - Ringtone starts on IncomingCall event
  - Ringtone stops on Accept/Reject/CallEnded
- `client-gui/src/views/settings.rs` - Ringtone and auto-answer UI
  - "Incoming Calls" section in General settings tab
  - Auto-answer checkbox with delay slider (0-30 seconds)
  - Ring device dropdown
  - Ringtone file browser with WAV filter
  - Ring volume slider (0.0 - 1.0)
  - Supported format info display

#### Phase 24.25: DTMF Support (RFC 4733)

- `client-types/src/dtmf.rs` - NEW file for DTMF types
  - `DtmfDigit` enum representing all DTMF digits (0-9, *, #, A-D)
  - `DtmfEvent` struct with digit, end flag, volume, and duration
  - RFC 4733 event codes (0=digit 0, 10=*, 11=#, 12-15=A-D)
  - `encode()` / `decode()` for 4-byte RFC 4733 payload format
  - `from_char()` / `to_char()` for user input conversion
  - `duration_from_ms()` / `duration_to_ms()` for timestamp conversion
  - 8 tests for DTMF encoding/decoding
- `client-audio/src/rtp_handler.rs` - DTMF RTP transmission
  - `DTMF_PAYLOAD_TYPE` constant (101)
  - `DTMF_CLOCK_RATE` constant (8000 Hz)
  - `send_dtmf()` method in RtpTransmitter
  - Marker bit on first packet of event
  - End bit on final packets (3x for reliability)
  - 1 test for DTMF send
- `client-audio/src/pipeline.rs` - AudioPipeline DTMF support
  - `send_dtmf(digit, duration_ms)` method
  - Full event lifecycle: initial packet, continuation every 20ms, end packets
  - Duration increments with each continuation packet
- `client-core/src/audio_session.rs` - AudioSession DTMF forwarding
  - `send_dtmf()` delegates to pipeline
- `client-core/src/call_manager.rs` - CallManager DTMF API
  - `send_dtmf()` sends on focused call
  - Error handling for no active call
- `client-core/src/app.rs` - ClientApp public DTMF API
  - `send_dtmf(digit)` with default 100ms duration
- `client-gui/src/views/call.rs` - Dialpad UI
  - `CallAction::Dtmf { digit }` variant
  - `show_dialpad` toggle in CallView
  - Keypad toggle button in call controls
  - `render_dialpad()` with phone-style 4x3 grid
  - Click-to-send DTMF digits
- `client-gui/src/app.rs` - DTMF action handling
  - Handle `CallAction::Dtmf` by calling `app.send_dtmf()`
  - Status message shows sent digit

#### Phase 24.26: Audio Device Hot-Switching

- `client-audio/src/pipeline.rs` - Device switching in AudioPipeline
  - `switch_input_device()` - Recreate capture stream with new device
  - `switch_output_device()` - Recreate playback stream with new device
  - `input_device_name()` / `output_device_name()` accessors
  - Seamless switching without stopping RTP transmission
- `client-core/src/audio_session.rs` - AudioSession device switching
  - `switch_input_device()` / `switch_output_device()` methods
  - `input_device_name()` / `output_device_name()` accessors
  - Routes changes to pipeline when session is running
- `client-core/src/call_manager.rs` - CallManager device switching
  - `switch_input_device()` / `switch_output_device()` for active call
  - `current_input_device()` / `current_output_device()` accessors
- `client-core/src/app.rs` - ClientApp public device API
  - `switch_input_device()` / `switch_output_device()` public methods
  - `current_input_device()` / `current_output_device()` accessors
- `client-gui/src/views/call.rs` - Audio device menu in call view
  - `CallAction::SwitchInputDevice` / `CallAction::SwitchOutputDevice` variants
  - `show_audio_menu` toggle (mutually exclusive with dialpad)
  - `render_audio_menu()` with microphone and speaker dropdowns
  - Available devices listed with current selection highlighted
- `client-gui/src/app.rs` - Audio device integration
  - `available_inputs` / `available_outputs` device lists
  - `current_input_device` / `current_output_device` tracking
  - `refresh_audio_devices()` called when entering call view
  - Device switch action handlers with status messages

#### Phase 24.27: Codec Negotiation from SDP

- `client-core/src/call_manager.rs` - SDP codec negotiation
  - `parse_codec_from_sdp()` - Extract negotiated codec from SDP answer
    - Parses m=audio line for first payload type
    - Maps static payload types (0=PCMU, 8=PCMA, 9=G722)
    - Looks up dynamic payload types via rtpmap attributes (e.g., Opus)
  - `negotiated_codecs: HashMap<String, CodecPreference>` - Per-call codec storage
  - `handle_sdp_answer()` - Stores negotiated codec from remote SDP
  - `start_audio_session()` - Uses negotiated codec (falls back to preferred)
  - Cleanup: negotiated codec removed on call termination or hangup
- Unit tests for SDP codec parsing
  - `test_parse_codec_from_sdp_pcmu` - Static payload type 0
  - `test_parse_codec_from_sdp_pcma` - Static payload type 8
  - `test_parse_codec_from_sdp_g722` - Static payload type 9
  - `test_parse_codec_from_sdp_opus` - Dynamic payload type with rtpmap
  - `test_parse_codec_from_sdp_no_audio` - Missing m=audio line

#### Phase 24.28: Call Transfer Support (RFC 3515 REFER)

- `client-sip-ua/src/call_agent.rs` - REFER method implementation
  - `transfer_call()` - Initiates blind call transfer
    - Validates call state (Connected or OnHold only)
    - Returns error for invalid states (Dialing, Ringing, Terminated)
  - `send_refer()` - Builds and sends REFER request
    - Increments CSeq for new transaction
    - Creates `ClientNonInviteTransaction` for REFER
    - Sets call state to `CallState::Transferring`
  - `build_refer_request_static()` - RFC 3515 compliant REFER construction
    - `Refer-To` header with transfer target URI
    - `Referred-By` header with local AOR
    - Standard dialog headers (Call-ID, From, To, Via, CSeq)
    - Contact header for responses
- `client-core/src/call_manager.rs` - Transfer coordination
  - `transfer_call()` - Transfer focused call to target URI
  - `transfer_call_by_id()` - Transfer specific call by ID
  - Error handling for no active call scenario
- `client-core/src/app.rs` - Transfer API
  - `transfer_call()` - Public API for ClientApp
- `client-gui/src/views/call.rs` - Transfer UI
  - `CallAction::Transfer { target_uri }` - Transfer action variant
  - `show_transfer_dialog` / `transfer_target` state fields
  - Transfer button in call controls (arrows icon)
  - Modal transfer dialog with SIP URI input
  - Enter key support for quick submission
- `client-gui/src/app.rs` - Transfer action handler
  - Routes `CallAction::Transfer` to `ClientApp::transfer_call()`
  - Status messages for success/failure

#### Phase 24.29: NOTIFY Handling for REFER (RFC 3515)

- `client-sip-ua/src/call_agent.rs` - NOTIFY processing
  - `handle_notify()` - Process incoming NOTIFY for REFER subscriptions
    - Event header validation (Event: refer)
    - Subscription-State header parsing for final status detection
    - Automatic 200 OK response generation via `build_200_ok_for_notify()`
  - `parse_sipfrag()` - Extract SIP status code from NOTIFY body
    - Format: "SIP/2.0 {status-code} {reason-phrase}"
    - Maps to `ReferStatus` (Trying, Ringing, Success, Failed)
  - `ReferRequest` tracking in `CallSession`
    - Tracks implicit subscription state
    - Updates status from NOTIFY messages
  - `CallEvent::TransferProgress` - New event variant
    - call_id, target_uri, status, is_final fields
- `client-sip-ua/src/lib.rs` - Re-exports
  - `ReferStatus` re-exported for public access
- `client-core/src/call_manager.rs` - Transfer progress handling
  - `CallManagerEvent::TransferProgress` - New event variant
  - `handle_transfer_progress()` - Forward status to app layer
- `client-core/src/app.rs` - Application event handling
  - `AppEvent::TransferProgress` - New event variant
  - Routes `CallEvent::TransferProgress` to CallManager
  - Routes `CallManagerEvent::TransferProgress` to GUI
- `client-gui/src/app.rs` - GUI progress display
  - `AppEvent::TransferProgress` handler
  - Real-time status messages ("Trying...", "Ringing...", etc.)
  - Final result message on transfer completion

#### Phase 24.30: PIN Handling & Smart Card Signing

- `client-core/src/cert_store.rs` - Smart card signing support
  - `SignatureAlgorithm` enum - EcdsaSha384, EcdsaSha256, RsaSha384, RsaSha256
  - `sign_data()` - Sign data with certificate private key
    - Uses CryptAcquireCertificatePrivateKey to acquire NCrypt key handle
    - Signs via NCryptSignHash (Windows CryptoNG)
    - Supports ECDSA (no padding) and RSA (PKCS#1 padding)
    - Maps Windows error codes: NTE_USER_CANCELLED, SCARD_W_WRONG_CHV, etc.
  - `verify_pin()` - Verify smart card PIN without signing
    - Acquires key handle with CRYPT_ACQUIRE_SILENT_FLAG
    - Sets PIN via NCryptSetProperty with "SmartCardPin" property
    - Returns PinIncorrect, SmartCardNotPresent, or success
  - Non-Windows stub implementations
    - Deterministic fake signatures based on algorithm type
    - PIN validation accepts 4+ digit PINs for testing
- `client-core/src/lib.rs` - Public exports
  - `SignatureAlgorithm` exported for external use
- `client-gui/src/app.rs` - PIN dialog integration
  - `use_certificate_with_pin()` verifies PIN before configuring certificate
  - Handles CertStoreError::PinIncorrect with retry UI
  - Handles CertStoreError::SmartCardNotPresent with insertion prompt
  - PIN attempt tracking with lockout warning at 3 attempts
- 6 new tests for signing and PIN verification

#### Phase 24.31: Settings Persistence

- `client-gui/src/views/settings.rs` - Settings view data flow
  - `SettingsAction::Discard` variant - Trigger settings reload
  - `load_from_settings()` - Load Settings struct into view fields
    - Maps General, Audio, Network, UI settings to view state
    - Clears dirty flag after loading
  - `collect_settings()` - Collect view state into settings components
    - Returns (GeneralSettings, AudioConfig, NetworkSettings, UiSettings)
    - Maps view fields back to settings structs
  - `is_dirty()` / `clear_dirty()` - Dirty state management
- `client-gui/src/app.rs` - Save/Discard implementation
  - `SettingsManager` added to SipClientApp struct
  - Settings loaded from disk on startup via load_from_settings()
  - `save_settings()` - Persist settings to TOML file
    - Collects settings from view
    - Updates SettingsManager and saves atomically
    - Syncs with ClientApp if available
    - Shows status message on success/failure
  - `discard_settings()` - Reload settings from disk
    - Reloads from SettingsManager into view
    - Shows "Changes discarded" status
  - Exit prompt for unsaved changes
    - Intercepts close via ViewportCommand::CancelClose
    - Shows confirmation dialog with Save/Discard/Cancel
    - Also handles tray exit with dirty settings

#### Phase 24.32: Account Registration UI

- `client-gui/src/views/settings.rs` - Registration UI improvements
  - `registration_in_progress` field - Track registration state
  - `set_registration_in_progress()` - Toggle spinner visibility
  - `build_account()` - Create SipAccount from view fields
    - Validates required fields (SIP URI, Registrar)
    - Returns None if validation fails
  - Register button disabled when fields empty
  - Spinner shown during registration
- `client-gui/src/app.rs` - Registration handlers
  - `register_account()` - Initiate SIP registration
    - Builds SipAccount from view state
    - Calls ClientApp::register_account()
    - Shows error dialog on failure
  - `unregister_account()` - Initiate SIP unregistration
    - Calls ClientApp::unregister()
    - Error handling with status messages
  - `AppEvent::RegistrationStateChanged` handler updated
    - Clears registration spinner on final state
    - Handles Registered, Unregistered, and Failed states

#### Phase 24.33: Contact Management UI

- `client-gui/src/views/contacts.rs` - Contact CRUD dialogs
  - `ContactsAction` enum expanded with Add, ToggleFavorite, SaveContact, ConfirmDelete
  - `ContactDialogMode` enum for Add vs Edit modes
  - `open_add_dialog()` - Initialize empty dialog for new contact
  - `open_edit_dialog()` - Pre-populate fields from existing contact
  - `open_delete_dialog()` - Set up deletion confirmation
  - `render_contact_dialog()` - Modal with name, SIP URI, organization, notes, favorite
    - Validation: Name required, SIP URI must start with sip: or sips:
    - Cancel/Save buttons with visual feedback
  - `render_delete_dialog()` - Confirmation with contact name display
    - Warning message about irreversible action
    - Cancel/Delete buttons (Delete in red)
  - Favorite toggle button on contact row
  - Context menu with Call, Edit, Add/Remove Favorites, Delete options
  - `set_contacts()` - Load contacts from iterator with sorting
- `client-gui/src/app.rs` - Contact management integration
  - Added `ContactManager` field for persistence
  - Initialize ContactManager on startup, load contacts into view
  - `handle_contacts_action()` handlers for all actions:
    - `Add` - Opens add dialog
    - `Edit` - Loads contact into edit dialog
    - `Delete` - Opens delete confirmation
    - `ToggleFavorite` - Toggles and persists favorite status
    - `SaveContact` - Saves to ContactManager, refreshes view
    - `ConfirmDelete` - Removes from ContactManager, refreshes view
  - Auto-save contacts on all modifications

#### Phase 24.34: Server Certificate Verification

- `client-core/src/sip_transport.rs` - Certificate loading utilities
  - `load_certs_from_pem_file()` - Load CA certificates from PEM or DER files
  - `parse_pem_certificates()` - Parse PEM-encoded certificates with base64 decoding
  - Support for both PEM (.pem, .crt) and DER (.der, .cer) formats
  - Validation of loaded certificates
- `client-gui/src/app.rs` - Verification mode integration
  - `set_verification_mode()` rewritten to apply to SipTransport
    - Convert `ServerCertVerificationMode` → `CertVerificationMode`
    - Load certificates from file for Custom mode
    - Call `ClientApp::set_verification_mode()` to apply
    - Update UI cert count on success/failure
  - `browse_for_ca_file()` implemented with rfd
    - Native file dialog with certificate file filters
    - Validate certificate file before applying
    - Show error dialog if invalid
- `client-gui/src/views/settings.rs` - Certificate info display
  - Added `custom_ca_cert_count` field
  - Display "N certificate(s) loaded" in green when Custom mode active
  - `set_custom_ca_cert_count()` method for updating UI

**Dependencies Added (client-core)**

- `base64` 0.22: PEM certificate decoding

#### Phase 24.35: Platform-Specific UI Architecture

- Renamed `client-gui` to `client-gui-windows`
  - Crate is now explicitly Windows-only via `#![cfg(target_os = "windows")]`
  - Binary renamed from `sip-softclient` to `sip-softclient-windows`
  - Removed `[target.'cfg(windows)'.dependencies]` - `winrt-notification` now unconditional
  - Removed cross-platform fallback code from `notifications.rs`
- Platform-specific UI architecture established
  - `client-gui-windows`: Windows desktop (egui/eframe with winrt-notification)
  - `client-gui-macos`: macOS desktop (planned)
  - `client-gui-linux`: Linux desktop (planned)
  - `client-gui-android`: Android mobile (planned)
  - `client-gui-ios`: iOS mobile (planned)
- Shared crates remain cross-platform
  - `client-types`: Data types and models
  - `client-core`: Application logic, SIP transport, contact management
  - `client-sip-ua`: SIP user agent protocol
  - `client-audio`: Audio pipeline (requires platform audio backend)

#### Phase 24.36: Windows UI Optimization

- `client-gui-windows/src/style.rs` - New centralized styling module
  - Color constants: `COLOR_PRIMARY`, `COLOR_DANGER`, `COLOR_WARNING`, etc.
  - Call state colors: `COLOR_CALL_CONNECTED`, `COLOR_CALL_HOLD`, etc.
  - Registration status colors: `COLOR_REG_REGISTERED`, `COLOR_REG_FAILED`, etc.
  - Certificate quality colors for CNSA 2.0 compliance indicators
  - Base size constants for buttons, spacing, fonts
  - `UiScale` struct for DPI-aware responsive scaling
  - Styled text helpers: `heading()`, `body()`, `secondary()`, `display()`, etc.
  - Button helpers: `primary_button()`, `danger_button()`, `warning_button()`
  - `apply_dark_theme()` for consistent theme application
  - Keyboard shortcut constants in `style::keys` module
- `client-gui-windows/src/views/dialer.rs` - Updated with new style system
  - Uses `UiScale` for DPI-aware button and spacing sizes
  - Uses `style::dialpad_text()` and `style::primary_button()` helpers
  - Added `set_default_domain()` to fix hardcoded domain issue
  - Keyboard shortcut hint displayed
  - Alt+C shortcut support for calling
- `client-gui-windows/src/app.rs` - Keyboard shortcuts and styling
  - Added `handle_keyboard_shortcuts()` method for global shortcuts
  - Navigation: Alt+D (Dialer), Alt+K (Contacts), Alt+S (Settings)
  - Call controls: Alt+H/Escape (Hangup), Alt+M (Mute), Alt+O (Hold)
  - Incoming calls: Alt+A (Accept), Alt+R (Reject)
  - Settings: Ctrl+S (Save), F5 (Refresh certificates)
  - Navigation bar updated to use style module colors
  - Status bar updated with style module colors
  - Uses `style::apply_dark_theme()` for initialization
  - Hover text hints for keyboard shortcuts on buttons

**Security**

- Smart card authentication ONLY (CAC/PIV/SIPR token)
- NO password-based digest authentication
- Mutual TLS with client certificates from Windows Certificate Store
- TLS 1.3 only for signaling (CNSA 2.0 compliance)

**Dependencies Added**

- `hound` 3.5: WAV file reading for Music on Hold
- `cpal` 0.17: Cross-platform audio I/O
- `ringbuf` 0.4: Lock-free ring buffers for audio threads
- `egui` 0.33: Immediate mode GUI
- `eframe` 0.33: egui framework with wgpu backend
- `directories` 6: Platform-specific config paths
- `tray-icon` 0.21: System tray integration
- `rfd` 0.17: Native file dialogs
- `winrt-notification` 0.5: Windows toast notifications
- `windows` 0.62: Windows CryptoAPI for smart card access
- `uuid` 1.16: UUID generation for call IDs

#### CDR Export Endpoints

**uc-api - CDR Export Routes (NIST 800-53: AU-2, AU-3, AU-9)**

- New CDR management routes (`/api/v1/cdrs/*`):
  - `GET /` - List CDRs with pagination and filtering
  - `GET /:id` - Get specific CDR by call ID
  - `GET /export` - Bulk export CDRs in JSON or CSV format
  - `GET /stats` - Get CDR statistics and summary metrics
  - `GET /search` - Search CDRs by caller, callee, or criteria
  - `GET /correlation/:correlation_id` - Get related calls by correlation ID
  - `DELETE /purge` - Purge CDRs older than specified date

- CDR API types (`cdr.rs`):
  - `CdrQueryParams` with filtering: time range, caller, callee, status, trunk, direction, duration, IPs
  - `CdrExportFormat` enum: Json, Csv with content type and extension helpers
  - `CdrExportRequest` with filters, format, header inclusion, field selection, limit
  - `CdrStats` with totals, ASR, failure rate, calls by status/cause/trunk
  - `CdrSearchResult` for search response items
  - `CdrPurgeRequest` / `CdrPurgeResponse` for maintenance operations
  - Query parameter parsing from HTTP query strings

- Permissions: `cdr:read`, `cdr:export`, `cdr:admin`
- `SbcRoutes::cdrs()` added to `SbcRoutes::all()` aggregate

**Tests**: 11 new tests for CDR routes and types

#### DNS Integration

**uc-dns - DNS Resolution for SIP (New Crate)**

- New crate for DNS-based SIP routing:
  - `SipResolver` implementing RFC 3263 NAPTR → SRV → A/AAAA resolution chain
  - `SipTarget` with address, transport, hostname, priority, weight
  - `TransportPreference` enum: Any, Udp, Tcp, Tls, Sctp, WebSocket, WebSocketSecure
  - Support for numeric IP addresses (bypass DNS)
  - Cache-aware resolution with configurable TTL

- `SrvResolver` for SRV record handling (RFC 2782):
  - `SrvRecord` with priority, weight, port, target, addresses
  - Weighted selection algorithm per RFC 2782
  - `sip_srv_name()` for constructing SRV query names
  - SRV record parsing from DNS response strings

- `NaptrResolver` for NAPTR record handling (RFC 3403):
  - `NaptrRecord` with order, preference, flags, service, regexp, replacement
  - `NaptrService` enum: SipUdp, SipTcp, SipsTcp, SipSctp, SipWs, SipsWs
  - Transport selection from NAPTR service field
  - NAPTR record parsing from DNS response strings

- `EnumResolver` for ENUM lookup (RFC 6116):
  - E.164 number to ENUM domain conversion
  - `EnumResult` with number, URI, service, order, preference
  - NAPTR regexp application for URI derivation
  - Multi-domain support (e164.arpa, e164.org)

- `DnsCache` for TTL-based caching:
  - `CachedRecord<T>` with TTL tracking, expiration, age
  - `CacheEntry` enum: Address, Srv, Naptr, Enum, Negative
  - Configurable min/max TTL bounds
  - Negative cache for NXDOMAIN responses
  - LRU-style eviction when at capacity
  - `CacheStats` for utilization monitoring

- Configuration structures:
  - `DnsConfig` with server addresses, timeout, retries, cache settings
  - `SipResolverConfig` with transport preferences, NAPTR/SRV flags
  - `EnumConfig` with domain suffixes, preferred services
  - `TransportPref` with `naptr_service()` and `srv_prefix()` methods
  - `DefaultPorts` for transport-specific default ports

- Hickory-resolver integration (optional `resolver` feature):
  - `HickoryDnsResolver` for actual DNS queries using hickory-resolver 0.25
  - A/AAAA lookup with `lookup_addresses()`
  - SRV lookup with `lookup_srv()` and `lookup_sip_srv()`
  - NAPTR lookup with `lookup_naptr()`
  - Combined SRV + address resolution with `lookup_srv_with_addresses()`
  - Integration with `SipResolver` for full RFC 3263 resolution
  - TTL-based caching with hickory responses
  - IP passthrough for numeric addresses

**Tests**: 46 tests for DNS crate (38 base + 8 hickory integration)

#### Phase 23: Specialized Protocols

**uc-t38 - T.38 Fax Relay (RFC 4612)**

- New crate for T.38 real-time fax relay:
  - `UdptlTransport` for UDP Transport Layer with error correction
  - `UdptlPacket` encode/decode with redundancy and FEC support
  - `ErrorCorrectionMode` enum: None, Redundancy, Fec
  - `IfpPacket` per ITU-T T.38 with 16 data types
  - `T30Indication` for fax signal indications (CNG, CED, training, etc.)
  - `DataType` enum with V.21, V.27ter, V.29, V.17, V.34 support
  - `SignalDetector` with Goertzel algorithm for CNG/CED tone detection
  - `T30Signal` enum with 22 T.30 signal types
  - `FaxPhase` enum: PhaseA through PhaseE
  - `T38Session` with full state machine and session statistics
  - `T38SessionManager` for multi-session management
  - `T38Config` with UDPTL, session, and error correction settings
  - Auto-switch from audio to T.38 on CNG/CED detection

**uc-transport - SCTP Transport (RFC 4168)**

- New feature `sctp` for SCTP transport support:
  - `SctpAssociation` implementing `Transport` and `StreamTransport` traits
  - `SctpState` enum: Closed, CookieWait, CookieEchoed, Established, ShutdownPending, ShutdownSent, ShutdownAckSent
  - `SctpConfig` with full SCTP parameters (streams, retransmissions, heartbeat, RTO, MTU)
  - `StreamId` for multi-stream support
  - Multi-homing with `add_peer_address()` and `set_primary_path()`
  - `SctpListener` for accepting incoming associations (stub)

**uc-types - Transport Type Extension**

- Added `TransportType::Sctp` variant for SCTP transport

**Tests**: 25 new tests for T.38 crate

#### Phase 20: WebRTC & Modern Transports

**uc-transport - WebSocket Transport (RFC 7118)**

- New WebSocket transport module (`websocket.rs`):
  - `WebSocketTransport` implementing `Transport` and `StreamTransport` traits
  - `WebSocketListener` for accepting incoming connections
  - `WebSocketState` enum: Connecting, Open, Closing, Closed
  - SIP-over-WebSocket framing (text frames for SIP messages)
  - Binary frame support for SDP bodies
  - Ping/pong keepalive handling
  - Secure WebSocket (WSS) support with TLS
  - `SIP_SUBPROTOCOL` constant ("sip") per RFC 7118
- New feature flag `websocket` with dependencies:
  - `tokio-tungstenite` for WebSocket protocol
  - `futures-util` for stream combinators

**uc-webrtc - WebRTC Gateway (New Crate)**

- New crate for SIP-to-WebRTC interworking:
  - `WebRtcGateway` for SIP-to-WebRTC call bridging
  - `GatewayResponse` with session ID, SDP, ICE credentials, DTLS fingerprint
  - `GatewayStats` for monitoring (sessions created/completed/failed, active sessions)
  - Session creation from SIP calls
  - Bidirectional SDP processing (SIP-to-WebRTC, WebRTC-to-SIP)
  - ICE candidate handling for remote candidates

- `WebRtcSession` session management:
  - `WebRtcSessionState` enum: New, HaveLocalDescription, HaveRemoteDescription, Connecting, DtlsHandshaking, Connected, Disconnected, Failed, Closed
  - Local and remote SDP storage
  - ICE candidate tracking (local and remote)
  - ICE credentials (ufrag, pwd) management
  - DTLS fingerprint storage
  - SIP Call-ID association
  - Session age and idle time tracking
  - `SessionManager` for multi-session management with configurable limits

- `SdpMunger` for SDP transformation:
  - `WebRtcSdpMode` enum: SipToWebRtc, WebRtcToSip
  - RTP-to-SRTP profile conversion (RTP/AVP to RTP/SAVPF)
  - ICE credential extraction from SDP
  - DTLS fingerprint extraction
  - Configurable SDP transformation rules

- `TrickleIce` for ICE candidate trickling (RFC 8838):
  - `TrickleCandidate` with candidate string, m-line index, mid, ufrag
  - `TrickleState` enum: Idle, Gathering, Receiving, Complete
  - Local and remote candidate management
  - Broadcast channel for new candidate notifications
  - End-of-candidates indicator support
  - `TrickleManager` for multi-session trickle ICE handling

- Configuration structures:
  - `WebRtcConfig` with enabled flag and sub-configs
  - `IceConfig` for ICE parameters (STUN servers, trickle, lite mode)
  - `DtlsConfig` for DTLS parameters (fingerprint algorithm, role)
  - `SessionConfig` for session limits (max sessions, idle timeout)
  - `SdpConfig` for SDP transformation options

**Tests**: 24 new tests across WebRTC components

#### Phase 22: High Availability & Clustering

**uc-cluster - Core Clustering Primitives**

- New crate for cluster management:
  - `NodeId`, `NodeRole` (Primary/Secondary/Witness), `NodeState` types
  - `ClusterNode` with endpoints, health score, zone/region awareness
  - `ClusterMembership` manager with add/remove/get node operations
  - `QuorumPolicy` enum: Majority, All, Count, Weighted
  - `HealthChecker` with heartbeat tracking and suspect/dead thresholds
  - `HealthStatus` enum: Healthy, Suspect, Dead
  - `FailoverCoordinator` with automatic and manual failover
  - `SessionTakeoverHandler` trait for session migration
  - `FailoverPhase` enum for failover state tracking
  - `TakeoverResult` with transfer statistics
  - Failover strategies: PreferSameZone, PreferSameRegion, LeastLoaded, Priority

**uc-discovery - Service Discovery**

- New crate for peer discovery:
  - `DiscoveryProvider` trait with async discover method
  - `StaticDiscovery` for configured peer lists
  - `DnsDiscovery` stub for DNS SRV/A lookup (feature-gated)
  - `KubernetesDiscovery` stub for K8s API (feature-gated)
  - `GossipProtocol` for SWIM-style failure detection
  - `MemberStatus` enum: Alive, Suspect, Dead
  - `GossipMessage` variants: Ping, Ack, PingReq, Membership

**uc-storage - Storage Backends**

- New crate for pluggable storage:
  - `StorageBackend` trait with get/set/delete/keys/increment
  - `InMemoryBackend` with TTL support and glob-style pattern matching
  - `RedisBackend` stub (feature-gated)
  - `PostgresBackend` stub (feature-gated)
  - `StorageManager` with health checking

**uc-state-sync - State Replication Engine**

- New crate for distributed state:
  - CRDT implementations: `GCounter`, `PNCounter`, `LWWRegister`
  - `Replicable` trait for state that can be replicated
  - `StateReplicator` with configurable replication modes
  - `ReplicationMode` enum: Sync, Async, SemiSync
  - `ReplicationMessage` protocol for wire format
  - `StateSnapshot` for bulk state transfer
  - `SnapshotWriter` and `SnapshotReader` for chunked transfers
  - `EntryType` enum: KeyValue, Registration, CallState, Crdt, Config

**uc-aaa - AAA Integration**

- New crate for authentication/authorization/accounting:
  - `AaaProvider` trait with authenticate/authorize/accounting methods
  - `RadiusClient` for RADIUS server communication (using `radius-proto` from usg-radius)
    - Async UDP transport with configurable timeout and retries
    - Server failover support (primary/secondary)
    - Message-Authenticator HMAC-MD5 for request integrity
    - Full accounting support (Start, Stop, Interim)
    - RFC 2865 (Authentication) and RFC 2866 (Accounting) compliant
  - `DiameterClient` for 3GPP Cx/Dx interface (IMS authentication)
    - RFC 6733 Diameter base protocol support
    - Capabilities Exchange (CER/CEA) for session establishment
    - User-Authorization-Request (UAR) for IMS registration
    - Multimedia-Auth-Request (MAR) for authentication vectors
    - Server-Assignment-Request (SAR) for user data
    - TCP transport with async I/O
  - `AuthRequest` and `AuthResponse` types
  - `AccountingRecord` for CDR-style accounting
  - `AccountingType` enum: Start, Stop, Interim
  - Feature flags: `radius` (uses radius-proto), `diameter` (uses diameter crate)

**uc-transport - Pure Rust SCTP Implementation (RFC 9260)**

- Full SCTP protocol implementation for SIP signaling (RFC 4168):
  - `sctp/chunk.rs` (~1900 lines) - All RFC 9260 chunk types:
    - DATA, INIT, INIT-ACK, SACK, HEARTBEAT, HEARTBEAT-ACK
    - ABORT, SHUTDOWN, SHUTDOWN-ACK, ERROR, COOKIE-ECHO, COOKIE-ACK
    - SHUTDOWN-COMPLETE with proper encoding/decoding
    - `InitParam` enum for INIT parameters (IPv4/IPv6, cookie, etc.)
    - `ErrorCause` enum for all error cause codes
    - 4-byte padding per RFC specification
  - `sctp/packet.rs` (~300 lines) - Packet structure:
    - SCTP common header with CRC32c checksum (using `crc32c` crate)
    - Chunk bundling validation per RFC 9260 Section 6.10
    - Encode/decode with checksum verification
  - `sctp/state.rs` (~730 lines) - State machine:
    - Full RFC 9260 Section 4 state machine
    - 8 states: CLOSED, COOKIE-WAIT, COOKIE-ECHOED, ESTABLISHED, shutdown states
    - 16 event types (application, received chunks, timers)
    - 20 action types (send chunks, timers, notifications)
  - `sctp/mod.rs` - Public API:
    - `SctpConfig` with full SCTP parameters
    - `StreamId` for stream identification (stream 0 for SIP signaling)
    - `SctpAssociation` implementing `Transport` and `StreamTransport` traits
    - `SctpListener` for server-side listening
    - Multi-homing support (add_peer_address, set_primary_path)
  - `sctp/association.rs` - Data transfer and reliability:
    - `RetransmitEntry` for tracking sent chunks with timestamps
    - `add_to_retransmit_queue()` method for DATA queuing
    - `process_gap_ack_blocks()` for selective acknowledgment
    - `update_miss_indications()` for fast retransmit detection (3+ misses)
    - T3-rtx timer integration for retransmission triggering
    - Flow control enforcement (peer rwnd and cwnd checks)
    - `FragmentBuffer` for multi-fragment message reassembly
    - B/E flag handling for fragmented DATA chunks
    - Path MTU-based fragmentation on send
  - `sctp/connected.rs` - Real socket I/O:
    - 100ms timer check interval in background loop
    - T3-rtx expiration triggers retransmissions
    - Heartbeat timer sends HEARTBEAT chunks with RTT timestamps
    - Fast retransmit chunks sent on each timer tick
    - UDP encapsulation for NAT traversal (RFC 6951):
      - `use_udp_encapsulation` and `udp_encap_config` in ConnectedSctpConfig
      - Builder methods: `with_udp_encapsulation()`, `with_udp_encap_ports()`
      - `encode_packet()` and `decode_packet()` with automatic encapsulation
      - `is_udp_encapsulated()` accessor
      - 8-byte overhead per packet for UDP header
  - `sctp/timer.rs` - Timer enhancements:
    - Heartbeat timer support with RTT calculation
  - `sctp/chunk.rs` - ECN support (RFC 9260 §3.3.11-12):
    - `EcneChunk` for Explicit Congestion Notification Echo
    - `CwrChunk` for Congestion Window Reduced
    - Both contain lowest_tsn field in 8-byte format
    - Full encode/decode support in Chunk enum
  - Cryptographically secure random via `rand` crate
  - `SctpAssociation` stub deprecated in favor of `ConnectedSctpAssociation`
  - Feature flag: `sctp` (optional, requires `crc32c`, `rand`)
  - 43+ unit tests

**uc-snmp - SNMP Trap Generation**

- New crate for SNMP monitoring:
  - `TrapSender` for SNMPv2c trap generation
  - `SnmpTrap` struct with OID, values, and timestamp
  - `TrapType` enum with 14 trap types:
    - NodeUp, NodeDown, NodeDegraded
    - CallStart, CallEnd, CallFailed
    - RegistrationAdded, RegistrationRemoved, RegistrationExpired
    - QuorumLost, QuorumRestored
    - HighCpuUsage, HighMemoryUsage
    - CertificateExpiring

**uc-syslog - Syslog Forwarding**

- New crate for log forwarding:
  - `SyslogForwarder` with UDP and TCP transport
  - `SyslogMessage` with RFC 5424 and BSD format support
  - `Severity` enum: Emergency through Debug
  - `Facility` enum: Kern, User, Mail, Daemon, Auth, Syslog, etc.
  - Automatic hostname and process ID detection

**sbc-config - Configuration Integration**

- Feature flags for optional clustering components:
  - `cluster` feature enables uc-cluster, uc-discovery, uc-storage, uc-state-sync
  - `aaa` feature enables uc-aaa
  - `snmp` feature enables uc-snmp
  - `syslog` feature enables uc-syslog
  - `full` feature enables all optional features
- `MonitoringConfig` struct with metrics endpoint and per-call metrics options
- Re-exports for cluster config types when features enabled

**uc-api - Cluster API Endpoints**

- New cluster management routes (`/api/v1/cluster/*`):
  - `GET /status` - Cluster status and quorum information
  - `GET /members` - List all cluster members
  - `GET /members/:id` - Get specific member details
  - `POST /failover` - Initiate automatic failover
  - `POST /failover/manual` - Manual failover to specific target
  - `POST /drain` - Drain sessions for maintenance
  - `POST /rejoin` - Rejoin cluster after maintenance
  - `GET /state/sync-status` - State synchronization status
  - `POST /state/force-sync` - Force state synchronization
  - `GET /state/snapshot` - Get current state snapshot
  - `POST /state/snapshot/restore` - Restore from snapshot
- `SbcRoutes::all()` method combining all route groups

#### P0 Critical RFC Compliance Gaps

**proto-dtls (RFC 6347 §4.2.4, §4.2.6)**

- DTLS certificate verification (`verify.rs`):
  - `DtlsCertificateVerifier` with RFC 6347 §4.2.4 compliant verification
  - `CertificateChainValidator` for X.509 chain validation
  - `verify_certificate_chain()` with trusted CA store
  - `verify_self_signed()` for fingerprint-based WebRTC validation
  - `VerificationMode` enum: FullChain, FingerprintOnly, SelfSignedAllowed
  - `CertificateInfo` extraction (subject, issuer, validity, fingerprint)
  - CNSA 2.0 compliant: SHA-384 fingerprints, P-384/P-521 curves only

- DTLS Finished message validation:
  - `verify_finished_message()` per RFC 6347 §4.2.6
  - PRF-based verify_data computation with HMAC-SHA384
  - Handshake transcript hashing for verification
  - `FinishedMessageError` variants for specific failure modes

**proto-ice (RFC 7675 §6)**

- ICE consent revocation (`consent.rs`):
  - `revoke_consent()` for explicit consent withdrawal per RFC 7675 §6
  - `ConsentState::Revoked` for distinguishing revocation from expiration
  - `ConsentRevocationReason` enum: UserInitiated, SecurityConcern, SessionTerminating, MediaTimeout, PolicyViolation
  - `is_revoked()` and `revocation_reason()` accessors
  - Revoked state immediately stops all media transmission

**proto-turn (RFC 5766 §9, §12)**

- TURN Send/Data indications (`indication.rs`):
  - `SendIndication` struct per RFC 5766 §9
  - `DataIndication` struct per RFC 5766 §12
  - XOR-PEER-ADDRESS and DATA attribute handling
  - `encode()` methods for wire format generation
  - Indication class (0x10) message type handling

**proto-sip (RFC 3261 §13.2.2.4)**

- SIP redirect handling (`redirect.rs`):
  - `RedirectHandler` for 3xx response processing
  - `RedirectContact` with q-value priority parsing
  - `RedirectResult` enum: Redirect, TooManyRedirects, Failure, NoAlternatives
  - `process_redirect_response()` for 300-305 handling
  - `select_next_target()` with priority-based selection
  - Loop detection via visited URI tracking
  - Configurable max_redirects limit

#### P1 High Priority RFC Compliance Gaps

**proto-registrar (RFC 5626 §5.2)**

- SIP Outbound flow maintenance (`outbound.rs`):
  - `FlowTransport` enum: Udp, Tcp, Tls, WebSocket, WebSocketSecure
  - `FlowState` enum: Active, Probing, Suspect, Failed, Recovering
  - `FlowId` and `FlowToken` types for flow identification
  - `Flow` struct with keepalive tracking and health monitoring
  - `OutboundFlowManager` for multi-flow management
  - `FlowAction` enum for keepalive actions (STUN, CRLF, WebSocket ping)
  - Transport-specific keepalive selection per RFC 5626
  - Configurable intervals and failure thresholds

**proto-ice (RFC 8445 §7.2.2)**

- ICE aggressive nomination support:
  - `IceConfig.aggressive_nomination` flag (was already present)
  - `IceAgent::aggressive_nomination()` accessor
  - `IceAgent::should_nominate_check()` - determines USE-CANDIDATE inclusion
  - `IceAgent::create_connectivity_check()` - auto-applies nomination strategy
  - `IceAgent::create_connectivity_check_with_nomination()` - explicit control
  - Controlling agent only: controlled agents cannot nominate
  - Exported `IceConfig` from lib.rs

**proto-sdp (RFC 3264 §8.4)**

- SDP offer/answer media modification rules (`offer_answer.rs`):
  - `MediaModificationValidator` for RFC 3264 compliance validation
  - `MediaModification` and `MediaModificationType` for change description
  - `generate_answer()` - creates answer from offer with capability matching
  - `validate_answer()` - validates answer against offer
  - `compute_answer_direction()` - direction negotiation per §6.1
  - `hold_media_stream()` / `resume_media_stream()` - call hold support
  - `disable_media_stream()` / `enable_media_stream()` - port=0 handling
  - `LocalCapabilities` and `LocalMediaCapability` for endpoint configuration
  - `NegotiationResult` and `MediaNegotiationResult` for validation results
  - `HoldType` enum: SendOnly, Inactive

**proto-stun (RFC 5389 §10.2)**

- STUN long-term credential mechanism (`credential.rs`):
  - `LongTermCredentials` for client-side authentication
  - `LongTermCredentialValidator` for server-side validation
  - `AuthResult` enum: Success, ChallengeRequired, Failed, StaleNonce
  - `update_from_challenge()` for 401 response handling
  - `compute_key()` using SHA-384 (CNSA 2.0 compliant deviation from MD5)
  - `generate_nonce()` with HMAC-SHA384 signatures and timestamps
  - `validate_nonce()` with expiration checking
  - `create_challenge_response()` for 401 generation
  - `create_stale_nonce_response()` for 438 generation
  - Configurable nonce lifetime (default 10 minutes per RFC 5389)

#### Phase 19: SIP Authentication & Security

**proto-registrar (RFC 3261 §22)**

- SIP Digest authentication (`authentication.rs`):
  - `Authenticator` struct with nonce generation/validation
  - `NonceState` with expiration tracking and nonce count validation
  - `AuthChallenge` for 401/407 response generation
  - `AuthCredentials` with full digest auth parameter parsing
  - `AuthResult` enum: Success, ChallengeRequired, StaleNonce, Failed
  - `AuthAlgorithm` enum: MD5, SHA256, SHA512_256
  - `AuthQop` enum: Auth, AuthInt (integrity protection)
  - `AuthenticatedRegistrar` combining Registrar + Authenticator
  - Password lookup callback pattern for credential retrieval
  - Nonce count (nc) tracking for replay attack prevention
  - Stale nonce detection and renewal with opaque parameter

**proto-sip (RFC 3323/RFC 5765)**

- Topology hiding (`topology.rs`):
  - `TopologyHider` for SIP message anonymization
  - `TopologyHidingConfig` with external host and mode settings
  - `TopologyHidingMode` enum: None, Basic, Aggressive
  - Via header stripping for internal network addresses
  - `anonymize_via()` with received/rport parameter hiding
  - Contact header anonymization with external URI substitution
  - Record-Route rewriting with anonymized record routes
  - Call-ID obfuscation with bidirectional mapping
  - `obfuscate_call_id()` / `restore_call_id()` for symmetric operation
  - Internal network detection via configurable prefixes (RFC 1918)
  - `hide_outbound_request()` and `hide_inbound_response()` convenience methods

**proto-sdp (RFC 4568)**

- SRTP-SDES key exchange (`srtp.rs`):
  - `CryptoAttribute` parsing per RFC 4568 format
  - `CipherSuite` enum: AES_CM_128_HMAC_SHA1_80/32, F8_128_HMAC_SHA1_80, AEAD_AES_128/256_GCM
  - `KeyParams` with base64 keying material, lifetime, MKI support
  - `master_key()` and `master_salt()` extraction per cipher suite
  - `SessionParams` for KDR, UNENCRYPTED_SRTP/SRTCP, FEC options
  - `FecOrder` enum: FecSrtp, SrtpFec
  - `SrtpNegotiator` for cipher suite selection with preferences
  - `extract_crypto_attributes()` for SDP parsing
  - `supports_sdes()` and `uses_dtls_srtp()` protocol detection helpers
  - `generate_keying_material()` for SRTP key generation

#### P3 Low Priority RFC Compliance Gaps

**proto-sdp (RFC 3264 §6.2)**

- Multicast stream negotiation (`multicast.rs`):
  - `MulticastAddress` struct with IPv4/IPv6 scope detection
  - `MulticastNegotiator` for offer/answer multicast validation
  - `MulticastScope` enum: NodeLocal, LinkLocal, RealmLocal, AdminLocal, SiteLocal, Organization, Global
  - `MulticastValidation` struct with TTL and scope validation results
  - `is_multicast_address()` for detecting multicast addresses
  - `is_multicast_media()` for checking if media description uses multicast
  - TTL validation for IPv4 multicast
  - Administrative scope checking for IPv6 multicast

**proto-rtp (RFC 3550 §7)**

- RTP translators and mixers (`translator.rs`):
  - `RtpTranslator` for SSRC-preserving packet forwarding
  - `RtpMixer` for multi-source mixing with CSRC list management
  - `SourceState` for tracking per-source RTP state (sequence, timestamp, packets)
  - `SsrcCollisionDetector` for loop prevention
  - `TranslatorRtcpBuilder` for combined RTCP reports from multiple sources
  - `CsrcValidation` struct for CSRC list validation results
  - `validate_csrc_list()` function for RFC compliance checking
  - `MAX_CSRC_COUNT` constant (15) per RFC 3550

**proto-sip (RFC 3261 §16.6)**

- SIP proxy request forwarding (`proxy.rs`):
  - `ProxyContext` for proxy configuration (URI, transport, host, port)
  - `ProxyValidation` struct for request validation results
  - `ForwardingTarget` with priority, q-value, and transport override
  - `ForkingMode` enum: None, Parallel, Sequential
  - `RequestForwarder` implementing full RFC 3261 §16.6 compliance:
    - Max-Forwards validation and decrement (§16.3, §16.6 step 3)
    - Via header insertion at correct position (§16.6 step 8)
    - Record-Route header insertion (§16.6 step 5)
    - Loop detection via Via headers (§16.3 step 4)
    - Request forking with priority/q-value ordering
  - `ResponseProcessor` for upstream forwarding:
    - Topmost Via removal (§16.7)
    - Best response selection for forked requests (6xx > 2xx > 3xx priority)
  - Helper functions: `create_trying_response()`, `create_too_many_hops_response()`, `create_loop_detected_response()`

#### Phase 21: Advanced SBC Features

**proto-sip Header Manipulation Engine**

- Header manipulation engine (`manipulation.rs`):
  - `ManipulationAction` enum: Add, Set, Remove, RemoveMatching, Replace, RegexReplace, Rename, Copy, Prepend, Append
  - `ManipulationCondition` enum: Always, HeaderExists, HeaderMissing, HeaderContains, HeaderEquals, HeaderMatches, MethodEquals, Any, All, Not
  - `ManipulationRule` with priority ordering and enable/disable
  - `ManipulationPolicy` per-direction and per-message-type policies
  - `HeaderManipulator` with global and per-trunk policy management
  - `ManipulationContext` for request/response/trunk filtering
  - `ManipulationPresets` for common rules (normalize UA, strip PAI, RPID-to-PAI)
  - Basic regex pattern matching (^anchor, $anchor, capture groups)
  - Exported from lib.rs for public API access

**uc-siprec - SIPREC Call Recording (RFC 7865/7866)**

New crate for session recording:
- `config.rs` - Recording configuration:
  - `SrsEndpoint` for recording server (primary/backup, weight, health)
  - `RecordingMode` enum: Selective, AllCalls, OnDemand, Disabled
  - `RecordingTrigger` conditions (trunk, caller/callee pattern, header match, time window)
  - `RecordingMediaOptions` for audio/video/DTMF settings
  - `RecordingConfig` with max sessions, retry, exempt trunks

- `metadata.rs` - Recording metadata per RFC 7865:
  - `RecordingMetadata` top-level container
  - `SessionMetadata` with recording session ID, state, timestamps
  - `Participant` with AoR, display name, role, join/leave times
  - `MediaStream` with codec, SSRC, direction, participant association
  - `ParticipantRole` enum: Caller, Callee, Observer, Supervisor
  - `StreamDirection` enum: Send, Receive, SendReceive, Inactive
  - `to_xml()` method for RFC 7865 compliant XML generation

- `forking.rs` - Media forking:
  - `MediaForker` for RTP stream duplication management
  - `StreamFork` with source/dest/fork addresses and SSRC
  - `ForkingMode` enum: BothDirections, InboundOnly, OutboundOnly, Disabled
  - `ForkerState` lifecycle: Uninitialized, Initialized, Active, Paused, Stopped, Error
  - Packet/byte counting statistics per stream

- `session.rs` - Recording session management:
  - `RecordingSession` with full lifecycle state machine
  - `RecordingSessionState`: Created, Inviting, Proceeding, Active, OnHold, Terminating, Terminated, Failed
  - `SessionRecordingClient` (SRC) for managing recording sessions
  - `RecordingContext` for trigger evaluation
  - `SessionRecordingEvent` for session lifecycle notifications
  - Participant and stream management

**uc-transport QoS Module (RFC 2474/4594)**

- QoS DSCP marking (`qos.rs`):
  - `DscpValue` enum with all standard classes: BE, CS1-7, AF11-43, EF
  - `to_tos()` conversion (DSCP << 2)
  - `TrafficType` classification: VoiceMedia, VideoMedia, VoiceSignaling, VideoSignaling, Management
  - `QosConfig` with traffic type and enable flag
  - `TrunkQosPolicy` for per-trunk signaling/media QoS settings
  - `QosPolicyManager` with global defaults and trunk overrides
  - `apply_dscp()` for IPv4 (`IP_TOS`) and IPv6 (`IPV6_TCLASS`) sockets
  - Preset configs: `voice_signaling()`, `voice_media()`, `video_signaling()`, `video_media()`

**uc-policy Call Admission Control**

- CAC and bandwidth management (`cac.rs`):
  - `CallAdmissionController` central admission control:
    - Per-trunk and global session limits
    - Bandwidth tracking with codec estimation
    - Call rate limiting (CPS)
    - Emergency call bypass per RFC 4412
  - `TrunkCacLimits` configuration:
    - `max_sessions`, `max_bandwidth_kbps`, `max_cps`
    - `emergency_reserve_percent` for priority calls
    - `allowed_codecs` for codec restriction
  - `AdmissionDecision` enum: Admitted, Rejected, Queued
  - `RejectionReason` enum: MaxSessionsExceeded, BandwidthExceeded, RateLimitExceeded, TrunkDisabled, CodecNotAllowed
  - `CallPriority` per RFC 4412: Emergency, Critical, Priority, Normal, NonUrgent, BestEffort
  - `CodecBandwidth` estimates (G.711: 90kbps, G.729: 32kbps, G.722: 90kbps, Opus: 50kbps)
  - `TrunkStats` with session/bandwidth utilization metrics
  - Commit/release call tracking for real-time counters

#### P2 Medium Priority RFC Compliance Gaps

**proto-registrar (RFC 5627 §5.1)**

- Proxy GRUU routing (`gruu.rs`):
  - `GruuRouter` for RFC 5627 §5.1 compliant GRUU routing
  - `GruuRoutingResult` enum: Resolved, RegistrationExpired, NotFound, NotAGruu
  - `route()` - resolves GRUU URI to routing target
  - `route_to_binding()` - returns full Binding for GRUU
  - `is_gruu_active()` - checks if GRUU has active registration
  - `get_aor_for_gruu()` - extracts AOR for authorization
  - `extract_gruu_info()` - parses GRUU type (public vs temporary)
  - Path header forwarding for outbound flows
  - Lowest reg-id selection per RFC 5627 §5.1 for multiple flows

**proto-rtp (RFC 3550 §6.3.5)**

- RTCP transmission scheduling (`scheduler.rs`):
  - `RtcpScheduler` implementing RFC 3550 Appendix A.7 algorithm
  - `SessionParams` for bandwidth, members, senders configuration
  - `compute_deterministic_interval()` based on RTCP bandwidth and participants
  - `compute_interval()` with [0.5, 1.5] randomization per §6.3.5
  - Sender/receiver bandwidth separation (25%/75%) per §6.3.1
  - Initial interval halving per §6.3.6
  - Timer reconsideration for membership changes
  - `IntervalBounds` for interval validation
  - Constants: `RTCP_MIN_INTERVAL_SECS`, `RTCP_BANDWIDTH_FRACTION`, `RTCP_COMPENSATION_FACTOR`

**proto-dialog (RFC 6665 §7.2)**

- Event package validation (`subscription.rs`):
  - `EventPackageRegistry` for IANA registration validation per RFC 6665 §7.2
  - `EventPackageValidation` enum: Valid, UnregisteredAllowed, Invalid
  - `IANA_REGISTERED_EVENT_PACKAGES` constant with all known packages
  - `validate()` - validates event type against registry
  - `is_iana_registered()` - checks IANA registration status
  - `add_custom_package()` / `remove_custom_package()` - extension support
  - Strict mode (rejects unregistered) vs permissive mode (warns only)
  - Case-insensitive validation
  - Convenience functions: `validate_event_package()`, `is_event_package_registered()`

**proto-sdp (RFC 4566 §5.11)**

- Repeat times r= line support (`session.rs`):
  - `RepeatTimes` struct per RFC 4566 §5.11
  - `TimeValue` with compact notation support (d/h/m/s suffixes)
  - `Timing` extended with `repeat_times` field
  - `RepeatTimes::parse()` / `to_string()` for r= line handling
  - `TimeValue::from_days()`, `from_hours()`, `from_minutes()`, `from_seconds()`
  - `TimeValue::to_compact_string()` for efficient encoding
  - `RepeatTimes::daily()` / `weekly()` convenience constructors
  - `is_valid()` validation (interval, duration, offsets)
  - Full SDP parsing/generation roundtrip support
  - Exported `Origin`, `Timing`, `RepeatTimes`, `TimeValue` from lib.rs

#### RFC Compliance Gaps - Phase 18 Completion

**proto-ice (RFC 8445 §6.2, §9-10, RFC 7675)**

- ICE connectivity check implementation (`connectivity.rs`):
  - `ConnectivityCheck` struct for STUN-based connectivity verification
  - `ConnectivityChecker` with triggered check queue per RFC 8445 §6.1.4
  - `IceStunServer` for processing STUN Binding requests/responses
  - `CheckResult` states: Success, Failure, Timeout, RoleConflict, InvalidCredentials
  - USE-CANDIDATE nomination for controlled/controlling role
  - Role conflict handling with 487 error response
  - Transaction ID generation and tracking

- ICE consent and keepalive implementation (`consent.rs`):
  - `ConsentTracker` with 5-second check interval per RFC 7675
  - 30-second consent timeout with automatic expiration
  - `KeepaliveTracker` with 15-second STUN Binding indications
  - `ConsentKeepaliveManager` combining consent and keepalive logic
  - `ConsentState` enum: Pending, Granted, Expired
  - `ConsentKeepaliveAction` enum for poll-based state machine

**proto-dtls (RFC 5764)**

- SRTP keying material export (`srtp_export.rs`):
  - `SrtpKeyExporter` for DTLS-SRTP key derivation
  - `EXTRACTOR-dtls_srtp` exporter label per RFC 5764 §4.2
  - 88-byte keying material layout (2×32-byte keys + 2×12-byte salts)
  - `UseSrtpExtension` encode/decode for use_srtp TLS extension
  - HKDF-SHA384 PRF for CNSA 2.0 compliant key derivation
  - Support for AEAD_AES_256_GCM profile (profile ID 0x0008)

#### Crate Extraction: Complete proto-* Stack

- Extracted all SIP application crates into standalone `proto-*` crates for reuse:
  - `proto-sip`: RFC 3261 SIP protocol parsing and generation
  - `proto-transaction`: RFC 3261 §17 transaction state machine
  - `proto-dialog`: RFC 3261 §12 dialog management, RFC 3515 REFER, RFC 4028 session timers
  - `proto-b2bua`: RFC 7092 B2BUA taxonomy, RFC 5853 SBC requirements
  - `proto-registrar`: RFC 3261 §10 registration, RFC 5626 outbound, RFC 5627 GRUU
- All proto-* crates are standalone with minimal dependencies (no SBC-specific code)
- Designed for reuse by SBC and future Call Manager projects
- Publishable to crates.io as independent libraries

#### RFC Compliance Improvements

**proto-transaction (RFC 3261 §17, RFC 3262)**

- CSeq validation for transaction matching (RFC 3261 §17.1.3):
  - `CSeqTracker` struct for tracking sequence numbers and methods
  - `CSeqValidation` enum: Valid, Retransmission, TooLow, MethodMismatch
  - Request validation with `validate()` and response correlation with `validate_response()`
- RFC 3261 branch magic cookie constant (`RFC3261_BRANCH_MAGIC = "z9hG4bK"`)
- UPDATE method transaction support (RFC 3311) using non-INVITE state machine
- Reliable provisional responses (RFC 3262 - 100rel):
  - `RAck` header parsing and formatting
  - `ReliableProvisionalTracker` for UAS-side PRACK management
  - `ClientReliableProvisionalTracker` for UAC-side tracking
  - RSeq sequence management with T1/T2 retransmission timers
  - `supports_100rel()` and `requires_100rel()` header parsing

**proto-sip (RFC 3261, RFC 3327)**

- Path header support (RFC 3327) for proxy routing:
  - `HeaderName::Path` variant with `allows_multiple() = true`
  - Helper methods: `path_values()`, `add_path()`, `prepend_path()`
- Routing module (`routing.rs`) with Route/Record-Route processing:
  - `process_record_route()` for UAC/UAS route set construction
  - `construct_request_route()` for in-dialog request routing
  - Loose routing (`lr` parameter) detection and handling

**proto-dialog (RFC 3261 §12, RFC 3515, RFC 4028, RFC 6665)**

- Multi-dialog forking support (RFC 3261 §12.2.2):
  - `ForkKey` struct for matching forked responses by Call-ID and local tag
  - `ForkedDialogSet` for managing parallel early dialogs from proxy forking
  - Methods: `receive_provisional()`, `receive_2xx()`, `receive_error()`
  - Auto-termination of non-confirmed dialogs when one is confirmed
  - `dialogs_to_terminate()` returns list of dialogs needing BYE/CANCEL
- Enhanced REFER support (RFC 3515):
  - `ReferHandler` for transfer request management
  - `ReferSubscriptionState`: Pending, Active, Terminated
  - Implicit subscription lifecycle tracking
- Session timer improvements (RFC 4028):
  - `SessionTimerNegotiation` for offer/answer session timer handling
  - `handle_422_response()` for Min-SE negotiation
  - `RefresherRole` enum: UAC, UAS, Unspecified
- Event notification framework (RFC 6665):
  - `EventPackage` for event type identification (presence, dialog, message-summary)
  - `Subscription` for subscriber-side subscription management
  - `Notifier` for server-side subscription handling
  - `SubscriptionState`: Pending, Active, Terminated
  - `SubscriptionStateHeader` parsing and formatting
  - `TerminationReason` enum for subscription termination causes

**proto-b2bua (RFC 7092, RFC 5853, RFC 3960)**

- B2BUA mode characteristics (`mode.rs`):
  - `ModeCharacteristics` with SDP modification, media handling, topology hiding per mode
  - `SdpModification`: Passthrough, RewriteConnection, FullModification
  - `MediaHandling`: None, Relay, Inspect, Terminate
  - `TopologyHiding`: None, SignalingOnly, Full
- SDP rewriting for media anchoring (`sdp_rewrite.rs`):
  - `SdpRewriter` with mode-based SDP modification
  - `rewrite_offer_for_b_leg()` and `rewrite_answer_for_a_leg()`
  - Connection (`c=`) and media port (`m=`) rewriting
  - IPv4 and IPv6 address support
  - Hold/Resume SDP direction handling: `rewrite_for_hold()`, `rewrite_for_resume()`
- Helper functions: `extract_media_address()`, `is_hold_sdp()`, `is_connection_hold()`
- `SdpRewriteContext` for per-leg address management
- Early media handling (RFC 3960):
  - `EarlyMediaHandler` for 183 Session Progress with SDP
  - `EarlyMediaMode`: None, LocalRingback, Relay, Gate
  - `EarlyMediaSession` for per-leg early media state
  - `EarlyMediaAction` enum for handler responses
  - `is_early_media_response()` and `should_setup_early_media()` helpers

**proto-registrar (RFC 3261 §10, RFC 5626, RFC 5627)**

- GRUU service (RFC 5627):
  - `GruuService` for pub-gruu and temp-gruu generation
  - `GruuEntry` with instance association and expiration
  - Lookup methods: `lookup_by_gruu()`, `lookup_by_contact()`
  - GRUU parameter formatting in Contact header
- Outbound support improvements (RFC 5626):
  - Instance-ID and Reg-ID parameter handling
  - Outbound binding key generation: `{aor}:{instance_id}:{reg_id}`
  - Flow token support for connection reuse

#### Crate Extraction: proto-sip

- Extracted `sbc-sip` into standalone `proto-sip` crate for reuse
  - `proto-sip`: RFC 3261 compliant SIP protocol parsing and generation
  - Standalone crate with no SBC-specific dependencies (only `thiserror`, `bytes`)
  - Designed for reuse by SBC and future Call Manager projects
  - Publishable to crates.io as independent library

#### RFC 3261 Compliance Improvements (proto-sip)

- Structured header parsing module (`header_params.rs`):
  - `ViaHeader`: Parsed Via with transport, host, port, branch, received, rport, ttl, maddr
  - `NameAddr`: Parsed From/To/Contact with display-name, URI, tag, parameters
  - `CSeqHeader`: Parsed CSeq with sequence number and method
  - `MaxForwardsHeader`: Parsed Max-Forwards with decrement logic
  - Via branch magic cookie validation (`z9hG4bK` prefix)
  - Random tag and branch generation utilities
- Extension method support per RFC 3261 Section 7.1:
  - `Method::Extension(String)` variant for custom methods
  - Unknown methods now parse successfully instead of error
  - `is_extension()` and `is_rfc3261_core()` classification methods
- Mandatory header validation:
  - `Headers::validate_request_headers()` - Via, To, From, Call-ID, CSeq, Max-Forwards
  - `Headers::validate_response_headers()` - Via, To, From, Call-ID, CSeq
- New header convenience methods:
  - `via_parsed()`, `via_all_parsed()`, `via_branch()`
  - `from_parsed()`, `to_parsed()`, `from_tag()`, `to_tag()`
  - `cseq_parsed()`, `max_forwards()`, `contact_parsed()`, `expires()`
- Additional RFC 3261 Section 20 headers:
  - Content-Disposition, Content-Language, Min-Expires
  - Accept, Accept-Encoding, Accept-Language
  - Alert-Info, Call-Info, Date, Error-Info, In-Reply-To
  - MIME-Version, Organization, Priority, Reply-To, Retry-After
  - Server, Subject, Timestamp, User-Agent, Warning
  - Allow-Events, Session-Expires, Min-SE
  - P-Asserted-Identity, P-Preferred-Identity, Reason
  - Refer-To, Referred-By, Replaces
- Additional compact form support: Subject (s), Refer-To (r), Allow-Events (u), Event (o)
- URI parameter accessors: `user_param()`, `is_phone()`, `method_param()`, `ttl()`, `maddr()`
- `HeaderName::allows_multiple()` for multi-value header validation

#### SIP Authentication (RFC 2617)

- New authentication module (`auth.rs`):
  - `DigestChallenge`: Parsed WWW-Authenticate/Proxy-Authenticate headers
  - `DigestCredentials`: Parsed Authorization/Proxy-Authorization headers
  - `DigestAlgorithm`: MD5, SHA-256, SHA-512-256 support
  - `Qop`: Quality of Protection (auth, auth-int)
  - Stale nonce detection support
  - Round-trip parsing and generation

#### Message Builder Utilities

- New builder module (`builder.rs`):
  - `RequestBuilder`: Fluent API for constructing SIP requests
  - `ResponseBuilder`: Fluent API for constructing SIP responses
  - Automatic header generation (Content-Length, Via branch, tags)
  - Convenience methods: `invite()`, `register()`, `ok()`, `unauthorized()`
  - Auto-copy headers from request to response
  - SDP body helpers with Content-Type
- ID generation utilities:
  - `generate_call_id()`: Thread-safe unique Call-ID generation
  - `generate_branch()`: RFC 3261 compliant branch with magic cookie
  - `generate_tag()`: Unique tag generation for From/To headers

#### Transport Definitions (RFC 3261, RFC 7118)

- New transport module (`transport.rs`):
  - `Transport` enum: UDP, TCP, TLS, SCTP, WS, WSS, DTLS-UDP
  - Transport validation and properties
  - `is_reliable()`, `is_secure()`, `default_port()`
  - RFC 3261 core transport identification

#### Safety-Critical Code Compliance

- NASA "Power of 10" rules compliance documentation
- Debug assertions for invariant checking (Rule 5)
- Loop bounds documentation (Rule 2)
- All functions have bounded execution
- Power of 10 Rule 4 compliance: Refactored 10 functions exceeding 60 lines into smaller helpers:
  - `uc-policy/condition.rs`: Extracted `match_ip()`, `match_optional_string()`, `evaluate_all()`, `evaluate_any()` helpers
  - `proto-sdp/session.rs`: Created `SdpParseState` struct with 13 helper methods for SDP parsing
  - `proto-sip/auth.rs`: Extracted `get_required_param()`, `filter_extra_params()` for digest auth parsing
  - `proto-sip/uri.rs`: Extracted `parse_uri_params()`, `parse_user_info()`, `parse_host_port()`, `parse_uri_headers()`
  - `proto-sip/header_params.rs`: Extracted `parse_quoted_display_name()`, `extract_display_name()`, `extract_uri_and_params()`, `parse_nameaddr_params()`
  - `uc-cdr/format.rs`: Extracted `add_required_fields()`, `add_optional_fields()`, `add_timing_fields()`, `format_custom_fields()`
  - `uc-transport/tcp.rs`: Extracted `create_tcp_socket()`, `configure_socket_options()`, `bind_and_listen()`, `socket_to_tokio_listener()`
  - `proto-ice/candidate.rs`: Extracted `parse_sdp_core_fields()`, `parse_sdp_transport()`, `parse_sdp_address()`, `parse_sdp_optional_fields()`, `parse_related_address()`
  - `proto-rtp/packet.rs`: Extracted `parse_first_byte()`, `parse_second_byte()`, `parse_csrc_list()`, `parse_extension_header()`
  - `uc-routing/router.rs`: Extracted `resolve_trunk_group()`, `select_trunk_from_group()`

### Fixed

- Comprehensive clippy lint fixes across 73 files in proto-*, uc-*, and sbc-daemon crates:
  - Added `#[allow(clippy::unwrap_used, clippy::expect_used)]` to test modules
  - Fixed `Attestation::from_str()` to use `Attestation::parse()` in proto-stir-shaken
  - Fixed type mismatches for `&NameAddr` and `&Candidate` parameters
  - Removed `.unwrap()` calls on unit type returns
  - Added numeric literal separators (e.g., `604_800`, `0x1234_5678`)
  - Fixed float comparisons to use epsilon-based comparison
  - Added `Default` implementations for types with `new()` constructors
  - Converted constant assertions to `const _: () = { assert!(...) };` blocks
  - Fixed similar variable name warnings with `#[allow(clippy::similar_names)]`
  - Fixed wildcard patterns in match arms
  - Added crate-level allows for `significant_drop_tightening`, `future_not_send`, `unused_async`
  - Converted `match` expressions to `let...else` where appropriate
  - Fixed cast truncation warnings with explicit `#[allow]` attributes
  - Fixed enum variant name warnings with `#[allow(clippy::enum_variant_names)]`
  - Fixed struct field name warnings with `#[allow(clippy::struct_field_names)]`

### Removed

- `sbc-sip` crate (replaced by `proto-sip`)

### Changed

- `sbc-daemon`: Now depends on `proto-sip` instead of `sbc-sip`
- `sbc-transaction`: Now depends on `proto-sip` instead of `sbc-sip`
- `sbc-dialog`: Now depends on `proto-sip` instead of `sbc-sip`
- `sbc-dtls/cipher_suite.rs`: Rewritten for CNSA 2.0 compliance (only AES-256-GCM-SHA384)
- `sbc-dtls/Cargo.toml`: Removed webrtc-dtls dependency
- `sbc-codecs/g722.rs`: Now uses pure Rust ADPCM implementation via `G722AdpcmCodec`

---

#### Phase 17: Complete Stub Implementations

- Custom DTLS 1.2 implementation with aws-lc-rs replacing webrtc-dtls
  - `sbc-dtls/record.rs`: DTLS record layer with AES-256-GCM encryption
  - `sbc-dtls/handshake.rs`: Full handshake state machine (client and server)
  - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 cipher suite (0xC02C)
  - P-384 ECDHE key exchange via `sbc-crypto`
  - TLS 1.2 PRF using HMAC-SHA384
  - SRTP keying material export per RFC 5764
  - Anti-replay protection with 64-bit sliding window
  - Cookie-based DoS protection (HelloVerifyRequest)
- STUN client implementation for server-reflexive candidate gathering
- TURN client implementation for relay candidate gathering
- ICE candidate gathering state machine updates
- G.722 ADPCM codec (pure Rust implementation)
  - QMF filter banks for sub-band splitting
  - Lower and higher band ADPCM encoding/decoding
- Opus FFI bindings via optional `opus-ffi` feature (audiopus crate)
- HMAC-SHA384 functions in `sbc-crypto/hkdf.rs` for TLS PRF

### Fixed

- Clippy warnings in `sbc-codecs` (format strings, bool_to_int_with_if, similar_names)
- Thread safety for `G722Codec` using `Mutex` instead of `RefCell`

---

#### Phase 1-2: Foundation & Transport
- Initial workspace structure with 27 crates organized in 9 layers
- Foundation crates: `sbc-types`, `sbc-crypto`, `sbc-audit`, `sbc-config`
- CNSA 2.0 cryptographic compliance enforcement via `sbc-crypto`
- NIST 800-53 Rev5 audit logging infrastructure via `sbc-audit`
- Transport crates: `sbc-transport`, `sbc-dtls`
- Project documentation: `CONTRIBUTING.md`, `CHANGELOG.md`
- Compliance documentation: `docs/NIST-800-53-CONTROLS.md`, `docs/CNSA-2-COMPLIANCE.md`

#### Phase 3: Protocol Core
- `sbc-sip`: SIP message parsing and generation
- `sbc-sdp`: SDP offer/answer model
- `sbc-rtp`: RTP packet handling
- `sbc-srtp`: Custom CNSA 2.0 compliant SRTP (AES-256-GCM, SHA-384 KDF)

#### Phase 4: NAT/ICE
- `sbc-stun`: STUN client/server
- `sbc-turn`: TURN relay
- `sbc-ice`: Full ICE implementation

#### Phase 5: Media Engine
- `sbc-codecs`: Opus, G.711 (pure Rust), G.722 codec support
- `sbc-media-engine`: Media relay and pass-through modes

#### Phase 6: SIP Application
- `sbc-transaction`: SIP transaction state machine
- `sbc-dialog`: SIP dialog management with session timers
- `sbc-b2bua`: B2BUA core per RFC 7092
- `sbc-registrar`: SIP registration with B2BUA and proxy modes

#### Phase 7: Security Services
- `sbc-stir-shaken`: STIR/SHAKEN with ES384 only (no ES256 per CNSA 2.0)
- `sbc-acl`: Access control lists with CIDR network matching
- `sbc-dos-protection`: Token bucket rate limiting with per-IP tracking

#### Phase 8: Orchestration & Management
- `sbc-policy`: Policy engine with conditions, actions, rules, and priority ordering
- `sbc-routing`: Dial plans, trunk management, LCR, and failover routing
- `sbc-cdr`: Call Detail Records with JSON/CSV export
- `sbc-api`: REST API framework with request/response types and routing
- `sbc-metrics`: Prometheus metrics (counters, gauges, histograms)
- `sbc-health`: Kubernetes liveness/readiness probes and health checks

#### Phase 9: Binaries & Integration
- `sbc-daemon`: Main SBC daemon with configuration loading, health checks, and graceful shutdown
- `sbc-cli`: Command-line interface with status, config, calls, health, and metrics commands
- `sbc-integration-tests`: Integration test suite for cross-crate testing

#### Phase 10: Async Runtime Integration

- Tokio async runtime integration in `sbc-daemon`
- Async UDP transport listeners with `sbc-transport` integration
- Unix signal handling with tokio (SIGTERM, SIGINT, SIGHUP)
- Async event loop for message processing with per-transport receive tasks
- Graceful shutdown with broadcast-based notification
- Health check polling loop with configurable interval
- Structured logging via tracing and tracing-subscriber

#### Phase 11: SIP Stack Integration

- SipStack module coordinating `sbc-sip`, `sbc-transaction`, `sbc-dialog`, `sbc-b2bua`, and `sbc-registrar`
- ProcessResult enum for message routing decisions (Response, Forward, NoAction, Error)
- SIP method handlers: REGISTER, INVITE, ACK, BYE, CANCEL, OPTIONS
- SIP processing integrated into transport receive loop
- Transaction, dialog, and call state management structures
- Support for both B2BUA registrar and proxy modes

#### Phase 12: Media Pipeline Integration

- MediaPipeline module coordinating `sbc-rtp`, `sbc-srtp`, `sbc-dtls`, `sbc-media-engine`, and `sbc-codecs`
- RTP/SRTP packet processing with relay and pass-through modes
- DTLS-SRTP key exchange for secure media transport
- Codec negotiation via CodecRegistry
- Session management with A-leg/B-leg addressing
- RTP sequence tracking and statistics

#### Phase 13: ICE/NAT Traversal Integration

- IceManager module coordinating `sbc-ice`, `sbc-stun`, and `sbc-turn`
- ICE session lifecycle management (create, gather, check, close)
- Candidate gathering with host and server-reflexive candidates
- Connectivity check state machine integration
- ICE-lite mode for server-side optimization
- STUN binding request/response processing
- ICE restart support for mid-session renegotiation
- Session statistics and monitoring

#### Phase 14: REST API Server

- ApiServer module providing HTTP management interface via axum
- Liveness probe endpoint (`GET /healthz`)
- Readiness probe endpoint (`GET /readyz`)
- Health status endpoint (`GET /api/v1/system/health`)
- Prometheus metrics endpoint (`GET /api/v1/system/metrics`)
- Server statistics endpoint (`GET /api/v1/system/stats`)
- Version endpoint (`GET /api/v1/system/version`)
- Calls listing endpoint (`GET /api/v1/calls`)
- Registrations listing endpoint (`GET /api/v1/registrations`)
- Graceful shutdown integration with SIP server
- JSON serialization for all API responses

#### Phase 15: Production Hardening

- Graceful shutdown with connection draining
  - ConnectionTracker for active calls, transactions, and registrations
  - Configurable drain timeout with periodic polling
  - DrainResult reporting with statistics
  - ForcedShutdown phase when timeout exceeded
- Configuration hot-reload via SIGHUP
  - Async config reload loop monitoring shutdown signal
  - ConfigReloadResult with change detection
  - Section-level change tracking (general, transport, media, security, logging)
- HTTPS support for API server
  - TLS 1.3 with CNSA 2.0 compliant cipher suites
  - Certificate and key loading from PEM files
  - tokio-rustls integration for async TLS
- Rate limiting integration with sbc-dos-protection
  - Per-IP token bucket rate limiting for SIP messages
  - Configurable via rate_limit section in config
  - RateLimitAction handling (Allow, Throttle, Reject, Block)
  - rate_limited counter in server statistics

#### Phase 16: Deployment & Operations

- Multi-stage Dockerfile for optimized container images
  - Rust 1.85 builder stage with cmake, pkg-config, libssl-dev
  - Minimal debian:bookworm-slim runtime image
  - Non-root user (UID 1000) for security
  - Health check via `sbc-cli health --quiet`
  - Exposed ports: SIP (5060/udp, 5060/tcp, 5061/tcp), API (8080, 8443), RTP (16384-16484/udp)
- Kubernetes manifests for production deployment
  - Namespace with Pod Security Standards (restricted)
  - Deployment with security context (non-root, read-only filesystem, dropped capabilities)
  - Services: LoadBalancer for SIP, ClusterIP for API and metrics
  - RBAC with minimal ServiceAccount permissions
  - PodDisruptionBudget (minAvailable: 1)
  - NetworkPolicies for defense in depth
- Helm chart for parameterized deployment
  - Configurable replicas, resources, and autoscaling
  - HorizontalPodAutoscaler support
  - ServiceMonitor for Prometheus Operator integration
  - Full config.toml templating from values.yaml
  - Network policies and security contexts
- Operational runbook documentation
  - Deployment procedures (Docker, Kubernetes, Helm)
  - Configuration hot-reload instructions
  - Graceful shutdown procedures
  - Monitoring and alerting guidance
  - Troubleshooting guide
  - Incident response procedures (P1-P4)
  - CNSA 2.0 compliance checklist
  - Maintenance procedures (certificate rotation, upgrades, backup/recovery)

### Security

- Enforced `#![forbid(unsafe_code)]` across all crates (documented exceptions only)
- CNSA 2.0 algorithm restrictions: AES-256 only, SHA-384+ only, P-384+ curves only
- Forbidden algorithms compile-time blocked: SHA-256, P-256, AES-128
- STIR/SHAKEN uses ES384 exclusively (ES256 forbidden)
- Container security: non-root user, read-only filesystem, dropped capabilities
- Kubernetes Pod Security Standards: restricted profile enforced
- Network segmentation via NetworkPolicies

[Unreleased]: https://github.com/usg/usg-uc-sbc/compare/v0.1.0...HEAD
