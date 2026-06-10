# crates/sbc Remediation Plan

Companion to [AUDIT-2026-06-10.md](AUDIT-2026-06-10.md). Five phases, each shippable as
one or more PRs. Phase 0 gates everything: until the management plane is authenticated
and on TLS, every other security fix is moot.

Design directive: **HTTPS/TLS is the default for both REST and gRPC.** Plain HTTP/h2c is
an explicit, logged opt-in.

---

## Phase 0 — Secure the management plane (C1, C2)

### 0.1 TLS by default for REST and gRPC

**Existing plumbing to reuse:** `api_server.rs` already has a rustls/`ReloadableTlsAcceptor`
HTTPS path (currently unreachable because `runtime.rs:331` builds
`ApiServerConfig { ..default() }` with `tls: None`); `grpc_server/mod.rs:279` already
builds `ServerTlsConfig` with optional mTLS when cert paths are set.

1. **Cert bootstrap (new):** add `rcgen` to `sbc-daemon`. On startup, if no cert/key is
   configured, generate a self-signed P-384 ECDSA cert (SANs: hostname, zone IPs,
   `localhost`) into `/var/lib/sbc/tls/{self-signed.crt,self-signed.key}` with mode 0600,
   reuse on subsequent boots, and log the SHA-256 fingerprint at startup so operators can
   pin it. Configured cert paths always win; the existing hot-reload endpoint keeps working.
2. **Schema (`sbc-config/src/schema.rs`):** add an `[api]` section (today the REST config
   exists only as hardcoded `ApiServerConfig::default()`):
   - `listen_addr` — default `0.0.0.0:8443` (HTTPS port; document the 8080→8443 move)
   - `tls_cert_path` / `tls_key_path` — optional; fall back to the bootstrap cert
   - `allow_insecure_http: bool` — default `false`
   Validate in `validate.rs`: if `allow_insecure_http` and the bind is non-loopback,
   refuse to start unless `i_understand_this_is_insecure = true` (or equivalent single
   explicit override); always log a prominent warning.
3. **Runtime wiring (`runtime.rs:325-340`):** build `ApiServerConfig` from the schema
   instead of `..default()`; pass the resolved TLS config so `run()` takes the HTTPS path.
4. **gRPC defaults (`grpc_server/mod.rs:158-172`):** when `tls_cert_path` is unset, use
   the bootstrap cert instead of falling through to plaintext. Replace the
   "running WITHOUT TLS" warn-and-continue with a hard error unless
   `grpc.allow_insecure = true` (new field, default false). Keep `require_mtls` as the
   recommended production posture; document it.
5. **Clients:** dashboard is served same-origin by the daemon so it inherits HTTPS for
   free. `sbc-cli` default `--api-url` becomes `https://127.0.0.1:8443`; add
   `--ca-cert` and `--insecure` flags for self-signed deployments (lands with 4.1).

**Acceptance:** fresh install with zero config serves REST and gRPC over TLS only;
`curl http://` fails; plaintext requires two explicit config acknowledgments; cert
fingerprint appears in startup logs.

### 0.2 Authentication and authorization

1. **Admin identity:** new `admin_users` store (separate from SIP users), argon2id
   password hashes, persisted 0600. First-boot bootstrap: generate a random admin
   password, print once to stdout/journal (or accept `SBC_ADMIN_PASSWORD` env / config
   field for automated deploys).
2. **REST:** `POST /api/v1/auth/login` → short-lived session token; delivered as an
   `HttpOnly; Secure; SameSite=Strict` cookie (dashboard) and accepted as
   `Authorization: Bearer` (CLI/automation). Static API keys in config (stored hashed)
   for non-interactive clients. Enforce via axum middleware on the entire `/api` nest;
   `/healthz` and `/metrics` stay open (read-only, no secrets — verify before exempting).
3. **gRPC:** tonic interceptor validating the same bearer/API key from request metadata;
   mTLS satisfies auth when `require_mtls` is on.
4. **Provisioning endpoint (`/provision/*`)** — cannot use admin auth (phones can't):
   per-phone provisioning token embedded in the provisioning URL (stored on the phone
   record), plus optional source-network allowlist and per-IP rate limiting. Serve only
   over TLS.
5. **Dashboard:** login view; `api.ts` `request()` sends credentials and redirects to
   login on 401 (fix the header-merge spread-order bug in `api.ts:20-23` while there).

**Acceptance:** every mutating REST/gRPC call without credentials returns 401/UNAUTHENTICATED;
integration tests pin this for each route; dashboard round-trips login → CRUD → logout.

### 0.3 Secret redaction and storage

1. `#[serde(skip_serializing)]` on `digest_ha1` (`uc-user-mgmt/src/model.rs:22`) or
   sanitized DTOs in `api_server.rs` user handlers.
2. Redact `sip_password` from all trunk-group GET responses (write-only field; PUT with
   omitted password keeps the stored one).
3. `save_trunk_groups()` (`api_server.rs:139-157`): write temp file with mode 0600 before
   rename; encrypt `sip_password` at rest with the existing `SBC_HA1_ENCRYPTION_KEY`
   AES-256-GCM machinery.
4. Trunk registrar logging (`trunk_registrar.rs:215-237,308-326`): drop raw SIP dumps to
   `trace!`, redact `Authorization`/`Proxy-Authorization` values at all levels.
5. Remove absolute cert paths from TLS status responses (`api_server.rs:2043-2052`,
   `system_service.rs:116-117,156-157`).

---

## Phase 1 — Media plane and unauthenticated DoS (C3, H1, H2)

### 1.1 RTP relay hardening (`media_pipeline.rs:902-1010`)
- Source validation: only forward packets whose source matches the negotiated remote, or
  implement symmetric-RTP latching (first valid packet locks the source; ignore others).
- Route relay packets through the existing SRTP protect/unprotect functions; honor
  `srtp_required` (drop plaintext when required, alarm metric on violations).
- Fix `RtpPortAllocator` checked arithmetic + range validation (`media_pipeline.rs:94-117`);
  guard `data.get(header_size..)` in RTP parse (`:793-795`).

### 1.2 Bounded state
- Remove `TransactionStore` entries on terminal transaction states (`sip_stack.rs:1461,1473`).
- Remove `announcement_calls` entries when the announcement task completes (`sip_stack.rs:186,2150`).
- Track SSRCs per session; drop trackers in `remove_session`; cap per-session SSRC count
  (`media_pipeline.rs:799`).

### 1.3 Admission control
- Wire `rate_limit.global_rps` and `per_user_rps` (today only `per_ip_rps` is enforced,
  `server.rs:173-181`); apply before any state allocation in `process_message`.
- Enforce `general.max_calls` / `max_registrations` as hard admission limits (currently
  only logged, `server.rs:249-250`).
- Per-source concurrent-call ceiling.

### 1.4 Trunk identity (H2)
- Stop treating bare source IP as authentication (`sip_stack.rs:1245-1268`): require
  digest auth or TLS/mTLS per trunk, or at minimum an explicit `trusted_source_networks`
  allowlist per trunk with a validation warning that IP trust is spoofable.

**Acceptance:** soak test — INVITE flood to unroutable numbers + RTP flood with random
SSRCs shows flat memory; RTP injection from a third-party address is dropped and counted.

---

## Phase 2 — Lifecycle and trunk reliability (H3–H7, related mediums)

### 2.1 Graceful shutdown (H3)
- Wire `ConnectionTracker` into real dialog/transaction lifecycle (or derive
  `total_active()` from the SipStack call map).
- Reorder shutdown: stop accepting new INVITEs (486/503) but keep receive loops alive to
  process in-dialog BYEs until drained or timeout, then abort tasks and close transports.
- Fix `fetch_sub` underflow (`shutdown.rs:216-219`); second SIGINT → immediate exit 130
  (`shutdown.rs:134-151`); await API/gRPC graceful shutdown instead of aborting
  (`runtime.rs:621-631`).

### 2.2 Trunk monitor/registrar (H4, H5, H6)
- Send OPTIONS/REGISTER through the main transport + transaction layer; match responses
  by Via branch + Call-ID. Eliminates the throwaway `:5060` REUSEPORT sockets that can
  swallow inbound INVITEs.
- Task registry: `HashMap<trunk_id, JoinHandle>` with abort-before-respawn, `stop_trunk()`
  on delete/disable, abort-all on shutdown.
- Re-register at `min(granted_expires, configured) * 80%`; exponential backoff with
  jitter on failure (5s → 60s cap).
- Fix status-init race (`trunk_registrar.rs:76-109`) with `entry().or_insert_with` like
  the monitor; async DNS (`tokio::net::lookup_host`) in monitor/registrar/zone; fix
  IPv4-only socket domain and IPv6 Via truncation.

### 2.3 Config reload honesty (H7)
- Distribute config via `tokio::sync::watch`; components that can react (rate limiter,
  trunk services, log level) subscribe. Components that can't (listeners) log exactly
  which sections require restart. Consolidate the SIGHUP path onto `reload_config()`.

### 2.4 Daemon resilience
- `select_all` over transport receive handles; unexpected task exit = fatal (or respawn
  with backoff) and surfaces in health (`server.rs:348-382`).
- Replace `AlwaysHealthyCheck` with real listener/trunk liveness; implement the
  health-poll stub (`server.rs:527-542`).
- Sleep + consecutive-error cap in receive loop (`server.rs:464-470`).
- Cluster: configured-but-failed init is fatal (no silent standalone fallback,
  `runtime.rs:73-88`); mark cluster mode experimental until heartbeat/membership exist
  (`cluster.rs:159-184`).
- Zones: bind one listener per `unique_signaling_addrs()` when a registry exists; refuse
  wildcard-bind + zones combination at validation (`runtime.rs:264-304`).
- Log seed.json read/parse failures (`runtime.rs:437-438`).

---

## Phase 3 — Protocol and API correctness

### 3.1 SIP dialog correctness (`sip_stack.rs`)
- Carry dialog From/To (with tags) + Max-Forwards in `CallAddresses`; populate on all
  in-dialog BYE/CANCEL/ACK (`:1596-1604, :1722-1733, :819-831`).
- Per-dialog CSeq counters instead of hardcoded values (`:824, :1598, :1719`).
- Match responses by top Via branch + CSeq method against stored client transactions
  (`:647-707`).
- REGISTER: sync bindings from the 200 OK's actual contacts, honoring `Expires: 0`
  (`:1056-1079`).
- Max-Forwards: reject 483 at 0, decrement and propagate (`:1379-1391`).
- Media cleanup on error-response path (`:913-938`).
- CSPRNG (rand/getrandom) for tags, branches, SSRCs (`:2385-2392`).
- Delete dead failover block and `match_response_to_transaction`, or finish them
  (`:858-911, :1822-1829`).

### 3.2 REST/gRPC correctness
- Shared error-response helper mapping domain errors → 404/409/503; eliminate
  200-with-`success:false` (`api_server.rs:1006,1267-1278,1546,1559,1693,1769`).
- `delete_trunk`: persist + re-sync to router; `update_phone`: merge instead of wholesale
  overwrite.
- Move `save_trunk_groups` I/O off the executor (`tokio::fs`/`spawn_blocking`) and out of
  the write-lock scope.
- gRPC stubs (`terminate_call`, `shutdown`, `update_config`, `reload_config`): implement
  or remove from the proto; same for REST CDR/call-ladder placeholders.

### 3.3 Config validation completeness (H8)
- New validators: routing/dial plans (enum whitelists, dangling trunk-group refs),
  trunk groups (empty id/host, port 0, duplicates), zones, header manipulation
  (RFC 3261 token syntax for names, reject control chars in values — CRLF injection),
  topology hiding, gRPC, logging, monitoring. Longer term: serde-tagged enums.
- TLS coherence: require cert/key when any TLS/WSS listener or gRPC is enabled; RTP range
  vs `max_calls` sizing check; duplicate-listener check.
- Wire-or-delete every dead schema field (STIR/SHAKEN, `audit_enabled`,
  `min_tls_version`, `ws_listen`/`wss_listen`, `realm_modes`, monitoring/gRPC tunables);
  interim: startup warning for set-but-unimplemented options.
- Config file permission check on load (warn on group/world-writable); error on unknown
  config file extensions; fix `stun0` interface-name collision
  (`interface.rs:91-97`); replace no-op CNSA validators with exhaustive matches.

---

## Phase 4 — Tooling, dashboard, dependencies, tests

### 4.1 sbc-cli (H9)
- Migrate to `clap` (fixes silent unknown-subcommand fallback and dropped trailing flags).
- Real HTTPS API client honoring `--api-url`, `--ca-cert`, `--insecure`, bearer token.
- Until each command is wired: exit non-zero with "not implemented" — never simulate
  success, never print fabricated data (status/calls/metrics/health).
- JSON output via `serde_json` only; one parseable document per invocation.

### 4.2 Dashboard
- Login flow (pairs with 0.2.5).
- Extract `useApiList<T>` hook + shared list-page layout (collapses ~600 duplicated lines
  across 9 pages); fix stale-response races and silent-poll spinner there once.
- Dashboard page: `Promise.allSettled`, real error states instead of eternal "Loading…".
- CDRs: wire Cloudscape `Pagination` (backend already returns paging metadata).
- Reboot confirm modal + loading/success feedback; `encodeURIComponent` on path params;
  wire sorting via `useCollection` or drop `sortingField`; delete `PlaceholderPage.tsx`.

### 4.3 Dependencies and lints
- `hickory-proto` → ≥0.26.1 (RUSTSEC-2026-0119); track RUSTSEC-2026-0118 (no fix yet).
- `sqlx` 0.8.0 → ≥0.8.1 (RUSTSEC-2024-0363).
- `npm audit fix` in sbc-dashboard (react-router open redirect).
- Fix upstream workspace clippy denials (`uc-phone-mgmt` 142, `proto-sip` 10, etc.) so
  the sbc crates actually get linted in CI.

### 4.4 Tests (gates each phase)
- Phase 0: per-route 401 tests; secret-redaction assertions (no `digest_ha1`/`sip_password`
  in any GET body); TLS-default boot test; file-permission assertions.
- Phase 1: memory-bound soak tests; RTP source-validation tests.
- Phase 2: shutdown-drain integration test (active call survives SIGTERM until BYE);
  trunk re-register honoring short granted Expires; duplicate-task regression test.
- Phase 3: config-validation table tests for every new rule; SIP dialog tests (BYE with
  tags, CSeq sequencing, forged-response rejection).
- Phase 4: CLI golden-output tests against a test daemon.

---

## Sequencing and PR breakdown

| # | PR | Phase | Depends on |
|---|----|-------|-----------|
| 1 | TLS-by-default: rcgen bootstrap, `[api]` schema section, runtime wiring, gRPC default-TLS | 0.1 | — |
| 2 | Auth: admin store, login, REST middleware, gRPC interceptor, provisioning tokens | 0.2 | 1 |
| 3 | Secret redaction + storage perms + log redaction | 0.3 | — (parallel with 1–2) |
| 4 | Dashboard login + api.ts credentials | 0.2/4.2 | 2 |
| 5 | RTP relay source validation + SRTP enforcement + allocator/parse hardening | 1.1 | — |
| 6 | Bounded state + rate limiting + admission control | 1.2/1.3 | — |
| 7 | Trunk auth / source-network allowlist | 1.4 | 6 |
| 8 | Shutdown drain rework | 2.1 | — |
| 9 | Trunk monitor/registrar rework (transport-layer sends, task registry, expires/backoff) | 2.2 | — |
| 10 | Config reload via watch channels | 2.3 | — |
| 11 | Daemon resilience (task death, health, cluster fail-fast, zone binds) | 2.4 | — |
| 12 | SIP dialog correctness | 3.1 | — |
| 13 | REST/gRPC correctness + status codes | 3.2 | 2 |
| 14 | Config validation completeness + dead-field reckoning | 3.3 | — |
| 15 | CLI rewrite on clap + real client | 4.1 | 2 |
| 16 | Dashboard consolidation (useApiList) + UX fixes | 4.2 | 4 |
| 17 | Dependency bumps + upstream clippy fixes | 4.3 | — |

PRs 1–3 are the security-critical path and should land before anything is exposed to a
network. 5–7 close the unauthenticated DoS/injection surface. Everything else can
proceed in parallel by subsystem.

## Compatibility notes
- **REST port moves 8080 → 8443 and scheme becomes `https`** — update the k8s/microk8s
  deploy manifests (readiness/liveness probes, Service ports), any dashboards, and the
  Kea/TEO provisioning URLs pointed at the daemon.
- Self-signed bootstrap means first-connect trust decisions for CLI/browser; document
  fingerprint pinning and the path to operator-provided certs.
- Existing `trunk_groups.json` files migrate on first save (plaintext → encrypted
  password field); keep a one-release fallback reader.
- gRPC clients must switch to TLS channel credentials; `enable_reflection` workflows need
  `grpcurl -insecure` or the CA cert.
