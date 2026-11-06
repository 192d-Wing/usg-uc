# USG Session Border Controller — Administrator Guide

## Overview

The USG SBC is a SIP Session Border Controller that provides:

- **B2BUA call control** — Back-to-back user agent with full call state management
- **SIP registration** — Binding storage and location service; REGISTER authentication via OIDC Bearer tokens (`SBC_AUTH_MODE=bearer`). Digest auth is compiled in but not configurable from `sbc.toml`; REGISTER is unauthenticated unless bearer mode is enabled.
- **Call routing** — Dial plans with pattern matching, number transforms, trunk selection
- **Media relay** — RTP/SRTP relay (anchored; no transcoding in the live relay path)
- **Header manipulation** — Per-trunk and global SIP header rewriting
- **Topology hiding** — Via/Contact/Call-ID anonymization
- **Rate limiting** — Per-IP and global DoS protection
- **gRPC management API** — Real-time call and registration monitoring (requires `--features grpc`)
- **High availability** — Optional shared registration state in Redis/PostgreSQL (requires `--features cluster`; automatic failover and call-state replication are planned — see [CLUSTERING.md](CLUSTERING.md))

### Architecture

``` mermaid
flowchart LR
    ua["SIP UA<br>(A-leg)"]
    subgraph sbc["USG SBC"]
        b2bua["B2BUA"]
        relay["RTP Relay"]
    end
    trunk["SIP Trunk / PSTN<br>(B-leg)"]
    ua <-->|SIP| b2bua
    b2bua <-->|SIP| trunk
    ua <-->|RTP| relay
    relay <-->|RTP| trunk
```

### Optional pods

The SBC ships as a single `sbc-daemon` binary (or container) that handles
all subsystems in-process. Two subsystems can be split out into dedicated
pods when the deployment grows beyond a single node:

| Pod | Env var switch | What it does |
| --- | --- | --- |
| `sbc-announcement-server` | `SBC_ANNOUNCEMENT_URL` | RTP playback of "number not in service" / "all circuits busy" announcements on a dedicated media node. The daemon retains the SIP dialog; the pod binds the UDP socket and streams PCMU audio. Falls back to in-process if the URL is unset or the pod is unreachable. |
| `sbc-trunk-agent` | `SBC_TRUNK_SERVICES=external` | Carrier REGISTER and SIP OPTIONS health loops running outside the daemon. Reads trunk config from Postgres and pushes status snapshots to the daemon via gRPC. **Deploy exactly one replica** — two agents would double-REGISTER to carriers. |

Both pods use the same fallback pattern: when the env var is absent or
the pod is unreachable, the daemon runs the subsystem in-process, so
single-node deployments require no configuration changes.

See [architecture.md](architecture.md) for the full pod topology diagram.

---

## Installation

### Build from Source

```bash
# Standard build
cargo build --release --bin sbc-daemon

# With gRPC management API
cargo build --release --bin sbc-daemon --features grpc

# With clustering support
cargo build --release --bin sbc-daemon --features full

# CLI tool (basic — status, config, calls, health, metrics)
cargo build --release --bin sbc-cli

# CLI tool with trunk subcommands (connects directly to daemon gRPC :9091)
cargo build --release --bin sbc-cli --features grpc
```

### Binary Location

```
target/release/sbc-daemon
target/release/sbc-cli
```

---

## Configuration

The SBC is configured via a TOML file (default: `sbc.toml`). All sections are optional with sensible defaults.

### Starting the SBC

```bash
# Default config
./sbc-daemon

# Custom config file
./sbc-daemon -c /etc/sbc/sbc.toml

# Verbose logging
./sbc-daemon -c sbc.toml -vvv
```

### Minimal Configuration

```toml
[general]
instance_name = "sbc-01"
max_calls = 10000
max_registrations = 50000

[transport]
udp_listen = ["0.0.0.0:5060"]
```

---

## General Settings

```toml
[general]
# Unique name for this SBC instance (used in Via/Contact headers)
instance_name = "sbc-prod-01"

# Optional cluster identifier
cluster_id = "dc-east-1"

# Maximum concurrent calls
max_calls = 10000

# Extra concurrent calls above max_calls that only emergency calls may use
# (see "Emergency Calls"). Default: 10% of max_calls, at least 1. When set it
# must be 1..=max_calls.
# emergency_reserve_calls = 1000

# Upper bound (seconds) for a trunk's Retry-After on 503. Default 300,
# accepted range 1..=3600.
trunk_retry_after_max_secs = 300

# Maximum registration bindings per node (enforced). Counted by binding key
# (+sip.instance/reg-id, else contact URI) after authentication; a REGISTER
# that would exceed it gets 503 Retry-After: 60. Refreshes, re-registration
# of an existing binding and de-registration are always allowed. 0 is rejected.
max_registrations = 50000
```

---

## Transport Configuration

```toml
[transport]
# UDP listen addresses. A [::] wildcard is dual-stack (IPV6_V6ONLY=0):
# one socket serves IPv4 and IPv6; v4-mapped sources are canonicalized.
udp_listen = ["[::]:5060"]

# SIP-over-TCP listen addresses (dual-stack on [::] like UDP).
tcp_listen = ["[::]:5060"]

# SIP-over-TLS listen addresses. Requires security.tls_cert_path /
# tls_key_path — when the cert paths are not set, TLS listeners are
# skipped at startup with a warning (the daemon serves UDP/TCP only).
tls_listen = ["[::]:5061"]

# SIP over WebSocket (RFC 7118), plain ws only. The WebSocket transport
# does not terminate TLS, so `wss_listen` is rejected by validate_config:
# terminate TLS at a reverse proxy in front of ws_listen, or use tls_listen.
ws_listen = ["0.0.0.0:8080"]
```

If no listeners are configured, the SBC binds to `[::]:5060` (IPv6 with IPv4 fallback).

Stream transports (TCP/TLS) frame messages by `Content-Length`
(RFC 3261 §18.3) and return responses over the connection the request
arrived on. Failed TLS handshakes are logged and do not stop the
listener.

> **Note:** setting `security.tls_cert_path` also activates HTTPS on the
> REST API. Unless `transport.api_tls_listen` is set, the API server
> switches its main listener to HTTPS-only; set `api_tls_listen` (e.g.
> `"0.0.0.0:8443"`) to keep HTTP on `api_listen` and serve HTTPS
> side-by-side. The Helm chart does this automatically when
> `sbcDaemon.sipTls.secretName` is set.

---

## SIP Registration

The SBC acts as a B2BUA registrar, storing user bindings in an in-memory location service. When clustering is enabled, bindings are replicated to Redis or PostgreSQL.

Registration is automatic — any SIP UA that sends a REGISTER request will have its bindings stored. The only authentication mode that can be enabled on a running daemon is OIDC Bearer tokens (RFC 8898, `SBC_AUTH_MODE=bearer` plus `SBC_OIDC_ISSUER` — the mode used by the soft client's sign-in flow). Without it the daemon logs `REGISTER is UNAUTHENTICATED: any peer can register any user` at startup.

### Transport to registered phones

A REGISTER records the source address and the transport it actually arrived on (not the `Via` or the Contact `transport=`). Calls to that phone go back on the same flow: UDP to the source address, or the phone's own accepted TCP/TLS connection. The SBC never dials a phone and never falls back to UDP. If a TCP/TLS-registered phone's connection has closed, the INVITE is not sent and the caller gets a 503 until the phone reconnects and registers again. Before this change such calls went out over UDP. A binding with a TCP/TLS Contact but no recorded flow (for example one created by the API or replicated from another node) is not routed.

### Authentication

- **Bearer (wired)**: set `SBC_AUTH_MODE=bearer` and `SBC_OIDC_ISSUER` (optionally an extra CA for the internal IdP). Tokens are validated via `proto-jwt` (JWKS cache). Note: the validator currently accepts `RS256`, `PS256`, `ES256` and `ES384` tokens.
- **Digest (not configurable)**: the `SipStackConfig` fields `require_auth`, `auth_realm` and `auth_credentials` exist in `sbc-daemon/src/sip_stack.rs`, but `build_sip_config` never populates them from `sbc.toml` or the environment, so digest REGISTER auth cannot be turned on without a code change (planned).

---

## Call Routing

### Overview

When an INVITE arrives, the SBC routes it through this pipeline:

1. **Location Service lookup** — check if the destination is a registered user
2. **Dial plan matching** — match the Request-URI against dial plan entries
3. **Trunk selection** — select the best trunk from the matched trunk group
4. **Number transformation** — apply prefix strip/add/replace transforms
5. **Failover** — if the selected trunk fails, try the next trunk in order

### Routing Configuration

```toml
[routing]
# Enable dial plan-based routing
use_dial_plan = true

# Maximum trunk failover attempts per call
max_failover_attempts = 3

# Default trunk group when no dial plan entry matches
default_trunk_group = "us-domestic"
```

### Dial Plans

Dial plans contain entries that match call destinations by pattern, direction, domain, and source trunk.

```toml
[[dial_plans]]
id = "main"
name = "Production Dial Plan"
active = true
```

### Dial Plan Entries

Each entry specifies what to match and where to route:

```toml
# Outbound: US domestic calls
[[dial_plans.entries]]
direction = "outbound"          # inbound, outbound, or both
pattern_type = "prefix"         # exact, prefix, wildcard, or any
pattern_value = "+1"
trunk_group = "us-domestic"
transform_type = "strip_prefix" # none, strip_prefix, add_prefix, replace_prefix
transform_value = "2"           # strip "+1" (2 chars)
priority = 10                   # lower = higher priority

# Outbound: international calls via access code
[[dial_plans.entries]]
direction = "outbound"
pattern_type = "prefix"
pattern_value = "011"
trunk_group = "international"
transform_type = "replace_prefix"
transform_value = "011|+"       # "011" becomes "+"
priority = 20

# Inbound: calls from BulkVS to @uc.mil domain → downstream call manager
[[dial_plans.entries]]
direction = "inbound"
source_trunk = "bulkvs-1"       # only match calls from this trunk
domain_pattern = "uc.mil"       # match uc.mil and *.uc.mil
pattern_type = "prefix"
pattern_value = ""              # match any number
trunk_group = "downstream-cm"
destination_type = "trunk_group"
priority = 5

# Inbound: DID to registered user
[[dial_plans.entries]]
direction = "inbound"
pattern_type = "prefix"
pattern_value = "+1555"
destination_type = "registered_user"  # look up in location service
transform_type = "strip_prefix"
transform_value = "5"                 # strip "+1555" → local ext
priority = 15

# Emergency: matches both directions
[[dial_plans.entries]]
direction = "both"
pattern_type = "exact"
pattern_value = "911"
trunk_group = "emergency"
priority = 1

# Wildcard: 11-digit US dialing
[[dial_plans.entries]]
direction = "outbound"
pattern_type = "wildcard"
pattern_value = "1XXXXXXXXXX"   # X = any digit
trunk_group = "us-domestic"
transform_type = "add_prefix"
transform_value = "+"           # add + prefix
priority = 30

# Voicemail: static destination
[[dial_plans.entries]]
direction = "both"
pattern_type = "exact"
pattern_value = "*86"
destination_type = "static_uri"
static_destination = "sip:voicemail@vm.uc.mil:5060"
priority = 1
```

#### Pattern Types

| Type | Example | Matches |
|------|---------|---------|
| `exact` | `"911"` | Only `"911"` |
| `prefix` | `"+1"` | `"+15551234567"`, `"+1800..."` |
| `wildcard` | `"1XXXXXXXXXX"` | 11-digit numbers starting with 1 (`X` = any digit, `.` = any remaining) |
| `any` | — | Matches everything |

#### Direction

| Value | Meaning |
|-------|---------|
| `outbound` | Calls from registered users to external destinations |
| `inbound` | Calls arriving from trunks to internal destinations |
| `both` | Matches in either direction |

#### Destination Types

| Value | Behavior |
|-------|----------|
| `trunk_group` | Route to the specified trunk group (default) |
| `registered_user` | Look up the (transformed) number in the location service |
| `static_uri` | Route to a fixed SIP URI |

#### Number Transforms

| Type | Value | Example |
|------|-------|---------|
| `none` | — | No transformation |
| `strip_prefix` | `"2"` (count) | `"+15551234567"` → `"5551234567"` |
| `add_prefix` | `"+"` (prefix) | `"15551234567"` → `"+15551234567"` |
| `replace_prefix` | `"011\|+"` (from\|to) | `"01144..."` → `"+44..."` |

#### Domain Matching

The `domain_pattern` field matches the host part of the Request-URI:

- `"uc.mil"` — matches `uc.mil` and `sip.uc.mil` (suffix match)
- `"*.mil"` — matches any `.mil` domain
- Omitted — matches any domain

#### Source Trunk Filtering

The `source_trunk` field restricts an entry to calls arriving from a specific trunk:

```toml
source_trunk = "bulkvs-1"  # only match calls from this trunk ID
```

This enables different routing for the same number pattern based on which carrier delivered the call.

---

## Trunk Groups

Trunk groups define collections of SIP trunks (carriers, gateways, downstream systems) with selection strategies and failover.

```toml
[[trunk_groups]]
id = "us-domestic"
name = "US Domestic Trunks"
strategy = "least_connections"   # selection strategy

  [[trunk_groups.trunks]]
  id = "bulkvs-1"
  host = "sip.bulkvs.com"
  port = 5060
  protocol = "udp"               # udp, tcp, or tls — see note below
  priority = 1                   # lower = preferred
  weight = 70                    # for weighted selection
  max_calls = 200                # capacity limit
  cooldown_secs = 30             # recovery time after failures
  max_failures = 5               # failures before cooldown

  [[trunk_groups.trunks]]
  id = "bulkvs-2"
  host = "sip2.bulkvs.com"
  port = 5060
  protocol = "udp"
  priority = 1
  weight = 30
  max_calls = 200

  [[trunk_groups.trunks]]
  id = "telnyx-backup"
  host = "sip.telnyx.com"
  port = 5060
  protocol = "tls"               # needs security.trunk_tls_ca_path and transport.tls_listen
  priority = 2                   # lower priority = used for failover
  max_calls = 100
```

> **Trunk `protocol`**: every request toward a trunk (INVITE, failover INVITE, ACK, CANCEL, BYE, re-INVITE, retransmissions) is sent over the trunk's own protocol. For `tcp` and `tls` the SBC opens and reuses an outbound connection and reads the trunk's responses from it. A `tls` trunk gets a `sips:` Request-URI and a `SIP/2.0/TLS` Via with the `tls_listen` port. A `tls` trunk needs `transport.tls_listen`, and a `tcp` trunk needs `transport.tcp_listen`; otherwise the config is rejected. A trunk that stops reading has its connection closed after a 2 s write deadline, and the INVITE fails over. A failed dial is remembered for 2 s, and sends to that trunk inside that window fail at once. Its certificate is always verified against `security.trunk_tls_ca_path` (required once any trunk uses TLS) and against `tls_server_name`, or against `host` when that is unset. An IP-literal host is matched against an IP SAN. If the handshake or verification fails, the call fails over to the next trunk on that trunk's protocol, or the caller gets a 503. The SBC never retries over plaintext.
>
> ```toml
> [security]
> trunk_tls_ca_path = "/etc/sbc/trunk-ca.pem"   # CAs for trunk server certs (not tls_ca_path)
>
>   [[trunk_groups.trunks]]
>   protocol = "tls"
>   tls_server_name = "sip.telnyx.com"   # optional; defaults to host
>   tls_client_cert = false              # true: present security.tls_cert_path (mTLS)
> ```
>
> `tls_server_name` and `tls_client_cert` are accepted only on `tls` trunks. `tls_server_name` must be a DNS name or IP address without a port. `tls_client_cert = true` needs `security.tls_cert_path` / `tls_key_path`. `security.min_tls_version` applies to trunk connections too. Cipher suites are not restricted. A TLS handshake or verify failure is logged as a warning and counted in `sip_egress_connect_failures_total`; it does not produce its own audit event. Trunk connects time out after 5 s, and the SBC holds at most 1024 trunk connections.
>
> A group may mix `tls` and `udp`/`tcp` trunks. Without `require_tls`, failover from a TLS trunk to a UDP trunk is allowed and sends that attempt in clear. Set `require_tls` (below) if plaintext failover is not acceptable.

### TLS-only trunk groups (`require_tls`)

NIST 800-53 Rev5 SC-8 (POA&M-48 closed). Set `require_tls = true` on a group to keep every call routed to it off clear-text transports:

```toml
[security]
trunk_tls_ca_path = "/etc/sbc/trunk-ca.pem"
require_tls_trunks = false      # true: every trunk group is TLS-only; groups cannot opt out

[[trunk_groups]]
id = "pstn"
require_tls = true              # default false
```

- Primary selection and every failover hop consider only trunks with `protocol = "tls"`, whatever the selection strategy. UDP/TCP trunks in the group stay configured, health-checked and visible. They are just never selected for this group.
- If no TLS trunk is usable, the INVITE gets **503** and is never tried over UDP/TCP. When the policy is the cause (only UDP/TCP trunks could have taken the call, or the group has no trunk at all), the 503 carries `Reason: Q.850;cause=79;text="no TLS trunk"` and **no Retry-After** (retrying cannot help). When the TLS trunks are down, cooling down or at `max_calls`, the 503 carries Retry-After as for "no usable trunk".
- **`sips:` calls:** an INVITE whose Request-URI is `sips:` is TLS-only in every group on its route, with or without `require_tls`, including failover and the next group in a route list (RFC 3261 §26.2.2). A `sip:` INVITE is unaffected.
- **Audit:** when the policy causes the refusal (a UDP/TCP trunk would otherwise have taken the call), the record is `InviteDenied` with reason `no-tls-trunk`. When the TLS trunks are simply down or full, the reason stays `no-usable-trunk`. The CDR is 503 / `NoRoute` in both cases.
- **Metrics** (unlabelled, monotonic): `routing_tls_required_skips` counts non-TLS trunks excluded, per routing decision. `routing_tls_required_rejects` counts group-level refusals; a later group in the route may still carry the call, so it is not a count of failed calls.
- **Reload:** `require_tls`, `security.require_tls_trunks` and any `[[trunk_groups]]` edit take effect only after a **restart**. A SIGHUP reload stores them but reports them under `restart_required` and logs a warning.
- **CA check:** a TLS trunk arriving through the API/TrunkSync while `security.trunk_tls_ca_path` is unset logs an error at startup replay and on every sync; such a trunk cannot connect (calls fail closed).
- **Audit of changes:** sbc-api-server trunk-group/trunk create, update and delete, and central-config trunk-group upserts and deletes, write a `ConfigurationChange` record (who, group, old -> new `require_tls`, changed trunk protocols, outcome) when `require_tls` or a trunk protocol changes.
- **Validation:**
  - Config file: a group with `require_tls` (or any group, when `security.require_tls_trunks` is set) must contain a `tls` trunk, otherwise the config is rejected. An empty group is also rejected.
  - REST API (`/api/v1/trunkgroups` group create/update and the `/trunks` add, update and delete calls): a non-bool `require_tls` or a protocol outside `udp`/`tcp`/`tls` returns **400**. A `require_tls` group that has trunks but no TLS trunk returns **422** and nothing is stored. This also applies to deleting the last TLS trunk. An empty `require_tls` group is accepted with `"warnings": ["require_tls group has no TLS trunk; calls will be rejected"]`, so a group can be created first and its trunks added after.
  - Central config: the same checks apply, except that an empty `require_tls` group also returns 422.
  - The sbc-api server cannot see the daemon's `security.require_tls_trunks`. With the global key on, a TLS-less API group is refused at call time (503 plus the metric and audit record above).
- **API/synced trunk transport:** API, TrunkSync, config-store and central trunks use `protocol` or, if that is absent, `transport` (the dashboard field). Values are `udp`, `tcp` or `tls`, case-insensitive. An absent value means `udp`. An unknown value causes the daemon to skip that trunk with a warning. An absent `port` means 5061 for TLS and 5060 otherwise; a port outside 1-65535 is rejected by the APIs (400) and skipped by the daemon. A non-bool `require_tls` reaching the daemon is treated as `true` (fail closed). `tls_server_name` and `tls_client_cert` are read for TLS trunks.
- **central-config-api exit codes:** 0 clean shutdown, 2 configuration error, 3 state (store) init failure, 4 listener bind failure, 5 server error while running, 6 audit logger init failure (the service refuses to start without its audit trail).
- **Per group only (POA&M-57).** A route (route list or dial plan) that names a TLS-only group and then a plain group can still fail over to the plain group's UDP trunks for a `sip:` call. Set `require_tls` on every group in the route, or use `security.require_tls_trunks`.
- Turning `security.require_tls_trunks` off does not clear the flag on groups already loaded (fails safe); restart to apply.
- **Signaling only:** `require_tls` does not require SRTP on the B-leg. Configure media security separately. Cipher suites are still unrestricted (POA&M-26).
- **Clusters:** upgrade every node before enabling the flag. Older nodes ignore it and also send API trunks over UDP.

### Trunk transport: breaking changes (POA&M-5)

- A config with any `protocol = "tls"` trunk is rejected unless `security.trunk_tls_ca_path` is set to an absolute path. Setting it with no TLS trunk is also rejected. The public web PKI is not trusted for trunks.
- A `tls` trunk without `transport.tls_listen`, or a `tcp` trunk without `transport.tcp_listen`, is rejected.
- The B-leg Request-URI host and port are now the trunk's `host` and `port` (`sips:` for TLS, `;transport=tcp` for TCP) instead of the dialled host. Trunks that expected the SBC domain in the Request-URI need a header-manipulation rule or a config change.
- B-leg transaction timers follow the trunk's protocol, not the caller's: a TCP caller to a UDP trunk now gets UDP retransmissions on the B-leg.
- Calls to registered phones use the transport the phone registered on (see SIP Registration).

### Selection Strategies

| Strategy | Behavior |
|----------|----------|
| `priority` | Always select the trunk with the lowest priority number |
| `round_robin` | Cycle through trunks in order |
| `weighted_random` | Random selection weighted by `weight` field |
| `least_connections` | Select the trunk with fewest active calls |
| `best_success_rate` | Select the trunk with highest success rate (auto-learns) |

### Trunk Failover

The SBC router and the dial-plan router return the selected route groups; the remaining usable trunks, in selection order, form the failover list (capped by `routing.max_failover_attempts`).

The call moves to the next trunk when the current trunk answers **408, 500, 502, 503 or 504**, when Timer B fires, or when the trunk URI cannot be resolved. 503 and timeouts are the RFC 3263 §4.3 triggers; 500/502/504 are local B2BUA policy. The SBC does **not** fail over on any other 4xx (for example 486) or on 6xx; those are relayed to the caller. It also does not fail over once a 2xx or a reliable (100rel) 18x carrying SDP has been relayed to the caller; a 180 without SDP, an unreliable 183, or a reliable 18x without SDP does not stop failover.

Each failover attempt is a new B-leg INVITE (new Call-ID, branch, From tag, CSeq) with the same SDP and the translated number. Intermediate failures are not shown to the caller. When all trunks are exhausted, the last trunk's final response is relayed (Timer B exhausted gives 408).

A transport error on the **first send** of a B-leg INVITE also fails over at once, without waiting for Timer B (32 s): a UDP send error, a TCP/TLS connect, handshake or write failure, or the 30 s send timeout. The failed attempt counts as a trunk failure but does not start a cooldown, and each attempt fails over at most once. If no trunk is left the caller gets 503 (RFC 3261 §8.1.3.1). Send failures of retransmissions, ACK, CANCEL and in-dialog requests are only logged.

Limitations: the failover INVITE keeps the original Request-URI host and scheme and the UDP Via transport (see the POA&M in [NIST-800-53-CONTROLS.md](NIST-800-53-CONTROLS.md)).

### Trunk Capacity and Cooldown

- `max_calls` is enforced **per SBC node**. A trunk at `max_calls` is skipped. When every trunk in the route is full or down, the caller gets `503` with `Retry-After: 5`. `max_calls = 0` is rejected by validation.
- A trunk that answers 503 goes into cooldown. If the 503 carries `Retry-After` with delta-seconds, the cooldown is that many seconds (down to 1 s), capped at `general.trunk_retry_after_max_secs` (default 300, max 3600). A trailing comment or `;duration=` parameter is ignored. A missing, zero or malformed value uses `cooldown_secs`.
- Emergency calls may exceed a trunk's `max_calls` by its `emergency_reserve_calls` (default 10% of `max_calls`, at least 1; when set must be 1..=`max_calls`). Normal calls never use the reserve.
- After `max_failures` consecutive failures a trunk enters cooldown for `cooldown_secs` and is excluded from selection; it becomes available again afterwards. `max_failures = 0` is rejected.

### Emergency Calls

Emergency numbers are set in the VPS section and apply whether or not the VPS is enabled. If `[vps]` is absent or disabled, the default list is used.

```toml
[vps]
# Exact match on the dialed Request-URI user, before number translation.
# "+" and visual separators (- . ( ) space) are ignored; no prefix match
# (9111 and 988 are not emergency numbers). At most 32 entries of at most
# 32 characters, using digits, *, # and +. An empty list turns the bypass
# off (a warning is logged at startup).
emergency_numbers = ["911", "933", "112"]
```

For an emergency call the SBC skips the VPS caller-prefix blocklist, rate limits, `per_callee_max_concurrent`, STIR/SHAKEN screening and deny rules. It can use the emergency reserve above `general.max_calls` and above each trunk's `max_calls`. Past `max_calls + emergency_reserve_calls` it gets 503 like any other call; that 503 carries no `Retry-After`.

Still enforced for emergency calls: operator source-IP block entries in the VPS, source admission (ACL), authentication, the per-source-IP flood limiter, draining, Max-Forwards, trunk reachability and trunk cooldown.

Each admitted emergency call is audited as an `AuthorizationDecision` with `policy = "emergency-bypass"` and the source IP, and counted in `sbc_emergency_calls_admitted`.

### Trunk OPTIONS Health

Config-file trunks can be probed with SIP OPTIONS:

```toml
  [[trunk_groups.trunks]]
  id = "bulkvs-1"
  # ...
  options_ping_enabled = true        # default false
  options_ping_interval_secs = 30    # default 30; must be 5..=3600 when enabled
```

A trunk that the OPTIONS monitor (or, in agent mode, a gRPC `PublishTrunkStatus` report) marks down is skipped by new calls; in-flight calls are not affected. It is used again when it is marked up. Trunks created through the API are monitored the same way.

### Number Translation

The translated number from the SBC router (`transformed_number`) or the dial plan (`destination`) is written to the user part of the B-leg Request-URI and To header (also on failover attempts). The per-callee concurrency limit (`per_callee_max_concurrent`) is keyed on the dialed number, before translation. A translated number longer than 64 characters or containing characters outside the RFC 3261 unreserved/user-unreserved set (for example `;`, `?`, `%`, `@`, `<`, `>`, spaces or line breaks) is rejected: the caller gets 500 and nothing is sent to the trunk. The Request-URI host is still taken from the A-leg Request-URI, not from the trunk.

---

## Media Configuration

```toml
[media]
# Media relay mode: only "Relay" is accepted. "PassThrough" and
# "SignalingOnly" are rejected by validation; media.realm_modes must be empty.
default_mode = "Relay"

# Must be the default set (order-insensitive); any other list is rejected
codecs = ["Opus", "G722", "G711Ulaw", "G711Alaw"]

# RTP port range for media relay
rtp_port_min = 16384
rtp_port_max = 32768

[media.srtp]
# Require SRTP encryption (CNSA 2.0: AEAD_AES_256_GCM is the only profile)
required = true
profile = "AeadAes256Gcm"        # only value; the relay rejects any other profile
# "Relay" passes DTLS-SRTP through end-to-end; "Terminate" has the SBC
# terminate DTLS-SRTP on each leg (requires [media.dtls] sidecar_socket
# and fingerprint_file — the daemon aborts at startup otherwise).
mode = "Relay"

[media.dtls]
# Optional operator-provided DTLS identity; when unset the SBC generates a
# self-signed P-384 certificate at startup.
cert_path = "/etc/sbc/dtls-cert.pem"
key_path = "/etc/sbc/dtls-key.pem"
fingerprint_hash = "Sha384"      # Sha384 (default) or Sha512
# Required when srtp.mode = "Terminate": the Go DTLS-SRTP terminator
# sidecar's Unix socket and the file it publishes its fingerprint to.
sidecar_socket = "/run/sbc/dtls-sidecar.sock"
fingerprint_file = "/run/sbc/dtls-fingerprint"
```

Values for `profile`, `fingerprint_hash` and `codecs` are the Rust enum variant names (see `deploy/config/config.toml` for the canonical example).

### Media Mode and Codecs

The live relay always anchors media (`Relay`) and does not transcode. The `Transcoder` in `sbc-media-core` is not in the live relay path. Validation therefore rejects:

- `media.default_mode` other than `"Relay"` (the `sbc-media` pod also refuses any `SBC_MEDIA_DEFAULT_MODE` other than `relay` at startup);
- any entry in `media.realm_modes`;
- a `media.codecs` list that is not exactly the default set (order does not matter; subsets, single codecs and duplicates are rejected; an empty list is rejected by the "at least one codec" check).

Codec names:

| Codec | Config name | Payload Type | Clock Rate | Bandwidth |
|-------|-------------|-------------|------------|-----------|
| G.711 u-law (PCMU) | `G711Ulaw` | 0 | 8 kHz | 64 kbps |
| G.711 A-law (PCMA) | `G711Alaw` | 8 | 8 kHz | 64 kbps |
| G.722 | `G722` | 9 | 16 kHz | 64 kbps |
| Opus | `Opus` | 111 (dynamic) | 48 kHz | 6-510 kbps |

---

## Header Manipulation

SIP header manipulation rules can be applied globally or per-trunk.

```toml
[header_manipulation]

# Global rules (applied to all calls)
[[header_manipulation.global_rules]]
name = "strip-internal-headers"
direction = "outbound"           # inbound, outbound, or both
action = "remove"                # add, set, remove, replace, prepend, append
header = "X-Internal-ID"

[[header_manipulation.global_rules]]
name = "add-sbc-id"
direction = "outbound"
action = "add"
header = "X-SBC-Instance"
value = "sbc-prod-01"

# Per-trunk rules
[[header_manipulation.trunk_rules]]
trunk_id = "bulkvs-1"
name = "set-user-agent"
action = "set"
header = "User-Agent"
value = "USG-SBC/1.0"

[[header_manipulation.trunk_rules]]
trunk_id = "bulkvs-1"
name = "strip-pai"
action = "remove"
header = "P-Asserted-Identity"
```

### Actions

| Action | Behavior |
|--------|----------|
| `add` | Add a new header (allows duplicates) |
| `set` | Set header value (replaces if exists, adds if not) |
| `remove` | Remove all instances of the header |
| `replace` | Replace a pattern in the header value |
| `prepend` | Add a prefix to the header value |
| `append` | Add a suffix to the header value |

---

## Topology Hiding

Topology hiding prevents internal network information from leaking to external networks.

```toml
[topology_hiding]
enabled = true
mode = "full"                    # none, signaling_only, or full
external_host = "sbc.uc.mil"    # hostname to present externally
external_port = 5060
obfuscate_call_id = true         # replace internal Call-IDs
```

### Modes

| Mode | Behavior |
|------|----------|
| `none` | No topology hiding |
| `signaling_only` | Anonymize Via headers, replace internal IPs |
| `full` | Anonymize Via, Contact, Record-Route, and optionally Call-ID |

---

## Security

### TLS Configuration

```toml
[security]
tls_cert_path = "/etc/sbc/tls-cert.pem"
tls_key_path = "/etc/sbc/tls-key.pem"
min_tls_version = "1.3"         # "1.3" (default) or "1.2"; applied to SIP-TLS listeners
curve = "P384"                   # P384 or P521; validated only (see note)
require_mtls = false             # SIP-TLS clients must present a certificate (needs tls_ca_path)
# tls_ca_path = "/etc/sbc/client-ca.pem"   # PEM bundle of CAs issuing client certificates
```

Notes on what the daemon actually does with these keys:

- `tls_cert_path` / `tls_key_path` (wired): used for SIP-over-TLS listeners (`transport.tls_listen`) and REST HTTPS. Must be set together.
- `min_tls_version` (wired): SIP-TLS listeners accept TLS 1.3 only by default; `"1.2"` also admits TLS 1.2 clients. Cipher suites are not restricted beyond the protocol version. The REST HTTPS listener uses rustls defaults (TLS 1.2 permitted) and is not affected by this key.
- `curve` only constrains the configuration enum; the key type of the loaded certificate is not checked (P-256/RSA certificates are accepted by rustls).
- `trunk_tls_ca_path` (wired): PEM bundle of the CAs that issue trunk server certificates. Required when any trunk uses `protocol = "tls"`; separate from `tls_ca_path` (client CA for the listener). See Trunk Groups.
- `require_mtls` (wired for SIP-TLS and gRPC): the SIP-TLS listener requires a client certificate chaining to `tls_ca_path`; `validate_config` rejects `require_mtls = true` without `tls_cert_path` and `tls_ca_path`. The gRPC listener has its own `[grpc] require_mtls` / `tls_ca_path`.

### Rate Limiting

```toml
[rate_limit]
enabled = true
global_rps = 10000              # Global requests per second
per_ip_rps = 100                # Per source IP
per_user_rps = 50               # Per From user (after parsing); 0 disables. Over the rate → 503 + Retry-After: 1
burst_multiplier = 2.0          # Allow short bursts
```

`global_rps` and `per_ip_rps` feed two `uc-dos-protection` token-bucket limiters in `sbc-daemon/src/server.rs`. `general.max_calls` additionally rejects INVITEs with 503 once the concurrent-call limit is reached. When rate limits are exceeded:

- **Throttle**: Suggested delay (logged at debug level, message still processed)
- **Reject**: Message silently dropped (`rate_limited` stat incremented)
- **Block**: Message dropped and the source remains blocked for the limiter's block duration

---

## Logging

```toml
[logging]
level = "info"                   # trace, debug, info, warn, error
format = "json"                  # json or text
output = "stdout"                # stdout, stderr, or a file path (appended)
audit_enabled = false            # NIST AU-2 audit trail (uc-audit, SHA-384 hash-chained records)
audit_path = "/var/log/sbc/audit.log"   # JSON lines; omit to emit audit records on the log (target "audit")
```

`level` is the base log level; `-v` / `-vv` raise it to debug / trace and `RUST_LOG`, when set, overrides the filter entirely. The subscriber is configured from this section before anything else logs. With `audit_enabled`, the daemon records startup/shutdown, REGISTER authentication outcomes (bearer or digest), INVITE admission and VPS rejections, call establishment and termination (with duration and reason), rate-limit rejections, emergency-bypass grants, trunk failovers (`TrunkFailover`, reason: status, timeout or transport error) and trunk reachability changes (`TrunkReachabilityChanged`, source: OPTIONS or trunk agent). `AuthorizationDecision` records carry `source_ip` when it is known. Each record carries a sequence number and a SHA-384 hash chain for tamper evidence (`uc-audit`).

Audit writes never block call handling. Records go onto a queue of 4096 and a background thread writes them. If the queue is full or the writer thread has died, the record is **dropped** and counted, and an error is logged at most once every 10 s. On shutdown the daemon waits up to 2 s for the queue to drain; records still queued after that are lost. Watch these:

- health component `audit`: unhealthy when the writer thread has exited; degraded while the last dropped record is less than 60 s old (message `N audit records dropped, last Ns ago`), healthy again after that. The 60 s window is fixed, not configurable;
- gauge `sbc_audit_records_dropped` (records dropped since start; never reset). Because health recovers after 60 s, a short burst of drops between health polls can leave no trace in health status. Alert on any increase of this counter (for example `increase(sbc_audit_records_dropped[5m]) > 0`), not only on the `audit` health status;
- gauge `sbc_audit_writer_alive` (1 or 0);
- gauge `sbc_emergency_calls_admitted` (emergency calls admitted so far).

---

## STIR/SHAKEN

The SBC can sign outbound INVITEs (authentication service, RFC 8224 §5) and verify inbound Identity headers (verification service, RFC 8224 §6.2, ATIS-1000074). Both are off by default and enabled per trunk.

**Breaking change (0.10):** `verification_enabled` now defaults to `false` (it was `true` and verified nothing). The flat keys `certificate_path`, `private_key_path`, `certificate_url`, `ca_bundle_path`, `default_attestation` and `max_passport_age_secs` are accepted for one release as deprecated aliases (a warning is logged) and map to the nested keys below. `default_attestation` now defaults to `C`.

```toml
[stir_shaken]
signing_enabled = true
verification_enabled = true
algorithm = "ES256"                    # SHAKEN mandates ES256 (CNSA exception); ES384 is rejected

[stir_shaken.signing]
certificate_url = "https://certs.example.com/sti.pem"   # x5u; https only
private_key_path = "/etc/sbc/certs/sti.key"             # PKCS#8 P-256; regular file, mode 0600/0400, owned by the SBC user, not a symlink
certificate_path = "/etc/sbc/certs/sti.pem"             # must match the key, be valid now, carry TNAuthList
key_source = "file"                                     # "pkcs11" is reserved and rejected

[stir_shaken.attestation]
default = "C"
owned_numbers = ["1202555*"]          # A needs an owned number provisioned for the caller's own registration (see below); authenticated otherwise = B
[[stir_shaken.attestation.rules]]     # evaluated first; first match wins
source_trunk = "pbx-group"
orig_prefix = "1703"
attest = "B"

[stir_shaken.verification]
failure_policy = "mark"               # "mark" (verstat=TN-Validation-Failed, continue) | "pass-through" | "reject"
require_identity = false              # true: 428 when a verify trunk sends no Identity
trust_anchors_path = "/etc/sbc/certs/sti-cr"   # STI-CR PEM bundle or directory (*.pem/*.crt/*.cer)
trust_anchor_refresh_secs = 86400     # also reloaded on SIGHUP
cert_fetch_timeout_ms = 1500          # 100..=5000
cert_cache_entries = 4096             # 1..=100000
cert_cache_ttl_secs = 3600            # capped by Cache-Control and the cert's notAfter
negative_cache_ttl_secs = 60
max_cert_bytes = 16384
max_concurrent_fetches = 32           # beyond this (or 4 per x5u host) an INVITE fails fast (cert-fetch-busy)
x5u_allow_hosts = []                  # optional allow-list; empty = any public host on port 443
max_passport_age_secs = 60

[[trunk_groups.trunks]]
id = "carrier-a"
host = "198.51.100.10"
stir_shaken = { sign = true, verify = true, strip_inbound_identity = true }
```

Per-trunk `sign`/`verify` require the global switch; validation rejects them otherwise. `strip_inbound_identity = false` marks a trunk trusted: its Identity headers are relayed to the B-leg verbatim and the call is not re-signed.

**Signing.** The PASSporT is signed after routing, number translation and header manipulation, so `orig`/`dest` match the wire: `orig` is the B-leg P-Asserted-Identity user (else From), `dest` the B-leg Request-URI user. The B-leg From stays the SBC's own identity. Toward a `sign = true` trunk the SBC adds a P-Asserted-Identity with the caller's number (unless a header-manipulation rule already set one): the A-leg P-Asserted-Identity when the call comes from a configured trunk (RFC 3325 trust domain; a PAI from any other source is ignored), else the A-leg From user when the source is a trunk or an authenticated endpoint. The value is rebuilt as `<sip:NUMBER@domain;user=phone>`. The B-leg `Date` header is set to the signing time, replacing any relayed A-leg `Date`, so it matches `iat` (RFC 8224 §4.1). If no number qualifies, the INVITE is sent unsigned and a `StirSignFailure` (`bad-number`) is audited. Trunks with `sign = false` get no added PAI.

**Attestation for registered endpoints.** A call from a registered phone (not a trunk) counts as authenticated only when REGISTER authentication is enabled and the INVITE arrives from the same source IP, port and transport on which a successful REGISTER for that AOR was received, and that registration is still live. The From user must be the AOR user or a DID mapped to it. Consequences:

- **A** requires a REGISTER over **TCP or TLS** and the INVITE on that same flow, with the calling number provisioned for that registration and listed in `owned_numbers`.
- **UDP-registered phones get at most B**, because a UDP source can be spoofed and the SBC does not challenge INVITEs.
- Bindings created through the management API or by cluster replication, and phones registered on another cluster node, do not count. Calls from them get the default (C) unless a rule matches.
- These limits apply to the built-in decision. `[[stir_shaken.attestation.rules]]` are evaluated first and set whatever level they name, so a rule with `attest = "A"` overrides them; write rules accordingly.
- TCP/TLS flows are matched by address and port, not by connection, so behind a shared NAT a reused source port can inherit the previous phone's binding until it expires (POA&M-36). On failover the Identity is removed and the step is redone for the next trunk: re-signed with a fresh `iat` if it signs, no Identity or added PAI if it does not (a relayed Identity from a trusted ingress trunk is relayed again).

**Verification.** The certificate named by `info`/`x5u` is fetched over HTTPS only, after an SSRF check (loopback, private, link-local/metadata, CGNAT, multicast, ULA, documentation and mapped forms are refused; the connection goes to the vetted address; no redirects; body and time limits), validated to the trust anchors, and cached. A cache miss waits up to `cert_fetch_timeout_ms`. The result sets `verstat` on the B-leg P-Asserted-Identity URI (on the From only when there is no PAI), is passed to `[vps.stir_shaken]` screening (so `mode = "enforce"` with `minimum_attestation` can block), and is recorded in the CDR. `reject` answers 436 Bad Identity Info (bad info / certificate unobtainable), 437 Unsupported Credential (untrusted certificate / algorithm), 403 Stale Date (`iat` outside `max_passport_age_secs`) or 438 Invalid Identity Header (any other failure), with `Reason: SIP;cause=<code>;text="..."`; 428 Use Identity Header with `require_identity`. `ppt=div` PASSporTs are ignored (RFC 8946 is not implemented). There is no replay cache and no revocation checking. National-format numbers (no leading `+`) are compared and signed as received, without country-code normalisation (POA&M-44). `orig` is accepted if it matches either the PAI or the From (POA&M-45). Identity headers from a trunk with `strip_inbound_identity = false` are relayed whatever the verification result (POA&M-42).

`[stir_shaken]` and its `signing`, `attestation` and `verification` tables reject unknown keys. A deprecated flat key that disagrees with its nested replacement (including `max_passport_age_secs` and `default_attestation`) is an error.

**CDR (schema v2).** `stir_attestation` (level the SBC signed with), `stir_verstat`, `stir_verify_reason`, `stir_inbound_attestation`, `stir_x5u_host` (host only). CSV inserts the four new columns before `prev_hash,hash`.

**Audit.** `StirKeyLoaded`, `StirTrustAnchorsReloaded`, `StirTrustAnchorReloadFailed`, `StirSignFailure` and `StirVerifyFailure` (aggregated: one per trunk and reason per 10 s, with a count and the last source IP and Call-ID hash), and `StirAuditEventsDropped` (the aggregator table was full and events were dropped; also counted in `stir_audit_events_dropped_total`).

**Metrics.** `stir_sign_ok_total`, `stir_sign_failed_total`, `stir_verify_passed_total`, `stir_verify_failed_total`, `stir_verify_absent_total`, `stir_verify_rejected_total`, `stir_verify_parked_calls`, `stir_cert_cache_entries`, `stir_signing_cert_expiry_seconds`, `stir_audit_events_dropped_total` (unlabelled gauges).

**Metrics.** `stir_sign_ok_total`, `stir_sign_failed_total`, `stir_verify_{passed,failed,absent,rejected}_total`, `stir_verify_parked_calls`, `stir_cert_cache_entries`, `stir_signing_cert_expiry_seconds`.

---

## Call Detail Records

Each call attempt that passes source admission produces one Call Detail Record (CDR, schema v2; readers and `sbc-cli cdrs verify` accept v1 files) when it ends: answered, cancelled, failed, rejected at admission, by policy or for lack of a route, or rejected by the trunk with a 4xx/5xx/6xx. INVITEs that only draw a 401/407 challenge produce no CDR unless `record_auth_challenges = true`. Traffic dropped by the ACL or DoS protection, and INVITEs refused by source admission (403, neither a trunk nor registered; audited as an `AuthorizationDecision`), produce no CDR. A retransmitted INVITE that is rejected again within 32 s does not produce a second CDR.

```toml
[cdr]
enabled = true
format = "jsonl"                    # jsonl (default) | csv
directory = "/var/lib/usg-sbc/cdr"  # absolute path; created 0750, files 0640
# node_id = "sbc-a"                 # default: general.instance_name, then $HOSTNAME
rotate_size_mb = 100                # 1..=4096
rotate_interval = "1h"              # "0" = size only, otherwise 5m..=24h (s, m, h)
retention_files = 168               # closed files kept; 0 = no count limit
retention_days = 90                 # 0 = no age limit (both 0 is rejected)
fsync_interval_ms = 1000            # 0 = fsync after every record; max 60000
queue_capacity = 8192               # 64..=1000000
ring_capacity = 10000               # recent CDRs kept in memory for the API; 0..=200000
hash_chain = true                   # SHA-384 chain over records
record_unanswered = "all"           # all | routed | none
record_auth_challenges = false
pii = "full"                        # full | mask_caller | hash
# pii_hash_key_file = "/etc/usg-sbc/cdr-hmac.key"   # required with pii = "hash"
on_failure = "continue"             # continue | reject_new_calls

[cdr.syslog]
enabled = false
target = "tls://collector.example.net:6514"   # TLS only (RFC 5425)
# ca_path = "/etc/usg-sbc/syslog-ca.pem"
facility = 16
```

The table rejects unknown keys. Validation also rejects a relative `directory` or key path, `pii = "hash"` without `pii_hash_key_file`, a key file given with any other `pii` mode, out-of-range sizes and intervals, a `node_id` outside `[A-Za-z0-9._-]{1,64}`, a syslog `target` that is not `tls://host:port`, and `retention_files = 0` together with `retention_days = 0`. The `[cdr.syslog]` keys are validated even while `syslog.enabled = false`. When CDRs are enabled and the directory cannot be created or written, the daemon refuses to start (AU-5).

**Files.** Files are named `cdr-{node}-{YYYYmmddTHHMMSS}.{jsonl|csv}` (UTC), with `_NNN` added if the name already exists. A JSONL file starts with a header line `{"schema_version":1,"type":"header","node_id":..,"created_ms":..,"chain_start":..,"first_sequence":..}`, followed by one record per line. A CSV file starts with a `# usg-sbc cdr ...` comment line carrying the same values, then a fixed header row. A CSV value that starts with `= + - @`, TAB or CR gets a leading `'` so spreadsheets do not run it as a formula, so E.164 numbers appear as `'+1...`. When a file is closed by rotation or shutdown, a `<file>.sha384` sidecar in `sha384sum` format is written next to it. Retention deletes the oldest closed files and their sidecars. The open file is never deleted.

**Integrity.** The chain and sidecars are tamper-evident only. They are unkeyed and unsigned, so anyone who can write the CDR directory can rewrite records, chain and sidecars together (no AU-10 non-repudiation; signing is on the POA&M). Anchor the files off-host by keeping the `CdrFileRotated` audit events (enable the uc-audit chain and forward it) or by enabling the syslog sink; `cdrs verify` prints a reminder. With `hash_chain = true`, each record carries `prev_hash` and `hash`, where `hash` is SHA-384 over the previous hash followed by the record's canonical JSON with `hash` empty. The `sequence` number continues across restarts and the chain continues from the last complete record of the newest file. A torn final line (crash mid-write), or a CSV row with a quoted CR/LF, is skipped and reported as `chain_ok = false`; the sequence is never reset while records exist. If none of the newest 8 files holds a complete record, startup fails rather than reuse record ids. `sbc-cli cdrs verify <file>...` checks the header, sequence continuity and every hash, and checks that each file continues the one before it. A CSV file is covered by its sidecar digest only.

**PII.** By default numbers are stored as received. `mask_caller` replaces all but the last four characters of the caller fields with `*`. `hash` replaces caller and callee fields with hex HMAC-SHA-384 under the key file, which must hold at least 48 bytes and must not be a symlink or readable by group or other (mode 0600 or 0400); the daemon refuses to start otherwise. The file is opened with `O_NOFOLLOW` and its type and mode are checked on the open handle. A Kubernetes Secret volume fails this check, because Secret files are `..data/` symlinks with mode 0644 (or 0440) by default. Mount the key with `subPath` (a regular file, not a symlink) and `defaultMode: 0400`, or copy it in an initContainer (`install -m 0400 /secret/key /var/lib/sbc/keys/cdr-hmac.key`) and point `pii_hash_key_file` at the copy. The Helm chart has no PII key option and mounts no key; add the volume to the daemon Deployment as described. A symlinked parent directory is not detected. CDR content is never written to the tracing log. Hot reload applies changes to `pii`, `record_unanswered` and the retention keys. Changes to sinks, the directory or the format need a restart.

**Failure handling.** Emitting a CDR never blocks call handling. If the queue is full or the writer has stopped, the record is dropped and counted. The health component `cdr` reports unhealthy when the writer has exited or a file write failed in the last 60 s, and degraded when a record was dropped or the syslog sink failed in the last 5 minutes. The syslog sink runs on its own thread with its own queue (4096 records, DNS resolution capped at 5 s, at most one lookup in flight, and the last good collector address reused while the resolver fails): a slow or unreachable collector never delays file writes; records it cannot take are counted in `sbc_cdr_syslog_dropped_total` and kept in the file. With `on_failure = "reject_new_calls"`, new non-emergency INVITEs get `503` (with `Retry-After`) while the `cdr` health component is unhealthy, and each refusal is audited as an `AuthorizationDecision` with policy `cdr-unavailable`. Emergency calls are always admitted. Writer failures, drops and file rotations are also recorded on the audit trail (`CdrSinkFailure`, `CdrFileRotated`).

**Metrics.** `sbc_cdr_emitted_total`, `sbc_cdr_dropped_queue_full_total`, `sbc_cdr_dropped_writer_dead_total`, `sbc_cdr_write_errors_total`, `sbc_cdr_syslog_dropped_total`, `sbc_cdr_queue_depth`, `sbc_cdr_rotations_total`, `sbc_cdr_writer_alive` and `sbc_cdr_last_write_timestamp_seconds`.

**Deployment.** The daemon fails to start when the CDR directory is not writable. The error names the directory and the `cdr.directory` and `cdr.enabled` keys. The container image creates `/var/lib/usg-sbc/cdr` owned by the `sbc` user. The Helm chart sets `cdr.directory = "/var/lib/sbc/cdr"` on its own 1 GiB volume (`sbcDaemon.cdr.persistence`), so a CDR burst cannot fill the user/config store; the defaults keep 48 files of 16 MiB. Keep `retentionFiles * rotateSizeMb` below the volume size. On a host install, create the directory yourself or run the Ansible playbook with `-e sbc_host_install=true --tags cdr`. Calls still up at shutdown get a CDR with `release_cause = "shutdown"` before the writer closes its file.

**Access.** sbc-api serves `GET /api/v1/cdrs` (filters `start`, `end` in epoch ms, `caller`, `callee`, `disposition`, `trunk`, `page_token`, `page_size` up to 500), `GET /api/v1/cdrs/{record_id}` and `GET /api/v1/cdrs/stats` with the `cdr:read` permission, and `GET /api/v1/cdrs/export?format=jsonl|csv` with `cdr:export`. Each export is audited (`CdrExport` with an `outcome` of `success`, `truncated`, `failed` or `busy`; caller and callee filter values are recorded as `<redacted>`), a refused `cdr:*` request is audited as an `AuthorizationDecision`, one export runs at a time per sbc-api replica, and an export returns at most 50 000 records. The legacy admin credential holds both permissions. An OIDC operator needs the role `cdr-reader`, `auditor` or `fleet-admin` (read), or `cdr-exporter` or `fleet-admin` (export), or the scope `cdr:read` / `cdr:export`. The `config-admin` scope alone does not grant CDR access. These endpoints read the node's in-memory ring. The files remain the durable record. There is no delete or purge endpoint. The CLI equivalents are `sbc-cli cdrs list|show|export` (gRPC, `--features grpc`) and `sbc-cli cdrs verify` (offline).

The daemon gRPC `CdrService` does no per-user permission check (sbc-api enforces `cdr:read` / `cdr:export`), so it is mounted only when `grpc.require_mtls = true` or `grpc.listen_addr` is a loopback address; otherwise the daemon logs a warning and sbc-api answers the CDR endpoints with 503. In Helm, set `sbcDaemon.grpcMtls.enabled = true` with a cert-manager `clusterIssuer` (ECDSA P-384 server and client certificates are issued) or existing `serverSecretName`/`clientSecretName` Secrets; sbc-api then dials the daemon over mTLS (`SBC_DAEMON_GRPC_TLS_{CA,CERT,KEY}_FILE`). This cannot yet be combined with `sbcTrunkAgent.enabled`. With `require_mtls`, the daemon also checks every gRPC call (all services) against `grpc.allowed_client_names`: the client certificate must have a SAN DNS name, SAN URI or subject CN on the list, or the call fails with `PERMISSION_DENIED` and an `AuthorizationDecision` deny (policy `grpc.allowed_client_names`) is audited. An empty list admits any certificate that chains to `tls_ca_path` and logs a startup warning. The chart sets the list to its sbc-api client certificate CN (`<release>-sbc-api`) unless `sbcDaemon.grpcMtls.allowedClientNames` is given. Use a dedicated issuer for this CA (`issuerKind: Issuer`, a namespaced CA Issuer used for nothing else): with a shared ClusterIssuer, other workloads can obtain certificates from the same CA. The daemon audits every gRPC CDR read as `CdrExport`. The `user` is the authenticated certificate name (`cert:<name>@<peer>`), and the caller-asserted `x-sbc-user` (`api:<user>` or `cli:<user>`) is recorded separately as `on_behalf_of`. On a loopback listener without mTLS there is no authentication: `user` is `unauthenticated@<peer>`, and access relies on host or pod isolation (POA&M). `sbc-cli cdrs` has no TLS client: run it against a loopback listener on the host. The gRPC server and the sbc-api client use tonic's default TLS suites, not the CNSA 2.0 profile (POA&M); the P-384 certificates alone do not make the negotiated suite compliant.

**Cluster.** CDRs are per node, so `node_id` and `sequence` identify where a record came from. The daemon has no dialog takeover yet (an in-dialog request for a call this node does not hold gets 481), so `failover_takeover` is never set and a call lost in a node crash produces no CDR on any node.

**Known gaps (POA&M).** An operator `TerminateCall` produces no `operator_terminated` CDR, because the RPC is not implemented. No BYE is sent to either leg at shutdown. SCTP A-legs are recorded with `transport = "tcp"`. `stir_attestation` is always empty in schema v1 records (written before the STIR/SHAKEN release). The syslog sink sends no client certificate. Its TLS 1.3 connection does not restrict cipher suites to the CNSA 2.0 set. See the POA&M in [NIST-800-53-CONTROLS.md](NIST-800-53-CONTROLS.md).

---

## Monitoring

### Health Endpoints

`sbc-daemon` itself serves only kubelet probes and two read-only resources on `transport.api_listen` (default port 8080):

| Endpoint | Served by | Description |
|----------|-----------|-------------|
| `GET /healthz` | sbc-daemon | Liveness check |
| `GET /readyz` | sbc-daemon | Readiness check |
| `GET /api/v1/dialplans`, `GET /api/v1/dialplans/{id}/entries` | sbc-daemon | Read-only view of the live dial plans |
| `GET /api/v1/cdrs` | sbc-daemon | Read-only CDR list |
| `GET /api/v1/system/health` | sbc-api-server | Detailed health status |
| `GET /api/v1/system/stats` | sbc-api-server | Call/registration statistics |
| `GET /api/v1/system/metrics` | sbc-api-server | Prometheus metrics |
| `GET /api/v1/system/tls`, `POST /api/v1/system/tls/reload` | sbc-api-server | TLS status / certificate reload |

System health, stats and metrics (and all configuration CRUD) moved to the `sbc-api-server` pod, which talks to the daemon over gRPC. There is no root `/metrics` path.

### gRPC Management API

Requires `--features grpc`:

```toml
[grpc]
enabled = true
listen_addr = "0.0.0.0:9090"     # default; Helm/CLI examples use 9091
tls_cert_path = "/etc/sbc/grpc-cert.pem"   # optional; TLS off when unset
tls_key_path = "/etc/sbc/grpc-key.pem"
tls_ca_path = "/etc/sbc/grpc-ca.pem"       # client CA for mTLS
require_mtls = false             # enforced for gRPC when true
# allowed_client_names = ["sbc-api"]   # client cert SAN DNS/URI or CN; needs require_mtls; max 64
max_connections = 100
request_timeout_secs = 30
enable_reflection = false        # requires --features grpc-reflection
```

Available gRPC services and their wiring state:

- **CallService** — `ListCalls`, `GetCall`, `GetCallStats`, `WatchCalls` wired; `TerminateCall` returns `UNIMPLEMENTED`
- **RegistrationService** — `ListRegistrations`, `GetRegistration`, `DeleteRegistration`, `GetRegistrationStats` wired
- **ConfigService** — `GetConfig`, `ValidateConfig` wired; `UpdateConfig` and `ReloadConfig` return `UNIMPLEMENTED`
- **SystemService** — `GetVersion`, `GetStats`, `GetMetrics`, `ReloadTls`, `GetTlsStatus` wired; `Shutdown` returns `UNIMPLEMENTED`
- **Health** — standard gRPC health check (includes cluster components with `--features cluster`)
- **TrunkHealthService** — List trunk health and registration status (reads from in-process monitor or `sbc-trunk-agent` snapshot, transparently)
- **TrunkStatusPublishService** — Receives status snapshots from `sbc-trunk-agent` (consumed by the agent pod, not by operators directly)
- **TrunkSyncService**, **DialPlanSyncService**, **DidMappingSyncService**, **SbcSyncService** — push trunk-group / dial-plan / DID / partition-CSS-route-pattern-route-list changes from `sbc-api-server` into the live router
- **ClusterService** (with `--features cluster`) — `GetClusterStatus`, `ListNodes`, `GetNodeStatus`, `DrainNode`, `WatchCluster` wired; `InitiateFailover` and `UndoFailover` return `UNIMPLEMENTED`

---

## Announcement Playback

When a call cannot be completed (unallocated DID, all trunks in cooldown,
etc.) the daemon plays a PCMU announcement to the caller before sending BYE.
By default this runs in-process. For deployments where media should not
terminate on the signaling node, set `SBC_ANNOUNCEMENT_URL` to point at a
running `sbc-announcement-server` pod.

```sh
SBC_ANNOUNCEMENT_URL=http://sbc-announcement.sbc-system.svc.cluster.local:9095
```

**Fallback behaviour**: if the env var is unset, or the pod is unreachable at
call time (connection refused, timeout > 2 s), the daemon silently falls back
to in-process playback. No call is dropped due to the announcement pod being
unavailable.

**Announcement pod configuration** (env vars on `sbc-announcement-server`):

| Variable | Default | Description |
| --- | --- | --- |
| `SBC_ANN_GRPC_LISTEN` | `0.0.0.0:9095` | gRPC listener address |
| `SBC_ANN_ADVERTISED_IP` | *(required)* | IP embedded in SDP and returned to the daemon in the `Bound` event. Must be reachable by calling phones/carriers. |
| `SBC_ANN_BIND_IP` | `0.0.0.0` | Local IP to bind RTP sockets on. |
| `SBC_ANN_RTP_PORT_MIN` | *(ephemeral)* | Lower bound of RTP port range. |
| `SBC_ANN_RTP_PORT_MAX` | *(ephemeral)* | Upper bound of RTP port range. |
| `SBC_ANN_DEFAULT_DELAY_MS` | `200` | Silence before the first media frame (ms). |

The pod is stateless and scales horizontally. The daemon picks one instance
per call at gRPC connection time; any replica can serve any call.

---

## Trunk Agent

By default, carrier REGISTER and SIP OPTIONS health loops run inside
`sbc-daemon`. For deployments where SIP registration must originate from a
node with a stable public IP (separate from the signaling node), or where
trunk restarts should not affect the SIP-serving process, run
`sbc-trunk-agent` as a separate pod.

Set the following on `sbc-daemon` to disable its own trunk loops:

```sh
SBC_TRUNK_SERVICES=external
```

The agent reads trunk configuration from Postgres, runs OPTIONS probes and
outbound REGISTER, and pushes status snapshots to the daemon's
`TrunkStatusPublishService` gRPC endpoint on the configured interval. The
existing `TrunkHealthService` RPCs (used by `sbc-cli trunk list` and the
dashboard) automatically read from the agent's snapshot when the daemon's
own loops are disabled — no CLI or dashboard changes are required.

> **Single-replica requirement**: run exactly **one** replica of
> `sbc-trunk-agent`. A second instance would send duplicate REGISTER
> requests to every carrier, causing authentication failures and potential
> carrier-side rate limiting. Use `strategy: Recreate` (not RollingUpdate)
> in the Deployment so the old pod terminates before the new one starts.

**Trunk agent configuration** (env vars on `sbc-trunk-agent`):

| Variable | Default | Description |
| --- | --- | --- |
| `SBC_POSTGRES_URL` | *(required)* | Postgres DSN — same database the daemon reads. |
| `SBC_DAEMON_GRPC_URL` | *(required)* | gRPC URL of the daemon's management port (`:9091`). |
| `SBC_AGENT_GRPC_LISTEN` | `0.0.0.0:9096` | gRPC health probe listener. |
| `SBC_INSTANCE_NAME` | `$HOSTNAME` | Agent identity reported in status snapshots. |
| `SBC_SIP_CONTACT_IP` | *(unset)* | SIP Contact IP for REGISTER/OPTIONS. Must be the public IP visible to carriers. If unset, carriers may route inbound calls to the agent pod IP instead of the daemon — set this in almost all deployments. |
| `SBC_TRUNK_BIND_IP` | *(unset)* | Bind local UDP `:5060` on this IP for NAT keepalive (requires `CAP_NET_BIND_SERVICE`). |
| `SBC_TRUNK_POLL_SECS` | `30` | How often to poll Postgres for trunk config changes. |
| `SBC_PUBLISH_INTERVAL_SECS` | `10` | How often to push a status snapshot to the daemon. |

### Monitoring trunk health from the CLI

`sbc-cli` (built with `--features grpc`) can query trunk state directly from the
daemon's gRPC management port:

```sh
# OPTIONS-ping health for every trunk
sbc-cli trunk list

# Outbound-registration status for every trunk
sbc-cli trunk registrations

# Target a remote daemon
sbc-cli --grpc-url http://sbc-daemon.sbc.svc.cluster.local:9091 trunk list
```

When `sbc-trunk-agent` is deployed (`SBC_TRUNK_SERVICES=external`), a
**staleness indicator** is printed to stderr before the table:

| Indicator | Condition | Meaning |
| --- | --- | --- |
| `OK       Snapshot Xs ago` | `age ≤ 30 s` | Agent is healthy and reporting normally |
| `WARNING  Snapshot Xs ago` | `30 s < age ≤ 120 s` | Agent is slow or backlogged |
| `STALE    Snapshot Xs ago` | `age > 120 s` | Agent may be down — data unreliable |
| `WARNING  No snapshot received yet` | `age = 0` | Agent not yet connected or not running |

No indicator is printed when trunk services run in-process (default mode).

---

## Clustering (Optional)

Requires `--features cluster` (plus `redis` / `postgres` for those backends; `--features full` enables everything). Without the feature the `[cluster]` and `[storage]` sections are ignored. What is wired today is **shared registration state** in the storage backend plus cluster health reporting; heartbeat, automatic failover, session takeover and call-state replication are planned. See [CLUSTERING.md](CLUSTERING.md) for the full status table.

```toml
[cluster]
enabled = true
cluster_id = "production"
node_id = "sbc-01"
role = "primary"                 # primary, secondary, witness (key is `role`, not `node_role`)

[cluster.heartbeat]              # parsed, not used yet (planned)
interval_ms = 1000
suspect_threshold = 3
dead_threshold = 5

[cluster.replication]            # parsed, not used yet (planned)
mode = "semi_synchronous"       # synchronous, asynchronous, semi_synchronous
batch_size = 100

[cluster.failover]               # parsed, not used yet (planned)
auto_failover = true
failure_detection_timeout_ms = 5000
drain_timeout_ms = 30000
strategy = "prefer_same_zone"    # prefer_same_zone, prefer_same_region, least_loaded, priority

[storage]                        # wired
backend = "redis"                # memory, redis, postgres
key_prefix = "sbc:"

[storage.redis]
url = "redis://redis-cluster:6379"
cluster_mode = true
pool_size = 10
```

---

## Signal Handling

| Signal | Action |
|--------|--------|
| `SIGTERM` / `SIGINT` | Graceful shutdown (drain connections, flush state) |
| `SIGHUP` | Re-reads `sbc.toml` into the daemon's shared config snapshot only. The running `Server` and `SipStack` keep their original settings (the daemon logs that a restart is required). TLS certificate reload is done via gRPC `SystemService.ReloadTls` or `sbc-api-server` `POST /api/v1/system/tls/reload`, not SIGHUP. |

---

## Operational Notes

### CNSA 2.0 Compliance

The SBC is designed for CNSA 2.0 compliance:

- SIP-over-TLS is TLS 1.3 only (cipher suites are not further restricted; P-384 certificate type is recommended but not enforced)
- SRTP with AEAD_AES_256_GCM (256-bit) — the only profile the media plane accepts
- DTLS-SRTP (DTLS 1.2, Go terminator sidecar) with SHA-384 fingerprint and a self-signed P-384 SBC identity

See [CNSA-2-COMPLIANCE.md](CNSA-2-COMPLIANCE.md) for details.

### NIST 800-53 Rev5 Controls

The SBC implements controls from NIST 800-53 Rev5 (wiring state in parentheses):

- **AC-3/AC-4**: Source admission (trunk IP or active registration) and routing / topology hiding (wired)
- **AU-2/AU-3/AU-5**: Audit logging (wired, opt-in via `logging.audit_enabled`; non-blocking writer, drops counted and exposed in health and metrics)
- **CM-2/CM-6**: Configuration management (wired)
- **IA-2**: REGISTER authentication (wired for OIDC Bearer via `SBC_AUTH_MODE=bearer`; digest not configurable; SIP mTLS planned)
- **SC-5**: DoS protection (rate limiting, `max_calls` admission, per-trunk `max_calls`, `per_callee_max_concurrent`, `max_registrations` — wired, per node; bounded emergency reserve)
- **SC-7**: Boundary protection (topology hiding — wired)
- **SC-8**: Transmission confidentiality (TLS 1.3 SIP listeners, AEAD SRTP — wired)
- **SC-13**: Cryptographic protection (FIPS aws-lc-rs provider — wired)
- **SC-24**: Fail in known state (single-node graceful shutdown wired; cluster failover planned)

See [NIST-800-53-CONTROLS.md](NIST-800-53-CONTROLS.md) for details.

### Performance Considerations

- Each active call uses 2 RTP relay tasks (A→B and B→A)
- RTP port range should be sized for `2 * max_concurrent_calls` ports
- The jitter buffer and codec state are per-session (no shared state contention)
- Rate limiter uses per-IP token buckets with O(1) check time
