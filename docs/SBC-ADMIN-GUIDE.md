# USG Session Border Controller — Administrator Guide

## Overview

The USG SBC is a SIP Session Border Controller that provides:

- **B2BUA call control** — Back-to-back user agent with full call state management
- **SIP registration** — Binding storage and location service; REGISTER authentication via OIDC Bearer tokens (`SBC_AUTH_MODE=bearer`). Digest auth is compiled in but not configurable from `sbc.toml`; REGISTER is unauthenticated unless bearer mode is enabled.
- **Call routing** — Dial plans with pattern matching, number transforms, trunk selection
- **Media relay** — RTP/SRTP relay with codec transcoding
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

# Maximum concurrent registrations
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

# WebSocket / Secure WebSocket listen addresses.
# Parsed by sbc-config but NOT bound by sbc-daemon (planned); the
# uc-transport WebSocket transport is library-only today.
ws_listen = ["0.0.0.0:8080"]
wss_listen = ["0.0.0.0:8443"]
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
  protocol = "tls"
  priority = 2                   # lower priority = used for failover
  max_calls = 100
```

> **Trunk `protocol`**: `tcp`/`tls` currently only change the trunk URI scheme (`sip:` vs `sips:`) in the router. Forwarded requests are transmitted on the transport the A-leg arrived on (`server.rs`, `transport.send`); the daemon does not open outbound TCP/TLS client connections to trunks (planned).

### Selection Strategies

| Strategy | Behavior |
|----------|----------|
| `priority` | Always select the trunk with the lowest priority number |
| `round_robin` | Cycle through trunks in order |
| `weighted_random` | Random selection weighted by `weight` field |
| `least_connections` | Select the trunk with fewest active calls |
| `best_success_rate` | Select the trunk with highest success rate (auto-learns) |

### Trunk Failover

When a trunk returns an error (4xx/5xx/6xx), the SBC automatically tries the next trunk in failover order (sorted by priority). The maximum number of retries is controlled by `routing.max_failover_attempts`.

Failover is transparent to the calling party — they never see intermediate failures.

### Trunk Cooldown

When a trunk accumulates `max_failures` consecutive failures, it enters cooldown for `cooldown_secs` and is excluded from selection. After the cooldown period, it automatically becomes available again.

---

## Media Configuration

```toml
[media]
# Media relay mode: "Relay" (full B2BUA) or "PassThrough" (direct)
default_mode = "Relay"

# Supported codecs in preference order (uc-types CodecId variant names)
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

### Codec Transcoding

When the A-leg and B-leg negotiate different codecs, the SBC automatically transcodes between them. Supported codecs:

| Codec | Config name | Payload Type | Clock Rate | Bandwidth |
|-------|-------------|-------------|------------|-----------|
| G.711 u-law (PCMU) | `G711Ulaw` | 0 | 8 kHz | 64 kbps |
| G.711 A-law (PCMA) | `G711Alaw` | 8 | 8 kHz | 64 kbps |
| G.722 | `G722` | 9 | 16 kHz | 64 kbps |
| Opus | `Opus` | 111 (dynamic) | 48 kHz | 6-510 kbps |

Transcoding is implemented in `sbc-media-core` (`media_pipeline.rs`, `Transcoder`) and runs in the daemon's in-process media plane or the `sbc-media` pod.

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
min_tls_version = "1.3"         # "1.2" or "1.3"; validated only (see note)
curve = "P384"                   # P384 or P521; validated only (see note)
require_mtls = false             # parsed; NOT applied to SIP-TLS (see note)
```

Notes on what the daemon actually does with these keys:

- `tls_cert_path` / `tls_key_path` (wired): used for SIP-over-TLS listeners (`transport.tls_listen`) and REST HTTPS. Must be set together.
- SIP-TLS listeners are always **TLS 1.3 only** (`uc-transport::tls::create_server_config`); `min_tls_version` is checked by `sbc-config` validation but not read at runtime. Cipher suites are not restricted beyond the protocol version. The REST HTTPS listener uses rustls defaults (TLS 1.2 permitted).
- `curve` only constrains the configuration enum; the key type of the loaded certificate is not checked (P-256/RSA certificates are accepted by rustls).
- `require_mtls` is parsed but the SIP-TLS listener is built with `with_no_client_auth()` — SIP client-certificate authentication is planned. mTLS **is** enforced for the gRPC listener via `[grpc] require_mtls`.
- There is no `security.ca_bundle_path` key (one exists under `[stir_shaken]`, which the daemon does not use).

### Rate Limiting

```toml
[rate_limit]
enabled = true
global_rps = 10000              # Global requests per second
per_ip_rps = 100                # Per source IP
per_user_rps = 50               # Parsed but NOT applied by sbc-daemon (planned)
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
format = "json"                  # parsed, not applied by sbc-daemon (planned)
output = "stdout"                # parsed, not applied by sbc-daemon (planned)
audit_enabled = false            # parsed, not applied — no audit sink is wired (planned)
audit_path = "/var/log/sbc/audit.log"
```

The daemon's log level is driven by the `-v` flags and `RUST_LOG`; output is always `tracing` to stdout. The `uc-audit` crate (structured, hash-chained audit records) exists but is not used by any shipped binary.

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
- **AU-2**: Audit logging (planned — `uc-audit` is library-only; only `tracing` logs today)
- **CM-2/CM-6**: Configuration management (wired)
- **IA-2**: REGISTER authentication (wired for OIDC Bearer via `SBC_AUTH_MODE=bearer`; digest not configurable; SIP mTLS planned)
- **SC-5**: DoS protection (rate limiting, `max_calls` admission — wired)
- **SC-7**: Boundary protection (topology hiding — wired)
- **SC-8**: Transmission confidentiality (TLS 1.3 SIP listeners, AEAD SRTP — wired)
- **SC-13**: Cryptographic protection (FIPS aws-lc-rs provider — wired)
- **SC-24**: Fail in known state (single-node graceful shutdown wired; cluster failover planned)

See [NIST-800-53-CONTROLS.md](NIST-800-53-CONTROLS.md) for details.

### Performance Considerations

- Each active call uses 2 RTP relay tasks (A→B and B→A)
- RTP port range should be sized for `2 * max_concurrent_calls` ports
- Transcoding adds ~100us per RTP packet (negligible vs network jitter)
- The jitter buffer and codec state are per-session (no shared state contention)
- Rate limiter uses per-IP token buckets with O(1) check time
