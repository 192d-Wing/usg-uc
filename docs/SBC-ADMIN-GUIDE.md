# USG Session Border Controller — Administrator Guide

## Overview

The USG SBC is a SIP Session Border Controller that provides:

- **B2BUA call control** — Back-to-back user agent with full call state management
- **SIP registration** — Digest authentication, binding storage, location service
- **Call routing** — Dial plans with pattern matching, number transforms, trunk selection
- **Media relay** — RTP/SRTP relay with codec transcoding
- **Header manipulation** — Per-trunk and global SIP header rewriting
- **Topology hiding** — Via/Contact/Call-ID anonymization
- **Rate limiting** — Per-IP and global DoS protection
- **gRPC management API** — Real-time call and registration monitoring
- **High availability** — Optional clustering with Redis/PostgreSQL state replication

### Architecture

```
                    +-----------+
  SIP UA ---------> |           | ---------> SIP Trunk / PSTN
  (A-leg)           |  USG SBC  |            (B-leg)
  <----------------- |           | <---------
                    |  -------  |
                    |  | RTP |  |
  RTP (A-leg) ----> |  |Relay|  | ---------> RTP (B-leg)
  <----------------- |  -------  | <---------
                    +-----------+
```

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

# CLI tool
cargo build --release --bin sbc-cli
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
# UDP listen addresses (IPv4 and/or IPv6)
udp_listen = ["0.0.0.0:5060", "[::]:5060"]

# TCP listen addresses
tcp_listen = ["0.0.0.0:5060"]

# TLS listen addresses (requires security.tls_cert_path)
tls_listen = ["0.0.0.0:5061"]

# WebSocket listen addresses
ws_listen = ["0.0.0.0:8080"]

# Secure WebSocket listen addresses
wss_listen = ["0.0.0.0:8443"]
```

If no listeners are configured, the SBC binds to `[::]:5060` (IPv6 with IPv4 fallback).

---

## SIP Registration

The SBC acts as a B2BUA registrar, storing user bindings in an in-memory location service. When clustering is enabled, bindings are replicated to Redis or PostgreSQL.

Registration is automatic — any SIP UA that sends a REGISTER request will have its bindings stored. Digest authentication can be enabled for security.

### Authentication

Authentication is configured in the SBC startup code. The SipStackConfig supports:

- `require_auth: bool` — whether REGISTER requires digest credentials
- `auth_realm: String` — the digest auth realm
- `auth_credentials: HashMap<String, String>` — username-to-password map

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
  protocol = "udp"               # udp, tcp, or tls
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

# Supported codecs in preference order
codecs = ["opus", "g722", "pcmu", "pcma"]

# RTP port range for media relay
rtp_port_min = 16384
rtp_port_max = 32768

[media.srtp]
# Require SRTP encryption (CNSA 2.0: AEAD_AES_256_GCM)
required = true
profile = "AEAD_AES_256_GCM"

[media.dtls]
# DTLS certificate for SRTP key exchange
cert_path = "/etc/sbc/dtls-cert.pem"
key_path = "/etc/sbc/dtls-key.pem"
fingerprint_hash = "sha-384"
```

### Codec Transcoding

When the A-leg and B-leg negotiate different codecs, the SBC automatically transcodes between them. Supported codecs:

| Codec | Payload Type | Clock Rate | Bandwidth |
|-------|-------------|------------|-----------|
| G.711 u-law (PCMU) | 0 | 8 kHz | 64 kbps |
| G.711 A-law (PCMA) | 8 | 8 kHz | 64 kbps |
| G.722 | 9 | 16 kHz | 64 kbps |
| Opus | 111 (dynamic) | 48 kHz | 6-510 kbps |

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
tls_min_version = "1.3"         # CNSA 2.0 requires TLS 1.3
curve = "P-384"                  # CNSA 2.0 curve
require_client_cert = false      # Enable mTLS
ca_bundle_path = "/etc/sbc/ca-bundle.pem"
```

### Rate Limiting

```toml
[rate_limit]
enabled = true
global_rps = 10000              # Global requests per second
per_ip_rps = 100                # Per source IP
per_user_rps = 50               # Per authenticated user
burst_multiplier = 2.0          # Allow short bursts
```

When rate limits are exceeded:
- **Throttle**: Suggested delay (logged but not enforced)
- **Reject**: Message silently dropped
- **Block**: Source temporarily blocked

---

## Logging

```toml
[logging]
level = "info"                   # trace, debug, info, warn, error
format = "json"                  # json or text
output = "stdout"                # stdout or file path
audit_enabled = false
audit_path = "/var/log/sbc/audit.log"
```

---

## Monitoring

### Health Endpoints

The SBC exposes REST endpoints on port 8080 (default):

| Endpoint | Description |
|----------|-------------|
| `GET /healthz` | Liveness check |
| `GET /readyz` | Readiness check |
| `GET /api/v1/system/health` | Detailed health status |
| `GET /metrics` | Prometheus metrics |
| `GET /api/v1/system/stats` | Call/registration statistics |

### gRPC Management API

Enable with `--features grpc`:

```toml
[grpc]
enabled = true
listen_addr = "0.0.0.0:50051"
tls_enabled = false
max_connections = 100
```

Available gRPC services:
- **CallService** — List, get, terminate calls; watch call events
- **RegistrationService** — List, get, delete registrations; stats
- **ConfigService** — Get, update, validate, reload configuration
- **SystemService** — Version, stats, metrics, TLS reload, shutdown
- **ClusterService** — Cluster status, node management, failover (with `--features cluster`)

---

## Clustering (Optional)

Enable with `--features cluster`:

```toml
[cluster]
cluster_id = "production"
node_id = "sbc-01"
node_role = "primary"            # primary, secondary, standby, witness

[cluster.heartbeat]
interval_ms = 1000
suspect_threshold = 3
dead_threshold = 5

[cluster.replication]
mode = "semi_synchronous"       # synchronous, asynchronous, semi_synchronous
batch_size = 100

[cluster.failover]
auto_failover = true
failure_detection_timeout_ms = 5000
drain_timeout_ms = 30000
strategy = "prefer_same_zone"    # prefer_same_zone, prefer_same_region, least_loaded, priority

[storage]
backend = "redis"
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
| `SIGHUP` | Configuration hot-reload (TLS certs, rate limits) |

---

## Operational Notes

### CNSA 2.0 Compliance

The SBC is designed for CNSA 2.0 compliance:
- TLS 1.3 with P-384 ECDSA certificates
- SRTP with AEAD_AES_256_GCM (256-bit)
- DTLS-SRTP key exchange with SHA-384 fingerprint

See [CNSA-2-COMPLIANCE.md](CNSA-2-COMPLIANCE.md) for details.

### NIST 800-53 Rev5 Controls

The SBC implements controls from NIST 800-53 Rev5:
- **AC-4**: Information flow enforcement (routing, topology hiding)
- **AU-2**: Audit logging
- **CM-2/CM-6**: Configuration management
- **IA-2/IA-3**: Authentication (digest auth, mTLS)
- **SC-5**: DoS protection (rate limiting)
- **SC-7**: Boundary protection (topology hiding)
- **SC-8**: Transmission confidentiality (TLS/SRTP)
- **SC-13**: Cryptographic protection (CNSA 2.0)
- **SC-24**: Fail in known state (graceful shutdown, cluster failover)

See [NIST-800-53-CONTROLS.md](NIST-800-53-CONTROLS.md) for details.

### Performance Considerations

- Each active call uses 2 RTP relay tasks (A→B and B→A)
- RTP port range should be sized for `2 * max_concurrent_calls` ports
- Transcoding adds ~100us per RTP packet (negligible vs network jitter)
- The jitter buffer and codec state are per-session (no shared state contention)
- Rate limiter uses per-IP token buckets with O(1) check time
