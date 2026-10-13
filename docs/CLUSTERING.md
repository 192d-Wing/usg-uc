# High Availability Clustering Guide

This document describes the clustering architecture and configuration for the USG Session Border Controller.

> **Status legend.** *Wired (sbc-daemon | sbc-media-core | soft client)* — a shipped binary has a call site for this (the binary is named). *Library-only* — implemented and tested in a `proto-*`/`uc-*` crate, but no shipped binary calls it. *Planned* — not implemented. A row that says only "Full"/"Complete" describes crate-level capability; the wiring column/annotation says what the running SBC actually does.
>
> **Build requirement.** Everything in this document requires `sbc-daemon` to be built with the `cluster` cargo feature (`--features cluster` or `--features full`; Redis/PostgreSQL additionally need `redis` / `postgres`). The default build (`default = []`) compiles a stub `ClusterManager` and ignores the `[cluster]` and `[storage]` sections entirely (`sbc-daemon/src/cluster.rs`, `sbc-config/src/schema.rs`).

## Overview

Clustering support is split between library crates (`uc-cluster`, `uc-discovery`, `uc-storage`, `uc-state-sync`) and the daemon's `ClusterManager` (`sbc-daemon/src/cluster.rs`). Current wiring state:

| Capability | Status | Notes |
|------------|--------|-------|
| Shared storage backends (in-memory, Redis, PostgreSQL) | **Wired (sbc-daemon, `cluster` feature)** | `StorageManager` initialised and health-checked at startup (`cluster.rs`). |
| Registrations in shared storage | **Wired (sbc-daemon, `cluster` feature)** | `AsyncLocationService` over `uc-storage` (`proto-registrar` `storage` feature); initial cache sync at startup. |
| Static peer discovery | **Wired (sbc-daemon, `cluster` feature)** | One `discover()` call at start with `DiscoveryConfig::default()` (static method, **empty** peer list); no periodic refresh. |
| Cluster component in health check | **Wired (sbc-daemon, `cluster` feature)** | `/readyz` / gRPC Health include storage, discovery and location-service health. |
| gRPC `ClusterService` read-only RPCs + `DrainNode` | **Wired (sbc-daemon, `cluster` + `grpc` features)** | `GetClusterStatus`, `ListNodes`, `GetNodeStatus`, `DrainNode`, `WatchCluster`. |
| Active-Passive roles, membership tracking | Library-only (`uc-cluster::membership`) | `ClusterMembership` is created with the local node; no peers are ever added by the daemon. |
| Heartbeat protocol / failure detection | Planned | `ClusterManager::start` does not spawn heartbeat tasks. |
| Automatic failover, `FailoverCoordinator` | Library-only (`uc-cluster::failover`) / Planned in daemon | gRPC `InitiateFailover` and `UndoFailover` return `UNIMPLEMENTED`. |
| Session takeover (active calls preserved) | Planned | No call state is replicated. |
| State replication (`uc-state-sync`), CRDTs, snapshots | Library-only | `uc-state-sync` is a daemon dependency but has no call site in `sbc-daemon`. |
| DNS / Kubernetes / Gossip discovery | Library-only (`uc-discovery`) | No `[discovery]` config section exists; the daemon hard-codes the default static config. |
| Quorum policies | Library-only (`uc-cluster::membership::QuorumPolicy`) | Not configurable, not evaluated by the daemon. |
| Cluster REST API | Planned | Only a route *table* exists in `uc-api::routes::cluster` (no handlers); neither `sbc-daemon` nor `sbc-api-server` serve `/api/v1/cluster/*`. |
| Cluster Prometheus metrics (`sbc_cluster_*`) | Planned | No such metric names exist in `uc-metrics` or the daemon. |
| Control-plane listener / TLS (`control_bind`) | Planned | `control_bind` is parsed but nothing binds it. |

## NIST 800-53 Rev5 Controls

| Control | Description | Status | Implementation |
|---------|-------------|--------|----------------|
| SC-24 | Fail in Known State | Planned | Graceful degradation / state preservation across nodes is not implemented. Single-node graceful shutdown (drain) is wired in `sbc-daemon/src/shutdown.rs`. |
| CP-7 | Alternate Processing Site | Planned | Multi-zone/region fields (`region`, `zone`) are parsed but not used for placement or failover. |
| CP-10 | System Recovery | Planned | Automatic failover and rejoin are not implemented. |

## Architecture

``` mermaid
flowchart TB
    subgraph cm["Cluster Manager (uc-cluster)"]
        direction LR
        membership["Membership<br>Tracking<br>(Library-only)"]
        heartbeat["Heartbeat<br>Protocol<br>(Planned)"]
        failover["Failover<br>Coordinator<br>(Library-only)"]
        quorum["Quorum<br>Policy<br>(Library-only)"]
    end
    subgraph sd["Service Discovery (uc-discovery)"]
        direction LR
        static["Static<br>List<br>(Wired, empty list)"]
        dns["DNS<br>SRV/A<br>(Library-only)"]
        k8s["Kubernetes<br>Endpoints<br>(Library-only)"]
        gossip["Gossip<br>Protocol<br>(Library-only)"]
    end
    subgraph sb["Storage Backends (uc-storage)"]
        direction LR
        mem["In-Memory<br>(Wired)"]
        redis["Redis<br>(Wired, redis feature)"]
        pg["PostgreSQL<br>(Wired, postgres feature)"]
    end
    cm --> sd
    sd --> sb
```

## Node Roles

Defined in `uc-cluster::NodeRole` (Library-only; the daemon records the local node's role but does not act on it).

| Role | Description | Minimum Count |
|------|-------------|---------------|
| **Primary** | Active node handling all traffic | 1 |
| **Secondary** | Standby node ready for failover | 1+ |
| **Witness** | Quorum participant, no traffic handling | 0-1 |

## Node States

Defined in `uc-cluster::NodeState` (Library-only). The daemon does not drive this state machine; `ClusterManager::stop` marks the local node failed.

``` mermaid
stateDiagram-v2
    [*] --> Starting
    Starting --> Syncing
    Syncing --> Ready
    Ready --> Active
    Active --> Draining
    Draining --> ShuttingDown
    Syncing --> Unhealthy
    Active --> Unhealthy
    ShuttingDown --> [*]
```

| State | Description |
|-------|-------------|
| `Starting` | Node is initializing |
| `Syncing` | Synchronizing state from primary |
| `Ready` | Ready to accept traffic |
| `Active` | Currently handling traffic |
| `Draining` | Gracefully draining connections |
| `Unhealthy` | Failed health checks |
| `ShuttingDown` | Shutting down gracefully |

## Configuration

### Basic Cluster Configuration

The `[cluster]` section is `uc_cluster::ClusterConfig` re-exported by `sbc-config` (feature `cluster`). All keys below **parse**; only `cluster_id`, `node_id`, `role` and the `[storage]` section are **acted on** by the daemon today. Heartbeat, failover and replication values are stored but have no consumer (Planned).

```toml
[cluster]
enabled = true
cluster_id = "production-sbc"
node_id = "node-01"
role = "primary"                 # primary, secondary, witness
region = "us-east-1"             # parsed, not used
zone = "us-east-1a"              # parsed, not used
control_bind = "[::]:5070"       # parsed, nothing binds it (planned)

[cluster.heartbeat]              # parsed, not used (planned)
interval_ms = 1000
suspect_threshold = 3
dead_threshold = 5

[cluster.failover]               # parsed, not used (planned)
failure_detection_timeout_ms = 5000
drain_timeout_ms = 30000
sync_timeout_ms = 10000
strategy = "prefer_same_zone"
auto_failover = true

[cluster.replication]            # parsed, not used (planned)
mode = "semi_synchronous"
batch_size = 100
replication_interval_ms = 100
snapshot_interval_secs = 300
max_lag_ms = 5000
```

There is **no** `quorum_policy` key in `ClusterConfig`.

### Heartbeat Configuration (Planned)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `interval_ms` | 1000 | Heartbeat send interval |
| `suspect_threshold` | 3 | Missed heartbeats before suspect |
| `dead_threshold` | 5 | Missed heartbeats before dead |

**Timeouts (as designed):**

- Suspect timeout = interval × suspect_threshold = 3 seconds
- Dead timeout = interval × dead_threshold = 5 seconds

### Failover Configuration (Planned)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `failure_detection_timeout_ms` | 5000 | Time before declaring node dead |
| `drain_timeout_ms` | 30000 | Grace period for connection draining |
| `sync_timeout_ms` | 10000 | Maximum time for state sync |
| `strategy` | `prefer_same_zone` | Failover target selection |
| `auto_failover` | true | Enable automatic failover |

### Failover Strategies (Library-only, `uc-cluster::FailoverStrategy`)

| Strategy | Description |
|----------|-------------|
| `prefer_same_zone` | Select target in same availability zone |
| `prefer_same_region` | Select target in same region |
| `least_loaded` | Select target with fewest active calls |
| `priority` | Use explicit priority ordering |

### Replication Modes (Library-only, `uc-cluster::ReplicationMode`)

| Mode | Description | Use Case |
|------|-------------|----------|
| `synchronous` | Wait for N acknowledgments | Maximum consistency |
| `semi_synchronous` | Wait for 1 acknowledgment | Balanced |
| `asynchronous` | Fire and forget | Maximum performance |

## Service Discovery

`uc-discovery` implements static, DNS SRV/A and Kubernetes discovery plus a SWIM-style gossip protocol (Library-only). **The daemon does not read any discovery configuration**: `ClusterManager::new` constructs `DiscoveryConfig::default()` (static method, empty peer list) and calls `discover()` once at start, so no peers are ever found. There is no `[discovery]` section in `SbcConfig`; the snippets below document the `uc-discovery` config types and are **Planned** for exposure in `sbc.toml`.

### Static Discovery (Planned)

```toml
[discovery]
method = "static"
static_peers = ["node-02:5070", "node-03:5070"]
```

### DNS Discovery (Planned)

```toml
[discovery]
method = "dns_srv"          # or "dns_a"

[discovery.dns]
domain = "sbc.example.com"
default_port = 5070
timeout_ms = 5000
```

### Kubernetes Discovery (Planned)

```toml
[discovery]
method = "kubernetes"

[discovery.kubernetes]
namespace = "sbc"
service_name = "sbc-control"
port = { named = "control" }
in_cluster = true
```

See [STORAGE-BACKENDS.md](STORAGE-BACKENDS.md) for storage configuration (the `[storage]` section **is** wired).

## Quorum Policies (Library-only)

`uc-cluster::membership::QuorumPolicy` implements the following; the daemon neither configures nor evaluates quorum.

| Policy | Description |
|--------|-------------|
| `majority` | More than half of nodes must agree |
| `all` | All nodes must agree |
| `count(N)` | At least N nodes must agree |
| `weighted` | Based on node weights |

### Split-Brain Prevention (Planned)

Quorum-based split-brain prevention is the intended design. There is currently no `quorum_policy` configuration key and no quorum check in the failover path (failover itself is unimplemented in the daemon).

## Failover Process

### Automatic Failover (Planned)

Intended sequence (not implemented in `sbc-daemon`):

1. Primary node fails health checks
2. Health status transitions: Healthy → Suspect → Dead
3. Secondary nodes detect failure via heartbeat timeout
4. Quorum is checked before proceeding
5. Highest-priority secondary initiates takeover
6. State is synchronized from storage backend
7. New primary starts accepting traffic
8. Other nodes update their membership view

### Manual Failover (Planned)

There is no REST endpoint for failover. The gRPC `ClusterService.InitiateFailover` and `ClusterService.UndoFailover` RPCs exist in the API but return `UNIMPLEMENTED` ("requires FailoverCoordinator integration", `sbc-daemon/src/grpc_server/cluster_service.rs`).

### Drain for Maintenance

Wired via gRPC only (`--features cluster,grpc`): `ClusterService.DrainNode` marks the local node draining in `ClusterMembership`. There is no REST `/api/v1/cluster/drain` endpoint and no `rejoin` RPC (Planned).

## State Synchronization

### What is Replicated

| Data Type | Status | Storage Key Pattern |
|-----------|--------|---------------------|
| Registrations | **Wired** (shared `uc-storage` backend via `AsyncLocationService`) | `sip:binding:{aor}:{key}` |
| Call State | Planned | `call:{call_id}` (design only) |
| Rate Limits | Planned (CRDT design in `uc-state-sync`) | `ratelimit:{ip}` (design only) |
| Configuration | Planned | `config:{section}` (design only) |

### CRDT Support (Library-only)

`uc-state-sync::crdt` implements Conflict-free Replicated Data Types for the eventually consistent data above; nothing in `sbc-daemon` uses them yet:

- **GCounter**: Grow-only counter (e.g., call count)
- **PNCounter**: Increment/decrement counter (e.g., concurrent calls)
- **LWWRegister**: Last-writer-wins register (e.g., configuration)

## Monitoring

### Cluster Status (gRPC)

Wired (`--features cluster,grpc`) on the daemon's gRPC management port (`[grpc] listen_addr`, default `0.0.0.0:9090`):

| RPC | Status |
|-----|--------|
| `ClusterService.GetClusterStatus` | Wired (`replication_lag_ms` is always 0 — TODO in code) |
| `ClusterService.ListNodes` | Wired (local node only; no peers are joined) |
| `ClusterService.GetNodeStatus` | Wired |
| `ClusterService.DrainNode` | Wired |
| `ClusterService.WatchCluster` | Wired |
| `ClusterService.InitiateFailover` | **Unimplemented** |
| `ClusterService.UndoFailover` | **Unimplemented** |

There are no REST `/api/v1/cluster/*` endpoints (Planned; a route table exists in `uc-api` without handlers).

### Prometheus Metrics (Planned)

The following metric names are the intended design; none are emitted today.

| Metric | Type | Description |
|--------|------|-------------|
| `sbc_cluster_members_total` | Gauge | Total cluster members |
| `sbc_cluster_healthy_members` | Gauge | Healthy members |
| `sbc_cluster_failovers_total` | Counter | Failover count |
| `sbc_cluster_replication_lag_ms` | Gauge | Replication lag |

### Health Checks (Wired)

- `/healthz` - Liveness probe (node is running) — `sbc-daemon` REST
- `/readyz` - Readiness probe (node is ready for traffic) — `sbc-daemon` REST; with the `cluster` feature the async health check adds `cluster`, `cluster_storage`, `cluster_discovery` and `cluster_location` components (`sbc-daemon/src/api_server.rs`)
- gRPC `Health.Check` reports the same components

## Troubleshooting

### Common Issues

#### Node Not Joining Cluster

Peer joining is not implemented (static discovery runs with an empty peer list). Until peer discovery is exposed in configuration, every node runs as a standalone member sharing only the storage backend. Checks that still apply:

1. Verify storage backend connectivity (startup fails if the storage health check fails)
2. Verify `cluster_id` matches across all nodes (used as the storage key namespace with `storage.key_prefix`)

#### Frequent Failovers

Not applicable — automatic failover is not implemented.

#### State Sync Failures

1. Verify storage backend connectivity
2. Check storage backend health
3. Review storage backend logs

(`sync_timeout_ms` is parsed but not used.)

### Debug Logging

There is no `[logging.filter]` section in `sbc-config` (`LoggingConfig` has `level`, `format`, `output`, `audit_enabled`, `audit_path`). Use the `RUST_LOG` environment variable / `-v` flags instead:

```sh
RUST_LOG=info,uc_cluster=debug,uc_discovery=debug,uc_storage=debug ./sbc-daemon -c sbc.toml
```

## Best Practices

### Production Deployment

Given the current wiring, the achievable HA posture is **shared registration state** across independently load-balanced nodes:

1. **Use Redis or PostgreSQL** for shared state (not in-memory) so registrations survive a node restart
2. **Spread across zones** at the infrastructure level (Kubernetes/anti-affinity); the daemon does not place or fail over nodes itself
3. **Front nodes with an external load balancer / DNS SRV** for signaling failover — there is no SBC-level session takeover
4. **Configure TLS to the storage backend** (`[storage.redis.tls]`, `[storage.postgres] ssl_mode`); control-plane TLS is Planned because there is no control plane listener
5. Planned items (heartbeat, quorum, automatic failover, replication lag monitoring) should not be relied upon

### Network Requirements

| Port | Protocol | Purpose |
|------|----------|---------|
| 5060 | UDP/TCP | SIP signaling |
| 5061 | TLS | SIP over TLS |
| 5070 | TCP | Cluster control plane (Planned — nothing binds `control_bind` today) |
| 8080 | HTTP | Daemon probes (`/healthz`, `/readyz`) and `sbc-api-server` REST |
| 8443 | HTTPS | API (external) |
| 9090 | gRPC | Daemon management API (`ClusterService`, default `[grpc] listen_addr`) |
| 16384-32767 | UDP | RTP media |

### Sizing Guidelines

| Calls per Second | Nodes | Storage Backend |
|------------------|-------|-----------------|
| < 100 | 2 | In-Memory or Redis |
| 100-1000 | 3 | Redis |
| 1000+ | 5+ | Redis Cluster or PostgreSQL |

## Related Documentation

- [STORAGE-BACKENDS.md](STORAGE-BACKENDS.md) - Storage backend configuration
- [API-REFERENCE.md](API-REFERENCE.md) - REST API documentation
- [RUNBOOK.md](https://github.com/192d-Wing/usg-uc/blob/main/deploy/docs/RUNBOOK.md) - Operational procedures
