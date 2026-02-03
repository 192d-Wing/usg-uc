# High Availability Clustering Guide

This document describes the clustering architecture and configuration for the USG Session Border Controller.

## Overview

The USG SBC supports carrier-grade high availability through:

- **Active-Passive Clustering**: Primary node handles traffic, secondary nodes ready for failover
- **Automatic Failover**: Heartbeat-based failure detection with configurable thresholds
- **Session Takeover**: Active calls preserved during failover
- **State Replication**: Registrations and call state synchronized across nodes

## NIST 800-53 Rev5 Controls

| Control | Description | Implementation |
|---------|-------------|----------------|
| SC-24 | Fail in Known State | Graceful degradation, state preservation |
| CP-7 | Alternate Processing Site | Multi-zone/region clustering |
| CP-10 | System Recovery | Automatic failover and rejoin |

## Architecture

```text
┌─────────────────────────────────────────────────────────────────────┐
│                        Cluster Manager                               │
├─────────────────────────────────────────────────────────────────────┤
│  Membership    │   Heartbeat     │   Failover      │   Quorum      │
│  Tracking      │   Protocol      │   Coordinator   │   Policy      │
├─────────────────────────────────────────────────────────────────────┤
│                     Service Discovery                                │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐            │
│  │  Static  │  │   DNS    │  │ Kubernetes│  │  Gossip  │            │
│  │   List   │  │  SRV/A   │  │ Endpoints │  │ Protocol │            │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘            │
├─────────────────────────────────────────────────────────────────────┤
│                     Storage Backends                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                          │
│  │ In-Memory│  │  Redis   │  │PostgreSQL│                          │
│  └──────────┘  └──────────┘  └──────────┘                          │
└─────────────────────────────────────────────────────────────────────┘
```

## Node Roles

| Role | Description | Minimum Count |
|------|-------------|---------------|
| **Primary** | Active node handling all traffic | 1 |
| **Secondary** | Standby node ready for failover | 1+ |
| **Witness** | Quorum participant, no traffic handling | 0-1 |

## Node States

```text
Starting → Syncing → Ready → Active → Draining → ShuttingDown
                ↓              ↓
            Unhealthy ←────────┘
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

```toml
[cluster]
enabled = true
cluster_id = "production-sbc"
node_id = "node-01"
role = "primary"
region = "us-east-1"
zone = "us-east-1a"
control_bind = "[::]:5070"

[cluster.heartbeat]
interval_ms = 1000
suspect_threshold = 3
dead_threshold = 5

[cluster.failover]
failure_detection_timeout_ms = 5000
drain_timeout_ms = 30000
sync_timeout_ms = 10000
strategy = "prefer_same_zone"
auto_failover = true

[cluster.replication]
mode = "semi_synchronous"
batch_size = 100
replication_interval_ms = 100
snapshot_interval_secs = 300
max_lag_ms = 5000
```

### Heartbeat Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `interval_ms` | 1000 | Heartbeat send interval |
| `suspect_threshold` | 3 | Missed heartbeats before suspect |
| `dead_threshold` | 5 | Missed heartbeats before dead |

**Timeouts:**
- Suspect timeout = interval × suspect_threshold = 3 seconds
- Dead timeout = interval × dead_threshold = 5 seconds

### Failover Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `failure_detection_timeout_ms` | 5000 | Time before declaring node dead |
| `drain_timeout_ms` | 30000 | Grace period for connection draining |
| `sync_timeout_ms` | 10000 | Maximum time for state sync |
| `strategy` | `prefer_same_zone` | Failover target selection |
| `auto_failover` | true | Enable automatic failover |

### Failover Strategies

| Strategy | Description |
|----------|-------------|
| `prefer_same_zone` | Select target in same availability zone |
| `prefer_same_region` | Select target in same region |
| `least_loaded` | Select target with fewest active calls |
| `priority` | Use explicit priority ordering |

### Replication Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `synchronous` | Wait for N acknowledgments | Maximum consistency |
| `semi_synchronous` | Wait for 1 acknowledgment | Balanced |
| `asynchronous` | Fire and forget | Maximum performance |

## Service Discovery

The cluster uses service discovery to find peer nodes. Configure one of:

### Static Discovery

```toml
[discovery]
method = "static"
static_peers = ["node-02:5070", "node-03:5070"]
```

### DNS Discovery

```toml
[discovery]
method = "dns_srv"

[discovery.dns]
domain = "sbc.example.com"
default_port = 5070
timeout_ms = 5000
```

### Kubernetes Discovery

```toml
[discovery]
method = "kubernetes"

[discovery.kubernetes]
namespace = "sbc"
service_name = "sbc-control"
port = { named = "control" }
in_cluster = true
```

See [STORAGE-BACKENDS.md](STORAGE-BACKENDS.md) for storage configuration.

## Quorum Policies

| Policy | Description |
|--------|-------------|
| `majority` | More than half of nodes must agree |
| `all` | All nodes must agree |
| `count(N)` | At least N nodes must agree |
| `weighted` | Based on node weights |

### Split-Brain Prevention

The cluster uses quorum policies to prevent split-brain scenarios:

```toml
[cluster]
quorum_policy = "majority"
```

With 3 nodes, at least 2 must be healthy for the cluster to operate.

## Failover Process

### Automatic Failover

1. Primary node fails health checks
2. Health status transitions: Healthy → Suspect → Dead
3. Secondary nodes detect failure via heartbeat timeout
4. Quorum is checked before proceeding
5. Highest-priority secondary initiates takeover
6. State is synchronized from storage backend
7. New primary starts accepting traffic
8. Other nodes update their membership view

### Manual Failover

```bash
# Initiate manual failover
curl -X POST http://localhost:8080/api/v1/cluster/failover/manual \
  -H "Content-Type: application/json" \
  -d '{"target_node_id": "node-02"}'
```

### Drain for Maintenance

```bash
# Drain node before maintenance
curl -X POST http://localhost:8080/api/v1/cluster/drain

# Rejoin after maintenance
curl -X POST http://localhost:8080/api/v1/cluster/rejoin
```

## State Synchronization

### What is Replicated

| Data Type | Consistency | Storage Key Pattern |
|-----------|-------------|---------------------|
| Registrations | Strong | `sip:binding:{aor}:{key}` |
| Call State | Eventual | `call:{call_id}` |
| Rate Limits | Eventual (CRDT) | `ratelimit:{ip}` |
| Configuration | Strong | `config:{section}` |

### CRDT Support

For eventually consistent data, the system uses Conflict-free Replicated Data Types:

- **GCounter**: Grow-only counter (e.g., call count)
- **PNCounter**: Increment/decrement counter (e.g., concurrent calls)
- **LWWRegister**: Last-writer-wins register (e.g., configuration)

## Monitoring

### Cluster Status API

```bash
# Get cluster status
curl http://localhost:8080/api/v1/cluster/status

# List cluster members
curl http://localhost:8080/api/v1/cluster/members

# Get sync status
curl http://localhost:8080/api/v1/cluster/state/sync-status
```

### Prometheus Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `sbc_cluster_members_total` | Gauge | Total cluster members |
| `sbc_cluster_healthy_members` | Gauge | Healthy members |
| `sbc_cluster_failovers_total` | Counter | Failover count |
| `sbc_cluster_replication_lag_ms` | Gauge | Replication lag |

### Health Checks

The cluster exposes health endpoints:

- `/healthz` - Liveness probe (node is running)
- `/readyz` - Readiness probe (node is ready for traffic)

## Troubleshooting

### Common Issues

#### Node Not Joining Cluster

1. Verify network connectivity to control plane port
2. Check firewall rules for port 5070 (or configured port)
3. Verify cluster_id matches across all nodes
4. Check service discovery configuration

#### Frequent Failovers

1. Increase `suspect_threshold` and `dead_threshold`
2. Check network stability between nodes
3. Verify system resources (CPU, memory, disk I/O)
4. Review logs for heartbeat timeouts

#### State Sync Failures

1. Verify storage backend connectivity
2. Check storage backend health
3. Increase `sync_timeout_ms` if needed
4. Review storage backend logs

### Debug Logging

Enable debug logging for clustering:

```toml
[logging]
level = "info"

[logging.filter]
"uc_cluster" = "debug"
"uc_discovery" = "debug"
"uc_state_sync" = "debug"
```

## Best Practices

### Production Deployment

1. **Use 3+ nodes** for quorum-based failover
2. **Spread across zones** for availability zone failures
3. **Use Redis or PostgreSQL** for shared state (not in-memory)
4. **Configure TLS** for control plane communication
5. **Monitor replication lag** to detect sync issues

### Network Requirements

| Port | Protocol | Purpose |
|------|----------|---------|
| 5060 | UDP/TCP | SIP signaling |
| 5061 | TLS | SIP over TLS |
| 5070 | TCP | Cluster control plane |
| 8080 | HTTP | API (internal) |
| 8443 | HTTPS | API (external) |
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
- [RUNBOOK.md](../deploy/docs/RUNBOOK.md) - Operational procedures
