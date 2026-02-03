# Storage Backends Configuration Guide

This document describes the storage backend options for the USG Session Border Controller.

## Overview

The USG SBC supports multiple storage backends for persisting:

- **SIP Registrations**: User bindings with contact URIs
- **Call State**: Active call information for failover
- **Rate Limit Counters**: Per-IP request tracking
- **Configuration**: Dynamic configuration updates

## NIST 800-53 Rev5 Controls

| Control | Description | Implementation |
|---------|-------------|----------------|
| SC-28 | Protection of Information at Rest | Encrypted storage, TLS connections |
| AU-4 | Audit Log Storage Capacity | Configurable retention, TTL support |
| CP-9 | System Backup | PostgreSQL backup support |

## Architecture

```text
┌─────────────────────────────────────────────────────────────────────┐
│                      Storage Manager                                 │
├─────────────────────────────────────────────────────────────────────┤
│                      StorageBackend Trait                            │
│   get() | set() | delete() | keys() | increment() | health_check() │
├─────────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │  In-Memory   │  │    Redis     │  │  PostgreSQL  │              │
│  │   HashMap    │  │  Cluster/Pool│  │ Connection   │              │
│  │   + TTL      │  │  + TLS       │  │   Pool       │              │
│  └──────────────┘  └──────────────┘  └──────────────┘              │
└─────────────────────────────────────────────────────────────────────┘
```

## Backend Comparison

| Feature | In-Memory | Redis | PostgreSQL |
|---------|-----------|-------|------------|
| **Persistence** | No | Optional (RDB/AOF) | Yes |
| **Clustering** | No | Yes (Redis Cluster) | Yes (replication) |
| **Performance** | Fastest | Fast | Moderate |
| **TTL Support** | Yes | Yes | Yes |
| **Use Case** | Development, single-node | Production HA | Long-term storage |

## Configuration

### Basic Configuration

```toml
[storage]
backend = "in_memory"  # or "redis" or "postgres"
key_prefix = "sbc:"
default_ttl_secs = 0   # 0 = no expiry
```

### In-Memory Backend

The in-memory backend stores data in a local HashMap with TTL support. Suitable for:
- Development and testing
- Single-node deployments
- Ephemeral data only

```toml
[storage]
backend = "in_memory"
key_prefix = "sbc:"
```

**Limitations:**
- Data lost on restart
- Not shared between nodes
- Memory-bound capacity

### Redis Backend

The Redis backend provides distributed caching with connection pooling. Suitable for:
- Multi-node clusters
- High-performance requirements
- Session state sharing

```toml
[storage]
backend = "redis"
key_prefix = "sbc:"

[storage.redis]
url = "redis://localhost:6379"
pool_size = 10
connection_timeout_ms = 5000
command_timeout_ms = 1000
cluster_mode = false

[storage.redis.retry]
max_attempts = 3
initial_backoff_ms = 100
max_backoff_ms = 5000
backoff_multiplier = 2.0
```

#### Redis Configuration Options

| Parameter | Default | Description |
|-----------|---------|-------------|
| `url` | `redis://localhost:6379` | Redis connection URL |
| `pool_size` | 10 | Connection pool size |
| `connection_timeout_ms` | 5000 | Connection timeout |
| `command_timeout_ms` | 1000 | Command timeout |
| `cluster_mode` | false | Enable Redis Cluster |

#### Redis URL Formats

```
# Standard
redis://localhost:6379

# With password
redis://:password@localhost:6379

# With database
redis://localhost:6379/0

# Redis Sentinel
redis+sentinel://sentinel1:26379,sentinel2:26379/mymaster

# Redis Cluster
redis://node1:6379,node2:6379,node3:6379
```

#### Redis TLS Configuration

```toml
[storage.redis.tls]
ca_cert_path = "/etc/ssl/certs/redis-ca.crt"
client_cert_path = "/etc/ssl/certs/redis-client.crt"
client_key_path = "/etc/ssl/private/redis-client.key"
verify_certificate = true
```

**Note:** For CNSA 2.0 compliance, use TLS 1.3 with AES-256-GCM.

### PostgreSQL Backend

The PostgreSQL backend provides persistent relational storage. Suitable for:
- Long-term data retention
- Audit trail requirements
- Complex queries

```toml
[storage]
backend = "postgres"
key_prefix = "sbc:"

[storage.postgres]
url = "postgres://user:password@localhost/sbc"
database = "sbc"
pool_min_size = 2
pool_max_size = 10
connection_timeout_ms = 5000
query_timeout_ms = 30000
run_migrations = true
ssl_mode = "prefer"
```

#### PostgreSQL Configuration Options

| Parameter | Default | Description |
|-----------|---------|-------------|
| `url` | `postgres://localhost/sbc` | PostgreSQL connection URL |
| `database` | `sbc` | Database name |
| `pool_min_size` | 2 | Minimum pool connections |
| `pool_max_size` | 10 | Maximum pool connections |
| `connection_timeout_ms` | 5000 | Connection timeout |
| `query_timeout_ms` | 30000 | Query timeout |
| `run_migrations` | true | Auto-run migrations |
| `ssl_mode` | `prefer` | SSL connection mode |

#### PostgreSQL SSL Modes

| Mode | Description |
|------|-------------|
| `disable` | No SSL |
| `prefer` | Use SSL if available |
| `require` | Require SSL |
| `verify_ca` | Require SSL + verify CA |
| `verify_full` | Require SSL + verify CA + hostname |

**For production**, use `verify_full` with proper certificates.

#### Database Schema

The PostgreSQL backend auto-creates these tables:

```sql
-- Key-value storage
CREATE TABLE kv_store (
    key TEXT PRIMARY KEY,
    value BYTEA NOT NULL,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Counters
CREATE TABLE kv_counters (
    key TEXT PRIMARY KEY,
    value BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for TTL cleanup
CREATE INDEX idx_kv_store_expires ON kv_store(expires_at)
    WHERE expires_at IS NOT NULL;
```

## SIP Registrar Integration

The `AsyncLocationService` integrates storage backends with the SIP registrar:

```toml
# Enable storage feature in proto-registrar
[dependencies]
proto-registrar = { features = ["storage"] }
```

### Storage Key Format

| Data Type | Key Pattern | Example |
|-----------|-------------|---------|
| Binding | `sip:binding:{aor}:{key}` | `sip:binding:alice@example.com:contact-1` |
| Call | `call:{call_id}` | `call:abc123` |
| Rate Limit | `ratelimit:{ip}` | `ratelimit:192.168.1.100` |

### TTL Management

Bindings are stored with TTL = expires + buffer:

```rust
// TTL = registration expires + 60 second buffer
let ttl = Duration::from_secs(binding.expires as u64 + 60);
storage.set(&key, &data, Some(ttl)).await?;
```

The buffer accounts for:
- Clock skew between nodes
- Grace period for re-registration
- Network latency

## Programmatic Usage

### Creating a Storage Manager

```rust
use uc_storage::{StorageConfig, StorageManager};

// In-memory
let config = StorageConfig::in_memory();
let storage = StorageManager::new(config).await?;

// Redis
let config = StorageConfig::redis("redis://localhost:6379");
let storage = StorageManager::new(config).await?;

// PostgreSQL
let config = StorageConfig::postgres("postgres://localhost/sbc");
let storage = StorageManager::new(config).await?;
```

### Basic Operations

```rust
use std::time::Duration;

// Set with TTL
storage.set("key", b"value", Some(Duration::from_secs(3600))).await?;

// Get
if let Some(value) = storage.get("key").await? {
    println!("Value: {:?}", value);
}

// Delete
let deleted = storage.delete("key").await?;

// List keys by pattern
let keys = storage.keys("sip:binding:*").await?;

// Atomic increment
let new_value = storage.increment("counter", 1).await?;

// Health check
if storage.health_check().await {
    println!("Storage is healthy");
}
```

### AsyncLocationService Usage

```rust
use proto_registrar::{AsyncLocationService, Binding};
use uc_storage::{StorageConfig, StorageManager};
use std::sync::Arc;

// Create storage
let config = StorageConfig::redis("redis://localhost:6379");
let storage = Arc::new(StorageManager::new(config).await?);

// Create location service
let location = AsyncLocationService::new(storage);

// Add binding
let binding = Binding::new(
    "sip:alice@example.com",
    "sip:alice@192.168.1.100",
    "call-id-123",
    1,
);
location.add_binding(binding).await?;

// Lookup
let bindings = location.lookup("sip:alice@example.com").await;

// Get stats
let stats = location.stats().await;
println!("Cached AORs: {}", stats.cached_aors);
```

## Feature Flags

Storage backends are feature-gated in `uc-storage`:

```toml
[dependencies]
uc-storage = { version = "0.1", features = ["redis", "postgres"] }
```

| Feature | Dependencies | Description |
|---------|--------------|-------------|
| `redis` | bb8, bb8-redis, redis | Redis backend |
| `postgres` | sqlx | PostgreSQL backend |

## Monitoring

### Health Checks

Each backend provides health checking:

```rust
// Check backend health
let healthy = storage.health_check().await;
```

- **In-Memory**: Always healthy
- **Redis**: PING command
- **PostgreSQL**: Connection acquisition

### Prometheus Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `sbc_storage_operations_total` | Counter | Total operations |
| `sbc_storage_operation_duration_seconds` | Histogram | Operation latency |
| `sbc_storage_errors_total` | Counter | Error count |
| `sbc_storage_pool_connections` | Gauge | Active pool connections |

## Performance Tuning

### Redis

1. **Pool Size**: Set based on concurrent requests
   - Rule of thumb: 2-4x the number of worker threads

2. **Timeouts**: Balance between responsiveness and reliability
   - Connection: 5 seconds (initial setup)
   - Command: 1 second (per operation)

3. **Pipelining**: Batch operations when possible

### PostgreSQL

1. **Pool Size**: Match to expected concurrent queries
   - min_size: Number of always-ready connections
   - max_size: Peak concurrent query capacity

2. **Query Timeout**: Set based on expected query complexity
   - Simple key-value: 1-5 seconds
   - Pattern matching: 10-30 seconds

3. **Indexes**: The schema includes indexes for TTL cleanup

## Troubleshooting

### Connection Failures

**Redis:**
```bash
# Test connectivity
redis-cli -h localhost -p 6379 ping

# Check authentication
redis-cli -h localhost -p 6379 -a password ping
```

**PostgreSQL:**
```bash
# Test connectivity
psql -h localhost -U user -d sbc -c "SELECT 1"

# Check SSL
psql "host=localhost user=user dbname=sbc sslmode=require"
```

### TTL Not Working

1. Verify `default_ttl_secs` is set
2. Check clock synchronization between nodes
3. For PostgreSQL, verify background cleanup is running

### High Latency

1. Check network latency to storage backend
2. Increase pool size for concurrent access
3. Consider using Redis for lower latency
4. Add read replicas for read-heavy workloads

## Migration Between Backends

### Export/Import

```bash
# Export from Redis
redis-cli --scan --pattern "sbc:*" | while read key; do
  redis-cli GET "$key" >> backup.txt
done

# Import to PostgreSQL
# Use provided migration script
./scripts/migrate-storage.sh redis postgres
```

### Online Migration

1. Configure both backends
2. Enable dual-write mode
3. Migrate existing data
4. Switch reads to new backend
5. Disable old backend

## Related Documentation

- [CLUSTERING.md](CLUSTERING.md) - High availability configuration
- [API-REFERENCE.md](API-REFERENCE.md) - REST API documentation
- [RUNBOOK.md](../deploy/docs/RUNBOOK.md) - Operational procedures
