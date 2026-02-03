# REST API Reference

This document describes the REST API endpoints for the USG Session Border Controller.

## Overview

The SBC exposes a RESTful API for management and monitoring. The API is available on:
- HTTP: Port 8080 (internal)
- HTTPS: Port 8443 (external, TLS 1.3 required)

## Authentication

All endpoints require authentication unless otherwise noted.

```bash
# Using API key
curl -H "Authorization: Bearer <api-key>" \
  https://sbc.example.com:8443/api/v1/system/health
```

## API Versioning

The API is versioned via URL path:
- Current version: `/api/v1/`

## Common Response Formats

### Success Response

```json
{
  "data": { ... },
  "metadata": {
    "id": "resource-id",
    "created_at": "2024-01-15T10:30:00Z",
    "updated_at": "2024-01-15T10:30:00Z",
    "version": 1,
    "links": {
      "self": "/api/v1/resource/id"
    }
  }
}
```

### List Response

```json
{
  "items": [ ... ],
  "total": 100,
  "page": 1,
  "page_size": 50,
  "total_pages": 2
}
```

### Error Response

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request parameters",
    "request_id": "abc123",
    "field_errors": [
      {
        "field": "expires",
        "code": "RANGE_ERROR",
        "message": "Value must be between 60 and 604800"
      }
    ]
  }
}
```

## Pagination

List endpoints support pagination:

| Parameter | Default | Range | Description |
|-----------|---------|-------|-------------|
| `page` | 1 | 1+ | Page number |
| `page_size` | 50 | 1-1000 | Items per page |
| `sort_by` | varies | - | Sort field |
| `sort_order` | `asc` | `asc`, `desc` | Sort direction |

---

## System Endpoints

### Health Check

Check system health status.

```
GET /api/v1/system/health
```

**Response:**
```json
{
  "status": "healthy",
  "components": {
    "sip": "healthy",
    "media": "healthy",
    "storage": "healthy",
    "cluster": "healthy"
  },
  "uptime_seconds": 86400
}
```

### Get Metrics

Retrieve Prometheus-format metrics.

```
GET /api/v1/system/metrics
```

**Response:** Prometheus text format

### Get Configuration

Get current system configuration.

```
GET /api/v1/system/config
```

**Permission:** `config:read`

### Update Configuration

Update system configuration (triggers hot-reload).

```
PUT /api/v1/system/config
```

**Permission:** `config:write`

---

## Call Management

### List Active Calls

List currently active calls.

```
GET /api/v1/calls
```

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `trunk_id` | string | Filter by trunk |
| `caller` | string | Filter by caller |
| `callee` | string | Filter by callee |

**Response:**
```json
{
  "items": [
    {
      "call_id": "abc123@sbc.example.com",
      "caller": "sip:alice@example.com",
      "callee": "sip:bob@example.com",
      "state": "connected",
      "start_time": "2024-01-15T10:30:00Z",
      "duration_seconds": 120,
      "trunk_id": "trunk-01"
    }
  ],
  "total": 1
}
```

### Get Call Details

Get details for a specific call.

```
GET /api/v1/calls/:call_id
```

**Response:**
```json
{
  "call_id": "abc123@sbc.example.com",
  "caller": "sip:alice@example.com",
  "callee": "sip:bob@example.com",
  "state": "connected",
  "start_time": "2024-01-15T10:30:00Z",
  "duration_seconds": 120,
  "trunk_id": "trunk-01",
  "a_leg": {
    "contact": "sip:alice@192.168.1.100",
    "codec": "OPUS/48000",
    "srtp": true
  },
  "b_leg": {
    "contact": "sip:bob@192.168.1.200",
    "codec": "G722/16000",
    "srtp": true
  }
}
```

### Hangup Call

Terminate an active call.

```
DELETE /api/v1/calls/:call_id
```

**Permission:** `calls:admin`

**Response:** `204 No Content`

---

## Trunk Management

### List Trunks

List all configured trunks.

```
GET /api/v1/trunks
```

**Response:**
```json
{
  "items": [
    {
      "id": "trunk-01",
      "name": "Primary PSTN",
      "enabled": true,
      "host": "pstn.carrier.com",
      "port": 5060,
      "transport": "tls",
      "active_calls": 5,
      "max_calls": 100
    }
  ],
  "total": 1
}
```

### Get Trunk

Get trunk details.

```
GET /api/v1/trunks/:id
```

### Create Trunk

Create a new trunk.

```
POST /api/v1/trunks
```

**Permission:** `trunks:write`

**Request Body:**
```json
{
  "name": "Primary PSTN",
  "host": "pstn.carrier.com",
  "port": 5060,
  "transport": "tls",
  "max_calls": 100,
  "credentials": {
    "username": "sbc",
    "realm": "carrier.com"
  }
}
```

### Update Trunk

Update trunk configuration.

```
PUT /api/v1/trunks/:id
```

**Permission:** `trunks:write`

### Delete Trunk

Delete a trunk.

```
DELETE /api/v1/trunks/:id
```

**Permission:** `trunks:admin`

---

## Route Management

### List Routes

List all dial plan routes.

```
GET /api/v1/routes
```

### Get Route

Get route details.

```
GET /api/v1/routes/:id
```

### Create Route

Create a new route.

```
POST /api/v1/routes
```

**Permission:** `routes:write`

**Request Body:**
```json
{
  "name": "Local Calls",
  "pattern": "^1[0-9]{10}$",
  "priority": 100,
  "trunk_group": "local-trunks",
  "enabled": true
}
```

### Update Route

Update route configuration.

```
PUT /api/v1/routes/:id
```

**Permission:** `routes:write`

### Delete Route

Delete a route.

```
DELETE /api/v1/routes/:id
```

**Permission:** `routes:admin`

---

## Call Detail Records (CDR)

**NIST 800-53 Rev5 Controls:** AU-2, AU-3, AU-9

### List CDRs

List call detail records with filtering.

```
GET /api/v1/cdrs
```

**Permission:** `cdr:read`

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `start_time` | ISO 8601 | Filter by start time (from) |
| `end_time` | ISO 8601 | Filter by end time (to) |
| `caller` | string | Filter by caller URI |
| `callee` | string | Filter by callee URI |
| `status` | string | Filter by status (completed, failed, etc.) |
| `trunk_id` | string | Filter by trunk |
| `direction` | string | Filter by direction (inbound, outbound) |
| `min_duration` | integer | Minimum duration in seconds |
| `max_duration` | integer | Maximum duration in seconds |
| `source_ip` | string | Filter by source IP |
| `dest_ip` | string | Filter by destination IP |

**Response:**
```json
{
  "items": [
    {
      "call_id": "abc123@sbc.example.com",
      "caller": "sip:alice@example.com",
      "callee": "sip:bob@example.com",
      "status": "completed",
      "start_time": "2024-01-15T10:30:00Z",
      "end_time": "2024-01-15T10:35:00Z",
      "duration_seconds": 300,
      "trunk_id": "trunk-01",
      "direction": "outbound"
    }
  ],
  "total": 100
}
```

### Get CDR

Get a specific CDR by call ID.

```
GET /api/v1/cdrs/:call_id
```

**Permission:** `cdr:read`

### Export CDRs

Export CDRs in JSON or CSV format.

```
GET /api/v1/cdrs/export
```

**Permission:** `cdr:export`

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `format` | string | Export format: `json` or `csv` |
| `include_headers` | boolean | Include column headers (CSV) |
| `fields` | string | Comma-separated field list |
| `limit` | integer | Maximum records to export |

Plus all filtering parameters from List CDRs.

### CDR Statistics

Get CDR statistics and summary metrics.

```
GET /api/v1/cdrs/stats
```

**Permission:** `cdr:read`

**Response:**
```json
{
  "total_records": 10000,
  "completed_calls": 9500,
  "failed_calls": 500,
  "total_duration_seconds": 1500000,
  "average_duration_seconds": 157.89,
  "answer_seizure_ratio": 0.95,
  "failure_rate": 0.05,
  "calls_by_status": {
    "completed": 9500,
    "failed": 300,
    "busy": 200
  },
  "calls_by_cause": {
    "normal_clearing": 9500,
    "user_busy": 200,
    "no_answer": 300
  },
  "calls_by_trunk": {
    "trunk-01": 5000,
    "trunk-02": 5000
  }
}
```

### Search CDRs

Search CDRs by various criteria.

```
GET /api/v1/cdrs/search
```

**Permission:** `cdr:read`

### Get Correlated CDRs

Get all CDRs with the same correlation ID (related calls).

```
GET /api/v1/cdrs/correlation/:correlation_id
```

**Permission:** `cdr:read`

### Purge CDRs

Delete CDRs older than a specified date.

```
DELETE /api/v1/cdrs/purge
```

**Permission:** `cdr:admin`

**Request Body:**
```json
{
  "before_time": "2023-01-01T00:00:00Z",
  "status_filter": ["completed", "failed"],
  "dry_run": false
}
```

**Response:**
```json
{
  "records_deleted": 5000,
  "dry_run": false,
  "cutoff_time": "2023-01-01T00:00:00Z"
}
```

---

## Cluster Management

**NIST 800-53 Rev5 Control:** SC-24 (Fail in Known State)

### Cluster Status

Get overall cluster status and quorum information.

```
GET /api/v1/cluster/status
```

**Permission:** `cluster:read`

**Response:**
```json
{
  "cluster_id": "production-sbc",
  "local_node_id": "node-01",
  "local_role": "primary",
  "state": "active",
  "quorum": true,
  "members_healthy": 3,
  "members_total": 3,
  "last_failover": null
}
```

### List Cluster Members

List all cluster members.

```
GET /api/v1/cluster/members
```

**Permission:** `cluster:read`

**Response:**
```json
{
  "items": [
    {
      "node_id": "node-01",
      "role": "primary",
      "state": "active",
      "health": "healthy",
      "region": "us-east-1",
      "zone": "us-east-1a",
      "control_address": "10.0.1.10:5070",
      "last_heartbeat": "2024-01-15T10:30:00Z",
      "active_calls": 50
    },
    {
      "node_id": "node-02",
      "role": "secondary",
      "state": "ready",
      "health": "healthy",
      "region": "us-east-1",
      "zone": "us-east-1b",
      "control_address": "10.0.2.10:5070",
      "last_heartbeat": "2024-01-15T10:30:00Z",
      "active_calls": 0
    }
  ],
  "total": 2
}
```

### Get Cluster Member

Get details for a specific cluster member.

```
GET /api/v1/cluster/members/:node_id
```

**Permission:** `cluster:read`

### Initiate Failover

Initiate automatic failover from a failed node.

```
POST /api/v1/cluster/failover
```

**Permission:** `cluster:admin`

**Request Body:**
```json
{
  "failed_node_id": "node-01"
}
```

### Manual Failover

Manually failover to a specific target node.

```
POST /api/v1/cluster/failover/manual
```

**Permission:** `cluster:admin`

**Request Body:**
```json
{
  "target_node_id": "node-02"
}
```

### Drain Node

Drain sessions from local node for maintenance.

```
POST /api/v1/cluster/drain
```

**Permission:** `cluster:admin`

**Request Body:**
```json
{
  "timeout_seconds": 300
}
```

### Rejoin Cluster

Rejoin the cluster after maintenance.

```
POST /api/v1/cluster/rejoin
```

**Permission:** `cluster:admin`

### Sync Status

Get state synchronization status.

```
GET /api/v1/cluster/state/sync-status
```

**Permission:** `cluster:read`

**Response:**
```json
{
  "mode": "semi_synchronous",
  "lag_ms": 50,
  "last_sync": "2024-01-15T10:30:00Z",
  "peers": {
    "node-02": {
      "lag_ms": 50,
      "status": "synced"
    }
  }
}
```

### Force Sync

Force state synchronization with peers.

```
POST /api/v1/cluster/state/force-sync
```

**Permission:** `cluster:admin`

### Get State Snapshot

Get current state snapshot for backup or debugging.

```
GET /api/v1/cluster/state/snapshot
```

**Permission:** `cluster:read`

### Restore Snapshot

Restore state from a snapshot.

```
POST /api/v1/cluster/state/snapshot/restore
```

**Permission:** `cluster:admin`

---

## Health Probes

Kubernetes-compatible health probes (no authentication required):

### Liveness Probe

```
GET /healthz
```

**Response:** `200 OK` if node is running

### Readiness Probe

```
GET /readyz
```

**Response:** `200 OK` if node is ready to accept traffic

---

## Permissions Reference

| Permission | Description |
|------------|-------------|
| `calls:read` | View active calls |
| `calls:admin` | Terminate calls |
| `trunks:read` | View trunk configuration |
| `trunks:write` | Create/update trunks |
| `trunks:admin` | Delete trunks |
| `routes:read` | View routing configuration |
| `routes:write` | Create/update routes |
| `routes:admin` | Delete routes |
| `cdr:read` | View call detail records |
| `cdr:export` | Export CDRs |
| `cdr:admin` | Purge CDRs |
| `cluster:read` | View cluster status |
| `cluster:admin` | Manage cluster (failover, drain) |
| `config:read` | View configuration |
| `config:write` | Update configuration |

---

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `UNAUTHORIZED` | 401 | Authentication required |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `VALIDATION_ERROR` | 400 | Invalid request parameters |
| `CONFLICT` | 409 | Resource conflict (e.g., duplicate) |
| `RATE_LIMITED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Server error |

---

## Rate Limiting

API endpoints are rate-limited per client IP:
- Default: 100 requests/minute
- Export endpoints: 10 requests/minute

Rate limit headers:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1705320000
```

---

## Related Documentation

- [CLUSTERING.md](CLUSTERING.md) - High availability configuration
- [STORAGE-BACKENDS.md](STORAGE-BACKENDS.md) - Storage backend configuration
- [RUNBOOK.md](../deploy/docs/RUNBOOK.md) - Operational procedures
