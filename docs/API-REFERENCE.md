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

API keys are configured by digest, never in clear:
`SBC_API_KEY_SHA384` is a comma-separated list of SHA-384 hex digests
(`printf %s "$KEY" | sha384sum | cut -d' ' -f1`). The former
`SBC_API_KEY_SHA256` is no longer accepted and stops startup if set.
An API key must be a random value of at least 256 bits (for example
`openssl rand -hex 32`), never a chosen password: the server stores only
a fast SHA-384 digest, which protects a random key but not a guessable one.

### Admin login (`POST /api/v1/auth/login`)

Body: `{"username": "...", "password": "..."}`. Responses:

| Status | Body `error` | When |
|---|---|---|
| `200` | (token body) | Valid credentials. Returns `token`, `expires_in_secs` and an `sbc_session` cookie. Resets the failure counts. |
| `400` | `invalid credentials format` | Username over 256 bytes or password over 1024 bytes. Not counted. |
| `401` | `invalid credentials` | Wrong credentials. Counts as one failure. |
| `413` | (none) | Request body over 4 KiB. Not counted. |
| `429` | `too many login attempts, try again later` | The client IP has 5 failures, or all sources together have 10, in the current 15 min window. `Retry-After` is the seconds left in the window. |
| `429` | `login busy, retry shortly` | All password-verification slots are in use. `Retry-After: 1`. Not counted. |

Windows open at the first failure and are kept per sbc-api replica. The client IP is the TCP peer, or `X-Real-IP` when the peer is in `SBC_TRUSTED_PROXIES`. IPv6 clients are counted per /64. The number of verification slots (at most 4) is lowered at startup when the `SBC_ADMIN_PASSWORD_HASH` memory cost would exceed 96 MiB in total.

### Audit of logins and writes

Every login and every write is recorded in the audit log.

- **Logins.** A successful admin login is an `AuthenticationAttempt` with method `Password`. A failed login, a `400` or `429` refusal, and a rejected bearer token or session cookie are failure records; a rejected credential is tagged `Session` (cookie or `v2.` token), `Jwt` (three dot-separated segments) or `ApiKey`. Failures are aggregated per client and reason (`invalid_credentials`, `invalid_format`, `rate_limited`, `busy`, `invalid_token`) over 60 s. The client is the IPv4 address or the IPv6 /64, and the record keeps the full address. The first failure is recorded at once, and later ones are reported as `"<reason> count=<n>"` by a flush that runs every 5 s and emits at most 256 records. Each of the tables below is guaranteed a fifth of every flush, and unused share goes to the others. First failures are limited to 256 records per second across the whole process. A first failure over that limit is not written; it is counted in the next `AuditRecordsDropped` record (reason `Aggregated`), together with failures dropped because a table was full. Password failures, lockouts, other login refusals and token rejects are tracked in separate bounded tables, so one cannot crowd out another. The username is recorded only when it is the configured admin name; any other name is recorded as `unknown`. When a lockout bucket first locks, a `RateLimitTriggered` record is written with `limit_name` `admin-login-lockout:<ip|ip-overflow|account>`. A request with no credential is not audited.
- **Writes.** Every `POST`, `PUT` and `DELETE`, including `/auth/logout`, produces one `ConfigurationChange`. Its `admin` field is the actor: `oidc:<sub>@<iss>`, `admin:<subject>` (session token) or `apikey:<id>`. The API-key id is the first 16 hex digits of HMAC-SHA-384 under the token-signing key, so it is stable only while `SBC_AUTH_SIGNING_KEY` is. Its `description` reads `entity=<e> id=<id> op=<op> outcome=<ok|failed> [reason=<r>] ... [iss=<iss>] [user=<preferred_username>] [src=<client ip>]`. Trunk ids are `<group>/<trunk>`. A delete of an absent id still answers `200` and is recorded `outcome=failed reason=not_found`. A body that is not a JSON object answers `400` and is recorded. Permission denials name the same actor id, with the same 250-byte cap.
- **Stored rows.** Rows written through sbc-api carry `updated_by = 'local:<actor>'`. The actor is capped at 250 bytes, the same cap as the audit `admin` field. Rows written before this release keep `'local'`. When the site uploads them to central, each upload change carries the row's `updated_by` as `origin_actor`. Central records it on the `sync_change` record as `claimed_origin_actor` (capped at 250 bytes). It is the site's claim; the record's actor is still the site's service account.
- **Central.** central-config-api records every operator write with the same grammar. A write whose body is refused before the token is checked is recorded with actor `unauthenticated` and `reason=invalid`, aggregated per client like an auth failure.

Paths under `/api/v1` that sbc-api does not own are read-only: `GET` is forwarded to the daemon, and `POST`, `PUT` and `DELETE` answer `405` with `Allow: GET`.

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

Check system health status. `status` is `"healthy"` when the SBC daemon
answers on its SystemService gRPC, `"degraded"` (with an `error` field)
when it does not. Always returns 200 — degradation is reported in the
payload, not as a transport error.

```
GET /api/v1/system/health
```

**Response:**
```json
{
  "status": "healthy",
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

**NIST 800-53 Rev5 Controls:** AU-3, AU-6, AC-3, AC-6, SI-12 (see `docs/NIST-800-53-CONTROLS.md`, Call Detail Records)

Served by `sbc-api-server` (`crates/sbc/sbc-api-server/src/handlers/cdrs.rs`). Each request is forwarded to the daemon's gRPC `CdrService` and reads that node's in-memory ring of recent CDRs (at most `cdr.ring_capacity`). The rotated files on the daemon are the durable record. There is no search, correlation, delete or purge endpoint, and no `cdr:admin` permission.

The daemon mounts `CdrService` only on an mTLS listener (`grpc.require_mtls = true`, with sbc-api given `SBC_DAEMON_GRPC_TLS_{CA,CERT,KEY}_FILE`) or a loopback listener. Otherwise every endpoint below returns `503` with an explanation. With the default Helm chart (`sbcDaemon.grpcMtls.enabled = false`) these endpoints return `503`.

Errors use the body `{"error": "<message>"}`. Status mapping: `400` for invalid parameters or an invalid argument from the daemon; `403` without the permission; `404` when the CDR is not found; `429` when an export is already running; `502` when the daemon is unreachable or returned an invalid CDR; `503` when the daemon does not expose CdrService or CDRs are disabled.

Records use schema v1, the JSON form of `uc_cdr::CallRecord`. Times are UTC epoch milliseconds (`setup_ms`, `ring_ms`, `answer_ms`, `end_ms`). Caller and callee fields are stored after the daemon's `cdr.pii` policy, so they may be masked or HMAC-hashed.

### List CDRs

```text
GET /api/v1/cdrs
```

**Permission:** `cdr:read`

**Query Parameters** (unknown parameters are rejected with 400; values are limited to 256 bytes):

| Parameter | Type | Description |
| --- | --- | --- |
| `start` | integer | Inclusive lower bound on `setup_ms` (epoch ms) |
| `end` | integer | Exclusive upper bound on `setup_ms` (epoch ms); must be after `start` |
| `caller` | string | Exact match on `caller` (as stored) |
| `callee` | string | Exact match on `callee_dialed` or `callee_translated` |
| `disposition` | string | `answered`, `failed`, `cancelled`, `rejected`, `busy`, `no_answer`, `media_failure`, `operator_terminated` or `recording_failure` |
| `trunk` | string | Matches `final_trunk` or any `trunks_tried` entry |
| `page_token` | string | Opaque (digits) token from a previous response |
| `page_size` | integer | Default 100, capped at 500 |

**Response:** newest first.

```json
{
  "cdrs": [ { "schema_version": 1, "record_id": "sbc-a-42", "a_call_id": "...", "disposition": "answered", "...": "..." } ],
  "next_page_token": "41",
  "total": 10000,
  "node_id": "sbc-a"
}
```

`next_page_token` is `null` on the last page. `total` is the number of records in the node's ring.

Records written since CDR schema v4 can carry `recording` (`recorded`, `partial`, `failed`, `not_recordable`, `opt_out`; absent when the call did not match the `[recording]` trigger) and `recording_session_id` (RFC 7865 session UUID). The gRPC-to-REST conversion is tested (`recording_fields_round_trip`); the REST endpoint itself is not tested with these fields. See "Call Recording (SIPREC)" in [SBC-ADMIN-GUIDE.md](SBC-ADMIN-GUIDE.md).

### Get CDR

```text
GET /api/v1/cdrs/{record_id}
```

**Permission:** `cdr:read`

Returns one record (`{node_id}-{sequence}`), or 404.

### Export CDRs

```text
GET /api/v1/cdrs/export
```

**Permission:** `cdr:export`

**Query Parameters:** `format` = `jsonl` (default) or `csv`, plus the List CDRs filters.

Response: `200` with `Content-Type: application/x-ndjson` (jsonl) or `text/csv; charset=utf-8` (csv), `Content-Disposition: attachment; filename="cdrs.<ext>"`, and `x-cdr-truncated: true|false`. An export returns at most 50 000 records. Each sbc-api replica runs one export at a time and answers `429` to a concurrent export. The body is built in memory before it is sent (POA&M-21). CSV cells that start with `= + - @`, TAB or CR are prefixed with `'`. Every export after the permission check is audited as a `CdrExport` event with `outcome` `success`, `truncated`, `failed` or `busy`; `caller` and `callee` filter values are recorded as `<redacted>`.

### CDR Statistics

```text
GET /api/v1/cdrs/stats
```

**Permission:** `cdr:read`

**Response** (pipeline counters of the node, not call statistics):

```json
{
  "emitted": 10000,
  "dropped": 0,
  "write_errors": 0,
  "queue_depth": 0,
  "ring_size": 10000,
  "last_write_ms": 1762261200000,
  "chain_ok": true,
  "writer_alive": true,
  "rotations": 12,
  "health": "healthy",
  "node_id": "sbc-a"
}
```

### Authorization for CDR endpoints

An OIDC token reaches sbc-api only when it carries the `config-admin` scope **and** realm role `fleet-admin` with `sites` containing `*`. Any other valid token gets `403 {"error": "insufficient role"}`, audited as an `AuthorizationDecision` deny with policy `sbc-api-oidc`, before the per-route checks below run.

| Credential | `cdr:read` | `cdr:export` |
| --- | --- | --- |
| Legacy admin credential | yes | yes |
| OIDC fleet admin (`fleet-admin`, `sites` ∋ `*`) | yes | yes |
| OIDC `config-admin` scope without `fleet-admin` on `*` | no (403 at the gate) | no (403 at the gate) |

The per-route check grants from roles only (`cdr-reader` / `auditor` read, `cdr-exporter` / `fleet-admin` export); requested scopes such as `cdr:read` / `cdr:export` grant nothing. On sbc-api only a fleet admin passes the gate. A refused request gets `403 {"error": "permission cdr:read required"}` (or `cdr:export`). It is audited as an `AuthorizationDecision` deny with policy `cdr-rbac` and the user, or `anonymous`.

### gRPC CdrService (daemon)

Defined in `crates/sbc/sbc-grpc-api/proto/cdr.proto` (package `sbc.api.v1`) and served by `sbc-daemon/src/grpc_server/cdr_service.rs`. It is mounted only under `grpc.require_mtls` or on a loopback `grpc.listen_addr`.

| RPC | Request | Response |
| --- | --- | --- |
| `ListCdrs` | `ListCdrsRequest{start_ms, end_ms, caller, callee, disposition, trunk, page_token, page_size}` (page size 0 means 100, capped at 500) | `ListCdrsResponse{cdrs, next_page_token, total_in_ring, node_id}` |
| `GetCdr` | `GetCdrRequest{record_id}` | `GetCdrResponse{cdr}` (`NOT_FOUND` if absent) |
| `GetCdrStats` | `GetCdrStatsRequest{}` | `GetCdrStatsResponse{emitted, dropped, write_errors, queue_depth, ring_size, last_write_ms, chain_ok, writer_alive, rotations, health, node_id}` |

Invalid input returns `INVALID_ARGUMENT`. Disabled CDRs return `FAILED_PRECONDITION`. Under mTLS, every gRPC call (all services) must present a client certificate whose SAN DNS, SAN URI or subject CN is in `grpc.allowed_client_names` (when the list is non-empty), or it gets `PERMISSION_DENIED`. The daemon does no per-user permission check; sbc-api enforces `cdr:read` / `cdr:export`. `ListCdrs` and `GetCdr` are audited as `CdrExport`. The `user` is `cert:<name>@<peer>` under mTLS, or `unauthenticated@<peer>` on loopback. The optional `x-sbc-user` metadata (sbc-api sends `api:<user>`, sbc-cli sends `cli:<user>`) is recorded only as `on_behalf_of`. Loopback access is unauthenticated (POA&M-22). The channel uses tonic's default TLS suites, not CNSA 2.0 (POA&M-16).

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
| `cdr:read` | View call detail records (`/api/v1/cdrs`, `/cdrs/{record_id}`, `/cdrs/stats`); see [Authorization for CDR endpoints](#authorization-for-cdr-endpoints) |
| `cdr:export` | Export CDRs (`/api/v1/cdrs/export`); implies `cdr:read` |
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
- [RUNBOOK.md](https://github.com/192d-Wing/usg-uc/blob/main/deploy/docs/RUNBOOK.md) - Operational procedures
