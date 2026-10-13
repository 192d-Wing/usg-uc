# Route Pattern Reference

Route patterns define how the SBC matches and routes inbound calls. When a call arrives on a trunk with a Calling Search Space (CSS) assigned, the SBC evaluates the called number against route patterns in the CSS's partitions.

Implementation notes:

- Matching is implemented in `uc-routing::SbcRouter` and is wired into `sbc-daemon` (`sip_stack.rs`): the inbound trunk's source IP is mapped to its trunk group and `css_id`, and the dialed digits are routed through the CSS before falling back to dial-plan routing.
- The REST API for partitions, CSS, route patterns, route lists and trunk groups is served by **`sbc-api-server`** (default port 8080), not by `sbc-daemon`. Changes are pushed to the daemon over gRPC (`SbcSyncService`, `TrunkSyncService`), which updates the live router.
- `uc-routing::RoutePattern` carries its own number `transform`, applied inside `SbcRouter::route` before the route list/group is resolved. The REST API accepts it as `transform_type` / `transform_value` (validated on create/update) and the daemon's sync path (`apply_route_pattern_to_router`) sets it on the pattern.

## Pattern Types

### Prefix (default)

Matches numbers that **start with** the given digits.

| Pattern | Matches | Does Not Match |
|---------|---------|----------------|
| `+1213` | +12131234567, +12139160002 | +14151234567 |
| `911` | 911, 9114 | 811 |
| `+1` | +12131234567, +18005551234 | +442071234567 |

### Exact

Matches the number **exactly** (no partial matching).

| Pattern | Matches | Does Not Match |
|---------|---------|----------------|
| `+12139160002` | +12139160002 | +12139160003 |
| `911` | 911 | 9114, 91 |

### Wildcard

Uses special characters for flexible matching:

- **`X`** = any single digit (0-9)
- **`.`** = any remaining digits (greedy, matches rest of string)
- All other characters match literally

| Pattern | Matches | Does Not Match |
|---------|---------|----------------|
| `+1XXXXXXXXXX` | +12131234567, +18005551234 | +442071234567, +1213123456 |
| `+1213XXXXXXX` | +12131234567, +12130000000 | +14151234567 |
| `9.` | 911, 9876543210 | 811 |
| `+1.` | +12131234567, +1 | +442071234567 |
| `XXXX` | 1234, 9876 | 123, 12345 |
| `+1XXX555XXXX` | +12135551234 | +12135561234 |

### Any

Matches **all numbers** unconditionally. Used as a catch-all or default route.

### Regex (library-only)

`uc-routing::DialPattern::Regex` exists in the routing library, but the API-to-daemon sync (`apply_route_pattern_to_router`) does not accept a `regex` pattern type — it falls back to `prefix`. Regex patterns cannot currently be created through the REST API.

## Route Pattern Fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique identifier (e.g., `rp-emergency`) |
| `pattern` | Yes | The pattern string (see types above) |
| `pattern_type` | No | `prefix` (default), `exact`, `wildcard`, or `any`. Unknown values (including `regex`) fall back to `prefix` when applied to the daemon. |
| `partition_id` | Yes | Partition this pattern belongs to |
| `route_group_id` | No | Trunk group to route matched calls to |
| `route_list_id` | No | Route list (ordered route groups; overrides route_group_id). See the failover note below. |
| `blocked` | No | `true` rejects any call matching this pattern in this partition (checked before normal matches) |
| `description` | No | Human-readable description |
| `priority` | No | Lower number = higher priority (default: 100) |
| `transform_type` | No | Digit manipulation applied to the dialled number before routing: `none` (default), `strip_prefix`, `add_prefix`, `replace_prefix`, `replace`. Same spelling as dial-plan entries. |
| `transform_value` | With a transform | `strip_prefix`: number of leading digits to remove (> 0). `add_prefix`: digits to prepend. `replace_prefix`: `from|to`. `replace`: the whole replacement number. The API rejects a missing or malformed value with 400. |

## Routing Chain

``` mermaid
flowchart TD
    call["Inbound Call"] --> tg["Trunk Group<br>(has CSS assigned)"]
    tg --> css["Calling Search Space<br>(ordered list of Partitions)"]
    css --> p1["Partition 1 — Route Patterns<br>(matched by specificity then priority)"]
    p1 -->|match| rg["Route Group<br>(direct trunk selection)"]
    p1 -->|match| rl["Route List<br>(ordered Route Groups — daemon uses the first only)"]
    p1 -->|no match| p2["Partition 2 — Route Patterns …"]
    p2 -->|no match| ann["Announcement<br>(&quot;Number Not In Service&quot;)"]
```

## Pattern Specificity

Partitions are walked in CSS order and **the first partition containing any match wins**; later partitions are not consulted. Within that partition, when multiple patterns match, the highest specificity *score* wins. The score is a heuristic (`SbcRouter::pattern_specificity`), not a strict class ordering:

| Type | Score |
|------|-------|
| **Exact** | 2 × pattern length |
| **Prefix** | pattern length |
| **Wildcard** | number of literal characters before the first `X` or `.` |
| **Any** / **Regex** | 0 |

In practice this yields Exact > Prefix > Wildcard > Any for patterns of similar length, but a long prefix can outscore a short exact pattern (e.g. `+1213916` prefix scores 8, `911` exact scores 6).

If scores are equal, the `priority` field breaks the tie (lower = preferred). A `blocked` pattern matching the digits in the current partition rejects the call before any other pattern is considered.

### Route List Failover (partially wired)

`SbcRouter::route` returns the route list's members in order, but **`sbc-daemon` currently sends the call only to the first route group** (`sip_stack.rs`, `route_group_ids.first()`); subsequent members are not retried on failure. Trunk-level failover inside a trunk group (priority order, `routing.max_failover_attempts`) does work. Retrying across route-list members is planned.

## Examples

### Route all US numbers to a trunk group

```json
{
  "id": "rp-us-domestic",
  "pattern": "+1XXXXXXXXXX",
  "pattern_type": "wildcard",
  "partition_id": "pt-inbound",
  "route_group_id": "rg-internal-phones",
  "description": "US domestic numbers to internal phones"
}
```

### Route emergency calls

```json
{
  "id": "rp-emergency",
  "pattern": "911",
  "pattern_type": "exact",
  "partition_id": "pt-emergency",
  "route_group_id": "rg-psap",
  "priority": 1,
  "description": "Emergency calls to PSAP trunk"
}
```

### Catch-all with route list (first member used today)

```json
{
  "id": "rp-catch-all",
  "pattern": ".",
  "pattern_type": "wildcard",
  "partition_id": "pt-default",
  "route_list_id": "rl-failover",
  "priority": 999,
  "description": "Default route with carrier failover"
}
```

### Strip +1 prefix and route

To strip a dialled `+1` before the call reaches the trunk, give the pattern a transform:

```json
{
  "id": "rp-us-e164",
  "pattern": "+1",
  "pattern_type": "prefix",
  "partition_id": "pt-pstn",
  "route_group_id": "rg-carrier",
  "transform_type": "strip_prefix",
  "transform_value": "2"
}
```

`+15551234567` is then routed as `5551234567`. Use `add_prefix` to put a `+1` back on, `replace_prefix` (`"011|+"`) to convert an international dial prefix to E.164, or `replace` to send every match to one fixed number.

## API Examples

These endpoints are served by **`sbc-api-server`** (the address below is an sbc-api instance), and are synced to the daemon over gRPC. `sbc-daemon` itself only exposes read-only `/api/v1/dialplans` and `/api/v1/cdrs` plus `/healthz` and `/readyz`. A `/api/v1/routelists` resource exists alongside the ones shown.

### Create a partition

```bash
curl -X POST http://192.168.0.242:8080/api/v1/partitions \
  -H 'Content-Type: application/json' \
  -d '{"id": "pt-inbound", "name": "Inbound Partition"}'
```

### Create a CSS with partitions

```bash
curl -X POST http://192.168.0.242:8080/api/v1/css \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "css-bulkvs",
    "name": "BulkVS Inbound",
    "partitions": ["pt-inbound"]
  }'
```

### Create a route pattern

```bash
curl -X POST http://192.168.0.242:8080/api/v1/routepatterns \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "rp-all-calls",
    "pattern": "+1.",
    "pattern_type": "wildcard",
    "partition_id": "pt-inbound",
    "route_group_id": "rg-internal",
    "description": "Route all US calls to internal phones"
  }'
```

### Assign CSS to a trunk group

```bash
curl -X PUT http://192.168.0.242:8080/api/v1/trunkgroups/rg-bulkvs \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "rg-bulkvs",
    "name": "BulkVS",
    "strategy": "priority",
    "css_id": "css-bulkvs"
  }'
```
