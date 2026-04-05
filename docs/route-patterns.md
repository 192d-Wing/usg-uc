# Route Pattern Reference

Route patterns define how the SBC matches and routes inbound calls. When a call arrives on a trunk with a Calling Search Space (CSS) assigned, the SBC evaluates the called number against route patterns in the CSS's partitions.

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

## Route Pattern Fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique identifier (e.g., `rp-emergency`) |
| `pattern` | Yes | The pattern string (see types above) |
| `pattern_type` | No | `prefix` (default), `exact`, `wildcard`, or `any` |
| `partition_id` | Yes | Partition this pattern belongs to |
| `route_group_id` | No | Trunk group to route matched calls to |
| `route_list_id` | No | Route list for failover (overrides route_group_id) |
| `description` | No | Human-readable description |
| `priority` | No | Lower number = higher priority (default: 100) |

## Routing Chain

```
Inbound Call
  |
  v
Trunk Group (has CSS assigned)
  |
  v
Calling Search Space (ordered list of Partitions)
  |
  v
Partition 1 --> Route Patterns (matched by specificity then priority)
  |                |
  |                +--> Route Group (direct trunk selection)
  |                +--> Route List (failover: try Route Groups in order)
  |
Partition 2 --> Route Patterns ...
  |
  v
No match --> Announcement ("Number Not In Service")
```

## Pattern Specificity

When multiple patterns match, the most specific wins:

1. **Exact** (highest priority)
2. **Prefix** (longer prefix beats shorter)
3. **Wildcard** (more literal characters beats fewer)
4. **Any** (lowest priority, catch-all)

If specificity is equal, the `priority` field breaks the tie (lower = preferred).

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

### Catch-all with route list failover

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

Create the route pattern, then use a dial plan entry with a `strip_prefix` transform to remove the `+1` before forwarding to the destination.

## API Examples

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
