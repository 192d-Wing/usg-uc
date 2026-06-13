# Keycloak clients for central-config

`central-config-api` authorizes two distinct token populations, separated
by OAuth scope. Both validate against the same realm/issuer and audience
(`CENTRAL_OIDC_AUDIENCE`, default `usg-uc-config`).

## 1. Per-site sync service accounts — `usg-uc-site-sync`

One **client credentials** grant per base. The token must carry:

- scope **`config-sync`**
- claim **`site_code`** = the base's canonical (uppercase) site code,
  e.g. `OOPL-001`. The API requires this to equal the `{site_code}` in the
  request path, so a base can only ever read its own shard.

Realm config (per site, via a client-scope mapper that emits a constant
`site_code` claim, or a per-site client with a hardcoded mapper):

```jsonc
{
  "clientId": "usg-uc-site-sync-oopl-001",
  "protocol": "openid-connect",
  "publicClient": false,
  "serviceAccountsEnabled": true,
  "standardFlowEnabled": false,
  "attributes": { "access.token.lifespan": "900" },
  "protocolMappers": [
    {
      "name": "site_code",
      "protocolMapper": "oidc-hardcoded-claim-mapper",
      "config": {
        "claim.name": "site_code",
        "claim.value": "OOPL-001",
        "access.token.claim": "true",
        "jsonType.label": "String"
      }
    }
  ],
  "defaultClientScopes": ["config-sync"]
}
```

The client secret is delivered to the site as the `token` key of the
`<release>-config-sync` Secret (see `sbcConfigSync.tokenSecret`). The
agent presents the resulting access token; rotating it is a Secret update
+ pod restart. (A token-refresh loop in the agent is a planned follow-up;
today the Secret holds a current access token.)

## 2. Operator / dashboard — `usg-uc-config-admin`

Operators (the dashboard, admin tooling) authenticate with the base scope
**`config`** — the coarse "may reach the operator API" gate. *What* an
operator may do is decided per request by **ABAC** in `central-config-api`
([`policy.rs`]), from two token claims the IdP maps in:

- **`roles`** (string array) — capability roles, AWS-IAM-shaped. Each role
  is either a **managed name** or a raw **`entity:verb`** pattern (with `*`
  wildcards). An action is `entity:verb`, e.g. `phones:write`,
  `dialplans:read`; a request is allowed iff some role grants the action.
  Managed names:
  - `fleet-admin` / `site-admin` → `*:*`
  - `auditor` / `config-reader` → `*:read`
  - `phones-admin` → `phones:*`, `directory-admin` → `directory:*`,
    `trunk-admin` → `trunkgroups:*`, `dialplan-admin` → `dialplans:*` +
    `routing:*`
  - any other string is treated as a raw pattern, so the IdP can emit
    `phones:write`, `routing:*`, `*:read`, etc. directly.
- **`sites`** (string array) — the site-code allowlist the roles apply to,
  or `["*"]` for the whole fleet. A request to `/v1/sites/{site}/…` is
  allowed only if `site` ∈ `sites` (or `sites` contains `*`). Fleet-level
  resources (the site registry `POST /v1/sites`, the global
  `/v1/templates/*` surface) require the `*` site grant.

Entities: `phones`, `directory`, `trunkgroups`, `dialplans`, `routing`,
`site_config` (site-scoped); `sites`, `templates` (fleet-level). Verbs:
`read` (GET), `write` (POST/PUT/DELETE).

**Back-compat.** A token carrying the legacy **`config-admin`** scope is
treated as a full fleet admin (`*:*` on every site) regardless of
`roles`/`sites`, so existing operator credentials keep working. Make
`config-admin` an **optional** client scope issued only to entitled fleet
admins; make `config` a **default** scope for every operator. (A token
without `config` is rejected at the gate; a `config`-only token with no
`roles`/`sites` reaches the API but is denied every action.)

A site's `config-sync` token cannot reach the operator surface (wrong
scope), and an operator token cannot read the per-site `/v1/sync` surface
as a site (that needs `config-sync` + a matching `site_code`).

[`policy.rs`]: ../../crates/sbc/central-config-api/src/policy.rs

### Mapping `roles` and `sites` in Keycloak

Map realm/client roles into a `roles` claim and a user attribute into a
`sites` claim:

```jsonc
"protocolMappers": [
  {
    "name": "roles",
    "protocolMapper": "oidc-usermodel-realm-role-mapper",
    "config": {
      "claim.name": "roles", "jsonType.label": "String",
      "multivalued": "true", "access.token.claim": "true"
    }
  },
  {
    "name": "sites",
    "protocolMapper": "oidc-usermodel-attribute-mapper",
    "config": {
      "user.attribute": "sites", "claim.name": "sites",
      "jsonType.label": "String", "multivalued": "true",
      "access.token.claim": "true"
    }
  }
]
```

A per-site auditor is then a user with realm role `auditor` and a `sites`
attribute of `["OOPL-001"]`; a fleet admin gets `["*"]` (or the optional
`config-admin` scope).

**Single sign-on for the dashboard.** A `config-admin` (fleet-admin) token
also authorizes the per-site `sbc-api-server` runtime endpoints
(registrations, CDRs, system, users, phone reboot): when `SBC_OIDC_ISSUER`/
`SBC_OIDC_AUDIENCE` are set (Helm `sbcApi.oidc`), sbc-api accepts these
tokens alongside its legacy cookie/HMAC admin login. So a fleet admin signs
in once and the dashboard uses one token for both the central config API
and every site's runtime API. The token's `aud` must therefore satisfy
both validators — set the central audience (`usg-uc-config`) on the
operator client and configure `sbcApi.oidc.audience` to match. (sbc-api's
runtime surface still gates on `config-admin`; a granular central-only
operator without it can manage central config but not the per-site runtime
endpoints.)

```jsonc
{
  "clientId": "usg-uc-config-admin",
  "protocol": "openid-connect",
  "publicClient": true,
  "standardFlowEnabled": true,
  "attributes": { "pkce.code.challenge.method": "S256" },
  // `config` (the operator gate) + the role/site mappers go to every
  // operator; `config-admin` is optional, granted only to fleet admins.
  "defaultClientScopes": ["config"],
  "optionalClientScopes": ["config-admin"]
}
```

Define `config-sync`, `config`, and `config-admin` as realm client scopes
so the mappers and audience (`usg-uc-config`) are attached consistently.
Attach the `roles`/`sites` mappers to the `config` scope so every operator
token carries them.
