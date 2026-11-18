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

**The `config-admin` scope grants nothing by itself.** A client chooses
which scopes to request, so authorization is decided on the `roles` and
`sites` claims only (RFC 6749 §3.3): fleet access needs role `fleet-admin`
(or `site-admin` / `config-admin` as role names) **and** `sites` containing
`*`. A token that carries the `config-admin` scope without them is denied
like any other. Keep `config-admin` an **optional** client scope with a role
scope mapping to `fleet-admin`, so Keycloak issues it only to fleet admins
(defence in depth; the API checks do not depend on it); make `config` a
**default** scope for every operator. (A token without `config` is rejected
at the gate; a `config`-only token with no `roles`/`sites` reaches the API
but is denied every action.)

**Upgrade note.** Earlier releases treated a `config-admin`-scoped token as a
full fleet admin regardless of `roles`/`sites`. Before upgrading, give every
fleet operator realm role `fleet-admin` and a `sites` attribute of `["*"]`;
operators without them get 403 from central-config-api and sbc-api.

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
attribute of `["OOPL-001"]`; a fleet admin gets realm role `fleet-admin` and
`["*"]`.

**Single sign-on for the dashboard.** A fleet-admin token (realm role
`fleet-admin`, `sites` ∋ `*`, scope `config-admin`) also authorizes the
per-site `sbc-api-server` runtime endpoints
(registrations, CDRs, system, users, phone reboot): when `SBC_OIDC_ISSUER`/
`SBC_OIDC_AUDIENCE` are set (Helm `sbcApi.oidc`), sbc-api accepts these
tokens alongside its legacy cookie/HMAC admin login. So a fleet admin signs
in once and the dashboard uses one token for both the central config API
and every site's runtime API. The token's `aud` must therefore satisfy
both validators — set the central audience (`usg-uc-config`) on the
operator client and configure `sbcApi.oidc.audience` to match. (sbc-api
requires the `config-admin` scope as a coarse gate **and** role
`fleet-admin` with `sites` ∋ `*`; any other valid token gets 403 and an
`AuthorizationDecision` deny with policy `sbc-api-oidc`. A granular
central-only operator can manage central config but not the per-site
runtime endpoints.)

**Per-site SIP user accounts.** `config-admin` alone no longer grants
`/users`: reads need realm role `users-reader`, `users-admin`, `auditor` or
`fleet-admin`; create/update/delete need `users-admin` or `fleet-admin`.
Requested scopes (`users:read`, `users:admin`, `cdr:read`, `cdr:export`)
grant nothing. Today only a fleet admin passes the sbc-api OIDC gate, so on
sbc-api these roles matter for fleet admins only. Create the `users-admin`
and `users-reader` realm roles and include them in the `roles` mapper. Denials are audited (`AuthorizationDecision`, policy `users-rbac`);
every account change is audited (`AccountManagement`).

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

**Required after every realm import: bind the `config-admin` scope to realm
role `fleet-admin`** (role scope mapping). `dcim-central-config-partial-import.json`
records it as `scopeMappings`, but Keycloak partial import does not apply
realm-level scope mappings (and `ifResourceExists: SKIP` leaves an existing
`config-admin` scope unchanged), so set it explicitly. Admin console:
*Client scopes* → `config-admin` → *Scope* → *Assign role* → `fleet-admin`.
Or with `kcadm.sh` (and `jq`):

```sh
SCOPE_ID=$(kcadm.sh get client-scopes -r dcim --fields id,name \
  | jq -r '.[] | select(.name == "config-admin") | .id')
ROLE=$(kcadm.sh get roles/fleet-admin -r dcim --fields id,name)
kcadm.sh create "client-scopes/$SCOPE_ID/scope-mappings/realm" -r dcim -b "[$ROLE]"

# Verify: must print exactly "fleet-admin".
kcadm.sh get "client-scopes/$SCOPE_ID/scope-mappings/realm" -r dcim --fields name \
  | jq -r '.[].name'
```

Attach the verification output to the deployment record. The server-side
checks (role and `sites` claims) are the control; this mapping keeps the
scope from being issued to other users.

**The `sites` attribute must be editable by administrators only.** With the
scope no longer authorizing anything, `roles` and `sites` decide access, so a
user who could edit their own `sites` could widen their site scope. In the
realm *User profile*:

- declare `sites` as an attribute with **edit permission `admin` only** (view
  may include `user`), and
- set the **unmanaged attribute policy** to anything other than `ENABLED`
  (`ADMIN_EDIT`, `ADMIN_VIEW` or disabled), so undeclared attributes cannot be
  set from the account console.

Verify:

```sh
kcadm.sh get users/profile -r dcim \
  | jq '{unmanaged: .unmanagedAttributePolicy,
         sites: (.attributes[] | select(.name == "sites") | .permissions)}'
# expect: unmanaged != "ENABLED"; sites.permissions.edit == ["admin"]
```
