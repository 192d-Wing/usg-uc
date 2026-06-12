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

Operators (the dashboard, admin tooling) get scope **`config-admin`**,
which the API requires on every write (`POST/PUT/DELETE`). No `site_code`
claim — an operator is a fleet admin and names the site in the path. A
`config-admin` token cannot read the per-site `/v1/sync` surface as a
site (that requires `config-sync` + a matching `site_code`), and a
`config-sync` token cannot write.

```jsonc
{
  "clientId": "usg-uc-config-admin",
  "protocol": "openid-connect",
  "publicClient": true,
  "standardFlowEnabled": true,
  "attributes": { "pkce.code.challenge.method": "S256" },
  "defaultClientScopes": ["config-admin"]
}
```

Define `config-sync` and `config-admin` as realm client scopes so the
mappers and audience (`usg-uc-config`) are attached consistently.
