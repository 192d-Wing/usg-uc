# Client Provisioning & OIDC Sign-In Design

Status: **Draft / proposal**
Scope: Desktop (Tauri) and Android soft clients, SBC fleet, Keycloak IdP.

## Goal

A user installs the soft client, types a single value — the service domain
(`sip.example.mil`) — and everything else is automatic:

1. The client discovers the nearest POP via the anycast/GeoDNS address.
2. The POP points the client at the IdP (Keycloak).
3. The user authenticates in the **system browser** — Device Authorization
   Grant (RFC 8628) on desktop (no loopback listener, no redirect URI);
   Authorization Code + PKCE (RFC 8252) via claimed App Links on Android.
4. The client fetches its per-user configuration (DN, SIP identity, registrar domain) with the bearer token.
5. The client REGISTERs to its assigned unicast SBC.

No SIP password is ever typed. No per-device provisioning files.

## Architecture Overview

```mermaid
flowchart TD
    U["User enters sip.example.mil"] --> C["Soft client"]
    C -->|"1. HTTPS discovery (anycast)"| D["Discovery endpoint<br/>nearest POP"]
    D -->|"2. issuer + endpoints"| C
    C -->|"3. RFC 8628 device grant<br/>(system browser)"| K["Keycloak<br/>idp.example.mil"]
    K -->|"4. access + refresh token"| C
    C -->|"5. GET /v1/client-config<br/>Bearer token"| P["Provisioning API<br/>nearest POP"]
    P -->|"6. DN, SIP identity, registrar domain"| C
    C -->|"7. NAPTR + SRV (RFC 3263)"| DNS["DNS"]
    C -->|"8. REGISTER (unicast)"| S1["SBC pop-east"]
    C -.->|"SRV failover"| S2["SBC pop-west"]
    P -->|"validate JWT via JWKS"| K
    S1 -->|"validate JWT via JWKS"| K
```

Key routing decision: **anycast for first contact, unicast for registration.**
The discovery/config responses are served from the POP the anycast route
landed on; that POP returns its own **POP-scoped registrar domain**. The
client resolves it per RFC 3263 (NAPTR for transport, SRV for targets), which
yields the POP's unicast SBCs first and a backup POP at lower SRV priority —
the long-lived SIP/TLS connection is never exposed to BGP route flaps, and
transport selection plus failover order live in DNS, not in client config.

## Sign-In Sequence

```mermaid
sequenceDiagram
    autonumber
    participant User
    participant Client as Soft Client
    participant Browser as System Browser
    participant POP as Nearest POP (anycast)
    participant KC as Keycloak
    participant SBC as SBC (unicast)

    User->>Client: enter "sip.example.mil"
    Client->>POP: GET /.well-known/sip-client-config
    POP-->>Client: 200 discovery JSON (issuer, endpoints, pop_id)
    Client->>KC: GET /.well-known/openid-configuration
    KC-->>Client: OIDC metadata
    Client->>KC: POST /auth/device (client_id, scope)
    KC-->>Client: device_code + user_code + verification_uri_complete
    Client->>Browser: open verification_uri_complete (user_code shown in app)
    Browser->>KC: login page (SSO / password / WebAuthn)
    User->>Browser: authenticate + approve device code
    loop poll every `interval` seconds
        Client->>KC: POST /token (device_code)
        KC-->>Client: authorization_pending
    end
    KC-->>Client: access_token + refresh_token + id_token
    Client->>POP: GET /v1/client-config (Authorization: Bearer)
    POP->>KC: validate JWT (cached JWKS)
    POP-->>Client: 200 config JSON (DN, SIP identity, registrar domain)
    Note over Client: resolve registrar domain via NAPTR + SRV (RFC 3263)
    Client->>SBC: REGISTER (Bearer per RFC 8898, or RFC 8760 digest)
    SBC->>KC: validate JWT (cached JWKS)
    SBC-->>Client: 200 OK (expires=300)

    loop every ~half token lifetime
        Client->>KC: POST /token (refresh_token)
        KC-->>Client: new access_token
        Client->>SBC: re-REGISTER with fresh token
    end
```

Token-expiry edge case: if the refresh token is revoked or the Keycloak SSO
session ends, the client drops to the `signed_out` state and re-runs the
browser flow. Active calls are not torn down — only re-REGISTER fails.

## Endpoint 1: Discovery

`GET https://sip.example.mil/.well-known/sip-client-config`

- Served on the anycast VIP, TLS required, no auth.
- Cacheable (`Cache-Control: max-age=300`) — contents are per-POP but stable.
- This is the only URL the client ever constructs from user input.
- The entered service domain must be `host`, `host:port` or
  `https://host[:port]`, with an optional trailing `/`. Any other scheme,
  userinfo, path, query, fragment, IP literal, non-LDH label, or a host that
  is itself a public suffix is refused before any request
  (`client-provisioning/src/discovery.rs` `parse_service_domain`).
- All provisioning and OIDC HTTP requests are https-only and do not follow
  redirects; a 3xx response is an error (`client-provisioning/src/http.rs`
  `build_http_client`, `src/lib.rs` `check_success`).

### Discovery example

```json
{
  "schema_version": 1,
  "service_name": "Example Voice",
  "pop_id": "us-east-1",
  "oidc": {
    "issuer": "https://idp.example.mil/realms/voice",
    "client_id": "usg-uc-softclient",
    "scopes": ["openid", "profile", "offline_access", "sip"]
  },
  "provisioning": {
    "config_endpoint": "https://us-east-1.pop.example.mil/v1/client-config"
  },
  "minimum_client_version": {
    "desktop": "0.7.0",
    "android": "0.2.0"
  }
}
```

### Discovery JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://sip.example.mil/schemas/discovery.v1.json",
  "title": "SIP Client Discovery Document",
  "type": "object",
  "required": ["schema_version", "pop_id", "oidc", "provisioning"],
  "properties": {
    "schema_version": { "type": "integer", "const": 1 },
    "service_name": { "type": "string" },
    "pop_id": { "type": "string" },
    "oidc": {
      "type": "object",
      "required": ["issuer", "client_id", "scopes"],
      "properties": {
        "issuer": { "type": "string", "format": "uri" },
        "client_id": { "type": "string" },
        "scopes": { "type": "array", "items": { "type": "string" } }
      }
    },
    "provisioning": {
      "type": "object",
      "required": ["config_endpoint"],
      "properties": {
        "config_endpoint": { "type": "string", "format": "uri" }
      }
    },
    "minimum_client_version": {
      "type": "object",
      "additionalProperties": { "type": "string" }
    }
  }
}
```

Notes:

- `issuer` is the OIDC issuer; the client fetches
  `{issuer}/.well-known/openid-configuration` from there — we never hardcode
  Keycloak paths in the client.
- The client MUST verify that the discovery document's `issuer` is https,
  has no userinfo, query or fragment, and its host is under the same
  registrable domain as the entered service domain, or matches a build-time
  pin scoped to that registrable domain (`PINNED_ISSUERS`). A pin applies
  only to service domains under its own registrable domain. The only pin,
  `icam.oopl.dev.mil` for `oopl.dev.mil`, is already covered by the
  same-domain rule and grants no further trust. This limits which IdP a
  POP can send the client to.
- "Registrable domain" is one label plus the longest matching entry of a
  built-in suffix list (`dev.mil`; otherwise the TLD), not the full Public
  Suffix List (POA&M-370). So `sbc.oopl.dev.mil` is scoped to
  `oopl.dev.mil`, and `a.dev.mil` and `b.dev.mil` are different scopes.
- `provisioning.config_endpoint` MUST be https, without userinfo, with a
  DNS host inside the entered service domain's registrable domain (any
  port). The client checks this before sending the bearer token
  (`fetch_client_config`).
- The OIDC metadata `issuer` and its authorization, token,
  device_authorization, end_session and revocation endpoints, and the
  device grant's `verification_uri` / `verification_uri_complete`, MUST be
  https, without userinfo, inside the issuer's registrable domain
  (`verify_oidc_endpoints`, `verify_device_authorization`).

## Endpoint 2: Client Config (provisioning)

`GET https://{pop}/v1/client-config`
`Authorization: Bearer <access_token>`

- Requires a valid JWT from the `voice` realm with the `sip` scope.
- The provisioning service maps `sub` (or `preferred_username`) to the user's
  directory entry and returns everything the SIP UA needs.
- `Cache-Control: no-store` — contains identity material.

### Config example

```json
{
  "schema_version": 1,
  "user": {
    "display_name": "Jane Doe",
    "email": "jdoe@example.mil"
  },
  "sip": {
    "uri": "sip:1456055067@example.mil",
    "dn": "1456055067",
    "extension": "5067",
    "domain": "example.mil",
    "auth": {
      "mode": "bearer",
      "digest": null
    }
  },
  "registration": {
    "expires_seconds": 300,
    "registrar_domain": "us-east-1.reg.example.mil"
  },
  "media": {
    "codecs": ["opus", "pcmu", "pcma"],
    "dtmf": "rfc4733",
    "srtp": "none"
  },
  "features": {
    "voicemail_uri": "sip:*97@example.mil",
    "mwi": true
  },
  "ttl_seconds": 3600
}
```

When `sip.auth.mode` is `"ephemeral-digest"`, the `digest` object is populated
instead:

```json
"auth": {
  "mode": "ephemeral-digest",
  "digest": {
    "username": "1456055067",
    "password": "tGq9...one-time...",
    "realm": "example.mil",
    "expires_at": "2026-06-11T19:30:00Z"
  }
}
```

### Config JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://sip.example.mil/schemas/client-config.v1.json",
  "title": "SIP Client Configuration",
  "type": "object",
  "required": ["schema_version", "sip", "registration", "ttl_seconds"],
  "properties": {
    "schema_version": { "type": "integer", "const": 1 },
    "user": {
      "type": "object",
      "properties": {
        "display_name": { "type": "string" },
        "email": { "type": "string", "format": "email" }
      }
    },
    "sip": {
      "type": "object",
      "required": ["uri", "dn", "domain", "auth"],
      "properties": {
        "uri": { "type": "string", "pattern": "^sips?:" },
        "dn": { "type": "string" },
        "extension": { "type": "string" },
        "domain": { "type": "string" },
        "auth": {
          "type": "object",
          "required": ["mode"],
          "properties": {
            "mode": { "enum": ["bearer", "ephemeral-digest"] },
            "digest": {
              "type": ["object", "null"],
              "required": ["username", "password", "realm", "expires_at"],
              "properties": {
                "username": { "type": "string" },
                "password": { "type": "string" },
                "realm": { "type": "string" },
                "expires_at": { "type": "string", "format": "date-time" }
              }
            }
          }
        }
      }
    },
    "registration": {
      "type": "object",
      "required": ["expires_seconds", "registrar_domain"],
      "properties": {
        "expires_seconds": { "type": "integer", "minimum": 60 },
        "registrar_domain": { "type": "string", "format": "hostname" }
      }
    },
    "media": {
      "type": "object",
      "properties": {
        "codecs": { "type": "array", "items": { "type": "string" } },
        "dtmf": { "enum": ["rfc4733", "inband", "info"] },
        "srtp": { "enum": ["none", "sdes", "dtls"] }
      }
    },
    "features": { "type": "object" },
    "ttl_seconds": { "type": "integer", "minimum": 60 }
  }
}
```

Notes:

- `registration.registrar_domain` is **POP-scoped** — the POP that served the
  request returns its own domain; this is the anycast-to-unicast handoff. The
  client resolves it per RFC 3263, so transport selection and failover order
  come from DNS, never from the config payload:

  ```text
  ; transport selection (NAPTR, RFC 3263)
  us-east-1.reg.example.mil.            IN NAPTR 10 50 "s" "SIPS+D2T" "" _sips._tcp.us-east-1.reg.example.mil.

  ; target selection + failover (SRV priority/weight)
  _sips._tcp.us-east-1.reg.example.mil. IN SRV 10 50  5061 sbc1.us-east-1.pop.example.mil.
  _sips._tcp.us-east-1.reg.example.mil. IN SRV 10 50  5061 sbc2.us-east-1.pop.example.mil.
  _sips._tcp.us-east-1.reg.example.mil. IN SRV 20 100 5061 sbc1.us-west-2.pop.example.mil.
  ```

  *Implementation status:* the desktop client does not resolve NAPTR/SRV
  yet — it does an A/AAAA lookup of the registrar domain (IPv6 preferred)
  with the default port derived from the URI scheme (`sips:` → 5061,
  `sip:` → 5060). See Implementation Phases below.

- The client refuses a config whose `registration.registrar_domain` is not
  a bare `host` or `host:port` (LDH DNS name, port 1-65535) inside the
  entered service domain's registrable domain. `sip.uri` must be
  `sip:`/`sips:` `[user@]host[:port]` with no parameters or headers, and
  `sip.domain` a bare DNS host, both in the same scope
  (`client-provisioning/src/discovery.rs` `verify_client_config`).
  `features` is not checked. This is a client-side check only; a matching
  check where the POP builds the config is an SBC-side follow-up.

- Registration robustness uses SIP Outbound (RFC 5626): the Contact carries
  `reg-id` and `+sip.instance`, flows are kept alive per RFC 5626 keepalives,
  and on flow failure the client re-resolves and registers to the next SRV
  target.
- `ttl_seconds` tells the client when to re-fetch config (picks up DN changes,
  POP drains, codec policy changes) without re-authenticating.
- The two `auth.mode` values let us ship ephemeral-digest first (the existing
  digest stack extended with RFC 8760) and move to bearer (RFC 8898) later;
  the client supports both from day one. Both modes are specified in the SIP
  Authentication Profile below.

## SIP Authentication Profile

### Bearer mode (RFC 8898)

Bearer authentication applies to **all** SIP requests, not only REGISTER:

- REGISTER carries `Authorization: Bearer <access_token>`. The registrar
  validates the JWT (ES384 signature via JWKS, `iss`/`aud`/`exp`, `nbf` when
  present) and requires the To-URI user part to equal the `dn` claim.
- Out-of-dialog requests (INVITE, SUBSCRIBE, MESSAGE) proactively carry the
  current access token the same way. On `401` with
  `WWW-Authenticate: Bearer` or `407` with `Proxy-Authenticate: Bearer`, the
  client refreshes the token and retries once with `Authorization` /
  `Proxy-Authorization` respectively.
- Mid-dialog requests (re-INVITE, UPDATE, BYE) may also be challenged, so the
  client attaches its freshest valid token to every request. Established
  dialogs are **not** torn down when a token expires — enforcement is per
  transaction, so an active call survives a token rotation.
- A challenge with `error="invalid_token"` means refresh-and-retry; any other
  Bearer error parameter is terminal and drops the client to the
  `Authenticating` state.

### Digest mode (RFC 8760 mandatory)

Ephemeral-digest mode **MUST use RFC 8760 hash algorithms**:

- SBC challenges offer `algorithm=SHA-256` (optionally `SHA-512-256`); MD5
  challenges are never emitted and MD5 responses are rejected.
- RFC 3261's MD5 default does not meet this deployment's CNSA/FIPS posture
  (see [CNSA-2-COMPLIANCE.md](CNSA-2-COMPLIANCE.md)).
- Credentials remain one-time-fetch and short-lived as specified in the
  config endpoint section.

## Keycloak Setup

### Realm: `voice`

| Setting | Value | Why |
| --- | --- | --- |
| Realm name | `voice` | Issuer becomes `https://idp.example.mil/realms/voice` |
| Access token lifespan | 5 min | Matches REGISTER expiry; SBC sees fresh tokens |
| SSO session idle / max | 10 h / 24 h | One browser login per workday |
| Offline session (with `offline_access`) | 30 d idle | Mobile clients survive long idle periods |
| Refresh token rotation | enabled (revoke on reuse) | Public client hardening |
| Required actions | configure per policy (WebAuthn, OTP) | Client is agnostic — it only sees the browser |
| Default signature algorithm | `ES384` | CNSA 2.0; the SBC rejects every other algorithm (see Token signing) |

### Token signing (required)

`proto-jwt` accepts only ES384 access tokens signed by an EC P-384 key.
RS256, PS256 and ES256 tokens get 401. Keycloak signs with RS256 by default,
and `Configure-Voice.ps1` does not change that. Set it on the realm:

1. Realm settings → Keys → Providers → Add provider `ecdsa-generated`,
   elliptic curve `P-384`, enabled and active.
2. Realm settings → Tokens → Default signature algorithm `ES384`
   (realm field `defaultSignatureAlgorithm`).
3. Leave the clients' access-token signature algorithm unset or `ES384`
   (client attribute `access.token.signed.response.alg`).

Check: decode a token from `Get-TestToken.ps1`; the header must show
`"alg":"ES384"`, and the JWKS entry for its `kid` must be `kty` `EC`,
`crv` `P-384`. A JWKS entry whose `alg` differs from the token's is refused.

Tokens must carry `exp`, `iss` and `aud`; `nbf` is checked when present
(30 s leeway, at most 300 s). A `crit` header, a header `typ` other than
`JWT` / `at+jwt` (also as `application/jwt` / `application/at+jwt`, case-insensitive), and a Keycloak `typ` claim other than `Bearer` (ID,
refresh and logout tokens) are refused, as is a JWKS entry whose `use` is
not `sig` or whose `key_ops` lacks `verify`. An empty issuer or audience
set is refused when the validator is built: sbc-client-config-server exits
with code 2, and sbc-api-server, central-config-api and sbc-daemon (with
`SBC_AUTH_MODE=bearer`) do not start.

A token whose `aud` names several relying parties (for example
`usg-uc-provisioning` and `sbc`) is accepted by each of them. Map only the
audiences a client needs. `nbf` is optional and `iat` is not checked, so
the realm's access-token lifespan bounds how long a stolen token is
usable.

### Client 1: `usg-uc-softclient` (the soft client)

| Setting | Value |
| --- | --- |
| Type | **Public** (no secret — it's a native app) |
| Device authorization grant | **enabled** (RFC 8628) — the desktop sign-in flow: no listening socket, no redirect URI |
| Standard flow | enabled only when App Link redirect URIs are registered (Authorization Code for Android) |
| Direct access grants | **disabled** (no password grant, ever) |
| PKCE | **required**, method `S256` (set `pkce.code.challenge.method` on the client; applies to the code flow) |
| Valid redirect URIs | none for desktop; `https://app.example.mil/oauth2redirect` (Android **claimed App Link** — preferred per RFC 8252 §7.2, verified via hosted `assetlinks.json`); `org.example.usguc:/oauth2redirect` (custom-scheme fallback only, RFC 8252 §7.1) |
| Web origins | none needed (not a browser app) |
| Consent | off for first-party deployment |

### Client 2: `usg-uc-provisioning` (the config API)

| Setting | Value |
| --- | --- |
| Type | Confidential, **bearer-only** usage (it never logs users in) |
| Purpose | Audience for tokens; service account for admin lookups if the directory lives in Keycloak |

### Client scope: `sip`

A dedicated client scope (default for `usg-uc-softclient`) carrying the
voice-specific claims via protocol mappers:

| Mapper | Type | Claim | Source |
| --- | --- | --- | --- |
| `sip-dn` | User Attribute | `dn` | user attribute `sipDn` (e.g. `1456055067`) |
| `sip-domain` | Hardcoded claim | `sip_domain` | `example.mil` |
| `audience` | Audience | `aud` | adds `usg-uc-provisioning` and `sbc` |

Resulting access-token payload (trimmed):

```json
{
  "iss": "https://idp.example.mil/realms/voice",
  "sub": "f3a9...",
  "aud": ["usg-uc-provisioning", "sbc"],
  "preferred_username": "jdoe",
  "dn": "1456055067",
  "sip_domain": "example.mil",
  "scope": "openid profile offline_access sip",
  "exp": 1781234567
}
```

With `dn` in the token, the **SBC can authorize REGISTER without calling the
provisioning service**: validate the ES384 signature against cached JWKS,
check `iss`/`aud`/`exp` (and `nbf` when present), then require that the To-URI user part equals the `dn`
claim. The provisioning API uses the same claim to build the config response.

### Trust relationships

```mermaid
flowchart LR
    KC["Keycloak realm voice"]
    SC["usg-uc-softclient<br/>public + PKCE"]
    PR["usg-uc-provisioning<br/>bearer-only"]
    SBC["SBC fleet"]
    DIR["User directory<br/>attribute sipDn"]

    SC -->|"device grant (desktop)<br/>auth code + PKCE (App Link)"| KC
    KC -->|"JWT with dn claim"| SC
    PR -->|"fetch JWKS, validate ES384, iss/aud/exp"| KC
    SBC -->|"fetch JWKS, validate ES384, iss/aud/exp"| KC
    KC --- DIR
```

JWKS handling on POPs: cache keys, refresh on unknown `kid`, and keep serving
with the cached set if Keycloak is briefly unreachable — IdP downtime must not
take down re-registration. (With ephemeral-digest mode, IdP downtime only
blocks *new* sign-ins, which is another argument for shipping it first.)

How `proto-jwt` `JwksCache` does this (all four validators: SBC daemon,
provisioning, central config, sbc-api):

- Tokens signed with a cached key validate without waiting for any fetch,
  and `/readyz` does not wait either.
- An unknown `kid` triggers one refresh (discovery document, then JWKS).
  Concurrent unknown-`kid` requests share that one fetch, and at most one
  fetch starts per 30 s per process. A key the IdP rotates in can therefore
  be rejected for up to 30 s after the previous fetch (NIST POA&M-423).
- One refresh is bounded to 10 s in total. On timeout or any error the
  cached set stays in service; with no cached set the request fails.
- The discovery document may be at most 64 KiB and the JWKS 256 KiB. A
  redirected or non-2xx response is refused, and the `jwks_uri` must be
  https unless the issuer itself is http.
- The SBC daemon, provisioning and central clients still follow redirects
  before the response is refused (NIST POA&M-424). The sbc-api client does
  not follow redirects, times out after 5 s connect and 10 s per request,
  and sbc-api does not start if `SBC_OIDC_EXTRA_CA_CERT_FILE` is set but
  cannot be read or holds no PEM certificate.

## Client State Machine

```mermaid
stateDiagram-v2
    [*] --> NeedsDomain
    NeedsDomain --> Discovering: user enters domain
    Discovering --> Authenticating: discovery OK
    Discovering --> NeedsDomain: discovery failed
    Authenticating --> Provisioning: tokens received
    Authenticating --> NeedsDomain: user cancelled
    Provisioning --> Registered: RFC 3263 resolve, REGISTER 200
    Registered --> Provisioning: config TTL expired
    Registered --> Refreshing: access token near expiry
    Refreshing --> Registered: refresh OK
    Refreshing --> Authenticating: refresh revoked or expired
    Registered --> Failover: flow failure (RFC 5626 keepalive)
    Failover --> Registered: next SRV target OK
    Failover --> Discovering: all SRV targets failed
```

Persisted across restarts: the service domain and the non-secret session
slice, in the settings file. Tokens are not persisted: the desktop client
keeps the access and refresh tokens only in the in-memory session
(`client-gui-tauri/src/signin.rs`; `refresh_token_persisted` is always
written `false`), so every launch starts with a browser sign-in, and each
sign-in deletes any refresh token an earlier build left in the OS keystore.
`SettingsManager::store_refresh_token` (OS keystore only: macOS Keychain,
Windows Credential Manager, Linux Secret Service; with no usable keyring it
returns `Ok(false)` and stores nothing, NIST POA&M-372) has no caller
today. The last-known config is not persisted. The mobile clients do not
run OIDC sign-in yet (`client-ffi` has no `oidc` feature). Silent resume
straight to `Refreshing` on launch is therefore not active.

## Security Considerations

- **System browser only** (RFC 8252). Embedded webviews are forbidden: they
  break SSO/WebAuthn and expose credentials to the app.
- **No loopback listener on desktop.** The Device Authorization Grant
  (RFC 8628) means the client never opens a listening socket and registers
  no redirect URI — nothing for host-based security tooling to flag, and no
  authorization code transiting an interceptable redirect. The app displays
  the `user_code` so the user can match it against the browser page
  (RFC 8628 §5.4 remote-phishing mitigation); the token binding is
  possession of the `device_code` on the client's TLS polling channel.
- **Issuer pinning.** Discovery is the trust bootstrap. The issuer must be
  in the entered domain's registrable domain or match a built-in pin scoped
  to that registrable domain; the config endpoint, registrar and SIP
  identity must be in the entered domain's registrable domain, and the OIDC
  endpoints in the issuer's. Requests are https-only and redirects are not
  followed. See Endpoint 1 notes.
- **No `password` grant.** Direct access grants stay disabled even though
  they would be "easier" — they bypass MFA and train users to type IdP
  passwords into native apps.
- **Refresh token storage**: not persisted today (in-memory session only).
  The keystore-only API (`store_refresh_token`) never writes a config file
  and, with no keystore, stores nothing (NIST POA&M-372).
- **Ephemeral digest credentials** are one-time-fetch, short-lived (≤ token
  lifetime), and `no-store`; the SBC's credential table is fed by the
  provisioning service, not a static subscriber database. Digest exchanges
  use SHA-256 per RFC 8760 — MD5 is rejected.
- **Claimed HTTPS redirects** on Android (App Links) prevent another app from
  registering the redirect and intercepting the authorization code; the
  custom scheme exists only as a fallback for builds that cannot host
  `assetlinks.json`.
- **Logout** = revoke refresh token at Keycloak + un-REGISTER + wipe keystore
  entries.

## Implementation Phases

1. **Provisioning service** — implemented:
   `crates/sbc/sbc-client-config-server` (axum pod, `sbc-<name>-server`
   conventions). Serves `/.well-known/sip-client-config` +
   `/v1/client-config` with JWT validation via the IdP's JWKS (cached,
   kid-rotation refresh, stale-serve on IdP outage). Stateless: identity
   comes from token claims (`dn`, `sip_domain`), policy from
   `SBC_CLIENT_CONFIG_*` env. Bearer mode only so far — ephemeral-digest
   minting and a directory-backed user store are follow-ups. Deploy:
   `deploy/helm/sbc/templates/21-sbc-client-config.yaml`
   (`sbcClientConfig.*` values, disabled by default) +
   per-POP image `crates/sbc/sbc-client-config-server/Dockerfile`.
2. **Client sign-in flow** — implemented: Device Authorization Grant
   (RFC 8628) browser sign-in in the Tauri backend
   (`client-gui-tauri/src/signin.rs` — no loopback listener; the app shows
   the `user_code` and polls the token endpoint), in-memory refresh
   token (not persisted), and auto-provisioning via `client-provisioning`
   (config → `SipAccount`, `auth_mode = Bearer`). The Authorization Code +
   PKCE helpers remain in `client-provisioning` for the Android
   claimed-App-Link flow.
   Registration runs over SIP-over-TLS: the UA derives the default port
   from the registrar URI scheme (`sips:` → 5061), presents the registrar
   domain as SNI, and trusts the provisioning extra-CA file for SIP TLS in
   private-CA environments. That extra-CA file is the *only* way to reach
   a private-CA service from a release build — the "continue anyway"
   untrusted-certificate prompt exists in debug builds only (see
   [deploy/keycloak/README.md → Private-CA labs](../deploy/keycloak/README.md#private-ca-labs-soft-client-trust)). **Still pending:** RFC 3263 NAPTR/SRV
   resolution (the UA currently does A/AAAA lookup of the registrar
   domain, preferring IPv6) and RFC 5626 outbound (reg-id, instance-id,
   keepalives) — until those land, transport selection comes from the
   provisioned account, not DNS.
3. **Keycloak**: `voice` realm, two clients, `sip` scope and mappers as above,
   and an ES384 / P-384 signing key (manual step, see Token signing).
4. **Bearer SIP auth (RFC 8898)** — implemented for REGISTER on both sides:
   the client attaches `Authorization: Bearer` and reacts to 401 rejection
   with a token refresh + re-register; the SBC validates the JWT against
   the IdP JWKS and challenges with `WWW-Authenticate: Bearer` /
   `error="invalid_token"` (`proto-registrar`, `SBC_AUTH_MODE=bearer`).
   Mid-dialog request authorization and ephemeral-digest retirement are
   follow-ups.
