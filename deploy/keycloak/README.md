# Keycloak / IdP configuration for soft-client provisioning

PowerShell 7 scripts that configure an existing Keycloak realm for the
USG-UC soft-client sign-in flow via the **Admin REST API** — no console
clicking, idempotent, re-runnable. Cross-platform (Windows, macOS, Linux —
anywhere `pwsh` runs). Design:
[CLIENT-PROVISIONING-OIDC.md](../../docs/CLIENT-PROVISIONING-OIDC.md).

| Script | Purpose |
| --- | --- |
| `Configure-Voice.ps1` | Creates/updates the `sip` client scope + claim mappers, the public client (`usg-uc-softclient` — RFC 8628 device grant for desktop sign-in; PKCE code flow only when App Link redirect URIs are given), the bearer-only audience client (`usg-uc-provisioning`), realm token policy, the `sipDn` user-profile attribute, and optionally a ready-to-use test user. |
| `Get-TestToken.ps1` | Mints a real access token via the Device Authorization Grant (RFC 8628) — auth happens in your browser (CAC/SSO works), the script polls and returns the token. Use it to exercise `sbc-client-config-server` before any client code exists. |

## Quick start against icam

```powershell
$env:KC_ADMIN_TOKEN = '...'        # see "Auth" below

./Configure-Voice.ps1 -KcUrl https://icam.oopl.dev.mil -Realm voice `
    -SipDomain example.mil `
    -TestUser jdoe -TestUserDn 1455550100
```

Every parameter also reads an env var (`KC_URL`, `KC_REALM`,
`VOICE_SIP_DOMAIN`, `TEST_USER`, `TEST_USER_DN`, …) so the script drops
into CI without a wrapper.

Then verify end to end:

```powershell
# 1. realm answers OIDC discovery
(Invoke-RestMethod https://icam.oopl.dev.mil/realms/voice/.well-known/openid-configuration).issuer

# 2. mint a token (open the printed URL in a browser; CAC/SSO happens there)
$token = ./Get-TestToken.ps1 -KcUrl https://icam.oopl.dev.mil -Realm voice

# 3. replay it against the provisioning pod
Invoke-RestMethod https://<pop>/v1/client-config -Headers @{ Authorization = "Bearer $token" }
```

`Get-TestToken.ps1` prints the decoded claims — they must contain `dn`,
`sip_domain`, `aud: usg-uc-provisioning`, and `scope: ... sip`. If any is
missing, the scope/mapper step needs another look before blaming the pod.

## Auth

In order of preference (the script picks the first available; each flag
also reads the matching env var):

1. `-AdminToken` / `$env:KC_ADMIN_TOKEN` — a pre-obtained admin bearer
   token. On a CAC-only admin console, grab one from the browser session
   (DevTools → any `/admin/` request → `Authorization` header).
   Short-lived but fine for a one-shot run.
2. `-SaClientId` / `-SaClientSecret` — a confidential service-account
   client with `realm-management` roles (`manage-clients`, `manage-users`,
   `manage-realm`). The right answer for CI / repeated runs.
3. `-AdminUser` / `-AdminPassword` — `admin-cli` password grant. Lab use
   only.

`-AuthRealm` (default `master`) controls where the credential lives — set
it to the target realm if your admin account is realm-local.

## DoD PKI

`Invoke-RestMethod` uses the **OS trust store**, so install the DoD CA
chain at the OS level (Windows cert store / macOS Keychain /
`update-ca-trust` on Linux). Do not use `-SkipCertificateCheck` outside a
throwaway lab.

> **Pod-side counterpart:** `sbc-client-config-server` currently builds
> reqwest with `rustls-tls` (compiled-in Mozilla roots), which will NOT
> trust a DoD-PKI-served IdP. Switch to `rustls-tls-native-roots` + mount
> the DoD bundle before pointing the pod at icam. Tracked as a follow-up.

## Realm choice

`-Realm` must already exist. Two valid shapes:

- **Existing org realm** (users + CAC login already configured): just run
  the script against it — everything voice-specific is contained in the
  `sip` client scope and the two clients.
- **Dedicated `voice` realm**: create it first
  (`POST /admin/realms {"realm":"voice","enabled":true}` or console),
  configure its identity-provider/CAC federation, then run the script.

## Local dev loop

Validated against Keycloak 26 in a container:

```powershell
podman run -d --name kc-dev -p 8081:8080 `
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin `
  quay.io/keycloak/keycloak:26.0 start-dev

# create the realm, then configure it
$t = (Invoke-RestMethod -Method Post http://127.0.0.1:8081/realms/master/protocol/openid-connect/token `
  -Body @{grant_type='password'; client_id='admin-cli'; username='admin'; password='admin'}).access_token
Invoke-RestMethod -Method Post http://127.0.0.1:8081/admin/realms `
  -Headers @{Authorization="Bearer $t"} -ContentType application/json `
  -Body '{"realm":"voice","enabled":true}'

./Configure-Voice.ps1 -KcUrl http://127.0.0.1:8081 -Realm voice `
  -AdminUser admin -AdminPassword admin -SipDomain example.mil `
  -TestUser jdoe -TestUserDn 1455550100 -TestUserPassword test-only
```

## Handing off to a central ICAM team

If you don't administer icam, send them this directory plus the parameter
values you'd use — `Configure-Voice.ps1` is a precise, reviewable
statement of the required configuration, and `Get-TestToken.ps1` is the
acceptance test.
