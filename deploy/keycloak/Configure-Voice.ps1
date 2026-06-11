#!/usr/bin/env pwsh
#Requires -Version 7
<#
.SYNOPSIS
Configures the USG-UC voice pieces in a Keycloak realm via the Admin REST
API. Idempotent: safe to re-run; existing objects are updated, not
duplicated.

.DESCRIPTION
Implements the Keycloak section of docs/CLIENT-PROVISIONING-OIDC.md:
  1. sipDn declared as a user-profile attribute
  2. client scope `sip` with mappers: dn (user attribute), sip_domain
     (hardcoded), audience (usg-uc-provisioning)
  3. public PKCE client `usg-uc-softclient` (browser sign-in flow)
  4. bearer-only client `usg-uc-provisioning` (audience anchor)
  5. realm token policy: 5 min access tokens, refresh rotation,
     10h/24h SSO sessions, 30d offline sessions
  6. (optional) a test user with a sipDn

.EXAMPLE
$env:KC_ADMIN_TOKEN = '...'   # or -AdminUser/-AdminPassword
./Configure-Voice.ps1 -KcUrl https://icam.oopl.dev.mil -Realm voice `
    -SipDomain example.mil -TestUser jdoe -TestUserDn 1455550100

.EXAMPLE
# Everything except credentials from a YAML file (see example.yaml;
# validated against voice-config.schema.json when present):
$env:KC_ADMIN_TOKEN = '...'
./Configure-Voice.ps1 -ConfigFile ./example.yaml

.NOTES
Auth, in order of preference:
  -AdminToken / $env:KC_ADMIN_TOKEN            pre-obtained admin bearer token
  -SaClientId + -SaClientSecret                service-account client_credentials
  -AdminUser + -AdminPassword                  admin-cli password grant (lab use)

DoD PKI: pwsh's Invoke-RestMethod uses the OS trust store — install the
DoD CA chain at the OS level, or run with -SkipCertificateCheck ONLY in a
throwaway lab.
#>
[CmdletBinding()]
param(
    # YAML config file (see example.yaml / voice-config.schema.json).
    # Precedence: explicit CLI flag > config file > env var > default.
    # Credentials are NOT read from the file — flags/env only.
    [string]$ConfigFile = $env:KC_CONFIG_FILE,

    [string]$KcUrl = $env:KC_URL,
    [string]$Realm = $env:KC_REALM,
    # Realm the admin credential lives in (master for the global admin).
    [string]$AuthRealm = $(if ($env:KC_AUTH_REALM) { $env:KC_AUTH_REALM } else { 'master' }),

    [string]$AdminToken = $env:KC_ADMIN_TOKEN,
    [string]$SaClientId = $env:KC_SA_CLIENT_ID,
    [string]$SaClientSecret = $env:KC_SA_CLIENT_SECRET,
    [string]$AdminUser = $env:KC_ADMIN_USER,
    [string]$AdminPassword = $env:KC_ADMIN_PASSWORD,

    [string]$SipDomain = $env:VOICE_SIP_DOMAIN,
    [string]$SoftClientId = $(if ($env:SOFTCLIENT_ID) { $env:SOFTCLIENT_ID } else { 'usg-uc-softclient' }),
    [string]$ProvisioningClientId = $(if ($env:PROVISIONING_CLIENT_ID) { $env:PROVISIONING_CLIENT_ID } else { 'usg-uc-provisioning' }),
    # Loopback for desktop (RFC 8252 §7.3) + Android App Link URL(s).
    [string[]]$RedirectUris = $(if ($env:REDIRECT_URIS) { $env:REDIRECT_URIS -split ',' } else { @('http://127.0.0.1/*') }),
    # Device flow lets Get-TestToken.ps1 mint tokens with browser (CAC) auth.
    [bool]$EnableDeviceFlow = $true,

    [string]$TestUser = $env:TEST_USER,
    [string]$TestUserDn = $env:TEST_USER_DN,
    # When set, the test user gets this password and no pending required
    # actions, so it is immediately usable for token tests.
    [string]$TestUserPassword = $env:TEST_USER_PASSWORD,

    # Skip TLS certificate verification on ALL calls. Lab/dev only — for
    # DoD PKI, install the CA chain in the OS trust store instead.
    [switch]$SkipCertificateCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- optional YAML config file ------------------------------------------
if ($ConfigFile) {
    if (-not (Test-Path $ConfigFile)) { throw "config file not found: $ConfigFile" }
    if (-not (Get-Command ConvertFrom-Yaml -ErrorAction SilentlyContinue)) {
        try { Import-Module powershell-yaml -ErrorAction Stop }
        catch { throw 'Reading YAML requires the powershell-yaml module: Install-Module powershell-yaml -Scope CurrentUser' }
    }
    $cfg = Get-Content -Raw $ConfigFile | ConvertFrom-Yaml

    # Validate against the schema when it sits next to this script.
    $schemaPath = Join-Path $PSScriptRoot 'voice-config.schema.json'
    if (Test-Path $schemaPath) {
        $json = $cfg | ConvertTo-Json -Depth 8
        try {
            if (-not (Test-Json -Json $json -SchemaFile $schemaPath -ErrorAction Stop)) {
                throw "$ConfigFile does not conform to voice-config.schema.json"
            }
        }
        catch [System.Management.Automation.RuntimeException] {
            # Test-Json reports schema violations as terminating errors with
            # detail in the message — surface them.
            throw "config file invalid: $($_.Exception.Message)"
        }
    }

    # CLI flag > file > env/default ($PSBoundParameters knows what was typed).
    $kcSection = $cfg['keycloak']
    if ($kcSection) {
        if ($kcSection['url'] -and -not $PSBoundParameters.ContainsKey('KcUrl')) { $KcUrl = $kcSection['url'] }
        if ($kcSection['realm'] -and -not $PSBoundParameters.ContainsKey('Realm')) { $Realm = $kcSection['realm'] }
        if ($kcSection['authRealm'] -and -not $PSBoundParameters.ContainsKey('AuthRealm')) { $AuthRealm = $kcSection['authRealm'] }
    }
    $voiceSection = $cfg['voice']
    if ($voiceSection) {
        if ($voiceSection['sipDomain'] -and -not $PSBoundParameters.ContainsKey('SipDomain')) { $SipDomain = $voiceSection['sipDomain'] }
        if ($voiceSection['softClientId'] -and -not $PSBoundParameters.ContainsKey('SoftClientId')) { $SoftClientId = $voiceSection['softClientId'] }
        if ($voiceSection['provisioningClientId'] -and -not $PSBoundParameters.ContainsKey('ProvisioningClientId')) { $ProvisioningClientId = $voiceSection['provisioningClientId'] }
        if ($voiceSection['redirectUris'] -and -not $PSBoundParameters.ContainsKey('RedirectUris')) { $RedirectUris = @($voiceSection['redirectUris']) }
        if ($null -ne $voiceSection['enableDeviceFlow'] -and -not $PSBoundParameters.ContainsKey('EnableDeviceFlow')) { $EnableDeviceFlow = [bool]$voiceSection['enableDeviceFlow'] }
    }
    $tuSection = $cfg['testUser']
    if ($tuSection) {
        if ($tuSection['username'] -and -not $PSBoundParameters.ContainsKey('TestUser')) { $TestUser = $tuSection['username'] }
        if ($tuSection['dn'] -and -not $PSBoundParameters.ContainsKey('TestUserDn')) { $TestUserDn = "$($tuSection['dn'])" }
        if ($tuSection['password'] -and -not $PSBoundParameters.ContainsKey('TestUserPassword')) { $TestUserPassword = $tuSection['password'] }
    }
}

if (-not $KcUrl) { throw 'Set -KcUrl or $env:KC_URL (e.g. https://icam.oopl.dev.mil)' }
if (-not $Realm) { throw 'Set -Realm or $env:KC_REALM (target realm; must already exist)' }
if (-not $SipDomain) { throw 'Set -SipDomain or $env:VOICE_SIP_DOMAIN (e.g. example.mil)' }
$KcUrl = $KcUrl.TrimEnd('/')

function Write-Note([string]$Message) { Write-Host "==> $Message" -ForegroundColor Green }

# --- admin token -------------------------------------------------------
if ($SkipCertificateCheck) {
    Write-Warning 'TLS certificate verification is DISABLED — lab use only'
}
$tls = @{ SkipCertificateCheck = [bool]$SkipCertificateCheck }
$tokenEndpoint = "$KcUrl/realms/$AuthRealm/protocol/openid-connect/token"
if ($AdminToken) {
    $token = $AdminToken
}
elseif ($SaClientId -and $SaClientSecret) {
    $token = (Invoke-RestMethod -Method Post -Uri $tokenEndpoint @tls -Body @{
            grant_type = 'client_credentials'; client_id = $SaClientId; client_secret = $SaClientSecret
        }).access_token
}
elseif ($AdminUser -and $AdminPassword) {
    $token = (Invoke-RestMethod -Method Post -Uri $tokenEndpoint @tls -Body @{
            grant_type = 'password'; client_id = 'admin-cli'; username = $AdminUser; password = $AdminPassword
        }).access_token
}
else {
    throw 'Provide -AdminToken, -SaClientId/-SaClientSecret, or -AdminUser/-AdminPassword'
}
if (-not $token) { throw 'Could not obtain an admin token' }

$admin = "$KcUrl/admin/realms/$Realm"
$headers = @{ Authorization = "Bearer $token" }

function Invoke-Kc {
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Path,
        $Body
    )
    $params = @{ Method = $Method; Uri = "$admin$Path"; Headers = $headers } + $tls
    if ($null -ne $Body) {
        $params.ContentType = 'application/json'
        $params.Body = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 16 }
    }
    # Invoke-RestMethod can emit a JSON array as ONE pipeline object;
    # emitting it via a variable enumerates the elements so callers can
    # pipe straight into Where-Object.
    $result = Invoke-RestMethod @params
    $result
}

# Sanity: realm exists and we can read it.
$null = Invoke-Kc GET ''
Write-Note "connected to $KcUrl, realm $Realm"

# --- 1. user-profile attribute sipDn (Keycloak 24+ declarative profile) -
try {
    $upConfig = Invoke-Kc GET '/users/profile'
    if ($upConfig.attributes.name -notcontains 'sipDn') {
        $upConfig.attributes += [pscustomobject]@{
            name        = 'sipDn'
            displayName = 'SIP Directory Number'
            permissions = @{ view = @('admin', 'user'); edit = @('admin') }
            multivalued = $false
        }
        $null = Invoke-Kc PUT '/users/profile' $upConfig
        Write-Note 'declared user-profile attribute sipDn'
    }
    else { Write-Note 'user-profile attribute sipDn already declared' }
}
catch { Write-Note 'user-profile endpoint unavailable (older Keycloak) — skipping declaration' }

# --- 2. client scope `sip` + mappers ------------------------------------
$scope = Invoke-Kc GET '/client-scopes' | Where-Object { $_ -and $_.PSObject.Properties['name'] -and $_.name -eq 'sip' }
if (-not $scope) {
    $null = Invoke-Kc POST '/client-scopes' @{
        name        = 'sip'
        description = 'USG-UC voice claims (dn, sip_domain) + provisioning audience'
        protocol    = 'openid-connect'
        attributes  = @{ 'include.in.token.scope' = 'true'; 'display.on.consent.screen' = 'false' }
    }
    $scope = Invoke-Kc GET '/client-scopes' | Where-Object { $_ -and $_.PSObject.Properties['name'] -and $_.name -eq 'sip' }
    Write-Note "created client scope sip ($($scope.id))"
}
else { Write-Note "client scope sip exists ($($scope.id))" }

function Set-Mapper {
    param([Parameter(Mandatory)][hashtable]$Mapper)
    $existing = Invoke-Kc GET "/client-scopes/$($scope.id)/protocol-mappers/models" |
        Where-Object { $_ -and $_.PSObject.Properties['name'] -and $_.name -eq $Mapper.name }
    if ($existing) { Write-Note "mapper $($Mapper.name) exists" }
    else {
        $null = Invoke-Kc POST "/client-scopes/$($scope.id)/protocol-mappers/models" $Mapper
        Write-Note "created mapper $($Mapper.name)"
    }
}

Set-Mapper @{
    name           = 'sip-dn'
    protocol       = 'openid-connect'
    protocolMapper = 'oidc-usermodel-attribute-mapper'
    config         = @{
        'user.attribute'       = 'sipDn'
        'claim.name'           = 'dn'
        'jsonType.label'       = 'String'
        'access.token.claim'   = 'true'
        'id.token.claim'       = 'false'
        'userinfo.token.claim' = 'true'
    }
}
Set-Mapper @{
    name           = 'sip-domain'
    protocol       = 'openid-connect'
    protocolMapper = 'oidc-hardcoded-claim-mapper'
    config         = @{
        'claim.name'         = 'sip_domain'
        'claim.value'        = $SipDomain
        'jsonType.label'     = 'String'
        'access.token.claim' = 'true'
        'id.token.claim'     = 'false'
    }
}
Set-Mapper @{
    name           = 'provisioning-audience'
    protocol       = 'openid-connect'
    protocolMapper = 'oidc-audience-mapper'
    config         = @{
        'included.custom.audience' = $ProvisioningClientId
        'access.token.claim'       = 'true'
        'id.token.claim'           = 'false'
    }
}

# --- 3. public PKCE client (the soft client) ----------------------------
$softClient = @{
    clientId                  = $SoftClientId
    name                      = 'USG-UC Soft Client'
    description               = 'Native soft client browser sign-in (RFC 8252: system browser, auth code + PKCE S256). docs/CLIENT-PROVISIONING-OIDC.md'
    protocol                  = 'openid-connect'
    publicClient              = $true
    standardFlowEnabled       = $true
    directAccessGrantsEnabled = $false
    implicitFlowEnabled       = $false
    serviceAccountsEnabled    = $false
    redirectUris              = @($RedirectUris | ForEach-Object Trim)
    webOrigins                = @()
    consentRequired           = $false
    attributes                = @{
        'pkce.code.challenge.method'                = 'S256'
        'oauth2.device.authorization.grant.enabled' = "$EnableDeviceFlow".ToLower()
        'post.logout.redirect.uris'                 = '+'
    }
}
$existing = Invoke-Kc GET "/clients?clientId=$SoftClientId"
if (-not $existing) {
    $null = Invoke-Kc POST '/clients' $softClient
    $existing = Invoke-Kc GET "/clients?clientId=$SoftClientId"
    Write-Note "created client $SoftClientId ($($existing[0].id))"
}
else {
    $null = Invoke-Kc PUT "/clients/$($existing[0].id)" $softClient
    Write-Note "updated client $SoftClientId ($($existing[0].id))"
}
$null = Invoke-Kc PUT "/clients/$($existing[0].id)/default-client-scopes/$($scope.id)"
Write-Note "attached scope sip as default on $SoftClientId"

# --- 4. bearer-only audience client -------------------------------------
$provClient = @{
    clientId                  = $ProvisioningClientId
    name                      = 'USG-UC Provisioning API'
    description               = 'Audience anchor for sbc-client-config-server; never logs users in'
    protocol                  = 'openid-connect'
    bearerOnly                = $true
    publicClient              = $false
    standardFlowEnabled       = $false
    directAccessGrantsEnabled = $false
}
$existingProv = Invoke-Kc GET "/clients?clientId=$ProvisioningClientId"
if (-not $existingProv) {
    $null = Invoke-Kc POST '/clients' $provClient
    Write-Note "created client $ProvisioningClientId"
}
else {
    $null = Invoke-Kc PUT "/clients/$($existingProv[0].id)" $provClient
    Write-Note "updated client $ProvisioningClientId"
}

# --- 5. realm token policy (merge into existing settings) ---------------
$realmRep = Invoke-Kc GET ''
$realmRep.accessTokenLifespan = 300          # matches REGISTER expiry
$realmRep.ssoSessionIdleTimeout = 36000      # 10 h
$realmRep.ssoSessionMaxLifespan = 86400      # 24 h
$realmRep.offlineSessionIdleTimeout = 2592000 # 30 d (mobile offline_access)
$realmRep.revokeRefreshToken = $true         # rotation: revoke on reuse
$realmRep.refreshTokenMaxReuse = 0
$null = Invoke-Kc PUT '' $realmRep
Write-Note 'realm token policy set (access 5m, SSO 10h/24h, offline 30d, refresh rotation on)'

# --- 6. optional test user ----------------------------------------------
if ($TestUser -and $TestUserDn) {
    $found = Invoke-Kc GET "/users?username=$TestUser&exact=true"
    if (-not $found) {
        # email/name + no required actions: usable for token tests right
        # away ("Account is not fully set up" otherwise on Keycloak 24+).
        $null = Invoke-Kc POST '/users' @{
            username        = $TestUser
            enabled         = $true
            email           = "$TestUser@$SipDomain"
            emailVerified   = $true
            firstName       = 'Test'
            lastName        = $TestUser
            requiredActions = @()
            attributes      = @{ sipDn = @($TestUserDn) }
        }
        $found = Invoke-Kc GET "/users?username=$TestUser&exact=true"
        Write-Note "created test user $TestUser (sipDn=$TestUserDn)"
    }
    else {
        $user = Invoke-Kc GET "/users/$($found[0].id)"
        if (-not $user.PSObject.Properties['attributes'] -or $null -eq $user.attributes) {
            $user | Add-Member -NotePropertyName attributes -NotePropertyValue ([pscustomobject]@{}) -Force
        }
        $user.attributes | Add-Member -NotePropertyName sipDn -NotePropertyValue @($TestUserDn) -Force
        $null = Invoke-Kc PUT "/users/$($found[0].id)" $user
        Write-Note "set sipDn=$TestUserDn on existing user $TestUser"
    }
    if ($TestUserPassword) {
        $null = Invoke-Kc PUT "/users/$($found[0].id)/reset-password" @{
            type = 'password'; value = $TestUserPassword; temporary = $false
        }
        Write-Note "set password on $TestUser"
    }
    else {
        Write-Note "no -TestUserPassword given — set a credential before token tests"
    }
}

Write-Note "done. issuer: $KcUrl/realms/$Realm"
Write-Note "verify: Invoke-RestMethod $KcUrl/realms/$Realm/.well-known/openid-configuration | Select-Object issuer"
