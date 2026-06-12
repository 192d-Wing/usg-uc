#!/usr/bin/env pwsh
#Requires -Version 7
<#
.SYNOPSIS
Mints a real access token from the IdP using the OAuth Device
Authorization Grant (RFC 8628), so you can exercise
sbc-client-config-server before the soft-client sign-in flow exists.

.DESCRIPTION
Auth happens in YOUR browser (CAC/SSO works); this script just polls.
Requires the device grant on the client, which Configure-Voice.ps1
enables by default. Prints the decoded claims to the information stream
and the raw token to stdout.

.EXAMPLE
$token = ./Get-TestToken.ps1 -KcUrl https://icam.oopl.dev.mil -Realm voice
Invoke-RestMethod "https://<pop>/v1/client-config" -Headers @{ Authorization = "Bearer $token" }
#>
[CmdletBinding()]
param(
    [string]$KcUrl = $env:KC_URL,
    [string]$Realm = $env:KC_REALM,
    [string]$ClientId = $(if ($env:CLIENT_ID) { $env:CLIENT_ID } else { 'usg-uc-softclient' }),
    [string]$Scopes = $(if ($env:SCOPES) { $env:SCOPES } else { 'openid profile sip' })
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $KcUrl) { throw 'Set -KcUrl or $env:KC_URL' }
if (-not $Realm) { throw 'Set -Realm or $env:KC_REALM' }
$base = "$($KcUrl.TrimEnd('/'))/realms/$Realm/protocol/openid-connect"

function ConvertFrom-JwtPayload([string]$Jwt) {
    # JWT payloads are unpadded base64url.
    $payload = $Jwt.Split('.')[1].Replace('-', '+').Replace('_', '/')
    $payload += '=' * ((4 - $payload.Length % 4) % 4)
    [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json
}

# The client is configured with pkce.code.challenge.method=S256
# (Configure-Voice.ps1), which Keycloak enforces on the device grant too.
$verifierBytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($verifierBytes)
$codeVerifier = [Convert]::ToBase64String($verifierBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
$challengeBytes = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::ASCII.GetBytes($codeVerifier))
$codeChallenge = [Convert]::ToBase64String($challengeBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')

$dev = Invoke-RestMethod -Method Post -Uri "$base/auth/device" -Body @{
    client_id             = $ClientId
    scope                 = $Scopes
    code_challenge        = $codeChallenge
    code_challenge_method = 'S256'
}
$verificationUri = if ($dev.PSObject.Properties['verification_uri_complete']) {
    $dev.verification_uri_complete
} else { $dev.verification_uri }
$interval = if ($dev.PSObject.Properties['interval']) { [int]$dev.interval } else { 5 }
$expiresIn = if ($dev.PSObject.Properties['expires_in']) { [int]$dev.expires_in } else { 600 }

Write-Host 'Open in a browser and authenticate:' -ForegroundColor Yellow
Write-Host "  $verificationUri" -ForegroundColor Yellow
Write-Host "(polling every ${interval}s, expires in ${expiresIn}s)"

$deadline = [DateTime]::UtcNow.AddSeconds($expiresIn)
while ([DateTime]::UtcNow -lt $deadline) {
    Start-Sleep -Seconds $interval
    try {
        $resp = Invoke-RestMethod -Method Post -Uri "$base/token" -Body @{
            grant_type    = 'urn:ietf:params:oauth:grant-type:device_code'
            client_id     = $ClientId
            device_code   = $dev.device_code
            code_verifier = $codeVerifier
        }
        Write-Host 'claims:' -ForegroundColor Green
        ConvertFrom-JwtPayload $resp.access_token | ConvertTo-Json -Depth 4 | Write-Host
        return $resp.access_token
    }
    catch {
        # ErrorDetails is $null on non-HTTP failures (DNS, timeout); guard it
        # or StrictMode turns the property access into a masking error.
        $msg = if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { $_.Exception.Message }
        $err = try { ($msg | ConvertFrom-Json).error } catch { 'unknown' }
        switch ($err) {
            'authorization_pending' { }                       # keep polling
            'slow_down' { $interval += 5 }
            default { throw "device grant failed: $msg" }
        }
    }
}
throw 'device authorization expired before completion'
