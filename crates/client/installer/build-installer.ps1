# USG SIP Soft Client - Windows Installer Build Script
#
# Prerequisites:
#   - Rust toolchain (rustup)
#   - WiX Toolset v4.x (dotnet tool install --global wix)
#   - Windows SDK (for signtool, optional)
#
# Usage:
#   .\build-installer.ps1
#   .\build-installer.ps1 -Release
#   .\build-installer.ps1 -Release -Sign -CertThumbprint "ABCD1234..."

param(
    [switch]$Release,
    [switch]$Sign,
    [string]$CertThumbprint = "",
    [string]$TimestampServer = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"

# Configuration
$ProjectRoot = (Get-Item $PSScriptRoot).Parent.Parent.Parent.FullName
$ClientRoot = Join-Path $ProjectRoot "crates\client"
$InstallerDir = Join-Path $ClientRoot "installer"
$OutputDir = Join-Path $InstallerDir "dist"
$ResourcesDir = Join-Path $InstallerDir "resources"

# Version from Cargo.toml
$CargoToml = Get-Content (Join-Path $ProjectRoot "Cargo.toml") -Raw
if ($CargoToml -match 'version\s*=\s*"([^"]+)"') {
    $Version = $Matches[1]
} else {
    $Version = "0.1.0"
}

Write-Host "=== USG SIP Client Installer Build ===" -ForegroundColor Cyan
Write-Host "Version: $Version"
Write-Host "Project Root: $ProjectRoot"
Write-Host ""

# Create output directory
if (!(Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

# Build profile
if ($Release) {
    $BuildProfile = "release"
    $BuildFlags = "--release"
} else {
    $BuildProfile = "debug"
    $BuildFlags = ""
}

$BuildOutput = Join-Path $ProjectRoot "target\$BuildProfile"

# Step 1: Build the Rust application
Write-Host "Building Rust application ($BuildProfile)..." -ForegroundColor Yellow
Push-Location $ProjectRoot
try {
    $BuildCmd = "cargo build -p client-gui $BuildFlags"
    Write-Host "  Running: $BuildCmd"
    Invoke-Expression $BuildCmd
    if ($LASTEXITCODE -ne 0) {
        throw "Cargo build failed"
    }
} finally {
    Pop-Location
}

# Verify executable exists
$ExePath = Join-Path $BuildOutput "sip-softclient.exe"
if (!(Test-Path $ExePath)) {
    throw "Executable not found: $ExePath"
}
Write-Host "  Executable: $ExePath" -ForegroundColor Green

# Step 2: Code signing (if requested)
if ($Sign) {
    Write-Host "Signing executable..." -ForegroundColor Yellow

    if ([string]::IsNullOrEmpty($CertThumbprint)) {
        throw "Certificate thumbprint required for signing. Use -CertThumbprint parameter."
    }

    $SignToolArgs = @(
        "sign",
        "/sha1", $CertThumbprint,
        "/fd", "SHA384",  # CNSA 2.0 compliant
        "/tr", $TimestampServer,
        "/td", "SHA384",
        "/v",
        $ExePath
    )

    Write-Host "  Running: signtool $($SignToolArgs -join ' ')"
    & signtool @SignToolArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Code signing failed"
    }
    Write-Host "  Signed successfully" -ForegroundColor Green
}

# Step 3: Build MSI installer
Write-Host "Building MSI installer..." -ForegroundColor Yellow

# Check for WiX
$WixVersion = & wix --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "  WiX not found. Install with: dotnet tool install --global wix" -ForegroundColor Red
    Write-Host "  Skipping MSI build." -ForegroundColor Red
} else {
    Write-Host "  WiX Version: $WixVersion"

    $WxsFile = Join-Path $InstallerDir "usg-sip-client.wxs"
    $MsiFile = Join-Path $OutputDir "USG-SIP-Client-$Version.msi"

    Push-Location $InstallerDir
    try {
        $WixCmd = "wix build -o `"$MsiFile`" -d BuildOutput=`"$BuildOutput`" `"$WxsFile`""
        Write-Host "  Running: $WixCmd"
        Invoke-Expression $WixCmd
        if ($LASTEXITCODE -ne 0) {
            throw "WiX build failed"
        }
        Write-Host "  MSI: $MsiFile" -ForegroundColor Green

        # Sign the MSI if requested
        if ($Sign) {
            Write-Host "Signing MSI..." -ForegroundColor Yellow
            $SignToolArgs = @(
                "sign",
                "/sha1", $CertThumbprint,
                "/fd", "SHA384",
                "/tr", $TimestampServer,
                "/td", "SHA384",
                "/v",
                $MsiFile
            )
            & signtool @SignToolArgs
            if ($LASTEXITCODE -ne 0) {
                throw "MSI signing failed"
            }
            Write-Host "  MSI signed successfully" -ForegroundColor Green
        }
    } finally {
        Pop-Location
    }
}

# Step 4: Create portable ZIP
Write-Host "Creating portable ZIP..." -ForegroundColor Yellow

$ZipContents = @(
    @{ Source = $ExePath; Dest = "sip-softclient.exe" }
)

# Add resources if they exist
$DefaultConfig = Join-Path $ResourcesDir "default-settings.toml"
if (Test-Path $DefaultConfig) {
    $ZipContents += @{ Source = $DefaultConfig; Dest = "config\settings.toml" }
}

$ZipFile = Join-Path $OutputDir "USG-SIP-Client-$Version-portable.zip"
$TempDir = Join-Path $OutputDir "temp-zip"

if (Test-Path $TempDir) {
    Remove-Item -Recurse -Force $TempDir
}
New-Item -ItemType Directory -Path $TempDir | Out-Null

foreach ($Item in $ZipContents) {
    $DestPath = Join-Path $TempDir $Item.Dest
    $DestDir = Split-Path $DestPath -Parent
    if (!(Test-Path $DestDir)) {
        New-Item -ItemType Directory -Path $DestDir | Out-Null
    }
    Copy-Item $Item.Source $DestPath
}

Compress-Archive -Path "$TempDir\*" -DestinationPath $ZipFile -Force
Remove-Item -Recurse -Force $TempDir

Write-Host "  ZIP: $ZipFile" -ForegroundColor Green

# Summary
Write-Host ""
Write-Host "=== Build Complete ===" -ForegroundColor Cyan
Write-Host "Output directory: $OutputDir"
Write-Host ""
Get-ChildItem $OutputDir | ForEach-Object {
    $Size = "{0:N2} MB" -f ($_.Length / 1MB)
    Write-Host "  $($_.Name) ($Size)"
}
