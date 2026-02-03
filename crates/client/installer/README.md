# USG SIP Soft Client - Windows Installer

This directory contains the Windows installer build system for the USG SIP Soft Client.

## Prerequisites

### Required

- **Rust toolchain** (via rustup)
- **WiX Toolset v4.x** for MSI creation:

  ```powershell
  dotnet tool install --global wix
  ```

### Optional (for code signing)

- **Windows SDK** (for signtool.exe)
- **Code signing certificate** (SHA-384 for CNSA 2.0 compliance)

## Building the Installer

### Basic Build (Debug)

```powershell
.\build-installer.ps1
```

### Release Build

```powershell
.\build-installer.ps1 -Release
```

### Release Build with Code Signing

```powershell
.\build-installer.ps1 -Release -Sign -CertThumbprint "YOUR_CERT_THUMBPRINT"
```

## Output

The build script produces the following artifacts in the `dist/` directory:

| File | Description |
|------|-------------|
| `USG-SIP-Client-{version}.msi` | Windows Installer package |
| `USG-SIP-Client-{version}-portable.zip` | Portable ZIP (no installation required) |

## Directory Structure

```
installer/
├── build-installer.ps1     # Main build script
├── usg-sip-client.wxs      # WiX installer definition
├── README.md               # This file
├── resources/
│   ├── license.rtf         # License agreement (shown during install)
│   ├── default-settings.toml # Default configuration
│   └── app-icon.ico        # Application icon (TODO: add actual icon)
└── dist/                   # Build output (created by script)
```

## WiX Installer Features

The MSI installer includes:

- **Main Application**: `sip-softclient.exe` installed to Program Files
- **Start Menu Shortcuts**: Desktop and Start Menu shortcuts
- **Registry Entries**:
  - Uninstall information
  - SIP/SIPS URI handlers for click-to-call
- **Configuration**: Default settings in `%APPDATA%`

## Code Signing Requirements (CNSA 2.0)

For CNSA 2.0 compliance, code signing should use:

- **Signature Algorithm**: SHA-384
- **Timestamp**: SHA-384 with RFC 3161 timestamp server
- **Certificate**: P-384 ECDSA or RSA-3072+ key

Example signing command:

```powershell
signtool sign /sha1 <thumbprint> /fd SHA384 /tr http://timestamp.digicert.com /td SHA384 /v sip-softclient.exe
```

## Customization

### Changing Product Information

Edit the following in `usg-sip-client.wxs`:

- `ProductCode`: Generate new GUID for each major release
- `UpgradeCode`: Keep constant for upgrade detection
- `Manufacturer`, `ProductName`: Company/product branding

### Adding Files to Installer

1. Add file to the appropriate `Directory` element in the WXS
2. Add a `Component` with the file
3. Reference the component in the `Feature` element

### Changing Default Settings

Edit `resources/default-settings.toml` to modify the default configuration that ships with the installer.

## Troubleshooting

### "WiX not found"

Install WiX Toolset:

```powershell
dotnet tool install --global wix
```

### "signtool not found"

Install Windows SDK from <https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/>

### Build fails with "file not found"

Ensure you've built the Rust application first:

```powershell
cargo build --release -p client-gui
```

## Security Notes

- The installer does NOT require administrative privileges for per-user installation
- System-wide installation (Program Files) requires elevation
- Smart card authentication is required - no passwords are stored
- All sensitive data is zeroized on application exit
