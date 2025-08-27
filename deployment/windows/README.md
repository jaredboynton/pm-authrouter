# Postman Enterprise with AuthRouter - Windows Deployment Guide

## Overview

This package deploys Postman Enterprise for Windows with mandatory SAML SSO authentication enforcement. All authentication attempts are automatically redirected through your organization's SSO portal, ensuring compliance with corporate security policies.

## Package Contents

The combined MSI installers include:
- Full Postman Enterprise application
- AuthRouter service
- Uninstall cleanup script
- Certificate management
- Service configuration

## Prerequisites

1. **Original Postman MSI**: Download from your Postman Enterprise portal
2. **SSL Certificates**: Auto-generated on first build in `/ssl/` directory
3. **Build Tools**: Go compiler and WiX v6 (auto-installed if needed)

## Building the Package

Generate a customized MSI for your organization:

### Windows (PowerShell)
```powershell
cd deployment\windows
# Build with configuration (optional)
.\build_msi_mdm_win.ps1 -TeamName "team" -SamlUrl "https://identity.getpostman.com/sso/.../init" [-OutputMSI "custom.msi"]

# Or build without configuration - service installs but remains inactive until configured
.\build_msi_mdm_win.ps1
```

### macOS/Linux (Bash with msitools)
```bash
cd deployment/windows
# Build with configuration (optional)
./build_msi_mdm_unix.sh --team "team" --saml-url "https://identity.getpostman.com/sso/.../init" [--output "custom.msi"]

# Or build without configuration - service installs but remains inactive until configured
./build_msi_mdm_unix.sh
```

### Available Options

**PowerShell Script for Windows (`build_msi_mdm_win.ps1`):**

All parameters are optional - service will be installed but requires configuration:

- `-TeamName` (Optional) - Your Postman team name (can be set via MSI properties at install time)
- `-SamlUrl` (Optional) - Your organization's SAML SSO URL (can be set via MSI properties at install time)  
- `-OutputMSI` - Custom output filename (auto-generated if not specified)
- `-UseExistingCerts` - Use existing certificate files instead of generating new ones
- `-Debug` - Enable debug logging
- `-LogFile` - Optional log file path for CI/CD pipelines

**Bash Script for MacOS/Linux (`build_msi_mdm_unix.sh`):**

All parameters are optional - service will be installed but requires configuration:

- `--team` (Optional) - Your Postman team name (can be set via MSI properties at install time)
- `--saml-url` (Optional) - Your organization's SAML SSO URL (can be set via MSI properties at install time)
- `--output` - Custom output filename (auto-generated if not specified)
- `--skip-deps` - Skip dependency installation (assume present)
- `--offline` - Offline mode - use existing MSI only
- `--debug` - Enable debug logging
- `--cert-org` - Certificate organization (default: Postdot Technologies, Inc)
- `--help` - Show all options

### Build Process Technical Details

**PowerShell Approach (`build_msi_mdm_win.ps1`):**
- Uses WiX Toolset v3.11 with `dark.exe` and `light.exe`
- Extracts MSI structure while preserving cabinet compression
- Auto-installs dependencies (Go, WiX) via winget if needed
- Comprehensive 5-layer validation framework
- Service management with automatic installation
- Certificate trust via Windows certificate store
- Build time: ~3-5 minutes

**Bash Approach (`build_msi_mdm_unix.sh`):**
- Uses `wixl` for optimized compression (60% compression ratio)
- Native Windows Installer tables (ServiceInstall.idt, ServiceControl.idt)
- Avoids Custom Actions for improved reliability
- Comprehensive validation with MSI structure integrity checks
- Cross-platform build capability
- Build time: ~2-3 minutes

**Common Build Process:**
- Generates stable certificates in `/ssl/` directory (one-time setup)
- Builds AuthRouter service binary (~7-8MB)
- Creates uninstall.bat for manual cleanup scenarios
- Preserves original Postman MSI integrity
- Results in ~120-150MB final MSI

## Deployment Methods

### Option 1: Pre-configured MSI (Optional)

Build an MSI with embedded configuration:

**Windows:**
```powershell
.\build_msi_mdm_win.ps1 -TeamName "your-team" -SamlUrl "https://identity.getpostman.com/.../init"
```

**macOS/Linux:**
```bash
./build_msi_mdm_unix.sh --team "your-team" --saml-url "https://identity.getpostman.com/.../init"
```

Deploy via:
- **Direct installation**: `msiexec /i installer.msi /quiet`
- **Group Policy**: Add to software installation GPO
- **SCCM/Intune**: Deploy as standard application

**Pros:**
- Simplest deployment - just push the MSI
- No runtime configuration needed
- Works immediately after installation

**Cons:**
- Need separate MSIs for different teams/configurations
- Cannot change configuration without rebuilding MSI

### Option 2: Runtime Configuration (Recommended)

Build generic MSI and configure at install time:

**Windows:**
```powershell
# Build without parameters - service installs but remains inactive until configured
.\build_msi_mdm_win.ps1
```

**macOS/Linux:**
```bash
# Build without parameters - service installs but remains inactive until configured
./build_msi_mdm_unix.sh
```

Deploy with MSI properties:
```cmd
msiexec /i installer.msi TEAM_NAME="your-team" SAML_URL="https://..." /quiet
```

**Pros:**
- One MSI for all deployments
- Configure per-deployment via MSI properties
- Can script different configurations
- Service always installed, activated when configured

**Cons:**
- Requires MSI property configuration
- More complex deployment command

### Option 3: Group Policy Deployment

1. Place MSI on network share accessible by domain computers
2. Create GPO in Group Policy Management Console
3. Navigate to Computer Configuration > Policies > Software Settings > Software Installation
4. Add new package pointing to MSI
5. Set MSI properties if using generic package:
   - TEAM_NAME = your-team
   - SAML_URL = your-saml-url
6. Link GPO to appropriate OUs

### Option 4: SCCM/Intune Deployment

Deploy as standard Windows application with command line:
```cmd
msiexec /i "Postman-Enterprise-saml.msi" TEAM_NAME="your-team" SAML_URL="https://..." /quiet /norestart
```

### Option 5: Post-Installation Registry Configuration

For environments where MSI properties aren't available or when configuration needs to be changed after installation, use registry-based configuration.

#### Group Policy Configuration (Most Common)

1. Open **Group Policy Management Console**
2. Create or edit a GPO
3. Navigate to: **Computer Configuration** > **Preferences** > **Windows Settings** > **Registry**
4. Create three registry items:

**Service Configuration:**
- **Hive**: HKEY_LOCAL_MACHINE
- **Key Path**: `SYSTEM\CurrentControlSet\Services\PMAuthRouter`
- **Value Name**: ImagePath
- **Value Type**: REG_EXPAND_SZ
- **Value Data**: `"C:\Program Files\Postman\Postman Enterprise\pm-authrouter.exe" --mode service --team "YOUR_TEAM" --saml-url "YOUR_SAML_URL"`

**Team and SAML URL:**
- **Key Path**: `SOFTWARE\Postman\Enterprise`
- **Values**: TeamName (REG_SZ), SamlUrl (REG_SZ)

#### Other Methods

- **Intune**: Use OMA-URI registry settings or PowerShell scripts
- **SCCM**: Create Configuration Items for registry values
- **PowerShell DSC**: Registry resources with Service dependency
- **Manual**: `reg add` commands for testing

#### Verification

```cmd
reg query "HKLM\SOFTWARE\Postman\Enterprise"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\PMAuthRouter" /v ImagePath
net stop PMAuthRouter && net start PMAuthRouter
```

## Certificate Trust Management

### Automatic Trust During Installation
The MSI installer automatically handles certificate trust:
1. **Certificate Generation**: Build process creates certificates in `/ssl/`
2. **MSI Embedding**: Certificates included in MSI package
3. **Installation**: MSI installs certificate to Trusted Root Certificate Authorities
4. **Verification**: Service validates certificate on startup

### Manual Certificate Deployment (Optional)
For organizations preferring centralized certificate management:

#### Via Group Policy
1. Export certificate: `certutil -encode server.crt identity.cer`
2. Create GPO in Group Policy Management
3. Navigate to: Computer Configuration → Policies → Windows Settings → Security Settings → Public Key Policies
4. Right-click "Trusted Root Certification Authorities" → Import
5. Select the certificate file
6. Link GPO to appropriate OUs

#### Via PowerShell (Requires Admin)
```powershell
# Import certificate to Trusted Root
Import-Certificate -FilePath "identity.getpostman.com.crt" -CertStoreLocation Cert:\LocalMachine\Root
```

#### Via SCCM/Intune
1. Create Configuration Item for certificate deployment
2. Target certificate to: `Cert:\LocalMachine\Root`
3. Deploy to device collections

### Certificate Verification
```cmd
# Check if certificate is installed
certutil -store Root | findstr "identity.getpostman.com"

# View certificate details
certutil -store Root "identity.getpostman.com"

# Test certificate validity
certutil -verify "C:\Program Files\Postman\Postman Enterprise\server.crt"

# Check certificate SHA1 fingerprint
powershell "Get-ChildItem Cert:\LocalMachine\Root | Where-Object {$_.Subject -like '*identity.getpostman.com*'} | Select-Object Thumbprint, Subject"
```

### Certificate Rotation
When updating certificates:
1. Generate new certificates in `/ssl/` directory
2. Rebuild MSI with new certificates
3. Deploy updated MSI (handles trust automatically)
4. Or deploy new certificate via GPO before MSI update

## How SAML Enforcement Works

The package includes a native Go Windows service that:
- Intercepts authentication requests to `identity.getpostman.com`
- Redirects users to your SSO portal
- Prevents direct password entry
- Manages SSL certificates automatically
- Maintains hosts file entries
- Logs authentication attempts for compliance

Technical details:
- Service: `PostmanAuthRouter`
- Proxy: `127.0.0.1:443`
- Binary: `C:\Program Files\Postman\Postman Enterprise\pm-authrouter.exe`
- Arguments stored in service registry
- Runs as LocalSystem account
- Auto-start service type
- Transparent to end users

### DNS Interception Methods (in order of preference):
1. **Netsh Routing** - Routes specific IP traffic (most reliable)
2. **DNS Registry Override** - Modifies DNS resolution at system level
3. **Hosts File** - Fallback method for DNS redirection
4. Automatic fallback chain if primary methods fail

## File Locations

- **Application**: `C:\Program Files\Postman\Postman Enterprise\`
- **AuthRouter**: `C:\Program Files\Postman\Postman Enterprise\pm-authrouter.exe`
- **Uninstaller**: `C:\Program Files\Postman\Postman Enterprise\uninstall.bat`
- **Certificates**: `C:\Program Files\Postman\Postman Enterprise\ca.crt`, `server.crt`, `server.key`
- **Logs**: `C:\ProgramData\Postman\pm-authrouter.log`
- **Hosts File**: `C:\Windows\System32\drivers\etc\hosts`

## Uninstallation

### Automatic Uninstall (via MSI)

The MSI includes a CustomAction that runs cleanup on uninstall:

```cmd
msiexec /x installer.msi /quiet
```

Or via Control Panel:
1. Open Control Panel > Programs and Features
2. Find "Postman Enterprise with AuthRouter"
3. Click Uninstall

### Manual Cleanup

If needed, run the uninstall script directly:
```cmd
"C:\Program Files\Postman\Postman Enterprise\uninstall.bat"
```

This removes:
- Windows service registration
- SSL certificates from trust store
- Hosts file modifications
- Generated certificate files
- Service logs

Note: The uninstall process removes the AuthRouter completely. Postman application is also removed as part of the MSI uninstall.

## Service Management

### Check Service Status
```cmd
sc query PMAuthRouter
```

### View Service Configuration
```cmd
sc qc PMAuthRouter
```

### Stop Service
```cmd
net stop PMAuthRouter
```

### Start Service
```cmd
net start PMAuthRouter
```

### View Logs
```powershell
Get-Content "C:\ProgramData\Postman\pm-authrouter.log" -Tail 50
```

### Verify Certificate Installation
```cmd
certutil -store Root | findstr "identity.getpostman.com"

# Alternative method with PowerShell
powershell "Get-ChildItem Cert:\LocalMachine\Root | Where-Object {$_.Subject -like '*identity.getpostman.com*'}"
```

### Check Hosts File
```cmd
type C:\Windows\System32\drivers\etc\hosts | findstr identity.getpostman.com
```

## Runtime Troubleshooting

### Service Won't Start
1. Check logs at `C:\ProgramData\Postman\pm-authrouter.log`
2. Verify configuration in service properties
3. Ensure port 443 is not in use: `netstat -an | findstr :443`
4. Check certificate installation in Trusted Root store

### Authentication Not Redirecting
1. Verify hosts file entry exists
2. Check if service is running
3. Test with: `nslookup identity.getpostman.com` (should show 127.0.0.1)
4. Clear browser cache and cookies

### Certificate Errors
1. Check if certificate is in Trusted Root: `certutil -store Root`
2. Verify certificate files exist in installation directory
3. Check certificate expiration in logs

## Registry Keys

The service stores configuration in:
```
HKLM\SOFTWARE\Postman\Enterprise
  - AuthRouterPath: Path to pm-authrouter.exe
  - CertificatePath: Path to server certificate
  - KeyPath: Path to private key
  - CAPath: Path to CA certificate

HKLM\SYSTEM\CurrentControlSet\Services\PMAuthRouter
  - ImagePath: Service executable with arguments
  - DisplayName: Postman Enterprise Authentication Router
  - Start: 2 (Automatic startup)
```

## Requirements

- Windows 10/11 or Windows Server 2016+
- Administrator privileges
- .NET Framework 4.7.2+ (included in Windows 10 1803+)
- Network access to SSO provider

## Testing Configuration Values

For testing with ADFS:
- Team: `cs-demo`
- SAML URL: `https://identity.getpostman.com/sso/adfs/1d7b9d2030a64fc6adc6edb0ce7c09b3/init`

## Security Features

- **Service runs as SYSTEM**: Ensures enforcement cannot be bypassed
- **Hosts file protection**: DNS redirection at system level
- **Certificate validation**: SSL/TLS interception with trusted cert
- **Audit logging**: All authentication attempts logged
- **Auto-start service**: Starts before user login
- **Registry-based config**: Protected configuration storage

## Compliance Notes

This solution enforces:
- **Zero Trust**: All authentication through SSO
- **NIST 800-63B**: Federation and strong authentication
- **SOC 2**: Audit trail of access attempts
- **ISO 27001**: Access control implementation
- **Windows Security**: Service hardening and certificate pinning

## Advanced Build Options

### Certificate Management

**Using Existing Certificates (PowerShell):**
```powershell
.\build_msi_mdm_win.ps1 -TeamName "team" -SamlUrl "url" -UseExistingCerts
```

**Custom Certificate Organization (Bash):**
```bash
./build_msi_mdm_unix.sh --team "team" --saml-url "url" --cert-org "My Company"
```

### Dependency Management

**Skip Dependencies (CI/CD environments):**
```bash
./build_msi_mdm_unix.sh --team "team" --saml-url "url" --skip-deps
```

**Offline Mode (air-gapped environments):**
```bash
./build_msi_mdm_unix.sh --team "team" --saml-url "url" --offline
```

### Debug and Logging

**Enable Debug Mode:**
```powershell
.\build_msi_mdm_win.ps1 -TeamName "team" -SamlUrl "url" -Debug -LogFile "build.log"
```

```bash
./build_msi_mdm_unix.sh --team "team" --saml-url "url" --debug
```

## Support

For issues or questions about deployment:
1. Check service status with `sc query PMAuthRouter`
2. Review logs at `C:\ProgramData\Postman\pm-authrouter.log`
3. Verify certificate and hosts file configuration
4. Ensure firewall allows localhost connections on port 443
5. Check build logs in `%TEMP%\pm-authrouter-logs` (Windows) or `/tmp/pm-authrouter-logs` (Unix)
