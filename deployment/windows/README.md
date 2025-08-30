# Postman Enterprise SAML Deployment - Windows

Deploys Postman Enterprise with mandatory SAML SSO enforcement. All auth attempts redirect through your SSO portal.

## Quick Start

Most common deployment:

```powershell
# 1. Build package (generic - no embedded config)
.\build_msi_mdm_win.ps1

# 2. Deploy via your MDM/GPO:
#    - Software package: Postman-Enterprise-VERSION-x64-saml.msi (generated)
#    - Configure via MSI properties or registry (see below)
```

## Build Options

```powershell
# Generic build (recommended)
.\build_msi_mdm_win.ps1

# With embedded config (simpler but less flexible)  
.\build_msi_mdm_win.ps1 -TeamName "your-team" -SamlUrl "https://identity.getpostman.com/.../init"

# Cross-platform build from macOS/Linux
./build_msi_mdm_unix.sh --team "your-team" --saml-url "https://identity.getpostman.com/.../init"

# Other options
.\build_msi_mdm_win.ps1 -?
./build_msi_mdm_unix.sh --help
```

**Output:**
- `Postman-Enterprise-VERSION-x64-saml.msi` (installer package)

## Deployment Requirements

Every deployment needs these 2 components:

### 1. Software Package
Deploy the MSI via your MDM, GPO, or SCCM.

**Note:** Manual installation requires PowerShell with Administrator privileges:
```powershell
# Run PowerShell as Administrator, then:
msiexec /i "C:\path\to\Postman-Enterprise-VERSION-x64-saml.msi" /qn
```

### 2. SAML Configuration
Choose one:

**Option A: Runtime Config (Recommended)**
Install with MSI properties (requires admin):

```cmd
# From elevated Command Prompt or PowerShell:
msiexec /i installer.msi TEAM_NAME="YOURTEAM" SAML_URL="https://identity.getpostman.com/*****/init" /qn
```

**Option B: Registry Config (Post-Install)**
Set via GPO or script:

```
HKLM\SOFTWARE\Postman\Enterprise
  TeamName = YOURTEAM
  SamlUrl = https://identity.getpostman.com/*****/init
```

**Option C: Build-time Config**
Use `-TeamName` and `-SamlUrl` flags when building (embedded in MSI).

## Verification

After deployment:

```powershell
# Check service is running
sc query PostmanAuthRouter

# Test SAML redirect (should return 302)
curl.exe -I -H "Host: identity.getpostman.com" https://127.0.0.1:443/login -k

# Check certificate trust
certutil -store Root | findstr "identity.getpostman.com"

# View logs
Get-Content C:\ProgramData\Postman\pm-authrouter.log -Tail 20
```

## Common Issues

**Service not starting:**
```powershell
# Check configuration
sc qc PostmanAuthRouter

# View error logs
Get-EventLog -LogName System -Source "Service Control Manager" -Newest 10
```

**Certificate warnings:**
```powershell
# Verify certificate installed
certutil -store Root | findstr "identity.getpostman.com"

# Re-import if needed (requires admin)
certutil -addstore Root "C:\Program Files\Postman\Postman Enterprise\auth\ca.crt"
```

**No SAML redirect:**
```powershell
# Check if port 443 is bound
netstat -an | findstr :443

# Verify hosts file entry
type C:\Windows\System32\drivers\etc\hosts | findstr identity.getpostman.com
```

## Uninstall

### Standard Uninstall
```cmd
msiexec /x installer.msi /qn
```
Removes entire Postman Enterprise including AuthRouter service, certificates, and configuration.

### Manual Cleanup (if needed)
```cmd
"C:\Program Files\Postman\Postman Enterprise\auth\uninstall.bat"
```

**What gets removed:**
- AuthRouter service (`PostmanAuthRouter`)
- SSL certificates from Trusted Root store
- Registry configuration (`HKLM\SOFTWARE\Postman\Enterprise`)
- Hosts file modifications (`identity.getpostman.com` entries)
- Log files (`C:\ProgramData\Postman\`)
- Postman Enterprise application

## Requirements

- Windows 10+ or Server 2016+ (x64)
- Admin privileges for deployment
- .NET Framework 4.7.2+ (included in Windows 10 1803+)

## Validation Status

**Fully Tested & Validated:**
- **Windows**: Build, installation, and configuration validated via Microsoft Intune MDM on Windows 10/11 (latest versions as of August 2025)
- **macOS**: Build, installation, and configuration validated via JAMF Pro MDM
- **Build Environment**: Tested on macOS 15.5 Ventura for both Windows and macOS deployments