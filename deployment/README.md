# Postman Enterprise AuthRouter - Deployment Guide

This directory contains everything needed to deploy Postman Enterprise with SAML SSO enforcement across Windows and macOS.

## Quick Start

### 1. Get Original Postman Installer
Download the official Postman Enterprise installer for your platform and place it in the appropriate directory:
- **macOS**: Place `.pkg` files in `deployment/macos/`
- **Windows**: Place `.msi` files in `deployment/windows/`

### 2. Generate SSL Certificates (One-Time Setup)
The build process needs stable SSL certificates for HTTPS interception. These are generated automatically on first build:
```bash
# Certificates are auto-generated in /ssl/ directory on first build
# Or manually generate them:
cd ssl/
./generate_stable_cert.sh
```

**Important**: Each organization generates their own unique certificates. These are:
- Created once and reused for all builds
- Unique to your organization (never shared)
- Excluded from version control (.gitignore)

### 3. Build Your Package

Choose your configuration approach:

#### Option A: Configure at Build Time (Optional)
Build with your team's settings embedded for immediate deployment:
```bash
# macOS
cd deployment/macos
./build_pkg_mdm.sh --team "your-team" --saml-url "https://identity.getpostman.com/sso/.../init"

# Windows
cd deployment/windows
./build_msi_mdm_win.ps1 -TeamName "your-team" -SamlUrl "https://identity.getpostman.com/sso/.../init"
```

#### Option B: Configure at Install Time (Recommended)
Build generic package, configure during deployment:
```bash
# Build without configuration - services always installed but inactive until configured
./build_pkg_mdm.sh        # macOS
./build_msi_mdm_win.ps1   # Windows

# Deploy with configuration
# macOS: Use Jamf parameters or Configuration Profile
# Windows: msiexec /i package.msi TEAM_NAME="team" SAML_URL="url" /quiet
```

### 4. Deploy Package
Use your preferred method:
- **Direct**: `sudo installer -pkg package.pkg -target /` (macOS) or `msiexec /i package.msi /quiet` (Windows)
- **MDM**: Jamf, Intune, SCCM, Workspace ONE
- **GPO**: Windows Group Policy

### 5. Deploy Certificate Trust (Required)

The AuthRouter intercepts HTTPS traffic, requiring certificate trust on client machines.

#### macOS - MDM Profile Deployment
The build process generates a `.mobileconfig` file that MUST be deployed via MDM:

1. **File Generated**: `Postman-Enterprise-VERSION-enterprise01-auth.mobileconfig`
2. **Deploy Via MDM**:
   - **Jamf Pro**: Configuration Profiles → Upload → Scope to target computers
   - **Microsoft Intune**: Devices → Configuration profiles → Create profile → macOS → Templates → Custom
   - **VMware Workspace ONE**: Devices → Profiles & Resources → Profiles → Add → macOS → Custom Settings
3. **Timing**: Deploy profile BEFORE or WITH package installation
4. **Verification**: 
   ```bash
   security find-certificate -c "identity.getpostman.com" /Library/Keychains/System.keychain
   ```

#### Windows - Automatic Trust
- **MSI Installation**: Certificate is automatically installed to Trusted Root during MSI installation
- **Group Policy**: Can also deploy certificate via GPO if needed
- **Verification**:
  ```cmd
  certutil -store Root | findstr "identity.getpostman.com"
  ```

**Why This Matters**: Without proper certificate trust:
- macOS: Users see certificate warnings (functionality works but poor UX)
- Windows: HTTPS interception may fail
- Both: Compliance logging may be incomplete

## What Gets Installed

**macOS:**
- Postman App: `/Applications/Postman Enterprise.app`
- AuthRouter: `/usr/local/bin/postman/pm-authrouter`
- Uninstaller: `/usr/local/bin/postman/uninstall.sh`
- Service Config: `/Library/LaunchDaemons/com.postman.pm-authrouter.plist`
- Logs: `/var/log/postman/pm-authrouter.log`

**Windows:**
- Postman App: `C:\Program Files\Postman\Postman Enterprise\`
- AuthRouter: `C:\Program Files\Postman\Postman Enterprise\pm-authrouter.exe`
- Uninstaller: `C:\Program Files\Postman\Postman Enterprise\uninstall.bat`
- Service Config: Windows Service (PostmanAuthRouter)
- Logs: `C:\ProgramData\Postman\pm-authrouter.log`

## Configuration Options

### Build-time Configuration (Optional)
Embed settings when building the package:
- Simple, single-step deployment
- No runtime configuration needed
- Best for single-team deployments

### Runtime Configuration (Recommended)
Configure during or after installation:
- **macOS**: Jamf script parameters, Configuration Profiles, or MDM managed preferences
- **Windows**: MSI properties or registry values
- Best for multi-team environments, testing, or centralized management
- Services always installed but remain inactive until configured

See platform-specific READMEs for detailed configuration methods.

## Uninstallation

Both platforms include complete uninstall scripts:

**macOS:**
```bash
sudo /usr/local/bin/postman/uninstall.sh
```

**Windows:**
```cmd
msiexec /x package.msi /quiet
# or manually: "C:\Program Files\Postman\Postman Enterprise\uninstall.bat"
```

Removes: service/daemon, certificates, hosts file entries, logs (but preserves Postman app on macOS).

## Platform Details

For complete deployment instructions, monitoring, and troubleshooting:
- [macOS Deployment Guide](macos/README.md) - All macOS architectures, MDM integration
- [Windows Deployment Guide](windows/README.md) - GPO, SCCM, Intune deployment

## How It Works

The AuthRouter:
1. Runs as a system service (starts at boot)
2. Intercepts requests to `identity.getpostman.com`
3. Redirects all authentication to your SSO provider
4. Transparent to users - no manual configuration needed
5. Logs all authentication attempts for compliance

## Certificate Troubleshooting

### Common Certificate Issues

**"Certificate not trusted" warnings:**
- **macOS**: Ensure MDM profile is deployed before/with PKG
- **Windows**: Verify certificate in Trusted Root store
- **Both**: Check certificate SHA1 matches across build and deployment

**Certificate generation fails:**
```bash
# Manually generate certificates
cd ssl/
./generate_stable_cert.sh
# Check permissions
ls -la identity.getpostman.com.*
```

**MDM profile not installing (macOS):**
- Verify profile is deployed at Computer level, not User level
- Check profile UUID is unique
- Ensure no conflicting profiles with same identifier

**Certificate rotation issues:**
- Deploy new trust profile/GPO before updating packages
- Keep old certificate trusted during transition period
- Verify new SHA1 in logs after deployment

## Support

Check logs for troubleshooting:
- **macOS**: `/var/log/postman/pm-authrouter.log`
- **Windows**: `C:\ProgramData\Postman\pm-authrouter.log`

Certificate locations:
- **Build time**: `/ssl/` directory in project
- **macOS runtime**: `/usr/local/bin/postman/identity.getpostman.com.crt`
- **Windows runtime**: `C:\Program Files\Postman\Postman Enterprise\server.crt`
