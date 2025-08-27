# Postman Enterprise with AuthRouter - macOS Deployment Guide

## Overview

This package deploys Postman Enterprise with mandatory SAML SSO authentication enforcement. All authentication attempts are automatically redirected through your organization's SSO portal, ensuring compliance with corporate security policies.

## Package Contents

The combined installer includes:
- Full Postman Enterprise application (Apple Silicon or Intel)
- AuthRouter daemon
- Uninstaller script
- LaunchDaemon configuration
- MDM profile generator for certificate trust

## Prerequisites for Building

**Build Environment**: macOS with Xcode Command Line Tools installed
   - **Automatic Dependency Detection**: Script validates required tools
   - **Tool Installation**: Use `brew install pkgutil pkgbuild productbuild openssl go uuidgen`
   - **Cross-compilation Support**: Go configured for Darwin ARM64/AMD64 builds

## Building the Package

```bash
cd deployment/macos
./build_pkg_mdm.sh [options]
```

**Current Script Version**: Enterprise 1.0 with Validation
Use `./build_pkg_mdm.sh --version` to see detailed build environment information including tool versions and configuration status.

### Build Options

**All parameters are optional - service will be installed but requires configuration:**

- `--team <name>` - Your Postman team name (optional - can be set at install time)
- `--saml-url <url>` - Your organization's SAML SSO URL (optional - can be set at install time)
- `--output <file>` - Custom output filename (auto-generated if not specified)
- `--cert-org <org>` - Certificate organization name (default: Postdot Technologies, Inc)
- `--quiet` - Reduce output for CI/CD environments
- `--debug` - Enable debug logging and file operation tracking
- `--skip-deps` - Skip dependency validation (for CI/CD with pre-validated environment)
- `--offline` - Disable automatic PKG downloads (requires pre-placed PKG files)
- `--version` - Show version and build environment information
- `--help` - Show all options

**Note**: When `--team` and `--saml-url` are provided at build time, the script validates:
- SAML URL format (should be HTTPS and end with `/init`)
- Team name length and character validation  
- Path traversal prevention for output filenames
- Missing parameters result in warnings, not errors - service installs but remains inactive until configured

### Build Output
The script generates:
1. **Architecture-specific PKGs**:
   - `Postman-Enterprise-VERSION-ARCH-saml.pkg` (for each architecture found)
2. **MDM Configuration Profile**:
   - `Postman-Enterprise-VERSION-enterprise01-auth.mobileconfig` (single profile for all architectures)

### Build Features

**Automatic PKG Discovery & Download:**
- Detects existing PKGs with flexible naming patterns (spaces, underscores, case variants)
- Downloads missing PKGs automatically from Postman's CDN with retry logic
- Handles both ARM64 and Intel architectures with enhanced Rosetta detection
- Intelligent architecture selection (prioritizes native ARM64 on Apple Silicon)
- Works offline with `--offline` flag when PKGs are pre-placed

**Validation:**
- **Phase 1**: Dependency Management and Feature Detection
- **Phase 2**: Original PKG Validation (integrity, size, component count)
- **Phase 3**: Source Component Validation (binary architecture, size, format)
- **Phase 4**: Final PKG Validation (integrity, structure, component inclusion)
- **Phase 5**: Build Output Validation (certificates, MDM profiles)
- Enhanced error reporting with validation_error() and validation_success() functions
- Debug logging with file operation tracking and MD5 checksums

**Enterprise CI/CD Features:**
- `--skip-deps` flag for pre-validated CI/CD environments
- `--quiet` mode for silent automation
- `--offline` mode for air-gapped builds
- Configurable validation thresholds via environment variables
- Process-specific temp directory cleanup with PID isolation
- Enhanced logging with timestamps and debug traces

**The build process:**
- Detects and processes both ARM64 and Intel packages automatically
- Embeds AuthRouter daemon with architecture-specific binaries
- Creates uninstaller at `/usr/local/bin/postman/uninstall.sh`
- Generates certificates in `/ssl/` directory for consistency if not already present
- Generates MDM profile for certificate trust deployment

## Deployment Methods

### Option 1: Build with Configuration (Optional)

Build a PKG with embedded configuration:

```bash
./build_pkg_mdm.sh --team "your-team" --saml-url "https://identity.getpostman.com/.../init"
```

Deploy via:
- **Direct installation**: `sudo installer -pkg package.pkg -target /`
- **MDM/Jamf**: Upload and deploy as standard package
- **Munki/AutoPkg**: Add to catalog

**Pros:**
- Simplest deployment - just push the PKG
- No runtime configuration needed
- Works immediately after installation

**Cons:**
- Need separate PKGs for different teams/configurations
- Cannot change configuration without rebuilding PKG

### Option 2: Runtime Configuration (Recommended)

Build generic package and configure at install time:

```bash
# Build without parameters - service installs but remains inactive until configured
./build_pkg_mdm.sh
```

Configure via:
- **MDM Configuration Profile** with `teamName` and `samlUrl` keys
- **Jamf script parameters** ($4 = team, $5 = SAML URL)  
- **Manual configuration** using service arguments or managed preferences

## Critical: Certificate Trust Deployment

**REQUIRED FOR PRODUCTION**: The build process generates a `.mobileconfig` file that must be deployed via your MDM solution.

### Certificate Generation & Management
1. **Build-time Generation**: Certificates are generated once in `/ssl/` directory
2. **Stable SHA1**: Same certificate used across all builds ensures MDM profile consistency
3. **Package Embedding**: Certificates are copied to PKG during build
4. **MDM Profile Creation**: `.mobileconfig` generated with correct SHA1 fingerprint

### Why MDM Deployment Is Required
- AuthRouter intercepts HTTPS traffic to `identity.getpostman.com`
- macOS 11+ requires MDM-deployed profiles for system-level certificate trust
- Manual trust methods (`security add-trusted-cert`) require user interaction
- Without proper trust: Users see certificate warnings (functionality still works)

### MDM Deployment Steps

#### Jamf Pro
1. Navigate to **Computers** → **Configuration Profiles**
2. Click **Upload** and select the `.mobileconfig` file
3. Set **Distribution Method** to "Install Automatically"
4. Configure **Scope** to target computers
5. Save and deploy

#### Microsoft Intune
1. Go to **Devices** → **Configuration profiles**
2. Click **Create profile**
3. Select **Platform**: macOS, **Profile type**: Templates → Custom
4. Upload the `.mobileconfig` file
5. Assign to appropriate groups

#### VMware Workspace ONE
1. Navigate to **Devices** → **Profiles & Resources** → **Profiles**
2. Click **Add** → **Add Profile** → **macOS** → **Device Profile**
3. Select **Custom Settings**
4. Upload the `.mobileconfig` file
5. Configure assignment groups

#### Generic MDM
1. Upload `.mobileconfig` as Custom Configuration Profile
2. Set to install at Computer/Device level (not User level)
3. Deploy before or with PKG installation

### Verification Commands
```bash
# Check if certificate is in keychain
security find-certificate -c "identity.getpostman.com" /Library/Keychains/System.keychain

# Verify certificate SHA1 matches MDM profile
openssl x509 -in /usr/local/bin/postman/identity.getpostman.com.crt -noout -fingerprint -sha1

# Test certificate trust (should not show warnings)
curl -I https://identity.getpostman.com/health

# Check if MDM profile is installed
profiles list | grep -i postman
```

### Certificate Rotation
When certificates need renewal (expiry, security update):
1. Generate new certificates in `/ssl/` directory
2. Rebuild packages with new certificates
3. Generate new MDM profile with updated SHA1
4. Deploy new MDM profile FIRST
5. Then deploy updated PKG
6. Old certificate remains trusted during transition

### Testing Without MDM (Development Only)
```bash
# Manual install profile for testing (requires user interaction)
open Postman-Enterprise-VERSION-enterprise01-auth.mobileconfig
# Go to System Settings > Privacy & Security > Profiles > Install

# Note: Manual installation may still show trust warnings on macOS 13+
```

## How SAML Enforcement Works

The package includes a native Go daemon that:
- Intercepts authentication requests to `identity.getpostman.com`
- Redirects users to your SSO portal
- Prevents direct password entry
- Manages SSL certificates automatically
- Maintains hosts file entries
- Logs authentication attempts for compliance

Technical details:
- Service: `com.postman.pm-authrouter`
- Proxy: `127.0.0.1:443`
- Binary: `/usr/local/bin/postman/pm-authrouter`
- Config: LaunchDaemon plist or MDM managed preferences
- Starts automatically on boot
- Transparent to end users

## File Locations

**Installed Components:**
- **Application**: `/Applications/Postman Enterprise.app`
- **AuthRouter**: `/usr/local/bin/postman/pm-authrouter`
- **Uninstaller**: `/usr/local/bin/postman/uninstall.sh`
- **MDM Profile Generator**: `/usr/local/bin/postman/generate_mdm_profile.sh`

**Runtime Configuration:**
- **LaunchDaemon**: `/Library/LaunchDaemons/com.postman.pm-authrouter.plist`
- **MDM Managed Preferences**: `/Library/Managed Preferences/com.postman.pm-authrouter.plist`

**Runtime Data:**
- **Certificates**: `/usr/local/bin/postman/identity.getpostman.com.crt` (and `.key`)
- **Logs**: `/var/log/postman/pm-authrouter.log`, `/var/log/postman/pm-authrouter.error.log`
- **Generated MDM Profile**: `/usr/local/bin/postman/PostmanAuthRouterCertificate.mobileconfig`

## Uninstallation

Complete removal script included:

```bash
sudo /usr/local/bin/postman/uninstall.sh
```

This removes:
- AuthRouter daemon and LaunchDaemon plist
- SSL certificates from System keychain
- Hosts file modifications
- Generated certificate files
- Service logs

Note: Postman Enterprise.app is NOT removed (drag to Trash if needed)

## Monitoring & Management

### Quick Status Check
```bash
# Check if service is running
sudo launchctl list | grep com.postman.pm-authrouter

# View current configuration
/usr/libexec/PlistBuddy -c "Print :ProgramArguments" /Library/LaunchDaemons/com.postman.pm-authrouter.plist

# Test SAML redirect (should return 302)
curl -I -H "Host: identity.getpostman.com" https://127.0.0.1:443/login -k
```

### Log Monitoring
```bash
# View recent logs
tail -20 /var/log/postman/pm-authrouter.log

# Monitor live logs
tail -f /var/log/postman/pm-authrouter.log

# Check for errors
tail -20 /var/log/postman/pm-authrouter.error.log
```

### Service Management
```bash
# Stop service
sudo launchctl unload -w /Library/LaunchDaemons/com.postman.pm-authrouter.plist

# Start service
sudo launchctl load -w /Library/LaunchDaemons/com.postman.pm-authrouter.plist

# Force restart
sudo launchctl unload /Library/LaunchDaemons/com.postman.pm-authrouter.plist
sudo launchctl load /Library/LaunchDaemons/com.postman.pm-authrouter.plist
```

### Certificate Verification
```bash
# Check certificate installation
security find-certificate -c "identity.getpostman.com" /Library/Keychains/System.keychain

# View certificate details
security find-certificate -c "identity.getpostman.com" -p /Library/Keychains/System.keychain | openssl x509 -noout -text

# Test certificate trust (should not show warnings)
curl -I https://identity.getpostman.com/health
```

## Extension Attributes (for MDM)

### AuthRouter Status
```bash
#!/bin/bash
if launchctl list | grep -q com.postman.pm-authrouter; then
    PLIST="/Library/LaunchDaemons/com.postman.pm-authrouter.plist"
    TEAM=$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:2" "$PLIST" 2>/dev/null | grep -v "\-\-")

    if [ -n "$TEAM" ]; then
        echo "<result>Running - Team: $TEAM</result>"
    else
        echo "<result>Running - Unconfigured</result>"
    fi
else
    echo "<result>Not Running</result>"
fi
```

### Certificate Status
```bash
#!/bin/bash
if security find-certificate -c "identity.getpostman.com" /Library/Keychains/System.keychain >/dev/null 2>&1; then
    CERT_INFO=$(security find-certificate -c "identity.getpostman.com" -p /Library/Keychains/System.keychain | openssl x509 -noout -enddate 2>/dev/null)
    echo "<result>Installed - $CERT_INFO</result>"
else
    echo "<result>Not Installed</result>"
fi
```

## Requirements

- macOS 11.0 or later (ARM64 or Intel)
- Administrator privileges
- Network access to SSO provider

## Compliance Notes

This solution enforces:
- **Zero Trust**: All authentication through SSO
- **NIST 800-63B**: Federation and strong authentication
- **SOC 2**: Audit trail of access attempts
- **ISO 27001**: Access control implementation
- **macOS Security**: Transparent proxy with certificate pinning

## Testing & Validation

### Pre-Deployment Testing

Before deploying to production, validate the build and functionality:

```bash
cd test
# Test PKG build process (no root required)
./test_macos_build.sh

# Test daemon functionality (requires root)
sudo ./test_macos_daemon.sh

# Test full deployment lifecycle (requires root)
sudo ./test_macos_integration.sh
```

### Test Coverage

**Build Tests** (`test_macos_build.sh`):
- PKG generation for both ARM64 and Intel architectures
- Certificate and MDM profile generation
- Parameter validation and error handling
- File structure and permissions

**Functional Tests** (`test_macos_daemon.sh`):
- HTTPS proxy server on port 443
- SAML redirect functionality (critical for SSO enforcement)
- Health endpoint validation
- Certificate trust and SSL termination
- DNS interception via hosts file
- Log file creation and rotation

**Integration Tests** (`test_macos_integration.sh`):
- End-to-end PKG installation
- Service activation and configuration
- Certificate trust deployment
- System cleanup and uninstall process

### Manual Validation Commands

```bash
# Quick deployment test
sudo installer -pkg Postman-Enterprise-VERSION-ARCH-saml.pkg -target /

# Verify service is running
sudo launchctl list | grep com.postman.pm-authrouter

# Test SAML redirection (key functionality)
curl -I -H "Host: identity.getpostman.com" https://127.0.0.1:443/login -k
# Should return: HTTP/1.1 302 Found with Location header

# Test certificate trust
curl -I https://identity.getpostman.com/health
# Should NOT show certificate warnings if MDM profile deployed

# Check configuration
/usr/libexec/PlistBuddy -c "Print :ProgramArguments" /Library/LaunchDaemons/com.postman.pm-authrouter.plist

# Validate build output
ls -la Postman-Enterprise-*-saml.pkg *.mobileconfig
# Should show PKG files and single MDM profile for all architectures
```
### Test Environment Cleanup

All tests automatically clean up:
- Stop daemon processes and unload LaunchDaemon
- Remove test certificates from keychain
- Clean hosts file entries
- Remove log files and directories
- No manual cleanup required

## Troubleshooting

### Common Deployment Issues

**Service Not Starting:**
```bash
# Check service status
sudo launchctl list | grep com.postman.pm-authrouter

# View service logs for errors
tail -20 /var/log/postman/pm-authrouter.error.log

# Check configuration
/usr/libexec/PlistBuddy -c "Print :ProgramArguments" /Library/LaunchDaemons/com.postman.pm-authrouter.plist
```

**Certificate Trust Issues:**
```bash
# Verify certificate is installed
security find-certificate -c "identity.getpostman.com" /Library/Keychains/System.keychain

# Check if MDM profile is deployed
profiles list | grep -i postman

# Test certificate trust
curl -I https://identity.getpostman.com/health 2>&1 | grep -i certificate
```

**SAML Redirection Not Working:**
```bash
# Test redirection manually
curl -I -H "Host: identity.getpostman.com" https://127.0.0.1:443/login -k
# Should return 302 with Location header pointing to your SAML URL

# Check if port 443 is bound
sudo lsof -i :443

# Verify hosts file entry
grep identity.getpostman.com /etc/hosts
```

**Build Issues:**
- **Missing Original PKGs**: Script will attempt automatic download, or place files manually
- **Download Failures**: Check network connectivity, or use `--offline` with pre-placed PKGs
- **Permission Denied**: Ensure Xcode Command Line Tools are installed
- **Go Build Errors**: Verify Go environment and dependencies
- **PKG Validation Errors**: Check for corrupted downloads or insufficient disk space
- **Dependency Issues**: Use `brew install` to install missing tools, or `--skip-deps` for CI/CD

### Support Resources

- **Log Location**: `/var/log/postman/pm-authrouter.log`
- **Error Logs**: `/var/log/postman/pm-authrouter.error.log`
- **Uninstall Script**: `/usr/local/bin/postman/uninstall.sh`
- **Configuration**: `/Library/LaunchDaemons/com.postman.pm-authrouter.plist`
