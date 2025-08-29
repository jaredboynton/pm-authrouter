# Postman AuthRouter (Go)

Enterprise authentication (SAML) enforcement for Postman Desktop Enterprise.

**Fully Tested & Validated as of August 2025:**
- **macOS**: Installation and configuration validated via JAMF on macOS 15.6 Sequoia
- **Windows**: Installation and configuration validated via Microsoft Intune MDM on Windows 10 22H2 and Windows 11 24H2
- **Build Environment**: Tested on macOS 15.5 Ventura for both Windows and macOS deployments, Windows 10/11 for Windows deployment.

## Project Structure

```
postman_saml_enforcer_go/
├── cmd/
│   └── pm-authrouter/          # Main application entry points
├── internal/
│   ├── config/                 # Configuration management
│   ├── dns/                    # DNS interception
│   ├── proxy/                  # HTTPS proxy server and handlers
│   ├── sessions/               # Browser session cleanup
│   ├── system/                 # System integration
│   └── tls/                    # Certificate management
├── ssl/                         # [SSL certificates](ssl/README.md)
├── deployment/
│   ├── macos/                  # [macOS Deployment Guide](deployment/macos/README.md)
│   └── windows/                # [Windows Deployment Guide](deployment/windows/README.md)
├── dev/
│   └── service/
│       ├── macos/              # [macOS Development Guide](dev/service/macos/README.md)
│       └── windows/            # [Windows Development Guide](dev/service/windows/README.md)
├── test/
│   ├── macos/                  # macOS test scripts
│   └── windows/                # Windows test scripts
```

### Documentation

- **[Main Deployment Guide](deployment/README.md)** - Enterprise deployment overview
- **[Testing Guide](test/README.md)** - Functional Testing framework and validation

## The Problem

"How do we force our users to log in with our company SSO instead of personal accounts?"

The request comes up constantly. Teams want to ensure that:
- Employees use corporate-managed accounts, not personal Gmail/Yahoo accounts
- All API usage is properly audited and tied to company identity
- Sensitive collections and environments stay within corporate boundaries
- Data exfiltration risks are effectively nullified (short of intentional malice)

Traditional approaches like blocking Postman entirely create terrible user experiences and drive employees to workarounds that are even less secure.

## The Solution

1. Configure SSO in Postman Enterprise
2. Enforce Device Trust for your SAML flow to ensure *only* company devices can access your Enterprise team.
3. Deploy this via MDM to all company devices, ensuring that company devices can *only* access *your* Postman Enterprise team.

### *Done!*

This helper provides seamless SAML enforcement by intelligently intercepting Postman's authentication flow. Instead of blocking access, it transparently redirects users to your enterprise SSO provider, eliminating the team selection screen and authentication method choices entirely.

**Why This is the Best Possible Solution:**

- Works on or off corporate network
- Eliminates accidental data exfiltration scenarios entirely
- Works with both Postman Desktop and web applications
- Encourages proper collaboration within the corporate workspace

*For Users:*
- Totally seamless UX - users are redirected to corporate login smoothly

*For IT:*
- Deploys alongside the Postman Enterprise App
- Centralized deployment through standard enterprise tools (SCCM, Jamf Pro, etc.)
- Works with existing SAML infrastructure (Okta, Azure AD, etc.)
- Comprehensive logging and monitoring capabilities
- Easy rollback if issues arise

## Technical Architecture Highlights

### Multi-Layer DNS Resilience
The DNS interception cascades through 4+ methods per platform. When enterprise environments break one method, the system automatically switches to another:
- **Windows**: WFP (Windows Filtering Platform) → API Hooking → Registry DNS Override → Hosts File
- **macOS**: Network Extensions → pfctl (packet filter) → route manipulation → Hosts File
- **Linux**: iptables → nftables → Hosts File

Each fallback method is progressively less intrusive, ensuring compatibility even in highly restricted environments.

### Binary-Level Browser Session Management
The helper performs direct binary manipulation on browser storage files:
- **Chrome/Edge**: SQLite database modification - nullifies domain strings without SQL parsing
- **Firefox**: Direct cookies.sqlite binary manipulation
- **Safari**: Binary plist editing with domain prefix handling

This approach bypasses fragile browser APIs and extension dependencies, working regardless of browser updates.

### Enterprise-Native Deployment
- **Zero Custom Consoles**: IT teams deploy with existing tools (Jamf, Intune, SCCM, GPO)
- **MDM Configuration Profiles**: Automatically generated for certificate trust
- **Windows Certificate Store Integration**: Direct API usage for trust establishment
- **No User Prompts**: Certificate trust happens silently through platform-native mechanisms

### Self-Healing System Integration
Every system modification includes automatic recovery:
- 30-second health check loops detect and repair removed hosts entries
- Certificate validation with automatic regeneration on expiry
- Service recovery with exponential backoff (5s, 10s, 15s)
- Atomic operations with rollback capability - nothing gets left broken

### Production-Grade Network Proxy
- **CDN-Aware**: Preserves SNI headers for correct CDN routing (Cloudflare, Fastly)
- **Zero-Copy Streaming**: Uses `io.Copy` for exact byte preservation
- **Selective Interception**: Only auth paths are redirected, everything else passes through
- **Graceful Degradation**: Falls back through multiple DNS methods if primary fails

### CI/CD Integration Ready
The solution is drop-in ready for Postman's CI/CD pipeline:
- Build scripts automatically enhance any Postman Enterprise installer
- No product modifications required - works with any version
- Generates architecture-specific packages (ARM64, x64)
- Creates both installer and MDM configuration in one pass

This combination of multi-layer DNS fallbacks, binary cookie manipulation, and CDN-aware proxying represents months of specialized enterprise engineering, delivered as a ready-to-deploy solution.

## How It Works

### Why a Helper is Necessary

Simple DNS redirection or basic HTTP redirects won't work for SAML enforcement because:

- **Parameter Transformation**: Authentication requests contain critical parameters (`auth_challenge`, `continue`, `team`) that must be preserved and transformed for proper SAML flow
- **Selective Interception**: Only specific authentication paths need redirection - everything else must proxy normally to maintain Postman functionality
- **SSL Termination**: Browsers expect valid SSL certificates for `identity.getpostman.com` - the helper generates and trusts certificates automatically
- **CDN Compatibility**: Real Postman servers use CDN infrastructure requiring proper SNI headers that simple redirects can't provide
- **Environment Resilience**: Enterprise environments often have DNS proxies, virtualization, and network security tools that block simple DNS methods, requiring advanced fallback techniques

### Technical Implementation

The helper operates as an intelligent SSL proxy with multi-layered DNS interception:

1. **Multi-Method DNS Interception**: Uses fallback strategies including hosts file, Windows Filtering Platform, macOS Network Extensions, and registry overrides
2. **Selective Interception**: Only intercepts authentication endpoints (`/login`, `/enterprise/login`, `/enterprise/login/authchooser`)
3. **Parameter Preservation**: Extracts and forwards authentication parameters to your SAML provider
4. **Transparent Proxying**: All other requests pass through to real Postman servers with proper SSL/SNI handling and CDN compatibility

This ensures normal Postman functionality while enforcing corporate authentication policies without breaking existing workflows.

## Prerequisites

- **Postman Enterprise License**: This solution requires Postman Enterprise with SAML/SSO configured
- **Identity Provider**: Okta, Azure AD, ADFS, or other SAML 2.0 provider
- **Enterprise Deployment Tools**: MDM (Jamf, Intune, Workspace ONE) or GPO for certificate trust
- **Administrative Access**: Required for system-level deployment and certificate management

## Enterprise Quick Start

### 1. Evaluate the Solution

**How It Works:**
The build scripts work with **any version** of Postman Enterprise:
- Place your organization's Postman Enterprise .pkg (macOS) or .msi (Windows) in the deployment folder
- The build scripts automatically enhance them with organization-bound SAML enforcement capabilities
- Configurable via deployment-time configuration via MDM/GPO
- Automatic certificate trust management, complete uninstall support, enterprise logging and monitoring
- No user interaction required

**Test with Your Identity Provider:**
1. Deploy test package to pilot machines via MDM/GPO
2. Verify SAML redirection to your SSO provider
3. Confirm certificate trust deployment via MDM profiles
4. Validate compliance logging and monitoring

### 2. Enterprise Deployment

**Deployment Methods:**
- **Windows**: SCCM, Group Policy, Microsoft Intune, PowerShell DSC
- **macOS**: Jamf Pro, Apple Business Manager, MDM, Munki

**See Platform-Specific Guides:**
- **[macOS Enterprise Deployment](deployment/macos/README.md)** - PKG packages with MDM certificate profiles
- **[Windows Enterprise Deployment](deployment/windows/README.md)** - MSI packages with automated certificate trust

### 3. Configuration Options

**Build-time (Recommended for single-org deployments):**
```bash
# Embed your organization's settings
./build_pkg_mdm.sh --team "your-team" --saml-url "https://identity.getpostman.com/sso/..."
```

**Runtime (Flexible for multi-org/testing):**
- **macOS**: MDM Configuration Profiles or Jamf script parameters
- **Windows**: MSI properties during deployment

**Supported Identity Providers:**
- Okta: `https://identity.getpostman.com/sso/okta/tenant-id/init`
- Azure AD: `https://identity.getpostman.com/sso/adfs/tenant-id/init`
- SAML 2.0: `https://identity.getpostman.com/sso/saml/tenant-id/init`


## Documentation

### Enterprise Deployment
- **[Deployment Guide](deployment/README.md)** - Production packages and enterprise deployment overview
- **[macOS Deployment](deployment/macos/README.md)** - macOS PKG packages with MDM support
- **[Windows Deployment](deployment/windows/README.md)** - Windows MSI packages with GPO support
- **[Testing Guide](test/README.md)** - Functional testing framework and validation


## Configuration

**Supported Identity Providers:**
- Okta: `https://identity.getpostman.com/sso/okta/tenant-id/init`
- Azure AD: `https://identity.getpostman.com/sso/adfs/tenant-id/init`
- Everything Else: `https://identity.getpostman.com/sso/saml/tenant-id/init`

## Session Management

The AuthRouter includes comprehensive session clearing functionality to ensure fresh authentication flows:

### Clear All Postman Sessions

Use the `refresh` command to clear all existing Postman authentication sessions:

```bash
# macOS
sudo dev/service/macos/install-service.sh refresh

# Windows (as Administrator)
.\service\windows\install-service.ps1 refresh
```

**What this clears:**
- **Browser Cookies:** All Postman authentication cookies from Chrome, Firefox, Safari, and Edge using direct binary manipulation
- **Application Sessions:** Postman Desktop and Postman Enterprise session files
- **Process Management:** For applications that require restart (Firefox, Desktop Apps), does so gracefully

**When to use:**
- Initial deployment to ensure all users get fresh SAML authentication
- After changing SAML configuration or identity provider settings
- When users report authentication issues or cached login states
- As part of routine maintenance to enforce policy compliance

This ensures users cannot bypass SAML enforcement through cached authentication tokens or sessions.

**Enterprise Use Cases:**
- Initial deployment to ensure all users authenticate via corporate SSO
- After changing SAML configuration or switching identity providers
- Routine compliance maintenance to enforce security policies
- When users report authentication bypass issues


## Security & Compliance

**Security Features:**
- **Zero Trust Enforcement**: All authentication through corporate SSO
- **Certificate Pinning**: Self-signed certificates trusted via MDM/GPO only
- **Selective Interception**: Only auth paths redirected, all other traffic passes through
- **Local Binding**: 127.0.0.1:443 prevents external access
- **Audit Trail**: Comprehensive logging for compliance reporting

**Compliance Standards:**
- **NIST 800-63B**: Federation and strong authentication
- **SOC 2**: Complete audit trail of access attempts
- **ISO 27001**: Mandatory access control implementation
- **Zero Trust Architecture**: Eliminates password-based authentication

**Enterprise Security:**
- Prevents accidental data exfiltration to personal accounts
- Enforces corporate identity for all Postman API usage
- Works on/off corporate network
- Transparent to end users

## Enterprise Support

**Deployment Support:**
- **[Enterprise Deployment Guide](deployment/README.md)** - Complete deployment overview
- **[macOS Enterprise Guide](deployment/macos/README.md)** - MDM, Jamf Pro, certificate profiles
- **[Windows Enterprise Guide](deployment/windows/README.md)** - GPO, SCCM, Intune, certificate stores
- **[Testing Framework](test/README.md)** - Validation and functional testing

**System Requirements:**
- **Windows**: Windows 10/11, Windows Server 2016+
- **macOS**: macOS 11.0+, Intel and Apple Silicon
- **Network**: Access to identity.getpostman.com and your SAML provider
- **Privileges**: Administrative deployment rights for certificate trust

## Development & Testing

For local development and testing:
- **[macOS Development Guide](dev/service/macos/README.md)** - Local LaunchDaemon installation
- **[Windows Development Guide](dev/service/windows/README.md)** - Local Windows Service installation

**Build from Source:**
```bash
./dev/build.sh  # Builds for all platforms
```

## Note for Postman

This solution is CI/CD-ready. Postman could drag and drop and enable secure collaboration for tens of thousands more highly-secure Postman Enterprise users overnight - Zero product modification necessary - just stick it in the build pipeline, and whenever a new version is pushed, the build scripts automatically enhance any Postman Enterprise installer with mandatory SSO enforcement, making it enterprise-compliant out of the box.
