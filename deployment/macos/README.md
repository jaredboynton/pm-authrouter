# Postman Enterprise SAML Deployment - macOS

Deploys Postman Enterprise with mandatory SAML SSO enforcement. All auth attempts redirect through your SSO portal.

## Quick Start

Most common deployment:

```bash
# 1. Build package (generic - no embedded config)
./build_pkg_mdm.sh

# 2. Deploy via your MDM:
#    - Certificate trust profile: Postman-Enterprise-VERSION-enterprise01-auth.mobileconfig
#    - SAML config profile: Create managed preferences (see below)
#    - Software package: Postman-Enterprise-VERSION-ARCH-saml.pkg
```

## Build Options

```bash
# Generic build (recommended)
./build_pkg_mdm.sh

# With embedded config (simpler but less flexible)
./build_pkg_mdm.sh --team "your-team" --saml-url "https://identity.getpostman.com/.../init"

# Other options
./build_pkg_mdm.sh --help
```

**Output:**
- `Postman-Enterprise-VERSION-ARCH-saml.pkg` (one per architecture)
- `Postman-Enterprise-VERSION-enterprise01-auth.mobileconfig` (certificate trust)

## Deployment Requirements

Every deployment needs these 3 components:

### 1. Software Package
Deploy the PKG via your MDM software distribution.

### 2. Certificate Trust Profile
Deploy the generated `.mobileconfig` file via MDM configuration profiles.
**Required** - without this, users see certificate warnings.

### 3. SAML Configuration
Choose one:

**Option A: Runtime Config (Recommended)**
Create MDM configuration profile with managed preferences:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadDisplayName</key>
            <string>Postman AuthRouter Configuration</string>
            <key>PayloadIdentifier</key>
            <string>com.postman.pm-authrouter</string>
            <key>PayloadType</key>
            <string>com.apple.ManagedClient.preferences</string>
            <key>PayloadUUID</key>
            <string>YOUR-UUID-HERE</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadEnabled</key>
            <true/>
            <key>PayloadOrganization</key>
            <string>Your Organization</string>
            <key>PayloadScope</key>
            <string>System</string>
            <key>teamName</key>
            <string>YOURTEAM</string>
            <key>samlUrl</key>
            <string>https://identity.getpostman.com/*****/init</string>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>Postman AuthRouter Settings</string>
    <key>PayloadIdentifier</key>
    <string>com.postman.pm-authrouter.config</string>
    <key>PayloadOrganization</key>
    <string>Your Organization</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadScope</key>
    <string>System</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>YOUR-UUID-HERE</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
```

**Customize the template:**
1. **Generate UUIDs**: Replace both `YOUR-UUID-HERE` with unique UUIDs
   ```bash
   uuidgen  # Run twice, use different UUID for each PayloadUUID
   ```
2. **Organization**: Replace `Your Organization` (appears twice) with your company name
3. **Team Name**: Replace the teamName value with your Postman team name
   - From your Postman URL: if `YOURTEAM.postman.co`, use `YOURTEAM`
4. **SAML URL**: Replace the samlUrl value with your SAML SSO init URL
   - Must end with `/init` (example: `https://identity.getpostman.com/sso/okta/abc123/init`)

**Option B: Build-time Config**
Use `--team` and `--saml-url` flags when building (embedded in PKG).

## Verification

After deployment:

```bash
# Check service is running
sudo launchctl list | grep com.postman.pm-authrouter

# Test SAML redirect (should return 302)
curl -I -H "Host: identity.getpostman.com" https://127.0.0.1:443/login -k

# Check certificate trust (no warnings if MDM profile deployed)
curl -I https://identity.getpostman.com/health

# View logs
tail -f /var/log/postman/pm-authrouter.log
```

## Common Issues

**Service not starting:**
```bash
# Check configuration
/usr/libexec/PlistBuddy -c "Print :ProgramArguments" /Library/LaunchDaemons/com.postman.pm-authrouter.plist

# View error logs
tail -20 /var/log/postman/pm-authrouter.error.log
```

**Certificate warnings:**
```bash
# Verify certificate installed
security find-certificate -c "identity.getpostman.com" /Library/Keychains/System.keychain

# Check MDM profile deployed
profiles list | grep -i postman
```

**No SAML redirect:**
```bash
# Check if port 443 is bound
sudo lsof -i :443

# Verify hosts file entry
grep identity.getpostman.com /etc/hosts
```

## Uninstall

### Service Only (Default)
```bash
sudo /usr/local/bin/postman/uninstall.sh
```
Removes AuthRouter daemon, certificates, and configuration. **Postman Enterprise.app is preserved.**

### Complete Removal
```bash
sudo /usr/local/bin/postman/uninstall.sh --all
```
Removes **everything**: AuthRouter daemon, certificates, configuration, **and Postman Enterprise.app**.

### Interactive Mode
```bash
sudo /usr/local/bin/postman/uninstall.sh --interactive
sudo /usr/local/bin/postman/uninstall.sh --all --interactive
```
Enables confirmation prompts before removal.

### Help
```bash
sudo /usr/local/bin/postman/uninstall.sh --help
```

**What gets removed:**
- AuthRouter daemon (`/usr/local/bin/postman/`)
- LaunchDaemon configuration (`/Library/LaunchDaemons/com.postman.pm-authrouter.plist`)
- SSL certificates from System keychain
- Generated certificate files
- Hosts file modifications (`identity.getpostman.com` entries)
- Log files (`/var/log/postman/`)
- **With `--all`**: Postman Enterprise.app (`/Applications/Postman Enterprise.app`)

## Requirements

- macOS 11+ (ARM64 or Intel)
- Admin privileges for deployment
- MDM solution for certificate trust
