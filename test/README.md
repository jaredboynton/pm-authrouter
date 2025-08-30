# Postman AuthRouter Test Suite

Comprehensive test suite for validating the Postman Enterprise AuthRouter build process, deployment, and functionality across macOS and Windows platforms.

## Test Structure Overview

### File Organization
- **`/test/`** - Cross-platform essential tests and documentation
- **`/test/windows/`** - Windows-specific test suites and runners  
- **`/test/macos/`** - macOS-specific test suites and utilities
- **`/test/unix/`** - Unix cross-platform tests (macOS/Linux build validation)
- **`/test/config/`** - Unified test configuration and platform matrix

## Windows Tests (`windows/`)

### Essential Tests

- **`Test-Essential.ps1`** - Minimal critical validation (also available in `/test/`)
  - Build validation and MSI size checking (<125MB requirement)
  - Post-installation service verification (PostmanAuthRouter service)
  - SAML redirect functionality testing
  - DNS interception via hosts file validation
  - No mocks, just real validation of what matters

### Build Process Tests

- **`Test-BuildMsiWix3.ps1`** - WiX build process validation (supports v3.x and v4.x)
  - WiX Toolset installation and tool detection (v3.x/v4.x)
  - WXS compilation with proper namespaces and schemas
  - ServiceInstall and ServiceControl element validation
  - 5-phase validation framework integration
  - Certificate generation (PFX format) capability
  - MSI structure and component GUID validation
  - Build script integration testing

- **`Test-MsiValidation.ps1`** - Comprehensive 5-phase validation framework
  - **Phase 1**: Environment validation (PowerShell, Windows version, privileges, disk space)
  - **Phase 2**: Dependencies validation (Go 1.21+, WiX v3.x/v4.x)
  - **Phase 3**: Source files validation (project structure, Go modules, deployment scripts)
  - **Phase 4**: Build process validation (Go compilation, WiX compilation, MSI extraction)
  - **Phase 5**: Output validation (MSI size limits, structure requirements, GUID formats)
  - Service management and certificate validation
  - Error handling and recovery procedures

- **`Test-BuildMsi.ps1`** - Legacy MSI build process tests
  - Build script parameter validation and help system
  - Dependency detection and installation
  - MSI extraction and AuthRouter binary building
  - Certificate generation and security validation
  - Critical MSI size validation (≤125MB)
  - End-to-end integration testing

- **`Test-MsiSizeValidation.ps1`** - Critical size compliance testing
  - Hard 125MB size limit validation (enterprise deployment requirement)
  - Compression efficiency analysis with LZX:21
  - Warning threshold at 112MB (90% of limit)
  - Target size optimization at 110MB
  - MSI component breakdown and recommendations

- **`Test-BuildEdgeCases.ps1`** - Edge cases and error handling
  - Dependency installation failures (WiX, Go)
  - Build process interruption and recovery scenarios
  - File system edge cases (paths with spaces, Unicode, permissions)
  - MSI extraction failures and corruption handling
  - Certificate generation edge cases
  - Cleanup and temporary file management

### Service Functionality Tests

- **`Test-AuthRouterFunctionality.ps1`** - Comprehensive service functionality
  - Service installation, configuration, and lifecycle management
  - DNS interception via hosts file modification
  - HTTPS proxy server and certificate management
  - SAML redirect functionality for desktop and web flows
  - Upstream proxy functionality with SNI handling
  - Configuration loading and logging validation
  - Error handling and recovery scenarios
  - Performance benchmarks and resource monitoring

- **`Test-DNSInterceptionMethods.ps1`** - DNS interception method testing
  - Hosts file modification and backup/restore
  - Windows Filtering Platform (WFP) integration
  - Registry-based DNS override methods
  - Netsh routing configuration
  - DNS cache flushing and validation
  - Real-time DNS resolution testing

- **`Test-ServiceRecovery.ps1`** - Service crash recovery and restart scenarios
  - Service lifecycle management and state validation
  - Signal handling and graceful shutdown testing
  - Process crash simulation and recovery validation
  - Service restart policies and failure handling
  - Log rotation and error reporting
  - Performance monitoring during recovery

- **`Test-SystemIntegration.ps1`** - End-to-end integration testing
  - Complete flow: DNS interception → HTTPS proxy → SAML redirect
  - Certificate validation in system stores
  - Multi-URL testing (login, enterprise, API endpoints)
  - Browser compatibility (Chrome, Edge, Firefox)
  - Network configuration and routing validation
  - Real SAML provider integration testing

### Browser Session Tests

- **`Test-BrowserSessionCleanup.ps1`** - Browser session cleanup validation (also in `/test/`)
  - Browser profile detection (Chrome, Edge, Firefox)
  - Cookie file analysis and domain detection
  - Session cleanup with domain nullification
  - Multiple profile support and error handling
  - Performance testing with large cookie databases

### Test Runner Scripts

- **`Run-Tests.ps1`** - Simple essential test runner
  - Focus on critical validation (build, install, function)
  - Options: `-Build`, `-PostInstall`, `-Full`
  - Streamlined for quick validation cycles

- **`Run-WindowsTests.ps1`** - Comprehensive test orchestrator
  - Coordinates all Windows test suites with caching
  - Test categorization: `-Smoke`, `-Fast`, `-Component`, `-Full`  
  - Parallel execution with resource management
  - Prerequisites checking and MSI build caching
  - Pester framework integration with tag filtering

## macOS Tests (`macos/`)

### Core Functionality Tests

- **`test_macos_build.sh`** - PKG build process validation
  - Build script execution and dependency management (both ARM64 and Intel)
  - PKG extraction and enhancement process
  - Binary compilation with proper Go flags
  - Certificate generation and LaunchDaemon plist creation
  - Final package size and structure validation
  - Speed mode integration (`smoke`, `fast`, `component`, `full`)

- **`test_macos_daemon.sh`** - LaunchDaemon functionality testing
  - Daemon installation and service management
  - Configuration loading from MDM managed preferences
  - DNS interception via hosts file and pfctl
  - Certificate trust and keychain management
  - Port 443 binding and network configuration

- **`test_macos_integration.sh`** - End-to-end integration testing
  - Full deployment workflow validation
  - SAML enforcement functionality testing
  - Browser session cleanup integration
  - Uninstallation and cleanup verification
  - Cross-architecture compatibility (ARM64/Intel)

- **`test_build_outputs.sh`** - Build output validation and analysis
  - Build script output parsing and validation
  - Binary size and optimization verification
  - PKG structure analysis and metadata validation
  - Architecture-specific output validation

### System Component Tests

- **`test_browser_sessions.sh`** - Browser profile detection and session management
  - Chrome/Chromium profile detection and cookie paths
  - Firefox profile enumeration and session files
  - Safari cookie detection (macOS 10.15+ and legacy locations)
  - Edge profile support on macOS
  - Session file cleanup simulation and verification

- **`test_dns_methods.sh`** - DNS interception method testing
  - Hosts file manipulation with atomic backup/restore
  - pfctl rule management and NAT redirection
  - Route-based DNS redirection via `route` command
  - DNS cache flushing across macOS versions (10.15-14.x)
  - Fallback mechanism testing and validation
  - Real IP resolution via external DNS (8.8.8.8, 1.1.1.1)

- **`test_cleanup_manager.sh`** - Comprehensive cleanup testing
  - LaunchDaemon service removal and validation
  - Certificate removal from System keychain
  - Hosts file restoration from timestamped backups
  - Binary and log file cleanup with permission handling
  - Partial failure recovery scenarios
  - Cleanup idempotency and safety validation

- **`test_privilege_escalation.sh`** - Privilege and permission testing
  - Root privilege detection and sudo requirements
  - Environment preservation during privilege escalation
  - Port 443 binding verification without conflicts
  - System file modification permissions (hosts, pfctl)
  - Capability detection for all operations
  - Security context validation and error handling

- **`test_mdm_certificate.sh`** - MDM certificate profile testing
  - Certificate trust establishment via configuration profiles
  - .mobileconfig validation and deployment
  - Cross-platform certificate handling and trust verification
  - Enterprise deployment scenario testing

### Cache and Resource Management

- **`test_cache.sh`** - Unified caching system (replaces multiple legacy scripts)
  - Artifact caching and intelligent retrieval
  - Dependency tracking with SHA-256 validation
  - Test fixture management and expiration
  - Certificate pair caching and reuse
  - Cache cleanup and maintenance operations
  - Performance optimization for test runs

- **`test_download_robustness.sh`** - Download reliability and corruption testing
  - PKG download interruption and resume handling
  - Corrupted file detection and validation
  - Size threshold validation (undersized/oversized files)
  - Connection timeout and retry logic testing
  - PKG integrity validation via `pkgutil --expand`
  - Download resume capability with `-C` flag testing

- **`cache_manager.sh`** - Legacy cache manager (**deprecated**, use `test_cache.sh`)
  - Basic artifact caching functionality
  - Replaced by unified caching system

- **`dependency_tracker.sh`** - Legacy dependency tracker (**deprecated**, merged into `test_cache.sh`)
- **`dependency_chain.sh`** - Dependency chain analysis (**deprecated**, merged into `test_cache.sh`) 
- **`fixture_cache.sh`** - Legacy fixture cache (**deprecated**, merged into `test_cache.sh`)

### Test Orchestration

- **`run_macos_tests.sh`** - Master test orchestrator and runner
  - Parallel and sequential execution modes with configurable job limits
  - Resource isolation for concurrent tests (port allocation, file locking)
  - Speed mode categorization: `--smoke`, `--fast`, `--component`, `--full`
  - Port 443 mutex management for service tests
  - Comprehensive logging and result aggregation
  - Cache system integration and optimization

- **`vm_macos_tests.sh`** - VM-based testing environment
  - Isolated testing in virtual environments
  - Cross-version macOS compatibility testing
  - Network isolation and configuration testing

## Unix Cross-Platform Tests (`unix/`)

**NEW**: Comprehensive Unix testing infrastructure for cross-platform build validation and consistency testing between Unix and Windows MSI builds.

### Core Unix Build Testing

- **`run_unix_tests.sh`** - Master Unix test orchestrator
  - Cross-platform testing coordinator for macOS and Linux
  - Automatic platform detection and dependency management  
  - Speed mode categorization: `--smoke`, `--fast`, `--component`, `--full`
  - Parallel execution with resource isolation
  - Automatic MSI tool installation (msitools, wixl, gcab)
  - Comprehensive reporting and cross-platform validation

- **`test_build_validation.sh`** - Unix Build Script Validation
  - Comprehensive testing of `build_msi_mdm_unix.sh` functionality
  - Dependency checking and auto-installation validation
  - MSI extraction and IDT table validation testing
  - Certificate generation and wixl compression testing
  - 5-phase validation system verification
  - Error handling and security validation testing
  - IDT schema and format validation

- **`test_build_consistency.sh`** - Unix vs Windows Build Consistency
  - Validates Unix-built MSIs are functionally identical to Windows builds
  - IDT table structure comparison and verification
  - Cabinet content verification (starship.cab integrity)
  - Service configuration parity testing
  - Certificate handling consistency validation
  - File sequence and GUID consistency testing
  - MSI size and compression consistency validation

### Platform-Specific Unix Testing

- **`test_platform_specific.sh`** - Platform Environment Testing
  - macOS-specific build environment validation
  - Linux distribution-specific dependency management
  - Package manager integration (Homebrew, MacPorts, apt, yum, dnf)
  - Cross-compilation environment validation
  - msitools compilation from source testing

- **`test_dependency_validation.sh`** - Dependency Management Testing  
  - Automatic dependency installation testing across platforms
  - Missing tool detection and recovery scenarios
  - Package manager compatibility and fallback testing
  - Build environment setup and validation
  - Tool version compatibility testing

### MSI Structure and Integrity Testing

- **`test_msi_structure.sh`** - MSI Structure Validation
  - MSI internal structure and component validation
  - Cabinet content integrity and compression testing
  - Stream extraction and validation
  - Binary file format compliance testing

- **`test_idt_validation.sh`** - IDT Schema and Relationship Testing
  - IDT table schema validation and compliance testing
  - Cross-table relationship integrity validation
  - Data format and type validation
  - Referential integrity constraint testing

- **`test_regression_testing.sh`** - Build Regression Testing
  - Regression testing against known good builds
  - Compatibility testing across MSI versions
  - Performance regression detection
  - Build artifact consistency over time

### Unix Testing Features

**Platform Support:**
- **macOS**: Intel (x64) and Apple Silicon (ARM64)
- **Linux**: Ubuntu 20.04+, CentOS 8+, RHEL 8+, Fedora

**Automatic Dependency Management:**
- **msitools**: msiextract, msidump, msibuild, wixl
- **Supporting Tools**: gcab, openssl, curl, uuidgen
- **Build Tools**: gcc, make, go compiler
- **Package Managers**: Homebrew, MacPorts, apt, yum, dnf

**Cross-Platform Validation:**
- MSI structure consistency between Unix and Windows builds
- Service configuration parity validation
- Certificate handling consistency
- Build process validation phases (5-phase system)
- File sequence and GUID generation consistency

## Unified Test Configuration (`config/`)

### Configuration Management

- **`test_matrix.json`** - Unified Cross-Platform Test Configuration
  - Platform-specific test suite definitions
  - Speed mode categorizations for all platforms
  - Test requirements and dependency specifications
  - Build validation phase definitions
  - Service and certificate configuration standards
  - CI/CD integration matrix and failure thresholds

## Test Categories and Speed Classifications

### Speed Mode Categories

**Smoke Tests** (`--smoke` / `-Smoke`)
- Critical path validation only (~10 seconds)
- Essential functionality verification
- Build exists, service starts, basic connectivity
- Fastest feedback for CI/CD pipelines

**Fast Tests** (`--fast` / `-Fast`)
- Unit-level validation (~30 seconds)
- Parameter validation and configuration parsing
- Basic functionality checks and security validation
- Pester tags: `Fast`, `Unit`

**Component Tests** (`--component` / `-Component`) 
- Component-level integration (~2 minutes)
- Service lifecycle management and certificate operations
- DNS interception methods and build process components
- Pester tags: `Fast`, `Unit`, `Medium`, `Component`

**Full Tests** (`--full` / `-Full`)
- Complete test coverage (~5+ minutes)
- Full build processes and end-to-end deployment
- Performance benchmarks and VM-based testing
- All Pester tags included

### Test Categorization by Platform

**Windows Pester Tags:**
- `Fast`, `Unit` - Quick validation tests
- `Medium`, `Component` - Service and build component tests  
- `Slow`, `Integration` - End-to-end and performance tests

**macOS Speed Modes:**
- `smoke` - Critical path only
- `fast` - Unit tests and quick validation
- `component` - Fast + Medium tests
- `full` - Complete test coverage

## Critical Requirements

### Size Constraints
- **Windows MSI**: Must be ≤125MB (hard enterprise deployment limit)
- **Warning Threshold**: 112MB (90% of limit)
- **Target Optimization**: 110MB with LZX:21 compression
- Automated size validation in all build tests

### Platform Support
- **macOS**: Intel (x64) and Apple Silicon (ARM64) architectures
- **Windows**: Windows 10/11 with WiX toolset (v3.x or v4.x)
- **Cross-compilation**: Full support for building on any platform

### Enterprise Requirements
- **Certificate Management**: Self-signed certificate generation and system trust
- **DNS Interception**: Multiple methods (hosts file, WFP, pfctl, routing)
- **Session Cleanup**: Browser session clearing across Chrome, Edge, Firefox, Safari
- **Service Integration**: Windows Service and macOS LaunchDaemon with proper lifecycle
- **MDM Support**: Configuration via managed preferences and profiles

## Running Tests

### Windows

**IMPORTANT: Run PowerShell as Administrator for all Windows deployment testing**

**Essential Tests (Simple Runner):**
```powershell
# Quick build validation only
.\test\windows\Run-Tests.ps1 -Build

# Post-installation service validation  
.\test\windows\Run-Tests.ps1 -PostInstall

# Full cycle: build, install, and test
.\test\windows\Run-Tests.ps1 -Full

# Cross-platform essential tests
.\test\Test-Essential.ps1
.\test\Test-Essential.ps1 -PostInstall
```

**Comprehensive Test Suite (Advanced Runner):**
```powershell
# Run all test suites with caching
.\test\windows\Run-WindowsTests.ps1

# Speed-based execution
.\test\windows\Run-WindowsTests.ps1 -Smoke      # ~10 seconds, critical path
.\test\windows\Run-WindowsTests.ps1 -Fast       # ~30 seconds, unit tests  
.\test\windows\Run-WindowsTests.ps1 -Component  # ~2 minutes, integration
.\test\windows\Run-WindowsTests.ps1 -Full       # ~5+ minutes, complete

# Specific test suites
.\test\windows\Run-WindowsTests.ps1 -Build -Functionality
.\test\windows\Run-WindowsTests.ps1 -DNSInterception -ServiceRecovery
.\test\windows\Run-WindowsTests.ps1 -SystemIntegration

# Skip MSI build (use existing)
.\test\windows\Run-WindowsTests.ps1 -SkipBuild -Functionality

# Verbose output for debugging
.\test\windows\Run-WindowsTests.ps1 -VerboseOutput
```

**Individual Windows Tests:**
```powershell
# WiX build process
.\test\windows\Test-BuildMsiWix3.ps1

# 5-phase validation framework
.\test\windows\Test-MsiValidation.ps1

# Critical size validation
.\test\windows\Test-MsiSizeValidation.ps1 -StrictMode

# Service functionality
.\test\windows\Test-AuthRouterFunctionality.ps1

# DNS interception methods
.\test\windows\Test-DNSInterceptionMethods.ps1

# Service recovery scenarios
.\test\windows\Test-ServiceRecovery.ps1

# End-to-end integration
.\test\windows\Test-SystemIntegration.ps1
```

### macOS

**Orchestrated Test Execution:**
```bash
# Master test runner with all capabilities
./test/macos/run_macos_tests.sh

# Speed-based execution
./test/macos/run_macos_tests.sh --smoke      # Critical path only
./test/macos/run_macos_tests.sh --fast       # Unit tests
./test/macos/run_macos_tests.sh --component  # Fast + Medium tests
./test/macos/run_macos_tests.sh --full       # Complete coverage

# Parallel execution (default: 3 jobs, max: 8)
./test/macos/run_macos_tests.sh --parallel
./test/macos/run_macos_tests.sh --parallel 5
./test/macos/run_macos_tests.sh --sequential

# Specific test suites
./test/macos/run_macos_tests.sh --build --daemon
./test/macos/run_macos_tests.sh --integration --browser
./test/macos/run_macos_tests.sh --dns --cleanup --privilege
./test/macos/run_macos_tests.sh --cache --download
```

**Individual macOS Tests:**
```bash
# Core functionality
./test/macos/test_macos_build.sh
./test/macos/test_macos_daemon.sh  
./test/macos/test_macos_integration.sh
./test/macos/test_build_outputs.sh

# System components
./test/macos/test_browser_sessions.sh
./test/macos/test_dns_methods.sh
./test/macos/test_cleanup_manager.sh
./test/macos/test_privilege_escalation.sh
./test/macos/test_mdm_certificate.sh

# Cache and resource management
./test/macos/test_cache.sh test
./test/macos/test_cache.sh init
./test/macos/test_cache.sh cleanup

# Download robustness testing
./test/macos/test_download_robustness.sh
```

### Unix Cross-Platform Tests

**Master Unix Test Runner:**
```bash
# Complete Unix cross-platform testing
./test/unix/run_unix_tests.sh

# Speed-based execution
./test/unix/run_unix_tests.sh --smoke      # Critical functionality (~30s)
./test/unix/run_unix_tests.sh --fast       # Unit tests (~2 minutes)
./test/unix/run_unix_tests.sh --component  # Component tests (~5 minutes)  
./test/unix/run_unix_tests.sh --full       # Complete coverage (~15+ minutes)

# Specific test suites
./test/unix/run_unix_tests.sh --build-validation      # Unix build script validation
./test/unix/run_unix_tests.sh --build-consistency     # Unix vs Windows consistency
./test/unix/run_unix_tests.sh --platform-specific     # Platform environment tests

# Configuration options
./test/unix/run_unix_tests.sh --install-deps --verbose    # Auto-install dependencies + verbose
./test/unix/run_unix_tests.sh --parallel 4               # Parallel execution (4 jobs)
./test/unix/run_unix_tests.sh --sequential               # Sequential execution
```

**Individual Unix Tests:**
```bash
# Core build validation
./test/unix/test_build_validation.sh         # Unix build script comprehensive testing
./test/unix/test_build_consistency.sh        # Unix vs Windows MSI consistency  

# Platform-specific testing (when implemented)
./test/unix/test_platform_specific.sh        # Platform environment validation
./test/unix/test_dependency_validation.sh    # Dependency management testing
./test/unix/test_msi_structure.sh           # MSI structure and integrity
./test/unix/test_idt_validation.sh          # IDT schema and relationships
./test/unix/test_regression_testing.sh      # Build regression testing
```

### Cross-Platform Essential Tests

```bash
# These tests exist in both /test/ and platform-specific directories
./test/Test-Essential.ps1                    # Windows PowerShell
./test/Test-BrowserSessionCleanup.ps1        # Windows PowerShell
```

## Key Test Validations

### Build Process Validation
- **Dependencies**: Go 1.21+, WiX toolset (v3.x/v4.x)
- **Binary Compilation**: Cross-platform builds with proper optimization flags  
- **Certificate Generation**: Self-signed certificates with system trust installation
- **Package Assembly**: MSI/PKG creation with compression and size optimization
- **Metadata Validation**: Version extraction, upgrade codes, component GUIDs

### Deployment Verification  
- **Service Management**: Windows Service and macOS LaunchDaemon lifecycle
- **Network Configuration**: Port 443 binding without conflicts
- **DNS Interception**: Multiple methods (hosts, WFP, pfctl, routing)
- **Certificate Trust**: System keychain/certificate store integration
- **Configuration Loading**: MDM managed preferences, command-line flags, registry

### SAML Enforcement Validation
- **Login Redirection**: Automatic redirect to configured SAML identity provider
- **Parameter Preservation**: Query strings and authentication state maintenance
- **Multi-Protocol Support**: Browser and desktop application compatibility  
- **Session Management**: Browser session cleanup for fresh authentication flows
- **Error Handling**: Graceful fallback for network and configuration issues

### System Integration Testing
- **Complete Flow**: DNS → Proxy → SAML → Certificate validation
- **Browser Compatibility**: Chrome, Edge, Firefox, Safari session handling
- **Network Resilience**: Upstream proxy failures and recovery scenarios
- **Performance Monitoring**: Resource usage and response time validation

## Test Configuration Data

### Windows Test Configuration (ADFS)
- **Team**: `cs-demo`  
- **SAML URL**: `https://identity.getpostman.com/sso/adfs/1d7b9d2030a64fc6adc6edb0ce7c09b3/init`
- **Service Name**: `PostmanAuthRouter`
- **Test Domain**: `identity.getpostman.com`

### macOS Test Configuration (Okta)
- **Team**: `postman`
- **SAML URL**: `https://identity.getpostman.com/sso/okta/db1b1a3764f24213906d682e26fd366f/init`  
- **Service Name**: `com.postman.pm-authrouter`
- **Test Domain**: `identity.getpostman.com`

## Performance and Resource Requirements

### Build Performance Targets
- **Windows MSI Build**: <10 minutes (including LZX:21 compression)
- **macOS PKG Build**: <5 minutes per architecture (ARM64/Intel)
- **Cache Hit Rate**: >80% for incremental builds
- **Parallel Test Execution**: 3-8 concurrent jobs on macOS

### Runtime Resource Limits
- **Memory Usage**: <100MB per service instance
- **CPU Usage (Idle)**: <5% on modern hardware
- **Disk Usage**: <500MB for all build artifacts and cache
- **Network Latency**: <200ms for SAML redirects, <50ms DNS resolution

### Test Execution Performance
- **Smoke Tests**: <10 seconds (critical path only)
- **Fast Tests**: <30 seconds (unit validation)  
- **Component Tests**: <2 minutes (integration testing)
- **Full Test Suite**: <10 minutes (complete validation)

## Debugging and Troubleshooting

### Service Log Locations
- **Windows**: `C:\ProgramData\Postman\pm-authrouter.log`
- **macOS**: `/var/log/postman/pm-authrouter.log`
- **Test Logs**: `test/windows/*.txt`, `test/macos/test_results_*.txt`

### Common Test Failure Scenarios

**MSI Size Limit Exceeded (>125MB)**
- Check compression settings (should use LZX:21)
- Analyze component sizes with `Test-MsiSizeValidation.ps1 -Detailed`
- Review included dependencies and unnecessary files

**Service Installation Failures**
- Verify Administrator privileges on Windows
- Check for port 443 conflicts (`netstat -an | findstr :443`)
- Validate WiX toolset installation (v3.x/v4.x)
- Review Windows Event Log for service errors

**Certificate Trust Issues**
- **Windows**: Check certificate is in Trusted Root Certification Authorities
- **macOS**: Verify System keychain contains certificate with trust settings
- Test certificate validation: `certutil -verify cert.crt` (Windows)

**DNS Interception Not Working**
- **Windows**: Verify hosts file modification permissions
- **macOS**: Check pfctl rules and DNS cache flush
- Test resolution: `nslookup identity.getpostman.com`
- Verify no DNS-over-HTTPS interference

**Build Environment Issues** 
- **Missing Dependencies**: Run validation framework tests first
- **Antivirus Interference**: Add build directories to exclusions
- **Disk Space**: Ensure >2GB free space for build process
- **Network Access**: Verify connectivity for dependency downloads

**Unix Cross-Platform Build Issues**

**Missing MSI Tools (msitools package)**
- **Auto-install**: Use `./test/unix/run_unix_tests.sh --install-deps`
- **macOS Manual**: `brew install msitools` or `sudo port install msitools`
- **Linux Manual**: `sudo apt install msitools` (Ubuntu) or `sudo yum install msitools` (RHEL/CentOS)
- **Source Build**: Build from https://github.com/libyal/libmsi if package unavailable

**Unix Build Script Validation Failures**
- Verify original Postman MSI is present in `deployment/windows/`
- Check that `build_msi_mdm_unix.sh` is executable (`chmod +x`)
- Ensure sufficient disk space for MSI extraction and rebuilding
- Run `./test/unix/test_build_validation.sh` independently for detailed diagnostics

**Cross-Platform Consistency Issues**  
- Verify GUIDs are generated deterministically (not random)
- Check service configuration parameters match Windows builds
- Validate certificate generation produces identical subject/issuer
- Compare IDT table structures with `./test/unix/test_build_consistency.sh`

**Platform-Specific Dependency Issues**
- **macOS Homebrew**: `brew doctor` to check for issues
- **macOS MacPorts**: Ensure Xcode Command Line Tools installed
- **Linux Package Managers**: Update package lists (`apt update`, `yum update`)
- **Cross-compilation**: Verify Go cross-compilation environment

**Pester Version Compatibility (Windows)**
- Test runner now auto-detects and adapts to Pester 3.4.0 through 5.x
- Priority order: 3.4.0 (preferred) → 4.x → 5.x → latest available
- Legacy parameter sets attempted before new configuration syntax
- Manual fallback: `Import-Module Pester -Force` if auto-detection fails

### Test Environment Prerequisites
- **Administrative Privileges**: Required for service installation and testing
- **Clean Environment**: No conflicting services on port 443
- **Network Connectivity**: Access to identity.getpostman.com for integration tests
- **Build Tools**: Platform-appropriate toolchain (WiX v3.x/v4.x, Xcode, Go 1.21+)

This comprehensive test suite validates the Postman AuthRouter across all deployment scenarios, with emphasis on enterprise requirements, security, and the critical 125MB size constraint for Windows MSI packages.
