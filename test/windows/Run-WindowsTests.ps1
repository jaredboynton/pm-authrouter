# Run-WindowsTests.ps1 - Master test runner for all Windows tests
# Coordinates and runs all Windows test suites for Postman AuthRouter

[CmdletBinding()]
param(
    [switch]$Build,           # Run only build tests
    [switch]$Functionality,   # Run only functionality tests
    [switch]$BrowserCleanup,  # Run only browser cleanup tests
    [switch]$EdgeCases,       # Run only edge case tests
    [switch]$DNSInterception, # Run only DNS interception method tests
    [switch]$ServiceRecovery, # Run only service recovery tests
    [switch]$SystemIntegration, # Run only system integration tests
    [switch]$SkipBuild,       # Skip building the MSI
    [switch]$VerboseOutput,   # Verbose output
    [switch]$Help,            # Show help
    # Test categorization switches
    [switch]$Smoke,           # Run smoke tests (fastest subset)
    [switch]$Fast,            # Run fast tests (under 30 seconds)
    [switch]$Component,       # Run component tests (fast + medium)
    [switch]$Full             # Run all tests (fast + medium + slow)
)

# Colors for output
$Colors = @{
    Red    = [ConsoleColor]::Red
    Green  = [ConsoleColor]::Green
    Yellow = [ConsoleColor]::Yellow
    Blue   = [ConsoleColor]::Blue
    White  = [ConsoleColor]::White
}

# Test configuration  
$ScriptRoot = $PSScriptRoot
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $ScriptRoot)
$TestResults = @()
$TotalFailures = 0

# Test suite configuration
$TestSuites = @{
    'Build' = @{
        Name = 'MSI Build Tests (WiX 3.11)'
        Script = 'Test-BuildMsiWix3.ps1'
        Description = 'Tests MSI build process with WiX 3.11 and validation framework'
    }
    'Validation' = @{
        Name = 'MSI Validation Framework Tests'
        Script = 'Test-MsiValidation.ps1'
        Description = 'Tests 5-phase validation system and build prerequisites'
    }
    'Functionality' = @{
        Name = 'AuthRouter Functionality Tests'
        Script = 'Test-AuthRouterFunctionality.ps1'
        Description = 'Tests Windows service operations and SAML enforcement'
    }
    'BrowserCleanup' = @{
        Name = 'Browser Session Cleanup Tests'
        Script = 'Test-BrowserSessionCleanup.ps1'
        Description = 'Tests browser session cleanup functionality'
    }
    'EdgeCases' = @{
        Name = 'Edge Case Tests'
        Script = 'Test-BuildEdgeCases.ps1'
        Description = 'Tests error handling and edge cases'
    }
    'DNSInterception' = @{
        Name = 'DNS Interception Methods Tests'
        Script = 'Test-DNSInterceptionMethods.ps1'
        Description = 'Tests all Windows DNS interception methods'
    }
    'ServiceRecovery' = @{
        Name = 'Service Recovery Tests'
        Script = 'Test-ServiceRecovery.ps1'
        Description = 'Tests service crash recovery and restart scenarios'
    }
    'SystemIntegration' = @{
        Name = 'System Integration Tests'
        Script = 'Test-SystemIntegration.ps1'
        Description = 'End-to-end integration tests for the complete system'
    }
}

# Helper functions
function Write-ColorText {
    param(
        [string]$Text,
        [ConsoleColor]$Color = [ConsoleColor]::White
    )
    Write-Host $Text -ForegroundColor $Color
}

function Write-Info {
    param([string]$Message)
    Write-ColorText "[INFO] $Message" -Color $Colors.Blue
}

function Write-Success {
    param([string]$Message)
    Write-ColorText "[SUCCESS] $Message" -Color $Colors.Green
}

function Write-Warning {
    param([string]$Message)
    Write-ColorText "[WARNING] $Message" -Color $Colors.Yellow
}

function Write-Error {
    param([string]$Message)
    Write-ColorText "[ERROR] $Message" -Color $Colors.Red
}

function Write-Separator {
    Write-ColorText "========================================" -Color $Colors.White
}

function Show-Help {
    Write-Host @"
Run-WindowsTests.ps1 - Windows Test Suite Runner

SYNOPSIS
    Runs comprehensive test suites for Windows Postman AuthRouter

SYNTAX
    .\Run-WindowsTests.ps1 [OPTIONS]

OPTIONS - Test Suite Selection
    -Build              Run only MSI build tests
    -Functionality      Run only functionality tests  
    -BrowserCleanup     Run only browser cleanup tests
    -EdgeCases          Run only edge case tests
    -DNSInterception    Run only DNS interception method tests
    -ServiceRecovery    Run only service recovery tests
    -SystemIntegration  Run only system integration tests
    
OPTIONS - Test Categorization (Fast Development)
    -Smoke              Run smoke tests (~10 seconds) - Critical path validation
    -Fast               Run fast tests (~30 seconds) - Unit tests & quick validation
    -Component          Run component tests (~2 minutes) - Fast + medium tests
    -Full               Run all tests (~5+ minutes) - Complete test coverage
    
OPTIONS - Configuration
    -SkipBuild          Skip building the MSI before tests
    -VerboseOutput      Enable verbose output
    -Help               Show this help message

EXAMPLES
    # Quick smoke test for critical functionality
    .\Run-WindowsTests.ps1 -Smoke
    
    # Fast feedback loop for development
    .\Run-WindowsTests.ps1 -Fast
    
    # Comprehensive pre-commit validation
    .\Run-WindowsTests.ps1 -Component
    
    # Full test coverage (CI/CD)
    .\Run-WindowsTests.ps1 -Full
    
    # Run specific test suite
    .\Run-WindowsTests.ps1 -Build
    
    # Run build and functionality tests
    .\Run-WindowsTests.ps1 -Build -Functionality
    
    # Run tests without building MSI first
    .\Run-WindowsTests.ps1 -SkipBuild

NOTES
    - Some tests require Administrator privileges
    - Tests may modify system state (services, registry, hosts file)
    - Run from elevated PowerShell for full coverage
    - Original Postman MSI must be present in deployment/windows/
    
REQUIREMENTS
    - Windows 10/11 or Windows Server 2019+
    - PowerShell 5.1+ (PowerShell 7+ recommended)
    - Administrator privileges (for some tests)
    - Original Postman Enterprise MSI file
    - WiX Toolset 3.11 (install from https://github.com/wixtoolset/wix3/releases/tag/wix3112rtm)
    - Go compiler (for building AuthRouter binary)

"@
}

function Test-Prerequisites {
    Write-Info "Checking prerequisites..."
    
    $Prerequisites = @()
    
    # Check Windows version
    $WindowsVersion = [System.Environment]::OSVersion.Version
    if ($WindowsVersion.Major -lt 10) {
        $Prerequisites += "Windows 10 or later required"
    }
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        $Prerequisites += "PowerShell 5.1 or later required"
    }
    
    # Check if running as Administrator
    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $IsAdmin) {
        Write-Warning "Not running as Administrator - some tests will be skipped"
        Write-Info "For full coverage, run from elevated PowerShell"
    } else {
        Write-Info "Running as Administrator - full test coverage available"
    }
    
    # Check for Go
    try {
        $GoVersion = & go version 2>$null
        Write-Info "Go detected: $GoVersion"
    }
    catch {
        $Prerequisites += "Go compiler not found - binary compilation tests will fail"
    }
    
    # Check for original Postman MSI (using robust path handling)
    $msiDir = Join-Path $ProjectRoot "deployment\windows"
    Write-Info "Looking for MSI in: $msiDir"
    
    # Try provider -Filter first, then fall back to PowerShell wildcard matching
    $PostmanMsi = Get-ChildItem -LiteralPath $msiDir -File -Filter "Postman-Enterprise-*.msi" -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch "saml" } | Select-Object -First 1
    
    if (-not $PostmanMsi) {
        # Fallback to PowerShell wildcard pattern (works around UNC provider issues)
        $pattern = New-Object System.Management.Automation.WildcardPattern "Postman-Enterprise-*.msi","IgnoreCase"
        $PostmanMsi = Get-ChildItem -LiteralPath $msiDir -File -ErrorAction SilentlyContinue |
            Where-Object { $pattern.IsMatch($_.Name) -and $_.Name -notmatch "saml" } | Select-Object -First 1
    }
    
    if (-not $PostmanMsi) {
        $Prerequisites += "Original Postman Enterprise MSI not found in deployment/windows/"
    } else {
        Write-Info "Found original MSI: $($PostmanMsi.Name)"
    }
    
    # Report prerequisites
    if ($Prerequisites.Count -gt 0) {
        Write-Warning "Prerequisites issues found:"
        foreach ($Issue in $Prerequisites) {
            Write-ColorText "  - $Issue" -Color $Colors.Yellow
        }
        Write-Info "Some tests may be skipped or fail"
    } else {
        Write-Success "All prerequisites met"
    }
    
    return $Prerequisites.Count -eq 0
}

function Invoke-TestSuite {
    param(
        [string]$SuiteName,
        [hashtable]$SuiteConfig,
        [string[]]$TagFilter = @()
    )
    
    Write-Separator
    Write-ColorText "Running $($SuiteConfig.Name)" -Color $Colors.Yellow
    Write-Separator
    Write-Info $SuiteConfig.Description
    Write-Host ""
    
    $TestScript = Join-Path $ScriptRoot $SuiteConfig.Script
    
    if (-not (Test-Path $TestScript)) {
        Write-Error "Test script not found: $TestScript"
        return $false
    }
    
    try {
        $TestParams = @{}
        if ($VerboseOutput) { $TestParams['Verbose'] = $true }
        
        # Add tag filter if using categorization
        if ($TagFilter.Count -gt 0) {
            Write-Info "Running with tag filter: $($TagFilter -join ', ')"
            
            # Check if this is actually a Pester test file
            $isPesterTest = (Get-Content $TestScript -Raw) -match "Describe\s"
            
            if ($isPesterTest) {
                # Determine Pester version and use appropriate syntax
                $pesterModule = Get-Module -ListAvailable -Name Pester | Sort-Object Version -Descending | Select-Object -First 1
                
# Dynamic Pester version compatibility handling
                $availablePesterVersions = Get-Module -ListAvailable -Name Pester | Sort-Object Version -Descending
                $pesterToUse = $null
                $pesterSyntax = "unknown"
                
                # Priority order: 3.4.0, 4.x, 5.x, latest available
                foreach ($version in $availablePesterVersions) {
                    if ($version.Version.ToString() -eq "3.4.0") {
                        $pesterToUse = $version
                        $pesterSyntax = "v3"
                        Write-Info "Found preferred Pester 3.4.0 for enterprise compatibility"
                        break
                    }
                }
                
                if (-not $pesterToUse) {
                    foreach ($version in $availablePesterVersions) {
                        if ($version.Version.Major -eq 4) {
                            $pesterToUse = $version
                            $pesterSyntax = "v4"
                            Write-Info "Using Pester 4.x for compatibility"
                            break
                        }
                    }
                }
                
                if (-not $pesterToUse) {
                    foreach ($version in $availablePesterVersions) {
                        if ($version.Version.Major -eq 5) {
                            $pesterToUse = $version
                            $pesterSyntax = "v5"
                            Write-Warning "Using Pester 5.x - some compatibility issues may occur"
                            break
                        }
                    }
                }
                
                if (-not $pesterToUse) {
                    $pesterToUse = $availablePesterVersions | Select-Object -First 1
                    $pesterSyntax = "latest"
                    Write-Warning "Using latest available Pester $($pesterToUse.Version) - compatibility not guaranteed"
                }
                
                if (-not $pesterToUse) {
                    Write-Error "No Pester module found - tests cannot run"
                    return $false
                }
                
                # Import the selected Pester version
                try {
                    Import-Module Pester -RequiredVersion $pesterToUse.Version -Force -ErrorAction Stop
                    Write-Info "Successfully loaded Pester $($pesterToUse.Version)"
                } catch {
                    Write-Warning "Failed to import Pester $($pesterToUse.Version): $($_.Exception.Message)"
                    Write-Info "Attempting to import any available Pester version"
                    Import-Module Pester -Force
                }
                
                # Execute tests using appropriate syntax
                try {
                    switch ($pesterSyntax) {
                        "v3" {
                            $result = Invoke-Pester -Script $TestScript -Tag $TagFilter -PassThru -Quiet:(-not $VerboseOutput)
                            $success = $result.FailedCount -eq 0
                        }
                        "v4" {
                            $result = Invoke-Pester -Script $TestScript -Tag $TagFilter -PassThru -Quiet:(-not $VerboseOutput)
                            $success = $result.FailedCount -eq 0
                        }
                        "v5" {
                            # Try legacy parameter set first for backwards compatibility
                            try {
                                $result = Invoke-Pester -Script $TestScript -Tag $TagFilter -PassThru -Quiet:(-not $VerboseOutput) -LegacyParameterSet -ErrorAction Stop
                            } catch {
                                # Fall back to new syntax
                                $config = New-PesterConfiguration
                                $config.Run.Path = $TestScript
                                if ($TagFilter.Count -gt 0) { $config.Filter.Tag = $TagFilter }
                                $config.Output.Verbosity = if ($VerboseOutput) { 'Detailed' } else { 'Normal' }
                                $result = Invoke-Pester -Configuration $config
                            }
                            $success = $result.FailedCount -eq 0
                        }
                        default {
                            # Try modern syntax first
                            try {
                                $config = New-PesterConfiguration
                                $config.Run.Path = $TestScript
                                if ($TagFilter.Count -gt 0) { $config.Filter.Tag = $TagFilter }
                                $config.Output.Verbosity = if ($VerboseOutput) { 'Detailed' } else { 'Normal' }
                                $result = Invoke-Pester -Configuration $config
                            } catch {
                                # Fall back to legacy syntax
                                $result = Invoke-Pester -Script $TestScript -Tag $TagFilter -PassThru -Quiet:(-not $VerboseOutput)
                            }
                            $success = $result.FailedCount -eq 0
                        }
                    }
                } catch {
                    Write-Error "Failed to execute Pester tests: $($_.Exception.Message)"
                    return $false
                }
                
                if ($success) {
                    Write-Host "Passed: $($result.PassedCount) tests" -ForegroundColor Green
                } else {
                    Write-Host "Failed: $($result.FailedCount) tests, Passed: $($result.PassedCount) tests" -ForegroundColor Red
                }
                
                return $success
            } else {
                Write-Info "Not a Pester test file - running as utility script"
                # Execute non-Pester script normally
                $Result = & $TestScript @TestParams
            }
        } else {
            # Execute test script normally
            $Result = & $TestScript @TestParams
        }
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "$($SuiteConfig.Name) completed successfully"
            return $true
        } else {
            Write-Error "$($SuiteConfig.Name) failed with exit code $LASTEXITCODE"
            return $false
        }
    }
    catch {
        Write-Error "$($SuiteConfig.Name) failed with exception: $($_.Exception.Message)"
        if ($VerboseOutput) {
            Write-ColorText $_.ScriptStackTrace -Color $Colors.Red
        }
        return $false
    }
}

function Get-SourceHash {
    param([string]$ProjectRoot)
    
    $sourceFiles = @()
    $sourceFiles += Get-ChildItem "$ProjectRoot\cmd" -Recurse -File -ErrorAction SilentlyContinue
    $sourceFiles += Get-ChildItem "$ProjectRoot\internal" -Recurse -File -ErrorAction SilentlyContinue
    $sourceFiles += Get-ChildItem "$ProjectRoot\deployment\windows" -Recurse -File -ErrorAction SilentlyContinue
    $sourceFiles += Get-ChildItem "$ProjectRoot\go.mod" -ErrorAction SilentlyContinue
    $sourceFiles += Get-ChildItem "$ProjectRoot\go.sum" -ErrorAction SilentlyContinue
    
    if ($sourceFiles.Count -eq 0) {
        return "no-source-files"
    }
    
    # Create hash from file sizes and last write times
    $hashInput = ($sourceFiles | Sort-Object FullName | ForEach-Object {
        "$($_.FullName):$($_.Length):$($_.LastWriteTime.Ticks)"
    }) -join "|"
    
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($hashInput))
    return [System.BitConverter]::ToString($hashBytes).Replace("-", "").ToLower()
}

function Test-CachedMSI {
    param(
        [string]$ProjectRoot,
        [string]$CacheDir = "$env:TEMP\msi_build_cache"
    )
    
    if (-not (Test-Path $CacheDir)) {
        New-Item -ItemType Directory -Path $CacheDir -Force | Out-Null
    }
    
    $sourceHash = Get-SourceHash -ProjectRoot $ProjectRoot
    $hashFile = Join-Path $CacheDir "source.hash"
    $msiFile = Join-Path $CacheDir "cached-build.msi"
    
    if (-not (Test-Path $hashFile) -or -not (Test-Path $msiFile)) {
        return @{ Valid = $false; Reason = "Cache files missing" }
    }
    
    $cachedHash = Get-Content $hashFile -Raw -ErrorAction SilentlyContinue
    if ($cachedHash -ne $sourceHash) {
        return @{ Valid = $false; Reason = "Source code has changed" }
    }
    
    # Check if MSI is valid
    $msiInfo = Get-Item $msiFile -ErrorAction SilentlyContinue
    if (-not $msiInfo -or $msiInfo.Length -lt 1MB) {
        return @{ Valid = $false; Reason = "Cached MSI appears invalid" }
    }
    
    return @{ 
        Valid = $true
        Path = $msiFile
        Hash = $sourceHash
        Size = [math]::Round($msiInfo.Length / 1MB, 2)
    }
}

function Save-CachedMSI {
    param(
        [string]$ProjectRoot,
        [string]$MsiPath,
        [string]$CacheDir = "$env:TEMP\msi_build_cache"
    )
    
    if (-not (Test-Path $CacheDir)) {
        New-Item -ItemType Directory -Path $CacheDir -Force | Out-Null
    }
    
    $sourceHash = Get-SourceHash -ProjectRoot $ProjectRoot
    $hashFile = Join-Path $CacheDir "source.hash"
    $cachedMsiFile = Join-Path $CacheDir "cached-build.msi"
    
    try {
        Copy-Item $MsiPath $cachedMsiFile -Force
        $sourceHash | Out-File $hashFile -Encoding UTF8 -NoNewline
        
        $msiSize = [math]::Round((Get-Item $cachedMsiFile).Length / 1MB, 2)
        Write-Success "MSI cached successfully ($msiSize MB, hash: $($sourceHash.Substring(0,8))...)"
        return $true
    }
    catch {
        Write-Warning "Failed to cache MSI: $($_.Exception.Message)"
        return $false
    }
}

function Build-AuthRouterMSI {
    if ($SkipBuild) {
        Write-Info "Skipping MSI build as requested"
        return $true
    }
    
    Write-Separator
    Write-ColorText "Building AuthRouter MSI" -Color $Colors.Yellow
    Write-Separator
    
    # Check for cached MSI first
    Write-Info "Checking for cached MSI build..."
    $cacheResult = Test-CachedMSI -ProjectRoot $ProjectRoot
    
    if ($cacheResult.Valid) {
        Write-Success "Using cached MSI build ($($cacheResult.Size) MB, hash: $($cacheResult.Hash.Substring(0,8))...)"
        
        # Copy cached MSI to deployment directory
        $deploymentDir = Join-Path $ProjectRoot "deployment\windows"
        $targetMsi = Get-ChildItem "$deploymentDir\Postman-Enterprise-*-saml.msi" -ErrorAction SilentlyContinue | Select-Object -First 1
        
        if ($targetMsi) {
            Copy-Item $cacheResult.Path $targetMsi.FullName -Force
        } else {
            $defaultTarget = Join-Path $deploymentDir "Postman-Enterprise-cached-saml.msi"
            Copy-Item $cacheResult.Path $defaultTarget -Force
        }
        
        Write-Success "Cached MSI restored successfully"
        return $true
    } else {
        Write-Info "Cache miss: $($cacheResult.Reason)"
    }
    
    $BuildScript = Join-Path $ProjectRoot "deployment\windows\build_msi_mdm_win.ps1"
    
    if (-not (Test-Path $BuildScript)) {
        Write-Error "Build script not found: $BuildScript"
        return $false
    }
    
    try {
        Write-Info "Starting MSI build process..."
        $buildStartTime = Get-Date
        
        $BuildParams = @{
            'TeamName' = 'test-team'
            'SamlUrl' = 'https://identity.getpostman.com/sso/test/init'
        }
        
        if ($VerboseOutput) { $BuildParams['VerboseOutput'] = $true }
        
        & $BuildScript @BuildParams
        
        if ($LASTEXITCODE -eq 0) {
            $buildDuration = [math]::Round(((Get-Date) - $buildStartTime).TotalSeconds, 1)
            Write-Success "MSI build completed successfully in $buildDuration seconds"
            
            # Cache the built MSI
            $deploymentDir = Join-Path $ProjectRoot "deployment\windows"
            $builtMsi = Get-ChildItem "$deploymentDir\*-saml.msi" -ErrorAction SilentlyContinue | Select-Object -First 1
            
            if ($builtMsi) {
                Save-CachedMSI -ProjectRoot $ProjectRoot -MsiPath $builtMsi.FullName
            }
            
            return $true
        } else {
            Write-Error "MSI build failed with exit code $LASTEXITCODE"
            return $false
        }
    }
    catch {
        Write-Error "MSI build failed with exception: $($_.Exception.Message)"
        return $false
    }
}

function Get-TestSuitesToRun {
    $SuitesToRun = @()
    
    # Check if categorization switches are used
    if ($Smoke -or $Fast -or $Component -or $Full) {
        # Only include Pester-based test suites for tag filtering
        $SuitesToRun = $TestSuites.Keys | Where-Object { 
            -not $TestSuites[$_].ContainsKey('IsPesterTest') -or $TestSuites[$_].IsPesterTest -ne $false 
        }
        return $SuitesToRun
    }
    
    # Traditional suite selection
    if ($Build) { $SuitesToRun += 'Build' }
    if ($Functionality) { $SuitesToRun += 'Functionality' }
    if ($BrowserCleanup) { $SuitesToRun += 'BrowserCleanup' }
    if ($EdgeCases) { $SuitesToRun += 'EdgeCases' }
    if ($DNSInterception) { $SuitesToRun += 'DNSInterception' }
    if ($ServiceRecovery) { $SuitesToRun += 'ServiceRecovery' }
    if ($SystemIntegration) { $SuitesToRun += 'SystemIntegration' }
    
    # If no specific suites selected, run all
    if ($SuitesToRun.Count -eq 0) {
        $SuitesToRun = $TestSuites.Keys
    }
    
    return $SuitesToRun
}

function Get-TestTagFilter {
    # Determine which tags to run based on categorization switches
    if ($Smoke) {
        return @("Fast")  # Only fastest tests for smoke
    } elseif ($Fast) {
        return @("Fast", "Unit")  # Fast unit tests
    } elseif ($Component) {
        return @("Fast", "Unit", "Medium", "Component")  # Fast + Medium tests
    } elseif ($Full) {
        return @()  # No filter - run all tests
    }
    return @()  # Default - no filter
}

function Generate-Summary {
    param(
        [string[]]$FailedSuites
    )
    
    Write-Separator
    Write-ColorText "Test Summary" -Color $Colors.Yellow
    Write-Separator
    
    $TotalSuites = $TestResults.Count
    $PassedSuites = ($TestResults | Where-Object { $_ }).Count
    $FailedSuites = $TotalSuites - $PassedSuites
    
    Write-Info "Total Test Suites: $TotalSuites"
    Write-ColorText "Passed: $PassedSuites" -Color $Colors.Green
    
    if ($FailedSuites -gt 0) {
        Write-ColorText "Failed: $FailedSuites" -Color $Colors.Red
        Write-Host ""
        Write-Error "The following test suites failed:"
        foreach ($Suite in ($TestResults.Keys | Where-Object { -not $TestResults[$_] })) {
            Write-ColorText "  - $($TestSuites[$Suite].Name)" -Color $Colors.Red
        }
    } else {
        Write-ColorText "Failed: 0" -Color $Colors.Green
        Write-Host ""
        Write-Success "All test suites passed!"
    }
    
    # Show result files
    Write-Host ""
    Write-Info "Test result files:"
    Get-ChildItem "$ScriptRoot\*.txt" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-ColorText "  - $($_.Name)" -Color $Colors.White
    }
    
    Write-Host ""
    Write-Info "Test logs and artifacts stored in: $ScriptRoot"
}

# Main execution
function Main {
    if ($Help) {
        Show-Help
        return
    }
    
    Write-Separator
    Write-ColorText "Windows Test Suite Runner" -Color $Colors.White
    Write-Separator
    Write-Info "Started: $(Get-Date)"
    Write-Info "Platform: $([System.Environment]::OSVersion.VersionString)"
    Write-Info "PowerShell: $($PSVersionTable.PSVersion)"
    if (Get-Command go -ErrorAction SilentlyContinue) {
        Write-Info "Go: $(& go version)"
    }
    Write-Host ""
    
    # Check prerequisites
    $PrereqsPassed = Test-Prerequisites
    
    # Change to project root
    Set-Location $ProjectRoot
    
    # Build MSI if needed (skip for fast unit tests)
    $TagFilter = Get-TestTagFilter
    $NeedsMSI = -not ($Smoke -or $Fast) # Smoke and Fast tests don't need MSI
    
    if (-not $SkipBuild -and $NeedsMSI) {
        $BuildSuccess = Build-AuthRouterMSI
        if (-not $BuildSuccess -and -not $SkipBuild) {
            Write-Error "MSI build failed - aborting tests"
            exit 1
        }
    } elseif (-not $NeedsMSI) {
        Write-Info "Skipping MSI build for fast unit tests"
    }
    
    # Determine which test suites to run
    $SuitesToRun = Get-TestSuitesToRun
    $TagFilter = Get-TestTagFilter
    
    Write-Host ""
    if ($TagFilter.Count -gt 0) {
        Write-Info "Test categorization: Running tests with tags: $($TagFilter -join ', ')"
        Write-Info "Test suites to filter: $($SuitesToRun -join ', ')"
    } else {
        Write-Info "Test suites to run: $($SuitesToRun -join ', ')"
    }
    Write-Host ""
    
    # Run test suites
    $script:TestResults = @{}
    foreach ($SuiteName in $SuitesToRun) {
        if ($TestSuites.ContainsKey($SuiteName)) {
            $SuiteConfig = $TestSuites[$SuiteName]
            $Success = Invoke-TestSuite -SuiteName $SuiteName -SuiteConfig $SuiteConfig -TagFilter $TagFilter
            $script:TestResults[$SuiteName] = $Success
            
            if (-not $Success) {
                $script:TotalFailures++
            }
        } else {
            Write-Error "Unknown test suite: $SuiteName"
        }
    }
    
    # Generate summary
    Generate-Summary
    
    # Exit with appropriate code
    if ($script:TotalFailures -eq 0) {
        exit 0
    } else {
        exit 1
    }
}

# Run if executed directly
if ($MyInvocation.InvocationName -ne '.') {
    Main
}