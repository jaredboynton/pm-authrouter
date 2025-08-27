# Run-Tests.ps1
# Simple test runner for what actually matters

param(
    [switch]$Build,
    [switch]$PostInstall,
    [switch]$Full,
    [switch]$Help
)

if ($Help) {
    Write-Host @"
Postman AuthRouter Test Runner

Usage:
  .\Run-Tests.ps1 -Build       # Test MSI build process
  .\Run-Tests.ps1 -PostInstall # Test after installation
  .\Run-Tests.ps1 -Full        # Build, install, and test everything

What this actually tests:
  1. Can we build an MSI under 125MB?
  2. Does the service install and start?
  3. Does SAML redirection work?

That's it. No mocks, no unit tests, just real validation.
"@
    exit 0
}

$ErrorActionPreference = "Stop"

Write-Host "=" * 50 -ForegroundColor Cyan
Write-Host "POSTMAN AUTHROUTER - ESSENTIAL TESTS" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Cyan

# Default to build test if nothing specified
if (-not $Build -and -not $PostInstall -and -not $Full) {
    $Build = $true
}

$testScript = "$PSScriptRoot\Test-Essential.ps1"

if (-not (Test-Path $testScript)) {
    Write-Host "ERROR: Essential test script not found" -ForegroundColor Red
    exit 1
}

# Run build tests
if ($Build -or $Full) {
    Write-Host "`nRunning build validation..." -ForegroundColor Yellow
    & $testScript
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "`nBuild validation failed" -ForegroundColor Red
        exit 1
    }
}

# Run installation if doing full test
if ($Full) {
    Write-Host "`nInstalling MSI for full testing..." -ForegroundColor Yellow
    
    $msi = Get-ChildItem "$PSScriptRoot\..\..\deployment\windows\*-saml.msi" | 
           Sort-Object LastWriteTime -Descending | 
           Select-Object -First 1
    
    if (-not $msi) {
        Write-Host "ERROR: No MSI found to install" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "Installing: $($msi.Name)" -ForegroundColor Gray
    $proc = Start-Process msiexec -ArgumentList "/i", "`"$($msi.FullName)`"", "/qn", "/norestart" -Wait -PassThru
    
    if ($proc.ExitCode -ne 0) {
        Write-Host "ERROR: MSI installation failed (exit code: $($proc.ExitCode))" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "MSI installed successfully" -ForegroundColor Green
    Start-Sleep -Seconds 5  # Give service time to start
    
    $PostInstall = $true
}

# Run post-installation tests
if ($PostInstall) {
    Write-Host "`nRunning post-installation validation..." -ForegroundColor Yellow
    & $testScript -PostInstall
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "`nPost-installation validation failed" -ForegroundColor Red
        exit 1
    }
}

Write-Host "`n" + ("=" * 50) -ForegroundColor Green
Write-Host "ALL TESTS PASSED" -ForegroundColor Green
Write-Host ("=" * 50) -ForegroundColor Green

# Cleanup reminder for full test
if ($Full) {
    Write-Host @"

Note: MSI is still installed. To uninstall:
  msiexec /x "$($msi.FullName)" /qn
"@ -ForegroundColor Yellow
}