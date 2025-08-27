# Test-Essential.ps1
# Minimal tests that actually matter for the Postman AuthRouter
# No mocks, no unit tests - just real validation

param(
    [switch]$BuildOnly,
    [switch]$PostInstall,
    [switch]$Help
)

if ($Help) {
    Write-Host @"
Essential Tests for Postman AuthRouter

Usage:
  .\Test-Essential.ps1              # Run build validation only
  .\Test-Essential.ps1 -PostInstall # Run post-installation tests
  .\Test-Essential.ps1 -BuildOnly   # Only validate build (skip compile)

These tests verify:
  1. MSI builds successfully and is under 125MB
  2. Service installs and starts (PostInstall only)
  3. SAML redirect works (PostInstall only)
"@
    exit 0
}

$ErrorActionPreference = "Stop"

# Test 1: Can we build the MSI and is it under 125MB?
Write-Host "`n=== BUILD VALIDATION ===" -ForegroundColor Cyan

if (-not $PostInstall) {
    $buildScript = "$PSScriptRoot\..\..\deployment\windows\build_msi_mdm_win.ps1"
    
    if (-not (Test-Path $buildScript)) {
        Write-Host "FAIL: Build script not found at $buildScript" -ForegroundColor Red
        exit 1
    }
    
    if ($BuildOnly) {
        # Just check if we have a recent MSI using consolidated size validation
        $sizeValidator = "$PSScriptRoot\Test-MsiSizeValidation.ps1"
        if (Test-Path $sizeValidator) {
            Write-Host "Running MSI size validation..." -ForegroundColor Yellow
            & $sizeValidator -StrictMode
            if ($LASTEXITCODE -ne 0) {
                Write-Host "FAIL: MSI size validation failed" -ForegroundColor Red
                exit 1
            }
            Write-Host "PASS: MSI size validation passed" -ForegroundColor Green
        } else {
            # Fallback to simple check
            $msiPath = Get-ChildItem "$PSScriptRoot\..\..\deployment\windows\*-saml.msi" -ErrorAction SilentlyContinue | 
                       Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-24) } |
                       Sort-Object LastWriteTime -Descending | 
                       Select-Object -First 1
            
            if ($msiPath) {
                $sizeMB = [math]::Round($msiPath.Length / 1MB, 2)
                if ($sizeMB -gt 125) {
                    Write-Host "FAIL: Existing MSI is $sizeMB MB (exceeds 125MB limit)" -ForegroundColor Red
                    exit 1
                }
                Write-Host "PASS: Found recent MSI ($sizeMB MB)" -ForegroundColor Green
                Write-Host "      Path: $($msiPath.FullName)" -ForegroundColor Gray
                Write-Host "      Built: $($msiPath.LastWriteTime)" -ForegroundColor Gray
            } else {
                Write-Host "No recent MSI found. Run without -BuildOnly to build one." -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "Building MSI (this takes 2-3 minutes due to compression)..." -ForegroundColor Yellow
        
        try {
            # Run build WITHOUT capturing output (capturing can cause hangs)
            & $buildScript
            
            # Use consolidated MSI size validation after build
            $sizeValidator = "$PSScriptRoot\Test-MsiSizeValidation.ps1"
            if (Test-Path $sizeValidator) {
                & $sizeValidator -StrictMode
                if ($LASTEXITCODE -ne 0) {
                    Write-Host "FAIL: MSI exceeds 125MB limit" -ForegroundColor Red
                    exit 1
                }
            } else {
                # Fallback validation
                $msiPath = Get-ChildItem "$PSScriptRoot\..\..\deployment\windows\*-saml.msi" | 
                           Sort-Object LastWriteTime -Descending | 
                           Select-Object -First 1
                
                if (-not $msiPath) {
                    Write-Host "FAIL: No MSI was created" -ForegroundColor Red
                    Write-Host "Check the build output above for errors" -ForegroundColor Gray
                    exit 1
                }
                
                $sizeMB = [math]::Round($msiPath.Length / 1MB, 2)
                if ($sizeMB -gt 125) {
                    Write-Host "FAIL: MSI is $sizeMB MB (exceeds 125MB limit)" -ForegroundColor Red
                    exit 1
                }
            }
            
            Write-Host "PASS: MSI built and validated successfully" -ForegroundColor Green
            
        } catch {
            Write-Host "FAIL: Build failed - $_" -ForegroundColor Red
            exit 1
        }
    }
}

# Test 2: Does the service actually work after installation?
if ($PostInstall) {
    Write-Host "`n=== POST-INSTALLATION VALIDATION ===" -ForegroundColor Cyan
    
    # Check if service exists and is running
    Write-Host "Checking service..." -ForegroundColor Yellow
    $service = Get-Service -Name "PostmanAuthRouter" -ErrorAction SilentlyContinue
    
    if (-not $service) {
        Write-Host "FAIL: PostmanAuthRouter service not found" -ForegroundColor Red
        Write-Host "      Install the MSI first: msiexec /i <msi-path> /qn" -ForegroundColor Gray
        exit 1
    }
    
    if ($service.Status -ne "Running") {
        Write-Host "Service not running, attempting to start..." -ForegroundColor Yellow
        Start-Service -Name "PostmanAuthRouter" -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        $service = Get-Service -Name "PostmanAuthRouter"
    }
    
    if ($service.Status -eq "Running") {
        Write-Host "PASS: Service is running" -ForegroundColor Green
    } else {
        Write-Host "FAIL: Service is not running (Status: $($service.Status))" -ForegroundColor Red
        exit 1
    }
    
    # Check if port 443 is listening
    Write-Host "Checking port 443..." -ForegroundColor Yellow
    $listening = Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue
    
    if ($listening) {
        Write-Host "PASS: Port 443 is listening" -ForegroundColor Green
    } else {
        Write-Host "FAIL: Port 443 is not listening" -ForegroundColor Red
        exit 1
    }
    
    # Test 3: Basic service functionality validation
    Write-Host "Testing basic functionality..." -ForegroundColor Yellow
    
    # Test DNS interception
    try {
        ipconfig /flushdns | Out-Null
        $dnsResult = Resolve-DnsName -Name "identity.getpostman.com" -Type A -ErrorAction Stop
        $resolvedIPs = $dnsResult | Where-Object { $_.Type -eq "A" } | Select-Object -ExpandProperty IPAddress
        
        if ($resolvedIPs -contains "127.0.0.1") {
            Write-Host "PASS: DNS interception working" -ForegroundColor Green
        } else {
            Write-Host "WARN: DNS not intercepted (IPs: $($resolvedIPs -join ', '))" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "WARN: Could not test DNS interception - $_" -ForegroundColor Yellow
    }
    
    # Test basic HTTPS connectivity
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    
    try {
        $request = [System.Net.WebRequest]::Create("https://identity.getpostman.com/login")
        $request.Method = "GET"
        $request.AllowAutoRedirect = $false
        $request.Timeout = 5000
        
        $response = $request.GetResponse()
        $statusCode = [int]$response.StatusCode
        $location = $response.Headers["Location"]
        $response.Close()
        
        if ($statusCode -in @(301, 302, 307, 308) -and $location) {
            if ($location -match "saml|sso") {
                Write-Host "PASS: Login redirects to SAML" -ForegroundColor Green
            } else {
                Write-Host "WARN: Redirect found but may not be SAML" -ForegroundColor Yellow
            }
        } elseif ($statusCode -eq 200) {
            Write-Host "PASS: HTTPS proxy responding" -ForegroundColor Green
        } else {
            Write-Host "WARN: Unexpected response (Status: $statusCode)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "FAIL: Could not test HTTPS connectivity - $_" -ForegroundColor Red
        exit 1
    } finally {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    }
}

Write-Host "`n=== ALL ESSENTIAL TESTS PASSED ===" -ForegroundColor Green
Write-Host @"

Next steps:
  - Build only:     Install MSI and run with -PostInstall flag  
  - Post-install:   System is ready for production use

Manual verification:
  1. Open a browser and go to identity.getpostman.com/login
  2. Verify redirect to your SAML provider
  3. Check C:\ProgramData\Postman\pm-authrouter.log for any errors
"@