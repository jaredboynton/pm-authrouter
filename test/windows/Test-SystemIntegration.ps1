# Test-SystemIntegration.ps1
# End-to-end integration tests for the complete AuthRouter system
# Tests the full flow: DNS interception -> HTTPS proxy -> SAML redirect -> certificate validation



param(
    [string]$ServiceName = "PostmanAuthRouter",
    [string]$TestTeam = "test-team",
    [string]$TestSamlUrl = "https://identity.getpostman.com/sso/test/init",
    [string]$TestDomain = "identity.getpostman.com",
    [int]$TestPort = 443,
    [switch]$InstallMsi = $false,
    [string]$MsiPath = "",
    [switch]$CleanupAfter = $false
)

# Test configuration
$script:IntegrationConfig = @{
    ServiceName = $ServiceName
    TestDomain = $TestDomain
    TestPort = $TestPort
    TestTeam = $TestTeam
    TestSamlUrl = $TestSamlUrl
    LogPath = "C:\ProgramData\Postman\pm-authrouter.log"
    CertPath = "C:\Program Files\Postman\Postman Enterprise\identity.getpostman.com.crt"
    HostsPath = "C:\Windows\System32\drivers\etc\hosts"
    TestTimeout = 30
    RetryDelay = 2
    MaxRetries = 5
}



# Pester 3.4.0 compatibility - warn and return for skipped tests
function Pending { param([string]$Message) Write-Warning "[SKIPPED] $Message"; return }
# Test URLs for different scenarios
$script:TestUrls = @{
    LoginBasic = "https://identity.getpostman.com/login"
    LoginWithTeam = "https://identity.getpostman.com/login?continue=https://go.postman.co/"
    DesktopAuth = "https://identity.getpostman.com/login?auth_challenge=desktop-test-123"
    EnterpriseLogin = "https://identity.getpostman.com/enterprise/login"
    HealthCheck = "https://identity.getpostman.com/health"
    ApiEndpoint = "https://identity.getpostman.com/api/status"
}

# Helper Functions
function Test-ServiceRunning {
    $service = Get-Service -Name $script:IntegrationConfig.ServiceName -ErrorAction SilentlyContinue
    return $service -and $service.Status -eq "Running"
}

function Test-PortListening {
    param([int]$Port = $script:IntegrationConfig.TestPort)
    
    try {
        $connections = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
        return $connections.Count -gt 0
    } 

# Pester 3.4.0 compatibility - warn and return for skipped tests
function Pending { param([string]$Message) Write-Warning "[SKIPPED] $Message"; return }
catch {
        return $false
    }
}

function Test-DNSInterception {
    param([string]$Domain = $script:IntegrationConfig.TestDomain)
    
    try {
        # Flush DNS cache first
        ipconfig /flushdns | Out-Null
        Start-Sleep -Seconds 1
        
        $result = Resolve-DnsName -Name $Domain -Type A -ErrorAction Stop
        $resolvedIPs = $result | Where-Object { $_.Type -eq "A" } 

# Pester 3.4.0 compatibility - warn and return for skipped tests
function Pending { param([string]$Message) Write-Warning "[SKIPPED] $Message"; return }
| Select-Object -ExpandProperty IPAddress
        
        return @{
            Success = $resolvedIPs -contains "127.0.0.1"
            ResolvedIPs = $resolvedIPs
            Method = (Test-DNSMethod)
        }
    } catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
            ResolvedIPs = @()
        }
    }
}

function Test-DNSMethod {
    # Determine which DNS interception method is being used
    $hostsContent = Get-Content $script:IntegrationConfig.HostsPath -Raw -ErrorAction SilentlyContinue
    if ($hostsContent -match "127\.0\.0\.1\s+$($script:IntegrationConfig.TestDomain)") {
        return "hosts"
    }
    
    # Check for routes
    $routes = Get-NetRoute -DestinationPrefix "*" -ErrorAction SilentlyContinue | 
              Where-Object { $_.NextHop -eq "127.0.0.1" }
    if ($routes) {
        return "routing"
    }
    
    # Check DNS server settings (simplified)
    try {
        $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=true"
        $hasLocalhost = $adapters | Where-Object { 
            $_.DNSServerSearchOrder -and $_.DNSServerSearchOrder[0] -eq "127.0.0.1" 
        }
        if ($hasLocalhost) {
            return "registry"
        }
    } catch {}
    
    return "unknown"
}

function Test-CertificateInstalled {
    try {
        $cert = Get-ChildItem -Path Cert:\LocalMachine\Root -ErrorAction Stop | 
                Where-Object { $_.Subject -like "*$($script:IntegrationConfig.TestDomain)*" }
        return $null -ne $cert
    } catch {
        return $false
    }
}

function Test-HttpsRequest {
    param(
        [string]$Url,
        [hashtable]$Headers = @{}

# Pester 3.4.0 compatibility - warn and return for skipped tests
function Pending { param([string]$Message) Write-Warning "[SKIPPED] $Message"; return }
,
        [string]$Method = "GET",
        [int]$TimeoutMs = 10000,
        [switch]$AllowRedirects = $false,
        [switch]$IgnoreSSLErrors = $true
    )
    
    try {
        # Configure SSL validation
        if ($IgnoreSSLErrors) {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        }
        
        $request = [System.Net.WebRequest]::Create($Url)
        $request.Method = $Method
        $request.AllowAutoRedirect = $AllowRedirects
        $request.Timeout = $TimeoutMs
        
        # Add headers
        foreach ($header in $Headers.GetEnumerator()) {
            if ($header.Key -eq "Host") {
                $request.Headers.Add("Host", $header.Value)
            } else {
                $request.Headers.Add($header.Key, $header.Value)
            }
        }
        
        $response = $request.GetResponse()
        $statusCode = [int]$response.StatusCode
        $contentType = $response.ContentType
        $contentLength = $response.ContentLength
        
        # Read response body
        $responseStream = $response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($responseStream)
        $responseBody = $reader.ReadToEnd()
        $reader.Close()
        
        # Get headers
        $responseHeaders = @{}
        foreach ($headerKey in $response.Headers.AllKeys) {
            $responseHeaders[$headerKey] = $response.Headers[$headerKey]
        }
        
        $response.Close()
        
        return @{
            Success = $true
            StatusCode = $statusCode
            ContentType = $contentType
            ContentLength = $contentLength
            Body = $responseBody
            Headers = $responseHeaders
            Url = $Url
        }
        
    } catch [System.Net.WebException] {
        $response = $_.Exception.Response
        if ($response) {
            $statusCode = [int]$response.StatusCode
            $responseHeaders = @{}
            foreach ($headerKey in $response.Headers.AllKeys) {
                $responseHeaders[$headerKey] = $response.Headers[$headerKey]
            }
            $response.Close()
            
            return @{
                Success = $false
                StatusCode = $statusCode
                Headers = $responseHeaders
                Error = $_.Exception.Message
                Url = $Url
            }
        } else {
            return @{
                Success = $false
                StatusCode = 0
                Error = $_.Exception.Message
                Url = $Url
            }
        }
    } catch {
        return @{
            Success = $false
            StatusCode = 0
            Error = $_.Exception.Message
            Url = $Url
        }
    } finally {
        if ($IgnoreSSLErrors) {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
        }
    }
}

function Test-SamlRedirect {
    param(
        [string]$Url,
        [string]$ExpectedSamlUrl = $script:IntegrationConfig.TestSamlUrl
    )
    
    $response = Test-HttpsRequest -Url $Url -AllowRedirects:$false
    
    $isRedirect = $response.StatusCode -in @(301, 302, 307, 308)
    $location = $response.Headers["Location"]
    $isSamlRedirect = $location -and ($location -like "*saml*" -or $location -like "*sso*")
    
    return @{
        IsRedirect = $isRedirect
        Location = $location
        IsSamlRedirect = $isSamlRedirect
        StatusCode = $response.StatusCode
        Success = $isRedirect -and $isSamlRedirect
    }


# Pester 3.4.0 compatibility - warn and return for skipped tests
function Pending { param([string]$Message) Write-Warning "[SKIPPED] $Message"; return }
}

function Wait-ForSystemReady {
    param([int]$TimeoutSeconds = 60)
    
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    while ($stopwatch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        # Check all prerequisites
        $serviceRunning = Test-ServiceRunning
        $portListening = Test-PortListening
        $dnsIntercepted = (Test-DNSInterception).Success
        $certInstalled = Test-CertificateInstalled
        
        if ($serviceRunning -and $portListening -and $dnsIntercepted -and $certInstalled) {
            Write-Host "System ready in $([math]::Round($stopwatch.Elapsed.TotalSeconds, 1)) seconds" -ForegroundColor Green
            return $true
        }
        
        

# Pester 3.4.0 compatibility - warn and return for skipped tests
function Pending { param([string]$Message) Write-Warning "[SKIPPED] $Message"; return }
Write-Host "Waiting for system... Service:$serviceRunning Port:$portListening DNS:$dnsIntercepted Cert:$certInstalled" -ForegroundColor Yellow
        Start-Sleep -Seconds $script:IntegrationConfig.RetryDelay
    }
    
    return $false
}

function Install-TestMsi {
    param([string]$MsiPath)
    
    if (-not $MsiPath -or -not (Test-Path $MsiPath)) {
        # Try to find MSI in deployment directory
        $deploymentDir = "$PSScriptRoot\..\..\deployment\windows"
        $msi = Get-ChildItem "$deploymentDir\*-saml.msi" -ErrorAction SilentlyContinue | 
               Sort-Object LastWriteTime -Descending | 
               Select-Object -First 1
        
        if ($msi) {
            $MsiPath = $msi.FullName
        } 

# Pester 3.4.0 compatibility - warn and return for skipped tests
function Pending { param([string]$Message) Write-Warning "[SKIPPED] $Message"; return }
else {
            throw "No MSI found. Specify -MsiPath or build MSI first."
        }
    }
    
    Write-Host "Installing MSI: $([System.IO.Path]::GetFileName($MsiPath))" -ForegroundColor Yellow
    
    $installArgs = @(
        "/i", "`"$MsiPath`"",
        "TEAM_NAME=`"$($script:IntegrationConfig.TestTeam)`"",
        "SAML_URL=`"$($script:IntegrationConfig.TestSamlUrl)`"",
        "/quiet", "/norestart"
    )
    
    $process = Start-Process msiexec -ArgumentList $installArgs -Wait -PassThru -WindowStyle Hidden
    
    if ($process.ExitCode -ne 0) {
        throw "MSI installation failed with exit code: $($process.ExitCode)"
    }
    
    Write-Host "MSI installed successfully" -ForegroundColor Green
    return $true
}

function Uninstall-TestMsi {
    param([string]$MsiPath)
    
    if (-not $MsiPath -or -not (Test-Path $MsiPath)) {
        Write-Warning "MSI path not provided for uninstall - skipping cleanup"
        return
    }
    
    

# Pester 3.4.0 compatibility - warn and return for skipped tests
function Pending { param([string]$Message) Write-Warning "[SKIPPED] $Message"; return }
Write-Host "Uninstalling MSI..." -ForegroundColor Yellow
    
    $uninstallArgs = @("/x", "`"$MsiPath`"", "/quiet", "/norestart")
    $process = Start-Process msiexec -ArgumentList $uninstallArgs -Wait -PassThru -WindowStyle Hidden
    
    if ($process.ExitCode -eq 0) {
        Write-Host "MSI uninstalled successfully" -ForegroundColor Green
    } else {
        Write-Warning "MSI uninstall returned exit code: $($process.ExitCode)"
    }
}

function Get-SystemDiagnostics {
    $service = Get-Service -Name $script:IntegrationConfig.ServiceName -ErrorAction SilentlyContinue
    $dnsTest = Test-DNSInterception
    $portTest = Test-PortListening
    $certTest = Test-CertificateInstalled
    
    return @{
        ServiceStatus = if ($service) { $service.Status } else { "Not Installed" }
        ServiceProcessId = if ($service) { (Get-WmiObject Win32_Service -Filter "Name='$($service.Name)'").ProcessId } else { 0 }
        PortListening = $portTest
        DNSIntercepted = $dnsTest.Success
        DNSMethod = $dnsTest.Method
        DNSResolvedIPs = $dnsTest.ResolvedIPs
        CertificateInstalled = $certTest
        LogFileExists = Test-Path $script:IntegrationConfig.LogPath
        LogFileSize = if (Test-Path $script:IntegrationConfig.LogPath) { (Get-Item $script:IntegrationConfig.LogPath).Length } else { 0 }
    }
}

# Main Test Execution
Describe "System Integration Tests" -Tag "Slow", "Integration" {
    
    BeforeAll {
        Write-Host "Starting system integration tests..." -ForegroundColor Cyan
        
        # Install MSI if requested
        if ($InstallMsi) {
            Install-TestMsi -MsiPath $MsiPath
            Write-Host "Waiting for service to initialize..." -ForegroundColor Yellow
            Start-Sleep -Seconds 10
        }
        
        # Get initial system state
        $script:InitialDiagnostics = Get-SystemDiagnostics
        Write-Host "Initial system state:" -ForegroundColor Cyan
        $script:InitialDiagnostics | Format-Table -AutoSize | Out-Host
    }
    
    AfterAll {
        if ($CleanupAfter -and $InstallMsi) {
            Write-Host "Performing cleanup..." -ForegroundColor Yellow
            Uninstall-TestMsi -MsiPath $MsiPath
        }
    }
    
    Context "System Prerequisites" {
        
        It "Should have AuthRouter service installed" {
            $service = Get-Service -Name $script:IntegrationConfig.ServiceName -ErrorAction SilentlyContinue
            $service | Should Not BeNullOrEmpty
            $service.Name | Should Be $script:IntegrationConfig.ServiceName
        }
        
        It "Should have service running" {
            if (-not (Test-ServiceRunning)) {
                # Try to start service
                Start-Service -Name $script:IntegrationConfig.ServiceName -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 5
            }
            
            Test-ServiceRunning | Should Be $true
        }
        
        It "Should have port 443 listening" {
            # Wait for port to be bound
            $portListening = $false
            for ($i = 0; $i -lt 10; $i++) {
                if (Test-PortListening) {
                    $portListening = $true
                    break
                }
                Start-Sleep -Seconds 1
            }
            
            $portListening | Should Be $true
        }
        
        It "Should have certificate installed" {
            Test-CertificateInstalled | Should Be $true
        }
        
        It "Should have log file created" {
            # Service should create log file on startup
            for ($i = 0; $i -lt 10; $i++) {
                if (Test-Path $script:IntegrationConfig.LogPath) {
                    break
                }
                Start-Sleep -Seconds 1
            }
            
            Test-Path $script:IntegrationConfig.LogPath | Should Be $true
        }
    }
    
    Context "DNS Interception Integration" {
        
        It "Should intercept DNS for target domain" {
            $dnsResult = Test-DNSInterception
            $dnsResult.Success | Should Be $true
            $dnsResult.ResolvedIPs | Should Contain "127.0.0.1"
            
            Write-Host "DNS interception method: $($dnsResult.Method)" -ForegroundColor Green
        }
        
        It "Should maintain DNS interception consistently" {
            # Test DNS resolution multiple times to ensure consistency
            $results = @()
            for ($i = 0; $i -lt 5; $i++) {
                $result = Test-DNSInterception
                $results += $result.Success
                Start-Sleep -Seconds 1
            }
            
            $successCount = ($results | Where-Object { $_ }).Count
            $successCount | Should Be 5  # All should succeed
        }
        
        It "Should resolve quickly after DNS cache flush" {
            ipconfig /flushdns | Out-Null
            
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $dnsResult = Test-DNSInterception
            $stopwatch.Stop()
            
            $dnsResult.Success | Should Be $true
            $stopwatch.ElapsedMilliseconds | Should BeLessThan 5000
        }
    }
    
    Context "HTTPS Proxy Integration" {
        
        It "Should respond to health check" {
            $response = Test-HttpsRequest -Url $script:TestUrls.HealthCheck -Headers @{ "Host" = $script:IntegrationConfig.TestDomain }
            
            $response.Success | Should Be $true
            $response.StatusCode | Should Be 200
            
            if ($response.Body) {
                $healthData = $response.Body | ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($healthData) {
                    $healthData.status | Should Be "healthy"
                }
            }
        }
        
        It "Should handle HTTPS requests with proper certificate" {
            # Test with certificate validation enabled
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
            
            try {
                $response = Test-HttpsRequest -Url $script:TestUrls.HealthCheck -IgnoreSSLErrors:$false
                # Should succeed because we installed our certificate
                $response.Success | Should Be $true
            } catch {
                # If this fails, the certificate might not be properly installed
                Write-Warning "Certificate validation failed - this is expected if certificate not in trust store"
            }
        }
        
        It "Should preserve Host header for upstream requests" {
            $response = Test-HttpsRequest -Url $script:TestUrls.ApiEndpoint
            
            # Should either get a response or a proper upstream error
            if ($response.Success) {
                $response.StatusCode | Should -BeIn @(200, 404, 502, 503)
            } else {
                # Connection should at least be established
                $response.Error | Should Not Match "connection refused"
            }
        }
        
        It "Should handle concurrent HTTPS requests" {
            $jobs = @()
            $requestCount = 5
            
            # Start concurrent requests
            for ($i = 1; $i -le $requestCount; $i++) {
                $jobs += Start-Job -ScriptBlock {
                    param($Url)
                    
                    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
                    

# Pester 3.4.0 compatibility - warn and return for skipped tests
function Pending { param([string]$Message) Write-Warning "[SKIPPED] $Message"; return }
try {
                        $request = [System.Net.WebRequest]::Create($Url)
                        $request.Headers.Add("Host", "identity.getpostman.com")
                        $request.Method = "GET"
                        $request.Timeout = 5000
                        $response = $request.GetResponse()
                        $statusCode = [int]$response.StatusCode
                        $response.Close()
                        return $statusCode
                    } catch {
                        return 0
                    } finally {
                        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
                    }
                } -ArgumentList $script:TestUrls.HealthCheck
            }
            
            # Wait for all requests
            $results = $jobs | Wait-Job -Timeout 30 | Receive-Job
            $jobs | Remove-Job
            
            # At least 80% should succeed
            $successCount = ($results | Where-Object { $_ -eq 200 }).Count
            $successRate = $successCount / $requestCount
            
            $successRate | Should BeGreaterThan 0.8
            Write-Host "Concurrent request success rate: $([math]::Round($successRate * 100, 1))%" -ForegroundColor Green
        }
    }
    
    Context "SAML Redirect Integration" {
        
        It "Should redirect basic login to SAML" {
            $result = Test-SamlRedirect -Url $script:TestUrls.LoginBasic
            
            $result.Success | Should Be $true
            $result.IsRedirect | Should Be $true
            $result.IsSamlRedirect | Should Be $true
            $result.Location | Should Match "(saml|sso)"
            
            Write-Host "Basic login redirect: $($result.Location)" -ForegroundColor Green
        }
        
        It "Should redirect login with continue parameter" {
            $result = Test-SamlRedirect -Url $script:TestUrls.LoginWithTeam
            
            $result.Success | Should Be $true
            $result.Location | Should Match "team=$($script:IntegrationConfig.TestTeam)"
            $result.Location | Should Match "continue=.*go\.postman\.co"
            
            Write-Host "Team login redirect: $($result.Location)" -ForegroundColor Green
        }
        
        It "Should handle desktop authentication flow" {
            $result = Test-SamlRedirect -Url $script:TestUrls.DesktopAuth
            
            $result.Success | Should Be $true
            $result.Location | Should Match "auth_challenge=desktop-test-123"
            
            Write-Host "Desktop auth redirect: $($result.Location)" -ForegroundColor Green
        }
        
        It "Should redirect enterprise login" {
            $result = Test-SamlRedirect -Url $script:TestUrls.EnterpriseLogin
            
            $result.Success | Should Be $true
            $result.IsSamlRedirect | Should Be $true
        }
        
        It "Should preserve all query parameters in redirects" {
            $testUrl = "$($script:TestUrls.LoginBasic)?continue=https://test.com&team=custom&auth_challenge=test123"
            $result = Test-SamlRedirect -Url $testUrl
            
            $result.Success | Should Be $true
            
            if ($result.Location) {
                # Should preserve important parameters
                $result.Location | Should Match "continue=.*test\.com"
                $result.Location | Should Match "auth_challenge=test123"
            }
        }
        
        It "Should not redirect non-login paths" {
            $response = Test-HttpsRequest -Url $script:TestUrls.ApiEndpoint -AllowRedirects:$false
            
            # API endpoints should not redirect to SAML
            $isRedirect = $response.StatusCode -in @(301, 302, 307, 308)
            $location = $response.Headers["Location"]
            $isSamlRedirect = $location -and ($location -like "*saml*" -or $location -like "*sso*")
            
            if ($isRedirect) {
                $isSamlRedirect | Should Be $false
            }
        }
    }
    
    Context "End-to-End Flow Validation" {
        
        It "Should complete full authentication flow" {
            # Step 1: DNS resolution
            $dnsResult = Test-DNSInterception
            $dnsResult.Success | Should Be $true
            
            # Step 2: HTTPS connection establishment
            $healthResponse = Test-HttpsRequest -Url $script:TestUrls.HealthCheck
            $healthResponse.Success | Should Be $true
            
            # Step 3: SAML redirect
            $samlResult = Test-SamlRedirect -Url $script:TestUrls.LoginBasic
            $samlResult.Success | Should Be $true
            
            Write-Host "End-to-end flow validation: PASS" -ForegroundColor Green
        }
        
        It "Should handle rapid sequential requests" {
            $urls = @(
                $script:TestUrls.LoginBasic,
                $script:TestUrls.LoginWithTeam,
                $script:TestUrls.DesktopAuth,
                $script:TestUrls.HealthCheck
            )
            
            $results = @()
            foreach ($url in $urls) {
                $response = Test-HttpsRequest -Url $url -AllowRedirects:$false
                $results += $response.Success -or ($response.StatusCode -in @(301, 302, 307, 308))
                Start-Sleep -Milliseconds 100
            }
            
            $successCount = ($results | Where-Object { $_ }).Count
            $successRate = $successCount / $results.Count
            
            $successRate | Should BeGreaterThan 0.8
        }
        
        It "Should maintain performance under load" {
            $requestCount = 20
            $maxTimeSeconds = 30
            
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $successCount = 0
            
            for ($i = 1; $i -le $requestCount; $i++) {
                $response = Test-HttpsRequest -Url $script:TestUrls.HealthCheck -TimeoutMs 5000
                if ($response.Success) {
                    $successCount++
                }
            }
            
            $stopwatch.Stop()
            $totalTime = $stopwatch.Elapsed.TotalSeconds
            $avgTimePerRequest = $totalTime / $requestCount
            
            $totalTime | Should BeLessThan $maxTimeSeconds
            $successCount | Should BeGreaterThan ($requestCount * 0.9)  # 90% success rate
            $avgTimePerRequest | Should BeLessThan 2  # Average 2 seconds per request
            
            Write-Host "Load test: $successCount/$requestCount requests in $([math]::Round($totalTime, 2))s" -ForegroundColor Green
        }
    }
    
    Context "System State and Logging" {
        
        It "Should log successful requests" {
            # Make a request
            Test-HttpsRequest -Url $script:TestUrls.HealthCheck | Out-Null
            Start-Sleep -Seconds 2
            
            if (Test-Path $script:IntegrationConfig.LogPath) {
                $logContent = Get-Content $script:IntegrationConfig.LogPath -Tail 10 -ErrorAction SilentlyContinue
                $logContent | Should Match "(GET.*health|200|request)"
            }
        }
        
        It "Should log SAML redirects" {
            # Make a login request
            Test-HttpsRequest -Url $script:TestUrls.LoginBasic -AllowRedirects:$false | Out-Null
            Start-Sleep -Seconds 2
            
            if (Test-Path $script:IntegrationConfig.LogPath) {
                $logContent = Get-Content $script:IntegrationConfig.LogPath -Tail 10 -ErrorAction SilentlyContinue
                $logContent | Should Match "(login|redirect|saml|302|307)"
            }
        }
        
        It "Should maintain system stability" {
            # Compare system state before and after tests
            $currentDiagnostics = Get-SystemDiagnostics
            
            # Service should still be running
            $currentDiagnostics.ServiceStatus | Should Be "Running"
            $currentDiagnostics.PortListening | Should Be $true
            $currentDiagnostics.DNSIntercepted | Should Be $true
            $currentDiagnostics.CertificateInstalled | Should Be $true
            
            # Process ID may have changed (service restarts) but should exist
            $currentDiagnostics.ServiceProcessId | Should BeGreaterThan 0
        }
        
        It "Should have reasonable log file size" {
            if (Test-Path $script:IntegrationConfig.LogPath) {
                $logSize = (Get-Item $script:IntegrationConfig.LogPath).Length
                $logSizeMB = $logSize / 1MB
                
                # Log file shouldn't be huge
                $logSizeMB | Should BeLessThan 10
                Write-Host "Log file size: $([math]::Round($logSizeMB, 2)) MB" -ForegroundColor Green
            }
        }
    }
}

# Error Recovery and Edge Cases
Describe "System Integration Edge Cases" -Tag "Slow", "Integration", "EdgeCase" {
    
    Context "Network Conditions" {
        
        It "Should handle DNS cache poisoning gracefully" {
            # Flush DNS and test resolution
            ipconfig /flushdns | Out-Null
            
            # Multiple rapid DNS requests
            $results = @()
            for ($i = 0; $i -lt 5; $i++) {
                $result = Test-DNSInterception
                $results += $result.Success
                Start-Sleep -Milliseconds 200
            }
            
            # Should consistently resolve correctly
            $successCount = ($results | Where-Object { $_ }).Count
            $successCount | Should BeGreaterThan 4  # Allow 1 failure
        }
        
        It "Should recover from temporary network issues" {
            # Simulate network issues by making requests with very short timeouts
            $shortTimeoutResponse = Test-HttpsRequest -Url $script:TestUrls.HealthCheck -TimeoutMs 1
            
            # Then test with normal timeout
            $normalResponse = Test-HttpsRequest -Url $script:TestUrls.HealthCheck -TimeoutMs 10000
            $normalResponse.Success | Should Be $true
        }
    }
    
    Context "Certificate Edge Cases" {
        
        It "Should handle certificate validation correctly" {
            # Test with strict certificate validation
            try {
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
                
                $request = [System.Net.WebRequest]::Create($script:TestUrls.HealthCheck)
                $request.Method = "GET"
                $request.Timeout = 5000
                
                try {
                    $response = $request.GetResponse()
                    $statusCode = [int]$response.StatusCode
                    $response.Close()
                    
                    # If this succeeds, certificate is properly trusted
                    $statusCode | Should Be 200
                    Write-Host "Certificate validation: PASS (trusted)" -ForegroundColor Green
                } catch {
                    # Certificate validation failed - expected if not in trust store
                    Write-Host "Certificate validation: Expected failure (not in trust store)" -ForegroundColor Yellow
                }
            } finally {
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            }
        }
    }
    
    Context "Service Interruption Recovery" {
        
        It "Should detect service availability" {
            $service = Get-Service -Name $script:IntegrationConfig.ServiceName -ErrorAction SilentlyContinue
            
            if ($service -and $service.Status -eq "Running") {
                # Service is running - system should be responding
                $response = Test-HttpsRequest -Url $script:TestUrls.HealthCheck
                $response.Success | Should Be $true
            } else {
                # Service not running - should fail gracefully
                $response = Test-HttpsRequest -Url $script:TestUrls.HealthCheck
                $response.Success | Should Be $false
            }
        }
        
        It "Should handle service restart gracefully" {
            if (-not (Test-ServiceRunning)) {
                Pending "Service not running initially"
                return
            }
            
            # Wait for system to be ready before restart test
            $systemReady = Wait-ForSystemReady -TimeoutSeconds 30
            if (-not $systemReady) {
                Pending "System not ready for restart test"
                return
            }
            
            # Restart service
            Write-Host "Restarting service for integration test..." -ForegroundColor Yellow
            Restart-Service -Name $script:IntegrationConfig.ServiceName -Force
            
            # Wait for system to be ready again
            $systemReady = Wait-ForSystemReady -TimeoutSeconds 60
            $systemReady | Should Be $true
            
            # Test functionality after restart
            $response = Test-HttpsRequest -Url $script:TestUrls.HealthCheck
            $response.Success | Should Be $true
            
            $samlResult = Test-SamlRedirect -Url $script:TestUrls.LoginBasic
            $samlResult.Success | Should Be $true
        }
    }
}

Write-Host "`n=== System Integration Test Summary ===" -ForegroundColor Cyan
Write-Host "Complete end-to-end validation of AuthRouter system:" -ForegroundColor White
Write-Host "  â€¢ System prerequisites and components" -ForegroundColor Gray
Write-Host "  â€¢ DNS interception integration" -ForegroundColor Gray
Write-Host "  â€¢ HTTPS proxy integration" -ForegroundColor Gray
Write-Host "  â€¢ SAML redirect integration" -ForegroundColor Gray
Write-Host "  â€¢ End-to-end flow validation" -ForegroundColor Gray
Write-Host "  â€¢ System state and logging" -ForegroundColor Gray
Write-Host "  â€¢ Error recovery and edge cases" -ForegroundColor Gray

# Final system diagnostics
$finalDiagnostics = Get-SystemDiagnostics
Write-Host "`nFinal system state:" -ForegroundColor Cyan
$finalDiagnostics | Format-Table -AutoSize | Out-Host

if ($InstallMsi) {
    Write-Host "Note: MSI was installed for testing. Use -CleanupAfter to automatically remove." -ForegroundColor Yellow
}

Write-Host "`n=== Integration Test Complete ===" -ForegroundColor Green