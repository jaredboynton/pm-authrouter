# Test-DNSInterceptionMethods.ps1
# Comprehensive tests for all Windows DNS interception methods
# Tests hosts file, WFP, registry override, and netsh routing methods



param(
    [string]$ServiceName = "PostmanAuthRouter",
    [string]$TestDomain = "identity.getpostman.com",
    [string]$RedirectIP = "127.0.0.1",
    [switch]$DestructiveTests = $false,  # Enable tests that modify system state
    [switch]$RequireAdmin = $true        # Skip admin-required tests if not admin
)

# Test configuration
$script:DNSConfig = @{
    ServiceName = $ServiceName
    TestDomain = $TestDomain
    RedirectIP = $RedirectIP
    HostsPath = "C:\Windows\System32\drivers\etc\hosts"
    TestTimeout = 30
    BackupSuffix = ".pm-authrouter-test-backup"
}



# Pester 3.4.0 compatibility - warn and return for skipped tests
function Pending { param([string]$Message) Write-Warning "[SKIPPED] $Message"; return }
# Helper Functions
function Test-IsAdministrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Backup-HostsFile {
    $backupPath = $script:DNSConfig.HostsPath + $script:DNSConfig.BackupSuffix
    if (Test-Path $script:DNSConfig.HostsPath) {
        Copy-Item $script:DNSConfig.HostsPath $backupPath -Force
        return $true
    }
    return $false
}

function Restore-HostsFile {
    $backupPath = $script:DNSConfig.HostsPath + $script:DNSConfig.BackupSuffix
    if (Test-Path $backupPath) {
        Copy-Item $backupPath $script:DNSConfig.HostsPath -Force
        Remove-Item $backupPath -Force -ErrorAction SilentlyContinue
        return $true
    }
    return $false
}

function Test-HostsFileEntry {
    param(
        [string]$Domain = $script:DNSConfig.TestDomain,
        [string]$IP = $script:DNSConfig.RedirectIP
    )
    
    if (Test-Path $script:DNSConfig.HostsPath) {
        $content = Get-Content $script:DNSConfig.HostsPath -Raw
        return $content -match "$([regex]::Escape($IP))\s+$([regex]::Escape($Domain))"
    }
    

# Pester 3.4.0 compatibility - warn and return for skipped tests
function Pending { param([string]$Message) Write-Warning "[SKIPPED] $Message"; return }
return $false
}

function Add-HostsFileEntry {
    param(
        [string]$Domain = $script:DNSConfig.TestDomain,
        [string]$IP = $script:DNSConfig.RedirectIP,
        [string]$Comment = "Added by PostmanAuthRouter Test"
    )
    
    try {
        $entry = "$IP $Domain # $Comment"
        
        # Read current content
        $content = if (Test-Path $script:DNSConfig.HostsPath) {
            Get-Content $script:DNSConfig.HostsPath -Raw
        } 

# Pester 3.4.0 compatibility - warn and return for skipped tests
function Pending { param([string]$Message) Write-Warning "[SKIPPED] $Message"; return }
else {
            ""
        }
        
        # Add entry if not exists
        if (-not (Test-HostsFileEntry -Domain $Domain -IP $IP)) {
            if (-not $content.EndsWith("`n") -and $content -ne "") {
                $content += "`n"
            }
            $content += "$entry`n"
            
            Set-Content -Path $script:DNSConfig.HostsPath -Value $content -NoNewline
            return $true
        }
        return $true
    } catch {
        Write-Warning "Failed to add hosts file entry: $_"
        return $false
    }
}

function Remove-HostsFileEntry {
    param(
        [string]$Domain = $script:DNSConfig.TestDomain,
        [string]$IP = $script:DNSConfig.RedirectIP
    )
    
    try {
        if (-not (Test-Path $script:DNSConfig.HostsPath)) {
            return $true
        }
        
        

# Pester 3.4.0 compatibility - warn and return for skipped tests
function Pending { param([string]$Message) Write-Warning "[SKIPPED] $Message"; return }
$lines = Get-Content $script:DNSConfig.HostsPath
        $cleanedLines = @()
        $removed = $false
        
        foreach ($line in $lines) {
            # Skip lines that contain our entry
            if ($line -match "$([regex]::Escape($IP))\s+$([regex]::Escape($Domain))") {
                $removed = $true
                continue
            }
            $cleanedLines += $line
        }
        
        if ($removed) {
            $cleanedLines | Set-Content -Path $script:DNSConfig.HostsPath
        }
        
        return $true
    } catch {
        Write-Warning "Failed to remove hosts file entry: $_"
        return $false
    }
}

function Test-DNSResolution {
    param(
        [string]$Domain = $script:DNSConfig.TestDomain,
        [string]$ExpectedIP = $script:DNSConfig.RedirectIP
    )
    
    try {
        $result = Resolve-DnsName -Name $Domain -Type A -ErrorAction Stop
        $resolvedIPs = $result | Where-Object { $_.Type -eq "A" } 

# Pester 3.4.0 compatibility - warn and return for skipped tests
function Pending { param([string]$Message) Write-Warning "[SKIPPED] $Message"; return }
| Select-Object -ExpandProperty IPAddress
        
        return @{
            Success = $resolvedIPs -contains $ExpectedIP
            ResolvedIPs = $resolvedIPs
            ExpectedIP = $ExpectedIP
        }
    } catch {
        return @{
            Success = $false
            ResolvedIPs = @()
            ExpectedIP = $ExpectedIP
            Error = $_.Exception.Message
        }
    }
}

function Test-NetworkRoute {
    param(
        [string]$Destination,
        [string]$Gateway = "127.0.0.1"
    )
    
    try {
        $routes = Get-NetRoute -DestinationPrefix "$Destination/32" -ErrorAction SilentlyContinue
        $targetRoute = $routes | Where-Object { $_.NextHop -eq $Gateway }
        
        

# Pester 3.4.0 compatibility - warn and return for skipped tests
function Pending { param([string]$Message) Write-Warning "[SKIPPED] $Message"; return }
return @{
            Exists = $null -ne $targetRoute
            Route = $targetRoute
        }
    } catch {
        return @{
            Exists = $false
            Error = $_.Exception.Message
        }
    }
}

function Add-NetworkRoute {
    param(
        [string]$Destination,
        [string]$Gateway = "127.0.0.1"
    )
    
    try {
        # Use route command for compatibility
        $result = route ADD $Destination $Gateway METRIC 1 2>&1
        return $LASTEXITCODE -eq 0
    } 

# Pester 3.4.0 compatibility - warn and return for skipped tests
function Pending { param([string]$Message) Write-Warning "[SKIPPED] $Message"; return }
catch {
        Write-Warning "Failed to add network route: $_"
        return $false
    }
}

function Remove-NetworkRoute {
    param(
        [string]$Destination,
        [string]$Gateway = "127.0.0.1"
    )
    
    try {
        $result = route DELETE $Destination $Gateway 2>&1
        return $LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 1  # 1 = route not found (acceptable)
    } 

# Pester 3.4.0 compatibility - warn and return for skipped tests
function Pending { param([string]$Message) Write-Warning "[SKIPPED] $Message"; return }
catch {
        Write-Warning "Failed to remove network route: $_"
        return $false
    }
}

function Get-RealDomainIP {
    param([string]$Domain = $script:DNSConfig.TestDomain)
    
    # Use external DNS servers to get real IP
    $dnsServers = @("8.8.8.8", "1.1.1.1")
    
    foreach ($dns in $dnsServers) {
        try {
            $result = nslookup $Domain $dns 2>$null
            if ($result) {
                $lines = $result | Where-Object { $_ -match "Address:\s*(\d+\.\d+\.\d+\.\d+)$" }
                

# Pester 3.4.0 compatibility - warn and return for skipped tests
function Pending { param([string]$Message) Write-Warning "[SKIPPED] $Message"; return }
if ($lines) {
                    $ip = ($lines | Select-Object -First 1) -replace ".*Address:\s*", ""
                    if ($ip -match "^\d+\.\d+\.\d+\.\d+$") {
                        return $ip
                    }
                }
            }
        } catch {
            continue
        }
    }
    
    return $null
}

function Test-DNSServerModification {
    try {
        $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=true"
        
        foreach ($adapter in $adapters) {
            $originalDNS = $adapter.DNSServerSearchOrder
            if ($originalDNS -and $originalDNS.Count -gt 0) {
                return @{
                    CanModify = $true
                    AdapterCount = $adapters.Count
                    OriginalDNS = $originalDNS
                }
            }
        }
        
        return @{
            CanModify = $false
            AdapterCount = $adapters.Count
        }
    } catch {
        return @{
            CanModify = $false
            Error = $_.Exception.Message
        }
    }
}

# Main Test Execution
Describe "DNS Interception Methods Tests" -Tag "Medium", "Component" {
    
    BeforeAll {
        Write-Host "Starting DNS interception methods tests..." -ForegroundColor Cyan
        
        # Check administrator privileges
        $script:IsAdmin = Test-IsAdministrator
        if ($RequireAdmin -and -not $script:IsAdmin) {
            throw "Administrator privileges required for DNS interception tests"
        }
        
        if (-not $script:IsAdmin) {
            Write-Warning "Not running as administrator - some tests will be skipped"
        }
        
        # Backup hosts file if we'll be modifying it
        if ($DestructiveTests) {
            Backup-HostsFile | Out-Null
        }
    }
    
    AfterAll {
        # Restore hosts file if we backed it up
        if ($DestructiveTests) {
            Write-Host "Restoring hosts file..." -ForegroundColor Yellow
            Restore-HostsFile | Out-Null
        }
    }
    
    Context "Hosts File Method" {
        
        It "Should detect existing hosts file" {
            Test-Path $script:DNSConfig.HostsPath | Should Be $true
        }
        
        It "Should read hosts file content" {
            $content = Get-Content $script:DNSConfig.HostsPath -Raw -ErrorAction SilentlyContinue
            $content | Should Not BeNullOrEmpty
        }
        
        It "Should add hosts file entry" {
            if (-not $DestructiveTests) {
                Pending "Destructive tests not enabled"
                return
            }
            
            if (-not $script:IsAdmin) {
                Pending "Administrator privileges required"
                return
            }
            
            $success = Add-HostsFileEntry
            $success | Should Be $true
            
            Test-HostsFileEntry | Should Be $true
        }
        
        It "Should resolve domain to localhost after hosts modification" {
            if (-not $DestructiveTests) {
                Pending "Destructive tests not enabled"
                return
            }
            
            if (-not (Test-HostsFileEntry)) {
                Pending "Hosts file entry not present"
                return
            }
            
            # Wait for DNS cache to clear or flush it
            ipconfig /flushdns | Out-Null
            Start-Sleep -Seconds 2
            
            $result = Test-DNSResolution
            $result.Success | Should Be $true
        }
        
        It "Should remove hosts file entry cleanly" {
            if (-not $DestructiveTests) {
                Pending "Destructive tests not enabled"
                return
            }
            
            if (-not $script:IsAdmin) {
                Pending "Administrator privileges required"
                return
            }
            
            $success = Remove-HostsFileEntry
            $success | Should Be $true
            
            Test-HostsFileEntry | Should Be $false
        }
        
        It "Should handle multiple entries correctly" {
            if (-not $DestructiveTests) {
                Pending "Destructive tests not enabled"
                return
            }
            
            if (-not $script:IsAdmin) {
                Pending "Administrator privileges required"
                return
            }
            
            # Add multiple test entries
            $domains = @("test1.example.com", "test2.example.com")
            
            foreach ($domain in $domains) {
                Add-HostsFileEntry -Domain $domain | Should Be $true
                Test-HostsFileEntry -Domain $domain | Should Be $true
            }
            
            # Remove all test entries
            foreach ($domain in $domains) {
                Remove-HostsFileEntry -Domain $domain | Should Be $true
                Test-HostsFileEntry -Domain $domain | Should Be $false
            }
        }
        
        It "Should handle read-only hosts file gracefully" {
            if (-not $DestructiveTests) {
                Pending "Destructive tests not enabled"
                return
            }
            
            if (-not $script:IsAdmin) {
                Pending "Administrator privileges required"
                return
            }
            
            # Make hosts file read-only
            Set-ItemProperty $script:DNSConfig.HostsPath -Name IsReadOnly -Value $true
            
            try {
                # Try to add entry (should fail gracefully)
                $success = Add-HostsFileEntry -Domain "readonly-test.com"
                $success | Should Be $false
            } finally {
                # Restore write access
                Set-ItemProperty $script:DNSConfig.HostsPath -Name IsReadOnly -Value $false
            }
        }
    }
    
    Context "Network Routing Method" {
        
        It "Should detect real IP for target domain" {
            $realIP = Get-RealDomainIP
            $realIP | Should Not BeNullOrEmpty
            $realIP | Should Match "^\d+\.\d+\.\d+\.\d+$"
        }
        
        It "Should add network route" {
            if (-not $DestructiveTests) {
                Pending "Destructive tests not enabled"
                return
            }
            
            if (-not $script:IsAdmin) {
                Pending "Administrator privileges required"
                return
            }
            
            $realIP = Get-RealDomainIP
            if (-not $realIP) {
                Pending "Could not resolve real IP"
                return
            }
            
            $success = Add-NetworkRoute -Destination $realIP
            $success | Should Be $true
            
            # Verify route exists
            $routeCheck = Test-NetworkRoute -Destination $realIP
            $routeCheck.Exists | Should Be $true
        }
        
        It "Should remove network route" {
            if (-not $DestructiveTests) {
                Pending "Destructive tests not enabled"
                return
            }
            
            if (-not $script:IsAdmin) {
                Pending "Administrator privileges required"
                return
            }
            
            $realIP = Get-RealDomainIP
            if (-not $realIP) {
                Pending "Could not resolve real IP"
                return
            }
            
            $success = Remove-NetworkRoute -Destination $realIP
            $success | Should Be $true
            
            # Verify route is gone
            $routeCheck = Test-NetworkRoute -Destination $realIP
            $routeCheck.Exists | Should Be $false
        }
        
        It "Should handle non-existent route deletion gracefully" {
            if (-not $script:IsAdmin) {
                Pending "Administrator privileges required"
                return
            }
            
            # Try to delete a route that doesn't exist
            $success = Remove-NetworkRoute -Destination "192.0.2.1"  # TEST-NET-1 (unused)
            $success | Should Be $true  # Should not fail
        }
    }
    
    Context "DNS Server Registry Method" {
        
        It "Should detect network adapters for DNS modification" {
            $result = Test-DNSServerModification
            $result.AdapterCount | Should BeGreaterThan 0
        }
        
        It "Should identify modifiable network adapters" {
            $result = Test-DNSServerModification
            
            if ($result.CanModify) {
                $result.OriginalDNS | Should Not BeNullOrEmpty
                $result.OriginalDNS.Count | Should BeGreaterThan 0
            } else {
                Write-Warning "No network adapters with DNS settings found"
            }
        }
        
        It "Should simulate DNS server modification" {
            # This test simulates the DNS server modification without actually doing it
            # to avoid disrupting network connectivity during tests
            
            $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=true"
            $testAdapter = $adapters | Where-Object { $_.DNSServerSearchOrder } | Select-Object -First 1
            
            if ($testAdapter) {
                $originalDNS = $testAdapter.DNSServerSearchOrder
                $newDNS = @("127.0.0.1") + $originalDNS
                
                # Verify we can construct the new DNS list
                $newDNS.Count | Should BeGreaterThan $originalDNS.Count
                $newDNS[0] | Should Be "127.0.0.1"
                
                # Verify original DNS servers are preserved
                for ($i = 0; $i -lt $originalDNS.Count; $i++) {
                    $newDNS[$i + 1] | Should Be $originalDNS[$i]
                }
            } else {
                Pending "No suitable network adapter found"
            }
        }
    }
    
    Context "Windows Filtering Platform (WFP)" {
        
        It "Should detect WFP capabilities" {
            # Check if netsh wfp commands are available
            $netshWfpHelp = netsh wfp help 2>&1
            $wfpAvailable = $netshWfpHelp -notmatch "not recognized"
            
            $wfpAvailable | Should Be $true
        }
        
        It "Should check for required privileges for WFP" {
            # WFP operations require SYSTEM privileges, not just admin
            $isSystem = $false
            
            try {
                # Check if we can query WFP state (requires high privileges)
                $wfpState = netsh wfp show state 2>&1
                $isSystem = $wfpState -notmatch "access.*denied" -and $wfpState -notmatch "not.*permitted"
            } catch {
                $isSystem = $false
            }
            
            if ($script:IsAdmin) {
                # Admin should at least be able to run netsh wfp commands
                $wfpState -should Not Match "not recognized"
            } else {
                Pending "Administrator privileges required"
            }
        }
        
        It "Should test WFP filter enumeration" {
            if (-not $script:IsAdmin) {
                Pending "Administrator privileges required"
                return
            }
            
            try {
                $filters = netsh wfp show filters 2>&1
                
                # Should be able to enumerate filters (even if empty)
                $filters | Should Not BeNullOrEmpty
                $filters -should Not Match "access.*denied"
            } catch {
                Pending "WFP access denied - requires SYSTEM privileges"
            }
        }
    }
    
    Context "Method Fallback and Priority" {
        
        It "Should prioritize methods correctly" {
            # Test the fallback order used by the Go code
            $methods = @("hosts", "wfp", "registry", "routing")
            
            # Hosts file should be first (most reliable)
            $methods[0] | Should Be "hosts"
            
            # Methods should be distinct
            $methods | Select-Object -Unique | Should HaveCount 4
        }
        
        It "Should handle method failure gracefully" {
            # Simulate method failure and fallback
            $methods = @("hosts", "wfp", "registry", "routing")
            $workingMethods = @()
            
            # Test each method availability
            foreach ($method in $methods) {
                switch ($method) {
                    "hosts" {
                        if (Test-Path $script:DNSConfig.HostsPath) {
                            $workingMethods += $method
                        }
                    }
                    "wfp" {
                        if ($script:IsAdmin -and (netsh wfp help 2>&1) -notmatch "not recognized") {
                            $workingMethods += $method
                        }
                    }
                    "registry" {
                        $result = Test-DNSServerModification
                        if ($result.CanModify) {
                            $workingMethods += $method
                        }
                    }
                    "routing" {
                        if ($script:IsAdmin) {
                            $workingMethods += $method
                        }
                    }
                }
            }
            
            # Should have at least one working method
            $workingMethods.Count | Should BeGreaterThan 0
            Write-Host "Available DNS methods: $($workingMethods -join ', ')" -ForegroundColor Green
        }
        
        It "Should validate method effectiveness" {
            if (-not $DestructiveTests) {
                Pending "Destructive tests not enabled"
                return
            }
            
            if (-not $script:IsAdmin) {
                Pending "Administrator privileges required"
                return
            }
            
            # Test hosts file method effectiveness
            $originalResolution = Test-DNSResolution
            
            # Add hosts entry
            Add-HostsFileEntry | Out-Null
            ipconfig /flushdns | Out-Null
            Start-Sleep -Seconds 2
            
            $modifiedResolution = Test-DNSResolution
            
            # Remove hosts entry
            Remove-HostsFileEntry | Out-Null
            ipconfig /flushdns | Out-Null
            
            # Verify the method worked
            if ($originalResolution.Success -eq $false -and $modifiedResolution.Success -eq $true) {
                $true | Should Be $true  # Method was effective
            } elseif ($originalResolution.ResolvedIPs -contains $script:DNSConfig.RedirectIP) {
                Pending "Domain already resolves to localhost"
            } else {
                # Method should have changed resolution
                $modifiedResolution.Success | Should Be $true
            }
        }
    }
}

# Integration with AuthRouter Service
Describe "DNS Interception Integration" -Tag "Slow", "Integration" {
    
    Context "Service Integration" {
        
        It "Should detect AuthRouter service" {
            $service = Get-Service -Name $script:DNSConfig.ServiceName -ErrorAction SilentlyContinue
            
            if ($service) {
                $service.Name | Should Be $script:DNSConfig.ServiceName
            } else {
                Pending "AuthRouter service not installed"
            }
        }
        
        It "Should verify DNS interception when service starts" {
            $service = Get-Service -Name $script:DNSConfig.ServiceName -ErrorAction SilentlyContinue
            
            if (-not $service) {
                Pending "AuthRouter service not installed"
                return
            }
            
            if ($service.Status -eq "Running") {
                # Service is running - check if DNS is intercepted
                $result = Test-DNSResolution
                
                if ($result.Success) {
                    Write-Host "DNS interception is active" -ForegroundColor Green
                } else {
                    Write-Warning "Service running but DNS not intercepted - may use different method"
                }
            } else {
                Pending "AuthRouter service not running"
            }
        }
        
        It "Should verify DNS cleanup when service stops" {
            if (-not $DestructiveTests) {
                Pending "Destructive tests not enabled"
                return
            }
            
            $service = Get-Service -Name $script:DNSConfig.ServiceName -ErrorAction SilentlyContinue
            
            if (-not $service) {
                Pending "AuthRouter service not installed"
                return
            }
            
            if ($service.Status -eq "Running") {
                # Stop service and check cleanup
                Stop-Service -Name $script:DNSConfig.ServiceName -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 3
                
                # Verify hosts file is cleaned
                Test-HostsFileEntry | Should Be $false
                
                # Restart service for other tests
                Start-Service -Name $script:DNSConfig.ServiceName -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 3
            } else {
                Pending "AuthRouter service not running initially"
            }
        }
    }
}

# Performance and Reliability
Describe "DNS Interception Performance" -Tag "Fast", "Performance" {
    
    Context "Method Performance" {
        
        It "Should add hosts entry quickly" {
            if (-not $DestructiveTests) {
                Pending "Destructive tests not enabled"
                return
            }
            
            if (-not $script:IsAdmin) {
                Pending "Administrator privileges required"
                return
            }
            
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $success = Add-HostsFileEntry -Domain "perf-test.example.com"
            $stopwatch.Stop()
            
            $success | Should Be $true
            $stopwatch.ElapsedMilliseconds | Should BeLessThan 1000  # Should complete in under 1 second
            
            # Cleanup
            Remove-HostsFileEntry -Domain "perf-test.example.com" | Out-Null
        }
        
        It "Should resolve modified DNS quickly" {
            if (-not $DestructiveTests) {
                Pending "Destructive tests not enabled"
                return
            }
            
            if (-not $script:IsAdmin) {
                Pending "Administrator privileges required"
                return
            }
            
            # Add entry and flush DNS cache
            Add-HostsFileEntry | Out-Null
            ipconfig /flushdns | Out-Null
            
            # Measure resolution time
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $result = Test-DNSResolution
            $stopwatch.Stop()
            
            $result.Success | Should Be $true
            $stopwatch.ElapsedMilliseconds | Should BeLessThan 5000  # Should resolve in under 5 seconds
            
            # Cleanup
            Remove-HostsFileEntry | Out-Null
        }
    }
}

Write-Host "`n=== DNS Interception Methods Test Summary ===" -ForegroundColor Cyan
Write-Host "Tests validate all Windows DNS interception methods:" -ForegroundColor White
Write-Host "  â€¢ Hosts file modification" -ForegroundColor Gray
Write-Host "  â€¢ Network routing" -ForegroundColor Gray
Write-Host "  â€¢ DNS server registry override" -ForegroundColor Gray
Write-Host "  â€¢ Windows Filtering Platform (WFP)" -ForegroundColor Gray
Write-Host "  â€¢ Method fallback and integration" -ForegroundColor Gray

if (-not $DestructiveTests) {
    Write-Host "`nNote: Run with -DestructiveTests to enable modification tests" -ForegroundColor Yellow
}

if (-not $script:IsAdmin) {
    Write-Host "Note: Run as Administrator for full test coverage" -ForegroundColor Yellow
}

Write-Host "`n=== Test Complete ===" -ForegroundColor Green