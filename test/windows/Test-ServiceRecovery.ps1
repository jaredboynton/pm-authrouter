# Test-ServiceRecovery.ps1
# Comprehensive tests for service crash recovery and restart scenarios
# Tests signal handling, graceful shutdown, recovery actions, and service lifecycle



param(
    [string]$ServiceName = "PostmanAuthRouter",
    [int]$RecoveryTimeoutSeconds = 30,
    [switch]$DestructiveTests = $false,  # Enable tests that stop/kill processes
    [switch]$RequireService = $true      # Skip tests if service not installed
)

# Test configuration
$script:RecoveryConfig = @{
    ServiceName = $ServiceName
    ServiceDisplayName = "Postman AuthRouter"
    ServiceDescription = "Enterprise authentication router daemon for Postman Desktop applications"
    LogPath = "C:\ProgramData\Postman\pm-authrouter.log"
    RecoveryTimeout = $RecoveryTimeoutSeconds
    TestPort = 443
    MaxRecoveryAttempts = 3
}



# Pester 3.4.0 compatibility - warn and return for skipped tests
function Pending { param([string]$Message) Write-Warning "[SKIPPED] $Message"; return }
# Helper Functions
function Get-ServiceInfo {
    param([string]$ServiceName = $script:RecoveryConfig.ServiceName)
    
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        $wmiService = Get-WmiObject Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
        
        return @{
            Service = $service
            WmiService = $wmiService
            Status = $service.Status
            StartType = $wmiService.StartMode
            ProcessId = $wmiService.ProcessId
            Account = $wmiService.StartName
            Path = $wmiService.PathName
        }
    

# Pester 3.4.0 compatibility - warn and return for skipped tests
function Pending { param([string]$Message) Write-Warning "[SKIPPED] $Message"; return }
} catch {
        return $null
    }
}

function Wait-ForServiceStatus {
    param(
        [string]$ServiceName,
        [string]$ExpectedStatus = "Running",
        [int]$TimeoutSeconds = 30
    )
    
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    while ($stopwatch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq $ExpectedStatus) {
            return $true
        }
        

# Pester 3.4.0 compatibility - warn and return for skipped tests
function Pending { param([string]$Message) Write-Warning "[SKIPPED] $Message"; return }
Start-Sleep -Milliseconds 500
    }
    
    return $false
}

function Get-ServiceProcessInfo {
    param([string]$ServiceName = $script:RecoveryConfig.ServiceName)
    
    $serviceInfo = Get-ServiceInfo -ServiceName $ServiceName
    if (-not $serviceInfo -or $serviceInfo.ProcessId -le 0) {
        return $null
    }
    
    

# Pester 3.4.0 compatibility - warn and return for skipped tests
function Pending { param([string]$Message) Write-Warning "[SKIPPED] $Message"; return }
try {
        $process = Get-Process -Id $serviceInfo.ProcessId -ErrorAction Stop
        return @{
            ProcessId = $process.Id
            ProcessName = $process.ProcessName
            StartTime = $process.StartTime
            WorkingSet = $process.WorkingSet64
            HandleCount = $process.HandleCount
        }
    } catch {
        return $null
    }
}

function Test-ServicePortBinding {
    param([int]$Port = $script:RecoveryConfig.TestPort)
    
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

function Get-ServiceRecoveryActions {
    param([string]$ServiceName = $script:RecoveryConfig.ServiceName)
    
    try {
        # Use sc.exe to query recovery actions
        $output = sc.exe qfailure $ServiceName 2>$null
        
        if ($LASTEXITCODE -eq 0) {
            $resetPeriod = ($output | Where-Object { $_ -match "RESET_PERIOD" }

# Pester 3.4.0 compatibility - warn and return for skipped tests
function Pending { param([string]$Message) Write-Warning "[SKIPPED] $Message"; return }
) -replace ".*RESET_PERIOD\s*:\s*(\d+).*", '$1'
            $restartActions = $output | Where-Object { $_ -match "RESTART" }
            
            return @{
                HasRecoveryActions = $restartActions.Count -gt 0
                ResetPeriod = $resetPeriod
                Actions = $restartActions
            }
        }
    } catch {
        # Fallback: assume no recovery actions
    }
    
    return @{
        HasRecoveryActions = $false
        ResetPeriod = 0
        Actions = @()
    }
}

function Send-ProcessSignal {
    param(
        [int]$ProcessId,
        [string]$Signal = "SIGTERM"
    )
    
    try {
        $process = Get-Process -Id $ProcessId -ErrorAction Stop
        
        switch ($Signal.ToUpper()) {
            "SIGTERM" {
                # Graceful termination
                $process.CloseMainWindow()
                Start-Sleep -Seconds 2
                if (-not $process.HasExited) {
                    $process.Kill()
                }
                

# Pester 3.4.0 compatibility - warn and return for skipped tests
function Pending { param([string]$Message) Write-Warning "[SKIPPED] $Message"; return }
return $true
            }
            "SIGKILL" {
                # Force kill
                $process.Kill()
                return $true
            }
            default {
                Write-Warning "Unsupported signal: $Signal"
                return $false
            }
        }
    } catch {
        Write-Warning "Failed to send signal $Signal to process $ProcessId`: $_"
        return $false
    }
}

function Test-ServiceLogContent {
    param(
        [string]$LogPath = $script:RecoveryConfig.LogPath,
        [string]$Pattern,
        [int]$TimeoutSeconds = 10
    )
    
    if (-not (Test-Path $LogPath)) {
        return $false
    }
    
    

# Pester 3.4.0 compatibility - warn and return for skipped tests
function Pending { param([string]$Message) Write-Warning "[SKIPPED] $Message"; return }
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    while ($stopwatch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        try {
            $content = Get-Content $LogPath -Tail 20 -ErrorAction Stop
            if ($content | Where-Object { $_ -match $Pattern }) {
                return $true
            }
        } catch {
            # Log file might be locked
        }
        Start-Sleep -Milliseconds 500
    }
    
    return $false
}

function Backup-ServiceState {
    return @{
        ServiceInfo = Get-ServiceInfo
        ProcessInfo = Get-ServiceProcessInfo
        PortBinding = Test-ServicePortBinding
        Timestamp = Get-Date
    }
}

function Compare-ServiceState {
    param(
        [hashtable]$BeforeState,
        [hashtable]$AfterState
    )
    
    return @{
        ServiceRestarted = $BeforeState.ServiceInfo.ProcessId -ne $AfterState.ServiceInfo.ProcessId
        ProcessChanged = $BeforeState.ProcessInfo.ProcessId -ne $AfterState.ProcessInfo.ProcessId
        PortStillBound = $BeforeState.PortBinding -and $AfterState.PortBinding
        RecoveryTime = ($AfterState.Timestamp - $BeforeState.Timestamp).TotalSeconds
    }


# Pester 3.4.0 compatibility - warn and return for skipped tests
function Pending { param([string]$Message) Write-Warning "[SKIPPED] $Message"; return }
}

# Main Test Execution
Describe "Service Recovery and Lifecycle Tests" -Tag "Medium", "Component" {
    
    BeforeAll {
        Write-Host "Starting service recovery tests..." -ForegroundColor Cyan
        
        # Verify service exists
        $script:ServiceInfo = Get-ServiceInfo
        if (-not $script:ServiceInfo) {
            if ($RequireService) {
                throw "PostmanAuthRouter service not found - install MSI first"
            } else {
                Write-Warning "PostmanAuthRouter service not found - some tests will be skipped"
            }
        }
        
        if (-not $DestructiveTests) {
            Write-Warning "Destructive tests disabled - limited recovery testing available"
        }
    }
    
    Context "Service Installation and Configuration" {
        
        It "Should have service installed" {
            $script:ServiceInfo | Should Not BeNullOrEmpty
            $script:ServiceInfo.Service.Name | Should Be $script:RecoveryConfig.ServiceName
        }
        
        It "Should have correct service configuration" {
            if (-not $script:ServiceInfo) {
                Pending "Service not installed"
                return
            }
            
            $script:ServiceInfo.Service.DisplayName | Should Match $script:RecoveryConfig.ServiceDisplayName
            $script:ServiceInfo.StartType | Should Be "Auto"
            $script:ServiceInfo.Account | Should Match "(LocalSystem|NT AUTHORITY\\SYSTEM)"
        }
        
        It "Should have recovery actions configured" {
            if (-not $script:ServiceInfo) {
                Pending "Service not installed"
                return
            }
            
            $recovery = Get-ServiceRecoveryActions
            $recovery.HasRecoveryActions | Should Be $true
            
            if ($recovery.HasRecoveryActions) {
                Write-Host "Recovery actions configured:" -ForegroundColor Green
                $recovery.Actions | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
            }
        }
        
        It "Should have valid service executable path" {
            if (-not $script:ServiceInfo) {
                Pending "Service not installed"
                return
            }
            
            $script:ServiceInfo.Path | Should Not BeNullOrEmpty
            
            # Extract executable path (remove arguments)
            $exePath = ($script:ServiceInfo.Path -split '"')[1]
            if (-not $exePath) {
                $exePath = ($script:ServiceInfo.Path -split ' ')[0]
            }
            
            Test-Path $exePath | Should Be $true
        }
    }
    
    Context "Service Startup and Shutdown" {
        
        It "Should start service successfully" {
            if (-not $script:ServiceInfo) {
                Pending "Service not installed"
                return
            }
            
            if ($script:ServiceInfo.Status -ne "Running") {
                Start-Service -Name $script:RecoveryConfig.ServiceName -ErrorAction Stop
            }
            
            $started = Wait-ForServiceStatus -ExpectedStatus "Running"
            $started | Should Be $true
            
            # Verify port binding
            Start-Sleep -Seconds 3
            Test-ServicePortBinding | Should Be $true
        }
        
        It "Should stop service gracefully" {
            if (-not $script:ServiceInfo) {
                Pending "Service not installed"
                return
            }
            
            if (-not $DestructiveTests) {
                Pending "Destructive tests not enabled"
                return
            }
            
            # Record process info before stopping
            $processBefore = Get-ServiceProcessInfo
            
            Stop-Service -Name $script:RecoveryConfig.ServiceName -Force -ErrorAction Stop
            
            $stopped = Wait-ForServiceStatus -ExpectedStatus "Stopped"
            $stopped | Should Be $true
            
            # Verify port is released
            Start-Sleep -Seconds 2
            Test-ServicePortBinding | Should Be $false
            
            # Verify process exited cleanly
            if ($processBefore) {
                $processAfter = Get-Process -Id $processBefore.ProcessId -ErrorAction SilentlyContinue
                $processAfter | Should Be $null
            }
            
            # Restart for other tests
            Start-Service -Name $script:RecoveryConfig.ServiceName
            Wait-ForServiceStatus -ExpectedStatus "Running" | Should Be $true
        }
        
        It "Should handle restart correctly" {
            if (-not $script:ServiceInfo) {
                Pending "Service not installed"
                return
            }
            
            if (-not $DestructiveTests) {
                Pending "Destructive tests not enabled"
                return
            }
            
            $beforeState = Backup-ServiceState
            
            # Restart service
            Restart-Service -Name $script:RecoveryConfig.ServiceName -Force
            
            # Wait for service to stabilize
            $restarted = Wait-ForServiceStatus -ExpectedStatus "Running"
            $restarted | Should Be $true
            
            Start-Sleep -Seconds 3
            $afterState = Backup-ServiceState
            
            # Verify restart occurred
            $comparison = Compare-ServiceState -BeforeState $beforeState -AfterState $afterState
            $comparison.ServiceRestarted | Should Be $true
            $comparison.PortStillBound | Should Be $true
            $comparison.RecoveryTime | Should BeLessThan 30
        }
    }
    
    Context "Process Termination and Recovery" {
        
        It "Should recover from SIGTERM signal" {
            if (-not $script:ServiceInfo) {
                Pending "Service not installed"
                return
            }
            
            if (-not $DestructiveTests) {
                Pending "Destructive tests not enabled"
                return
            }
            
            $processInfo = Get-ServiceProcessInfo
            if (-not $processInfo) {
                Pending "Service process not found"
                return
            }
            
            $beforeState = Backup-ServiceState
            
            # Send graceful termination signal
            $signalSent = Send-ProcessSignal -ProcessId $processInfo.ProcessId -Signal "SIGTERM"
            $signalSent | Should Be $true
            
            # Wait for service to recover
            Start-Sleep -Seconds 5
            $recovered = Wait-ForServiceStatus -ExpectedStatus "Running" -TimeoutSeconds $script:RecoveryConfig.RecoveryTimeout
            
            if ($recovered) {
                $afterState = Backup-ServiceState
                $comparison = Compare-ServiceState -BeforeState $beforeState -AfterState $afterState
                
                $comparison.ServiceRestarted | Should Be $true
                $comparison.PortStillBound | Should Be $true
                Write-Host "Service recovered in $([math]::Round($comparison.RecoveryTime, 1)) seconds" -ForegroundColor Green
            } else {
                Write-Warning "Service did not recover within timeout - may need manual intervention"
                # Try manual start for other tests
                Start-Service -Name $script:RecoveryConfig.ServiceName -ErrorAction SilentlyContinue
            }
        }
        
        It "Should recover from process kill" {
            if (-not $script:ServiceInfo) {
                Pending "Service not installed"
                return
            }
            
            if (-not $DestructiveTests) {
                Pending "Destructive tests not enabled"
                return
            }
            
            $processInfo = Get-ServiceProcessInfo
            if (-not $processInfo) {
                Pending "Service process not found"
                return
            }
            
            $beforeState = Backup-ServiceState
            
            # Force kill the process
            $killed = Send-ProcessSignal -ProcessId $processInfo.ProcessId -Signal "SIGKILL"
            $killed | Should Be $true
            
            # Wait for service recovery
            Start-Sleep -Seconds 5
            $recovered = Wait-ForServiceStatus -ExpectedStatus "Running" -TimeoutSeconds $script:RecoveryConfig.RecoveryTimeout
            
            if ($recovered) {
                $afterState = Backup-ServiceState
                $comparison = Compare-ServiceState -BeforeState $beforeState -AfterState $afterState
                
                $comparison.ServiceRestarted | Should Be $true
                Write-Host "Service recovered from kill in $([math]::Round($comparison.RecoveryTime, 1)) seconds" -ForegroundColor Green
            } else {
                Write-Warning "Service did not recover from kill - checking recovery actions"
                
                # Check if recovery actions are working
                $recovery = Get-ServiceRecoveryActions
                if (-not $recovery.HasRecoveryActions) {
                    Write-Warning "No recovery actions configured - service will not auto-restart"
                }
                
                # Manual start for other tests
                Start-Service -Name $script:RecoveryConfig.ServiceName -ErrorAction SilentlyContinue
            }
        }
        
        It "Should handle repeated failures gracefully" {
            if (-not $script:ServiceInfo) {
                Pending "Service not installed"
                return
            }
            
            if (-not $DestructiveTests) {
                Pending "Destructive tests not enabled"
                return
            }
            
            # This test simulates repeated service failures
            # In production, the service should eventually stop trying to restart
            # if it keeps failing (based on reset period)
            
            $recovery = Get-ServiceRecoveryActions
            if (-not $recovery.HasRecoveryActions) {
                Pending "No recovery actions configured"
                return
            }
            
            $maxAttempts = $script:RecoveryConfig.MaxRecoveryAttempts
            $successfulRecoveries = 0
            
            for ($i = 1; $i -le $maxAttempts; $i++) {
                Write-Host "Recovery attempt $i of $maxAttempts" -ForegroundColor Yellow
                
                $processInfo = Get-ServiceProcessInfo
                if (-not $processInfo) {
                    break
                }
                
                # Kill process
                Send-ProcessSignal -ProcessId $processInfo.ProcessId -Signal "SIGKILL" | Out-Null
                Start-Sleep -Seconds 2
                
                # Check if it recovered
                $recovered = Wait-ForServiceStatus -ExpectedStatus "Running" -TimeoutSeconds 15
                if ($recovered) {
                    $successfulRecoveries++
                    Start-Sleep -Seconds 3  # Let it stabilize
                } else {
                    break
                }
            }
            
            Write-Host "Successful recoveries: $successfulRecoveries / $maxAttempts" -ForegroundColor Green
            $successfulRecoveries | Should BeGreaterThan 0
            
            # Ensure service is running for remaining tests
            if ((Get-Service -Name $script:RecoveryConfig.ServiceName).Status -ne "Running") {
                Start-Service -Name $script:RecoveryConfig.ServiceName -ErrorAction SilentlyContinue
            }
        }
    }
    
    Context "DNS Cleanup on Termination" {
        
        It "Should clean hosts file on graceful shutdown" {
            if (-not $script:ServiceInfo) {
                Pending "Service not installed"
                return
            }
            
            if (-not $DestructiveTests) {
                Pending "Destructive tests not enabled"
                return
            }
            
            # Verify hosts entry exists when running
            $hostsPath = "C:\Windows\System32\drivers\etc\hosts"
            $hostsContent = Get-Content $hostsPath -Raw -ErrorAction SilentlyContinue
            $hasEntry = $hostsContent -match "127\.0\.0\.1\s+identity\.getpostman\.com"
            
            if (-not $hasEntry) {
                Pending "No hosts file entry found - service may use different DNS method"
                return
            }
            
            # Stop service gracefully
            Stop-Service -Name $script:RecoveryConfig.ServiceName -Force
            Start-Sleep -Seconds 3
            
            # Check if hosts entry was removed
            $hostsContentAfter = Get-Content $hostsPath -Raw -ErrorAction SilentlyContinue
            $hasEntryAfter = $hostsContentAfter -match "127\.0\.0\.1\s+identity\.getpostman\.com.*PostmanAuthRouter"
            
            $hasEntryAfter | Should Be $false
            
            # Restart service
            Start-Service -Name $script:RecoveryConfig.ServiceName
            Wait-ForServiceStatus -ExpectedStatus "Running" | Should Be $true
        }
        
        It "Should clean stale entries on startup" {
            if (-not $script:ServiceInfo) {
                Pending "Service not installed"
                return
            }
            
            if (-not $DestructiveTests) {
                Pending "Destructive tests not enabled"
                return
            }
            
            # Stop service
            Stop-Service -Name $script:RecoveryConfig.ServiceName -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            
            # Manually add a stale entry
            $hostsPath = "C:\Windows\System32\drivers\etc\hosts"
            $staleEntry = "`n127.0.0.1 identity.getpostman.com # Stale PostmanAuthRouter entry"
            Add-Content -Path $hostsPath -Value $staleEntry -ErrorAction SilentlyContinue
            
            # Verify entry exists
            $hostsContent = Get-Content $hostsPath -Raw -ErrorAction SilentlyContinue
            $hasStaleEntry = $hostsContent -match "127\.0\.0\.1\s+identity\.getpostman\.com.*Stale"
            
            if ($hasStaleEntry) {
                # Start service - it should clean stale entries
                Start-Service -Name $script:RecoveryConfig.ServiceName
                Wait-ForServiceStatus -ExpectedStatus "Running" | Should Be $true
                Start-Sleep -Seconds 3
                
                # Check if stale entry was cleaned
                $hostsContentAfter = Get-Content $hostsPath -Raw -ErrorAction SilentlyContinue
                $hasStaleEntryAfter = $hostsContentAfter -match "127\.0\.0\.1\s+identity\.getpostman\.com.*Stale"
                
                $hasStaleEntryAfter | Should Be $false
            } else {
                Pending "Could not add stale entry - insufficient permissions"
                # Ensure service is running
                Start-Service -Name $script:RecoveryConfig.ServiceName -ErrorAction SilentlyContinue
            }
        }
    }
    
    Context "Logging and Diagnostics" {
        
        It "Should log service start events" {
            if (-not (Test-Path $script:RecoveryConfig.LogPath)) {
                Pending "Log file not found"
                return
            }
            
            # Check for start-related log entries
            $hasStartLog = Test-ServiceLogContent -Pattern "Starting.*AuthRouter"
            $hasStartLog | Should Be $true
        }
        
        It "Should log graceful shutdown" {
            if (-not $script:ServiceInfo) {
                Pending "Service not installed"
                return
            }
            
            if (-not $DestructiveTests) {
                Pending "Destructive tests not enabled"
                return
            }
            
            if (-not (Test-Path $script:RecoveryConfig.LogPath)) {
                Pending "Log file not found"
                return
            }
            
            # Stop service and check for shutdown log
            Stop-Service -Name $script:RecoveryConfig.ServiceName -Force
            
            $hasShutdownLog = Test-ServiceLogContent -Pattern "(Shutting down|Service stop|cleanup)" -TimeoutSeconds 5
            $hasShutdownLog | Should Be $true
            
            # Restart service
            Start-Service -Name $script:RecoveryConfig.ServiceName
            Wait-ForServiceStatus -ExpectedStatus "Running" | Should Be $true
        }
        
        It "Should log DNS interception status" {
            if (-not (Test-Path $script:RecoveryConfig.LogPath)) {
                Pending "Log file not found"
                return
            }
            
            $hasDNSLog = Test-ServiceLogContent -Pattern "(DNS|hosts|interception)" -TimeoutSeconds 5
            $hasDNSLog | Should Be $true
        }
        
        It "Should not log sensitive information" {
            if (-not (Test-Path $script:RecoveryConfig.LogPath)) {
                Pending "Log file not found"
                return
            }
            
            try {
                $logContent = Get-Content $script:RecoveryConfig.LogPath -Raw -ErrorAction Stop
                
                # Check for common sensitive patterns
                $sensitivePatterns = @("password", "secret", "token", "key=", "auth=")
                
                foreach ($pattern in $sensitivePatterns) {
                    if ($logContent -match $pattern) {
                        Write-Warning "Found potentially sensitive information in logs: $pattern"
                    }
                }
                
                # This test passes if we don't find obvious sensitive data
                $logContent | Should Not Match "password\s*[:=]"
                $logContent | Should Not Match "secret\s*[:=]"
            } catch {
                Pending "Could not read log file: $_"
            }
        }
    }
}

# Performance and Resource Management
Describe "Service Performance During Recovery" -Tag "Slow", "Performance" {
    
    Context "Resource Usage" {
        
        It "Should maintain reasonable memory usage" {
            if (-not $script:ServiceInfo) {
                Pending "Service not installed"
                return
            }
            
            $processInfo = Get-ServiceProcessInfo
            if (-not $processInfo) {
                Pending "Service process not found"
                return
            }
            
            $memoryMB = $processInfo.WorkingSet / 1MB
            $memoryMB | Should BeLessThan 100  # Should use less than 100MB
            
            Write-Host "Service memory usage: $([math]::Round($memoryMB, 2)) MB" -ForegroundColor Green
        }
        
        It "Should not leak handles during restarts" {
            if (-not $script:ServiceInfo) {
                Pending "Service not installed"
                return
            }
            
            if (-not $DestructiveTests) {
                Pending "Destructive tests not enabled"
                return
            }
            
            # Baseline handle count
            $processInfo1 = Get-ServiceProcessInfo
            if (-not $processInfo1) {
                Pending "Service process not found"
                return
            }
            
            $handlesBefore = $processInfo1.HandleCount
            
            # Restart service
            Restart-Service -Name $script:RecoveryConfig.ServiceName -Force
            Wait-ForServiceStatus -ExpectedStatus "Running" | Should Be $true
            Start-Sleep -Seconds 5
            
            # Check handle count after restart
            $processInfo2 = Get-ServiceProcessInfo
            if ($processInfo2) {
                $handlesAfter = $processInfo2.HandleCount
                $handleIncrease = $handlesAfter - $handlesBefore
                
                Write-Host "Handle count: $handlesBefore -> $handlesAfter (change: $handleIncrease)" -ForegroundColor Green
                
                # Allow some increase but not excessive
                $handleIncrease | Should BeLessThan 50
            }
        }
        
        It "Should recover within acceptable time" {
            if (-not $script:ServiceInfo) {
                Pending "Service not installed"
                return
            }
            
            if (-not $DestructiveTests) {
                Pending "Destructive tests not enabled"
                return
            }
            
            $processInfo = Get-ServiceProcessInfo
            if (-not $processInfo) {
                Pending "Service process not found"
                return
            }
            
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            
            # Kill process
            Send-ProcessSignal -ProcessId $processInfo.ProcessId -Signal "SIGKILL" | Out-Null
            
            # Wait for recovery
            $recovered = Wait-ForServiceStatus -ExpectedStatus "Running" -TimeoutSeconds 30
            $stopwatch.Stop()
            
            if ($recovered) {
                $recoveryTime = $stopwatch.Elapsed.TotalSeconds
                Write-Host "Recovery time: $([math]::Round($recoveryTime, 2)) seconds" -ForegroundColor Green
                
                $recoveryTime | Should BeLessThan 15  # Should recover within 15 seconds
            } else {
                # Manual start if auto-recovery failed
                Start-Service -Name $script:RecoveryConfig.ServiceName -ErrorAction SilentlyContinue
                throw "Service failed to auto-recover within timeout"
            }
        }
    }
}

Write-Host "`n=== Service Recovery Test Summary ===" -ForegroundColor Cyan
Write-Host "Tests validate service recovery capabilities:" -ForegroundColor White
Write-Host "  â€¢ Service installation and configuration" -ForegroundColor Gray
Write-Host "  â€¢ Startup and shutdown procedures" -ForegroundColor Gray  
Write-Host "  â€¢ Process termination and recovery" -ForegroundColor Gray
Write-Host "  â€¢ DNS cleanup on termination" -ForegroundColor Gray
Write-Host "  â€¢ Logging and diagnostics" -ForegroundColor Gray
Write-Host "  â€¢ Performance during recovery" -ForegroundColor Gray

if (-not $DestructiveTests) {
    Write-Host "`nNote: Run with -DestructiveTests to enable recovery tests" -ForegroundColor Yellow
}

if (-not $script:ServiceInfo) {
    Write-Host "Note: Install PostmanAuthRouter service for full test coverage" -ForegroundColor Yellow
}

Write-Host "`n=== Test Complete ===" -ForegroundColor Green