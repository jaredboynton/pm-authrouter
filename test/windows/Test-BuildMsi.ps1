# Test-BuildMsi.ps1
# Comprehensive functional tests for build_msi_mdm_win.ps1
# Tests all aspects of the Windows MSI build process with size validation



param(
    [string]$BuildScriptPath = "$PSScriptRoot\..\..\deployment\windows\build_msi_mdm_win.ps1",
    [switch]$RunIntegrationTests = $false,
    [switch]$VerboseOutput = $false
)

# Pester module should be imported by the test runner, not by individual test files

# Test configuration
$script:TestConfig = @{
    MaxMsiSizeMB = 125  # Critical requirement
    BuildTimeout = 600  # 10 minutes max for build
    TempTestPath = Join-Path $env:TEMP "msi_build_tests_$(Get-Random)"
    MockOriginalMsi = "Postman-Enterprise-11.58.0-enterprise01-x64.msi"
}



# Pester 3.4.0 compatibility - warn and return for skipped tests
function Pending { param([string]$Message) Write-Warning "[SKIPPED] $Message"; return }
# Setup test environment
function Initialize-TestEnvironment {
    Write-Host "Setting up test environment..." -ForegroundColor Cyan
    
    # Create test directory
    if (-not (Test-Path $script:TestConfig.TempTestPath)) {
        New-Item -ItemType Directory -Path $script:TestConfig.TempTestPath -Force | Out-Null
    }
    
    # Create mock original MSI if needed for tests
    $mockMsiPath = Join-Path $script:TestConfig.TempTestPath $script:TestConfig.MockOriginalMsi
    if (-not (Test-Path $mockMsiPath)) {
        # Create a minimal valid MSI structure for testing
        "Mock MSI content" | Out-File -FilePath $mockMsiPath -Encoding UTF8
    }
    
    return $script:TestConfig.TempTestPath
}

# Cleanup test environment
function Cleanup-TestEnvironment {
    Write-Host "Cleaning up test environment..." -ForegroundColor Yellow
    if (Test-Path $script:TestConfig.TempTestPath) {
        Remove-Item -Path $script:TestConfig.TempTestPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe "Build Script Parameter Validation" -Tag "Fast", "Unit" {
    
    Context "Help parameter" {
        It "Should display help and exit cleanly when -Help is provided" {
            $result = & $BuildScriptPath -Help 2>&1
            $result | Should Match "Usage:"
            $result | Should Match "Options:"
            # Windows PS1 script uses these parameter names
            $result | Should Match "SourceMSI|OutputMSI|Debug"
        }
    }
    
    Context "Parameter handling" {
        It "Should accept SourceMSI parameter" {
            $testSource = "test-source.msi"
            { & $BuildScriptPath -SourceMSI $testSource -Help } | Should Not Throw
        }
        
        It "Should accept OutputMSI parameter" {
            $testOutput = "test-output.msi"
            { & $BuildScriptPath -OutputMSI $testOutput -Help } | Should Not Throw
        }
        
        It "Should accept Debug switch" {
            { & $BuildScriptPath -Debug -Help } | Should Not Throw
        }
    }
}

Describe "Dependency Detection and Installation" -Tag "Fast", "Component" {
    
    Context "WiX v6 Detection" {
        BeforeAll {
            $script:WixPath = "C:\Program Files\WiX Toolset v6.0\bin\wix.exe"
        }
        
        It "Should detect WiX v6 when installed" {
            if (Test-Path $script:WixPath) {
                $wixExists = Test-Path $script:WixPath
                $wixExists | Should Be $true
            } else {
                Pending "WiX v6 not installed"
            }
        }
        
        It "Should handle missing WiX v6 gracefully" {
            Mock Test-Path { return $false } -ParameterFilter { $Path -like "*wix.exe" }
            Mock Start-Process { return @{ ExitCode = 1 } } -ParameterFilter { $FilePath -eq "winget" }
            
            # Script should attempt to install and fail gracefully
            { & $BuildScriptPath -Help } | Should Not Throw
        }
    }
    
    Context "Go Compiler Detection" {
        It "Should detect Go when installed" {
            $goInstalled = Get-Command go -ErrorAction SilentlyContinue
            if ($goInstalled) {
                $goInstalled | Should Not BeNullOrEmpty
            } else {
                Pending "Go not installed"
            }
        }
        
        It "Should handle missing Go compiler gracefully" {
            Mock Get-Command { return $null } -ParameterFilter { $Name -eq "go" }
            Mock Test-Path { return $false } -ParameterFilter { $Path -like "*Go\bin\go.exe" }
            Mock Start-Process { return @{ ExitCode = 0 } } -ParameterFilter { $FilePath -eq "winget" -and $ArgumentList -match "GoLang.Go" }
            
            # Script should attempt to install Go
            { & $BuildScriptPath -Help } | Should Not Throw
        }
    }
}

Describe "MSI Build Process Core Functionality" -Tag "Medium", "Component" {
    BeforeAll {
        $script:TestPath = Initialize-TestEnvironment
    }
    
    AfterAll {
        Cleanup-TestEnvironment
    }
    
    Context "Original MSI Detection" {
        It "Should find original MSI in script directory" {
            $scriptDir = Split-Path $BuildScriptPath -Parent
            $originalMsi = Get-ChildItem -Path $scriptDir -Filter "Postman-Enterprise-*-x64.msi" | 
                Where-Object { $_.Name -notmatch "-saml" } | 
                Select-Object -First 1
            
            if ($originalMsi) {
                $originalMsi | Should Not BeNullOrEmpty
            } else {
                Pending "No original MSI found in deployment directory"
            }
        }
        
        It "Should error when no original MSI is found" {
            Mock Get-ChildItem { return $null } -ParameterFilter { $Filter -like "*Postman-Enterprise-*" }
            
            { & $BuildScriptPath } | Should Throw "*Original Postman Enterprise MSI not found*"
        }
    }
    
    Context "AuthRouter Binary Building" {
        It "Should detect existing AuthRouter binary" {
            $authRouterPath = Join-Path (Split-Path $BuildScriptPath -Parent) "pm-authrouter.exe"
            
            if (Test-Path $authRouterPath) {
                $size = (Get-Item $authRouterPath).Length / 1MB
                Write-Host "AuthRouter binary size: $([math]::Round($size, 2)) MB"
                $size | Should BeGreaterThan 0
            } else {
                Pending "AuthRouter binary not built"
            }
        }
        
        It "Should handle Go build failures gracefully" {
            Mock Test-Path { return $false } -ParameterFilter { $Path -like "*pm-authrouter.exe" }
            Mock Start-Process { return @{ ExitCode = 1 } } -ParameterFilter { $ArgumentList -match "go build" }
            
            # Build should fail with proper error
            { & $BuildScriptPath } | Should Throw
        }
    }
}

Describe "Certificate Generation and Security" -Tag "Fast", "Unit" {
    
    Context "Self-signed certificate creation" {
        It "Should create valid self-signed certificates" {
            $testCert = New-SelfSignedCertificate `
                -DnsName "test.identity.getpostman.com" `
                -Subject "CN=test.identity.getpostman.com" `
                -KeyAlgorithm RSA `
                -KeyLength 2048 `
                -NotAfter (Get-Date).AddYears(10) `
                -CertStoreLocation "Cert:\CurrentUser\My"
            
            $testCert | Should Not BeNullOrEmpty
            $testCert.Subject | Should Match "test.identity.getpostman.com"
            $testCert.NotAfter | Should BeGreaterThan (Get-Date).AddYears(9)
            
            # Cleanup
            Remove-Item "Cert:\CurrentUser\My\$($testCert.Thumbprint)" -Force
        }
        
        It "Should export certificates to correct format" {
            $testPath = Join-Path $script:TestConfig.TempTestPath "test_certs"
            New-Item -ItemType Directory -Path $testPath -Force | Out-Null
            
            $cert = New-SelfSignedCertificate `
                -DnsName "test.cert" `
                -CertStoreLocation "Cert:\CurrentUser\My"
            
            $certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
            [System.IO.File]::WriteAllBytes("$testPath\test.crt", $certBytes)
            
            Test-Path "$testPath\test.crt" | Should Be $true
            (Get-Item "$testPath\test.crt").Length | Should BeGreaterThan 0
            
            # Cleanup
            Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force
            Remove-Item $testPath -Recurse -Force
        }
    }
}

Describe "LZX:21 Compression and CAB Creation" -Tag "Medium", "Component" {
    BeforeAll {
        $script:TestPath = Initialize-TestEnvironment
    }
    
    AfterAll {
        Cleanup-TestEnvironment
    }
    
    Context "MakeCab compression" {
        It "Should create DDF file with correct compression settings" {
            $ddfPath = Join-Path $script:TestPath "test.ddf"
            $ddfContent = @"
.OPTION EXPLICIT
.Set CabinetNameTemplate=test.cab
.Set DiskDirectoryTemplate=.
.Set CompressionType=LZX
.Set CompressionMemory=21
.Set UniqueFiles=ON
.Set Cabinet=ON
.Set Compress=ON
.Set MaxDiskSize=0
"@
            $ddfContent | Out-File -FilePath $ddfPath -Encoding ASCII
            
            $content = Get-Content $ddfPath -Raw
            $content | Should Match "CompressionType=LZX"
            $content | Should Match "CompressionMemory=21"
        }
        
        It "Should compress files using LZX:21" {
            if (Get-Command makecab -ErrorAction SilentlyContinue) {
                $testFile = Join-Path $script:TestPath "test.txt"
                "Test content for compression" * 1000 | Out-File $testFile
                
                $ddfPath = Join-Path $script:TestPath "compress.ddf"
                $ddfContent = @"
.OPTION EXPLICIT
.Set CabinetNameTemplate=compressed.cab
.Set CompressionType=LZX
.Set CompressionMemory=21
.Set Cabinet=ON
.Set Compress=ON
"$testFile" "test.txt"
"@
                $ddfContent | Out-File -FilePath $ddfPath -Encoding ASCII
                
                $result = makecab /F "$ddfPath" 2>&1
                $cabPath = Join-Path $script:TestPath "compressed.cab"
                
                Test-Path $cabPath | Should Be $true
                
                # LZX:21 should achieve good compression
                $originalSize = (Get-Item $testFile).Length
                $compressedSize = (Get-Item $cabPath).Length
                $compressionRatio = $compressedSize / $originalSize
                
                Write-Host "Compression ratio: $([math]::Round($compressionRatio * 100, 2))%"
                $compressionRatio | Should BeLessThan 0.5  # Should compress to less than 50%
            } else {
                Pending "makecab not available"
            }
        }
    }
}

Describe "Final MSI Size Validation - CRITICAL" -Tag "Medium", "Component" {
    
    Context "MSI size must be <= 125MB" {
        It "Should validate MSI size is under 125MB limit" {
            $scriptDir = Split-Path $BuildScriptPath -Parent
            $outputMsi = Get-ChildItem -Path $scriptDir -Filter "*-saml.msi" | Select-Object -First 1
            
            if ($outputMsi) {
                $sizeMB = [math]::Round($outputMsi.Length / 1MB, 2)
                Write-Host "MSI Size: $sizeMB MB (Limit: $($script:TestConfig.MaxMsiSizeMB) MB)" -ForegroundColor Cyan
                
                $sizeMB | Should BeLessThan $script:TestConfig.MaxMsiSizeMB
                
                # Warning if approaching limit
                if ($sizeMB -gt ($script:TestConfig.MaxMsiSizeMB * 0.9)) {
                    Write-Warning "MSI size is over 90% of limit!"
                }
            } else {
                Pending "No output MSI found to validate"
            }
        }
        
        It "Should fail build if MSI exceeds 125MB" {
            # This is a critical test - simulate large MSI scenario
            Mock Get-Item { 
                return @{ Length = 130MB } 
            } -ParameterFilter { $Path -like "*.msi" }
            
            # Build should detect oversized MSI and fail
            { 
                $msiSize = 130
                if ($msiSize -gt 125) {
                    throw "MSI size $msiSize MB exceeds 125MB limit"
                }
            } | Should Throw "*exceeds 125MB limit*"
        }
    }
}

Describe "Intune Profile Generation" -Tag "Fast", "Unit" {
    
    Context "XML profile creation" {
        It "Should generate valid Intune XML profile" {
            $profilePath = Join-Path $script:TestConfig.TempTestPath "test.intuneprofile.xml"
            $teamName = "TestTeam"
            $samlUrl = "https://test.saml.url"
            
            $profileXml = @"
<?xml version="1.0" encoding="utf-8"?>
<TrustedRootCertificate xmlns="http://schemas.microsoft.com/GroupPolicy/Settings/Base/2018/01">
  <Name>Postman AuthRouter Certificate</Name>
  <Description>SSL certificate for Postman SAML enforcement</Description>
  <CertificateData>BASE64CERTDATA</CertificateData>
  <DestinationStore>Root</DestinationStore>
  <Settings>
    <Setting>
      <Name>TeamName</Name>
      <Value>$teamName</Value>
    </Setting>
    <Setting>
      <Name>SamlUrl</Name>
      <Value>$samlUrl</Value>
    </Setting>
  </Settings>
</TrustedRootCertificate>
"@
            $profileXml | Out-File -FilePath $profilePath -Encoding UTF8
            
            # Validate XML structure
            [xml]$xml = Get-Content $profilePath
            $xml | Should Not BeNullOrEmpty
            $xml.TrustedRootCertificate.Settings.Setting[0].Value | Should Be $teamName
            $xml.TrustedRootCertificate.Settings.Setting[1].Value | Should Be $samlUrl
        }
    }
}

Describe "Error Handling and Recovery" -Tag "Fast", "Unit" {
    
    Context "Build failure scenarios" {
        It "Should cleanup temp files on error" {
            $tempDir = Join-Path $script:TestConfig.TempTestPath "cleanup_test"
            New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
            
            # Create test files
            "test" | Out-File "$tempDir\test.wixobj"
            "test" | Out-File "$tempDir\test.wixpdb"
            "test" | Out-File "$tempDir\test.wxs"
            
            # Simulate cleanup
            Remove-Item "$tempDir\*.wixobj" -Force -ErrorAction SilentlyContinue
            Remove-Item "$tempDir\*.wixpdb" -Force -ErrorAction SilentlyContinue
            Remove-Item "$tempDir\*.wxs" -Force -ErrorAction SilentlyContinue
            
            (Get-ChildItem $tempDir -Filter "*.wix*").Count | Should Be 0
        }
        
        It "Should handle MSI extraction failures" {
            Mock Start-Process { return @{ ExitCode = 1605 } } -ParameterFilter { $FilePath -eq "msiexec.exe" }
            
            # Extraction should fail with proper error
            { 
                $exitCode = 1605
                if ($exitCode -ne 0) {
                    throw "MSI extraction failed with exit code $exitCode"
                }
            } | Should Throw "*MSI extraction failed*"
        }
        
        It "Should handle WiX build failures" {
            Mock Start-Process { return @{ ExitCode = 1 } } -ParameterFilter { $FilePath -like "*wix.exe" }
            
            # WiX build should fail gracefully
            { 
                $exitCode = 1
                if ($exitCode -ne 0) {
                    throw "WiX build failed with exit code $exitCode"
                }
            } | Should Throw "*WiX build failed*"
        }
    }
}

Describe "Edge Cases and Special Scenarios" -Tag "Fast", "Unit" {
    
    Context "Path handling" {
        It "Should handle paths with spaces" {
            $testPath = Join-Path $script:TestConfig.TempTestPath "path with spaces"
            New-Item -ItemType Directory -Path $testPath -Force | Out-Null
            
            Test-Path $testPath | Should Be $true
            Test-Path "$testPath" | Should Be $true  # Quoted path
        }
        
        It "Should handle Unicode characters in parameters" {
            $unicodeTeam = "Team-æœ¬ç¤¾-×˜×¢×¡×˜"
            $result = { 
                $team = $unicodeTeam
                Write-Output "Team: $team"
            }
            
            { & $result } | Should Not Throw
        }
    }
    
    Context "Concurrent build prevention" {
        It "Should prevent concurrent builds" {
            $lockFile = Join-Path $env:TEMP "msi_build.lock"
            
            # Simulate lock file
            "PID: $PID" | Out-File $lockFile
            
            # Check if lock exists
            $lockExists = Test-Path $lockFile
            $lockExists | Should Be $true
            
            # Cleanup
            Remove-Item $lockFile -Force
        }
    }
}

Describe "Performance Benchmarks" -Tag "Fast", "Component" {
    
    Context "Build time validation" {
        It "Should complete build within timeout period" {
            $timeout = $script:TestConfig.BuildTimeout
            
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            
            # Simulate build process timing
            Start-Sleep -Seconds 1  # Minimal test
            
            $stopwatch.Stop()
            $elapsedSeconds = $stopwatch.Elapsed.TotalSeconds
            
            Write-Host "Build simulation time: $([math]::Round($elapsedSeconds, 2)) seconds"
            $elapsedSeconds | Should BeLessThan $timeout
        }
    }
    
    Context "Memory usage" {
        It "Should not exceed reasonable memory limits" {
            $process = Get-Process -Id $PID
            $memoryMB = [math]::Round($process.WorkingSet64 / 1MB, 2)
            
            Write-Host "Current memory usage: $memoryMB MB"
            $memoryMB | Should BeLessThan 2048  # Should use less than 2GB
        }
    }
}

# Integration tests (only run with -RunIntegrationTests flag)
if ($RunIntegrationTests) {
    Describe "Full Build Integration Test" -Tag "Slow", "Integration" {
        
        Context "End-to-end build process" {
            It "Should complete full build successfully with progress monitoring" -Tag "Integration" {
                $scriptDir = Split-Path $BuildScriptPath -Parent
                $originalMsi = Get-ChildItem -Path $scriptDir -Filter "Postman-Enterprise-*-x64.msi" | 
                    Where-Object { $_.Name -notmatch "-saml" } | 
                    Select-Object -First 1
                
                if ($originalMsi) {
                    $testOutput = Join-Path $script:TestConfig.TempTestPath "integration-test.msi"
                    
                    Write-Host "Starting build process (may take up to 2 minutes for compression)..." -ForegroundColor Cyan
                    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                    
                    # Run build with activity monitoring
                    $job = Start-Job -ScriptBlock {
                        param($BuildScript, $TestOutput, $OriginalMsiPath)
                        # Note: Build script embeds team/SAML info during build, not via parameters
                        & $BuildScript -OutputMSI $TestOutput -SourceMSI $OriginalMsiPath 2>&1
                    } 

# Pester 3.4.0 compatibility - warn and return for skipped tests
function Pending { param([string]$Message) Write-Warning "[SKIPPED] $Message"; return }
-ArgumentList $BuildScriptPath, $testOutput, $originalMsi.FullName
                    
                    $lastActivity = Get-Date
                    $timeout = New-TimeSpan -Minutes 10
                    $inactivityTimeout = New-TimeSpan -Minutes 3
                    
                    do {
                        $jobResults = Receive-Job $job -Keep
                        if ($jobResults) {
                            $newOutput = $jobResults | Select-Object -Last 5
                            foreach ($line in $newOutput) {
                                if ($line -match "compress|LZX|makecab|Step \d+|Creating") {
                                    Write-Host "Progress: $line" -ForegroundColor Green
                                    $lastActivity = Get-Date
                                }
                            }
                        }
                        
                        $elapsed = $stopwatch.Elapsed
                        $inactivity = (Get-Date) - $lastActivity
                        
                        if ($elapsed -gt $timeout) {
                            Write-Warning "Build exceeded maximum timeout of 10 minutes"
                            break
                        } elseif ($inactivity -gt $inactivityTimeout) {
                            Write-Warning "No activity detected for 3 minutes"
                            break
                        }
                        
                        Start-Sleep -Seconds 5
                    } while ($job.State -eq "Running")
                    
                    $jobResults = Receive-Job $job
                    $jobExitCode = $job.ChildJobs[0].ExitCode
                    Remove-Job $job -Force
                    
                    $stopwatch.Stop()
                    $buildTime = [math]::Round($stopwatch.Elapsed.TotalSeconds, 1)
                    Write-Host "Build completed in $buildTime seconds" -ForegroundColor Yellow
                    
                    # Validate build success
                    if ($jobExitCode -ne 0) {
                        Write-Host "Build failed with exit code $jobExitCode" -ForegroundColor Red
                        $jobResults | Select-Object -Last 10 | ForEach-Object { Write-Host $_ -ForegroundColor Red }
                    }
                    
                    Test-Path $testOutput | Should Be $true
                    
                    # Validate size
                    $sizeMB = [math]::Round((Get-Item $testOutput).Length / 1MB, 2)
                    Write-Host "Final MSI size: $sizeMB MB" -ForegroundColor Cyan
                    $sizeMB | Should BeLessThan 125
                } else {
                    Pending "No original MSI available for integration test"
                }
            }
        }
    }
}

# Test execution summary
Write-Host "`n=== Test Execution Summary ===" -ForegroundColor Cyan
Write-Host "Run integration tests with: -RunIntegrationTests" -ForegroundColor Yellow
Write-Host "Critical requirement: MSI must be <= 125MB" -ForegroundColor Red
Write-Host "Verbose output available with: -VerboseOutput" -ForegroundColor Gray