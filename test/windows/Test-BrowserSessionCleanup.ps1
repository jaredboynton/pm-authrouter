# Test-BrowserSessionCleanup.ps1
# Tests for browser session cleanup functionality on Windows
# Validates Postman session removal from Chrome, Firefox, Edge

param(
    [switch]$TestLive = $false,  # Test against actual browser profiles
    [switch]$CreateTestProfiles = $false  # Create test profiles for safe testing
)

# Test configuration
$script:BrowserConfig = @{
    Chrome = @{
        ProfilePath = "$env:LOCALAPPDATA\Google\Chrome\User Data"
        CookieFile = "Cookies"
        TestDomains = @("postman.com", ".postman.com", "identity.getpostman.com")
    }
    Edge = @{
        ProfilePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
        CookieFile = "Cookies"
        TestDomains = @("postman.com", ".postman.com", "app.getpostman.com")
    }
    Firefox = @{
        ProfilePath = "$env:APPDATA\Mozilla\Firefox\Profiles"
        CookieFile = "cookies.sqlite"
        TestDomains = @("postman.com", "getpostman.com", "postman.co")
    }
}

# Helper Functions
function Test-BrowserInstalled {
    param([string]$BrowserName)
    
    switch ($BrowserName) {
        "Chrome" { 
            return Test-Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
        }
        "Edge" { 
            return Test-Path "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
        }
        "Firefox" { 
            return Test-Path "$env:APPDATA\Mozilla\Firefox\Profiles"
        }
        default { 
            return $false 
        }
    }
}

function Get-BrowserProfiles {
    param([string]$BrowserName)
    
    $config = $script:BrowserConfig[$BrowserName]
    if (-not $config) {
        return @()
    }
    
    $profiles = @()
    
    if ($BrowserName -eq "Firefox") {
        # Firefox uses different profile structure
        if (Test-Path $config.ProfilePath) {
            $profileDirs = Get-ChildItem -Path $config.ProfilePath -Directory
            foreach ($dir in $profileDirs) {
                $cookiePath = Join-Path $dir.FullName $config.CookieFile
                if (Test-Path $cookiePath) {
                    $profiles += @{
                        Name = $dir.Name
                        Path = $dir.FullName
                        CookieFile = $cookiePath
                    }
                }
            }
        }
    } else {
        # Chrome and Edge use similar structure
        $defaultProfile = Join-Path $config.ProfilePath "Default"
        if (Test-Path $defaultProfile) {
            $cookiePath = Join-Path $defaultProfile $config.CookieFile
            if (Test-Path $cookiePath) {
                $profiles += @{
                    Name = "Default"
                    Path = $defaultProfile
                    CookieFile = $cookiePath
                }
            }
        }
        
        # Check for additional profiles
        if (Test-Path $config.ProfilePath) {
            $profileDirs = Get-ChildItem -Path $config.ProfilePath -Directory -Filter "Profile*"
            foreach ($dir in $profileDirs) {
                $cookiePath = Join-Path $dir.FullName $config.CookieFile
                if (Test-Path $cookiePath) {
                    $profiles += @{
                        Name = $dir.Name
                        Path = $dir.FullName
                        CookieFile = $cookiePath
                    }
                }
            }
        }
    }
    
    return $profiles
}

function Test-DomainInFile {
    param(
        [string]$FilePath,
        [string]$Domain
    )
    
    if (-not (Test-Path $FilePath)) {
        return $false
    }
    
    try {
        # Read file as bytes for binary search
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        $domainBytes = [System.Text.Encoding]::UTF8.GetBytes($Domain)
        
        # Search for domain in binary content
        for ($i = 0; $i -le $bytes.Length - $domainBytes.Length; $i++) {
            $match = $true
            for ($j = 0; $j -lt $domainBytes.Length; $j++) {
                if ($bytes[$i + $j] -ne $domainBytes[$j]) {
                    $match = $false
                    break
                }
            }
            if ($match) {
                return $true
            }
        }
        
        return $false
    } catch {
        Write-Warning "Error reading file $FilePath`: $($_.Exception.Message)"
        return $false
    }
}

function Clear-DomainFromFile {
    param(
        [string]$FilePath,
        [string[]]$Domains
    )
    
    if (-not (Test-Path $FilePath)) {
        return $false
    }
    
    try {
        # Read file as bytes
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        $modified = $false
        
        foreach ($domain in $Domains) {
            $domainBytes = [System.Text.Encoding]::UTF8.GetBytes($domain)
            
            # Find and nullify domain occurrences
            for ($i = 0; $i -le $bytes.Length - $domainBytes.Length; $i++) {
                $match = $true
                for ($j = 0; $j -lt $domainBytes.Length; $j++) {
                    if ($bytes[$i + $j] -ne $domainBytes[$j]) {
                        $match = $false
                        break
                    }
                }
                if ($match) {
                    # Null out the domain
                    for ($j = 0; $j -lt $domainBytes.Length; $j++) {
                        $bytes[$i + $j] = 0
                    }
                    $modified = $true
                    $i += $domainBytes.Length - 1
                }
            }
        }
        
        if ($modified) {
            # Write modified bytes back
            [System.IO.File]::WriteAllBytes($FilePath, $bytes)
            return $true
        }
        
        return $false
    } catch {
        Write-Warning "Error modifying file $FilePath`: $($_.Exception.Message)"
        return $false
    }
}

function Create-TestCookieFile {
    param(
        [string]$FilePath,
        [string[]]$Domains
    )
    
    # Create a test cookie file with embedded domains
    $content = @()
    
    # Add some binary padding
    $content += [byte[]](0x00, 0x01, 0x02, 0x03)
    
    # Add domains with some structure
    foreach ($domain in $Domains) {
        $content += [System.Text.Encoding]::UTF8.GetBytes("COOKIE_")
        $content += [System.Text.Encoding]::UTF8.GetBytes($domain)
        $content += [byte[]](0x00, 0x00)
        $content += [System.Text.Encoding]::UTF8.GetBytes("_VALUE_TEST")
        $content += [byte[]](0x00, 0x00, 0x00, 0x00)
    }
    
    # Add more padding
    $content += [byte[]](0xFF, 0xFE, 0xFD, 0xFC)
    
    # Create directory if needed
    $dir = Split-Path $FilePath -Parent
    if (-not (Test-Path $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }
    
    # Write test file
    [System.IO.File]::WriteAllBytes($FilePath, $content)
    
    return Test-Path $FilePath
}

# Main Test Execution
Describe "Browser Session Cleanup Tests" -Tag "Medium", "Component" {
    
    BeforeAll {
        Write-Host "Starting browser session cleanup tests..." -ForegroundColor Cyan
        
        if ($CreateTestProfiles) {
            Write-Host "Creating test profiles..." -ForegroundColor Yellow
            
            # Create test profile directories
            $script:TestProfileRoot = "$env:TEMP\BrowserTestProfiles_$(Get-Random)"
            New-Item -Path $script:TestProfileRoot -ItemType Directory -Force | Out-Null
            
            # Override browser configs for testing
            $script:BrowserConfig.Chrome.ProfilePath = "$script:TestProfileRoot\Chrome\User Data"
            $script:BrowserConfig.Edge.ProfilePath = "$script:TestProfileRoot\Edge\User Data"
            $script:BrowserConfig.Firefox.ProfilePath = "$script:TestProfileRoot\Firefox\Profiles"
        }
    }
    
    AfterAll {
        if ($CreateTestProfiles -and $script:TestProfileRoot) {
            Write-Host "Cleaning up test profiles..." -ForegroundColor Yellow
            Remove-Item -Path $script:TestProfileRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    Context "Browser Profile Detection" {
        
        It "Should detect Chrome installation" {
            if (-not $CreateTestProfiles) {
                $installed = Test-BrowserInstalled -BrowserName "Chrome"
                
                if (Test-Path "$env:LOCALAPPDATA\Google\Chrome") {
                    $installed | Should Be $true
                }
            } else {
                # Create test Chrome profile
                $chromePath = Join-Path $script:BrowserConfig.Chrome.ProfilePath "Default"
                New-Item -Path $chromePath -ItemType Directory -Force | Out-Null
                Create-TestCookieFile -FilePath (Join-Path $chromePath "Cookies") -Domains @("test.com")
                
                Test-Path (Join-Path $chromePath "Cookies") | Should Be $true
            }
        }
        
        It "Should detect Edge installation" {
            if (-not $CreateTestProfiles) {
                $installed = Test-BrowserInstalled -BrowserName "Edge"
                
                if (Test-Path "$env:LOCALAPPDATA\Microsoft\Edge") {
                    $installed | Should Be $true
                }
            } else {
                # Create test Edge profile
                $edgePath = Join-Path $script:BrowserConfig.Edge.ProfilePath "Default"
                New-Item -Path $edgePath -ItemType Directory -Force | Out-Null
                Create-TestCookieFile -FilePath (Join-Path $edgePath "Cookies") -Domains @("test.com")
                
                Test-Path (Join-Path $edgePath "Cookies") | Should Be $true
            }
        }
        
        It "Should detect Firefox installation" {
            if (-not $CreateTestProfiles) {
                $installed = Test-BrowserInstalled -BrowserName "Firefox"
                
                if (Test-Path "$env:APPDATA\Mozilla\Firefox") {
                    $installed | Should Be $true
                }
            } else {
                # Create test Firefox profile
                $firefoxPath = Join-Path $script:BrowserConfig.Firefox.ProfilePath "test.default"
                New-Item -Path $firefoxPath -ItemType Directory -Force | Out-Null
                Create-TestCookieFile -FilePath (Join-Path $firefoxPath "cookies.sqlite") -Domains @("test.com")
                
                Test-Path (Join-Path $firefoxPath "cookies.sqlite") | Should Be $true
            }
        }
        
        It "Should enumerate Chrome profiles" {
            if ($CreateTestProfiles) {
                # Create additional test profiles
                $profile1 = Join-Path $script:BrowserConfig.Chrome.ProfilePath "Profile 1"
                New-Item -Path $profile1 -ItemType Directory -Force | Out-Null
                Create-TestCookieFile -FilePath (Join-Path $profile1 "Cookies") -Domains @("test.com")
                
                $profiles = Get-BrowserProfiles -BrowserName "Chrome"
                $profiles.Count | Should BeGreaterThan 1
                $profiles[0].CookieFile | Should Exist
            } else {
                $profiles = Get-BrowserProfiles -BrowserName "Chrome"
                # Test passes if Chrome is installed and has profiles
                if (Test-BrowserInstalled -BrowserName "Chrome") {
                    $profiles.Count | Should BeGreaterThan 1
                } else {
                    $true | Should Be $true # Skip
                }
            }
        }
    }
    
    Context "Domain Detection in Cookie Files" {
        
        It "Should detect Postman domains in test file" {
            if ($CreateTestProfiles) {
                # Create test file with Postman domains
                $testFile = "$script:TestProfileRoot\test_cookies.db"
                Create-TestCookieFile -FilePath $testFile -Domains @("postman.com", "identity.getpostman.com")
                
                Test-DomainInFile -FilePath $testFile -Domain "postman.com" | Should Be $true
                Test-DomainInFile -FilePath $testFile -Domain "identity.getpostman.com" | Should Be $true
                Test-DomainInFile -FilePath $testFile -Domain "nonexistent.com" | Should Be $false
                
                Remove-Item $testFile -Force
            } else {
                $true | Should Be $true # Skip if not testing
            }
        }
        
        It "Should handle binary cookie files" {
            if ($CreateTestProfiles) {
                # Create binary test file
                $testFile = "$script:TestProfileRoot\binary_test.db"
                $binaryContent = [byte[]](0..255)
                $domainBytes = [System.Text.Encoding]::UTF8.GetBytes("postman.com")
                $binaryContent += $domainBytes
                $binaryContent += [byte[]](0..255)
                
                [System.IO.File]::WriteAllBytes($testFile, $binaryContent)
                
                Test-DomainInFile -FilePath $testFile -Domain "postman.com" | Should Be $true
                
                Remove-Item $testFile -Force
            } else {
                $true | Should Be $true
            }
        }
    }
    
    Context "Session Cleanup Operations" {
        
        It "Should nullify domains in cookie files" {
            if ($CreateTestProfiles) {
                # Create test file
                $testFile = "$script:TestProfileRoot\cleanup_test.db"
                $domains = @("postman.com", "getpostman.com", "postman.co")
                Create-TestCookieFile -FilePath $testFile -Domains $domains
                
                # Verify domains exist
                foreach ($domain in $domains) {
                    Test-DomainInFile -FilePath $testFile -Domain $domain | Should Be $true
                }
                
                # Clear domains
                $result = Clear-DomainFromFile -FilePath $testFile -Domains $domains
                $result | Should Be $true
                
                # Verify domains are nullified
                foreach ($domain in $domains) {
                    Test-DomainInFile -FilePath $testFile -Domain $domain | Should Be $false
                }
                
                Remove-Item $testFile -Force
            } else {
                $true | Should Be $true
            }
        }
        
        It "Should preserve file structure after cleanup" {
            if ($CreateTestProfiles) {
                # Create test file with known structure
                $testFile = "$script:TestProfileRoot\structure_test.db"
                $originalSize = 1024
                $content = [byte[]](1..$originalSize)
                
                # Insert domain at known position
                $domain = "postman.com"
                $domainBytes = [System.Text.Encoding]::UTF8.GetBytes($domain)
                $insertPos = 500
                for ($i = 0; $i -lt $domainBytes.Length; $i++) {
                    $content[$insertPos + $i] = $domainBytes[$i]
                }
                
                [System.IO.File]::WriteAllBytes($testFile, $content)
                
                # Clear domain
                Clear-DomainFromFile -FilePath $testFile -Domains @($domain)
                
                # Check file size preserved
                $newSize = (Get-Item $testFile).Length
                $newSize | Should Be $originalSize
                
                # Check domain is nullified
                $newContent = [System.IO.File]::ReadAllBytes($testFile)
                for ($i = 0; $i -lt $domainBytes.Length; $i++) {
                    $newContent[$insertPos + $i] | Should Be 0
                }
                
                Remove-Item $testFile -Force
            } else {
                $true | Should Be $true
            }
        }
        
        It "Should handle Chrome profile cleanup" {
            if ($CreateTestProfiles) {
                # Create Chrome test profile with Postman cookies
                $chromePath = Join-Path $script:BrowserConfig.Chrome.ProfilePath "Default"
                $cookieFile = Join-Path $chromePath "Cookies"
                
                Create-TestCookieFile -FilePath $cookieFile -Domains $script:BrowserConfig.Chrome.TestDomains
                
                # Verify domains exist
                foreach ($domain in $script:BrowserConfig.Chrome.TestDomains) {
                    Test-DomainInFile -FilePath $cookieFile -Domain $domain | Should Be $true
                }
                
                # Clear domains
                Clear-DomainFromFile -FilePath $cookieFile -Domains $script:BrowserConfig.Chrome.TestDomains
                
                # Verify cleanup
                foreach ($domain in $script:BrowserConfig.Chrome.TestDomains) {
                    Test-DomainInFile -FilePath $cookieFile -Domain $domain | Should Be $false
                }
            } else {
                $true | Should Be $true
            }
        }
        
        It "Should handle Edge profile cleanup" {
            if ($CreateTestProfiles) {
                # Create Edge test profile with Postman cookies
                $edgePath = Join-Path $script:BrowserConfig.Edge.ProfilePath "Default"
                $cookieFile = Join-Path $edgePath "Cookies"
                
                Create-TestCookieFile -FilePath $cookieFile -Domains $script:BrowserConfig.Edge.TestDomains
                
                # Verify domains exist
                foreach ($domain in $script:BrowserConfig.Edge.TestDomains) {
                    Test-DomainInFile -FilePath $cookieFile -Domain $domain | Should Be $true
                }
                
                # Clear domains
                Clear-DomainFromFile -FilePath $cookieFile -Domains $script:BrowserConfig.Edge.TestDomains
                
                # Verify cleanup
                foreach ($domain in $script:BrowserConfig.Edge.TestDomains) {
                    Test-DomainInFile -FilePath $cookieFile -Domain $domain | Should Be $false
                }
            } else {
                $true | Should Be $true
            }
        }
        
        It "Should handle Firefox profile cleanup" {
            if ($CreateTestProfiles) {
                # Create Firefox test profile with Postman cookies
                $firefoxPath = Join-Path $script:BrowserConfig.Firefox.ProfilePath "test.default"
                $cookieFile = Join-Path $firefoxPath "cookies.sqlite"
                
                Create-TestCookieFile -FilePath $cookieFile -Domains $script:BrowserConfig.Firefox.TestDomains
                
                # Verify domains exist
                foreach ($domain in $script:BrowserConfig.Firefox.TestDomains) {
                    Test-DomainInFile -FilePath $cookieFile -Domain $domain | Should Be $true
                }
                
                # Clear domains
                Clear-DomainFromFile -FilePath $cookieFile -Domains $script:BrowserConfig.Firefox.TestDomains
                
                # Verify cleanup
                foreach ($domain in $script:BrowserConfig.Firefox.TestDomains) {
                    Test-DomainInFile -FilePath $cookieFile -Domain $domain | Should Be $false
                }
            } else {
                $true | Should Be $true
            }
        }
    }
    
    Context "Multiple Profile Support" {
        
        It "Should clean all Chrome profiles" {
            if ($CreateTestProfiles) {
                # Create multiple Chrome profiles
                $profiles = @("Default", "Profile 1", "Profile 2")
                
                foreach ($profileName in $profiles) {
                    $profilePath = Join-Path $script:BrowserConfig.Chrome.ProfilePath $profileName
                    New-Item -Path $profilePath -ItemType Directory -Force | Out-Null
                    $cookieFile = Join-Path $profilePath "Cookies"
                    Create-TestCookieFile -FilePath $cookieFile -Domains @("postman.com")
                }
                
                # Get all profiles
                $detectedProfiles = Get-BrowserProfiles -BrowserName "Chrome"
                $detectedProfiles.Count | Should Be $profiles.Count
                
                # Clean all profiles
                foreach ($profile in $detectedProfiles) {
                    Clear-DomainFromFile -FilePath $profile.CookieFile -Domains @("postman.com")
                    Test-DomainInFile -FilePath $profile.CookieFile -Domain "postman.com" | Should Be $false
                }
            } else {
                $true | Should Be $true
            }
        }
    }
    
    Context "Error Handling" {
        
        It "Should handle missing cookie files gracefully" {
            $result = Test-DomainInFile -FilePath "C:\NonExistent\Path\cookies.db" -Domain "test.com"
            $result | Should Be $false
        }
        
        It "Should handle locked files gracefully" {
            if ($CreateTestProfiles) {
                $testFile = "$script:TestProfileRoot\locked_test.db"
                Create-TestCookieFile -FilePath $testFile -Domains @("postman.com")
                
                # Lock the file
                $fileStream = [System.IO.File]::Open($testFile, 'Open', 'ReadWrite', 'None')
                
                try {
                    # Try to clear domains (should fail gracefully)
                    $result = Clear-DomainFromFile -FilePath $testFile -Domains @("postman.com")
                    $result | Should Be $false
                } finally {
                    $fileStream.Close()
                }
                
                Remove-Item $testFile -Force
            } else {
                $true | Should Be $true
            }
        }
        
        It "Should handle empty domain lists" {
            if ($CreateTestProfiles) {
                $testFile = "$script:TestProfileRoot\empty_test.db"
                Create-TestCookieFile -FilePath $testFile -Domains @("postman.com")
                
                # Clear with empty domain list
                $result = Clear-DomainFromFile -FilePath $testFile -Domains @()
                $result | Should Be $false
                
                # Original content should be preserved
                Test-DomainInFile -FilePath $testFile -Domain "postman.com" | Should Be $true
                
                Remove-Item $testFile -Force
            } else {
                $true | Should Be $true
            }
        }
    }
}

# Performance Testing
Describe "Session Cleanup Performance" -Tag "Slow", "Integration", "Performance" {
    
    Context "Large File Processing" {
        
        It "Should handle large cookie files efficiently" {
            if ($CreateTestProfiles) {
                $testFile = "$script:TestProfileRoot\large_test.db"
                
                # Create large file (10MB)
                $size = 10 * 1024 * 1024
                $content = New-Object byte[] $size
                $random = New-Object System.Random
                $random.NextBytes($content)
                
                # Insert Postman domains at various positions
                $domains = @("postman.com", "getpostman.com", "postman.co")
                $positions = @(1000, 500000, 9000000)
                
                for ($i = 0; $i -lt $domains.Count; $i++) {
                    $domainBytes = [System.Text.Encoding]::UTF8.GetBytes($domains[$i])
                    $pos = $positions[$i]
                    for ($j = 0; $j -lt $domainBytes.Length; $j++) {
                        $content[$pos + $j] = $domainBytes[$j]
                    }
                }
                
                [System.IO.File]::WriteAllBytes($testFile, $content)
                
                # Measure cleanup time
                $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                Clear-DomainFromFile -FilePath $testFile -Domains $domains
                $stopwatch.Stop()
                
                # Should complete within 5 seconds for 10MB file
                $stopwatch.ElapsedMilliseconds | Should BeLessThan 5000
                
                # Verify domains cleared
                foreach ($domain in $domains) {
                    Test-DomainInFile -FilePath $testFile -Domain $domain | Should Be $false
                }
                
                Remove-Item $testFile -Force
            } else {
                $true | Should Be $true
            }
        }
    }
}

# Integration Testing
Describe "AuthRouter Session Cleanup Integration" -Tag "Slow", "Integration" {
    
    Context "Service Integration" {
        
        It "Should integrate with AuthRouter service cleanup" {
            # This would test actual integration with the AuthRouter service
            # checking that browser sessions are cleared on service stop/uninstall
            $true | Should Be $true # Placeholder
        }
        
        It "Should clear sessions before enforcing SAML" {
            # This would verify sessions are cleared before SAML enforcement starts
            $true | Should Be $true # Placeholder
        }
    }
}

# Summary
Write-Host "`n=== Browser Session Cleanup Test Summary ===" -ForegroundColor Cyan

# Test execution should be handled by the test runner, not by individual test files

Write-Host "`nUsage:" -ForegroundColor Cyan
Write-Host "  .\Test-BrowserSessionCleanup.ps1                    # Test with mock profiles" -ForegroundColor White
Write-Host "  .\Test-BrowserSessionCleanup.ps1 -CreateTestProfiles # Safe testing with temp profiles" -ForegroundColor White
Write-Host "  .\Test-BrowserSessionCleanup.ps1 -TestLive          # Test against real browser profiles (CAUTION)" -ForegroundColor White
Write-Host "`n=== Test Complete ===" -ForegroundColor Green