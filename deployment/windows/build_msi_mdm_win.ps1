# Postman Enterprise MSI Repackaging Script
# This script extracts the original MSI, adds custom files, and repackages it

param(
    [string]$TeamName = "",  # OPTIONAL: Team name for SAML configuration (can be set via MSI properties at install time)
    
    [string]$SamlUrl = "",  # OPTIONAL: SAML initialization URL (can be set via MSI properties at install time)
    
    [string]$SourceMSI = "",  # Will auto-detect or download if not specified
    [string]$OutputMSI = "",  # Will be auto-generated if not specified
    [string]$TempDir = "",  # Will be auto-generated if not specified
    [string]$WixPath = "C:\Program Files (x86)\WiX Toolset v3.11\bin",
    [switch]$Debug = $false,
    [switch]$ValidateCompression = $true,
    [ValidateSet('none', 'low', 'medium', 'high', 'mszip')]
    [string]$CompressionLevel = 'high',
    [switch]$KeepPDB = $false,
    [switch]$FastBuild = $false,
    [int]$Threads = $env:NUMBER_OF_PROCESSORS,
    [switch]$UseExistingCerts = $false,  # Use existing cert files instead of generating new ones
    [string]$LogFile = ""  # Optional log file path for CI/CD pipelines
)

# Set up script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrEmpty($scriptDir)) {
    $scriptDir = Get-Location
}

# Enhanced Structured Logging System with File Operation Tracking
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [string]$Component = "",
        [hashtable]$Metadata = @{}
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $processId = $PID
    $threadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId
    
    # Build structured log message
    $logParts = @(
        "[$timestamp]",
        "[PID:$processId]",
        "[TID:$threadId]",
        "[$Level]"
    )
    
    if (-not [string]::IsNullOrEmpty($Component)) {
        $logParts += "[$Component]"
    }
    
    $logMessage = ($logParts -join " ") + " $Message"
    
    # Add metadata if provided
    if ($Metadata.Count -gt 0) {
        $metadataString = ($Metadata.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join " "
        $logMessage += " | $metadataString"
    }
    
    # Write to console with appropriate colors
    switch ($Level) {
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        "DEBUG" { if ($Debug) { Write-Host $logMessage -ForegroundColor Cyan } }
        "TRACE" { if ($Debug) { Write-Host $logMessage -ForegroundColor Gray } }
        default { Write-Host $logMessage }
    }
    
    # Write to log file if specified
    if (-not [string]::IsNullOrEmpty($LogFile)) {
        try {
            # Ensure log directory exists
            $logDir = Split-Path $LogFile -Parent
            if (-not (Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            Add-Content -Path $LogFile -Value $logMessage -Encoding UTF8
        } catch {
            Write-Host "Failed to write to log file: $_" -ForegroundColor Red
        }
    }
}

# File operation tracking functions
function Write-FileOperation {
    param(
        [string]$Operation,
        [string]$SourcePath = "",
        [string]$DestinationPath = "",
        [string]$Status = "SUCCESS",
        [long]$FileSize = 0,
        [string]$Details = ""
    )
    
    $metadata = @{
        "Operation" = $Operation
        "Status" = $Status
    }
    
    if ($SourcePath) { $metadata["Source"] = $SourcePath }
    if ($DestinationPath) { $metadata["Destination"] = $DestinationPath }
    if ($FileSize -gt 0) { $metadata["Size"] = "$('{0:N0}' -f $FileSize)bytes" }
    if ($Details) { $metadata["Details"] = $Details }
    
    $message = "File operation: $Operation"
    if ($SourcePath -and $DestinationPath) {
        $message += " from '$SourcePath' to '$DestinationPath'"
    } elseif ($SourcePath) {
        $message += " on '$SourcePath'"
    }
    
    $level = if ($Status -eq "SUCCESS") { "INFO" } elseif ($Status -eq "WARNING") { "WARNING" } else { "ERROR" }
    Write-Log -Message $message -Level $level -Component "FileOps" -Metadata $metadata
}

function Start-OperationTimer {
    param([string]$OperationName)
    
    if (-not $script:OperationTimers) { $script:OperationTimers = @{} }
    $script:OperationTimers[$OperationName] = Get-Date
    Write-Log "Started: $OperationName" -Level INFO -Component "Timer"
}

function Stop-OperationTimer {
    param([string]$OperationName)
    
    if ($script:OperationTimers -and $script:OperationTimers.ContainsKey($OperationName)) {
        $duration = (Get-Date) - $script:OperationTimers[$OperationName]
        $metadata = @{ "Duration" = "$($duration.TotalSeconds)s" }
        Write-Log "Completed: $OperationName" -Level SUCCESS -Component "Timer" -Metadata $metadata
        $script:OperationTimers.Remove($OperationName)
    } else {
        Write-Log "Warning: Timer for '$OperationName' not found" -Level WARNING -Component "Timer"
    }
}

# Enhanced file operations with logging
function Copy-FileWithLogging {
    param(
        [string]$Source,
        [string]$Destination,
        [switch]$Force = $false
    )
    
    try {
        if (-not (Test-Path $Source)) {
            Write-FileOperation -Operation "COPY" -SourcePath $Source -Status "ERROR" -Details "Source file not found"
            return $false
        }
        
        $sourceInfo = Get-ItemProperty $Source
        $destinationDir = Split-Path $Destination -Parent
        
        # Ensure destination directory exists
        if (-not (Test-Path $destinationDir)) {
            New-Item -ItemType Directory -Path $destinationDir -Force | Out-Null
            Write-FileOperation -Operation "MKDIR" -DestinationPath $destinationDir -Status "SUCCESS"
        }
        
        # Perform the copy
        if ($Force) {
            Copy-Item $Source $Destination -Force
        } else {
            Copy-Item $Source $Destination
        }
        
        Write-FileOperation -Operation "COPY" -SourcePath $Source -DestinationPath $Destination -Status "SUCCESS" -FileSize $sourceInfo.Length
        return $true
        
    } catch {
        Write-FileOperation -Operation "COPY" -SourcePath $Source -DestinationPath $Destination -Status "ERROR" -Details $_.Exception.Message
        return $false
    }
}

function Remove-FileWithLogging {
    param(
        [string]$Path,
        [switch]$Recurse = $false,
        [switch]$Force = $false
    )
    
    try {
        if (-not (Test-Path $Path)) {
            Write-FileOperation -Operation "DELETE" -SourcePath $Path -Status "WARNING" -Details "Path not found"
            return $true  # Consider success if file doesn't exist
        }
        
        $itemInfo = Get-ItemProperty $Path
        $size = if ($itemInfo.PSIsContainer) { 0 } else { $itemInfo.Length }
        
        if ($Recurse -and $Force) {
            Remove-Item $Path -Recurse -Force
        } elseif ($Recurse) {
            Remove-Item $Path -Recurse
        } elseif ($Force) {
            Remove-Item $Path -Force
        } else {
            Remove-Item $Path
        }
        
        Write-FileOperation -Operation "DELETE" -SourcePath $Path -Status "SUCCESS" -FileSize $size
        return $true
        
    } catch {
        Write-FileOperation -Operation "DELETE" -SourcePath $Path -Status "ERROR" -Details $_.Exception.Message
        return $false
    }
}

# Function to check if running as administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Comprehensive Validation Framework - 5-Layer System
function Test-Environment {
    Write-Log "=== Phase 1: Environment Validation ===" -Level INFO
    $validationErrors = @()
    
    # Check administrator privileges
    if (-not (Test-Administrator)) {
        $validationErrors += "Must run as Administrator for MSI operations and certificate installation"
    }
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        $validationErrors += "PowerShell 5.0 or higher required (current: $($PSVersionTable.PSVersion))"
    }
    
    # Check available disk space (need at least 2GB for MSI operations)
    try {
        $systemDrive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" | 
                      Where-Object { $_.DeviceID -eq $env:SystemDrive } |
                      Select-Object -First 1
        if ($systemDrive) {
            $freeSpace = $systemDrive.FreeSpace
            if ($freeSpace -lt 2GB) {
                $validationErrors += "Insufficient disk space on $($systemDrive.DeviceID). Need at least 2GB free (current: $('{0:N2}' -f ($freeSpace/1GB))GB)"
            }
        } else {
            $validationErrors += "Cannot determine system drive disk space"
        }
    } catch {
        $validationErrors += "Failed to check disk space: $_"
    }
    
    # Check system architecture
    if ($env:PROCESSOR_ARCHITECTURE -ne "AMD64") {
        $validationErrors += "x64 architecture required (current: $($env:PROCESSOR_ARCHITECTURE))"
    }
    
    if ($validationErrors.Count -gt 0) {
        Write-Log "Environment validation failed:" -Level ERROR
        foreach ($error in $validationErrors) {
            Write-Log "  - $error" -Level ERROR
        }
        return $false
    }
    
    Write-Log "Environment validation passed" -Level SUCCESS
    return $true
}

function Test-Dependencies {
    Write-Log "=== Phase 2: Dependency Validation ===" -Level INFO
    $validationErrors = @()
    
    # Check Go installation
    try {
        $goVersion = & go version 2>$null
        if ($LASTEXITCODE -ne 0) {
            $validationErrors += "Go compiler not found or not in PATH"
        } else {
            Write-Log "Found Go: $goVersion" -Level INFO
            # Check minimum Go version (1.21+)
            if ($goVersion -match "go(\d+)\.(\d+)") {
                $major = [int]$matches[1]
                $minor = [int]$matches[2]
                if ($major -lt 1 -or ($major -eq 1 -and $minor -lt 21)) {
                    $validationErrors += "Go 1.21 or higher required (found: go$major.$minor)"
                }
            }
        }
    } catch {
        $validationErrors += "Go compiler not found: $_"
    }
    
    # Check WiX Toolset
    $wixFound = $false
    $wixPaths = @(
        $WixPath,
        "${env:ProgramFiles(x86)}\WiX Toolset v3.11\bin",
        "${env:ProgramFiles}\WiX Toolset v3.11\bin",
        "${env:ProgramFiles(x86)}\WiX Toolset v4.0\bin",
        "${env:ProgramFiles}\WiX Toolset v4.0\bin"
    )
    
    foreach ($path in $wixPaths) {
        if (Test-Path "$path\candle.exe" -and (Test-Path "$path\light.exe")) {
            $global:WixPath = $path
            $wixFound = $true
            Write-Log "Found WiX Toolset at: $path" -Level INFO
            break
        }
    }
    
    if (-not $wixFound) {
        $validationErrors += "WiX Toolset not found. Install WiX Toolset v3.11 or v4.0"
    }
    
    # Check MSI tools
    $msiexecPath = Get-Command msiexec -ErrorAction SilentlyContinue
    if (-not $msiexecPath) {
        $validationErrors += "msiexec.exe not found in system PATH"
    }
    
    if ($validationErrors.Count -gt 0) {
        Write-Log "Dependency validation failed:" -Level ERROR
        foreach ($error in $validationErrors) {
            Write-Log "  - $error" -Level ERROR
        }
        return $false
    }
    
    Write-Log "Dependency validation passed" -Level SUCCESS
    return $true
}

function Test-SourceFiles {
    Write-Log "=== Phase 3: Source File Validation ===" -Level INFO
    $validationErrors = @()
    
    # Check source MSI file
    if ([string]::IsNullOrEmpty($SourceMSI) -or (-not (Test-Path $SourceMSI))) {
        $validationErrors += "Source MSI file not found or not specified"
    } else {
        # Validate MSI file
        try {
            $msiInfo = Get-ItemProperty $SourceMSI
            if ($msiInfo.Length -lt 50MB) {
                $validationErrors += "Source MSI file seems too small ($('{0:N1}' -f ($msiInfo.Length/1MB))MB)"
            }
            Write-Log "Source MSI: $SourceMSI ($('{0:N1}' -f ($msiInfo.Length/1MB))MB)" -Level INFO
        } catch {
            $validationErrors += "Cannot read source MSI file: $_"
        }
    }
    
    # Check Go source files exist
    $goSourceFiles = @(
        "$scriptDir\..\..\cmd\pm-authrouter\main.go",
        "$scriptDir\..\..\go.mod"
    )
    
    foreach ($file in $goSourceFiles) {
        if (-not (Test-Path $file)) {
            $validationErrors += "Go source file not found: $file"
        }
    }
    
    # Check critical directories
    $requiredDirs = @(
        "$scriptDir\..\..\cmd\pm-authrouter",
        "$scriptDir\..\..\internal"
    )
    
    foreach ($dir in $requiredDirs) {
        if (-not (Test-Path $dir -PathType Container)) {
            $validationErrors += "Required directory not found: $dir"
        }
    }
    
    if ($validationErrors.Count -gt 0) {
        Write-Log "Source file validation failed:" -Level ERROR
        foreach ($error in $validationErrors) {
            Write-Log "  - $error" -Level ERROR
        }
        return $false
    }
    
    Write-Log "Source file validation passed" -Level SUCCESS
    return $true
}

function Test-BuildProcess {
    Write-Log "=== Phase 4: Build Process Validation ===" -Level INFO
    $validationErrors = @()
    
    # Test Go build capability
    try {
        Write-Log "Testing Go build capability..." -Level INFO
        $testDir = Join-Path $TempDir "build-test"
        New-Item -ItemType Directory -Path $testDir -Force | Out-Null
        
        # Create simple test program
        $testGoCode = @"
package main
import "fmt"
func main() {
    fmt.Println("Build test successful")
}
"@
        Set-Content -Path "$testDir\test.go" -Value $testGoCode -Encoding UTF8
        
        # Try cross-compilation build
        $env:GOOS = "windows"
        $env:GOARCH = "amd64"
        $env:CGO_ENABLED = "0"
        
        Push-Location $testDir
        try {
            & go build -o test.exe test.go 2>$null
            if ($LASTEXITCODE -ne 0 -or (-not (Test-Path "test.exe"))) {
                $validationErrors += "Go cross-compilation test failed"
            } else {
                Write-Log "Go build test successful" -Level INFO
            }
        } finally {
            Pop-Location
            Remove-Item $testDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    } catch {
        $validationErrors += "Go build test failed: $_"
    }
    
    # Check WiX tools functionality
    try {
        Write-Log "Testing WiX toolset functionality..." -Level INFO
        $candleVersion = & "$WixPath\candle.exe" -? 2>&1 | Select-String "version" | Select-Object -First 1
        if ($candleVersion) {
            Write-Log "WiX Candle available: $($candleVersion.ToString().Trim())" -Level INFO
        } else {
            $validationErrors += "WiX Candle tool not responding correctly"
        }
    } catch {
        $validationErrors += "WiX tools validation failed: $_"
    }
    
    if ($validationErrors.Count -gt 0) {
        Write-Log "Build process validation failed:" -Level ERROR
        foreach ($error in $validationErrors) {
            Write-Log "  - $error" -Level ERROR
        }
        return $false
    }
    
    Write-Log "Build process validation passed" -Level SUCCESS
    return $true
}

function Test-OutputValidation {
    param(
        [string]$OutputPath
    )
    
    Write-Log "=== Phase 5: Output Validation ===" -Level INFO
    $validationErrors = @()
    
    if (-not (Test-Path $OutputPath)) {
        $validationErrors += "Output MSI file was not created: $OutputPath"
        return $false
    }
    
    try {
        # Check file size (should be reasonable size for an MSI)
        $outputInfo = Get-ItemProperty $OutputPath
        $sizeMB = $outputInfo.Length / 1MB
        
        if ($sizeMB -lt 50) {
            $validationErrors += "Output MSI too small ($('{0:N1}' -f $sizeMB)MB) - likely incomplete"
        } elseif ($sizeMB -gt 200) {
            $validationErrors += "Output MSI too large ($('{0:N1}' -f $sizeMB)MB) - may have issues"
        } else {
            Write-Log "Output MSI size: $('{0:N1}' -f $sizeMB)MB" -Level INFO
        }
        
        # Try to read MSI properties using msiexec
        Write-Log "Validating MSI structure..." -Level INFO
        $tempValidationDir = Join-Path $TempDir "msi-validation"
        New-Item -ItemType Directory -Path $tempValidationDir -Force | Out-Null
        
        # Try to extract MSI to validate structure
        & msiexec /a "$OutputPath" /qn "TARGETDIR=$tempValidationDir" 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Log "MSI structure validation passed" -Level SUCCESS
            # Check for key files in extracted MSI
            $keyFiles = @("Postman.exe")
            foreach ($file in $keyFiles) {
                if (-not (Get-ChildItem $tempValidationDir -Recurse -Name $file -ErrorAction SilentlyContinue)) {
                    $validationErrors += "Key file missing from MSI: $file"
                }
            }
        } else {
            $validationErrors += "MSI structure validation failed - cannot extract MSI"
        }
        
        # Cleanup validation directory
        Remove-Item $tempValidationDir -Recurse -Force -ErrorAction SilentlyContinue
        
    } catch {
        $validationErrors += "Output validation failed: $_"
    }
    
    if ($validationErrors.Count -gt 0) {
        Write-Log "Output validation failed:" -Level ERROR
        foreach ($error in $validationErrors) {
            Write-Log "  - $error" -Level ERROR
        }
        return $false
    }
    
    Write-Log "Output validation passed" -Level SUCCESS
    return $true
}

# Function to generate or copy stable certificates from /ssl/ directory
function Ensure-StableCertificates {
    Write-Log "Checking for stable certificates..." -Level INFO
    
    # Find project root by locating go.mod
    $currentPath = $PSScriptRoot
    $projectRoot = $null
    
    while ($currentPath -ne [System.IO.Path]::GetPathRoot($currentPath)) {
        if (Test-Path (Join-Path $currentPath "go.mod")) {
            $projectRoot = $currentPath
            break
        }
        $currentPath = Split-Path $currentPath -Parent
    }
    
    if (-not $projectRoot) {
        Write-Log "Could not find project root (go.mod not found)" -Level ERROR
        throw "Project root not found"
    }
    
    $sslDir = Join-Path $projectRoot "ssl"
    
    $certPath = Join-Path $sslDir "identity.getpostman.com.crt"
    $keyPath = Join-Path $sslDir "identity.getpostman.com.key"
    
    # Generate certificates if they don't exist
    if (-not (Test-Path $certPath) -or -not (Test-Path $keyPath)) {
        Write-Log "Stable certificates not found, generating them now..." -Level INFO
        
        # Ensure SSL directory exists
        if (-not (Test-Path $sslDir)) {
            New-Item -ItemType Directory -Path $sslDir -Force | Out-Null
        }
        
        # Check if OpenSSL is available
        $opensslPath = $null
        $opensslPaths = @(
            "openssl",
            "C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
            "C:\OpenSSL-Win64\bin\openssl.exe"
        )
        
        foreach ($path in $opensslPaths) {
            try {
                $null = & $path version 2>$null
                if ($LASTEXITCODE -eq 0) {
                    $opensslPath = $path
                    break
                }
            } catch {
                continue
            }
        }
        
        if ($opensslPath) {
            Write-Log "Generating certificates with OpenSSL..." -Level INFO
            
            # Generate private key
            & $opensslPath genrsa -out $keyPath 2048 2>$null
            
            # Generate certificate
            $subject = "/C=US/O=Postdot Technologies, Inc/CN=identity.getpostman.com"
            & $opensslPath req -new -x509 -key $keyPath -out $certPath -days 3650 -subj $subject 2>$null
        } else {
            Write-Log "OpenSSL not found, using PowerShell to generate certificates..." -Level INFO
            
            # Generate using PowerShell (fallback)
            $cert = New-SelfSignedCertificate `
                -Subject "CN=identity.getpostman.com" `
                -DnsName "identity.getpostman.com", "localhost" `
                -KeyUsage DigitalSignature, KeyEncipherment `
                -KeyExportPolicy Exportable `
                -NotAfter (Get-Date).AddYears(10) `
                -CertStoreLocation "Cert:\CurrentUser\My"
            
            # Export certificate
            Export-Certificate -Cert "Cert:\CurrentUser\My\$($cert.Thumbprint)" -FilePath $certPath -Type CERT | Out-Null
            
            # Note: PowerShell method doesn't easily export private key in PEM format
            # User should use OpenSSL or the generate_stable_cert.sh script for proper key generation
            Write-Log "WARNING: Certificate generated but private key export requires OpenSSL" -Level WARNING
            Write-Log "Run generate_stable_cert.sh in $sslDir for complete certificate generation" -Level WARNING
        }
        
        Write-Log "Certificates generated in $sslDir" -Level SUCCESS
    } else {
        Write-Log "Using existing stable certificates from $sslDir" -Level INFO
    }
    
    try {
        # Copy server certificate and key
        Write-Log "Copying certificates to build directory..." -Level INFO
        Copy-Item -Path $certPath -Destination "server.crt" -Force
        Copy-Item -Path $keyPath -Destination "server.key" -Force -ErrorAction SilentlyContinue
        
        # For Windows compatibility, also create CA files (same as server for self-signed)
        Copy-Item -Path $certPath -Destination "ca.crt" -Force
        
        # Export Server private key (using PFX format for Windows compatibility)
        Write-Log "Exporting server private key..." -Level INFO
        $tempPfx = "$env:TEMP\server_temp.pfx"
        
        # Generate a random password for temporary PFX
        $passwordChars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz0123456789!@#$%^&*()"
        $randomPassword = -join ($passwordChars.ToCharArray() | Get-Random -Count 20)
        $password = ConvertTo-SecureString -String $randomPassword -Force -AsPlainText
        
        # Export certificate with private key to PFX
        Export-PfxCertificate -Cert $serverCertPath -FilePath $tempPfx -Password $password | Out-Null
        
        # Extract private key from PFX and save as PEM format for Go daemon compatibility
        Write-Log "Extracting private key to PEM format..." -Level INFO
        
        try {
            # Use OpenSSL to extract private key from PFX if available
            $opensslFound = $false
            $opensslPaths = @(
                "openssl",
                "C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
                "C:\OpenSSL-Win64\bin\openssl.exe"
            )
            
            foreach ($opensslPath in $opensslPaths) {
                try {
                    $null = & $opensslPath version 2>$null
                    if ($LASTEXITCODE -eq 0) {
                        $opensslFound = $true
                        $openssl = $opensslPath
                        break
                    }
                } catch {
                    continue
                }
            }
            
            if ($opensslFound) {
                # Extract private key using OpenSSL
                Write-Log "Using OpenSSL to extract private key from PFX..." -Level INFO
                $tempKeyFile = "$env:TEMP\server_key_temp.pem"
                
                # Create password file for OpenSSL
                $passwordFile = "$env:TEMP\pfx_password.txt"
                Set-Content -Path $passwordFile -Value $randomPassword -Encoding ASCII
                
                try {
                    # Extract private key from PFX
                    $opensslArgs = @(
                        "pkcs12", "-in", $tempPfx, "-nocerts", "-out", $tempKeyFile,
                        "-passin", "file:$passwordFile", "-passout", "pass:", "-nodes"
                    )
                    & $openssl @opensslArgs 2>$null
                    
                    if ($LASTEXITCODE -eq 0 -and (Test-Path $tempKeyFile)) {
                        # Copy the extracted key to final location
                        Copy-Item $tempKeyFile "server.key" -Force
                        Write-Log "[OK] Private key extracted successfully as PEM format" -Level SUCCESS
                    } else {
                        throw "OpenSSL key extraction failed"
                    }
                } finally {
                    # Clean up temporary files
                    Remove-Item $tempKeyFile -Force -ErrorAction SilentlyContinue
                    Remove-Item $passwordFile -Force -ErrorAction SilentlyContinue
                }
            } else {
                # Fallback: Use .NET crypto APIs to extract private key
                Write-Log "OpenSSL not found, using .NET crypto APIs..." -Level INFO
                
                # Load the certificate from PFX
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($tempPfx, $randomPassword, 'Exportable')
                
                # Get the private key
                $privateKey = $cert.PrivateKey
                if ($privateKey -eq $null) {
                    throw "Cannot extract private key from certificate"
                }
                
                # Export private key as RSA PEM format
                if ($privateKey -is [System.Security.Cryptography.RSACng] -or $privateKey -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
                    $rsaKey = [System.Security.Cryptography.RSA]$privateKey
                    $pemBytes = $rsaKey.ExportRSAPrivateKey()
                    
                    # Convert to PEM format
                    $base64Key = [Convert]::ToBase64String($pemBytes)
                    $pemLines = @()
                    $pemLines += "-----BEGIN RSA PRIVATE KEY-----"
                    for ($i = 0; $i -lt $base64Key.Length; $i += 64) {
                        $line = $base64Key.Substring($i, [Math]::Min(64, $base64Key.Length - $i))
                        $pemLines += $line
                    }
                    $pemLines += "-----END RSA PRIVATE KEY-----"
                    
                    Set-Content -Path "server.key" -Value ($pemLines -join "`r`n") -Encoding ASCII
                    Write-Log "[OK] Private key extracted successfully using .NET APIs" -Level SUCCESS
                } else {
                    throw "Unsupported private key type: $($privateKey.GetType().Name)"
                }
                
                # Clean up certificate object
                $cert.Dispose()
            }
            
            # Also save PFX for Windows compatibility (backup)
            if (Copy-FileWithLogging -Source $tempPfx -Destination "server.pfx" -Force) {
                Write-Log "PFX backup saved successfully" -Level INFO
            }
            
        } finally {
            # Clean up temporary files and sensitive variables
            Remove-Item $tempPfx -Force -ErrorAction SilentlyContinue
            Clear-Variable randomPassword -Force -ErrorAction SilentlyContinue
            Clear-Variable password -Force -ErrorAction SilentlyContinue
        }
        
        # Clean up certificates from store
        Remove-Item -Path $caCertPath -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $serverCertPath -Force -ErrorAction SilentlyContinue
        
        Write-Log "[OK] Certificates generated successfully" -Level SUCCESS
        Write-Log "  - ca.crt: Postman Enterprise AuthRouter CA" -Level INFO 
        Write-Log "  - server.crt: identity.getpostman.com (valid for $validityYears years)" -Level INFO
        Write-Log "  - server.key: Private key for server certificate (PEM format)" -Level INFO
        Write-Log "  - server.pfx: Certificate backup (PFX format)" -Level INFO
        
    } catch {
        Write-Log "Failed to generate certificates: $_" -Level ERROR
        exit 1
    }
}

# Dependency Management System with Auto-Installation
function Test-CommandAvailable {
    param([string]$Command)
    
    if ([string]::IsNullOrWhiteSpace($Command)) {
        Write-Log "Command parameter is required for Test-CommandAvailable" -Level WARNING
        return $false
    }
    
    try {
        $commandInfo = Get-Command $Command -ErrorAction SilentlyContinue
        $available = $commandInfo -ne $null
        Write-Log "Command '$Command' availability: $available" -Level DEBUG
        return $available
    } catch {
        Write-Log "Error checking command availability for '$Command': $_" -Level DEBUG
        return $false
    }
}

function Get-InstalledSoftware {
    param([string]$DisplayName)
    
    if ([string]::IsNullOrWhiteSpace($DisplayName)) {
        Write-Log "DisplayName parameter is required for Get-InstalledSoftware" -Level WARNING
        return $null
    }
    
    $uninstallKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    foreach ($key in $uninstallKeys) {
        try {
            if (-not (Test-Path (Split-Path $key -Parent))) {
                continue  # Skip if registry path doesn't exist
            }
            
            $installed = Get-ItemProperty $key -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -and $_.DisplayName -like "*$DisplayName*" } |
                Select-Object -First 1
            if ($installed) {
                Write-Log "Found installed software: $($installed.DisplayName)" -Level DEBUG
                return $installed
            }
        } catch {
            Write-Log "Error accessing registry key $key`: $_" -Level DEBUG
            continue
        }
    }
    
    Write-Log "Software '$DisplayName' not found in installed programs" -Level DEBUG
    return $null
}

function Install-Winget {
    Write-Log "Installing winget package manager..." -Level INFO
    
    try {
        # Check if winget is already available
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            Write-Log "Winget is already installed" -Level INFO
            return $true
        }
        
        # Download and install winget via App Installer
        $appxUrl = "https://aka.ms/getwinget"
        $tempPath = "$env:TEMP\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
        
        Write-Log "Downloading winget installer..." -Level INFO
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $appxUrl -OutFile $tempPath -UseBasicParsing
        
        Write-Log "Installing winget..." -Level INFO
        Add-AppxPackage -Path $tempPath -ErrorAction Stop
        
        # Clean up
        Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
        
        # Verify installation
        Start-Sleep -Seconds 3
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            Write-Log "Winget installed successfully" -Level SUCCESS
            return $true
        } else {
            Write-Log "Winget installation verification failed" -Level ERROR
            return $false
        }
        
    } catch {
        Write-Log "Failed to install winget: $_" -Level ERROR
        return $false
    }
}

function Install-DependencyViaWinget {
    param(
        [string]$PackageId,
        [string]$DisplayName,
        [string]$FallbackUrl = "",
        [string]$FallbackInstaller = ""
    )
    
    Write-Log "Installing $DisplayName via winget..." -Level INFO
    
    # Ensure winget is available
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        if (-not (Install-Winget)) {
            Write-Log "Cannot install $DisplayName`: winget not available" -Level ERROR
            return $false
        }
    }
    
    try {
        # Try to install via winget
        Write-Log "Running: winget install --id $PackageId --silent --accept-package-agreements --accept-source-agreements" -Level DEBUG
        $result = & winget install --id $PackageId --silent --accept-package-agreements --accept-source-agreements 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "$DisplayName installed successfully via winget" -Level SUCCESS
            return $true
        } else {
            Write-Log "Winget installation failed with exit code $LASTEXITCODE" -Level WARNING
            Write-Log "Winget output: $result" -Level DEBUG
        }
    } catch {
        Write-Log "Winget installation failed: $_" -Level WARNING
    }
    
    # Fallback to manual installation if provided
    if ($FallbackUrl -and $FallbackInstaller) {
        Write-Log "Attempting fallback installation from $FallbackUrl" -Level INFO
        try {
            $tempInstaller = Join-Path $env:TEMP $FallbackInstaller
            
            Write-Log "Downloading $DisplayName installer..." -Level INFO
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $FallbackUrl -OutFile $tempInstaller -UseBasicParsing
            
            Write-Log "Running installer: $tempInstaller" -Level INFO
            if ($FallbackInstaller.EndsWith(".msi")) {
                & msiexec /i $tempInstaller /quiet /norestart
            } else {
                & $tempInstaller /S /silent
            }
            
            if ($LASTEXITCODE -eq 0) {
                Write-Log "$DisplayName installed successfully via fallback" -Level SUCCESS
                Remove-Item $tempInstaller -Force -ErrorAction SilentlyContinue
                return $true
            } else {
                Write-Log "Fallback installation failed with exit code $LASTEXITCODE" -Level ERROR
            }
            
            Remove-Item $tempInstaller -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Log "Fallback installation failed: $_" -Level ERROR
        }
    }
    
    return $false
}

function Confirm-DependencyInstallation {
    param(
        [string]$Command = "",
        [string]$DisplayName = "",
        [string]$RegistryName = ""
    )
    
    $installed = $false
    
    # Check command availability
    if ($Command -and (Test-CommandAvailable $Command)) {
        Write-Log "$DisplayName command available: $Command" -Level INFO
        $installed = $true
    }
    
    # Check registry installation
    if ($RegistryName -and (Get-InstalledSoftware $RegistryName)) {
        Write-Log "$DisplayName found in installed programs" -Level INFO
        $installed = $true
    }
    
    if ($installed) {
        Write-Log "$DisplayName installation confirmed" -Level SUCCESS
    } else {
        Write-Log "$DisplayName installation could not be confirmed" -Level WARNING
    }
    
    return $installed
}

function Install-AllDependencies {
    Write-Log "=== Dependency Installation Phase ===" -Level INFO
    $installationFailed = $false
    
    # Check and install Go
    if (-not (Test-CommandAvailable "go")) {
        Write-Log "Go compiler not found, attempting installation..." -Level INFO
        if (-not (Install-DependencyViaWinget -PackageId "GoLang.Go" -DisplayName "Go Programming Language" -FallbackUrl "https://go.dev/dl/go1.25.0.windows-amd64.msi" -FallbackInstaller "go1.25.0.windows-amd64.msi")) {
            $installationFailed = $true
        }
        
        # Refresh PATH to include Go
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
        
        if (-not (Confirm-DependencyInstallation -Command "go" -DisplayName "Go" -RegistryName "Go Programming Language")) {
            $installationFailed = $true
        }
    } else {
        Write-Log "Go compiler already available" -Level INFO
    }
    
    # Check and install WiX Toolset
    $wixFound = $false
    $wixPaths = @(
        "${env:ProgramFiles(x86)}\WiX Toolset v3.11\bin",
        "${env:ProgramFiles}\WiX Toolset v3.11\bin",
        "${env:ProgramFiles(x86)}\WiX Toolset v4.0\bin",
        "${env:ProgramFiles}\WiX Toolset v4.0\bin"
    )
    
    foreach ($path in $wixPaths) {
        if (Test-Path "$path\candle.exe") {
            $wixFound = $true
            $global:WixPath = $path
            Write-Log "WiX Toolset found at: $path" -Level INFO
            break
        }
    }
    
    if (-not $wixFound) {
        Write-Log "WiX Toolset not found, attempting installation..." -Level INFO
        if (-not (Install-DependencyViaWinget -PackageId "WiXToolset.WiXToolset" -DisplayName "WiX Toolset" -FallbackUrl "https://github.com/wixtoolset/wix3/releases/download/wix3112rtm/wix311.exe" -FallbackInstaller "wix311.exe")) {
            $installationFailed = $true
        }
        
        # Re-check WiX installation
        foreach ($path in $wixPaths) {
            if (Test-Path "$path\candle.exe") {
                $wixFound = $true
                $global:WixPath = $path
                Write-Log "WiX Toolset installation confirmed at: $path" -Level SUCCESS
                break
            }
        }
        
        if (-not $wixFound) {
            Write-Log "WiX Toolset installation could not be confirmed" -Level ERROR
            $installationFailed = $true
        }
    }
    
    # Check Git (optional but useful)
    if (-not (Test-CommandAvailable "git")) {
        Write-Log "Git not found, attempting installation..." -Level INFO
        Install-DependencyViaWinget -PackageId "Git.Git" -DisplayName "Git" | Out-Null
        # Git installation is optional, don't fail the build if it fails
    }
    
    if ($installationFailed) {
        Write-Log "One or more critical dependencies could not be installed" -Level ERROR
        return $false
    }
    
    Write-Log "All dependencies are available" -Level SUCCESS
    return $true
}

# Advanced Service Management Checks
function Test-ServiceManagement {
    Write-Log "=== Service Management Validation ===" -Level INFO
    $validationErrors = @()
    
    # Check Service Control Manager access
    try {
        $scmAccess = Get-Service -Name "Spooler" -ErrorAction SilentlyContinue
        if (-not $scmAccess) {
            $validationErrors += "Cannot access Service Control Manager"
        } else {
            Write-Log "Service Control Manager access confirmed" -Level INFO
        }
    } catch {
        $validationErrors += "Service Control Manager access failed: $_"
    }
    
    # Check for existing Postman services
    Write-Log "Checking for existing Postman services..." -Level INFO
    $postmanServices = Get-Service | Where-Object { $_.ServiceName -like "*Postman*" -or $_.DisplayName -like "*Postman*" }
    
    foreach ($service in $postmanServices) {
        $metadata = @{
            "ServiceName" = $service.ServiceName
            "DisplayName" = $service.DisplayName
            "Status" = $service.Status
            "StartType" = $service.StartType
        }
        Write-Log "Found existing service: $($service.ServiceName)" -Level INFO -Component "ServiceMgmt" -Metadata $metadata
        
        # Check if it's our auth service
        if ($service.ServiceName -eq "PostmanSAMLEnforcer" -or $service.DisplayName -like "*Auth*") {
            Write-Log "Found existing authentication service: $($service.ServiceName)" -Level WARNING
            
            # Check service executable path
            try {
                $serviceConfig = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($service.ServiceName)'" -ErrorAction SilentlyContinue
                if ($serviceConfig) {
                    Write-Log "Service executable: $($serviceConfig.PathName)" -Level INFO
                }
            } catch {
                Write-Log "Could not retrieve service configuration: $_" -Level WARNING
            }
        }
    }
    
    # Check registry permissions for service installation
    try {
        $serviceRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services"
        $regAccess = Get-Item $serviceRegPath -ErrorAction SilentlyContinue
        if (-not $regAccess) {
            $validationErrors += "Cannot access service registry location: $serviceRegPath"
        } else {
            Write-Log "Service registry access confirmed" -Level INFO
        }
    } catch {
        $validationErrors += "Service registry access failed: $_"
    }
    
    # Check Windows service dependencies
    $requiredServices = @("RpcSs", "PlugPlay")  # Services typically required for service installation
    foreach ($serviceName in $requiredServices) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if (-not $service) {
                $validationErrors += "Required Windows service not found: $serviceName"
            } elseif ($service.Status -ne "Running") {
                Write-Log "Required service '$serviceName' is not running (Status: $($service.Status))" -Level WARNING
            } else {
                Write-Log "Required service '$serviceName' is running" -Level INFO
            }
        } catch {
            $validationErrors += "Cannot check required service '$serviceName': $_"
        }
    }
    
    if ($validationErrors.Count -gt 0) {
        Write-Log "Service management validation failed:" -Level ERROR
        foreach ($error in $validationErrors) {
            Write-Log "  - $error" -Level ERROR
        }
        return $false
    }
    
    Write-Log "Service management validation passed" -Level SUCCESS
    return $true
}

function Test-ServiceCleanup {
    param([string]$ServiceName = "PostmanSAMLEnforcer")
    
    Write-Log "Testing service cleanup capabilities for: $ServiceName" -Level INFO
    
    try {
        # Check if service exists
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $service) {
            Write-Log "Service '$ServiceName' does not exist - no cleanup needed" -Level INFO
            return $true
        }
        
        Write-Log "Found existing service: $ServiceName (Status: $($service.Status))" -Level INFO
        
        # Test stopping the service if it's running
        if ($service.Status -eq "Running") {
            Write-Log "Testing service stop capability..." -Level INFO
            try {
                # We won't actually stop it, just test the capability
                $stopCapability = $service.CanStop
                if ($stopCapability) {
                    Write-Log "Service can be stopped" -Level INFO
                } else {
                    Write-Log "Service cannot be stopped - this may cause issues during upgrade" -Level WARNING
                }
            } catch {
                Write-Log "Cannot determine service stop capability: $_" -Level WARNING
            }
        }
        
        # Check service executable and permissions
        try {
            $serviceConfig = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
            if ($serviceConfig) {
                $exePath = $serviceConfig.PathName -replace '"', ''  # Remove quotes
                $exePath = ($exePath -split ' ')[0]  # Get just the exe path, ignore arguments
                
                if (Test-Path $exePath) {
                    $fileInfo = Get-ItemProperty $exePath
                    Write-Log "Service executable found: $exePath ($('{0:N1}' -f ($fileInfo.Length/1MB))MB)" -Level INFO
                    
                    # Test file deletion capability (check permissions without actually deleting)
                    try {
                        $fileAcl = Get-Acl $exePath
                        Write-Log "Can access service executable ACL - cleanup should be possible" -Level INFO
                    } catch {
                        Write-Log "Cannot access service executable ACL: $_" -Level WARNING
                    }
                } else {
                    Write-Log "Service executable not found: $exePath" -Level WARNING
                }
            }
        } catch {
            Write-Log "Cannot retrieve service configuration: $_" -Level WARNING
        }
        
        Write-Log "Service cleanup validation completed" -Level SUCCESS
        return $true
        
    } catch {
        Write-Log "Service cleanup validation failed: $_" -Level ERROR
        return $false
    }
}

function Get-ServiceDependencyInfo {
    param([string]$ServiceName = "PostmanSAMLEnforcer")
    
    Write-Log "Gathering service dependency information for: $ServiceName" -Level INFO
    
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $service) {
            Write-Log "Service '$ServiceName' not found" -Level INFO
            return
        }
        
        # Get detailed service information
        $serviceWmi = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
        if ($serviceWmi) {
            $metadata = @{
                "ServiceName" = $serviceWmi.Name
                "DisplayName" = $serviceWmi.DisplayName
                "StartMode" = $serviceWmi.StartMode
                "ServiceType" = $serviceWmi.ServiceType
                "ErrorControl" = $serviceWmi.ErrorControl
                "PathName" = $serviceWmi.PathName
                "ServiceAccount" = $serviceWmi.StartName
            }
            
            Write-Log "Service configuration details" -Level INFO -Component "ServiceMgmt" -Metadata $metadata
            
            # Check service dependencies
            if ($serviceWmi.ServiceDependsOn) {
                Write-Log "Service dependencies: $($serviceWmi.ServiceDependsOn -join ', ')" -Level INFO
            } else {
                Write-Log "Service has no dependencies" -Level INFO
            }
        }
        
        # Check what depends on this service
        $dependentServices = Get-Service | Where-Object { $_.ServicesDependedOn -contains $service }
        if ($dependentServices) {
            $dependentNames = $dependentServices | ForEach-Object { $_.Name }
            Write-Log "Services that depend on '$ServiceName': $($dependentNames -join ', ')" -Level WARNING
        } else {
            Write-Log "No other services depend on '$ServiceName'" -Level INFO
        }
        
    } catch {
        Write-Log "Failed to gather service dependency information: $_" -Level ERROR
    }
}

# Function to check and install Go
function Install-Go {
    Write-Log "Go not found. Installing Go 1.25.0 automatically..." -Level WARNING
    
    # Check if we have admin rights for installation
    if (-not (Test-Administrator)) {
        Write-Log "Administrator privileges required to install Go." -Level ERROR
        Write-Log "Please run this script as Administrator for automatic installation." -Level ERROR
        Write-Log "Or install Go manually from: https://go.dev/dl/" -Level ERROR
        exit 1
    }
    
    $goUrl = "https://go.dev/dl/go1.25.0.windows-amd64.msi"
    $goInstaller = "$env:TEMP\go1.25.0.windows-amd64.msi"
    
    try {
        Write-Log "Downloading Go 1.25.0..." -Level INFO
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $goUrl -OutFile $goInstaller -UseBasicParsing
        
        Write-Log "Installing Go 1.25.0 (this may take a few minutes)..." -Level INFO
        Start-Process -FilePath "msiexec" -ArgumentList "/i", $goInstaller, "/quiet", "/norestart" -Wait
        
        # Clean up installer
        Remove-Item $goInstaller -Force -ErrorAction SilentlyContinue
        
        # Refresh PATH to include Go
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
        
        Write-Log "Go 1.25.0 installed successfully!" -Level SUCCESS
    } catch {
        Write-Log "Failed to install Go: $_" -Level ERROR
        Write-Log "Please install manually from: https://go.dev/dl/" -Level ERROR
        exit 1
    }
}

# Function to install WiX Toolset
function Install-WixToolset {
    Write-Log "WiX Toolset 3.11 not found. Installing automatically..." -Level WARNING
    
    # Check if we have admin rights for installation
    if (-not (Test-Administrator)) {
        Write-Log "Administrator privileges required to install WiX Toolset." -Level ERROR
        Write-Log "Please run this script as Administrator for automatic installation." -Level ERROR
        Write-Log "Or install WiX Toolset 3.11 manually from: https://github.com/wixtoolset/wix3/releases/tag/wix3112rtm" -Level ERROR
        exit 1
    }
    
    $wixUrl = "https://github.com/wixtoolset/wix3/releases/download/wix3112rtm/wix311.exe"
    $wixInstaller = "$env:TEMP\wix311.exe"
    
    try {
        Write-Log "Downloading WiX Toolset 3.11..." -Level INFO
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $wixUrl -OutFile $wixInstaller -UseBasicParsing
        
        Write-Log "Installing WiX Toolset 3.11 (this may take a few minutes)..." -Level INFO
        Start-Process -FilePath $wixInstaller -ArgumentList "/quiet", "/norestart" -Wait
        
        # Clean up installer
        Remove-Item $wixInstaller -Force -ErrorAction SilentlyContinue
        
        Write-Log "WiX Toolset 3.11 installed successfully!" -Level SUCCESS
    } catch {
        Write-Log "Failed to install WiX Toolset: $_" -Level ERROR
        Write-Log "Please install manually from: https://github.com/wixtoolset/wix3/releases/tag/wix3112rtm" -Level ERROR
        exit 1
    }
}

# Function to find Postman MSI
function Find-PostmanMSI {
    Write-Log "Looking for Postman Enterprise MSI in current directory..." -Level INFO
    
    # Look for Postman MSI files matching common patterns
    $patterns = @(
        "Postman-Enterprise-*.msi",
        "Postman-*.msi",
        "*postman*.msi"
    )
    
    foreach ($pattern in $patterns) {
        $files = Get-ChildItem -Path . -Filter $pattern -File | 
                 Where-Object { $_.Name -notmatch "-saml\.msi$" } |
                 Sort-Object LastWriteTime -Descending
        
        if ($files.Count -gt 0) {
            $msiFile = $files[0].Name
            Write-Log "Found MSI: $msiFile" -Level SUCCESS
            return $msiFile
        }
    }
    
    return $null
}

# Function to download Postman MSI
function Download-PostmanMSI {
    Write-Log "Downloading latest Postman Enterprise MSI..." -Level WARNING
    
    $downloadUrl = "https://dl.pstmn.io/download/latest/version/11/win64?channel=enterprise&filetype=msi"
    $outputFile = "Postman-Enterprise-latest-x64.msi"
    
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        
        Write-Log "Downloading from: $downloadUrl" -Level INFO
        Write-Log "This may take a few minutes depending on your connection speed..." -Level INFO
        
        # Use WebClient for better progress reporting
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($downloadUrl, $outputFile)
        
        if (Test-Path $outputFile) {
            $fileSize = (Get-Item $outputFile).Length / 1MB
            Write-Log "Downloaded successfully: $outputFile ($([math]::Round($fileSize, 2)) MB)" -Level SUCCESS
            return $outputFile
        } else {
            throw "Download completed but file not found"
        }
    } catch {
        Write-Log "Failed to download Postman MSI: $_" -Level ERROR
        Write-Log "You can manually download from: $downloadUrl" -Level ERROR
        exit 1
    }
}

# Parameter validation with warnings
if ([string]::IsNullOrEmpty($TeamName)) {
    Write-Log "No team name provided. Service will be installed but not activated until configured via MSI properties." -Level WARNING
    Write-Log "Configuration options:" -Level INFO
    Write-Log "  - MSI install: msiexec /i package.msi TEAM_NAME=myteam SAML_URL=https://..." -Level INFO
    Write-Log "  - Registry: Set values under HKLM\\SOFTWARE\\Postman\\Enterprise" -Level INFO
} elseif ($TeamName.Length -lt 2) {
    Write-Log "Team name too short (minimum 2 characters recommended): $TeamName" -Level WARNING
} elseif ($TeamName.Length -gt 100) {
    Write-Log "Team name too long (maximum 100 characters recommended): $TeamName" -Level WARNING
}

if ([string]::IsNullOrEmpty($SamlUrl)) {
    Write-Log "No SAML URL provided. Service will be installed but not activated until configured via MSI properties." -Level WARNING
    Write-Log "Configuration options:" -Level INFO
    Write-Log "  - MSI install: msiexec /i package.msi TEAM_NAME=myteam SAML_URL=https://..." -Level INFO
    Write-Log "  - Registry: Set values under HKLM\\SOFTWARE\\Postman\\Enterprise" -Level INFO
} elseif (-not ($SamlUrl -match '^https?://')) {
    Write-Log "SAML URL should be a valid HTTP/HTTPS URL: $SamlUrl" -Level WARNING
} elseif (-not ($SamlUrl -match '/init$')) {
    Write-Log "SAML URL should end with '/init' for proper SAML initialization: $SamlUrl" -Level WARNING
}

# Main script starts here
Write-Log "=== Postman Enterprise MSI Repackaging Script ===" -Level INFO
Write-Log "Script directory: $scriptDir" -Level INFO
Write-Log "Team Name: $(if ($TeamName) { $TeamName } else { '[not configured - will be set at install time]' })" -Level INFO
Write-Log "SAML URL: $(if ($SamlUrl) { $SamlUrl } else { '[not configured - will be set at install time]' })" -Level INFO
if (-not [string]::IsNullOrEmpty($LogFile)) {
    Write-Log "Logging to: $LogFile" -Level INFO
}

# Check if running as administrator
if (-not (Test-Administrator)) {
    Write-Log "WARNING: This script is not running as Administrator" -Level WARNING
    Write-Log "Some operations may fail without elevated privileges:" -Level WARNING
    Write-Log "  - Installing Go or WiX Toolset automatically" -Level WARNING
    Write-Log "  - Certificate installation during MSI install" -Level WARNING
    Write-Log "  - Service installation during MSI install" -Level WARNING
    Write-Log "" -Level WARNING
    Write-Log "To run as Administrator:" -Level WARNING
    Write-Log "  Right-click PowerShell -> 'Run as Administrator'" -Level WARNING
    Write-Log "  Then run: .\build_msi_mdm_win.ps1" -Level WARNING
    Write-Log "" -Level WARNING
    
    $response = Read-Host "Continue anyway? (y/N)"
    if ($response -notmatch "^[Yy]$") {
        Write-Log "Script cancelled by user" -Level INFO
        exit 0
    }
    Write-Log "Continuing without administrator privileges..." -Level WARNING
}

# Run comprehensive validation framework
Write-Log "Starting comprehensive validation framework..." -Level INFO
Start-OperationTimer "Comprehensive-Validation"

if (-not (Test-Environment)) {
    Write-Log "Environment validation failed. Exiting." -Level ERROR
    exit 1
}

if (-not (Test-Dependencies)) {
    Write-Log "Dependency validation failed. Attempting automatic installation..." -Level WARNING
    if (-not (Install-AllDependencies)) {
        Write-Log "Critical dependencies could not be installed. Exiting." -Level ERROR
        exit 1
    }
    
    # Re-validate dependencies after installation
    if (-not (Test-Dependencies)) {
        Write-Log "Dependencies still not available after installation attempt. Exiting." -Level ERROR
        exit 1
    }
}

if (-not (Test-ServiceManagement)) {
    Write-Log "Service management validation failed. Exiting." -Level ERROR
    exit 1
}

# Test service cleanup capabilities for existing installations
Test-ServiceCleanup
Get-ServiceDependencyInfo

Stop-OperationTimer "Comprehensive-Validation"

Write-Host ""

# Step 1: Check and install dependencies (legacy compatibility)
Write-Log "Final dependency verification..." -Level INFO

# Check for Go
$goVersion = ""
try {
    $goVersion = & go version 2>$null
    if ($LASTEXITCODE -eq 0 -and $goVersion) {
        Write-Log "[OK] Go found: $goVersion" -Level SUCCESS
    } else {
        throw "Go not found"
    }
} catch {
    Install-Go
    
    # Verify installation
    try {
        $goVersion = & go version 2>$null
        if ($LASTEXITCODE -eq 0 -and $goVersion) {
            Write-Log "[OK] Go installed: $goVersion" -Level SUCCESS
        } else {
            throw "Go installation verification failed"
        }
    } catch {
        Write-Log "Go installation verification failed. Please install manually." -Level ERROR
        exit 1
    }
}

# Check for WiX Toolset
if (-not (Test-Path "$WixPath\dark.exe") -or -not (Test-Path "$WixPath\candle.exe") -or -not (Test-Path "$WixPath\light.exe")) {
    Install-WixToolset
    
    # Verify installation
    if (-not (Test-Path "$WixPath\dark.exe")) {
        Write-Log "WiX Toolset installation verification failed. Please install manually." -Level ERROR
        exit 1
    }
} else {
    Write-Log "[OK] WiX Toolset 3.11 found" -Level SUCCESS
}

# Step 2: Find or download source MSI
if ([string]::IsNullOrWhiteSpace($SourceMSI)) {
    # Try to find existing MSI
    $SourceMSI = Find-PostmanMSI
    
    if ($null -eq $SourceMSI) {
        # No MSI found, download it automatically
        Write-Log "No Postman MSI found in current directory. Downloading..." -Level WARNING
        $SourceMSI = Download-PostmanMSI
    }
}

# Check if source MSI exists
if (-not (Test-Path $SourceMSI)) {
    Write-Log "Source MSI '$SourceMSI' not found." -Level ERROR
    exit 1
}

# Run source file validation
Write-Log "Validating source files..." -Level INFO
if (-not (Test-SourceFiles)) {
    Write-Log "Source file validation failed. Exiting." -Level ERROR
    exit 1
}

# Auto-generate output filename if not specified
if ([string]::IsNullOrWhiteSpace($OutputMSI)) {
    $sourceFile = Get-Item $SourceMSI
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($sourceFile.Name)
    $extension = $sourceFile.Extension
    $OutputMSI = "$baseName-saml$extension"
    Write-Log "Output MSI will be: $OutputMSI" -Level INFO
}

# Auto-generate temp directory if not specified
if ([string]::IsNullOrWhiteSpace($TempDir)) {
    $randomSuffix = Get-Random -Minimum 10000 -Maximum 99999
    $tempBase = $env:TEMP
    if ([string]::IsNullOrEmpty($tempBase)) {
        $tempBase = $env:TMP
    }
    if ([string]::IsNullOrEmpty($tempBase)) {
        $tempBase = "C:\Windows\Temp"
    }
    $TempDir = Join-Path $tempBase "postman-repack-$randomSuffix"
    Write-Log "Using temp directory: $TempDir" -Level INFO
}

# Create temp directory first
Write-Log "Creating temporary directory: $TempDir" -Level INFO
if (Test-Path $TempDir) {
    Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

# Step 3: Generate or check certificates in temp directory
if (-not $UseExistingCerts) {
    # Generate certificates automatically in temp directory
    Push-Location $TempDir
    try {
        Ensure-StableCertificates
    } finally {
        Pop-Location
    }
} else {
    # Check for existing certificate files in temp directory
    Write-Log "Checking for existing certificate files..." -Level INFO
    $certFiles = @("ca.crt", "server.crt", "server.key")
    $missingCerts = @()
    
    foreach ($cert in $certFiles) {
        $certPath = Join-Path $TempDir $cert
        if (Test-Path $certPath) {
            Write-Log "[OK] Found: $cert" -Level SUCCESS
        } else {
            $missingCerts += $cert
        }
    }
    
    if ($missingCerts.Count -gt 0) {
        Write-Log "Missing certificates. Generating new ones..." -Level WARNING
        Push-Location $TempDir
        try {
            Ensure-StableCertificates
        } finally {
            Pop-Location
        }
    }
}

# Step 4: Check for other required files
Write-Log "Checking for other required files..." -Level INFO

# Build pm-authrouter.exe from Go source
Write-Log "Building pm-authrouter.exe from source..." -Level INFO

# Find the project root directory (where go.mod is located)
$projectRoot = $scriptDir
do {
    if (Test-Path (Join-Path $projectRoot "go.mod")) {
        break
    }
    $parent = Split-Path $projectRoot -Parent
    if ($parent -eq $projectRoot) {
        Write-Log "Could not find go.mod file. Please run from project directory." -Level ERROR
        exit 1
    }
    $projectRoot = $parent
} while ($true)

Write-Log "Found project root: $projectRoot" -Level INFO
Write-Log "Building Windows binary for pm-authrouter..." -Level INFO

# Save current location and switch to project root
Push-Location $projectRoot
try {
    # Set environment variables for Windows cross-compilation
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    $env:CGO_ENABLED = "0"
    
    # Build command with optimized flags for production
    $buildCmd = "go"
    $buildArgs = @(
        "build",
        "-ldflags=-w -s",  # Strip debugging info and symbol table
        "-o", "$TempDir\pm-authrouter.exe",
        ".\cmd\pm-authrouter"
    )
    
    Write-Log "Executing: $buildCmd $($buildArgs -join ' ')" -Level INFO
    & $buildCmd @buildArgs
    
    if ($LASTEXITCODE -ne 0) {
        throw "Go build failed with exit code $LASTEXITCODE"
    }
    
    # Verify the binary was created
    if (Test-Path "$TempDir\pm-authrouter.exe") {
        $binarySize = (Get-Item "$TempDir\pm-authrouter.exe").Length / 1MB
        Write-Log "[OK] Built pm-authrouter.exe ($([math]::Round($binarySize, 2)) MB)" -Level SUCCESS
    } else {
        throw "Binary not found after build"
    }
    
} catch {
    Write-Log "Failed to build pm-authrouter.exe: $_" -Level ERROR
    exit 1
} finally {
    Pop-Location
    # Clean up environment variables
    Remove-Item env:GOOS -ErrorAction SilentlyContinue
    Remove-Item env:GOARCH -ErrorAction SilentlyContinue  
    Remove-Item env:CGO_ENABLED -ErrorAction SilentlyContinue
}

# Always generate uninstall.bat in temp directory for consistency
Write-Log "Generating uninstall.bat..." -Level INFO
$uninstallContent = @"
@echo off
echo Uninstalling Postman Enterprise Authentication Router...
sc stop PMAuthRouter 2>nul
sc delete PMAuthRouter 2>nul
echo Removing registry configuration...
reg delete "HKLM\SOFTWARE\Postman\Enterprise" /f 2>nul
echo Postman Enterprise Authentication Router has been removed.
"@
Set-Content -Path "$TempDir\uninstall.bat" -Value $uninstallContent -Encoding ASCII
Write-Log "[OK] Generated uninstall.bat" -Level SUCCESS

Write-Log "[OK] All required files ready" -Level SUCCESS

# Get original MSI size for comparison
$originalSize = (Get-Item $SourceMSI).Length
Write-Log "Original MSI size: $([math]::Round($originalSize / 1MB, 2)) MB" -Level INFO

# Validation functions
function Test-CabinetCompression {
    param([string]$ExtractedPath)
    
    if ($ValidateCompression) {
        Write-Host "Validating cabinet compression..."
        
        # Check if starship.cab exists and is still compressed
        $starshipCab = Get-ChildItem -Path $ExtractedPath -Name "starship.cab" -Recurse -ErrorAction SilentlyContinue
        
        if ($starshipCab) {
            $cabPath = Join-Path $ExtractedPath $starshipCab
            $cabSize = (Get-Item $cabPath).Length
            Write-Host "Found starship.cab: $([math]::Round($cabSize / 1MB, 2)) MB (compressed)" -ForegroundColor Green
            return $true
        } else {
            # Check if we accidentally extracted cabinet contents
            $extractedFiles = Get-ChildItem -Path $ExtractedPath -Recurse -File | Where-Object { $_.Extension -in @('.exe', '.dll', '.pak', '.dat') -and $_.Name -ne 'pm-authrouter.exe' }
            
            if ($extractedFiles.Count -gt 50) {  # Arbitrary threshold indicating extraction
                Write-Warning "Detected $($extractedFiles.Count) extracted files - starship.cab may have been decompressed!"
                if ($Debug) {
                    Write-Host "First 10 extracted files:"
                    $extractedFiles | Select-Object -First 10 | ForEach-Object { Write-Host "  - $($_.Name)" }
                }
                return $false
            } else {
                Write-Host "Cabinet appears to remain compressed (found $($extractedFiles.Count) individual files)" -ForegroundColor Green
                return $true
            }
        }
    }
    return $true
}

function Write-DebugInfo {
    param([string]$Message, [string]$Color = "Cyan")
    if ($Debug) {
        Write-Host "[DEBUG] $Message" -ForegroundColor $Color
    }
}


try {
    # Extract MSI using WiX dark.exe
    Write-Log "Extracting MSI with dark.exe..." -Level INFO
    Write-DebugInfo "Using dark.exe args: -x $TempDir\extracted -v $SourceMSI $TempDir\Product.wxs"
    
    $darkArgs = @(
        "-x", "$TempDir\extracted"
        "-v"
        $SourceMSI
        "$TempDir\Product.wxs"
    )
    
    & "$WixPath\dark.exe" @darkArgs
    if ($LASTEXITCODE -ne 0) {
        throw "dark.exe failed with exit code $LASTEXITCODE"
    }
    
    # Validate that cabinet files remain compressed
    $compressionValid = Test-CabinetCompression -ExtractedPath "$TempDir\extracted"
    if (-not $compressionValid) {
        Write-Warning "Cabinet compression validation failed! This may result in an oversized MSI."
    }

    # Copy custom files to extracted directory
    Write-Log "Adding custom files to MSI..." -Level INFO
    $customFiles = @(
        "$TempDir\server.key",
        "$TempDir\pm-authrouter.exe", 
        "$TempDir\uninstall.bat",
        "$TempDir\ca.crt",
        "$TempDir\server.crt"
    )

    foreach ($file in $customFiles) {
        if (Test-Path $file) {
            if (Copy-FileWithLogging -Source $file -Destination "$TempDir\extracted\" -Force) {
                $fileName = Split-Path $file -Leaf
                Write-Log "Added custom file: $fileName" -Level SUCCESS
            } else {
                Write-Log "Failed to add custom file: $fileName" -Level ERROR
            }
        } else {
            $fileName = Split-Path $file -Leaf
            Write-Warning "Custom file not found: $fileName"
        }
    }

    # Modify WiX source file to include custom components
    Write-Log "Modifying WiX source file..." -Level INFO
    $wxsPath = "$TempDir\Product.wxs"
    
    if (-not (Test-Path $wxsPath)) {
        throw "Product.wxs not found after extraction"
    }

    # Read the WXS content
    $wxsContent = Get-Content -Path $wxsPath -Raw

    # Generate GUIDs for our components
    $guid1 = [System.Guid]::NewGuid().ToString().ToUpper()
    $guid2 = [System.Guid]::NewGuid().ToString().ToUpper()
    $guid3 = [System.Guid]::NewGuid().ToString().ToUpper()
    $guid4 = [System.Guid]::NewGuid().ToString().ToUpper()
    $guid5 = [System.Guid]::NewGuid().ToString().ToUpper()
    
    # Create auth directory and components
    $customComponents = @"
                        <Directory Id="AuthDirectory" Name="auth">
                            <Component Id="ServerKeyComponent" Guid="{$guid1}" Win64="yes">
                                <File Id="ServerKey" Source="server.key" KeyPath="yes" />
                            </Component>
                            <Component Id="AuthRouterComponent" Guid="{$guid2}" Win64="yes">
                                <File Id="AuthRouter" Source="pm-authrouter.exe" KeyPath="yes" />
                                
                                <!-- Service Installation -->
                                <ServiceInstall Id="PMAuthRouterService" 
                                               Name="PMAuthRouter"
                                               DisplayName="Postman Enterprise Authentication Router"
                                               Description="Postman Enterprise Authentication Router Service for SAML enforcement"
                                               Type="ownProcess"
                                               Start="auto"
                                               Account="LocalSystem"
                                               ErrorControl="normal"
                                               Vital="yes">
                                    <util:ServiceConfig FirstFailureActionType="restart" 
                                                       SecondFailureActionType="restart" 
                                                       ThirdFailureActionType="none" 
                                                       RestartServiceDelayInSeconds="60" />
                                </ServiceInstall>
                                
                                <ServiceControl Id="PMAuthRouterServiceControl"
                                               Name="PMAuthRouter"
                                               Start="install"
                                               Stop="both"
                                               Remove="uninstall" />
                            </Component>
                            <Component Id="UninstallBatComponent" Guid="{$guid3}" Win64="yes">
                                <File Id="UninstallBat" Source="uninstall.bat" KeyPath="yes" />
                            </Component>
                            <Component Id="CaCrtComponent" Guid="{$guid4}" Win64="yes">
                                <File Id="CaCrt" Source="ca.crt" KeyPath="yes" />
                                
                                <!-- Install CA certificate to LocalMachine Root store -->
                                <iis:Certificate Id="CACertificate" 
                                               Name="Postman Enterprise AuthRouter CA"
                                               StoreLocation="localMachine"
                                               StoreName="root"
                                               BinaryKey="CaCertBinary"
                                               Overwrite="yes" />
                            </Component>
                            <Component Id="ServerCrtComponent" Guid="{$guid5}" Win64="yes">
                                <File Id="ServerCrt" Source="server.crt" KeyPath="yes" />
                                
                                <!-- Registry Configuration -->
                                <RegistryKey Root="HKLM" Key="SOFTWARE\Postman\Enterprise">
                                    <RegistryValue Name="AuthRouterPath" Type="string" Value="[INSTALLDIR]auth\pm-authrouter.exe" />
                                    <RegistryValue Name="CertificatePath" Type="string" Value="[INSTALLDIR]auth\server.crt" />
                                    <RegistryValue Name="KeyPath" Type="string" Value="[INSTALLDIR]auth\server.key" />
                                    <RegistryValue Name="CAPath" Type="string" Value="[INSTALLDIR]auth\ca.crt" />
                                    <!-- Team name from build-time parameter or MSI property -->
                                    <RegistryValue Name="TeamName" Type="string" Value="[TEAM_NAME]" />
                                    <!-- SAML URL from build-time parameter or MSI property -->
                                    <RegistryValue Name="SamlUrl" Type="string" Value="[SAML_URL]" />
                                </RegistryKey>
                            </Component>
                        </Directory>
"@

    # Add util and iis namespaces if not present
    if ($wxsContent -notmatch 'xmlns:util=') {
        $wxsContent = $wxsContent -replace '<Wix xmlns="[^"]*"', '$0 xmlns:util="http://schemas.microsoft.com/wix/UtilExtension"'
    }
    if ($wxsContent -notmatch 'xmlns:iis=') {
        $wxsContent = $wxsContent -replace '<Wix xmlns="[^"]*"', '$0 xmlns:iis="http://schemas.microsoft.com/wix/IIsExtension"'
    }

    # Split the file into lines for easier manipulation
    $lines = $wxsContent -split "`r`n|`r|`n"
    
    # Find where to insert auth directory (before closing </Directory> of INSTALLDIR)
    $installDirStart = -1
    $installDirEnd = -1
    $featureStart = -1
    $featureEnd = -1
    $directoryDepth = 0
    
    for ($i = 0; $i -lt $lines.Length; $i++) {
        if ($lines[$i] -match '<Directory Id="INSTALLDIR"') {
            $installDirStart = $i
            $directoryDepth = 0
        }
        if ($installDirStart -ge 0) {
            if ($lines[$i] -match '<Directory') {
                $directoryDepth++
            }
            if ($lines[$i] -match '</Directory>') {
                $directoryDepth--
                if ($directoryDepth -eq 0 -and $installDirEnd -eq -1) {
                    $installDirEnd = $i  # This is the closing </Directory> for INSTALLDIR
                }
            }
        }
        if ($lines[$i] -match '<Feature Id="Application"') {
            $featureStart = $i
        }
        if ($featureStart -ge 0 -and $lines[$i] -match '</Feature>' -and $featureEnd -eq -1) {
            $featureEnd = $i
        }
    }
    
    # Insert auth directory before closing </Directory> of INSTALLDIR
    if ($installDirEnd -gt 0) {
        $componentLines = $customComponents -split "`r`n|`r|`n"
        $lines = $lines[0..($installDirEnd - 1)] + $componentLines + $lines[$installDirEnd..($lines.Length - 1)]
        
        # Adjust indices after insertion
        $featureEnd += $componentLines.Length
    }
    
    # Insert component references in Feature
    if ($featureEnd -ge 0) {
        $componentRefs = @(
            '            <ComponentRef Id="ServerKeyComponent" />',
            '            <ComponentRef Id="AuthRouterComponent" />',
            '            <ComponentRef Id="UninstallBatComponent" />',
            '            <ComponentRef Id="CaCrtComponent" />',
            '            <ComponentRef Id="ServerCrtComponent" />'
        )
        $lines = $lines[0..($featureEnd - 1)] + $componentRefs + $lines[$featureEnd..($lines.Length - 1)]
    }
    
    # Add Binary element for certificate data after Feature section
    $binarySection = @(
        '',
        '        <!-- Binary data for certificates -->',
        '        <Binary Id="CaCertBinary" SourceFile="ca.crt" />',
        '',
        '        <!-- MSI Properties for install-time configuration -->',
        "        <Property Id=`"TEAM_NAME`" Value=`"$(if ($TeamName) { $TeamName } else { '' })`" />",
        "        <Property Id=`"SAML_URL`" Value=`"$(if ($SamlUrl) { $SamlUrl } else { '' })`" />"
    )
    
    # Find the end of the Product element to insert Binary before it
    $productEnd = -1
    for ($i = $lines.Length - 1; $i -ge 0; $i--) {
        if ($lines[$i] -match '</Product>') {
            $productEnd = $i
            break
        }
    }
    
    if ($productEnd -ge 0) {
        $lines = $lines[0..($productEnd - 1)] + $binarySection + $lines[$productEnd..($lines.Length - 1)]
    }
    
    # Rejoin the lines
    $wxsContent = $lines -join "`r`n"

    # Write modified WXS back
    Set-Content -Path $wxsPath -Value $wxsContent -Encoding UTF8

    # Run build process validation before starting
    Write-Log "Validating build process prerequisites..." -Level INFO
    if (-not (Test-BuildProcess)) {
        throw "Build process validation failed"
    }

    # Compile WiX source with candle.exe
    Write-Log "Compiling WiX source..." -Level INFO
    $candleArgs = @(
        "-ext", "WixUtilExtension"
        "-ext", "WixIIsExtension"
        "-out", "$TempDir\Product.wixobj"
        $wxsPath
    )
    
    & "$WixPath\candle.exe" @candleArgs
    if ($LASTEXITCODE -ne 0) {
        throw "candle.exe failed with exit code $LASTEXITCODE"
    }

    # Link MSI with light.exe
    Write-Log "Linking MSI (Compression: $CompressionLevel, Threads: $Threads)..." -Level INFO
    
    $lightArgs = @(
        "-ext", "WixUtilExtension"
        "-ext", "WixIIsExtension"
        "-out", $OutputMSI
        "-b", "$TempDir\extracted"
        "-dcl:$CompressionLevel"  # Compression level
        "-ct", $Threads  # Number of threads for cabinet creation
        "$TempDir\Product.wixobj"
    )
    
    # Add optional flags based on parameters
    if ($FastBuild) {
        Write-Host "Fast build mode enabled - skipping validations"
        $lightArgs += "-sval"  # Skip validation
        $lightArgs += "-sh"    # Skip file hash verification
        $lightArgs += "-ss"    # Skip schema validation
        $lightArgs += "-ai"    # Allow identical rows
    }
    
    if (-not $KeepPDB) {
        $lightArgs += "-spdb"  # Suppress PDB creation
    } else {
        Write-Host "Keeping PDB file for debugging/patching"
    }
    
    # Suppress common warnings that don't affect functionality
    $lightArgs += "-sw1076"  # ICE76: Duplicate sequence numbers
    
    Write-DebugInfo "Light.exe arguments: $($lightArgs -join ' ')"
    
    & "$WixPath\light.exe" @lightArgs
    if ($LASTEXITCODE -ne 0) {
        throw "light.exe failed with exit code $LASTEXITCODE"
    }

    Write-Host "Successfully created modified MSI: $OutputMSI" -ForegroundColor Green
    
    # Run output validation
    Write-Log "Validating output MSI..." -Level INFO
    if (-not (Test-OutputValidation -OutputPath $OutputMSI)) {
        throw "Output validation failed"
    }
    
    # Show file info and size comparison
    if (Test-Path $OutputMSI) {
        $fileInfo = Get-Item $OutputMSI
        $newSize = $fileInfo.Length
        $sizeDifference = $newSize - $originalSize
        $percentIncrease = [math]::Round(($sizeDifference / $originalSize) * 100, 2)
        
        Write-Host "Original MSI size: $([math]::Round($originalSize / 1MB, 2)) MB"
        Write-Host "Modified MSI size: $([math]::Round($newSize / 1MB, 2)) MB" -ForegroundColor $(if ($percentIncrease -gt 50) { "Yellow" } else { "Green" })
        Write-Host "Size difference: $([math]::Round($sizeDifference / 1MB, 2)) MB ($percentIncrease% increase)"
        Write-Host "Created: $($fileInfo.CreationTime)"
        
        # Custom files size
        $customFilesTotalSize = 0
        $customFiles = @("server.key", "pm-authrouter.exe", "uninstall.bat", "ca.crt", "server.crt")
        foreach ($file in $customFiles) {
            if (Test-Path $file) {
                $customFilesTotalSize += (Get-Item $file).Length
            }
        }
        Write-Host "Custom files total: $([math]::Round($customFilesTotalSize / 1MB, 2)) MB"
        
        # Warn if size increase is unexpectedly large
        if ($percentIncrease -gt 50) {
            Write-Warning "Size increase is larger than expected! This may indicate cabinet decompression occurred."
            Write-Warning "Expected increase should be close to custom files size + small overhead."
        }
    }

} catch {
    Write-Log "Error during repackaging: $_" -Level ERROR
    exit 1
} finally {
    # Clean up temp directory
    if (Test-Path $TempDir) {
        Write-Log "Cleaning up temporary files..." -Level INFO
        Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    # Clean up temporary files
    $tempFiles = @("server.pfx")
    
    # Clean up WiX PDB unless explicitly kept
    if (-not $KeepPDB) {
        $tempFiles += "*.wixpdb"
    }
    
    # Clean up if we failed OR if not keeping PDB
    foreach ($pattern in $tempFiles) {
        Remove-Item $pattern -Force -ErrorAction SilentlyContinue
    }
}

Write-Log "MSI repackaging completed successfully!" -Level SUCCESS
Write-Log "Output file: $OutputMSI" -Level SUCCESS