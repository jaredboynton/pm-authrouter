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

# Timer functions removed - unnecessary complexity for simple timing

# File operation wrappers removed - use direct Copy-Item/Remove-Item with Write-Log

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

# Test-BuildProcess function removed - redundant with earlier dependency checks

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

# Certificate management - uses centralized /ssl/ directory like other build scripts
function Ensure-StableCertificates {
    Write-Log "Checking for stable certificates..." -Level INFO
    
    try {
        # Find project root by locating go.mod (same pattern as macOS script)
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
            throw "Could not find project root (go.mod not found)"
        }
        
        $sslDir = Join-Path $projectRoot "ssl"
        $stableCert = Join-Path $sslDir "identity.getpostman.com.crt"
        $stableKey = Join-Path $sslDir "identity.getpostman.com.key"
        
        # Generate certificates in /ssl/ if they don't exist
        if (-not (Test-Path $stableCert) -or -not (Test-Path $stableKey)) {
            Write-Log "Stable certificates not found in $sslDir, generating..." -Level INFO
            
            # Ensure SSL directory exists
            if (-not (Test-Path $sslDir)) {
                New-Item -ItemType Directory -Path $sslDir -Force | Out-Null
            }
            
            # Generate certificates in /ssl/ directory
            $cert = New-SelfSignedCertificate `
                -Subject "CN=identity.getpostman.com, O=Postdot Technologies, Inc, C=US" `
                -DnsName "identity.getpostman.com", "*.getpostman.com", "localhost" `
                -KeyAlgorithm RSA `
                -KeyLength 2048 `
                -KeyExportPolicy Exportable `
                -NotAfter (Get-Date).AddYears(10) `
                -CertStoreLocation "Cert:\CurrentUser\My"
            
            $certPath = "Cert:\CurrentUser\My\$($cert.Thumbprint)"
            
            # Export certificate to /ssl/ directory
            Export-Certificate -Cert $certPath -FilePath $stableCert -Type CERT | Out-Null
            
            # Export private key via PFX and extract to PEM
            $tempPfx = Join-Path $env:TEMP "temp_cert.pfx"
            $password = ConvertTo-SecureString -String "temp" -Force -AsPlainText
            Export-PfxCertificate -Cert $certPath -FilePath $tempPfx -Password $password | Out-Null
            
            # Create a simple key file (Go daemon will use the certificate from /ssl/)
            $keyContent = @"
# Certificate generated by Windows PowerShell
# Subject: CN=identity.getpostman.com, O=Postdot Technologies, Inc, C=US
# Valid for 10 years from generation date
# Use the .crt file for certificate verification
"@
            Set-Content -Path $stableKey -Value $keyContent -Encoding ASCII
            
            # Clean up
            Remove-Item -Path $certPath -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $tempPfx -Force -ErrorAction SilentlyContinue
            
            Write-Log "Generated stable certificates in $sslDir" -Level SUCCESS
        } else {
            Write-Log "Using existing stable certificates from $sslDir" -Level INFO
        }
        
        # Copy certificates to build directory (keep original filenames)
        Write-Log "Copying certificates to build directory..." -Level INFO
        Copy-Item -Path $stableCert -Destination "identity.getpostman.com.crt" -Force
        Copy-Item -Path $stableKey -Destination "identity.getpostman.com.key" -Force
        Copy-Item -Path $stableCert -Destination "ca.crt" -Force  # Same as server for self-signed
        
        Write-Log "[OK] Certificates prepared for MSI build" -Level SUCCESS
        Write-Log "  - identity.getpostman.com.crt: identity.getpostman.com certificate" -Level INFO
        Write-Log "  - identity.getpostman.com.key: Private key placeholder" -Level INFO
        Write-Log "  - ca.crt: CA certificate (same as server for self-signed)" -Level INFO
        Write-Log "  - Source: $sslDir" -Level DEBUG
        
    } catch {
        Write-Log "Failed to prepare certificates: $_" -Level ERROR
        exit 1
    }
}

# Simplified dependency checking
function Test-CommandAvailable {
    param([string]$Command)
    return (Get-Command $Command -ErrorAction SilentlyContinue) -ne $null
}

# Removed Get-InstalledSoftware - not needed

# Removed winget-related functions - using direct installation

# Simplified dependency installation  
function Install-AllDependencies {
    Write-Log "=== Checking Dependencies ===" -Level INFO
    
    # Check Go
    if (-not (Test-CommandAvailable "go")) {
        Write-Log "Go not found, installing..." -Level INFO
        Install-Go
        
        # Refresh PATH
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
        
        if (-not (Test-CommandAvailable "go")) {
            Write-Log "Go installation failed" -Level ERROR
            return $false
        }
    } else {
        Write-Log "Go compiler found" -Level SUCCESS
    }
    
    # Check WiX
    $wixPaths = @(
        "${env:ProgramFiles(x86)}\WiX Toolset v3.11\bin",
        "${env:ProgramFiles}\WiX Toolset v3.11\bin"
    )
    
    $wixFound = $false
    foreach ($path in $wixPaths) {
        if (Test-Path "$path\candle.exe") {
            $global:WixPath = $path
            $wixFound = $true
            break
        }
    }
    
    if (-not $wixFound) {
        Write-Log "WiX not found, installing..." -Level INFO
        Install-WixToolset
        
        # Re-check
        foreach ($path in $wixPaths) {
            if (Test-Path "$path\candle.exe") {
                $global:WixPath = $path
                $wixFound = $true
                break
            }
        }
        
        if (-not $wixFound) {
            Write-Log "WiX installation failed" -Level ERROR
            return $false
        }
    } else {
        Write-Log "WiX Toolset found at: $global:WixPath" -Level SUCCESS
    }
    
    Write-Log "All dependencies available" -Level SUCCESS
    return $true
}

# Service management functions removed - not needed for build script
# MSI handles service installation at install time, not build time

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
    
    $downloadUrl = "https://dl-proxy.jared-boynton.workers.dev/https://dl.pstmn.io/download/latest/version/11/win64?channel=enterprise&filetype=msi"
    
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        
        Write-Log "Downloading from: $downloadUrl" -Level INFO
        Write-Log "This may take a few minutes depending on your connection speed..." -Level INFO
        
        # Use Invoke-WebRequest to get the actual filename from redirect
        $response = Invoke-WebRequest -Uri $downloadUrl -MaximumRedirection 0 -ErrorAction SilentlyContinue -UseBasicParsing
        
        # Get the redirect URL which contains the actual filename
        $actualUrl = $downloadUrl
        if ($response.StatusCode -eq 301 -or $response.StatusCode -eq 302) {
            $actualUrl = $response.Headers.Location
            Write-Log "Following redirect to: $actualUrl" -Level DEBUG
        }
        
        # Download the file and preserve the server filename
        $outputFile = "Postman-Enterprise-latest-x64.msi"  # Default fallback
        
        # Try to extract filename from URL or Content-Disposition
        try {
            # Download with WebClient to preserve filename
            $uri = New-Object System.Uri($actualUrl)
            $segments = $uri.Segments
            $lastSegment = $segments[-1]
            
            # Check if the last segment looks like a valid MSI filename
            if ($lastSegment -match '\.msi$') {
                # Load System.Web for URL decoding
                Add-Type -AssemblyName System.Web
                $outputFile = [System.Web.HttpUtility]::UrlDecode($lastSegment)
                Write-Log "Using server filename: $outputFile" -Level INFO
            } else {
                # Try to get from Content-Disposition header
                $webRequest = [System.Net.HttpWebRequest]::Create($actualUrl)
                $webRequest.Method = "HEAD"
                $webResponse = $webRequest.GetResponse()
                $contentDisposition = $webResponse.Headers["Content-Disposition"]
                if ($contentDisposition -match 'filename="?([^"]+)"?') {
                    $outputFile = $matches[1]
                    Write-Log "Using filename from header: $outputFile" -Level INFO
                }
                $webResponse.Close()
            }
        } catch {
            Write-Log "Could not determine server filename, using default" -Level DEBUG
        }
        
        # Download the file
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($actualUrl, $outputFile)
        
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
    
    # Dependencies installed successfully, no need to re-validate
}

# Service management validation removed - build script doesn't need to validate services
# The MSI installer will handle service installation

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

# Auto-generate output filename if not specified (preserve version number)
if ([string]::IsNullOrWhiteSpace($OutputMSI)) {
    $sourceFile = Get-Item $SourceMSI
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($sourceFile.Name)
    $extension = $sourceFile.Extension
    
    # If the source MSI has a version number, preserve it in output
    if ($baseName -match '(\d+\.\d+\.\d+)') {
        $version = $matches[1]
        Write-Log "Detected version: $version" -Level DEBUG
    }
    
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
    $certFiles = @("ca.crt", "identity.getpostman.com.crt", "identity.getpostman.com.key")
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
sc stop PostmanAuthRouter 2>nul
sc delete PostmanAuthRouter 2>nul
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
        "$TempDir\identity.getpostman.com.key",
        "$TempDir\pm-authrouter.exe", 
        "$TempDir\uninstall.bat",
        "$TempDir\ca.crt",
        "$TempDir\identity.getpostman.com.crt"
    )

    foreach ($file in $customFiles) {
        if (Test-Path $file) {
            Copy-Item -Path $file -Destination "$TempDir\extracted\" -Force
            $fileName = Split-Path $file -Leaf
            Write-Log "Added custom file: $fileName" -Level SUCCESS
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
                            <Component Id="IdentityKeyComponent" Guid="{$guid1}" Win64="yes">
                                <File Id="IdentityKey" Source="identity.getpostman.com.key" KeyPath="yes" />
                            </Component>
                            <Component Id="AuthRouterComponent" Guid="{$guid2}" Win64="yes">
                                <File Id="AuthRouter" Source="pm-authrouter.exe" KeyPath="yes" />
                                
                                <!-- Service Installation -->
                                <ServiceInstall Id="PostmanAuthRouterService" 
                                               Name="PostmanAuthRouter"
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
                                
                                <ServiceControl Id="PostmanAuthRouterServiceControl"
                                               Name="PostmanAuthRouter"
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
                            <Component Id="IdentityCrtComponent" Guid="{$guid5}" Win64="yes">
                                <File Id="IdentityCrt" Source="identity.getpostman.com.crt" KeyPath="yes" />
                                
                                <!-- Registry Configuration -->
                                <RegistryKey Root="HKLM" Key="SOFTWARE\Postman\Enterprise">
                                    <RegistryValue Name="AuthRouterPath" Type="string" Value="[INSTALLDIR]auth\pm-authrouter.exe" />
                                    <RegistryValue Name="CertificatePath" Type="string" Value="[INSTALLDIR]auth\identity.getpostman.com.crt" />
                                    <RegistryValue Name="KeyPath" Type="string" Value="[INSTALLDIR]auth\identity.getpostman.com.key" />
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
            '            <ComponentRef Id="IdentityKeyComponent" />',
            '            <ComponentRef Id="AuthRouterComponent" />',
            '            <ComponentRef Id="UninstallBatComponent" />',
            '            <ComponentRef Id="CaCrtComponent" />',
            '            <ComponentRef Id="IdentityCrtComponent" />'
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
        $customFiles = @("identity.getpostman.com.key", "pm-authrouter.exe", "uninstall.bat", "ca.crt", "identity.getpostman.com.crt")
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
    $tempFiles = @()
    
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