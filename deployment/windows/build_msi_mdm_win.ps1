# Postman Enterprise MSI Repackaging Script
# This script extracts the original MSI, adds custom files, and repackages it

param(
    [string]$team = "",
    [string]$saml_url = "",
    [switch]$debug = $false,
    [string]$log_file = ""  # Optional log file path for CI/CD pipelines
)

# Set up script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrEmpty($scriptDir)) {
    $scriptDir = Get-Location
}

# Simplified Logging System
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    # Write to console with appropriate colors
    switch ($Level) {
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        "DEBUG" { if ($debug) { Write-Host $logMessage -ForegroundColor Cyan } }
        default { Write-Host $logMessage }
    }

    # Write to log file if specified
    if (-not [string]::IsNullOrEmpty($log_file)) {
        try {
            $logDir = Split-Path $log_file -Parent
            if (-not (Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            Add-Content -Path $log_file -Value $logMessage -Encoding UTF8
        } catch {
            Write-Host "Failed to write to log file: $_" -ForegroundColor Red
        }
    }
}

# Intelligent function to find project root by looking for go.mod
function Find-ProjectRoot {
    param(
        [string]$StartPath = $PSScriptRoot
    )
    
    Write-Log "Searching for project root starting from: $StartPath" -Level DEBUG
    
    # Start with the provided path (no symbolic link resolution for UNC paths)
    $currentPath = $StartPath
    
    # Traverse up the directory tree looking for go.mod
    $maxDepth = 10  # Prevent infinite loops
    $depth = 0
    
    while ($currentPath -and $depth -lt $maxDepth) {
        $goModPath = Join-Path $currentPath "go.mod"
        Write-Log "Checking for go.mod at: $goModPath" -Level DEBUG
        
        if (Test-Path $goModPath) {
            Write-Log "Found go.mod at: $goModPath" -Level DEBUG
            
            # Verify it's the right go.mod by checking for expected structure
            $cmdPath = Join-Path $currentPath "cmd\pm-authrouter"
            Write-Log "Checking for cmd directory at: $cmdPath" -Level DEBUG
            
            if (Test-Path $cmdPath) {
                Write-Log "Found project root at: $currentPath" -Level DEBUG
                return $currentPath
            } else {
                Write-Log "Found go.mod but missing cmd\pm-authrouter, continuing search..." -Level DEBUG
            }
        }
        
        # Get parent directory
        $parent = Split-Path $currentPath -Parent
        
        # Check if we've reached the root or if parent is the same as current
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $currentPath) {
            Write-Log "Reached filesystem root" -Level DEBUG
            break
        }
        
        $currentPath = $parent
        $depth++
    }
    
    if ($depth -eq $maxDepth) {
        Write-Log "Max depth reached while searching for project root" -Level WARNING
    }
    
    Write-Log "Could not find project root with go.mod and cmd\pm-authrouter" -Level ERROR
    return $null
}

# Utility Functions for Common Patterns
function Add-ValidationError {
    param(
        [ref]$ErrorArray,
        [string]$Message
    )
    $ErrorArray.Value += $Message
}

function Format-FileSize {
    param([long]$SizeInBytes)

    if ($SizeInBytes -ge 1MB) {
        return "$('{0:N1}' -f ($SizeInBytes/1MB))MB"
    } elseif ($SizeInBytes -ge 1KB) {
        return "$('{0:N0}' -f ($SizeInBytes/1KB))KB"
    } else {
        return "$SizeInBytes bytes"
    }
}

function Clear-EnvironmentVariables {
    $envVarsToClean = @('GOOS', 'GOARCH', 'CGO_ENABLED')
    foreach ($var in $envVarsToClean) {
        Remove-Item "env:$var" -ErrorAction SilentlyContinue
    }
}

function Test-ConfigurationParameters {
    if ([string]::IsNullOrEmpty($team) -or [string]::IsNullOrEmpty($saml_url)) {
        Write-Log "Missing configuration parameters. Service will be installed but not activated until configured." -Level WARNING
        Write-Log "Configure via: msiexec /i package.msi TEAM_NAME=myteam SAML_URL=https://saml.url/init" -Level INFO
    }
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Dependency checker with auto-installation
function Test-AndInstallDependencies {
    Write-Log "Checking dependencies..." -Level INFO

    # Check Go
    $goFound = $false
    try {
        $goVersion = & go version 2>$null
        if ($LASTEXITCODE -eq 0 -and $goVersion -match "go(\d+)\.(\d+)") {
            $major = [int]$matches[1]
            $minor = [int]$matches[2]
            if ($major -gt 1 -or ($major -eq 1 -and $minor -ge 21)) {
                Write-Log "Found Go: $goVersion" -Level SUCCESS
                $goFound = $true
            }
        }
    } catch { }

    if (-not $goFound) {
        Write-Log "Go not found or version too old. Installing..." -Level WARNING
        Install-Go
    }

    # Check WiX - support both v3.x and v4.x versions
    $global:WixPath = $null
    $wixSearchPaths = @("${env:ProgramFiles}", "${env:ProgramFiles(x86)}")
    
    foreach ($basePath in $wixSearchPaths) {
        $found = Get-ChildItem "$basePath\WiX Toolset*" -Directory -ErrorAction SilentlyContinue | 
                 Where-Object { Test-Path "$($_.FullName)\bin\candle.exe" } | 
                 Sort-Object Name -Descending | Select-Object -First 1
        if ($found) {
            $global:WixPath = "$($found.FullName)\bin"
            Write-Log "Found WiX Toolset at: $global:WixPath" -Level SUCCESS
            break
        }
    }

    if (-not $global:WixPath) {
        Write-Log "WiX Toolset not found. Installing WiX v3.14.1..." -Level WARNING
        Install-WixToolset
        # Re-check after installation - WiX 3.14 installs to Program Files (x86) by default
        $global:WixPath = "${env:ProgramFiles(x86)}\WiX Toolset v3.14\bin"
        if (-not (Test-Path "$global:WixPath\candle.exe")) {
            $global:WixPath = $null
        }
    }

    return ($goFound -or (Test-CommandAvailable "go")) -and $global:WixPath
}

function Test-SourceFiles {
    # Quick validation of essential files using intelligent project root detection
    $projectRoot = Find-ProjectRoot -StartPath $scriptDir
    
    if (-not $projectRoot) {
        Write-Log "Could not find project root for source file validation" -Level ERROR
        return $false
    }
    
    $requiredFiles = @(
        "$projectRoot\go.mod"
    )

    foreach ($file in $requiredFiles) {
        if (-not (Test-Path $file)) {
            Write-Log "Missing required file: $file" -Level ERROR
            return $false
        }
    }

    if (-not (Test-Path "$projectRoot\cmd\pm-authrouter" -PathType Container)) {
        Write-Log "Missing required directory: cmd\pm-authrouter" -Level ERROR
        return $false
    }

    Write-Log "Source files validated" -Level SUCCESS
    return $true
}

function Test-OutputValidation {
    param(
        [string]$OutputPath,
        [string]$TempDirectory
    )
    
    Write-Log "=== Phase 5: Output Validation ===" -Level INFO
    $validationErrors = @()
    
    if (-not (Test-Path $OutputPath)) {
        $validationErrors += "Output MSI file was not created: $OutputPath"
        return $false
    }
    
    try {
        $outputInfo = Get-ItemProperty $OutputPath
        $sizeMB = $outputInfo.Length / 1MB
        
        if ($sizeMB -lt 50) {
            Add-ValidationError -ErrorArray ([ref]$validationErrors) -Message "Output MSI too small ($(Format-FileSize -SizeInBytes $outputInfo.Length)) - likely incomplete"
        } elseif ($sizeMB -gt 200) {
            Add-ValidationError -ErrorArray ([ref]$validationErrors) -Message "Output MSI too large ($(Format-FileSize -SizeInBytes $outputInfo.Length)) - may have issues"
        } else {
            Write-Log "Output MSI size: $(Format-FileSize -SizeInBytes $outputInfo.Length)" -Level INFO
        }
        
        # Try to read MSI properties using msiexec
        Write-Log "Validating MSI structure..." -Level INFO
        $tempValidationDir = Join-Path $TempDirectory "msi-validation"
        New-Item -ItemType Directory -Path $tempValidationDir -Force | Out-Null
        
        Write-Log "MSI structure validated during WiX linking process" -Level SUCCESS
        
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

# Certificate management
function Ensure-StableCertificates {
    Write-Log "Checking for stable certificates..." -Level INFO
    
    try {
        $projectRoot = Find-ProjectRoot -StartPath $PSScriptRoot
        
        if (-not $projectRoot) {
            throw "Could not find project root (go.mod not found)"
        }
        
        $sslDir = Join-Path $projectRoot "ssl"
        $stableCert = Join-Path $sslDir "identity.getpostman.com.crt"
        $stableKey = Join-Path $sslDir "identity.getpostman.com.key"
        
        if (-not (Test-Path $stableCert) -or -not (Test-Path $stableKey)) {
            Write-Log "Stable certificates not found in $sslDir, generating..." -Level INFO
            
            if (-not (Test-Path $sslDir)) {
                New-Item -ItemType Directory -Path $sslDir -Force | Out-Null
            }
            
            $cert = New-SelfSignedCertificate `
                -Subject "CN=identity.getpostman.com, O=Postdot Technologies, Inc, C=US" `
                -DnsName "identity.getpostman.com", "*.getpostman.com", "localhost" `
                -KeyAlgorithm RSA `
                -KeyLength 2048 `
                -KeyExportPolicy Exportable `
                -NotAfter (Get-Date).AddYears(10) `
                -CertStoreLocation "Cert:\CurrentUser\My"
            
            $certPath = "Cert:\CurrentUser\My\$($cert.Thumbprint)"
            
            Export-Certificate -Cert $certPath -FilePath $stableCert -Type CERT | Out-Null
            
            $tempPfx = Join-Path $env:TEMP "temp_cert.pfx"
            $password = ConvertTo-SecureString -String "temp" -Force -AsPlainText
            Export-PfxCertificate -Cert $certPath -FilePath $tempPfx -Password $password | Out-Null
            
            $keyContent = @"
# Certificate generated by Windows PowerShell
# Subject: CN=identity.getpostman.com, O=Postdot Technologies, Inc, C=US
# Valid for 10 years from generation date
# Use the .crt file for certificate verification
"@
            Set-Content -Path $stableKey -Value $keyContent -Encoding ASCII
            
            Remove-Item -Path $certPath -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $tempPfx -Force -ErrorAction SilentlyContinue
            
            Write-Log "Generated stable certificates in $sslDir" -Level SUCCESS
        } else {
            Write-Log "Using existing stable certificates from $sslDir" -Level INFO
        }
        
        Write-Log "Copying certificates to temp directory..." -Level INFO
        # Copy to temp directory instead of current directory
        $tempCertPath = Join-Path $TempDir "identity.getpostman.com.crt"
        $tempKeyPath = Join-Path $TempDir "identity.getpostman.com.key"
        Copy-Item -Path $stableCert -Destination $tempCertPath -Force
        Copy-Item -Path $stableKey -Destination $tempKeyPath -Force
        
        Write-Log "[OK] Certificates prepared for MSI build" -Level SUCCESS
        Write-Log "  - identity.getpostman.com.crt: Server certificate for identity.getpostman.com" -Level INFO
        Write-Log "  - identity.getpostman.com.key: Private key placeholder" -Level INFO

        
    } catch {
        Write-Log "Failed to prepare certificates: $_" -Level ERROR
        exit 1
    }
}

function Test-CommandAvailable {
    param([string]$Command)
    return (Get-Command $Command -ErrorAction SilentlyContinue) -ne $null
}

# Function to check and install Go
function Install-Go {
    Write-Log "Go not found. Installing Go 1.25.0 automatically..." -Level WARNING
    
    # Admin check is handled by main script
    
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
    Write-Log "WiX Toolset not found. Installing WiX v3.14.1 automatically..." -Level WARNING
    
    # Admin check is handled by main script
    
    $wixUrl = "https://github.com/wixtoolset/wix3/releases/download/wix3141rtm/wix314.exe"
    $wixInstaller = "$env:TEMP\wix314.exe"
    
    try {
        Write-Log "Downloading WiX Toolset v3.14.1..." -Level INFO
        Write-Log "Note: WiX v3.14.1 supports ARM64 Windows via x86 emulation" -Level INFO
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $wixUrl -OutFile $wixInstaller -UseBasicParsing
        
        Write-Log "Installing WiX Toolset v3.14.1 (this may take a few minutes)..." -Level INFO
        Start-Process -FilePath $wixInstaller -ArgumentList "/quiet", "/norestart" -Wait
        
        # Clean up installer
        Remove-Item $wixInstaller -Force -ErrorAction SilentlyContinue
        
        Write-Log "WiX Toolset v3.14.1 installed successfully!" -Level SUCCESS
    } catch {
        Write-Log "Failed to install WiX Toolset: $_" -Level ERROR
        Write-Log "Please install manually from: https://github.com/wixtoolset/wix3/releases" -Level ERROR
        exit 1
    }
}

# Function to find Postman MSI
function Find-PostmanMSI {
    Write-Log "Looking for Postman Enterprise MSI in script directory..." -Level INFO
    
    # Look in script directory, not current directory
    $searchPath = $scriptDir
    
    # Look for Postman MSI files matching common patterns
    $patterns = @(
        "Postman-Enterprise-*.msi",
        "Postman-*.msi",
        "*postman*.msi"
    )
    
    foreach ($pattern in $patterns) {
        $files = Get-ChildItem -Path $searchPath -Filter $pattern -File -ErrorAction SilentlyContinue | 
                 Where-Object { $_.Name -notmatch "-saml\.msi$" } |
                 Sort-Object LastWriteTime -Descending
        
        if ($files.Count -gt 0) {
            $msiFile = $files[0].FullName  # Return full path
            Write-Log "Found MSI: $($files[0].Name)" -Level SUCCESS
            return $msiFile
        }
    }
    
    return $null
}

# Function to download Postman MSI
function Download-PostmanMSI {
    Write-Log "Downloading Postman Enterprise MSI..." -Level WARNING
    
    $downloadUrl = "https://dl-proxy.jared-boynton.workers.dev/https://dl.pstmn.io/download/latest/version/11/win64?channel=enterprise&filetype=msi"
    
    # Enable TLS 1.2 for secure connections
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    
    Write-Log "Downloading from: $downloadUrl" -Level INFO
    Write-Log "This may take a few minutes depending on your connection speed..." -Level INFO
    
    # Mimic curl behavior with -J -O flags (respect Content-Disposition and save with server filename)
    $outputFile = $null
    $maxRetries = 2
    $retryDelay = 3
    $connectTimeout = 10  # seconds
    $maxTime = 60  # 15 minutes max download time
    
    for ($retry = 0; $retry -le $maxRetries; $retry++) {
        try {
            if ($retry -gt 0) {
                Write-Log "Retry attempt $retry of $maxRetries (waiting ${retryDelay}s)..." -Level WARNING
                Start-Sleep -Seconds $retryDelay
            }
            
            Write-Log "Attempt $($retry + 1): Fetching headers to determine filename..." -Level INFO
            
            # First, make a HEAD request to get Content-Disposition header (like curl -J)
            $webRequest = [System.Net.HttpWebRequest]::Create($downloadUrl)
            $webRequest.Method = "HEAD"
            $webRequest.Timeout = $connectTimeout * 1000  # Convert to milliseconds
            $webRequest.AllowAutoRedirect = $true  # Follow redirects like curl -L
            $webRequest.UserAgent = "pm-authrouter"  # Set user agent like curl -A
            $webRequest.KeepAlive = $true  # TCP keep-alive like curl --tcp-nodelay
            
            try {
                $webResponse = $webRequest.GetResponse()
                
                # Check Content-Disposition header for filename (curl -J behavior)
                $contentDisposition = $webResponse.Headers["Content-Disposition"]
                if ($contentDisposition) {
                    Write-Log "Content-Disposition header found: $contentDisposition" -Level DEBUG
                    if ($contentDisposition -match 'filename\s*=\s*"?([^";]+)"?') {
                        $serverFilename = $matches[1].Trim('"').Trim()
                        if ($serverFilename -match '\.msi$') {
                            $outputFile = $serverFilename
                            Write-Log "Server provided filename: $outputFile" -Level SUCCESS
                        }
                    }
                }
                
                # If no Content-Disposition, try to get filename from final URL after redirects
                if (-not $outputFile) {
                    $finalUrl = $webResponse.ResponseUri.ToString()
                    Write-Log "Final URL after redirects: $finalUrl" -Level DEBUG
                    
                    # Extract filename from URL
                    if ($finalUrl -match '/([^/]+\.msi)(\?|$)') {
                        $urlFilename = $matches[1]
                        if ($urlFilename) {
                            Add-Type -AssemblyName System.Web
                            $outputFile = [System.Web.HttpUtility]::UrlDecode($urlFilename)
                            Write-Log "Filename from URL: $outputFile" -Level INFO
                        }
                    }
                }
                
                $webResponse.Close()
            } catch {
                Write-Log "Failed to get headers: $_" -Level WARNING
            }
            
            # Fallback filename if we couldn't determine it
            if (-not $outputFile) {
                $outputFile = "Postman-Enterprise-11.60.0-enterprise01-x64.msi"
                Write-Log "Using fallback filename: $outputFile" -Level WARNING
            }
            
            # Ensure we download to script directory, not current directory
            $outputFile = Join-Path $scriptDir $outputFile
            
            Write-Log "Downloading to: $outputFile" -Level INFO
            
            # Now download the actual file (like curl -O)
            $webClient = New-Object System.Net.WebClient
            $webClient.Headers.Add("User-Agent", "pm-authrouter")
            
            # Register event for progress reporting if in debug mode
            if ($debug) {
                $progressShown = $false
                Register-ObjectEvent -InputObject $webClient -EventName DownloadProgressChanged -Action {
                    if (-not $progressShown) {
                        Write-Host "Download progress: $($EventArgs.ProgressPercentage)%" -NoNewline
                        Write-Host "`r" -NoNewline
                        if ($EventArgs.ProgressPercentage -eq 100) {
                            $progressShown = $true
                        }
                    }
                } | Out-Null
            }
            
            # Set up timeout for download
            $downloadTimer = [System.Diagnostics.Stopwatch]::StartNew()
            
            # Async download with timeout check
            $downloadTask = $webClient.DownloadFileTaskAsync($downloadUrl, $outputFile)
            
            while (-not $downloadTask.IsCompleted) {
                if ($downloadTimer.Elapsed.TotalSeconds -gt $maxTime) {
                    $webClient.CancelAsync()
                    throw "Download timeout after $maxTime seconds"
                }
                Start-Sleep -Milliseconds 100
            }
            
            if ($downloadTask.IsFaulted) {
                throw $downloadTask.Exception.InnerException
            }
            
            # Verify the file was downloaded
            if (Test-Path $outputFile) {
                $fileSize = (Get-Item $outputFile).Length
                if ($fileSize -gt 0) {
                    Write-Log "Downloaded successfully: $outputFile ($(Format-FileSize -SizeInBytes $fileSize))" -Level SUCCESS
                    return $outputFile
                } else {
                    throw "Downloaded file is empty"
                }
            } else {
                throw "Download completed but file not found"
            }
            
        } catch {
            Write-Log "Download attempt $($retry + 1) failed: $_" -Level ERROR
            
            # Clean up partial download
            if ($outputFile -and (Test-Path $outputFile)) {
                Remove-Item $outputFile -Force -ErrorAction SilentlyContinue
            }
            
            if ($retry -eq $maxRetries) {
                Write-Log "Failed to download Postman MSI after $($maxRetries + 1) attempts" -Level ERROR
                Write-Log "You can manually download from: $downloadUrl" -Level ERROR
                exit 1
            }
        }
    }
}

Test-ConfigurationParameters

# Main script starts here
Write-Log "=== Postman Enterprise MSI Repackaging Script ===" -Level INFO
Write-Log "Script directory: $scriptDir" -Level INFO
Write-Log "Team Name: $(if ($team) { $team } else { '[not configured - will be set at install time]' })" -Level INFO
Write-Log "SAML URL: $(if ($saml_url) { $saml_url } else { '[not configured - will be set at install time]' })" -Level INFO
if (-not [string]::IsNullOrEmpty($log_file)) {
    Write-Log "Logging to: $log_file" -Level INFO
}

# Single administrator check with user prompt
if (-not (Test-Administrator)) {
    Write-Log "WARNING: Not running as Administrator" -Level WARNING
    Write-Log "Some operations may require elevated privileges (auto-install tools, MSI operations)" -Level WARNING
    $response = Read-Host "Continue anyway? (y/N)"
    if ($response -notmatch "^[Yy]$") {
        Write-Log "Script cancelled by user" -Level INFO
        exit 0
    }
    Write-Log "Continuing without administrator privileges..." -Level WARNING
}

# Run consolidated validation
Write-Log "Validating environment and dependencies..." -Level INFO

# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Log "PowerShell 5.0+ required. Exiting." -Level ERROR
    exit 1
}

if (-not (Test-AndInstallDependencies)) {
    Write-Log "Dependencies validation failed. Exiting." -Level ERROR
    exit 1
}

# Dependencies are now validated - proceed with MSI operations

# Auto-detect or download source MSI
$SourceMSI = Find-PostmanMSI

if ($null -eq $SourceMSI) {
    # No MSI found, download it automatically
    Write-Log "No Postman MSI found in script directory. Downloading..." -Level WARNING
    $SourceMSI = Download-PostmanMSI
}

if (-not (Test-Path $SourceMSI)) {
    Write-Log "Source MSI not found after download attempt." -Level ERROR
    exit 1
}

# Run source file validation
Write-Log "Validating source files..." -Level INFO
if (-not (Test-SourceFiles)) {
    Write-Log "Source file validation failed. Exiting." -Level ERROR
    exit 1
}

# Auto-generate output filename (preserve version number)
$sourceFile = Get-Item $SourceMSI
$baseName = [System.IO.Path]::GetFileNameWithoutExtension($sourceFile.Name)
$extension = $sourceFile.Extension

# If the source MSI has a version number, preserve it in output
if ($baseName -match '(\d+\.\d+\.\d+)') {
    $version = $matches[1]
}

# Always save output to script directory
$OutputMSI = Join-Path $scriptDir "$baseName-saml$extension"
Write-Log "Output MSI will be: $OutputMSI" -Level INFO

# Auto-generate temp directory
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

Write-Log "Creating temporary directory: $TempDir" -Level INFO
if (Test-Path $TempDir) {
    Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

# Generate certificates in temp directory
Push-Location $TempDir
try {
    Ensure-StableCertificates
} finally {
    Pop-Location
}

Write-Log "Checking for other required files..." -Level INFO

Write-Log "Building pm-authrouter.exe from source..." -Level INFO
$projectRoot = Find-ProjectRoot -StartPath $scriptDir

if (-not $projectRoot) {
    Write-Log "Could not find go.mod file. Please ensure the script is run from within the project directory structure." -Level ERROR
    Write-Log "Expected structure: project root should contain go.mod and cmd\pm-authrouter" -Level ERROR
    exit 1
}

Write-Log "Found project root: $projectRoot" -Level INFO
Write-Log "Building Windows binary for pm-authrouter..." -Level INFO

# Save current location and switch to project root
Push-Location $projectRoot
try {
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    $env:CGO_ENABLED = "0"

    $buildArgs = @(
        "build",
        "-buildvcs=false",  # Disable VCS stamping
        "-ldflags=-w -s",  # Strip debugging info and symbol table
        "-o", "$TempDir\pm-authrouter.exe",
        ".\cmd\pm-authrouter"
    )

    Write-Log "Executing: go $($buildArgs -join ' ')" -Level INFO
    & go @buildArgs
    
    if ($LASTEXITCODE -ne 0) {
        throw "Go build failed with exit code $LASTEXITCODE"
    }
    
    # Verify the binary was created
    if (Test-Path "$TempDir\pm-authrouter.exe") {
        $binarySize = (Get-Item "$TempDir\pm-authrouter.exe").Length
        Write-Log "[OK] Built pm-authrouter.exe ($(Format-FileSize -SizeInBytes $binarySize))" -Level SUCCESS
    } else {
        throw "Binary not found after build"
    }
    
} catch {
    Write-Log "Failed to build pm-authrouter.exe: $_" -Level ERROR
    exit 1
} finally {
    Pop-Location
    Clear-EnvironmentVariables
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
Write-Log "Original MSI size: $(Format-FileSize -SizeInBytes $originalSize)" -Level INFO

# Validation functions
function Test-CabinetCompression {
    param([string]$ExtractedPath)
    
    if ($ValidateCompression) {
        Write-Log "Validating cabinet compression..."
        
        $starshipCab = Get-ChildItem -Path $ExtractedPath -Name "starship.cab" -Recurse -ErrorAction SilentlyContinue

        if ($starshipCab) {
            $cabPath = Join-Path $ExtractedPath $starshipCab
            $cabSize = (Get-Item $cabPath).Length
            Write-Log "Found starship.cab: $(Format-FileSize -SizeInBytes $cabSize) (compressed)" -ForegroundColor Green
            return $true
        } else {
            $extractedFiles = Get-ChildItem -Path $ExtractedPath -Recurse -File | Where-Object { $_.Extension -in @('.exe', '.dll', '.pak', '.dat') -and $_.Name -ne 'pm-authrouter.exe' }

            if ($extractedFiles.Count -gt 50) {  # Arbitrary threshold indicating extraction
                Write-Log "Warning: Detected $($extractedFiles.Count) extracted files - starship.cab may have been decompressed!" -Level WARNING
                return $false
            } else {
                Write-Log "Cabinet appears to remain compressed (found $($extractedFiles.Count) individual files)" -ForegroundColor Green
                return $true
            }
        }
    }
    return $true
}

try {
    # Extract MSI using WiX dark.exe
    Write-Log "Extracting MSI with dark.exe..." -Level INFO
    
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

    Write-Log "Adding custom files to MSI..." -Level INFO
    $customFiles = @(
        "$TempDir\identity.getpostman.com.key",
        "$TempDir\pm-authrouter.exe",
        "$TempDir\uninstall.bat",
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

    $guid1 = [System.Guid]::NewGuid().ToString().ToUpper()
    $guid2 = [System.Guid]::NewGuid().ToString().ToUpper()
    $guid3 = [System.Guid]::NewGuid().ToString().ToUpper()
    $guid4 = [System.Guid]::NewGuid().ToString().ToUpper()
    $guid5 = [System.Guid]::NewGuid().ToString().ToUpper()
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
                                               Arguments="--mode service --team &quot;[TEAM_NAME]&quot; --saml-url &quot;[SAML_URL]&quot;"
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
                            <Component Id="IdentityCrtComponent" Guid="{$guid4}" Win64="yes">
                                <File Id="IdentityCrt" Source="identity.getpostman.com.crt" KeyPath="yes" />

                                <!-- Install server certificate to LocalMachine Root store for browser trust -->
                                <iis:Certificate Id="ServerCertificate"
                                               Name="identity.getpostman.com"
                                               StoreLocation="localMachine"
                                               StoreName="root"
                                               BinaryKey="ServerCertBinary"
                                               Overwrite="yes" />

                                <!-- Registry Configuration -->
                                <RegistryKey Root="HKLM" Key="SOFTWARE\Postman\Enterprise">
                                    <RegistryValue Name="AuthRouterPath" Type="string" Value="[INSTALLDIR]auth\pm-authrouter.exe" />
                                    <RegistryValue Name="CertificatePath" Type="string" Value="[INSTALLDIR]auth\identity.getpostman.com.crt" />
                                    <RegistryValue Name="KeyPath" Type="string" Value="[INSTALLDIR]auth\identity.getpostman.com.key" />
                                    <!-- Team name from build-time parameter or MSI property -->
                                    <RegistryValue Name="TeamName" Type="string" Value="[TEAM_NAME]" />
                                    <!-- SAML URL from build-time parameter or MSI property -->
                                    <RegistryValue Name="SamlUrl" Type="string" Value="[SAML_URL]" />
                                </RegistryKey>
                            </Component>
                        </Directory>
"@

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
            '            <ComponentRef Id="IdentityCrtComponent" />'
        )
        $lines = $lines[0..($featureEnd - 1)] + $componentRefs + $lines[$featureEnd..($lines.Length - 1)]
    }
    
    $binarySection = @(
        '',
        '        <!-- Binary data for certificates -->',
        '        <Binary Id="ServerCertBinary" SourceFile="identity.getpostman.com.crt" />',
        '',
        '        <!-- MSI Properties for install-time configuration -->'
    )
    
    # Add properties - use provided values or default placeholders for MSI property substitution
    if (-not [string]::IsNullOrEmpty($team)) {
        $binarySection += "        <Property Id=`"TEAM_NAME`" Value=`"$team`" />"
    } else {
        # Add default placeholder for command-line override at install time
        $binarySection += "        <Property Id=`"TEAM_NAME`" Value=`"BLANK`" />"
    }
    if (-not [string]::IsNullOrEmpty($saml_url)) {
        $binarySection += "        <Property Id=`"SAML_URL`" Value=`"$saml_url`" />"
    } else {
        # Add default placeholder for command-line override at install time
        $binarySection += "        <Property Id=`"SAML_URL`" Value=`"https://identity.getpostman.com/sso/BLANK/init`" />"
    }
    
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
    Write-Log "Linking MSI with optimized settings..." -Level INFO

    $lightArgs = @(
        "-ext", "WixUtilExtension"
        "-ext", "WixIIsExtension"
        "-out", $OutputMSI
        "-b", "$TempDir\extracted"
        "-dcl:high"  # High compression
        "-ct", $env:NUMBER_OF_PROCESSORS  # Use all available threads
        "$TempDir\Product.wixobj"
    )
    
    $lightArgs += "-spdb"  # Suppress PDB creation
    
    # Suppress common warnings that don't affect functionality
    $lightArgs += "-sw1076"  # ICE76: Duplicate sequence numbers
    
    & "$WixPath\light.exe" @lightArgs
    if ($LASTEXITCODE -ne 0) {
        throw "light.exe failed with exit code $LASTEXITCODE"
    }

    Write-Log "Successfully created modified MSI: $OutputMSI" -ForegroundColor Green
    
    # Run output validation
    Write-Log "Validating output MSI..." -Level INFO
    if (-not (Test-OutputValidation -OutputPath $OutputMSI -TempDirectory $TempDir)) {
        throw "Output validation failed"
    }
    
    # Show file info and size comparison
    if (Test-Path $OutputMSI) {
        $fileInfo = Get-Item $OutputMSI
        $newSize = $fileInfo.Length
        $sizeDifference = $newSize - $originalSize
        $percentIncrease = [math]::Round(($sizeDifference / $originalSize) * 100, 2)
        
        Write-Log "Original MSI size: $(Format-FileSize -SizeInBytes $originalSize)"
        Write-Log "Modified MSI size: $(Format-FileSize -SizeInBytes $newSize)" -ForegroundColor $(if ($percentIncrease -gt 50) { "Yellow" } else { "Green" })
        Write-Log "Created: $($fileInfo.CreationTime)"
        
        # Custom files size
        $customFilesTotalSize = 0
        $customFiles = @("identity.getpostman.com.key", "pm-authrouter.exe", "uninstall.bat", "identity.getpostman.com.crt")
        foreach ($file in $customFiles) {
            $filePath = Join-Path $TempDir $file
            if (Test-Path $filePath) {
                $customFilesTotalSize += (Get-Item $filePath).Length
            }
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
}

Write-Log "Output file: $OutputMSI" -Level SUCCESS