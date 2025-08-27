# Test-MsiSizeValidation.ps1
# Critical tests for MSI size validation (must be <= 125MB)
# Validates compression efficiency and size optimization

param(
    [string]$BuildScriptPath = "$PSScriptRoot\..\..\deployment\windows\build_msi_mdm_win.ps1",
    [string]$MsiToTest = "",
    [switch]$StrictMode = $false
)

# Critical size limits
$script:Config = @{
    MaxSizeMB = 125          # Hard limit
    WarningSizeMB = 112      # 90% warning threshold  
    TargetSizeMB = 110       # Target size with LZX:21
    MinCompressionRatio = 0.4 # Expected compression ratio
}

function Test-MsiSize {
    param(
        [Parameter(Mandatory)]
        [string]$MsiPath,
        [switch]$Detailed
    )
    
    if (-not (Test-Path $MsiPath)) {
        throw "MSI file not found: $MsiPath"
    }
    
    $msi = Get-Item $MsiPath
    $sizeMB = [math]::Round($msi.Length / 1MB, 2)
    $sizeGB = [math]::Round($msi.Length / 1GB, 3)
    
    $result = @{
        Path = $MsiPath
        FileName = $msi.Name
        SizeMB = $sizeMB
        SizeGB = $sizeGB
        SizeBytes = $msi.Length
        PassesLimit = $sizeMB -le $script:Config.MaxSizeMB
        InWarningZone = $sizeMB -gt $script:Config.WarningSizeMB
        MeetsTarget = $sizeMB -le $script:Config.TargetSizeMB
        PercentOfLimit = [math]::Round(($sizeMB / $script:Config.MaxSizeMB) * 100, 1)
    }
    
    # Color-coded output
    $color = if ($result.PassesLimit) {
        if ($result.InWarningZone) { "Yellow" } else { "Green" }
    } else {
        "Red"
    }
    
    Write-Host "`n=== MSI SIZE VALIDATION ===" -ForegroundColor Cyan
    Write-Host "File: $($result.FileName)" -ForegroundColor White
    Write-Host "Size: $($result.SizeMB) MB ($($result.PercentOfLimit)% of limit)" -ForegroundColor $color
    Write-Host "Limit: $($script:Config.MaxSizeMB) MB" -ForegroundColor White
    Write-Host "Target: $($script:Config.TargetSizeMB) MB" -ForegroundColor White
    
    if ($result.PassesLimit) {
        Write-Host "STATUS: PASS" -ForegroundColor Green
        if ($result.InWarningZone) {
            Write-Host "WARNING: Size exceeds 90% of limit!" -ForegroundColor Yellow
        }
    } else {
        Write-Host "STATUS: FAIL - EXCEEDS 125MB LIMIT!" -ForegroundColor Red
        $excess = $sizeMB - $script:Config.MaxSizeMB
        Write-Host "Excess: $excess MB over limit" -ForegroundColor Red
    }
    
    if ($Detailed) {
        Write-Host "`nDetailed Analysis:" -ForegroundColor Cyan
        Write-Host "  Bytes: $($result.SizeBytes)" -ForegroundColor Gray
        Write-Host "  GB: $($result.SizeGB)" -ForegroundColor Gray
        Write-Host "  Meets target (<= $($script:Config.TargetSizeMB) MB): $($result.MeetsTarget)" -ForegroundColor Gray
    }
    
    return $result
}

function Test-CompressionEfficiency {
    param(
        [string]$OriginalPath,
        [string]$CompressedPath
    )
    
    if (-not (Test-Path $OriginalPath)) {
        Write-Warning "Original file not found for compression analysis"
        return
    }
    
    if (-not (Test-Path $CompressedPath)) {
        Write-Warning "Compressed file not found for compression analysis"
        return
    }
    
    $originalSize = (Get-Item $OriginalPath).Length
    $compressedSize = (Get-Item $CompressedPath).Length
    $ratio = $compressedSize / $originalSize
    $savings = 100 * (1 - $ratio)
    
    Write-Host "`n=== COMPRESSION ANALYSIS ===" -ForegroundColor Cyan
    Write-Host "Original size: $([math]::Round($originalSize / 1MB, 2)) MB" -ForegroundColor White
    Write-Host "Compressed size: $([math]::Round($compressedSize / 1MB, 2)) MB" -ForegroundColor White
    Write-Host "Compression ratio: $([math]::Round($ratio, 3))" -ForegroundColor $(if ($ratio -le $script:Config.MinCompressionRatio) { "Green" } else { "Yellow" })
    Write-Host "Space savings: $([math]::Round($savings, 1))%" -ForegroundColor $(if ($savings -ge 60) { "Green" } else { "Yellow" })
    
    if ($ratio -gt $script:Config.MinCompressionRatio) {
        Write-Warning "Compression ratio higher than expected. Consider optimizing compression settings."
    }
    
    return @{
        OriginalSizeMB = [math]::Round($originalSize / 1MB, 2)
        CompressedSizeMB = [math]::Round($compressedSize / 1MB, 2)
        CompressionRatio = [math]::Round($ratio, 3)
        SpaceSavingsPercent = [math]::Round($savings, 1)
        MeetsTarget = $ratio -le $script:Config.MinCompressionRatio
    }
}

function Test-LZXCompression {
    param(
        [string]$TestFilePath,
        [string]$OutputPath = "$env:TEMP\lzx_test_$(Get-Random).cab"
    )
    
    Write-Host "`n=== LZX:21 COMPRESSION TEST ===" -ForegroundColor Cyan
    
    if (-not (Get-Command makecab -ErrorAction SilentlyContinue)) {
        Write-Warning "makecab not available - skipping LZX compression test"
        return
    }
    
    # Create test file if not provided
    if (-not $TestFilePath -or -not (Test-Path $TestFilePath)) {
        $TestFilePath = "$env:TEMP\lzx_test_$(Get-Random).txt"
        # Generate compressible content
        $content = "Test data for LZX compression. " * 10000
        $content | Out-File $TestFilePath -Encoding UTF8
    }
    
    $originalSize = (Get-Item $TestFilePath).Length
    
    # Create DDF for LZX:21 compression
    $ddfPath = "$env:TEMP\lzx_test_$(Get-Random).ddf"
    $ddfContent = @"
.OPTION EXPLICIT
.Set CabinetNameTemplate=$([System.IO.Path]::GetFileName($OutputPath))
.Set DiskDirectoryTemplate=$([System.IO.Path]::GetDirectoryName($OutputPath))
.Set CompressionType=LZX
.Set CompressionMemory=21
.Set UniqueFiles=ON
.Set Cabinet=ON
.Set Compress=ON
.Set MaxDiskSize=0
"$TestFilePath" "$([System.IO.Path]::GetFileName($TestFilePath))"
"@
    $ddfContent | Out-File $ddfPath -Encoding ASCII
    
    # Run compression
    $result = makecab /F "$ddfPath" 2>&1
    $success = Test-Path $OutputPath
    
    if ($success) {
        $compressedSize = (Get-Item $OutputPath).Length
        $ratio = $compressedSize / $originalSize
        $savings = 100 * (1 - $ratio)
        
        Write-Host "Original: $([math]::Round($originalSize / 1KB, 2)) KB" -ForegroundColor White
        Write-Host "Compressed: $([math]::Round($compressedSize / 1KB, 2)) KB" -ForegroundColor White
        Write-Host "Ratio: $([math]::Round($ratio, 3)) ($([math]::Round($savings, 1))% savings)" -ForegroundColor Green
        Write-Host "LZX:21 compression: SUCCESS" -ForegroundColor Green
        
        # Cleanup
        Remove-Item $OutputPath -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "LZX:21 compression: FAILED" -ForegroundColor Red
        Write-Host "Error: $result" -ForegroundColor Red
    }
    
    # Cleanup
    Remove-Item $ddfPath -Force -ErrorAction SilentlyContinue
    if ($TestFilePath -like "*lzx_test_*") {
        Remove-Item $TestFilePath -Force -ErrorAction SilentlyContinue
    }
    
    return $success
}

function Get-MsiComponents {
    param(
        [string]$MsiPath
    )
    
    if (-not (Test-Path $MsiPath)) {
        Write-Warning "MSI not found for component analysis"
        return
    }
    
    Write-Host "`n=== MSI COMPONENT ANALYSIS ===" -ForegroundColor Cyan
    
    # Extract MSI to analyze components (requires admin for full extraction)
    $extractPath = "$env:TEMP\msi_extract_$(Get-Random)"
    
    try {
        # Silent extraction
        $process = Start-Process -FilePath "msiexec.exe" `
            -ArgumentList "/a", "`"$MsiPath`"", "/qn", "TARGETDIR=`"$extractPath`"" `
            -Wait -PassThru -WindowStyle Hidden
        
        if ($process.ExitCode -eq 0 -and (Test-Path $extractPath)) {
            # Analyze extracted files
            $files = Get-ChildItem -Path $extractPath -Recurse -File
            $totalSize = ($files | Measure-Object -Property Length -Sum).Sum
            $fileCount = $files.Count
            
            # Group by extension
            $byExtension = $files | Group-Object Extension | Sort-Object { ($_.Group | Measure-Object Length -Sum).Sum } -Descending
            
            Write-Host "Total files: $fileCount" -ForegroundColor White
            Write-Host "Total size: $([math]::Round($totalSize / 1MB, 2)) MB" -ForegroundColor White
            Write-Host "`nLargest components by type:" -ForegroundColor Yellow
            
            $byExtension | Select-Object -First 10 | ForEach-Object {
                $extSize = ($_.Group | Measure-Object Length -Sum).Sum
                $percent = ($extSize / $totalSize) * 100
                Write-Host "  $($_.Name): $([math]::Round($extSize / 1MB, 2)) MB ($([math]::Round($percent, 1))%)" -ForegroundColor Gray
            }
            
            # Find largest individual files
            Write-Host "`nLargest individual files:" -ForegroundColor Yellow
            $files | Sort-Object Length -Descending | Select-Object -First 10 | ForEach-Object {
                Write-Host "  $($_.Name): $([math]::Round($_.Length / 1MB, 2)) MB" -ForegroundColor Gray
            }
            
            # Cleanup
            Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue
            
            return @{
                FileCount = $fileCount
                TotalSizeMB = [math]::Round($totalSize / 1MB, 2)
                ByExtension = $byExtension
            }
        } else {
            Write-Warning "Failed to extract MSI for analysis (may require admin privileges)"
        }
    } catch {
        Write-Warning "Error analyzing MSI components: $_"
    } finally {
        if (Test-Path $extractPath) {
            Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-BuildOptimizations {
    Write-Host "`n=== BUILD OPTIMIZATION RECOMMENDATIONS ===" -ForegroundColor Cyan
    
    $recommendations = @()
    
    # Check if original Postman MSI is available
    $scriptDir = if ($BuildScriptPath) { Split-Path $BuildScriptPath -Parent } else { "$PSScriptRoot\..\..\deployment\windows" }
    $originalMsi = Get-ChildItem -Path $scriptDir -Filter "Postman-Enterprise-*-x64.msi" -ErrorAction SilentlyContinue | 
        Where-Object { $_.Name -notmatch "-saml" } | 
        Select-Object -First 1
    
    if ($originalMsi) {
        $originalSizeMB = [math]::Round($originalMsi.Length / 1MB, 2)
        Write-Host "Original Postman MSI: $originalSizeMB MB" -ForegroundColor White
        
        if ($originalSizeMB -gt 100) {
            $recommendations += "Consider requesting a smaller base Postman MSI from vendor"
        }
    }
    
    # Check AuthRouter binary size
    $authRouterPath = Join-Path $scriptDir "pm-authrouter.exe"
    if (Test-Path $authRouterPath) {
        $authRouterSizeMB = [math]::Round((Get-Item $authRouterPath).Length / 1MB, 2)
        Write-Host "AuthRouter binary: $authRouterSizeMB MB" -ForegroundColor White
        
        if ($authRouterSizeMB -gt 10) {
            $recommendations += "AuthRouter binary is large - consider additional stripping or compression"
        }
    }
    
    # Provide recommendations
    if ($recommendations.Count -gt 0) {
        Write-Host "`nOptimization recommendations:" -ForegroundColor Yellow
        $recommendations | ForEach-Object {
            Write-Host "  • $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "No immediate optimizations needed" -ForegroundColor Green
    }
    
    # Size reduction techniques
    Write-Host "`nSize reduction techniques in use:" -ForegroundColor Cyan
    Write-Host "   LZX:21 compression (maximum compression)" -ForegroundColor Green
    Write-Host "   Single CAB file embedding" -ForegroundColor Green
    Write-Host "   Stripped Go binary (ldflags -w)" -ForegroundColor Green
    Write-Host "   Minimal WiX overhead" -ForegroundColor Green
}

# Main execution
Write-Host "MSI Size Validation Tool" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan
Write-Host "Critical requirement: MSI must be <= 125MB" -ForegroundColor Red
Write-Host ""

if ($MsiToTest -and (Test-Path $MsiToTest)) {
    # Test specific MSI
    $result = Test-MsiSize -MsiPath $MsiToTest -Detailed
    
    if (-not $result.PassesLimit) {
        Write-Host "`n!!! CRITICAL FAILURE !!!" -ForegroundColor Red
        Write-Host "MSI exceeds 125MB limit and cannot be deployed!" -ForegroundColor Red
        
        # Analyze components to find size culprits
        Get-MsiComponents -MsiPath $MsiToTest
        
        # Provide optimization recommendations
        Test-BuildOptimizations
        
        if ($StrictMode) {
            throw "MSI size validation failed - exceeds 125MB limit"
        }
    }
} else {
    # Look for MSI in deployment directory
    $scriptDir = if ($BuildScriptPath) { Split-Path $BuildScriptPath -Parent } else { "$PSScriptRoot\..\..\deployment\windows" }
    $msiFiles = Get-ChildItem -Path $scriptDir -Filter "*-saml.msi" -ErrorAction SilentlyContinue
    
    if ($msiFiles) {
        Write-Host "Found MSI files to validate:" -ForegroundColor Yellow
        $msiFiles | ForEach-Object {
            Write-Host "  - $($_.Name)" -ForegroundColor Gray
        }
        
        foreach ($msi in $msiFiles) {
            $result = Test-MsiSize -MsiPath $msi.FullName -Detailed:$false
            
            if (-not $result.PassesLimit -and $StrictMode) {
                throw "MSI size validation failed for $($msi.Name)"
            }
        }
    } else {
        Write-Host "No MSI files found to validate" -ForegroundColor Yellow
        Write-Host "Run the build script first or specify -MsiToTest parameter" -ForegroundColor Gray
    }
}

# Test LZX compression if no MSI specified
if (-not $MsiToTest) {
    Test-LZXCompression
}

Write-Host "`n=== Validation Complete ===" -ForegroundColor Cyan