# Cross-platform build script for whitedns
# Builds for: Windows (current), Linux AMD64, Linux ARM64, macOS AMD64, macOS ARM64, Termux (Android ARM64)

param(
    [switch]$CleanBuild,
    [switch]$VerboseOutput
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Run all build commands from the go-port directory so relative package paths
# like ./cmd/whitedns resolve correctly even when the script is launched from
# the repository root.
Push-Location $ScriptDir
try {

# Create builds directory
$BuildDir = Join-Path $ScriptDir "builds"
if ($CleanBuild -and (Test-Path $BuildDir)) {
    Write-Host "[*] Cleaning builds directory..." -ForegroundColor Yellow
    Remove-Item $BuildDir -Recurse -Force
}

if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
}

$SuccessCount = 0
$FailCount = 0

# Function to build for a specific platform
function Invoke-CrossPlatformBuild {
    param(
        [string]$OS,
        [string]$Arch,
        [string]$OutputName,
        [string]$Description
    )
    
    Write-Host "`n[+] Building for $Description ($OS/$Arch)..." -ForegroundColor Cyan
    
    $OldGOOS = $Env:GOOS
    $OldGOARCH = $Env:GOARCH
    $Env:GOOS = $OS
    $Env:GOARCH = $Arch
    
    $OutputPath = Join-Path $BuildDir $OutputName
    
    $StartTime = Get-Date
    
    try {
        $BuildCmd = "go build -o `"$OutputPath`" -ldflags=`"-s -w`" ./cmd/whitedns"
        if ($VerboseOutput) {
            Write-Host "  Command: $BuildCmd" -ForegroundColor Gray
        }
        
        Invoke-Expression $BuildCmd -ErrorAction Stop
        
        $EndTime = Get-Date
        $Duration = ($EndTime - $StartTime).TotalSeconds
        
        if (Test-Path $OutputPath) {
            $Size = (Get-Item $OutputPath).Length
            $SizeMB = [math]::Round($Size / 1MB, 2)
            Write-Host "  [OK] Built successfully" -ForegroundColor Green
            Write-Host "       Output: $OutputPath" -ForegroundColor Gray
            Write-Host "       Size: $SizeMB MB" -ForegroundColor Gray
            Write-Host "       Time: ${Duration}s" -ForegroundColor Gray
            return $true
        }
        else {
            Write-Host "  [FAIL] Output file not created" -ForegroundColor Red
            return $false
        }
    }
    catch {
        Write-Host "  [FAIL] Build error: $_" -ForegroundColor Red
        return $false
    }
    finally {
        if ([string]::IsNullOrEmpty($OldGOOS)) {
            Remove-Item Env:GOOS -ErrorAction SilentlyContinue
        }
        else {
            $Env:GOOS = $OldGOOS
        }

        if ([string]::IsNullOrEmpty($OldGOARCH)) {
            Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
        }
        else {
            $Env:GOARCH = $OldGOARCH
        }
    }
}

# Build configurations
$Builds = @(
    @{ OS = "windows"; Arch = "amd64"; OutputName = "whitedns-windows-amd64.exe"; Description = "Windows 64-bit (AMD64)" },
    @{ OS = "linux"; Arch = "amd64"; OutputName = "whitedns-linux-amd64"; Description = "Linux 64-bit (AMD64)" },
    @{ OS = "linux"; Arch = "arm64"; OutputName = "whitedns-linux-arm64"; Description = "Linux ARM64 (Raspberry Pi, servers)" },
    @{ OS = "darwin"; Arch = "amd64"; OutputName = "whitedns-macos-amd64"; Description = "macOS 64-bit (Intel AMD64)" },
    @{ OS = "darwin"; Arch = "arm64"; OutputName = "whitedns-macos-arm64"; Description = "macOS ARM64 (Apple Silicon)" },
    @{ OS = "android"; Arch = "arm64"; OutputName = "whitedns-termux-arm64"; Description = "Termux/Android ARM64" }
)

Write-Host @"
================================================================
WHITEDNS CROSS-PLATFORM BUILD SYSTEM
================================================================
Target platforms: $($Builds.Count)
Build directory: $BuildDir
Clean build: $CleanBuild
Verbose: $VerboseOutput
================================================================
"@ -ForegroundColor Yellow

# Execute builds
foreach ($Build in $Builds) {
    if (Invoke-CrossPlatformBuild -OS $Build.OS -Arch $Build.Arch -OutputName $Build.OutputName -Description $Build.Description) {
        $SuccessCount++
    }
    else {
        $FailCount++
    }
}

    # Copy IranASNs and assets to builds folder
    Write-Host "`n[*] Copying data files to builds directory..." -ForegroundColor Yellow

    $IranASNsSource = Join-Path $ScriptDir "IranASNs"
    $IranASNsDest = Join-Path $BuildDir "IranASNs"
    if (Test-Path $IranASNsSource) {
        try {
            if (Test-Path $IranASNsDest) {
                Remove-Item $IranASNsDest -Recurse -Force -ErrorAction Stop
            }
            Copy-Item $IranASNsSource -Destination $IranASNsDest -Recurse -Force -ErrorAction Stop
            Write-Host "  [OK] Copied IranASNs folder" -ForegroundColor Green
        }
        catch {
            Write-Host "  [WARN] Could not refresh IranASNs folder: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "  [WARN] IranASNs folder not found at $IranASNsSource" -ForegroundColor Yellow
    }

    $AssetsSource = Join-Path $ScriptDir "assets"
    $AssetsDest = Join-Path $BuildDir "assets"
    if (Test-Path $AssetsSource) {
        try {
            if (Test-Path $AssetsDest) {
                Remove-Item $AssetsDest -Recurse -Force -ErrorAction Stop
            }
            Copy-Item $AssetsSource -Destination $AssetsDest -Recurse -Force -ErrorAction Stop
            Write-Host "  [OK] Copied assets folder" -ForegroundColor Green
        }
        catch {
            Write-Host "  [WARN] Could not refresh assets folder: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "  [WARN] assets folder not found at $AssetsSource" -ForegroundColor Yellow
    }

# Summary
Write-Host @"
================================================================
BUILD SUMMARY
================================================================
Successful: $SuccessCount / $($Builds.Count)
Failed: $FailCount
================================================================
"@ -ForegroundColor Cyan

    if ($SuccessCount -eq $Builds.Count) {
        Write-Host "[SUCCESS] All platforms built successfully!" -ForegroundColor Green
        Write-Host "`nGenerated binaries:" -ForegroundColor Green
        Get-ChildItem $BuildDir -File | ForEach-Object {
            $Size = [math]::Round($_.Length / 1MB, 2)
            Write-Host "  - $($_.Name) ($Size MB)" -ForegroundColor Green
        }
        Write-Host "`nData files:" -ForegroundColor Green
        if (Test-Path $IranASNsDest) {
            Write-Host "  - IranASNs/" -ForegroundColor Green
        }
        if (Test-Path $AssetsDest) {
            Write-Host "  - assets/" -ForegroundColor Green
        }
        exit 0
    }
    else {
        Write-Host "[ERROR] Some builds failed!" -ForegroundColor Red
        exit 1
    }
}
finally {
    Pop-Location
}
