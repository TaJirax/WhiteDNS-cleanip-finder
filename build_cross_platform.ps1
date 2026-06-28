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

# Apply generated app icon assets before building. This only changes icon files.
$IconScript = Join-Path $ScriptDir "scripts\apply_app_icon.py"
if (Test-Path $IconScript) {
    $PythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if ($PythonCmd) {
        $OldErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        & $PythonCmd.Source -c "import PIL" *> $null
        $PillowExitCode = $LASTEXITCODE
        $ErrorActionPreference = $OldErrorActionPreference
        if ($PillowExitCode -eq 0) {
            Write-Host "[*] Applying app icon assets..." -ForegroundColor Yellow
            & $PythonCmd.Source $IconScript
            if ($LASTEXITCODE -ne 0) {
                throw "icon generation failed with exit code $LASTEXITCODE"
            }
        }
        else {
            Write-Host "[!] Python Pillow package not found; using existing icon assets. Install with: python -m pip install -r requirements.txt" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "[!] Python not found; using existing icon assets." -ForegroundColor Yellow
    }
}

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
$DesktopIconPath = Join-Path $ScriptDir "android\app\src\main\res\drawable-nodpi\whitedns_logo.png"
$WindowsResConfig = Join-Path $ScriptDir "cmd\whitedns\winres\winres.json"
$WindowsIconPath = Join-Path $ScriptDir "cmd\whitedns\winres\whitedns-icon-256.png"
$WindowsResPrefix = Join-Path $ScriptDir "cmd\whitedns\rsrc"

function Get-GoWinresPath {
    $cmd = Get-Command go-winres -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    $gopath = (& go env GOPATH).Trim()
    if ($gopath) {
        $candidate = Join-Path $gopath "bin\go-winres.exe"
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    return $null
}

function Update-WindowsIconResource {
    if (-not (Test-Path $DesktopIconPath)) {
        throw "desktop icon PNG not found: $DesktopIconPath"
    }
    if (-not (Test-Path $WindowsResConfig)) {
        throw "Windows resource config not found: $WindowsResConfig"
    }

    $goWinres = Get-GoWinresPath
    if (-not $goWinres) {
        throw "go-winres is required to embed the Windows icon. Install it with: go install github.com/tc-hib/go-winres@latest"
    }

    Add-Type -AssemblyName System.Drawing
    $source = [System.Drawing.Image]::FromFile($DesktopIconPath)
    try {
        $bitmap = New-Object System.Drawing.Bitmap 256, 256
        try {
            $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
            try {
                $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
                $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
                $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
                $graphics.Clear([System.Drawing.Color]::Transparent)
                $graphics.DrawImage($source, 0, 0, 256, 256)
                $bitmap.Save($WindowsIconPath, [System.Drawing.Imaging.ImageFormat]::Png)
            }
            finally {
                $graphics.Dispose()
            }
        }
        finally {
            $bitmap.Dispose()
        }
    }
    finally {
        $source.Dispose()
    }

    Write-Host "  [*] Updating Windows icon resources..." -ForegroundColor Gray
    & $goWinres make --in $WindowsResConfig --arch amd64 --out $WindowsResPrefix
    if ($LASTEXITCODE -ne 0) {
        throw "go-winres failed with exit code $LASTEXITCODE"
    }
}

function Copy-DesktopIconAsset {
    if (Test-Path $DesktopIconPath) {
        Copy-Item -LiteralPath $DesktopIconPath -Destination (Join-Path $BuildDir "whitedns-icon.png") -Force
    }
}

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
    $OldCGOEnabled = $Env:CGO_ENABLED
    $OldGO111MODULE = $Env:GO111MODULE
    $Env:GOOS = $OS
    $Env:GOARCH = $Arch
    $Env:CGO_ENABLED = "0"
    $Env:GO111MODULE = "on"
    
    $OutputPath = Join-Path $BuildDir $OutputName
    
    $StartTime = Get-Date
    
    try {
        if ($OS -eq "windows") {
            Update-WindowsIconResource
        }

        $BuildArgs = @(
            "build",
            "-trimpath",
            "-ldflags=-s -w",
            "-o", $OutputPath,
            "./cmd/whitedns"
        )
        if ($VerboseOutput) {
            Write-Host "  Command: go $($BuildArgs -join ' ')" -ForegroundColor Gray
        }
        
        & go @BuildArgs
        if ($LASTEXITCODE -ne 0) {
            throw "go build failed with exit code $LASTEXITCODE"
        }
        
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

        if ([string]::IsNullOrEmpty($OldCGOEnabled)) {
            Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
        }
        else {
            $Env:CGO_ENABLED = $OldCGOEnabled
        }

        if ([string]::IsNullOrEmpty($OldGO111MODULE)) {
            Remove-Item Env:GO111MODULE -ErrorAction SilentlyContinue
        }
        else {
            $Env:GO111MODULE = $OldGO111MODULE
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

    Write-Host "`n[*] Standalone package mode:" -ForegroundColor Yellow
    Write-Host "  [OK] No sidecar Python/runtime folders are copied to builds/" -ForegroundColor Green

    Write-Host "`n[*] Bundled data notice:" -ForegroundColor Yellow
    Write-Host "  [OK] ASN CSV and assets/cf-domains.txt are embedded into each binary" -ForegroundColor Green
    Copy-DesktopIconAsset
    Write-Host "  [OK] Desktop icon asset copied to builds/whitedns-icon.png" -ForegroundColor Green

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
        Write-Host "`nRuntime behavior:" -ForegroundColor Green
        Write-Host "  - ASN data and cf-domains are loaded from inside each binary" -ForegroundColor Green
        Write-Host "  - Runtime outputs are written beside the executable under whitedns logs" -ForegroundColor Green
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



