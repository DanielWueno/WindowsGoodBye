<#
.SYNOPSIS
    Builds all WindowsGoodBye components and packages them into a release folder.

.DESCRIPTION
    1. Publishes the Windows Service (self-contained, single file)
    2. Publishes the TrayApp (self-contained, single file)
    3. Builds the Credential Provider DLL (C++)
    4. Builds the Android APK (MAUI)
    5. Copies everything + installer into release\

.EXAMPLE
    .\Build-Release.ps1
    .\Build-Release.ps1 -SkipAndroid
    .\Build-Release.ps1 -SkipCredentialProvider
#>

param(
    [switch]$SkipAndroid,
    [switch]$SkipCredentialProvider,
    [switch]$SkipExeWrapper
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot | Split-Path -Parent
$ReleaseDir = Join-Path $Root "release"
$Config = "Release"

function Write-Step($step, $msg) {
    Write-Host ""
    Write-Host "[$step] $msg" -ForegroundColor Yellow
}

function Write-OK($step, $msg) {
    Write-Host "[$step] $msg" -ForegroundColor Green
}

function Write-Skip($step, $msg) {
    Write-Host "[$step] SKIPPED: $msg" -ForegroundColor DarkYellow
}

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║   WindowsGoodBye — Build Release         ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Clean release dir
if (Test-Path $ReleaseDir) {
    Remove-Item $ReleaseDir -Recurse -Force
}
New-Item -Path $ReleaseDir -ItemType Directory -Force | Out-Null

# ─────────────────────────────────────────────
# 1. Publish Windows Service (self-contained single file)
# ─────────────────────────────────────────────
Write-Step "1/5" "Publishing Windows Service..."

$serviceProj = Join-Path $Root "src\WindowsGoodBye.Service\WindowsGoodBye.Service.csproj"
$servicePub  = Join-Path $Root "src\WindowsGoodBye.Service\bin\publish"

dotnet publish $serviceProj -c $Config -r win-x64 --self-contained true `
    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
    -o $servicePub 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Service publish failed!" -ForegroundColor Red
    exit 1
}

# Copy service files
$serviceOut = Join-Path $ReleaseDir "Service"
New-Item $serviceOut -ItemType Directory -Force | Out-Null
Copy-Item (Join-Path $servicePub "WindowsGoodBye.Service.exe") $serviceOut
# Copy any config files
if (Test-Path (Join-Path $servicePub "appsettings.json")) {
    Copy-Item (Join-Path $servicePub "appsettings.json") $serviceOut
}

Write-OK "1/5" "Service published -> release\Service\"

# ─────────────────────────────────────────────
# 2. Publish TrayApp (self-contained single file)
# ─────────────────────────────────────────────
Write-Step "2/5" "Publishing TrayApp..."

$trayProj = Join-Path $Root "src\WindowsGoodBye.TrayApp\WindowsGoodBye.TrayApp.csproj"
$trayPub  = Join-Path $Root "src\WindowsGoodBye.TrayApp\bin\publish"

dotnet publish $trayProj -c $Config -r win-x64 --self-contained true `
    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
    -o $trayPub 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: TrayApp publish failed!" -ForegroundColor Red
    exit 1
}

Copy-Item (Join-Path $trayPub "WindowsGoodBye.TrayApp.exe") $serviceOut

Write-OK "2/5" "TrayApp published -> release\Service\"

# ─────────────────────────────────────────────
# 3. Build Credential Provider (C++ DLL)
# ─────────────────────────────────────────────
if (-not $SkipCredentialProvider) {
    Write-Step "3/5" "Building Credential Provider..."

    $vcvarsall = $null

    # Try vswhere first (most reliable)
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $vsPath = & $vswhere -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
        if ($vsPath) {
            $candidate = Join-Path $vsPath "VC\Auxiliary\Build\vcvarsall.bat"
            if (Test-Path $candidate) { $vcvarsall = $candidate }
        }
    }

    # Fallback: well-known paths
    if (-not $vcvarsall) {
        $searchPaths = @(
            "${env:ProgramFiles}\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvarsall.bat",
            "${env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat",
            "${env:ProgramFiles}\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat",
            "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat",
            "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat",
            "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat"
        )
        foreach ($path in $searchPaths) {
            if (Test-Path $path) { $vcvarsall = $path; break }
        }
    }

    if ($vcvarsall) {
        $credDir  = Join-Path $Root "src\WindowsGoodBye.CredentialProvider"
        $srcFile  = Join-Path $credDir "WinGBProvider.cpp"
        $defFile  = Join-Path $credDir "provider.def"
        $outDll   = Join-Path $serviceOut "WinGBCredentialProvider.dll"

        $buildCmd = @"
call "$vcvarsall" x64
cl.exe /EHsc /LD /DUNICODE /D_UNICODE /std:c++17 /O2 "$srcFile" /Fe"$outDll" /link /DEF:"$defFile" ole32.lib advapi32.lib user32.lib
"@
        $buildCmd | cmd.exe /S 2>&1
        if ($LASTEXITCODE -eq 0) {
            # Clean temp obj files
            Get-ChildItem $serviceOut -Filter "*.obj" | Remove-Item -Force -ErrorAction SilentlyContinue
            Get-ChildItem $serviceOut -Filter "*.lib" | Remove-Item -Force -ErrorAction SilentlyContinue
            Get-ChildItem $serviceOut -Filter "*.exp" | Remove-Item -Force -ErrorAction SilentlyContinue
            Write-OK "3/5" "Credential Provider built -> release\Service\"
        } else {
            Write-Host "[3/5] WARNING: C++ build failed. DLL not included." -ForegroundColor DarkYellow
        }
    } else {
        Write-Skip "3/5" "Visual Studio C++ tools not found."
    }
} else {
    Write-Skip "3/5" "Credential Provider (use without -SkipCredentialProvider)"
}

# ─────────────────────────────────────────────
# 4. Build Android APK (MAUI)
# ─────────────────────────────────────────────
if (-not $SkipAndroid) {
    Write-Step "4/5" "Building Android APK..."

    $mobileProj = Join-Path $Root "src\WindowsGoodBye.Mobile\WindowsGoodBye.Mobile.csproj"

    dotnet publish $mobileProj -c $Config -f net9.0-android 2>&1

    if ($LASTEXITCODE -ne 0) {
        Write-Host "[4/5] WARNING: Android build failed. APK not included." -ForegroundColor DarkYellow
    } else {
        # Find the signed APK
        $apkSearch = Get-ChildItem -Path (Join-Path $Root "src\WindowsGoodBye.Mobile\bin\$Config") `
            -Filter "*-Signed.apk" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1

        if (-not $apkSearch) {
            # Fallback: any APK
            $apkSearch = Get-ChildItem -Path (Join-Path $Root "src\WindowsGoodBye.Mobile\bin\$Config") `
                -Filter "*.apk" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        }

        if ($apkSearch) {
            Copy-Item $apkSearch.FullName (Join-Path $ReleaseDir "WindowsGoodBye.apk")
            Write-OK "4/5" "APK built -> release\WindowsGoodBye.apk"
        } else {
            Write-Host "[4/5] WARNING: APK not found after build." -ForegroundColor DarkYellow
        }
    }
} else {
    Write-Skip "4/5" "Android APK (use without -SkipAndroid)"
}

# ─────────────────────────────────────────────
# 5. Copy installer scripts + BAT
# ─────────────────────────────────────────────
Write-Step "5/5" "Packaging installer..."

# Copy the setup PS1
Copy-Item (Join-Path $PSScriptRoot "WindowsGoodBye-Setup.ps1") $ReleaseDir
Copy-Item (Join-Path $PSScriptRoot "WindowsGoodBye-Setup.bat") $ReleaseDir

# Generate EXE wrapper with ps2exe (optional)
if (-not $SkipExeWrapper) {
    $setupPs1 = Join-Path $ReleaseDir "WindowsGoodBye-Setup.ps1"
    $setupExe = Join-Path $ReleaseDir "WindowsGoodBye-Setup.exe"

    if (Get-Module -ListAvailable -Name ps2exe) {
        Write-Host "  Generating Setup EXE with ps2exe..." -ForegroundColor Gray
        try {
            Invoke-PS2EXE -InputFile $setupPs1 `
                          -OutputFile $setupExe `
                          -RequireAdmin `
                          -Title "WindowsGoodBye Setup" `
                          -Description "Installs WindowsGoodBye fingerprint unlock for Windows" `
                          -Company "WindowsGoodBye" `
                          -Version "1.0.0.0" `
                          -NoConsole:$false 2>&1 | Out-Null
            Write-OK "5/5" "Setup EXE created -> release\WindowsGoodBye-Setup.exe"
        } catch {
            Write-Host "  ps2exe wrapper failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
            Write-Host "  Use the .bat or .ps1 installer instead." -ForegroundColor DarkYellow
        }
    } else {
        Write-Host "  ps2exe not installed. Run: Install-Module ps2exe -Scope CurrentUser" -ForegroundColor DarkYellow
        Write-Host "  Skipping EXE wrapper — .bat and .ps1 are still available." -ForegroundColor DarkYellow
    }
}

Write-OK "5/5" "Installer packaged."

# ─────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║   Release ready!                          ║" -ForegroundColor Green
Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Output:  $ReleaseDir" -ForegroundColor White
Write-Host ""
Write-Host "  Contents:" -ForegroundColor White

Get-ChildItem $ReleaseDir -Recurse -File | ForEach-Object {
    $rel = $_.FullName.Substring($ReleaseDir.Length + 1)
    $size = "{0:N1} MB" -f ($_.Length / 1MB)
    Write-Host "    $rel  ($size)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "  To distribute:" -ForegroundColor Yellow
Write-Host "    1. Zip the 'release' folder" -ForegroundColor White
Write-Host "    2. On target PC: run WindowsGoodBye-Setup.exe (or .bat) as Admin" -ForegroundColor White
Write-Host "    3. APK: install on Android phone via ADB or file transfer" -ForegroundColor White
Write-Host ""
