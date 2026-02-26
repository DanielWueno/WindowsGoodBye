# WindowsGoodBye - Build All Script
# Run from the project root directory

param(
    [switch]$Release,
    [switch]$SkipCredentialProvider
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot | Split-Path -Parent

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host " WindowsGoodBye - Build All" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

$config = if ($Release) { "Release" } else { "Debug" }

# 1. Build .NET solution
Write-Host "[1/3] Building .NET solution ($config)..." -ForegroundColor Yellow
Push-Location $Root
try {
    dotnet build WindowsGoodBye.sln -c $config
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: .NET build failed!" -ForegroundColor Red
        exit 1
    }
    Write-Host "[1/3] .NET build succeeded!" -ForegroundColor Green
} finally {
    Pop-Location
}

# 2. Build Credential Provider (requires Visual Studio C++ tools)
if (-not $SkipCredentialProvider) {
    Write-Host ""
    Write-Host "[2/3] Building Credential Provider..." -ForegroundColor Yellow

    $vcvarsall = $null
    $searchPaths = @(
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat",
        "${env:ProgramFiles}\Microsoft Visual Studio\2026\Enterprise\VC\Auxiliary\Build\vcvarsall.bat",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
    )

    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            $vcvarsall = $path
            break
        }
    }

    if ($vcvarsall) {
        $credProvDir = Join-Path $Root "src\WindowsGoodBye.CredentialProvider"
        $outDir = Join-Path $credProvDir "bin\$config"
        New-Item -Path $outDir -ItemType Directory -Force | Out-Null

        $sourceFile = Join-Path $credProvDir "WinGBProvider.cpp"
        $defFile = Join-Path $credProvDir "provider.def"
        $outDll = Join-Path $outDir "WinGBCredentialProvider.dll"

        # Build using cl.exe from Visual Studio
        $buildCmd = @"
call "$vcvarsall" x64
cl.exe /EHsc /LD /DUNICODE /D_UNICODE /std:c++17 /O2 "$sourceFile" /Fe"$outDll" /link /DEF:"$defFile" ole32.lib advapi32.lib user32.lib
"@
        $buildCmd | cmd.exe /S
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[2/3] Credential Provider build succeeded!" -ForegroundColor Green
        } else {
            Write-Host "[2/3] WARNING: Credential Provider build failed. You may need Windows SDK." -ForegroundColor DarkYellow
        }
    } else {
        Write-Host "[2/3] SKIPPED: Visual Studio C++ tools not found." -ForegroundColor DarkYellow
        Write-Host "       Install 'Desktop development with C++' workload in Visual Studio." -ForegroundColor DarkYellow
    }
} else {
    Write-Host ""
    Write-Host "[2/3] Credential Provider build SKIPPED (use -SkipCredentialProvider:$false to build)" -ForegroundColor DarkYellow
}

# 3. Android - just check Gradle wrapper exists
Write-Host ""
Write-Host "[3/3] Android app..." -ForegroundColor Yellow
$androidDir = Join-Path $Root "android"
if (Test-Path (Join-Path $androidDir "gradlew.bat")) {
    Write-Host "       To build the Android app, run:" -ForegroundColor DarkYellow
    Write-Host "       cd android && .\gradlew.bat assembleDebug" -ForegroundColor White
} else {
    Write-Host "       Android project exists but gradlew.bat not found." -ForegroundColor DarkYellow
    Write-Host "       Open in Android Studio to build." -ForegroundColor DarkYellow
}

Write-Host ""
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host " Build complete!" -ForegroundColor Green
Write-Host "=====================================" -ForegroundColor Cyan
