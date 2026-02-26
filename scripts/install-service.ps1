# WindowsGoodBye - Install Service Script
# Must be run as Administrator

#Requires -RunAsAdministrator

param(
    [string]$ServicePath,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot | Split-Path -Parent
$ServiceName = "WindowsGoodByeService"
$DisplayName = "WindowsGoodBye Authentication Service"

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host " WindowsGoodBye - Service Installer" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

if ($Uninstall) {
    Write-Host "Stopping and removing service..." -ForegroundColor Yellow

    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existingService) {
        if ($existingService.Status -eq 'Running') {
            Stop-Service -Name $ServiceName -Force
            Write-Host "Service stopped." -ForegroundColor Green
        }
        sc.exe delete $ServiceName | Out-Null
        Write-Host "Service removed." -ForegroundColor Green
    } else {
        Write-Host "Service not found." -ForegroundColor DarkYellow
    }
    exit 0
}

# Determine service executable path
if (-not $ServicePath) {
    $ServicePath = Join-Path $Root "src\WindowsGoodBye.Service\bin\Release\net9.0-windows\WindowsGoodBye.Service.exe"
    if (-not (Test-Path $ServicePath)) {
        $ServicePath = Join-Path $Root "src\WindowsGoodBye.Service\bin\Debug\net9.0-windows\WindowsGoodBye.Service.exe"
    }
}

if (-not (Test-Path $ServicePath)) {
    Write-Host "ERROR: Service executable not found at: $ServicePath" -ForegroundColor Red
    Write-Host "Build the solution first: dotnet build -c Release" -ForegroundColor Yellow
    exit 1
}

Write-Host "Service executable: $ServicePath" -ForegroundColor White

# Stop existing service if running
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "Removing existing service..." -ForegroundColor Yellow
    if ($existingService.Status -eq 'Running') {
        Stop-Service -Name $ServiceName -Force
    }
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

# Create the Windows service
Write-Host "Creating service..." -ForegroundColor Yellow
sc.exe create $ServiceName `
    binpath= "`"$ServicePath`"" `
    start= auto `
    DisplayName= "$DisplayName" `
    obj= "LocalSystem"

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to create service!" -ForegroundColor Red
    exit 1
}

# Set service description
sc.exe description $ServiceName "Listens for Android fingerprint authentication to unlock Windows"

# Set recovery options: restart on failure
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000

# Create data directory
$dataDir = Join-Path $env:ProgramData "WindowsGoodBye"
if (-not (Test-Path $dataDir)) {
    New-Item -Path $dataDir -ItemType Directory -Force | Out-Null
    Write-Host "Created data directory: $dataDir" -ForegroundColor Green
}

# Set SoftwareSASGeneration registry key
# This allows the service to simulate Ctrl+Alt+Del (Secure Attention Sequence)
# which may be needed for some credential provider scenarios
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$currentValue = Get-ItemProperty -Path $regPath -Name "SoftwareSASGeneration" -ErrorAction SilentlyContinue
if (-not $currentValue -or $currentValue.SoftwareSASGeneration -ne 1) {
    Set-ItemProperty -Path $regPath -Name "SoftwareSASGeneration" -Value 1 -Type DWord
    Write-Host "Enabled SoftwareSASGeneration registry key." -ForegroundColor Green
}

# Start the service
Write-Host "Starting service..." -ForegroundColor Yellow
Start-Service -Name $ServiceName

$svc = Get-Service -Name $ServiceName
Write-Host ""
Write-Host "Service '$DisplayName' installed and $($svc.Status)!" -ForegroundColor Green
Write-Host ""
Write-Host "Firewall rules may be needed. Run register-firewall.ps1 if PCs can't discover this machine." -ForegroundColor DarkYellow
