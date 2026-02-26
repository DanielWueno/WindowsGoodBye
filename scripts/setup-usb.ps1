<#
.SYNOPSIS
    Set up ADB reverse port forwarding for WindowsGoodBye USB transport.
.DESCRIPTION
    When the Android phone is connected via USB, this makes the phone's
    localhost:26820 forward to the PC's localhost:26820, allowing the
    MAUI app to communicate with the Service over USB (no WiFi needed).
    
    Run this AFTER connecting the phone via USB.
    Must be re-run each time the phone reconnects.
#>

$ErrorActionPreference = 'Stop'

Write-Host "Setting up ADB reverse for WindowsGoodBye..." -ForegroundColor Cyan

# Check ADB
$adb = Get-Command adb -ErrorAction SilentlyContinue
if (-not $adb) {
    Write-Host "ERROR: adb not found in PATH. Install Android SDK Platform Tools." -ForegroundColor Red
    exit 1
}

# Check device
$devices = (adb devices 2>&1) | Select-String "device$"
if (-not $devices) {
    Write-Host "ERROR: No Android device connected. Plug in your phone via USB." -ForegroundColor Red
    exit 1
}

Write-Host "Device found: $($devices.Line.Split()[0])" -ForegroundColor Green

# Set up reverse forwarding
adb reverse tcp:26820 tcp:26820

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "[OK] ADB reverse active: phone:26820 -> PC:26820 over USB" -ForegroundColor Green
    Write-Host "     The MAUI app can now connect to the Service via TCP/USB." -ForegroundColor Gray
    Write-Host ""
    Write-Host "Verify with: adb reverse --list" -ForegroundColor Gray
} else {
    Write-Host "ERROR: adb reverse failed." -ForegroundColor Red
}
