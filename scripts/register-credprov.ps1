# WindowsGoodBye - Register Credential Provider
# Must be run as Administrator

#Requires -RunAsAdministrator

param(
    [string]$DllPath,
    [switch]$Unregister
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot | Split-Path -Parent

$CLSID = "{5C8A1D42-7B3F-4E8A-9D2C-1A3B5E7F9012}"
$ProviderName = "WindowsGoodBye Fingerprint Unlock"

$CredProvKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$CLSID"
$ClsidKey = "HKLM:\SOFTWARE\Classes\CLSID\$CLSID"
$InprocKey = "$ClsidKey\InprocServer32"

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host " WindowsGoodBye - Credential Provider" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

if ($Unregister) {
    Write-Host "Unregistering credential provider..." -ForegroundColor Yellow

    if (Test-Path $CredProvKey) {
        Remove-Item -Path $CredProvKey -Force
        Write-Host "Removed credential provider registration." -ForegroundColor Green
    }
    if (Test-Path $ClsidKey) {
        Remove-Item -Path $ClsidKey -Recurse -Force
        Write-Host "Removed CLSID registration." -ForegroundColor Green
    }

    Write-Host "Credential provider unregistered. Restart required to take effect." -ForegroundColor Green
    exit 0
}

# Find DLL
if (-not $DllPath) {
    $DllPath = Join-Path $Root "src\WindowsGoodBye.CredentialProvider\bin\Release\WinGBCredentialProvider.dll"
    if (-not (Test-Path $DllPath)) {
        $DllPath = Join-Path $Root "src\WindowsGoodBye.CredentialProvider\bin\Debug\WinGBCredentialProvider.dll"
    }
}

if (-not (Test-Path $DllPath)) {
    Write-Host "ERROR: Credential Provider DLL not found at: $DllPath" -ForegroundColor Red
    Write-Host "Build the credential provider first using build-all.ps1" -ForegroundColor Yellow
    exit 1
}

# Copy DLL to System32 (credential providers must be in a trusted location)
$systemDll = Join-Path $env:SystemRoot "System32\WinGBCredentialProvider.dll"
Write-Host "Copying DLL to $systemDll..." -ForegroundColor Yellow
Copy-Item -Path $DllPath -Destination $systemDll -Force

# Register CLSID
Write-Host "Registering CLSID..." -ForegroundColor Yellow
if (-not (Test-Path $ClsidKey)) {
    New-Item -Path $ClsidKey -Force | Out-Null
}
Set-ItemProperty -Path $ClsidKey -Name "(Default)" -Value $ProviderName

if (-not (Test-Path $InprocKey)) {
    New-Item -Path $InprocKey -Force | Out-Null
}
Set-ItemProperty -Path $InprocKey -Name "(Default)" -Value $systemDll
Set-ItemProperty -Path $InprocKey -Name "ThreadingModel" -Value "Apartment"

# Register as Credential Provider
Write-Host "Registering as Credential Provider..." -ForegroundColor Yellow
if (-not (Test-Path $CredProvKey)) {
    New-Item -Path $CredProvKey -Force | Out-Null
}
Set-ItemProperty -Path $CredProvKey -Name "(Default)" -Value $ProviderName

Write-Host ""
Write-Host "Credential Provider registered successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "IMPORTANT:" -ForegroundColor Yellow
Write-Host "- The credential provider will appear on the lock/login screen after a restart." -ForegroundColor White
Write-Host "- Make sure the WindowsGoodBye service is running before locking your PC." -ForegroundColor White
Write-Host "- KEEP AN ALTERNATIVE LOGIN METHOD (password/PIN) in case of issues." -ForegroundColor Red
Write-Host ""
Write-Host "To unregister: .\register-credprov.ps1 -Unregister" -ForegroundColor DarkYellow
