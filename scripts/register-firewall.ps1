#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Registers Windows Firewall rules required by WindowsGoodBye.

.DESCRIPTION
    Creates inbound firewall rules so the WindowsGoodBye Service can
    receive UDP multicast/unicast messages and TCP connections from
    Android devices on the local network.

    Run this script once (elevated) after installing the Service.
#>

$ErrorActionPreference = 'Stop'

$rules = @(
    @{
        Name        = 'WindowsGoodBye - UDP Multicast (26817)'
        Description = 'Allow WindowsGoodBye Service to receive UDP multicast from Android devices'
        Protocol    = 'UDP'
        LocalPort   = 26817
    },
    @{
        Name        = 'WindowsGoodBye - UDP Unicast (26818)'
        Description = 'Allow WindowsGoodBye Service to receive UDP unicast replies from Android devices'
        Protocol    = 'UDP'
        LocalPort   = 26818
    },
    @{
        Name        = 'WindowsGoodBye - TCP USB (26820)'
        Description = 'Allow WindowsGoodBye Service to accept TCP connections (ADB-forwarded USB)'
        Protocol    = 'TCP'
        LocalPort   = 26820
    }
)

foreach ($r in $rules) {
    $existing = Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "[OK]  Rule already exists: $($r.Name)" -ForegroundColor Cyan
    }
    else {
        New-NetFirewallRule `
            -DisplayName $r.Name `
            -Description $r.Description `
            -Direction Inbound `
            -Action Allow `
            -Protocol $r.Protocol `
            -LocalPort $r.LocalPort `
            -Profile Any `
            -Enabled True | Out-Null

        Write-Host "[ADD] Created rule: $($r.Name)" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "Firewall rules registered. Make sure your WiFi network is set to Private profile." -ForegroundColor Yellow
Write-Host "To check:  Get-NetConnectionProfile | Select Name,NetworkCategory" -ForegroundColor Gray
