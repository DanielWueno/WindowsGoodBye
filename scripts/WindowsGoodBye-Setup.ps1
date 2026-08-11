<#
.SYNOPSIS
    WindowsGoodBye — All-in-one installer.
    Installs the Service, Credential Provider, TrayApp, firewall rules,
    the Cloudflare Tunnel (Push Auth relay), and optionally the Android APK via ADB.

.DESCRIPTION
    This script must be run as Administrator.
    It expects to be in the same folder as:
      Service\WindowsGoodBye.Service.exe
      Service\WindowsGoodBye.TrayApp.exe
      Service\WinGBCredentialProvider.dll   (optional)
      Service\cloudflared.exe               (optional — downloaded + checksum/signature-verified
                                              automatically if not bundled, see Fase 11)
      WindowsGoodBye.apk                   (optional)
      credentials.json                     (optional — only if using a classic `cloudflared tunnel
                                              create` Named Tunnel instead of a dashboard connector token)

.EXAMPLE
    .\WindowsGoodBye-Setup.ps1
    .\WindowsGoodBye-Setup.ps1 -Uninstall
#>

param(
    [switch]$Uninstall,
    [switch]$Silent
)

# ═══════════════════════════════════════════════════
# Config
# ═══════════════════════════════════════════════════

$ErrorActionPreference = "Stop"

$ServiceName   = "WindowsGoodByeService"
$DisplayName   = "WindowsGoodBye Authentication Service"
$CLSID         = "{5C8A1D42-7B3F-4E8A-9D2C-1A3B5E7F9012}"
$ProviderName  = "WindowsGoodBye Fingerprint Unlock"
$InstallDir    = Join-Path $env:ProgramFiles "WindowsGoodBye"
$DataDir       = Join-Path $env:ProgramData  "WindowsGoodBye"

$SetupDir      = $PSScriptRoot
$ServiceSrc    = Join-Path $SetupDir "Service"

# Detect if we're inside the release folder or running from scripts\
if (-not (Test-Path $ServiceSrc)) {
    # Maybe we're in scripts\, look for release\Service\
    $ServiceSrc = Join-Path ($SetupDir | Split-Path -Parent) "release\Service"
}

$CredProvKey   = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$CLSID"
$ClsidKey      = "HKLM:\SOFTWARE\Classes\CLSID\$CLSID"
$InprocKey     = "$ClsidKey\InprocServer32"

# ═══════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════

function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║                                                      ║" -ForegroundColor Cyan
    Write-Host "  ║       WindowsGoodBye — Setup                         ║" -ForegroundColor Cyan
    Write-Host "  ║       Unlock Windows with your phone fingerprint     ║" -ForegroundColor Cyan
    Write-Host "  ║                                                      ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Confirm-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "  Elevando a Administrador..." -ForegroundColor Yellow
        # Re-launch self as admin
        $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
        if ($Uninstall) { $args += '-Uninstall' }
        if ($Silent)    { $args += '-Silent' }
        try {
            Start-Process powershell -ArgumentList $args -Verb RunAs -Wait
        } catch {
            Write-Host "ERROR: No se pudo elevar a Administrador." -ForegroundColor Red
            Write-Host "       Haz clic derecho -> Ejecutar como administrador." -ForegroundColor Yellow
            if (-not $Silent) { Read-Host "Presione ENTER para salir" }
        }
        exit
    }
}

function Write-Step($num, $total, $msg) {
    Write-Host ""
    Write-Host "  [$num/$total] $msg" -ForegroundColor Yellow
}

function Write-Done($msg) {
    Write-Host "         $msg" -ForegroundColor Green
}

function Write-Warn($msg) {
    Write-Host "         $msg" -ForegroundColor DarkYellow
}

function Write-Err($msg) {
    Write-Host "         $msg" -ForegroundColor Red
}

function Ask-YesNo($question) {
    if ($Silent) { return $true }
    $r = Read-Host "$question (S/N)"
    return ($r -match "^[SsYy]")
}

# ═══════════════════════════════════════════════════
# Fase 11 (docs/plan_push_auth_v2.md): Cloudflare Tunnel / cloudflared.exe
# ═══════════════════════════════════════════════════

function Test-CloudflaredSignature {
    <#
    Verifies cloudflared.exe carries a valid Authenticode signature issued to Cloudflare. Checked
    unconditionally (unlike the SHA-256 digest below, which depends on whether GitHub's API happened
    to publish one for this asset) — this is the check we never skip.
    #>
    param([Parameter(Mandatory)][string]$FilePath)

    $sig = Get-AuthenticodeSignature -FilePath $FilePath
    if ($sig.Status -ne 'Valid') { return $false }
    if ($sig.SignerCertificate -and $sig.SignerCertificate.Subject -notmatch 'Cloudflare') { return $false }
    return $true
}

function Get-CloudflaredReleaseAsset {
    <#
    Queries the official GitHub Releases API for cloudflare/cloudflared's latest release and returns
    the Windows amd64 asset's download URL plus its expected SHA-256 digest, when GitHub reports one.
    GitHub started exposing a `digest` field ("sha256:<hex>") per release asset for uploads made from
    mid-2024 onward — older releases (or a compromised/self-hosted API mirror) may not have it, so the
    checksum check below is "verify when available", not "trust blindly when absent". The Authenticode
    signature check (Test-CloudflaredSignature) is the one that is never optional.
    #>
    $releaseUrl = "https://api.github.com/repos/cloudflare/cloudflared/releases/latest"
    $release = Invoke-RestMethod -Uri $releaseUrl -Headers @{ "User-Agent" = "WindowsGoodBye-Setup" }
    $asset = $release.assets | Where-Object { $_.name -eq "cloudflared-windows-amd64.exe" } | Select-Object -First 1
    if (-not $asset) { throw "No se encontro el asset 'cloudflared-windows-amd64.exe' en el ultimo release de GitHub." }

    $expectedSha256 = $null
    if ($asset.digest -and $asset.digest -match '^sha256:([0-9a-fA-F]{64})$') {
        $expectedSha256 = $Matches[1].ToLowerInvariant()
    }

    return [PSCustomObject]@{
        DownloadUrl    = $asset.browser_download_url
        ExpectedSha256 = $expectedSha256
        Version        = $release.tag_name
    }
}

function Install-CloudflaredBinary {
    <#
    Downloads cloudflared.exe from the official GitHub release and verifies it BEFORE copying it into
    $DestinationPath — supply-chain verification per docs/plan_push_auth_v2.md, Fase 11 ("evita
    supply-chain compromise en el binario descargado"). The binary is rejected (never copied, never
    run) unless the Authenticode signature is valid AND, whenever GitHub published a digest for this
    asset, the downloaded bytes' SHA-256 matches it exactly. Throws on any verification failure —
    callers must NOT swallow the exception and silently proceed as if Push Auth were available.
    #>
    param([Parameter(Mandatory)][string]$DestinationPath)

    Write-Host "         Descargando cloudflared.exe desde el release oficial de GitHub..." -ForegroundColor Gray
    $info = Get-CloudflaredReleaseAsset
    $tempFile = Join-Path $env:TEMP "cloudflared-download-$([Guid]::NewGuid().ToString('N')).exe"

    try {
        Invoke-WebRequest -Uri $info.DownloadUrl -OutFile $tempFile -UseBasicParsing

        if ($info.ExpectedSha256) {
            $actualSha256 = (Get-FileHash -Path $tempFile -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actualSha256 -ne $info.ExpectedSha256) {
                throw "Checksum SHA-256 NO coincide con el release oficial de GitHub ($($info.Version)).`n" +
                      "         Esperado: $($info.ExpectedSha256)`n         Obtenido: $actualSha256`n" +
                      "         Posible compromiso de la cadena de suministro. Abortando instalacion de cloudflared."
            }
            Write-Done "Checksum SHA-256 verificado contra el release oficial ($($info.Version))."
        } else {
            Write-Warn "El release de GitHub no publico un digest SHA-256 para este asset; se confia solo en la firma Authenticode."
        }

        if (-not (Test-CloudflaredSignature -FilePath $tempFile)) {
            throw "La firma digital (Authenticode) de cloudflared.exe no es valida o no pertenece a Cloudflare.`n" +
                  "         Posible compromiso de la cadena de suministro. Abortando instalacion de cloudflared."
        }
        Write-Done "Firma digital (Authenticode) de Cloudflare verificada."

        Copy-Item $tempFile $DestinationPath -Force
    }
    finally {
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
    }
}

function Protect-SensitiveFile {
    <#
    Restricts NTFS permissions on $Path to BUILTIN\Administrators + NT AUTHORITY\SYSTEM (FullControl)
    only, stripping inherited/other ACEs — the exact same criterion AdminPipeServer.cs (Fase 0) applies
    to the admin named pipe's ACL (see the SECURITY comment there: previously Everyone+FullControl,
    restricted to Administrators/SYSTEM [+ INTERACTIVE for the pipe specifically, because the
    unelevated TrayApp needs to talk to it]). A Named Tunnel's credentials.json / embedded token is
    just as sensitive as DeviceKey — whoever can read it can impersonate this PC's tunnel identity — and
    unlike the admin pipe, nothing unelevated ever needs to read this file (only cloudflared.exe / the
    Service, both running elevated/as LocalSystem), so no INTERACTIVE grant is added here.
    Uses BOTH .NET's System.Security.AccessControl (primary) and icacls (belt-and-suspenders, in case
    of any ACL-provider quirk) — matching the two options the plan calls out explicitly for this step.
    #>
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path $Path)) { return }

    $acl = Get-Acl -Path $Path
    $acl.SetAccessRuleProtection($true, $false)  # $true = disable inheritance, $false = don't preserve inherited rules
    foreach ($rule in @($acl.Access)) { $acl.RemoveAccessRule($rule) | Out-Null }

    $admins = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    $system = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)

    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $admins, "FullControl", "Allow")))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $system, "FullControl", "Allow")))

    Set-Acl -Path $Path -AclObject $acl

    # Belt-and-suspenders: re-assert the same result via icacls (S-1-5-32-544 = Administrators,
    # S-1-5-18 = SYSTEM — the same well-known SIDs used above), in case any ACL-provider quirk left
    # Set-Acl's result different from what icacls would report.
    icacls "$Path" /inheritance:r | Out-Null
    icacls "$Path" /grant:r "*S-1-5-32-544:F" "*S-1-5-18:F" | Out-Null
}

# ═══════════════════════════════════════════════════
# UNINSTALL
# ═══════════════════════════════════════════════════

if ($Uninstall) {
    Write-Banner
    Confirm-Admin

    Write-Host "  Desinstalando WindowsGoodBye..." -ForegroundColor Yellow

    # 1. Stop & remove service
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -eq 'Running') { Stop-Service $ServiceName -Force }
        sc.exe delete $ServiceName 2>&1 | Out-Null
        Write-Done "Servicio eliminado."
    }

    # 2. Kill TrayApp
    Get-Process -Name "WindowsGoodBye.TrayApp" -ErrorAction SilentlyContinue | Stop-Process -Force

    # 3. Unregister credential provider
    if (Test-Path $CredProvKey) { Remove-Item $CredProvKey -Force }
    if (Test-Path $ClsidKey) { Remove-Item $ClsidKey -Recurse -Force }
    $sysDll = Join-Path $env:SystemRoot "System32\WinGBCredentialProvider.dll"
    if (Test-Path $sysDll) { Remove-Item $sysDll -Force }
    Write-Done "Credential Provider eliminado."

    # 4. Remove firewall rules
    # NOTE (docs/plan_push_auth_v2.md, Fase 11): the embedded relay port (26821, Protocol.RelayPort)
    # is deliberately NOT in this list — see the matching comment on $firewallRules below for why.
    @('WindowsGoodBye - UDP Multicast (26817)',
      'WindowsGoodBye - UDP Unicast (26818)',
      'WindowsGoodBye - TCP USB (26820)') | ForEach-Object {
        Remove-NetFirewallRule -DisplayName $_ -ErrorAction SilentlyContinue
    }
    Write-Done "Reglas de firewall eliminadas."

    # 5. Remove cloudflared.exe (the Named Tunnel token / credentials.json, if any, stay under
    #    $DataDir\cloudflared — same "data persists on uninstall" policy already applied to devices.db).
    Get-Process -Name "cloudflared" -ErrorAction SilentlyContinue | Stop-Process -Force
    $cloudflaredDst = Join-Path $InstallDir "cloudflared.exe"
    if (Test-Path $cloudflaredDst) {
        Remove-Item $cloudflaredDst -Force -ErrorAction SilentlyContinue
        Write-Done "cloudflared.exe eliminado."
    }

    # 6. Remove TrayApp from startup
    $startupLink = Join-Path ([Environment]::GetFolderPath('CommonStartup')) "WindowsGoodBye TrayApp.lnk"
    if (Test-Path $startupLink) { Remove-Item $startupLink -Force }
    Write-Done "Acceso directo de inicio eliminado."

    # 7. Optionally remove install dir (keep data)
    if (Test-Path $InstallDir) {
        if (Ask-YesNo "  Eliminar archivos de programa ($InstallDir)?") {
            Remove-Item $InstallDir -Recurse -Force
            Write-Done "Archivos eliminados."
        }
    }

    Write-Host ""
    Write-Host "  WindowsGoodBye desinstalado." -ForegroundColor Green
    Write-Host "  Los datos permanecen en: $DataDir" -ForegroundColor Gray
    Write-Host "  Reinicia para que el Credential Provider deje de aparecer." -ForegroundColor Yellow
    Write-Host ""
    if (-not $Silent) { Read-Host "Presione ENTER para salir" }
    exit 0
}

# ═══════════════════════════════════════════════════
# INSTALL
# ═══════════════════════════════════════════════════

Write-Banner
Confirm-Admin

# Validate files exist
if (-not (Test-Path (Join-Path $ServiceSrc "WindowsGoodBye.Service.exe"))) {
    Write-Err "No se encontro WindowsGoodBye.Service.exe en: $ServiceSrc"
    Write-Host "  Asegurate de ejecutar el instalador desde la carpeta release." -ForegroundColor Yellow
    if (-not $Silent) { Read-Host "Presione ENTER para salir" }
    exit 1
}

$totalSteps = 8
$hasCredProv         = Test-Path (Join-Path $ServiceSrc "WinGBCredentialProvider.dll")
$hasApk              = Test-Path (Join-Path $SetupDir "WindowsGoodBye.apk")
$hasTrayApp          = Test-Path (Join-Path $ServiceSrc "WindowsGoodBye.TrayApp.exe")
$hasCloudflaredBundled = Test-Path (Join-Path $ServiceSrc "cloudflared.exe")

Write-Host "  Componentes detectados:" -ForegroundColor White
Write-Host "    [+] Windows Service"                                 -ForegroundColor Green
Write-Host "    $(if ($hasTrayApp) {'[+]'} else {'[-]'}) TrayApp"    -ForegroundColor $(if ($hasTrayApp) {'Green'} else {'DarkYellow'})
Write-Host "    $(if ($hasCredProv) {'[+]'} else {'[-]'}) Credential Provider (DLL)" -ForegroundColor $(if ($hasCredProv) {'Green'} else {'DarkYellow'})
Write-Host "    $(if ($hasApk) {'[+]'} else {'[-]'}) Android APK"   -ForegroundColor $(if ($hasApk) {'Green'} else {'DarkYellow'})
Write-Host "    $(if ($hasCloudflaredBundled) {'[+]'} else {'[-]'}) cloudflared.exe (incluido en el paquete)" -ForegroundColor $(if ($hasCloudflaredBundled) {'Green'} else {'DarkYellow'})
Write-Host ""

if (-not $Silent) {
    if (-not (Ask-YesNo "  Continuar con la instalacion?")) {
        Write-Host "  Instalacion cancelada." -ForegroundColor Yellow
        exit 0
    }
}

# ─── 1. Create install directory ───
Write-Step 1 $totalSteps "Creando directorio de instalacion..."

New-Item -Path $InstallDir -ItemType Directory -Force | Out-Null
New-Item -Path $DataDir    -ItemType Directory -Force | Out-Null

# Copy all Service files
Copy-Item (Join-Path $ServiceSrc "*") $InstallDir -Force -Recurse
Write-Done "Archivos copiados a: $InstallDir"

# ─── 2. Install Windows Service ───
Write-Step 2 $totalSteps "Instalando servicio de Windows..."

$svcExe = Join-Path $InstallDir "WindowsGoodBye.Service.exe"

# Stop & remove if exists
$existingSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingSvc) {
    if ($existingSvc.Status -eq 'Running') {
        Stop-Service $ServiceName -Force
        Start-Sleep -Seconds 1
    }
    sc.exe delete $ServiceName 2>&1 | Out-Null
    Start-Sleep -Seconds 2
}

# Create service with auto-start
sc.exe create $ServiceName binpath= "`"$svcExe`"" start= auto DisplayName= "$DisplayName" obj= "LocalSystem" 2>&1 | Out-Null
sc.exe description $ServiceName "Escucha autenticacion por huella desde dispositivos Android para desbloquear Windows" 2>&1 | Out-Null
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 2>&1 | Out-Null

# SoftwareSASGeneration (needed for some credential provider scenarios)
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $regPath -Name "SoftwareSASGeneration" -Value 1 -Type DWord -ErrorAction SilentlyContinue

# Start service
Start-Service $ServiceName -ErrorAction SilentlyContinue
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
Write-Done "Servicio instalado y $($svc.Status)."

# ─── 3. Register Credential Provider ───
Write-Step 3 $totalSteps "Registrando Credential Provider..."

if ($hasCredProv) {
    $dllSrc = Join-Path $InstallDir "WinGBCredentialProvider.dll"
    $dllDst = Join-Path $env:SystemRoot "System32\WinGBCredentialProvider.dll"

    Copy-Item $dllSrc $dllDst -Force

    # CLSID registration
    if (-not (Test-Path $ClsidKey)) { New-Item -Path $ClsidKey -Force | Out-Null }
    Set-ItemProperty -Path $ClsidKey -Name "(Default)" -Value $ProviderName

    if (-not (Test-Path $InprocKey)) { New-Item -Path $InprocKey -Force | Out-Null }
    Set-ItemProperty -Path $InprocKey -Name "(Default)" -Value $dllDst
    Set-ItemProperty -Path $InprocKey -Name "ThreadingModel" -Value "Apartment"

    # Credential Provider registration
    if (-not (Test-Path $CredProvKey)) { New-Item -Path $CredProvKey -Force | Out-Null }
    Set-ItemProperty -Path $CredProvKey -Name "(Default)" -Value $ProviderName

    Write-Done "Credential Provider registrado. Aparecera en la lock screen al reiniciar."
} else {
    Write-Warn "DLL no encontrada. El Credential Provider no fue instalado."
    Write-Warn "Puedes registrarlo despues con: register-credprov.ps1"
}

# ─── 4. Configure Firewall ───
Write-Step 4 $totalSteps "Configurando reglas de firewall..."

$firewallRules = @(
    @{ Name = 'WindowsGoodBye - UDP Multicast (26817)'; Protocol = 'UDP'; Port = 26817;
       Desc = 'WindowsGoodBye: UDP multicast from Android' },
    @{ Name = 'WindowsGoodBye - UDP Unicast (26818)';   Protocol = 'UDP'; Port = 26818;
       Desc = 'WindowsGoodBye: UDP unicast from Android' },
    @{ Name = 'WindowsGoodBye - TCP USB (26820)';       Protocol = 'TCP'; Port = 26820;
       Desc = 'WindowsGoodBye: TCP/USB from Android (ADB)' }
)

# NOTE (docs/plan_push_auth_v2.md, Fase 11): unlike the three inbound rules above — which exist because
# UdpManager/BluetoothServer/TcpUsbServer accept connections FROM the phone on those ports, arriving
# over the LAN/USB/Bluetooth — the embedded push-auth relay's port (26821, Protocol.RelayPort) does NOT
# get a firewall rule here, and that is deliberate, not an oversight:
#   - RelayServer (WindowsGoodBye.Service/RelayServer.cs) binds EXCLUSIVELY to http://127.0.0.1:26821
#     (loopback) — never 0.0.0.0 — so Windows Firewall's inbound rules for OTHER hosts/interfaces never
#     even apply to it; it is unreachable from the LAN/internet by construction, with or without a rule.
#   - The only way anything remote reaches it is through cloudflared's tunnel, which is an OUTBOUND
#     connection this PC initiates to Cloudflare's edge (see the "Configurando Cloudflare Tunnel" step
#     below) — outbound connections are allowed by Windows Firewall's default profile and need no rule.
#   - If RelayServer were ever reconfigured to bind 0.0.0.0, that would expose plaintext HTTP to the
#     whole LAN and would need TLS added BEFORE any firewall rule, not instead of one — see "Aislamiento
#     y Resiliencia del Relay" in the plan.
foreach ($r in $firewallRules) {
    $existing = Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-NetFirewallRule -DisplayName $r.Name -Description $r.Desc `
            -Direction Inbound -Action Allow -Protocol $r.Protocol `
            -LocalPort $r.Port -Profile Any -Enabled True | Out-Null
        Write-Host "         + $($r.Name)" -ForegroundColor Gray
    } else {
        Write-Host "         = $($r.Name) (ya existia)" -ForegroundColor DarkGray
    }
}
Write-Done "Firewall configurado."

# ─── 5. TrayApp startup shortcut ───
Write-Step 5 $totalSteps "Configurando TrayApp en inicio..."

if ($hasTrayApp) {
    $trayExe = Join-Path $InstallDir "WindowsGoodBye.TrayApp.exe"
    $startupFolder = [Environment]::GetFolderPath('CommonStartup')
    $shortcutPath  = Join-Path $startupFolder "WindowsGoodBye TrayApp.lnk"

    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $trayExe
    $shortcut.WorkingDirectory = $InstallDir
    $shortcut.Description = "WindowsGoodBye - Bandeja del sistema"
    $shortcut.Save()

    Write-Done "TrayApp se iniciara automaticamente al iniciar sesion."

    # Launch TrayApp now
    Start-Process $trayExe -WorkingDirectory $InstallDir
    Write-Done "TrayApp iniciado."
} else {
    Write-Warn "TrayApp no encontrado en el paquete."
}

# ─── 6. Android APK ───
Write-Step 6 $totalSteps "Android APK..."

if ($hasApk) {
    $apkPath = Join-Path $SetupDir "WindowsGoodBye.apk"
    $apkSize = "{0:N1} MB" -f ((Get-Item $apkPath).Length / 1MB)

    Write-Host "         APK encontrado: WindowsGoodBye.apk ($apkSize)" -ForegroundColor White

    # Check for ADB
    $adbPath = $null
    try {
        $adbPath = (Get-Command adb -ErrorAction SilentlyContinue).Source
    } catch { }

    if ($adbPath) {
        # Check if device connected
        $devices = & $adbPath devices 2>&1
        $hasDevice = $devices -match "\tdevice$"

        if ($hasDevice) {
            if (Ask-YesNo "         Dispositivo Android detectado. Instalar APK ahora?") {
                Write-Host "         Instalando APK..." -ForegroundColor Gray
                & $adbPath install -r $apkPath 2>&1 | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    Write-Done "APK instalado en el dispositivo!"
                } else {
                    Write-Warn "Error al instalar. Copia el APK manualmente al telefono."
                }
            }
        } else {
            Write-Warn "ADB disponible pero ningun dispositivo conectado."
            Write-Host "         Conecta el telefono por USB e instala manualmente:" -ForegroundColor Gray
            Write-Host "           adb install WindowsGoodBye.apk" -ForegroundColor White
        }
    } else {
        Write-Warn "ADB no encontrado. Opciones para instalar la app:"
        Write-Host "         1. Copia WindowsGoodBye.apk al telefono e instalalo" -ForegroundColor Gray
        Write-Host "         2. Instala ADB y ejecuta: adb install WindowsGoodBye.apk" -ForegroundColor Gray
    }

    # Also copy APK to install dir for later use
    Copy-Item $apkPath $InstallDir -Force
    Write-Host "         APK guardado en: $InstallDir\WindowsGoodBye.apk" -ForegroundColor DarkGray
} else {
    Write-Warn "APK no incluido en el paquete."
    Write-Host "         Compila la app Android por separado con:" -ForegroundColor Gray
    Write-Host "           dotnet publish -c Release -f net9.0-android" -ForegroundColor White
}

# ─── 7. Cloudflare Tunnel (Push Auth relay, docs/plan_push_auth_v2.md Fase 11) ───
Write-Step 7 $totalSteps "Configurando Cloudflare Tunnel (Push Auth)..."

$cloudflaredDst  = Join-Path $InstallDir "cloudflared.exe"
$appsettingsPath = Join-Path $InstallDir "appsettings.json"
$pushAuthEnabled = $false

if (Ask-YesNo "         Deseas habilitar Push Auth (notificaciones push via Cloudflare Tunnel)?") {

    # cloudflared.exe: reuse one already bundled in the release package (offline installs) if present
    # and the operator explicitly trusts that package's provenance; otherwise download + verify it now
    # against the official GitHub release (Install-CloudflaredBinary, defined above).
    $bundledCloudflared = Join-Path $ServiceSrc "cloudflared.exe"
    $cloudflaredReady = $false

    if ($hasCloudflaredBundled) {
        Write-Host "         cloudflared.exe encontrado en el paquete de release." -ForegroundColor White
        if (Ask-YesNo "         Usar este binario sin re-verificar checksum/firma? (No recomendado si no confias en el origen del paquete)") {
            Copy-Item $bundledCloudflared $cloudflaredDst -Force
            $cloudflaredReady = $true
        }
    }

    if (-not $cloudflaredReady) {
        try {
            Install-CloudflaredBinary -DestinationPath $cloudflaredDst
            $cloudflaredReady = $true
        } catch {
            Write-Err "No se pudo instalar cloudflared.exe de forma segura:"
            Write-Err "         $($_.Exception.Message)"
            Write-Warn "Push Auth (Ruta C) quedara deshabilitado. Los transportes directos"
            Write-Warn "(Bluetooth / USB / WiFi) siguen funcionando sin ningun cambio."
        }
    }

    if ($cloudflaredReady) {
        Write-Done "cloudflared.exe instalado en: $cloudflaredDst"

        # --- Named Tunnel token (recommended — stable URL, see el plan "Opciones de tunel") ---
        Write-Host ""
        Write-Host "         Para una URL estable, crea un Named Tunnel gratuito en Cloudflare Zero Trust:" -ForegroundColor White
        Write-Host "           https://one.dash.cloudflare.com/  ->  Networks -> Tunnels -> Create a tunnel" -ForegroundColor Gray
        Write-Host "         y copia el token del conector (o deja esto en blanco para usar un Quick" -ForegroundColor Gray
        Write-Host "         Tunnel sin cuenta, con URL aleatoria que cambia en cada reinicio del Servicio)." -ForegroundColor Gray

        $tunnelToken = if ($Silent) { "" } else { Read-Host "         Named Tunnel token (opcional, ENTER para omitir)" }

        # credentials.json: only produced by the classic `cloudflared tunnel login` + `tunnel create`
        # flow (as opposed to a Zero Trust dashboard connector token, which is self-contained and needs
        # no credentials file at all). Protected here exactly like the admin pipe / DeviceKey IF the
        # operator already generated one and dropped it next to this script, following the same
        # "optional file in the package" pattern already used above for the APK / bundled cloudflared.exe.
        $bundledCredentials = Join-Path $SetupDir "credentials.json"
        if (Test-Path $bundledCredentials) {
            $credDir = Join-Path $DataDir "cloudflared"
            New-Item -Path $credDir -ItemType Directory -Force | Out-Null
            $credDst = Join-Path $credDir "credentials.json"
            Copy-Item $bundledCredentials $credDst -Force
            Protect-SensitiveFile -Path $credDst
            Write-Done "credentials.json protegido con ACL restringida (Administrators/SYSTEM): $credDst"
        }

        if (-not [string]::IsNullOrWhiteSpace($tunnelToken)) {
            # Persist into appsettings.json (Tunnel:NamedTunnelToken), preserving the rest of the file
            # (same shape TunnelHostedService/Program.cs already read from — see appsettings.json's
            # existing "Tunnel" section and its _comment, added in Fase 4).
            $settings = if (Test-Path $appsettingsPath) {
                Get-Content $appsettingsPath -Raw | ConvertFrom-Json
            } else {
                [PSCustomObject]@{}
            }
            if (-not ($settings.PSObject.Properties.Name -contains 'Tunnel')) {
                $settings | Add-Member -MemberType NoteProperty -Name 'Tunnel' -Value ([PSCustomObject]@{})
            }
            $settings.Tunnel | Add-Member -MemberType NoteProperty -Name 'NamedTunnelToken' -Value $tunnelToken -Force
            $settings | ConvertTo-Json -Depth 10 | Set-Content -Path $appsettingsPath -Encoding utf8

            # appsettings.json now embeds a Named Tunnel token (a bearer credential for this tunnel) —
            # protect it with the same restrictive ACL as credentials.json / the admin pipe.
            Protect-SensitiveFile -Path $appsettingsPath
            Write-Done "Named Tunnel token guardado (appsettings.json protegido con ACL restringida)."
            $pushAuthEnabled = $true
        } else {
            Write-Warn "Sin token: se usara un Quick Tunnel (URL aleatoria, cambia en cada reinicio del Servicio)."
            $pushAuthEnabled = $true
        }

        # Restart the service so TunnelHostedService picks up cloudflared.exe / the new token immediately,
        # instead of waiting for the next natural restart.
        Restart-Service $ServiceName -ErrorAction SilentlyContinue
    }
} else {
    Write-Warn "Push Auth deshabilitado. Solo transportes directos (Bluetooth/USB/WiFi) estaran disponibles."
}

# ─── 8. Summary ───
Write-Step 8 $totalSteps "Verificacion final..."

$svcStatus = (Get-Service $ServiceName -ErrorAction SilentlyContinue).Status

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║   Instalacion completada!                            ║" -ForegroundColor Green
Write-Host "  ╚══════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Estado:" -ForegroundColor White
Write-Host "    Servicio:            $svcStatus" -ForegroundColor $(if ($svcStatus -eq 'Running') {'Green'} else {'DarkYellow'})
Write-Host "    Credential Provider: $(if ($hasCredProv) {'Registrado (reinicia para activar)'} else {'No instalado'})" -ForegroundColor $(if ($hasCredProv) {'Green'} else {'DarkYellow'})
Write-Host "    TrayApp:             $(if ($hasTrayApp) {'Instalado + inicio auto'} else {'No incluido'})" -ForegroundColor $(if ($hasTrayApp) {'Green'} else {'DarkYellow'})
Write-Host "    Firewall:            Configurado" -ForegroundColor Green
Write-Host "    Push Auth (relay):   $(if ($pushAuthEnabled) {'Habilitado (cloudflared + Cloudflare Tunnel)'} else {'Deshabilitado (solo transportes directos)'})" -ForegroundColor $(if ($pushAuthEnabled) {'Green'} else {'DarkYellow'})
Write-Host "    Instalacion:         $InstallDir" -ForegroundColor Gray
Write-Host "    Datos:               $DataDir" -ForegroundColor Gray
Write-Host ""
Write-Host "  Siguientes pasos:" -ForegroundColor Yellow
Write-Host "    1. Abre WindowsGoodBye TrayApp (en la bandeja del sistema)" -ForegroundColor White
Write-Host "    2. Configura tu contrasena de Windows en la TrayApp" -ForegroundColor White
Write-Host "    3. Instala la app Android y empareja escaneando el QR" -ForegroundColor White
Write-Host "    4. Bloquea la PC (Win+L) y desbloquea con tu huella!" -ForegroundColor White
Write-Host ""

if ($hasCredProv) {
    Write-Host "  IMPORTANTE: Reinicia el equipo para que el Credential Provider" -ForegroundColor Red
    Write-Host "  aparezca en la pantalla de bloqueo." -ForegroundColor Red
    Write-Host ""
}

Write-Host "  Para desinstalar: WindowsGoodBye-Setup.exe -Uninstall" -ForegroundColor DarkGray
Write-Host ""

if (-not $Silent) {
    Read-Host "  Presione ENTER para salir"
}
