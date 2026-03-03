<#
.SYNOPSIS
    WindowsGoodBye — All-in-one installer.
    Installs the Service, Credential Provider, TrayApp, firewall rules,
    and optionally the Android APK via ADB.

.DESCRIPTION
    This script must be run as Administrator.
    It expects to be in the same folder as:
      Service\WindowsGoodBye.Service.exe
      Service\WindowsGoodBye.TrayApp.exe
      Service\WinGBCredentialProvider.dll   (optional)
      WindowsGoodBye.apk                   (optional)

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
        Write-Host "ERROR: Este instalador requiere privilegios de Administrador." -ForegroundColor Red
        Write-Host "       Haz clic derecho -> Ejecutar como administrador." -ForegroundColor Yellow
        Write-Host ""
        if (-not $Silent) { Read-Host "Presione ENTER para salir" }
        exit 1
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
    @('WindowsGoodBye - UDP Multicast (26817)',
      'WindowsGoodBye - UDP Unicast (26818)',
      'WindowsGoodBye - TCP USB (26820)') | ForEach-Object {
        Remove-NetFirewallRule -DisplayName $_ -ErrorAction SilentlyContinue
    }
    Write-Done "Reglas de firewall eliminadas."

    # 5. Remove TrayApp from startup
    $startupLink = Join-Path ([Environment]::GetFolderPath('CommonStartup')) "WindowsGoodBye TrayApp.lnk"
    if (Test-Path $startupLink) { Remove-Item $startupLink -Force }
    Write-Done "Acceso directo de inicio eliminado."

    # 6. Optionally remove install dir (keep data)
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

$totalSteps = 7
$hasCredProv = Test-Path (Join-Path $ServiceSrc "WinGBCredentialProvider.dll")
$hasApk      = Test-Path (Join-Path $SetupDir "WindowsGoodBye.apk")
$hasTrayApp  = Test-Path (Join-Path $ServiceSrc "WindowsGoodBye.TrayApp.exe")

Write-Host "  Componentes detectados:" -ForegroundColor White
Write-Host "    [+] Windows Service"                                 -ForegroundColor Green
Write-Host "    $(if ($hasTrayApp) {'[+]'} else {'[-]'}) TrayApp"    -ForegroundColor $(if ($hasTrayApp) {'Green'} else {'DarkYellow'})
Write-Host "    $(if ($hasCredProv) {'[+]'} else {'[-]'}) Credential Provider (DLL)" -ForegroundColor $(if ($hasCredProv) {'Green'} else {'DarkYellow'})
Write-Host "    $(if ($hasApk) {'[+]'} else {'[-]'}) Android APK"   -ForegroundColor $(if ($hasApk) {'Green'} else {'DarkYellow'})
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

# ─── 7. Summary ───
Write-Step 7 $totalSteps "Verificacion final..."

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
