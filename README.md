# WindowsGoodBye

Desbloquea tu PC con Windows usando la huella dactilar de tu teléfono Android — sin necesidad de Windows Hello ni hardware biométrico en la PC.

## Descripción

WindowsGoodBye es un sistema completo que permite usar el lector de huellas de un dispositivo Android como método de autenticación para desbloquear una PC con Windows. El sistema se compone de:

- **Credential Provider** nativo (C++ COM DLL) que se integra en la pantalla de bloqueo de Windows
- **Servicio de Windows** (.NET 9) que coordina la comunicación entre el Credential Provider y el teléfono
- **TrayApp** (WinForms) para gestionar el pareado y configurar credenciales
- **App Android** (.NET MAUI) que escucha solicitudes de autenticación y presenta el prompt biométrico

Para el desglose completo de componentes, diagramas y la estructura del repo, ver [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). Para el modelo de amenazas y la criptografía usada, ver [`docs/SECURITY.md`](docs/SECURITY.md).

### Características principales

- Desbloqueo por huella dactilar vía Bluetooth, USB o WiFi
- Auto-reconexión automática al perder conexión
- Detección automática de dispositivos USB (ADB watcher)
- Notificaciones push (FCM) para despertar la app Android
- Solo pide huella cuando la PC está realmente bloqueada (no antes)
- Servicio de Windows con auto-arranque y recuperación ante fallos
- Instalador todo-en-uno con soporte para `ps2exe` (genera EXE standalone)
- 🚧 **Push Auth estilo Google Prompt** (en desarrollo, ver más abajo)

## 🚧 Push Auth (en desarrollo)

Cuando la PC y el teléfono no comparten red local (p. ej. el teléfono está fuera de casa, en datos móviles), un modo alternativo de desbloqueo enviará una notificación push al teléfono — similar a "Google Prompt" — con **number matching** (un código de verificación que el usuario compara entre la PC y el teléfono) para evitar ataques de phishing y de "push fatigue" (bombardeo de solicitudes hasta que el usuario acepta una por cansancio).

- Diseño completo y auditoría de seguridad: [`docs/plan_push_auth_v2.md`](docs/plan_push_auth_v2.md)
- Estado real de implementación (qué fases están hechas, qué falta, qué está bloqueado): [`docs/implementation_progress_push_auth_v2.md`](docs/implementation_progress_push_auth_v2.md)

**Aún no está disponible de punta a punta.** Ya funcionan y están probados (build + tests automatizados) el cifrado AES-256-GCM, el relay HTTP embebido con rate limiting y aislamiento de fallos, la orquestación de la carrera de rutas de autenticación en el Service, y la recepción del challenge en Android. Falta el wiring del Credential Provider (mostrar el código en el tile de login), el pairing con la URL del relay, el instalador empaquetando `cloudflared`, y la configuración desde la TrayApp — sin eso, el flujo de push no se puede usar todavía para desbloquear una sesión real.

## Instalación rápida (release)

Si tienes el paquete `release/` ya compilado:

```powershell
# Ejecutar el instalador como Administrador
.\WindowsGoodBye-Setup.bat

# O directamente:
.\WindowsGoodBye-Setup.exe
```

El instalador realiza automáticamente:

1. Copia archivos a `%ProgramFiles%\WindowsGoodBye`
2. Instala el servicio de Windows (auto-start + recuperación ante fallos)
3. Registra el Credential Provider (DLL → System32 + registry)
4. Configura reglas de firewall (UDP 26817/26818, TCP 26820)
5. Crea acceso directo de TrayApp en inicio
6. Opcionalmente instala el APK en Android vía ADB

Para desinstalar:

```powershell
.\WindowsGoodBye-Setup.exe -Uninstall
```

## Requisitos

### PC (Windows)

- Windows 10/11 (x64)
- .NET 9 SDK (solo para compilar; el release es self-contained)
- Visual Studio con **"Desktop development with C++"** (solo para compilar el Credential Provider)
- Bluetooth (opcional, para transporte BT)

### Android

- Android 9.0+ (API 28+)
- Sensor de huellas o biometría
- .NET MAUI workload instalado (solo para compilar)

## Compilación desde código fuente

### 1. Generar release completo

```powershell
git clone https://github.com/DanielWueno/WindowsGoodBye.git
cd WindowsGoodBye

# Compilar todo y empaquetar en release/
.\scripts\Build-Release.ps1
```

Flags disponibles:

| Flag                      | Efecto                      |
| ------------------------- | ---------------------------- |
| `-SkipAndroid`            | No compila el APK            |
| `-SkipCredentialProvider` | No compila la DLL C++        |
| `-SkipExeWrapper`         | No genera el EXE con ps2exe  |

### 2. Generar el EXE standalone del instalador

```powershell
# Instalar ps2exe (una sola vez)
Install-Module ps2exe -Scope CurrentUser

# Compilar todo incluyendo el EXE wrapper
.\scripts\Build-Release.ps1
```

### 3. Solo compilar para desarrollo

```powershell
# Compilar solución .NET
dotnet build WindowsGoodBye.sln

# Ejecutar servicio manualmente
dotnet run --project src/WindowsGoodBye.Service

# Ejecutar TrayApp
dotnet run --project src/WindowsGoodBye.TrayApp

# Instalar APK en dispositivo conectado
dotnet build src/WindowsGoodBye.Mobile -t:Install -f net9.0-android

# Correr los tests automatizados
dotnet test tests/WindowsGoodBye.Core.Tests
dotnet test tests/WindowsGoodBye.Service.Tests
```

## Uso

### Primer uso — Pareado

1. Asegurar que el **Servicio** está corriendo
2. Abrir el **TrayApp** (icono en la bandeja del sistema)
3. Click derecho → **"Pair New Device"**
4. En el teléfono, abrir la app → **"Pair New PC"** → escanear el QR
5. Click derecho → **"Set Windows Password"** → ingresar credenciales

### Desbloqueo diario

1. Asegurar que la app Android tiene el servicio de escucha activo
2. Bloquear la PC (`Win + L`)
3. En la pantalla de bloqueo → seleccionar tile **"WindowsGoodBye"**
4. Tocar el sensor de huellas en el teléfono → **PC desbloqueada**

> **Nota:** El servicio de Windows arranca automáticamente con el sistema.
> La app Android se mantiene activa con un foreground service y se reinicia al arrancar el teléfono.

## Tecnologías

- **.NET 9** — Core, Service, TrayApp
- **.NET MAUI** — App Android (target `net9.0-android`, minSdk 28)
- **C++17** — Credential Provider (COM DLL)
- **ASP.NET Core / Kestrel** — Relay HTTP embebido en el Service (push auth, en desarrollo)
- **Cloudflare Tunnel** (`cloudflared`) — Exposición del relay a internet sin port-forwarding (en desarrollo)
- **SQLite** — Base de datos local (con migraciones automáticas)
- **InTheHand.Net.Bluetooth v4** — Bluetooth RFCOMM en Windows
- **ZXing.Net.Maui** — Escáner QR en Android
- **Firebase Cloud Messaging** — Push notifications (wake-up y challenges de push auth)
- **AES-256-GCM** / **HMAC-SHA256** / **HKDF** / **JWT (HS256)** / **DPAPI** — Criptografía (ver [`docs/SECURITY.md`](docs/SECURITY.md))
- **xUnit** — Tests unitarios/integración
- **ps2exe** — Generación de EXE standalone del instalador

## Scripts

| Script                     | Descripción                                    | Requiere Admin |
| -------------------------- | ----------------------------------------------- | :------------: |
| `Build-Release.ps1`        | Compila todo y empaqueta en `release/`          |       No       |
| `WindowsGoodBye-Setup.ps1` | Instalador/desinstalador todo-en-uno (7 pasos)  |       Sí       |
| `WindowsGoodBye-Setup.bat` | Launcher del instalador con elevación de admin  |       No       |

## Solución de Problemas

| Problema                                       | Solución                                                                                                |
| ----------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| El tile no aparece en la pantalla de bloqueo    | Verificar que el instalador se ejecutó como Admin. Reiniciar la PC.                                       |
| Timeout al esperar huella                       | Verificar que la app Android está activa y el transporte conectado (USB/BT/WiFi).                         |
| "No stored credentials" en el log del servicio  | Usar TrayApp → "Set Windows Password" para guardar las credenciales.                                      |
| Pide huella sin que la PC esté bloqueada        | Verificar que el servicio está actualizado (debe tener `IsAuthWaiting` gate).                             |
| Pipe UnauthorizedAccessException                | El servicio corre como SYSTEM pero el TrayApp como usuario. Verificar ACLs de PipeSecurity.               |
| El servicio no inicia tras reinicio             | Ejecutar `WindowsGoodBye-Setup.ps1` o `sc.exe query WindowsGoodByeService` para verificar el registro.     |
| ADB no detecta el teléfono                      | Verificar que USB debugging está activado y el dispositivo aparece en `adb devices`.                      |

## Documentación

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — Componentes, diagramas, estructura completa del repo
- [`docs/SECURITY.md`](docs/SECURITY.md) — Modelo de amenazas, criptografía, fronteras de confianza
- [`docs/plan_push_auth_v2.md`](docs/plan_push_auth_v2.md) — Diseño completo de Push Auth (fuente de verdad)
- [`docs/implementation_progress_push_auth_v2.md`](docs/implementation_progress_push_auth_v2.md) — Estado de implementación de Push Auth, fase por fase

## Licencia

MIT License

## Créditos

Inspirado en el concepto original de [WindowsGoodbye](https://github.com/cqjjjzr/WindowsGoodbye) por cqjjjzr.
Reescrito completamente con arquitectura moderna (.NET 9, MAUI, Credential Provider nativo).
