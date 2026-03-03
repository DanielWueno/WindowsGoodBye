# WindowsGoodBye

Desbloquea tu PC con Windows usando la huella dactilar de tu teléfono Android — sin necesidad de Windows Hello ni hardware biométrico en la PC.

## Descripción

WindowsGoodBye es un sistema completo que permite usar el lector de huellas de un dispositivo Android como método de autenticación para desbloquear una PC con Windows. El sistema se compone de:

- **Credential Provider** nativo (C++ COM DLL) que se integra en la pantalla de bloqueo de Windows
- **Servicio de Windows** (.NET 9) que coordina la comunicación entre el Credential Provider y el teléfono
- **TrayApp** (WinForms) para gestionar el pareado y configurar credenciales
- **App Android** (.NET MAUI) que escucha solicitudes de autenticación y presenta el prompt biométrico

### Características principales

- Desbloqueo por huella dactilar vía Bluetooth, USB o WiFi
- Auto-reconexión automática al perder conexión
- Detección automática de dispositivos USB (ADB watcher)
- Notificaciones push (FCM) para despertar la app Android
- Solo pide huella cuando la PC está realmente bloqueada (no antes)
- Servicio de Windows con auto-arranque y recuperación ante fallos
- Instalador todo-en-uno con soporte para `ps2exe` (genera EXE standalone)

## Arquitectura

```
┌──────────────────────────┐        ┌────────────────────────┐
│     Windows PC           │        │   Android Phone        │
│                          │        │                        │
│  ┌────────────────────┐  │        │  ┌──────────────────┐  │
│  │ Credential Provider│  │        │  │   MAUI App        │  │
│  │   (C++ COM DLL)    │  │        │  │                  │  │
│  └────────┬───────────┘  │        │  │  ┌────────────┐  │  │
│           │Named Pipe    │        │  │  │ Biometric  │  │  │
│  ┌────────┴───────────┐  │        │  │  │  Prompt    │  │  │
│  │   Windows Service  │◄─┼────────┼──┤  └────────────┘  │  │
│  │   (.NET 9 Worker)  │  │  BT /  │  │                  │  │
│  └────────┬───────────┘  │  USB / │  └──────────────────┘  │
│           │Named Pipe    │  WiFi/ │                        │
│  ┌────────┴───────────┐  │  FCM   └────────────────────────┘
│  │    TrayApp         │  │
│  │   (WinForms)       │  │
│  └────────────────────┘  │
└──────────────────────────┘
```

## Transportes de Comunicación

El sistema soporta tres métodos de comunicación simultáneamente (con auto-reconexión):

| Prioridad | Transporte                | Puerto/Canal                                      | Descripción                    |
| --------- | ------------------------- | ------------------------------------------------- | ------------------------------ |
| 1         | **Bluetooth RFCOMM**      | UUID `a1b2c3d4-...`                               | Sin necesidad de WiFi ni cable |
| 2         | **TCP/USB** (ADB reverse) | `localhost:26820`                                 | Conexión por cable USB (auto-detectado) |
| 3         | **UDP WiFi**              | Multicast `225.67.76.67:26817` / Unicast `:26818` | Fallback por red local         |
| Wake-up   | **FCM Push**              | Firebase Cloud Messaging                          | Despierta la app si está dormida |

## Flujo de Funcionamiento

### Pareado (una sola vez)

1. En el **TrayApp** → "Pair New Device" → se genera un código QR
2. En la **app Android** → "Pair New PC" → escanear el QR
3. Se intercambian claves criptográficas (AES-256, HMAC-SHA256)
4. El dispositivo queda registrado en la base de datos

### Desbloqueo

1. Se bloquea la PC → aparece el tile **"WindowsGoodBye"** en la pantalla de login
2. El usuario selecciona el tile → el Credential Provider se conecta al Servicio
3. El Servicio detecta que la PC está bloqueada (`IsAuthWaiting`) y envía un challenge
4. Si la app está dormida, se envía push FCM → la app se despierta
5. El Servicio envía `auth_discover` al teléfono (por BT / USB / WiFi)
6. El teléfono responde `auth_alive` → el Servicio envía un challenge cifrado (`auth_req`)
7. El teléfono muestra el **prompt de huella** → el usuario toca el sensor
8. El teléfono responde con un HMAC del nonce (`auth_resp`)
9. El Servicio verifica el HMAC y envía las credenciales al Credential Provider
10. **La PC se desbloquea automáticamente**

## Estructura del Proyecto

```
WindowsGoodBye/
├── src/
│   ├── WindowsGoodBye.Core/              # Biblioteca compartida (.NET 9)
│   │   ├── Protocol.cs                   # Constantes del protocolo
│   │   ├── CryptoUtils.cs               # AES-256-CBC, HMAC-SHA256, DPAPI
│   │   ├── StreamTransport.cs            # Framing length-prefixed para BT/TCP
│   │   ├── UdpManager.cs                # Multicast/Unicast UDP
│   │   ├── PairingSession.cs            # Lógica de pareado PC↔Android
│   │   ├── AppDatabase.cs               # SQLite con migraciones automáticas
│   │   └── Models.cs                    # DeviceInfo, AuthRecord, StoredCredential
│   │
│   ├── WindowsGoodBye.Service/           # Servicio de Windows (.NET 9 Worker)
│   │   ├── Program.cs                   # Entry point + CLI (install/uninstall/start)
│   │   ├── AuthWorker.cs                # Lógica principal + IsAuthWaiting gate
│   │   ├── PipeServer.cs               # Named pipe ↔ Credential Provider
│   │   ├── AdminPipeServer.cs           # Named pipe ↔ TrayApp
│   │   ├── BluetoothServer.cs           # Servidor Bluetooth RFCOMM
│   │   ├── TcpUsbServer.cs             # Servidor TCP para USB
│   │   ├── AdbDeviceWatcher.cs          # Auto-detección USB (WMI events)
│   │   └── FcmPushSender.cs            # Push notifications vía FCM
│   │
│   ├── WindowsGoodBye.TrayApp/          # App de bandeja del sistema (WinForms)
│   │   ├── Program.cs                   # Entry point
│   │   └── TrayApplicationContext.cs    # Pareado, credenciales, gestión
│   │
│   ├── WindowsGoodBye.Mobile/           # App Android (.NET MAUI)
│   │   ├── MainPage.xaml.cs             # UI principal, manejo de auth
│   │   ├── QrScanPage.xaml.cs           # Escáner QR para pareado
│   │   ├── Data/
│   │   │   └── MobileDatabase.cs        # SQLite local del teléfono
│   │   ├── Services/
│   │   │   ├── AuthListener.cs          # Listener multi-transporte + auto-reconexión
│   │   │   ├── TcpUsbTransport.cs       # Transporte TCP/USB
│   │   │   └── IBiometricService.cs     # Interfaz de biometría
│   │   └── Platforms/Android/
│   │       ├── AuthForegroundService.cs # Servicio Android foreground
│   │       ├── BluetoothTransport.cs    # Transporte Bluetooth Android
│   │       ├── AndroidBiometricService.cs # BiometricPrompt wrapper
│   │       ├── FcmService.cs            # Receptor de push FCM
│   │       └── BootReceiver.cs          # Auto-inicio al arrancar Android
│   │
│   └── WindowsGoodBye.CredentialProvider/ # Credential Provider (C++ COM DLL)
│       ├── WinGBProvider.cpp            # Implementación ICredentialProvider
│       ├── WinGBProvider.h              # Declaraciones de clases
│       ├── guid.h                       # CLSID del provider
│       ├── helpers.h                    # Utilidades de pipe
│       └── provider.def                 # Exports de la DLL
│
├── scripts/
│   ├── Build-Release.ps1                # Compila todo y genera release/
│   ├── WindowsGoodBye-Setup.ps1         # Instalador/desinstalador todo-en-uno
│   └── WindowsGoodBye-Setup.bat         # Launcher con elevación de admin
│
├── tools/
│   └── TestAuthClient/                  # Cliente de prueba (simula CredProvider)
│
└── WindowsGoodBye.sln
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

## Compilación desde código fuente

### 1. Generar release completo

```powershell
git clone https://github.com/DanielWueno/WindowsGoodBye.git
cd WindowsGoodBye

# Compilar todo y empaquetar en release/
.\scripts\Build-Release.ps1
```

Flags disponibles:

| Flag                      | Efecto                                 |
| ------------------------- | -------------------------------------- |
| `-SkipAndroid`            | No compila el APK                      |
| `-SkipCredentialProvider` | No compila la DLL C++                  |
| `-SkipExeWrapper`         | No genera el EXE con ps2exe            |

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

## Seguridad

| Aspecto                      | Implementación                                          |
| ---------------------------- | ------------------------------------------------------- |
| Pareado                      | Intercambio de claves via QR (canal visual seguro)      |
| Cifrado de transporte        | AES-256-CBC con clave única por dispositivo             |
| Autenticación                | Challenge-response con HMAC-SHA256 + nonce anti-replay  |
| Almacenamiento de contraseña | DPAPI (`DataProtectionScope.LocalMachine`)              |
| Named Pipes                  | ACLs con PipeSecurity (Everyone ReadWrite para IPC)     |
| Biometría                    | `Android.Hardware.Biometrics.BiometricPrompt` (API 28+) |
| Gate de autenticación        | Solo pide huella cuando la PC está bloqueada (`IsAuthWaiting`) |

### Modelo de amenazas

- La contraseña de Windows se almacena cifrada con DPAPI en `%ProgramData%\WindowsGoodBye\devices.db`
- Las claves de pareado nunca se transmiten después del pareado inicial (solo via QR)
- Cada sesión de autenticación usa un nonce aleatorio (anti-replay)
- La respuesta HMAC es verificada por el servicio antes de enviar credenciales
- La autenticación biométrica solo se solicita cuando el Credential Provider está activo (PC bloqueada)

## Tecnologías

- **.NET 9** — Core, Service, TrayApp
- **.NET MAUI** — App Android (target `net9.0-android`, minSdk 28)
- **C++17** — Credential Provider (COM DLL)
- **SQLite** — Base de datos local (con migraciones automáticas)
- **InTheHand.Net.Bluetooth v4** — Bluetooth RFCOMM en Windows
- **ZXing.Net.Maui** — Escáner QR en Android
- **Firebase Cloud Messaging** — Push notifications para wake-up
- **AES-256-CBC** / **HMAC-SHA256** / **DPAPI** — Criptografía
- **ps2exe** — Generación de EXE standalone del instalador

## Scripts

| Script                       | Descripción                                    | Requiere Admin |
| ---------------------------- | ---------------------------------------------- | :------------: |
| `Build-Release.ps1`         | Compila todo y empaqueta en `release/`          |       No       |
| `WindowsGoodBye-Setup.ps1`  | Instalador/desinstalador todo-en-uno (7 pasos)  |       Sí       |
| `WindowsGoodBye-Setup.bat`  | Launcher del instalador con elevación de admin   |       No       |

## Solución de Problemas

| Problema                                       | Solución                                                                                                    |
| ---------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| El tile no aparece en la pantalla de bloqueo   | Verificar que el instalador se ejecutó como Admin. Reiniciar la PC.                                         |
| Timeout al esperar huella                      | Verificar que la app Android está activa y el transporte conectado (USB/BT/WiFi).                           |
| "No stored credentials" en el log del servicio | Usar TrayApp → "Set Windows Password" para guardar las credenciales.                                        |
| Pide huella sin que la PC esté bloqueada       | Verificar que el servicio está actualizado (debe tener `IsAuthWaiting` gate).                               |
| Pipe UnauthorizedAccessException               | El servicio corre como SYSTEM pero el TrayApp como usuario. Verificar ACLs de PipeSecurity.                 |
| El servicio no inicia tras reinicio            | Ejecutar `WindowsGoodBye-Setup.ps1` o `sc.exe query WindowsGoodByeService` para verificar el registro.     |
| ADB no detecta el teléfono                     | Verificar que USB debugging está activado y el dispositivo aparece en `adb devices`.                        |

## Licencia

MIT License

## Créditos

Inspirado en el concepto original de [WindowsGoodbye](https://github.com/cqjjjzr/WindowsGoodbye) por cqjjjzr.
Reescrito completamente con arquitectura moderna (.NET 9, MAUI, Credential Provider nativo).
