# WindowsGoodBye

Desbloquea tu PC con Windows usando la huella dactilar de tu teléfono Android — sin necesidad de Windows Hello ni hardware biométrico en la PC.

## Descripción

WindowsGoodBye es un sistema completo que permite usar el lector de huellas de un dispositivo Android como método de autenticación para desbloquear una PC con Windows. El sistema se compone de:

- **Credential Provider** nativo (C++ COM DLL) que se integra en la pantalla de bloqueo de Windows
- **Servicio de Windows** (.NET 9) que coordina la comunicación entre el Credential Provider y el teléfono
- **TrayApp** (WinForms) para gestionar el pareado y configurar credenciales
- **App Android** (.NET MAUI) que escucha solicitudes de autenticación y presenta el prompt biométrico

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
│           │Named Pipe    │  WiFi  │                        │
│  ┌────────┴───────────┐  │        └────────────────────────┘
│  │    TrayApp         │  │
│  │   (WinForms)       │  │
│  └────────────────────┘  │
└──────────────────────────┘
```

## Transportes de Comunicación

El sistema soporta tres métodos de comunicación (en orden de prioridad):

| Prioridad | Transporte                | Puerto/Canal                                      | Descripción                    |
| --------- | ------------------------- | ------------------------------------------------- | ------------------------------ |
| 1         | **Bluetooth RFCOMM**      | UUID `a1b2c3d4-...`                               | Sin necesidad de WiFi ni cable |
| 2         | **TCP/USB** (ADB reverse) | `localhost:26820`                                 | Conexión por cable USB         |
| 3         | **UDP WiFi**              | Multicast `225.67.76.67:26817` / Unicast `:26818` | Fallback por red local         |

## Flujo de Funcionamiento

### Pareado (una sola vez)

1. En el **TrayApp** → "Pair New Device" → se genera un código QR
2. En la **app Android** → "Pair New PC" → escanear el QR
3. Se intercambian claves criptográficas (AES-256, HMAC-SHA256)
4. El dispositivo queda registrado en la base de datos

### Desbloqueo

1. Se bloquea la PC → aparece el tile **"WindowsGoodBye"** en la pantalla de login
2. El usuario selecciona el tile → el Credential Provider se conecta al Servicio
3. El Servicio envía `auth_discover` al teléfono (por BT / USB / WiFi)
4. El teléfono responde `auth_alive` → el Servicio envía un challenge cifrado (`auth_req`)
5. El teléfono muestra el **prompt de huella** → el usuario toca el sensor
6. El teléfono responde con un HMAC del nonce (`auth_resp`)
7. El Servicio verifica el HMAC y envía las credenciales al Credential Provider
8. **La PC se desbloquea automáticamente**

## Estructura del Proyecto

```
WindowsGoodBye/
├── src/
│   ├── WindowsGoodBye.Core/              # Biblioteca compartida
│   │   ├── Protocol.cs                   # Constantes del protocolo
│   │   ├── CryptoUtils.cs               # AES-256-CBC, HMAC-SHA256, DPAPI
│   │   ├── StreamTransport.cs            # Framing length-prefixed para BT/TCP
│   │   ├── UdpManager.cs                # Multicast/Unicast UDP
│   │   ├── AppDatabase.cs               # EF Core SQLite (PC)
│   │   └── Models.cs                    # DeviceInfo, AuthRecord, StoredCredential
│   │
│   ├── WindowsGoodBye.Service/           # Servicio de Windows (.NET 9 Worker)
│   │   ├── AuthWorker.cs                # Lógica principal de autenticación
│   │   ├── PipeServer.cs               # Named pipe ↔ Credential Provider
│   │   ├── AdminPipeServer.cs           # Named pipe ↔ TrayApp
│   │   ├── BluetoothServer.cs           # Servidor Bluetooth RFCOMM
│   │   └── TcpUsbServer.cs             # Servidor TCP para USB
│   │
│   ├── WindowsGoodBye.TrayApp/          # App de bandeja del sistema (WinForms)
│   │   └── TrayApplicationContext.cs    # Pareado, credenciales, gestión
│   │
│   ├── WindowsGoodBye.Mobile/           # App Android (.NET MAUI)
│   │   ├── MainPage.xaml.cs             # UI principal, manejo de auth
│   │   ├── QrScanPage.xaml.cs           # Escáner QR para pareado
│   │   ├── Services/
│   │   │   ├── AuthListener.cs          # Listener multi-transporte
│   │   │   ├── TcpUsbTransport.cs       # Transporte TCP/USB
│   │   │   └── BiometricService.cs      # Wrapper de BiometricPrompt
│   │   └── Platforms/Android/
│   │       ├── AuthForegroundService.cs # Servicio Android foreground
│   │       └── BluetoothTransport.cs    # Transporte Bluetooth Android
│   │
│   └── WindowsGoodBye.CredentialProvider/ # Credential Provider (C++ COM DLL)
│       ├── WinGBProvider.cpp            # Implementación ICredentialProvider
│       ├── WinGBProvider.h              # Declaraciones de clases
│       ├── guid.h                       # CLSID del provider
│       ├── helpers.h                    # Utilidades de pipe
│       └── provider.def                 # Exports de la DLL
│
├── scripts/
│   ├── build-all.ps1                    # Compilación completa (.NET + C++)
│   ├── install-service.ps1              # Instalación como servicio de Windows
│   ├── register-credprov.ps1            # Registro del Credential Provider
│   ├── register-firewall.ps1            # Reglas de firewall
│   └── setup-usb.ps1                   # Configuración ADB reverse
│
├── tools/
│   └── TestAuthClient/                  # Cliente de prueba (simula CredProvider)
│
└── WindowsGoodBye.sln                   # Solución .NET
```

## Requisitos

### PC (Windows)

- Windows 10/11 (x64)
- .NET 9 SDK
- Visual Studio 2022+ con **"Desktop development with C++"** (para compilar el Credential Provider)
- Bluetooth (opcional, para transporte BT)
- ADB (opcional, para transporte USB)

### Android

- Android 9.0+ (API 28+)
- Sensor de huellas o biometría
- .NET MAUI workload instalado para compilar

## Instalación

### 1. Compilar todo

```powershell
# Clonar el repositorio
git clone https://github.com/<tu-usuario>/WindowsGoodBye.git
cd WindowsGoodBye

# Compilar solución .NET
dotnet build WindowsGoodBye.sln

# Compilar Credential Provider (requiere VS C++ tools)
.\scripts\build-all.ps1
```

### 2. Registrar el Credential Provider (como Admin)

```powershell
# Copia la DLL a System32 y registra el COM CLSID
.\scripts\register-credprov.ps1
```

### 3. Configurar Firewall (como Admin)

```powershell
.\scripts\register-firewall.ps1
```

### 4. Instalar como servicio de Windows (opcional)

```powershell
# Para ejecución manual:
dotnet run --project src/WindowsGoodBye.Service

# Para instalar como servicio de Windows (como Admin):
.\scripts\install-service.ps1
```

### 5. Instalar la app en Android

```powershell
# Conectar dispositivo Android por USB
dotnet build src/WindowsGoodBye.Mobile -t:Install -f net9.0-android
```

### 6. Configurar USB (opcional)

```powershell
# Configura ADB reverse para comunicación USB
.\scripts\setup-usb.ps1
# O manualmente:
adb reverse tcp:26820 tcp:26820
```

## Uso

### Primer uso — Pareado

1. Ejecutar el **Servicio**: `dotnet run --project src/WindowsGoodBye.Service`
2. Ejecutar el **TrayApp**: `dotnet run --project src/WindowsGoodBye.TrayApp`
3. Click derecho en el icono de la bandeja → **"Pair New Device"**
4. En el teléfono, abrir la app → **"Pair New PC"** → escanear el QR
5. Una vez pareado, click derecho → **"Set Windows Password"** → ingresar credenciales

### Desbloqueo diario

1. Asegurar que el Servicio está corriendo (como servicio de Windows o manualmente)
2. Asegurar que la app Android tiene el servicio de escucha activo
3. Bloquear la PC (`Win + L`)
4. En la pantalla de bloqueo → seleccionar tile **"WindowsGoodBye"**
5. Tocar el sensor de huellas en el teléfono → **PC desbloqueada**

## Seguridad

| Aspecto                      | Implementación                                          |
| ---------------------------- | ------------------------------------------------------- |
| Pareado                      | Intercambio de claves via QR (canal visual seguro)      |
| Cifrado de transporte        | AES-256-CBC con clave única por dispositivo             |
| Autenticación                | Challenge-response con HMAC-SHA256                      |
| Almacenamiento de contraseña | DPAPI (`DataProtectionScope.LocalMachine`)              |
| Named Pipes                  | ACLs con PipeSecurity (Everyone ReadWrite para IPC)     |
| Biometría                    | `Android.Hardware.Biometrics.BiometricPrompt` (API 28+) |

### Modelo de amenazas

- La contraseña de Windows se almacena cifrada con DPAPI en `%ProgramData%\WindowsGoodBye\devices.db`
- Las claves de pareado nunca se transmiten después del pareado inicial (solo via QR)
- Cada sesión de autenticación usa un nonce aleatorio (anti-replay)
- La respuesta HMAC es verificada por el servicio antes de enviar credenciales

## Tecnologías

- **.NET 9** — Core, Service, TrayApp
- **.NET MAUI** — App Android (target `net9.0-android`, minSdk 28)
- **C++17** — Credential Provider (COM DLL)
- **EF Core + SQLite** — Base de datos local
- **InTheHand.Net.Bluetooth v4** — Bluetooth RFCOMM en Windows
- **ZXing.Net.Maui** — Escáner QR en Android
- **AES-256-CBC** / **HMAC-SHA256** / **DPAPI** — Criptografía

## Scripts

| Script                  | Descripción                                 | Requiere Admin |
| ----------------------- | ------------------------------------------- | :------------: |
| `build-all.ps1`         | Compila .NET + C++ CredProvider             |       No       |
| `install-service.ps1`   | Instala/desinstala servicio de Windows      |       Sí       |
| `register-credprov.ps1` | Registra/desregistra el Credential Provider |       Sí       |
| `register-firewall.ps1` | Crea reglas de firewall (UDP/TCP)           |       Sí       |
| `setup-usb.ps1`         | Configura ADB reverse para USB              |       No       |

## Desinstalación

```powershell
# Desregistrar Credential Provider (como Admin)
.\scripts\register-credprov.ps1 -Unregister

# Desinstalar servicio (como Admin)
.\scripts\install-service.ps1 -Uninstall

# Eliminar datos
Remove-Item "$env:ProgramData\WindowsGoodBye" -Recurse -Force
```

## Solución de Problemas

| Problema                                       | Solución                                                                                                    |
| ---------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| El tile no aparece en la pantalla de bloqueo   | Verificar que `register-credprov.ps1` se ejecutó como Admin. Reiniciar la PC.                               |
| Timeout al esperar huella                      | Verificar que la app Android está activa y el transporte conectado (USB/BT/WiFi).                           |
| "No stored credentials" en el log del servicio | Usar TrayApp → "Set Windows Password" para guardar las credenciales.                                        |
| Pipe UnauthorizedAccessException               | El servicio corre como SYSTEM pero el TrayApp como usuario. Verificar que se usan las ACLs de PipeSecurity. |
| ADB reverse no funciona                        | Ejecutar `adb reverse tcp:26820 tcp:26820`. Verificar que el dispositivo aparece en `adb devices`.          |

## Licencia

MIT License

## Créditos

Inspirado en el concepto original de [WindowsGoodbye](https://github.com/cqjjjzr/WindowsGoodbye) por cqjjjzr.
Reescrito completamente con arquitectura moderna (.NET 9, MAUI, Credential Provider nativo).
