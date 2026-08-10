# Arquitectura

Documento de referencia detallado. Para una introducción rápida al proyecto, ver el [README](../README.md).

## Componentes

```
┌──────────────────────────────────────────────────────────────┐
│                        Windows PC                             │
│                                                                │
│  ┌──────────────┐    Named Pipe    ┌────────────────────────┐│
│  │  Credential  │◄────────────────►│    Windows Service      ││
│  │  Provider    │   (sin cambios)  │    (.NET 9 Worker)      ││
│  │  (C++ COM)   │                  │                          ││
│  └──────────────┘                  │  ┌────────────────────┐  ││
│                                    │  │     AuthWorker      │  ││
│         ┌──────────────┐          │  │  (orquestador —     │  ││
│         │   TrayApp    │◄─Pipe────┤  │   RunAuthRaceAsync) │  ││
│         │  (WinForms)  │  Admin   │  └──┬────────┬────────┘  ││
│         └──────────────┘          │     │        │           ││
│                                    │┌────▼───┐┌───▼─────────┐││
│                                    ││BT/TCP/ ││  RelayServer ││
│                                    ││ UDP    ││  (Kestrel    ││
│                                    ││Servers ││  embebido)   ││
│                                    │└────┬───┘└───┬─────────┘││
│                                    │     │        │           ││
│                                    │     │  ┌─────▼────────┐  ││
│                                    │     │  │TunnelManager │  ││
│                                    │     │  │(cloudflared) │  ││
│                                    │     │  └─────┬────────┘  ││
└────────────────────────────────────┼─────┼────────┼──────────┘│
                                      │     │        │
                               BT/USB/WiFi FCM   Cloudflare Tunnel
                               (red local) (Google)   (Internet)
                                      │     │        │
┌─────────────────────────────────────┼─────┼────────┼──────────┐
│                    Android Phone    ▼     ▼        ▼          │
│                                                                │
│  ┌────────────┐  ┌───────────┐  ┌──────────────────────────┐ │
│  │AuthListener│  │FcmService │  │   PushAuthActivity        │ │
│  │(BT/TCP/UDP)│  │  (recv)   │  │   (number matching +      │ │
│  └─────┬──────┘  └─────┬─────┘  │    BiometricPrompt)       │ │
│        │               │        └──────────┬───────────────┘ │
│        └───────┬───────┴───────────────────┘                 │
│                │  HttpRelayClient → HTTPS POST al relay       │
└────────────────┼───────────────────────────────────────────────┘
```

- **Credential Provider** (C++ COM DLL): se integra en la pantalla de bloqueo de Windows, habla con el Service exclusivamente por named pipe. No ha cambiado en esta ronda de trabajo.
- **Windows Service** (.NET 9 Worker): dueño del ciclo de autenticación. `AuthWorker.RunAuthRaceAsync()` lanza en paralelo los transportes directos (Ruta A, siempre), FCM wake-up legacy (Ruta B, condicional) y el challenge de push-auth completo vía el relay embebido (Ruta C, condicional a que el túnel esté activo) — gana la primera ruta que **complete con éxito** la verificación, no la primera que simplemente responda.
- **RelayServer**: servidor HTTP (Kestrel/ASP.NET Minimal API) embebido en el propio proceso del Service, bindeado solo a loopback (`127.0.0.1`). Expone los endpoints que consume Android a través de internet (vía el túnel) y una API in-process que usa `AuthWorker` directamente (sin HTTP de por medio) — ver [`docs/plan_push_auth_v2.md`](plan_push_auth_v2.md) para el diseño completo de endpoints, rate limiting y aislamiento.
- **TunnelManager**: gestiona el proceso `cloudflared.exe` y expone la URL pública del túnel al resto del Service.
- **TrayApp** (WinForms): pareado, credenciales, y (pendiente) configuración de Push Auth por dispositivo.
- **App Android** (.NET MAUI): `AuthListener` para los transportes directos, `FcmService` para recibir challenges/wake-ups por push, y `PushAuthActivity` para el flujo de number matching + biometría cuando el desbloqueo llega por push.

## Transportes de Comunicación

| Prioridad | Transporte                | Puerto/Canal                                      | Descripción                                  |
| --------- | ------------------------- | -------------------------------------------------- | --------------------------------------------- |
| 1         | **Bluetooth RFCOMM**      | UUID `a1b2c3d4-...`                                | Sin necesidad de WiFi ni cable               |
| 2         | **TCP/USB** (ADB reverse) | `localhost:26820`                                  | Conexión por cable USB (auto-detectado)      |
| 3         | **UDP WiFi**              | Multicast `225.67.76.67:26817` / Unicast `:26818`  | Fallback por red local                        |
| Wake-up   | **FCM Push**              | Firebase Cloud Messaging                           | Despierta la app si está dormida             |
| Push Auth *(en desarrollo)* | **Relay HTTP + Cloudflare Tunnel** | `localhost:26821` (local) / URL del túnel (internet) | Desbloqueo completo vía notificación push cuando PC y teléfono no comparten red local |

## Flujo de Funcionamiento

### Pareado (una sola vez)

1. En el **TrayApp** → "Pair New Device" → se genera un código QR
2. En la **app Android** → "Pair New PC" → escanear el QR
3. Se intercambian/derivan las claves criptográficas del dispositivo (`DeviceKey`, y de ella `AuthKey`/`RelayKey` vía HKDF)
4. El dispositivo queda registrado en la base de datos; en Android, `DeviceKey` se persiste cifrada (envelope encryption vía Android Keystore/StrongBox — ver [`SECURITY.md`](SECURITY.md))

### Desbloqueo — transporte directo (Ruta A, producción)

1. Se bloquea la PC → aparece el tile **"WindowsGoodBye"** en la pantalla de login
2. El usuario selecciona el tile → el Credential Provider se conecta al Servicio
3. El Servicio detecta que la PC está bloqueada y envía un challenge
4. Si la app está dormida, se envía push FCM de wake-up → la app se despierta
5. El Servicio envía `auth_discover` al teléfono (por BT / USB / WiFi)
6. El teléfono responde `auth_alive` → el Servicio envía un challenge cifrado (`auth_req`)
7. El teléfono muestra el **prompt de huella** → el usuario toca el sensor
8. El teléfono responde con un HMAC del nonce (`auth_resp`)
9. El Servicio verifica el HMAC y envía las credenciales al Credential Provider
10. **La PC se desbloquea automáticamente**

### Desbloqueo — push auth (Ruta C, en desarrollo)

Pensado para cuando la PC y el teléfono no comparten red local (p. ej. el teléfono está en datos móviles). Flujo conceptual — ver [`docs/plan_push_auth_v2.md`](plan_push_auth_v2.md) para el protocolo completo y [`docs/implementation_progress_push_auth_v2.md`](implementation_progress_push_auth_v2.md) para qué parte ya está implementada:

1. El Service cifra un nonce (AES-256-GCM) y lo envía por FCM junto a un **código de verificación de 2 dígitos**.
2. Android muestra una notificación heads-up; al tocarla, `PushAuthActivity` pide confirmar que el código coincide con el que se ve en la pantalla de la PC (number matching) **antes** de pedir biometría — mitiga ataques de "push fatigue".
3. Tras confirmar y autenticar con `BiometricPrompt`, el teléfono firma un HMAC (con `AuthKey`, derivada por HKDF) y lo envía de vuelta a través del relay (directamente si hay red local, o vía Cloudflare Tunnel si no).
4. El Service verifica el HMAC con ventanas anti-replay y desbloquea la PC.

## Estructura del Proyecto

```
WindowsGoodBye/
├── src/
│   ├── WindowsGoodBye.Core/                  # Biblioteca compartida (.NET 9)
│   │   ├── Protocol.cs                       # Constantes del protocolo (transportes + push auth)
│   │   ├── CryptoUtils.cs                    # AES-256-GCM (CBC legado, obsoleto, solo migración)
│   │   ├── JwtHelper.cs                      # JWT HS256 sin dependencias externas
│   │   ├── RelayKeyDerivation.cs             # HKDF: deriva AuthKey/RelayKey desde DeviceKey
│   │   ├── StreamTransport.cs                # Framing length-prefixed para BT/TCP
│   │   ├── UdpManager.cs                     # Multicast/Unicast UDP
│   │   ├── PairingSession.cs                 # Lógica de pareado PC↔Android
│   │   ├── AppDatabase.cs                    # SQLite con migraciones automáticas
│   │   └── Models.cs                         # DeviceInfo, AuthRecord, StoredCredential, PushAuthSession
│   │
│   ├── WindowsGoodBye.Service/                # Servicio de Windows (.NET 9 Worker)
│   │   ├── Program.cs                        # Entry point + CLI + registro de RelayServer/TunnelManager
│   │   ├── AuthWorker.cs                     # Orquestador: RunAuthRaceAsync (Ruta A/B/C)
│   │   ├── AuthRaceCombinator.cs             # Combinador "primer éxito gana" de la carrera
│   │   ├── PushFatigueGuard.cs               # Rate-limit/backoff de generación de challenge por PC
│   │   ├── RelayServer.cs                    # Relay HTTP embebido (Kestrel, loopback-only)
│   │   ├── RelayModels.cs                    # DTOs y límites del relay
│   │   ├── TunnelManager.cs                  # Gestión del proceso cloudflared.exe
│   │   ├── ITunnelStatusProvider.cs          # Abstracción de estado del túnel para AuthWorker
│   │   ├── PipeServer.cs                     # Named pipe ↔ Credential Provider
│   │   ├── AdminPipeServer.cs                # Named pipe ↔ TrayApp (ACL restringida)
│   │   ├── BluetoothServer.cs                # Servidor Bluetooth RFCOMM
│   │   ├── TcpUsbServer.cs                   # Servidor TCP para USB
│   │   ├── AdbDeviceWatcher.cs               # Auto-detección USB (WMI events)
│   │   └── FcmPushSender.cs                  # Push notifications vía FCM HTTP v1 + OAuth2
│   │
│   ├── WindowsGoodBye.TrayApp/                # App de bandeja del sistema (WinForms)
│   │   ├── Program.cs                        # Entry point
│   │   └── TrayApplicationContext.cs         # Pareado, credenciales, gestión
│   │
│   ├── WindowsGoodBye.Mobile/                 # App Android (.NET MAUI)
│   │   ├── MainPage.xaml.cs                  # UI principal, manejo de auth
│   │   ├── QrScanPage.xaml.cs                # Escáner QR para pareado
│   │   ├── Data/
│   │   │   └── MobileDatabase.cs             # SQLite local (DeviceKey cifrada en reposo)
│   │   ├── Services/
│   │   │   ├── AuthListener.cs               # Listener multi-transporte + auto-reconexión
│   │   │   ├── TcpUsbTransport.cs            # Transporte TCP/USB
│   │   │   ├── HttpRelayClient.cs            # Cliente HTTP hacia el relay (token sync, respond/reject)
│   │   │   └── IBiometricService.cs          # Interfaz de biometría (con BiometricErrorType)
│   │   └── Platforms/Android/
│   │       ├── AuthForegroundService.cs      # Servicio Android foreground
│   │       ├── BluetoothTransport.cs         # Transporte Bluetooth Android
│   │       ├── AndroidBiometricService.cs    # AndroidX BiometricPrompt wrapper
│   │       ├── SecureKeyStorage.cs           # Envelope encryption de DeviceKey (Keystore/StrongBox)
│   │       ├── PushAuthChallengeInfo.cs      # Parseo del challenge de push-auth
│   │       ├── PushAuthActivity.cs           # UI de number matching + biometría (push-auth)
│   │       ├── FcmService.cs                 # Receptor de push FCM (wake-up y challenge)
│   │       └── BootReceiver.cs               # Auto-inicio al arrancar Android
│   │
│   └── WindowsGoodBye.CredentialProvider/     # Credential Provider (C++ COM DLL)
│       ├── WinGBProvider.cpp                 # Implementación ICredentialProvider
│       ├── WinGBProvider.h                   # Declaraciones de clases
│       ├── guid.h                            # CLSID del provider
│       ├── helpers.h                         # Utilidades de pipe
│       └── provider.def                      # Exports de la DLL
│
├── scripts/
│   ├── Build-Release.ps1                     # Compila todo y genera release/
│   ├── WindowsGoodBye-Setup.ps1              # Instalador/desinstalador todo-en-uno
│   └── WindowsGoodBye-Setup.bat              # Launcher con elevación de admin
│
├── tests/
│   ├── WindowsGoodBye.Core.Tests/            # CryptoUtils, JwtHelper, RelayKeyDerivation
│   └── WindowsGoodBye.Service.Tests/         # RelayServer (integración loopback), fatiga, carrera, HMAC
│
├── tools/
│   └── TestAuthClient/                       # Cliente de prueba (simula CredProvider)
│
├── docs/
│   ├── plan_push_auth_v2.md                  # Diseño completo de Push Auth (fuente de verdad)
│   ├── implementation_progress_push_auth_v2.md # Estado de implementación fase por fase
│   ├── ARCHITECTURE.md                       # Este documento
│   └── SECURITY.md                           # Modelo de amenazas y criptografía
│
└── WindowsGoodBye.sln
```

> Nota: el Credential Provider (C++), el instalador y la TrayApp todavía no tienen wiring de Push Auth (eso corresponde a fases posteriores del plan, ver el log de progreso). No asumas que el flujo de push-auth es utilizable de punta a punta todavía.
