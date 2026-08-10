# 📋 Plan: Autenticación Push (Estilo Google Prompt) para WindowsGoodBye

## Estado Actual del Proyecto

### Lo que ya existe y funciona
- **Transporte USB/TCP** (ADB reverse): canal principal activo en `localhost:26820`
- **Transporte Bluetooth RFCOMM**: servidor activo, auto-reconexión
- **Transporte UDP/WiFi**: multicast discovery + unicast para auth
- **Flujo de autenticación completo**: challenge-response con HMAC-SHA256
- **Credential Provider C++ COM**: integrado en pantalla de login de Windows
- **Biometric Prompt Android**: wrapper de `BiometricPrompt` (API 28+)
- **FCM Sender (PC)**: envía push con `FirebaseAdmin SDK` usando service account
- **FCM Receiver (Android)**: `FcmService` hereda de `FirebaseMsgService`, recibe data messages

### Cómo funciona actualmente (simplificado)
```
PC Bloqueada → Credential Provider → Named Pipe → Service
    ↓
Service envía "auth_discover" por BT/USB/WiFi (conexión persistente)
    ↓
Si app dormida → FCM push "wake-up" (solo despierta la app)
    ↓
Android responde "auth_alive" → Service envía challenge cifrado
    ↓
Android muestra BiometricPrompt → usuario toca huella
    ↓
Android responde con HMAC del nonce → Service verifica → desbloquea PC
```

### Problema actual con el enfoque
El FCM **solo se usa como "wake-up call"** — despierta la app para que establezca conexión por BT/USB/WiFi. La autenticación real viaja por esos transportes persistentes. Esto significa:

1. **Se necesita conexión activa** (BT, USB o WiFi en misma red) para completar auth
2. Si el teléfono está en otra red/lugar, el FCM despierta la app pero no puede completar auth
3. El flujo depende de que `AuthListener` en Android esté conectado y escuchando

---

## 🎯 Objetivo: Autenticación 100% Push (Estilo Google Prompt)

### Qué queremos lograr
Como lo hace Google cuando te pide verificación en tu teléfono:

1. **PC se bloquea** → aparece tile WindowsGoodBye
2. **Service envía push notification** al teléfono (no wake-up, sino el **challenge completo**)
3. **El teléfono muestra una notificación interactiva** tipo "¿Eres tú? PC-Daniel quiere desbloquearse"
4. **El usuario toca la notificación** → se abre el BiometricPrompt
5. **El teléfono responde** con el HMAC **vía HTTPS** (no necesita BT/USB/WiFi directo)
6. **La PC se desbloquea**

### Ventajas
- ✅ Funciona sin importar la red del teléfono (móvil, WiFi diferente, cualquier lugar)
- ✅ No requiere conexión persistente (BT/USB/WiFi)
- ✅ Experiencia idéntica a Google Prompt / Microsoft Authenticator
- ✅ Los transportes existentes siguen funcionando como alternativa más rápida

---

## 🏗️ Arquitectura Propuesta

```
                    ┌─────────────────┐
                    │  Firebase Cloud  │
                    │   Messaging      │
                    └───────┬─────────┘
                            │
           ┌────────────────┼────────────────┐
           │ Data Push      │                │ HTTPS Response
           │ (challenge)    │                │ (HMAC)
           ▼                │                ▼
┌──────────────────┐        │     ┌──────────────────────┐
│   Windows PC     │        │     │   Android Phone      │
│                  │        │     │                      │
│  CredProvider    │        │     │  FCM → Notificación  │
│      ↓           │        │     │  "¿Eres tú?"        │
│  Service         │────────┘     │      ↓               │
│   ↓              │              │  BiometricPrompt     │
│  FcmPushSender   │              │      ↓               │
│   (envía reto)   │              │  HMAC Response       │
│                  │              │      ↓               │
│  RelayServer ◄───┼──────────────┤  HTTPS POST          │
│   (recibe resp)  │   Internet   │  al Relay Server     │
│      ↓           │              │                      │
│  Desbloquea PC   │              └──────────────────────┘
└──────────────────┘
```

---

## 📦 Componentes a Crear/Modificar

### Fase 1: Canal de Retorno (Response Channel)

> [!IMPORTANT]
> El problema principal es: FCM es **unidireccional** (server→device). Necesitamos un canal de retorno para que Android envíe la respuesta HMAC de vuelta a la PC.

#### Opción A: Relay Server propio (Recomendada)
- Un servidor HTTP/HTTPS ligero (puede ser una Azure Function, Cloudflare Worker, o self-hosted)
- La PC se suscribe para recibir respuestas (WebSocket o long-polling)
- Android envía HMAC vía HTTPS POST al relay
- **Pros**: Control total, sin dependencias de terceros para datos sensibles
- **Contras**: Requiere hosting

#### Opción B: Firebase Realtime Database / Firestore como relay
- Android escribe la respuesta en Firestore
- PC escucha cambios en Firestore
- **Pros**: No necesita server propio, Firebase ya está configurado
- **Contras**: Datos sensibles pasan por Firebase, latencia algo mayor

#### Opción C: FCM Upstream (Deprecado) ❌
- FCM upstream messaging está deprecado por Google — descartada

#### Opción D: Tunnel TCP/WebSocket directo entre PC y Relay
- Similar a Opción A pero usando un servicio como Ably, Pusher, o SignalR
- **Pros**: Real-time, baja latencia
- **Contras**: Dependencia de terceros

### Decisión requerida
> [!WARNING]  
> Se necesita decidir cuál opción de relay usar antes de proceder. **La Opción A (relay propio) es la más segura y da control total.** Se puede implementar como:
> - Azure Function (gratuito hasta ~1M requests/mes)
> - Cloudflare Worker (gratuito hasta 100K requests/día)
> - Self-hosted en la misma PC (si solo se usa en LAN)

---

### Fase 2: Modificaciones en el Servicio de Windows

#### 2.1 Nuevo modo de autenticación: `PushAuth`

**Archivo**: [`AuthWorker.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Service/AuthWorker.cs)

```diff
 // Agregar nuevo modo de autenticación
+private enum AuthMode { Transport, Push, Hybrid }
+private AuthMode _currentMode = AuthMode.Hybrid;

 // En el loop de autenticación, después de detectar PC bloqueada:
+if (_currentMode is AuthMode.Push or AuthMode.Hybrid)
+{
+    await TryPushAuthAsync(device, ct);
+}
```

#### 2.2 Mejorar `FcmPushSender` para enviar challenge completo

**Archivo**: [`FcmPushSender.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Service/FcmPushSender.cs)

Actualmente solo envía un wake-up genérico. Necesita enviar:
- `action`: `"auth_challenge"` (no solo wake-up)
- `nonce`: el challenge aleatorio cifrado
- `pc_name`: nombre de la PC
- `session_id`: ID único de esta sesión de auth
- `relay_url`: URL donde Android debe enviar la respuesta

```diff
-// Solo envía wake-up
-Data = new Dictionary<string, string> { ["action"] = "wakeup" }
+// Envía challenge completo
+Data = new Dictionary<string, string>
+{
+    ["action"] = "auth_challenge",
+    ["session_id"] = sessionId,
+    ["nonce"] = Convert.ToBase64String(encryptedNonce),
+    ["pc_name"] = Environment.MachineName,
+    ["relay_url"] = _relayUrl,
+    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()
+}
```

#### 2.3 Nuevo componente: `RelayClient`

**Archivo nuevo**: `src/WindowsGoodBye.Service/RelayClient.cs`

```csharp
/// <summary>
/// Se conecta al Relay Server vía WebSocket y espera la respuesta 
/// HMAC del dispositivo Android después de enviar un push auth challenge.
/// </summary>
public class RelayClient : IAsyncDisposable
{
    // Flujo:
    // 1. Registra session_id en el relay server
    // 2. Escucha vía WebSocket por la respuesta
    // 3. Cuando Android POST la respuesta, relay la reenvía por WS
    // 4. Verifica HMAC y completa autenticación
    
    Task<AuthResponse?> WaitForResponseAsync(string sessionId, TimeSpan timeout, CancellationToken ct);
}
```

---

### Fase 3: Modificaciones en la App Android

#### 3.1 Mejorar `FcmService` para manejar auth challenges

**Archivo**: [`FcmService.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Mobile/Platforms/Android/FcmService.cs)

Actualmente solo recibe wake-up y arranca `AuthForegroundService`. Necesita:

```diff
 public override void OnMessageReceived(RemoteMessage msg)
 {
     var data = msg.Data;
     var action = data.GetValueOrDefault("action");
     
-    if (action == "wakeup")
-    {
-        // Solo arranca el foreground service
-        StartForegroundServiceCompat();
-    }
+    switch (action)
+    {
+        case "wakeup":
+            StartForegroundServiceCompat();
+            break;
+            
+        case "auth_challenge":
+            // NUEVO: Mostrar notificación interactiva + procesar challenge
+            ShowAuthNotification(data);
+            break;
+    }
 }
+
+private void ShowAuthNotification(IDictionary<string, string> data)
+{
+    // 1. Crear notificación de alta prioridad con:
+    //    - Título: "¿Eres tú?"
+    //    - Texto: "PC-Daniel quiere desbloquearse"
+    //    - Acción: Abrir BiometricPrompt
+    //    - Full-screen intent (aparece incluso con pantalla apagada)
+    
+    // 2. Al tocar → abrir Activity transparente con BiometricPrompt
+    
+    // 3. Tras huella exitosa:
+    //    - Descifrar nonce
+    //    - Calcular HMAC
+    //    - POST al relay_url con session_id + HMAC
+}
```

#### 3.2 Nueva Activity: `PushAuthActivity`

**Archivo nuevo**: `Platforms/Android/PushAuthActivity.cs`

```csharp
/// <summary>
/// Activity transparente que se lanza desde la notificación push.
/// Muestra BiometricPrompt y envía respuesta al relay.
/// Similar a como Google muestra el prompt de verificación.
/// </summary>
[Activity(Theme = "@style/TransparentActivity", LaunchMode = LaunchMode.SingleTask)]
public class PushAuthActivity : Activity
{
    // 1. Recibe datos del challenge via Intent extras
    // 2. Muestra BiometricPrompt
    // 3. En OnAuthenticationSucceeded:
    //    a. Descifra nonce con clave del dispositivo pareado
    //    b. Calcula HMAC-SHA256
    //    c. Envía POST HTTPS al relay_url
    // 4. Muestra feedback visual (✓ o ✗) y cierra
}
```

#### 3.3 Mejorar notificación para que aparezca como Google Prompt

```csharp
// Crear canal de notificación de alta importancia
var channel = new NotificationChannel(
    "push_auth", 
    "Authentication Requests",
    NotificationImportance.High  // Heads-up notification
);

// Notificación con full-screen intent (aparece sobre lock screen)
var notification = new NotificationCompat.Builder(this, "push_auth")
    .SetSmallIcon(Resource.Drawable.ic_fingerprint)
    .SetContentTitle("¿Eres tú?")
    .SetContentText($"{pcName} quiere desbloquearse")
    .SetPriority(NotificationCompat.PriorityHigh)
    .SetCategory(NotificationCompat.CategoryCall)  // Alta prioridad
    .SetFullScreenIntent(pendingIntent, true)       // Sobre lock screen
    .SetAutoCancel(true)
    .SetTimeoutAfter(60_000)  // 60 segundos timeout
    .Build();
```

---

### Fase 4: Relay Server

#### Opción recomendada: Azure Function (C#)

**Estructura mínima:**

```
relay-server/
├── AuthRelay/
│   ├── RegisterSession.cs    // PC registra session_id
│   ├── SubmitResponse.cs     // Android envía HMAC response
│   └── WaitResponse.cs       // PC espera respuesta (long-poll / WS)
```

**Flujo:**
```
1. PC → POST /api/register    { session_id, pc_id }
2. PC → GET  /api/wait/{id}   (long-poll, timeout 60s)
3. Android → POST /api/respond { session_id, hmac, device_id }
4. Relay notifica a PC vía la conexión long-poll
5. PC recibe HMAC → verifica → desbloquea
```

**Seguridad del relay:**
- Session IDs son UUIDs efímeros (expiran en 60s)
- El relay NO conoce las claves ni puede descifrar nada
- Todo el payload viaja cifrado AES-256 extremo a extremo
- El relay solo es un buzón temporal
- Rate limiting por IP/device

---

### Fase 5: Cambios en Protocolo Core

**Archivo**: [`Protocol.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Core/Protocol.cs)

```diff
 // Nuevas constantes de protocolo
+public const string PushAuthChallenge = "push_auth_req";
+public const string PushAuthResponse  = "push_auth_resp";
+public const int    PushAuthTimeoutSec = 60;
```

**Archivo**: [`Models.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Core/Models.cs)

```diff
 // En DeviceInfo, agregar FCM token
+[Column("fcm_token")]
+public string? FcmToken { get; set; }
+
+[Column("push_auth_enabled")]
+public bool PushAuthEnabled { get; set; }
```

---

### Fase 6: Almacenamiento del FCM Token

#### En el pareado (QR):
Actualmente el QR intercambia claves crypto. Necesita también intercambiar:
- FCM token del dispositivo Android
- Preferencia de push auth habilitado/deshabilitado

#### Actualización periódica del token:
- FCM tokens se rotan periódicamente
- Android debe notificar a la PC cuando cambia (`OnNewToken` en `FcmService`)
- Se puede enviar por los transportes existentes (BT/USB/WiFi) o vía un endpoint del relay

---

## 🗓️ Fases de Implementación

| Fase | Componente | Esfuerzo | Descripción |
|------|-----------|----------|-------------|
| **1** | Protocol + Models | 🟢 Bajo | Agregar constantes y campos para push auth |
| **2** | Relay Server | 🟡 Medio | Azure Function con register/respond/wait |
| **3** | Service - FcmPushSender | 🟢 Bajo | Enviar challenge completo en push |
| **4** | Service - RelayClient | 🟡 Medio | WebSocket/long-poll para recibir respuesta |
| **5** | Service - AuthWorker | 🟡 Medio | Integrar modo PushAuth en flujo existente |
| **6** | Android - FcmService | 🟡 Medio | Procesar auth_challenge, mostrar notificación |
| **7** | Android - PushAuthActivity | 🟡 Medio | Activity con BiometricPrompt + HTTP response |
| **8** | Android - Token sync | 🟢 Bajo | Sincronizar FCM token durante/después del pareado |
| **9** | TrayApp - Config UI | 🟢 Bajo | Toggle para habilitar push auth |
| **10** | Testing & Polish | 🔴 Alto | Tests E2E, manejo de errores, timeouts |

---

## ⚠️ Decisiones Pendientes

### 1. Relay Server — ¿Dónde hospearlo?
| Opción | Costo | Complejidad | Latencia |
|--------|-------|-------------|----------|
| Azure Function | Gratis (tier free) | Baja | ~200ms |
| Cloudflare Worker | Gratis (100K/día) | Baja | ~100ms |
| Self-hosted en PC | Gratis | Media (necesita DDNS/port forward) | Variable |
| Firebase Firestore | Gratis (tier free) | Baja | ~300ms |

### 2. ¿Mantener transportes existentes como fallback?
- **Recomendación**: Sí → modo **Hybrid** (intenta push primero, fallback a BT/USB/WiFi)
- Esto da la mejor experiencia: push cuando estás fuera, transporte directo cuando estás cerca

### 3. ¿Timeout del challenge?
- **Recomendación**: 60 segundos (igual que Google Prompt)
- Si no responde en 60s, el challenge expira y el Credential Provider muestra error

### 4. ¿Seguridad del relay?
- El nonce y HMAC ya van cifrados AES-256 extremo a extremo
- El relay solo ve blobs opacos — nunca puede descifrar
- Session IDs efímeros eliminan replay attacks
- ¿Se necesita autenticación adicional al relay? (API key, JWT del dispositivo)

### 5. ¿Notificación o Activity directa?
- **Google-style**: Notificación heads-up con full-screen intent → al tocar, BiometricPrompt
- **Microsoft Authenticator style**: Notificación que abre la app con prompt de aprobación
- **Recomendación**: Full-screen intent (se muestra sobre lock screen automáticamente)

---

## 🔐 Flujo de Seguridad Detallado (Push Auth)

```
PC (Service)                          Relay                           Android
    │                                   │                                │
    ├── 1. Genera nonce aleatorio       │                                │
    ├── 2. Cifra nonce con AES-256     │                                │
    │       (clave del dispositivo)      │                                │
    ├── 3. Genera session_id (UUID)     │                                │
    │                                   │                                │
    ├── POST /register {session_id} ───►│                                │
    │                                   │                                │
    ├── FCM push ──────────────────────────────────────────────────────►│
    │   {action: auth_challenge,        │                                │
    │    session_id, nonce(cifrado),     │                                │
    │    pc_name, relay_url}            │                                │
    │                                   │                                │
    ├── GET /wait/{session_id} ────────►│ (long-poll, espera 60s)       │
    │                                   │                                │
    │                                   │        Notificación: "¿Eres tú?" 
    │                                   │        Usuario toca notificación │
    │                                   │        BiometricPrompt ──► ✓   │
    │                                   │                                │
    │                                   │        Descifra nonce (AES)    │
    │                                   │        Calcula HMAC-SHA256     │
    │                                   │                                │
    │                                   │◄── POST /respond ─────────────┤
    │                                   │   {session_id, hmac, device_id}│
    │                                   │                                │
    │◄── Response {hmac, device_id} ────┤                                │
    │                                   │                                │
    ├── 4. Verifica HMAC                │                                │
    ├── 5. Si válido → envía creds      │                                │
    │       al Credential Provider      │                                │
    ├── 6. PC se desbloquea ✓           │                                │
```

---

## 📝 Issues Existentes Detectados (Bonus)

Durante la investigación del código actual, se detectaron estos issues:

1. **`AdminPipeServer.cs`**: El `PipeSecurity` usa `Everyone` con `FullControl` — riesgo de seguridad, debería usar ACLs más restrictivos
2. **`AuthWorker.cs`**: El loop de retry de push usa `Thread.Sleep` en lugar de `await Task.Delay` — bloquea el thread
3. **`FcmPushSender.cs`**: El service account JSON está hardcodeado como ruta relativa — debería ser configurable
4. **`BluetoothServer.cs`**: No tiene timeout en `AcceptBluetoothClient` — puede bloquear indefinidamente
5. **`FcmService.cs` (Android)**: Solo arranca el foreground service al recibir push, no procesa el mensaje
6. **Token FCM**: No hay mecanismo para sincronizar el token FCM actualizado desde Android a PC
7. **`UdpManager.cs`**: El multicast join puede fallar silenciosamente en interfaces sin multicast

---

> [!TIP]
> **Siguiente paso**: Revisar este plan y tomar las decisiones pendientes (especialmente el Relay Server) antes de comenzar a implementar.
