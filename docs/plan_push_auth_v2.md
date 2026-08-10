# 📋 Plan v2: Push Auth Estilo Google Prompt — WindowsGoodBye

> **Estado**: Revisado con todas las fisuras corregidas  
> **Versión**: 2.0 — Post-revisión arquitectónica

---

## Decisiones Arquitectónicas Tomadas

| # | Decisión | Resolución |
|---|----------|------------|
| 1 | **Relay Server** | Self-hosted embebido en el Service + Cloudflare Tunnel para internet |
| 2 | **Cifrado del nonce** | AES-256-**GCM** con `DeviceKey` + `session_id` como AAD |
| 3 | **Dueño del RelayClient** | El Service (.NET) — el CredentialProvider no cambia |
| 4 | **Auth de la PC al relay** | JWT ligero firmado con `DeviceKey` + binding por `device_id` |
| 5 | **Comportamiento offline** | Detección automática por estado del túnel + carrera paralela |

---

## 🏗️ Arquitectura Final

```
┌──────────────────────────────────────────────────────────────┐
│                     Windows PC                               │
│                                                              │
│  ┌──────────────┐    Named Pipe    ┌──────────────────────┐  │
│  │  Credential  │◄───────────────►│   Windows Service     │  │
│  │  Provider    │  (sin cambios)   │   (.NET 9 Worker)    │  │
│  │  (C++ COM)   │                  │                      │  │
│  └──────────────┘                  │  ┌────────────────┐  │  │
│                                    │  │  AuthWorker     │  │  │
│                                    │  │  (orquestador)  │  │  │
│                                    │  └───────┬────────┘  │  │
│                                    │          │           │  │
│                    ┌───────────────┼──────────┼───────────┤  │
│                    │               │          │           │  │
│              ┌─────▼─────┐  ┌─────▼────┐ ┌───▼────────┐ │  │
│              │ BT/TCP/UDP│  │ FCM Push  │ │ Relay HTTP │ │  │
│              │ Transports│  │  Sender   │ │  Server    │ │  │
│              │ (actuales)│  │ (mejorado)│ │  (NUEVO)   │ │  │
│              └─────┬─────┘  └─────┬────┘ └───┬────────┘ │  │
│                    │              │           │          │  │
└────────────────────┼──────────────┼───────────┼──────────┘  │
                     │              │           │             │
              BT/USB/WiFi      FCM (Google)    │             │
              (red local)      (unidireccional)│             │
                     │              │           │             │
                     │              │    ┌──────▼──────────┐  │
                     │              │    │ Cloudflare      │  │
                     │              │    │ Tunnel          │  │
                     │              │    │ (cloudflared)   │  │
                     │              │    └──────┬──────────┘  │
                     │              │           │
                     │              │       Internet
                     │              │           │
                     ▼              ▼           ▼
              ┌─────────────────────────────────────────────┐
              │              Android Phone                  │
              │                                             │
              │  ┌───────────┐  ┌──────────┐  ┌──────────┐ │
              │  │ AuthListen│  │ FcmServ  │  │ PushAuth │ │
              │  │ er (BT/   │  │ ice      │  │ Activity │ │
              │  │ TCP/UDP)  │  │ (recv)   │  │ (NUEVO)  │ │
              │  └─────┬─────┘  └────┬─────┘  └────┬─────┘ │
              │        │             │              │       │
              │        │         ┌───▼──────────────▼───┐   │
              │        │         │   BiometricPrompt    │   │
              │        │         └───────────┬──────────┘   │
              │        │                     │              │
              │        │              HTTPS POST            │
              │        │           al Relay (vía Tunnel)    │
              └────────┼─────────────────────┼──────────────┘
                       │                     │
                  Transporte directo    Canal de retorno
                  (más rápido ~50ms)    push (más lento ~300ms)
```

### ¿Por qué Self-hosted + Cloudflare Tunnel?

| Aspecto | Beneficio |
|---------|-----------|
| **Sin DDNS ni port-forwarding** | `cloudflared` crea un túnel inverso — funciona detrás de NAT, firewalls |
| **Sin cold-starts** | El HTTP server es local al Service, siempre caliente |
| **Control total de datos** | Los blobs cifrados nunca salen de tu infraestructura (pasan por Cloudflare pero son opacos) |
| **Sin vendor lock-in en lógica** | El relay es un ASP.NET Kestrel embebido. Cloudflare es solo el túnel, reemplazable por ngrok, bore, etc. |
| **Sin costo** | Cloudflare Tunnel es gratuito |
| **Oráculo de disponibilidad** | Estado del túnel = "¿tengo internet para push?" — detección instantánea |

---

## 🔄 Algoritmo de Decisión del Modo Hybrid

> [!IMPORTANT]
> Resuelve la **Fisura #1** (SPOF del relay) y la **Decisión #5** (offline).

```
                    ┌────────────────────────┐
                    │  PipeServer recibe      │
                    │  WAITING del CP         │
                    └───────────┬────────────┘
                                │
                    ┌───────────▼────────────┐
                    │  AuthWorker.RunAuth()   │
                    │  Inicia CARRERA         │
                    │  PARALELA               │
                    └───────────┬────────────┘
                                │
                 ┌──────────────┼──────────────┐
                 │              │              │
          ┌──────▼──────┐ ┌────▼────┐  ┌──────▼──────┐
          │ RUTA A:     │ │ RUTA B: │  │ RUTA C:     │
          │ Transportes │ │ Push    │  │ Push Auth   │
          │ Directos    │ │ FCM     │  │ (challenge  │
          │ (BT/TCP/UDP)│ │ Wake-up │  │ completo)   │
          │             │ │(legacy) │  │             │
          │ auth_discov │ │         │  │ Solo si:    │
          │ → auth_alive│ │         │  │ tunnel.IsUp │
          │ → auth_req  │ │         │  │             │
          │ → biometric │ │         │  │ FCM + relay │
          │ → auth_resp │ │         │  │ roundtrip   │
          └──────┬──────┘ └────┬────┘  └──────┬──────┘
                 │             │              │
                 └─────────────┼──────────────┘
                               │
                    ┌──────────▼───────────┐
                    │  Task.WhenAny(       │
                    │    rutas[]            │
                    │  )                    │
                    │                       │
                    │  PRIMERO QUE          │
                    │  RESPONDE →           │
                    │  cancela los demás    │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │  Verifica HMAC       │
                    │  (mismo flujo actual) │
                    │                       │
                    │  → AuthEvent.Set()   │
                    │  → PC se desbloquea   │
                    └──────────────────────┘
```

### Reglas del algoritmo:

```
1. SIEMPRE lanzar Ruta A (transportes directos) — es la más rápida (~50ms)
2. SI tunnel.IsConnected:
     → TAMBIÉN lanzar Ruta C (push auth challenge completo vía relay)
3. SI tunnel.IsConnected Y NO hay transporte directo activo:
     → TAMBIÉN lanzar Ruta B (FCM wake-up para despertar AuthListener)
4. Task.WhenAny() — el primero en completar auth gana
5. CancellationToken cancela las demás rutas
6. TIMEOUT GLOBAL: 60 segundos (configurable)
7. SI timeout → CredentialProvider muestra "Tiempo agotado" + botón "Reintentar"
```

### Tiempos esperados por ruta:

| Ruta | Escenario | Latencia esperada |
|------|-----------|-------------------|
| A (USB directo) | Cable conectado | ~50-100ms |
| A (Bluetooth) | BT pareado y conectado | ~200-500ms |
| A (WiFi/UDP) | Misma red | ~100-300ms |
| B (FCM wake + transporte) | App dormida, misma red | ~2-5s |
| C (Push auth completo) | Redes diferentes | ~1-3s |
| C (Push auth, teléfono dormido) | Doze mode | ~5-15s |

---

## 🔐 Protocolo de Seguridad Revisado

> [!IMPORTANT]
> Resuelve las **Fisuras #3** (replay-delay), **#5** (token rotation), **#6** (nomenclatura), **#7** (device_id binding).

### Cifrado: Migración a AES-256-GCM

**Problema actual**: `CryptoUtils.cs` usa AES-256-**CBC** con **IV estático hardcodeado** — esto es una vulnerabilidad criptográfica grave.

**Solución**: Migrar a AES-256-**GCM** con:
- **IV aleatorio por operación** (12 bytes, generado con `RandomNumberGenerator`)
- **AAD** (Additional Authenticated Data) = `session_id` — binding criptográfico de sesión
- **Auth Tag** (16 bytes) — integridad verificada por GCM automáticamente

```diff
// CryptoUtils.cs — ANTES
-private static readonly byte[] FixedIV = { 0x43, 0x79, ... }; // ❌ IV estático
-Aes.Create() → CBC mode, PaddingMode.PKCS7

// CryptoUtils.cs — DESPUÉS
+public static (byte[] ciphertext, byte[] nonce, byte[] tag) EncryptGcm(
+    byte[] plaintext, byte[] key, byte[]? aad = null)
+{
+    var nonce = new byte[12]; // 96-bit nonce, generado aleatoriamente
+    RandomNumberGenerator.Fill(nonce);
+    var tag = new byte[16];   // 128-bit auth tag
+    var ciphertext = new byte[plaintext.Length];
+    
+    using var aes = new AesGcm(key, tagSizeInBytes: 16);
+    aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
+    return (ciphertext, nonce, tag);
+}
+
+public static byte[] DecryptGcm(
+    byte[] ciphertext, byte[] key, byte[] nonce, byte[] tag, byte[]? aad = null)
+{
+    var plaintext = new byte[ciphertext.Length];
+    using var aes = new AesGcm(key, tagSizeInBytes: 16);
+    aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);
+    return plaintext;
+}
```

> [!WARNING]
> **Decisión de compatibilidad**: La migración de CBC→GCM rompe compatibilidad con dispositivos ya pareados. Opciones:
> 1. Forzar re-pairing (más limpio, recomendado si hay pocos usuarios)
> 2. Soportar ambos modos y migrar automáticamente en la siguiente auth exitosa

### Anti-Replay-Delay: Timestamp Firmado

**Problema (Fisura #3)**: Un relay malicioso puede retener la respuesta HMAC y reenviarla después.

**Solución**: El HMAC incluye un timestamp que la PC verifica:

```
// Lo que firma Android:
HMAC_payload = nonce ‖ challenge_timestamp ‖ response_timestamp ‖ session_id
HMAC = HMAC-SHA256(HMAC_payload, AuthKey)

// Lo que verifica la PC:
1. Verifica HMAC correcta ✓
2. Verifica: response_timestamp - challenge_timestamp < 60 segundos ✓
3. Verifica: now() - response_timestamp < 10 segundos ✓  ← anti-delay
4. Verifica: session_id coincide con el registrado ✓
```

Esto da una **ventana de validez de 10 segundos** para la respuesta después de que Android la genera. Un relay malicioso que retenga la respuesta por más de 10 segundos la invalida.

### Binding de Session-Device en el Relay

**Problema (Fisura #7)**: Cualquiera con el `session_id` podría intentar responder.

**Solución**:

```
// PC registra sesión con device_id esperado:
POST /register {
    session_id: "uuid-xxx",
    expected_device_id: "device-yyy",  // ← NUEVO
    jwt: "<firmado con DeviceKey>"
}

// Android responde:
POST /respond {
    session_id: "uuid-xxx",
    device_id: "device-yyy",
    hmac: "...",
    response_timestamp: 1723234567
}

// Relay valida ANTES de reenviar:
if (request.device_id != session.expected_device_id) → 403 Forbidden
```

### JWT para Autenticación al Relay

```json
// Header
{ "alg": "HS256", "typ": "JWT" }

// Payload — generado por PC o Android
{
  "sub": "<device_id>",        // Quién soy
  "sid": "<session_id>",       // Para qué sesión
  "iat": 1723234500,           // Timestamp
  "exp": 1723234560            // Expira en 60s
}

// Signature
HMACSHA256(header + "." + payload, DeviceKey)
```

El relay valida la firma usando el `DeviceKey` del dispositivo registrado. Esto previene:
- DoS por registros falsos (sin key válida = 401)
- Impersonación de dispositivos
- Reutilización de JWTs viejos (exp = 60s)

> [!NOTE]
> El relay necesita conocer los `DeviceKey` de dispositivos autorizados. Opciones:
> 1. **Pre-registrar durante pairing**: El Service almacena un hash del key en el relay
> 2. **Derivar una relay-specific key**: `RelayKey = HKDF(DeviceKey, "relay-auth")` — el relay solo conoce la derivada, no la key original
> 
> **Recomendación**: Opción 2 — así si el relay es comprometido, la `DeviceKey` original no se expone.

---

## 📱 UX en Android Moderno (Fisura #4 Resuelta)

### El flujo real con teléfono bloqueado:

```
1. FCM push llega
2. Android muestra Heads-up Notification (sobre lock screen)
   ┌─────────────────────────────────────┐
   │ 🔐 ¿Eres tú?                       │
   │ PC-Daniel quiere desbloquearse      │
   │                                     │
   │ [Tap para verificar]                │
   └─────────────────────────────────────┘
3. Usuario toca la notificación
4. Android pide desbloquear el teléfono primero (PIN/Pattern/Face)
   → Esto es inevitable y es lo mismo que hace Google Prompt
5. PushAuthActivity se abre (transparente)
6. BiometricPrompt aparece: "Verificar huella para WindowsGoodBye"
7. Usuario toca sensor → respuesta HMAC → PC se desbloquea
```

### Permisos Android 13+:

| Permiso | Necesario | Notas |
|---------|-----------|-------|
| `POST_NOTIFICATIONS` | Sí (runtime, API 33+) | Pedirlo en primer uso |
| `USE_FULL_SCREEN_INTENT` | **No** — evitado | Usamos notificación Heads-up con alta prioridad, no full-screen intent |
| `FOREGROUND_SERVICE_CONNECTED_DEVICE` | Sí (ya existe) | Para el AuthForegroundService |

> [!TIP]
> **Decisión UX**: No usar `setFullScreenIntent()`. En su lugar, usamos:
> - `NotificationCompat.PriorityHigh` + canal `IMPORTANCE_HIGH` = **Heads-up notification**
> - Funciona en Android 13-15 sin permisos especiales
> - Es exactamente lo que hace Google para "¿Eres tú?" — una notificación, no una pantalla completa
> - El usuario **siempre** tiene que desbloquear el teléfono primero — documentarlo en la UI

### Pantalla de la PushAuthActivity:

```
┌─────────────────────────────────┐
│                                 │
│         🖥️ PC-Daniel            │
│    quiere desbloquearse         │
│                                 │
│    ┌─────────────────────┐      │
│    │   👆                │      │
│    │   Toca el sensor    │      │
│    │   de huella         │      │
│    └─────────────────────┘      │
│                                 │
│    ⏱️ 45 segundos restantes     │
│                                 │
│         [Cancelar]              │
│                                 │
└─────────────────────────────────┘
```

---

## 📡 FCM: Manejo de Fallos (Fisura #2 Resuelta)

### Qué puede fallar y qué hacemos:

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Árbol de Fallos de FCM                         │
├─────────────────────────┬───────────────────────────────────────────┤
│ Fallo                   │ Manejo                                   │
├─────────────────────────┼───────────────────────────────────────────┤
│ FCM throttle (Doze)     │ La carrera paralela usa transportes      │
│                         │ directos como fallback automático         │
├─────────────────────────┼───────────────────────────────────────────┤
│ Token inválido (rotado) │ FcmPushSender detecta error 404 de FCM  │
│                         │ → marca device.PushAuthEnabled = false   │
│                         │ → solo usa transportes directos          │
│                         │ → próxima conexión directa sincroniza    │
│                         │   token nuevo                            │
├─────────────────────────┼───────────────────────────────────────────┤
│ Teléfono offline        │ Carrera paralela: si ninguna ruta        │
│                         │ responde en 60s → timeout con UI         │
├─────────────────────────┼───────────────────────────────────────────┤
│ Fabricante bloquea FCM  │ Transportes directos funcionan normal.   │
│ (Xiaomi, Huawei)        │ Push auth se degrada silenciosamente.    │
│                         │ UI: "Push no disponible, usa BT/USB"     │
├─────────────────────────┼───────────────────────────────────────────┤
│ Push llega pero usuario │ Timeout de 60s en el relay. Session      │
│ no responde             │ expira. CP muestra "Tiempo agotado"      │
│                         │ + botón "Reintentar"                     │
└─────────────────────────┴───────────────────────────────────────────┘
```

### UI del Credential Provider durante espera:

```
Estado 1 (inicial):          Estado 2 (buscando):        Estado 3 (timeout):
┌──────────────────┐         ┌──────────────────┐        ┌──────────────────┐
│ WindowsGoodBye   │         │ WindowsGoodBye   │        │ WindowsGoodBye   │
│                  │         │                  │        │                  │
│ Seleccione para  │         │ ⏳ Esperando     │        │ ❌ Tiempo agotado│
│ desbloquear      │         │ confirmación     │        │                  │
│                  │         │ en tu teléfono...│        │ [Reintentar]     │
│                  │         │                  │        │                  │
│                  │         │ 📱 Push enviado  │        │ O usa tu         │
│                  │         │ a Galaxy S24     │        │ contraseña       │
└──────────────────┘         └──────────────────┘        └──────────────────┘
```

> [!NOTE]
> Los estados se comunican vía Named Pipe. El Service envía mensajes de progreso al CP:
> - `STATUS:searching` → "Buscando dispositivo..."
> - `STATUS:push_sent:Galaxy S24` → "Esperando confirmación en Galaxy S24..."
> - `STATUS:timeout` → "Tiempo agotado"
> - `AUTH_READY\n...` → Desbloqueo (como hoy)

---

## 🔄 Rotación de FCM Token (Fisura #5 Resuelta)

### Flujo de sincronización de token:

```
Android: OnNewToken(newToken)
    │
    ├── 1. Guardar en MobileDatabase (local)
    │
    ├── 2. Si hay transporte directo activo (BT/TCP/UDP):
    │      → Enviar: "wingb://token_update?device_id=X&token=<newToken>"
    │      → (cifrado AES-GCM con DeviceKey)
    │
    └── 3. Si NO hay transporte directo:
           → POST al Relay: /api/device/{device_id}/fcm-token
           → Body: { token: "<newToken>", jwt: "<firmado>" }
           → El Service en la PC escucha cambios del relay
           → Actualiza DeviceInfo.FcmToken en AppDatabase
```

### Manejo del gap de sincronización:

```
Escenario: Token rotó, Android desconectado, PC intenta push con token viejo

1. FcmPushSender envía push al token viejo
2. FCM responde: "registration-token-not-registered" (HTTP 404)
3. Service detecta el error:
   a. Marca device.FcmTokenValid = false
   b. NO intenta más pushes hasta que el token se sincronice
   c. Continúa con transportes directos normalmente
4. Próxima conexión directa (BT/USB/WiFi):
   a. Android envía automáticamente token_update
   b. Service actualiza FcmToken y marca FcmTokenValid = true
```

---

## 🖥️ Múltiples PCs Emparejadas (Propuesta A Resuelta)

### Escenario: 2 PCs bloqueadas envían push simultáneamente

```
Android recibe 2 FCM data messages:
  push_1: { session_id: "aaa", pc_name: "PC-Oficina", nonce: "..." }
  push_2: { session_id: "bbb", pc_name: "PC-Casa",    nonce: "..." }

Comportamiento:
1. FcmService muestra 2 notificaciones separadas (NotificationId basado en session_id)
   ┌──────────────────────────────┐
   │ 🔐 PC-Oficina               │  ← Notificación 1
   │ Quiere desbloquearse        │
   └──────────────────────────────┘
   ┌──────────────────────────────┐
   │ 🔐 PC-Casa                  │  ← Notificación 2
   │ Quiere desbloquearse        │
   └──────────────────────────────┘

2. Usuario toca una → PushAuthActivity recibe los datos de ESA sesión
3. BiometricPrompt muestra el nombre de la PC específica
4. Responde solo a esa sesión → solo esa PC se desbloquea
5. La otra notificación expira en 60s o el usuario la toca separadamente
```

### En el relay:
- Cada `session_id` es independiente
- El relay no necesita lógica especial — solo son 2 sesiones separadas
- El `expected_device_id` es el mismo para ambas (mismo teléfono)

---

## 🛠️ Relay HTTP Server Embebido — Diseño

### Endpoints:

```
POST   /api/auth/register      ← PC registra sesión (JWT requerido)
GET    /api/auth/wait/{sid}     ← PC long-poll esperando respuesta (JWT requerido)
POST   /api/auth/respond        ← Android envía HMAC (JWT requerido)
POST   /api/device/token        ← Android actualiza FCM token (JWT requerido)
GET    /api/health              ← Health check para Cloudflare Tunnel
```

### Implementación:

```csharp
// RelayServer.cs — embebido en el Service
public class RelayServer : IAsyncDisposable
{
    private WebApplication? _app;
    private readonly ConcurrentDictionary<string, PendingSession> _sessions = new();
    
    public async Task StartAsync(int port = 26821)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseUrls($"http://localhost:{port}");
        
        _app = builder.Build();
        
        // Middleware: JWT validation en todos los endpoints excepto /health
        _app.Use(async (ctx, next) => { /* validar JWT */ });
        
        _app.MapPost("/api/auth/register", RegisterSession);
        _app.MapGet("/api/auth/wait/{sessionId}", WaitForResponse);
        _app.MapPost("/api/auth/respond", SubmitResponse);
        _app.MapPost("/api/device/token", UpdateFcmToken);
        _app.MapGet("/api/health", () => Results.Ok("ok"));
        
        await _app.StartAsync();
    }
}

public class PendingSession
{
    public string SessionId { get; init; }
    public string ExpectedDeviceId { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset ExpiresAt { get; init; } // CreatedAt + 60s
    public TaskCompletionSource<AuthRelayResponse> ResponseTcs { get; } = new();
}
```

### Long-poll `/wait/{sid}`:

```csharp
async Task<IResult> WaitForResponse(string sessionId, CancellationToken ct)
{
    if (!_sessions.TryGetValue(sessionId, out var session))
        return Results.NotFound();
    
    if (session.ExpiresAt < DateTimeOffset.UtcNow)
    {
        _sessions.TryRemove(sessionId, out _);
        return Results.Json(new { status = "expired" }, statusCode: 408);
    }
    
    using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
    timeoutCts.CancelAfter(session.ExpiresAt - DateTimeOffset.UtcNow);
    
    try
    {
        var response = await session.ResponseTcs.Task.WaitAsync(timeoutCts.Token);
        _sessions.TryRemove(sessionId, out _);
        return Results.Ok(response);
    }
    catch (OperationCanceledException)
    {
        _sessions.TryRemove(sessionId, out _);
        return Results.Json(new { status = "timeout" }, statusCode: 408);
    }
}
```

### Cloudflare Tunnel:

```powershell
# Instalación (una vez, en el setup)
# cloudflared se distribuye como binario standalone
cloudflared.exe tunnel --url http://localhost:26821 --no-autoupdate

# Output:
# Your quick Tunnel has been created! 
# https://random-name.trycloudflare.com
```

> [!NOTE]
> Opciones de túnel:
> 1. **Quick Tunnel** (sin cuenta CF): URL aleatoria cambia cada reinicio — Android debe actualizarla
> 2. **Named Tunnel** (con cuenta CF gratuita): URL fija tipo `wingb-xxx.cfargotunnel.com` — estable
> 
> **Recomendación**: Named Tunnel para estabilidad. La URL se comparte durante el pairing (se incluye en el QR).

---

## 📨 Flujo Completo de Seguridad (Versión Final)

```
PC (Service)                    Relay (local+Tunnel)              Android
    │                                   │                            │
    ├─ 1. nonce = RandomBytes(32)       │                            │
    ├─ 2. challenge_ts = now()          │                            │
    ├─ 3. session_id = NewGuid()        │                            │
    ├─ 4. (ct, iv, tag) = AES-256-GCM( │                            │
    │      plaintext: nonce,            │                            │
    │      key: DeviceKey,              │                            │
    │      aad: session_id.ToBytes())   │                            │
    │                                   │                            │
    ├─ 5. jwt_pc = JWT(sub=pc_id,       │                            │
    │      sid=session_id,              │                            │
    │      key=RelayKey)                │                            │
    │                                   │                            │
    ├── POST /register ───────────────►│                            │
    │   { session_id, expected_device,  │                            │
    │     jwt: jwt_pc }                 │                            │
    │                                   │                            │
    ├── FCM data push ─────────────────────────────────────────────►│
    │   { action: "auth_challenge",     │                            │
    │     session_id,                   │                            │
    │     encrypted_nonce: base64(iv+ct+tag),                       │
    │     challenge_ts,                 │                            │
    │     pc_name: "PC-Daniel",         │                            │
    │     relay_url: "https://wingb.cf.com" }                       │
    │                                   │                            │
    ├── GET /wait/{session_id} ────────►│ (long-poll, 60s max)      │
    │   { jwt: jwt_pc }                 │                            │
    │                                   │                            │
    │                                   │   6. Notificación: "¿Eres tú?"
    │                                   │   7. Usuario toca → desbloquea tel.
    │                                   │   8. PushAuthActivity abre
    │                                   │   9. BiometricPrompt → huella ✓
    │                                   │                            │
    │                                   │  10. Descifra nonce:       │
    │                                   │      AES-GCM-Decrypt(      │
    │                                   │        ct, DeviceKey,      │
    │                                   │        iv, tag,            │
    │                                   │        aad=session_id)     │
    │                                   │                            │
    │                                   │  11. response_ts = now()   │
    │                                   │  12. hmac_payload =        │
    │                                   │       nonce ‖              │
    │                                   │       challenge_ts ‖       │
    │                                   │       response_ts ‖        │
    │                                   │       session_id           │
    │                                   │  13. hmac = HMAC-SHA256(   │
    │                                   │       hmac_payload, AuthKey)│
    │                                   │                            │
    │                                   │  14. jwt_android = JWT(    │
    │                                   │       sub=device_id,       │
    │                                   │       sid=session_id,      │
    │                                   │       key=RelayKey)        │
    │                                   │                            │
    │                                   │◄── POST /respond ─────────┤
    │                                   │  { session_id, device_id,  │
    │                                   │    hmac, response_ts,      │
    │                                   │    jwt: jwt_android }      │
    │                                   │                            │
    │                                   │  15. Relay valida:         │
    │                                   │      device_id == expected ✓│
    │                                   │      JWT válido ✓          │
    │                                   │      session no expirada ✓ │
    │                                   │                            │
    │◄── Long-poll response ────────────┤                            │
    │  { hmac, device_id, response_ts } │                            │
    │                                   │                            │
    ├─ 16. Verifica response_ts:        │                            │
    │       response_ts - challenge_ts  │                            │
    │       < 60s ✓                     │                            │
    │       now() - response_ts < 10s ✓ │                            │
    │                                   │                            │
    ├─ 17. Reconstruye hmac_payload     │                            │
    │       y verifica HMAC con         │                            │
    │       FixedTimeEquals() ✓         │                            │
    │                                   │                            │
    ├─ 18. Descifra password (DPAPI)    │                            │
    ├─ 19. AuthEvent.Set()              │                            │
    ├─ 20. Pipe → CP: AUTH_READY        │                            │
    ├─ 21. PC se desbloquea ✓           │                            │
```

---

## 🔧 Cambios por Archivo — Detalle de Implementación

### Fase 0: Correcciones de seguridad base (Prerequisito)

| Archivo | Cambio | Prioridad |
|---------|--------|-----------|
| [`CryptoUtils.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Core/CryptoUtils.cs) | Migrar de AES-CBC con IV estático a AES-256-GCM con IV aleatorio + AAD | 🔴 Crítica |
| [`CryptoUtils.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Core/CryptoUtils.cs) | Mantener métodos CBC legacy con `[Obsolete]` para migración | 🟡 Media |
| [`FcmPushSender.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Service/FcmPushSender.cs) | Migrar de FCM Legacy HTTP API (deprecada) a HTTP v1 + OAuth2 | 🔴 Crítica |

### Fase 1: Protocolo y Modelos

| Archivo | Cambio |
|---------|--------|
| [`Protocol.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Core/Protocol.cs) | Agregar constantes: `PushAuthChallenge`, `PushAuthResponse`, `TokenUpdate`, `RelayPort = 26821` |
| [`Models.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Core/Models.cs) | Agregar a `DeviceInfo`: `FcmTokenValid`, `PushAuthEnabled`, `RelayUrl` |
| [`Models.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Core/Models.cs) | Nuevo modelo: `PushAuthSession` (session_id, nonce, timestamps, device_id) |
| [`AppDatabase.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Core/AppDatabase.cs) | Migración para nuevas columnas |
| **Nuevo** `JwtHelper.cs` | Generación y validación de JWT ligeros con HMAC-SHA256 |
| **Nuevo** `RelayKeyDerivation.cs` | `HKDF(DeviceKey, "relay-auth")` para derivar RelayKey |

### Fase 2: Relay Server Embebido

| Archivo | Cambio |
|---------|--------|
| **Nuevo** `RelayServer.cs` | ASP.NET Minimal API: `/register`, `/wait`, `/respond`, `/device/token`, `/health` |
| **Nuevo** `RelayModels.cs` | DTOs: `RegisterRequest`, `RespondRequest`, `WaitResponse`, `TokenUpdateRequest` |
| **Nuevo** `TunnelManager.cs` | Gestión del proceso `cloudflared.exe`: arrancar, monitorear, obtener URL del túnel |
| `WindowsGoodBye.Service.csproj` | Agregar paquete `Microsoft.AspNetCore.App` para Kestrel embebido |

### Fase 3: Service — Orquestación Push Auth

| Archivo | Cambio |
|---------|--------|
| [`AuthWorker.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Service/AuthWorker.cs) | `RunAuthRaceAsync()`: carrera paralela transportes + push |
| [`AuthWorker.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Service/AuthWorker.cs) | `TryPushAuthAsync()`: generar challenge, registrar en relay, enviar FCM, esperar en long-poll |
| [`AuthWorker.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Service/AuthWorker.cs) | `VerifyPushAuthResponse()`: verificar HMAC con timestamps anti-replay |
| [`AuthWorker.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Service/AuthWorker.cs) | Reemplazar `.Wait()` sincrónico por `await` (fix existente) |
| [`FcmPushSender.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Service/FcmPushSender.cs) | `SendAuthChallengeAsync()`: enviar challenge completo en FCM data message |
| [`FcmPushSender.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Service/FcmPushSender.cs) | Detectar error `registration-token-not-registered` y marcar token inválido |
| [`PipeServer.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Service/PipeServer.cs) | Enviar mensajes de progreso al CP: `STATUS:searching`, `STATUS:push_sent:...` |

### Fase 4: Startup del Service

| Archivo | Cambio |
|---------|--------|
| [`Program.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Service/Program.cs) | Registrar `RelayServer` y `TunnelManager` como hosted services |
| [`Program.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Service/Program.cs) | Incluir `cloudflared.exe` en el proceso de instalación |

### Fase 5: Android — Recepción de Challenge Push

| Archivo | Cambio |
|---------|--------|
| [`FcmService.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Mobile/Platforms/Android/FcmService.cs) | `case "auth_challenge"`: parsear challenge, mostrar notificación interactiva |
| [`FcmService.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Mobile/Platforms/Android/FcmService.cs) | Fix: timing bug — pasar datos por Intent extras, no por `Instance?.` |
| [`FcmService.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Mobile/Platforms/Android/FcmService.cs) | `OnNewToken()`: sincronizar via relay endpoint si no hay transporte directo |

### Fase 6: Android — PushAuthActivity

| Archivo | Cambio |
|---------|--------|
| **Nuevo** `PushAuthActivity.cs` | Activity transparente: recibe challenge → BiometricPrompt → HTTPS POST al relay |
| **Nuevo** `PushAuthActivity.cs` | UI: nombre de PC, countdown timer, botón cancelar |
| **Nuevo** `PushAuthActivity.cs` | Feedback visual: ✓ verde (éxito) / ✗ rojo (fallo) con auto-dismiss |
| **Nuevo** `HttpRelayClient.cs` | Cliente HTTP para POST /respond con JWT |

### Fase 7: Android — Mejoras BiometricService

| Archivo | Cambio |
|---------|--------|
| [`AndroidBiometricService.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Mobile/Platforms/Android/AndroidBiometricService.cs) | Migrar de API 28 nativa a `AndroidX.Biometric.BiometricPrompt` |
| [`AndroidBiometricService.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Mobile/Platforms/Android/AndroidBiometricService.cs) | Usar `BiometricManager.CanAuthenticate()` para check de disponibilidad |
| [`IBiometricService.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Mobile/Services/IBiometricService.cs) | Agregar `BiometricErrorType` enum al result |

### Fase 8: Token Sync y Multi-PC

| Archivo | Cambio |
|---------|--------|
| [`AuthListener.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Mobile/Services/AuthListener.cs) | Handler para `wingb://token_update_ack` (confirmación de token recibido) |
| [`AuthListener.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Mobile/Services/AuthListener.cs) | Enviar `token_update` automáticamente al conectar si token cambió |
| [`AuthListener.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Mobile/Services/AuthListener.cs) | Fix: thread-safety en `Instance` getter (usar `Lazy<T>`) |
| [`FcmService.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Mobile/Platforms/Android/FcmService.cs) | Notificaciones con ID único por `session_id` (soporte multi-PC) |

### Fase 9: Credential Provider — Status Messages

| Archivo | Cambio |
|---------|--------|
| [`WinGBProvider.cpp`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.CredentialProvider/WinGBProvider.cpp) | Parsear mensajes `STATUS:...` del pipe y actualizar `WINGB_FID_SMALL_TEXT` |
| [`helpers.h`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.CredentialProvider/helpers.h) | Lectura asíncrona con loop de mensajes STATUS hasta AUTH_READY o TIMEOUT |

### Fase 10: Pairing — Incluir relay_url

| Archivo | Cambio |
|---------|--------|
| [`PairingSession.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Core/PairingSession.cs) | Incluir `relay_url` del Cloudflare Tunnel en el payload del QR |
| [`PairingSession.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Core/PairingSession.cs) | Derivar `RelayKey` de `DeviceKey` durante pairing |
| [`MobileDatabase.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Mobile/Data/MobileDatabase.cs) | Agregar `RelayUrl` y `RelayKey` al modelo `PairedPc` |

### Fase 11: Instalador y Setup

| Archivo | Cambio |
|---------|--------|
| [`WindowsGoodBye-Setup.ps1`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/scripts/WindowsGoodBye-Setup.ps1) | Incluir descarga/instalación de `cloudflared.exe` |
| [`WindowsGoodBye-Setup.ps1`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/scripts/WindowsGoodBye-Setup.ps1) | Configurar Cloudflare Tunnel (named tunnel con token) |
| [`WindowsGoodBye-Setup.ps1`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/scripts/WindowsGoodBye-Setup.ps1) | Regla de firewall para puerto 26821 (relay local) |

---

## 📊 Esfuerzo y Orden de Implementación

| Orden | Fase | Descripción | Esfuerzo | Dependencias |
|:-----:|:----:|------------|:--------:|:------------:|
| 1 | 0 | AES-GCM + FCM v1 migration | 🟡 Medio | Ninguna |
| 2 | 1 | Protocol + Models + JWT + HKDF | 🟢 Bajo | Fase 0 |
| 3 | 2 | Relay Server embebido | 🟡 Medio | Fase 1 |
| 4 | 3 | AuthWorker carrera paralela | 🔴 Alto | Fases 1, 2 |
| 5 | 4 | Service startup + tunnel | 🟢 Bajo | Fases 2, 3 |
| 6 | 5 | Android FCM challenge handler | 🟡 Medio | Fase 1 |
| 7 | 6 | PushAuthActivity | 🟡 Medio | Fases 5, 7 |
| 8 | 7 | BiometricService AndroidX | 🟢 Bajo | Ninguna (parallelizable) |
| 9 | 8 | Token sync + Multi-PC | 🟢 Bajo | Fases 2, 5 |
| 10 | 9 | CP status messages | 🟡 Medio | Fase 3 |
| 11 | 10 | Pairing con relay_url | 🟢 Bajo | Fases 2, 4 |
| 12 | 11 | Instalador | 🟢 Bajo | Todas |

### Paralelización posible:

```
        Fase 0 (crypto + FCM)
              │
        Fase 1 (protocol)
         ┌────┴────┐
    Fase 2 (relay)  Fase 7 (biometric) ← puede arrancar en paralelo
         │              │
    Fase 3 (auth)  Fase 5 (FCM Android)
         │              │
    Fase 4 (startup) Fase 6 (PushAuthActivity)
         │              │
    Fase 9 (CP)    Fase 8 (token sync)
         │              │
         └──────┬───────┘
           Fase 10 (pairing)
                │
           Fase 11 (installer)
```

---

## ✅ Checklist de Fisuras Resueltas

| # | Fisura | Estado | Solución |
|---|--------|--------|----------|
| 1 | Relay SPOF | ✅ | Carrera paralela — relay down = fallback automático a transportes directos |
| 2 | FCM no garantiza entrega | ✅ | Carrera paralela + UI de progreso/reintentar + manejo de errores FCM |
| 3 | Replay-delay del relay | ✅ | Timestamp firmado en HMAC, ventana de 10s post-respuesta |
| 4 | Full-screen intent Android 13+ | ✅ | Heads-up notification sin full-screen, documentado paso de desbloqueo |
| 5 | FCM token rotation gap | ✅ | Endpoint relay + sync por transporte directo + manejo de token inválido |
| 6 | Nomenclatura nonce/challenge | ✅ | Definido: nonce cifrado AES-256-GCM con DeviceKey + session_id como AAD |
| 7 | Session-device binding | ✅ | Relay valida `device_id == expected_device_id` en registro |
| A | Múltiples PCs | ✅ | Notificaciones separadas por session_id, relay maneja sesiones independientes |
| B | Auth PC al relay | ✅ | JWT firmado con RelayKey (HKDF derivada de DeviceKey) |
| C | CP ciclo de vida | ✅ | Service es dueño exclusivo del RelayClient; CP solo usa pipe |
| D | Offline | ✅ | Detección por estado del túnel; sin túnel = solo transportes directos |

---

## ⚠️ Riesgos Residuales Aceptados

| Riesgo | Mitigación | Impacto |
|--------|------------|---------|
| Cloudflare outage global | Transportes directos siguen funcionando | Bajo |
| Latencia FCM en Doze | Carrera paralela cubre; transporte directo responde primero | Bajo |
| Rompe compat CBC→GCM | Re-pairing necesario para dispositivos existentes | Medio (pocos usuarios) |
| `cloudflared` requiere download separado | Setup lo instala automáticamente | Bajo |
| Android Keystore migration (keys en SQLite) | Fuera de scope v1; marcar como TODO p/ v2.1 | Medio (deuda técnica) |
