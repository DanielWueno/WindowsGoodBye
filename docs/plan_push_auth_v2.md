# 📋 Plan v2: Push Auth Estilo Google Prompt — WindowsGoodBye

> **Estado**: Revisado con todas las fisuras corregidas + issues bonus, huecos de cobertura y auditoría de seguridad (push fatigue, aislamiento del relay, Keystore, separación de claves) incorporados  
> **Versión**: 2.2 — Post-revisión arquitectónica + cierre de gaps vs. análisis original + cierre de auditoría de seguridad pre-implementación

---

## Decisiones Arquitectónicas Tomadas

| # | Decisión | Resolución |
|---|----------|------------|
| 1 | **Relay Server** | Self-hosted embebido en el Service + Cloudflare Tunnel para internet |
| 2 | **Cifrado del nonce** | AES-256-**GCM** con `DeviceKey` + `session_id` como AAD |
| 3 | **Dueño del ciclo de vida push-auth** | El Service (.NET). `AuthWorker` invoca a `RelayServer` **in-process** (mismo `ConcurrentDictionary<string, PendingSession>`) — no existe un `RelayClient` de red separado en la PC, porque el relay vive embebido en el propio Service. El CredentialProvider no cambia, solo usa el pipe. |
| 4 | **Auth de la PC al relay** | JWT ligero firmado con `DeviceKey` + binding por `device_id` |
| 5 | **Comportamiento offline** | Detección automática por estado del túnel + carrera paralela |
| 6 | **Rate limiting del relay** | Límite fijo por IP y por `device_id` en cada endpoint público (ver [Rate Limiting en el Relay](#-rate-limiting-en-el-relay)) |
| 7 | **Preferencia de Push Auth** | Toggle en la TrayApp (`PushAuthEnabled`), sincronizado a Android durante el pairing y persistido en `DeviceInfo`/`PairedPc` |
| 8 | **Anti push-fatigue** | Number matching (código de 2 dígitos PC↔teléfono) + rate-limit de generación de challenge por PC + contador de intentos visible en el prompt (ver [Defensa contra Push Fatigue](#-defensa-contra-push-fatigue)) |
| 9 | **Aislamiento y resiliencia del relay** | Middleware de excepción global + límite de tamaño de body en Kestrel; el relay sigue in-process en v1 como decisión consciente de esfuerzo, no como garantía absoluta (ver [Aislamiento y Resiliencia del Relay](#-aislamiento-y-resiliencia-del-relay)) |
| 10 | **Almacenamiento de `DeviceKey` en Android** | Envelope encryption: `DeviceKey` se persiste cifrada en SQLite con una clave AES no exportable generada en Android Keystore (StrongBox si está disponible) — sube de "TODO v2.1" a requisito de v1 (ver [Almacenamiento Seguro de DeviceKey en Android](#-almacenamiento-seguro-de-devicekey-en-android)) |
| 11 | **Compatibilidad CBC→GCM** | Sin modo dual: se fuerza re-pairing y se elimina CBC por completo (cierra el riesgo de downgrade) |
| 12 | **Separación de claves para HMAC vs. cifrado** | `AuthKey = HKDF(DeviceKey, "auth-hmac")`, derivada de forma independiente a `RelayKey = HKDF(DeviceKey, "relay-auth")` — ninguna primitiva reutiliza `DeviceKey` cruda directamente salvo el cifrado del nonce |

> [!NOTE]
> **Nomenclatura**: en el resto del documento, cuando se dice "el relay recibe/valida" en realidad es código dentro del mismo proceso del Service (`RelayServer` + `AuthWorker`), no una llamada de red saliente de la PC. La única llamada de red saliente hacia el relay ocurre desde **Android**, vía Cloudflare Tunnel.

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
| **Control total de datos** | Solo el `nonce` viaja cifrado (AES-GCM). `session_id`, `device_id`, `hmac`, timestamps y los JWT viajan **en claro** dentro del túnel — Cloudflare Tunnel termina TLS en el edge y ve ese metadata como intermediario. Es una frontera de confianza explícita, aceptable para uso doméstico, no "opacidad total" |
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
> **Decisión de compatibilidad (cerrada)**: La migración de CBC→GCM rompe compatibilidad con dispositivos ya pareados. Se descarta el modo dual porque abre un vector de **downgrade attack**: si el protocolo acepta ambos modos, un atacante que controle o influya el tráfico (o simplemente fuerce que la sesión "parezca" legacy) puede degradar la negociación a CBC con IV estático — exactamente la vulnerabilidad original que esta migración busca cerrar. Y aunque el modo se atara al HMAC/AAD para hacerlo no negociable por el cliente, sigue siendo superficie de ataque innecesaria cuando la alternativa es barata.
>
> **Decisión**: Forzar re-pairing. No se implementa modo dual. Un dispositivo pareado con el esquema viejo (CBC) deja de autenticar hasta re-parear; el Service detecta la versión de esquema en `DeviceInfo` y, si es legacy, la marca como inválida y guía al usuario a re-parear desde la TrayApp.

### Anti-Replay-Delay: Timestamp Firmado

**Problema (Fisura #3)**: Un relay malicioso puede retener la respuesta HMAC y reenviarla después.

**Solución**: El HMAC incluye un timestamp que la PC verifica:

```
// Lo que firma Android:
HMAC_payload = nonce ‖ challenge_timestamp ‖ response_timestamp ‖ session_id
HMAC = HMAC-SHA256(HMAC_payload, AuthKey)

// AuthKey NO es DeviceKey ni RelayKey — se deriva por separado para no
// reutilizar la misma clave cruda entre primitivas distintas (cifrado vs. HMAC):
AuthKey  = HKDF(DeviceKey, info: "auth-hmac")
RelayKey = HKDF(DeviceKey, info: "relay-auth")   // ya definida más abajo, mismo criterio

// Lo que verifica la PC:
1. Verifica HMAC correcta ✓
2. Verifica: response_timestamp - challenge_timestamp < 60 segundos ✓
3. Verifica: now() - response_timestamp < 10 segundos ✓  ← anti-delay
4. Verifica: session_id coincide con el registrado ✓
```

Esto da una **ventana de validez de 10 segundos** para la respuesta después de que Android la genera. Un relay malicioso que retenga la respuesta por más de 10 segundos la invalida.

> [!NOTE]
> **Nota operativa — clock skew**: las ventanas de 60s (JWT `exp`/`iat`, `challenge_ts`) y 10s (`response_ts`) asumen reloj razonablemente sincronizado en ambos lados. Windows sincroniza con NTP por defecto y Android también, pero no es garantía absoluta (relojes de hardware desviados, redes sin NTP). Si en pruebas aparecen rechazos falsos por timestamp, lo primero a verificar es el skew real entre PC y teléfono antes de ampliar las ventanas — ampliarlas a ciegas debilita la defensa anti-replay-delay.

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

### 🛡️ Rate Limiting en el Relay

**Problema**: el relay embebido queda expuesto a internet vía Cloudflare Tunnel. Sin límites, un atacante puede intentar fuerza bruta de `session_id`/JWT o saturar el proceso del Service con requests.

**Solución**: `RelayServer` aplica límites en memoria (no requiere infraestructura extra, el volumen esperado es bajo — un usuario/hogar):

| Endpoint | Límite | Ventana | Acción al exceder |
|----------|--------|---------|--------------------|
| `POST /api/auth/register` | 10 req | por minuto, por IP | 429 Too Many Requests |
| `POST /api/auth/respond` | 5 intentos | por `session_id` | 403 Forbidden + invalida la sesión |
| `GET /api/auth/wait/{sid}` | 1 conexión concurrente | por `session_id` | 409 Conflict (evita long-poll duplicado) |
| `POST /api/device/token` | 5 req | por minuto, por `device_id` | 429 Too Many Requests |
| Global (todos los endpoints) | 100 req | por minuto, por IP | 429 Too Many Requests |

> [!NOTE]
> Implementación vía `Microsoft.AspNetCore.RateLimiting` (built-in en ASP.NET Core desde .NET 7) con `PartitionedRateLimiter` particionado por IP remota y por `device_id` extraído del JWT. Los contadores viven en memoria del proceso — se resetean si el Service reinicia, lo cual es aceptable dado el volumen esperado.

> [!WARNING]
> Esta tabla limita **requests al relay**, no **challenges generados por la PC**. Son cosas distintas: alguien con acceso físico a la pantalla de login puede reintentar "Iniciar sesión con teléfono" repetidamente sin que ninguna de estas reglas lo detenga, porque cada intento es un `session_id` nuevo y legítimo desde el punto de vista del relay. Ese es el vector de **push fatigue**, cerrado en la siguiente sección.

---

## 🛡️ Defensa contra Push Fatigue

> [!IMPORTANT]
> Cierra el hallazgo crítico de la auditoría de seguridad pre-implementación: sin esto, cualquiera con acceso físico a la pantalla de bloqueo puede generar pushes ilimitados hacia el teléfono hasta que el usuario acepte uno por cansancio — el mismo vector que comprometió MFA push-based en incidentes reales (Uber 2022, Cisco, Microsoft). Es la recomendación explícita de CISA/NIST para push-MFA: **number matching** + límite de frecuencia + contexto visible.

### 1. Number matching

```
PC (CredentialProvider)                          Android (PushAuthActivity)
┌────────────────────────┐                       ┌────────────────────────┐
│ WindowsGoodBye          │                       │  🖥️ PC-Daniel          │
│                         │                       │  quiere desbloquearse  │
│ Código de verificación: │   el usuario compara  │                        │
│                         │  ─────────────────►   │  ¿Ves el código 42     │
│        42               │   ambos códigos       │  en tu PC?             │
│                         │                       │                        │
│ Esperando confirmación  │                       │  [Sí, es correcto]     │
│ en tu teléfono...       │                       │  [No es mi PC]         │
└────────────────────────┘                       └────────────────────────┘
```

- `AuthWorker` genera `display_code` (2 dígitos, `RandomNumberGenerator`) junto con el `nonce`, y lo manda tanto al CP (vía pipe, `STATUS:code:42`) como en el payload FCM del challenge. **No es secreto** — su función no es criptográfica, es forzar que el usuario mire la pantalla de la PC antes de aprobar, igual que hace Google Prompt/Microsoft Authenticator.
- `PushAuthActivity` muestra el código recibido y exige una confirmación explícita **antes** de abrir `BiometricPrompt`. Si el usuario toca "No es mi PC", se llama a `POST /api/auth/reject` — el relay marca la sesión como rechazada (no solo expirada) y el CP muestra "Solicitud rechazada desde el teléfono", una señal más fuerte que un simple timeout.
- Con esto, aunque un atacante dispare 20 challenges seguidos, cada uno le exige al usuario un acto consciente de comparar un código, no un tap reflejo sobre una notificación.

### 2. Rate-limit de generación de challenge (lado PC, no lado relay)

`AuthWorker` mantiene su propio contador en memoria por sesión de login del CP (no depende del relay ni de red):

| Regla | Valor |
|-------|-------|
| Mínimo entre challenges consecutivos | 8 segundos |
| Backoff tras 3 intentos en 2 minutos | +30s de espera obligatoria antes de permitir el siguiente |
| Backoff tras 6 intentos en 10 minutos | +5 min de espera obligatoria + banner en CP: "Demasiados intentos, usa tu contraseña" |
| Tope duro | 10 challenges/hora por sesión de login — a partir de ahí solo contraseña, hasta reinicio de la pantalla de bloqueo |

Esto es intencionalmente independiente del rate-limiting del relay (tabla anterior): ese protege al *proceso* de abuso de red; este protege al *usuario* de fatiga, y debe aplicar incluso si Ruta A/B (transportes directos/FCM legacy) es la que dispara los intentos, no solo Ruta C.

### 3. Contexto visible para el usuario

El payload del challenge (y por tanto la notificación/`PushAuthActivity`) incluye un contador que `AuthWorker` ya tiene en memoria por el punto 2: **"3er intento en los últimos 2 minutos"**. Un usuario que ve ese texto reconoce el patrón de un ataque de fatiga en curso, en vez de ver cada push como un evento aislado.

---

## 🛡️ Aislamiento y Resiliencia del Relay

> [!IMPORTANT]
> Cierra el hallazgo crítico de la auditoría: la Ruta A (transportes directos) se documentó como inmune a la caída del relay ("relay down = fallback automático"), pero `RelayServer` corre in-process dentro del mismo Worker Service que aloja `AuthWorker` y el pipe con el CredentialProvider. Un endpoint expuesto a internet (vía Cloudflare Tunnel) que reciba un payload malformado y provoque una excepción no controlada podría, en el peor caso, tumbar el proceso completo del Service — el mismo proceso del que depende Ruta A. La afirmación de inmunidad de la Fisura #1 solo es cierta si el relay no puede arrastrar al Service consigo.

### Mitigación para v1 (obligatoria)

| Medida | Detalle |
|--------|---------|
| Middleware de excepción global | Primer middleware del pipeline de `RelayServer`, envuelve todos los endpoints (excepto `/health`) en `try/catch`; cualquier excepción no controlada devuelve `500` y se loguea, nunca propaga hacia arriba del `WebApplication` |
| Límite de tamaño de body | `Kestrel.Limits.MaxRequestBodySize` fijado a un valor bajo (p. ej. 16 KB — ningún endpoint del relay necesita más) para evitar payloads diseñados para agotar memoria del proceso compartido |
| Timeouts de request | `Kestrel` con `MinRequestBodyDataRate` y timeout de request explícito, para que una conexión lenta/maliciosa no agote los workers del pool |
| Validación estricta de entrada | Deserialización de DTOs con límites de longitud en todos los campos string (`session_id`, `device_id`, JWT) antes de cualquier lógica de negocio |

### Decisión de arquitectura (explícita, no implícita)

`RelayServer` **permanece in-process** en v1 — no se aísla en un proceso hijo supervisado ni en un `AppDomain` separado. Es una decisión consciente de costo/beneficio para un proyecto de uso doméstico, no una garantía de que el riesgo desaparece:

- Las mitigaciones de la tabla anterior reducen drásticamente la probabilidad de que un request malicioso tumbe el proceso, pero no la eliminan al 100% (un bug por debajo de la capa de middleware, en el propio Kestrel/ASP.NET, seguiría siendo capaz de hacerlo).
- Por eso el checklist de fisuras (más abajo) ya no afirma que Ruta A sea "inmune" sin matices — dice "mitigado", que es lo honesto.
- Si en el futuro se detecta inestabilidad real del Service asociada al relay, la vía de escape es mover `RelayServer` a un proceso hijo (`dotnet` separado, comunicado por pipe con el Worker Service) — anotado aquí como opción de hardening futura, no bloqueante para v1.

---

## 🔑 Almacenamiento Seguro de DeviceKey en Android

> [!IMPORTANT]
> Cierra el hallazgo crítico de la auditoría: toda la cadena de seguridad del protocolo (AES-GCM, HMAC, JWT, HKDF) depende de que `DeviceKey` sea secreta. Guardarla en SQLite plano en Android — como estaba anotado en riesgos residuales para "v2.1" — deja la puerta abierta a que malware con root, o un backup no cifrado del teléfono, la exfiltre y falsifique respuestas de auth sin tocar el sensor biométrico, anulando el resto del modelo de amenazas. Esto sube de "riesgo Medio, TODO futuro" a **requisito de v1**.

### Diseño: envelope encryption con Android Keystore

`DeviceKey` sigue siendo una clave simétrica compartida con la PC (no puede vivir *solo* dentro del Keystore como clave no-exportable, porque la PC también la necesita en claro para AES-GCM/HKDF). Lo que cambia es cómo se guarda **en reposo** en el teléfono:

1. Durante el pairing, además de recibir/derivar `DeviceKey`, la app genera (una sola vez, por instalación) una clave AES-256 **no exportable** en `AndroidKeyStore`, usando `StrongBox` si `PackageManager.FEATURE_STRONGBOX_KEYSTORE` está disponible, o el TEE del dispositivo si no.
2. `DeviceKey` se cifra con esa clave (`AES/GCM/NoPadding`, IV aleatorio) antes de persistirse. En `MobileDatabase`/`PairedPc` solo se guarda el ciphertext + IV — nunca la clave en claro.
3. En cada uso (descifrar el nonce del challenge, calcular el HMAC de respuesta), la app descifra `DeviceKey` a memoria a través de la clave del Keystore, la usa, y la deja fuera de alcance (best-effort — .NET/MAUI en Android no garantiza scrubbing de memoria administrada, pero ya no queda persistida en claro en disco).
4. **Hardening opcional recomendado** (no bloqueante para v1): atar el uso de la clave del Keystore a autenticación biométrica reciente (`setUserAuthenticationRequired` + `setUserAuthenticationParameters`), de forma que ni siquiera con la app comprometida en runtime se pueda desenvolver `DeviceKey` sin biometría — encaja naturalmente porque `BiometricPrompt` ya es parte obligatoria del flujo.

Esto no hace que el compromiso sea imposible (un atacante con control total del proceso de la app en runtime, mientras la key está desenvuelta en memoria, sigue siendo un riesgo — igual que en cualquier esquema de software), pero eleva el ataque de "leer un archivo SQLite" a "romper o abusar en vivo del TEE/StrongBox del dispositivo", que es la barra correcta para el material de claves de este protocolo.

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
POST   /api/auth/reject         ← Android rechaza explícitamente (number matching fallido, JWT requerido)
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

### Fase 0: Correcciones de seguridad y estabilidad base (Prerequisito)

> [!NOTE]
> Además de las correcciones criptográficas, esta fase absorbe los **issues bonus** detectados en la auditoría inicial del código (`push_auth_analysis.md`). Se agrupan aquí porque son fixes baratos e independientes que conviene resolver antes de construir el resto del sistema encima.

| Archivo | Cambio | Prioridad |
|---------|--------|-----------|
| [`CryptoUtils.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Core/CryptoUtils.cs) | Migrar de AES-CBC con IV estático a AES-256-GCM con IV aleatorio + AAD | 🔴 Crítica |
| [`CryptoUtils.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Core/CryptoUtils.cs) | Mantener métodos CBC legacy con `[Obsolete]` para migración | 🟡 Media |
| [`FcmPushSender.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Service/FcmPushSender.cs) | Migrar de FCM Legacy HTTP API (deprecada) a HTTP v1 + OAuth2 | 🔴 Crítica |
| [`FcmPushSender.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Service/FcmPushSender.cs) | **(Bonus)** Ruta del service account JSON hardcodeada como relativa → mover a `appsettings.json` / variable de entorno configurable | 🟡 Media |
| [`AdminPipeServer.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Service/AdminPipeServer.cs) | **(Bonus)** `PipeSecurity` usa `Everyone` + `FullControl` → restringir ACL a `BUILTIN\Administrators` + `NT AUTHORITY\SYSTEM` (o el usuario de sesión interactiva concreto) | 🔴 Crítica (superficie de ataque local) |
| [`BluetoothServer.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Service/BluetoothServer.cs) | **(Bonus)** `AcceptBluetoothClient` sin timeout → envolver en `Task.WhenAny` con `CancellationTokenSource` para evitar bloqueo indefinido | 🟡 Media |
| [`UdpManager.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Core/UdpManager.cs) | **(Bonus)** El `join` de multicast puede fallar silenciosamente en interfaces sin soporte → loguear el fallo por interfaz y continuar con las demás en vez de tragarse la excepción | 🟢 Baja |

### Fase 1: Protocolo y Modelos

| Archivo | Cambio |
|---------|--------|
| [`Protocol.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Core/Protocol.cs) | Agregar constantes: `PushAuthChallenge`, `PushAuthResponse`, `TokenUpdate`, `RelayPort = 26821` |
| [`Models.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Core/Models.cs) | Agregar a `DeviceInfo`: `FcmTokenValid`, `PushAuthEnabled`, `RelayUrl` |
| [`Models.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Core/Models.cs) | Nuevo modelo: `PushAuthSession` (session_id, nonce, timestamps, device_id) |
| [`AppDatabase.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Core/AppDatabase.cs) | Migración para nuevas columnas |
| **Nuevo** `JwtHelper.cs` | Generación y validación de JWT ligeros con HMAC-SHA256 |
| **Nuevo** `RelayKeyDerivation.cs` | `HKDF(DeviceKey, "relay-auth")` para derivar `RelayKey`, y `HKDF(DeviceKey, "auth-hmac")` para derivar `AuthKey` — misma clase, dos derivaciones con contexto separado |
| **Nuevo** `SecureKeyStorage.cs` (Android) | Envelope encryption de `DeviceKey`: genera/usa clave AES no exportable en `AndroidKeyStore` (StrongBox si disponible) para cifrar `DeviceKey` antes de persistirla en `MobileDatabase` — ver [Almacenamiento Seguro de DeviceKey en Android](#-almacenamiento-seguro-de-devicekey-en-android) |

### Fase 2: Relay Server Embebido

| Archivo | Cambio |
|---------|--------|
| **Nuevo** `RelayServer.cs` | ASP.NET Minimal API: `/register`, `/wait`, `/respond`, `/reject`, `/device/token`, `/health` |
| **Nuevo** `RelayServer.cs` | Middleware de excepción global (primer middleware del pipeline, envuelve todo excepto `/health`) — ver [Aislamiento y Resiliencia del Relay](#-aislamiento-y-resiliencia-del-relay) |
| **Nuevo** `RelayServer.cs` | Configurar `Kestrel.Limits.MaxRequestBodySize` (16 KB) y timeouts de request explícitos |
| **Nuevo** `RelayModels.cs` | DTOs: `RegisterRequest`, `RespondRequest`, `RejectRequest`, `WaitResponse`, `TokenUpdateRequest` — con límites de longitud en campos string |
| **Nuevo** `TunnelManager.cs` | Gestión del proceso `cloudflared.exe`: arrancar, monitorear, obtener URL del túnel |
| `WindowsGoodBye.Service.csproj` | Agregar paquete `Microsoft.AspNetCore.App` para Kestrel embebido |

### Fase 3: Service — Orquestación Push Auth

| Archivo | Cambio |
|---------|--------|
| [`AuthWorker.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Service/AuthWorker.cs) | `RunAuthRaceAsync()`: carrera paralela transportes + push |
| [`AuthWorker.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Service/AuthWorker.cs) | `TryPushAuthAsync()`: generar challenge, registrar en relay, enviar FCM, esperar en long-poll |
| [`AuthWorker.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Service/AuthWorker.cs) | `VerifyPushAuthResponse()`: verificar HMAC con timestamps anti-replay |
| [`AuthWorker.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Service/AuthWorker.cs) | Reemplazar `.Wait()` sincrónico por `await` en el flujo de espera de auth (fix existente) |
| [`AuthWorker.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Service/AuthWorker.cs) | **(Bonus)** Reemplazar `Thread.Sleep` por `await Task.Delay(ct)` en el loop de retry de push — issue distinto al `.Wait()` de arriba, ambos bloqueaban el thread en puntos diferentes |
| [`AuthWorker.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Service/AuthWorker.cs) | Generar `display_code` (2 dígitos) junto al `nonce`; mantener contador en memoria de intentos por sesión de login del CP y aplicar backoff — ver [Defensa contra Push Fatigue](#-defensa-contra-push-fatigue) |
| [`AuthWorker.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Service/AuthWorker.cs) | `VerifyPushAuthResponse()`: usar `AuthKey = HKDF(DeviceKey, "auth-hmac")` para verificar el HMAC, no `DeviceKey` directa |
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
| [`FcmService.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Mobile/Platforms/Android/FcmService.cs) | Parsear `display_code` y contador de intentos del payload; incluirlos en el texto de la notificación |
| [`FcmService.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Mobile/Platforms/Android/FcmService.cs) | Fix: timing bug — pasar datos por Intent extras, no por `Instance?.` |
| [`FcmService.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Mobile/Platforms/Android/FcmService.cs) | `OnNewToken()`: sincronizar via relay endpoint si no hay transporte directo |

### Fase 6: Android — PushAuthActivity

| Archivo | Cambio |
|---------|--------|
| **Nuevo** `PushAuthActivity.cs` | Activity transparente: recibe challenge → **confirmación de number matching** → BiometricPrompt → HTTPS POST al relay |
| **Nuevo** `PushAuthActivity.cs` | UI: nombre de PC, `display_code` de 2 dígitos, contador de intentos recientes, countdown timer, botones "Sí, es correcto" / "No es mi PC" / cancelar |
| **Nuevo** `PushAuthActivity.cs` | Feedback visual: ✓ verde (éxito) / ✗ rojo (fallo o rechazo) con auto-dismiss |
| **Nuevo** `HttpRelayClient.cs` | Cliente HTTP para POST `/respond` y POST `/reject`, ambos con JWT |

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
| [`WinGBProvider.cpp`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.CredentialProvider/WinGBProvider.cpp) | Parsear `STATUS:code:NN` y mostrar el código de verificación de number matching de forma prominente en el tile |
| [`helpers.h`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.CredentialProvider/helpers.h) | Lectura asíncrona con loop de mensajes STATUS hasta AUTH_READY o TIMEOUT |

### Fase 10: Pairing — Incluir relay_url

| Archivo | Cambio |
|---------|--------|
| [`PairingSession.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Core/PairingSession.cs) | Incluir `relay_url` del Cloudflare Tunnel en el payload del QR |
| [`PairingSession.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Core/PairingSession.cs) | Derivar `RelayKey` de `DeviceKey` durante pairing |
| [`PairingSession.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Core/PairingSession.cs) | **(Bonus)** Incluir preferencia inicial `push_auth_enabled` (valor por defecto de la PC, configurable luego en la TrayApp) en el payload del QR |
| [`MobileDatabase.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Mobile/Data/MobileDatabase.cs) | Agregar `RelayUrl`, `RelayKey` y `PushAuthEnabled` al modelo `PairedPc` |

### Fase 11: Instalador y Setup

| Archivo | Cambio |
|---------|--------|
| [`WindowsGoodBye-Setup.ps1`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/scripts/WindowsGoodBye-Setup.ps1) | Incluir descarga/instalación de `cloudflared.exe` |
| [`WindowsGoodBye-Setup.ps1`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/scripts/WindowsGoodBye-Setup.ps1) | **Verificar checksum/firma** de `cloudflared.exe` contra el release oficial de GitHub antes de ejecutarlo — evita supply-chain compromise en el binario descargado |
| [`WindowsGoodBye-Setup.ps1`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/scripts/WindowsGoodBye-Setup.ps1) | Configurar Cloudflare Tunnel (named tunnel con token) |
| [`WindowsGoodBye-Setup.ps1`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/scripts/WindowsGoodBye-Setup.ps1) | Proteger `credentials.json` del Named Tunnel con la misma ACL restringida (`Administrators`/`SYSTEM`) ya aplicada al pipe en Fase 0 — es tan sensible como `DeviceKey` |
| [`WindowsGoodBye-Setup.ps1`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/scripts/WindowsGoodBye-Setup.ps1) | ~~Regla de firewall para puerto 26821~~ — **no aplica**: `RelayServer` usa `UseUrls("http://localhost:...")`, solo bindea a loopback, no necesita ni debería tener regla de firewall. Solo sería necesaria si en el futuro se bindeara a `0.0.0.0`, lo cual expondría HTTP plano a la LAN y requeriría TLS, no solo firewall |

### Fase 12: TrayApp — Config UI de Push Auth

> [!IMPORTANT]
> Cubre la Fase 9 del `push_auth_analysis.md` original, ausente en la v2.0: sin esta fase el usuario no tiene forma de deshabilitar Push Auth desde la PC (solo se apagaba automáticamente si FCM fallaba).

| Archivo | Cambio |
|---------|--------|
| [`TrayApplicationContext.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.TrayApp/TrayApplicationContext.cs) | Agregar ítem de menú "Push Auth" con submenú por dispositivo pareado: Habilitado/Deshabilitado |
| [`TrayApplicationContext.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.TrayApp/TrayApplicationContext.cs) | Al cambiar el toggle: actualizar `DeviceInfo.PushAuthEnabled` en `AppDatabase` y notificar al Service (vía pipe admin o señal de config reload) |
| **Nuevo** `PushAuthSettingsForm.cs` (o menú simple, a definir según UX de la TrayApp actual) | Mostrar estado por dispositivo: habilitado / deshabilitado / no disponible (sin FCM token válido) |
| [`AuthWorker.cs`](file:///C:/Users/danie/OneDrive/Documentos/Soft/WindowsGoodBye/src/WindowsGoodBye.Service/AuthWorker.cs) | Verificar `DeviceInfo.PushAuthEnabled` antes de lanzar Ruta C (push auth) en la carrera paralela — respeta la preferencia del usuario, no solo el estado técnico del token |

### Fase 13: Testing & Polish

> [!IMPORTANT]
> Cubre la Fase 10 del `push_auth_analysis.md` original. Dado que este es un flujo de seguridad crítico (desbloqueo de sesión de Windows), no se libera sin este checklist mínimo cubierto.

| Tipo | Casos a cubrir |
|------|-----------------|
| **Unit** | `CryptoUtils` GCM (encrypt/decrypt, tamper del tag, AAD incorrecto), `JwtHelper` (firma válida/inválida, expiración), `RelayKeyDerivation` (HKDF determinístico) |
| **Unit** | Verificación HMAC con timestamps: ventana válida, `response_ts` fuera de ventana (>10s), `challenge_ts` expirado (>60s) |
| **Integración** | `RelayServer`: register → wait (long-poll) → respond, sesión expirada (408), `device_id` no coincide (403), rate limiting (429) |
| **Integración** | `AuthWorker.RunAuthRaceAsync()`: Ruta A gana, Ruta C gana, timeout global sin ninguna ruta, cancelación cruzada de rutas perdedoras |
| **E2E manual** | Flujo completo con teléfono en red distinta (solo Ruta C), con teléfono en Doze mode, con `cloudflared` caído (fallback a transportes directos) |
| **E2E manual** | Multi-PC: 2 PCs bloqueadas simultáneamente, responder solo a una, verificar que la otra sigue esperando/expira independientemente |
| **E2E manual** | Rotación de token FCM: token viejo → 404 → marca inválido → reconexión directa → resincroniza → push auth vuelve a funcionar |
| **Seguridad** | Intento de replay de una respuesta HMAC capturada (debe fallar por ventana de 10s), intento de responder con `device_id` ajeno (debe fallar 403) |
| **Seguridad** | Push fatigue: disparar >6 challenges en 10 min desde el CP y verificar backoff/tope duro; verificar que `POST /reject` invalida la sesión de forma distinguible de un timeout |
| **Seguridad** | Relay: enviar body malformado/oversized a cada endpoint y verificar que el proceso del Service no cae (solo 400/413/500 controlado) |
| **Unit (Android)** | `SecureKeyStorage`: round-trip de envelope encryption (wrap/unwrap de `DeviceKey`), fallo si la clave del Keystore no existe o el dispositivo no soporta StrongBox (fallback a TEE) |
| **Regresión** | Migración CBC→GCM: dispositivo pareado con esquema viejo intenta autenticar — debe fallar y guiar a re-pairing forzado (sin modo dual) |

---

## 📊 Esfuerzo y Orden de Implementación

| Orden | Fase | Descripción | Esfuerzo | Dependencias |
|:-----:|:----:|------------|:--------:|:------------:|
| 1 | 0 | AES-GCM + FCM v1 migration + issues bonus (ACL pipe, timeout BT, path config, UDP logging) | 🟡 Medio | Ninguna |
| 2 | 1 | Protocol + Models + JWT + HKDF (AuthKey/RelayKey) + SecureKeyStorage Android (Keystore/StrongBox) | 🟡 Medio | Fase 0 |
| 3 | 2 | Relay Server embebido + rate limiting + middleware de excepción/límites de body | 🟡 Medio | Fase 1 |
| 4 | 3 | AuthWorker carrera paralela | 🔴 Alto | Fases 1, 2 |
| 5 | 4 | Service startup + tunnel | 🟢 Bajo | Fases 2, 3 |
| 6 | 5 | Android FCM challenge handler | 🟡 Medio | Fase 1 |
| 7 | 6 | PushAuthActivity | 🟡 Medio | Fases 5, 7 |
| 8 | 7 | BiometricService AndroidX | 🟢 Bajo | Ninguna (parallelizable) |
| 9 | 8 | Token sync + Multi-PC | 🟢 Bajo | Fases 2, 5 |
| 10 | 9 | CP status messages | 🟡 Medio | Fase 3 |
| 11 | 10 | Pairing con relay_url + preferencia push auth | 🟢 Bajo | Fases 2, 4 |
| 12 | 11 | Instalador | 🟢 Bajo | Todas |
| 13 | 12 | TrayApp — Config UI | 🟢 Bajo | Fases 1, 3, 10 |
| 14 | 13 | Testing & Polish | 🔴 Alto | Todas |

### Paralelización posible:

```
        Fase 0 (crypto + FCM + bonus)
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
         ┌──────┴──────┐
    Fase 11 (installer) Fase 12 (TrayApp config)
         └──────┬──────┘
           Fase 13 (testing & polish)
```

---

## ✅ Checklist de Fisuras Resueltas

| # | Fisura | Estado | Solución |
|---|--------|--------|----------|
| 1 | Relay SPOF | ⚠️ Mitigado | Carrera paralela — relay down (proceso vivo, endpoint caído) = fallback automático a transportes directos. Un crash del *proceso* del Service arrastraría también a Ruta A; mitigado (no eliminado) por middleware de excepción global + límites de body — ver [Aislamiento y Resiliencia del Relay](#-aislamiento-y-resiliencia-del-relay) |
| 2 | FCM no garantiza entrega | ✅ | Carrera paralela + UI de progreso/reintentar + manejo de errores FCM |
| 3 | Replay-delay del relay | ✅ | Timestamp firmado en HMAC, ventana de 10s post-respuesta |
| 4 | Full-screen intent Android 13+ | ✅ | Heads-up notification sin full-screen, documentado paso de desbloqueo |
| 5 | FCM token rotation gap | ✅ | Endpoint relay + sync por transporte directo + manejo de token inválido |
| 6 | Nomenclatura nonce/challenge | ✅ | Definido: nonce cifrado AES-256-GCM con DeviceKey + session_id como AAD |
| 7 | Session-device binding | ✅ | Relay valida `device_id == expected_device_id` en registro |
| A | Múltiples PCs | ✅ | Notificaciones separadas por session_id, relay maneja sesiones independientes |
| B | Auth PC al relay | ✅ | JWT firmado con RelayKey (HKDF derivada de DeviceKey) |
| C | CP ciclo de vida | ✅ | Service es dueño exclusivo del ciclo push-auth (relay embebido + `AuthWorker` in-process); CP solo usa pipe |
| D | Offline | ✅ | Detección por estado del túnel; sin túnel = solo transportes directos |
| E | Abuso/DoS del relay expuesto a internet | ✅ | Rate limiting por IP y `device_id` en todos los endpoints (Fase 2) |
| F | `AdminPipeServer` ACL `Everyone`+`FullControl` | ✅ | Restringir a `Administrators`/`SYSTEM` (Fase 0, bonus) |
| G | `Thread.Sleep` bloqueante en retry de push | ✅ | Reemplazo por `await Task.Delay` (Fase 0/3, bonus) |
| H | Service account JSON con ruta hardcodeada | ✅ | Configurable vía `appsettings.json`/env var (Fase 0, bonus) |
| I | `BluetoothServer` sin timeout de accept / `UdpManager` fallo silencioso de multicast | ✅ | Timeout con cancelación / logging por interfaz (Fase 0, bonus) |
| J | Sin control de usuario para deshabilitar Push Auth | ✅ | Toggle en TrayApp + `PushAuthEnabled` respetado por `AuthWorker` (Fase 12) |
| K | Sin plan de pruebas explícito para un flujo de seguridad crítico | ✅ | Fase 13 — unit, integración, E2E manual y casos de seguridad (replay, device_id ajeno) |
| L | Push fatigue / prompt bombing | ✅ | Number matching + rate-limit de generación de challenge por PC con backoff + contexto de intentos en el prompt (Fase 3/5/6/9) |
| M | `DeviceKey` en SQLite plano en Android | ✅ | Envelope encryption con Android Keystore/StrongBox, requisito de v1 (Fase 1) — ver [Almacenamiento Seguro de DeviceKey en Android](#-almacenamiento-seguro-de-devicekey-en-android) |
| N | Reutilización de `DeviceKey` cruda entre cifrado y HMAC | ✅ | `AuthKey = HKDF(DeviceKey, "auth-hmac")`, separada de `RelayKey` (Fase 1) |
| O | Downgrade attack vía modo dual CBC/GCM | ✅ | Descartado el modo dual; se fuerza re-pairing, CBC se elimina por completo |
| P | Metadata en claro visible para Cloudflare | ✅ | Declarado como frontera de confianza explícita — solo el nonce va cifrado; aceptable para uso doméstico (documentado, no minimizado) |

---

## ⚠️ Riesgos Residuales Aceptados

| Riesgo | Mitigación | Impacto |
|--------|------------|---------|
| Cloudflare outage global | Transportes directos siguen funcionando | Bajo |
| Latencia FCM en Doze | Carrera paralela cubre; transporte directo responde primero | Bajo |
| Rompe compat CBC→GCM | Re-pairing necesario para dispositivos existentes (modo dual descartado explícitamente por riesgo de downgrade) | Medio (pocos usuarios) |
| `cloudflared` requiere download separado | Setup lo instala automáticamente, con verificación de checksum/firma | Bajo |
| Rate limiting en memoria se resetea al reiniciar el Service | Volumen esperado bajo (uso doméstico/personal); revisar si se detecta abuso real | Bajo |
| Fase 13 (Testing) alarga el cronograma total | Se considera no negociable por tratarse de un flujo de desbloqueo de sesión de Windows | Medio (tiempo) |
| Cloudflare ve metadata en claro (`session_id`, `device_id`, `hmac`, timestamps, JWT) — solo el nonce va cifrado | Frontera de confianza declarada explícitamente; aceptable para uso doméstico/personal, no para un caso multi-tenant o corporativo | Bajo (doméstico) |
| Relay embebido in-process: un bug por debajo del middleware de excepción global podría aún tumbar el proceso del Service (y con él, Ruta A) | Middleware de excepción global + límites de body/timeout reducen drásticamente la probabilidad; aislamiento en proceso hijo queda como hardening futuro si se detecta inestabilidad real | Medio (baja probabilidad, alto impacto si ocurre) |
| `DeviceKey` desenvuelta en memoria de la app Android durante el uso, aunque en reposo esté cifrada con Keystore | Ventana de exposición mínima (solo durante decrypt/HMAC); atar el uso de la key del Keystore a biometría reciente es hardening opcional recomendado, no bloqueante para v1 | Bajo |
