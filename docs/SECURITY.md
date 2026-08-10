# Seguridad

Para el diseño y la auditoría completa del sistema de Push Auth (incluyendo hallazgos críticos, decisiones cerradas y riesgos residuales aceptados), ver [`plan_push_auth_v2.md`](plan_push_auth_v2.md). Este documento resume el estado de seguridad general del proyecto, transporte directo incluido.

## Primitivas criptográficas

| Aspecto                               | Implementación                                                                 |
| -------------------------------------- | ------------------------------------------------------------------------------- |
| Pareado                                | Intercambio de claves vía QR (canal visual, sin red)                            |
| Cifrado de transporte                  | **AES-256-GCM** (IV aleatorio por operación, AAD = `session_id`/`device_id`) — el modo CBC con IV estático queda `[Obsolete]` únicamente como ruta de migración, sin soporte dual |
| Autenticación (transporte directo)     | Challenge-response con HMAC-SHA256 + nonce anti-replay                          |
| Autenticación (push auth)              | HMAC-SHA256 sobre `nonce ‖ challenge_ts ‖ response_ts ‖ session_id`, con ventanas anti-replay-delay (60s / 10s) |
| Derivación de claves                   | HKDF: `AuthKey = HKDF(DeviceKey, "auth-hmac")`, `RelayKey = HKDF(DeviceKey, "relay-auth")` — ninguna primitiva reutiliza `DeviceKey` cruda para dos propósitos distintos |
| Autenticación PC↔relay / Android↔relay | JWT HS256 de vida corta (60s), firmado con `RelayKey`                          |
| Almacenamiento de contraseña de Windows | DPAPI (`DataProtectionScope.LocalMachine`)                                      |
| Almacenamiento de `DeviceKey` en Android | Envelope encryption: cifrada con una clave AES no exportable en Android Keystore (StrongBox si está disponible, TEE si no) — nunca en claro en SQLite |
| Named Pipes (CredentialProvider)       | ACL restringida (no `Everyone`)                                                 |
| Named Pipes (TrayApp/admin)            | ACL restringida a `Administrators`/`SYSTEM`/`INTERACTIVE` (ver nota abajo)      |
| Biometría                              | `AndroidX.Biometric.BiometricPrompt`, con `BiometricManager.CanAuthenticate()` previo |
| Gate de autenticación                  | Solo pide huella cuando la PC está bloqueada (`IsAuthWaiting`)                  |

> **Nota sobre el ACL del pipe admin**: el plan original proponía restringir a solo `Administrators`+`SYSTEM`, pero la TrayApp corre sin elevar — con UAC activo eso la habría dejado sin poder parear nunca. Se agregó `INTERACTIVE` con `ReadWrite` como alternativa explícitamente contemplada por el plan. El objetivo de la fisura original (ACL `Everyone`+`FullControl`, expuesto a `Anonymous`/`Guest`/`Network`) queda cerrado igual.

## Modelo de amenazas

- La contraseña de Windows se almacena cifrada con DPAPI en `%ProgramData%\WindowsGoodBye\devices.db`.
- Las claves de pareado (`DeviceKey`) nunca se transmiten después del pareado inicial — solo vía QR, y en Android se persisten cifradas en reposo (nunca en claro en SQLite).
- Cada sesión de autenticación usa un nonce aleatorio (anti-replay); las respuestas de push-auth además llevan timestamps firmados con ventanas de validez cortas (anti-replay-delay).
- La respuesta HMAC es verificada por el servicio antes de enviar credenciales al Credential Provider.
- La autenticación biométrica solo se solicita cuando el Credential Provider está activo (PC bloqueada).
- El relay HTTP embebido (push-auth) bindea solo a loopback, nunca a `0.0.0.0`; el middleware de excepción global evita que un request malformado tumbe el proceso que también aloja el pipe de login real.

## Fronteras de confianza declaradas explícitamente

- **Cloudflare Tunnel** (push-auth, en desarrollo): solo el `nonce` viaja cifrado end-to-end. `session_id`, `device_id`, `hmac`, timestamps y los JWT viajan **en claro** dentro del túnel — Cloudflare ve ese metadata como intermediario TLS. Aceptable para uso doméstico/personal, no para un despliegue multi-tenant o corporativo.
- **Relay in-process**: el `RelayServer` comparte proceso con `AuthWorker` y el pipe del Credential Provider (decisión de v1 por costo/beneficio). Las mitigaciones (middleware de excepción global, límites de tamaño de body, timeouts) reducen drásticamente el riesgo de que un request malicioso tumbe el proceso de login, pero no lo eliminan al 100%.
- **`DeviceKey` desenvuelta en memoria** durante su uso en Android, aunque en reposo esté cifrada — ventana de exposición mínima, no eliminada.

Para el detalle completo de estos hallazgos (incluyendo push fatigue, number matching, y por qué se descartó el modo dual CBC/GCM), ver [`plan_push_auth_v2.md`](plan_push_auth_v2.md).

## Qué falta para que Push Auth esté listo para producción

Ver [`implementation_progress_push_auth_v2.md`](implementation_progress_push_auth_v2.md) para el estado exacto fase por fase. A alto nivel, antes de considerar este flujo listo para uso real falta: wiring del Credential Provider (mostrar el código de verificación en el tile de login), pairing con `relay_url`/preferencia de usuario, el instalador empaquetando `cloudflared` con verificación de checksum, la UI de configuración en la TrayApp, y la suite de pruebas de seguridad end-to-end (replay, rechazo, rate limiting) contra infraestructura real.
