using System.Text.Json.Serialization;

namespace WindowsGoodBye.Service;

/// <summary>
/// Wire-format DTOs and hard limits for the embedded push-auth relay's HTTP surface. Field names use
/// snake_case (<see cref="JsonPropertyNameAttribute"/>) to match the JSON shapes documented in
/// docs/plan_push_auth_v2.md, section "🛠️ Relay HTTP Server Embebido — Diseño" and "📨 Flujo Completo
/// de Seguridad".
///
/// Every DTO exposes a small, allocation-free <c>TryValidate</c> that enforces length limits BEFORE
/// any business logic runs — see "🛡️ Aislamiento y Resiliencia del Relay" ("Validación estricta de
/// entrada: deserialización de DTOs con límites de longitud en todos los campos string"). Kestrel's
/// <c>MaxRequestBodySize</c> (see <see cref="RelayLimits.MaxRequestBodyBytes"/>) is the outer guard;
/// these are the inner, per-field guard.
/// </summary>
public static class RelayLimits
{
    // --- Field length limits (defense in depth, on top of Kestrel's body-size cap) ---
    public const int MaxSessionIdLength = 64;      // session_id is a GUID string ("d"/"n" format) — 36 chars max, some slack
    public const int MaxDeviceIdLength = 64;       // device_id is a GUID string — same reasoning
    public const int MaxJwtLength = 2048;          // HS256 JWT with our fixed claim set is a few hundred bytes; generous cap
    public const int MaxHmacBase64Length = 96;      // base64(HMAC-SHA256) = 44 chars; generous cap
    public const int MaxFcmTokenLength = 4096;     // FCM registration tokens are typically ~150-200 chars but can be longer
    public const int MaxReasonLength = 200;

    /// <summary>Kestrel <c>Limits.MaxRequestBodySize</c> — see "Aislamiento y Resiliencia del Relay".</summary>
    public const long MaxRequestBodyBytes = 16 * 1024; // 16 KB

    // --- Rate limits, exact values from "🛡️ Rate Limiting en el Relay" ---
    public const int RegisterPerMinutePerIp = 10;
    public const int DeviceTokenPerMinutePerDeviceId = 5;
    public const int GlobalPerMinutePerIp = 100;

    /// <summary>
    /// "POST /api/auth/respond | 5 intentos | por session_id | 403 Forbidden + invalida la sesión".
    /// Implemented as bespoke per-session counting (not the generic RateLimiting middleware) because
    /// the remediation is business logic (kill the session), not a plain 429 — see RelayServer.cs.
    /// </summary>
    public const int MaxRespondAttemptsPerSession = 5;
}

/// <summary>
/// PC → relay: register a pending push-auth session (Ruta C). Per the plan's wire format this does
/// NOT carry the nonce — the nonce is delivered to Android separately via the encrypted FCM payload,
/// and is only ever needed locally by whichever side already holds it (Android to decrypt/HMAC,
/// AuthWorker to verify the HMAC after the fact). The relay's job is purely to correlate
/// register → wait → respond/reject by <c>session_id</c>, never to see the nonce.
/// </summary>
public sealed class RegisterRequest
{
    [JsonPropertyName("session_id")] public string SessionId { get; set; } = "";
    [JsonPropertyName("expected_device_id")] public string ExpectedDeviceId { get; set; } = "";
    [JsonPropertyName("jwt")] public string Jwt { get; set; } = "";

    public bool TryValidate(out string? error)
    {
        if (string.IsNullOrEmpty(SessionId) || SessionId.Length > RelayLimits.MaxSessionIdLength)
        { error = "invalid session_id"; return false; }
        if (string.IsNullOrEmpty(ExpectedDeviceId) || ExpectedDeviceId.Length > RelayLimits.MaxDeviceIdLength)
        { error = "invalid expected_device_id"; return false; }
        if (string.IsNullOrEmpty(Jwt) || Jwt.Length > RelayLimits.MaxJwtLength)
        { error = "invalid jwt"; return false; }
        error = null;
        return true;
    }
}

/// <summary>Android → relay: proof-of-possession response for a push-auth session.</summary>
public sealed class RespondRequest
{
    [JsonPropertyName("session_id")] public string SessionId { get; set; } = "";
    [JsonPropertyName("device_id")] public string DeviceId { get; set; } = "";
    /// <summary>base64(HMAC-SHA256(nonce ‖ challenge_ts ‖ response_ts ‖ session_id, AuthKey)).</summary>
    [JsonPropertyName("hmac")] public string Hmac { get; set; } = "";
    /// <summary>Unix seconds (UTC) when Android computed the HMAC — anti-replay-delay check (PC-side).</summary>
    [JsonPropertyName("response_ts")] public long ResponseTimestamp { get; set; }
    [JsonPropertyName("jwt")] public string Jwt { get; set; } = "";

    public bool TryValidate(out string? error)
    {
        if (string.IsNullOrEmpty(SessionId) || SessionId.Length > RelayLimits.MaxSessionIdLength)
        { error = "invalid session_id"; return false; }
        if (string.IsNullOrEmpty(DeviceId) || DeviceId.Length > RelayLimits.MaxDeviceIdLength)
        { error = "invalid device_id"; return false; }
        if (string.IsNullOrEmpty(Hmac) || Hmac.Length > RelayLimits.MaxHmacBase64Length)
        { error = "invalid hmac"; return false; }
        if (string.IsNullOrEmpty(Jwt) || Jwt.Length > RelayLimits.MaxJwtLength)
        { error = "invalid jwt"; return false; }
        if (ResponseTimestamp <= 0)
        { error = "invalid response_ts"; return false; }
        error = null;
        return true;
    }
}

/// <summary>
/// Android → relay: explicit rejection (number-matching failed / "No es mi PC") — distinct from a
/// timeout so the CP can surface a stronger signal than "tiempo agotado". See "🛡️ Defensa contra
/// Push Fatigue".
/// </summary>
public sealed class RejectRequest
{
    [JsonPropertyName("session_id")] public string SessionId { get; set; } = "";
    [JsonPropertyName("device_id")] public string DeviceId { get; set; } = "";
    [JsonPropertyName("reason")] public string? Reason { get; set; }
    [JsonPropertyName("jwt")] public string Jwt { get; set; } = "";

    public bool TryValidate(out string? error)
    {
        if (string.IsNullOrEmpty(SessionId) || SessionId.Length > RelayLimits.MaxSessionIdLength)
        { error = "invalid session_id"; return false; }
        if (string.IsNullOrEmpty(DeviceId) || DeviceId.Length > RelayLimits.MaxDeviceIdLength)
        { error = "invalid device_id"; return false; }
        if (Reason is { Length: > RelayLimits.MaxReasonLength })
        { error = "reason too long"; return false; }
        if (string.IsNullOrEmpty(Jwt) || Jwt.Length > RelayLimits.MaxJwtLength)
        { error = "invalid jwt"; return false; }
        error = null;
        return true;
    }
}

/// <summary>Outcome of a push-auth session as resolved by <see cref="RelayServer"/>'s long-poll wait.</summary>
public enum PushAuthOutcomeStatus
{
    /// <summary>Android responded successfully with proof-of-possession (HMAC).</summary>
    Ok,
    /// <summary>Android explicitly rejected the challenge ("No es mi PC") via <c>/api/auth/reject</c>.</summary>
    Rejected,
    /// <summary>The session's TTL elapsed before anyone (waiter or responder) touched it.</summary>
    Expired,
    /// <summary>The waiter's own wait window (bounded by the session TTL and/or its own CancellationToken) elapsed.</summary>
    Timeout
}

/// <summary>
/// Result of waiting on a push-auth session — returned by both the HTTP <c>GET /api/auth/wait/{sid}</c>
/// endpoint and <see cref="RelayServer.WaitForResponseDirectAsync"/> (the in-process path AuthWorker uses).
/// </summary>
public sealed record PushAuthOutcome(
    PushAuthOutcomeStatus Status,
    string? DeviceId = null,
    string? Hmac = null,
    long? ResponseTimestamp = null,
    string? RejectReason = null);

/// <summary>Android → relay: FCM registration token rotated and no direct transport is available.</summary>
public sealed class TokenUpdateRequest
{
    [JsonPropertyName("device_id")] public string DeviceId { get; set; } = "";
    [JsonPropertyName("token")] public string Token { get; set; } = "";
    [JsonPropertyName("jwt")] public string Jwt { get; set; } = "";

    public bool TryValidate(out string? error)
    {
        if (string.IsNullOrEmpty(DeviceId) || DeviceId.Length > RelayLimits.MaxDeviceIdLength)
        { error = "invalid device_id"; return false; }
        if (string.IsNullOrEmpty(Token) || Token.Length > RelayLimits.MaxFcmTokenLength)
        { error = "invalid token"; return false; }
        if (string.IsNullOrEmpty(Jwt) || Jwt.Length > RelayLimits.MaxJwtLength)
        { error = "invalid jwt"; return false; }
        error = null;
        return true;
    }
}
