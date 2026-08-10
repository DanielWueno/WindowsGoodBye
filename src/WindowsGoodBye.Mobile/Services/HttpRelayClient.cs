using System.Net.Http.Json;
using System.Text.Json.Serialization;
using WindowsGoodBye.Core;

namespace WindowsGoodBye.Mobile.Services;

/// <summary>
/// HTTP client for the embedded relay's <c>/api/*</c> surface (docs/plan_push_auth_v2.md, "🛠️ Relay
/// HTTP Server Embebido — Diseño"). Started small in Fase 5 (only <see cref="UpdateFcmTokenAsync"/>,
/// needed by <c>FcmService.OnNewToken</c> when no direct transport was available) and extended in
/// Fase 6 with <see cref="RespondAsync"/>/<see cref="RejectAsync"/> for <c>PushAuthActivity</c>'s
/// number-matching confirm/reject flow — both built on the same <see cref="PostJsonAsync"/> primitive
/// so none of the three duplicate the HttpClient/JWT plumbing.
///
/// Not Android-specific (no Android APIs used) despite living under a Mobile-only build target —
/// kept under Services/ rather than Platforms/Android/ so it's trivially reusable if the project ever
/// grows other platform heads.
/// </summary>
public static class HttpRelayClient
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(15) };

    /// <summary>
    /// POST /api/auth/respond — Android's proof-of-possession reply for a push-auth challenge (Fase 6,
    /// <c>PushAuthActivity</c>), after the user confirmed number-matching AND passed
    /// <c>BiometricPrompt</c>. <paramref name="hmacBase64"/> must be
    /// <c>base64(PushAuthHmac.ComputeHmac(nonce, challengeTimestamp, responseTimestamp, sessionId, authKey))</c>
    /// — see docs/plan_push_auth_v2.md, "Anti-Replay-Delay: Timestamp Firmado".
    /// </summary>
    /// <param name="relayKey"><c>RelayKeyDerivation.DeriveRelayKey(pairedPc.DeviceKey)</c> — signs the request's JWT, NOT the response HMAC itself.</param>
    public static async Task<PushAuthRelayResult> RespondAsync(
        string relayBaseUrl, string sessionId, string deviceId, string hmacBase64, long responseTimestamp,
        byte[] relayKey, CancellationToken ct = default)
    {
        var jwt = JwtHelper.CreateToken(deviceId, sessionId, relayKey);
        var body = new RespondBody(sessionId, deviceId, hmacBase64, responseTimestamp, jwt);
        var response = await PostJsonAsync(relayBaseUrl, "/api/auth/respond", body, ct);
        return await PushAuthRelayResult.FromResponseAsync(response);
    }

    /// <summary>
    /// POST /api/auth/reject — explicit rejection ("No es mi PC" / number-matching failed), Fase 6.
    /// Distinct from just letting the session time out — see "🛡️ Defensa contra Push Fatigue": the
    /// relay marks the session <c>rejected</c> (not <c>expired</c>), so the CP can show a stronger
    /// "Solicitud rechazada desde el teléfono" instead of a generic timeout.
    /// </summary>
    public static async Task<PushAuthRelayResult> RejectAsync(
        string relayBaseUrl, string sessionId, string deviceId, string? reason, byte[] relayKey, CancellationToken ct = default)
    {
        var jwt = JwtHelper.CreateToken(deviceId, sessionId, relayKey);
        var body = new RejectBody(sessionId, deviceId, reason, jwt);
        var response = await PostJsonAsync(relayBaseUrl, "/api/auth/reject", body, ct);
        return await PushAuthRelayResult.FromResponseAsync(response);
    }

    /// <summary>
    /// POST /api/device/token — sync a rotated FCM registration token to a paired PC's relay when no
    /// direct transport (BT/TCP/UDP) is available. See docs/plan_push_auth_v2.md, "Rotación de FCM Token".
    /// </summary>
    /// <param name="relayBaseUrl">The PC's current public relay URL (e.g. "https://wingb-xxx.trycloudflare.com").</param>
    /// <param name="deviceId">This phone's device_id for that specific PC pairing (matches <c>PairedPc.DeviceId</c>).</param>
    /// <param name="newToken">The freshly rotated FCM registration token.</param>
    /// <param name="relayKey">
    /// <c>RelayKeyDerivation.DeriveRelayKey(pairedPc.DeviceKey)</c> — used to sign the short-lived JWT
    /// the relay's JWT-validation middleware requires on every endpoint except <c>/api/health</c>.
    /// </param>
    public static async Task<bool> UpdateFcmTokenAsync(
        string relayBaseUrl, string deviceId, string newToken, byte[] relayKey, CancellationToken ct = default)
    {
        // /api/device/token isn't scoped to a push-auth session, so there's no real session_id to bind
        // the JWT to — the relay's JWT middleware only checks sub==device_id for this endpoint (see
        // RelayServer.UpdateFcmTokenEndpoint, which never calls MatchesValidatedSession). A fixed,
        // descriptive placeholder "sid" is fine.
        var jwt = JwtHelper.CreateToken(deviceId, "device-token-update", relayKey);

        var request = new TokenUpdateBody(deviceId, newToken, jwt);
        var response = await PostJsonAsync(relayBaseUrl, "/api/device/token", request, ct);
        return response.IsSuccessStatusCode;
    }

    /// <summary>Generic reusable POST helper — Fase 6 builds <c>/api/auth/respond</c>/<c>/reject</c> on top of this.</summary>
    public static Task<HttpResponseMessage> PostJsonAsync(
        string relayBaseUrl, string path, object body, CancellationToken ct = default)
    {
        var url = CombineUrl(relayBaseUrl, path);
        return Http.PostAsJsonAsync(url, body, ct);
    }

    private static string CombineUrl(string baseUrl, string path) =>
        baseUrl.TrimEnd('/') + (path.StartsWith('/') ? path : "/" + path);

    private sealed class TokenUpdateBody
    {
        public TokenUpdateBody(string deviceId, string token, string jwt)
        {
            DeviceId = deviceId;
            Token = token;
            Jwt = jwt;
        }

        [JsonPropertyName("device_id")] public string DeviceId { get; }
        [JsonPropertyName("token")] public string Token { get; }
        [JsonPropertyName("jwt")] public string Jwt { get; }
    }

    /// <summary>Wire shape matches the relay's <c>RespondRequest</c> DTO (WindowsGoodBye.Service.RelayModels) exactly.</summary>
    private sealed class RespondBody
    {
        public RespondBody(string sessionId, string deviceId, string hmac, long responseTimestamp, string jwt)
        {
            SessionId = sessionId;
            DeviceId = deviceId;
            Hmac = hmac;
            ResponseTimestamp = responseTimestamp;
            Jwt = jwt;
        }

        [JsonPropertyName("session_id")] public string SessionId { get; }
        [JsonPropertyName("device_id")] public string DeviceId { get; }
        [JsonPropertyName("hmac")] public string Hmac { get; }
        [JsonPropertyName("response_ts")] public long ResponseTimestamp { get; }
        [JsonPropertyName("jwt")] public string Jwt { get; }
    }

    /// <summary>Wire shape matches the relay's <c>RejectRequest</c> DTO (WindowsGoodBye.Service.RelayModels) exactly.</summary>
    private sealed class RejectBody
    {
        public RejectBody(string sessionId, string deviceId, string? reason, string jwt)
        {
            SessionId = sessionId;
            DeviceId = deviceId;
            Reason = reason;
            Jwt = jwt;
        }

        [JsonPropertyName("session_id")] public string SessionId { get; }
        [JsonPropertyName("device_id")] public string DeviceId { get; }
        [JsonPropertyName("reason")] public string? Reason { get; }
        [JsonPropertyName("jwt")] public string Jwt { get; }
    }
}

/// <summary>
/// Outcome of a <see cref="HttpRelayClient.RespondAsync"/>/<see cref="HttpRelayClient.RejectAsync"/>
/// call — a bit more than a bare bool so <c>PushAuthActivity</c> can distinguish "the relay is
/// unreachable/misbehaving" (network error, non-2xx) from "the relay explicitly said no" (e.g. the
/// session already expired or hit its 5-attempt cap — see "🛡️ Rate Limiting en el Relay") without
/// parsing the response body itself.
/// </summary>
public sealed record PushAuthRelayResult(bool Success, int StatusCode, string? Body)
{
    public static async Task<PushAuthRelayResult> FromResponseAsync(HttpResponseMessage response)
    {
        string? body = null;
        try { body = await response.Content.ReadAsStringAsync(); }
        catch { /* best-effort — never let reading the body for diagnostics throw */ }
        return new PushAuthRelayResult(response.IsSuccessStatusCode, (int)response.StatusCode, body);
    }
}
