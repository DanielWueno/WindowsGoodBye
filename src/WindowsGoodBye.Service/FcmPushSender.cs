using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Configuration;
using WindowsGoodBye.Core;

namespace WindowsGoodBye.Service;

/// <summary>
/// Sends Firebase Cloud Messaging (FCM) push notifications to wake the Android device
/// when the PC lock screen activates and needs authentication.
///
/// Uses the FCM HTTP v1 API (OAuth2 service-account auth) — the legacy "server key" API this class
/// used previously (<c>https://fcm.googleapis.com/fcm/send</c> with an "Authorization: key=..."
/// header) is deprecated/shut down by Google. See docs/plan_push_auth_v2.md, Fase 0.
///
/// Configuration (checked in this order):
///  1. appsettings.json: <c>{ "Fcm": { "ProjectId": "...", "ServiceAccountJsonPath": "..." } }</c>
///  2. Environment variables: <c>Fcm__ProjectId</c>, <c>Fcm__ServiceAccountJsonPath</c>
///     (standard .NET configuration env-var binding — Host.CreateDefaultBuilder already wires this up)
///  3. Legacy fallback: <c>fcm_config.json</c> beside the Service executable, with
///     <c>{ "projectId": "...", "serviceAccountJson": "path/to/serviceaccount.json" }</c>
///     (kept only for continuity with existing installs; logs a deprecation notice when used).
///
/// <c>ServiceAccountJsonPath</c> may be absolute, or relative to the Service's base directory.
/// The referenced file is the standard Google Cloud service-account key JSON downloaded from the
/// Firebase/GCP console, with at least "client_email" and "private_key".
///
/// Setup:
/// 1. Create a Firebase project at https://console.firebase.google.com
/// 2. Add an Android app with package name: com.windowsgoodbye.mobile
/// 3. Download google-services.json and place it in the Android project's Platforms/Android/
/// 4. In the Firebase console: Project Settings -> Service Accounts -> Generate new private key.
///    Save the downloaded JSON somewhere the Service can read, and point ServiceAccountJsonPath at it.
/// </summary>
public class FcmPushSender
{
    private const string FcmMessagingScope = "https://www.googleapis.com/auth/firebase.messaging";
    private const string OAuthTokenEndpoint = "https://oauth2.googleapis.com/token";

    private static readonly string LegacyConfigPath = Path.Combine(
        AppContext.BaseDirectory, "fcm_config.json");

    private readonly ILogger<FcmPushSender> _logger;
    private readonly HttpClient _http;

    private string? _projectId;
    private GoogleServiceAccount? _serviceAccount;
    private GoogleOAuthTokenProvider? _tokenProvider;
    private bool _initialized;

    public FcmPushSender(ILogger<FcmPushSender> logger, IConfiguration configuration)
    {
        _logger = logger;
        _http = new HttpClient();
        LoadConfig(configuration);
    }

    /// <summary>Whether FCM v1 is configured (project id + a loadable service account) and available.</summary>
    /// <remarks>
    /// Fase 13 (Testing): marked <c>virtual</c> (behavior unchanged) so a test-only subclass can fake
    /// "FCM is available" without a real service account/OAuth2 setup — see
    /// tests/WindowsGoodBye.Service.Tests/AuthWorkerRaceIntegrationTests.cs.
    /// </remarks>
    public virtual bool IsAvailable => _initialized && _serviceAccount != null && !string.IsNullOrEmpty(_projectId);

    private void LoadConfig(IConfiguration configuration)
    {
        try
        {
            var projectId = configuration["Fcm:ProjectId"];
            var serviceAccountPath = configuration["Fcm:ServiceAccountJsonPath"];

            if (string.IsNullOrEmpty(projectId) && string.IsNullOrEmpty(serviceAccountPath)
                && File.Exists(LegacyConfigPath))
            {
                _logger.LogWarning(
                    "Loading FCM config from legacy {Path}. This is deprecated — move ProjectId/" +
                    "ServiceAccountJsonPath into appsettings.json under an \"Fcm\" section, or set " +
                    "the Fcm__ProjectId / Fcm__ServiceAccountJsonPath environment variables.",
                    LegacyConfigPath);

                var json = File.ReadAllText(LegacyConfigPath);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                if (root.TryGetProperty("projectId", out var projProp))
                    projectId = projProp.GetString();
                if (root.TryGetProperty("serviceAccountJson", out var pathProp))
                    serviceAccountPath = pathProp.GetString();
            }

            if (string.IsNullOrEmpty(projectId) || string.IsNullOrEmpty(serviceAccountPath))
            {
                _logger.LogInformation(
                    "FCM not configured (missing ProjectId/ServiceAccountJsonPath). Push notifications disabled.");
                return;
            }

            var resolvedPath = Path.IsPathRooted(serviceAccountPath)
                ? serviceAccountPath
                : Path.Combine(AppContext.BaseDirectory, serviceAccountPath);

            if (!File.Exists(resolvedPath))
            {
                _logger.LogWarning("FCM service account file not found at {Path}. Push notifications disabled.", resolvedPath);
                return;
            }

            _serviceAccount = GoogleServiceAccount.LoadFromFile(resolvedPath);
            _projectId = projectId;
            _tokenProvider = new GoogleOAuthTokenProvider(_http, _serviceAccount, FcmMessagingScope, OAuthTokenEndpoint);
            _initialized = true;

            _logger.LogInformation("FCM v1 configured for project {ProjectId} (service account {Email})",
                _projectId, _serviceAccount.ClientEmail);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to load FCM config: {Msg}", ex.Message);
        }
    }

    /// <summary>
    /// Send a push notification to wake the Android device for authentication (Ruta B — legacy
    /// wake-up, prompts Android to reconnect over a direct transport rather than carrying a full
    /// push-auth challenge).
    /// </summary>
    /// <param name="fcmToken">The device's FCM registration token.</param>
    /// <param name="pcName">Name of the PC requesting auth.</param>
    public async Task<FcmSendResult> SendAuthWakeAsync(string fcmToken, string pcName)
    {
        var data = new Dictionary<string, string>
        {
            ["action"] = Protocol.FcmActionAuthWake,
            ["pc_name"] = pcName,
            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()
        };

        return await SendDataMessageAsync(fcmToken, data);
    }

    /// <summary>
    /// Send a full push-auth challenge (Ruta C — docs/plan_push_auth_v2.md, "📨 Flujo Completo de
    /// Seguridad" and "🛡️ Defensa contra Push Fatigue"). Built on top of <see cref="SendDataMessageAsync"/>
    /// rather than duplicating the OAuth2/HTTP v1 plumbing.
    /// </summary>
    /// <param name="fcmToken">The paired device's current FCM registration token.</param>
    /// <param name="sessionId">Relay session id this challenge is registered under (see <c>RelayServer.RegisterSessionDirect</c>).</param>
    /// <param name="deviceId">
    /// The device_id this specific PC assigned to the phone during pairing (<c>DeviceInfo.DeviceId</c>).
    /// NOT part of the plan's illustrative FCM payload listing, but Android needs it to know which
    /// locally-paired PC (and therefore which DeviceKey) this challenge belongs to — see
    /// docs/implementation_progress_push_auth_v2.md, Fase 3 notes, for why this was added.
    /// </param>
    /// <param name="encryptedNonceBlob">
    /// <c>nonce ‖ tag ‖ ciphertext</c> as produced by <see cref="CryptoUtils.EncryptGcmToBlob"/>
    /// (AES-256-GCM, key = DeviceKey, AAD = session_id) — sent as base64.
    /// </param>
    /// <param name="challengeTimestamp">When the challenge was generated (anti-replay-delay check, PC-side).</param>
    /// <param name="pcName">Friendly PC name shown on the phone.</param>
    /// <param name="relayUrl">Current public relay URL (Cloudflare Tunnel), or null if not yet known.</param>
    /// <param name="displayCode">Two-digit number-matching code (push fatigue defense).</param>
    /// <param name="attemptNumber">How many challenges have been generated in the current CP login session/window — shown as "contexto visible" per the plan.</param>
    public async Task<FcmSendResult> SendAuthChallengeAsync(
        string fcmToken,
        string sessionId,
        string deviceId,
        byte[] encryptedNonceBlob,
        DateTimeOffset challengeTimestamp,
        string pcName,
        string? relayUrl,
        string displayCode,
        int attemptNumber)
    {
        var data = new Dictionary<string, string>
        {
            ["action"] = Protocol.PushAuthChallenge,
            ["session_id"] = sessionId,
            ["device_id"] = deviceId,
            ["encrypted_nonce"] = Convert.ToBase64String(encryptedNonceBlob),
            ["challenge_ts"] = challengeTimestamp.ToUnixTimeSeconds().ToString(),
            ["pc_name"] = pcName,
            ["relay_url"] = relayUrl ?? "",
            ["display_code"] = displayCode,
            ["attempt_number"] = attemptNumber.ToString()
        };

        return await SendDataMessageAsync(fcmToken, data);
    }

    /// <summary>
    /// Send an arbitrary FCM data message (no notification payload — Android decides how/whether to
    /// surface it) using the HTTP v1 API. Shared by <see cref="SendAuthWakeAsync"/> and
    /// <see cref="SendAuthChallengeAsync"/>.
    /// </summary>
    /// <remarks>
    /// Fase 13 (Testing): marked <c>virtual</c> (behavior unchanged) so a test-only subclass can fake
    /// FCM send outcomes (success/token-invalid/failed) without ever calling the real
    /// oauth2.googleapis.com/fcm.googleapis.com endpoints — see
    /// tests/WindowsGoodBye.Service.Tests/AuthWorkerRaceIntegrationTests.cs.
    /// </remarks>
    public virtual async Task<FcmSendResult> SendDataMessageAsync(string fcmToken, IDictionary<string, string> data)
    {
        if (!IsAvailable)
        {
            _logger.LogDebug("FCM not available, skipping push");
            return FcmSendResult.NotConfigured;
        }

        string accessToken;
        try
        {
            accessToken = await _tokenProvider!.GetAccessTokenAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to obtain FCM OAuth2 access token: {Msg}", ex.Message);
            return FcmSendResult.Failed;
        }

        try
        {
            var payload = new
            {
                message = new
                {
                    token = fcmToken,
                    data,
                    android = new { priority = "high" }
                }
            };

            var json = JsonSerializer.Serialize(payload);
            var url = $"https://fcm.googleapis.com/v1/projects/{_projectId}/messages:send";
            var request = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json")
            };
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            var response = await _http.SendAsync(request);
            var responseBody = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                _logger.LogInformation("FCM v1 push sent to {Token}: {Response}",
                    MaskToken(fcmToken), responseBody);
                return FcmSendResult.Success;
            }

            // FCM v1 reports a rotated/invalid token as HTTP 404 with errorCode "UNREGISTERED"
            // (previously "registration-token-not-registered" in the legacy API).
            var isUnregistered = response.StatusCode == System.Net.HttpStatusCode.NotFound
                || responseBody.Contains("UNREGISTERED", StringComparison.OrdinalIgnoreCase);

            if (isUnregistered)
            {
                _logger.LogWarning("FCM token unregistered/invalid for {Token}: {Status} {Body}",
                    MaskToken(fcmToken), response.StatusCode, responseBody);
                return FcmSendResult.TokenInvalid;
            }

            _logger.LogWarning("FCM push failed: {Status} {Body}", response.StatusCode, responseBody);
            return FcmSendResult.Failed;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "FCM send error: {Msg}", ex.Message);
            return FcmSendResult.Failed;
        }
    }

    private static string MaskToken(string token) =>
        token.Length > 20 ? token[..20] + "..." : token;
}

/// <summary>Outcome of an FCM v1 send attempt.</summary>
public enum FcmSendResult
{
    Success,
    /// <summary>FCM reported the token as unregistered/rotated (HTTP 404 / "UNREGISTERED").
    /// Callers should mark <c>DeviceInfo.FcmTokenValid = false</c> — see docs/plan_push_auth_v2.md,
    /// "FCM: Manejo de Fallos" (this wiring happens in AuthWorker, Fase 3).</summary>
    TokenInvalid,
    Failed,
    NotConfigured
}

/// <summary>Minimal parsed representation of a Google service-account key JSON file.</summary>
internal sealed class GoogleServiceAccount
{
    public required string ClientEmail { get; init; }
    public required string PrivateKeyPem { get; init; }
    public string? TokenUri { get; init; }

    public static GoogleServiceAccount LoadFromFile(string path)
    {
        var json = File.ReadAllText(path);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        var clientEmail = root.GetProperty("client_email").GetString()
            ?? throw new InvalidDataException("Service account JSON missing 'client_email'");
        var privateKey = root.GetProperty("private_key").GetString()
            ?? throw new InvalidDataException("Service account JSON missing 'private_key'");
        var tokenUri = root.TryGetProperty("token_uri", out var t) ? t.GetString() : null;

        return new GoogleServiceAccount
        {
            ClientEmail = clientEmail,
            PrivateKeyPem = privateKey,
            TokenUri = tokenUri
        };
    }
}

/// <summary>
/// Obtains and caches OAuth2 access tokens for a Google service account using the JWT Bearer grant
/// (RFC 7523) — this is the standard "server-to-server" flow Google service accounts use, hand-rolled
/// here (RS256 JWT assertion signed with the service account's RSA private key) to avoid pulling in
/// the full Google.Apis.Auth dependency tree for a single OAuth call.
/// </summary>
internal sealed class GoogleOAuthTokenProvider
{
    private readonly HttpClient _http;
    private readonly GoogleServiceAccount _account;
    private readonly string _scope;
    private readonly string _tokenEndpoint;

    private readonly SemaphoreSlim _lock = new(1, 1);
    private string? _cachedToken;
    private DateTimeOffset _cachedTokenExpiresAt = DateTimeOffset.MinValue;

    // Refresh a bit before actual expiry to avoid racing a request against token expiration.
    private static readonly TimeSpan RefreshMargin = TimeSpan.FromMinutes(2);

    public GoogleOAuthTokenProvider(HttpClient http, GoogleServiceAccount account, string scope, string tokenEndpoint)
    {
        _http = http;
        _account = account;
        _scope = scope;
        _tokenEndpoint = string.IsNullOrEmpty(account.TokenUri) ? tokenEndpoint : account.TokenUri;
    }

    public async Task<string> GetAccessTokenAsync()
    {
        if (_cachedToken != null && DateTimeOffset.UtcNow < _cachedTokenExpiresAt - RefreshMargin)
            return _cachedToken;

        await _lock.WaitAsync();
        try
        {
            if (_cachedToken != null && DateTimeOffset.UtcNow < _cachedTokenExpiresAt - RefreshMargin)
                return _cachedToken;

            var assertion = BuildSignedJwtAssertion();

            var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "urn:ietf:params:oauth:grant-type:jwt-bearer",
                ["assertion"] = assertion
            });

            using var response = await _http.PostAsync(_tokenEndpoint, form);
            var body = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
                throw new InvalidOperationException($"OAuth2 token request failed: {response.StatusCode} {body}");

            var tokenResponse = JsonSerializer.Deserialize<GoogleTokenResponse>(body)
                ?? throw new InvalidOperationException("OAuth2 token response was empty/malformed");

            _cachedToken = tokenResponse.AccessToken;
            _cachedTokenExpiresAt = DateTimeOffset.UtcNow.AddSeconds(tokenResponse.ExpiresIn);
            return _cachedToken;
        }
        finally
        {
            _lock.Release();
        }
    }

    private string BuildSignedJwtAssertion()
    {
        var now = DateTimeOffset.UtcNow;
        var iat = now.ToUnixTimeSeconds();
        var exp = now.AddHours(1).ToUnixTimeSeconds(); // Google caps JWT assertion lifetime at 1 hour

        var header = new { alg = "RS256", typ = "JWT" };
        var claims = new
        {
            iss = _account.ClientEmail,
            scope = _scope,
            aud = _tokenEndpoint,
            iat,
            exp
        };

        var headerSegment = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(header));
        var claimsSegment = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(claims));
        var signingInput = $"{headerSegment}.{claimsSegment}";

        using var rsa = RSA.Create();
        rsa.ImportFromPem(_account.PrivateKeyPem);
        var signature = rsa.SignData(
            Encoding.UTF8.GetBytes(signingInput), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return $"{signingInput}.{Base64UrlEncode(signature)}";
    }

    private static string Base64UrlEncode(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private sealed class GoogleTokenResponse
    {
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; } = "";

        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; }
    }
}
