using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace WindowsGoodBye.Service;

/// <summary>
/// Sends Firebase Cloud Messaging (FCM) push notifications to wake the Android device
/// when the PC lock screen activates and needs authentication.
///
/// Supports both FCM v1 API (OAuth2) and legacy API (server key).
/// Configuration is loaded from fcm_config.json beside the service executable.
///
/// Setup:
/// 1. Create a Firebase project at https://console.firebase.google.com
/// 2. Add an Android app with package name: com.windowsgoodbye.mobile
/// 3. Download google-services.json and place it in the Android project's Platforms/Android/
/// 4. For the Windows service, create fcm_config.json with:
///    { "serverKey": "YOUR_FCM_LEGACY_SERVER_KEY" }
///    OR for v1 API:
///    { "projectId": "your-project-id", "serviceAccountJson": "path/to/serviceaccount.json" }
/// </summary>
public class FcmPushSender
{
    private readonly ILogger<FcmPushSender> _logger;
    private readonly HttpClient _http;
    private string? _serverKey;
    private string? _projectId;
    private bool _initialized;

    private static readonly string ConfigPath = Path.Combine(
        AppContext.BaseDirectory, "fcm_config.json");

    public FcmPushSender(ILogger<FcmPushSender> logger)
    {
        _logger = logger;
        _http = new HttpClient();
        LoadConfig();
    }

    /// <summary>Whether FCM is configured and available.</summary>
    public bool IsAvailable => _initialized && !string.IsNullOrEmpty(_serverKey);

    private void LoadConfig()
    {
        try
        {
            if (!File.Exists(ConfigPath))
            {
                _logger.LogInformation("FCM not configured (no {Path}). Push notifications disabled.", ConfigPath);
                return;
            }

            var json = File.ReadAllText(ConfigPath);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            if (root.TryGetProperty("serverKey", out var keyProp))
            {
                _serverKey = keyProp.GetString();
            }

            if (root.TryGetProperty("projectId", out var projProp))
            {
                _projectId = projProp.GetString();
            }

            _initialized = !string.IsNullOrEmpty(_serverKey);

            if (_initialized)
                _logger.LogInformation("FCM configured with legacy server key");
            else
                _logger.LogWarning("FCM config found but no serverKey. Push notifications disabled.");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to load FCM config: {Msg}", ex.Message);
        }
    }

    /// <summary>
    /// Send a push notification to wake the Android device for authentication.
    /// Uses FCM legacy HTTP API for simplicity.
    /// </summary>
    /// <param name="fcmToken">The device's FCM registration token.</param>
    /// <param name="pcName">Name of the PC requesting auth.</param>
    public async Task<bool> SendAuthWakeAsync(string fcmToken, string pcName)
    {
        if (!IsAvailable)
        {
            _logger.LogDebug("FCM not available, skipping push");
            return false;
        }

        try
        {
            var payload = new
            {
                to = fcmToken,
                priority = "high",
                data = new
                {
                    action = "auth_wake",
                    pc_name = pcName,
                    timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()
                }
            };

            var json = JsonSerializer.Serialize(payload);
            var request = new HttpRequestMessage(HttpMethod.Post, "https://fcm.googleapis.com/fcm/send")
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json")
            };
            request.Headers.Authorization = new AuthenticationHeaderValue("key", $"={_serverKey}");

            var response = await _http.SendAsync(request);
            var responseBody = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                _logger.LogInformation("FCM push sent to {Token} for {PC}: {Response}",
                    fcmToken[..20] + "...", pcName, responseBody);
                return true;
            }
            else
            {
                _logger.LogWarning("FCM push failed: {Status} {Body}",
                    response.StatusCode, responseBody);
                return false;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "FCM send error: {Msg}", ex.Message);
            return false;
        }
    }
}
