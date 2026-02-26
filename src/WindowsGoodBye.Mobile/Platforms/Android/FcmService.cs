using Android.App;
using Android.Content;
using Firebase.Messaging;
using WindowsGoodBye.Mobile.Data;

namespace WindowsGoodBye.Mobile.Platforms.Android;

/// <summary>
/// Firebase Cloud Messaging service that receives push notifications from the Windows PC.
/// When the PC locks and needs authentication, it sends an FCM push that wakes this service
/// even if the app was force-stopped. The service then starts the foreground service
/// which connects to the PC and handles the auth flow.
/// </summary>
[Service(Name = "com.windowsgoodbye.mobile.FcmService", Exported = false)]
[IntentFilter(new[] { "com.google.firebase.MESSAGING_EVENT" })]
public class FcmService : FirebaseMessagingService
{
    /// <summary>
    /// Called when the FCM token is refreshed. Save it to the database
    /// so it can be sent to the PC during pairing.
    /// </summary>
    public override void OnNewToken(string token)
    {
        base.OnNewToken(token);
        System.Diagnostics.Debug.WriteLine($"[FCM] New token: {token[..20]}...");
        SaveToken(token);
    }

    /// <summary>
    /// Called when a data message is received from the PC.
    /// Starts the foreground service if not running, which will
    /// auto-reconnect and handle the auth flow.
    /// </summary>
    public override void OnMessageReceived(RemoteMessage message)
    {
        base.OnMessageReceived(message);

        var data = message.Data;
        if (data == null) return;

        System.Diagnostics.Debug.WriteLine($"[FCM] Message received: {string.Join(", ", data.Keys)}");

        if (data.TryGetValue("action", out var action) && action == "auth_wake")
        {
            var pcName = data.TryGetValue("pc_name", out var name) ? name : "PC";
            System.Diagnostics.Debug.WriteLine($"[FCM] Auth wake from {pcName}");

            // Start the foreground service (it will auto-reconnect and handle auth)
            AuthForegroundService.StartService(ApplicationContext!);

            // Also show a notification to bring the user's attention
            AuthForegroundService.Instance?.ShowAuthPromptNotification(pcName);
        }
    }

    private void SaveToken(string token)
    {
        try
        {
            using var db = new MobileDatabase();
            db.Initialize();

            // Store the FCM token as a simple key-value setting
            var existing = db.Settings.FirstOrDefault(s => s.Key == "fcm_token");
            if (existing != null)
            {
                existing.Value = token;
            }
            else
            {
                db.Settings.Add(new AppSetting { Key = "fcm_token", Value = token });
            }
            db.SaveChanges();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[FCM] Save token error: {ex.Message}");
        }
    }

    /// <summary>Get the current FCM token from the database.</summary>
    public static string? GetTokenFromDb()
    {
        try
        {
            using var db = new MobileDatabase();
            db.Initialize();
            return db.Settings.FirstOrDefault(s => s.Key == "fcm_token")?.Value;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[FCM] GetToken error: {ex.Message}");
            return null;
        }
    }

    /// <summary>Request a fresh FCM token (fires OnNewToken when ready).</summary>
    public static void RequestToken()
    {
        try
        {
            // Just calling GetToken() triggers OnNewToken callback if needed
            FirebaseMessaging.Instance.GetToken();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[FCM] RequestToken error: {ex.Message}");
        }
    }
}
