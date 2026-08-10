using Android.App;
using Android.Content;
using Firebase.Messaging;
using WindowsGoodBye.Core;
using WindowsGoodBye.Mobile.Data;
using WindowsGoodBye.Mobile.Services;

namespace WindowsGoodBye.Mobile.Platforms.Android;

/// <summary>
/// Firebase Cloud Messaging service that receives push notifications from the Windows PC.
/// When the PC locks and needs authentication, it sends an FCM push that wakes this service
/// even if the app was force-stopped. The service then starts the foreground service
/// which connects to the PC and handles the auth flow.
///
/// Fase 5 (docs/plan_push_auth_v2.md, "Android — Recepción de Challenge Push") adds handling for the
/// full push-auth challenge ("auth_challenge", Ruta C) alongside the pre-existing legacy wake-up
/// ("auth_wake", Ruta B), and fixes a timing bug in how both used to hand data to
/// <see cref="AuthForegroundService"/> — see <see cref="AuthForegroundService.StartForAuthWake"/> /
/// <see cref="AuthForegroundService.StartForPushChallenge"/>.
/// </summary>
[Service(Name = "com.windowsgoodbye.mobile.FcmService", Exported = false)]
[IntentFilter(new[] { "com.google.firebase.MESSAGING_EVENT" })]
public class FcmService : FirebaseMessagingService
{
    /// <summary>
    /// Called when the FCM token is refreshed. Save it locally and try to sync it to every paired PC —
    /// see docs/plan_push_auth_v2.md, "🔄 Rotación de FCM Token".
    /// </summary>
    public override void OnNewToken(string token)
    {
        base.OnNewToken(token);
        System.Diagnostics.Debug.WriteLine($"[FCM] New token: {token[..Math.Min(20, token.Length)]}...");
        SaveToken(token);
        _ = SyncTokenToPairedPcsAsync(token);
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

        if (!data.TryGetValue("action", out var action)) return;

        if (action == Protocol.FcmActionAuthWake)
        {
            var pcName = data.TryGetValue("pc_name", out var name) ? name : "PC";
            System.Diagnostics.Debug.WriteLine($"[FCM] Auth wake from {pcName}");

            // Start the foreground service AND show the notification atomically from within its own
            // OnStartCommand (Intent extras) — see the class XML doc re: the timing-bug fix. The old
            // code called AuthForegroundService.Instance?.ShowAuthPromptNotification(pcName)
            // immediately after StartService(), which could race ahead of OnStartCommand actually
            // running and setting Instance, silently dropping the notification.
            AuthForegroundService.StartForAuthWake(ApplicationContext!, pcName);
        }
        else if (action == Protocol.PushAuthChallenge)
        {
            var info = PushAuthChallengeInfo.FromFcmData(data);
            if (info == null)
            {
                System.Diagnostics.Debug.WriteLine("[FCM] auth_challenge payload missing required fields, ignoring");
                return;
            }

            System.Diagnostics.Debug.WriteLine(
                $"[FCM] Push-auth challenge from {info.PcName} (session {info.SessionId}, attempt #{info.AttemptNumber})");

            TryUpdateRelayUrl(info.DeviceId, info.RelayUrl);

            // Same fix as auth_wake above: pass the whole challenge via Intent extras, let
            // AuthForegroundService show the notification from within its own OnStartCommand.
            AuthForegroundService.StartForPushChallenge(ApplicationContext!, info);
        }
    }

    /// <summary>Opportunistically remember the PC's current relay URL — see <c>PairedPc.RelayUrl</c>.</summary>
    private static void TryUpdateRelayUrl(string deviceId, string? relayUrl)
    {
        if (string.IsNullOrEmpty(relayUrl)) return;
        try
        {
            using var db = new MobileDatabase();
            db.Initialize();
            var pc = db.PairedPcs.FirstOrDefault(p => p.DeviceId == deviceId && p.IsPaired);
            if (pc != null && pc.RelayUrl != relayUrl)
            {
                pc.RelayUrl = relayUrl;
                db.SaveChanges();
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[FCM] RelayUrl sync error: {ex.Message}");
        }
    }

    /// <summary>
    /// Sync a rotated FCM token to every paired PC: over the active direct transport if one is
    /// connected, otherwise via the relay's <c>/api/device/token</c> endpoint if we know that PC's
    /// relay URL. If neither is available right now, the PC will pick up the new token next time a
    /// direct transport connects (see docs/plan_push_auth_v2.md, "Manejo del gap de sincronización").
    /// </summary>
    private static async Task SyncTokenToPairedPcsAsync(string token)
    {
        try
        {
            using var db = new MobileDatabase();
            db.Initialize();
            var pcs = db.PairedPcs.Where(p => p.IsPaired).ToList();

            foreach (var pc in pcs)
            {
                if (!Guid.TryParse(pc.DeviceId, out var deviceIdGuid)) continue;

                try
                {
                    if (AuthListener.Instance.IsTransportConnected)
                    {
                        // Best-effort: only reaches whichever PC is actually on the other end of the
                        // single active direct-transport connection today. Harmless for the others —
                        // AuthWorker.HandleTokenUpdate silently no-ops if the embedded device_id isn't
                        // one of ITS OWN paired devices. See docs/implementation_progress_push_auth_v2.md.
                        await AuthListener.Instance.SendTokenUpdateAsync(deviceIdGuid, pc.DeviceKey, token);
                    }
                    else if (!string.IsNullOrEmpty(pc.RelayUrl))
                    {
                        var relayKey = RelayKeyDerivation.DeriveRelayKey(pc.DeviceKey);
                        await HttpRelayClient.UpdateFcmTokenAsync(pc.RelayUrl!, pc.DeviceId, token, relayKey);
                    }
                    // else: no known way to reach this PC right now.
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[FCM] Token sync failed for {pc.PcName}: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[FCM] SyncTokenToPairedPcsAsync error: {ex.Message}");
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
