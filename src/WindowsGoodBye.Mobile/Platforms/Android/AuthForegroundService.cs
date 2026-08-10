using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.Net.Wifi;
using Android.OS;
using AndroidX.Core.App;
using WindowsGoodBye.Mobile.Services;

namespace WindowsGoodBye.Mobile.Platforms.Android;

/// <summary>
/// Android foreground service that keeps the AuthListener alive.
/// Uses a partial wake lock to prevent CPU sleep, multicast lock for UDP,
/// and auto-reconnect to maintain connection even when the screen is off.
/// </summary>
[Service(
    Name = "com.windowsgoodbye.mobile.AuthForegroundService",
    ForegroundServiceType = ForegroundService.TypeConnectedDevice,
    Exported = false)]
public class AuthForegroundService : Service
{
    private const int NotificationId = 5135;
    private const string ChannelId = "wingb_auth_channel";
    public const string AuthPromptChannelId = "wingb_auth_prompt_channel";
    public const int AuthPromptNotificationId = 5136;

    // --- Intent extras used to pass notification requests in (fixes the Fase 5 timing bug — see
    // HandlePendingNotificationIntent below) ---
    private const string ExtraNotifyKind = "wingb.notify_kind";
    private const string NotifyKindAuthWake = "auth_wake";
    private const string NotifyKindPushChallenge = "auth_challenge";
    private const string ExtraPcName = "wingb.pc_name";

    private WifiManager.MulticastLock? _multicastLock;
    private PowerManager.WakeLock? _wakeLock;

    /// <summary>Singleton reference for posting notifications from AuthListener.</summary>
    public static AuthForegroundService? Instance { get; private set; }

    public override IBinder? OnBind(Intent? intent) => null;

    public override StartCommandResult OnStartCommand(Intent? intent, StartCommandFlags flags, int startId)
    {
        Instance = this;
        CreateNotificationChannels();

        var notification = BuildServiceNotification("Listening for PC unlock requests...");
        StartForeground(NotificationId, notification, ForegroundService.TypeConnectedDevice);

        // Acquire partial wake lock - keeps CPU running when screen is off
        var powerManager = (PowerManager?)GetSystemService(PowerService);
        if (powerManager != null)
        {
            _wakeLock = powerManager.NewWakeLock(WakeLockFlags.Partial, "WindowsGoodBye::AuthService");
            _wakeLock.Acquire();
        }

        // Acquire multicast lock - required on Android to receive UDP multicast
        var wifiManager = (WifiManager?)GetSystemService(WifiService);
        if (wifiManager != null)
        {
            _multicastLock = wifiManager.CreateMulticastLock("WindowsGoodBye");
            _multicastLock.SetReferenceCounted(false);
            _multicastLock.Acquire();
        }

        // Start the cross-platform listener (with auto-reconnect enabled)
        AuthListener.Instance.Start();

        // Show any notification requested by the caller (FcmService) — see
        // HandlePendingNotificationIntent's XML doc for why this replaces the old
        // "StartService(); Instance?.ShowXxx();" two-step pattern.
        HandlePendingNotificationIntent(intent);

        return StartCommandResult.Sticky;
    }

    /// <summary>
    /// Fase 5 timing-bug fix (docs/plan_push_auth_v2.md): callers used to do
    /// <c>AuthForegroundService.StartService(ctx); AuthForegroundService.Instance?.ShowAuthPromptNotification(pcName);</c>
    /// immediately after each other. <c>StartService</c>/<c>StartForegroundService</c> only *schedules*
    /// <see cref="OnStartCommand"/> to run — it does not run synchronously — so the second line could
    /// (and sometimes did) execute before <c>Instance</c> was set, silently dropping the notification.
    /// Fix: never read <c>Instance</c> from outside. Callers pass what to show as Intent extras via
    /// <see cref="StartForAuthWake"/>/<see cref="StartForPushChallenge"/>, and this method — which only
    /// ever runs from within this service's own <see cref="OnStartCommand"/>, after <c>Instance = this</c>
    /// above — is the sole place that decides whether/what to show.
    /// </summary>
    private void HandlePendingNotificationIntent(Intent? intent)
    {
        if (intent == null) return;

        switch (intent.GetStringExtra(ExtraNotifyKind))
        {
            case NotifyKindAuthWake:
                var pcName = intent.GetStringExtra(ExtraPcName) ?? "PC";
                ShowAuthPromptNotification(pcName);
                break;

            case NotifyKindPushChallenge:
                var info = PushAuthChallengeInfo.FromIntent(intent);
                if (info != null)
                    ShowPushAuthChallengeNotification(info);
                break;
        }
    }

    public override void OnDestroy()
    {
        Instance = null;
        AuthListener.Instance.Stop();

        if (_multicastLock?.IsHeld == true)
            _multicastLock.Release();

        if (_wakeLock?.IsHeld == true)
            _wakeLock.Release();

        base.OnDestroy();
    }

    /// <summary>Update the foreground notification text (e.g. transport status).</summary>
    public void UpdateNotification(string text)
    {
        var notification = BuildServiceNotification(text);
        var nm = (NotificationManager?)GetSystemService(NotificationService);
        nm?.Notify(NotificationId, notification);
    }

    private Notification BuildServiceNotification(string text)
    {
        return new NotificationCompat.Builder(this, ChannelId)
            .SetContentTitle("WindowsGoodBye")
            .SetContentText(text)
            .SetSmallIcon(global::Android.Resource.Drawable.IcLockIdleLock)
            .SetOngoing(true)
            .SetPriority(NotificationCompat.PriorityLow)
            .Build();
    }

    private void CreateNotificationChannels()
    {
        if (Build.VERSION.SdkInt < BuildVersionCodes.O) return;

        var notificationManager = (NotificationManager?)GetSystemService(NotificationService);

        // Low-priority channel for the persistent service notification
        var serviceChannel = new NotificationChannel(ChannelId, "Auth Listener", NotificationImportance.Low)
        {
            Description = "Required to listen for PC unlock requests"
        };
        notificationManager?.CreateNotificationChannel(serviceChannel);

        // High-priority channel for auth prompts (shows over lock screen like a phone call)
        var authChannel = new NotificationChannel(AuthPromptChannelId, "Unlock Requests", NotificationImportance.High)
        {
            Description = "Shows when your PC needs fingerprint unlock",
            LockscreenVisibility = NotificationVisibility.Public
        };
        authChannel.SetBypassDnd(true);
        authChannel.EnableVibration(true);
        authChannel.EnableLights(true);
        notificationManager?.CreateNotificationChannel(authChannel);
    }

    /// <summary>
    /// Show a high-priority full-screen notification to prompt biometric auth.
    /// This works even when the phone is locked or the app is in background.
    /// </summary>
    public void ShowAuthPromptNotification(string pcName)
    {
        // Intent to bring the app to foreground when notification is tapped
        var launchIntent = new Intent(this, typeof(MainActivity));
        launchIntent.SetFlags(ActivityFlags.NewTask | ActivityFlags.ClearTop | ActivityFlags.SingleTop);
        launchIntent.PutExtra("auth_prompt", true);
        launchIntent.PutExtra("pc_name", pcName);

        var pendingIntent = PendingIntent.GetActivity(
            this, 0, launchIntent,
            PendingIntentFlags.UpdateCurrent | PendingIntentFlags.Immutable);

        var notification = new NotificationCompat.Builder(this, AuthPromptChannelId)
            .SetContentTitle("🔓 PC Unlock Request")
            .SetContentText($"{pcName} needs your fingerprint")
            .SetSmallIcon(global::Android.Resource.Drawable.IcDialogInfo)
            .SetPriority(NotificationCompat.PriorityHigh)
            .SetCategory(NotificationCompat.CategoryCall)
            .SetAutoCancel(true)
            .SetFullScreenIntent(pendingIntent, true)  // Shows over lock screen
            .SetContentIntent(pendingIntent)
            .SetVisibility(NotificationCompat.VisibilityPublic)
            .SetVibrate(new long[] { 0, 250, 250, 250 })
            .SetTimeoutAfter(30000)  // Auto dismiss after 30 seconds
            .Build();

        var nm = (NotificationManager?)GetSystemService(NotificationService);
        nm?.Notify(AuthPromptNotificationId, notification);
    }

    /// <summary>Dismiss the auth prompt notification.</summary>
    public void DismissAuthPromptNotification()
    {
        var nm = (NotificationManager?)GetSystemService(NotificationService);
        nm?.Cancel(AuthPromptNotificationId);
    }

    /// <summary>
    /// Show a push-auth (Ruta C) challenge notification — heads-up, NOT full-screen. Per
    /// docs/plan_push_auth_v2.md, "📱 UX en Android Moderno": deliberately does NOT call
    /// <c>SetFullScreenIntent</c> (unlike the legacy <see cref="ShowAuthPromptNotification"/> above) —
    /// a high-priority notification on a high-importance channel is already a heads-up notification on
    /// Android 13-15 without needing <c>USE_FULL_SCREEN_INTENT</c>. The user unlocks the phone and taps
    /// it, same as Google Prompt. Tapping opens Fase 6's <c>PushAuthActivity</c> (not yet implemented —
    /// referenced by component name only, so this compiles and works today for everything up to the
    /// tap; Fase 6 supplies the activity itself).
    /// </summary>
    public void ShowPushAuthChallengeNotification(PushAuthChallengeInfo info)
    {
        var launchIntent = new Intent();
        launchIntent.SetClassName(PackageName!, "com.windowsgoodbye.mobile.PushAuthActivity");
        launchIntent.SetFlags(ActivityFlags.NewTask | ActivityFlags.ClearTop | ActivityFlags.SingleTop);
        info.WriteToIntent(launchIntent);

        var notificationId = NotificationIdForSession(info.SessionId);
        var pendingIntent = PendingIntent.GetActivity(
            this, notificationId, launchIntent,
            PendingIntentFlags.UpdateCurrent | PendingIntentFlags.Immutable);

        var attemptSuffix = info.AttemptNumber > 1
            ? $" · intento #{info.AttemptNumber} en los últimos minutos"
            : "";

        var notification = new NotificationCompat.Builder(this, AuthPromptChannelId)
            .SetContentTitle("🔐 ¿Eres tú?")
            .SetContentText($"{info.PcName} quiere desbloquearse — código {info.DisplayCode}{attemptSuffix}")
            .SetSmallIcon(global::Android.Resource.Drawable.IcLockIdleLock)
            .SetPriority(NotificationCompat.PriorityHigh)
            .SetCategory(NotificationCompat.CategoryCall)
            .SetAutoCancel(true)
            .SetContentIntent(pendingIntent)
            .SetVisibility(NotificationCompat.VisibilityPublic)
            .SetVibrate(new long[] { 0, 250, 250, 250 })
            .SetTimeoutAfter(60000) // matches the relay session's 60s TTL
            .Build();

        var nm = (NotificationManager?)GetSystemService(NotificationService);
        nm?.Notify(notificationId, notification);
    }

    /// <summary>
    /// Stable per-session notification ID so simultaneous challenges from different paired PCs (or
    /// repeated attempts) each get their own notification instead of overwriting one another — see
    /// docs/plan_push_auth_v2.md, "🖥️ Múltiples PCs Emparejadas". Distinct range from
    /// <see cref="NotificationId"/>/<see cref="AuthPromptNotificationId"/>.
    /// </summary>
    private static int NotificationIdForSession(string sessionId) =>
        6000 + (int)((uint)sessionId.GetHashCode() % 4000);

    /// <summary>Start the foreground service from any context (no notification request attached).</summary>
    public static void StartService(Context context)
    {
        LaunchService(context, new Intent(context, typeof(AuthForegroundService)));
    }

    /// <summary>Start (or update) the foreground service and show the legacy FCM-wake prompt from within its own OnStartCommand.</summary>
    public static void StartForAuthWake(Context context, string pcName)
    {
        var intent = new Intent(context, typeof(AuthForegroundService));
        intent.PutExtra(ExtraNotifyKind, NotifyKindAuthWake);
        intent.PutExtra(ExtraPcName, pcName);
        LaunchService(context, intent);
    }

    /// <summary>Start (or update) the foreground service and show a push-auth challenge notification from within its own OnStartCommand.</summary>
    public static void StartForPushChallenge(Context context, PushAuthChallengeInfo info)
    {
        var intent = new Intent(context, typeof(AuthForegroundService));
        intent.PutExtra(ExtraNotifyKind, NotifyKindPushChallenge);
        info.WriteToIntent(intent);
        LaunchService(context, intent);
    }

    private static void LaunchService(Context context, Intent intent)
    {
        if (Build.VERSION.SdkInt >= BuildVersionCodes.O)
            context.StartForegroundService(intent);
        else
            context.StartService(intent);
    }

    /// <summary>Stop the foreground service.</summary>
    public static void StopService(Context context)
    {
        var intent = new Intent(context, typeof(AuthForegroundService));
        context.StopService(intent);
    }
}
