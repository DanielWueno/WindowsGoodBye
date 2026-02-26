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

        return StartCommandResult.Sticky;
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

    /// <summary>Start the foreground service from any context.</summary>
    public static void StartService(Context context)
    {
        var intent = new Intent(context, typeof(AuthForegroundService));
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
