using Android.App;
using Android.Content;

namespace WindowsGoodBye.Mobile.Platforms.Android;

/// <summary>
/// Starts the auth foreground service on device boot.
/// </summary>
[BroadcastReceiver(Enabled = true, Exported = true, DirectBootAware = false)]
[IntentFilter(new[] { Intent.ActionBootCompleted })]
public class BootReceiver : BroadcastReceiver
{
    public override void OnReceive(Context? context, Intent? intent)
    {
        if (context == null) return;
        if (intent?.Action == Intent.ActionBootCompleted)
        {
            AuthForegroundService.StartService(context);
        }
    }
}
