using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.OS;
using WindowsGoodBye.Mobile.Services;

namespace WindowsGoodBye.Mobile;

[Activity(
    Theme = "@style/Maui.SplashTheme",
    MainLauncher = true,
    LaunchMode = LaunchMode.SingleTop,
    ShowOnLockScreen = true,
    TurnScreenOn = true,
    ConfigurationChanges = ConfigChanges.ScreenSize | ConfigChanges.Orientation | ConfigChanges.UiMode |
                           ConfigChanges.ScreenLayout | ConfigChanges.SmallestScreenSize | ConfigChanges.Density)]
public class MainActivity : MauiAppCompatActivity
{
    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);

        // Allow showing over lock screen (for auth prompt notifications)
        if (Build.VERSION.SdkInt >= BuildVersionCodes.OMr1)
        {
            SetShowWhenLocked(true);
            SetTurnScreenOn(true);

            var keyguardManager = (KeyguardManager?)GetSystemService(KeyguardService);
            keyguardManager?.RequestDismissKeyguard(this, null);
        }
    }

    protected override void OnNewIntent(Intent? intent)
    {
        base.OnNewIntent(intent);
        Intent = intent;
        HandleAuthPromptIntent(intent);
    }

    protected override void OnResume()
    {
        base.OnResume();
        HandleAuthPromptIntent(Intent);
    }

    private void HandleAuthPromptIntent(Intent? intent)
    {
        if (intent?.GetBooleanExtra("auth_prompt", false) != true) return;

        // Clear the flag so we don't re-trigger
        intent.RemoveExtra("auth_prompt");

        // The AuthListener has a pending request — trigger biometric from MainPage
        var pendingRequest = AuthListener.Instance.PendingAuthRequest;
        if (pendingRequest != null)
        {
            System.Diagnostics.Debug.WriteLine("[MainActivity] Auth prompt intent received, triggering biometric...");
            // The MainPage's AuthenticationRequested handler will pick this up
            // But in case it didn't fire while in background, re-fire it
            MainThread.BeginInvokeOnMainThread(() =>
            {
                // Post a message that MainPage can observe
                MessagingCenter.Send<object, AuthRequest>(this, "AuthPrompt", pendingRequest);
            });
        }
    }
}
