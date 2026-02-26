using Android.Hardware.Biometrics;
using Android.OS;
using WindowsGoodBye.Mobile.Services;

namespace WindowsGoodBye.Mobile.Platforms.Android;

/// <summary>
/// Android implementation of IBiometricService using Android.Hardware.Biometrics.BiometricPrompt (API 28+).
/// </summary>
public class AndroidBiometricService : IBiometricService
{
    public bool IsAvailable
    {
        get
        {
            var context = global::Android.App.Application.Context;
            var pm = context.PackageManager;
            return pm?.HasSystemFeature("android.hardware.fingerprint") == true ||
                   pm?.HasSystemFeature("android.hardware.biometrics.face") == true ||
                   pm?.HasSystemFeature("android.hardware.biometrics.iris") == true;
        }
    }

    public Task<BiometricResult> AuthenticateAsync(string title, string subtitle)
    {
        var tcs = new TaskCompletionSource<BiometricResult>();

        var activity = Platform.CurrentActivity;
        if (activity is null)
        {
            tcs.SetResult(new BiometricResult(false, "No activity available"));
            return tcs.Task;
        }

        MainThread.BeginInvokeOnMainThread(() =>
        {
            try
            {
                var callback = new BiometricCallback(tcs);
                var cancellationSignal = new CancellationSignal();

                var promptBuilder = new BiometricPrompt.Builder(activity)
                    .SetTitle(title)
                    .SetSubtitle(subtitle)
                    .SetNegativeButton("Cancel",
                        activity.MainExecutor!,
                        new NegativeButtonListener(tcs));

                var prompt = promptBuilder.Build();
                prompt.Authenticate(cancellationSignal, activity.MainExecutor!, callback);
            }
            catch (Exception ex)
            {
                tcs.TrySetResult(new BiometricResult(false, ex.Message));
            }
        });

        return tcs.Task;
    }

    private class BiometricCallback : BiometricPrompt.AuthenticationCallback
    {
        private readonly TaskCompletionSource<BiometricResult> _tcs;

        public BiometricCallback(TaskCompletionSource<BiometricResult> tcs) => _tcs = tcs;

        public override void OnAuthenticationSucceeded(BiometricPrompt.AuthenticationResult? result)
        {
            base.OnAuthenticationSucceeded(result);
            _tcs.TrySetResult(new BiometricResult(true));
        }

        public override void OnAuthenticationFailed()
        {
            base.OnAuthenticationFailed();
            // Don't complete yet - user can retry
        }

        public override void OnAuthenticationError(BiometricErrorCode errorCode, Java.Lang.ICharSequence? errString)
        {
            base.OnAuthenticationError(errorCode, errString);
            _tcs.TrySetResult(new BiometricResult(false, errString?.ToString()));
        }
    }

    private class NegativeButtonListener : Java.Lang.Object, global::Android.Content.IDialogInterfaceOnClickListener
    {
        private readonly TaskCompletionSource<BiometricResult> _tcs;

        public NegativeButtonListener(TaskCompletionSource<BiometricResult> tcs) => _tcs = tcs;

        public void OnClick(global::Android.Content.IDialogInterface? dialog, int which)
        {
            _tcs.TrySetResult(new BiometricResult(false, "Cancelled"));
        }
    }
}
