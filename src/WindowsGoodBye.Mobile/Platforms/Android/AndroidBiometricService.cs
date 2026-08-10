using AndroidX.Biometric;
using AndroidX.Fragment.App;
using WindowsGoodBye.Mobile.Services;

namespace WindowsGoodBye.Mobile.Platforms.Android;

/// <summary>
/// Android implementation of IBiometricService using AndroidX.Biometric.BiometricPrompt.
///
/// Fase 7 (docs/plan_push_auth_v2.md, "Android — Mejoras BiometricService"): migrated from the
/// platform's own, older <c>Android.Hardware.Biometrics.BiometricPrompt</c> (API 28+) to the
/// AndroidX/Jetpack library, which is what Google documents/maintains going forward and — critically —
/// is what exposes <see cref="BiometricManager.CanAuthenticate(int)"/>, letting callers check hardware
/// AND enrollment readiness up front instead of only reacting to a prompt error after the fact.
/// </summary>
public class AndroidBiometricService : IBiometricService
{
    // BIOMETRIC_WEAK accepts any sensor the OEM classifies as at least "weak" strength (fingerprint,
    // face, iris) — matches the previous IsAvailable check's intent (any biometric hardware present),
    // while additionally accounting for enrollment, which the old HasSystemFeature-only check did not.
    private const int Authenticators = BiometricManager.Authenticators.BiometricWeak;

    public bool IsAvailable
    {
        get
        {
            var context = global::Android.App.Application.Context;
            var manager = BiometricManager.From(context);
            return manager.CanAuthenticate(Authenticators) == BiometricManager.BiometricSuccess;
        }
    }

    public Task<BiometricResult> AuthenticateAsync(string title, string subtitle)
    {
        var tcs = new TaskCompletionSource<BiometricResult>();

        var activity = Platform.CurrentActivity as FragmentActivity;
        if (activity is null)
        {
            tcs.SetResult(new BiometricResult(false, "No activity available", BiometricErrorType.Unknown));
            return tcs.Task;
        }

        MainThread.BeginInvokeOnMainThread(() =>
        {
            try
            {
                // BiometricManager.CanAuthenticate() up front — fail fast with a specific
                // BiometricErrorType instead of only finding out via a prompt error callback.
                var manager = BiometricManager.From(activity);
                var readiness = manager.CanAuthenticate(Authenticators);
                if (readiness != BiometricManager.BiometricSuccess)
                {
                    var (message, errorType) = MapReadiness(readiness);
                    tcs.TrySetResult(new BiometricResult(false, message, errorType));
                    return;
                }

                var promptInfo = new BiometricPrompt.PromptInfo.Builder()
                    .SetTitle(title)
                    .SetSubtitle(subtitle)
                    .SetNegativeButtonText("Cancel")
                    .Build();

                var callback = new BiometricCallback(tcs);
                var executor = activity.MainExecutor!;
                var prompt = new BiometricPrompt(activity, executor, callback);
                prompt.Authenticate(promptInfo!);
            }
            catch (Exception ex)
            {
                tcs.TrySetResult(new BiometricResult(false, ex.Message, BiometricErrorType.Unknown));
            }
        });

        return tcs.Task;
    }

    /// <summary>Maps a <see cref="BiometricManager.CanAuthenticate(int)"/> readiness code to a user-facing message + BiometricErrorType.</summary>
    private static (string message, BiometricErrorType type) MapReadiness(int readiness)
    {
        if (readiness == BiometricManager.BiometricErrorNoHardware)
            return ("No biometric hardware available on this device", BiometricErrorType.NoHardware);
        if (readiness == BiometricManager.BiometricErrorHwUnavailable)
            return ("Biometric hardware is currently unavailable", BiometricErrorType.HardwareUnavailable);
        if (readiness == BiometricManager.BiometricErrorNoneEnrolled)
            return ("No fingerprint or face enrolled on this device", BiometricErrorType.NoneEnrolled);
        return ("Biometric authentication is not available", BiometricErrorType.Unknown);
    }

    /// <summary>Maps a <see cref="BiometricPrompt.AuthenticationCallback.OnAuthenticationError(int, Java.Lang.ICharSequence)"/> error code to a BiometricErrorType.</summary>
    private static BiometricErrorType MapErrorCode(int errorCode)
    {
        if (errorCode == BiometricPrompt.ErrorNegativeButton
            || errorCode == BiometricPrompt.ErrorUserCanceled
            || errorCode == BiometricPrompt.ErrorCanceled)
            return BiometricErrorType.UserCanceled;
        if (errorCode == BiometricPrompt.ErrorHwNotPresent)
            return BiometricErrorType.NoHardware;
        if (errorCode == BiometricPrompt.ErrorHwUnavailable)
            return BiometricErrorType.HardwareUnavailable;
        if (errorCode == BiometricPrompt.ErrorNoBiometrics
            || errorCode == BiometricPrompt.ErrorNoDeviceCredential)
            return BiometricErrorType.NoneEnrolled;
        if (errorCode == BiometricPrompt.ErrorLockout
            || errorCode == BiometricPrompt.ErrorLockoutPermanent)
            return BiometricErrorType.LockedOut;
        if (errorCode == BiometricPrompt.ErrorTimeout)
            return BiometricErrorType.Timeout;
        return BiometricErrorType.Unknown;
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
            // A single failed match attempt (e.g. wrong finger) — the prompt stays open for retry,
            // so we don't complete the task yet. Mirrors the pre-migration behavior.
        }

        public override void OnAuthenticationError(int errorCode, Java.Lang.ICharSequence? errString)
        {
            base.OnAuthenticationError(errorCode, errString ?? new Java.Lang.String(string.Empty));
            _tcs.TrySetResult(new BiometricResult(false, errString?.ToString(), MapErrorCode(errorCode)));
        }
    }
}
