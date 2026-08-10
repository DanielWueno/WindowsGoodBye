using System.Text;
using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.OS;
using Android.Util;
using Android.Views;
using Android.Widget;
using AndroidX.AppCompat.App;
using WindowsGoodBye.Core;
using WindowsGoodBye.Mobile.Data;
using WindowsGoodBye.Mobile.Services;

namespace WindowsGoodBye.Mobile.Platforms.Android;

/// <summary>
/// Fase 6 (docs/plan_push_auth_v2.md, "Android — PushAuthActivity"): transparent-ish activity opened
/// by tapping the heads-up "🔐 ¿Eres tú?" notification (<see cref="AuthForegroundService.ShowPushAuthChallengeNotification"/>,
/// referenced there by component name only, as this class). Implements the full number-matching UX
/// from "🛡️ Defensa contra Push Fatigue" / "📱 UX en Android Moderno":
/// <list type="number">
/// <item><description>Shows the PC name, the 2-digit <see cref="PushAuthChallengeInfo.DisplayCode"/>,
/// the recent-attempt counter, and a 60s countdown — BEFORE touching biometrics, so the user makes a
/// conscious comparison instead of a reflex tap.</description></item>
/// <item><description>"Sí, es correcto" → <see cref="IBiometricService"/> (Fase 7,
/// <c>AndroidBiometricService</c>) → on success, decrypts the nonce, signs the HMAC response with
/// EXACTLY the same byte layout the PC verifies (<see cref="PushAuthHmac"/>, shared in
/// <c>WindowsGoodBye.Core</c> — see that class's XML doc for why it's not reimplemented here), and
/// POSTs it via <see cref="HttpRelayClient.RespondAsync"/>.</description></item>
/// <item><description>"No es mi PC" → <see cref="HttpRelayClient.RejectAsync"/> (distinct from just
/// letting the session time out).</description></item>
/// <item><description>"Cancelar" → closes without notifying the relay; the session simply expires on
/// the PC side like a timeout.</description></item>
/// </list>
///
/// Deliberately does NOT request <c>SetShowWhenLocked</c>/<c>SetTurnScreenOn</c>/keyguard dismissal
/// (unlike the legacy <c>MainActivity</c> auth-prompt path) — per "📱 UX en Android Moderno", the user
/// is REQUIRED to unlock their phone first via the OS's normal lock screen before this activity is
/// ever shown; tapping the (non-full-screen-intent) notification already enforces that automatically.
/// </summary>
[Activity(
    Name = "com.windowsgoodbye.mobile.PushAuthActivity",
    Theme = "@style/Maui.SplashTheme",
    Exported = false,
    LaunchMode = LaunchMode.SingleTop,
    ConfigurationChanges = ConfigChanges.ScreenSize | ConfigChanges.Orientation | ConfigChanges.UiMode |
                           ConfigChanges.ScreenLayout | ConfigChanges.SmallestScreenSize | ConfigChanges.Density)]
public class PushAuthActivity : AppCompatActivity
{
    /// <summary>Matches the PC-side default push-auth session TTL (<c>AuthWorker.TryPushAuthAsync</c> / <c>RelayServer</c>'s default).</summary>
    private const int SessionTtlSeconds = 60;

    private PushAuthChallengeInfo? _challenge;
    private CancellationTokenSource? _countdownCts;

    /// <summary>True once this challenge has been responded to, rejected, expired, or cancelled — guards against double-submit and stale async continuations (e.g. countdown firing after a response already went out).</summary>
    private bool _resolved;

    private TextView _titleText = null!;
    private TextView _attemptText = null!;
    private TextView _codeText = null!;
    private TextView _countdownText = null!;
    private TextView _statusText = null!;
    private global::Android.Widget.Button _confirmButton = null!;
    private global::Android.Widget.Button _rejectButton = null!;
    private global::Android.Widget.Button _cancelButton = null!;

    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);
        BuildUi();
        LoadChallenge(Intent);
    }

    protected override void OnNewIntent(Intent? intent)
    {
        base.OnNewIntent(intent);
        Intent = intent;

        // A different push-auth notification was tapped while this Activity (possibly for another
        // PC/session — see "🖥️ Múltiples PCs Emparejadas") was still on screen. LaunchMode.SingleTop
        // reuses this instance instead of creating a new one. Reset everything for the new challenge
        // rather than silently keep showing/acting on the stale one.
        _resolved = false;
        _countdownCts?.Cancel();
        SetButtonsEnabled(true);
        _statusText.Text = "";
        LoadChallenge(intent);
    }

    protected override void OnDestroy()
    {
        _countdownCts?.Cancel();
        base.OnDestroy();
    }

    private void LoadChallenge(Intent? intent)
    {
        var info = PushAuthChallengeInfo.FromIntent(intent);
        if (info == null)
        {
            System.Diagnostics.Debug.WriteLine("[PushAuthActivity] Missing/invalid challenge extras, finishing.");
            Finish();
            return;
        }

        _challenge = info;
        _titleText.Text = $"🖥️ {info.PcName}\nquiere desbloquearse";

        var showAttempt = info.AttemptNumber > 1;
        _attemptText.Visibility = showAttempt ? ViewStates.Visible : ViewStates.Gone;
        _attemptText.Text = showAttempt ? $"Intento #{info.AttemptNumber} en los últimos minutos" : "";

        _codeText.Text = info.DisplayCode;

        _countdownCts?.Cancel();
        _countdownCts = new CancellationTokenSource();
        _ = RunCountdownAsync(_countdownCts.Token);
    }

    // ============================================================================================
    // Actions
    // ============================================================================================

    private async Task OnConfirmAsync()
    {
        if (_resolved || _challenge == null) return;
        SetButtonsEnabled(false);
        _statusText.Text = "Verificando...";

        var pc = LoadPairedPc(_challenge.DeviceId);
        if (pc == null)
        {
            FailAndFinish("PC no reconocida — vuelve a emparejar desde la app");
            return;
        }

        IBiometricService biometric;
        try
        {
            biometric = IPlatformApplication.Current!.Services.GetRequiredService<IBiometricService>();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[PushAuthActivity] Could not resolve IBiometricService: {ex.Message}");
            FailAndFinish("Error interno de la app");
            return;
        }

        var result = await biometric.AuthenticateAsync("WindowsGoodBye", $"Verificar para desbloquear {_challenge.PcName}");
        if (_resolved) return; // countdown (or a re-entrant OnNewIntent) already resolved this while the prompt was up

        if (!result.Success)
        {
            if (result.ErrorType == BiometricErrorType.UserCanceled)
            {
                _statusText.Text = "";
                SetButtonsEnabled(true);
                return;
            }

            _statusText.Text = string.IsNullOrEmpty(result.ErrorMessage)
                ? "No se pudo verificar tu identidad — intenta de nuevo"
                : result.ErrorMessage;
            SetButtonsEnabled(true);
            return;
        }

        await RespondSuccessAsync(pc);
    }

    /// <summary>
    /// Decrypt the nonce, sign the response with <see cref="PushAuthHmac"/> (the SAME byte layout
    /// <c>AuthWorker.VerifyPushAuthResponseCore</c> verifies on the PC), and POST it to the relay.
    /// </summary>
    private async Task RespondSuccessAsync(PairedPc pc)
    {
        if (_resolved || _challenge == null) return;

        byte[] deviceKey;
        byte[] nonce;
        try
        {
            deviceKey = pc.DeviceKey; // envelope-decrypted on demand via Android Keystore (SecureKeyStorage)
            var blob = Convert.FromBase64String(_challenge.EncryptedNonceBase64);
            // AAD must match EXACTLY what AuthWorker.TryPushAuthAsync used when encrypting:
            // UTF-8 bytes of the session_id STRING (not the device_id) — see docs/implementation_progress_push_auth_v2.md.
            nonce = CryptoUtils.DecryptGcmFromBlob(blob, deviceKey, aad: Encoding.UTF8.GetBytes(_challenge.SessionId));
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[PushAuthActivity] Nonce decrypt failed: {ex.Message}");
            FailAndFinish("Error de seguridad al procesar el desafío");
            return;
        }

        var challengeTs = DateTimeOffset.FromUnixTimeSeconds(_challenge.ChallengeTimestamp);
        var responseTs = DateTimeOffset.UtcNow;
        var authKey = RelayKeyDerivation.DeriveAuthKey(deviceKey);
        var hmacBase64 = Convert.ToBase64String(
            PushAuthHmac.ComputeHmac(nonce, challengeTs, responseTs, _challenge.SessionId, authKey));

        var relayUrl = !string.IsNullOrEmpty(_challenge.RelayUrl) ? _challenge.RelayUrl : pc.RelayUrl;
        if (string.IsNullOrEmpty(relayUrl))
        {
            FailAndFinish("No se conoce la dirección del relay de esta PC");
            return;
        }

        var relayKey = RelayKeyDerivation.DeriveRelayKey(deviceKey);

        try
        {
            var result = await HttpRelayClient.RespondAsync(
                relayUrl!, _challenge.SessionId, _challenge.DeviceId, hmacBase64,
                responseTs.ToUnixTimeSeconds(), relayKey);

            if (_resolved) return;

            if (result.Success)
            {
                _resolved = true;
                ShowResult(success: true, "✓ Desbloqueado");
                AutoFinishAfter(1200);
            }
            else
            {
                FailAndFinish($"✗ No se pudo confirmar (código {result.StatusCode})");
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[PushAuthActivity] RespondAsync failed: {ex.Message}");
            FailAndFinish("✗ No se pudo contactar la PC");
        }
    }

    private async Task OnRejectAsync(string reason)
    {
        if (_resolved || _challenge == null) return;
        SetButtonsEnabled(false);
        _statusText.Text = "Rechazando...";

        var pc = LoadPairedPc(_challenge.DeviceId);
        var relayUrl = !string.IsNullOrEmpty(_challenge.RelayUrl) ? _challenge.RelayUrl : pc?.RelayUrl;

        if (pc != null && !string.IsNullOrEmpty(relayUrl))
        {
            try
            {
                var relayKey = RelayKeyDerivation.DeriveRelayKey(pc.DeviceKey);
                await HttpRelayClient.RejectAsync(relayUrl!, _challenge.SessionId, _challenge.DeviceId, reason, relayKey);
            }
            catch (Exception ex)
            {
                // Best-effort: even if the relay never learns about the explicit rejection, the user
                // still declined locally — worst case the session just expires on the PC side (a
                // slightly weaker signal — "timeout" instead of "rejected" — but not a functional bug).
                System.Diagnostics.Debug.WriteLine($"[PushAuthActivity] RejectAsync failed: {ex.Message}");
            }
        }

        _resolved = true;
        ShowResult(success: false, "✗ Rechazado");
        AutoFinishAfter(1200);
    }

    // ============================================================================================
    // Countdown
    // ============================================================================================

    private async Task RunCountdownAsync(CancellationToken ct)
    {
        try
        {
            var baseTs = _challenge!.ChallengeTimestamp > 0
                ? _challenge.ChallengeTimestamp
                : DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var expiresAt = DateTimeOffset.FromUnixTimeSeconds(baseTs).AddSeconds(SessionTtlSeconds);

            while (!ct.IsCancellationRequested)
            {
                var remaining = expiresAt - DateTimeOffset.UtcNow;
                if (remaining <= TimeSpan.Zero)
                {
                    OnCountdownExpired();
                    return;
                }

                _countdownText.Text = $"⏱️ {(int)Math.Ceiling(remaining.TotalSeconds)} segundos restantes";
                await Task.Delay(1000, ct);
            }
        }
        catch (System.OperationCanceledException)
        {
            // Expected: superseded by a response/reject/new-challenge/destroy.
        }
    }

    private void OnCountdownExpired()
    {
        if (_resolved) return;
        _resolved = true;
        ShowResult(success: false, "⏱️ Tiempo agotado");
        AutoFinishAfter(1500);
    }

    // ============================================================================================
    // UI helpers
    // ============================================================================================

    private PairedPc? LoadPairedPc(string deviceId)
    {
        try
        {
            using var db = new MobileDatabase();
            db.Initialize();
            return db.PairedPcs.FirstOrDefault(p => p.DeviceId == deviceId && p.IsPaired);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[PushAuthActivity] LoadPairedPc failed: {ex.Message}");
            return null;
        }
    }

    private void FailAndFinish(string message)
    {
        _resolved = true;
        ShowResult(success: false, message);
        AutoFinishAfter(2000);
    }

    private void ShowResult(bool success, string message)
    {
        _countdownCts?.Cancel();
        _statusText.Text = message;
        _statusText.SetTextColor(success
            ? global::Android.Graphics.Color.ParseColor("#A5D6A7")
            : global::Android.Graphics.Color.ParseColor("#FFCDD2"));
        SetButtonsEnabled(false);
    }

    private void SetButtonsEnabled(bool enabled)
    {
        _confirmButton.Enabled = enabled;
        _rejectButton.Enabled = enabled;
        _cancelButton.Enabled = enabled;
    }

    /// <summary>Feedback (✓/✗) auto-dismiss — see "PushAuthActivity" UI spec, "Feedback visual ✓/✗ con auto-dismiss".</summary>
    private void AutoFinishAfter(int delayMs)
    {
        _ = Task.Run(async () =>
        {
            await Task.Delay(delayMs);
            RunOnUiThread(Finish);
        });
    }

    private void BuildUi()
    {
        var root = new LinearLayout(this) { Orientation = global::Android.Widget.Orientation.Vertical };
        root.SetGravity(GravityFlags.Center);
        var padding = DpToPx(24);
        root.SetPadding(padding, padding, padding, padding);
        root.SetBackgroundColor(global::Android.Graphics.Color.ParseColor("#1976D2"));

        _titleText = new TextView(this) { TextSize = 22, Gravity = GravityFlags.Center };
        _titleText.SetTextColor(global::Android.Graphics.Color.White);
        _titleText.SetTypeface(_titleText.Typeface, global::Android.Graphics.TypefaceStyle.Bold);

        _attemptText = new TextView(this)
        {
            TextSize = 13,
            Gravity = GravityFlags.Center,
            Visibility = ViewStates.Gone
        };
        _attemptText.SetTextColor(global::Android.Graphics.Color.ParseColor("#FFE0B2"));

        var codeLabel = new TextView(this) { Text = "¿Ves este código en tu PC?", TextSize = 14, Gravity = GravityFlags.Center };
        codeLabel.SetTextColor(global::Android.Graphics.Color.White);

        _codeText = new TextView(this) { TextSize = 56, Gravity = GravityFlags.Center };
        _codeText.SetTextColor(global::Android.Graphics.Color.White);
        _codeText.SetTypeface(_codeText.Typeface, global::Android.Graphics.TypefaceStyle.Bold);

        _countdownText = new TextView(this) { TextSize = 14, Gravity = GravityFlags.Center };
        _countdownText.SetTextColor(global::Android.Graphics.Color.ParseColor("#E3F2FD"));

        _statusText = new TextView(this) { TextSize = 18, Gravity = GravityFlags.Center };
        _statusText.SetTextColor(global::Android.Graphics.Color.White);
        _statusText.SetTypeface(_statusText.Typeface, global::Android.Graphics.TypefaceStyle.Bold);

        _confirmButton = new global::Android.Widget.Button(this) { Text = "Sí, es correcto" };
        _confirmButton.Click += async (_, _) => await OnConfirmAsync();

        _rejectButton = new global::Android.Widget.Button(this) { Text = "No es mi PC" };
        _rejectButton.Click += async (_, _) => await OnRejectAsync("user_rejected");

        _cancelButton = new global::Android.Widget.Button(this) { Text = "Cancelar" };
        _cancelButton.Click += (_, _) => Finish();

        void AddSpacer(int heightDp) =>
            root.AddView(new Space(this), new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MatchParent, DpToPx(heightDp)));

        root.AddView(_titleText);
        AddSpacer(8);
        root.AddView(_attemptText);
        AddSpacer(24);
        root.AddView(codeLabel);
        root.AddView(_codeText);
        AddSpacer(16);
        root.AddView(_countdownText);
        AddSpacer(8);
        root.AddView(_statusText);
        AddSpacer(24);

        var buttonParams = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MatchParent, ViewGroup.LayoutParams.WrapContent)
        {
            TopMargin = DpToPx(8)
        };
        root.AddView(_confirmButton, buttonParams);
        root.AddView(_rejectButton, buttonParams);
        root.AddView(_cancelButton, buttonParams);

        SetContentView(root);
    }

    private int DpToPx(int dp) => (int)TypedValue.ApplyDimension(ComplexUnitType.Dip, dp, Resources!.DisplayMetrics);
}
