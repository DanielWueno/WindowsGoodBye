using Android.Content;

namespace WindowsGoodBye.Mobile.Platforms.Android;

/// <summary>
/// Parsed "auth_challenge" FCM data payload (Ruta C — see docs/plan_push_auth_v2.md, "📨 Flujo
/// Completo de Seguridad"). Passed between <c>FcmService</c> -&gt; <c>AuthForegroundService</c> -&gt;
/// (Fase 6) <c>PushAuthActivity</c> exclusively via <see cref="Intent"/> extras — NEVER via a static
/// <c>Instance</c> reference read immediately after starting a service/activity, which is exactly the
/// timing bug docs/plan_push_auth_v2.md's Fase 5 calls out (the receiving component might not have run
/// its startup code — and therefore not have set its <c>Instance</c> — by the time the caller reads it).
/// </summary>
public sealed class PushAuthChallengeInfo
{
    public const string ExtraSessionId = "wingb.session_id";
    public const string ExtraDeviceId = "wingb.device_id";
    public const string ExtraPcName = "wingb.pc_name";
    public const string ExtraDisplayCode = "wingb.display_code";
    public const string ExtraAttemptNumber = "wingb.attempt_number";
    public const string ExtraChallengeTs = "wingb.challenge_ts";
    public const string ExtraEncryptedNonceB64 = "wingb.encrypted_nonce";
    public const string ExtraRelayUrl = "wingb.relay_url";

    /// <summary>Relay session id (also the FCM/relay correlation key).</summary>
    public required string SessionId { get; init; }

    /// <summary>The device_id this PC assigned to this phone during pairing (matches <c>PairedPc.DeviceId</c>).</summary>
    public required string DeviceId { get; init; }

    public required string PcName { get; init; }

    /// <summary>Two-digit number-matching code — see "🛡️ Defensa contra Push Fatigue".</summary>
    public required string DisplayCode { get; init; }

    /// <summary>How many challenges the PC has generated recently — shown as "3er intento en los últimos 2 minutos".</summary>
    public int AttemptNumber { get; init; } = 1;

    /// <summary>Unix seconds (UTC) when the PC generated the challenge.</summary>
    public long ChallengeTimestamp { get; init; }

    /// <summary>base64(nonce ‖ tag ‖ ciphertext) — see <c>CryptoUtils.EncryptGcmToBlob</c>/<c>DecryptGcmFromBlob</c>.</summary>
    public required string EncryptedNonceBase64 { get; init; }

    /// <summary>Current public relay URL, if the PC included one.</summary>
    public string? RelayUrl { get; init; }

    public void WriteToIntent(Intent intent)
    {
        intent.PutExtra(ExtraSessionId, SessionId);
        intent.PutExtra(ExtraDeviceId, DeviceId);
        intent.PutExtra(ExtraPcName, PcName);
        intent.PutExtra(ExtraDisplayCode, DisplayCode);
        intent.PutExtra(ExtraAttemptNumber, AttemptNumber);
        intent.PutExtra(ExtraChallengeTs, ChallengeTimestamp);
        intent.PutExtra(ExtraEncryptedNonceB64, EncryptedNonceBase64);
        if (!string.IsNullOrEmpty(RelayUrl))
            intent.PutExtra(ExtraRelayUrl, RelayUrl);
    }

    /// <summary>Reconstruct from the Intent extras written by <see cref="WriteToIntent"/> (Fase 6 will use this too).</summary>
    public static PushAuthChallengeInfo? FromIntent(Intent? intent)
    {
        if (intent == null) return null;

        var sessionId = intent.GetStringExtra(ExtraSessionId);
        var deviceId = intent.GetStringExtra(ExtraDeviceId);
        var encryptedNonce = intent.GetStringExtra(ExtraEncryptedNonceB64);
        if (string.IsNullOrEmpty(sessionId) || string.IsNullOrEmpty(deviceId) || string.IsNullOrEmpty(encryptedNonce))
            return null;

        return new PushAuthChallengeInfo
        {
            SessionId = sessionId,
            DeviceId = deviceId,
            PcName = intent.GetStringExtra(ExtraPcName) ?? "PC",
            DisplayCode = intent.GetStringExtra(ExtraDisplayCode) ?? "--",
            AttemptNumber = Math.Max(1, intent.GetIntExtra(ExtraAttemptNumber, 1)),
            ChallengeTimestamp = intent.GetLongExtra(ExtraChallengeTs, 0),
            EncryptedNonceBase64 = encryptedNonce,
            RelayUrl = intent.GetStringExtra(ExtraRelayUrl)
        };
    }

    /// <summary>Parse straight from the FCM data dictionary (<c>FcmService.OnMessageReceived</c>).</summary>
    public static PushAuthChallengeInfo? FromFcmData(IDictionary<string, string> data)
    {
        if (!data.TryGetValue("session_id", out var sessionId) || string.IsNullOrEmpty(sessionId)) return null;
        if (!data.TryGetValue("device_id", out var deviceId) || string.IsNullOrEmpty(deviceId)) return null;
        if (!data.TryGetValue("encrypted_nonce", out var encNonce) || string.IsNullOrEmpty(encNonce)) return null;

        data.TryGetValue("pc_name", out var pcName);
        data.TryGetValue("display_code", out var displayCode);
        data.TryGetValue("relay_url", out var relayUrl);

        long challengeTs = 0;
        if (data.TryGetValue("challenge_ts", out var tsStr)) long.TryParse(tsStr, out challengeTs);

        var attemptNumber = 1;
        if (data.TryGetValue("attempt_number", out var attStr) && int.TryParse(attStr, out var parsedAttempt) && parsedAttempt > 0)
            attemptNumber = parsedAttempt;

        return new PushAuthChallengeInfo
        {
            SessionId = sessionId,
            DeviceId = deviceId,
            PcName = string.IsNullOrEmpty(pcName) ? "PC" : pcName,
            DisplayCode = string.IsNullOrEmpty(displayCode) ? "--" : displayCode,
            AttemptNumber = attemptNumber,
            ChallengeTimestamp = challengeTs,
            EncryptedNonceBase64 = encNonce,
            RelayUrl = string.IsNullOrEmpty(relayUrl) ? null : relayUrl
        };
    }
}
