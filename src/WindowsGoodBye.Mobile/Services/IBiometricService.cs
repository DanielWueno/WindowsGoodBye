namespace WindowsGoodBye.Mobile.Services;

/// <summary>
/// Cross-platform interface for biometric authentication.
/// Implemented per-platform (Android uses AndroidX.Biometric.BiometricPrompt — see
/// docs/plan_push_auth_v2.md, Fase 7 "Android — Mejoras BiometricService").
/// </summary>
public interface IBiometricService
{
    /// <summary>Returns true if biometric auth (fingerprint/face) is available.</summary>
    bool IsAvailable { get; }

    /// <summary>
    /// Prompt the user for biometric authentication.
    /// Returns true on success, false on cancel/failure — check <see cref="BiometricResult.ErrorType"/>
    /// for why, e.g. to decide whether to fall back to a PIN/pattern flow or surface a "no fingerprint
    /// enrolled" message instead of a generic failure.
    /// </summary>
    Task<BiometricResult> AuthenticateAsync(string title, string subtitle);
}

/// <summary>
/// Coarse classification of why a biometric prompt did not succeed, distinct from the free-text
/// <see cref="BiometricResult.ErrorMessage"/> (which is platform-specific and only meant for logs/UI
/// display, not for branching logic). Callers that need to react differently — e.g. offer "use PIN
/// instead" only when hardware/enrollment is the problem, vs. just retrying on a transient failure —
/// should switch on this instead of parsing <see cref="BiometricResult.ErrorMessage"/>.
/// </summary>
public enum BiometricErrorType
{
    /// <summary>No error — <see cref="BiometricResult.Success"/> is true.</summary>
    None,
    /// <summary>The device has no biometric hardware at all.</summary>
    NoHardware,
    /// <summary>Biometric hardware exists but is currently unavailable (e.g. in use by another process).</summary>
    HardwareUnavailable,
    /// <summary>Hardware exists but the user has no fingerprint/face enrolled.</summary>
    NoneEnrolled,
    /// <summary>Too many failed attempts — biometric sensor temporarily or permanently locked out.</summary>
    LockedOut,
    /// <summary>The user dismissed the prompt or tapped the negative/cancel button.</summary>
    UserCanceled,
    /// <summary>The prompt's own timeout elapsed without a definitive success/failure.</summary>
    Timeout,
    /// <summary>Any other platform-reported error not covered above.</summary>
    Unknown
}

public record BiometricResult(bool Success, string? ErrorMessage = null, BiometricErrorType ErrorType = BiometricErrorType.None);
