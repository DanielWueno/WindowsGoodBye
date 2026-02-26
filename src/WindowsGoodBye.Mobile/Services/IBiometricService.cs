namespace WindowsGoodBye.Mobile.Services;

/// <summary>
/// Cross-platform interface for biometric authentication.
/// Implemented per-platform (Android uses BiometricPrompt).
/// </summary>
public interface IBiometricService
{
    /// <summary>Returns true if biometric auth (fingerprint/face) is available.</summary>
    bool IsAvailable { get; }

    /// <summary>
    /// Prompt the user for biometric authentication.
    /// Returns true on success, false on cancel/failure.
    /// </summary>
    Task<BiometricResult> AuthenticateAsync(string title, string subtitle);
}

public record BiometricResult(bool Success, string? ErrorMessage = null);
