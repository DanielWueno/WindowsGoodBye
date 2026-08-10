using Android.Content.PM;
using Android.Security.Keystore;
using Java.Security;
using Javax.Crypto;
using Javax.Crypto.Spec;

namespace WindowsGoodBye.Mobile.Platforms.Android;

/// <summary>
/// Envelope encryption for the shared <c>DeviceKey</c> at rest on Android.
///
/// <c>DeviceKey</c> is a symmetric key shared with the paired PC — it cannot live ONLY inside the
/// Android Keystore as a non-exportable key, because the PC also needs the raw bytes for its own
/// AES-GCM/HKDF operations. What this class protects instead is how <c>DeviceKey</c> sits at rest in
/// <c>MobileDatabase</c>: instead of the raw key sitting in a plaintext SQLite column (previously the
/// case — recoverable by malware with root, or from an unencrypted device backup, without ever
/// touching the biometric sensor), it is wrapped with a non-exportable AES-256-GCM key generated
/// in the Android Keystore (StrongBox-backed when the device has a StrongBox module, falling back to
/// the TEE otherwise). Only the ciphertext + IV are ever persisted.
///
/// See docs/plan_push_auth_v2.md, section "🔑 Almacenamiento Seguro de DeviceKey en Android"
/// (this is flagged there as a critical pre-implementation security-audit finding, not a nice-to-have).
///
/// Threat model note (documented, not hidden): while <c>DeviceKey</c> is unwrapped in managed memory
/// during actual use (decrypting a push-auth nonce, computing an HMAC), it is not persisted in that
/// form. .NET/MAUI on Android does not guarantee scrubbing of managed memory, so a live, full compromise
/// of the app process while a key is unwrapped is still a residual risk — same as any software-only
/// key-handling scheme. This moves the bar from "read a SQLite file" to "break or abuse the device's
/// live TEE/StrongBox", which is the intended threshold.
/// </summary>
public static class SecureKeyStorage
{
    private const string KeyStoreProviderName = "AndroidKeyStore";
    private const string WrappingKeyAlias = "wingb_device_key_wrap_v1";
    private const string Transformation = "AES/GCM/NoPadding";
    private const int GcmTagLengthBits = 128;

    /// <summary>
    /// Encrypt <paramref name="plaintextKey"/> (the raw DeviceKey bytes) with the app's Keystore-backed
    /// wrapping key, generating it on first use. Returns (ciphertext, iv) — both safe to persist.
    /// </summary>
    public static (byte[] ciphertext, byte[] iv) Wrap(byte[] plaintextKey)
    {
        var wrappingKey = GetOrCreateWrappingKey();

        using var cipher = Cipher.GetInstance(Transformation)
            ?? throw new InvalidOperationException("Could not obtain AES/GCM/NoPadding Cipher instance");
        cipher.Init(CipherMode.EncryptMode, wrappingKey);

        var ciphertext = cipher.DoFinal(plaintextKey)
            ?? throw new InvalidOperationException("Cipher.DoFinal returned null while wrapping DeviceKey");
        var iv = cipher.GetIV()
            ?? throw new InvalidOperationException("Cipher.GetIV returned null while wrapping DeviceKey");

        return (ciphertext, iv);
    }

    /// <summary>
    /// Decrypt a (ciphertext, iv) pair previously produced by <see cref="Wrap"/> back into the raw
    /// DeviceKey bytes, using the same Keystore-backed wrapping key. Throws if the Keystore key is
    /// missing (e.g. app data was restored onto a different device, or the Keystore was reset) or if
    /// the ciphertext/tag don't validate.
    /// </summary>
    public static byte[] Unwrap(byte[] ciphertext, byte[] iv)
    {
        var wrappingKey = GetExistingWrappingKeyOrThrow();

        using var cipher = Cipher.GetInstance(Transformation)
            ?? throw new InvalidOperationException("Could not obtain AES/GCM/NoPadding Cipher instance");
        var spec = new GCMParameterSpec(GcmTagLengthBits, iv);
        cipher.Init(CipherMode.DecryptMode, wrappingKey, spec);

        return cipher.DoFinal(ciphertext)
            ?? throw new InvalidOperationException("Cipher.DoFinal returned null while unwrapping DeviceKey");
    }

    /// <summary>
    /// True if a StrongBox secure element is available on this device
    /// (<c>PackageManager.FEATURE_STRONGBOX_KEYSTORE</c>). When true, <see cref="Wrap"/>/<see cref="Unwrap"/>
    /// use a StrongBox-backed key; otherwise they fall back to the device's regular TEE-backed Keystore.
    /// </summary>
    public static bool IsStrongBoxAvailable
    {
        get
        {
            try
            {
                var pm = global::Android.App.Application.Context.PackageManager;
                return pm != null && pm.HasSystemFeature(PackageManager.FeatureStrongboxKeystore);
            }
            catch
            {
                return false;
            }
        }
    }

    private static ISecretKey GetOrCreateWrappingKey()
    {
        var keyStore = KeyStore.GetInstance(KeyStoreProviderName)!;
        keyStore.Load(null);

        if (keyStore.ContainsAlias(WrappingKeyAlias)
            && keyStore.GetEntry(WrappingKeyAlias, null) is KeyStore.SecretKeyEntry existing)
        {
            return existing.SecretKey!;
        }

        return GenerateWrappingKey();
    }

    private static ISecretKey GetExistingWrappingKeyOrThrow()
    {
        var keyStore = KeyStore.GetInstance(KeyStoreProviderName)!;
        keyStore.Load(null);

        if (keyStore.ContainsAlias(WrappingKeyAlias)
            && keyStore.GetEntry(WrappingKeyAlias, null) is KeyStore.SecretKeyEntry existing)
        {
            return existing.SecretKey!;
        }

        throw new InvalidOperationException(
            $"Android Keystore wrapping key '{WrappingKeyAlias}' not found. The device was likely " +
            "restored/reset or app data was moved to another device — the paired DeviceKey cannot be " +
            "recovered and the phone must be re-paired.");
    }

    /// <summary>
    /// Generates the wrapping key, preferring StrongBox and transparently falling back to the
    /// regular (TEE-backed) Keystore if StrongBox generation fails — StrongBox availability can be
    /// reported by <see cref="PackageManager.HasSystemFeature"/> yet still fail at key-generation time
    /// on some OEM devices, so we treat the capability check as a hint, not a guarantee.
    /// </summary>
    private static ISecretKey GenerateWrappingKey()
    {
        Exception? strongBoxFailure = null;

        if (IsStrongBoxAvailable)
        {
            try
            {
                return GenerateWrappingKeyCore(useStrongBox: true);
            }
            catch (Exception ex)
            {
                strongBoxFailure = ex;
            }
        }

        try
        {
            return GenerateWrappingKeyCore(useStrongBox: false);
        }
        catch (Exception ex)
        {
            if (strongBoxFailure != null)
                throw new InvalidOperationException(
                    "Failed to generate DeviceKey wrapping key, both with and without StrongBox", ex);
            throw;
        }
    }

    private static ISecretKey GenerateWrappingKeyCore(bool useStrongBox)
    {
        var purposes = KeyStorePurpose.Encrypt | KeyStorePurpose.Decrypt;
        var builder = new KeyGenParameterSpec.Builder(WrappingKeyAlias, purposes)
            .SetBlockModes(KeyProperties.BlockModeGcm)
            .SetEncryptionPaddings(KeyProperties.EncryptionPaddingNone)
            .SetKeySize(256)
            .SetRandomizedEncryptionRequired(true);

        if (useStrongBox)
            builder.SetIsStrongBoxBacked(true);

        var keyGenerator = KeyGenerator.GetInstance(KeyProperties.KeyAlgorithmAes, KeyStoreProviderName)!;
        keyGenerator.Init(builder.Build());
        return keyGenerator.GenerateKey()!;
    }
}
