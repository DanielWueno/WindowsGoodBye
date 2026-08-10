using System.Security.Cryptography;

namespace WindowsGoodBye.Core;

/// <summary>
/// Cryptographic utilities for secure communication between PC and phone.
///
/// v2: AES-256-GCM (<see cref="EncryptGcm"/>/<see cref="DecryptGcm"/>) is the current, supported
/// authenticated-encryption primitive — random 96-bit nonce per operation + optional AAD binding
/// (e.g. session_id) + a 128-bit auth tag verified automatically by <see cref="AesGcm"/>.
///
/// The old AES-256-CBC methods (<see cref="EncryptAes"/>/<see cref="DecryptAes"/>) used a hardcoded,
/// shared IV — a serious cryptographic flaw (identical plaintext blocks always encrypt to identical
/// ciphertext, and reused IVs undermine CBC's security guarantees entirely). They are kept ONLY as
/// [Obsolete] markers for the explicit CBC→GCM migration path. Per the closed design decision in
/// docs/plan_push_auth_v2.md ("Decisión de compatibilidad (cerrada)"), there is NO dual-mode support:
/// accepting both schemes at runtime would let an attacker force a downgrade back to the broken IV
/// scheme. Devices paired under the old CBC scheme must be re-paired; callers must not silently
/// branch on both APIs.
/// See docs/plan_push_auth_v2.md, section "Cifrado: Migración a AES-256-GCM".
/// </summary>
public static class CryptoUtils
{
    // Fixed IV shared between Android and Windows (from original project).
    // ONLY referenced by the [Obsolete] CBC methods below — do not use for new code.
    private static readonly byte[] FixedIV =
    {
        0x43, 0x79, 0x43, 0x68, 0x61, 0x72, 0x6C, 0x69,
        0x65, 0x4C, 0x61, 0x73, 0x6D, 0x43, 0x4C, 0x43
    };

    /// <summary>GCM nonce size in bytes (96-bit, per NIST SP 800-38D recommendation).</summary>
    public const int GcmNonceLength = 12;

    /// <summary>GCM authentication tag size in bytes (128-bit).</summary>
    public const int GcmTagLength = 16;

    /// <summary>Generate a random 256-bit AES key.</summary>
    public static byte[] GenerateAesKey()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    /// <summary>Generate a random nonce of the specified length.</summary>
    public static byte[] GenerateNonce(int length = 32)
    {
        var nonce = new byte[length];
        RandomNumberGenerator.Fill(nonce);
        return nonce;
    }

    /// <summary>
    /// Encrypt <paramref name="plaintext"/> using AES-256-GCM with a fresh random 96-bit nonce.
    /// </summary>
    /// <param name="plaintext">Data to encrypt.</param>
    /// <param name="key">256-bit (32-byte) AES key.</param>
    /// <param name="aad">
    /// Optional Additional Authenticated Data — authenticated but not encrypted (e.g. session_id,
    /// to cryptographically bind the ciphertext to a specific session and prevent cross-session replay).
    /// </param>
    /// <returns>The ciphertext, the randomly generated 12-byte nonce, and the 16-byte auth tag.</returns>
    public static (byte[] ciphertext, byte[] nonce, byte[] tag) EncryptGcm(
        byte[] plaintext, byte[] key, byte[]? aad = null)
    {
        var nonce = new byte[GcmNonceLength];
        RandomNumberGenerator.Fill(nonce);
        var tag = new byte[GcmTagLength];
        var ciphertext = new byte[plaintext.Length];

        using var aes = new AesGcm(key, GcmTagLength);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        return (ciphertext, nonce, tag);
    }

    /// <summary>
    /// Decrypt data previously produced by <see cref="EncryptGcm"/>.
    /// Throws <see cref="AuthenticationTagMismatchException"/> if the tag/AAD don't match
    /// (tampering, wrong key, or wrong AAD) — GCM verifies integrity before returning plaintext.
    /// </summary>
    public static byte[] DecryptGcm(
        byte[] ciphertext, byte[] key, byte[] nonce, byte[] tag, byte[]? aad = null)
    {
        var plaintext = new byte[ciphertext.Length];
        using var aes = new AesGcm(key, GcmTagLength);
        aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);
        return plaintext;
    }

    /// <summary>
    /// Convenience wrapper around <see cref="EncryptGcm"/> that packs nonce ‖ tag ‖ ciphertext into a
    /// single blob for wire transport (matches the wire format used by the push-auth protocol,
    /// e.g. <c>encrypted_nonce: base64(iv+tag+ct)</c> in docs/plan_push_auth_v2.md).
    /// </summary>
    public static byte[] EncryptGcmToBlob(byte[] plaintext, byte[] key, byte[]? aad = null)
    {
        var (ciphertext, nonce, tag) = EncryptGcm(plaintext, key, aad);
        var blob = new byte[nonce.Length + tag.Length + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, blob, 0, nonce.Length);
        Buffer.BlockCopy(tag, 0, blob, nonce.Length, tag.Length);
        Buffer.BlockCopy(ciphertext, 0, blob, nonce.Length + tag.Length, ciphertext.Length);
        return blob;
    }

    /// <summary>Inverse of <see cref="EncryptGcmToBlob"/>: unpacks nonce ‖ tag ‖ ciphertext and decrypts.</summary>
    public static byte[] DecryptGcmFromBlob(byte[] blob, byte[] key, byte[]? aad = null)
    {
        if (blob.Length < GcmNonceLength + GcmTagLength)
            throw new ArgumentException("Blob too short to contain nonce + tag", nameof(blob));

        var nonce = new byte[GcmNonceLength];
        var tag = new byte[GcmTagLength];
        var ciphertext = new byte[blob.Length - GcmNonceLength - GcmTagLength];
        Buffer.BlockCopy(blob, 0, nonce, 0, GcmNonceLength);
        Buffer.BlockCopy(blob, GcmNonceLength, tag, 0, GcmTagLength);
        Buffer.BlockCopy(blob, GcmNonceLength + GcmTagLength, ciphertext, 0, ciphertext.Length);

        return DecryptGcm(ciphertext, key, nonce, tag, aad);
    }

    /// <summary>
    /// Encrypt data using AES-256-CBC with PKCS7 padding and a hardcoded shared IV.
    /// </summary>
    /// <remarks>
    /// OBSOLETE / INSECURE: the IV is a fixed constant shared across all callers, which breaks CBC's
    /// security model entirely. Kept only so the explicit CBC→GCM re-pairing migration path has
    /// something to migrate FROM. Do not call this from new code — use <see cref="EncryptGcm"/>.
    /// No dual-mode negotiation is supported (see class remarks) — this is intentional.
    /// </remarks>
    [Obsolete("AES-CBC with a fixed IV is cryptographically broken. Use EncryptGcm instead. " +
              "This method exists only for the explicit CBC->GCM re-pairing migration path — " +
              "do not use it for new protocol traffic.")]
    public static byte[] EncryptAes(byte[] plaintext, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = key;
        aes.IV = FixedIV;

        using var encryptor = aes.CreateEncryptor();
        return encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
    }

    /// <summary>Decrypt data using AES-256-CBC with PKCS7 padding and a hardcoded shared IV.</summary>
    /// <remarks>
    /// OBSOLETE / INSECURE: see <see cref="EncryptAes"/> remarks. Use <see cref="DecryptGcm"/> instead.
    /// </remarks>
    [Obsolete("AES-CBC with a fixed IV is cryptographically broken. Use DecryptGcm instead. " +
              "This method exists only for the explicit CBC->GCM re-pairing migration path — " +
              "do not use it for new protocol traffic.")]
    public static byte[] DecryptAes(byte[] ciphertext, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = key;
        aes.IV = FixedIV;

        using var decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
    }

    /// <summary>Compute HMAC-SHA256 of data using the provided key.</summary>
    public static byte[] ComputeHmac(byte[] data, byte[] key)
    {
        using var hmac = new HMACSHA256(key);
        return hmac.ComputeHash(data);
    }

    /// <summary>Verify HMAC-SHA256 of data.</summary>
    public static bool VerifyHmac(byte[] data, byte[] key, byte[] expectedHmac)
    {
        var computed = ComputeHmac(data, key);
        return CryptographicOperations.FixedTimeEquals(computed, expectedHmac);
    }

#if WINDOWS
    /// <summary>
    /// Encrypt data using Windows DPAPI (machine scope).
    /// Used for storing the Windows password on disk.
    /// </summary>
    public static byte[] ProtectData(byte[] plaintext)
    {
        return System.Security.Cryptography.ProtectedData.Protect(
            plaintext, null, DataProtectionScope.LocalMachine);
    }

    /// <summary>
    /// Decrypt data using Windows DPAPI (machine scope).
    /// </summary>
    public static byte[] UnprotectData(byte[] ciphertext)
    {
        return System.Security.Cryptography.ProtectedData.Unprotect(
            ciphertext, null, DataProtectionScope.LocalMachine);
    }
#endif
}
