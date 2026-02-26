using System.Security.Cryptography;

namespace WindowsGoodBye.Core;

/// <summary>
/// Cryptographic utilities for secure communication between PC and phone.
/// Uses AES-256-CBC for symmetric encryption and HMAC-SHA256 for authentication.
/// Compatible with the Android counterpart (CryptoUtils.java).
/// </summary>
public static class CryptoUtils
{
    // Fixed IV shared between Android and Windows (from original project)
    private static readonly byte[] FixedIV =
    {
        0x43, 0x79, 0x43, 0x68, 0x61, 0x72, 0x6C, 0x69,
        0x65, 0x4C, 0x61, 0x73, 0x6D, 0x43, 0x4C, 0x43
    };

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

    /// <summary>Encrypt data using AES-256-CBC with PKCS7 padding.</summary>
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

    /// <summary>Decrypt data using AES-256-CBC with PKCS7 padding.</summary>
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
