using System.Security.Cryptography;
using WindowsGoodBye.Core;
using Xunit;

namespace WindowsGoodBye.Core.Tests;

/// <summary>Smoke tests for the AES-256-GCM migration (docs/plan_push_auth_v2.md, Fase 0).</summary>
public class CryptoUtilsGcmTests
{
    [Fact]
    public void EncryptDecryptGcm_RoundTrips()
    {
        var key = CryptoUtils.GenerateAesKey();
        var plaintext = CryptoUtils.GenerateNonce(32);
        var aad = System.Text.Encoding.UTF8.GetBytes("session-123");

        var (ciphertext, nonce, tag) = CryptoUtils.EncryptGcm(plaintext, key, aad);
        var decrypted = CryptoUtils.DecryptGcm(ciphertext, key, nonce, tag, aad);

        Assert.Equal(plaintext, decrypted);
        Assert.Equal(12, nonce.Length);
        Assert.Equal(16, tag.Length);
    }

    [Fact]
    public void EncryptGcm_ProducesDifferentNonceEachTime()
    {
        var key = CryptoUtils.GenerateAesKey();
        var plaintext = CryptoUtils.GenerateNonce(16);

        var (_, nonce1, _) = CryptoUtils.EncryptGcm(plaintext, key);
        var (_, nonce2, _) = CryptoUtils.EncryptGcm(plaintext, key);

        Assert.NotEqual(nonce1, nonce2);
    }

    [Fact]
    public void DecryptGcm_WithTamperedTag_Throws()
    {
        var key = CryptoUtils.GenerateAesKey();
        var plaintext = CryptoUtils.GenerateNonce(16);
        var (ciphertext, nonce, tag) = CryptoUtils.EncryptGcm(plaintext, key);

        tag[0] ^= 0xFF; // tamper

        Assert.Throws<AuthenticationTagMismatchException>(
            () => CryptoUtils.DecryptGcm(ciphertext, key, nonce, tag));
    }

    [Fact]
    public void DecryptGcm_WithWrongAad_Throws()
    {
        var key = CryptoUtils.GenerateAesKey();
        var plaintext = CryptoUtils.GenerateNonce(16);
        var aad = System.Text.Encoding.UTF8.GetBytes("session-A");
        var wrongAad = System.Text.Encoding.UTF8.GetBytes("session-B");

        var (ciphertext, nonce, tag) = CryptoUtils.EncryptGcm(plaintext, key, aad);

        Assert.Throws<AuthenticationTagMismatchException>(
            () => CryptoUtils.DecryptGcm(ciphertext, key, nonce, tag, wrongAad));
    }

    [Fact]
    public void DecryptGcm_WithWrongKey_Throws()
    {
        var key = CryptoUtils.GenerateAesKey();
        var wrongKey = CryptoUtils.GenerateAesKey();
        var plaintext = CryptoUtils.GenerateNonce(16);

        var (ciphertext, nonce, tag) = CryptoUtils.EncryptGcm(plaintext, key);

        Assert.Throws<AuthenticationTagMismatchException>(
            () => CryptoUtils.DecryptGcm(ciphertext, wrongKey, nonce, tag));
    }

    [Fact]
    public void EncryptDecryptGcmBlob_RoundTrips()
    {
        var key = CryptoUtils.GenerateAesKey();
        var plaintext = System.Text.Encoding.UTF8.GetBytes("hello push-auth");
        var aad = System.Text.Encoding.UTF8.GetBytes("session-xyz");

        var blob = CryptoUtils.EncryptGcmToBlob(plaintext, key, aad);
        var decrypted = CryptoUtils.DecryptGcmFromBlob(blob, key, aad);

        Assert.Equal(plaintext, decrypted);
    }

#pragma warning disable CS0618 // Testing the intentionally-Obsolete legacy CBC path
    [Fact]
    public void LegacyEncryptAes_StillWorksForMigrationPath()
    {
        var key = CryptoUtils.GenerateAesKey();
        var plaintext = System.Text.Encoding.UTF8.GetBytes("legacy payload");

        var ciphertext = CryptoUtils.EncryptAes(plaintext, key);
        var decrypted = CryptoUtils.DecryptAes(ciphertext, key);

        Assert.Equal(plaintext, decrypted);
    }
#pragma warning restore CS0618
}
