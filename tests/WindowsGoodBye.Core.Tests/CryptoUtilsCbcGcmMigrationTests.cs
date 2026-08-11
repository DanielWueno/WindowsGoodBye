using System.Security.Cryptography;
using WindowsGoodBye.Core;
using Xunit;

namespace WindowsGoodBye.Core.Tests;

/// <summary>
/// Fase 13 (Testing &amp; Polish) — regression coverage for docs/plan_push_auth_v2.md's closed design
/// decision #11 ("Compatibilidad CBC→GCM: Sin modo dual ... se elimina CBC por completo").
///
/// <b>What this class DOES prove</b>: there is no silent format-sniffing fallback at the crypto
/// primitive level — ciphertext produced by the legacy, [Obsolete] CBC path
/// (<see cref="CryptoUtils.EncryptAes"/>) is never mistakenly accepted by the current GCM API
/// (<see cref="CryptoUtils.DecryptGcm"/>/<see cref="CryptoUtils.DecryptGcmFromBlob"/>), and vice versa.
/// This is the PC-side, automatable slice of "no dual mode" — the plan's actual security property is
/// stronger (an attacker can't force a downgrade), and this test is a proxy for one concrete failure
/// mode of that property, not a full re-derivation of it.
///
/// <b>What this class deliberately does NOT prove</b> (and why): the plan's literal Fase 13 regression
/// case — "dispositivo pareado con esquema viejo intenta autenticar tras la migración — debe fallar y
/// guiar a re-pairing" — manifests ENTIRELY on the Android side, in
/// <c>WindowsGoodBye.Mobile/Data/MobileDatabase.cs</c>'s <c>PairedPc.DeviceKey</c> getter: a device
/// paired before Fase 1 (Android envelope-encryption migration) only has the old, now-orphaned
/// <c>DeviceKeyBase64</c> plaintext column populated; <c>DeviceKeyEncryptedBase64</c>/
/// <c>DeviceKeyIvBase64</c> are empty (Fase 1 deliberately did NOT migrate the old value forward — see
/// docs/implementation_progress_push_auth_v2.md, Fase 0+1 notes), so the getter throws
/// <c>InvalidOperationException("DeviceKey has not been set for this PairedPc.")</c> the moment
/// anything (FCM challenge decrypt, HMAC response signing, a token_update send) tries to read
/// <c>pc.DeviceKey</c> — which is exactly "fails and forces re-pairing" in practice (there is no code
/// path where a legacy-paired phone can produce a valid response at all).
///
/// That class lives in <c>WindowsGoodBye.Mobile</c>, which targets ONLY <c>net9.0-android</c> — it
/// cannot be referenced from this net9.0 xunit project, and <c>dotnet test</c> cannot execute
/// Android-targeted test assemblies without a device/emulator (same limitation already documented for
/// <c>SecureKeyStorage</c> in Fase 0/1). A physical Android device WAS detected on this dev machine via
/// <c>adb devices</c> (serial <c>57090DLCQ0001N</c>) while auditing this gap, but per this batch's
/// explicit rule ("no tocar hardware/red real ... Android físico"), it was deliberately NOT used to run
/// anything. This remains a required MANUAL verification step before production — see
/// docs/implementation_progress_push_auth_v2.md, Fase 13 notes, for the exact repro steps.
/// </summary>
public class CryptoUtilsCbcGcmMigrationTests
{
#pragma warning disable CS0618 // Deliberately exercising the [Obsolete] CBC path to prove no cross-compat
    [Fact]
    public void LegacyCbcCiphertext_IsNeverAcceptedByGcmDecrypt_NoSilentDowngrade()
    {
        var key = CryptoUtils.GenerateAesKey();
        var plaintext = System.Text.Encoding.UTF8.GetBytes("legacy pre-migration payload");

        var cbcCiphertext = CryptoUtils.EncryptAes(plaintext, key);

        // There is no "detect the scheme and branch" code path anywhere in CryptoUtils — GCM decrypt
        // requires a separate nonce/tag that CBC ciphertext never produced. Feeding CBC output into the
        // GCM blob decryptor must fail LOUDLY (either "too short to contain nonce+tag", or — if the CBC
        // ciphertext happens to be long enough — an authentication-tag mismatch), never silently return
        // plausible-looking plaintext.
        var thrown = Record.Exception(() => CryptoUtils.DecryptGcmFromBlob(cbcCiphertext, key));
        Assert.NotNull(thrown);
        Assert.True(thrown is ArgumentException or AuthenticationTagMismatchException or CryptographicException,
            $"Expected a controlled crypto/format exception, got {thrown!.GetType()}");
    }

    [Fact]
    public void GcmBlob_IsNeverAcceptedByLegacyCbcDecrypt_NoSilentUpgradeEither()
    {
        var key = CryptoUtils.GenerateAesKey();
        var plaintext = System.Text.Encoding.UTF8.GetBytes("post-migration push-auth nonce");
        var aad = System.Text.Encoding.UTF8.GetBytes("session-id");

        var gcmBlob = CryptoUtils.EncryptGcmToBlob(plaintext, key, aad);

        // CBC decrypt has no notion of a 12-byte nonce + 16-byte tag prefix, no AAD, and PKCS7-pads —
        // running GCM output through it must not produce the original plaintext back (that would mean
        // the two schemes are accidentally interchangeable, defeating the whole point of forcing
        // re-pairing instead of a dual-mode fallback).
        try
        {
            var result = CryptoUtils.DecryptAes(gcmBlob, key);
            Assert.NotEqual(plaintext, result);
        }
        catch (CryptographicException)
        {
            // Also an acceptable outcome (e.g. padding validation failure) — either way, the GCM blob
            // is never silently reinterpreted as valid CBC plaintext.
        }
    }
#pragma warning restore CS0618
}
