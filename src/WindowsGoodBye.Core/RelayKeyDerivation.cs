using System.Security.Cryptography;
using System.Text;

namespace WindowsGoodBye.Core;

/// <summary>
/// Derives purpose-specific subkeys from the shared <c>DeviceKey</c> using HKDF-SHA256, so that
/// different cryptographic primitives (relay authentication, HMAC signing, nonce encryption) never
/// reuse the same raw key material.
///
/// See docs/plan_push_auth_v2.md, decision #12 ("Separación de claves para HMAC vs. cifrado") and the
/// "Anti-Replay-Delay: Timestamp Firmado" section.
///
/// <list type="bullet">
/// <item><description><see cref="DeriveRelayKey"/> — <c>RelayKey = HKDF(DeviceKey, "relay-auth")</c>.
/// Used to sign/verify the JWTs the PC and Android use to authenticate to the embedded relay. If the
/// relay is ever compromised, only this derived key leaks — never the raw <c>DeviceKey</c>.</description></item>
/// <item><description><see cref="DeriveAuthKey"/> — <c>AuthKey = HKDF(DeviceKey, "auth-hmac")</c>.
/// Used as the HMAC-SHA256 key for the push-auth response signature (nonce ‖ challenge_ts ‖
/// response_ts ‖ session_id).</description></item>
/// </list>
///
/// <para>
/// ⚠️ NAMING COLLISION — READ BEFORE USING: <see cref="DeviceInfo"/> and the legacy pairing protocol
/// already have an unrelated field also called "AuthKey" (<see cref="DeviceInfo.AuthKey"/>,
/// <see cref="PairingSession.AuthKey"/>) — a separate, independently random 32-byte key generated at
/// pairing time and used to HMAC-authenticate the existing direct-transport (BT/TCP/UDP) challenge in
/// <c>AuthWorker.HandleAuthResponse</c>. That is a DIFFERENT key from the one this class derives.
/// <see cref="DeriveAuthKey"/> must ONLY be used for verifying push-auth (Ruta C / relay) HMAC
/// responses; the legacy <c>DeviceInfo.AuthKey</c> must ONLY be used for the legacy direct-transport
/// flow. Do not use one where the other is expected.
/// </para>
/// </summary>
public static class RelayKeyDerivation
{
    private const int DerivedKeyLengthBytes = 32; // 256-bit, matches DeviceKey/AesGcm key size

    private static readonly byte[] RelayAuthInfo = Encoding.UTF8.GetBytes("relay-auth");
    private static readonly byte[] AuthHmacInfo = Encoding.UTF8.GetBytes("auth-hmac");

    /// <summary>
    /// Derive the relay authentication key: <c>RelayKey = HKDF-SHA256(DeviceKey, info: "relay-auth")</c>.
    /// Used to sign the JWTs sent to the embedded relay's <c>/api/auth/*</c> endpoints.
    /// </summary>
    public static byte[] DeriveRelayKey(byte[] deviceKey) => Derive(deviceKey, RelayAuthInfo);

    /// <summary>
    /// Derive the push-auth HMAC key: <c>AuthKey = HKDF-SHA256(DeviceKey, info: "auth-hmac")</c>.
    /// Used as the HMAC-SHA256 key for the push-auth response signature. See the naming-collision
    /// warning on the class remarks — this is NOT the same key as <see cref="DeviceInfo.AuthKey"/>.
    /// </summary>
    public static byte[] DeriveAuthKey(byte[] deviceKey) => Derive(deviceKey, AuthHmacInfo);

    private static byte[] Derive(byte[] deviceKey, byte[] info)
    {
        if (deviceKey == null || deviceKey.Length == 0)
            throw new ArgumentException("DeviceKey must not be null or empty", nameof(deviceKey));

        // salt: null is acceptable per RFC 5869 when the input keying material (DeviceKey) already
        // has sufficient entropy (it's a randomly generated 256-bit AES key).
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, deviceKey, DerivedKeyLengthBytes, salt: null, info: info);
    }
}
