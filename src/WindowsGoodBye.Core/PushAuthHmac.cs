using System.Text;

namespace WindowsGoodBye.Core;

/// <summary>
/// Shared, dependency-free implementation of the push-auth (Ruta C) response HMAC's exact byte
/// layout — see docs/plan_push_auth_v2.md, "Anti-Replay-Delay: Timestamp Firmado".
///
/// This originated as a private detail of <c>WindowsGoodBye.Service.AuthWorker</c> (Fase 3), which
/// only needed to VERIFY the HMAC. It was promoted to <c>WindowsGoodBye.Core</c> in Fase 6 so both
/// sides of the wire build byte-identical input from the exact same code: the PC
/// (<c>AuthWorker.VerifyPushAuthResponseCore</c>, which now forwards to <see cref="BuildPayload"/>)
/// and Android (<c>PushAuthActivity</c>, which signs with <see cref="ComputeHmac"/>) — instead of
/// trusting two hand-written, independent reimplementations to never silently drift apart.
///
/// Wire format: <c>nonce ‖ challenge_ts ‖ response_ts ‖ session_id</c>, with both timestamps encoded
/// as 8-byte big-endian Unix-seconds longs and <c>session_id</c> as UTF-8.
/// </summary>
public static class PushAuthHmac
{
    /// <summary><c>nonce ‖ challenge_ts ‖ response_ts ‖ session_id</c> (timestamps as 8-byte big-endian Unix seconds).</summary>
    public static byte[] BuildPayload(byte[] nonce, DateTimeOffset challengeTimestamp, DateTimeOffset responseTimestamp, string sessionId)
    {
        var sessionIdBytes = Encoding.UTF8.GetBytes(sessionId);
        var payload = new byte[nonce.Length + 8 + 8 + sessionIdBytes.Length];
        var offset = 0;
        Buffer.BlockCopy(nonce, 0, payload, offset, nonce.Length); offset += nonce.Length;
        WriteInt64BigEndian(payload, offset, challengeTimestamp.ToUnixTimeSeconds()); offset += 8;
        WriteInt64BigEndian(payload, offset, responseTimestamp.ToUnixTimeSeconds()); offset += 8;
        Buffer.BlockCopy(sessionIdBytes, 0, payload, offset, sessionIdBytes.Length);
        return payload;
    }

    /// <summary>
    /// Convenience: build the payload and HMAC-SHA256 it with <paramref name="authKey"/>
    /// (<see cref="RelayKeyDerivation.DeriveAuthKey"/>) in one call. This is what Android's
    /// <c>PushAuthActivity</c> calls when signing its <c>POST /api/auth/respond</c> body.
    /// </summary>
    public static byte[] ComputeHmac(
        byte[] nonce, DateTimeOffset challengeTimestamp, DateTimeOffset responseTimestamp, string sessionId, byte[] authKey) =>
        CryptoUtils.ComputeHmac(BuildPayload(nonce, challengeTimestamp, responseTimestamp, sessionId), authKey);

    private static void WriteInt64BigEndian(byte[] buffer, int offset, long value)
    {
        for (int i = 7; i >= 0; i--)
        {
            buffer[offset + i] = (byte)(value & 0xFF);
            value >>= 8;
        }
    }
}
