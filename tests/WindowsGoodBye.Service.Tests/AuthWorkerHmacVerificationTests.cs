using System.Security.Cryptography;
using WindowsGoodBye.Core;
using WindowsGoodBye.Service;
using Xunit;

namespace WindowsGoodBye.Service.Tests;

/// <summary>
/// Smoke tests for <see cref="AuthWorker.VerifyPushAuthResponseCore"/> — the pure core of push-auth
/// (Ruta C) HMAC verification (docs/plan_push_auth_v2.md, "Anti-Replay-Delay: Timestamp Firmado").
/// Confirms: a correctly-signed, in-window response verifies; the two anti-replay-delay windows
/// (challenge_ts→response_ts &lt; 60s, now→response_ts &lt; 10s) are enforced; tampering with any input
/// (nonce, key, session_id, HMAC bytes) is rejected.
/// </summary>
public class AuthWorkerHmacVerificationTests
{
    private static readonly byte[] Nonce = RandomNumberGenerator.GetBytes(32);
    private static readonly byte[] AuthKey = RandomNumberGenerator.GetBytes(32);
    private const string SessionId = "abc123sessionid";

    private static string SignValid(DateTimeOffset challengeTs, DateTimeOffset responseTs, byte[]? nonce = null, byte[]? key = null, string? sessionId = null)
    {
        var payload = AuthWorker.BuildHmacPayload(nonce ?? Nonce, challengeTs, responseTs, sessionId ?? SessionId);
        var hmac = CryptoUtils.ComputeHmac(payload, key ?? AuthKey);
        return Convert.ToBase64String(hmac);
    }

    [Fact]
    public void ValidResponse_WithinWindows_Verifies()
    {
        var challengeTs = DateTimeOffset.UtcNow;
        var responseTs = challengeTs.AddSeconds(5);
        var now = responseTs.AddSeconds(2);
        var hmac = SignValid(challengeTs, responseTs);

        var ok = AuthWorker.VerifyPushAuthResponseCore(Nonce, AuthKey, challengeTs, responseTs, now, SessionId, hmac);

        Assert.True(ok);
    }

    [Fact]
    public void ResponseTimestamp_MoreThan60sAfterChallenge_IsRejected()
    {
        var challengeTs = DateTimeOffset.UtcNow;
        var responseTs = challengeTs.AddSeconds(61);
        var now = responseTs.AddSeconds(1);
        var hmac = SignValid(challengeTs, responseTs);

        var ok = AuthWorker.VerifyPushAuthResponseCore(Nonce, AuthKey, challengeTs, responseTs, now, SessionId, hmac);

        Assert.False(ok);
    }

    [Fact]
    public void ResponseOlderThan10Seconds_IsRejected_AntiReplayDelay()
    {
        // Simulates a relay withholding the response for >10s before the PC sees it.
        var challengeTs = DateTimeOffset.UtcNow;
        var responseTs = challengeTs.AddSeconds(3);
        var now = responseTs.AddSeconds(11);
        var hmac = SignValid(challengeTs, responseTs);

        var ok = AuthWorker.VerifyPushAuthResponseCore(Nonce, AuthKey, challengeTs, responseTs, now, SessionId, hmac);

        Assert.False(ok);
    }

    [Fact]
    public void ResponseTimestampBeforeChallenge_IsRejected()
    {
        var challengeTs = DateTimeOffset.UtcNow;
        var responseTs = challengeTs.AddSeconds(-1);
        var now = responseTs.AddSeconds(1);
        var hmac = SignValid(challengeTs, responseTs);

        var ok = AuthWorker.VerifyPushAuthResponseCore(Nonce, AuthKey, challengeTs, responseTs, now, SessionId, hmac);

        Assert.False(ok);
    }

    [Fact]
    public void TamperedHmac_IsRejected()
    {
        var challengeTs = DateTimeOffset.UtcNow;
        var responseTs = challengeTs.AddSeconds(1);
        var now = responseTs.AddSeconds(1);
        var hmacBytes = Convert.FromBase64String(SignValid(challengeTs, responseTs));
        hmacBytes[0] ^= 0xFF; // flip a bit
        var tampered = Convert.ToBase64String(hmacBytes);

        var ok = AuthWorker.VerifyPushAuthResponseCore(Nonce, AuthKey, challengeTs, responseTs, now, SessionId, tampered);

        Assert.False(ok);
    }

    [Fact]
    public void WrongAuthKey_IsRejected()
    {
        var challengeTs = DateTimeOffset.UtcNow;
        var responseTs = challengeTs.AddSeconds(1);
        var now = responseTs.AddSeconds(1);
        var hmac = SignValid(challengeTs, responseTs); // signed with AuthKey

        var wrongKey = RandomNumberGenerator.GetBytes(32);
        var ok = AuthWorker.VerifyPushAuthResponseCore(Nonce, wrongKey, challengeTs, responseTs, now, SessionId, hmac);

        Assert.False(ok);
    }

    [Fact]
    public void WrongSessionId_IsRejected_CrossSessionReplay()
    {
        var challengeTs = DateTimeOffset.UtcNow;
        var responseTs = challengeTs.AddSeconds(1);
        var now = responseTs.AddSeconds(1);
        var hmac = SignValid(challengeTs, responseTs, sessionId: "original-session");

        // Same nonce/timestamps/HMAC, but verified against a DIFFERENT session_id — simulates trying
        // to replay a captured response against another pending session.
        var ok = AuthWorker.VerifyPushAuthResponseCore(Nonce, AuthKey, challengeTs, responseTs, now, "different-session", hmac);

        Assert.False(ok);
    }

    [Fact]
    public void MalformedBase64Hmac_IsRejected_NotAnException()
    {
        var challengeTs = DateTimeOffset.UtcNow;
        var responseTs = challengeTs.AddSeconds(1);
        var now = responseTs.AddSeconds(1);

        var ok = AuthWorker.VerifyPushAuthResponseCore(Nonce, AuthKey, challengeTs, responseTs, now, SessionId, "not-valid-base64!!");

        Assert.False(ok);
    }
}
