using System.Security.Cryptography;
using System.Text;
using WindowsGoodBye.Core;
using Xunit;

namespace WindowsGoodBye.Core.Tests;

/// <summary>
/// Smoke tests for <see cref="PushAuthHmac"/> — the shared byte-layout builder promoted to Core in
/// Fase 6 specifically so the PC (<c>AuthWorker.VerifyPushAuthResponseCore</c>, which now forwards to
/// <see cref="PushAuthHmac.BuildPayload"/>) and Android (<c>PushAuthActivity</c>, which signs via
/// <see cref="PushAuthHmac.ComputeHmac"/>) can never silently drift into two different wire formats.
/// </summary>
public class PushAuthHmacTests
{
    private static readonly byte[] Nonce = RandomNumberGenerator.GetBytes(32);
    private static readonly byte[] AuthKey = RandomNumberGenerator.GetBytes(32);

    [Fact]
    public void BuildPayload_IsDeterministic()
    {
        var challengeTs = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);
        var responseTs = challengeTs.AddSeconds(3);

        var a = PushAuthHmac.BuildPayload(Nonce, challengeTs, responseTs, "session-abc");
        var b = PushAuthHmac.BuildPayload(Nonce, challengeTs, responseTs, "session-abc");

        Assert.Equal(a, b);
    }

    [Fact]
    public void BuildPayload_MatchesExpectedByteLayout()
    {
        // nonce ‖ challenge_ts (8B BE) ‖ response_ts (8B BE) ‖ session_id (UTF-8) — spelled out
        // explicitly here (built from BitConverter, NOT PushAuthHmac's own writer, to avoid a
        // tautological test) so a future change to the layout fails loudly instead of two
        // implementations silently agreeing on a NEW (but still mutually-consistent) format.
        var nonce = new byte[] { 1, 2, 3, 4 };
        var challengeTs = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);
        var responseTs = DateTimeOffset.FromUnixTimeSeconds(1_700_000_005);
        const string sessionId = "abc";

        var payload = PushAuthHmac.BuildPayload(nonce, challengeTs, responseTs, sessionId);

        var expected = nonce
            .Concat(ToBigEndianBytes(challengeTs.ToUnixTimeSeconds()))
            .Concat(ToBigEndianBytes(responseTs.ToUnixTimeSeconds()))
            .Concat(Encoding.UTF8.GetBytes(sessionId))
            .ToArray();

        Assert.Equal(expected, payload);
    }

    private static byte[] ToBigEndianBytes(long value)
    {
        var bytes = BitConverter.GetBytes(value);
        if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
        return bytes;
    }

    [Fact]
    public void ComputeHmac_MatchesManualComputeHmacOverBuildPayload()
    {
        var challengeTs = DateTimeOffset.UtcNow;
        var responseTs = challengeTs.AddSeconds(2);
        const string sessionId = "session-xyz";

        var viaConvenience = PushAuthHmac.ComputeHmac(Nonce, challengeTs, responseTs, sessionId, AuthKey);
        var viaManualSteps = CryptoUtils.ComputeHmac(
            PushAuthHmac.BuildPayload(Nonce, challengeTs, responseTs, sessionId), AuthKey);

        Assert.Equal(viaManualSteps, viaConvenience);
    }

    [Fact]
    public void ComputeHmac_DifferentSessionId_ProducesDifferentHmac()
    {
        var challengeTs = DateTimeOffset.UtcNow;
        var responseTs = challengeTs.AddSeconds(1);

        var hmac1 = PushAuthHmac.ComputeHmac(Nonce, challengeTs, responseTs, "session-1", AuthKey);
        var hmac2 = PushAuthHmac.ComputeHmac(Nonce, challengeTs, responseTs, "session-2", AuthKey);

        Assert.NotEqual(hmac1, hmac2);
    }
}
