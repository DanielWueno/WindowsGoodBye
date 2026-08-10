using WindowsGoodBye.Core;
using Xunit;

namespace WindowsGoodBye.Core.Tests;

/// <summary>Smoke tests for JwtHelper (docs/plan_push_auth_v2.md, Fase 1, "JWT para Autenticación al Relay").</summary>
public class JwtHelperTests
{
    private static byte[] TestKey() => CryptoUtils.GenerateAesKey();

    [Fact]
    public void CreateAndValidateToken_RoundTrips()
    {
        var key = TestKey();
        var token = JwtHelper.CreateToken("device-123", "session-abc", key);

        var ok = JwtHelper.TryValidateToken(token, key, out var payload, out var error);

        Assert.True(ok, error);
        Assert.NotNull(payload);
        Assert.Equal("device-123", payload!.Sub);
        Assert.Equal("session-abc", payload.Sid);
    }

    [Fact]
    public void ValidateToken_WithWrongKey_Fails()
    {
        var key = TestKey();
        var wrongKey = TestKey();
        var token = JwtHelper.CreateToken("device-123", "session-abc", key);

        var ok = JwtHelper.TryValidateToken(token, wrongKey, out var payload, out var error);

        Assert.False(ok);
        Assert.Null(payload);
        Assert.NotNull(error);
    }

    [Fact]
    public void ValidateToken_Expired_Fails()
    {
        var key = TestKey();
        var token = JwtHelper.CreateToken("device-123", "session-abc", key, TimeSpan.FromSeconds(-1));

        var ok = JwtHelper.TryValidateToken(token, key, out _, out var error);

        Assert.False(ok);
        Assert.Contains("expired", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateToken_Expired_WithinClockSkew_Succeeds()
    {
        var key = TestKey();
        var token = JwtHelper.CreateToken("device-123", "session-abc", key, TimeSpan.FromSeconds(-1));

        var ok = JwtHelper.TryValidateToken(token, key, out _, out var error, clockSkew: TimeSpan.FromSeconds(5));

        Assert.True(ok, error);
    }

    [Fact]
    public void ValidateToken_Malformed_Fails()
    {
        var ok = JwtHelper.TryValidateToken("not-a-jwt", TestKey(), out var payload, out var error);

        Assert.False(ok);
        Assert.Null(payload);
        Assert.NotNull(error);
    }

    [Fact]
    public void ValidateToken_TamperedPayload_FailsSignatureCheck()
    {
        var key = TestKey();
        var token = JwtHelper.CreateToken("device-123", "session-abc", key);
        var parts = token.Split('.');

        // Flip a character in the payload segment to simulate tampering.
        var tamperedPayload = parts[1][..^1] + (parts[1][^1] == 'A' ? 'B' : 'A');
        var tampered = $"{parts[0]}.{tamperedPayload}.{parts[2]}";

        var ok = JwtHelper.TryValidateToken(tampered, key, out _, out var error);

        Assert.False(ok);
        Assert.NotNull(error);
    }

    [Fact]
    public void PeekSubjectUnsafe_ReadsSubWithoutValidatingSignature()
    {
        var key = TestKey();
        var token = JwtHelper.CreateToken("device-999", "session-abc", key);

        var subject = JwtHelper.PeekSubjectUnsafe(token);

        Assert.Equal("device-999", subject);
    }
}
