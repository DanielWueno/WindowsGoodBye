using WindowsGoodBye.Core;
using Xunit;

namespace WindowsGoodBye.Core.Tests;

/// <summary>
/// Smoke tests for PairingSession (docs/plan_push_auth_v2.md, Fase 10): the QR wire format
/// (relay_url + push_auth_enabled segments added on top of the pre-existing fixed key blob + IP
/// list), the key-serialization round trip used by the TrayApp -&gt; Service admin pipe handoff, and
/// the derived RelayKey/PushAuthKey convenience properties.
/// </summary>
public class PairingSessionTests
{
    [Fact]
    public void GenerateQrData_StartsWithPairPrefix()
    {
        var session = new PairingSession();

        var qr = session.GenerateQrData();

        Assert.StartsWith(Protocol.PairQrPrefix, qr);
    }

    [Fact]
    public void GenerateQrData_DefaultParams_HasEmptyRelayUrlSegment_AndPushAuthEnabledTrue()
    {
        var session = new PairingSession();

        var qr = session.GenerateQrData();
        var parts = SplitAfterPrefix(qr);

        // segments: [0]=base64 blob, [1]=ips, [2]=relayUrl, [3]=pushAuthEnabledDefault
        Assert.Equal(4, parts.Length);
        Assert.Equal("", parts[2]); // no relayUrl passed -> empty segment, not omitted
        Assert.Equal("1", parts[3]); // default push_auth_enabled = true
    }

    [Fact]
    public void GenerateQrData_WithRelayUrl_IsUrlEncodedAndRoundTrips()
    {
        var session = new PairingSession();
        const string relayUrl = "https://wingb-abc123.trycloudflare.com/api?x=1&y=2";

        var qr = session.GenerateQrData(relayUrl: relayUrl);
        var parts = SplitAfterPrefix(qr);

        Assert.NotEqual(relayUrl, parts[2]); // must be encoded (raw URL contains '&', ':', '/')
        Assert.Equal(relayUrl, Uri.UnescapeDataString(parts[2]));
    }

    [Fact]
    public void GenerateQrData_PushAuthEnabledFalse_EncodesZero()
    {
        var session = new PairingSession();

        var qr = session.GenerateQrData(pushAuthEnabledDefault: false);
        var parts = SplitAfterPrefix(qr);

        Assert.Equal("0", parts[3]);
    }

    [Fact]
    public void GenerateQrData_KeyBlobSegment_HasFixedPairPayloadLength()
    {
        var session = new PairingSession();

        var qr = session.GenerateQrData(relayUrl: "https://example.trycloudflare.com");
        var parts = SplitAfterPrefix(qr);
        var payload = Convert.FromBase64String(parts[0]);

        // Adding relay_url/push_auth_enabled must NOT change the fixed key blob's length/layout —
        // QrScanPage.ProcessQrCode still validates payload.Length == Protocol.PairPayloadLength
        // before touching DeviceId/DeviceKey/AuthKey/PairEncryptKey.
        Assert.Equal(Protocol.PairPayloadLength, payload.Length);
    }

    [Fact]
    public void SerializeKeys_FromSerializedKeys_RoundTripsAllFourKeys()
    {
        var original = new PairingSession();

        var restored = PairingSession.FromSerializedKeys(original.SerializeKeys());

        Assert.Equal(original.DeviceId, restored.DeviceId);
        Assert.Equal(original.DeviceKey, restored.DeviceKey);
        Assert.Equal(original.AuthKey, restored.AuthKey);
        Assert.Equal(original.PairEncryptKey, restored.PairEncryptKey);
    }

    [Fact]
    public void RelayKey_MatchesRelayKeyDerivation_DeriveRelayKey()
    {
        var session = new PairingSession();

        Assert.Equal(RelayKeyDerivation.DeriveRelayKey(session.DeviceKey), session.RelayKey);
    }

    [Fact]
    public void PushAuthKey_MatchesRelayKeyDerivation_DeriveAuthKey()
    {
        var session = new PairingSession();

        Assert.Equal(RelayKeyDerivation.DeriveAuthKey(session.DeviceKey), session.PushAuthKey);
    }

    [Fact]
    public void RelayKey_PushAuthKey_And_LegacyAuthKey_AreAllDifferent()
    {
        // Guards the naming-collision documented in RelayKeyDerivation.cs: PairingSession.AuthKey is
        // an independently-random legacy key (direct-transport HMAC), NOT the same as the two
        // HKDF-derived keys used by push-auth/relay.
        var session = new PairingSession();

        Assert.NotEqual(session.AuthKey, session.RelayKey);
        Assert.NotEqual(session.AuthKey, session.PushAuthKey);
        Assert.NotEqual(session.RelayKey, session.PushAuthKey);
    }

    [Fact]
    public void RelayKey_And_PushAuthKey_AreDeterministic_ForSameDeviceKey()
    {
        var original = new PairingSession();
        var restored = PairingSession.FromSerializedKeys(original.SerializeKeys());

        Assert.Equal(original.RelayKey, restored.RelayKey);
        Assert.Equal(original.PushAuthKey, restored.PushAuthKey);
    }

    /// <summary>
    /// Splits a QR string the same way QrScanPage.ProcessQrCode does: strip the prefix, then split
    /// on '|' into [base64Blob, ips, relayUrl, pushAuthEnabledDefault].
    /// </summary>
    private static string[] SplitAfterPrefix(string qr)
    {
        Assert.StartsWith(Protocol.PairQrPrefix, qr);
        var afterPrefix = qr[Protocol.PairQrPrefix.Length..];
        return afterPrefix.Split('|');
    }
}
