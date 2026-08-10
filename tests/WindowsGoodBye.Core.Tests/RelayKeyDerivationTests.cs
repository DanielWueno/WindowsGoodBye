using WindowsGoodBye.Core;
using Xunit;

namespace WindowsGoodBye.Core.Tests;

/// <summary>
/// Smoke tests for RelayKeyDerivation (docs/plan_push_auth_v2.md, decision #12 — key separation
/// between RelayKey and AuthKey, both derived from DeviceKey via HKDF-SHA256).
/// </summary>
public class RelayKeyDerivationTests
{
    [Fact]
    public void DeriveRelayKey_IsDeterministic()
    {
        var deviceKey = CryptoUtils.GenerateAesKey();

        var relayKey1 = RelayKeyDerivation.DeriveRelayKey(deviceKey);
        var relayKey2 = RelayKeyDerivation.DeriveRelayKey(deviceKey);

        Assert.Equal(relayKey1, relayKey2);
    }

    [Fact]
    public void DeriveAuthKey_IsDeterministic()
    {
        var deviceKey = CryptoUtils.GenerateAesKey();

        var authKey1 = RelayKeyDerivation.DeriveAuthKey(deviceKey);
        var authKey2 = RelayKeyDerivation.DeriveAuthKey(deviceKey);

        Assert.Equal(authKey1, authKey2);
    }

    [Fact]
    public void RelayKeyAndAuthKey_AreDifferent()
    {
        var deviceKey = CryptoUtils.GenerateAesKey();

        var relayKey = RelayKeyDerivation.DeriveRelayKey(deviceKey);
        var authKey = RelayKeyDerivation.DeriveAuthKey(deviceKey);

        Assert.NotEqual(relayKey, authKey);
    }

    [Fact]
    public void DerivedKeys_DifferentForDifferentDeviceKeys()
    {
        var deviceKeyA = CryptoUtils.GenerateAesKey();
        var deviceKeyB = CryptoUtils.GenerateAesKey();

        Assert.NotEqual(
            RelayKeyDerivation.DeriveRelayKey(deviceKeyA),
            RelayKeyDerivation.DeriveRelayKey(deviceKeyB));
    }

    [Fact]
    public void DerivedKeys_Are32Bytes()
    {
        var deviceKey = CryptoUtils.GenerateAesKey();

        Assert.Equal(32, RelayKeyDerivation.DeriveRelayKey(deviceKey).Length);
        Assert.Equal(32, RelayKeyDerivation.DeriveAuthKey(deviceKey).Length);
    }
}
