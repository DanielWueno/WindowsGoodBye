using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using WindowsGoodBye.Core;
using WindowsGoodBye.Service;
using Xunit;

namespace WindowsGoodBye.Service.Tests;

/// <summary>
/// Fase 4 smoke tests for <see cref="RelayKeyResolver"/> — the lookup extracted out of
/// <c>AuthWorker.ResolveRelayKeyForDevice</c> so <c>Program.cs</c> can wire the exact same logic into a
/// DI-registered <see cref="RelayServer"/> singleton (see <see cref="RelayHostedService"/>) without
/// needing a live <c>AuthWorker</c> instance first.
///
/// Uses the testable <see cref="RelayKeyResolver.Resolve(string, ILogger, Func{AppDatabase})"/>
/// overload with a throwaway SQLite file per test — NEVER the real per-machine devices.db that the
/// production 2-arg overload reads (touching that would violate this batch's "no afectar el sistema
/// real" rule and would be flaky/order-dependent on a machine with a real WindowsGoodBye install).
/// </summary>
public sealed class RelayKeyResolverTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"wingb-test-{Guid.NewGuid():n}.db");

    private AppDatabase DbFactory() => new(_dbPath);

    public void Dispose()
    {
        try { File.Delete(_dbPath); } catch { /* best effort */ }
    }

    [Fact]
    public void Resolve_KnownEnabledDevice_ReturnsDerivedRelayKey()
    {
        var deviceId = Guid.NewGuid();
        var deviceKey = RandomNumberGenerator.GetBytes(32);

        using (var db = DbFactory())
        {
            db.Initialize();
            db.Devices.Add(new DeviceInfo { DeviceId = deviceId, DeviceKey = deviceKey, Enabled = true });
            db.SaveChanges();
        }

        var result = RelayKeyResolver.Resolve(deviceId.ToString(), NullLogger.Instance, DbFactory);

        Assert.NotNull(result);
        Assert.Equal(RelayKeyDerivation.DeriveRelayKey(deviceKey), result);
    }

    [Fact]
    public void Resolve_DisabledDevice_ReturnsNull()
    {
        var deviceId = Guid.NewGuid();
        using (var db = DbFactory())
        {
            db.Initialize();
            db.Devices.Add(new DeviceInfo { DeviceId = deviceId, DeviceKey = RandomNumberGenerator.GetBytes(32), Enabled = false });
            db.SaveChanges();
        }

        var result = RelayKeyResolver.Resolve(deviceId.ToString(), NullLogger.Instance, DbFactory);

        Assert.Null(result);
    }

    [Fact]
    public void Resolve_UnknownDeviceId_ReturnsNull()
    {
        using (var db = DbFactory()) db.Initialize(); // DB exists but has no devices

        var result = RelayKeyResolver.Resolve(Guid.NewGuid().ToString(), NullLogger.Instance, DbFactory);

        Assert.Null(result);
    }

    [Fact]
    public void Resolve_MalformedDeviceIdString_ReturnsNull_WithoutTouchingDatabase()
    {
        // Never even calls the factory — Guid.TryParse fails first.
        var result = RelayKeyResolver.Resolve("not-a-guid", NullLogger.Instance, () =>
            throw new InvalidOperationException("dbFactory should not be invoked for a malformed device_id"));

        Assert.Null(result);
    }
}
