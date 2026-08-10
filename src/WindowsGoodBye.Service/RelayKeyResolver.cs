using WindowsGoodBye.Core;

namespace WindowsGoodBye.Service;

/// <summary>
/// Shared "device_id (string GUID) → RelayKeyDerivation.DeriveRelayKey(device.DeviceKey)" lookup used
/// by <see cref="RelayServer"/>'s JWT-validation middleware to resolve which key to check a JWT's
/// signature against.
///
/// Extracted out of <c>AuthWorker</c> (which originally had this as a private instance method,
/// <c>ResolveRelayKeyForDevice</c>, Fase 3) so Fase 4 can wire the exact same lookup into a
/// <see cref="RelayServer"/> singleton constructed directly in <c>Program.cs</c> — as of Fase 4 the
/// Service itself (via <see cref="RelayHostedService"/>), not <c>AuthWorker</c>, owns the relay's
/// startup/shutdown lifecycle, so the resolver delegate can no longer depend on a live
/// <c>AuthWorker</c> instance existing first. <c>AuthWorker.ResolveRelayKeyForDevice</c> now simply
/// forwards here, so both paths (the DI-registered relay used in production, and AuthWorker's own
/// fallback instance used by callers/tests that construct it directly without DI) resolve identically.
/// </summary>
public static class RelayKeyResolver
{
    /// <summary>Production entry point — always reads the real, per-machine <see cref="AppDatabase"/>.</summary>
    public static byte[]? Resolve(string deviceIdStr, ILogger logger) =>
        Resolve(deviceIdStr, logger, static () => new AppDatabase());

    /// <summary>
    /// Testable overload — takes an <see cref="AppDatabase"/> factory instead of hardcoding
    /// <c>new AppDatabase()</c>, so tests can point it at a throwaway SQLite file instead of the real
    /// per-machine one. Public (not test-only/internal) to avoid an <c>InternalsVisibleTo</c> just for
    /// this; it's a harmless, pure overload.
    /// </summary>
    public static byte[]? Resolve(string deviceIdStr, ILogger logger, Func<AppDatabase> dbFactory)
    {
        if (!Guid.TryParse(deviceIdStr, out var deviceId)) return null;
        try
        {
            using var db = dbFactory();
            var device = db.Devices.Find(deviceId);
            if (device == null || !device.Enabled) return null;
            return RelayKeyDerivation.DeriveRelayKey(device.DeviceKey);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "RelayKeyResolver.Resolve failed for {DeviceId}", deviceIdStr);
            return null;
        }
    }
}
