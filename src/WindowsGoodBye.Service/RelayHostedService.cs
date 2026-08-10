namespace WindowsGoodBye.Service;

/// <summary>
/// Fase 4 (docs/plan_push_auth_v2.md, "Startup del Service"): owns the embedded <see cref="RelayServer"/>'s
/// lifecycle at Service startup/shutdown. Registered as a hosted service BEFORE <c>AuthWorker</c> in
/// <c>Program.cs</c> — the generic host awaits each <see cref="IHostedService.StartAsync"/> in
/// registration order before starting the next, so the relay is already listening by the time
/// <c>AuthWorker.ExecuteAsync</c> runs its own "start it if nobody has" fallback (see that class's
/// constructor XML doc / <c>_ownsRelay</c>). That fallback becomes a no-op once this hosted service is
/// registered (<see cref="RelayServer.IsRunning"/> is already true), but is deliberately left in place
/// in <c>AuthWorker</c> for tests/callers that construct it directly without DI.
///
/// Never lets a relay startup/shutdown failure take the Service down — a relay that fails to bind
/// (e.g. the port is already in use by another instance) degrades to "Ruta C unavailable", not a
/// crashed Service (which would also take Ruta A down with it — see "🛡️ Aislamiento y Resiliencia del
/// Relay").
/// </summary>
public sealed class RelayHostedService : IHostedService
{
    private readonly RelayServer _relay;
    private readonly ILogger<RelayHostedService> _logger;

    public RelayHostedService(RelayServer relay, ILogger<RelayHostedService> logger)
    {
        _relay = relay;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _relay.StartAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Relay server failed to start at Service startup — Ruta C (push auth " +
                                    "via relay) unavailable; direct transports (BT/TCP/UDP) are unaffected.");
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _relay.StopAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error stopping relay server");
        }
    }
}
