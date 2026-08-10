using WindowsGoodBye.Core;

namespace WindowsGoodBye.Service;

/// <summary>
/// Fase 4 (docs/plan_push_auth_v2.md, "Startup del Service"): real <see cref="ITunnelStatusProvider"/>
/// implementation, registered as a DI singleton so <c>AuthWorker</c> (Fase 3) picks it up automatically
/// in place of <see cref="NullTunnelStatusProvider"/> — no <c>AuthWorker</c> changes required, exactly
/// as documented on that constructor's XML doc.
/// </summary>
public sealed class TunnelStatusAdapter : ITunnelStatusProvider
{
    private readonly TunnelManager _tunnelManager;

    public TunnelStatusAdapter(TunnelManager tunnelManager) => _tunnelManager = tunnelManager;

    public bool IsConnected => _tunnelManager.IsRunning && _tunnelManager.CurrentUrl != null;
    public string? PublicUrl => _tunnelManager.CurrentUrl;
}

/// <summary>
/// Fase 4: owns <see cref="TunnelManager"/>'s lifecycle at Service startup/shutdown, and syncs
/// <see cref="DeviceInfo.RelayUrl"/> for every enabled paired device whenever the tunnel (re)assigns a
/// public URL — Quick Tunnel URLs are random and rotate on every process restart (see
/// docs/plan_push_auth_v2.md, "Opciones de túnel"), so without this, <c>AuthWorker.TryPushAuthAsync</c>
/// would keep sending Android a stale/empty <c>relay_url</c> after any Service or cloudflared restart.
///
/// Registered AFTER <see cref="RelayHostedService"/> in <c>Program.cs</c> so the relay is already
/// listening on <see cref="Protocol.RelayPort"/> by the time cloudflared is told to forward to it (not
/// strictly required — cloudflared would just retry/502 until the port comes up — but it avoids a
/// needless race on every startup).
///
/// Deliberately tolerant of <c>cloudflared.exe</c> being absent: this batch (Fase 4) does not download
/// or verify that binary — that is explicitly Fase 11's job (checksum-verified install). This class's
/// <see cref="StartAsync"/> catches <see cref="TunnelManager"/>'s <see cref="FileNotFoundException"/>
/// and logs a warning instead of taking the Service down; direct transports (Ruta A) are entirely
/// unaffected either way. No real <c>cloudflared.exe</c> process is spawned unless that file actually
/// exists on disk at the configured path — this class never downloads or installs it.
/// </summary>
public sealed class TunnelHostedService : IHostedService
{
    private readonly TunnelManager _tunnelManager;
    private readonly ILogger<TunnelHostedService> _logger;

    public TunnelHostedService(TunnelManager tunnelManager, ILogger<TunnelHostedService> logger)
    {
        _tunnelManager = tunnelManager;
        _logger = logger;
        _tunnelManager.TunnelUrlChanged += OnTunnelUrlChanged;
        _tunnelManager.TunnelDown += OnTunnelDown;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _tunnelManager.StartAsync(cancellationToken);
        }
        catch (FileNotFoundException ex)
        {
            _logger.LogWarning(
                "cloudflared.exe not found ({Path}) — Ruta C (push auth via internet relay) will be " +
                "unavailable until it's installed (see docs/plan_push_auth_v2.md, Fase 11). Direct " +
                "transports (BT/TCP/UDP) are unaffected.", ex.FileName);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to start Cloudflare Tunnel — Ruta C via internet relay unavailable.");
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _tunnelManager.TunnelUrlChanged -= OnTunnelUrlChanged;
        _tunnelManager.TunnelDown -= OnTunnelDown;
        try
        {
            await _tunnelManager.StopAsync();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error stopping Cloudflare Tunnel");
        }
    }

    private void OnTunnelDown(int exitCode) =>
        _logger.LogWarning("Cloudflare Tunnel process exited unexpectedly (code {Code}) — Ruta C unavailable " +
                            "until the Service restarts (no auto-restart policy implemented yet, see " +
                            "TunnelManager.MonitorAsync's XML doc).", exitCode);

    private void OnTunnelUrlChanged(string url)
    {
        try
        {
            using var db = new AppDatabase();
            var changed = false;
            foreach (var device in db.Devices.Where(d => d.Enabled))
            {
                if (device.RelayUrl != url)
                {
                    device.RelayUrl = url;
                    changed = true;
                }
            }
            if (changed) db.SaveChanges();
            _logger.LogInformation("Synced relay URL {Url} to enabled paired devices", url);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to sync tunnel URL {Url} to DeviceInfo.RelayUrl", url);
        }
    }
}
