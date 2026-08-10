using System.Diagnostics;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using WindowsGoodBye.Core;

namespace WindowsGoodBye.Service;

/// <summary>
/// Manages the child <c>cloudflared.exe</c> process that exposes the embedded, loopback-only
/// <see cref="RelayServer"/> to the internet via a Cloudflare Tunnel. See docs/plan_push_auth_v2.md,
/// section "Cloudflare Tunnel".
///
/// NOT wired into <c>Program.cs</c> yet — this class only needs to compile and be ready for Fase 4,
/// which registers it as a hosted service, starts it after <see cref="RelayServer"/> is listening, and
/// hooks <see cref="TunnelUrlChanged"/> up to sync <see cref="DeviceInfo.RelayUrl"/> per paired device.
/// Nothing here spawns a real <c>cloudflared.exe</c> process as a side effect of construction — the
/// caller must explicitly call <see cref="StartAsync"/>.
///
/// Supports two modes, per the plan's "Opciones de túnel" note:
/// <list type="bullet">
/// <item><description>Quick Tunnel (no Cloudflare account): <c>cloudflared tunnel --url http://localhost:{port} --no-autoupdate</c>.
/// URL is randomly assigned and changes every restart — the whole reason <see cref="TunnelUrlChanged"/> exists.</description></item>
/// <item><description>Named Tunnel (recommended, stable URL): <c>cloudflared tunnel run --token {token}</c>,
/// when a tunnel token is supplied. Fase 11 (installer) is responsible for provisioning that token and its
/// <c>credentials.json</c>, ACL'd the same as the admin pipe (see docs/plan_push_auth_v2.md, Fase 11).</description></item>
/// </list>
/// </summary>
public sealed class TunnelManager : IAsyncDisposable
{
    // Matches both the Quick Tunnel's random *.trycloudflare.com URL and a Named Tunnel's
    // *.cfargotunnel.com URL, whichever cloudflared happens to print.
    private static readonly Regex TunnelUrlPattern = new(
        @"https://[a-zA-Z0-9-]+\.(trycloudflare\.com|cfargotunnel\.com)",
        RegexOptions.Compiled);

    private readonly ILogger<TunnelManager> _logger;
    private readonly string _cloudflaredPath;
    private readonly int _localPort;
    private readonly string? _namedTunnelToken;

    private Process? _process;
    private CancellationTokenSource? _monitorCts;
    private Task? _monitorTask;

    /// <summary>Raised whenever cloudflared reports a (new) public URL for the tunnel.</summary>
    public event Action<string>? TunnelUrlChanged;

    /// <summary>Raised when the cloudflared process exits unexpectedly (crash, killed, etc.).</summary>
    public event Action<int>? TunnelDown;

    /// <summary>The most recent public URL reported by cloudflared, if any.</summary>
    public string? CurrentUrl { get; private set; }

    /// <summary>True while a cloudflared child process is alive.</summary>
    public bool IsRunning => _process is { HasExited: false };

    /// <param name="logger">Logger for tunnel lifecycle events.</param>
    /// <param name="cloudflaredPath">Full path to <c>cloudflared.exe</c> (installed/verified by Fase 11's setup script).</param>
    /// <param name="localPort">The loopback port <see cref="RelayServer"/> is listening on. Defaults to <see cref="Protocol.RelayPort"/>.</param>
    /// <param name="namedTunnelToken">
    /// If supplied, runs a Named Tunnel (<c>cloudflared tunnel run --token ...</c>) instead of a Quick
    /// Tunnel. Null/empty falls back to a Quick Tunnel, whose URL rotates on every start.
    /// </param>
    public TunnelManager(
        ILogger<TunnelManager> logger, string cloudflaredPath, int localPort = Protocol.RelayPort, string? namedTunnelToken = null)
    {
        _logger = logger;
        _cloudflaredPath = cloudflaredPath;
        _localPort = localPort;
        _namedTunnelToken = namedTunnelToken;
    }

    public Task StartAsync(CancellationToken ct = default)
    {
        if (IsRunning) return Task.CompletedTask;

        if (!File.Exists(_cloudflaredPath))
        {
            // Fase 11 is responsible for downloading + checksum-verifying cloudflared.exe. Fase 2's
            // job is just to fail loudly and predictably if it's missing, not to fetch it.
            _logger.LogWarning("cloudflared.exe not found at {Path} — push auth Ruta C (relay) will be unavailable; " +
                                "direct transports (BT/TCP/UDP) are unaffected.", _cloudflaredPath);
            throw new FileNotFoundException("cloudflared.exe not found. Run the installer or set the correct path.", _cloudflaredPath);
        }

        var arguments = string.IsNullOrEmpty(_namedTunnelToken)
            ? $"tunnel --url http://localhost:{_localPort} --no-autoupdate"
            : $"tunnel run --token {_namedTunnelToken}";

        var startInfo = new ProcessStartInfo(_cloudflaredPath, arguments)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        _process = new Process { StartInfo = startInfo, EnableRaisingEvents = true };
        _process.OutputDataReceived += (_, e) => OnOutputLine(e.Data);
        _process.ErrorDataReceived += (_, e) => OnOutputLine(e.Data); // cloudflared logs to stderr by default
        _process.Exited += OnProcessExited;

        _logger.LogInformation("Starting cloudflared: {Path} {Args}",
            _cloudflaredPath, string.IsNullOrEmpty(_namedTunnelToken) ? arguments : "tunnel run --token ****");

        _process.Start();
        _process.BeginOutputReadLine();
        _process.BeginErrorReadLine();

        _monitorCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _monitorTask = MonitorAsync(_monitorCts.Token);

        return Task.CompletedTask;
    }

    public async Task StopAsync()
    {
        _monitorCts?.Cancel();

        if (_process is { HasExited: false })
        {
            try
            {
                _process.Exited -= OnProcessExited; // this is an intentional stop, not a crash
                _process.Kill(entireProcessTree: true);
                await _process.WaitForExitAsync();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error stopping cloudflared process");
            }
        }

        _process?.Dispose();
        _process = null;
        CurrentUrl = null;

        if (_monitorTask != null)
        {
            try { await _monitorTask; } catch (OperationCanceledException) { /* expected on stop */ }
        }
        _monitorCts?.Dispose();
        _monitorCts = null;
        _monitorTask = null;
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
    }

    private void OnOutputLine(string? line)
    {
        if (string.IsNullOrEmpty(line)) return;

        _logger.LogDebug("[cloudflared] {Line}", line);

        var match = TunnelUrlPattern.Match(line);
        if (match.Success && match.Value != CurrentUrl)
        {
            CurrentUrl = match.Value;
            _logger.LogInformation("Cloudflare Tunnel URL: {Url}", CurrentUrl);
            TunnelUrlChanged?.Invoke(CurrentUrl);
        }
    }

    private void OnProcessExited(object? sender, EventArgs e)
    {
        var exitCode = -1;
        try { exitCode = _process?.ExitCode ?? -1; } catch { /* process already disposed */ }

        _logger.LogWarning("cloudflared exited unexpectedly (code {Code}) — Ruta C (push auth via relay) is " +
                            "unavailable until it restarts; direct transports (BT/TCP/UDP) are unaffected.", exitCode);
        CurrentUrl = null;
        TunnelDown?.Invoke(exitCode);
    }

    /// <summary>
    /// Liveness loop — currently just observes cancellation so StopAsync() has something to await.
    /// Fase 4 owns actual restart/backoff policy on top of <see cref="TunnelDown"/>; this class only
    /// exposes the primitive (start/stop/current URL/events), not a supervision policy.
    /// </summary>
    private static async Task MonitorAsync(CancellationToken ct)
    {
        try
        {
            await Task.Delay(Timeout.Infinite, ct);
        }
        catch (OperationCanceledException)
        {
            // expected on StopAsync()
        }
    }
}
