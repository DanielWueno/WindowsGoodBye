using System.Reflection;
using Microsoft.Extensions.Logging.Abstractions;
using WindowsGoodBye.Service;
using Xunit;

namespace WindowsGoodBye.Service.Tests;

/// <summary>
/// Fase 4 smoke tests for <see cref="TunnelStatusAdapter"/> (the real <c>ITunnelStatusProvider</c>
/// wired up in <c>Program.cs</c>/<c>TunnelHostedService</c>, replacing the <c>NullTunnelStatusProvider</c>
/// stub) and <see cref="TunnelManager"/>'s cloudflared-output URL parsing.
///
/// Never starts a real <c>cloudflared.exe</c> process (none is installed in this environment, and this
/// batch's rules forbid it) — <see cref="TunnelManager.OnOutputLine"/> is invoked directly via
/// reflection to simulate cloudflared's stdout, which is exactly the code path
/// <see cref="TunnelManager.TunnelUrlChanged"/> is driven from regardless of whether the underlying
/// process is real.
/// </summary>
public class TunnelStatusAdapterTests
{
    private static TunnelManager NewTunnelManager() =>
        new(NullLogger<TunnelManager>.Instance, cloudflaredPath: "cloudflared-does-not-exist.exe");

    private static void InvokeOnOutputLine(TunnelManager manager, string? line)
    {
        var method = typeof(TunnelManager).GetMethod("OnOutputLine", BindingFlags.NonPublic | BindingFlags.Instance)
                     ?? throw new MissingMethodException(nameof(TunnelManager), "OnOutputLine");
        method.Invoke(manager, new object?[] { line });
    }

    [Fact]
    public void IsConnected_BeforeStart_IsFalse()
    {
        var manager = NewTunnelManager();
        var adapter = new TunnelStatusAdapter(manager);

        Assert.False(adapter.IsConnected);
        Assert.Null(adapter.PublicUrl);
    }

    [Fact]
    public void IsConnected_UrlKnownButProcessNeverStarted_StillFalse()
    {
        // Regression guard for the adapter's AND logic (IsRunning && CurrentUrl != null) — knowing a
        // URL alone must never be enough to report "connected" if the cloudflared process itself isn't
        // actually alive (e.g. it already exited/crashed after printing its URL once).
        var manager = NewTunnelManager();
        var adapter = new TunnelStatusAdapter(manager);

        InvokeOnOutputLine(manager, "Your quick Tunnel has been created! https://random-name.trycloudflare.com");

        Assert.Equal("https://random-name.trycloudflare.com", manager.CurrentUrl);
        Assert.False(manager.IsRunning); // no real process was ever started
        Assert.False(adapter.IsConnected);
    }

    [Fact]
    public void TunnelUrlChanged_FiresWithParsedUrl_QuickTunnel()
    {
        var manager = NewTunnelManager();
        string? raised = null;
        manager.TunnelUrlChanged += url => raised = url;

        InvokeOnOutputLine(manager, "2024-01-01T00:00:00Z INF |  https://some-words-here.trycloudflare.com  |");

        Assert.Equal("https://some-words-here.trycloudflare.com", raised);
    }

    [Fact]
    public void TunnelUrlChanged_FiresWithParsedUrl_NamedTunnel()
    {
        var manager = NewTunnelManager();
        string? raised = null;
        manager.TunnelUrlChanged += url => raised = url;

        InvokeOnOutputLine(manager, "Connection established to https://wingb-abc123.cfargotunnel.com");

        Assert.Equal("https://wingb-abc123.cfargotunnel.com", raised);
    }

    [Fact]
    public void OnOutputLine_NoUrlInLine_DoesNotRaiseEvent()
    {
        var manager = NewTunnelManager();
        var raised = false;
        manager.TunnelUrlChanged += _ => raised = true;

        InvokeOnOutputLine(manager, "just a regular log line with no url in it");

        Assert.False(raised);
        Assert.Null(manager.CurrentUrl);
    }

    [Fact]
    public void OnOutputLine_SameUrlTwice_RaisesEventOnlyOnce()
    {
        var manager = NewTunnelManager();
        var raiseCount = 0;
        manager.TunnelUrlChanged += _ => raiseCount++;

        InvokeOnOutputLine(manager, "https://same-url.trycloudflare.com");
        InvokeOnOutputLine(manager, "https://same-url.trycloudflare.com");

        Assert.Equal(1, raiseCount);
    }
}
