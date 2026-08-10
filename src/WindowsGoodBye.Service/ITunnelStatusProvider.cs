namespace WindowsGoodBye.Service;

/// <summary>
/// Oracle for "does this PC currently have a working path to the internet for push auth" — see
/// docs/plan_push_auth_v2.md, decision #5 and "🔄 Algoritmo de Decisión del Modo Hybrid" ("Estado del
/// túnel = ¿tengo internet para push? — detección instantánea").
///
/// <see cref="AuthWorker"/> (Fase 3) depends on this small interface instead of <see cref="TunnelManager"/>
/// directly:
/// <list type="bullet">
/// <item><description><b>Fase 4 (current state)</b>: <c>Program.cs</c> registers <see cref="TunnelStatusAdapter"/>
/// (a thin wrapper over <see cref="TunnelManager.IsRunning"/>/<see cref="TunnelManager.CurrentUrl"/>,
/// see <c>TunnelHostedService.cs</c>) as the DI singleton for this interface — <see cref="AuthWorker"/>
/// receives it automatically via its existing optional constructor parameter, no AuthWorker changes
/// were needed. In an environment with no <c>cloudflared.exe</c> installed (e.g. this dev/test
/// environment), <see cref="TunnelManager.IsRunning"/> stays false, so <see cref="TunnelStatusAdapter.IsConnected"/>
/// correctly reports "not connected" and Ruta B/C simply don't fire — direct transports (Ruta A) are
/// entirely unaffected either way.</description></item>
/// <item><description><see cref="NullTunnelStatusProvider"/> (below) remains the default used only when
/// nothing is registered in DI — e.g. tests/callers that construct <see cref="AuthWorker"/> directly
/// without going through <c>Program.cs</c>'s host.</description></item>
/// </list>
/// </summary>
public interface ITunnelStatusProvider
{
    /// <summary>True when the Cloudflare Tunnel is up and the relay is reachable from the internet.</summary>
    bool IsConnected { get; }

    /// <summary>The current public relay URL, if known (e.g. "https://wingb-xxx.trycloudflare.com").</summary>
    string? PublicUrl { get; }
}

/// <summary>Default "no tunnel" stand-in used until Fase 4 registers a real <see cref="ITunnelStatusProvider"/>.</summary>
public sealed class NullTunnelStatusProvider : ITunnelStatusProvider
{
    public static readonly NullTunnelStatusProvider Instance = new();

    public bool IsConnected => false;
    public string? PublicUrl => null;
}
