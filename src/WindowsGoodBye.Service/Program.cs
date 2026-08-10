using System.Diagnostics;
using WindowsGoodBye.Core;
using WindowsGoodBye.Service;

// --- Service install/uninstall via command-line ---
if (args.Length > 0)
{
    var cmd = args[0].ToLowerInvariant();
    var exePath = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule!.FileName;

    if (cmd is "install" or "--install")
    {
        Console.WriteLine("Installing WindowsGoodBye service...");
        RunSc($"create WindowsGoodByeService binPath= \"\\\"{exePath}\\\"\" start= auto DisplayName= \"WindowsGoodBye Auth Service\"");
        RunSc("description WindowsGoodByeService \"Handles fingerprint unlock from paired Android devices\"");
        RunSc("failure WindowsGoodByeService reset= 60 actions= restart/5000/restart/10000/restart/30000");
        Console.WriteLine("Service installed. Start with: sc start WindowsGoodByeService");
        return;
    }
    if (cmd is "uninstall" or "--uninstall")
    {
        Console.WriteLine("Stopping and removing WindowsGoodBye service...");
        RunSc("stop WindowsGoodByeService");
        RunSc("delete WindowsGoodByeService");
        Console.WriteLine("Service removed.");
        return;
    }
    if (cmd is "start" or "--start")
    {
        RunSc("start WindowsGoodByeService");
        return;
    }

    static void RunSc(string arguments)
    {
        try
        {
            var p = Process.Start(new ProcessStartInfo("sc.exe", arguments)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            });
            p?.WaitForExit(10_000);
            var output = p?.StandardOutput.ReadToEnd()?.Trim();
            if (!string.IsNullOrEmpty(output)) Console.WriteLine("  " + output);
            var error = p?.StandardError.ReadToEnd()?.Trim();
            if (!string.IsNullOrEmpty(error)) Console.WriteLine("  ERROR: " + error);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  Failed: {ex.Message}");
        }
    }
}

// --- Normal service startup ---
var builder = Host.CreateDefaultBuilder(args);

builder.UseWindowsService(options =>
{
    options.ServiceName = "WindowsGoodByeService";
});

builder.ConfigureServices((context, services) =>
{
    var configuration = context.Configuration;

    // --- Fase 4 (docs/plan_push_auth_v2.md, "Startup del Service"): embedded relay (Ruta C) +
    // Cloudflare Tunnel are now Service-owned singletons/hosted services, registered BEFORE AuthWorker
    // so both are already running by the time AuthWorker.ExecuteAsync starts (DI hosted services start
    // sequentially, in registration order). AuthWorker/PipeServer are unmodified — DI injects the
    // RelayServer singleton and the ITunnelStatusProvider singleton into AuthWorker's existing optional
    // constructor parameters automatically.
    services.AddSingleton(sp => new RelayServer(
        sp.GetRequiredService<ILogger<RelayServer>>(),
        deviceIdStr => RelayKeyResolver.Resolve(deviceIdStr, sp.GetRequiredService<ILogger<RelayServer>>())));
    services.AddHostedService<RelayHostedService>();

    services.AddSingleton(sp =>
    {
        // Fase 11 (installer) is responsible for actually downloading/checksum-verifying
        // cloudflared.exe and dropping it next to the Service executable (or wherever
        // Tunnel:CloudflaredPath points). This batch only wires the plumbing — TunnelHostedService
        // tolerates the file being absent (logs a warning, Ruta A/B unaffected) rather than crashing.
        var cloudflaredPath = configuration["Tunnel:CloudflaredPath"];
        if (string.IsNullOrWhiteSpace(cloudflaredPath))
            cloudflaredPath = Path.Combine(AppContext.BaseDirectory, "cloudflared.exe");

        // Named Tunnel token (stable URL, recommended — see plan's "Opciones de túnel"). Empty/unset
        // falls back to a Quick Tunnel (random URL, rotates every restart).
        var namedTunnelToken = configuration["Tunnel:NamedTunnelToken"];

        return new TunnelManager(
            sp.GetRequiredService<ILogger<TunnelManager>>(),
            cloudflaredPath,
            Protocol.RelayPort,
            string.IsNullOrWhiteSpace(namedTunnelToken) ? null : namedTunnelToken);
    });
    services.AddHostedService<TunnelHostedService>();
    services.AddSingleton<ITunnelStatusProvider>(sp => new TunnelStatusAdapter(sp.GetRequiredService<TunnelManager>()));

    services.AddHostedService<AuthWorker>();
    services.AddHostedService<PipeServer>();
    services.AddHostedService<AdminPipeServer>();
});

var host = builder.Build();
await host.RunAsync();
