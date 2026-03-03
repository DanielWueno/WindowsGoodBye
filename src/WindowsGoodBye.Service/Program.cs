using System.Diagnostics;
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

builder.ConfigureServices(services =>
{
    services.AddHostedService<AuthWorker>();
    services.AddHostedService<PipeServer>();
    services.AddHostedService<AdminPipeServer>();
});

var host = builder.Build();
await host.RunAsync();
