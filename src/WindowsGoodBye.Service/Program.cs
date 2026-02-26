using WindowsGoodBye.Service;

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
