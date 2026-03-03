using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using WindowsGoodBye.Core;

namespace WindowsGoodBye.Service;

/// <summary>
/// Named pipe server that communicates with the Credential Provider DLL.
/// The credential provider connects when the lock screen is shown and waits
/// for an auth signal. When the phone authenticates, this server sends the
/// stored credentials through the pipe for auto-login.
/// </summary>
public class PipeServer : BackgroundService
{
    private readonly ILogger<PipeServer> _logger;

    public PipeServer(ILogger<PipeServer> logger)
    {
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Pipe server starting on pipe: {PipeName}", Protocol.PipeName);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                // Create a pipe with ACL allowing any user to connect (needed when Service runs as SYSTEM)
                var ps = new PipeSecurity();
                ps.AddAccessRule(new PipeAccessRule(
                    new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                    PipeAccessRights.ReadWrite,
                    AccessControlType.Allow));
                ps.AddAccessRule(new PipeAccessRule(
                    new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                    PipeAccessRights.FullControl,
                    AccessControlType.Allow));

                using var pipe = NamedPipeServerStreamAcl.Create(
                    Protocol.PipeName,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Message,
                    PipeOptions.Asynchronous,
                    0, 0, ps);

                _logger.LogDebug("Waiting for credential provider connection...");
                await pipe.WaitForConnectionAsync(stoppingToken);
                _logger.LogInformation("Credential provider connected!");

                await HandleClientAsync(pipe, stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Pipe server error");
                await Task.Delay(1000, stoppingToken);
            }
        }
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        try
        {
            var buffer = new byte[1024];
            var bytesRead = await pipe.ReadAsync(buffer, ct);
            var command = Encoding.UTF8.GetString(buffer, 0, bytesRead).Trim();

            if (command == Protocol.PipeCmd_Waiting)
            {
                _logger.LogInformation("Credential provider is waiting for auth...");

                // Signal that the lock screen is active — allow auth challenges
                AuthWorker.IsAuthWaiting = true;
                // Reset any stale auth from previous sessions
                AuthWorker.AuthenticatedPassword = null;
                AuthWorker.AuthEvent.Reset();

                // Trigger device discovery
                // The AuthWorker will handle responses and set AuthEvent
                var db = new AppDatabase();
                var devices = db.Devices.Where(d => d.Enabled).ToList();
                if (devices.Count == 0)
                {
                    _logger.LogWarning("No paired devices found");
                    await WritePipeAsync(pipe, "NO_DEVICES", ct);
                    return;
                }

                // Send discovery to all devices via ALL active transports
                if (AuthWorker.Instance != null)
                {
                    await AuthWorker.Instance.DiscoverDevicesAsync();
                }
                else
                {
                    // Fallback: UDP only
                    using var udp = new UdpManager();
                    foreach (var device in devices)
                    {
                        var payload = Convert.ToBase64String(device.DeviceId.ToByteArray());
                        var message = Protocol.AuthDiscoverPrefix + payload;
                        await udp.SendToDeviceAsync(message, device.LastIpAddress);
                    }
                }

                // Wait for auth (up to 60 seconds)
                var authReceived = AuthWorker.AuthEvent.Wait(60_000, ct);

                if (authReceived && AuthWorker.AuthenticatedPassword != null)
                {
                    _logger.LogInformation("Sending auth credentials to credential provider");
                    await WritePipeAsync(pipe, Protocol.PipeCmd_AuthReady + "\n" + AuthWorker.AuthenticatedPassword, ct);
                    AuthWorker.AuthenticatedPassword = null;
                    AuthWorker.AuthEvent.Reset();
                    AuthWorker.IsAuthWaiting = false;
                }
                else
                {
                    _logger.LogInformation("Auth timeout or cancelled");
                    await WritePipeAsync(pipe, "TIMEOUT", ct);
                    AuthWorker.IsAuthWaiting = false;
                }
            }
            else if (command == Protocol.PipeCmd_Cancel)
            {
                _logger.LogInformation("Credential provider cancelled auth request");
                AuthWorker.IsAuthWaiting = false;
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Error handling credential provider client");
        }
    }

    private static async Task WritePipeAsync(NamedPipeServerStream pipe, string message, CancellationToken ct)
    {
        var data = Encoding.UTF8.GetBytes(message);
        await pipe.WriteAsync(data, ct);
        await pipe.FlushAsync(ct);
    }
}
