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

                using var db = new AppDatabase();
                var devices = db.Devices.Where(d => d.Enabled).ToList();
                if (devices.Count == 0)
                {
                    _logger.LogWarning("No paired devices found");
                    await WritePipeAsync(pipe, "NO_DEVICES", ct);
                    AuthWorker.IsAuthWaiting = false;
                    return;
                }

                // Progress messages for the credential provider tile — see docs/plan_push_auth_v2.md,
                // "📡 FCM: Manejo de Fallos" / "🛡️ Defensa contra Push Fatigue": STATUS:searching,
                // STATUS:push_sent:<name>, STATUS:code:<NN>, STATUS:timeout, STATUS:blocked:<reason>.
                // Parsing these on the C++ side is Fase 9 — here we just make sure something is on the
                // wire for it to consume; unrecognized STATUS values should be safely ignorable by the CP.
                async Task SendStatusAsync(string status)
                {
                    try { await WritePipeAsync(pipe, "STATUS:" + status, ct); }
                    catch { /* CP may have disconnected — the outer auth flow doesn't depend on this */ }
                }

                AuthRaceOutcome outcome;
                if (AuthWorker.Instance != null)
                {
                    // RunAuthRaceAsync (Fase 3) orchestrates Ruta A/B/C in parallel and awaits the
                    // legacy AuthEvent asynchronously (no blocking .Wait()) internally.
                    outcome = await AuthWorker.Instance.RunAuthRaceAsync(SendStatusAsync, ct);
                }
                else
                {
                    // Fallback: UDP only (AuthWorker not started — shouldn't normally happen)
                    using var udp = new UdpManager();
                    foreach (var device in devices)
                    {
                        var payload = Convert.ToBase64String(device.DeviceId.ToByteArray());
                        var message = Protocol.AuthDiscoverPrefix + payload;
                        await udp.SendToDeviceAsync(message, device.LastIpAddress);
                    }

                    var signaled = await WaitAuthEventAsync(TimeSpan.FromSeconds(60), ct);
                    outcome = new AuthRaceOutcome(signaled);
                }

                if (outcome.Success && AuthWorker.AuthenticatedPassword != null)
                {
                    _logger.LogInformation("Sending auth credentials to credential provider");
                    await WritePipeAsync(pipe, Protocol.PipeCmd_AuthReady + "\n" + AuthWorker.AuthenticatedPassword, ct);
                    AuthWorker.AuthenticatedPassword = null;
                    AuthWorker.AuthEvent.Reset();
                }
                else
                {
                    _logger.LogInformation("Auth timeout, rejected, or cancelled");
                    await WritePipeAsync(pipe, "TIMEOUT", ct);
                }

                AuthWorker.IsAuthWaiting = false;
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

    /// <summary>
    /// Non-blocking wait on <see cref="AuthWorker.AuthEvent"/> for the rare fallback path where
    /// <see cref="AuthWorker.Instance"/> isn't available. Mirrors the same WaitHandle-to-Task bridge
    /// used in <c>AuthWorker.WaitOneAsync</c> — replaces the previous blocking
    /// <c>AuthWorker.AuthEvent.Wait(60_000, ct)</c> call (docs/plan_push_auth_v2.md, Fase 3 fix).
    /// </summary>
    private static Task<bool> WaitAuthEventAsync(TimeSpan timeout, CancellationToken ct)
    {
        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var registeredHandle = ThreadPool.RegisterWaitForSingleObject(
            AuthWorker.AuthEvent.WaitHandle,
            (state, timedOut) => ((TaskCompletionSource<bool>)state!).TrySetResult(!timedOut),
            tcs, timeout, executeOnlyOnce: true);
        var ctRegistration = ct.Register(() => tcs.TrySetCanceled(ct));

        return Await();

        async Task<bool> Await()
        {
            try { return await tcs.Task; }
            catch (OperationCanceledException) { return false; }
            finally
            {
                registeredHandle.Unregister(null);
                ctRegistration.Dispose();
            }
        }
    }
}
