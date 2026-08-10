using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using WindowsGoodBye.Core;

namespace WindowsGoodBye.Service;

/// <summary>
/// Named pipe server for TrayApp → Service communication.
/// Receives admin commands: start pairing, cancel pairing, etc.
/// Sends back results: pairing completed, errors.
/// </summary>
public class AdminPipeServer : BackgroundService
{
    private readonly ILogger<AdminPipeServer> _logger;

    public AdminPipeServer(ILogger<AdminPipeServer> logger)
    {
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Admin pipe server starting on pipe: {PipeName}", Protocol.AdminPipeName);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                // SECURITY (docs/plan_push_auth_v2.md, Fase 0 bonus / Fisura F): this pipe accepts
                // privileged admin commands (e.g. PAIR_START, which installs new crypto key material).
                // It previously granted Everyone + FullControl — any local process (including a
                // sandboxed/compromised one, Guest sessions, etc.) could not only talk to it but also
                // rewrite its ACL or take ownership. We restrict to:
                //   - BUILTIN\Administrators / NT AUTHORITY\SYSTEM: FullControl, for admin tooling
                //     and the Service's own SYSTEM identity.
                //   - INTERACTIVE (any locally logged-on console/RDP user): ReadWrite only.
                // The INTERACTIVE grant is required because the TrayApp — the only real caller of
                // this pipe — runs as the plain logged-in user with no elevation (no app.manifest
                // requestedExecutionLevel="requireAdministrator"), and on a UAC-enabled admin account
                // that process's token carries Administrators only as "use for deny only", so an
                // Administrators-only ACL would silently lock the TrayApp out. Scoping to INTERACTIVE
                // instead of Everyone still removes the actual attack surface this fix targets:
                // Network, Anonymous, Guest and other non-interactive/service SIDs. The plan's own
                // wording allows for this ("... o el usuario de sesión interactiva concreto)").
                var ps = new PipeSecurity();
                ps.AddAccessRule(new PipeAccessRule(
                    new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                    PipeAccessRights.FullControl,
                    AccessControlType.Allow));
                ps.AddAccessRule(new PipeAccessRule(
                    new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                    PipeAccessRights.FullControl,
                    AccessControlType.Allow));
                ps.AddAccessRule(new PipeAccessRule(
                    new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),
                    PipeAccessRights.ReadWrite,
                    AccessControlType.Allow));

                using var pipe = NamedPipeServerStreamAcl.Create(
                    Protocol.AdminPipeName,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Message,
                    PipeOptions.Asynchronous,
                    0, 0, ps);

                await pipe.WaitForConnectionAsync(stoppingToken);
                _logger.LogInformation("TrayApp connected to admin pipe");

                await HandleAdminClientAsync(pipe, stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Admin pipe server error");
                await Task.Delay(1000, stoppingToken);
            }
        }
    }

    private async Task HandleAdminClientAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        try
        {
            var buffer = new byte[4096];
            var bytesRead = await pipe.ReadAsync(buffer, ct);
            var command = Encoding.UTF8.GetString(buffer, 0, bytesRead).Trim();

            if (command.StartsWith(Protocol.AdminCmd_PairStart))
            {
                await HandlePairStart(pipe, command, ct);
            }
            else if (command == Protocol.AdminCmd_PairCancel)
            {
                PairingSession.Active = null;
                _logger.LogInformation("Pairing session cancelled by TrayApp");
                await WritePipeAsync(pipe, Protocol.AdminResp_Ok, ct);
            }
            else
            {
                _logger.LogWarning("Unknown admin command: {Cmd}", command);
                await WritePipeAsync(pipe, Protocol.AdminResp_Error + "\nUnknown command", ct);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Error handling admin pipe client");
        }
    }

    private async Task HandlePairStart(NamedPipeServerStream pipe, string command, CancellationToken ct)
    {
        try
        {
            // Command format: PAIR_START\n<base64 keys>
            var newlineIdx = command.IndexOf('\n');
            if (newlineIdx < 0)
            {
                await WritePipeAsync(pipe, Protocol.AdminResp_Error + "\nMissing key payload", ct);
                return;
            }

            var keysBase64 = command[(newlineIdx + 1)..].Trim();
            var session = PairingSession.FromSerializedKeys(keysBase64);
            PairingSession.Active = session;

            _logger.LogInformation("Pairing session started via admin pipe. DeviceId: {Id}", session.DeviceId);
            await WritePipeAsync(pipe, Protocol.AdminResp_Ok, ct);

            // Now wait for the pairing to complete (the AuthWorker will call session.Complete)
            // Keep the pipe open so we can send the result back to TrayApp
            try
            {
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeoutCts.CancelAfter(TimeSpan.FromMinutes(2)); // 2 min timeout

                var (name, model) = await session.WaitForCompletionAsync(timeoutCts.Token);

                var response = $"{Protocol.AdminResp_PairDone}\n{name}\n{model}";
                await WritePipeAsync(pipe, response, ct);
                _logger.LogInformation("Pairing result sent to TrayApp: {Name} ({Model})", name, model);
            }
            catch (TaskCanceledException)
            {
                PairingSession.Active = null;
                _logger.LogInformation("Pairing session timed out or was cancelled");
                // Pipe may already be disconnected if TrayApp closed the dialog
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in PairStart handler");
            try { await WritePipeAsync(pipe, Protocol.AdminResp_Error + "\n" + ex.Message, ct); } catch { }
            PairingSession.Active = null;
        }
    }

    private static async Task WritePipeAsync(NamedPipeServerStream pipe, string message, CancellationToken ct)
    {
        var data = Encoding.UTF8.GetBytes(message);
        await pipe.WriteAsync(data, ct);
        await pipe.FlushAsync(ct);
    }
}
