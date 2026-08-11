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
    private readonly ITunnelStatusProvider _tunnelStatus;

    /// <param name="tunnelStatus">
    /// Fase 12 (TrayApp Config UI, docs/plan_push_auth_v2.md): the same <see cref="ITunnelStatusProvider"/>
    /// singleton Fase 4 registers in <c>Program.cs</c> (a thin adapter over <see cref="TunnelManager"/>) —
    /// answers <see cref="Protocol.AdminCmd_GetRelayStatus"/> without needing to reach into <see cref="AuthWorker"/>.
    /// DI resolves this automatically since it's already registered before this hosted service.
    /// </param>
    public AdminPipeServer(ILogger<AdminPipeServer> logger, ITunnelStatusProvider tunnelStatus)
    {
        _logger = logger;
        _tunnelStatus = tunnelStatus;
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
            else if (command == Protocol.AdminCmd_GetRelayStatus)
            {
                await HandleGetRelayStatus(pipe, ct);
            }
            else if (command.StartsWith(Protocol.AdminCmd_SetPushAuth))
            {
                await HandleSetPushAuth(pipe, command, ct);
            }
            else if (command.StartsWith(Protocol.AdminCmd_DeleteDevice))
            {
                await HandleDeleteDevice(pipe, command, ct);
            }
            else if (command.StartsWith(Protocol.AdminCmd_SetDeviceEnabled))
            {
                await HandleSetDeviceEnabled(pipe, command, ct);
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

    /// <summary>
    /// Fase 12 (TrayApp Config UI): answers <see cref="Protocol.AdminCmd_GetRelayStatus"/> with the
    /// Service's current Cloudflare Tunnel public URL, if any. The TrayApp only needs this as a
    /// fallback when it has no already-paired, enabled <c>DeviceInfo.RelayUrl</c> to read locally from
    /// its own copy of <c>AppDatabase</c> (e.g. the very first pairing ever, before any device exists).
    /// </summary>
    private async Task HandleGetRelayStatus(NamedPipeServerStream pipe, CancellationToken ct)
    {
        var url = _tunnelStatus.PublicUrl ?? "";
        await WritePipeAsync(pipe, $"{Protocol.AdminResp_RelayStatus}\n{url}", ct);
    }

    /// <summary>
    /// Fase 12 (TrayApp Config UI): handles <see cref="Protocol.AdminCmd_SetPushAuth"/>
    /// ("SET_PUSH_AUTH\n{deviceId}\n{0|1}"). Prefers <see cref="AuthWorker.SetDevicePushAuthEnabled"/>
    /// (writes through the SAME tracked <see cref="AppDatabase"/> instance <c>AuthWorker.RunAuthRaceAsync</c>
    /// reads from — see that method's XML doc for why that matters); falls back to a fresh
    /// <see cref="AppDatabase"/> write only in the unlikely case <see cref="AuthWorker.Instance"/> isn't
    /// up yet (Service still starting), matching the existing fallback pattern already used by
    /// <c>PipeServer.WaitAuthEventAsync</c> for the same edge case.
    /// </summary>
    private async Task HandleSetPushAuth(NamedPipeServerStream pipe, string command, CancellationToken ct)
    {
        try
        {
            var parts = command.Split('\n');
            if (parts.Length != 3 || !Guid.TryParse(parts[1].Trim(), out var deviceId) ||
                (parts[2].Trim() != "0" && parts[2].Trim() != "1"))
            {
                await WritePipeAsync(pipe, Protocol.AdminResp_Error + "\nMalformed SET_PUSH_AUTH command", ct);
                return;
            }

            var enabled = parts[2].Trim() == "1";

            var applied = AuthWorker.Instance?.SetDevicePushAuthEnabled(deviceId, enabled) ?? false;
            if (!applied)
            {
                // AuthWorker not started yet (rare) — fall back to a fresh, one-off AppDatabase write.
                using var freshDb = new AppDatabase();
                var device = freshDb.Devices.Find(deviceId);
                if (device == null)
                {
                    await WritePipeAsync(pipe, Protocol.AdminResp_Error + "\nUnknown device_id", ct);
                    return;
                }
                device.PushAuthEnabled = enabled;
                freshDb.SaveChanges();
                applied = true;
            }

            await WritePipeAsync(pipe, Protocol.AdminResp_Ok, ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error handling SET_PUSH_AUTH");
            try { await WritePipeAsync(pipe, Protocol.AdminResp_Error + "\n" + ex.Message, ct); } catch { }
        }
    }

    /// <summary>
    /// Handles <see cref="Protocol.AdminCmd_DeleteDevice"/> ("DELETE_DEVICE\n{deviceId}"). Same
    /// AuthWorker-first / fresh-AppDatabase-fallback pattern as <see cref="HandleSetPushAuth"/> —
    /// see <c>AuthWorker.DeleteDevice</c> for why the Service must be the one performing the write.
    /// </summary>
    private async Task HandleDeleteDevice(NamedPipeServerStream pipe, string command, CancellationToken ct)
    {
        try
        {
            var parts = command.Split('\n');
            if (parts.Length != 2 || !Guid.TryParse(parts[1].Trim(), out var deviceId))
            {
                await WritePipeAsync(pipe, Protocol.AdminResp_Error + "\nMalformed DELETE_DEVICE command", ct);
                return;
            }

            var applied = AuthWorker.Instance?.DeleteDevice(deviceId) ?? false;
            if (!applied)
            {
                using var freshDb = new AppDatabase();
                var device = freshDb.Devices.Find(deviceId);
                if (device == null)
                {
                    await WritePipeAsync(pipe, Protocol.AdminResp_Error + "\nUnknown device_id", ct);
                    return;
                }
                freshDb.Devices.Remove(device);
                freshDb.SaveChanges();
            }

            await WritePipeAsync(pipe, Protocol.AdminResp_Ok, ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error handling DELETE_DEVICE");
            try { await WritePipeAsync(pipe, Protocol.AdminResp_Error + "\n" + ex.Message, ct); } catch { }
        }
    }

    /// <summary>
    /// Handles <see cref="Protocol.AdminCmd_SetDeviceEnabled"/> ("SET_DEVICE_ENABLED\n{deviceId}\n{0|1}").
    /// Same AuthWorker-first / fresh-AppDatabase-fallback pattern as <see cref="HandleSetPushAuth"/> —
    /// see <c>AuthWorker.SetDeviceEnabled</c> for why the Service must be the one performing the write.
    /// </summary>
    private async Task HandleSetDeviceEnabled(NamedPipeServerStream pipe, string command, CancellationToken ct)
    {
        try
        {
            var parts = command.Split('\n');
            if (parts.Length != 3 || !Guid.TryParse(parts[1].Trim(), out var deviceId) ||
                (parts[2].Trim() != "0" && parts[2].Trim() != "1"))
            {
                await WritePipeAsync(pipe, Protocol.AdminResp_Error + "\nMalformed SET_DEVICE_ENABLED command", ct);
                return;
            }

            var enabled = parts[2].Trim() == "1";

            var applied = AuthWorker.Instance?.SetDeviceEnabled(deviceId, enabled) ?? false;
            if (!applied)
            {
                using var freshDb = new AppDatabase();
                var device = freshDb.Devices.Find(deviceId);
                if (device == null)
                {
                    await WritePipeAsync(pipe, Protocol.AdminResp_Error + "\nUnknown device_id", ct);
                    return;
                }
                device.Enabled = enabled;
                freshDb.SaveChanges();
            }

            await WritePipeAsync(pipe, Protocol.AdminResp_Ok, ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error handling SET_DEVICE_ENABLED");
            try { await WritePipeAsync(pipe, Protocol.AdminResp_Error + "\n" + ex.Message, ct); } catch { }
        }
    }

    private static async Task WritePipeAsync(NamedPipeServerStream pipe, string message, CancellationToken ct)
    {
        var data = Encoding.UTF8.GetBytes(message);
        await pipe.WriteAsync(data, ct);
        await pipe.FlushAsync(ct);
    }
}
