using System.IO;
using System.IO.Pipes;
using System.Text;
using Microsoft.EntityFrameworkCore;
using WindowsGoodBye.Core;

namespace WindowsGoodBye.TrayApp;

/// <summary>
/// System tray application for managing WindowsGoodBye.
/// Provides: pairing with Android devices, credential setup, device management.
/// </summary>
public class TrayApplicationContext : ApplicationContext
{
    private readonly NotifyIcon _trayIcon;
    private readonly AppDatabase _db;
    private readonly UdpManager _udp;
    private ManageDevicesWindow? _mainWindow;

    public TrayApplicationContext()
    {
        _db = new AppDatabase();
        _db.Initialize();

        _udp = new UdpManager();
        _udp.MessageReceived += OnUdpMessage;
        _udp.StartListening();

        _trayIcon = new NotifyIcon
        {
            Icon = TrayIcon.Load(),
            Text = "WindowsGoodBye - Desbloquea con tu telefono",
            Visible = true,
            ContextMenuStrip = CreateContextMenu()
        };

        _trayIcon.DoubleClick += (_, _) => ShowMainForm();
    }

    private ContextMenuStrip CreateContextMenu()
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add("Emparejar dispositivo nuevo", null, (_, _) => StartPairing());
        menu.Items.Add("Configurar contrasena de Windows", null, (_, _) => SetCredentials());
        menu.Items.Add("Administrar dispositivos", null, (_, _) => ShowMainForm());
        menu.Items.Add(CreatePushAuthMenuItem());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Probar conexion con el Servicio", null, (_, _) => TestServiceConnection());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Salir", null, (_, _) => ExitApp());
        return menu;
    }

    // --- Fase 12 (docs/plan_push_auth_v2.md): Push Auth config UI ---

    /// <summary>
    /// "Push Auth" top-level menu item with one submenu per paired device (Habilitado/Deshabilitado).
    /// The device list is rebuilt on every <c>DropDownOpening</c> (not once at construction time) so it
    /// always reflects whatever is currently paired/toggled — including changes made from a second
    /// TrayApp session or a fresh pairing since the tray icon was created.
    /// </summary>
    private ToolStripMenuItem CreatePushAuthMenuItem()
    {
        var item = new ToolStripMenuItem("Push Auth");
        item.DropDownOpening += (_, _) => RebuildPushAuthSubmenu(item);
        return item;
    }

    private void RebuildPushAuthSubmenu(ToolStripMenuItem parent)
    {
        parent.DropDownItems.Clear();

        List<DeviceInfo> devices;
        try
        {
            // AsNoTracking: this TrayApp's _db is long-lived (constructed once, in the constructor) —
            // without AsNoTracking, once a DeviceInfo is tracked from an earlier query (e.g. opening
            // "Manage Devices"), EF Core's identity map would keep returning that SAME stale instance
            // here instead of re-reading PushAuthEnabled/FcmTokenValid from disk. The Service is the
            // sole writer of PushAuthEnabled (see AuthWorker.SetDevicePushAuthEnabled) precisely so this
            // read-only view always reflects the latest value without the TrayApp needing to write here.
            devices = _db.Devices.AsNoTracking().OrderBy(d => d.FriendlyName).ToList();
        }
        catch (Exception ex)
        {
            parent.DropDownItems.Add(new ToolStripMenuItem($"Error: {ex.Message}") { Enabled = false });
            return;
        }

        if (devices.Count == 0)
        {
            parent.DropDownItems.Add(new ToolStripMenuItem("(No hay dispositivos emparejados)") { Enabled = false });
            return;
        }

        foreach (var device in devices)
        {
            // "No disponible" per docs/plan_push_auth_v2.md Fase 12: a device can have Push Auth
            // enabled as a *preference* while technically unable to receive it right now because its
            // FCM token is known-bad (DeviceInfo.FcmTokenValid, set false by AuthWorker.HandleFcmSendResult
            // on a 404/UNREGISTERED from FCM) or simply missing (never synced yet). The toggle itself
            // still works either way — it's a preference for when the token DOES become valid again.
            var available = device.FcmTokenValid && !string.IsNullOrEmpty(device.FcmToken);
            var deviceItem = new ToolStripMenuItem(available ? device.FriendlyName : $"{device.FriendlyName} (no disponible)");
            if (!available)
            {
                deviceItem.ToolTipText = "Sin token FCM valido — requiere reconexion directa (Bluetooth/USB/WiFi) o re-emparejamiento.";
            }

            var enabledItem = new ToolStripMenuItem("Habilitado") { Checked = device.PushAuthEnabled };
            var disabledItem = new ToolStripMenuItem("Deshabilitado") { Checked = !device.PushAuthEnabled };

            enabledItem.Click += async (_, _) => await SetPushAuthPreferenceAsync(device, true, enabledItem, disabledItem);
            disabledItem.Click += async (_, _) => await SetPushAuthPreferenceAsync(device, false, enabledItem, disabledItem);

            deviceItem.DropDownItems.Add(enabledItem);
            deviceItem.DropDownItems.Add(disabledItem);
            parent.DropDownItems.Add(deviceItem);
        }
    }

    /// <summary>
    /// Sends <see cref="Protocol.AdminCmd_SetPushAuth"/> to the Service — which performs the actual
    /// <c>DeviceInfo.PushAuthEnabled</c> write in <c>AppDatabase</c> (see <c>AdminPipeServer.HandleSetPushAuth</c>
    /// / <c>AuthWorker.SetDevicePushAuthEnabled</c>), not the TrayApp itself. This keeps a single writer
    /// of that column and sidesteps the EF Core identity-map staleness gap a direct TrayApp-side write
    /// (a different DbContext/connection than the Service's own long-lived one) would otherwise leave
    /// until the Service restarts — documented in detail on <c>AuthWorker.SetDevicePushAuthEnabled</c>.
    /// </summary>
    private static async Task SetPushAuthPreferenceAsync(
        DeviceInfo device, bool enabled, ToolStripMenuItem enabledItem, ToolStripMenuItem disabledItem)
    {
        var command = $"{Protocol.AdminCmd_SetPushAuth}\n{device.DeviceId}\n{(enabled ? "1" : "0")}";
        var response = await AdminClient.SendCommandAsync(command);

        if (response != null && response.StartsWith(Protocol.AdminResp_Ok))
        {
            enabledItem.Checked = enabled;
            disabledItem.Checked = !enabled;
        }
        else
        {
            MessageBox.Show(
                "No se pudo actualizar la preferencia de Push Auth.\n\n" +
                "Asegurate de que el Servicio WindowsGoodBye este en ejecucion.",
                "Push Auth", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    /// <summary>
    /// Resolves what to pass to <c>PairingSession.GenerateQrData(relayUrl, pushAuthEnabledDefault)</c> —
    /// see docs/implementation_progress_push_auth_v2.md, Fase 10's note to Fase 12: before this method
    /// existed, <see cref="StartPairing"/> called <c>GenerateQrData()</c> with no arguments, so every QR
    /// carried an empty relay_url and Android never learned the tunnel URL until a later auth_challenge.
    /// </summary>
    private (string? relayUrl, bool pushAuthEnabledDefault) ResolvePairingDefaults()
    {
        string? relayUrl = null;
        try
        {
            // Cheapest source of truth, no IPC needed: TunnelHostedService (Fase 4) keeps
            // DeviceInfo.RelayUrl in sync for every enabled device whenever the tunnel URL changes, so
            // any already-paired device's column already holds the Service's current relay URL.
            relayUrl = _db.Devices.AsNoTracking()
                .Where(d => d.Enabled && d.RelayUrl != null && d.RelayUrl != "")
                .Select(d => d.RelayUrl)
                .FirstOrDefault();
        }
        catch { /* best effort — fall through to asking the Service directly */ }

        if (string.IsNullOrEmpty(relayUrl))
        {
            // No paired device yet (e.g. the very first pairing ever) — ask the Service directly; it
            // always knows its own current ITunnelStatusProvider.PublicUrl even before any device
            // exists to persist it on. Bounded synchronous wait (same pattern already used by
            // TestServiceConnection's pipe.Connect) — acceptable for a one-off pairing-setup click.
            var response = AdminClient.SendCommandAsync(Protocol.AdminCmd_GetRelayStatus).GetAwaiter().GetResult();
            if (response != null && response.StartsWith(Protocol.AdminResp_RelayStatus))
            {
                var parts = response.Split('\n');
                if (parts.Length > 1 && !string.IsNullOrWhiteSpace(parts[1]))
                    relayUrl = parts[1];
            }
        }

        // No dedicated "default Push Auth for new pairings" setting exists (out of scope for this
        // batch — see docs/implementation_progress_push_auth_v2.md, Fase 12 notes): true matches
        // DeviceInfo.PushAuthEnabled's own default; the user can flip it per-device afterwards from the
        // new "Push Auth" tray menu above.
        return (relayUrl, true);
    }

    private void ShowMainForm()
    {
        if (_mainWindow != null && _mainWindow.IsVisible)
        {
            _mainWindow.Activate();
            return;
        }

        _mainWindow = new ManageDevicesWindow();
        _mainWindow.Closed += (_, _) => _mainWindow = null;
        _mainWindow.Show();
        _mainWindow.Activate();
    }

    private void StartPairing()
    {
        var session = new PairingSession();
        PairingSession.Active = session;

        // Fase 12 (docs/plan_push_auth_v2.md): pass the Service's real relay_url + the Push Auth
        // default so Android learns the tunnel URL and initial preference from the QR itself, instead
        // of leaving the relay_url segment empty until a later auth_challenge (see
        // docs/implementation_progress_push_auth_v2.md, Fase 10's note to this phase).
        var (relayUrl, pushAuthEnabledDefault) = ResolvePairingDefaults();

        var window = new PairDeviceWindow(session, relayUrl, pushAuthEnabledDefault);
        window.ShowDialog();
    }

    private void SetCredentials()
    {
        var window = new CredentialsWindow();
        window.ShowDialog();
    }

    private void TestServiceConnection()
    {
        try
        {
            using var pipe = new System.IO.Pipes.NamedPipeClientStream(".", Protocol.PipeName,
                System.IO.Pipes.PipeDirection.InOut, System.IO.Pipes.PipeOptions.None);
            pipe.Connect(3000);
            MessageBox.Show("Conexion exitosa con el Servicio WindowsGoodBye!",
                "Conexion con el Servicio", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (TimeoutException)
        {
            MessageBox.Show("No se pudo conectar con el Servicio WindowsGoodBye.\n\n" +
                            "Verifica que el servicio este instalado y en ejecucion:\n" +
                            "  sc query WindowsGoodByeService",
                "Servicio no disponible", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error de conexion: {ex.Message}",
                "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void OnUdpMessage(string message, System.Net.IPAddress remoteIp)
    {
        // The tray app also listens for pairing messages to update UI
        // The actual auth logic is in the Service
    }

    private void ExitApp()
    {
        _udp.Dispose();
        _trayIcon.Visible = false;
        _trayIcon.Dispose();
        Application.Exit();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _udp.Dispose();
            _trayIcon.Dispose();
        }
        base.Dispose(disposing);
    }
}
