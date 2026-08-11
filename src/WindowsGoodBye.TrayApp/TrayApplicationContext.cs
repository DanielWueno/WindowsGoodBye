using System.IO.Pipes;
using System.Text;
using Microsoft.EntityFrameworkCore;
using WindowsGoodBye.Core;
using QRCoder;

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
    private Form? _mainForm;

    public TrayApplicationContext()
    {
        _db = new AppDatabase();
        _db.Initialize();

        _udp = new UdpManager();
        _udp.MessageReceived += OnUdpMessage;
        _udp.StartListening();

        _trayIcon = new NotifyIcon
        {
            Icon = SystemIcons.Shield,
            Text = "WindowsGoodBye - Unlock with phone",
            Visible = true,
            ContextMenuStrip = CreateContextMenu()
        };

        _trayIcon.DoubleClick += (_, _) => ShowMainForm();
    }

    private ContextMenuStrip CreateContextMenu()
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add("Pair New Device", null, (_, _) => StartPairing());
        menu.Items.Add("Set Windows Password", null, (_, _) => SetCredentials());
        menu.Items.Add("Manage Devices", null, (_, _) => ShowMainForm());
        menu.Items.Add(CreatePushAuthMenuItem());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Test Service Connection", null, (_, _) => TestServiceConnection());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Exit", null, (_, _) => ExitApp());
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
        var response = await SendAdminCommandAsync(command);

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
    /// Minimal one-shot request/response round trip over the admin pipe — for quick fire-and-wait
    /// commands (<see cref="Protocol.AdminCmd_SetPushAuth"/>, <see cref="Protocol.AdminCmd_GetRelayStatus"/>)
    /// that don't need the retry/keep-open dance <see cref="StartPairing"/> uses for the long-lived
    /// pairing handshake. Returns null on any failure (Service not running, timeout, etc.) — callers
    /// treat that as "couldn't reach the Service" and degrade gracefully rather than throwing.
    /// </summary>
    private static async Task<string?> SendAdminCommandAsync(string command, int connectTimeoutMs = 3000)
    {
        try
        {
            using var pipe = new NamedPipeClientStream(
                ".", Protocol.AdminPipeName, PipeDirection.InOut, PipeOptions.None);
            pipe.Connect(connectTimeoutMs);
            pipe.ReadMode = PipeTransmissionMode.Message;

            var cmdBytes = Encoding.UTF8.GetBytes(command);
            await pipe.WriteAsync(cmdBytes).ConfigureAwait(false);
            await pipe.FlushAsync().ConfigureAwait(false);

            var buf = new byte[4096];
            var bytesRead = await pipe.ReadAsync(buf).ConfigureAwait(false);
            return Encoding.UTF8.GetString(buf, 0, bytesRead).Trim();
        }
        catch
        {
            return null;
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
            var response = SendAdminCommandAsync(Protocol.AdminCmd_GetRelayStatus).GetAwaiter().GetResult();
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
        if (_mainForm != null && !_mainForm.IsDisposed)
        {
            _mainForm.BringToFront();
            return;
        }

        _mainForm = new Form
        {
            Text = "WindowsGoodBye - Device Manager",
            Size = new Size(600, 450),
            StartPosition = FormStartPosition.CenterScreen,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false
        };

        var listView = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true
        };
        listView.Columns.Add("Device Name", 180);
        listView.Columns.Add("Model", 120);
        listView.Columns.Add("Last IP", 120);
        listView.Columns.Add("Enabled", 60);
        listView.Columns.Add("Last Auth", 140);

        var devices = _db.Devices.ToList();
        foreach (var d in devices)
        {
            var item = new ListViewItem(d.FriendlyName);
            item.SubItems.Add(d.ModelName);
            item.SubItems.Add(d.LastIpAddress ?? "N/A");
            item.SubItems.Add(d.Enabled ? "Yes" : "No");
            item.SubItems.Add(d.LastAuthAt?.ToLocalTime().ToString("g") ?? "Never");
            item.Tag = d;
            listView.Items.Add(item);
        }

        var btnPanel = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            Height = 45,
            FlowDirection = FlowDirection.RightToLeft,
            Padding = new Padding(5)
        };

        var btnDelete = new Button { Text = "Delete Device", Width = 120 };
        btnDelete.Click += (_, _) =>
        {
            if (listView.SelectedItems.Count == 0) return;
            var device = (DeviceInfo)listView.SelectedItems[0].Tag;
            if (MessageBox.Show($"Delete device '{device.FriendlyName}'?", "Confirm",
                    MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes)
            {
                _db.Devices.Remove(device);
                _db.SaveChanges();
                listView.SelectedItems[0].Remove();
            }
        };

        var btnToggle = new Button { Text = "Enable/Disable", Width = 120 };
        btnToggle.Click += (_, _) =>
        {
            if (listView.SelectedItems.Count == 0) return;
            var device = (DeviceInfo)listView.SelectedItems[0].Tag;
            device.Enabled = !device.Enabled;
            _db.SaveChanges();
            listView.SelectedItems[0].SubItems[3].Text = device.Enabled ? "Yes" : "No";
        };

        btnPanel.Controls.Add(btnDelete);
        btnPanel.Controls.Add(btnToggle);

        _mainForm.Controls.Add(listView);
        _mainForm.Controls.Add(btnPanel);
        _mainForm.Show();
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
        var qrData = session.GenerateQrData(relayUrl, pushAuthEnabledDefault);

        // Generate QR code
        using var qrGenerator = new QRCodeGenerator();
        var qrCodeData = qrGenerator.CreateQrCode(qrData, QRCodeGenerator.ECCLevel.M);
        using var qrCode = new PngByteQRCode(qrCodeData);
        var qrBytes = qrCode.GetGraphic(8);

        using var ms = new MemoryStream(qrBytes);
        var qrImage = Image.FromStream(ms);

        // Show QR code in a dialog
        var dialog = new Form
        {
            Text = "Pair Android Device",
            Size = new Size(420, 520),
            StartPosition = FormStartPosition.CenterScreen,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false
        };

        var label = new Label
        {
            Text = "Scan this QR code with the WindowsGoodBye Android app:",
            Dock = DockStyle.Top,
            Height = 40,
            TextAlign = ContentAlignment.MiddleCenter,
            Font = new Font(FontFamily.GenericSansSerif, 10)
        };

        var pictureBox = new PictureBox
        {
            Image = qrImage,
            SizeMode = PictureBoxSizeMode.Zoom,
            Dock = DockStyle.Fill
        };

        var statusLabel = new Label
        {
            Text = "Waiting for device...",
            Dock = DockStyle.Bottom,
            Height = 30,
            TextAlign = ContentAlignment.MiddleCenter,
            ForeColor = Color.DarkBlue
        };

        dialog.Controls.Add(pictureBox);
        dialog.Controls.Add(label);
        dialog.Controls.Add(statusLabel);

        // Wait for pairing completion in background
        var cts = new CancellationTokenSource();
        dialog.FormClosed += (_, _) =>
        {
            cts.Cancel();
            PairingSession.Active = null;
        };

        // Send pairing session to the Service via admin pipe, then wait for completion
        Task.Run(async () =>
        {
            try
            {
                // Connect to the Service's admin pipe (retry up to 3 times)
                System.IO.Pipes.NamedPipeClientStream? pipe = null;
                for (int attempt = 1; attempt <= 3; attempt++)
                {
                    try
                    {
                        pipe = new System.IO.Pipes.NamedPipeClientStream(
                            ".", Protocol.AdminPipeName,
                            System.IO.Pipes.PipeDirection.InOut,
                            System.IO.Pipes.PipeOptions.None);
                        pipe.Connect(5000); // 5 second timeout
                        break; // connected
                    }
                    catch (TimeoutException)
                    {
                        pipe?.Dispose();
                        pipe = null;
                        if (attempt < 3)
                        {
                            dialog.Invoke(() =>
                            {
                                statusLabel.Text = $"Connecting to Service (attempt {attempt + 1}/3)...";
                                statusLabel.ForeColor = Color.DarkOrange;
                            });
                            await Task.Delay(1000, cts.Token);
                        }
                    }
                }

                if (pipe == null || !pipe.IsConnected)
                {
                    dialog.Invoke(() =>
                    {
                        statusLabel.Text = "Cannot reach Service — is it running?\nStart the Service and try again.";
                        statusLabel.ForeColor = Color.Red;
                    });
                    return;
                }

                using (pipe)
                {
                    pipe.ReadMode = System.IO.Pipes.PipeTransmissionMode.Message;

                    // Send PAIR_START with serialized keys
                    var cmd = Protocol.AdminCmd_PairStart + "\n" + session.SerializeKeys();
                    var cmdBytes = System.Text.Encoding.UTF8.GetBytes(cmd);
                    await pipe.WriteAsync(cmdBytes, cts.Token);
                    await pipe.FlushAsync(cts.Token);

                    // Read first response (OK or ERROR)
                    var buf = new byte[4096];
                    var bytesRead = await pipe.ReadAsync(buf, cts.Token);
                    var response = System.Text.Encoding.UTF8.GetString(buf, 0, bytesRead).Trim();

                    if (response.StartsWith(Protocol.AdminResp_Error))
                    {
                        var errMsg = response.Contains('\n') ? response[(response.IndexOf('\n') + 1)..] : "Unknown error";
                        dialog.Invoke(() =>
                        {
                            statusLabel.Text = $"Service error: {errMsg}";
                            statusLabel.ForeColor = Color.Red;
                        });
                        return;
                    }

                    dialog.Invoke(() =>
                    {
                        statusLabel.Text = "Service ready — waiting for phone to scan QR...";
                        statusLabel.ForeColor = Color.DarkBlue;
                    });

                    // Now wait for second message: PAIR_DONE or timeout (pipe stays open)
                    bytesRead = await pipe.ReadAsync(buf, cts.Token);
                    if (bytesRead > 0)
                    {
                        response = System.Text.Encoding.UTF8.GetString(buf, 0, bytesRead).Trim();
                        if (response.StartsWith(Protocol.AdminResp_PairDone))
                        {
                            var parts = response.Split('\n');
                            var name = parts.Length > 1 ? parts[1] : "Unknown";
                            var model = parts.Length > 2 ? parts[2] : "";

                            session.Complete(name, model);

                            dialog.Invoke(() =>
                            {
                                statusLabel.Text = $"Paired with {name} ({model})!";
                                statusLabel.ForeColor = Color.DarkGreen;
                                MessageBox.Show(
                                    $"Successfully paired with {name} ({model})!\n\n" +
                                    "Make sure to set your Windows password in the tray menu\n" +
                                    "if you haven't already.",
                                    "Pairing Successful", MessageBoxButtons.OK, MessageBoxIcon.Information);
                                dialog.Close();
                            });
                        }
                    }
                }
            }
            catch (TaskCanceledException) { }
            catch (Exception ex)
            {
                try
                {
                    dialog.Invoke(() =>
                    {
                        statusLabel.Text = $"Error: {ex.Message}";
                        statusLabel.ForeColor = Color.Red;
                    });
                }
                catch { }
            }
        }, cts.Token);

        dialog.ShowDialog();
    }

    private void SetCredentials()
    {
        var dialog = new Form
        {
            Text = "Set Windows Credentials",
            Size = new Size(400, 280),
            StartPosition = FormStartPosition.CenterScreen,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false,
            Padding = new Padding(15)
        };

        var tableLayout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 5,
            Padding = new Padding(5)
        };
        tableLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 100));
        tableLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        var lblInfo = new Label
        {
            Text = "Your Windows password is stored encrypted locally (DPAPI)\nand is used by the credential provider to unlock the PC.",
            AutoSize = true,
            Dock = DockStyle.Fill
        };
        tableLayout.SetColumnSpan(lblInfo, 2);
        tableLayout.Controls.Add(lblInfo, 0, 0);

        tableLayout.Controls.Add(new Label { Text = "Domain:", Anchor = AnchorStyles.Left, AutoSize = true }, 0, 1);
        var txtDomain = new TextBox { Text = Environment.UserDomainName, Dock = DockStyle.Fill };
        tableLayout.Controls.Add(txtDomain, 1, 1);

        tableLayout.Controls.Add(new Label { Text = "Username:", Anchor = AnchorStyles.Left, AutoSize = true }, 0, 2);
        var txtUsername = new TextBox { Text = Environment.UserName, Dock = DockStyle.Fill };
        tableLayout.Controls.Add(txtUsername, 1, 2);

        tableLayout.Controls.Add(new Label { Text = "Password:", Anchor = AnchorStyles.Left, AutoSize = true }, 0, 3);
        var txtPassword = new TextBox { PasswordChar = '*', Dock = DockStyle.Fill };
        tableLayout.Controls.Add(txtPassword, 1, 3);

        var btnSave = new Button
        {
            Text = "Save Credentials",
            Dock = DockStyle.Fill,
            Height = 35
        };
        tableLayout.SetColumnSpan(btnSave, 2);
        tableLayout.Controls.Add(btnSave, 0, 4);

        btnSave.Click += (_, _) =>
        {
            if (string.IsNullOrWhiteSpace(txtUsername.Text) || string.IsNullOrEmpty(txtPassword.Text))
            {
                MessageBox.Show("Username and password are required.", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            try
            {
                var encryptedPassword = CryptoUtils.ProtectData(
                    Encoding.UTF8.GetBytes(txtPassword.Text));

                // Remove existing credentials
                var existing = _db.Credentials.ToList();
                _db.Credentials.RemoveRange(existing);

                _db.Credentials.Add(new StoredCredential
                {
                    Username = txtUsername.Text,
                    Domain = txtDomain.Text,
                    EncryptedPassword = encryptedPassword,
                    UpdatedAt = DateTime.UtcNow
                });
                _db.SaveChanges();

                // Clear the password from the textbox
                txtPassword.Clear();

                MessageBox.Show("Credentials saved successfully!\n\n" +
                                "The credential provider will use these to unlock your PC\n" +
                                "when your phone authenticates.",
                    "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                dialog.Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to save credentials: {ex.Message}", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        };

        dialog.Controls.Add(tableLayout);
        dialog.ShowDialog();
    }

    private void TestServiceConnection()
    {
        try
        {
            using var pipe = new System.IO.Pipes.NamedPipeClientStream(".", Protocol.PipeName,
                System.IO.Pipes.PipeDirection.InOut, System.IO.Pipes.PipeOptions.None);
            pipe.Connect(3000);
            MessageBox.Show("Successfully connected to WindowsGoodBye Service!",
                "Service Connection", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (TimeoutException)
        {
            MessageBox.Show("Could not connect to the WindowsGoodBye Service.\n\n" +
                            "Make sure the service is installed and running:\n" +
                            "  sc query WindowsGoodByeService",
                "Service Not Running", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Connection error: {ex.Message}",
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
