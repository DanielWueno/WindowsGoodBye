using System.Text;
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
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Test Service Connection", null, (_, _) => TestServiceConnection());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Exit", null, (_, _) => ExitApp());
        return menu;
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
        var qrData = session.GenerateQrData();

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
