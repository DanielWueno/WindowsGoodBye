using System.Text;
using WindowsGoodBye.Core;
using WindowsGoodBye.Mobile.Data;
using WindowsGoodBye.Mobile.Services;
using ZXing.Net.Maui;

namespace WindowsGoodBye.Mobile;

public partial class QrScanPage : ContentPage
{
    private bool _qrProcessed;

    public QrScanPage()
    {
        InitializeComponent();
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();
        barcodeReader.IsDetecting = false;
    }

    private void OnBarcodesDetected(object? sender, BarcodeDetectionEventArgs e)
    {
        if (_qrProcessed) return;

        foreach (var barcode in e.Results)
        {
            if (barcode.Value?.StartsWith(Protocol.PairQrPrefix) == true)
            {
                _qrProcessed = true;
                barcodeReader.IsDetecting = false;
                MainThread.BeginInvokeOnMainThread(() => ProcessQrCode(barcode.Value));
                return;
            }
        }
    }

    private async void ProcessQrCode(string qrData)
    {
        statusOverlay.IsVisible = true;
        lblPairingStatus.Text = "QR detected! Starting pairing...";

        try
        {
            // Parse QR payload: wingb://pair?{base64}|{ip1},{ip2},...
            var afterPrefix = qrData[Protocol.PairQrPrefix.Length..];
            string payloadBase64;
            string[] pcIpAddresses = Array.Empty<string>();

            var pipeIdx = afterPrefix.IndexOf('|');
            if (pipeIdx >= 0)
            {
                payloadBase64 = afterPrefix[..pipeIdx];
                var ipPart = afterPrefix[(pipeIdx + 1)..];
                pcIpAddresses = ipPart.Split(',', StringSplitOptions.RemoveEmptyEntries);
                System.Diagnostics.Debug.WriteLine($"[QrScan] PC IPs from QR: {string.Join(", ", pcIpAddresses)}");
            }
            else
            {
                payloadBase64 = afterPrefix;
            }

            var payload = Convert.FromBase64String(payloadBase64);

            if (payload.Length != Protocol.PairPayloadLength)
            {
                await ShowError("Invalid QR code: unexpected payload size");
                return;
            }

            var deviceIdBytes = new byte[Protocol.GuidLength];
            var deviceKey = new byte[Protocol.KeyLength];
            var authKey = new byte[Protocol.KeyLength];
            var pairEncryptKey = new byte[Protocol.KeyLength];

            int offset = 0;
            Array.Copy(payload, offset, deviceIdBytes, 0, Protocol.GuidLength); offset += Protocol.GuidLength;
            Array.Copy(payload, offset, deviceKey, 0, Protocol.KeyLength); offset += Protocol.KeyLength;
            Array.Copy(payload, offset, authKey, 0, Protocol.KeyLength); offset += Protocol.KeyLength;
            Array.Copy(payload, offset, pairEncryptKey, 0, Protocol.KeyLength);

            var deviceId = new Guid(deviceIdBytes);

            lblPairingStatus.Text = "Saving device info...";

            // Save to local DB
            using var db = new MobileDatabase();
            db.Initialize();

            // Remove any previous pending entry
            var existing = db.PairedPcs.FirstOrDefault(p => !p.IsPaired);
            if (existing != null) db.PairedPcs.Remove(existing);

            // Also check if this device was already paired
            var alreadyPaired = db.PairedPcs.FirstOrDefault(p => p.DeviceId == deviceId.ToString());
            if (alreadyPaired != null) db.PairedPcs.Remove(alreadyPaired);

            db.PairedPcs.Add(new PairedPc
            {
                DeviceId = deviceId.ToString(),
                DeviceKeyBase64 = Convert.ToBase64String(deviceKey),
                AuthKeyBase64 = Convert.ToBase64String(authKey),
                PairEncryptKeyBase64 = Convert.ToBase64String(pairEncryptKey),
                PcName = "Pairing...",
                IsPaired = false,
                PairedAt = DateTime.UtcNow
            });
            db.SaveChanges();

            // --- Ensure the AuthListener / foreground service is running ---
            // Without it, we can't receive the pair_finish reply from the PC.
            lblPairingStatus.Text = "Starting listener...";

            if (!AuthListener.Instance.IsRunning)
            {
#if ANDROID
                Platforms.Android.AuthForegroundService.StartService(
                    Platform.CurrentActivity ?? Android.App.Application.Context);
#endif
            }

            // Wait until BT/TCP/UDP transport is fully bound (max 8 seconds)
            try
            {
                using var readyCts = new CancellationTokenSource(TimeSpan.FromSeconds(8));
                await AuthListener.Instance.WaitForTransportAsync(readyCts.Token);
            }
            catch (TaskCanceledException)
            {
                System.Diagnostics.Debug.WriteLine("[QrScan] Transport ready timeout — sending anyway");
            }

            // Subscribe to the PairingCompleted event with a TaskCompletionSource
            var pairingTcs = new TaskCompletionSource<string>();
            void onPaired(string devId, string pcName)
            {
                if (devId == deviceId.ToString())
                    pairingTcs.TrySetResult(pcName);
            }
            AuthListener.Instance.PairingCompleted += onPaired;

            lblPairingStatus.Text = "Sending pairing request...";

            // Get device info for the pairing request
            var friendlyName = Microsoft.Maui.Devices.DeviceInfo.Current.Name ?? "Android Device";
            var modelName = Microsoft.Maui.Devices.DeviceInfo.Current.Model ?? "Unknown";

            // Send pair request repeatedly (multicast can be lost) — stop as soon as we get a response
            using var pairCts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            _ = Task.Run(async () =>
            {
                for (int i = 0; i < 6 && !pairCts.IsCancellationRequested; i++)
                {
                    try
                    {
                        System.Diagnostics.Debug.WriteLine($"[QrScan] Sending pair_req attempt {i + 1}");
                        await AuthListener.Instance.SendPairRequestAsync(
                            deviceId, pairEncryptKey, friendlyName, modelName, pcIpAddresses);
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"[QrScan] Send error: {ex.Message}");
                    }
                    try { await Task.Delay(3000, pairCts.Token); } catch { break; }
                }
            }, pairCts.Token);

            lblPairingStatus.Text = "Pairing request sent!\nWaiting for PC confirmation...";

            // Wait for the pair_finish with a 20-second timeout
            pairCts.Token.Register(() => pairingTcs.TrySetCanceled());

            try
            {
                var pcName = await pairingTcs.Task;
                lblPairingStatus.Text = $"Paired with {pcName}!";
                await Task.Delay(1000);
            }
            catch (TaskCanceledException)
            {
                // Timeout — the pair_finish didn't arrive. The entry stays as "Pairing..."
                // but will be updated next time if the service processes it later.
                lblPairingStatus.Text = "Pair request sent, but no confirm yet.\nCheck that the TrayApp is showing the QR code.";
                await Task.Delay(2500);
            }
            finally
            {
                AuthListener.Instance.PairingCompleted -= onPaired;
            }

            await MainThread.InvokeOnMainThreadAsync(async () =>
            {
                await Shell.Current.GoToAsync("..");
            });
        }
        catch (Exception ex)
        {
            await ShowError($"Pairing failed: {ex.Message}");
        }
    }

    private async Task ShowError(string message)
    {
        statusOverlay.IsVisible = false;
        await DisplayAlert("Error", message, "OK");
        _qrProcessed = false;
        barcodeReader.IsDetecting = true;
    }
}
