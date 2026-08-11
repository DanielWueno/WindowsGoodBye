using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Windows;
using System.Windows.Media.Imaging;
using QRCoder;
using WindowsGoodBye.Core;

namespace WindowsGoodBye.TrayApp;

/// <summary>
/// Replaces the old WinForms pairing dialog. Same pipe protocol/session logic as before
/// (<see cref="Protocol.AdminCmd_PairStart"/>, <see cref="PairingSession"/>) — only the presentation
/// changed, plus swapping GDI+ <c>Image.FromStream</c> for a WPF <see cref="BitmapImage"/>.
/// </summary>
public partial class PairDeviceWindow : Window
{
    private readonly PairingSession _session;
    private readonly CancellationTokenSource _cts = new();

    public PairDeviceWindow(PairingSession session, string? relayUrl, bool pushAuthEnabledDefault)
    {
        InitializeComponent();
        _session = session;

        var qrData = session.GenerateQrData(relayUrl, pushAuthEnabledDefault);
        imgQr.Source = BuildQrImage(qrData);

        Closed += (_, _) =>
        {
            _cts.Cancel();
            PairingSession.Active = null;
        };

        _ = RunPairingAsync();
    }

    private static BitmapImage BuildQrImage(string qrData)
    {
        using var qrGenerator = new QRCodeGenerator();
        var qrCodeData = qrGenerator.CreateQrCode(qrData, QRCodeGenerator.ECCLevel.M);
        using var qrCode = new PngByteQRCode(qrCodeData);
        var qrBytes = qrCode.GetGraphic(8);

        var bitmap = new BitmapImage();
        using var stream = new MemoryStream(qrBytes);
        bitmap.BeginInit();
        bitmap.CacheOption = BitmapCacheOption.OnLoad;
        bitmap.StreamSource = stream;
        bitmap.EndInit();
        bitmap.Freeze();
        return bitmap;
    }

    private void SetStatus(string text) => Dispatcher.Invoke(() => txtStatus.Text = text);

    private async Task RunPairingAsync()
    {
        try
        {
            NamedPipeClientStream? pipe = null;
            for (int attempt = 1; attempt <= 3; attempt++)
            {
                try
                {
                    pipe = new NamedPipeClientStream(".", Protocol.AdminPipeName, PipeDirection.InOut, PipeOptions.None);
                    pipe.Connect(5000);
                    break;
                }
                catch (TimeoutException)
                {
                    pipe?.Dispose();
                    pipe = null;
                    if (attempt < 3)
                    {
                        SetStatus($"Conectando con el Servicio (intento {attempt + 1}/3)...");
                        await Task.Delay(1000, _cts.Token);
                    }
                }
            }

            if (pipe == null || !pipe.IsConnected)
            {
                SetStatus("No se pudo conectar con el Servicio.\nInicia el Servicio WindowsGoodBye e intenta de nuevo.");
                return;
            }

            using (pipe)
            {
                pipe.ReadMode = PipeTransmissionMode.Message;

                var cmd = Protocol.AdminCmd_PairStart + "\n" + _session.SerializeKeys();
                var cmdBytes = Encoding.UTF8.GetBytes(cmd);
                await pipe.WriteAsync(cmdBytes, _cts.Token);
                await pipe.FlushAsync(_cts.Token);

                var buf = new byte[4096];
                var bytesRead = await pipe.ReadAsync(buf, _cts.Token);
                var response = Encoding.UTF8.GetString(buf, 0, bytesRead).Trim();

                if (response.StartsWith(Protocol.AdminResp_Error))
                {
                    var errMsg = response.Contains('\n') ? response[(response.IndexOf('\n') + 1)..] : "Error desconocido";
                    SetStatus($"Error del Servicio: {errMsg}");
                    return;
                }

                SetStatus("Servicio listo — esperando a que el telefono escanee el QR...");

                bytesRead = await pipe.ReadAsync(buf, _cts.Token);
                if (bytesRead > 0)
                {
                    response = Encoding.UTF8.GetString(buf, 0, bytesRead).Trim();
                    if (response.StartsWith(Protocol.AdminResp_PairDone))
                    {
                        var parts = response.Split('\n');
                        var name = parts.Length > 1 ? parts[1] : "Desconocido";
                        var model = parts.Length > 2 ? parts[2] : "";

                        _session.Complete(name, model);

                        Dispatcher.Invoke(() =>
                        {
                            txtStatus.Text = $"¡Emparejado con {name} ({model})!";
                            System.Windows.MessageBox.Show(this,
                                $"Emparejamiento exitoso con {name} ({model}).\n\n" +
                                "No olvides configurar tu contrasena de Windows desde el menu de la bandeja\n" +
                                "si aun no lo has hecho.",
                                "Emparejamiento exitoso", MessageBoxButton.OK, MessageBoxImage.Information);
                            Close();
                        });
                    }
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            try { SetStatus($"Error: {ex.Message}"); } catch { }
        }
    }
}
