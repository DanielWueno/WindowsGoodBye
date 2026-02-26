using WindowsGoodBye.Mobile.Data;
using WindowsGoodBye.Mobile.Services;

namespace WindowsGoodBye.Mobile;

public partial class MainPage : ContentPage
{
    private readonly IBiometricService _biometric;
    private readonly AuthListener _authListener;

    public MainPage(IBiometricService biometric, AuthListener authListener)
    {
        InitializeComponent();
        _biometric = biometric;
        _authListener = authListener;

        _authListener.AuthenticationRequested += OnAuthRequested;
        _authListener.PairingCompleted += OnPairingCompleted;
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();
        RefreshPcList();
        UpdateServiceStatus();
    }

    private void RefreshPcList()
    {
        try
        {
            using var db = new MobileDatabase();
            db.Initialize();
            var pcs = db.PairedPcs.OrderByDescending(p => p.PairedAt).ToList();
            pcListView.ItemsSource = pcs.Select(p => new PcViewModel(p)).ToList();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[MainPage] DB error: {ex.Message}");
        }
    }

    private void UpdateServiceStatus()
    {
        if (_authListener.IsRunning)
        {
            lblStatus.Text = "Listening for unlock requests...";
            lblStatusIcon.TextColor = Colors.LightGreen;
            btnToggleService.Text = "Stop Service";

            lblTransport.Text = _authListener.ActiveTransport switch
            {
                WindowsGoodBye.Core.Protocol.TransportType.Bluetooth => "🔗 Connected via Bluetooth",
                WindowsGoodBye.Core.Protocol.TransportType.TcpUsb => "🔌 Connected via USB",
                _ => "📶 WiFi / UDP multicast"
            };
        }
        else
        {
            lblStatus.Text = "Service stopped";
            lblStatusIcon.TextColor = Color.FromArgb("#FF5252");
            btnToggleService.Text = "Start Service";
            lblTransport.Text = "";
        }
    }

    private async void OnToggleServiceClicked(object? sender, EventArgs e)
    {
        if (_authListener.IsRunning)
        {
#if ANDROID
            Platforms.Android.AuthForegroundService.StopService(
                Platform.CurrentActivity ?? Android.App.Application.Context);
#endif
        }
        else
        {
#if ANDROID
            Platforms.Android.AuthForegroundService.StartService(
                Platform.CurrentActivity ?? Android.App.Application.Context);
#endif
        }

        // Small delay for service to start/stop
        await Task.Delay(500);
        UpdateServiceStatus();
    }

    private async void OnPairNewClicked(object? sender, EventArgs e)
    {
        if (!_biometric.IsAvailable)
        {
            await DisplayAlert("Biometric Not Available",
                "This device does not support biometric authentication.\n" +
                "A fingerprint sensor or face unlock is required.",
                "OK");
            return;
        }

        await Shell.Current.GoToAsync(nameof(QrScanPage));
    }

    private async void OnDeletePcClicked(object? sender, EventArgs e)
    {
        if (sender is Button btn && btn.BindingContext is PcViewModel vm)
        {
            bool confirm = await DisplayAlert("Remove PC",
                $"Remove {vm.PcName} from paired devices?\nYou will need to pair again.",
                "Remove", "Cancel");

            if (confirm)
            {
                using var db = new MobileDatabase();
                db.Initialize();
                var pc = db.PairedPcs.FirstOrDefault(p => p.DeviceId == vm.DeviceId);
                if (pc != null)
                {
                    db.PairedPcs.Remove(pc);
                    db.SaveChanges();
                }
                RefreshPcList();
            }
        }
    }

    private void OnAuthRequested(AuthRequest request)
    {
        MainThread.BeginInvokeOnMainThread(async () =>
        {
            try
            {
                var result = await _biometric.AuthenticateAsync(
                    $"Unlock {request.PcName}",
                    "Verify your fingerprint to unlock the PC");

                if (result.Success)
                {
                    await _authListener.SendAuthResponseAsync(request);

                    lblStatus.Text = $"PC unlocked: {request.PcName}";
                    await Task.Delay(3000);
                    UpdateServiceStatus();
                }
                else
                {
                    System.Diagnostics.Debug.WriteLine(
                        $"[MainPage] Biometric failed: {result.ErrorMessage}");
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[MainPage] Auth error: {ex.Message}");
            }
        });
    }

    private void OnPairingCompleted(string deviceId, string pcName)
    {
        MainThread.BeginInvokeOnMainThread(async () =>
        {
            RefreshPcList();
            await DisplayAlert("Pairing Successful",
                $"Successfully paired with {pcName}!\n\n" +
                "Make sure to set your Windows password in the tray app if you haven't already.",
                "OK");
        });
    }
}

/// <summary>ViewModel for displaying a paired PC in the list.</summary>
public class PcViewModel
{
    public string DeviceId { get; }
    public string PcName { get; }
    public string StatusText { get; }
    public Color StatusColor { get; }
    public string DetailText { get; }

    public PcViewModel(PairedPc pc)
    {
        DeviceId = pc.DeviceId;
        PcName = string.IsNullOrEmpty(pc.PcName) ? "Unknown PC" : pc.PcName;
        StatusText = pc.IsPaired ? "Paired" : "Pairing...";
        StatusColor = pc.IsPaired ? Colors.Green : Colors.Orange;

        var parts = new List<string>();
        if (pc.PairedAt != default)
            parts.Add(pc.PairedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm"));
        if (!string.IsNullOrEmpty(pc.LastIp))
            parts.Add(pc.LastIp);
        DetailText = string.Join(" • ", parts);
    }
}
