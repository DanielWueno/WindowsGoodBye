using System.Windows;
using Microsoft.EntityFrameworkCore;
using WindowsGoodBye.Core;

namespace WindowsGoodBye.TrayApp;

/// <summary>
/// Replaces the old WinForms "Manage Devices" form. Delete/Enable-Disable now go through the Service
/// via <see cref="AdminClient"/> (<see cref="Protocol.AdminCmd_DeleteDevice"/> /
/// <see cref="Protocol.AdminCmd_SetDeviceEnabled"/>) instead of writing to a TrayApp-local
/// <see cref="AppDatabase"/> directly — see those commands' XML docs for why that matters
/// (EF Core identity-map staleness against the Service's own long-lived DbContext).
/// </summary>
public partial class ManageDevicesWindow : Window
{
    public ManageDevicesWindow()
    {
        InitializeComponent();
        Loaded += (_, _) => LoadDevices();
    }

    private void LoadDevices()
    {
        List<DeviceInfo> devices;
        try
        {
            using var db = new AppDatabase();
            db.Initialize();
            devices = db.Devices.AsNoTracking().OrderBy(d => d.FriendlyName).ToList();
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show(this, $"No se pudo leer la base de datos local: {ex.Message}",
                "WindowsGoodBye", MessageBoxButton.OK, MessageBoxImage.Error);
            devices = new List<DeviceInfo>();
        }

        itemsDevices.ItemsSource = devices.Select(d => new DeviceRowViewModel(d)).ToList();
        txtSubtitle.Text = devices.Count switch
        {
            0 => "No hay dispositivos emparejados",
            1 => "1 dispositivo",
            _ => $"{devices.Count} dispositivos"
        };
    }

    private async void OnToggleEnabledClicked(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is not DeviceRowViewModel vm) return;

        var command = $"{Protocol.AdminCmd_SetDeviceEnabled}\n{vm.DeviceId}\n{(vm.Enabled ? "0" : "1")}";
        var response = await AdminClient.SendCommandAsync(command);

        if (response != null && response.StartsWith(Protocol.AdminResp_Ok))
        {
            LoadDevices();
        }
        else
        {
            System.Windows.MessageBox.Show(this,
                "No se pudo actualizar el dispositivo.\n\nAsegurate de que el Servicio WindowsGoodBye este en ejecucion.",
                "WindowsGoodBye", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async void OnDeleteClicked(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is not DeviceRowViewModel vm) return;

        var confirm = System.Windows.MessageBox.Show(this,
            $"¿Eliminar '{vm.FriendlyName}' de los dispositivos emparejados?\nTendras que emparejarlo de nuevo.",
            "Eliminar dispositivo", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;

        var command = $"{Protocol.AdminCmd_DeleteDevice}\n{vm.DeviceId}";
        var response = await AdminClient.SendCommandAsync(command);

        if (response != null && response.StartsWith(Protocol.AdminResp_Ok))
        {
            LoadDevices();
        }
        else
        {
            System.Windows.MessageBox.Show(this,
                "No se pudo eliminar el dispositivo.\n\nAsegurate de que el Servicio WindowsGoodBye este en ejecucion.",
                "WindowsGoodBye", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void OnCloseClicked(object sender, RoutedEventArgs e) => Close();
}
