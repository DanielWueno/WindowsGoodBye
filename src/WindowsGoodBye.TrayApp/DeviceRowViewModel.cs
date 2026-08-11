using WindowsGoodBye.Core;

namespace WindowsGoodBye.TrayApp;

/// <summary>
/// Display-ready wrapper around a <see cref="DeviceInfo"/> row for <see cref="ManageDevicesWindow"/>'s
/// item list. Pill colors are computed once here (not via DynamicResource) because the six brand
/// accent colors (green/orange/etc.) are identical between the Light and Dark theme dictionaries —
/// only the pill's text shade needs to differ per theme, mirroring the mockup's
/// <c>[data-theme="dark"] .pill.green</c> overrides.
/// </summary>
internal sealed class DeviceRowViewModel
{
    private static readonly System.Windows.Media.Color GreenPillBg = System.Windows.Media.Color.FromArgb(0x3D, 0x34, 0xD3, 0x99);
    private static readonly System.Windows.Media.Color OrangePillBg = System.Windows.Media.Color.FromArgb(0x33, 0xF9, 0x73, 0x16);

    public Guid DeviceId { get; }
    public string FriendlyName { get; }
    public string ModelName { get; }
    public string DetailText { get; }
    public bool Enabled { get; }
    public string StatusText => Enabled ? "Habilitado" : "Deshabilitado";
    public string ToggleActionText => Enabled ? "Deshabilitar" : "Habilitar";
    public System.Windows.Media.Brush StatusBackground { get; }
    public System.Windows.Media.Brush StatusForeground { get; }

    public DeviceRowViewModel(DeviceInfo device)
    {
        DeviceId = device.DeviceId;
        FriendlyName = string.IsNullOrEmpty(device.FriendlyName) ? "Dispositivo sin nombre" : device.FriendlyName;
        ModelName = device.ModelName;
        Enabled = device.Enabled;

        var parts = new List<string>();
        if (!string.IsNullOrEmpty(device.LastIpAddress)) parts.Add(device.LastIpAddress!);
        parts.Add(device.LastAuthAt.HasValue
            ? $"Ultimo desbloqueo: {device.LastAuthAt.Value.ToLocalTime():g}"
            : "Nunca desbloqueado");
        DetailText = string.Join("  •  ", parts);

        StatusBackground = new System.Windows.Media.SolidColorBrush(Enabled ? GreenPillBg : OrangePillBg);
        StatusForeground = new System.Windows.Media.SolidColorBrush(Enabled
            ? (ThemeManager.IsDark ? System.Windows.Media.Color.FromRgb(0x7B, 0xE8, 0xC4) : System.Windows.Media.Color.FromRgb(0x0C, 0x8A, 0x5F))
            : (ThemeManager.IsDark ? System.Windows.Media.Color.FromRgb(0xFF, 0xB2, 0x7A) : System.Windows.Media.Color.FromRgb(0xC2, 0x56, 0x0F)));
    }
}
