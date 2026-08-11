using System.Windows;
using Microsoft.Win32;

namespace WindowsGoodBye.TrayApp;

/// <summary>
/// Applies the "Liquid Glass" WPF design system (Themes/Colors.Light.xaml, Colors.Dark.xaml,
/// Fonts.xaml, Styles.xaml) to <see cref="System.Windows.Application.Current"/>'s resources, so every WPF window
/// in the TrayApp (Manage Devices, Pair New Device, Set Windows Credentials) picks it up through
/// normal WPF resource-lookup — no per-window wiring needed.
/// </summary>
internal static class ThemeManager
{
    private const string LightDictPath = "Themes/Colors.Light.xaml";
    private const string DarkDictPath = "Themes/Colors.Dark.xaml";

    public static bool IsDark { get; private set; }

    /// <summary>
    /// Must be called once, after a <see cref="System.Windows.Application"/> instance exists
    /// (see <c>Program.Main</c>) and before any WPF window is shown.
    /// </summary>
    public static void Initialize()
    {
        var app = System.Windows.Application.Current ?? throw new InvalidOperationException(
            "ThemeManager.Initialize requires a System.Windows.Application instance to exist first.");

        app.Resources.MergedDictionaries.Add(LoadDictionary("Themes/Fonts.xaml"));
        app.Resources.MergedDictionaries.Add(LoadDictionary("Themes/Styles.xaml"));

        ApplyTheme(DetectSystemUsesDarkTheme());
    }

    /// <summary>Swaps in the Light or Dark color dictionary. Any open window using DynamicResource
    /// for its colors/brushes re-renders immediately — no restart needed.</summary>
    public static void ApplyTheme(bool dark)
    {
        var app = System.Windows.Application.Current;
        if (app == null) return;

        var dictionaries = app.Resources.MergedDictionaries;
        for (int i = dictionaries.Count - 1; i >= 0; i--)
        {
            var source = dictionaries[i].Source?.OriginalString ?? "";
            if (source.EndsWith("Colors.Light.xaml") || source.EndsWith("Colors.Dark.xaml"))
                dictionaries.RemoveAt(i);
        }

        dictionaries.Add(LoadDictionary(dark ? DarkDictPath : LightDictPath));
        IsDark = dark;
    }

    /// <summary>
    /// Reads the same registry value Windows itself uses for apps' light/dark preference
    /// (HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\AppsUseLightTheme).
    /// Defaults to light if the key is missing (e.g. very old Windows builds).
    /// </summary>
    public static bool DetectSystemUsesDarkTheme()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            var value = key?.GetValue("AppsUseLightTheme");
            if (value is int intValue)
                return intValue == 0;
        }
        catch
        {
            // Ignore — fall back to light.
        }
        return false;
    }

    private static ResourceDictionary LoadDictionary(string relativePath)
    {
        return new ResourceDictionary
        {
            Source = new Uri($"pack://application:,,,/WindowsGoodBye.TrayApp;component/{relativePath}")
        };
    }
}
