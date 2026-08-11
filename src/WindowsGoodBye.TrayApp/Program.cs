using WindowsGoodBye.TrayApp;

namespace WindowsGoodBye.TrayApp;

static class Program
{
    [STAThread]
    static void Main()
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.SetHighDpiMode(HighDpiMode.SystemAware);

        // A System.Windows.Application instance (never .Run()'d — WinForms' own message loop below
        // already pumps messages on this STA thread) is required so the WPF windows used by the
        // TrayApp (Manage Devices, Pair New Device, Set Windows Credentials) have an Application.Current
        // to resolve DynamicResource theme brushes/styles from. See ThemeManager.
        _ = new System.Windows.Application();
        ThemeManager.Initialize();

        Application.Run(new TrayApplicationContext());
    }
}
