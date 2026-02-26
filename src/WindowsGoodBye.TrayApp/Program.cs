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
        Application.Run(new TrayApplicationContext());
    }
}
