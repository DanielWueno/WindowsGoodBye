namespace WindowsGoodBye.Mobile;

public partial class AppShell : Shell
{
	public AppShell()
	{
		InitializeComponent();

		// Register routes for navigation
		Routing.RegisterRoute(nameof(QrScanPage), typeof(QrScanPage));
	}
}
