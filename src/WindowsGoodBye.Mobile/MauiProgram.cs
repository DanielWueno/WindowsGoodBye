using Microsoft.Extensions.Logging;
using ZXing.Net.Maui.Controls;
using WindowsGoodBye.Mobile.Data;
using WindowsGoodBye.Mobile.Services;

namespace WindowsGoodBye.Mobile;

public static class MauiProgram
{
	public static MauiApp CreateMauiApp()
	{
		var builder = MauiApp.CreateBuilder();
		builder
			.UseMauiApp<App>()
			.UseBarcodeReader()
			.ConfigureFonts(fonts =>
			{
				fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
				fonts.AddFont("OpenSans-Semibold.ttf", "OpenSansSemibold");
			});

		// Register services
#if ANDROID
		builder.Services.AddSingleton<IBiometricService, Platforms.Android.AndroidBiometricService>();
#endif
		builder.Services.AddSingleton<AuthListener>(AuthListener.Instance);
		builder.Services.AddTransient<MobileDatabase>();

		// Register pages
		builder.Services.AddTransient<MainPage>();
		builder.Services.AddTransient<QrScanPage>();

#if DEBUG
		builder.Logging.AddDebug();
#endif

		return builder.Build();
	}
}
