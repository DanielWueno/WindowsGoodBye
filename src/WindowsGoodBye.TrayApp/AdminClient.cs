using System.IO.Pipes;
using System.Text;
using WindowsGoodBye.Core;

namespace WindowsGoodBye.TrayApp;

/// <summary>
/// Shared one-shot request/response round trip over the Service's admin pipe. Extracted from
/// <c>TrayApplicationContext</c> so the WPF windows (Manage Devices, Pair New Device, Set Windows
/// Credentials) can send admin commands the same way the tray menu already does, without duplicating
/// the pipe plumbing.
/// </summary>
internal static class AdminClient
{
    public static async Task<string?> SendCommandAsync(string command, int connectTimeoutMs = 3000)
    {
        try
        {
            using var pipe = new NamedPipeClientStream(
                ".", Protocol.AdminPipeName, PipeDirection.InOut, PipeOptions.None);
            pipe.Connect(connectTimeoutMs);
            pipe.ReadMode = PipeTransmissionMode.Message;

            var cmdBytes = Encoding.UTF8.GetBytes(command);
            await pipe.WriteAsync(cmdBytes).ConfigureAwait(false);
            await pipe.FlushAsync().ConfigureAwait(false);

            var buf = new byte[4096];
            var bytesRead = await pipe.ReadAsync(buf).ConfigureAwait(false);
            return Encoding.UTF8.GetString(buf, 0, bytesRead).Trim();
        }
        catch
        {
            return null;
        }
    }
}
