using System.Net.Sockets;
using WindowsGoodBye.Core;

namespace WindowsGoodBye.Mobile.Services;

/// <summary>
/// TCP client transport for USB/ADB communication.
/// Requires ADB port forwarding:  adb forward tcp:26820 tcp:26820
/// Connects to 127.0.0.1:26820 on the Android device which is forwarded
/// to the Windows machine over USB.
/// </summary>
public class TcpUsbTransport : IDisposable
{
    private TcpClient? _client;
    private NetworkStream? _stream;
    private CancellationTokenSource? _cts;
    private bool _disposed;

    /// <summary>Fired when a message is received from the PC over TCP/USB.</summary>
    public event Action<string>? MessageReceived;

    public bool IsConnected => _client?.Connected == true;

    /// <summary>
    /// Try to connect to the Windows service via ADB-forwarded TCP port.
    /// Returns true if connected.
    /// </summary>
    public async Task<bool> ConnectAsync(CancellationToken ct = default)
    {
        try
        {
            _client = new TcpClient();

            // ADB reverse forwards localhost:26820 on Android → localhost:26820 on Windows
            using var timeoutCts = new CancellationTokenSource(3000);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

            await _client.ConnectAsync("127.0.0.1", Protocol.TcpUsbPort, linked.Token);

            if (!_client.Connected) return false;

            _stream = _client.GetStream();
            _cts = new CancellationTokenSource();
            _ = Task.Run(() => ReadLoop(_cts.Token));

            System.Diagnostics.Debug.WriteLine("[TCP/USB] Connected to 127.0.0.1:" + Protocol.TcpUsbPort);
            return true;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[TCP/USB] Connect failed: {ex.Message}");
            Disconnect();
            return false;
        }
    }

    /// <summary>Send a protocol message over the TCP connection.</summary>
    public async Task SendAsync(string message)
    {
        if (_stream == null) throw new InvalidOperationException("Not connected");
        await StreamTransport.SendAsync(_stream, message);
    }

    private async Task ReadLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _stream != null)
        {
            try
            {
                var message = await StreamTransport.ReceiveAsync(_stream, ct);
                if (message == null) break;

                MessageReceived?.Invoke(message);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[TCP/USB] Read error: {ex.Message}");
                break;
            }
        }
    }

    public void Disconnect()
    {
        _cts?.Cancel();
        try { _stream?.Close(); } catch { }
        try { _client?.Close(); } catch { }
        _stream = null;
        _client = null;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Disconnect();
        _cts?.Dispose();
    }
}
