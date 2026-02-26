using System.Net;
using System.Net.Sockets;
using WindowsGoodBye.Core;

namespace WindowsGoodBye.Service;

/// <summary>
/// TCP server listening on localhost for USB/ADB communication.
/// When the Android device is connected via USB, use:
///   adb forward tcp:26820 tcp:26820
/// and the MAUI app connects to 127.0.0.1:26820 for the same protocol messages.
/// </summary>
public class TcpUsbServer : IDisposable
{
    private readonly ILogger<TcpUsbServer> _logger;
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private bool _disposed;
    private readonly List<NetworkStream> _activeStreams = new();
    private readonly object _streamsLock = new();

    /// <summary>Fired when a message is received from a TCP client. Includes a reply callback.</summary>
    public event Action<string, Func<string, Task>>? MessageReceived;

    public TcpUsbServer(ILogger<TcpUsbServer> logger)
    {
        _logger = logger;
    }

    public void Start()
    {
        _cts = new CancellationTokenSource();

        try
        {
            _listener = new TcpListener(IPAddress.Loopback, Protocol.TcpUsbPort);
            _listener.Start();

            _logger.LogInformation("TCP/USB server started on 127.0.0.1:{Port}", Protocol.TcpUsbPort);
            _ = Task.Run(() => AcceptLoop(_cts.Token));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to start TCP/USB server");
        }
    }

    private async Task AcceptLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _listener != null)
        {
            try
            {
                var tcpClient = await _listener.AcceptTcpClientAsync(ct);
                var ep = tcpClient.Client.RemoteEndPoint as IPEndPoint;
                _logger.LogInformation("TCP/USB client connected from {EP}", ep);

                _ = Task.Run(() => HandleClient(tcpClient, ct));
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                _logger.LogError(ex, "TCP accept error");
                await Task.Delay(1000, ct);
            }
        }
    }

    private async Task HandleClient(TcpClient tcpClient, CancellationToken ct)
    {
        NetworkStream? stream = null;
        try
        {
            stream = tcpClient.GetStream();
            lock (_streamsLock) _activeStreams.Add(stream);

            while (!ct.IsCancellationRequested && tcpClient.Connected)
            {
                var message = await StreamTransport.ReceiveAsync(stream, ct);
                if (message == null) break; // Disconnected

                _logger.LogDebug("TCP msg: {Msg}", message.Length > 60 ? message[..60] + "..." : message);

                async Task ReplyAsync(string reply)
                {
                    try { await StreamTransport.SendAsync(stream, reply, ct); }
                    catch (Exception ex) { _logger.LogError(ex, "TCP reply error"); }
                }

                MessageReceived?.Invoke(message, ReplyAsync);
            }
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            _logger.LogWarning("TCP/USB client disconnected: {Msg}", ex.Message);
        }
        finally
        {
            if (stream != null)
            {
                lock (_streamsLock) _activeStreams.Remove(stream);
                try { stream.Dispose(); } catch { }
            }
            tcpClient.Dispose();
        }
    }

    /// <summary>Send a message to all currently connected TCP clients.</summary>
    public async Task SendToAllAsync(string message)
    {
        NetworkStream[] streams;
        lock (_streamsLock) streams = _activeStreams.ToArray();

        foreach (var stream in streams)
        {
            try { await StreamTransport.SendAsync(stream, message); }
            catch { /* client may have disconnected */ }
        }
    }

    public void Stop()
    {
        _cts?.Cancel();
        try { _listener?.Stop(); } catch { }
        _listener = null;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
        _cts?.Dispose();
    }
}
