using System.Net.Sockets;
using InTheHand.Net;
using InTheHand.Net.Bluetooth;
using InTheHand.Net.Sockets;
using WindowsGoodBye.Core;

namespace WindowsGoodBye.Service;

/// <summary>
/// Bluetooth RFCOMM server that listens for connections from paired Android devices.
/// Uses 32feet.NET (InTheHand.Net.Bluetooth).
/// Accepts one client at a time — the Android app connects, sends/receives protocol messages,
/// then the connection stays open for the session.
/// </summary>
public class BluetoothServer : IDisposable
{
    private readonly ILogger<BluetoothServer> _logger;
    private BluetoothListener? _listener;
    private CancellationTokenSource? _cts;
    private bool _disposed;
    private readonly List<Stream> _activeStreams = new();
    private readonly object _streamsLock = new();

    private static readonly Guid ServiceUuid = Guid.Parse(Protocol.BluetoothServiceUuid);

    /// <summary>Fired when a message is received from a Bluetooth client. Includes a reply callback.</summary>
    public event Action<string, Func<string, Task>>? MessageReceived;

    /// <summary>Whether the Bluetooth adapter is available on this machine.</summary>
    public static bool IsAvailable
    {
        get
        {
            try
            {
                var radio = BluetoothRadio.Default;
                return radio != null && radio.Mode != RadioMode.PowerOff;
            }
            catch { return false; }
        }
    }

    public BluetoothServer(ILogger<BluetoothServer> logger)
    {
        _logger = logger;
    }

    public void Start()
    {
        if (!IsAvailable)
        {
            _logger.LogWarning("Bluetooth adapter not available, BT server not started");
            return;
        }

        _cts = new CancellationTokenSource();

        try
        {
            _listener = new BluetoothListener(ServiceUuid)
            {
                ServiceName = Protocol.BluetoothServiceName
            };
            _listener.Start();

            _logger.LogInformation("Bluetooth RFCOMM server started (UUID: {Uuid})", Protocol.BluetoothServiceUuid);
            _ = Task.Run(() => AcceptLoop(_cts.Token));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to start Bluetooth server");
        }
    }

    private async Task AcceptLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _listener != null)
        {
            try
            {
                // AcceptBluetoothClient is blocking, run on thread pool
                var client = await Task.Run(() => _listener.AcceptBluetoothClient(), ct);
                _logger.LogInformation("Bluetooth client connected: {Name}",
                    client.RemoteMachineName ?? "Unknown");

                _ = Task.Run(() => HandleClient(client, ct));
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                _logger.LogError(ex, "Bluetooth accept error");
                await Task.Delay(1000, ct);
            }
        }
    }

    private async Task HandleClient(BluetoothClient client, CancellationToken ct)
    {
        var remoteName = client.RemoteMachineName ?? "Unknown";
        Stream? stream = null;
        try
        {
            stream = client.GetStream();
            lock (_streamsLock) _activeStreams.Add(stream);

            while (!ct.IsCancellationRequested && client.Connected)
            {
                var message = await StreamTransport.ReceiveAsync(stream, ct);
                if (message == null) break; // Disconnected

                _logger.LogDebug("BT msg from {Name}: {Msg}", remoteName,
                    message.Length > 60 ? message[..60] + "..." : message);

                // Provide a reply callback so the handler can respond over the same stream
                async Task ReplyAsync(string reply)
                {
                    try { await StreamTransport.SendAsync(stream, reply, ct); }
                    catch (Exception ex) { _logger.LogError(ex, "BT reply error"); }
                }

                MessageReceived?.Invoke(message, ReplyAsync);
            }
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            _logger.LogWarning(ex, "Bluetooth client {Name} disconnected: {Msg}", remoteName, ex.Message);
        }
        finally
        {
            if (stream != null)
            {
                lock (_streamsLock) _activeStreams.Remove(stream);
                try { stream.Dispose(); } catch { }
            }
            client.Dispose();
            _logger.LogInformation("Bluetooth client {Name} disconnected", remoteName);
        }
    }

    /// <summary>Send a message to all connected Bluetooth clients.</summary>
    public async Task SendToAllAsync(string message)
    {
        Stream[] streams;
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
