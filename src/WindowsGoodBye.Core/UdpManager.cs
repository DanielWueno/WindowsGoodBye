using System.Net;
using System.Net.Sockets;
using System.Text;

namespace WindowsGoodBye.Core;

/// <summary>
/// Handles UDP multicast and unicast communication with Android devices.
/// </summary>
public class UdpManager : IDisposable
{
    private UdpClient? _multicastClient;
    private UdpClient? _unicastClient;
    private readonly IPAddress _multicastGroup;
    private CancellationTokenSource? _cts;
    private bool _disposed;

    public event Action<string, IPAddress>? MessageReceived;

    public UdpManager()
    {
        _multicastGroup = IPAddress.Parse(Protocol.MulticastGroup);
    }

    public void StartListening()
    {
        _cts = new CancellationTokenSource();

        // Multicast listener
        _multicastClient = new UdpClient();
        _multicastClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        _multicastClient.Client.Bind(new IPEndPoint(IPAddress.Any, Protocol.MulticastPort));
        _multicastClient.JoinMulticastGroup(_multicastGroup);

        // Unicast listener
        _unicastClient = new UdpClient();
        _unicastClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        _unicastClient.Client.Bind(new IPEndPoint(IPAddress.Any, Protocol.UnicastPort));

        Task.Run(() => ListenLoop(_multicastClient, _cts.Token));
        Task.Run(() => ListenLoop(_unicastClient, _cts.Token));
    }

    private async Task ListenLoop(UdpClient client, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var result = await client.ReceiveAsync(ct);
                var message = Encoding.UTF8.GetString(result.Buffer);
                MessageReceived?.Invoke(message, result.RemoteEndPoint.Address);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[UdpManager] Receive error: {ex.Message}");
                await Task.Delay(100, ct);
            }
        }
    }

    /// <summary>Send a UDP message to a specific IP address (unicast).</summary>
    public async Task SendUnicastAsync(string message, IPAddress target, int port = Protocol.UnicastPort)
    {
        var data = Encoding.UTF8.GetBytes(message);
        using var client = new UdpClient();
        await client.SendAsync(data, data.Length, new IPEndPoint(target, port));
    }

    /// <summary>Send a UDP message to the multicast group.</summary>
    public async Task SendMulticastAsync(string message)
    {
        var data = Encoding.UTF8.GetBytes(message);
        using var client = new UdpClient();
        client.JoinMulticastGroup(_multicastGroup);
        await client.SendAsync(data, data.Length, new IPEndPoint(_multicastGroup, Protocol.MulticastPort));
    }

    /// <summary>Send to both a specific IP and the multicast group.</summary>
    public async Task SendToDeviceAsync(string message, string? lastKnownIp)
    {
        if (!string.IsNullOrWhiteSpace(lastKnownIp) && IPAddress.TryParse(lastKnownIp, out var ip))
        {
            try { await SendUnicastAsync(message, ip); } catch { /* ignore */ }
        }
        try { await SendMulticastAsync(message); } catch { /* ignore */ }
    }

    public void StopListening()
    {
        _cts?.Cancel();
        try { _multicastClient?.DropMulticastGroup(_multicastGroup); } catch { }
        _multicastClient?.Close();
        _unicastClient?.Close();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        StopListening();
        _multicastClient?.Dispose();
        _unicastClient?.Dispose();
        _cts?.Dispose();
    }
}
