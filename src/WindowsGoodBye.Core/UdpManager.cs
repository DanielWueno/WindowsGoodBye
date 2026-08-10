using System.Net;
using System.Net.NetworkInformation;
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
        JoinMulticastGroupOnAllInterfaces(_multicastClient);

        // Unicast listener
        _unicastClient = new UdpClient();
        _unicastClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        _unicastClient.Client.Bind(new IPEndPoint(IPAddress.Any, Protocol.UnicastPort));

        Task.Run(() => ListenLoop(_multicastClient, _cts.Token));
        Task.Run(() => ListenLoop(_unicastClient, _cts.Token));
    }

    /// <summary>
    /// Join the multicast group on every active, multicast-capable IPv4 network interface
    /// individually, instead of a single interface-agnostic join. A generic
    /// <c>JoinMulticastGroup(group)</c> call lets the OS pick one "default" interface, which may not
    /// be the one actually connected to the phone's LAN on multi-NIC machines (Ethernet + WiFi + VPN
    /// adapters, etc.) — and a single failed join used to either throw unhandled (crashing
    /// StartListening) or, depending on the interface, fail silently. Each interface is now attempted
    /// independently, with failures logged (not swallowed) and the rest still attempted.
    /// See docs/plan_push_auth_v2.md, Fase 0 bonus.
    /// </summary>
    private static void JoinMulticastGroupOnAllInterfaces(UdpClient client)
    {
        var joinedAny = false;

        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
                if (!ni.Supports(NetworkInterfaceComponent.IPv4)) continue;

                IPInterfaceProperties props;
                try { props = ni.GetIPProperties(); }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"[UdpManager] Could not read IP properties for interface '{ni.Name}': {ex.Message}");
                    continue;
                }

                var ipv4Props = props.GetIPv4Properties();
                if (ipv4Props == null) continue; // interface has no IPv4 configuration

                try
                {
                    client.JoinMulticastGroup(ipv4Props.Index, IPAddress.Parse(Protocol.MulticastGroup));
                    joinedAny = true;
                }
                catch (Exception ex)
                {
                    // Expected for some virtual/VPN adapters that don't support multicast — log and
                    // keep trying the remaining interfaces instead of aborting startup entirely.
                    Console.Error.WriteLine(
                        $"[UdpManager] Multicast join failed on interface '{ni.Name}' (index {ipv4Props.Index}): {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[UdpManager] Failed to enumerate network interfaces: {ex.Message}");
        }

        if (!joinedAny)
        {
            // Fallback: let the OS pick the default interface, same behavior as before this change.
            try
            {
                client.JoinMulticastGroup(IPAddress.Parse(Protocol.MulticastGroup));
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[UdpManager] Fallback multicast join (default interface) failed: {ex.Message}");
            }
        }
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
