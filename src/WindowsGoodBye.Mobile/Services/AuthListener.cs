using System.Net;
using System.Net.Sockets;
using System.Text;
using WindowsGoodBye.Core;
using WindowsGoodBye.Mobile.Data;

namespace WindowsGoodBye.Mobile.Services;

/// <summary>
/// Multi-transport auth listener that communicates with the Windows service.
/// Tries transports in priority order:
///   1. Bluetooth RFCOMM — works without WiFi
///   2. TCP/USB (ADB forward) — works over USB cable
///   3. UDP WiFi — multicast/unicast on the LAN (fallback)
///
/// Protocol flow (same on all transports):
/// 1. PC sends auth_discover → we respond auth_alive
/// 2. PC sends auth_req (encrypted nonce) → we trigger fingerprint → respond auth_resp (HMAC)
/// </summary>
public class AuthListener : IDisposable
{
    // UDP (WiFi fallback)
    private UdpClient? _multicastClient;
    private UdpClient? _unicastClient;
    private readonly IPAddress _multicastGroup;

    // Stream transports
#if ANDROID
    private Platforms.Android.BluetoothTransport? _btTransport;
#endif
    private TcpUsbTransport? _tcpTransport;

    private CancellationTokenSource? _cts;
    private bool _disposed;

    /// <summary>Fired when a PC requests fingerprint authentication.</summary>
    public event Action<AuthRequest>? AuthenticationRequested;

    /// <summary>Fired when pairing is finalized by the PC.</summary>
    public event Action<string, string>? PairingCompleted; // deviceId, pcName

    /// <summary>Current active transport type.</summary>
    public Protocol.TransportType ActiveTransport { get; private set; } = Protocol.TransportType.Udp;

    private static AuthListener? _instance;
    public static AuthListener Instance => _instance ??= new AuthListener();

    public bool IsRunning => _cts != null && !_cts.IsCancellationRequested;

    /// <summary>Completes when the transport layer is fully initialized (listeners bound).</summary>
    private TaskCompletionSource<bool> _transportReady = new();

    /// <summary>Wait until the AuthListener transport is fully ready (BT/TCP/UDP bound).</summary>
    public Task WaitForTransportAsync(CancellationToken ct = default)
    {
        ct.Register(() => _transportReady.TrySetCanceled());
        return _transportReady.Task;
    }

    private AuthListener()
    {
        _multicastGroup = IPAddress.Parse(Protocol.MulticastGroup);
    }

    public void Start()
    {
        if (IsRunning) return;

        _cts = new CancellationTokenSource();
        _transportReady = new TaskCompletionSource<bool>();
        _ = Task.Run(() => StartWithPriorityAsync(_cts.Token));
    }

    /// <summary>
    /// Attempt transports in priority order: Bluetooth → TCP/USB → UDP.
    /// Falls back automatically if higher-priority options fail.
    /// </summary>
    private async Task StartWithPriorityAsync(CancellationToken ct)
    {
        // 1. Try Bluetooth RFCOMM
#if ANDROID
        try
        {
            if (Platforms.Android.BluetoothTransport.IsAvailable)
            {
                _btTransport = new Platforms.Android.BluetoothTransport();
                _btTransport.MessageReceived += msg => ProcessMessage(msg, null);

                var address = await _btTransport.ConnectToAnyAsync(ct);
                if (address != null)
                {
                    ActiveTransport = Protocol.TransportType.Bluetooth;
                    System.Diagnostics.Debug.WriteLine($"[AuthListener] Connected via Bluetooth to {address}");

                    _transportReady.TrySetResult(true);
                    // Send alive for all paired PCs on this transport
                    await SendAliveForAllPcsAsync(SendBluetoothAsync);
                    return; // Bluetooth is active, no need for other transports
                }
                else
                {
                    _btTransport.Dispose();
                    _btTransport = null;
                    System.Diagnostics.Debug.WriteLine("[AuthListener] No Bluetooth connection available");
                }
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[AuthListener] Bluetooth init failed: {ex.Message}");
            _btTransport?.Dispose();
            _btTransport = null;
        }
#endif

        // 2. Try TCP/USB (ADB port forwarding)
        try
        {
            _tcpTransport = new TcpUsbTransport();
            _tcpTransport.MessageReceived += msg => ProcessMessage(msg, null);

            if (await _tcpTransport.ConnectAsync(ct))
            {
                ActiveTransport = Protocol.TransportType.TcpUsb;
                System.Diagnostics.Debug.WriteLine("[AuthListener] Connected via TCP/USB");

                _transportReady.TrySetResult(true);
                await SendAliveForAllPcsAsync(SendTcpAsync);
                return; // TCP is active
            }
            else
            {
                _tcpTransport.Dispose();
                _tcpTransport = null;
                System.Diagnostics.Debug.WriteLine("[AuthListener] TCP/USB not available");
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[AuthListener] TCP/USB init failed: {ex.Message}");
            _tcpTransport?.Dispose();
            _tcpTransport = null;
        }

        // 3. Fallback: UDP WiFi
        StartUdp();
        ActiveTransport = Protocol.TransportType.Udp;
        _transportReady.TrySetResult(true);
        System.Diagnostics.Debug.WriteLine("[AuthListener] Using WiFi/UDP fallback");
    }

    private void StartUdp()
    {
        try
        {
            _multicastClient = new UdpClient();
            _multicastClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            _multicastClient.Client.Bind(new IPEndPoint(IPAddress.Any, Protocol.MulticastPort));
            _multicastClient.JoinMulticastGroup(_multicastGroup);

            _unicastClient = new UdpClient();
            _unicastClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            _unicastClient.Client.Bind(new IPEndPoint(IPAddress.Any, Protocol.UnicastPort));

            _ = Task.Run(() => UdpListenLoop(_multicastClient, _cts!.Token));
            _ = Task.Run(() => UdpListenLoop(_unicastClient, _cts!.Token));

            System.Diagnostics.Debug.WriteLine("[AuthListener] UDP started");
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[AuthListener] UDP start failed: {ex.Message}");
        }
    }

    public void Stop()
    {
        _cts?.Cancel();

#if ANDROID
        _btTransport?.Disconnect();
        _btTransport = null;
#endif
        _tcpTransport?.Disconnect();
        _tcpTransport = null;

        try { _multicastClient?.DropMulticastGroup(_multicastGroup); } catch { }
        _multicastClient?.Close();
        _unicastClient?.Close();
        _multicastClient = null;
        _unicastClient = null;

        ActiveTransport = Protocol.TransportType.Udp;
        System.Diagnostics.Debug.WriteLine("[AuthListener] Stopped");
    }

    private async Task UdpListenLoop(UdpClient client, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var result = await client.ReceiveAsync(ct);
                var message = Encoding.UTF8.GetString(result.Buffer);
                ProcessMessage(message, result.RemoteEndPoint.Address);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[AuthListener] Error: {ex.Message}");
                try { await Task.Delay(200, ct); } catch { break; }
            }
        }
    }

    private void ProcessMessage(string message, IPAddress? fromAddress)
    {
        try
        {
            if (message.StartsWith(Protocol.AuthDiscoverPrefix))
                HandleAuthDiscover(message[Protocol.AuthDiscoverPrefix.Length..], fromAddress);
            else if (message.StartsWith(Protocol.AuthRequestPrefix))
                HandleAuthRequest(message[Protocol.AuthRequestPrefix.Length..], fromAddress);
            else if (message.StartsWith(Protocol.PairFinishPrefix))
                HandlePairFinish(message[Protocol.PairFinishPrefix.Length..]);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[AuthListener] Process error: {ex.Message}");
        }
    }

    private void HandleAuthDiscover(string payload, IPAddress? fromAddress)
    {
        var deviceIdBytes = Convert.FromBase64String(payload);
        if (deviceIdBytes.Length != Protocol.GuidLength) return;

        var deviceId = new Guid(deviceIdBytes).ToString();

        using var db = new MobileDatabase();
        db.Initialize();
        var pc = db.PairedPcs.FirstOrDefault(p => p.DeviceId == deviceId && p.IsPaired);
        if (pc == null) return;

        System.Diagnostics.Debug.WriteLine($"[AuthListener] Discover from {pc.PcName} via {ActiveTransport}");

        // Update last IP (only if from UDP)
        if (fromAddress != null)
        {
            pc.LastIp = fromAddress.ToString();
            db.SaveChanges();
        }

        // Respond: we're alive
        var response = Protocol.AuthAlivePrefix + Convert.ToBase64String(deviceIdBytes);
        _ = SendReplyAsync(response, fromAddress);
    }

    private void HandleAuthRequest(string payload, IPAddress? fromAddress)
    {
        var rawBytes = Convert.FromBase64String(payload);
        if (rawBytes.Length < Protocol.GuidLength) return;

        var deviceIdBytes = new byte[Protocol.GuidLength];
        Array.Copy(rawBytes, deviceIdBytes, Protocol.GuidLength);
        var deviceId = new Guid(deviceIdBytes).ToString();

        using var db = new MobileDatabase();
        db.Initialize();
        var pc = db.PairedPcs.FirstOrDefault(p => p.DeviceId == deviceId && p.IsPaired);
        if (pc == null) return;

        var encryptedNonce = new byte[rawBytes.Length - Protocol.GuidLength];
        Array.Copy(rawBytes, Protocol.GuidLength, encryptedNonce, 0, encryptedNonce.Length);

        byte[] nonce;
        try
        {
            nonce = CryptoUtils.DecryptAes(encryptedNonce, pc.DeviceKey);
        }
        catch
        {
            System.Diagnostics.Debug.WriteLine("[AuthListener] Failed to decrypt nonce");
            return;
        }

        System.Diagnostics.Debug.WriteLine($"[AuthListener] Auth request from {pc.PcName} via {ActiveTransport}");

        // Fire event for the UI to handle biometric auth
        AuthenticationRequested?.Invoke(new AuthRequest
        {
            PcName = pc.PcName,
            DeviceIdBytes = deviceIdBytes,
            Nonce = nonce,
            AuthKey = pc.AuthKey,
            FromAddress = fromAddress,
            Transport = ActiveTransport
        });
    }

    private void HandlePairFinish(string payload)
    {
        try
        {
            using var db = new MobileDatabase();
            db.Initialize();

            // Find the pending (not yet paired) entry
            var pending = db.PairedPcs.FirstOrDefault(p => !p.IsPaired);
            if (pending?.PairEncryptKey == null) return;

            var decrypted = CryptoUtils.DecryptAes(
                Convert.FromBase64String(payload), pending.PairEncryptKey);
            var pcName = Encoding.UTF8.GetString(decrypted);

            pending.PcName = pcName;
            pending.IsPaired = true;
            pending.PairedAt = DateTime.UtcNow;
            pending.PairEncryptKeyBase64 = null; // No longer needed
            db.SaveChanges();

            System.Diagnostics.Debug.WriteLine($"[AuthListener] Pairing completed: {pcName}");
            PairingCompleted?.Invoke(pending.DeviceId, pcName);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[AuthListener] PairFinish error: {ex.Message}");
        }
    }

    /// <summary>Send the auth response after successful fingerprint.</summary>
    public async Task SendAuthResponseAsync(AuthRequest request)
    {
        var hmac = CryptoUtils.ComputeHmac(request.Nonce, request.AuthKey);
        var responsePayload = new byte[Protocol.GuidLength + 32];
        Array.Copy(request.DeviceIdBytes, 0, responsePayload, 0, Protocol.GuidLength);
        Array.Copy(hmac, 0, responsePayload, Protocol.GuidLength, 32);

        var response = Protocol.AuthResponsePrefix + Convert.ToBase64String(responsePayload);
        await SendReplyAsync(response, request.FromAddress);
        System.Diagnostics.Debug.WriteLine($"[AuthListener] Auth response sent via {ActiveTransport}");
    }

    /// <summary>Send a pairing request using the current best transport.
    /// If pcIpAddresses are provided (from QR code), sends unicast directly to each PC IP.</summary>
    public async Task SendPairRequestAsync(Guid deviceId, byte[] pairEncryptKey,
        string friendlyName, string modelName, string[]? pcIpAddresses = null)
    {
        var deviceIdBytes = deviceId.ToByteArray();

        var nameBytes = Encoding.UTF8.GetBytes(friendlyName);
        var modelBytes = Encoding.UTF8.GetBytes(modelName);
        var plain = new byte[2 + nameBytes.Length + modelBytes.Length];
        plain[0] = (byte)nameBytes.Length;
        plain[1] = (byte)modelBytes.Length;
        Array.Copy(nameBytes, 0, plain, 2, nameBytes.Length);
        Array.Copy(modelBytes, 0, plain, 2 + nameBytes.Length, modelBytes.Length);

        var encrypted = CryptoUtils.EncryptAes(plain, pairEncryptKey);
        var payload = new byte[Protocol.GuidLength + encrypted.Length];
        Array.Copy(deviceIdBytes, 0, payload, 0, Protocol.GuidLength);
        Array.Copy(encrypted, 0, payload, Protocol.GuidLength, encrypted.Length);

        var message = Protocol.PairRequestPrefix + Convert.ToBase64String(payload);

        // 1. Try the active stream transport (BT / TCP-USB)
        await SendReplyAsync(message, null);

        // 2. Send UNICAST directly to every PC IP from the QR code — most reliable
        if (pcIpAddresses is { Length: > 0 })
        {
            foreach (var ipStr in pcIpAddresses)
            {
                if (IPAddress.TryParse(ipStr, out var ip))
                {
                    System.Diagnostics.Debug.WriteLine($"[AuthListener] Sending pair_req unicast to {ip}:{Protocol.UnicastPort}");
                    await SendUdpUnicastAsync(message, ip);
                }
            }
        }

        // 3. Also try multicast as fallback
        if (ActiveTransport == Protocol.TransportType.Udp)
            await SendMulticastAsync(message);
    }

    // --- Unified send: routes to the active transport ---

    private async Task SendReplyAsync(string message, IPAddress? udpTarget)
    {
        try
        {
            switch (ActiveTransport)
            {
                case Protocol.TransportType.Bluetooth:
#if ANDROID
                    if (_btTransport?.IsConnected == true)
                    {
                        await _btTransport.SendAsync(message);
                        return;
                    }
#endif
                    break;

                case Protocol.TransportType.TcpUsb:
                    if (_tcpTransport?.IsConnected == true)
                    {
                        await _tcpTransport.SendAsync(message);
                        return;
                    }
                    break;
            }

            // Fallback to UDP unicast
            if (udpTarget != null)
                await SendUdpUnicastAsync(message, udpTarget);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[AuthListener] Send error: {ex.Message}");
        }
    }

    private async Task SendAliveForAllPcsAsync(Func<string, Task> sendFunc)
    {
        try
        {
            using var db = new MobileDatabase();
            db.Initialize();
            var pcs = db.PairedPcs.Where(p => p.IsPaired).ToList();
            foreach (var pc in pcs)
            {
                if (!Guid.TryParse(pc.DeviceId, out var guid)) continue;
                var deviceIdBytes = guid.ToByteArray();
                var msg = Protocol.AuthAlivePrefix + Convert.ToBase64String(deviceIdBytes);
                await sendFunc(msg);
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[AuthListener] SendAlive error: {ex.Message}");
        }
    }

#if ANDROID
    private Task SendBluetoothAsync(string message) =>
        _btTransport?.IsConnected == true ? _btTransport.SendAsync(message) : Task.CompletedTask;
#endif

    private Task SendTcpAsync(string message) =>
        _tcpTransport?.IsConnected == true ? _tcpTransport.SendAsync(message) : Task.CompletedTask;

    private async Task SendUdpUnicastAsync(string message, IPAddress target)
    {
        try
        {
            var data = Encoding.UTF8.GetBytes(message);
            using var client = new UdpClient();
            await client.SendAsync(data, data.Length, new IPEndPoint(target, Protocol.UnicastPort));
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[AuthListener] SendUnicast error: {ex.Message}");
        }
    }

    private async Task SendMulticastAsync(string message)
    {
        try
        {
            var data = Encoding.UTF8.GetBytes(message);
            using var client = new UdpClient();
            client.JoinMulticastGroup(_multicastGroup);
            await client.SendAsync(data, data.Length,
                new IPEndPoint(_multicastGroup, Protocol.MulticastPort));
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[AuthListener] SendMulticast error: {ex.Message}");
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
#if ANDROID
        _btTransport?.Dispose();
#endif
        _tcpTransport?.Dispose();
        _cts?.Dispose();
    }
}

/// <summary>
/// Data for a pending authentication request from a PC.
/// </summary>
public class AuthRequest
{
    public required string PcName { get; init; }
    public required byte[] DeviceIdBytes { get; init; }
    public required byte[] Nonce { get; init; }
    public required byte[] AuthKey { get; init; }
    /// <summary>UDP source address (null for BT/TCP transports).</summary>
    public IPAddress? FromAddress { get; init; }
    /// <summary>Which transport this request arrived on.</summary>
    public Protocol.TransportType Transport { get; init; }
}
