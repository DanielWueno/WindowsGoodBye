using System.Net;
using System.Net.Sockets;
using System.Text;
using WindowsGoodBye.Core;
using WindowsGoodBye.Mobile.Data;

namespace WindowsGoodBye.Mobile.Services;

/// <summary>
/// Multi-transport auth listener with auto-reconnect.
/// Maintains a persistent connection to the Windows service, automatically
/// cycling through transports (BT -> TCP/USB -> UDP) when connections drop.
///
/// Protocol flow (same on all transports):
/// 1. PC sends auth_discover -> we respond auth_alive
/// 2. PC sends auth_req (encrypted nonce) -> we trigger fingerprint -> respond auth_resp (HMAC)
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

    // Auto-reconnect state
    private int _reconnectAttempts;
    private const int MaxReconnectDelaySec = 60;
    private const int BaseReconnectDelaySec = 5;
    private const int HealthCheckIntervalSec = 30;
    private DateTime _lastMessageReceived = DateTime.UtcNow;

    // Pending auth request (for background biometric handling)
    private AuthRequest? _pendingAuthRequest;
    internal AuthRequest? PendingAuthRequest => _pendingAuthRequest;

    /// <summary>Fired when a PC requests fingerprint authentication.</summary>
    public event Action<AuthRequest>? AuthenticationRequested;

    /// <summary>Fired when pairing is finalized by the PC.</summary>
    public event Action<string, string>? PairingCompleted;

    /// <summary>Fired when transport state changes (for UI updates).</summary>
    public event Action<Protocol.TransportType, bool>? TransportStateChanged;

    /// <summary>Current active transport type.</summary>
    public Protocol.TransportType ActiveTransport { get; private set; } = Protocol.TransportType.Udp;

    /// <summary>Whether the current transport is connected (BT/TCP have active streams).</summary>
    public bool IsTransportConnected { get; private set; }

    private static AuthListener? _instance;
    public static AuthListener Instance => _instance ??= new AuthListener();

    public bool IsRunning => _cts != null && !_cts.IsCancellationRequested;

    private TaskCompletionSource<bool> _transportReady = new();

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
        _reconnectAttempts = 0;
        _lastMessageReceived = DateTime.UtcNow;

        _ = Task.Run(() => ConnectionManagerLoop(_cts.Token));
    }

    /// <summary>
    /// Main connection manager loop. Continuously maintains the best available
    /// transport with automatic reconnection and health monitoring.
    /// </summary>
    private async Task ConnectionManagerLoop(CancellationToken ct)
    {
        System.Diagnostics.Debug.WriteLine("[AuthListener] Connection manager started");

        while (!ct.IsCancellationRequested)
        {
            try
            {
                var connected = await TryConnectBestTransportAsync(ct);

                if (connected)
                {
                    _reconnectAttempts = 0;
                    _transportReady.TrySetResult(true);
                    UpdateForegroundNotification();

                    await MonitorConnectionHealthAsync(ct);

                    System.Diagnostics.Debug.WriteLine(
                        $"[AuthListener] {ActiveTransport} connection lost, will reconnect...");
                    IsTransportConnected = false;
                    TransportStateChanged?.Invoke(ActiveTransport, false);
                    UpdateForegroundNotification();
                }
                else
                {
                    EnsureUdpRunning();
                    _transportReady.TrySetResult(true);
                }

                _reconnectAttempts++;
                var delaySec = Math.Min(
                    BaseReconnectDelaySec * (int)Math.Pow(2, Math.Min(_reconnectAttempts - 1, 4)),
                    MaxReconnectDelaySec);

                System.Diagnostics.Debug.WriteLine(
                    $"[AuthListener] Reconnect attempt {_reconnectAttempts}, waiting {delaySec}s...");

                await Task.Delay(delaySec * 1000, ct);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[AuthListener] Connection loop error: {ex.Message}");
                await Task.Delay(5000, ct);
            }
        }

        System.Diagnostics.Debug.WriteLine("[AuthListener] Connection manager stopped");
    }

    private async Task<bool> TryConnectBestTransportAsync(CancellationToken ct)
    {
#if ANDROID
        // 1. Try Bluetooth RFCOMM
        try
        {
            if (Platforms.Android.BluetoothTransport.IsAvailable)
            {
                var bt = new Platforms.Android.BluetoothTransport();
                bt.MessageReceived += msg =>
                {
                    _lastMessageReceived = DateTime.UtcNow;
                    ProcessMessage(msg, null);
                };

                using var btTimeout = new CancellationTokenSource(10000);
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, btTimeout.Token);

                var address = await bt.ConnectToAnyAsync(linked.Token);
                if (address != null)
                {
                    _btTransport?.Dispose();
                    _btTransport = bt;
                    ActiveTransport = Protocol.TransportType.Bluetooth;
                    IsTransportConnected = true;
                    TransportStateChanged?.Invoke(ActiveTransport, true);
                    System.Diagnostics.Debug.WriteLine($"[AuthListener] Connected via Bluetooth to {address}");
                    await SendAliveForAllPcsAsync(SendBluetoothAsync);
                    return true;
                }
                else
                {
                    bt.Dispose();
                }
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[AuthListener] BT connect failed: {ex.Message}");
            _btTransport?.Dispose();
            _btTransport = null;
        }
#endif

        // 2. Try TCP/USB (ADB port forwarding)
        try
        {
            var tcp = new TcpUsbTransport();
            tcp.MessageReceived += msg =>
            {
                _lastMessageReceived = DateTime.UtcNow;
                ProcessMessage(msg, null);
            };

            using var tcpTimeout = new CancellationTokenSource(5000);
            using var linked2 = CancellationTokenSource.CreateLinkedTokenSource(ct, tcpTimeout.Token);

            if (await tcp.ConnectAsync(linked2.Token))
            {
                _tcpTransport?.Dispose();
                _tcpTransport = tcp;
                ActiveTransport = Protocol.TransportType.TcpUsb;
                IsTransportConnected = true;
                TransportStateChanged?.Invoke(ActiveTransport, true);
                System.Diagnostics.Debug.WriteLine("[AuthListener] Connected via TCP/USB");
                await SendAliveForAllPcsAsync(SendTcpAsync);
                return true;
            }
            else
            {
                tcp.Dispose();
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[AuthListener] TCP connect failed: {ex.Message}");
            _tcpTransport?.Dispose();
            _tcpTransport = null;
        }

        // 3. Fallback: UDP WiFi
        System.Diagnostics.Debug.WriteLine("[AuthListener] Using WiFi/UDP fallback");
        ActiveTransport = Protocol.TransportType.Udp;
        IsTransportConnected = false;
        return false;
    }

    private async Task MonitorConnectionHealthAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            await Task.Delay(HealthCheckIntervalSec * 1000, ct);

            bool alive = false;
#if ANDROID
            if (ActiveTransport == Protocol.TransportType.Bluetooth)
                alive = _btTransport?.IsConnected == true;
#endif
            if (ActiveTransport == Protocol.TransportType.TcpUsb)
                alive = _tcpTransport?.IsConnected == true;

            if (!alive)
            {
                System.Diagnostics.Debug.WriteLine("[AuthListener] Health check: connection dead");
                DisconnectCurrentTransport();
                return;
            }

            if ((DateTime.UtcNow - _lastMessageReceived).TotalMinutes > 2)
            {
                System.Diagnostics.Debug.WriteLine("[AuthListener] No messages for 2 min, sending keep-alive...");
                try
                {
                    Func<string, Task> sendFunc = _ => Task.CompletedTask;
#if ANDROID
                    if (ActiveTransport == Protocol.TransportType.Bluetooth)
                        sendFunc = SendBluetoothAsync;
#endif
                    if (ActiveTransport == Protocol.TransportType.TcpUsb)
                        sendFunc = SendTcpAsync;
                    await SendAliveForAllPcsAsync(sendFunc);
                }
                catch
                {
                    System.Diagnostics.Debug.WriteLine("[AuthListener] Keep-alive failed, reconnecting...");
                    DisconnectCurrentTransport();
                    return;
                }
            }
        }
    }

    private void DisconnectCurrentTransport()
    {
#if ANDROID
        if (ActiveTransport == Protocol.TransportType.Bluetooth)
        {
            _btTransport?.Disconnect();
            _btTransport = null;
        }
#endif
        if (ActiveTransport == Protocol.TransportType.TcpUsb)
        {
            _tcpTransport?.Disconnect();
            _tcpTransport = null;
        }
        IsTransportConnected = false;
    }

    private void EnsureUdpRunning()
    {
        if (_multicastClient != null) return;
        StartUdp();
    }

    private void StartUdp()
    {
        try
        {
            _multicastClient?.Close();
            _unicastClient?.Close();

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
        IsTransportConnected = false;
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
                _lastMessageReceived = DateTime.UtcNow;
                ProcessMessage(message, result.RemoteEndPoint.Address);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[AuthListener] UDP error: {ex.Message}");
                try { await Task.Delay(200, ct); } catch { break; }
            }
        }
    }

    // ===== Message Processing =====

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

        if (fromAddress != null)
        {
            pc.LastIp = fromAddress.ToString();
            db.SaveChanges();
        }

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

        var request = new AuthRequest
        {
            PcName = pc.PcName,
            DeviceIdBytes = deviceIdBytes,
            Nonce = nonce,
            AuthKey = pc.AuthKey,
            FromAddress = fromAddress,
            Transport = ActiveTransport
        };

        _pendingAuthRequest = request;
        AuthenticationRequested?.Invoke(request);

#if ANDROID
        ShowBackgroundAuthNotification(pc.PcName);
#endif
    }

#if ANDROID
    private void ShowBackgroundAuthNotification(string pcName)
    {
        try
        {
            var activity = Platform.CurrentActivity;
            bool isInForeground = activity != null && !activity.IsFinishing && !activity.IsDestroyed;

            if (isInForeground)
            {
                var appProcessInfo = new global::Android.App.ActivityManager.RunningAppProcessInfo();
                global::Android.App.ActivityManager.GetMyMemoryState(appProcessInfo);
                isInForeground = appProcessInfo.Importance == global::Android.App.Importance.Foreground;
            }

            if (!isInForeground)
            {
                System.Diagnostics.Debug.WriteLine("[AuthListener] App in background, showing auth notification");
                Platforms.Android.AuthForegroundService.Instance?.ShowAuthPromptNotification(pcName);
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[AuthListener] Notification error: {ex.Message}");
        }
    }
#endif

    public void ClearPendingAuthRequest()
    {
        _pendingAuthRequest = null;
#if ANDROID
        Platforms.Android.AuthForegroundService.Instance?.DismissAuthPromptNotification();
#endif
    }

    private void HandlePairFinish(string payload)
    {
        try
        {
            using var db = new MobileDatabase();
            db.Initialize();

            var pending = db.PairedPcs.FirstOrDefault(p => !p.IsPaired);
            if (pending?.PairEncryptKey == null) return;

            var decrypted = CryptoUtils.DecryptAes(
                Convert.FromBase64String(payload), pending.PairEncryptKey);
            var pcName = Encoding.UTF8.GetString(decrypted);

            pending.PcName = pcName;
            pending.IsPaired = true;
            pending.PairedAt = DateTime.UtcNow;
            pending.PairEncryptKeyBase64 = null;
            db.SaveChanges();

            System.Diagnostics.Debug.WriteLine($"[AuthListener] Pairing completed: {pcName}");
            PairingCompleted?.Invoke(pending.DeviceId, pcName);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[AuthListener] PairFinish error: {ex.Message}");
        }
    }

    // ===== Sending =====

    public async Task SendAuthResponseAsync(AuthRequest request)
    {
        var hmac = CryptoUtils.ComputeHmac(request.Nonce, request.AuthKey);
        var responsePayload = new byte[Protocol.GuidLength + 32];
        Array.Copy(request.DeviceIdBytes, 0, responsePayload, 0, Protocol.GuidLength);
        Array.Copy(hmac, 0, responsePayload, Protocol.GuidLength, 32);

        var response = Protocol.AuthResponsePrefix + Convert.ToBase64String(responsePayload);
        await SendReplyAsync(response, request.FromAddress);
        ClearPendingAuthRequest();
        System.Diagnostics.Debug.WriteLine($"[AuthListener] Auth response sent via {ActiveTransport}");
    }

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

        await SendReplyAsync(message, null);

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

        if (ActiveTransport == Protocol.TransportType.Udp)
            await SendMulticastAsync(message);
    }

    private async Task SendReplyAsync(string message, IPAddress? udpTarget)
    {
        try
        {
#if ANDROID
            if (ActiveTransport == Protocol.TransportType.Bluetooth && _btTransport?.IsConnected == true)
            {
                await _btTransport.SendAsync(message);
                return;
            }
#endif
            if (ActiveTransport == Protocol.TransportType.TcpUsb && _tcpTransport?.IsConnected == true)
            {
                await _tcpTransport.SendAsync(message);
                return;
            }

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

    private void UpdateForegroundNotification()
    {
#if ANDROID
        try
        {
            var text = ActiveTransport switch
            {
                Protocol.TransportType.Bluetooth => "Connected via Bluetooth",
                Protocol.TransportType.TcpUsb when IsTransportConnected => "Connected via USB",
                _ when IsTransportConnected => $"Connected via {ActiveTransport}",
                _ => "WiFi/UDP - Reconnecting..."
            };
            Platforms.Android.AuthForegroundService.Instance?.UpdateNotification(text);
        }
        catch { }
#endif
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

/// <summary>Data for a pending authentication request from a PC.</summary>
public class AuthRequest
{
    public required string PcName { get; init; }
    public required byte[] DeviceIdBytes { get; init; }
    public required byte[] Nonce { get; init; }
    public required byte[] AuthKey { get; init; }
    public IPAddress? FromAddress { get; init; }
    public Protocol.TransportType Transport { get; init; }
}
