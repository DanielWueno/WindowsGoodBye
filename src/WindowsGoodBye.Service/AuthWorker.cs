using System.Net;
using System.Text;
using WindowsGoodBye.Core;

namespace WindowsGoodBye.Service;

/// <summary>
/// Background worker that handles device discovery and authentication.
/// Listens on three transports (in priority order):
///   1. Bluetooth RFCOMM — works without WiFi
///   2. TCP/USB (ADB forward) — works over USB cable
///   3. UDP WiFi — multicast/unicast on the LAN
/// When a device authenticates via fingerprint, signals the credential provider
/// through the named pipe to unlock the PC.
/// </summary>
public class AuthWorker : BackgroundService
{
    private readonly ILogger<AuthWorker> _logger;
    private readonly ILoggerFactory _loggerFactory;
    private UdpManager? _udp;
    private BluetoothServer? _bt;
    private TcpUsbServer? _tcp;
    private AppDatabase? _db;
    private FcmPushSender? _fcm;

    // Shared state: when a device authenticates, this is set so PipeServer can read it
    internal static volatile string? AuthenticatedPassword = null;
    internal static readonly ManualResetEventSlim AuthEvent = new(false);

    /// <summary>Singleton reference so PipeServer can send messages on active transports.</summary>
    internal static AuthWorker? Instance { get; private set; }

    public AuthWorker(ILogger<AuthWorker> logger, ILoggerFactory loggerFactory)
    {
        _logger = logger;
        _loggerFactory = loggerFactory;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("WindowsGoodBye Auth Service starting...");

        Instance = this;
        _db = new AppDatabase();
        _db.Initialize();

        // Initialize FCM push sender (optional — disabled if not configured)
        _fcm = new FcmPushSender(_loggerFactory.CreateLogger<FcmPushSender>());
        if (_fcm.IsAvailable)
            _logger.LogInformation("FCM push notifications enabled");

        // --- Start all transport listeners ---

        // 1. Bluetooth RFCOMM
        try
        {
            _bt = new BluetoothServer(_loggerFactory.CreateLogger<BluetoothServer>());
            _bt.MessageReceived += OnStreamMessageReceived;
            _bt.Start();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Bluetooth server not available: {Msg}", ex.Message);
        }

        // 2. TCP/USB
        try
        {
            _tcp = new TcpUsbServer(_loggerFactory.CreateLogger<TcpUsbServer>());
            _tcp.MessageReceived += OnStreamMessageReceived;
            _tcp.Start();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "TCP/USB server failed: {Msg}", ex.Message);
        }

        // 3. UDP WiFi (existing)
        _udp = new UdpManager();
        _udp.MessageReceived += OnUdpMessageReceived;
        _udp.StartListening();

        _logger.LogInformation(
            "Transports active — BT: {BT}, TCP/USB: {TCP}, UDP: {UDP}",
            _bt != null && BluetoothServer.IsAvailable ? "YES" : "NO",
            _tcp != null ? "YES" : "NO",
            "YES");

        // Keep alive loop
        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(2000, stoppingToken);
        }

        _bt?.Stop();
        _tcp?.Stop();
        _udp.StopListening();
        _logger.LogInformation("WindowsGoodBye Auth Service stopped.");
    }

    // --- UDP transport (fire-and-forget, reply via unicast) ---

    private void OnUdpMessageReceived(string message, IPAddress remoteIp)
    {
        try
        {
            Func<string, Task> replyFunc = async reply =>
            {
                if (_udp != null)
                    await _udp.SendUnicastAsync(reply, remoteIp);
            };

            ProcessMessage(message, remoteIp.ToString(), replyFunc);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing UDP message from {IP}", remoteIp);
        }
    }

    // --- Stream transports (BT / TCP): reply goes back on the same stream ---

    private void OnStreamMessageReceived(string message, Func<string, Task> replyFunc)
    {
        try
        {
            ProcessMessage(message, "stream", replyFunc);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing stream message");
        }
    }

    // --- Unified message processing ---

    private void ProcessMessage(string message, string source, Func<string, Task> replyFunc)
    {
        try
        {
            var prefix = message.Length > 30 ? message[..30] : message;
            _logger.LogInformation(">> Incoming message from [{Source}]: {Prefix}...", source, prefix);

            if (message.StartsWith(Protocol.PairRequestPrefix))
            {
                HandlePairRequest(message[Protocol.PairRequestPrefix.Length..], source, replyFunc);
            }
            else if (message.StartsWith(Protocol.AuthAlivePrefix))
            {
                HandleAuthAlive(message[Protocol.AuthAlivePrefix.Length..], source, replyFunc);
            }
            else if (message.StartsWith(Protocol.AuthResponsePrefix))
            {
                HandleAuthResponse(message[Protocol.AuthResponsePrefix.Length..], source);
            }
            else
            {
                _logger.LogWarning("Unknown message prefix from {Source}", source);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing message from {Source}", source);
        }
    }

    private void HandlePairRequest(string payload, string source, Func<string, Task> replyFunc)
    {
        _logger.LogInformation("Pair request from {Source}, Session active: {Active}",
            source, PairingSession.Active != null);

        if (PairingSession.Active == null)
        {
            _logger.LogWarning("No active pairing session, ignoring pair request");
            return;
        }

        var session = PairingSession.Active;
        var rawBytes = Convert.FromBase64String(payload);
        if (rawBytes.Length <= Protocol.GuidLength) return;

        // Extract device ID
        var deviceIdBytes = new byte[Protocol.GuidLength];
        Array.Copy(rawBytes, deviceIdBytes, Protocol.GuidLength);
        var deviceId = new Guid(deviceIdBytes);

        if (deviceId != session.DeviceId)
        {
            _logger.LogWarning("Device ID mismatch in pair request");
            return;
        }

        // Decrypt device info
        var encryptedLen = rawBytes.Length - Protocol.GuidLength;
        var encryptedData = new byte[encryptedLen];
        Array.Copy(rawBytes, Protocol.GuidLength, encryptedData, 0, encryptedLen);

        byte[] decryptedData;
        try
        {
            decryptedData = CryptoUtils.DecryptAes(encryptedData, session.PairEncryptKey);
        }
        catch
        {
            _logger.LogError("Failed to decrypt pair request data");
            return;
        }

        if (decryptedData.Length < 2) return;
        int friendlyNameLen = decryptedData[0];
        int modelNameLen = decryptedData[1];
        if (decryptedData.Length != 2 + friendlyNameLen + modelNameLen) return;

        var friendlyName = Encoding.UTF8.GetString(decryptedData, 2, friendlyNameLen);
        var modelName = Encoding.UTF8.GetString(decryptedData, 2 + friendlyNameLen, modelNameLen);

        _logger.LogInformation("Device detected: {Name} ({Model})", friendlyName, modelName);

        // Save to database
        var device = new DeviceInfo
        {
            DeviceId = session.DeviceId,
            FriendlyName = friendlyName,
            ModelName = modelName,
            DeviceKey = session.DeviceKey,
            AuthKey = session.AuthKey,
            LastIpAddress = source,
            Enabled = true,
            PairedAt = DateTime.UtcNow
        };

        _db!.Devices.Add(device);
        _db.SaveChanges();

        // Send pair finish to device (via same transport that received the request)
        var computerName = Environment.MachineName;
        var finishPayload = Convert.ToBase64String(
            CryptoUtils.EncryptAes(Encoding.UTF8.GetBytes(computerName), session.PairEncryptKey));
        var finishMessage = Protocol.PairFinishPrefix + finishPayload;

        replyFunc(finishMessage).Wait();

        _logger.LogInformation("Pairing completed with {Name}", friendlyName);
        session.Complete(friendlyName, modelName);
        PairingSession.Active = null;
    }

    private void HandleAuthAlive(string payload, string source, Func<string, Task> replyFunc)
    {
        var deviceIdBytes = Convert.FromBase64String(payload);
        if (deviceIdBytes.Length != Protocol.GuidLength) return;

        var deviceId = new Guid(deviceIdBytes);
        var device = _db?.Devices.Find(deviceId);
        if (device == null || !device.Enabled) return;

        _logger.LogInformation("Device {Name} is alive via {Source}", device.FriendlyName, source);

        // Update last known IP (for UDP only)
        if (source != "stream")
        {
            device.LastIpAddress = source;
            _db!.SaveChanges();
        }

        // Send auth challenge: nonce encrypted with device key
        var nonce = CryptoUtils.GenerateNonce(32);

        // Store the pending challenge
        PendingAuthChallenges.Add(deviceId, nonce);

        // Build challenge: [32 bytes nonce] - encrypted with deviceKey for transport
        var encryptedNonce = CryptoUtils.EncryptAes(nonce, device.DeviceKey);
        var challengePayload = Convert.ToBase64String(
            deviceIdBytes.Concat(encryptedNonce).ToArray());

        var challengeMessage = Protocol.AuthRequestPrefix + challengePayload;
        replyFunc(challengeMessage).Wait();

        _logger.LogInformation("Auth challenge sent to {Name}", device.FriendlyName);
    }

    private void HandleAuthResponse(string payload, string source)
    {
        var rawBytes = Convert.FromBase64String(payload);
        if (rawBytes.Length < Protocol.GuidLength + 32) return; // Need at least deviceId + HMAC

        var deviceIdBytes = new byte[Protocol.GuidLength];
        Array.Copy(rawBytes, deviceIdBytes, Protocol.GuidLength);
        var deviceId = new Guid(deviceIdBytes);

        var device = _db?.Devices.Find(deviceId);
        if (device == null || !device.Enabled) return;

        // Get the pending nonce
        if (!PendingAuthChallenges.TryGet(deviceId, out var expectedNonce))
        {
            _logger.LogWarning("No pending auth challenge for device {Id}", deviceId);
            return;
        }

        // Extract HMAC from response
        var hmacBytes = new byte[32];
        Array.Copy(rawBytes, Protocol.GuidLength, hmacBytes, 0, 32);

        // Verify HMAC: HMAC-SHA256(nonce, authKey)
        if (!CryptoUtils.VerifyHmac(expectedNonce, device.AuthKey, hmacBytes))
        {
            _logger.LogWarning("Auth HMAC verification failed for device {Name}", device.FriendlyName);
            return;
        }

        _logger.LogInformation("Device {Name} authenticated successfully via {Source}!", device.FriendlyName, source);

        // Update auth record
        device.LastAuthAt = DateTime.UtcNow;
        _db!.AuthRecords.Add(new AuthRecord
        {
            DeviceId = deviceId,
            Timestamp = DateTime.UtcNow,
            IpAddress = source
        });
        _db.SaveChanges();

        // Get stored Windows credential and signal the credential provider
        // Use a fresh context to ensure we see the latest credentials saved by TrayApp
        using var freshDb = new AppDatabase();
        var cred = freshDb.Credentials.FirstOrDefault();
        if (cred != null)
        {
            try
            {
                var password = Encoding.UTF8.GetString(CryptoUtils.UnprotectData(cred.EncryptedPassword));
                AuthenticatedPassword = $"{cred.Domain}\\{cred.Username}\n{password}";
                AuthEvent.Set();
                _logger.LogInformation("Auth signal sent to credential provider");

                // Auto-reset after 30 seconds
                Task.Run(async () =>
                {
                    await Task.Delay(30000);
                    AuthenticatedPassword = null;
                    AuthEvent.Reset();
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to decrypt stored credentials");
            }
        }
        else
        {
            _logger.LogWarning("No stored Windows credentials found. Run the TrayApp to set up credentials.");
        }

        PendingAuthChallenges.Remove(deviceId);
    }

    /// <summary>
    /// Send auth discovery to all known devices on ALL active transports.
    /// Called when the lock screen is detected.
    /// </summary>
    public async Task DiscoverDevicesAsync()
    {
        if (_db == null) return;

        var devices = _db.Devices.Where(d => d.Enabled).ToList();
        foreach (var device in devices)
        {
            var payload = Convert.ToBase64String(device.DeviceId.ToByteArray());
            var message = Protocol.AuthDiscoverPrefix + payload;
            await SendOnAllTransportsAsync(message, device.LastIpAddress);

            // Also try FCM push to wake the device (in case all transports are down)
            if (_fcm?.IsAvailable == true && !string.IsNullOrEmpty(device.FcmToken))
            {
                _logger.LogDebug("Sending FCM wake push to {Name}", device.FriendlyName);
                _ = _fcm.SendAuthWakeAsync(device.FcmToken, Environment.MachineName);
            }
        }
    }

    /// <summary>Send a message on every active transport (BT, TCP, UDP).</summary>
    internal async Task SendOnAllTransportsAsync(string message, string? lastIp = null)
    {
        // Bluetooth
        if (_bt != null)
        {
            try { await _bt.SendToAllAsync(message); }
            catch (Exception ex) { _logger.LogDebug("BT send error: {Msg}", ex.Message); }
        }

        // TCP/USB
        if (_tcp != null)
        {
            try { await _tcp.SendToAllAsync(message); }
            catch (Exception ex) { _logger.LogDebug("TCP send error: {Msg}", ex.Message); }
        }

        // UDP (unicast + multicast)
        if (_udp != null)
        {
            try { await _udp.SendToDeviceAsync(message, lastIp); }
            catch (Exception ex) { _logger.LogDebug("UDP send error: {Msg}", ex.Message); }
        }
    }
}

/// <summary>Temporary storage for pending auth challenges (nonces).</summary>
internal static class PendingAuthChallenges
{
    private static readonly Dictionary<Guid, byte[]> _challenges = new();
    private static readonly object _lock = new();

    public static void Add(Guid deviceId, byte[] nonce)
    {
        lock (_lock)
        {
            _challenges[deviceId] = nonce;
        }
    }

    public static bool TryGet(Guid deviceId, out byte[] nonce)
    {
        lock (_lock)
        {
            return _challenges.TryGetValue(deviceId, out nonce!);
        }
    }

    public static void Remove(Guid deviceId)
    {
        lock (_lock)
        {
            _challenges.Remove(deviceId);
        }
    }
}
