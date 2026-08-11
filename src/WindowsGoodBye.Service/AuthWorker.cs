using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
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
///
/// Fase 3 (docs/plan_push_auth_v2.md, "Service — Orquestación Push Auth") adds
/// <see cref="RunAuthRaceAsync"/>: the parallel Ruta A (direct transports) / Ruta B (legacy FCM
/// wake-up) / Ruta C (full push-auth challenge via the embedded relay) race, push-fatigue rate
/// limiting, and push-auth HMAC verification with anti-replay-delay windows.
/// </summary>
public class AuthWorker : BackgroundService
{
    private readonly ILogger<AuthWorker> _logger;
    private readonly ILoggerFactory _loggerFactory;
    private readonly IConfiguration _configuration;
    private UdpManager? _udp;
    private BluetoothServer? _bt;
    private TcpUsbServer? _tcp;
    private AppDatabase? _db;
    private FcmPushSender? _fcm;
    private AdbDeviceWatcher? _adbWatcher;

    private RelayServer? _relay;
    private bool _ownsRelay;
    private readonly ITunnelStatusProvider _tunnelStatus;
    private readonly PushFatigueGuard _pushFatigue = new();

    /// <summary>
    /// Global timeout for a full <see cref="RunAuthRaceAsync"/> cycle. Configurable via
    /// <c>PushAuth:GlobalTimeoutSeconds</c> in appsettings.json/env vars; defaults to the plan's 60s.
    /// </summary>
    private TimeSpan GlobalRaceTimeout =>
        TimeSpan.FromSeconds(_configuration.GetValue<int?>("PushAuth:GlobalTimeoutSeconds") ?? 60);

    // Shared state: when a device authenticates, this is set so PipeServer can read it
    internal static volatile string? AuthenticatedPassword = null;
    internal static readonly ManualResetEventSlim AuthEvent = new(false);

    /// <summary>
    /// True when the credential provider is connected and waiting for auth.
    /// Only when this is true should we send auth challenges to phones.
    /// Prevents premature auth prompts when PC is not locked.
    /// </summary>
    internal static volatile bool IsAuthWaiting = false;

    /// <summary>Singleton reference so PipeServer can send messages on active transports.</summary>
    internal static AuthWorker? Instance { get; private set; }

    /// <param name="relayServer">
    /// Optional shared <see cref="RelayServer"/> instance. Fase 4 is expected to register one as a
    /// singleton (started as part of Service startup, alongside <see cref="TunnelManager"/>) and have
    /// DI inject it here. Until then (not registered), this is null and <see cref="ExecuteAsync"/>
    /// creates+owns/starts/stops its own instance — see docs/implementation_progress_push_auth_v2.md.
    /// </param>
    /// <param name="tunnelStatus">
    /// Optional tunnel-connectivity oracle for Ruta C/B gating. Not registered in DI yet (Fase 4's
    /// job) — defaults to <see cref="NullTunnelStatusProvider"/> (always "not connected"), which is
    /// safe: it just means Ruta B/C never fire until Fase 4 wires the real tunnel.
    /// </param>
    public AuthWorker(
        ILogger<AuthWorker> logger,
        ILoggerFactory loggerFactory,
        IConfiguration configuration,
        RelayServer? relayServer = null,
        ITunnelStatusProvider? tunnelStatus = null)
    {
        _logger = logger;
        _loggerFactory = loggerFactory;
        _configuration = configuration;
        _relay = relayServer;
        _tunnelStatus = tunnelStatus ?? NullTunnelStatusProvider.Instance;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("WindowsGoodBye Auth Service starting...");

        Instance = this;
        _db = new AppDatabase();
        _db.Initialize();

        // Initialize FCM push sender (optional — disabled if not configured)
        _fcm = new FcmPushSender(_loggerFactory.CreateLogger<FcmPushSender>(), _configuration);
        if (_fcm.IsAvailable)
            _logger.LogInformation("FCM push notifications enabled");

        // --- Embedded relay (Ruta C) ---
        // If nobody injected a shared instance (Fase 4 not wired yet), create+own+start our own —
        // same pattern as _fcm/_udp below. See the constructor XML doc.
        if (_relay == null)
        {
            _ownsRelay = true;
            _relay = new RelayServer(_loggerFactory.CreateLogger<RelayServer>(), ResolveRelayKeyForDevice);
        }
        _relay.FcmTokenUpdateReceived += OnRelayFcmTokenUpdateReceived;
        if (!_relay.IsRunning)
        {
            try
            {
                await _relay.StartAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Relay server failed to start — Ruta C (push auth via relay) unavailable: {Msg}", ex.Message);
            }
        }

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

        // 4. ADB Device Watcher — auto-configures "adb reverse" when a phone is plugged in
        try
        {
            _adbWatcher = new AdbDeviceWatcher(_loggerFactory.CreateLogger<AdbDeviceWatcher>());
            _adbWatcher.AdbReverseEstablished += OnAdbReverseEstablished;
            _adbWatcher.DeviceDisconnected += OnAdbDeviceDisconnected;
            _adbWatcher.Start();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "ADB Device Watcher failed to start: {Msg}", ex.Message);
        }

        _logger.LogInformation(
            "Transports active — BT: {BT}, TCP/USB: {TCP}, UDP: {UDP}, ADB-Auto: {ADB}, Relay: {Relay}",
            _bt != null && BluetoothServer.IsAvailable ? "YES" : "NO",
            _tcp != null ? "YES" : "NO",
            "YES",
            _adbWatcher != null ? "YES" : "NO",
            _relay.IsRunning ? "YES" : "NO");

        // Keep alive loop
        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(2000, stoppingToken);
        }

        _adbWatcher?.Stop();
        _bt?.Stop();
        _tcp?.Stop();
        _udp.StopListening();

        if (_relay != null)
        {
            _relay.FcmTokenUpdateReceived -= OnRelayFcmTokenUpdateReceived;
            if (_ownsRelay)
            {
                try { await _relay.StopAsync(); } catch { /* best effort on shutdown */ }
            }
        }

        _logger.LogInformation("WindowsGoodBye Auth Service stopped.");
    }

    /// <summary>
    /// Resolves a device_id (string GUID) to its <see cref="RelayKeyDerivation.DeriveRelayKey"/> for
    /// the relay's JWT validation middleware. Only used for the fallback <see cref="RelayServer"/>
    /// instance this class creates+owns when nobody injected a shared one (see <see cref="_ownsRelay"/>
    /// and the constructor XML doc) — as of Fase 4, production always has one injected via DI
    /// (<c>Program.cs</c>'s own copy of this exact lookup, see <see cref="RelayKeyResolver"/>), so this
    /// only matters for tests/callers that construct <see cref="AuthWorker"/> directly without DI.
    /// </summary>
    private byte[]? ResolveRelayKeyForDevice(string deviceIdStr) => RelayKeyResolver.Resolve(deviceIdStr, _logger);

    /// <summary>
    /// Fase 8 hook (persisted here in Fase 3 since <see cref="RelayServer"/> already raises the event —
    /// see docs/plan_push_auth_v2.md, "Rotación de FCM Token"): Android POSTed a rotated FCM token via
    /// the relay because no direct transport was available. Persist it and mark the token valid again.
    /// </summary>
    private void OnRelayFcmTokenUpdateReceived(string deviceIdStr, string newToken)
    {
        if (!Guid.TryParse(deviceIdStr, out var deviceId)) return;
        try
        {
            using var freshDb = new AppDatabase();
            var device = freshDb.Devices.Find(deviceId);
            if (device == null) return;

            device.FcmToken = newToken;
            device.FcmTokenValid = true;
            freshDb.SaveChanges();
            _logger.LogInformation("FCM token resynced via relay for {Name}", device.FriendlyName);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to persist relay-synced FCM token for {DeviceId}", deviceIdStr);
        }
    }

    // --- ADB auto-setup events ---

    private void OnAdbReverseEstablished()
    {
        _logger.LogInformation("ADB reverse established — sending auth discovery on TCP/USB");
        // Trigger device discovery so the phone (just plugged in) gets an auth challenge immediately
        _ = Task.Run(async () =>
        {
            // Small delay to let the TCP connection from the phone come through
            await Task.Delay(1500);
            await DiscoverDevicesAsync();
        });
    }

    private void OnAdbDeviceDisconnected()
    {
        _logger.LogInformation("ADB device disconnected — USB transport no longer available");
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

    /// <summary>
    /// Fire-and-forget helper that logs (instead of silently swallowing) exceptions from async handlers
    /// invoked from a synchronous event-handler context (<see cref="ProcessMessage"/> itself can't be
    /// async without changing the BT/TCP/UDP event signatures) — replaces the previous ".Wait()" blocking
    /// pattern (docs/plan_push_auth_v2.md, Fase 3 bonus fix) without losing error visibility.
    /// </summary>
    private void FireAndForget(Task task, string context)
    {
        _ = task.ContinueWith(t =>
            _logger.LogError(t.Exception, "Unhandled exception in {Context}", context),
            TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously);
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
                FireAndForget(HandlePairRequestAsync(message[Protocol.PairRequestPrefix.Length..], source, replyFunc), "HandlePairRequestAsync");
            }
            else if (message.StartsWith(Protocol.AuthAlivePrefix))
            {
                FireAndForget(HandleAuthAliveAsync(message[Protocol.AuthAlivePrefix.Length..], source, replyFunc), "HandleAuthAliveAsync");
            }
            else if (message.StartsWith(Protocol.AuthResponsePrefix))
            {
                HandleAuthResponse(message[Protocol.AuthResponsePrefix.Length..], source);
            }
            else if (message.StartsWith(Protocol.TokenUpdatePrefix))
            {
                FireAndForget(HandleTokenUpdateAsync(message[Protocol.TokenUpdatePrefix.Length..], source, replyFunc), "HandleTokenUpdateAsync");
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

    private async Task HandlePairRequestAsync(string payload, string source, Func<string, Task> replyFunc)
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
#pragma warning disable CS0618 // Pairing still uses the legacy CBC transport encryption — see PairingSession/Fase 10.
            decryptedData = CryptoUtils.DecryptAes(encryptedData, session.PairEncryptKey);
#pragma warning restore CS0618
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
#pragma warning disable CS0618
        var finishPayload = Convert.ToBase64String(
            CryptoUtils.EncryptAes(Encoding.UTF8.GetBytes(computerName), session.PairEncryptKey));
#pragma warning restore CS0618
        var finishMessage = Protocol.PairFinishPrefix + finishPayload;

        await replyFunc(finishMessage);

        _logger.LogInformation("Pairing completed with {Name}", friendlyName);
        session.Complete(friendlyName, modelName);
        PairingSession.Active = null;
    }

    private async Task HandleAuthAliveAsync(string payload, string source, Func<string, Task> replyFunc)
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

        // Only send an auth challenge if the credential provider is actively waiting
        // (i.e., the PC is locked). This prevents premature biometric prompts.
        if (!IsAuthWaiting)
        {
            _logger.LogDebug("Device {Name} alive but PC not locked — skipping challenge", device.FriendlyName);
            return;
        }

        // Send auth challenge: nonce encrypted with device key
        var nonce = CryptoUtils.GenerateNonce(32);

        // Store the pending challenge
        PendingAuthChallenges.Add(deviceId, nonce);

        // Build challenge: [32 bytes nonce] - encrypted with deviceKey for transport
#pragma warning disable CS0618 // Legacy direct-transport challenge — unrelated to the GCM push-auth nonce (Ruta C).
        var encryptedNonce = CryptoUtils.EncryptAes(nonce, device.DeviceKey);
#pragma warning restore CS0618
        var challengePayload = Convert.ToBase64String(
            deviceIdBytes.Concat(encryptedNonce).ToArray());

        var challengeMessage = Protocol.AuthRequestPrefix + challengePayload;
        await replyFunc(challengeMessage);

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

        // Verify HMAC: HMAC-SHA256(nonce, authKey) — legacy direct-transport AuthKey (DeviceInfo.AuthKey),
        // NOT RelayKeyDerivation.DeriveAuthKey — see the naming-collision warning on RelayKeyDerivation.
        if (!CryptoUtils.VerifyHmac(expectedNonce, device.AuthKey, hmacBytes))
        {
            _logger.LogWarning("Auth HMAC verification failed for device {Name}", device.FriendlyName);
            return;
        }

        _logger.LogInformation("Device {Name} authenticated successfully via {Source}!", device.FriendlyName, source);
        PendingAuthChallenges.Remove(deviceId);

        device.LastAuthAt = DateTime.UtcNow;
        _db!.AuthRecords.Add(new AuthRecord
        {
            DeviceId = deviceId,
            Timestamp = DateTime.UtcNow,
            IpAddress = source
        });
        _db.SaveChanges();

        CompleteAuthentication(deviceId, "direct-transport (Ruta A/B)");
    }

    /// <summary>
    /// Handle an Android-originated <c>wingb://token_update</c> message (Fase 8 wire-up — see
    /// docs/plan_push_auth_v2.md, "Rotación de FCM Token"): sent over a direct transport when the FCM
    /// registration token rotated. Payload: <c>deviceIdBytes ‖ EncryptGcmToBlob(UTF8(newToken), DeviceKey, aad: deviceIdBytes)</c>.
    /// Symmetric counterpart lives in Android's <c>AuthListener.SendTokenUpdateAsync</c>.
    /// On success, replies with <see cref="Protocol.TokenUpdateAckPrefix"/> over the SAME transport the
    /// update arrived on — Android's <c>AuthListener</c> handles that to know the PC actually persisted
    /// the new token (as opposed to the message getting lost in transit).
    /// </summary>
    private async Task HandleTokenUpdateAsync(string payload, string source, Func<string, Task> replyFunc)
    {
        try
        {
            var rawBytes = Convert.FromBase64String(payload);
            if (rawBytes.Length <= Protocol.GuidLength) return;

            var deviceIdBytes = new byte[Protocol.GuidLength];
            Array.Copy(rawBytes, deviceIdBytes, Protocol.GuidLength);
            var deviceId = new Guid(deviceIdBytes);

            var device = _db?.Devices.Find(deviceId);
            if (device == null || !device.Enabled) return;

            var blob = new byte[rawBytes.Length - Protocol.GuidLength];
            Array.Copy(rawBytes, Protocol.GuidLength, blob, 0, blob.Length);

            var tokenBytes = CryptoUtils.DecryptGcmFromBlob(blob, device.DeviceKey, aad: deviceIdBytes);
            var newToken = Encoding.UTF8.GetString(tokenBytes);

            device.FcmToken = newToken;
            device.FcmTokenValid = true;
            _db!.SaveChanges();
            _logger.LogInformation("FCM token resynced via direct transport ({Source}) for {Name}", source, device.FriendlyName);

            var ackMessage = Protocol.TokenUpdateAckPrefix + Convert.ToBase64String(deviceIdBytes);
            await replyFunc(ackMessage);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to process token_update from {Source}", source);
        }
    }

    /// <summary>
    /// Shared "we now have proof of possession, unlock the PC" tail — used by both the legacy
    /// direct-transport flow (<see cref="HandleAuthResponse"/>) and push-auth (<see cref="TryPushAuthAsync"/>).
    /// </summary>
    private void CompleteAuthentication(Guid deviceId, string routeLabel)
    {
        _pushFatigue.Reset(); // successful unlock ends this "CP login session" for fatigue-tracking purposes.

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
                _logger.LogInformation("Auth signal sent to credential provider via {Route}", routeLabel);

                // Auto-reset after 10 seconds if no one consumed the auth
                // (safety net — PipeServer resets immediately on consumption)
                Task.Run(async () =>
                {
                    await Task.Delay(10000);
                    if (AuthenticatedPassword != null)
                    {
                        _logger.LogDebug("Auth result expired (not consumed within 10s)");
                        AuthenticatedPassword = null;
                        AuthEvent.Reset();
                    }
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
    }

    /// <summary>
    /// Convert the legacy blocking <see cref="AuthEvent"/> (a <see cref="ManualResetEventSlim"/>, set by
    /// <see cref="HandleAuthResponse"/> on ANY direct-transport reply — i.e. it's the unified completion
    /// signal for Ruta A and Ruta B, since Ruta B just wakes the phone to reconnect over Ruta A) into an
    /// awaitable <see cref="Task"/> without blocking a thread pool thread — this is the ".Wait() síncrono"
    /// fix called out in docs/plan_push_auth_v2.md, Fase 3. Uses the standard
    /// <see cref="ThreadPool.RegisterWaitForSingleObject"/> WaitHandle-to-Task bridge.
    /// </summary>
    private static Task<bool> WaitOneAsync(WaitHandle handle, TimeSpan timeout, CancellationToken ct)
    {
        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        var registeredHandle = ThreadPool.RegisterWaitForSingleObject(
            handle,
            (state, timedOut) => ((TaskCompletionSource<bool>)state!).TrySetResult(!timedOut),
            tcs,
            timeout,
            executeOnlyOnce: true);

        var ctRegistration = ct.Register(() => tcs.TrySetCanceled(ct));

        return AwaitAndCleanupAsync(tcs.Task, registeredHandle, ctRegistration);

        static async Task<bool> AwaitAndCleanupAsync(
            Task<bool> inner, RegisteredWaitHandle registered, CancellationTokenRegistration registration)
        {
            try
            {
                return await inner;
            }
            finally
            {
                registered.Unregister(null);
                registration.Dispose();
            }
        }
    }

    /// <summary>Ruta A/B leg of the race: wait for the legacy direct-transport auth signal.</summary>
    private async Task<AuthRaceOutcome> WaitForLegacyAuthAsync(CancellationToken ct)
    {
        try
        {
            var signaled = await WaitOneAsync(AuthEvent.WaitHandle, GlobalRaceTimeout, ct);
            return new AuthRaceOutcome(signaled, Route: "A/B");
        }
        catch (OperationCanceledException)
        {
            return new AuthRaceOutcome(false, Route: "A/B");
        }
    }

    /// <summary>
    /// Fase 12 (TrayApp Config UI, docs/plan_push_auth_v2.md) hook: called by <see cref="AdminPipeServer"/>
    /// when it receives <see cref="Protocol.AdminCmd_SetPushAuth"/>. Writes through THIS instance's own
    /// long-lived <see cref="_db"/> — the SAME <see cref="AppDatabase"/> context <see cref="RunAuthRaceAsync"/>
    /// queries devices from — rather than opening a fresh <see cref="AppDatabase"/> (the pattern used
    /// elsewhere for concurrency, e.g. <see cref="OnRelayFcmTokenUpdateReceived"/>). This is deliberate:
    /// EF Core's change tracker returns the SAME already-tracked <see cref="DeviceInfo"/> instance on
    /// every subsequent <c>_db.Devices.Where(...)</c> query without refreshing its scalar properties
    /// from the database — so a write made through a DIFFERENT DbContext/connection (e.g. the TrayApp's
    /// own <see cref="AppDatabase"/>) would silently not be picked up by <see cref="RunAuthRaceAsync"/>'s
    /// <c>d.PushAuthEnabled</c> check until the Service restarts. Writing through <c>_db</c> directly
    /// sidesteps that gap entirely — the very next auth race cycle sees the new value.
    /// </summary>
    /// <returns>False if the Service hasn't finished starting up yet (<c>_db</c> not initialized) or the
    /// device_id doesn't exist — the caller (<see cref="AdminPipeServer"/>) falls back to a fresh
    /// <see cref="AppDatabase"/> write in the former case.</returns>
    internal bool SetDevicePushAuthEnabled(Guid deviceId, bool enabled)
    {
        if (_db == null) return false;

        var device = _db.Devices.Find(deviceId);
        if (device == null) return false;

        device.PushAuthEnabled = enabled;
        _db.SaveChanges();
        _logger.LogInformation("Push Auth {State} for {Name} via TrayApp", enabled ? "enabled" : "disabled", device.FriendlyName);
        return true;
    }

    /// <summary>
    /// Same rationale as <see cref="SetDevicePushAuthEnabled"/>: called by <see cref="AdminPipeServer"/>
    /// on <see cref="Protocol.AdminCmd_SetDeviceEnabled"/> so the TrayApp's "Manage Devices" Enable/Disable
    /// toggle writes through THIS instance's own long-lived <see cref="_db"/> instead of the TrayApp's own
    /// <see cref="AppDatabase"/> — otherwise <see cref="RunAuthRaceAsync"/>'s <c>d.Enabled</c> filter would
    /// keep using the stale tracked value until the Service restarts.
    /// </summary>
    /// <returns>False if the Service hasn't finished starting up yet (<c>_db</c> not initialized) or the
    /// device_id doesn't exist — the caller (<see cref="AdminPipeServer"/>) falls back to a fresh
    /// <see cref="AppDatabase"/> write in the former case.</returns>
    internal bool SetDeviceEnabled(Guid deviceId, bool enabled)
    {
        if (_db == null) return false;

        var device = _db.Devices.Find(deviceId);
        if (device == null) return false;

        device.Enabled = enabled;
        _db.SaveChanges();
        _logger.LogInformation("Device {Name} {State} via TrayApp", device.FriendlyName, enabled ? "enabled" : "disabled");
        return true;
    }

    /// <summary>
    /// Same rationale as <see cref="SetDevicePushAuthEnabled"/>: called by <see cref="AdminPipeServer"/>
    /// on <see cref="Protocol.AdminCmd_DeleteDevice"/> so the TrayApp's "Manage Devices" delete action
    /// removes the row from THIS instance's own long-lived <see cref="_db"/> — otherwise
    /// <see cref="RunAuthRaceAsync"/>'s already-tracked <see cref="DeviceInfo"/> would keep being
    /// returned by <c>_db.Devices.Where(...)</c> (and could still be used to authenticate) until the
    /// Service restarts, even though the row was already gone from the database.
    /// </summary>
    /// <returns>False if the Service hasn't finished starting up yet (<c>_db</c> not initialized) or the
    /// device_id doesn't exist — the caller (<see cref="AdminPipeServer"/>) falls back to a fresh
    /// <see cref="AppDatabase"/> write in the former case.</returns>
    internal bool DeleteDevice(Guid deviceId)
    {
        if (_db == null) return false;

        var device = _db.Devices.Find(deviceId);
        if (device == null) return false;

        _db.Devices.Remove(device);
        _db.SaveChanges();
        _logger.LogInformation("Device {Name} deleted via TrayApp", device.FriendlyName);
        return true;
    }

    /// <summary>True if at least one BT or TCP/USB client currently has an open connection.</summary>
    internal bool HasActiveDirectTransport =>
        (_bt?.HasActiveConnections ?? false) || (_tcp?.HasActiveConnections ?? false);

    /// <summary>
    /// Entry point for a full authentication attempt cycle, called once per CP "WAITING" request.
    /// Implements docs/plan_push_auth_v2.md, "🔄 Algoritmo de Decisión del Modo Hybrid":
    /// <list type="number">
    /// <item><description>SIEMPRE lanza Ruta A (direct transports) — the existing discovery broadcast.</description></item>
    /// <item><description>SI tunnel.IsConnected: también lanza Ruta C (push-auth challenge vía relay) por cada
    /// dispositivo habilitado con PushAuthEnabled+FcmTokenValid+token.</description></item>
    /// <item><description>SI tunnel.IsConnected Y NO hay transporte directo activo: también lanza Ruta B (FCM
    /// wake-up legacy) — ambas rutas de FCM se gatean por "tunnel.IsConnected" porque eso es, en la
    /// práctica, el oráculo de "¿tengo internet en esta PC?" (FCM necesita salir a Google, no solo el
    /// relay necesita el túnel) — ver docs/plan_push_auth_v2.md, "Oráculo de disponibilidad".</description></item>
    /// <item><description>Primero en tener éxito gana (<see cref="AuthRaceCombinator"/>); todo lo demás se cancela
    /// vía el token de cancelación enlazado.</description></item>
    /// <item><description>Timeout global configurable (<see cref="GlobalRaceTimeout"/>, default 60s).</description></item>
    /// </list>
    /// The push-fatigue guard (<see cref="PushFatigueGuard"/>) gates the WHOLE cycle up front — per the
    /// plan, it "debe aplicar incluso si Ruta A/B ... es la que dispara los intentos, no solo Ruta C",
    /// because any route ends up pinging the phone for a biometric/number-matching prompt.
    /// </summary>
    public async Task<AuthRaceOutcome> RunAuthRaceAsync(Func<string, Task>? onStatus, CancellationToken ct)
    {
        if (_db == null) return new AuthRaceOutcome(false);

        var devices = _db.Devices.Where(d => d.Enabled).ToList();
        if (devices.Count == 0) return new AuthRaceOutcome(false);

        var decision = _pushFatigue.TryRecordChallenge(DateTimeOffset.UtcNow);
        if (!decision.IsAllowed)
        {
            _logger.LogWarning("Push-fatigue guard blocked a new auth attempt: {Reason} (retry after {RetryAfter})",
                decision.DenyReason, decision.RetryAfter);
            await SafeStatusAsync(onStatus, $"blocked:{decision.DenyReason}");
            return new AuthRaceOutcome(false);
        }

        await SafeStatusAsync(onStatus, "searching");

        using var raceCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        raceCts.CancelAfter(GlobalRaceTimeout);

        // Ruta A: ALWAYS — direct-transport discovery broadcast (existing helper). Does not itself
        // send the legacy FCM wake — that's gated separately below as Ruta B.
        await DiscoverDevicesAsync(sendFcmWake: false);

        var legs = new List<Task<AuthRaceOutcome>> { WaitForLegacyAuthAsync(raceCts.Token) };

        var tunnelConnected = _tunnelStatus.IsConnected;
        var hasDirectTransport = HasActiveDirectTransport;

        // Generate ONE display_code/attempt-number pair for this whole cycle — the user compares the
        // SAME code on the PC tile and on whichever phone(s) receive a Ruta C challenge.
        var displayCode = GenerateDisplayCode();
        var pushSentTo = new List<string>();

        if (tunnelConnected)
        {
            // Fase 12 (TrayApp Config UI): d.PushAuthEnabled is the user-facing toggle set via the
            // TrayApp's "Push Auth" menu (AdminPipeServer -> AuthWorker.SetDevicePushAuthEnabled) —
            // already gated here since Fase 3 alongside the purely-technical FcmTokenValid check, so
            // Ruta C respects the user's preference independently of whether the token happens to work.
            foreach (var device in devices.Where(d =>
                         d.PushAuthEnabled && d.FcmTokenValid && !string.IsNullOrEmpty(d.FcmToken)))
            {
                legs.Add(TryPushAuthAsync(device, displayCode, decision.AttemptNumber, onStatus, raceCts.Token));
                pushSentTo.Add(device.FriendlyName);
            }

            if (!hasDirectTransport)
            {
                foreach (var device in devices.Where(d => d.FcmTokenValid && !string.IsNullOrEmpty(d.FcmToken)))
                {
                    _ = SendLegacyFcmWakeAsync(device);
                }
            }
        }

        if (pushSentTo.Count > 0)
        {
            await SafeStatusAsync(onStatus, $"push_sent:{string.Join(", ", pushSentTo)}");
            await SafeStatusAsync(onStatus, $"code:{displayCode}");
        }

        var outcome = await AuthRaceCombinator.RunAsync(legs);

        if (!outcome.Success)
            await SafeStatusAsync(onStatus, "timeout");

        return outcome;
    }

    private static async Task SafeStatusAsync(Func<string, Task>? onStatus, string status)
    {
        if (onStatus == null) return;
        try { await onStatus(status); }
        catch { /* pipe may already be gone — never let a status update break the race */ }
    }

    private async Task SendLegacyFcmWakeAsync(DeviceInfo device)
    {
        if (_fcm?.IsAvailable != true || string.IsNullOrEmpty(device.FcmToken)) return;
        try
        {
            var result = await _fcm.SendAuthWakeAsync(device.FcmToken!, Environment.MachineName);
            HandleFcmSendResult(device, result);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Legacy FCM wake failed for {Name}", device.FriendlyName);
        }
    }

    /// <summary>
    /// Ruta C leg: generate a push-auth challenge, register it with the embedded relay, send it via
    /// FCM, and wait for Android's response — see docs/plan_push_auth_v2.md, "📨 Flujo Completo de
    /// Seguridad (Versión Final)".
    /// </summary>
    private async Task<AuthRaceOutcome> TryPushAuthAsync(
        DeviceInfo device, string displayCode, int attemptNumber, Func<string, Task>? onStatus, CancellationToken ct)
    {
        if (_relay == null || _fcm?.IsAvailable != true || string.IsNullOrEmpty(device.FcmToken))
            return new AuthRaceOutcome(false, Route: "C");

        var sessionId = Guid.NewGuid().ToString("n");
        var nonce = CryptoUtils.GenerateNonce(32);
        var challengeTimestamp = DateTimeOffset.UtcNow;
        var sessionIdBytes = Encoding.UTF8.GetBytes(sessionId);

        var session = _relay.RegisterSessionDirect(
            sessionId, device.DeviceId, nonce, displayCode, attemptNumber, ttl: TimeSpan.FromSeconds(60));

        try
        {
            var encryptedNonceBlob = CryptoUtils.EncryptGcmToBlob(nonce, device.DeviceKey, aad: sessionIdBytes);

            var sendResult = await _fcm.SendAuthChallengeAsync(
                device.FcmToken!,
                sessionId,
                device.DeviceId.ToString(),
                encryptedNonceBlob,
                challengeTimestamp,
                Environment.MachineName,
                device.RelayUrl,
                displayCode,
                attemptNumber);

            HandleFcmSendResult(device, sendResult);

            if (sendResult != FcmSendResult.Success)
                return new AuthRaceOutcome(false, Route: "C");

            var outcome = await _relay.WaitForResponseDirectAsync(sessionId, ct);

            switch (outcome.Status)
            {
                case PushAuthOutcomeStatus.Ok:
                    if (!VerifyPushAuthResponse(device, session, outcome))
                    {
                        _logger.LogWarning("Push-auth HMAC/timestamp verification failed for {Name} (session {Sid})",
                            device.FriendlyName, sessionId);
                        return new AuthRaceOutcome(false, Route: "C");
                    }

                    device.LastAuthAt = DateTime.UtcNow;
                    _db!.AuthRecords.Add(new AuthRecord
                    {
                        DeviceId = device.DeviceId,
                        Timestamp = DateTime.UtcNow,
                        IpAddress = "relay"
                    });
                    _db.SaveChanges();

                    CompleteAuthentication(device.DeviceId, "push-auth (Ruta C, relay)");
                    return new AuthRaceOutcome(true, device.FriendlyName, "C");

                case PushAuthOutcomeStatus.Rejected:
                    _logger.LogInformation("Push-auth explicitly rejected by {Name}: {Reason}",
                        device.FriendlyName, outcome.RejectReason ?? "(no reason)");
                    return new AuthRaceOutcome(false, Route: "C");

                default:
                    return new AuthRaceOutcome(false, Route: "C");
            }
        }
        finally
        {
            // If another leg (Ruta A/B) won first, make sure a late Android response can't resolve a
            // session nobody is waiting on anymore.
            _relay.RemoveSession(sessionId);
        }
    }

    private void HandleFcmSendResult(DeviceInfo device, FcmSendResult result)
    {
        if (result != FcmSendResult.TokenInvalid) return;

        // See docs/plan_push_auth_v2.md, "FCM: Manejo de Fallos" (Fisura #5): stop attempting push
        // sends to this token until a fresh one is synced (direct transport or relay /device/token).
        device.FcmTokenValid = false;
        try { _db!.SaveChanges(); }
        catch (Exception ex) { _logger.LogWarning(ex, "Failed to persist FcmTokenValid=false for {Name}", device.FriendlyName); }
        _logger.LogWarning("FCM token invalid/unregistered for {Name} — disabling push until resync", device.FriendlyName);
    }

    /// <summary>
    /// Verify Android's push-auth response per docs/plan_push_auth_v2.md, "Anti-Replay-Delay:
    /// Timestamp Firmado": HMAC over <c>nonce ‖ challenge_ts ‖ response_ts ‖ session_id</c> with
    /// <c>AuthKey = HKDF(DeviceKey, "auth-hmac")</c> (<see cref="RelayKeyDerivation.DeriveAuthKey"/> —
    /// NEVER <see cref="DeviceInfo.AuthKey"/>, see that class's naming-collision warning), plus the two
    /// timestamp windows.
    /// </summary>
    internal bool VerifyPushAuthResponse(DeviceInfo device, PushAuthSession session, PushAuthOutcome outcome)
    {
        if (outcome.Hmac == null || outcome.ResponseTimestamp == null) return false;

        var authKey = RelayKeyDerivation.DeriveAuthKey(device.DeviceKey);
        return VerifyPushAuthResponseCore(
            session.Nonce, authKey, session.ChallengeTimestamp,
            DateTimeOffset.FromUnixTimeSeconds(outcome.ResponseTimestamp.Value),
            DateTimeOffset.UtcNow, session.SessionId, outcome.Hmac);
    }

    /// <summary>
    /// Pure, dependency-free core of <see cref="VerifyPushAuthResponse"/> — factored out specifically so
    /// it's unit-testable without a live <see cref="RelayServer"/>/<see cref="AppDatabase"/>. Encodes
    /// timestamps as 8-byte big-endian Unix-seconds longs; <paramref name="sessionId"/> as UTF-8 —
    /// Android's <c>PushAuthActivity</c> (Fase 6) MUST build the identical byte layout when signing.
    /// </summary>
    public static bool VerifyPushAuthResponseCore(
        byte[] nonce, byte[] authKey, DateTimeOffset challengeTimestamp, DateTimeOffset responseTimestamp,
        DateTimeOffset now, string sessionId, string hmacBase64)
    {
        // "response_timestamp - challenge_timestamp < 60 segundos"
        if (responseTimestamp < challengeTimestamp || responseTimestamp - challengeTimestamp > TimeSpan.FromSeconds(60))
            return false;

        // "now() - response_timestamp < 10 segundos" — anti-replay-delay. A small forward-clock-skew
        // allowance (5s) avoids rejecting a legitimate response due to minor PC/phone clock drift; see
        // the plan's operational note on clock skew (don't widen this blindly).
        var age = now - responseTimestamp;
        if (age > TimeSpan.FromSeconds(10) || age < TimeSpan.FromSeconds(-5))
            return false;

        byte[] expectedHmac;
        try { expectedHmac = Convert.FromBase64String(hmacBase64); }
        catch (FormatException) { return false; }

        var payload = BuildHmacPayload(nonce, challengeTimestamp, responseTimestamp, sessionId);
        var computed = CryptoUtils.ComputeHmac(payload, authKey);
        return CryptographicOperations.FixedTimeEquals(computed, expectedHmac);
    }

    /// <summary>
    /// <c>nonce ‖ challenge_ts ‖ response_ts ‖ session_id</c> (timestamps as 8-byte big-endian Unix
    /// seconds). Thin wrapper kept here (public static, same signature) for the existing test suite
    /// (<c>AuthWorkerHmacVerificationTests</c>) — the actual byte layout now lives in
    /// <see cref="PushAuthHmac.BuildPayload"/> (promoted to <c>WindowsGoodBye.Core</c> in Fase 6) so
    /// Android's <c>PushAuthActivity</c> can call the EXACT same code when signing, instead of a
    /// separate hand-written reimplementation that could silently drift from this one.
    /// </summary>
    public static byte[] BuildHmacPayload(byte[] nonce, DateTimeOffset challengeTs, DateTimeOffset responseTs, string sessionId) =>
        PushAuthHmac.BuildPayload(nonce, challengeTs, responseTs, sessionId);

    /// <summary>Two-digit number-matching code (push fatigue defense) — not a secret, purely a UX control.</summary>
    private static string GenerateDisplayCode() => RandomNumberGenerator.GetInt32(0, 100).ToString("D2");

    /// <summary>
    /// Send auth discovery to all known devices on ALL active transports (Ruta A).
    /// </summary>
    /// <param name="sendFcmWake">
    /// Whether to also fire the legacy FCM wake-up (Ruta B) unconditionally for devices with a token.
    /// <see cref="RunAuthRaceAsync"/> passes <c>false</c> and handles Ruta B's gating itself (per the
    /// hybrid-mode algorithm); other callers (e.g. <see cref="OnAdbReverseEstablished"/>) keep the
    /// original unconditional behavior by leaving this at its default.
    /// </param>
    public async Task DiscoverDevicesAsync(bool sendFcmWake = true)
    {
        if (_db == null) return;

        var devices = _db.Devices.Where(d => d.Enabled).ToList();
        foreach (var device in devices)
        {
            var payload = Convert.ToBase64String(device.DeviceId.ToByteArray());
            var message = Protocol.AuthDiscoverPrefix + payload;
            await SendOnAllTransportsAsync(message, device.LastIpAddress);

            // Also try FCM push to wake the device (in case all transports are down)
            if (sendFcmWake && _fcm?.IsAvailable == true && !string.IsNullOrEmpty(device.FcmToken))
            {
                _logger.LogDebug("Sending FCM wake push to {Name}", device.FriendlyName);
                _ = SendLegacyFcmWakeAsync(device);
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
