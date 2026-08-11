namespace WindowsGoodBye.Core;

/// <summary>
/// Protocol constants shared between Windows and Android clients.
/// Communication channels (in priority order): Bluetooth RFCOMM, TCP/USB, UDP WiFi.
/// </summary>
public static class Protocol
{
    // --- Network (WiFi/UDP) ---
    public const string MulticastGroup = "225.67.76.67";
    public const int MulticastPort = 26817;
    public const int UnicastPort = 26818;
    public const int PipePort = 26819; // TCP for named pipe alternative
    public const int MaxPacketSize = 4096;

    // --- Bluetooth RFCOMM ---
    /// <summary>Custom UUID for the WindowsGoodBye Bluetooth service.</summary>
    public const string BluetoothServiceUuid = "a1b2c3d4-e5f6-7890-abcd-1234567890ab";
    /// <summary>SDP service name advertised by the Windows side.</summary>
    public const string BluetoothServiceName = "WindowsGoodBye";

    // --- TCP/USB (ADB port forwarding) ---
    /// <summary>TCP port for localhost communication via ADB USB forwarding.</summary>
    public const int TcpUsbPort = 26820;

    // --- Relay HTTP Server (embedded in the Service, exposed via Cloudflare Tunnel) ---
    /// <summary>
    /// Loopback-only port for the embedded push-auth relay (ASP.NET Kestrel). See
    /// docs/plan_push_auth_v2.md, section "Relay HTTP Server Embebido — Diseño".
    /// </summary>
    public const int RelayPort = 26821;

    // --- Transport Types ---
    public enum TransportType { Udp, Bluetooth, TcpUsb }

    // --- Message Prefixes ---
    public const string PairQrPrefix = "wingb://pair?";
    public const string PairRequestPrefix = "wingb://pair_req?";
    public const string PairFinishPrefix = "wingb://pair_finish?";
    public const string PairTerminatePrefix = "wingb://pair_terminate";

    public const string AuthDiscoverPrefix = "wingb://auth_discover?";
    public const string AuthAlivePrefix = "wingb://auth_alive?";
    public const string AuthRequestPrefix = "wingb://auth_req?";
    public const string AuthResponsePrefix = "wingb://auth_resp?";

    /// <summary>
    /// Direct-transport (BT/TCP/UDP) message: Android → PC, sent when the FCM registration token
    /// rotated and a direct transport is available (avoids the relay round-trip).
    /// Format: "wingb://token_update?device_id={base64 guid}&amp;token={new FCM token}" (payload
    /// itself is AES-256-GCM encrypted with DeviceKey — see "Rotación de FCM Token" in the plan).
    /// Named "TokenUpdate" in docs/plan_push_auth_v2.md.
    /// </summary>
    public const string TokenUpdatePrefix = "wingb://token_update?";

    /// <summary>
    /// Direct-transport (BT/TCP/UDP) message: PC → Android, sent immediately after the PC successfully
    /// processes a <see cref="TokenUpdatePrefix"/> message — Fase 8 (docs/plan_push_auth_v2.md,
    /// "🔄 Rotación de FCM Token"). Format: "wingb://token_update_ack?{base64 guid device_id}" (not
    /// encrypted — it carries no secret, just an acknowledgement correlated by device_id). There is no
    /// equivalent ack for the relay path (<c>POST /api/device/token</c>): the HTTP response itself
    /// (200 OK) already serves as the acknowledgement there — see <c>HttpRelayClient.UpdateFcmTokenAsync</c>.
    /// </summary>
    public const string TokenUpdateAckPrefix = "wingb://token_update_ack?";

    // --- FCM Push Auth (data message "action" field values) ---
    // These are the values carried in the FCM data payload's "action" key, not wingb:// prefixes,
    // because FCM is a one-way (PC -> Android) wake-up/data channel — see "Arquitectura Final".

    /// <summary>Legacy FCM wake-up action: tells Android to reconnect over a direct transport.</summary>
    public const string FcmActionAuthWake = "auth_wake";

    /// <summary>
    /// FCM data message action: full push-auth challenge (Ruta C). Payload includes
    /// session_id, encrypted_nonce (AES-256-GCM blob), challenge_ts, pc_name, relay_url and the
    /// number-matching display_code. See "Flujo Completo de Seguridad" / "Defensa contra Push Fatigue".
    /// </summary>
    public const string PushAuthChallenge = "auth_challenge";

    /// <summary>
    /// Discriminator for a push-auth response/result as carried through relay-related payloads
    /// (Android's POST /api/auth/respond body, and any status echoed back to the PC).
    /// Not sent over FCM — Android replies to the relay over HTTPS, never back over FCM.
    /// </summary>
    public const string PushAuthResponse = "auth_response";

    // --- Pairing QR Payload Layout ---
    // [16 bytes DeviceId (GUID)] [32 bytes DeviceKey] [32 bytes AuthKey] [32 bytes PairEncryptKey]
    public const int GuidLength = 16;
    public const int KeyLength = 32;
    public const int PairPayloadLength = GuidLength + KeyLength + KeyLength + KeyLength; // 112 bytes

    // --- Auth Challenge Layout ---
    // [1 byte nonceLen] [nonceLen bytes nonce] [32 bytes deviceId]
    // Auth Response Layout:
    // [32 bytes deviceId] [32 bytes HMAC-SHA256(nonce, authKey)]

    // --- Named Pipe (Credential Provider <-> Service) ---
    public const string PipeName = "WindowsGoodByeAuth";
    // Pipe commands:
    public const string PipeCmd_AuthReady = "AUTH_READY";    // Service -> CredProvider: auth succeeded, password follows
    public const string PipeCmd_Waiting = "WAITING";          // CredProvider -> Service: waiting for auth
    public const string PipeCmd_Cancel = "CANCEL";            // CredProvider -> Service: user cancelled

    // --- Named Pipe (TrayApp <-> Service) ---
    /// <summary>Pipe used by TrayApp to send admin commands (pairing, etc.) to the Service.</summary>
    public const string AdminPipeName = "WindowsGoodByeAdmin";
    // Admin pipe commands (TrayApp → Service):
    public const string AdminCmd_PairStart = "PAIR_START";        // Start pairing session — followed by \n + base64(keys)
    public const string AdminCmd_PairCancel = "PAIR_CANCEL";      // Cancel active pairing

    /// <summary>
    /// Fase 12 (TrayApp Config UI, docs/plan_push_auth_v2.md): query the Service's current Cloudflare
    /// Tunnel public URL (its own live <c>ITunnelStatusProvider.PublicUrl</c>), for the pairing QR's
    /// <c>relay_url</c> segment. Only needed as a fallback when the TrayApp has no already-paired,
    /// enabled <see cref="DeviceInfo.RelayUrl"/> to read locally (e.g. the very first pairing ever) —
    /// see <c>TrayApplicationContext.ResolvePairingDefaults</c>. No payload. Response: <see cref="AdminResp_RelayStatus"/>.
    /// </summary>
    public const string AdminCmd_GetRelayStatus = "GET_RELAY_STATUS";

    /// <summary>
    /// Fase 12: update a paired device's <see cref="DeviceInfo.PushAuthEnabled"/> preference.
    /// Format: <c>"SET_PUSH_AUTH\n{deviceId guid}\n{"1"|"0"}"</c>. The Service (not the TrayApp) performs
    /// the actual <c>AppDatabase</c> write — see <c>AuthWorker.SetDevicePushAuthEnabled</c> — specifically
    /// so the change lands on the SAME tracked <c>DeviceInfo</c> instance <c>AuthWorker.RunAuthRaceAsync</c>
    /// reads from, avoiding an EF Core identity-map staleness gap that a direct TrayApp-side DB write
    /// (a different DbContext/connection) would leave until the Service restarts. Response:
    /// <see cref="AdminResp_Ok"/> or <see cref="AdminResp_Error"/>.
    /// </summary>
    public const string AdminCmd_SetPushAuth = "SET_PUSH_AUTH";

    // Admin pipe responses (Service → TrayApp):
    public const string AdminResp_Ok = "OK";                      // Pairing session created / command applied
    public const string AdminResp_PairDone = "PAIR_DONE";         // Pairing complete — followed by \n + name \n + model
    public const string AdminResp_Error = "ERROR";                // Something failed — followed by \n + message

    /// <summary>Response to <see cref="AdminCmd_GetRelayStatus"/> — followed by \n + url (may be empty if no tunnel is connected).</summary>
    public const string AdminResp_RelayStatus = "RELAY_STATUS";
}
