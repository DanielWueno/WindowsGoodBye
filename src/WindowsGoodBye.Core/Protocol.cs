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
    // Admin pipe responses (Service → TrayApp):
    public const string AdminResp_Ok = "OK";                      // Pairing session created
    public const string AdminResp_PairDone = "PAIR_DONE";         // Pairing complete — followed by \n + name \n + model
    public const string AdminResp_Error = "ERROR";                // Something failed — followed by \n + message
}
