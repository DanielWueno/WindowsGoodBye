using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace WindowsGoodBye.Core;

/// <summary>Active pairing session state, shared between Service and TrayApp.</summary>
public class PairingSession
{
    public static PairingSession? Active { get; set; }

    public Guid DeviceId { get; }
    public byte[] DeviceKey { get; }
    public byte[] AuthKey { get; }
    public byte[] PairEncryptKey { get; }

    /// <summary>
    /// HKDF-derived relay authentication key (<c>RelayKeyDerivation.DeriveRelayKey(DeviceKey)</c>),
    /// computed on demand from <see cref="DeviceKey"/> — never persisted separately (see
    /// <see cref="RelayKeyDerivation"/>: it is fully determined by DeviceKey, so storing it would only
    /// duplicate secret material for no benefit). Exposed here (Fase 10,
    /// docs/plan_push_auth_v2.md) purely as a convenience for callers that already hold a
    /// PairingSession and need to reason about the relay identity of the device being paired
    /// (e.g. logging/diagnostics) without re-deriving it by hand.
    /// </summary>
    public byte[] RelayKey => RelayKeyDerivation.DeriveRelayKey(DeviceKey);

    /// <summary>
    /// HKDF-derived push-auth HMAC key (<c>RelayKeyDerivation.DeriveAuthKey(DeviceKey)</c>). NOT the
    /// same key as <see cref="AuthKey"/> above — that is an independently-random key used only for
    /// the legacy direct-transport (BT/TCP/UDP) HMAC challenge. See the naming-collision warning in
    /// <see cref="RelayKeyDerivation"/>. Named <c>PushAuthKey</c> here (rather than a second
    /// <c>AuthKey</c> overload) specifically to avoid resurrecting that collision.
    /// </summary>
    public byte[] PushAuthKey => RelayKeyDerivation.DeriveAuthKey(DeviceKey);

    private TaskCompletionSource<(string name, string model)>? _tcs;

    /// <summary>Create a new pairing session with freshly generated keys.</summary>
    public PairingSession()
    {
        DeviceId = Guid.NewGuid();
        DeviceKey = CryptoUtils.GenerateAesKey();
        AuthKey = CryptoUtils.GenerateAesKey();
        PairEncryptKey = CryptoUtils.GenerateAesKey();
        _tcs = new TaskCompletionSource<(string, string)>();
    }

    /// <summary>Reconstruct a pairing session from existing keys (used by Service via IPC).</summary>
    public PairingSession(Guid deviceId, byte[] deviceKey, byte[] authKey, byte[] pairEncryptKey)
    {
        DeviceId = deviceId;
        DeviceKey = deviceKey;
        AuthKey = authKey;
        PairEncryptKey = pairEncryptKey;
        _tcs = new TaskCompletionSource<(string, string)>();
    }

    /// <summary>Generate the QR code data string for pairing.
    /// Format: <c>wingb://pair?{base64}|{ip1,ip2,...}|{relayUrl}|{pushAuthEnabledDefault}</c>
    /// <list type="bullet">
    /// <item><description><c>{base64}</c>: the fixed 112-byte key blob (DeviceId ‖ DeviceKey ‖ AuthKey
    /// ‖ PairEncryptKey), unchanged from before Fase 10.</description></item>
    /// <item><description><c>ip1,ip2,...</c>: local IPv4 addresses, so the phone can send a direct
    /// unicast instead of relying on multicast. May be an empty segment.</description></item>
    /// <item><description><c>relayUrl</c>: this PC's current Cloudflare Tunnel URL for the embedded
    /// relay (Fase 2/4), <see cref="Uri.EscapeDataString(string)"/>-encoded. Empty when no tunnel is
    /// connected yet (e.g. <c>cloudflared</c> not installed, or still starting up) — Android falls
    /// back to learning it later from an "auth_challenge" FCM payload
    /// (<c>FcmService.TryUpdateRelayUrl</c>) or a future re-pair. <b>Callers must pass this in</b>
    /// (see <paramref name="relayUrl"/>) — <see cref="PairingSession"/> lives in
    /// <c>WindowsGoodBye.Core</c> and has no access to the Service's <c>TunnelManager</c>/
    /// <c>ITunnelStatusProvider</c> singleton, so it cannot look this up itself.</description></item>
    /// <item><description><c>pushAuthEnabledDefault</c>: <c>"1"</c>/<c>"0"</c>, seeding
    /// <c>PairedPc.PushAuthEnabled</c> on the Android side to match the PC's default policy for new
    /// devices (<see cref="DeviceInfo.PushAuthEnabled"/> also defaults to <c>true</c>). Purely an
    /// initial value — the user can flip it later from the TrayApp (Fase 12) or the Android
    /// app.</description></item>
    /// </list>
    /// <para>
    /// Both new segments are deliberately always present (even when empty) so segment position is
    /// unambiguous for the parser (<c>QrScanPage.ProcessQrCode</c>) — no version negotiation is
    /// needed since the PC and Android app are developed/deployed together in this repo (same
    /// no-dual-mode stance already taken for the CBC→GCM migration).
    /// </para>
    /// </summary>
    /// <param name="relayUrl">
    /// The Service's current public relay URL, or null/empty if no tunnel is connected right now.
    /// The caller (TrayApp) is expected to look this up — e.g. from <c>DeviceInfo.RelayUrl</c> of an
    /// already-paired, enabled device, since <c>TunnelHostedService</c> keeps that column in sync for
    /// all enabled devices whenever the tunnel URL changes.
    /// </param>
    /// <param name="pushAuthEnabledDefault">
    /// The PC's default Push Auth preference for newly paired devices. Defaults to <c>true</c>,
    /// matching <see cref="DeviceInfo.PushAuthEnabled"/>'s own default.
    /// </param>
    public string GenerateQrData(string? relayUrl = null, bool pushAuthEnabledDefault = true)
    {
        using var ms = new MemoryStream();
        ms.Write(DeviceId.ToByteArray());
        ms.Write(DeviceKey);
        ms.Write(AuthKey);
        ms.Write(PairEncryptKey);

        var qr = Protocol.PairQrPrefix + Convert.ToBase64String(ms.ToArray());

        // Append local IPv4 addresses so the phone can send unicast directly
        var ips = GetLocalIPv4Addresses();
        var relayUrlEncoded = string.IsNullOrEmpty(relayUrl) ? "" : Uri.EscapeDataString(relayUrl);
        qr += "|" + string.Join(",", ips)
            + "|" + relayUrlEncoded
            + "|" + (pushAuthEnabledDefault ? "1" : "0");

        return qr;
    }

    /// <summary>Get all non-loopback IPv4 addresses of active network interfaces.</summary>
    private static List<string> GetLocalIPv4Addresses()
    {
        var result = new List<string>();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType is NetworkInterfaceType.Loopback
                    or NetworkInterfaceType.Tunnel) continue;

                foreach (var addr in ni.GetIPProperties().UnicastAddresses)
                {
                    if (addr.Address.AddressFamily == AddressFamily.InterNetwork
                        && !IPAddress.IsLoopback(addr.Address))
                    {
                        result.Add(addr.Address.ToString());
                    }
                }
            }
        }
        catch { /* best-effort */ }
        return result;
    }

    /// <summary>Serialize just the key material (same layout as QR payload).</summary>
    public string SerializeKeys()
    {
        using var ms = new MemoryStream();
        ms.Write(DeviceId.ToByteArray());
        ms.Write(DeviceKey);
        ms.Write(AuthKey);
        ms.Write(PairEncryptKey);
        return Convert.ToBase64String(ms.ToArray());
    }

    /// <summary>Deserialize key material into a PairingSession.</summary>
    public static PairingSession FromSerializedKeys(string base64)
    {
        var payload = Convert.FromBase64String(base64);
        if (payload.Length != Protocol.PairPayloadLength)
            throw new ArgumentException("Invalid key payload length");

        int offset = 0;
        var deviceIdBytes = new byte[Protocol.GuidLength];
        Array.Copy(payload, offset, deviceIdBytes, 0, Protocol.GuidLength); offset += Protocol.GuidLength;

        var deviceKey = new byte[Protocol.KeyLength];
        Array.Copy(payload, offset, deviceKey, 0, Protocol.KeyLength); offset += Protocol.KeyLength;

        var authKey = new byte[Protocol.KeyLength];
        Array.Copy(payload, offset, authKey, 0, Protocol.KeyLength); offset += Protocol.KeyLength;

        var pairEncryptKey = new byte[Protocol.KeyLength];
        Array.Copy(payload, offset, pairEncryptKey, 0, Protocol.KeyLength);

        return new PairingSession(new Guid(deviceIdBytes), deviceKey, authKey, pairEncryptKey);
    }

    public void Complete(string friendlyName, string modelName)
    {
        _tcs?.TrySetResult((friendlyName, modelName));
    }

    public Task<(string name, string model)> WaitForCompletionAsync(CancellationToken ct = default)
    {
        ct.Register(() => _tcs?.TrySetCanceled());
        return _tcs!.Task;
    }
}
