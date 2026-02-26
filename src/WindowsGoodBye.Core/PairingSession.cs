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
    /// Format: wingb://pair?{base64}|{ip1},{ip2},...
    /// The IP addresses let the phone send a direct unicast instead of relying on multicast.</summary>
    public string GenerateQrData()
    {
        using var ms = new MemoryStream();
        ms.Write(DeviceId.ToByteArray());
        ms.Write(DeviceKey);
        ms.Write(AuthKey);
        ms.Write(PairEncryptKey);

        var qr = Protocol.PairQrPrefix + Convert.ToBase64String(ms.ToArray());

        // Append local IPv4 addresses so the phone can send unicast directly
        var ips = GetLocalIPv4Addresses();
        if (ips.Count > 0)
            qr += "|" + string.Join(",", ips);

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
