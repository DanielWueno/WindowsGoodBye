using System.ComponentModel.DataAnnotations;

namespace WindowsGoodBye.Core;

/// <summary>
/// Represents a paired Android device.
/// </summary>
public class DeviceInfo
{
    [Key]
    public Guid DeviceId { get; set; }

    /// <summary>Bluetooth/user-friendly name of the device (e.g. "John's Pixel").</summary>
    public string FriendlyName { get; set; } = "";

    /// <summary>Device model (e.g. "Pixel 7").</summary>
    public string ModelName { get; set; } = "";

    /// <summary>AES device key (32 bytes), used for device identification.</summary>
    public byte[] DeviceKey { get; set; } = Array.Empty<byte>();

    /// <summary>AES auth key (32 bytes), used for HMAC authentication challenges.</summary>
    public byte[] AuthKey { get; set; } = Array.Empty<byte>();

    /// <summary>Last known IP address of the device.</summary>
    public string? LastIpAddress { get; set; }

    /// <summary>MAC address of the device (if known).</summary>
    public string? MacAddress { get; set; }

    /// <summary>Whether this device is enabled for authentication.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>When the device was paired.</summary>
    public DateTime PairedAt { get; set; } = DateTime.UtcNow;

    /// <summary>Last successful authentication time.</summary>
    public DateTime? LastAuthAt { get; set; }

    /// <summary>Firebase Cloud Messaging token for push notifications (optional).</summary>
    public string? FcmToken { get; set; }
}

/// <summary>
/// Record of a successful authentication event.
/// </summary>
public class AuthRecord
{
    [Key]
    public int Id { get; set; }
    public Guid DeviceId { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string? IpAddress { get; set; }
}

/// <summary>
/// Stores the encrypted Windows credential for auto-unlock.
/// </summary>
public class StoredCredential
{
    [Key]
    public int Id { get; set; }

    /// <summary>Windows username.</summary>
    public string Username { get; set; } = "";

    /// <summary>Windows domain (or "." for local).</summary>
    public string Domain { get; set; } = ".";

    /// <summary>Encrypted password (DPAPI protected).</summary>
    public byte[] EncryptedPassword { get; set; } = Array.Empty<byte>();

    /// <summary>When the credential was last updated.</summary>
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
