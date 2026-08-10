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

    /// <summary>
    /// Whether <see cref="FcmToken"/> is currently known-good. Set to false when FCM reports the
    /// token as unregistered/invalid (e.g. HTTP 404 "UNREGISTERED" from the v1 API) — see
    /// docs/plan_push_auth_v2.md, "FCM: Manejo de Fallos" (Fisura #5). While false, the Service
    /// should not attempt push sends to this token and should rely on direct transports only, until
    /// a fresh token is synced (either via a direct-transport connection or the relay's
    /// <c>/api/device/token</c> endpoint).
    /// </summary>
    public bool FcmTokenValid { get; set; } = true;

    /// <summary>
    /// User/device preference for whether Push Auth (Ruta C — full challenge via the relay) may be
    /// attempted for this device, independent of whether the FCM token is technically valid. Set from
    /// the TrayApp toggle and synced during pairing; the Service must respect this even if
    /// <see cref="FcmTokenValid"/> is true. See docs/plan_push_auth_v2.md, decision #7 and Fase 12.
    /// </summary>
    public bool PushAuthEnabled { get; set; } = true;

    /// <summary>
    /// The Cloudflare Tunnel URL last shared with this device for reaching the embedded relay
    /// (e.g. "https://wingb-xxx.trycloudflare.com"). Recorded per-device so the Service can tell
    /// whether a given device still has the current tunnel URL, or needs it re-synced (relevant for
    /// Quick Tunnels, whose URL changes on every Service restart). See docs/plan_push_auth_v2.md,
    /// "Cloudflare Tunnel".
    /// </summary>
    public string? RelayUrl { get; set; }
}

/// <summary>
/// In-memory representation of a single push-auth (Ruta C) attempt, tracked by the Service while
/// waiting for Android's response. This is NOT persisted to <see cref="AppDatabase"/> — a push-auth
/// session is inherently ephemeral/short-lived (default 60s TTL) and must not survive a Service
/// restart, so it is plain state passed between <c>AuthWorker</c> and the embedded <c>RelayServer</c>
/// (see docs/plan_push_auth_v2.md, "Relay HTTP Server Embebido — Diseño").
/// </summary>
public class PushAuthSession
{
    /// <summary>Unique session identifier (GUID), generated per challenge attempt.</summary>
    public required string SessionId { get; init; }

    /// <summary>The paired device this challenge was sent to.</summary>
    public required Guid DeviceId { get; init; }

    /// <summary>Random nonce (32 bytes) that Android must decrypt and echo back proof of possession for.</summary>
    public required byte[] Nonce { get; init; }

    /// <summary>When the challenge was generated (used for the response_ts - challenge_ts anti-replay check).</summary>
    public DateTimeOffset ChallengeTimestamp { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// When this session stops accepting a response (default: 60s after <see cref="ChallengeTimestamp"/>).
    /// </summary>
    public DateTimeOffset ExpiresAt { get; init; }

    /// <summary>
    /// Two-digit number-matching code shown on both the PC tile and the phone prompt, so the user
    /// must consciously compare them before approving — see "Defensa contra Push Fatigue".
    /// Not a secret; purely a UX/anti-fatigue control.
    /// </summary>
    public required string DisplayCode { get; init; }

    /// <summary>How many push-auth challenges have been generated for this CP login session so far
    /// (including this one) — surfaced to the user as "3er intento en los últimos 2 minutos".</summary>
    public int AttemptNumber { get; init; } = 1;
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
