using Microsoft.EntityFrameworkCore;
#if ANDROID
using WindowsGoodBye.Mobile.Platforms.Android;
#endif

namespace WindowsGoodBye.Mobile.Data;

/// <summary>
/// Local database for storing paired PC information on the Android device.
/// Uses EF Core SQLite, stored in the app's private data directory.
/// </summary>
public class MobileDatabase : DbContext
{
    public DbSet<PairedPc> PairedPcs => Set<PairedPc>();
    public DbSet<AppSetting> Settings => Set<AppSetting>();

    private readonly string _dbPath;

    public MobileDatabase()
    {
        _dbPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "windowsgoodbye.db");
    }

    public MobileDatabase(string dbPath)
    {
        _dbPath = dbPath;
    }

    protected override void OnConfiguring(DbContextOptionsBuilder options)
    {
        options.UseSqlite($"Data Source={_dbPath}");
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<PairedPc>(e =>
        {
            e.HasKey(p => p.Id);
            e.Property(p => p.Id).ValueGeneratedOnAdd();
        });

        modelBuilder.Entity<AppSetting>(e =>
        {
            e.HasKey(s => s.Key);
        });
    }

    public void Initialize()
    {
        Database.EnsureCreated();
        MigrateSchema();
    }

    /// <summary>
    /// Lightweight schema migration, mirroring the pattern used by the PC-side AppDatabase:
    /// EnsureCreated() does not alter existing tables, so newly added columns are added manually.
    ///
    /// Push Auth v2 (docs/plan_push_auth_v2.md, Fase 1): PairedPc used to store the raw DeviceKey in
    /// plaintext (DeviceKeyBase64). It now stores only the AES-256-GCM-wrapped ciphertext + IV
    /// (envelope-encrypted with a non-exportable Android Keystore key — see SecureKeyStorage). Any
    /// pre-existing plaintext DeviceKeyBase64 column is left in place (unused, harmless) rather than
    /// migrated in-place: devices paired under the old CBC scheme must re-pair anyway (see
    /// CryptoUtils' migration notes), so there is no value in trying to re-wrap old key material.
    /// </summary>
    private void MigrateSchema()
    {
        var conn = Database.GetDbConnection();
        conn.Open();
        try
        {
            AddColumnIfMissing(conn, "PairedPcs", "DeviceKeyEncryptedBase64", "TEXT");
            AddColumnIfMissing(conn, "PairedPcs", "DeviceKeyIvBase64", "TEXT");

            // Fase 3/5 (push auth v2): learned opportunistically from an "auth_challenge" FCM payload
            // (see FcmService.cs) ahead of Fase 10 formally syncing it during pairing. Nullable — a
            // freshly paired device won't have one until either a challenge arrives or Fase 10 lands.
            AddColumnIfMissing(conn, "PairedPcs", "RelayUrl", "TEXT");
        }
        finally
        {
            conn.Close();
        }
    }

    private static void AddColumnIfMissing(
        System.Data.Common.DbConnection conn, string table, string column, string type)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"PRAGMA table_info({table})";
        using var reader = cmd.ExecuteReader();

        while (reader.Read())
        {
            if (string.Equals(reader.GetString(1), column, StringComparison.OrdinalIgnoreCase))
                return; // Column already exists
        }
        reader.Close();

        using var alter = conn.CreateCommand();
        alter.CommandText = $"ALTER TABLE {table} ADD COLUMN {column} {type}";
        alter.ExecuteNonQuery();
    }
}

/// <summary>
/// Represents a paired Windows PC.
/// </summary>
public class PairedPc
{
    public int Id { get; set; }

    /// <summary>Device ID (same GUID as on the PC side).</summary>
    public string DeviceId { get; set; } = "";

    /// <summary>
    /// AES-256-GCM-wrapped DeviceKey ciphertext (Base64) — envelope-encrypted with a non-exportable
    /// Android Keystore key (StrongBox-backed when available). The raw DeviceKey is NEVER persisted;
    /// see <see cref="DeviceKey"/> and <see cref="SetDeviceKey"/>, and
    /// docs/plan_push_auth_v2.md, "Almacenamiento Seguro de DeviceKey en Android".
    /// </summary>
    public string DeviceKeyEncryptedBase64 { get; set; } = "";

    /// <summary>GCM IV (Base64) used to wrap <see cref="DeviceKeyEncryptedBase64"/>.</summary>
    public string DeviceKeyIvBase64 { get; set; } = "";

    /// <summary>HMAC-SHA256 authentication key (Base64).</summary>
    public string AuthKeyBase64 { get; set; } = "";

    /// <summary>AES-256 pair encryption key used during pairing (Base64). Cleared after pairing.</summary>
    public string? PairEncryptKeyBase64 { get; set; }

    /// <summary>Display name of the PC.</summary>
    public string PcName { get; set; } = "";

    /// <summary>Last known IP address of the PC.</summary>
    public string? LastIp { get; set; }

    /// <summary>Whether pairing is fully complete.</summary>
    public bool IsPaired { get; set; }

    /// <summary>
    /// Current public Cloudflare Tunnel URL for reaching this PC's embedded relay (Ruta C), e.g.
    /// "https://wingb-xxx.trycloudflare.com". Populated opportunistically whenever an "auth_challenge"
    /// FCM payload carries one (see FcmService.cs) — Fase 10 is expected to also sync it during
    /// pairing/re-pairing so it's known even before the first push-auth attempt. Null until then.
    /// </summary>
    public string? RelayUrl { get; set; }

    /// <summary>When the device was paired (UTC).</summary>
    public DateTime PairedAt { get; set; } = DateTime.UtcNow;

    // Convenience properties

    /// <summary>
    /// The raw DeviceKey, decrypted on demand from <see cref="DeviceKeyEncryptedBase64"/>/
    /// <see cref="DeviceKeyIvBase64"/> via the Android Keystore-backed wrapping key. Never cached
    /// to a field — callers should use it immediately and let it fall out of scope.
    /// </summary>
    public byte[] DeviceKey
    {
        get
        {
#if ANDROID
            if (string.IsNullOrEmpty(DeviceKeyEncryptedBase64) || string.IsNullOrEmpty(DeviceKeyIvBase64))
                throw new InvalidOperationException("DeviceKey has not been set for this PairedPc.");

            return SecureKeyStorage.Unwrap(
                Convert.FromBase64String(DeviceKeyEncryptedBase64),
                Convert.FromBase64String(DeviceKeyIvBase64));
#else
            throw new PlatformNotSupportedException(
                "DeviceKey envelope decryption is only implemented for Android (SecureKeyStorage).");
#endif
        }
    }

    /// <summary>
    /// Envelope-encrypts <paramref name="plaintextKey"/> with the Android Keystore-backed wrapping key
    /// and stores only the resulting ciphertext + IV — the raw key is never persisted to SQLite.
    /// Call this instead of assigning a "DeviceKeyBase64"-style plaintext field directly.
    /// </summary>
    public void SetDeviceKey(byte[] plaintextKey)
    {
#if ANDROID
        var (ciphertext, iv) = SecureKeyStorage.Wrap(plaintextKey);
        DeviceKeyEncryptedBase64 = Convert.ToBase64String(ciphertext);
        DeviceKeyIvBase64 = Convert.ToBase64String(iv);
#else
        throw new PlatformNotSupportedException(
            "DeviceKey envelope encryption is only implemented for Android (SecureKeyStorage).");
#endif
    }

    public byte[] AuthKey => Convert.FromBase64String(AuthKeyBase64);
    public byte[]? PairEncryptKey => string.IsNullOrEmpty(PairEncryptKeyBase64)
        ? null : Convert.FromBase64String(PairEncryptKeyBase64);
}

/// <summary>
/// Simple key-value settings storage (FCM token, etc.)
/// </summary>
public class AppSetting
{
    public string Key { get; set; } = "";
    public string Value { get; set; } = "";
}
