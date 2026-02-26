using Microsoft.EntityFrameworkCore;

namespace WindowsGoodBye.Mobile.Data;

/// <summary>
/// Local database for storing paired PC information on the Android device.
/// Uses EF Core SQLite, stored in the app's private data directory.
/// </summary>
public class MobileDatabase : DbContext
{
    public DbSet<PairedPc> PairedPcs => Set<PairedPc>();

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
    }

    public void Initialize()
    {
        Database.EnsureCreated();
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

    /// <summary>AES-256 device encryption key (Base64).</summary>
    public string DeviceKeyBase64 { get; set; } = "";

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

    /// <summary>When the device was paired (UTC).</summary>
    public DateTime PairedAt { get; set; } = DateTime.UtcNow;

    // Convenience properties
    public byte[] DeviceKey => Convert.FromBase64String(DeviceKeyBase64);
    public byte[] AuthKey => Convert.FromBase64String(AuthKeyBase64);
    public byte[]? PairEncryptKey => string.IsNullOrEmpty(PairEncryptKeyBase64)
        ? null : Convert.FromBase64String(PairEncryptKeyBase64);
}
