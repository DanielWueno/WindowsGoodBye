using Microsoft.EntityFrameworkCore;

namespace WindowsGoodBye.Core;

public class AppDatabase : DbContext
{
    public DbSet<DeviceInfo> Devices => Set<DeviceInfo>();
    public DbSet<AuthRecord> AuthRecords => Set<AuthRecord>();
    public DbSet<StoredCredential> Credentials => Set<StoredCredential>();

    private readonly string _dbPath;

    public AppDatabase()
    {
        var appData = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "WindowsGoodBye");
        Directory.CreateDirectory(appData);
        _dbPath = Path.Combine(appData, "devices.db");
    }

    public AppDatabase(string dbPath)
    {
        _dbPath = dbPath;
    }

    protected override void OnConfiguring(DbContextOptionsBuilder options)
    {
        options.UseSqlite($"Data Source={_dbPath}");
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<DeviceInfo>(e =>
        {
            e.HasKey(d => d.DeviceId);
            e.Property(d => d.DeviceKey).IsRequired();
            e.Property(d => d.AuthKey).IsRequired();
        });

        modelBuilder.Entity<AuthRecord>(e =>
        {
            e.HasKey(r => r.Id);
            e.Property(r => r.Id).ValueGeneratedOnAdd();
        });

        modelBuilder.Entity<StoredCredential>(e =>
        {
            e.HasKey(c => c.Id);
            e.Property(c => c.Id).ValueGeneratedOnAdd();
        });
    }

    /// <summary>Ensure the database and tables exist, and apply any pending schema changes.</summary>
    public void Initialize()
    {
        Database.EnsureCreated();
        MigrateSchema();
    }

    /// <summary>
    /// Lightweight schema migration: adds columns that may be missing after model changes.
    /// EnsureCreated() does NOT alter existing tables, so we do it manually.
    /// </summary>
    private void MigrateSchema()
    {
        var conn = Database.GetDbConnection();
        conn.Open();
        try
        {
            // Check and add FcmToken column to Devices table
            AddColumnIfMissing(conn, "Devices", "FcmToken", "TEXT");
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
