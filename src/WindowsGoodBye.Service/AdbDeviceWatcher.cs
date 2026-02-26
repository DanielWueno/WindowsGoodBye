using System.Diagnostics;
using System.Management;
using WindowsGoodBye.Core;

namespace WindowsGoodBye.Service;

/// <summary>
/// Watches for USB device connections and automatically configures
/// ADB reverse port forwarding when an Android device is detected.
/// 
/// This eliminates the need to manually run "adb reverse tcp:26820 tcp:26820"
/// after each USB reconnection — critical for the unlock scenario where
/// the PC is locked and the user plugs the phone back in.
/// </summary>
public sealed class AdbDeviceWatcher : IDisposable
{
    private readonly ILogger<AdbDeviceWatcher> _logger;
    private ManagementEventWatcher? _connectWatcher;
    private ManagementEventWatcher? _disconnectWatcher;
    private Timer? _periodicCheck;
    private string? _adbPath;
    private bool _disposed;
    private bool _adbReverseActive;
    private readonly SemaphoreSlim _adbLock = new(1, 1);

    /// <summary>How often to poll for ADB devices as a fallback (seconds).</summary>
    private const int PeriodicCheckIntervalSec = 15;

    /// <summary>Fired when ADB reverse is successfully configured after a device connects.</summary>
    public event Action? AdbReverseEstablished;

    /// <summary>Fired when USB device disconnect is detected.</summary>
    public event Action? DeviceDisconnected;

    /// <summary>Whether ADB reverse port forwarding is currently active.</summary>
    public bool IsAdbReverseActive => _adbReverseActive;

    public AdbDeviceWatcher(ILogger<AdbDeviceWatcher> logger)
    {
        _logger = logger;
    }

    /// <summary>Start monitoring USB device events + periodic ADB checks.</summary>
    public void Start()
    {
        _adbPath = FindAdb();
        if (_adbPath == null)
        {
            _logger.LogWarning("ADB not found. USB auto-setup disabled. " +
                               "Install Android SDK Platform Tools and add to PATH.");
            return;
        }

        _logger.LogInformation("ADB found at {Path}", _adbPath);

        // WMI: Watch for USB device connections (PnP device creation)
        try
        {
            // Monitor USB device arrivals via Win32_DeviceChangeEvent (EventType=2 = ConfigChanged, but
            // we watch for __InstanceCreationEvent on Win32_PnPEntity for USB devices)
            _connectWatcher = new ManagementEventWatcher(new WqlEventQuery(
                "__InstanceCreationEvent",
                TimeSpan.FromSeconds(2),
                "TargetInstance ISA 'Win32_PnPEntity'"));
            _connectWatcher.EventArrived += OnUsbDeviceArrived;
            _connectWatcher.Start();

            _disconnectWatcher = new ManagementEventWatcher(new WqlEventQuery(
                "__InstanceDeletionEvent",
                TimeSpan.FromSeconds(2),
                "TargetInstance ISA 'Win32_PnPEntity'"));
            _disconnectWatcher.EventArrived += OnUsbDeviceRemoved;
            _disconnectWatcher.Start();

            _logger.LogInformation("WMI USB device watchers started");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "WMI USB watchers failed — falling back to periodic polling only");
        }

        // Periodic fallback: check for ADB devices every N seconds
        _periodicCheck = new Timer(OnPeriodicCheck, null,
            TimeSpan.FromSeconds(5),  // Initial delay (give service time to start)
            TimeSpan.FromSeconds(PeriodicCheckIntervalSec));

        _logger.LogInformation("ADB Device Watcher started (poll every {Sec}s)", PeriodicCheckIntervalSec);
    }

    /// <summary>Stop all watchers and timers.</summary>
    public void Stop()
    {
        _periodicCheck?.Change(Timeout.Infinite, Timeout.Infinite);
        _periodicCheck?.Dispose();
        _periodicCheck = null;

        try { _connectWatcher?.Stop(); } catch { }
        try { _disconnectWatcher?.Stop(); } catch { }
        _connectWatcher?.Dispose();
        _disconnectWatcher?.Dispose();
        _connectWatcher = null;
        _disconnectWatcher = null;

        _logger.LogInformation("ADB Device Watcher stopped");
    }

    // --- WMI Event Handlers ---

    private void OnUsbDeviceArrived(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var instance = (ManagementBaseObject)e.NewEvent["TargetInstance"];
            var deviceId = instance["DeviceID"]?.ToString() ?? "";
            var name = instance["Name"]?.ToString() ?? "";

            // Filter: look for USB-connected Android devices
            // Android devices typically show up as USB composite devices or 
            // with descriptors containing "Android", "ADB", or vendor IDs
            if (IsLikelyAndroidDevice(deviceId, name))
            {
                _logger.LogInformation("Possible Android USB device connected: {Name} ({DeviceId})",
                    name, deviceId);

                // Wait a moment for the device to fully enumerate
                Task.Run(async () =>
                {
                    await Task.Delay(2000);
                    await TrySetupAdbReverseAsync();
                });
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug("WMI connect event processing error: {Msg}", ex.Message);
        }
    }

    private void OnUsbDeviceRemoved(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var instance = (ManagementBaseObject)e.NewEvent["TargetInstance"];
            var deviceId = instance["DeviceID"]?.ToString() ?? "";
            var name = instance["Name"]?.ToString() ?? "";

            if (IsLikelyAndroidDevice(deviceId, name))
            {
                _logger.LogInformation("Android USB device disconnected: {Name}", name);
                _adbReverseActive = false;
                DeviceDisconnected?.Invoke();
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug("WMI disconnect event processing error: {Msg}", ex.Message);
        }
    }

    /// <summary>
    /// Heuristic: does this PnP device look like an Android phone?
    /// Common indicators: USB vendor IDs of major phone manufacturers,
    /// device names containing "Android", "ADB Interface", etc.
    /// </summary>
    private static bool IsLikelyAndroidDevice(string deviceId, string name)
    {
        var upper = (deviceId + " " + name).ToUpperInvariant();

        // ADB Interface is a dead giveaway
        if (upper.Contains("ADB") || upper.Contains("ANDROID"))
            return true;

        // Common Android USB vendor IDs (VID)
        // Google: 18D1, Samsung: 04E8, Xiaomi: 2717, OnePlus: 2A70,
        // Huawei: 12D1, LG: 1004, Motorola: 22B8, Sony: 0FCE,
        // HTC: 0BB4, OPPO: 22D9, Realme: 22D9, Vivo: 2D95
        string[] androidVendorIds = [
            "VID_18D1", "VID_04E8", "VID_2717", "VID_2A70",
            "VID_12D1", "VID_1004", "VID_22B8", "VID_0FCE",
            "VID_0BB4", "VID_22D9", "VID_2D95", "VID_05C6",
            "VID_1BBB", "VID_0E8D", "VID_1532", "VID_2A45",
            "VID_2B4C", "VID_19D2", "VID_0414", "VID_2916"
        ];

        foreach (var vid in androidVendorIds)
        {
            if (upper.Contains(vid))
                return true;
        }

        return false;
    }

    // --- Periodic Fallback Check ---

    private void OnPeriodicCheck(object? state)
    {
        _ = TrySetupAdbReverseAsync();
    }

    // --- ADB Operations ---

    /// <summary>
    /// Check if an ADB device is connected and set up reverse port forwarding.
    /// Thread-safe (uses semaphore).
    /// </summary>
    public async Task<bool> TrySetupAdbReverseAsync()
    {
        if (_adbPath == null) return false;
        if (!await _adbLock.WaitAsync(0)) return false; // Skip if another check is in progress

        try
        {
            // Step 1: Check if any ADB device is connected
            var devices = await RunAdbAsync("devices");
            if (devices == null) return false;

            var lines = devices.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            bool hasDevice = false;
            foreach (var line in lines)
            {
                // "List of devices attached" is the header, skip it
                if (line.StartsWith("List")) continue;
                // A connected device line looks like: "ABC123XYZ\tdevice"
                if (line.Contains("\tdevice"))
                {
                    hasDevice = true;
                    break;
                }
            }

            if (!hasDevice)
            {
                if (_adbReverseActive)
                {
                    _adbReverseActive = false;
                    _logger.LogInformation("ADB device no longer connected");
                    DeviceDisconnected?.Invoke();
                }
                return false;
            }

            // Step 2: Check if reverse is already active
            var reverseList = await RunAdbAsync("reverse --list");
            if (reverseList != null && reverseList.Contains($"tcp:{Protocol.TcpUsbPort}"))
            {
                if (!_adbReverseActive)
                {
                    _adbReverseActive = true;
                    _logger.LogInformation("ADB reverse already configured (port {Port})", Protocol.TcpUsbPort);
                }
                return true;
            }

            // Step 3: Set up ADB reverse
            var result = await RunAdbAsync($"reverse tcp:{Protocol.TcpUsbPort} tcp:{Protocol.TcpUsbPort}");
            if (result != null && !result.Contains("error"))
            {
                _adbReverseActive = true;
                _logger.LogInformation("ADB reverse tcp:{Port} configured automatically!", Protocol.TcpUsbPort);
                AdbReverseEstablished?.Invoke();
                return true;
            }
            else
            {
                _logger.LogWarning("ADB reverse failed: {Result}", result ?? "timeout");
                return false;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during ADB setup");
            return false;
        }
        finally
        {
            _adbLock.Release();
        }
    }

    /// <summary>Run an ADB command and return stdout. Returns null on failure/timeout.</summary>
    private async Task<string?> RunAdbAsync(string arguments, int timeoutMs = 10000)
    {
        try
        {
            using var process = new Process();
            process.StartInfo = new ProcessStartInfo
            {
                FileName = _adbPath!,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };

            process.Start();

            using var cts = new CancellationTokenSource(timeoutMs);
            var output = await process.StandardOutput.ReadToEndAsync(cts.Token);
            var error = await process.StandardError.ReadToEndAsync(cts.Token);

            await process.WaitForExitAsync(cts.Token);

            if (!string.IsNullOrEmpty(error) && process.ExitCode != 0)
            {
                _logger.LogDebug("ADB {Args} stderr: {Error}", arguments, error.Trim());
            }

            return output.Trim();
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("ADB {Args} timed out after {Ms}ms", arguments, timeoutMs);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogDebug("ADB {Args} error: {Msg}", arguments, ex.Message);
            return null;
        }
    }

    /// <summary>
    /// Find ADB executable by searching:
    /// 1. System PATH
    /// 2. Common Android SDK locations
    /// 3. Common standalone ADB locations
    /// </summary>
    private static string? FindAdb()
    {
        // 1. Check PATH (most reliable: covers custom installs)
        try
        {
            using var process = new Process();
            process.StartInfo = new ProcessStartInfo
            {
                FileName = "where.exe",
                Arguments = "adb",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };
            process.Start();
            var output = process.StandardOutput.ReadToEnd().Trim();
            process.WaitForExit(5000);

            if (!string.IsNullOrEmpty(output))
            {
                var firstPath = output.Split('\n')[0].Trim();
                if (File.Exists(firstPath))
                    return firstPath;
            }
        }
        catch { }

        // 2. Common SDK locations
        string[] candidates = [
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Android", "Sdk", "platform-tools", "adb.exe"),
            @"C:\Program Files (x86)\Android\android-sdk\platform-tools\adb.exe",
            @"C:\Android\platform-tools\adb.exe",
            @"D:\adb\adb.exe",
            @"D:\adb\scrcpy\adb.exe",
        ];

        foreach (var path in candidates)
        {
            if (File.Exists(path))
                return path;
        }

        return null;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
        _adbLock.Dispose();
    }
}
