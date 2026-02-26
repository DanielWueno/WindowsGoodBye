using Android.Bluetooth;
using Android.Content;
using Java.Util;
using WindowsGoodBye.Core;

namespace WindowsGoodBye.Mobile.Platforms.Android;

/// <summary>
/// Android Bluetooth RFCOMM client for communicating with the Windows service.
/// Connects to the paired PC's Bluetooth RFCOMM service and sends/receives
/// the same protocol messages used over UDP.
/// </summary>
public class BluetoothTransport : IDisposable
{
    private BluetoothSocket? _socket;
    private System.IO.Stream? _stream;
    private CancellationTokenSource? _cts;
    private bool _disposed;

    private static readonly UUID ServiceUuid =
        UUID.FromString(Protocol.BluetoothServiceUuid)!;

    /// <summary>Fired when a message is received from the PC over Bluetooth.</summary>
    public event Action<string>? MessageReceived;

    /// <summary>Check if Bluetooth is available and enabled.</summary>
    public static bool IsAvailable
    {
        get
        {
            var adapter = BluetoothAdapter.DefaultAdapter;
            return adapter != null && adapter.IsEnabled;
        }
    }

    /// <summary>Get all bonded (paired) Bluetooth devices.</summary>
    public static IReadOnlyList<(string Name, string Address)> GetBondedDevices()
    {
        var adapter = BluetoothAdapter.DefaultAdapter;
        if (adapter?.BondedDevices == null) return [];

        return adapter.BondedDevices
            .Where(d => d.Name != null && d.Address != null)
            .Select(d => (d.Name!, d.Address!))
            .ToList();
    }

    /// <summary>
    /// Try to connect to a Bluetooth device running the WindowsGoodBye service.
    /// Returns true if connected successfully.
    /// </summary>
    public async Task<bool> ConnectAsync(string macAddress, CancellationToken ct = default)
    {
        try
        {
            var adapter = BluetoothAdapter.DefaultAdapter;
            if (adapter == null) return false;

            // Cancel discovery to speed up connection
            adapter.CancelDiscovery();

            var device = adapter.GetRemoteDevice(macAddress);
            if (device == null) return false;

            _socket = device.CreateRfcommSocketToServiceRecord(ServiceUuid);
            if (_socket == null) return false;

            await Task.Run(() => _socket.Connect(), ct);

            if (!_socket.IsConnected) return false;

            _stream = _socket.InputStream != null && _socket.OutputStream != null
                ? new BluetoothStream(_socket.InputStream, _socket.OutputStream)
                : null;

            if (_stream == null)
            {
                _socket.Close();
                return false;
            }

            _cts = new CancellationTokenSource();
            _ = Task.Run(() => ReadLoop(_cts.Token));

            System.Diagnostics.Debug.WriteLine($"[BT] Connected to {device.Name} ({macAddress})");
            return true;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[BT] Connect failed: {ex.Message}");
            Disconnect();
            return false;
        }
    }

    /// <summary>
    /// Try connecting to the WindowsGoodBye service on any bonded device.
    /// Returns the MAC address of the device we connected to, or null.
    /// </summary>
    public async Task<string?> ConnectToAnyAsync(CancellationToken ct = default)
    {
        foreach (var (name, address) in GetBondedDevices())
        {
            if (ct.IsCancellationRequested) break;

            System.Diagnostics.Debug.WriteLine($"[BT] Trying {name} ({address})...");
            try
            {
                using var timeout = new CancellationTokenSource(5000);
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);

                if (await ConnectAsync(address, linked.Token))
                    return address;
            }
            catch { /* try next device */ }
        }

        return null;
    }

    /// <summary>Send a protocol message over the Bluetooth connection.</summary>
    public async Task SendAsync(string message)
    {
        if (_stream == null) throw new InvalidOperationException("Not connected");
        await StreamTransport.SendAsync(_stream, message);
    }

    public bool IsConnected => _socket?.IsConnected == true;

    private async Task ReadLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _stream != null)
        {
            try
            {
                var message = await StreamTransport.ReceiveAsync(_stream, ct);
                if (message == null) break; // Disconnected

                MessageReceived?.Invoke(message);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[BT] Read error: {ex.Message}");
                break;
            }
        }

        System.Diagnostics.Debug.WriteLine("[BT] Read loop ended");
    }

    public void Disconnect()
    {
        _cts?.Cancel();
        try { _stream?.Close(); } catch { }
        try { _socket?.Close(); } catch { }
        _stream = null;
        _socket = null;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Disconnect();
        _cts?.Dispose();
    }

    /// <summary>
    /// Wraps Android's separate InputStream/OutputStream into a single .NET Stream
    /// for use with StreamTransport.
    /// </summary>
    private class BluetoothStream : System.IO.Stream
    {
        private readonly System.IO.Stream _input;
        private readonly System.IO.Stream _output;

        public BluetoothStream(System.IO.Stream input, System.IO.Stream output)
        {
            _input = input;
            _output = output;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count) => _input.Read(buffer, offset, count);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) => _input.ReadAsync(buffer, ct);
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) => _input.ReadAsync(buffer, offset, count, ct);

        public override void Write(byte[] buffer, int offset, int count) => _output.Write(buffer, offset, count);
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default) => _output.WriteAsync(buffer, ct);
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct) => _output.WriteAsync(buffer, offset, count, ct);

        public override void Flush() => _output.Flush();
        public override Task FlushAsync(CancellationToken ct) => _output.FlushAsync(ct);

        public override long Seek(long offset, System.IO.SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _input.Dispose();
                _output.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
