using System.Text;

namespace WindowsGoodBye.Core;

/// <summary>
/// Utility for sending/receiving length-prefixed UTF-8 messages over any Stream
/// (Bluetooth RFCOMM socket, TCP socket, etc.).
/// 
/// Wire format: [4 bytes big-endian length] [UTF-8 payload]
/// </summary>
public static class StreamTransport
{
    /// <summary>Send a message as a length-prefixed frame.</summary>
    public static async Task SendAsync(Stream stream, string message, CancellationToken ct = default)
    {
        var payload = Encoding.UTF8.GetBytes(message);
        var lengthPrefix = BitConverter.GetBytes(payload.Length);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(lengthPrefix); // big-endian

        await stream.WriteAsync(lengthPrefix, ct);
        await stream.WriteAsync(payload, ct);
        await stream.FlushAsync(ct);
    }

    /// <summary>Read a single length-prefixed message. Returns null on disconnect.</summary>
    public static async Task<string?> ReceiveAsync(Stream stream, CancellationToken ct = default)
    {
        var lengthBuf = new byte[4];
        var bytesRead = await ReadExactAsync(stream, lengthBuf, 0, 4, ct);
        if (bytesRead < 4) return null; // Disconnected

        if (BitConverter.IsLittleEndian)
            Array.Reverse(lengthBuf); // from big-endian
        var length = BitConverter.ToInt32(lengthBuf, 0);

        if (length <= 0 || length > Protocol.MaxPacketSize)
            return null; // Invalid frame

        var payload = new byte[length];
        bytesRead = await ReadExactAsync(stream, payload, 0, length, ct);
        if (bytesRead < length) return null; // Disconnected

        return Encoding.UTF8.GetString(payload);
    }

    private static async Task<int> ReadExactAsync(Stream stream, byte[] buffer, int offset, int count, CancellationToken ct)
    {
        int totalRead = 0;
        while (totalRead < count)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset + totalRead, count - totalRead), ct);
            if (read == 0) return totalRead; // Stream closed
            totalRead += read;
        }
        return totalRead;
    }
}
