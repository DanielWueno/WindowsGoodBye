// Test client that simulates what the Credential Provider DLL does:
// 1. Connects to the named pipe "WindowsGoodByeAuth"
// 2. Sends "WAITING"
// 3. Waits for the Service to reply with "AUTH_READY\ndomain\username\npassword"
//
// This lets you test the full flow without building the C++ DLL.

using System.IO.Pipes;
using System.Text;

Console.WriteLine("=== WindowsGoodBye Test Auth Client ===");
Console.WriteLine("This simulates the Credential Provider.");
Console.WriteLine();

Console.WriteLine("Connecting to pipe 'WindowsGoodByeAuth'...");

try
{
    using var pipe = new NamedPipeClientStream(".", "WindowsGoodByeAuth",
        PipeDirection.InOut, PipeOptions.None);

    pipe.Connect(10_000); // 10 second timeout
    pipe.ReadMode = PipeTransmissionMode.Message;
    Console.WriteLine("Connected! Sending WAITING command...");

    // Send "WAITING" - this is what the CredentialProvider sends
    var waitingBytes = Encoding.UTF8.GetBytes("WAITING");
    pipe.Write(waitingBytes, 0, waitingBytes.Length);
    pipe.Flush();

    Console.WriteLine("Sent WAITING. Now waiting for auth response (up to 60s)...");
    Console.WriteLine(">>> Use your Android fingerprint when prompted! <<<");
    Console.WriteLine();

    // Read response
    var buffer = new byte[4096];
    var bytesRead = pipe.Read(buffer, 0, buffer.Length);
    var response = Encoding.UTF8.GetString(buffer, 0, bytesRead);

    Console.WriteLine($"Response received ({bytesRead} bytes):");
    Console.WriteLine($"---");

    if (response.StartsWith("AUTH_READY"))
    {
        var parts = response.Split('\n');
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("*** AUTHENTICATION SUCCESSFUL! ***");
        Console.ResetColor();
        if (parts.Length >= 2) Console.WriteLine($"  User: {parts[1]}");
        if (parts.Length >= 3) Console.WriteLine($"  Password: {new string('*', parts[2].Length)} ({parts[2].Length} chars)");
        Console.WriteLine();
        Console.WriteLine("The full unlock flow works! Your Android fingerprint unlocked successfully.");
    }
    else if (response == "TIMEOUT")
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("TIMEOUT - No fingerprint received within 60 seconds.");
        Console.ResetColor();
    }
    else if (response == "NO_DEVICES")
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("NO_DEVICES - No paired devices found.");
        Console.ResetColor();
        Console.WriteLine("Make sure you've paired your Android device first.");
    }
    else
    {
        Console.WriteLine($"Unknown response: {response}");
    }
}
catch (TimeoutException)
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine("ERROR: Could not connect to the pipe. Is the Service running?");
    Console.ResetColor();
}
catch (Exception ex)
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine($"ERROR: {ex.Message}");
    Console.ResetColor();
}

Console.WriteLine();
Console.WriteLine("Press any key to exit...");
Console.ReadKey();
