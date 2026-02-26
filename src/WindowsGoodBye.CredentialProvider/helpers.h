#pragma once
#include <windows.h>
#include <credentialprovider.h>
#include <string>

// Pipe name must match the .NET service
#define PIPE_NAME L"\\\\.\\pipe\\WindowsGoodByeAuth"
#define PIPE_CMD_WAITING "WAITING"
#define PIPE_CMD_AUTH_READY "AUTH_READY"
#define PIPE_CMD_CANCEL "CANCEL"
#define PIPE_TIMEOUT_MS 60000

// Helper: Read string from named pipe
inline bool ReadFromPipe(HANDLE hPipe, std::string& output, DWORD timeoutMs = PIPE_TIMEOUT_MS)
{
    char buffer[2048] = {};
    DWORD bytesRead = 0;

    OVERLAPPED overlapped = {};
    overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!overlapped.hEvent) return false;

    BOOL result = ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, &overlapped);
    if (!result && GetLastError() == ERROR_IO_PENDING)
    {
        DWORD waitResult = WaitForSingleObject(overlapped.hEvent, timeoutMs);
        if (waitResult == WAIT_OBJECT_0)
        {
            GetOverlappedResult(hPipe, &overlapped, &bytesRead, FALSE);
            result = TRUE;
        }
    }

    CloseHandle(overlapped.hEvent);

    if (result || bytesRead > 0)
    {
        buffer[bytesRead] = '\0';
        output = buffer;
        return true;
    }
    return false;
}

// Helper: Write string to named pipe
inline bool WriteToPipe(HANDLE hPipe, const std::string& data)
{
    DWORD bytesWritten = 0;
    return WriteFile(hPipe, data.c_str(), (DWORD)data.size(), &bytesWritten, NULL) != 0;
}

// Helper: Connect to the WindowsGoodBye service pipe
inline HANDLE ConnectToServicePipe()
{
    HANDLE hPipe = CreateFileW(
        PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        NULL);

    if (hPipe == INVALID_HANDLE_VALUE)
        return INVALID_HANDLE_VALUE;

    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(hPipe, &mode, NULL, NULL);
    return hPipe;
}
