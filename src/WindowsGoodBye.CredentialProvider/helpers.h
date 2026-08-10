#pragma once
#include <windows.h>
#include <credentialprovider.h>
#include <string>
#include <functional>
#include <cstring>

// Pipe name must match the .NET service
#define PIPE_NAME L"\\\\.\\pipe\\WindowsGoodByeAuth"
#define PIPE_CMD_WAITING "WAITING"
#define PIPE_CMD_AUTH_READY "AUTH_READY"
#define PIPE_CMD_CANCEL "CANCEL"
#define PIPE_CMD_TIMEOUT "TIMEOUT"
#define PIPE_CMD_NO_DEVICES "NO_DEVICES"
#define PIPE_STATUS_PREFIX "STATUS:"
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

// Helper: proper UTF-8 -> UTF-16 conversion (the pipe carries UTF-8, written by
// Encoding.UTF8.GetBytes on the .NET side — e.g. device friendly names in
// "STATUS:push_sent:<name>" may contain non-ASCII characters). A naive
// std::wstring(narrow.begin(), narrow.end()) widening (used elsewhere in this file for the
// ASCII-only domain/username/password fields) would mangle those, so status text gets the
// real conversion.
inline std::wstring Utf8ToWide(const std::string& utf8)
{
    if (utf8.empty()) return std::wstring();
    int required = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), NULL, 0);
    if (required <= 0) return std::wstring();
    std::wstring wide(required, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), &wide[0], required);
    return wide;
}

// Outcome of WaitForAuthResult() — see docs/plan_push_auth_v2.md, Fase 9.
enum class PipeAuthResult
{
    Success,    // AUTH_READY received and parsed — outDomain/outUsername/outPassword are valid
    Timeout,    // Explicit TIMEOUT/NO_DEVICES message, or no message arrived before the deadline
    Failed,     // Pipe error or a malformed/unrecognized terminal message
};

// Invoked for every "STATUS:<value>" progress message received while waiting (e.g. "searching",
// "push_sent:<name>", "code:<NN>", "blocked:<reason>", "timeout"). Must not block — it runs
// synchronously inside the wait loop between pipe reads. See PipeServer.cs (Service) for the
// authoritative list of values this can receive; unrecognized values must be safely ignorable.
using StatusCallback = std::function<void(const std::string& statusValue)>;

// Reads repeated "STATUS:..." progress messages off the pipe (invoking onStatus for each one)
// until a terminal message arrives: "AUTH_READY\n<domain>\<user>\n<password>" (success),
// "TIMEOUT"/"NO_DEVICES" (explicit failure), or the read itself times out/errors (also treated as
// PipeAuthResult::Timeout, matching the previous single-read behavior). Each individual ReadFile
// gets its own fresh `timeoutMs` budget — safe because the gap between two consecutive STATUS
// messages (or the last STATUS and the terminal message) is expected to be a small fraction of
// PIPE_TIMEOUT_MS, which itself matches AuthWorker's global race timeout (60s default).
inline PipeAuthResult WaitForAuthResult(
    HANDLE hPipe,
    const StatusCallback& onStatus,
    std::wstring& outDomain,
    std::wstring& outUsername,
    std::wstring& outPassword,
    DWORD timeoutMs = PIPE_TIMEOUT_MS)
{
    for (;;)
    {
        std::string response;
        if (!ReadFromPipe(hPipe, response, timeoutMs))
        {
            return PipeAuthResult::Timeout;
        }

        // "STATUS:..." is a progress update, not a terminal message — report it and keep waiting.
        if (response.rfind(PIPE_STATUS_PREFIX, 0) == 0)
        {
            if (onStatus) onStatus(response.substr(strlen(PIPE_STATUS_PREFIX)));
            continue;
        }

        if (response == PIPE_CMD_TIMEOUT || response == PIPE_CMD_NO_DEVICES)
        {
            return PipeAuthResult::Timeout;
        }

        std::string prefix = std::string(PIPE_CMD_AUTH_READY) + "\n";
        if (response.compare(0, prefix.size(), prefix) != 0)
        {
            return PipeAuthResult::Failed;
        }

        // Parse: "domain\\username\npassword"
        std::string credentials = response.substr(prefix.size());
        size_t newlinePos = credentials.find('\n');
        if (newlinePos == std::string::npos) return PipeAuthResult::Failed;

        std::string domainUser = credentials.substr(0, newlinePos);
        std::string password = credentials.substr(newlinePos + 1);

        size_t backslashPos = domainUser.find('\\');
        std::string domain, username;
        if (backslashPos != std::string::npos)
        {
            domain = domainUser.substr(0, backslashPos);
            username = domainUser.substr(backslashPos + 1);
        }
        else
        {
            domain = ".";
            username = domainUser;
        }

        outDomain = std::wstring(domain.begin(), domain.end());
        outUsername = std::wstring(username.begin(), username.end());
        outPassword = std::wstring(password.begin(), password.end());

        // Securely clear the narrow-string copies of the password before they fall out of scope.
        SecureZeroMemory((void*)password.data(), password.size());
        SecureZeroMemory((void*)credentials.data(), credentials.size());

        return PipeAuthResult::Success;
    }
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
