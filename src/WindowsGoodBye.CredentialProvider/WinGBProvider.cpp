/*
 * WindowsGoodBye Credential Provider Implementation
 *
 * The core logic:
 * 1. When the lock screen appears, LogonUI loads this DLL
 * 2. A "WindowsGoodBye" tile is shown
 * 3. When selected, Connect() is called which connects to the named pipe
 * 4. The pipe sends "WAITING" to the service
 * 5. The service broadcasts auth discovery to paired phones
 * 6. User touches fingerprint on phone
 * 7. Service receives auth and sends credentials through the pipe
 * 8. Connect() returns success
 * 9. GetSerialization() packages credentials for LogonUI
 * 10. PC is unlocked!
 */

#include "WinGBProvider.h"
#include <wincred.h>
#include <shlwapi.h>
#include <new>

#pragma comment(lib, "shlwapi.lib")

// Module reference count
static LONG g_cRef = 0;
HINSTANCE g_hInstance = NULL;

//----------------------------------------------------------------------
// DLL Entry Points
//----------------------------------------------------------------------

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        g_hInstance = hinstDLL;
        DisableThreadLibraryCalls(hinstDLL);
    }
    return TRUE;
}

STDAPI DllCanUnloadNow()
{
    return (g_cRef > 0) ? S_FALSE : S_OK;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv)
{
    if (rclsid == CLSID_WindowsGoodByeProvider)
    {
        auto* pFactory = new(std::nothrow) WinGBClassFactory();
        if (!pFactory) return E_OUTOFMEMORY;
        HRESULT hr = pFactory->QueryInterface(riid, ppv);
        pFactory->Release();
        return hr;
    }
    *ppv = nullptr;
    return CLASS_E_CLASSNOTAVAILABLE;
}

//----------------------------------------------------------------------
// WinGBProvider Implementation
//----------------------------------------------------------------------

WinGBProvider::WinGBProvider() { InterlockedIncrement(&g_cRef); }
WinGBProvider::~WinGBProvider()
{
    if (_pCredential) _pCredential->Release();
    InterlockedDecrement(&g_cRef);
}

ULONG WinGBProvider::AddRef() { return InterlockedIncrement(&_cRef); }
ULONG WinGBProvider::Release()
{
    LONG cRef = InterlockedDecrement(&_cRef);
    if (!cRef) delete this;
    return cRef;
}

HRESULT WinGBProvider::QueryInterface(REFIID riid, void** ppv)
{
    if (riid == IID_ICredentialProvider || riid == IID_IUnknown)
    {
        *ppv = static_cast<ICredentialProvider*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

HRESULT WinGBProvider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD)
{
    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        _cpus = cpus;
        if (!_pCredential)
        {
            _pCredential = new(std::nothrow) WinGBCredential();
            if (!_pCredential) return E_OUTOFMEMORY;
            _pCredential->SetUsage(cpus);
        }
        return S_OK;

    case CPUS_CHANGE_PASSWORD:
    case CPUS_CREDUI:
    default:
        return E_NOTIMPL;
    }
}

HRESULT WinGBProvider::SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) { return E_NOTIMPL; }

HRESULT WinGBProvider::Advise(ICredentialProviderEvents*, UINT_PTR) { return S_OK; }
HRESULT WinGBProvider::UnAdvise() { return S_OK; }

HRESULT WinGBProvider::GetFieldDescriptorCount(DWORD* pdwCount)
{
    *pdwCount = WINGB_FID_NUM_FIELDS;
    return S_OK;
}

HRESULT WinGBProvider::GetFieldDescriptorAt(DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{
    if (dwIndex >= WINGB_FID_NUM_FIELDS) return E_INVALIDARG;

    auto* pfd = (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR));
    if (!pfd) return E_OUTOFMEMORY;

    const auto& src = s_rgFieldDescriptors[dwIndex];
    pfd->dwFieldID = src.dwFieldID;
    pfd->cpft = src.cpft;
    pfd->guidFieldType = src.guidFieldType;

    if (src.pszLabel)
        SHStrDupW(src.pszLabel, &pfd->pszLabel);
    else
        pfd->pszLabel = nullptr;

    *ppcpfd = pfd;
    return S_OK;
}

HRESULT WinGBProvider::GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAutoLogonWithDefault)
{
    *pdwCount = 1;
    *pdwDefault = 0;
    *pbAutoLogonWithDefault = FALSE;
    return S_OK;
}

HRESULT WinGBProvider::GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc)
{
    if (dwIndex != 0 || !_pCredential) return E_INVALIDARG;
    _pCredential->AddRef();
    *ppcpc = _pCredential;
    return S_OK;
}

//----------------------------------------------------------------------
// WinGBCredential Implementation
//----------------------------------------------------------------------

WinGBCredential::WinGBCredential() { InterlockedIncrement(&g_cRef); }
WinGBCredential::~WinGBCredential()
{
    if (_hPipe != INVALID_HANDLE_VALUE) CloseHandle(_hPipe);
    // Securely clear password
    SecureZeroMemory((void*)_password.data(), _password.size() * sizeof(wchar_t));
    InterlockedDecrement(&g_cRef);
}

ULONG WinGBCredential::AddRef() { return InterlockedIncrement(&_cRef); }
ULONG WinGBCredential::Release()
{
    LONG cRef = InterlockedDecrement(&_cRef);
    if (!cRef) delete this;
    return cRef;
}

HRESULT WinGBCredential::QueryInterface(REFIID riid, void** ppv)
{
    if (riid == IID_IConnectableCredentialProviderCredential)
    {
        *ppv = static_cast<IConnectableCredentialProviderCredential*>(this);
        AddRef();
        return S_OK;
    }
    if (riid == IID_ICredentialProviderCredential || riid == IID_IUnknown)
    {
        *ppv = static_cast<ICredentialProviderCredential*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

HRESULT WinGBCredential::Advise(ICredentialProviderCredentialEvents* pcpce)
{
    if (_pCredProvCredentialEvents) _pCredProvCredentialEvents->Release();
    _pCredProvCredentialEvents = pcpce;
    _pCredProvCredentialEvents->AddRef();
    return S_OK;
}

HRESULT WinGBCredential::UnAdvise()
{
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->Release();
        _pCredProvCredentialEvents = nullptr;
    }
    return S_OK;
}

HRESULT WinGBCredential::SetSelected(BOOL* pbAutoLogon)
{
    *pbAutoLogon = FALSE;
    return S_OK;
}

HRESULT WinGBCredential::SetDeselected()
{
    // Cancel any pending pipe connection
    if (_hPipe != INVALID_HANDLE_VALUE)
    {
        WriteToPipe(_hPipe, PIPE_CMD_CANCEL);
        CloseHandle(_hPipe);
        _hPipe = INVALID_HANDLE_VALUE;
    }
    return S_OK;
}

HRESULT WinGBCredential::GetFieldState(DWORD dwFieldID, CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
                                         CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis)
{
    if (dwFieldID >= WINGB_FID_NUM_FIELDS) return E_INVALIDARG;

    switch (dwFieldID)
    {
    case WINGB_FID_ICON:
        *pcpfs = CPFS_DISPLAY_IN_BOTH;
        *pcpfis = CPFIS_NONE;
        break;
    case WINGB_FID_LARGE_TEXT:
        *pcpfs = CPFS_DISPLAY_IN_BOTH;
        *pcpfis = CPFIS_NONE;
        break;
    case WINGB_FID_SMALL_TEXT:
        *pcpfs = CPFS_DISPLAY_IN_BOTH;
        *pcpfis = CPFIS_NONE;
        break;
    case WINGB_FID_SUBMIT:
        *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
        *pcpfis = CPFIS_NONE;
        break;
    }
    return S_OK;
}

HRESULT WinGBCredential::GetStringValue(DWORD dwFieldID, LPWSTR* ppsz)
{
    switch (dwFieldID)
    {
    case WINGB_FID_LARGE_TEXT:
        return SHStrDupW(L"WindowsGoodBye", ppsz);
    case WINGB_FID_SMALL_TEXT:
        return SHStrDupW(_authenticated ? L"Authenticated! Press Enter..." : L"Tap fingerprint on phone to unlock", ppsz);
    default:
        return E_INVALIDARG;
    }
}

HRESULT WinGBCredential::GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp)
{
    if (dwFieldID != WINGB_FID_ICON) return E_INVALIDARG;
    // Use a default icon - in production, load from resource
    *phbmp = NULL;
    return E_NOTIMPL; // LogonUI will use default icon
}

HRESULT WinGBCredential::GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo)
{
    if (dwFieldID != WINGB_FID_SUBMIT) return E_INVALIDARG;
    *pdwAdjacentTo = WINGB_FID_SMALL_TEXT;
    return S_OK;
}

//----------------------------------------------------------------------
// Connect - This is where the magic happens!
// Called when the user selects the WindowsGoodBye tile.
// We connect to the service pipe and wait for auth.
//----------------------------------------------------------------------
HRESULT WinGBCredential::Connect(IQueryContinueWithStatus* pqcws)
{
    _authenticated = false;

    if (pqcws)
        pqcws->SetStatusMessage(L"Connecting to WindowsGoodBye service...");

    // Connect to the service's named pipe
    _hPipe = ConnectToServicePipe();
    if (_hPipe == INVALID_HANDLE_VALUE)
    {
        if (pqcws)
            pqcws->SetStatusMessage(L"WindowsGoodBye service is not running. Start the service first.");
        return E_FAIL;
    }

    if (pqcws)
        pqcws->SetStatusMessage(L"Waiting for phone authentication...\nTap your fingerprint on your Android device.");

    // Send "WAITING" command to the service
    if (!WriteToPipe(_hPipe, PIPE_CMD_WAITING))
    {
        CloseHandle(_hPipe);
        _hPipe = INVALID_HANDLE_VALUE;
        return E_FAIL;
    }

    // Wait for the service to respond with credentials
    std::string response;
    if (!ReadFromPipe(_hPipe, response, PIPE_TIMEOUT_MS))
    {
        if (pqcws)
            pqcws->SetStatusMessage(L"Timeout waiting for phone authentication.");
        CloseHandle(_hPipe);
        _hPipe = INVALID_HANDLE_VALUE;
        return E_FAIL;
    }

    CloseHandle(_hPipe);
    _hPipe = INVALID_HANDLE_VALUE;

    // Parse response: "AUTH_READY\ndomain\\username\npassword"
    std::string prefix = PIPE_CMD_AUTH_READY;
    prefix += "\n";
    if (response.substr(0, prefix.size()) != prefix)
    {
        if (pqcws)
            pqcws->SetStatusMessage(L"Authentication failed or timed out.");
        return E_FAIL;
    }

    std::string credentials = response.substr(prefix.size());
    // Parse: "domain\\username\npassword"
    size_t newlinePos = credentials.find('\n');
    if (newlinePos == std::string::npos) return E_FAIL;

    std::string domainUser = credentials.substr(0, newlinePos);
    std::string password = credentials.substr(newlinePos + 1);

    // Parse domain\\username
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

    // Convert to wide strings
    _domain = std::wstring(domain.begin(), domain.end());
    _username = std::wstring(username.begin(), username.end());
    _password = std::wstring(password.begin(), password.end());

    // Securely clear the narrow string password
    SecureZeroMemory((void*)password.data(), password.size());
    SecureZeroMemory((void*)credentials.data(), credentials.size());

    _authenticated = true;

    if (pqcws)
        pqcws->SetStatusMessage(L"Phone authenticated! Unlocking...");

    // Update the status text
    if (_pCredProvCredentialEvents)
        _pCredProvCredentialEvents->SetFieldString(this, WINGB_FID_SMALL_TEXT, L"Authenticated! Unlocking...");

    return S_OK;
}

HRESULT WinGBCredential::Disconnect()
{
    if (_hPipe != INVALID_HANDLE_VALUE)
    {
        WriteToPipe(_hPipe, PIPE_CMD_CANCEL);
        CloseHandle(_hPipe);
        _hPipe = INVALID_HANDLE_VALUE;
    }
    return S_OK;
}

//----------------------------------------------------------------------
// GetSerialization - Package credentials for LogonUI
// This creates the authentication package that Windows uses to log in.
//----------------------------------------------------------------------
HRESULT WinGBCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    LPWSTR* ppszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    if (!_authenticated)
    {
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_OK;
    }

    // Build a KERB_INTERACTIVE_UNLOCK_LOGON structure
    HRESULT hr = E_FAIL;

    // Get the authentication package
    HANDLE hLsa;
    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (status != 0)
    {
        *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
        return E_FAIL;
    }

    ULONG ulAuthPackage = 0;
    LSA_STRING authPackageName;
    authPackageName.Buffer = (PCHAR)MICROSOFT_KERBEROS_NAME_A;
    authPackageName.Length = (USHORT)strlen(MICROSOFT_KERBEROS_NAME_A);
    authPackageName.MaximumLength = authPackageName.Length + 1;

    status = LsaLookupAuthenticationPackage(hLsa, &authPackageName, &ulAuthPackage);
    LsaDeregisterLogonProcess(hLsa);
    if (status != 0)
    {
        *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
        return E_FAIL;
    }

    // Calculate buffer sizes
    DWORD cbDomain = (DWORD)(_domain.size() + 1) * sizeof(wchar_t);
    DWORD cbUsername = (DWORD)(_username.size() + 1) * sizeof(wchar_t);
    DWORD cbPassword = (DWORD)(_password.size() + 1) * sizeof(wchar_t);

    DWORD cbHeader = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON);
    DWORD cbSize = cbHeader + cbDomain + cbUsername + cbPassword;

    auto* pLogon = (KERB_INTERACTIVE_UNLOCK_LOGON*)CoTaskMemAlloc(cbSize);
    if (!pLogon)
    {
        *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
        return E_OUTOFMEMORY;
    }
    ZeroMemory(pLogon, cbSize);

    BYTE* pBuffer = (BYTE*)pLogon + cbHeader;

    // Fill in the logon structure
    KERB_INTERACTIVE_LOGON* pKil = &pLogon->Logon;
    pKil->MessageType = KerbInteractiveLogon;

    // Domain
    pKil->LogonDomainName.Length = (USHORT)((_domain.size()) * sizeof(wchar_t));
    pKil->LogonDomainName.MaximumLength = (USHORT)cbDomain;
    pKil->LogonDomainName.Buffer = (PWSTR)pBuffer;
    memcpy(pBuffer, _domain.c_str(), cbDomain);
    pBuffer += cbDomain;

    // Username
    pKil->UserName.Length = (USHORT)((_username.size()) * sizeof(wchar_t));
    pKil->UserName.MaximumLength = (USHORT)cbUsername;
    pKil->UserName.Buffer = (PWSTR)pBuffer;
    memcpy(pBuffer, _username.c_str(), cbUsername);
    pBuffer += cbUsername;

    // Password
    pKil->Password.Length = (USHORT)((_password.size()) * sizeof(wchar_t));
    pKil->Password.MaximumLength = (USHORT)cbPassword;
    pKil->Password.Buffer = (PWSTR)pBuffer;
    memcpy(pBuffer, _password.c_str(), cbPassword);

    // Fix up string buffer pointers to be offsets from the start of the structure
    // (required for serialization)
    pKil->LogonDomainName.Buffer = (PWSTR)((BYTE*)pKil->LogonDomainName.Buffer - (BYTE*)pLogon);
    pKil->UserName.Buffer = (PWSTR)((BYTE*)pKil->UserName.Buffer - (BYTE*)pLogon);
    pKil->Password.Buffer = (PWSTR)((BYTE*)pKil->Password.Buffer - (BYTE*)pLogon);

    // For unlock scenario
    if (_cpus == CPUS_UNLOCK_WORKSTATION)
    {
        pKil->MessageType = KerbWorkstationUnlockLogon;
    }

    // Fill the serialization structure
    pcpcs->ulAuthenticationPackage = ulAuthPackage;
    pcpcs->cbSerialization = cbSize;
    pcpcs->rgbSerialization = (BYTE*)pLogon;
    pcpcs->clsidCredentialProvider = CLSID_WindowsGoodByeProvider;

    *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;

    // Clear sensitive data
    SecureZeroMemory((void*)_password.data(), _password.size() * sizeof(wchar_t));
    _password.clear();
    _authenticated = false;

    *ppszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_SUCCESS;

    return S_OK;
}

HRESULT WinGBCredential::ReportResult(NTSTATUS, NTSTATUS, LPWSTR* ppszOptionalStatusText,
                                        CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    *ppszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    return S_OK;
}
