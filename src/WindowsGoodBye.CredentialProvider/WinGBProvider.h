/*
 * WindowsGoodBye Credential Provider
 *
 * Minimal Windows Credential Provider that communicates with the
 * WindowsGoodBye.Service via named pipe to unlock the PC when
 * an Android device authenticates via fingerprint.
 *
 * Based on Microsoft's Credential Provider V2 Sample.
 */

#pragma once

#include <windows.h>
#include <initguid.h>
#include <credentialprovider.h>
#include <ntsecapi.h>
#include <string>
#include "guid.h"
#include "helpers.h"

#pragma comment(lib, "secur32.lib")

// Define CPFG_ GUIDs not present in older SDK headers
// {2d837775-f6cd-464e-a745-482fd0b47493}
static const GUID CPFG_CREDENTIAL_PROVIDER_LOGO_LOCAL =
    { 0x2d837775, 0xf6cd, 0x464e, { 0xa7, 0x45, 0x48, 0x2f, 0xd0, 0xb4, 0x74, 0x93 } };

// Forward declarations
class WinGBCredential;

// Field IDs for our credential tile
enum WINGB_FIELD_ID
{
    WINGB_FID_ICON = 0,
    WINGB_FID_LARGE_TEXT = 1,
    WINGB_FID_SMALL_TEXT = 2,
    WINGB_FID_SUBMIT = 3,
    WINGB_FID_NUM_FIELDS = 4,
};

// Field descriptors (use GUID_NULL for fields without standard mapping)
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgFieldDescriptors[] =
{
    { WINGB_FID_ICON,       CPFT_TILE_IMAGE,    L"Icon",           CPFG_CREDENTIAL_PROVIDER_LOGO_LOCAL },
    { WINGB_FID_LARGE_TEXT,  CPFT_LARGE_TEXT,    L"WindowsGoodBye", GUID_NULL },
    { WINGB_FID_SMALL_TEXT,  CPFT_SMALL_TEXT,    L"Status",         GUID_NULL },
    { WINGB_FID_SUBMIT,     CPFT_SUBMIT_BUTTON, L"Submit",         GUID_NULL },
};

//----------------------------------------------------------------------
// WinGBCredential - The credential tile shown on the lock screen
//----------------------------------------------------------------------
class WinGBCredential : public IConnectableCredentialProviderCredential
{
public:
    WinGBCredential();
    virtual ~WinGBCredential();

    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef() override;
    IFACEMETHODIMP_(ULONG) Release() override;
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override;

    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* pcpce) override;
    IFACEMETHODIMP UnAdvise() override;
    IFACEMETHODIMP SetSelected(BOOL* pbAutoLogon) override;
    IFACEMETHODIMP SetDeselected() override;
    IFACEMETHODIMP GetFieldState(DWORD dwFieldID, CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
                                  CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis) override;
    IFACEMETHODIMP GetStringValue(DWORD dwFieldID, LPWSTR* ppsz) override;
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp) override;
    IFACEMETHODIMP GetCheckboxValue(DWORD, BOOL*, LPWSTR*) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetComboBoxValueCount(DWORD, DWORD*, DWORD*) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetComboBoxValueAt(DWORD, DWORD, LPWSTR*) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo) override;
    IFACEMETHODIMP SetStringValue(DWORD, LPCWSTR) override { return E_NOTIMPL; }
    IFACEMETHODIMP SetCheckboxValue(DWORD, BOOL) override { return E_NOTIMPL; }
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD, DWORD) override { return E_NOTIMPL; }
    IFACEMETHODIMP CommandLinkClicked(DWORD) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
                                     CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
                                     LPWSTR* ppszOptionalStatusText,
                                     CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) override;
    IFACEMETHODIMP ReportResult(NTSTATUS ntsStatus, NTSTATUS ntsSubstatus,
                                 LPWSTR* ppszOptionalStatusText,
                                 CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) override;

    // IConnectableCredentialProviderCredential
    IFACEMETHODIMP Connect(IQueryContinueWithStatus* pqcws) override;
    IFACEMETHODIMP Disconnect() override;

    void SetUsage(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus) { _cpus = cpus; }

private:
    LONG _cRef = 1;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO _cpus = CPUS_INVALID;
    ICredentialProviderCredentialEvents* _pCredProvCredentialEvents = nullptr;

    // Auth result from the service
    std::wstring _domain;
    std::wstring _username;
    std::wstring _password;
    bool _authenticated = false;
    HANDLE _hPipe = INVALID_HANDLE_VALUE;
};

//----------------------------------------------------------------------
// WinGBProvider - The credential provider
//----------------------------------------------------------------------
class WinGBProvider : public ICredentialProvider
{
public:
    WinGBProvider();
    virtual ~WinGBProvider();

    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef() override;
    IFACEMETHODIMP_(ULONG) Release() override;
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override;

    // ICredentialProvider
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags) override;
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs) override;
    IFACEMETHODIMP Advise(ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext) override;
    IFACEMETHODIMP UnAdvise() override;
    IFACEMETHODIMP GetFieldDescriptorCount(DWORD* pdwCount) override;
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd) override;
    IFACEMETHODIMP GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAutoLogonWithDefault) override;
    IFACEMETHODIMP GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc) override;

private:
    LONG _cRef = 1;
    WinGBCredential* _pCredential = nullptr;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO _cpus = CPUS_INVALID;
};

//----------------------------------------------------------------------
// ClassFactory
//----------------------------------------------------------------------
class WinGBClassFactory : public IClassFactory
{
public:
    WinGBClassFactory() : _cRef(1) {}

    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&_cRef); }
    IFACEMETHODIMP_(ULONG) Release() override
    {
        LONG cRef = InterlockedDecrement(&_cRef);
        if (!cRef) delete this;
        return cRef;
    }
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override
    {
        if (riid == IID_IClassFactory || riid == IID_IUnknown)
        {
            *ppv = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    // IClassFactory
    IFACEMETHODIMP CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv) override
    {
        if (pUnkOuter) return CLASS_E_NOAGGREGATION;
        auto* pProvider = new(std::nothrow) WinGBProvider();
        if (!pProvider) return E_OUTOFMEMORY;
        HRESULT hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
        return hr;
    }
    IFACEMETHODIMP LockServer(BOOL) override { return S_OK; }

private:
    LONG _cRef;
};
