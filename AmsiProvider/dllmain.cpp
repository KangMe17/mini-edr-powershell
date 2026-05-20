#include "provider.h"

#include <windows.h>
#include <strsafe.h>
#include <bcrypt.h>
#include <new>

#pragma comment(linker, "/EXPORT:DllCanUnloadNow,PRIVATE")
#pragma comment(linker, "/EXPORT:DllGetClassObject,PRIVATE")
#pragma comment(linker, "/EXPORT:DllRegisterServer,PRIVATE")
#pragma comment(linker, "/EXPORT:DllUnregisterServer,PRIVATE")

#pragma comment(lib, "bcrypt.lib")

// ─────────────────────────── GLOBALS ──────────────────────────────────────

volatile LONG g_cRefModule = 0;
HMODULE g_hModule = NULL;

// [BUG-4] Single definition of g_tlsPipeIdx.  Extern declaration is in
//         provider_fixed.cpp so both TUs share the same variable.
DWORD g_tlsPipeIdx = TLS_OUT_OF_INDEXES;

// [BUG-8] Guard to prevent FreeTlsState from calling TlsGetValue after
//         TlsFree has already been issued.
static volatile LONG g_tlsFreed = 0;

// Forward declaration from provider_fixed.cpp
extern void FreeTlsState();


// ─────────────────────────── REGISTRY STRINGS ─────────────────────────────

static const char* CLSID_STRING = "{11111111-2222-3333-4444-555555555555}";
static const char* PROVIDER_NAME = "Mini EDR AMSI Provider";
static const char* PROG_ID = "MiniEDR.AmsiProvider";

// ─────────────────────────── REGISTRY HELPERS ─────────────────────────────

static HRESULT SetRegistryStringA(HKEY root, const char* subKey,
    const char* valueName, const char* data)
{
    HKEY hKey = NULL;
    LSTATUS status = RegCreateKeyExA(root, subKey, 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
    if (status != ERROR_SUCCESS) return HRESULT_FROM_WIN32(status);

    status = RegSetValueExA(hKey, valueName, 0, REG_SZ,
        reinterpret_cast<const BYTE*>(data),
        static_cast<DWORD>(strlen(data) + 1));
    RegCloseKey(hKey);

    return (status == ERROR_SUCCESS) ? S_OK : HRESULT_FROM_WIN32(status);
}

static HRESULT DeleteRegistryTreeA(HKEY root, const char* subKey)
{
    LSTATUS status = RegDeleteTreeA(root, subKey);
    if (status == ERROR_FILE_NOT_FOUND) return S_OK;
    return (status == ERROR_SUCCESS) ? S_OK : HRESULT_FROM_WIN32(status);
}

// ─────────────────────────── CLASS FACTORY ────────────────────────────────

static volatile LONG g_serverLocks = 0;

class CClassFactory final : public IClassFactory
{
public:
    ULONG STDMETHODCALLTYPE AddRef()  override { return 2; }
    ULONG STDMETHODCALLTYPE Release() override { return 1; }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv) return E_POINTER;
        if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IClassFactory))
        {
            *ppv = static_cast<IClassFactory*>(this);
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* pOuter, REFIID riid,
        void** ppv) override
    {
        if (!ppv)   return E_POINTER;
        if (pOuter) return CLASS_E_NOAGGREGATION;

        CAmsiProvider* p = new (std::nothrow) CAmsiProvider();
        if (!p) return E_OUTOFMEMORY;

        HRESULT hr = p->QueryInterface(riid, ppv);
        p->Release();
        return hr;
    }

    HRESULT STDMETHODCALLTYPE LockServer(BOOL lock) override
    {
        if (lock) InterlockedIncrement(&g_serverLocks);
        else      InterlockedDecrement(&g_serverLocks);
        return S_OK;
    }
};

static CClassFactory g_classFactory;

// ─────────────────────────── COM EXPORTS ──────────────────────────────────

// [BUG-2] Only defined here, not in provider_fixed.cpp.
STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv)
{
    if (!ppv) return E_POINTER;
    if (IsEqualCLSID(rclsid, CLSID_CustomAmsiProvider))
        return g_classFactory.QueryInterface(riid, ppv);
    *ppv = nullptr;
    return CLASS_E_CLASSNOTAVAILABLE;
}

STDAPI DllCanUnloadNow()
{
    LONG locks = InterlockedCompareExchange(&g_serverLocks, 0, 0);
    LONG refs = InterlockedCompareExchange(&g_cRefModule, 0, 0);

    return (locks == 0 && refs == 0) ? S_OK : S_FALSE;
}

// ─────────────────────────── REGISTRATION ─────────────────────────────────

STDAPI DllRegisterServer()
{
    if (!g_hModule) return E_FAIL;

    char modulePath[MAX_PATH] = { 0 };
    DWORD len = GetModuleFileNameA(g_hModule, modulePath, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return HRESULT_FROM_WIN32(GetLastError());

    char clsidKey[512], inprocKey[512], progIdKey[512], amsiProviderKey[512];
    StringCchPrintfA(clsidKey, ARRAYSIZE(clsidKey),
        "SOFTWARE\\Classes\\CLSID\\%s", CLSID_STRING);
    StringCchPrintfA(inprocKey, ARRAYSIZE(inprocKey),
        "SOFTWARE\\Classes\\CLSID\\%s\\InprocServer32", CLSID_STRING);
    StringCchPrintfA(progIdKey, ARRAYSIZE(progIdKey),
        "SOFTWARE\\Classes\\%s\\CLSID", PROG_ID);
    StringCchPrintfA(amsiProviderKey, ARRAYSIZE(amsiProviderKey),
        "SOFTWARE\\Microsoft\\AMSI\\Providers\\%s", CLSID_STRING);

    HRESULT hr;
    if (FAILED(hr = SetRegistryStringA(HKEY_LOCAL_MACHINE, clsidKey,
        NULL, PROVIDER_NAME))) return hr;
    if (FAILED(hr = SetRegistryStringA(HKEY_LOCAL_MACHINE, inprocKey,
        NULL, modulePath)))     return hr;
    if (FAILED(hr = SetRegistryStringA(HKEY_LOCAL_MACHINE, inprocKey,
        "ThreadingModel", "Both"))) return hr;
    if (FAILED(hr = SetRegistryStringA(HKEY_LOCAL_MACHINE, progIdKey,
        NULL, CLSID_STRING)))   return hr;
    if (FAILED(hr = SetRegistryStringA(HKEY_LOCAL_MACHINE, amsiProviderKey,
        NULL, PROVIDER_NAME)))  return hr;
    return S_OK;
}

STDAPI DllUnregisterServer()
{
    char clsidKey[512], progIdRoot[512], amsiProviderKey[512];
    StringCchPrintfA(clsidKey, ARRAYSIZE(clsidKey),
        "SOFTWARE\\Classes\\CLSID\\%s", CLSID_STRING);
    StringCchPrintfA(progIdRoot, ARRAYSIZE(progIdRoot),
        "SOFTWARE\\Classes\\%s", PROG_ID);
    StringCchPrintfA(amsiProviderKey, ARRAYSIZE(amsiProviderKey),
        "SOFTWARE\\Microsoft\\AMSI\\Providers\\%s", CLSID_STRING);

    HRESULT hr1 = DeleteRegistryTreeA(HKEY_LOCAL_MACHINE, amsiProviderKey);
    HRESULT hr2 = DeleteRegistryTreeA(HKEY_LOCAL_MACHINE, clsidKey);
    HRESULT hr3 = DeleteRegistryTreeA(HKEY_LOCAL_MACHINE, progIdRoot);

    if (FAILED(hr1)) return hr1;
    if (FAILED(hr2)) return hr2;
    if (FAILED(hr3)) return hr3;
    return S_OK;
}

// ─────────────────────────── DLL MAIN ─────────────────────────────────────

// [BUG-3] Only defined here, not in provider_fixed.cpp.
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID /*reserved*/)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        g_hModule = hModule;

        g_tlsPipeIdx = TlsAlloc();
        break;

    case DLL_THREAD_DETACH:
        if (!InterlockedCompareExchange(&g_tlsFreed, 0, 0))
            FreeTlsState();
        break;

    case DLL_PROCESS_DETACH:
        // [BUG-8] Mark TLS as freed BEFORE calling TlsFree so that any
        //         concurrent DLL_THREAD_DETACH paths skip FreeTlsState.
        InterlockedExchange(&g_tlsFreed, 1);

        FreeTlsState();   // clean up the loader thread's own TLS entry

        if (g_tlsPipeIdx != TLS_OUT_OF_INDEXES)
        {
            TlsFree(g_tlsPipeIdx);
            g_tlsPipeIdx = TLS_OUT_OF_INDEXES;
        }
        break;
    }
    return TRUE;
}