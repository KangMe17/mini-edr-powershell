#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <amsi.h>
#include <unknwn.h>
#include <new>

#pragma comment(lib, "amsi.lib")

// {11111111-2222-3333-4444-555555555555}
static const CLSID CLSID_CustomAmsiProvider =
{ 0x11111111, 0x2222, 0x3333, { 0x44,0x44,0x55,0x55,0x55,0x55,0x55,0x55 } };

class CAmsiProvider : public IAntimalwareProvider
{
private:
    volatile ULONG m_refCount;

public:
    CAmsiProvider();
    virtual ~CAmsiProvider();

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv);
    ULONG STDMETHODCALLTYPE AddRef();
    ULONG STDMETHODCALLTYPE Release();

    // IAntimalwareProvider
    IFACEMETHODIMP Scan(IAmsiStream* stream, AMSI_RESULT* result);
    IFACEMETHODIMP_(void) CloseSession(ULONGLONG session);
    IFACEMETHODIMP DisplayName(LPWSTR* displayName);
};

// COM exports (cần khai báo trong .def hoặc dùng dllexport)
STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv);
STDAPI DllCanUnloadNow();