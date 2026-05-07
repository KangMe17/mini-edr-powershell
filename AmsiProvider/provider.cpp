#include "provider.h"

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <objbase.h>

#include <string>
#include <unordered_set>
#include <unordered_map>
#include <mutex>
#include <algorithm>
#include <cctype>
#include <vector>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Ole32.lib")

#define PIPE_NAME "\\\\.\\pipe\\EdrAmsiPipe"

// =====================================================
// AMSI Provider - Mini EDR
// Stable Reconstruct v2
//
// Role:
// 1. Receive script content from AMSI Scan()
// 2. Convert script to UTF-8 safely
// 3. Filter trivial/noisy PowerShell fragments
// 4. Reconstruct fragmented script chunks per process only when needed
// 5. Send suspicious fragments directly to avoid PSReadLine/internal noise
// 6. Decode obvious Base64 payloads when possible
// 7. Hash + deduplicate scripts
// 8. Send telemetry to C++ Native AMSI Bridge Agent through Named Pipe
// =====================================================

// ================= STRUCT SHARED WITH C++ AGENT =================
#pragma pack(push, 1)
struct ScanMessage
{
    DWORD pid;
    DWORD parentPid;

    char process[260];
    char parentProcess[260];

    char sha256[65];
    char script[4096];
};
#pragma pack(pop)

// ================= GLOBAL =================
static HANDLE g_pipe = INVALID_HANDLE_VALUE;
static std::mutex g_pipeLock;

static std::unordered_set<std::string> g_seen;
static std::mutex g_hashLock;

static std::unordered_map<DWORD, std::string> g_buffers;
static std::mutex g_bufferLock;

static const size_t MAX_SCRIPT_CHARS = 4096;
static const size_t MAX_RECONSTRUCT_BUFFER = 4096;
static const size_t MAX_DEDUP_CACHE = 5000;
static const DWORD PIPE_WAIT_MS = 50;

// ================= UTILS =================
std::string ToLowerCopy(const std::string& input)
{
    std::string out = input;

    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
        });

    return out;
}

std::string RemoveWhitespaceLower(const std::string& input)
{
    std::string out;
    out.reserve(input.size());

    for (unsigned char c : input)
    {
        if (!std::isspace(c))
            out += static_cast<char>(std::tolower(c));
    }

    return out;
}

bool ContainsAny(const std::string& haystackLower, const std::vector<std::string>& needlesLower)
{
    for (const auto& n : needlesLower)
    {
        if (haystackLower.find(n) != std::string::npos)
            return true;
    }

    return false;
}

bool IsSeparator(char c)
{
    return std::isspace(static_cast<unsigned char>(c)) ||
        c == '\0' ||
        c == '"' ||
        c == '\'' ||
        c == '`' ||
        c == '=' ||
        c == ':' ||
        c == ';' ||
        c == ',' ||
        c == '(' ||
        c == ')' ||
        c == '[' ||
        c == ']';
}

bool ContainsToken(const std::string& text, const std::string& token)
{
    if (token.empty())
        return false;

    size_t pos = text.find(token);

    while (pos != std::string::npos)
    {
        char before = (pos == 0) ? '\0' : text[pos - 1];
        char after = (pos + token.size() >= text.size()) ? '\0' : text[pos + token.size()];

        if (IsSeparator(before) && IsSeparator(after))
            return true;

        pos = text.find(token, pos + 1);
    }

    return false;
}

bool ContainsPowerShellEncodedFlag(const std::string& script)
{
    std::string s = ToLowerCopy(script);

    if (ContainsToken(s, "-encodedcommand"))
        return true;

    if (ContainsToken(s, "/encodedcommand"))
        return true;

    if (ContainsToken(s, "-enc"))
        return true;

    if (ContainsToken(s, "/enc"))
        return true;

    if (ContainsToken(s, "-e"))
        return true;

    return false;
}

bool ContainsInvokeExpression(const std::string& script)
{
    std::string s = ToLowerCopy(script);

    if (ContainsToken(s, "invoke-expression"))
        return true;

    if (ContainsToken(s, "iex"))
        return true;

    return false;
}

// ================= COM =================
IFACEMETHODIMP CAmsiProvider::QueryInterface(REFIID riid, void** ppv)
{
    if (!ppv)
        return E_POINTER;

    if (riid == IID_IUnknown || riid == __uuidof(IAntimalwareProvider))
    {
        *ppv = static_cast<IAntimalwareProvider*>(this);
        AddRef();
        return S_OK;
    }

    *ppv = nullptr;
    return E_NOINTERFACE;
}

ULONG CAmsiProvider::AddRef()
{
    return InterlockedIncrement(&m_refCount);
}

ULONG CAmsiProvider::Release()
{
    ULONG count = InterlockedDecrement(&m_refCount);

    if (count == 0)
        delete this;

    return count;
}

IFACEMETHODIMP CAmsiProvider::DisplayName(LPWSTR* displayName)
{
    if (!displayName)
        return E_POINTER;

    const wchar_t* name = L"Mini EDR AMSI Provider";
    size_t len = wcslen(name) + 1;

    *displayName = static_cast<LPWSTR>(CoTaskMemAlloc(len * sizeof(wchar_t)));
    if (!*displayName)
        return E_OUTOFMEMORY;

    wcscpy_s(*displayName, len, name);
    return S_OK;
}

void CAmsiProvider::CloseSession(ULONGLONG session)
{
    UNREFERENCED_PARAMETER(session);
}

// ================= PIPE =================
HANDLE GetPipe()
{
    std::lock_guard<std::mutex> lock(g_pipeLock);

    if (g_pipe != INVALID_HANDLE_VALUE)
        return g_pipe;

    // Do not block AMSI Scan() for too long.
    if (!WaitNamedPipeA(PIPE_NAME, PIPE_WAIT_MS))
        return INVALID_HANDLE_VALUE;

    g_pipe = CreateFileA(
        PIPE_NAME,
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    return g_pipe;
}

void ResetPipe()
{
    std::lock_guard<std::mutex> lock(g_pipeLock);

    if (g_pipe != INVALID_HANDLE_VALUE)
    {
        CloseHandle(g_pipe);
        g_pipe = INVALID_HANDLE_VALUE;
    }
}

// ================= PROCESS =================
DWORD GetParentPID(DWORD pid)
{
    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    DWORD parent = 0;

    if (Process32First(snap, &pe))
    {
        do
        {
            if (pe.th32ProcessID == pid)
            {
                parent = pe.th32ParentProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return parent;
}

std::string GetProcessName(DWORD pid)
{
    char name[MAX_PATH] = { 0 };

    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    if (h)
    {
        if (!GetModuleBaseNameA(h, NULL, name, sizeof(name)))
        {
            DWORD size = sizeof(name);
            QueryFullProcessImageNameA(h, 0, name, &size);
        }

        CloseHandle(h);
    }

    return std::string(name);
}

// ================= HASH =================
std::string SHA256(const std::string& data)
{
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;

    BYTE buf[32] = { 0 };
    DWORD len = sizeof(buf);

    char hex[65] = { 0 };

    if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return "";

    if (!CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash))
    {
        CryptReleaseContext(prov, 0);
        return "";
    }

    if (!CryptHashData(hash, reinterpret_cast<const BYTE*>(data.data()), static_cast<DWORD>(data.size()), 0))
    {
        CryptDestroyHash(hash);
        CryptReleaseContext(prov, 0);
        return "";
    }

    if (!CryptGetHashParam(hash, HP_HASHVAL, buf, &len, 0))
    {
        CryptDestroyHash(hash);
        CryptReleaseContext(prov, 0);
        return "";
    }

    for (DWORD i = 0; i < len; i++)
        sprintf_s(hex + i * 2, 3, "%02x", buf[i]);

    CryptDestroyHash(hash);
    CryptReleaseContext(prov, 0);

    return std::string(hex);
}

// ================= FILTER =================
bool IsNoise(const std::string& s)
{
    std::string lower = ToLowerCopy(s);

    if (lower.length() < 5)
        return true;

    if (lower.find("prompt") != std::string::npos)
        return true;

    if (lower.find("out-default") != std::string::npos)
        return true;

    if (lower.find("format-startdata") != std::string::npos)
        return true;

    if (lower == "get-history" || lower == "clear-host" || lower == "cls")
        return true;

    // Filter normal Microsoft PowerShell module manifests.
    if (lower.find("moduleversion") != std::string::npos &&
        lower.find("cmdletstoexport") != std::string::npos &&
        lower.find("guid") != std::string::npos &&
        lower.find("microsoft corporation") != std::string::npos)
    {
        return true;
    }

    return false;
}

// ================= DUP =================
bool IsDuplicate(const std::string& hash)
{
    if (hash.empty())
        return false;

    std::lock_guard<std::mutex> lock(g_hashLock);

    if (g_seen.find(hash) != g_seen.end())
        return true;

    g_seen.insert(hash);

    if (g_seen.size() > MAX_DEDUP_CACHE)
        g_seen.clear();

    return false;
}

// ================= BUFFER / RECONSTRUCT =================
bool IsSuspiciousFragment(const std::string& fragment)
{
    std::string compact = RemoveWhitespaceLower(fragment);

    return ContainsInvokeExpression(fragment) ||
        ContainsPowerShellEncodedFlag(fragment) ||
        compact.find("frombase64string") != std::string::npos ||
        compact.find("downloadstring") != std::string::npos ||
        compact.find("downloadfile") != std::string::npos ||
        compact.find("invoke-webrequest") != std::string::npos ||
        compact.find("invoke-restmethod") != std::string::npos ||
        compact.find("new-objectnet.webclient") != std::string::npos ||
        compact.find("mimikatz") != std::string::npos ||
        compact.find("sekurlsa") != std::string::npos ||
        compact.find("logonpasswords") != std::string::npos ||
        compact.find("lsadump") != std::string::npos ||
        compact.find("amsiutils") != std::string::npos ||
        compact.find("amsiinitfailed") != std::string::npos ||
        compact.find("set-mppreference") != std::string::npos ||
        compact.find("disablerealtimemonitoring") != std::string::npos;
}

bool ShouldStartNewBuffer(const std::string& fragment)
{
    std::string compact = RemoveWhitespaceLower(fragment);

    return compact.find("invoke-") != std::string::npos ||
        ContainsInvokeExpression(fragment) ||
        compact.find("powershell") != std::string::npos ||
        compact.find("pwsh") != std::string::npos ||
        ContainsPowerShellEncodedFlag(fragment);
}

std::string ReconstructScript(DWORD pid, const std::string& fragment)
{
    std::lock_guard<std::mutex> lock(g_bufferLock);

    // Important:
    // If the current fragment is already suspicious, send it directly.
    // This prevents logs like:
    //   iex "..." + PSReadLine internal DebuggerHidden/CommandNotFound blocks
    // AMSI often emits many PowerShell internal fragments in the same PID, and
    // blindly concatenating them makes the telemetry noisy.
    if (IsSuspiciousFragment(fragment))
    {
        g_buffers[pid].clear();
        return fragment;
    }

    std::string& buf = g_buffers[pid];

    if (ShouldStartNewBuffer(fragment))
        buf.clear();

    if (buf.size() + fragment.size() + 1 > MAX_RECONSTRUCT_BUFFER)
        buf.clear();

    buf += fragment;
    buf += " ";

    return buf;
}

// ================= BASE64 =================
bool LooksLikeBase64Blob(const std::string& token)
{
    if (token.length() < 20)
        return false;

    size_t valid = 0;
    for (unsigned char c : token)
    {
        if (std::isalnum(c) || c == '+' || c == '/' || c == '=')
            valid++;
    }

    double ratio = static_cast<double>(valid) / static_cast<double>(token.length());
    return ratio > 0.90;
}

bool HasBase64Indicator(const std::string& s)
{
    std::string compact = RemoveWhitespaceLower(s);

    return ContainsPowerShellEncodedFlag(s) ||
        compact.find("frombase64string") != std::string::npos ||
        compact.find("convert]::frombase64string") != std::string::npos ||
        compact.find("system.convert") != std::string::npos;
}

std::string ExtractLikelyBase64Token(const std::string& input)
{
    std::string best;
    std::string cur;

    for (unsigned char c : input)
    {
        if (std::isalnum(c) || c == '+' || c == '/' || c == '=')
        {
            cur += static_cast<char>(c);
        }
        else
        {
            if (cur.length() > best.length() && LooksLikeBase64Blob(cur))
                best = cur;
            cur.clear();
        }
    }

    if (cur.length() > best.length() && LooksLikeBase64Blob(cur))
        best = cur;

    return best;
}

std::string BytesToUtf8FromUtf16LE(const BYTE* data, DWORD byteLen)
{
    if (!data || byteLen < 2)
        return "";

    int wcharCount = static_cast<int>(byteLen / sizeof(wchar_t));
    const wchar_t* wide = reinterpret_cast<const wchar_t*>(data);

    int utf8Len = WideCharToMultiByte(CP_UTF8, 0, wide, wcharCount, NULL, 0, NULL, NULL);
    if (utf8Len <= 0)
        return "";

    std::string out(utf8Len, 0);
    int written = WideCharToMultiByte(CP_UTF8, 0, wide, wcharCount, &out[0], utf8Len, NULL, NULL);

    if (written <= 0)
        return "";

    return out;
}

std::string DecodeBase64Token(const std::string& token)
{
    if (token.empty())
        return "";

    DWORD len = 0;

    if (!CryptStringToBinaryA(token.c_str(), 0, CRYPT_STRING_BASE64, NULL, &len, NULL, NULL))
        return "";

    if (len == 0 || len > 8192)
        return "";

    std::vector<BYTE> bytes(len);

    if (!CryptStringToBinaryA(token.c_str(), 0, CRYPT_STRING_BASE64, bytes.data(), &len, NULL, NULL))
        return "";

    // PowerShell -EncodedCommand uses UTF-16LE.
    std::string utf16Decoded = BytesToUtf8FromUtf16LE(bytes.data(), len);
    if (!utf16Decoded.empty())
        return utf16Decoded;

    // Fallback for normal ASCII/UTF-8 Base64 strings.
    return std::string(reinterpret_cast<char*>(bytes.data()), len);
}

std::string TryDecodeEmbeddedBase64(const std::string& script)
{
    if (!HasBase64Indicator(script))
        return script;

    std::string token = ExtractLikelyBase64Token(script);
    if (token.empty())
        return script;

    std::string decoded = DecodeBase64Token(token);
    if (decoded.empty())
        return script;

    std::string combined = script;
    combined += "\n[decoded_base64]\n";
    combined += decoded;

    if (combined.size() > MAX_SCRIPT_CHARS - 1)
        combined.resize(MAX_SCRIPT_CHARS - 1);

    return combined;
}

// ================= SCRIPT EXTRACTION =================
bool GetAmsiContentAsUtf8(IAmsiStream* stream, std::string& script)
{
    script.clear();

    if (!stream)
        return false;

    PBYTE content = NULL;
    ULONG actualSize = 0;

    HRESULT hr = stream->GetAttribute(
        AMSI_ATTRIBUTE_CONTENT_ADDRESS,
        sizeof(content),
        reinterpret_cast<PBYTE>(&content),
        &actualSize);

    if (FAILED(hr) || !content)
        return false;

    ULONG contentSize = 0;
    ULONG sizeRet = 0;

    hr = stream->GetAttribute(
        AMSI_ATTRIBUTE_CONTENT_SIZE,
        sizeof(contentSize),
        reinterpret_cast<PBYTE>(&contentSize),
        &sizeRet);

    if (FAILED(hr) || contentSize == 0 || contentSize > 8192)
        contentSize = static_cast<ULONG>(wcsnlen_s(reinterpret_cast<wchar_t*>(content), MAX_SCRIPT_CHARS) * sizeof(wchar_t));

    if (contentSize < sizeof(wchar_t))
        return false;

    size_t wcharCount = contentSize / sizeof(wchar_t);
    if (wcharCount > MAX_SCRIPT_CHARS)
        wcharCount = MAX_SCRIPT_CHARS;

    wchar_t* wscript = reinterpret_cast<wchar_t*>(content);

    if (wcharCount < 3)
        return false;

    int utf8Len = WideCharToMultiByte(
        CP_UTF8,
        0,
        wscript,
        static_cast<int>(wcharCount),
        NULL,
        0,
        NULL,
        NULL);

    if (utf8Len <= 0)
        return false;

    if (utf8Len > static_cast<int>(MAX_SCRIPT_CHARS - 1))
        utf8Len = static_cast<int>(MAX_SCRIPT_CHARS - 1);

    std::string out(utf8Len, 0);

    int written = WideCharToMultiByte(
        CP_UTF8,
        0,
        wscript,
        static_cast<int>(wcharCount),
        &out[0],
        utf8Len,
        NULL,
        NULL);

    if (written <= 0)
        return false;

    if (written < utf8Len)
        out.resize(written);

    while (!out.empty() && out.back() == '\0')
        out.pop_back();

    script = out;
    return true;
}

// ================= SCAN =================
IFACEMETHODIMP CAmsiProvider::Scan(IAmsiStream* stream, AMSI_RESULT* result)
{
    if (!result)
        return E_POINTER;

    // Current version works as telemetry + near-real-time response.
    // Synchronous AMSI blocking will require verdict feedback from the Agent.
    *result = AMSI_RESULT_NOT_DETECTED;

    std::string script;
    if (!GetAmsiContentAsUtf8(stream, script))
        return S_OK;

    if (IsNoise(script))
        return S_OK;

    DWORD pid = GetCurrentProcessId();

    script = ReconstructScript(pid, script);
    script = TryDecodeEmbeddedBase64(script);

    if (script.empty())
        return S_OK;

    if (script.size() > MAX_SCRIPT_CHARS - 1)
        script.resize(MAX_SCRIPT_CHARS - 1);

    std::string hash = SHA256(script);

    if (IsDuplicate(hash))
        return S_OK;

    HANDLE pipe = GetPipe();
    if (pipe == INVALID_HANDLE_VALUE)
        return S_OK;

    ScanMessage msg{};

    msg.pid = pid;
    msg.parentPid = GetParentPID(pid);

    std::string proc = GetProcessName(pid);
    std::string parent = GetProcessName(msg.parentPid);

    strncpy_s(msg.process, sizeof(msg.process), proc.c_str(), _TRUNCATE);
    strncpy_s(msg.parentProcess, sizeof(msg.parentProcess), parent.c_str(), _TRUNCATE);
    strncpy_s(msg.sha256, sizeof(msg.sha256), hash.c_str(), _TRUNCATE);
    strncpy_s(msg.script, sizeof(msg.script), script.c_str(), _TRUNCATE);

    DWORD written = 0;
    BOOL ok = WriteFile(pipe, &msg, sizeof(msg), &written, NULL);

    if (!ok || written != sizeof(msg))
        ResetPipe();

    return S_OK;
}
