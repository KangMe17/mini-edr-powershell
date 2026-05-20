#define NOMINMAX

#include "provider.h"
#include "../Common/shared.h"
#include "../Common/detection_rules.h"

#include <windows.h>
#include <wincrypt.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <objbase.h>

#ifndef NT_SUCCESS
#  define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#include <string>
#include <unordered_map>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <algorithm>
#include <cctype>
#include <vector>
#include <list>
#include <chrono>
#include <atomic>
#include <new>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")   // [BUG-1]
#pragma comment(lib, "Ole32.lib")

// ─────────────────────────── CONSTANTS ────────────────────────────────────

static const size_t MAX_RECONSTRUCT_BUFFER = 16384;
static const size_t MAX_DEDUP_CACHE = 5000;
static const size_t MAX_ANALYSIS_CACHE = 4096;
static const size_t MAX_PROCESS_CONTEXT_CACHE = 2048;
static const size_t MAX_SESSION_BUFFERS = 1024;
static const int    SESSION_BUFFER_TTL_SEC = 60;
static const ULONGLONG ANALYSIS_CACHE_TTL_MS = 60000;
static const ULONGLONG PROCESS_CONTEXT_CACHE_TTL_MS = 10000;

static const DWORD  PIPE_CONNECT_WAIT_MS_MIN = 20;
static const DWORD  PIPE_CONNECT_WAIT_MS_MAX = 400;
static const int    PIPE_CONNECT_RETRIES = 4;
static const int    PIPE_THREAD_COOLDOWN_SEC = 5;
static const DWORD PIPE_WRITE_TIMEOUT_MS = 50;

static const bool ENABLE_AMSI_BLOCK = false;

static const char* SUSPICIOUS_PARENTS[] = {
    "winword.exe", "excel.exe", "powerpnt.exe",
    "outlook.exe",
    "acrord32.exe", "acrobat.exe",
    "chrome.exe", "firefox.exe", "msedge.exe",
    "mshta.exe", "wscript.exe", "cscript.exe",
    "regsvr32.exe", "rundll32.exe",
    nullptr
};

// ─────────────────────────── BCRYPT SHA-256 ───────────────────────────────

static BCRYPT_ALG_HANDLE g_providerSha256Alg = nullptr;
static std::once_flag g_providerShaInitOnce;

static void InitProviderSha256()
{
    BCryptOpenAlgorithmProvider(
        &g_providerSha256Alg,
        BCRYPT_SHA256_ALGORITHM,
        nullptr,
        0
    );
}

static std::string BCryptSHA256(const std::string& data)
{
    std::call_once(g_providerShaInitOnce, InitProviderSha256);

    if (!g_providerSha256Alg)
        return {};

    BCRYPT_HASH_HANDLE hHash = nullptr;

    if (!NT_SUCCESS(BCryptCreateHash(
        g_providerSha256Alg,
        &hHash,
        nullptr,
        0,
        nullptr,
        0,
        0)))
    {
        return {};
    }

    BCryptHashData(
        hHash,
        const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(data.data())),
        static_cast<ULONG>(data.size()),
        0
    );

    BYTE digest[32]{};

    if (!NT_SUCCESS(BCryptFinishHash(hHash, digest, sizeof(digest), 0)))
    {
        BCryptDestroyHash(hHash);
        return {};
    }

    BCryptDestroyHash(hHash);

    char hex[65]{};
    for (int i = 0; i < 32; ++i)
        sprintf_s(hex + i * 2, 3, "%02x", digest[i]);

    return hex;
}

// ─────────────────────────── LRU DEDUP CACHE ──────────────────────────────

class LruSet
{
public:
    explicit LruSet(size_t cap) : cap_(cap) {}

    bool ContainsOrAdd(const std::string& key)
    {
        if (key.empty()) return false;
        auto it = map_.find(key);
        if (it != map_.end())
        {
            list_.splice(list_.begin(), list_, it->second);
            it->second = list_.begin();
            return true;
        }
        list_.push_front(key);
        map_[key] = list_.begin();
        while (map_.size() > cap_)
        {
            map_.erase(list_.back());
            list_.pop_back();
        }
        return false;
    }

private:
    size_t cap_;
    std::list<std::string> list_;
    std::unordered_map<std::string, std::list<std::string>::iterator> map_;
};

static std::mutex g_hashLock;
static LruSet     g_seenLru(MAX_DEDUP_CACHE);

static bool IsDuplicateKey(const std::string& key)
{
    if (key.empty()) return false;
    std::lock_guard<std::mutex> lk(g_hashLock);
    return g_seenLru.ContainsOrAdd(key);
}

// ─────────────────────────── STRING UTILS ─────────────────────────────────

static std::string ToLower(const std::string& s)
{
    std::string o = s;
    std::transform(o.begin(), o.end(), o.begin(),
        [](unsigned char c) { return (char)std::tolower(c); });
    return o;
}

static std::string Compact(const std::string& s)
{
    std::string o;
    o.reserve(s.size());
    for (unsigned char c : s)
        if (!std::isspace(c)) o += (char)std::tolower(c);
    return o;
}

static bool IsSep(char c)
{
    return std::isspace((unsigned char)c) || c == '\0' || c == '"' ||
        c == '\'' || c == '`' || c == '=' || c == ':' || c == ';' ||
        c == ',' || c == '(' || c == ')' || c == '[' || c == ']';
}

static bool HasToken(const std::string& text, const std::string& tok)
{
    if (tok.empty()) return false;
    for (size_t p = text.find(tok); p != std::string::npos;
        p = text.find(tok, p + 1))
    {
        char b = (p == 0) ? '\0' : text[p - 1];
        char a = (p + tok.size() < text.size()) ? text[p + tok.size()] : '\0';
        if (IsSep(b) && IsSep(a)) return true;
    }
    return false;
}

static bool HasEncodedFlag(const std::string& script)
{
    std::string l = ToLower(script);
    return HasToken(l, "-encodedcommand") || HasToken(l, "/encodedcommand") ||
        HasToken(l, "-enc") || HasToken(l, "/enc");
}

static bool HasIex(const std::string& script)
{
    std::string l = ToLower(script);
    return HasToken(l, "invoke-expression") || HasToken(l, "iex");
}

static bool ProviderDebugEnabled()
{
    static int enabled = []() -> int {
        char value[16]{};
        DWORD n = GetEnvironmentVariableA("EDR_PROVIDER_DEBUG", value, sizeof(value));
        if (n == 0 || n >= sizeof(value))
            return 0;

        std::string v = ToLower(value);
        return (v == "1" || v == "true" || v == "yes" || v == "on") ? 1 : 0;
    }();

    return enabled != 0;
}

static void Dbg(const std::string& msg)
{
    if (!ProviderDebugEnabled())
        return;

    std::string line = "[MiniEDR Provider] " + msg + "\n";
    OutputDebugStringA(line.c_str());
}

// ─────────────────────────── NOISE FILTER ─────────────────────────────────

static bool IsPowerShellPromptHelpNoise(const std::string& s)
{
    std::string l = ToLower(s);

    bool hasPromptShape =
        l.find("$executioncontext.sessionstate.path.currentlocation") != std::string::npos ||
        l.find("$nestedpromptlevel") != std::string::npos ||
        l.find("ps $($executioncontext") != std::string::npos;

    bool hasHelpMetadata =
        l.find("# .link") != std::string::npos ||
        l.find("# .externalhelp") != std::string::npos ||
        l.find("system.management.automation.dll-help.xml") != std::string::npos;

    bool hasMicrosoftHelpLink =
        l.find("go.microsoft.com/fwlink") != std::string::npos ||
        l.find("linkid=") != std::string::npos;

    return hasPromptShape && hasHelpMetadata && hasMicrosoftHelpLink;
}

static bool IsPowerShellHelpMetadataNoise(const std::string& s)
{
    std::string l = ToLower(s);

    bool hasHelpMetadata =
        l.find("# .link") != std::string::npos ||
        l.find("# .externalhelp") != std::string::npos ||
        l.find("system.management.automation.dll-help.xml") != std::string::npos;

    bool hasMicrosoftHelpLink =
        l.find("go.microsoft.com/fwlink") != std::string::npos ||
        l.find("linkid=") != std::string::npos;

    bool hasPromptOrRawUiShape =
        l.find("$executioncontext.sessionstate.path.currentlocation") != std::string::npos ||
        l.find("$nestedpromptlevel") != std::string::npos ||
        l.find("$host.ui.rawui") != std::string::npos ||
        l.find("$rawui.setbuffercontents") != std::string::npos ||
        l.find("$rawui.cursorposition") != std::string::npos;

    return hasHelpMetadata && hasMicrosoftHelpLink && hasPromptOrRawUiShape;
}

static bool IsPowerShellNativeErrorFormattingNoise(const std::string& s)
{
    std::string l = ToLower(s);

    bool hasNativeErrorShape =
        l.find("nativecommanderrormessage") != std::string::npos &&
        l.find("fullyqualifiederrorid") != std::string::npos &&
        l.find("invocationinfo") != std::string::npos &&
        l.find("positionmessage") != std::string::npos;

    bool hasParserOrCategoryShape =
        l.find("categoryinfo") != std::string::npos ||
        l.find("parsererror") != std::string::npos ||
        l.find("mycommand") != std::string::npos;

    bool hasDangerousSignal =
        l.find("invoke-mimikatz") != std::string::npos ||
        l.find("mimikatz") != std::string::npos ||
        l.find("amsiutils") != std::string::npos ||
        l.find("set-mppreference") != std::string::npos ||
        l.find("downloadstring") != std::string::npos ||
        l.find("downloadfile") != std::string::npos ||
        HasToken(l, "iex") ||
        HasToken(l, "invoke-expression") ||
        l.find("virtualallocex") != std::string::npos ||
        l.find("writeprocessmemory") != std::string::npos ||
        l.find("createremotethread") != std::string::npos;

    return hasNativeErrorShape && hasParserOrCategoryShape && !hasDangerousSignal;
}

static bool IsNoise(const std::string& s)
{
    if (s.size() < 5)
        return true;

    if (IsPowerShellPromptHelpNoise(s))
        return true;

    if (IsPowerShellHelpMetadataNoise(s))
        return true;

    if (IsPowerShellNativeErrorFormattingNoise(s))
        return true;

    std::string l = ToLower(s);

    if (l == "get-history" || l == "clear-host" || l == "cls")
        return true;

    if (l == "prompt" || l == "out-default")
        return true;

    if (s.size() < 300 &&
        (l.find("psreadline") != std::string::npos ||
            l.find("psconsolehostreadline") != std::string::npos ||
            l.find("format-startdata") != std::string::npos))
    {
        return true;
    }

    std::string n = Compact(s);

    if (n.find("moduleversion") != std::string::npos &&
        n.find("cmdletstoexport") != std::string::npos &&
        n.find("guid") != std::string::npos &&
        n.find("microsoftcorporation") != std::string::npos)
    {
        return true;
    }

    return false;
}

// ─────────────────────────── SUSPICIOUS FRAGMENT DETECTOR ─────────────────

struct AnalysisCacheEntry
{
    LocalAnalysisResult result;
    ULONGLONG expiryTick = 0;
    size_t scriptLength = 0;
};

static std::mutex g_analysisCacheLock;
static std::list<std::string> g_analysisCacheLru;
static std::unordered_map<
    std::string,
    std::pair<AnalysisCacheEntry, std::list<std::string>::iterator>
> g_analysisCache;

static bool AnalysisCacheGet(const std::string& key, size_t scriptLength, LocalAnalysisResult& out)
{
    if (key.empty())
        return false;

    ULONGLONG now = GetTickCount64();
    std::lock_guard<std::mutex> lk(g_analysisCacheLock);

    auto it = g_analysisCache.find(key);
    if (it == g_analysisCache.end())
        return false;

    if (now >= it->second.first.expiryTick || it->second.first.scriptLength != scriptLength)
    {
        g_analysisCacheLru.erase(it->second.second);
        g_analysisCache.erase(it);
        return false;
    }

    g_analysisCacheLru.splice(g_analysisCacheLru.begin(), g_analysisCacheLru, it->second.second);
    it->second.second = g_analysisCacheLru.begin();
    out = it->second.first.result;
    return true;
}

static void AnalysisCachePut(const std::string& key, size_t scriptLength, const LocalAnalysisResult& result)
{
    if (key.empty())
        return;

    ULONGLONG now = GetTickCount64();
    std::lock_guard<std::mutex> lk(g_analysisCacheLock);

    auto it = g_analysisCache.find(key);
    if (it != g_analysisCache.end())
    {
        it->second.first.result = result;
        it->second.first.scriptLength = scriptLength;
        it->second.first.expiryTick = now + ANALYSIS_CACHE_TTL_MS;
        g_analysisCacheLru.splice(g_analysisCacheLru.begin(), g_analysisCacheLru, it->second.second);
        it->second.second = g_analysisCacheLru.begin();
        return;
    }

    g_analysisCacheLru.push_front(key);
    AnalysisCacheEntry entry;
    entry.result = result;
    entry.scriptLength = scriptLength;
    entry.expiryTick = now + ANALYSIS_CACHE_TTL_MS;
    g_analysisCache[key] = { entry, g_analysisCacheLru.begin() };

    while (g_analysisCache.size() > MAX_ANALYSIS_CACHE)
    {
        g_analysisCache.erase(g_analysisCacheLru.back());
        g_analysisCacheLru.pop_back();
    }
}

static LocalAnalysisResult AnalyzeWithCache(const std::string& script, std::string* hashOut = nullptr)
{
    std::string hash = BCryptSHA256(script);
    if (hashOut)
        *hashOut = hash;

    LocalAnalysisResult result;
    if (!hash.empty() && AnalysisCacheGet(hash, script.size(), result))
        return result;

    result = LocalAnalyze(script);

    if (!hash.empty())
        AnalysisCachePut(hash, script.size(), result);

    return result;
}

static bool IsSuspicious(const std::string& frag)
{
    LocalAnalysisResult r = AnalyzeWithCache(frag);
    return r.verdict != "ALLOW";
}

static bool ShouldResetBuffer(const std::string& frag)
{
    std::string n = Compact(frag);
    return n.find("invoke-") != std::string::npos ||
        HasIex(frag) ||
        HasEncodedFlag(frag) ||
        n.find("powershell") != std::string::npos ||
        n.find("pwsh") != std::string::npos;
}

// ─────────────────────────── SESSION RECONSTRUCT BUFFER ───────────────────

struct SessionKey
{
    DWORD     pid;
    ULONGLONG session;
    bool operator==(const SessionKey& o) const
    {
        return pid == o.pid && session == o.session;
    }
};

struct SessionKeyHash
{
    size_t operator()(const SessionKey& k) const
    {
        return std::hash<DWORD>{}(k.pid) ^
            (std::hash<ULONGLONG>{}(k.session) << 1);
    }
};

using TimePoint = std::chrono::steady_clock::time_point;

struct SessionEntry
{
    std::string buffer;
    TimePoint   lastSeen;
};

static std::unordered_map<SessionKey, SessionEntry, SessionKeyHash> g_sessions;
static std::map<TimePoint, std::vector<SessionKey>> g_sessionByTime;
static std::mutex g_sessionLock;

// Must be called with g_sessionLock held.
static void EvictExpiredLocked()
{
    auto cutoff = std::chrono::steady_clock::now() -
        std::chrono::seconds(SESSION_BUFFER_TTL_SEC);

    for (auto it = g_sessionByTime.begin();
        it != g_sessionByTime.end() && it->first < cutoff; )
    {
        for (const auto& k : it->second)
            g_sessions.erase(k);
        it = g_sessionByTime.erase(it);
    }

    while (g_sessions.size() > MAX_SESSION_BUFFERS)
    {
        if (g_sessionByTime.empty()) break;
        auto& oldest = g_sessionByTime.begin()->second;
        for (const auto& k : oldest) g_sessions.erase(k);
        g_sessionByTime.erase(g_sessionByTime.begin());
    }
}

// Must be called with g_sessionLock held.
static void TouchTimeLocked(const SessionKey& k, TimePoint oldTime,
    TimePoint newTime)
{
    if (oldTime != TimePoint{})
    {
        auto it = g_sessionByTime.find(oldTime);
        if (it != g_sessionByTime.end())
        {
            auto& vec = it->second;
            vec.erase(std::remove_if(vec.begin(), vec.end(),
                [&](const SessionKey& x) { return x == k; }),
                vec.end());
            if (vec.empty()) g_sessionByTime.erase(it);
        }
    }
    g_sessionByTime[newTime].push_back(k);
}

// [BUG-7] Split into locked/unlocked variants to avoid recursive mutex.
// Called WITHOUT g_sessionLock held.
static void CleanupSession(DWORD pid, ULONGLONG session)
{
    SessionKey k{ pid, session };
    std::lock_guard<std::mutex> lk(g_sessionLock);

    auto it = g_sessions.find(k);
    if (it == g_sessions.end()) return;

    auto t = it->second.lastSeen;
    g_sessions.erase(it);

    auto ti = g_sessionByTime.find(t);
    if (ti != g_sessionByTime.end())
    {
        auto& v = ti->second;
        v.erase(std::remove_if(v.begin(), v.end(),
            [&](const SessionKey& x) { return x == k; }), v.end());
        if (v.empty()) g_sessionByTime.erase(ti);
    }
}

// Called WITH g_sessionLock already held.
static void CleanupSessionLocked(DWORD pid, ULONGLONG session)
{
    SessionKey k{ pid, session };

    auto it = g_sessions.find(k);
    if (it == g_sessions.end()) return;

    auto t = it->second.lastSeen;
    g_sessions.erase(it);

    auto ti = g_sessionByTime.find(t);
    if (ti != g_sessionByTime.end())
    {
        auto& v = ti->second;
        v.erase(std::remove_if(v.begin(), v.end(),
            [&](const SessionKey& x) { return x == k; }), v.end());
        if (v.empty()) g_sessionByTime.erase(ti);
    }
}

static void SlidingAppend(std::string& buf, const std::string& frag)
{
    if (frag.empty()) return;
    if (frag.size() >= MAX_RECONSTRUCT_BUFFER)
    {
        buf = frag.substr(frag.size() - MAX_RECONSTRUCT_BUFFER);
        return;
    }
    size_t need = frag.size() + 1;
    if (buf.size() + need > MAX_RECONSTRUCT_BUFFER)
    {
        size_t keep = (MAX_RECONSTRUCT_BUFFER > need)
            ? MAX_RECONSTRUCT_BUFFER - need : 0;
        if (buf.size() > keep) buf.erase(0, buf.size() - keep);
    }
    if (!buf.empty()) buf += ' ';
    buf += frag;
}

// [BUG-7] IsSuspicious check is now done BEFORE acquiring g_sessionLock,
// avoiding the re-entrant CleanupSession -> lock pattern.
static std::string ReconstructScript(DWORD pid, ULONGLONG session,
    const std::string& frag)
{
    if (IsSuspicious(frag))
    {
        CleanupSession(pid, session);   // takes lock internally, safe here
        return frag;
    }

    SessionKey k{ pid, session };
    auto       now = std::chrono::steady_clock::now();

    std::lock_guard<std::mutex> lk(g_sessionLock);
    EvictExpiredLocked();

    auto it = g_sessions.find(k);
    TimePoint oldTime{};
    if (it != g_sessions.end()) oldTime = it->second.lastSeen;

    SessionEntry& e = g_sessions[k];
    if (ShouldResetBuffer(frag)) e.buffer.clear();
    SlidingAppend(e.buffer, frag);

    TouchTimeLocked(k, oldTime, now);
    e.lastSeen = now;

    return e.buffer;
}

// ─────────────────────────── BASE64 DECODE ────────────────────────────────

static bool LooksBase64(const std::string& tok)
{
    if (tok.size() < 20) return false;
    size_t v = 0;
    for (unsigned char c : tok)
        if (std::isalnum(c) || c == '+' || c == '/' || c == '=') v++;
    return (double)v / tok.size() > 0.90;
}

static bool HasBase64Indicator(const std::string& s)
{
    std::string n = Compact(s);
    return HasEncodedFlag(s) ||
        n.find("frombase64string") != std::string::npos ||
        n.find("system.convert") != std::string::npos;
}

static std::string ExtractBase64Token(const std::string& input)
{
    std::string best, cur;
    for (unsigned char c : input)
    {
        if (std::isalnum(c) || c == '+' || c == '/' || c == '=')
            cur += (char)c;
        else
        {
            if (cur.size() > best.size() && LooksBase64(cur)) best = cur;
            cur.clear();
        }
    }
    if (cur.size() > best.size() && LooksBase64(cur)) best = cur;
    return best;
}

static std::string DecodeBase64(const std::string& tok)
{
    if (tok.empty()) return {};
    DWORD len = 0;
    if (!CryptStringToBinaryA(tok.c_str(), 0, CRYPT_STRING_BASE64,
        nullptr, &len, nullptr, nullptr))
        return {};
    if (!len || len > MAX_SCRIPT_CHARS) return {};

    std::vector<BYTE> bytes(len);
    if (!CryptStringToBinaryA(tok.c_str(), 0, CRYPT_STRING_BASE64,
        bytes.data(), &len, nullptr, nullptr))
        return {};

    // Try UTF-16LE first (PowerShell -EncodedCommand).
    // [BUG-6] wLen must be byte_count / sizeof(wchar_t).
    int wLen = static_cast<int>(len / sizeof(wchar_t));
    int u8Len = WideCharToMultiByte(CP_UTF8, 0,
        reinterpret_cast<const wchar_t*>(bytes.data()),
        wLen, nullptr, 0, nullptr, nullptr);

    if (u8Len > 0)
    {
        std::string u8(u8Len, 0);
        WideCharToMultiByte(CP_UTF8, 0,
            reinterpret_cast<const wchar_t*>(bytes.data()),
            wLen, &u8[0], u8Len, nullptr, nullptr);

        // [BUG-6] Stricter guard: >60 % printable AND at least one alpha.
        int printable = 0, alpha = 0;
        for (unsigned char c : u8)
        {
            if (std::isprint(c)) printable++;
            if (std::isalpha(c)) alpha++;
        }
        if (printable > u8Len * 6 / 10 && alpha > 0)
            return u8;
    }

    // Fallback: raw ASCII/UTF-8.
    return { reinterpret_cast<char*>(bytes.data()), len };
}

static std::string TryDecodeBase64(const std::string& script)
{
    if (!HasBase64Indicator(script)) return script;
    std::string tok = ExtractBase64Token(script);
    if (tok.empty()) return script;
    std::string decoded = DecodeBase64(tok);
    if (decoded.empty()) return script;

    std::string combined = script + "\n[decoded_base64]\n" + decoded;
    if (combined.size() > MAX_SCRIPT_CHARS - 1)
        combined.resize(MAX_SCRIPT_CHARS - 1);
    return combined;
}

// ─────────────────────────── PROCESS HELPERS ──────────────────────────────

static DWORD GetParentPID(DWORD pid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe{ sizeof(pe) };
    DWORD parent = 0;
    if (Process32First(snap, &pe))
        do {
            if (pe.th32ProcessID == pid)
            {
                parent = pe.th32ParentProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));

    CloseHandle(snap);
    return parent;
}

static std::string GetProcName(DWORD pid)
{
    char name[MAX_PATH]{};
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
        FALSE, pid);
    if (h)
    {
        if (!GetModuleBaseNameA(h, nullptr, name, sizeof name))
        {
            DWORD sz = sizeof name;
            QueryFullProcessImageNameA(h, 0, name, &sz);
        }
        CloseHandle(h);
    }
    return name;
}

struct ProcessContext
{
    DWORD parentPid = 0;
    std::string processName;
    std::string parentName;
    ULONGLONG expiryTick = 0;
};

static std::unordered_map<DWORD, ProcessContext> g_processContextCache;
static std::mutex g_processContextCacheLock;

static std::string BaseNameLower(std::string path)
{
    std::replace(path.begin(), path.end(), '/', '\\');
    size_t pos = path.find_last_of('\\');
    if (pos != std::string::npos)
        path = path.substr(pos + 1);
    return ToLower(path);
}

static ProcessContext GetCachedProcessContext(DWORD pid)
{
    ULONGLONG now = GetTickCount64();

    {
        std::lock_guard<std::mutex> lk(g_processContextCacheLock);
        auto it = g_processContextCache.find(pid);
        if (it != g_processContextCache.end() && now < it->second.expiryTick)
            return it->second;
    }

    ProcessContext ctx;
    ctx.parentPid = GetParentPID(pid);
    ctx.processName = GetProcName(pid);
    ctx.parentName = ctx.parentPid ? GetProcName(ctx.parentPid) : "";
    ctx.expiryTick = now + PROCESS_CONTEXT_CACHE_TTL_MS;

    {
        std::lock_guard<std::mutex> lk(g_processContextCacheLock);
        if (g_processContextCache.size() > MAX_PROCESS_CONTEXT_CACHE)
            g_processContextCache.clear();
        g_processContextCache[pid] = ctx;
    }

    return ctx;
}

static bool IsSuspiciousParentName(const std::string& parent)
{
    std::string parentName = BaseNameLower(parent);
    if (parentName.empty())
        return false;

    for (auto p = SUSPICIOUS_PARENTS; *p; ++p)
    {
        if (parentName == *p)
            return true;
    }

    return false;
}

static bool LooksPrintableEnough(const std::string& s)
{
    if (s.empty())
        return false;

    int printable = 0;
    int useful = 0;

    for (unsigned char c : s)
    {
        if (std::isprint(c) || std::isspace(c))
            printable++;

        if (std::isalpha(c) || std::isdigit(c) ||
            c == '-' || c == '_' || c == '$' || c == '"' || c == '\'' ||
            c == '(' || c == ')' || c == '[' || c == ']' ||
            c == '{' || c == '}' || c == ':' || c == ';' ||
            c == '/' || c == '\\' || c == '.')
        {
            useful++;
        }
    }

    return printable > static_cast<int>(s.size()) / 2 && useful > 0;
}

static bool DecodeAmsiBytesToUtf8(const BYTE* data, ULONG size, std::string& out)
{
    out.clear();

    if (!data || size == 0)
        return false;

    ULONG cappedSize = size;
    ULONG maxBytes = static_cast<ULONG>(MAX_SCRIPT_CHARS * sizeof(wchar_t));

    if (cappedSize > maxBytes)
        cappedSize = maxBytes;

    // Try UTF-16LE first.
    if (cappedSize >= sizeof(wchar_t) && (cappedSize % sizeof(wchar_t)) == 0)
    {
        int wCount = static_cast<int>(cappedSize / sizeof(wchar_t));
        const wchar_t* ws = reinterpret_cast<const wchar_t*>(data);

        int u8Len = WideCharToMultiByte(
            CP_UTF8,
            0,
            ws,
            wCount,
            nullptr,
            0,
            nullptr,
            nullptr
        );

        if (u8Len > 0)
        {
            u8Len = std::min(u8Len, static_cast<int>(MAX_SCRIPT_CHARS - 1));

            std::string candidate(u8Len, 0);

            int written = WideCharToMultiByte(
                CP_UTF8,
                0,
                ws,
                wCount,
                &candidate[0],
                u8Len,
                nullptr,
                nullptr
            );

            if (written > 0)
            {
                if (written < u8Len)
                    candidate.resize(written);

                while (!candidate.empty() && candidate.back() == '\0')
                    candidate.pop_back();

                if (LooksPrintableEnough(candidate))
                {
                    out = candidate;
                    return true;
                }
            }
        }
    }

    // Fallback: raw bytes as UTF-8 / ASCII-ish.
    size_t rawLen = std::min<size_t>(cappedSize, MAX_SCRIPT_CHARS - 1);
    std::string candidate(reinterpret_cast<const char*>(data), rawLen);

    while (!candidate.empty() && candidate.back() == '\0')
        candidate.pop_back();

    if (!candidate.empty())
    {
        out = candidate;
        return true;
    }

    return false;
}

static bool GetScriptUtf8(IAmsiStream* stream, std::string& out)
{
    out.clear();

    if (!stream)
        return false;

    ULONGLONG contentSize64 = 0;
    ULONG sizeRet = 0;

    HRESULT hrSize = stream->GetAttribute(
        AMSI_ATTRIBUTE_CONTENT_SIZE,
        sizeof(contentSize64),
        reinterpret_cast<PBYTE>(&contentSize64),
        &sizeRet
    );

    if (FAILED(hrSize) || contentSize64 == 0)
    {
        Dbg("CONTENT_SIZE failed hr=" + std::to_string(hrSize) +
            " sizeRet=" + std::to_string(sizeRet));
        return false;
    }

    ULONGLONG maxBytes64 = static_cast<ULONGLONG>(MAX_SCRIPT_CHARS) * sizeof(wchar_t);

    if (contentSize64 > maxBytes64)
        contentSize64 = maxBytes64;

    ULONG readSize = static_cast<ULONG>(contentSize64);

    Dbg("CONTENT_SIZE OK bytes=" + std::to_string(readSize));

    // Method 1: Try AMSI_ATTRIBUTE_CONTENT_ADDRESS.
    PBYTE contentAddress = nullptr;
    ULONG addrRet = 0;

    HRESULT hrAddr = stream->GetAttribute(
        AMSI_ATTRIBUTE_CONTENT_ADDRESS,
        sizeof(contentAddress),
        reinterpret_cast<PBYTE>(&contentAddress),
        &addrRet
    );

    if (SUCCEEDED(hrAddr) && contentAddress)
    {
        if (DecodeAmsiBytesToUtf8(contentAddress, readSize, out))
        {
            Dbg("GetScriptUtf8 via CONTENT_ADDRESS OK len=" + std::to_string(out.size()));
            return true;
        }

        Dbg("CONTENT_ADDRESS decode failed");
    }
    else
    {
        Dbg("CONTENT_ADDRESS unavailable hr=" + std::to_string(hrAddr) +
            " addrRet=" + std::to_string(addrRet));
    }

    // Method 2: Fallback to IAmsiStream::Read().
    std::vector<BYTE> buffer(readSize);
    ULONG totalRead = 0;

    while (totalRead < readSize)
    {
        ULONG chunkRead = 0;
        ULONG remaining = readSize - totalRead;

        HRESULT hrRead = stream->Read(
            totalRead,
            remaining,
            buffer.data() + totalRead,
            &chunkRead
        );

        if (FAILED(hrRead))
        {
            Dbg("stream->Read failed hr=" + std::to_string(hrRead) +
                " totalRead=" + std::to_string(totalRead));
            break;
        }

        if (chunkRead == 0)
            break;

        totalRead += chunkRead;
    }

    if (totalRead == 0)
    {
        Dbg("stream->Read returned 0 bytes");
        return false;
    }

    if (DecodeAmsiBytesToUtf8(buffer.data(), totalRead, out))
    {
        Dbg("GetScriptUtf8 via Read OK len=" + std::to_string(out.size()));
        return true;
    }

    Dbg("Read decode failed totalRead=" + std::to_string(totalRead));
    return false;
}

// ─────────────────────────── PER-THREAD PIPE CONNECTION ───────────────────

struct ThreadPipeState
{
    HANDLE    handle = INVALID_HANDLE_VALUE;
    long long cooldownEnd = 0;
};

// Declared extern so DllMain in dllmain.cpp can TlsAlloc/TlsFree the slot.
// [BUG-4] Must NOT be defined in both TUs.
extern DWORD g_tlsPipeIdx;

static ThreadPipeState* GetTlsState()
{
    if (g_tlsPipeIdx == TLS_OUT_OF_INDEXES) return nullptr;
    auto* s = static_cast<ThreadPipeState*>(TlsGetValue(g_tlsPipeIdx));
    if (!s)
    {
        s = new ThreadPipeState();
        TlsSetValue(g_tlsPipeIdx, s);
    }
    return s;
}

// Non-static: called from dllmain.cpp in DLL_THREAD_DETACH / DLL_PROCESS_DETACH.
// Forward declaration: extern void FreeTlsState(); in dllmain_fixed.cpp.
void FreeTlsState()
{
    if (g_tlsPipeIdx == TLS_OUT_OF_INDEXES) return;
    auto* s = static_cast<ThreadPipeState*>(TlsGetValue(g_tlsPipeIdx));
    if (s)
    {
        if (s->handle != INVALID_HANDLE_VALUE) CloseHandle(s->handle);
        delete s;
        TlsSetValue(g_tlsPipeIdx, nullptr);
    }
}

static long long NowEpoch()
{
    return static_cast<long long>(std::time(nullptr));
}

static HANDLE GetThreadPipe()
{
    ThreadPipeState* ts = GetTlsState();
    if (!ts) return INVALID_HANDLE_VALUE;

    if (ts->handle != INVALID_HANDLE_VALUE) return ts->handle;
    if (NowEpoch() < ts->cooldownEnd)       return INVALID_HANDLE_VALUE;

    DWORD waitMs = PIPE_CONNECT_WAIT_MS_MIN;

    for (int attempt = 0; attempt < PIPE_CONNECT_RETRIES; ++attempt)
    {
        // [BUG-10] Pass the actual timeout (ms) to WaitNamedPipeA.
        if (!WaitNamedPipeA(EDR_PIPE_NAME, waitMs))
        {
            waitMs = std::min(waitMs * 2, PIPE_CONNECT_WAIT_MS_MAX);
            continue;
        }

        HANDLE h = CreateFileA(
            EDR_PIPE_NAME,
            GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            nullptr);

        if (h != INVALID_HANDLE_VALUE)
        {
            // [BUG-9] Do NOT set PIPE_READMODE_MESSAGE on a write-only handle.
            // The server already declared MESSAGE mode; this call would fail
            // silently and is not needed.
            ts->handle = h;
            return h;
        }

        DWORD err = GetLastError();
        if (err == ERROR_PIPE_BUSY)
        {
            waitMs = std::min(waitMs * 2, PIPE_CONNECT_WAIT_MS_MAX);
            Sleep(waitMs);
            continue;
        }
        break;  // unrecoverable
    }

    ts->cooldownEnd = NowEpoch() + PIPE_THREAD_COOLDOWN_SEC;
    return INVALID_HANDLE_VALUE;
}

static void ResetThreadPipe()
{
    ThreadPipeState* ts = GetTlsState();
    if (!ts) return;
    if (ts->handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(ts->handle);
        ts->handle = INVALID_HANDLE_VALUE;
    }
}

// ─────────────────────────── COM IMPLEMENTATION ───────────────────────────

extern volatile LONG g_cRefModule;

CAmsiProvider::CAmsiProvider()
    : m_refCount(1)
{
    InterlockedIncrement(&g_cRefModule);
}

CAmsiProvider::~CAmsiProvider()
{
    InterlockedDecrement(&g_cRefModule);
}

IFACEMETHODIMP CAmsiProvider::QueryInterface(REFIID riid, void** ppv)
{
    if (!ppv) return E_POINTER;
    if (riid == IID_IUnknown || riid == __uuidof(IAntimalwareProvider))
    {
        *ppv = static_cast<IAntimalwareProvider*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

ULONG CAmsiProvider::AddRef() { return InterlockedIncrement(&m_refCount); }
ULONG CAmsiProvider::Release()
{
    ULONG c = InterlockedDecrement(&m_refCount);
    if (!c) delete this;
    return c;
}

IFACEMETHODIMP CAmsiProvider::DisplayName(LPWSTR* name)
{
    if (!name) return E_POINTER;
    const wchar_t* n = L"Mini EDR AMSI Provider v4";
    size_t len = wcslen(n) + 1;
    *name = static_cast<LPWSTR>(CoTaskMemAlloc(len * sizeof(wchar_t)));
    if (!*name) return E_OUTOFMEMORY;
    wcscpy_s(*name, len, n);
    return S_OK;
}

void CAmsiProvider::CloseSession(ULONGLONG session)
{
    CleanupSession(GetCurrentProcessId(), session);
}

static bool WritePipeWithTimeout(HANDLE pipe,
    const ScanMessage& msg,
    DWORD timeoutMs,
    DWORD& writtenOut)
{
    writtenOut = 0;

    if (pipe == INVALID_HANDLE_VALUE)
        return false;

    OVERLAPPED ov{};
    ov.hEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);

    if (!ov.hEvent)
        return false;

    BOOL ok = WriteFile(
        pipe,
        &msg,
        sizeof(msg),
        nullptr,
        &ov);

    DWORD err = ok ? ERROR_SUCCESS : GetLastError();

    if (!ok && err != ERROR_IO_PENDING)
    {
        CloseHandle(ov.hEvent);
        SetLastError(err);
        return false;
    }

    if (err == ERROR_IO_PENDING)
    {
        DWORD wait = WaitForSingleObject(ov.hEvent, timeoutMs);

        if (wait != WAIT_OBJECT_0)
        {
            CancelIo(pipe);

            // Cho hệ thống một khoảng ngắn để hoàn tất cancel.
            WaitForSingleObject(ov.hEvent, 100);

            DWORD ignored = 0;
            GetOverlappedResult(pipe, &ov, &ignored, FALSE);

            CloseHandle(ov.hEvent);
            SetLastError(ERROR_TIMEOUT);
            return false;
        }
    }

    DWORD written = 0;

    if (!GetOverlappedResult(pipe, &ov, &written, FALSE))
    {
        DWORD finalErr = GetLastError();
        CloseHandle(ov.hEvent);
        SetLastError(finalErr);
        return false;
    }

    CloseHandle(ov.hEvent);

    writtenOut = written;
    return written == sizeof(msg);
}

// ─────────────────────────── SCAN ─────────────────────────────────────────

IFACEMETHODIMP CAmsiProvider::Scan(IAmsiStream* stream, AMSI_RESULT* result)
{
    Dbg("Scan called");

    if (!result)
    {
        Dbg("result is null");
        return E_POINTER;
    }

    *result = AMSI_RESULT_NOT_DETECTED;

    std::string script;
    if (!GetScriptUtf8(stream, script))
    {
        Dbg("GetScriptUtf8 failed");
        return S_OK;
    }

    Dbg("Script extracted len=" + std::to_string(script.size()) +
        " preview=" + script.substr(0, 160));

    DWORD pid = GetCurrentProcessId();
    ProcessContext procCtx = GetCachedProcessContext(pid);
    bool suspiciousParent = IsSuspiciousParentName(procCtx.parentName);

    LocalAnalysisResult preNoiseCheck = AnalyzeWithCache(script);
    bool suspiciousContent = preNoiseCheck.verdict != "ALLOW";

    if (!suspiciousContent && IsNoise(script) && !suspiciousParent)
    {
        Dbg("Noise skipped preview=" + script.substr(0, 160));
        return S_OK;
    }

    if (suspiciousContent)
    {
        Dbg("Suspicious content bypassed noise filter verdict=" +
            preNoiseCheck.verdict);
    }

    if (suspiciousParent)
    {
        Dbg("Suspicious parent detected, bypass noise filter");
    }

    ULONGLONG session = 0;
    ULONG sessionRet = 0;

    HRESULT sessionHr = stream->GetAttribute(
        AMSI_ATTRIBUTE_SESSION,
        sizeof(session),
        reinterpret_cast<PBYTE>(&session),
        &sessionRet);

    if (FAILED(sessionHr))
    {
        Dbg("AMSI_ATTRIBUTE_SESSION failed hr=" + std::to_string(sessionHr));
        session = 0;
    }

    script = ReconstructScript(pid, session, script);
    Dbg("After reconstruct len=" + std::to_string(script.size()) +
        " preview=" + script.substr(0, 160));

    script = TryDecodeBase64(script);

    if (script.empty())
    {
        Dbg("script empty after reconstruct/decode");
        return S_OK;
    }

    if (script.size() > MAX_SCRIPT_CHARS - 1)
        script.resize(MAX_SCRIPT_CHARS - 1);

    std::string hash;
    LocalAnalysisResult quickCheck = AnalyzeWithCache(script, &hash);

    Dbg("LocalAnalyze verdict=" + quickCheck.verdict +
        " score=" + std::to_string(quickCheck.score));

    if (ENABLE_AMSI_BLOCK && quickCheck.verdict == "TERMINATE")
    {
        std::string firstRule = quickCheck.ruleIds.empty() ? "" : quickCheck.ruleIds[0];

        Dbg("Blocking script via AMSI_RESULT_DETECTED rule=" + firstRule);

        *result = AMSI_RESULT_DETECTED;
    }

    Dbg("hash=" + hash);

    if (hash.empty())
    {
        Dbg("hash empty; dedup disabled for this event");
    }

    if (!hash.empty() && quickCheck.verdict == "ALLOW")
    {
        std::string dedupKey =
            std::to_string(pid) + "|" +
            std::to_string(session) + "|" +
            hash;

        if (IsDuplicateKey(dedupKey))
        {
            Dbg("duplicate benign skipped key=" + dedupKey);
            return S_OK;
        }
    }

    HANDLE pipe = GetThreadPipe();
    if (pipe == INVALID_HANDLE_VALUE)
    {
        Dbg("GetThreadPipe failed err=" + std::to_string(GetLastError()));
        return S_OK;
    }

    Dbg("GetThreadPipe OK");

    ScanMessage msg{};

    msg.pid = pid;
    msg.parentPid = procCtx.parentPid;

    std::string proc = procCtx.processName;
    std::string parent = procCtx.parentName;

    strncpy_s(msg.process, sizeof(msg.process), proc.c_str(), _TRUNCATE);
    strncpy_s(msg.parentProcess, sizeof(msg.parentProcess), parent.c_str(), _TRUNCATE);
    strncpy_s(msg.sha256, sizeof(msg.sha256), hash.c_str(), _TRUNCATE);
    strncpy_s(msg.script, sizeof(msg.script), script.c_str(), _TRUNCATE);

    DWORD written = 0;

    if (!WritePipeWithTimeout(pipe, msg, PIPE_WRITE_TIMEOUT_MS, written))
    {
        Dbg("WritePipeWithTimeout failed err=" + std::to_string(GetLastError()) +
            " written=" + std::to_string(written) +
            " expected=" + std::to_string(sizeof(msg)));

        ResetThreadPipe();
    }
    else
    {
        Dbg("WritePipeWithTimeout OK bytes=" + std::to_string(written));
    }

    return S_OK;
}
