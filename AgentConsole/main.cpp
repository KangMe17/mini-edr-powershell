#define NOMINMAX   // prevent windows.h from defining min/max macros

#include "../Common/detection_rules.h"
#include "../Common/shared.h"

#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <sddl.h>
#include <tlhelp32.h>
#ifndef NT_SUCCESS
#  define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#include <iostream>
#include <fstream>
#include <string>
#include <deque>
#include <vector>
#include <list>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <unordered_map>
#include <atomic>
#include <chrono>
#include <ctime>
#include <cctype>
#include <sstream>
#include <algorithm>
#include <cassert>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

// ─────────────────────────── CONFIGURATION ────────────────────────────────

static const wchar_t* TELEMETRY_HOST = L"127.0.0.1";
static const INTERNET_PORT TELEMETRY_PORT = 9001;
static const wchar_t* TELEMETRY_PATH = L"/telemetry";

static const bool TERMINATE_ON_HIGH_CONFIDENCE = false;
static const bool ENABLE_PYTHON_FORWARD = true;
static const bool FORWARD_ALLOW_EVENTS = false;
static const bool LOG_ALLOW_EVENTS = false;

static const size_t MAX_CACHE_SIZE = 5000;
static const int    VERDICT_CACHE_TTL_SECONDS = 300;
static const int    PYTHON_FAILURE_COOLDOWN_SEC = 10;
static const char* LOG_FILE = "edr_cpp_agent.log";

static const size_t MAX_QUEUE_SIZE = 4096;
static const size_t QUEUE_DROP_LOG_EVERY = 100;

// Worker pool: min 2, max 8, otherwise hardware_concurrency
static const unsigned int WORKER_MIN = 2;
static const unsigned int WORKER_MAX = 8;

// SDDL: pipe owner gets full control; everyone else is denied.
// D:  = DACL  P  = protected
// (A;;GRGW;;;WD) would be too open – we deliberately restrict to creator only.
static const wchar_t* PIPE_SDDL =
L"D:P(A;;GRGWGX;;;SY)(A;;GRGWGX;;;BA)";   // adjust to your deployment security policy

// ─────────────────────────── PIPE STATE MACHINE ───────────────────────────

enum class PipeState : DWORD
{
    Connecting = 0,   // Waiting for a client to connect
    Reading = 1,   // Waiting for ReadFile to complete
    Idle = 2,   // Connected but not currently reading (shouldn't linger)
};

struct PipeInstance
{
    OVERLAPPED   ov{};          // Must be first – cast trick for IOCP
    HANDLE       hPipe = INVALID_HANDLE_VALUE;
    ScanMessage  msg{};
    DWORD        bytesRead = 0;
    PipeState    state = PipeState::Connecting;
    DWORD        instanceId = 0;
};

// ─────────────────────────── GLOBALS ──────────────────────────────────────

static std::deque<ScanMessage>  g_queue;
static std::mutex               g_queueMutex;
static std::condition_variable  g_queueCv;
static std::atomic<uint64_t>    g_droppedQueueEvents{ 0 };

struct VerdictCacheEntry
{
    LocalAnalysisResult result;
    std::chrono::steady_clock::time_point expiresAt;
};

static std::list<std::string>     g_verdictCacheLru;
static std::unordered_map<
    std::string,
    std::pair<VerdictCacheEntry, std::list<std::string>::iterator>
> g_verdictCache;
static std::mutex                 g_cacheMutex;

static std::mutex                 g_logMutex;
static std::atomic<bool>          g_running{ true };
static std::atomic<long long>     g_nextPythonRetryEpoch{ 0 };

// IOCP handle shared between I/O loop and shutdown signalling
static HANDLE g_iocp = INVALID_HANDLE_VALUE;
static PSECURITY_DESCRIPTOR g_pSD = nullptr;
// Sentinel completion key used to wake the I/O loop on shutdown
static const ULONG_PTR IOCP_SHUTDOWN_KEY = (ULONG_PTR)(-1);

struct Stats
{
    std::atomic<uint64_t> totalScanned{ 0 };
    std::atomic<uint64_t> totalAllow{ 0 };
    std::atomic<uint64_t> totalAlert{ 0 };
    std::atomic<uint64_t> totalTerminate{ 0 };
    std::atomic<uint64_t> totalKilled{ 0 };
    std::atomic<uint64_t> cacheHits{ 0 };
    std::atomic<uint64_t> cacheMisses{ 0 };
    std::atomic<uint64_t> pyForwardOk{ 0 };
    std::atomic<uint64_t> pyForwardFail{ 0 };
};

static Stats g_stats;

// ─────────────────────────── UTILITIES ────────────────────────────────────

static long long NowEpoch()
{
    return static_cast<long long>(std::time(nullptr));
}

static std::string NowString()
{
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    tm lt{};
    localtime_s(&lt, &t);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &lt);
    return buf;
}

static void Log(const std::string& msg)
{
    std::lock_guard<std::mutex> lk(g_logMutex);
    std::string line = "[" + NowString() + "] " + msg;
    std::cout << line << "\n";
    if (std::ofstream out(LOG_FILE, std::ios::app); out)
        out << line << "\n";
}

static std::string SafeStr(const char* buf, size_t maxLen)
{
    if (!buf || !maxLen) return {};
    size_t n = strnlen_s(buf, maxLen);
    return { buf, n };
}

static std::string ToLower(const std::string& s)
{
    std::string o = s;
    std::transform(o.begin(), o.end(), o.begin(),
        [](unsigned char c) { return (char)std::tolower(c); });
    return o;
}

static std::string BaseNameLower(std::string path)
{
    std::replace(path.begin(), path.end(), '/', '\\');

    size_t pos = path.find_last_of('\\');
    if (pos != std::string::npos)
        path = path.substr(pos + 1);

    return ToLower(path);
}

static std::string Normalize(const std::string& s)
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
    for (size_t p = text.find(tok); p != std::string::npos; p = text.find(tok, p + 1))
    {
        char b = (p == 0) ? '\0' : text[p - 1];
        char a = (p + tok.size() < text.size()) ? text[p + tok.size()] : '\0';
        if (IsSep(b) && IsSep(a)) return true;
    }
    return false;
}

static std::string EscapeJson(const std::string& s)
{
    std::ostringstream o;
    for (unsigned char c : s)
    {
        switch (c)
        {
        case '"':  o << "\\\""; break;
        case '\\': o << "\\\\"; break;
        case '\b': o << "\\b";  break;
        case '\f': o << "\\f";  break;
        case '\n': o << "\\n";  break;
        case '\r': o << "\\r";  break;
        case '\t': o << "\\t";  break;
        default:
            if (c < 0x20) { char h[8]; sprintf_s(h, "\\u%04x", c); o << h; }
            else { o << c; }
        }
    }
    return o.str();
}

static std::string JsonArray(const std::vector<std::string>& v)
{
    std::string j = "[";
    for (size_t i = 0; i < v.size(); ++i)
    {
        if (i) j += ',';
        j += '"'; j += EscapeJson(v[i]); j += '"';
    }
    j += ']';
    return j;
}

static std::string Truncate(const std::string& s, size_t n = 700)
{
    return s.size() <= n ? s : s.substr(0, n) + " ...[truncated]";
}

static std::string CacheKey(const std::string& sha, const std::string& proc,
    const std::string& parent)
{
    if (sha.empty()) return {};
    return sha + "|" + ToLower(proc) + "|" + ToLower(parent);
}

// ─────────────────────────── SHA-256 (BCrypt) ─────────────────────────────
//
// BCrypt is thread-safe when each call uses its own hash handle.
// Algorithm handle (g_sha256Alg) can be shared read-only after opening.

static BCRYPT_ALG_HANDLE g_sha256Alg = nullptr;

static bool InitBCrypt()
{
    NTSTATUS s = BCryptOpenAlgorithmProvider(
        &g_sha256Alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    return NT_SUCCESS(s);
}

static std::string BCryptSHA256(const std::string& data)
{
    if (!g_sha256Alg) return {};

    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS s = BCryptCreateHash(g_sha256Alg, &hHash, nullptr, 0,
        nullptr, 0, 0);
    if (!NT_SUCCESS(s)) return {};

    BCryptHashData(hHash,
        const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(data.data())),
        static_cast<ULONG>(data.size()), 0);

    BYTE digest[32]{};
    BCryptFinishHash(hHash, digest, sizeof(digest), 0);
    BCryptDestroyHash(hHash);

    char hex[65]{};
    for (int i = 0; i < 32; ++i)
        sprintf_s(hex + i * 2, 3, "%02x", digest[i]);
    return hex;
}

static DWORD GetParentPID(DWORD pid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);

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

static std::string GetProcName(DWORD pid)
{
    if (!pid)
        return {};

    char path[MAX_PATH]{};

    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h)
        return {};

    DWORD size = static_cast<DWORD>(sizeof(path));

    if (!QueryFullProcessImageNameA(h, 0, path, &size))
    {
        CloseHandle(h);
        return {};
    }

    CloseHandle(h);
    return BaseNameLower(path);
}

static void EnrichScanMessageFromClient(ScanMessage& m, DWORD clientPid)
{
    m.pid = clientPid;
    m.parentPid = GetParentPID(clientPid);

    std::string proc = GetProcName(clientPid);
    std::string parent = GetProcName(m.parentPid);

    std::string script = SafeStr(m.script, sizeof m.script);
    std::string sha = BCryptSHA256(script);

    strncpy_s(m.process, sizeof(m.process), proc.c_str(), _TRUNCATE);
    strncpy_s(m.parentProcess, sizeof(m.parentProcess), parent.c_str(), _TRUNCATE);
    strncpy_s(m.sha256, sizeof(m.sha256), sha.c_str(), _TRUNCATE);
}

// ─────────────────────────── VERDICT CACHE (LRU + TTL) ────────────────────

static bool CacheGet(const std::string& key, LocalAnalysisResult& out)
{
    if (key.empty()) return false;
    std::lock_guard<std::mutex> lk(g_cacheMutex);

    auto it = g_verdictCache.find(key);
    if (it == g_verdictCache.end()) return false;

    if (std::chrono::steady_clock::now() >= it->second.first.expiresAt)
    {
        g_verdictCacheLru.erase(it->second.second);
        g_verdictCache.erase(it);
        return false;
    }

    // Move to front (MRU)
    g_verdictCacheLru.splice(g_verdictCacheLru.begin(),
        g_verdictCacheLru, it->second.second);
    it->second.second = g_verdictCacheLru.begin();
    out = it->second.first.result;
    return true;
}

static void CachePut(const std::string& key, const LocalAnalysisResult& r)
{
    if (key.empty()) return;
    std::lock_guard<std::mutex> lk(g_cacheMutex);

    auto exp = std::chrono::steady_clock::now() +
        std::chrono::seconds(VERDICT_CACHE_TTL_SECONDS);

    auto it = g_verdictCache.find(key);
    if (it != g_verdictCache.end())
    {
        it->second.first.result = r;
        it->second.first.expiresAt = exp;
        g_verdictCacheLru.splice(g_verdictCacheLru.begin(),
            g_verdictCacheLru, it->second.second);
        it->second.second = g_verdictCacheLru.begin();
        return;
    }

    g_verdictCacheLru.push_front(key);
    VerdictCacheEntry e;
    e.result = r;
    e.expiresAt = exp;
    g_verdictCache[key] = { e, g_verdictCacheLru.begin() };

    while (g_verdictCache.size() > MAX_CACHE_SIZE)
    {
        g_verdictCache.erase(g_verdictCacheLru.back());
        g_verdictCacheLru.pop_back();
    }
}

// ─────────────────────────── PROCESS CONTROL ──────────────────────────────

static bool ProcAlive(DWORD pid)
{
    if (!pid) return false;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    DWORD code = 0;
    bool alive = GetExitCodeProcess(h, &code) && code == STILL_ACTIVE;
    CloseHandle(h);
    return alive;
}

static bool KillProc(DWORD pid, const std::string& proc, const std::string& parent,
    const std::string& sha, const std::string& verdict,
    const std::string& script, const std::string& src)
{
    if (!pid || pid == GetCurrentProcessId()) return false;

    Log("[AUDIT] Terminate attempt src=" + src +
        " pid=" + std::to_string(pid) + " proc=" + proc +
        " parent=" + parent + " verdict=" + verdict +
        " sha256=" + sha + " preview=\"" + Truncate(script, 300) + "\"");

    if (!ProcAlive(pid))
    {
        Log("[AUDIT] Skip – process already exited. pid=" + std::to_string(pid));
        return false;
    }

    HANDLE h = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE, pid);
    if (!h)
    {
        Log("[ERROR] OpenProcess failed pid=" + std::to_string(pid) +
            " err=" + std::to_string(GetLastError()));
        return false;
    }

    DWORD code = 0;
    if (GetExitCodeProcess(h, &code) && code != STILL_ACTIVE)
    {
        CloseHandle(h);
        return false;
    }

    BOOL ok = TerminateProcess(h, 1);
    DWORD err = GetLastError();
    CloseHandle(h);

    if (!ok)
    {
        Log("[ERROR] TerminateProcess failed pid=" + std::to_string(pid) +
            " err=" + std::to_string(err));
        return false;
    }
    ++g_stats.totalKilled;

    Log("[ACTION] Terminated. pid=" + std::to_string(pid) + " proc=" + proc +
        " verdict=" + verdict + " sha256=" + sha);
    return true;
}

// ─────────────────────────── HTTP / TELEMETRY ─────────────────────────────

static bool PyInCooldown() { return NowEpoch() < g_nextPythonRetryEpoch.load(); }
static void SetPyCooldown()
{
    g_nextPythonRetryEpoch.store(NowEpoch() + PYTHON_FAILURE_COOLDOWN_SEC);
}

static std::string BuildJson(const ScanMessage& m, const LocalAnalysisResult& a)
{
    std::string proc = SafeStr(m.process, sizeof m.process);
    std::string parent = SafeStr(m.parentProcess, sizeof m.parentProcess);
    std::string sha = SafeStr(m.sha256, sizeof m.sha256);
    std::string script = SafeStr(m.script, sizeof m.script);

    std::string j = "{";
    j += "\"source\":\"amsi_cpp_bridge\","
        "\"agent_version\":\"cpp_bridge_v4\","
        "\"sensor_type\":\"amsi\","
        "\"received_at\":\"" + EscapeJson(NowString()) + "\","
        "\"pid\":" + std::to_string(m.pid) + ","
        "\"ppid\":" + std::to_string(m.parentPid) + ","
        "\"process\":\"" + EscapeJson(proc) + "\","
        "\"parent_process\":\"" + EscapeJson(parent) + "\","
        "\"sha256\":\"" + EscapeJson(sha) + "\","
        "\"script_length\":" + std::to_string(script.size()) + ","
        "\"local_verdict\":\"" + EscapeJson(a.verdict) + "\","
        "\"local_score\":" + std::to_string(a.score) + ","
        "\"local_rule_ids\":" + JsonArray(a.ruleIds) + ","
        "\"local_reasons\":" + JsonArray(a.reasons) + ","
        "\"script\":\"" + EscapeJson(script) + "\"}";
    return j;
}

static bool HttpPost(const wchar_t* host, INTERNET_PORT port,
    const wchar_t* path, const std::string& body,
    std::string& resp)
{
    resp.clear();
    HINTERNET hS = WinHttpOpen(L"EDR-CppAgent/3.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hS) return false;
    WinHttpSetTimeouts(hS, 700, 700, 700, 1200);

    HINTERNET hC = WinHttpConnect(hS, host, port, 0);
    if (!hC) { WinHttpCloseHandle(hS); return false; }

    HINTERNET hR = WinHttpOpenRequest(hC, L"POST", path, nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hR) { WinHttpCloseHandle(hC); WinHttpCloseHandle(hS); return false; }

    BOOL ok = WinHttpSendRequest(hR, L"Content-Type: application/json\r\n",
        (DWORD)-1L,
        (LPVOID)body.c_str(), (DWORD)body.size(),
        (DWORD)body.size(), 0);
    if (!ok || !WinHttpReceiveResponse(hR, nullptr))
    {
        WinHttpCloseHandle(hR); WinHttpCloseHandle(hC); WinHttpCloseHandle(hS);
        return false;
    }

    DWORD sc = 0, scLen = sizeof sc;
    WinHttpQueryHeaders(hR,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &sc, &scLen, WINHTTP_NO_HEADER_INDEX);

    char buf[2048]; DWORD br = 0;
    while (WinHttpReadData(hR, buf, sizeof buf, &br) && br)
    {
        resp.append(buf, br); br = 0;
    }

    WinHttpCloseHandle(hR); WinHttpCloseHandle(hC); WinHttpCloseHandle(hS);
    return sc >= 200 && sc < 300;
}

static std::string ParseVerdict(const std::string& resp)
{
    // Minimal JSON field extractor for "verdict"
    auto pos = resp.find("\"verdict\"");
    if (pos == std::string::npos) return "ALLOW";
    auto colon = resp.find(':', pos);
    if (colon == std::string::npos) return "ALLOW";
    auto q1 = resp.find('"', colon + 1);
    if (q1 == std::string::npos) return "ALLOW";
    auto q2 = resp.find('"', q1 + 1);
    if (q2 == std::string::npos) return "ALLOW";
    std::string v = ToLower(resp.substr(q1 + 1, q2 - q1 - 1));
    if (v == "terminate") return "TERMINATE";
    if (v == "alert")     return "ALERT";
    return "ALLOW";
}

static std::string ForwardToPython(const ScanMessage& m,
    const LocalAnalysisResult& a)
{
    if (!ENABLE_PYTHON_FORWARD || PyInCooldown()) return "ALLOW";

    std::string resp;
    if (!HttpPost(TELEMETRY_HOST, TELEMETRY_PORT, TELEMETRY_PATH,
        BuildJson(m, a), resp))
    {
        ++g_stats.pyForwardFail;

        Log("[WARN] Python Agent unreachable. Cooldown " +
            std::to_string(PYTHON_FAILURE_COOLDOWN_SEC) + "s.");
        SetPyCooldown();
        return "ALLOW";
    }
    ++g_stats.pyForwardOk;

    Log("[FORWARD] Telemetry OK. resp=" + resp);
    return ParseVerdict(resp);
}

static void PrintStats()
{
    uint64_t hits = g_stats.cacheHits.load();
    uint64_t misses = g_stats.cacheMisses.load();
    uint64_t totalCache = hits + misses;

    Log("========================================");
    Log("[STATS] total_scanned=" + std::to_string(g_stats.totalScanned.load()));

    Log("[STATS] allow=" + std::to_string(g_stats.totalAllow.load()) +
        " alert=" + std::to_string(g_stats.totalAlert.load()) +
        " terminate=" + std::to_string(g_stats.totalTerminate.load()));

    Log("[STATS] killed=" + std::to_string(g_stats.totalKilled.load()));

    Log("[STATS] cache_hits=" + std::to_string(hits) +
        " cache_misses=" + std::to_string(misses));

    if (totalCache > 0)
    {
        double hitRate = static_cast<double>(hits) * 100.0 /
            static_cast<double>(totalCache);

        Log("[STATS] cache_hit_rate=" + std::to_string(hitRate) + "%");
    }

    Log("[STATS] py_forward_ok=" + std::to_string(g_stats.pyForwardOk.load()) +
        " py_forward_fail=" + std::to_string(g_stats.pyForwardFail.load()));

    Log("[STATS] queue_dropped=" + std::to_string(g_droppedQueueEvents.load()));
}

// ─────────────────────────── WORK QUEUE ───────────────────────────────────

static void Enqueue(const ScanMessage& m)
{
    bool dropped = false;
    uint64_t cnt = 0;
    {
        std::lock_guard<std::mutex> lk(g_queueMutex);
        if (g_queue.size() >= MAX_QUEUE_SIZE)
        {
            g_queue.pop_front();
            cnt = ++g_droppedQueueEvents;
            dropped = true;
        }
        g_queue.push_back(m);
    }
    if (dropped && (cnt == 1 || cnt % QUEUE_DROP_LOG_EVERY == 0))
        Log("[QUEUE] Full – dropped oldest event. total_dropped=" + std::to_string(cnt));
    g_queueCv.notify_one();
}

// ─────────────────────────── WORKER POOL ──────────────────────────────────

static void WorkerThread()
{
    while (true)
    {
        ScanMessage m{};
        {
            std::unique_lock<std::mutex> lk(g_queueMutex);
            g_queueCv.wait(lk, [] { return !g_queue.empty() || !g_running.load(); });
            if (!g_running && g_queue.empty()) return;
            m = g_queue.front();
            g_queue.pop_front();
        }

        std::string script = SafeStr(m.script, sizeof m.script);
        std::string proc = SafeStr(m.process, sizeof m.process);
        std::string parent = SafeStr(m.parentProcess, sizeof m.parentProcess);

        if (script.empty() || DR_IsBenignNoise(script))
            continue;

        std::string sha = BCryptSHA256(script);

        if (sha.empty())
        {
            Log("[WARN] Agent failed to compute SHA-256; using provider hash as fallback.");
            sha = SafeStr(m.sha256, sizeof m.sha256);
        }

        if (sha.empty())
        {
            sha = "sha256_unavailable";
        }

        strncpy_s(m.sha256, sizeof(m.sha256), sha.c_str(), _TRUNCATE);

        ++g_stats.totalScanned;

        std::string key = CacheKey(sha, proc, parent);
        LocalAnalysisResult analysis;

        if (CacheGet(key, analysis))
        {
            ++g_stats.cacheHits;

            if (LOG_ALLOW_EVENTS || analysis.verdict != "ALLOW")
                Log("[CACHE HIT] hash=" + sha + " verdict=" + analysis.verdict);
        }
        else
        {
            ++g_stats.cacheMisses;

            analysis = LocalAnalyze(script);
            CachePut(key, analysis);
        }

        if (analysis.verdict == "TERMINATE")
            ++g_stats.totalTerminate;
        else if (analysis.verdict == "ALERT")
            ++g_stats.totalAlert;
        else
            ++g_stats.totalAllow;

        bool doLog = analysis.verdict != "ALLOW" || LOG_ALLOW_EVENTS;
        bool doForward = analysis.verdict != "ALLOW" || FORWARD_ALLOW_EVENTS;

        if (doLog)
        {
            Log("========================================");
            Log("[AMSI] pid=" + std::to_string(m.pid) +
                " ppid=" + std::to_string(m.parentPid) +
                " proc=" + proc + " parent=" + parent);
            Log("[SHA256] " + sha);
            Log("[VERDICT] " + analysis.verdict);
            Log("[SCORE] " + std::to_string(analysis.score));

            if (!analysis.ruleIds.empty())
                Log("[RULES]  " + JsonArray(analysis.ruleIds));

            if (!analysis.reasons.empty())
                Log("[REASON] " + JsonArray(analysis.reasons));

            Log("[SCRIPT] " + Truncate(script));
        }

        bool killed = false;
        if (analysis.verdict == "TERMINATE" && TERMINATE_ON_HIGH_CONFIDENCE)
            killed = KillProc(m.pid, proc, parent, sha,
                analysis.verdict, script, "local_rule");

        if (doForward)
        {
            std::string rv = ForwardToPython(m, analysis);
            if (doLog) Log("[PYTHON] verdict=" + rv);
            if (rv == "TERMINATE" && TERMINATE_ON_HIGH_CONFIDENCE && !killed)
                KillProc(m.pid, proc, parent, sha, rv, script, "python_agent");
        }
    }
}

// ─────────────────────────── PIPE HELPERS ─────────────────────────────────

static SECURITY_ATTRIBUTES* BuildPipeSecurity()
{
    static SECURITY_ATTRIBUTES sa{};

    if (g_pSD)
    {
        sa.nLength = sizeof(sa);
        sa.lpSecurityDescriptor = g_pSD;
        sa.bInheritHandle = FALSE;
        return &sa;
    }

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        PIPE_SDDL,
        SDDL_REVISION_1,
        &g_pSD,
        nullptr))
    {
        Log("[WARN] ConvertStringSecurityDescriptor failed err=" +
            std::to_string(GetLastError()) +
            "; using default pipe security.");
        return nullptr;
    }

    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = g_pSD;
    sa.bInheritHandle = FALSE;
    return &sa;
}

static void PostConnectCompletion(PipeInstance* pi)
{
    PostQueuedCompletionStatus(
        g_iocp,
        0,
        reinterpret_cast<ULONG_PTR>(pi),
        &pi->ov
    );
}

// Create one pipe instance in overlapped mode and post initial ConnectNamedPipe
static PipeInstance* CreatePipeInstance(DWORD id, SECURITY_ATTRIBUTES* pSA)
{
    auto* pi = new PipeInstance();
    pi->instanceId = id;

    pi->hPipe = CreateNamedPipeA(
        EDR_PIPE_NAME,
        PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        EDR_PIPE_MAX_INSTANCES,
        sizeof(ScanMessage),
        sizeof(ScanMessage),
        0,
        pSA);

    if (pi->hPipe == INVALID_HANDLE_VALUE)
    {
        Log("[ERROR] CreateNamedPipe #" + std::to_string(id) +
            " failed err=" + std::to_string(GetLastError()));
        delete pi;
        return nullptr;
    }

    // Associate with IOCP – completion key = pointer to PipeInstance
    if (!CreateIoCompletionPort(pi->hPipe, g_iocp,
        reinterpret_cast<ULONG_PTR>(pi), 0))
    {
        Log("[ERROR] CreateIoCompletionPort #" + std::to_string(id) +
            " err=" + std::to_string(GetLastError()));
        CloseHandle(pi->hPipe);
        delete pi;
        return nullptr;
    }

    // Begin async connect

    ZeroMemory(&pi->ov, sizeof(pi->ov));
    pi->state = PipeState::Connecting;

    BOOL ok = ConnectNamedPipe(pi->hPipe, &pi->ov);
    DWORD err = ok ? ERROR_SUCCESS : GetLastError();

    if (ok)
    {
        PostConnectCompletion(pi);
    }
    else
    {
        if (err == ERROR_IO_PENDING)
        {
            // Normal async path.
        }
        else if (err == ERROR_PIPE_CONNECTED)
        {
            PostConnectCompletion(pi);
        }
        else
        {
            Log("[ERROR] ConnectNamedPipe #" + std::to_string(id) +
                " err=" + std::to_string(err));
            CloseHandle(pi->hPipe);
            delete pi;
            return nullptr;
        }
    }

    return pi;
}

// Post an async ReadFile on a connected instance
static void BeginRead(PipeInstance* pi)
{
    ZeroMemory(&pi->ov, sizeof(pi->ov));
    ZeroMemory(&pi->msg, sizeof(pi->msg));
    pi->bytesRead = 0;
    pi->state = PipeState::Reading;

    BOOL ok = ReadFile(pi->hPipe, &pi->msg, sizeof(pi->msg),
        nullptr, &pi->ov);
    DWORD err = GetLastError();

    if (!ok && err != ERROR_IO_PENDING)
    {
        Log("[PIPE] ReadFile failed on instance #" + std::to_string(pi->instanceId) +
            " err=" + std::to_string(err) + "; resetting.");
        DisconnectNamedPipe(pi->hPipe);

        // Re-post a connect so the slot is reused
        ZeroMemory(&pi->ov, sizeof(pi->ov));
        pi->state = PipeState::Connecting;

        BOOL cok = ConnectNamedPipe(pi->hPipe, &pi->ov);
        DWORD cerr = cok ? ERROR_SUCCESS : GetLastError();

        if (cok)
        {
            PostConnectCompletion(pi);
        }
        else if (cerr == ERROR_PIPE_CONNECTED)
        {
            PostConnectCompletion(pi);
        }
        else if (cerr != ERROR_IO_PENDING)
        {
            Log("[PIPE] Reconnect after read failure failed on instance #" +
                std::to_string(pi->instanceId) +
                " err=" + std::to_string(cerr));
        }
    }
}

// Reset a pipe instance back to listening state after client disconnect
static void RecyclePipeInstance(PipeInstance* pi)
{
    DisconnectNamedPipe(pi->hPipe);
    ZeroMemory(&pi->ov, sizeof(pi->ov));
    pi->state = PipeState::Connecting;

    BOOL ok = ConnectNamedPipe(pi->hPipe, &pi->ov);
    DWORD err = ok ? ERROR_SUCCESS : GetLastError();

    if (ok)
    {
        PostConnectCompletion(pi);
    }
    else
    {
        if (err == ERROR_PIPE_CONNECTED)
        {
            PostConnectCompletion(pi);
        }
        else if (err != ERROR_IO_PENDING)
        {
            Log("[ERROR] RecyclePipeInstance ConnectNamedPipe err=" +
                std::to_string(err));
        }
    }
}

// ─────────────────────────── I/O COMPLETION LOOP ──────────────────────────

static void IoCompletionLoop(std::vector<PipeInstance*>& instances)
{
    Log("[PIPE] I/O completion loop started. Instances=" +
        std::to_string(instances.size()));

    while (true)
    {
        DWORD      bytesXfer = 0;
        ULONG_PTR  key = 0;
        OVERLAPPED* pOv = nullptr;

        // Timeout 500 ms so we can check g_running periodically
        BOOL ok = GetQueuedCompletionStatus(g_iocp, &bytesXfer, &key, &pOv, 500);

        if (!g_running) break;

        if (key == IOCP_SHUTDOWN_KEY) break;

        if (!ok)
        {
            DWORD err = GetLastError();
            if (err == WAIT_TIMEOUT) continue;  // normal poll timeout

            if (pOv)
            {
                // I/O on a specific pipe instance failed (e.g. client crashed)
                auto* pi = reinterpret_cast<PipeInstance*>(key);
                if (pi)
                {
                    Log("[PIPE] I/O error on instance #" +
                        std::to_string(pi->instanceId) +
                        " err=" + std::to_string(err) + "; recycling.");
                    RecyclePipeInstance(pi);
                }
            }
            continue;
        }

        if (!pOv || !key) continue;

        auto* pi = reinterpret_cast<PipeInstance*>(key);

        switch (pi->state)
        {
        case PipeState::Connecting:
            // Client just connected → start reading
            Log("[PIPE] Client connected on instance #" +
                std::to_string(pi->instanceId));
            BeginRead(pi);
            break;

        case PipeState::Reading:
        {
            pi->bytesRead = bytesXfer;

            if (pi->bytesRead != sizeof(ScanMessage))
            {
                Log("[WARN] Bad ScanMessage size=" + std::to_string(pi->bytesRead) +
                    " on instance #" + std::to_string(pi->instanceId));
                // Don't disconnect – provider might send another message
                BeginRead(pi);
                break;
            }

            ULONG clientPid = 0;

            if (!GetNamedPipeClientProcessId(pi->hPipe, &clientPid) || clientPid == 0)
            {
                Log("[SECURITY] Cannot verify named pipe client PID. Dropping message. err=" +
                    std::to_string(GetLastError()));
                BeginRead(pi);
                break;
            }

            if (pi->msg.pid != 0 && pi->msg.pid != clientPid)
            {
                Log("[SECURITY] Spoofed ScanMessage dropped. claimed_pid=" +
                    std::to_string(pi->msg.pid) +
                    " real_pid=" + std::to_string(clientPid));
                BeginRead(pi);
                break;
            }

            EnrichScanMessageFromClient(pi->msg, static_cast<DWORD>(clientPid));

            Enqueue(pi->msg);

            BeginRead(pi);
            break;
        }

        default:
            RecyclePipeInstance(pi);
            break;
        }
    }

    for (auto* pi : instances)
    {
        CancelIo(pi->hPipe);
        DisconnectNamedPipe(pi->hPipe);
        CloseHandle(pi->hPipe);
        delete pi;
    }
    instances.clear();
}

// ─────────────────────────── SHUTDOWN ─────────────────────────────────────

static BOOL WINAPI CtrlHandler(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT ||
        type == CTRL_CLOSE_EVENT)
    {
        Log("[EDR] Shutdown requested.");
        g_running = false;
        // Wake up I/O loop
        PostQueuedCompletionStatus(g_iocp, 0, IOCP_SHUTDOWN_KEY, nullptr);
        // Wake up worker pool
        g_queueCv.notify_all();
        return TRUE;
    }
    return FALSE;
}

// ─────────────────────────── MAIN ─────────────────────────────────────────

int main()
{
    if (!InitBCrypt())
    {
        std::cerr << "[FATAL] BCryptOpenAlgorithmProvider failed.\n";
        return 1;
    }

    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    Log("========================================");
    Log("   EDR Native AMSI Bridge Agent v3");
    Log("========================================");
    Log("[EDR] Pipe   : " EDR_PIPE_NAME);
    Log("[EDR] Forward: http://127.0.0.1:9001/telemetry");
    Log("[EDR] Policy : forward ALERT/TERMINATE only; suppress benign PS noise.");

    // ── Create IOCP ───────────────────────────────────────────────────────
    g_iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
    if (g_iocp == INVALID_HANDLE_VALUE)
    {
        Log("[FATAL] CreateIoCompletionPort failed err=" +
            std::to_string(GetLastError()));
        return 1;
    }

    // ── Create pipe instances ─────────────────────────────────────────────
    SECURITY_ATTRIBUTES* pSA = BuildPipeSecurity();
    std::vector<PipeInstance*> instances;

    for (DWORD i = 0; i < EDR_PIPE_MAX_INSTANCES; ++i)
    {
        auto* pi = CreatePipeInstance(i, pSA);
        if (pi) instances.push_back(pi);
    }

    if (instances.empty())
    {
        Log("[FATAL] No pipe instances could be created.");
        CloseHandle(g_iocp);
        return 1;
    }

    Log("[PIPE] " + std::to_string(instances.size()) + " instances listening.");

    // ── Worker thread pool ────────────────────────────────────────────────
    unsigned int nWorkers =
        std::max(WORKER_MIN,
            std::min(WORKER_MAX, std::thread::hardware_concurrency()));
    Log("[POOL] Starting " + std::to_string(nWorkers) + " worker threads.");

    std::vector<std::thread> workers;
    workers.reserve(nWorkers);
    for (unsigned int i = 0; i < nWorkers; ++i)
        workers.emplace_back(WorkerThread);

    // ── I/O completion loop (blocks until shutdown) ───────────────────────
    IoCompletionLoop(instances);

    // ── Shutdown ──────────────────────────────────────────────────────────
    g_running = false;
    g_queueCv.notify_all();

    for (auto& t : workers)
        if (t.joinable()) t.join();

    if (g_iocp != INVALID_HANDLE_VALUE) CloseHandle(g_iocp);
    if (g_sha256Alg) BCryptCloseAlgorithmProvider(g_sha256Alg, 0);

    if (g_pSD)
    {
        LocalFree(g_pSD);
        g_pSD = nullptr;
    }

    PrintStats();

    Log("[EDR] Agent stopped cleanly.");
    return 0;
}
