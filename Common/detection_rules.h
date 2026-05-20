#pragma once
// ═══════════════════════════════════════════════════════════════════════════
//  detection_rules.h  –  EDR Local IOA Engine  (v4)
//
//  Tách riêng khỏi main.cpp để dễ maintain và unit-test.
//  Mỗi rule có:
//    - ID  (format: CATEGORY-SUBCATEGORY-NNN)
//    - Confidence  (HIGH → TERMINATE, MED → ALERT, LOW → log only)
//    - Lý do mô tả tiếng Anh (dùng trong log / telemetry)
//
//  Quy tắc ưu tiên:
//    1. Một rule trả HIGH → dừng, TERMINATE ngay.
//    2. Tổng điểm MED ≥ 2 → nâng lên TERMINATE.
//    3. Bất kỳ MED → ALERT.
//    4. Không match → ALLOW.
// ═══════════════════════════════════════════════════════════════════════════

#include <string>
#include <vector>
#include <algorithm>
#include <cctype>

// ─────────────────────────── FORWARD DECLS ────────────────────────────────

struct LocalAnalysisResult
{
    std::string              verdict = "ALLOW";  // ALLOW | ALERT | TERMINATE
    std::vector<std::string> ruleIds;
    std::vector<std::string> reasons;
    int                      score = 0;        // tổng điểm MED rules
};

// ─────────────────────────── STRING HELPERS ───────────────────────────────

static inline std::string DR_ToLower(const std::string& s)
{
    std::string o = s;
    std::transform(o.begin(), o.end(), o.begin(),
        [](unsigned char c) { return (char)std::tolower(c); });
    return o;
}

// Loại bỏ whitespace + lowercase → dùng cho pattern matching không phụ thuộc khoảng trắng
static inline std::string DR_Compact(const std::string& s)
{
    std::string o;
    o.reserve(s.size());
    for (unsigned char c : s)
        if (!std::isspace(c)) o += (char)std::tolower(c);
    return o;
}

static inline bool DR_IsSep(char c)
{
    return std::isspace((unsigned char)c) || c == '\0' || c == '"' ||
        c == '\'' || c == '`' || c == '=' || c == ':' || c == ';' ||
        c == ',' || c == '(' || c == ')' || c == '[' || c == ']' ||
        c == '+' || c == '|' || c == '&' || c == '>' || c == '<';
}

// Token-aware search: tok phải bị bao bởi separator
static inline bool DR_HasToken(const std::string& text, const std::string& tok)
{
    if (tok.empty()) return false;
    for (size_t p = text.find(tok); p != std::string::npos; p = text.find(tok, p + 1))
    {
        char b = (p == 0) ? '\0' : text[p - 1];
        char a = (p + tok.size() < text.size()) ? text[p + tok.size()] : '\0';
        if (DR_IsSep(b) && DR_IsSep(a)) return true;
    }
    return false;
}

static inline bool DR_Contains(const std::string& haystack, const std::string& needle)
{
    return haystack.find(needle) != std::string::npos;
}

// ═══════════════════════════════════════════════════════════════════════════
//  HELPER: thêm rule vào result. Trả về true nếu verdict == TERMINATE
// ═══════════════════════════════════════════════════════════════════════════

static inline bool AddRule(LocalAnalysisResult& r,
    const std::string& id,
    const std::string& reason,
    const std::string& verdict)   // "HIGH"|"MED"|"LOW"
{
    r.ruleIds.push_back(id);
    r.reasons.push_back(reason);
    if (verdict == "HIGH")
    {
        r.verdict = "TERMINATE";
        return true;  // caller nên return ngay
    }
    else if (verdict == "MED")
    {
        r.score += 1;
        if (r.score >= 2) r.verdict = "TERMINATE";
        else              r.verdict = "ALERT";
    }
    else  // LOW
    {
        if (r.verdict == "ALLOW") r.verdict = "ALERT";
    }
    return false;
}

// ─────────────────────────── NOISE / MODULE MANIFEST ─────────────────────

static inline bool DR_IsModuleManifest(const std::string& n)
{
    return DR_Contains(n, "moduleversion") &&
        DR_Contains(n, "cmdletstoexport") &&
        DR_Contains(n, "guid");
}

static inline bool DR_IsPowerShellPromptHelpNoise(
    const std::string& script,
    const std::string& n)
{
    std::string l = DR_ToLower(script);

    bool hasPromptShape =
        DR_Contains(l, "$executioncontext.sessionstate.path.currentlocation") ||
        DR_Contains(l, "$nestedpromptlevel") ||
        DR_Contains(l, "ps $($executioncontext");

    bool hasHelpMetadata =
        DR_Contains(l, "# .link") ||
        DR_Contains(l, "# .externalhelp") ||
        DR_Contains(l, "system.management.automation.dll-help.xml");

    bool hasMicrosoftHelpLink =
        DR_Contains(l, "go.microsoft.com/fwlink") ||
        DR_Contains(l, "linkid=");

    // Đây là noise nội bộ kiểu prompt/help của PowerShell.
    // Không skip mọi script có microsoft.com, chỉ skip khi có shape rất đặc trưng.
    return hasPromptShape && hasHelpMetadata && hasMicrosoftHelpLink;
}

static inline bool DR_IsPowerShellHelpMetadataNoise(const std::string& script)
{
    std::string l = DR_ToLower(script);

    bool hasHelpMetadata =
        DR_Contains(l, "# .link") ||
        DR_Contains(l, "# .externalhelp") ||
        DR_Contains(l, "system.management.automation.dll-help.xml");

    bool hasMicrosoftHelpLink =
        DR_Contains(l, "go.microsoft.com/fwlink") ||
        DR_Contains(l, "linkid=");

    bool hasPromptOrRawUiShape =
        DR_Contains(l, "$executioncontext.sessionstate.path.currentlocation") ||
        DR_Contains(l, "$nestedpromptlevel") ||
        DR_Contains(l, "$host.ui.rawui") ||
        DR_Contains(l, "$rawui.setbuffercontents") ||
        DR_Contains(l, "$rawui.cursorposition");

    return hasHelpMetadata && hasMicrosoftHelpLink && hasPromptOrRawUiShape;
}

static inline bool DR_IsPowerShellNativeErrorFormattingNoise(const std::string& script)
{
    std::string l = DR_ToLower(script);

    bool hasNativeErrorShape =
        DR_Contains(l, "nativecommanderrormessage") &&
        DR_Contains(l, "fullyqualifiederrorid") &&
        DR_Contains(l, "invocationinfo") &&
        DR_Contains(l, "positionmessage");

    bool hasParserOrCategoryShape =
        DR_Contains(l, "categoryinfo") ||
        DR_Contains(l, "parsererror") ||
        DR_Contains(l, "mycommand");

    // Chỉ coi là noise nếu không có các hành vi thật sự nguy hiểm.
    bool hasDangerousSignal =
        DR_Contains(l, "invoke-mimikatz") ||
        DR_Contains(l, "mimikatz") ||
        DR_Contains(l, "amsiutils") ||
        DR_Contains(l, "set-mppreference") ||
        DR_Contains(l, "downloadstring") ||
        DR_Contains(l, "downloadfile") ||
        DR_HasToken(l, "iex") ||
        DR_HasToken(l, "invoke-expression") ||
        DR_Contains(l, "virtualallocex") ||
        DR_Contains(l, "writeprocessmemory") ||
        DR_Contains(l, "createremotethread");

    return hasNativeErrorShape && hasParserOrCategoryShape && !hasDangerousSignal;
}

static inline bool DR_IsBenignNoise(const std::string& script)
{
    if (script.size() < 5) return true;

    std::string n = DR_Compact(script);

    if (DR_IsPowerShellNativeErrorFormattingNoise(script))
        return true;

    if (DR_IsPowerShellHelpMetadataNoise(script))
        return true;

    if (DR_IsPowerShellPromptHelpNoise(script, n))
        return true;

    if (DR_IsModuleManifest(n))
        return true;

    if ((DR_Contains(n, "psconsolehostreadline") ||
        DR_Contains(n, "psreadline")) &&
        script.size() < 200)
        return true;

    // PowerShell internal command-not-found suggestion / PSReadLine helper block.
    if (
        DR_Contains(n, "system.diagnostics.debuggerhidden") &&
        DR_Contains(n, "commandnotfoundexception") &&
        DR_Contains(n, "wildcardpattern") &&
        DR_Contains(n, "path.combine")
        )
        return true;

    return false;
}

// ═══════════════════════════════════════════════════════════════════════════
//  RULE GROUPS
// ═══════════════════════════════════════════════════════════════════════════

// ─── GROUP 1: Credential Dumping ──────────────────────────────────────────
// HIGH confidence — luôn TERMINATE

static inline bool RuleGroup_CredDump(const std::string& n,
    LocalAnalysisResult& r)
{
    // Mimikatz variants
    if (DR_Contains(n, "invoke-mimikatz") ||
        DR_Contains(n, "mimikatz"))
        if (AddRule(r, "CRED-001", "Mimikatz / Invoke-Mimikatz detected", "HIGH")) return true;

    // LSASS credential extraction
    if (DR_Contains(n, "sekurlsa") ||
        DR_Contains(n, "logonpasswords") ||
        DR_Contains(n, "lsadump") ||
        DR_Contains(n, "dcsync"))
        if (AddRule(r, "CRED-002", "LSASS/DCSync credential extraction", "HIGH")) return true;

    // Credential vault / DPAPI abuse
    if (DR_Contains(n, "dpapi") &&
        (DR_Contains(n, "masterkey") || DR_Contains(n, "unprotect")))
        if (AddRule(r, "CRED-003", "DPAPI masterkey / credential decryption", "HIGH")) return true;

    // SAM / registry hive dump
    if ((DR_Contains(n, "reg") || DR_Contains(n, "regsave")) &&
        (DR_Contains(n, "sam") || DR_Contains(n, "system") || DR_Contains(n, "security")) &&
        DR_Contains(n, "hklm"))
        if (AddRule(r, "CRED-004", "SAM/SYSTEM hive registry dump", "HIGH")) return true;

    return false;
}

// ─── GROUP 2: Defence Evasion ─────────────────────────────────────────────

static inline bool RuleGroup_DefEvasion(const std::string& n,
    const std::string& l,   // lowercase, original spacing
    LocalAnalysisResult& r)
{
    // AMSI bypass
    if (DR_Contains(n, "amsiutils") ||
        DR_Contains(n, "amsiinitfailed") ||
        DR_Contains(n, "amsicontext") ||
        DR_Contains(n, "amsiscanbuffer"))
        if (AddRule(r, "EVASION-001", "AMSI bypass / patch attempt", "HIGH")) return true;

    // Defender disable
    if (DR_Contains(n, "set-mppreference") &&
        (DR_Contains(n, "disablerealtimemonitoring") ||
            DR_Contains(n, "disableioavprotection") ||
            DR_Contains(n, "disablescriptscanning") ||
            DR_Contains(n, "disablebehaviormonitoring")))
        if (AddRule(r, "EVASION-002", "Windows Defender disable via Set-MpPreference", "HIGH")) return true;

    // ETW patching / disabling
    if (DR_Contains(n, "etwenablettrace") ||
        (DR_Contains(n, "ntdll") && DR_Contains(n, "etwevent")) ||
        DR_Contains(n, "disabledetwmonitoring"))
        if (AddRule(r, "EVASION-003", "ETW (Event Tracing for Windows) disable/patch", "HIGH")) return true;

    // SBL (Script Block Logging) disable
    if (DR_Contains(n, "enablescriptblocklogging") &&
        (DR_Contains(n, "0") || DR_Contains(n, "false")))
        if (AddRule(r, "EVASION-004", "PowerShell Script Block Logging disabled", "HIGH")) return true;

    // Constrained Language Mode bypass
    bool hasLanguageModeBypass =
        DR_Contains(n, "__pslocklanguagemode") ||
        DR_Contains(n, "constrainedlanguagemode") ||
        (
            DR_Contains(n, "executioncontext") &&
            DR_Contains(n, "sessionstate") &&
            (
                DR_Contains(n, "languagemode") ||
                DR_Contains(n, "authorizationmanager") ||
                DR_Contains(n, "initialsessionstate")
                )
            );

    if (hasLanguageModeBypass)
        if (AddRule(r, "EVASION-005", "PowerShell language mode manipulation", "MED")) return false;

    // Signature bypass via reflection
    if (DR_Contains(n, "reflection.assembly") &&
        (DR_Contains(n, "load(") || DR_Contains(n, "loadfile") || DR_Contains(n, "loadwithpartialname")))
        if (AddRule(r, "EVASION-006", "Reflection Assembly load (possible bypass)", "MED")) return false;

    // EventLog clearing
    if (DR_Contains(n, "clear-eventlog") ||
        (DR_Contains(n, "wevtutil") && DR_Contains(n, "cl")))
        if (AddRule(r, "EVASION-007", "Event log clearing detected", "MED")) return false;

    return false;
}

// ─── GROUP 3: Download + Execute Chain ────────────────────────────────────

static inline bool RuleGroup_DlExec(const std::string& n,
    const std::string& l,
    LocalAnalysisResult& r,
    bool& out_hasDl,
    bool& out_hasDynExec)
{
    bool hasUrl =
        DR_Contains(n, "http://") ||
        DR_Contains(n, "https://") ||
        DR_Contains(n, "ftp://");

    bool hasDownloadPrimitive =
        DR_Contains(n, "downloadstring") ||
        DR_Contains(n, "downloadfile") ||
        DR_Contains(n, "downloaddata") ||
        DR_Contains(n, "invoke-webrequest") ||
        DR_Contains(n, "iwr") ||
        DR_Contains(n, "invoke-restmethod") ||
        DR_Contains(n, "irm") ||
        DR_Contains(n, "new-objectnet.webclient") ||
        DR_Contains(n, "system.net.webclient") ||
        DR_Contains(n, "start-bitstransfer") ||
        DR_Contains(n, "bitsadmin") ||
        DR_Contains(n, "certutil") ||
        DR_Contains(n, "mshta") ||
        DR_Contains(n, "regsvr32") ||
        DR_Contains(n, "rundll32");

    out_hasDl = hasDownloadPrimitive || (hasUrl && (
        DR_Contains(n, "download") ||
        DR_Contains(n, "webclient") ||
        DR_Contains(n, "invoke-webrequest") ||
        DR_Contains(n, "invoke-restmethod") ||
        DR_Contains(n, "start-bitstransfer") ||
        DR_Contains(n, "bitsadmin") ||
        DR_Contains(n, "certutil") ||
        DR_Contains(n, "mshta") ||
        DR_Contains(n, "regsvr32")
        ));

    out_hasDynExec =
        DR_HasToken(l, "invoke-expression") ||
        DR_HasToken(l, "iex") ||
        DR_Contains(n, "frombase64string") ||
        DR_Contains(n, "add-type") ||
        DR_Contains(n, "[scriptblock]::create") ||
        DR_Contains(n, "invoke-command") ||
        DR_Contains(n, ".invoke(");

    if (out_hasDl && out_hasDynExec)
        if (AddRule(r, "DL-EXEC-001", "Download + dynamic execution chain (dropper pattern)", "HIGH")) return true;

    if (out_hasDl)
        if (AddRule(r, "DL-001", "PowerShell downloader / remote URL access", "MED")) return false;

    if (out_hasDynExec)
        if (AddRule(r, "DL-002", "Dynamic / reflected code execution", "MED")) return false;

    return false;
}

// ─── GROUP 4: LOLBin Abuse (Living Off The Land) ─────────────────────────
//
// LOLBin = legitimate Windows binaries bị dùng để thực thi code độc hại.
// PowerShell thường gọi chúng qua Start-Process, &, Invoke-Expression, etc.

static inline bool RuleGroup_LOLBin(const std::string& n,
    const std::string& l,
    LocalAnalysisResult& r)
{
    // certutil: decode/download
    if (DR_Contains(n, "certutil") &&
        (DR_Contains(n, "-decode") || DR_Contains(n, "-urlcache") ||
            DR_Contains(n, "-f") || DR_Contains(n, "http")))
        if (AddRule(r, "LOLBIN-001", "certutil used for file decode/download", "HIGH")) return true;

    // mshta: execute HTML Application / VBScript
    if (DR_Contains(n, "mshta") &&
        (DR_Contains(n, "vbscript") || DR_Contains(n, "javascript") ||
            DR_Contains(n, "http") || DR_Contains(n, ".hta")))
        if (AddRule(r, "LOLBIN-002", "mshta executing HTA/VBScript payload", "HIGH")) return true;

    // regsvr32 / scrobj: COM scriptlet
    if ((DR_Contains(n, "regsvr32") || DR_Contains(n, "scrobj.dll")) &&
        (DR_Contains(n, "scrobj") || DR_Contains(n, "/s") ||
            DR_Contains(n, "http") || DR_Contains(n, ".sct")))
        if (AddRule(r, "LOLBIN-003", "regsvr32/scrobj scriptlet execution (Squiblydoo)", "HIGH")) return true;

    // rundll32 abuse
    if (DR_Contains(n, "rundll32") &&
        (DR_Contains(n, "javascript") || DR_Contains(n, "shell32") ||
            DR_Contains(n, "advpack") || DR_Contains(n, "ieadvpack") ||
            DR_Contains(n, "http")))
        if (AddRule(r, "LOLBIN-004", "rundll32 used for code execution (LOLBin)", "HIGH")) return true;

    // wscript / cscript: script execution
    if ((DR_Contains(n, "wscript") || DR_Contains(n, "cscript")) &&
        (DR_Contains(n, "http") || DR_Contains(n, ".vbs") ||
            DR_Contains(n, ".js") || DR_Contains(n, ".wsh")))
        if (AddRule(r, "LOLBIN-005", "wscript/cscript executing remote/suspicious script", "HIGH")) return true;

    // msiexec: remote MSI install
    if (DR_Contains(n, "msiexec") &&
        (DR_Contains(n, "http") || DR_Contains(n, "/q") || DR_Contains(n, "/quiet")))
        if (AddRule(r, "LOLBIN-006", "msiexec silent remote install", "MED")) return false;

    // InstallUtil: AppLocker bypass
    if (DR_Contains(n, "installutil") &&
        (DR_Contains(n, "/logfile=") || DR_Contains(n, "/logtoconsole=")))
        if (AddRule(r, "LOLBIN-007", "InstallUtil AppLocker/CLM bypass", "HIGH")) return true;

    // forfiles / pcalua: arbitrary command execution
    if (DR_Contains(n, "forfiles") && DR_Contains(n, "/c"))
        if (AddRule(r, "LOLBIN-008", "forfiles used for arbitrary command execution", "MED")) return false;

    // odbcconf: REGSVR bypass
    if (DR_Contains(n, "odbcconf") && DR_Contains(n, "regsvr"))
        if (AddRule(r, "LOLBIN-009", "odbcconf REGSVR execution bypass", "HIGH")) return true;

    // bitsadmin: download
    if (DR_Contains(n, "bitsadmin") &&
        (DR_Contains(n, "/transfer") || DR_Contains(n, "http")))
        if (AddRule(r, "LOLBIN-010", "bitsadmin file transfer (download)", "MED")) return false;

    // expand / extrac32: extract payload
    if ((DR_Contains(n, "extrac32") || (DR_Contains(n, "expand") && DR_Contains(n, ".cab"))) &&
        DR_Contains(n, "http"))
        if (AddRule(r, "LOLBIN-011", "expand/extrac32 remote payload extraction", "MED")) return false;

    return false;
}

// ─── GROUP 5: Process Injection ───────────────────────────────────────────
//
// Các pattern PowerShell gọi Win32 API để inject code vào process khác.

static inline bool RuleGroup_Injection(const std::string& n,
    const std::string& l,
    LocalAnalysisResult& r)
{
    // Classic VirtualAllocEx + WriteProcessMemory combo
    bool hasVAEx = DR_Contains(n, "virtualallocex") || DR_Contains(n, "virtualalloc");
    bool hasWPM = DR_Contains(n, "writeprocessmemory");
    bool hasCRT = DR_Contains(n, "createremotethread") || DR_Contains(n, "createremotethreadex");
    bool hasOProc = DR_Contains(n, "openprocess");

    if (hasVAEx && hasWPM)
        if (AddRule(r, "INJECT-001", "VirtualAllocEx + WriteProcessMemory (classic injection)", "HIGH")) return true;

    if (hasCRT && (hasVAEx || hasWPM))
        if (AddRule(r, "INJECT-002", "CreateRemoteThread + memory alloc/write (shellcode injection)", "HIGH")) return true;

    // QueueUserAPC injection
    if (DR_Contains(n, "queueuserapc") && (hasVAEx || hasWPM))
        if (AddRule(r, "INJECT-003", "QueueUserAPC injection pattern", "HIGH")) return true;

    // SetWindowsHookEx injection
    if (DR_Contains(n, "setwindowshookex"))
        if (AddRule(r, "INJECT-004", "SetWindowsHookEx hook injection", "MED")) return false;

    // NtMapViewOfSection / NtCreateSection (process hollowing)
    if (DR_Contains(n, "ntmapviewofsection") || DR_Contains(n, "ntcreatesection") ||
        DR_Contains(n, "zwmapviewofsection"))
        if (AddRule(r, "INJECT-005", "NtMapViewOfSection process hollowing API", "HIGH")) return true;

    // Reflective DLL injection pattern
    if (DR_Contains(n, "loadlibrary") &&
        (DR_Contains(n, "getprocaddress") || DR_Contains(n, "reflective")))
        if (AddRule(r, "INJECT-006", "Reflective DLL injection pattern", "HIGH")) return true;

    // P/Invoke DllImport với kernel32/ntdll APIs
    if (DR_Contains(n, "[dllimport(") &&
        (DR_Contains(n, "kernel32") || DR_Contains(n, "ntdll")) &&
        (hasVAEx || hasWPM || hasCRT))
        if (AddRule(r, "INJECT-007", "P/Invoke DllImport with injection APIs", "HIGH")) return true;

    // Generic: nhiều injection API trong cùng script
    int injApiCount = (int)hasVAEx + (int)hasWPM + (int)hasCRT + (int)hasOProc;
    if (injApiCount >= 3)
        if (AddRule(r, "INJECT-008", "Multiple process injection APIs in single script", "HIGH")) return true;

    return false;
}

// ─── GROUP 6: Reverse Shell / C2 ─────────────────────────────────────────

static inline bool RuleGroup_ReverseShell(const std::string& n,
    const std::string& l,
    LocalAnalysisResult& r)
{
    // TCPClient reverse shell (PowerShell classic)
    bool hasTcp = DR_Contains(n, "net.sockets.tcpclient") || DR_Contains(n, "system.net.sockets");
    bool hasStream = DR_Contains(n, "getstream") || DR_Contains(n, "networkstream");
    bool hasShell = DR_Contains(n, "cmd.exe") || DR_Contains(n, "powershell.exe") ||
        DR_Contains(n, "process::start") || DR_Contains(n, "start-process");

    if (hasTcp && hasStream && hasShell)
        if (AddRule(r, "REVSHELL-001", "TCP reverse shell pattern (TcpClient + stream + cmd)", "HIGH")) return true;

    if (hasTcp && hasStream)
        if (AddRule(r, "REVSHELL-002", "TCP socket stream (possible C2 channel)", "MED")) return false;

    // Named Pipe C2
    if (DR_Contains(n, "namedpipe") && (hasShell || DR_Contains(n, "pipestream")))
        if (AddRule(r, "REVSHELL-003", "Named pipe C2 communication pattern", "MED")) return false;

    // Web-based C2 (polling loop + exec)
    if ((DR_Contains(n, "invoke-webrequest") || DR_Contains(n, "webclient")) &&
        (DR_Contains(n, "while") || DR_Contains(n, "for") || DR_Contains(n, "loop")) &&
        (DR_Contains(n, "invoke-expression") || DR_Contains(n, "iex")))
        if (AddRule(r, "REVSHELL-004", "Web-based C2 polling loop (beacon/implant pattern)", "HIGH")) return true;

    // DNS C2
    if (DR_Contains(n, "resolve-dnsname") &&
        (DR_Contains(n, "invoke-expression") || DR_HasToken(l, "iex")))
        if (AddRule(r, "REVSHELL-005", "DNS C2 pattern (resolve + execute)", "HIGH")) return true;

    // Netcat-style: Start-Process nc / ncat
    if ((DR_Contains(n, "nc.exe") || DR_Contains(n, "ncat") || DR_Contains(n, "netcat")) &&
        DR_Contains(n, "-e"))
        if (AddRule(r, "REVSHELL-006", "Netcat/ncat reverse shell (-e flag)", "HIGH")) return true;

    return false;
}

// ─── GROUP 7: Obfuscation ─────────────────────────────────────────────────
//
// Đây là các dấu hiệu làm rối code — thường kết hợp với rules khác để
// nâng score. Một mình thường chỉ ALERT.

static inline bool RuleGroup_Obfuscation(const std::string& raw,
    const std::string& n,
    const std::string& l,
    LocalAnalysisResult& r)
{
    // -EncodedCommand / -enc
    bool hasEnc = DR_HasToken(l, "-encodedcommand") || DR_HasToken(l, "/encodedcommand") ||
        DR_HasToken(l, "-enc") || DR_HasToken(l, "/enc");
    if (hasEnc)
        if (AddRule(r, "OBFUS-001", "PowerShell -EncodedCommand flag", "MED")) return false;

    // String concatenation obfuscation: ('I'+'EX'), 'Invo'+'ke'
    {
        size_t concatCount = 0;
        for (size_t i = 0; i + 3 < raw.size(); ++i)
            if (raw[i] == '\'' && raw[i + 1] == '+' && raw[i + 2] == '\'') concatCount++;
        if (concatCount >= 4)
            if (AddRule(r, "OBFUS-002", "Heavy string concatenation obfuscation", "MED")) return false;
    }

    // Backtick obfuscation: `I`E`X
    {
        size_t backtickCount = 0;
        for (char c : raw) if (c == '`') backtickCount++;
        if (backtickCount >= 5)
            if (AddRule(r, "OBFUS-003", "Excessive backtick escape obfuscation", "MED")) return false;
    }

    // Format string obfuscation: '{0}{1}' -f 'I','EX'
    if (DR_Contains(n, "-f'") && DR_Contains(n, "'{0}"))
        if (AddRule(r, "OBFUS-004", "Format-string operator obfuscation (-f)", "MED")) return false;

    // Char-code obfuscation: [char]73 + [char]69...
    if (DR_Contains(n, "[char]"))
    {
        size_t cnt = 0, pos = 0;
        while ((pos = n.find("[char]", pos)) != std::string::npos) { cnt++; pos += 6; }
        if (cnt >= 4)
            if (AddRule(r, "OBFUS-005", "Char-code array obfuscation ([char]NNN)", "MED")) return false;
    }

    // SecureString / BSTR obfuscation
    if (DR_Contains(n, "securestring") && DR_Contains(n, "bstrtosecurestring"))
        if (AddRule(r, "OBFUS-006", "SecureString/BSTR obfuscation pattern", "LOW")) return false;

    // XOR decode pattern
    if (DR_Contains(n, "-bxor") || (DR_Contains(n, "xor") && DR_Contains(n, "foreach")))
        if (AddRule(r, "OBFUS-007", "XOR decode loop (payload deobfuscation)", "MED")) return false;

    return false;
}

// ─── GROUP 8: Persistence ─────────────────────────────────────────────────

static inline bool RuleGroup_Persistence(const std::string& n,
    const std::string& l,
    LocalAnalysisResult& r)
{
    // Scheduled task creation
    if ((DR_Contains(n, "schtasks") || DR_Contains(n, "new-scheduledtask") ||
        DR_Contains(n, "register-scheduledtask")) &&
        (DR_Contains(n, "/create") || DR_Contains(n, "-action") || DR_Contains(n, "-trigger")))
        if (AddRule(r, "PERSIST-001", "Scheduled task creation (persistence)", "MED")) return false;

    // Registry run key
    if (DR_Contains(n, "currentversion\\run") ||
        DR_Contains(n, "currentversion\\runonce") ||
        DR_Contains(n, "hkcu:software\\microsoft\\windows\\currentversion\\run") ||
        DR_Contains(n, "hklm:software\\microsoft\\windows\\currentversion\\run"))
        if (AddRule(r, "PERSIST-002", "Registry Run key persistence", "MED")) return false;

    // WMI subscription
    if ((DR_Contains(n, "__eventfilter") || DR_Contains(n, "commandlineeventconsumer") ||
        DR_Contains(n, "__filtertoconsumerbinding")) &&
        DR_Contains(n, "set-wminstance"))
        if (AddRule(r, "PERSIST-003", "WMI event subscription persistence", "HIGH")) return true;

    // Startup folder drop
    if (DR_Contains(n, "\\microsoft\\windows\\startmenu\\programs\\startup") ||
        DR_Contains(n, "\\currentversion\\explorer\\shell folders\\startup"))
        if (AddRule(r, "PERSIST-004", "Startup folder persistence", "MED")) return false;

    // Service creation
    if ((DR_Contains(n, "new-service") || DR_Contains(n, "sc.exe") || DR_Contains(n, "sc create")) &&
        DR_Contains(n, "binpath"))
        if (AddRule(r, "PERSIST-005", "Windows service creation", "MED")) return false;

    return false;
}

// ─── GROUP 9: Reconnaissance ──────────────────────────────────────────────
// LOW confidence — ghi log nhưng ít khi trigger TERMINATE một mình

static inline bool RuleGroup_Recon(const std::string& n,
    const std::string& l,
    LocalAnalysisResult& r)
{
    // Domain recon
    if (DR_Contains(n, "get-aduser") || DR_Contains(n, "get-adgroup") ||
        DR_Contains(n, "get-adcomputer") || DR_Contains(n, "get-addomain"))
        if (AddRule(r, "RECON-001", "Active Directory enumeration", "LOW")) return false;

    // Network scan
    if (DR_Contains(n, "test-netconnection") || DR_Contains(n, "portscanner") ||
        (DR_Contains(n, "net.sockets.tcpclient") && DR_Contains(n, "foreach")))
        if (AddRule(r, "RECON-002", "Network port/host scanning", "LOW")) return false;

    // Antivirus / EDR detection
    if (DR_Contains(n, "get-wmiobject") &&
        (DR_Contains(n, "antivirusproduct") || DR_Contains(n, "antispywareproduct")))
        if (AddRule(r, "RECON-003", "Antivirus/security product enumeration", "LOW")) return false;

    // PowerView / BloodHound indicators
    if (DR_Contains(n, "invoke-bloodhound") || DR_Contains(n, "sharphound") ||
        DR_Contains(n, "get-netuser") || DR_Contains(n, "get-netsession") ||
        DR_Contains(n, "invoke-sharedfinder"))
        if (AddRule(r, "RECON-004", "BloodHound/PowerView reconnaissance tool", "HIGH")) return true;

    return false;
}

// ═══════════════════════════════════════════════════════════════════════════
//  PUBLIC API: LocalAnalyze()
//
//  Gọi hàm này từ worker thread với nội dung script đã được normalize
//  (UTF-8, reconstruct, base64-decoded nếu có).
// ═══════════════════════════════════════════════════════════════════════════

inline LocalAnalysisResult LocalAnalyze(const std::string& script)
{
    LocalAnalysisResult r;

    // Fast-exit: module manifest / benign noise
    if (DR_IsBenignNoise(script))
    {
        r.verdict = "ALLOW";
        return r;
    }

    std::string n = DR_Compact(script);   // no-whitespace lowercase
    std::string l = DR_ToLower(script);   // lowercase, original spacing (for token matching)

    // ── Run rule groups in priority order ─────────────────────────────────
    // HIGH confidence groups first → early return on TERMINATE

    if (RuleGroup_CredDump(n, r))      return r;
    if (RuleGroup_DefEvasion(n, l, r)) return r;

    bool hasDl = false, hasDynExec = false;
    if (RuleGroup_DlExec(n, l, r, hasDl, hasDynExec)) return r;

    if (RuleGroup_LOLBin(n, l, r))    return r;
    if (RuleGroup_Injection(n, l, r)) return r;
    if (RuleGroup_ReverseShell(n, l, r)) return r;
    if (RuleGroup_Persistence(n, l, r))  return r;

    // MED/LOW groups — accumulate score
    RuleGroup_Obfuscation(script, n, l, r);
    RuleGroup_Recon(n, l, r);

    // Final score check: nếu tổng MED ≥ 2 thì đã TERMINATE trong AddRule()
    // Nếu không có rule nào → ALLOW
    return r;
}