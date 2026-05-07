
from flask import Flask, request, jsonify

import os
import re
import json
import time
import math
import queue
import hashlib
import threading
from collections import Counter

# Optional dependencies
try:
    import joblib
except ImportError:
    joblib = None

try:
    import pandas as pd
except ImportError:
    pd = None

try:
    import numpy as np
except ImportError:
    np = None

try:
    import psutil
except ImportError:
    psutil = None

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    Observer = None
    FileSystemEventHandler = object

try:
    import win32evtlog
except ImportError:
    win32evtlog = None

# =====================================================
# Python EDR Agent - Multi-Sensor + G2.96 Feature Extraction + ML Ready
#
# Role:
# 1. Receive telemetry from C++ Native AMSI Bridge Agent via /telemetry
# 2. Run Process Sensor for PowerShell/script interpreter command lines
# 3. Run File Sensor for script files
# 4. Run Event Log 4104 Sensor for PowerShell Script Block Logging
# 5. Normalize events into one queue
# 6. Apply G2.96 Feature Extraction from previous research project
# 7. Apply G2.96 Data Analysis / Risk Score interpretation
# 8. Run rule-based detection baseline
# 9. Optional Random Forest ML plugin
# 10. Return final verdict to C++ Agent
# =====================================================

app = Flask(__name__)

# ================= CONFIG =================
HOST = "127.0.0.1"
PORT = 9001

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
MODEL_DIR = os.path.join(BASE_DIR, "model")

EVENT_LOG_PATH = os.path.join(LOG_DIR, "edr_events.jsonl")
FEATURE_LOG_PATH = os.path.join(LOG_DIR, "edr_features_g296.csv")

MODEL_PATH = os.path.join(MODEL_DIR, "random_forest_model.pkl")
FEATURE_COLUMNS_PATH = os.path.join(MODEL_DIR, "feature_columns.pkl")

ENABLE_PROCESS_SENSOR = True
ENABLE_FILE_SENSOR = True
ENABLE_EVENTLOG_4104_SENSOR = True

WATCH_PATHS = [
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Downloads"),
    os.path.expanduser("~/Documents"),
]

SCRIPT_EXTENSIONS = (
    ".ps1", ".psm1", ".psd1",
    ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta",
    ".bat", ".cmd"
)

SUSPICIOUS_PROCESS_NAMES = {
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "reg.exe",
    "schtasks.exe",
}

POWERSHELL_EVENT_LOG = "Microsoft-Windows-PowerShell/Operational"
POWERSHELL_EVENT_ID = 4104

MAX_DEDUP_CACHE = 5000
MAX_SCRIPT_LOG_CHARS = 900
ML_MALICIOUS_CONFIDENCE_THRESHOLD = 0.90

# Risk thresholds based on G2.96 final_risk_score.
# These thresholds are intentionally conservative for runtime EDR usage.
G296_MEDIUM_RISK_THRESHOLD = 1.0
G296_HIGH_RISK_THRESHOLD = 3.0
G296_TERMINATE_RISK_THRESHOLD = 8.0

# ================= GLOBAL STATE =================
event_queue = queue.Queue()
seen_hashes = set()
seen_lock = threading.Lock()
log_lock = threading.Lock()

ml_model = None
feature_columns = None
ml_enabled = False


# =====================================================
# BASIC UTILS
# =====================================================
def ensure_dirs():
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(MODEL_DIR, exist_ok=True)


def now_ts():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def sha256_text(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="ignore")).hexdigest()


def normalize_compact(text: str) -> str:
    return "".join((text or "").lower().split())

def contains_token(text: str, token: str) -> bool:
    if not text or not token:
        return False

    pattern = r"(?<![A-Za-z0-9_])" + re.escape(token) + r"(?![A-Za-z0-9_])"
    return bool(re.search(pattern, text, flags=re.IGNORECASE))


def contains_encoded_flag(text: str) -> bool:
    text = text or ""

    return any([
        contains_token(text, "-encodedcommand"),
        contains_token(text, "/encodedcommand"),
        contains_token(text, "-enc"),
        contains_token(text, "/enc"),
        contains_token(text, "-e"),
    ])


def contains_invoke_expression(text: str) -> bool:
    text = text or ""

    return any([
        contains_token(text, "invoke-expression"),
        contains_token(text, "iex"),
    ])

def truncate(text: str, limit: int = MAX_SCRIPT_LOG_CHARS) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return text[:limit] + " ...[truncated]"


def safe_mean(values):
    if not values:
        return 0.0
    if np is not None:
        return float(np.mean(values))
    return sum(values) / len(values)


# =====================================================
# G2.96 HELPERS + PREPROCESSING
# Adapted from previous Feature_Extraction code.
# =====================================================
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0

    if np is not None:
        counts = np.bincount([ord(c) for c in s if ord(c) < 256])
        probs = counts[counts > 0] / len(s)
        return float(-np.sum(probs * np.log2(probs + 1e-10)))

    counter = Counter(c for c in s if ord(c) < 256)
    length = len(s)
    result = 0.0
    for count in counter.values():
        p = count / length
        result -= p * math.log2(p + 1e-10)
    return result


def count_pattern(text: str, pattern: str, flags=0) -> int:
    return len(re.findall(pattern, text or "", flags))


def has_pattern(text: str, pattern: str, flags=0) -> int:
    return int(bool(re.search(pattern, text or "", flags)))


def preprocess_raw(text: str) -> str:
    return (text or "").replace("\x00", "")


def preprocess_normalized(text: str) -> str:
    text = (text or "").lower()
    text = text.replace("'", "").replace('"', "")
    text = text.replace("`", "")
    text = re.sub(r'<#[\s\S]*?#>', ' ', text)
    text = re.sub(r'#.*', ' ', text)

    alias_map = {
        r'\biex\b': 'invoke-expression',
        r'\biwr\b': 'invoke-webrequest',
        r'\bgci\b': 'get-childitem',
        r'\bgc\b': 'get-content',
        r'\bgwmi\b': 'get-wmiobject',
        r'\bdl\b': 'downloadfile',
        r'\becho\b': 'write-output',
        r'\bshutdown\b': 'stop-computer',
        r'\?': 'where-object',
        r'\%': 'foreach-object',
        r'\bstart\b': 'start-process',
    }

    for alias, full in alias_map.items():
        text = re.sub(alias, full, text, flags=re.DOTALL | re.IGNORECASE)

    text = re.sub(r'[\s\(\)\[\]\{\};,`\^:\.=]+', ' ', text).strip()
    return text


def is_module_manifest(script: str) -> bool:
    s = normalize_compact(script)
    return (
        "moduleversion" in s
        and "cmdletstoexport" in s
        and "guid" in s
        and (
            "microsoftcorporation" in s
            or "rootmodule" in s
            or "nestedmodules" in s
        )
    )


def is_trivial_noise(script: str) -> bool:
    s = normalize_compact(script)

    if len(s) < 5:
        return True

    if is_module_manifest(script):
        return True

    if s in {"get-history", "clear-host", "cls"}:
        return True

    if "127.0.0.1:9001/health" in s or "localhost:9001/health" in s:
        return True

    if "entervsdevshell" in s or "microsoft.visualstudio.devshell" in s or "vsappid" in s:
        return True

    if "pcasvc.dll" in s:
        return True

    if "appxdeploymentextensions.onecore.dll" in s:
        return True

    if "remove-item" in s and ("edr_events.jsonl" in s or "edr_features_g296.csv" in s or "edr_cpp_agent.log" in s):
        return True

    if s.startswith("cd") and len(s) <= 80:
        return True

    if "psconsolehostreadline" in s or "psreadline" in s:
        suspicious = (
            contains_encoded_flag(script)
            or contains_invoke_expression(script)
            or any(k in s for k in [
                "downloadstring", "frombase64string", "mimikatz", "amsiutils",
                "set-mppreference", "disablerealtimemonitoring"
            ])
        )

        if not suspicious:
            return True

    return False


# =====================================================
# G2.96 FEATURE EXTRACTION
# This keeps the original feature names used in the previous ML pipeline.
# =====================================================
def extract_features_g296(script: str, event: dict | None = None) -> dict:
    event = event or {}

    raw = preprocess_raw(script or "")
    norm = preprocess_normalized(raw)
    lines = raw.splitlines()
    if not lines:
        lines = [""]

    f = {}
    f["path"] = event.get("path", event.get("source", "runtime_event"))

    # === 1. RAW features ===
    f["length"] = len(raw)
    f["lines"] = len(lines)
    f["is_one_liner"] = int(len(lines) == 1)
    f["avg_line_len"] = safe_mean([len(l) for l in lines])
    f["max_line_len"] = max([len(l) for l in lines])
    f["semicolon_ratio"] = raw.count(";") / len(raw) if raw else 0
    f["backtick_count"] = raw.count("`")
    f["whitespace_ratio"] = len(re.findall(r"\s", raw)) / len(raw) if raw else 0
    f["char_entropy"] = shannon_entropy(raw)
    f["is_high_entropy"] = 1 if f["char_entropy"] > 5.75 else 0
    alnum_count = len(re.findall(r"[a-zA-Z0-9]", raw))
    f["special_char_ratio"] = (len(raw) - alnum_count) / len(raw) if raw else 0
    f["caret_count"] = raw.count("^")
    f["concat_string_count"] = count_pattern(raw.lower(), r"\$\w+\s*\+\s*[\"']")

    # === 2. Payload features ===
    strings = re.findall(r'"([^"]*)"', raw) + re.findall(r"'([^']*)'", raw)
    f["num_strings"] = len(strings)
    f["longest_string"] = max([len(s) for s in strings] + [0])
    f["num_long_strings"] = sum(1 for s in strings if len(s) > 100)
    total_literal_len = sum(len(s) for s in strings)
    f["literal_ratio"] = total_literal_len / len(raw) if raw else 0
    f["has_base64_payload"] = has_pattern(raw, r"[A-Za-z0-9+/=]{50,}")
    f["has_hex_string"] = has_pattern(raw, r"0x[0-9A-Fa-f]{8,}")
    f["http_count"] = count_pattern(raw, r"http://", flags=re.IGNORECASE)
    f["httpsG_count"] = count_pattern(raw, r"https://", flags=re.IGNORECASE)
    f["ip_count"] = len(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", raw))
    f["domain_count"] = len(re.findall(r"\.[a-zA-Z]{2,}", raw))
    f["has_pe_header_b64"] = has_pattern(raw, r"TVqQ")
    f["has_hex_byte_array"] = has_pattern(raw.lower(), r"(0x[0-9a-f]{1,2}\s*,){10,}")
    f["has_exe_download"] = has_pattern(raw.lower(), r"download(file|string)\s*\(.*['\"].*\.exe\s*['\"]")

    f["payload_score"] = sum([f[k] > 0 for k in [
        "has_base64_payload", "has_hex_string", "has_hex_byte_array",
        "has_exe_download", "has_pe_header_b64"
    ]])

    # === 3. Variable features ===
    var_names = re.findall(r"\$(\{[^}]+\}|\w+)", raw)
    f["var_count"] = len(var_names)
    f["avg_var_len"] = safe_mean([len(v) for v in var_names]) if var_names else 0
    f["has_wildcard_var"] = has_pattern(raw, r"\$\w*\*\w*")
    f["var_entropy"] = shannon_entropy("".join(var_names)) if var_names else 0
    f["num_random_var"] = sum(1 for v in var_names if len(v) > 10)
    f["var_score"] = f["var_count"] + f["num_random_var"]

    # === 4. Benign features ===
    f["has_license"] = has_pattern(raw, r"<#\s*\.SYNOPSIS", re.I | re.DOTALL)
    f["comment_ratio"] = raw.count("#") / len(raw) if raw else 0
    f["function_count"] = count_pattern(raw.lower(), r"function\s+\w+")
    f["try_catch_count"] = count_pattern(raw.lower(), r"try\s*{")
    f["has_write_host"] = has_pattern(norm, r"\bwrite-host\b")
    f["has_write_output"] = has_pattern(norm, r"\bwrite-output\b")
    f["param_block"] = has_pattern(norm, r"\bparam\b")
    f["has_inline_param"] = has_pattern(raw.lower(), r"function\s+\w+\s+[^\(\{]*?\$")
    f["has_pester_test"] = has_pattern(norm, r"\binvoke-pester\b|\bdescribe\b|\bit\b")
    f["has_script_analyzer"] = has_pattern(norm, r"invoke-scriptanalyzer")
    f["has_build_task"] = has_pattern(norm, r"\btask\b|\bproperties\b")
    f["has_markdown_help"] = has_pattern(norm, r"new-markdownhelp|update-markdownhelp|new-externalhelp")
    f["has_io_path"] = has_pattern(norm, r"\bio\s+path\b")
    f["has_push_pop_location"] = has_pattern(norm, r"push-location|pop-location")
    f["has_psdatafile_import"] = has_pattern(norm, r"import-powershelldatafile")
    f["has_benign_framework"] = has_pattern(norm, r"pnp-powershell|\bofficedev\b")
    f["has_module_install"] = has_pattern(norm, r"install-module|\binstall-package\b")
    f["has_sql_admin"] = has_pattern(norm, r"sqlserver\s+smo|sqlbackup|sqlverify|sqlrestore")
    f["has_email_client"] = has_pattern(norm, r"net\s+mail\s+smtpclient|net\s+mail\s+mailmessage")
    f["has_hyperv_admin"] = has_pattern(norm, r"\bget-vm\b|\bmeasure-vm\b|\bget-physicaldisk\b|\bget-storagepool\b|\bget-virtualdisk\b|\bvmresourcemetering\b")
    f["has_convertto_html"] = has_pattern(norm, r"convertto-html")
    f["has_azure_admin"] = has_pattern(norm, r"\b(azresourcegroup|azstorage|azsql|azcontext)\b")
    f["has_service_point_manager"] = has_pattern(norm, r"net\s+servicepointmanager")
    f["has_whitelisted_download"] = has_pattern(norm, r"githubusercontent|github\s+com|\bofficedev\b|\bmicrosoft\s+com\b")
    f["has_secure_string"] = has_pattern(norm, r"\bconvertto-securestring\b")
    f["has_pscredential"] = has_pattern(norm, r"\bmanagement\s+automation\s+pscredential\b")
    f["has_benign_secure_string"] = f["has_secure_string"]
    f["has_benign_pscredential"] = f["has_pscredential"]
    f["has_benign_whitelisted_download"] = f.get("has_whitelisted_download", 0)
    f["has_winforms"] = has_pattern(norm, r"system\s+windows\s+forms")
    f["has_add_type"] = has_pattern(norm, r"\badd-type\b(?!.*\btest\b)")
    f["has_pinvoke"] = has_pattern(raw.lower(), r"\[dllimport.*(?!.*\btest\b)")
    f["has_benign_add_type"] = f["has_add_type"]
    f["has_benign_pinvoke"] = f["has_pinvoke"]

    f["benign_score"] = sum([f[k] > 0 for k in [
        "has_license", "has_write_host", "has_write_output", "function_count", "param_block",
        "try_catch_count", "has_inline_param", "has_pester_test", "has_script_analyzer",
        "has_build_task", "has_markdown_help", "has_io_path", "has_push_pop_location",
        "has_psdatafile_import", "has_benign_framework", "has_module_install", "has_sql_admin",
        "has_email_client", "has_hyperv_admin", "has_convertto_html", "has_azure_admin",
        "has_service_point_manager", "has_benign_secure_string", "has_benign_pscredential",
        "has_whitelisted_download", "has_benign_add_type", "has_benign_pinvoke"
    ]])

    # === 5. Obfuscation / danger features ===
    f["replace_count"] = count_pattern(norm, r"-c?i?replace\b")
    f["join_count"] = count_pattern(norm, r"-join\b(?!-path)|\bjoin\b(?!-path)")
    f["num_webclient"] = count_pattern(norm, r"net\s+webclient")
    f["num_downloadfile"] = count_pattern(norm, r"\bdownload(string|file)\b")
    f["char_cast_count"] = count_pattern(norm, r"\bchar\b|\bbyte\b|\bintptr\b")
    f["xor_count"] = count_pattern(norm, r"-bxor")
    f["num_frombase64"] = count_pattern(norm, r"frombase64string")
    f["bypass_policy"] = has_pattern(norm, r"-(executionpolicy|ep)\s+bypass\b")
    f["amsi_bypass"] = has_pattern(norm, r"\bamsiutils\b|\bamsi\s+fail\b|\bamsi\s+initfailed\b")
    f["encoded_cmd"] = int(contains_encoded_flag(raw))
    f["hidden_window"] = has_pattern(norm, r"-w(indowstyle)?\s+(1|h|hidden)\b")
    f["noprofile"] = int(bool(has_pattern(norm, r"-nop(rofile)?\b")) and not bool(f["has_pester_test"]))
    f["has_fromhexstring"] = has_pattern(raw.lower(), r"fromhexstring")
    f["has_verbosepref_iex"] = has_pattern(raw.lower(), r"verbosepreference.*\[.*1.*,.*3.*\]")
    f["has_format_op_iex"] = has_pattern(raw.lower(), r"""['"].*\{0\}.*\{1\}.*['"].*-f.*['"]i['"].*['"]ex['"]""")
    f["has_pshome_concat"] = has_pattern(raw.lower(), r"\$pshome\[")
    f["has_convert_frombinary"] = has_pattern(norm, r"convert\b.*toint(16|32|64).*\b2\b")
    f["has_tobase64string"] = has_pattern(norm, r"tobase64string")
    f["is_mostly_special_chars"] = 1 if f["special_char_ratio"] > 0.8 else 0
    f["has_assembly_load_b64"] = has_pattern(norm, r"assembly\s+load\s+.*base64")
    f["has_disable_name_checking"] = has_pattern(norm, r"disablenamechecking")
    f["has_marshal_class"] = has_pattern(norm, r"\binteropservices\s+marshal\b")
    f["has_securestring_convert"] = has_pattern(norm, r"\bsecurestring.*bstr\b|\bptr.*string\b")
    f["has_expand_env_vars"] = has_pattern(norm, r"environment\s+expandenvironmentvariables")
    f["complex_format_string"] = has_pattern(raw, r"\{\d+\}.*\{\d+\}.*\{\d+\}")
    f["string_reassembly"] = has_pattern(raw, r"\$\w+\s*=\s*\$\w+\s*\+\s*\$")

    f["obfuscation_score"] = sum([f[k] > 0 for k in [
        "replace_count", "join_count", "xor_count", "encoded_cmd", "hidden_window",
        "amsi_bypass", "has_fromhexstring", "has_verbosepref_iex", "has_format_op_iex",
        "has_pshome_concat", "has_convert_frombinary", "has_tobase64string",
        "has_assembly_load_b64", "noprofile", "bypass_policy", "is_high_entropy",
        "caret_count", "is_mostly_special_chars", "has_disable_name_checking",
        "has_marshal_class", "has_securestring_convert", "has_expand_env_vars",
        "complex_format_string", "string_reassembly"
    ]])

    # === 6. Behavior features ===
    f["iex_count"] = count_pattern(norm, r"\binvoke-expression\b") or count_pattern(raw.lower(), r"\binvoke-expression\b")
    f["has_IEX_alias"] = int(contains_invoke_expression(raw) or bool(re.search(r"i\s*`\s*e\s*`\s*x", raw, flags=re.IGNORECASE)))
    f["iwr_count"] = count_pattern(norm, r"\binvoke-webrequest\b|\biwr\b|\binvoke-restmethod\b|\birm\b|\bwget\b|\bcurl\b")
    f["start_process"] = count_pattern(norm, r"\bstart-process\b|\bstart(?!-)\b")
    f["reg_add"] = count_pattern(norm, r"\breg\s+add\b")
    f["schtasks"] = count_pattern(norm, r"\bschtasks\b")
    f["wmi_query"] = count_pattern(norm, r"\bget-wmiobject\b")
    f["add_mp_preference"] = count_pattern(norm, r"\b(add|set)-mppreference\b")
    f["clear_eventlog"] = count_pattern(norm, r"\bclear-eventlog\b")
    f["powershell_exe"] = has_pattern(norm, r"powershell\s+exe|\Apowershell\b")
    f["cmd_shell"] = has_pattern(norm, r"cmd\s+exe|\bcmd\b.*\b-c\b")
    f["reflected_assembly"] = has_pattern(norm, r"\breflection\s+assembly\s+(load\s|loadfile|loadfrom)\b|\bdefinedynamicassembly\b")
    f["has_marshal_copy"] = has_pattern(norm, r"\bmarshal\s+copy\b")
    f["has_virtualalloc"] = has_pattern(norm, r"\bvirtualalloc\b")
    f["has_createthread"] = has_pattern(norm, r"\bcreatethread\b")
    f["has_page_execute"] = has_pattern(raw, r"0x40")
    f["has_getprocaddress"] = has_pattern(norm, r"\bgetprocaddress\b")
    f["has_reflection_emit"] = has_pattern(norm, r"\breflection\s+emit\b")
    f["has_unsafe_native"] = has_pattern(norm, r"\bunsafenativemethods\b")
    f["has_definedynamic"] = has_pattern(norm, r"\bdefinedynamicassembly\b|\bdefinedynamicmodule\b")
    f["has_file_write"] = int(bool(has_pattern(norm, r"writealltext|set-content|io\s+file\s+create\b|writeallbytes|out-file|\badd-content\b")) or bool(has_pattern(raw.lower(), r">>?\s*[\"'\$]")))
    f["has_user_agent_spoof"] = int(bool(has_pattern(norm, r"headers\s+add\s+user-agent")) or bool(has_pattern(raw.lower(), r"\.useragent\s*=")))
    f["has_credential_cache"] = has_pattern(norm, r"\bcredentialcache\b")
    f["has_bitstransfer"] = has_pattern(norm, r"start-bitstransfer|\bbitsadmin\b")
    f["has_persistence"] = has_pattern(norm, r"currentversion\\run")
    f["suspicious_process"] = has_pattern(norm, r"\brundll32\b|\bregsvr32\b|\bmshta\b|\bwscript\b|\bcscript\b|\bsdbinst\b|\bmsiexec\b|\bnetsh\b")
    f["has_tcp_client"] = has_pattern(norm, r"net\s+sockets\s+tcpclient")
    f["has_stream_io"] = has_pattern(norm, r"io\s+streamreader|io\s+streamwriter")
    f["has_certutil"] = has_pattern(norm, r"\bcertutil\b")
    f["has_tcp_listener"] = has_pattern(norm, r"net\s+sockets\s+tcplistener")
    f["has_webrequest"] = has_pattern(norm, r"net\s+(http)?webrequest")
    f["has_runspace"] = has_pattern(norm, r"runspacefactory|powershell\s+create")
    f["has_ntdsutil"] = has_pattern(norm, r"\bntdsutil\b")
    f["has_admin_check"] = has_pattern(norm, r"security\s+principal\s+windowsidentity|isinrole")
    f["has_adsi_query"] = has_pattern(norm, r"\badsi\b|\bdirectoryservices\b")
    f["has_window_scrape"] = has_pattern(norm, r"windowstation|getforegroundwindow|mainwindowtitle")
    f["gc_count"] = count_pattern(norm, r"\bget-content\b(?!.*\braw\b)")
    f["has_network_recon"] = has_pattern(norm, r"net\s+dns\b|\bgethostaddresses\b|\bgetactivetcpconnections\b|\bipglobalproperties\b")
    f["has_sqlite_access"] = has_pattern(norm, r"data\s+sqlite")
    f["has_browser_recon"] = has_pattern(raw.lower(), r"typedurls|places\.sqlite|history|cookies|logindata")
    f["has_com_execution"] = has_pattern(norm, r"new object\s+com|\bshell\s+application\b|\bshellexecute\b")
    f["has_cred_dump"] = has_pattern(norm, r"key\s+clear|\bmimikatz\b")
    f["has_ps_scheduled_task"] = has_pattern(norm, r"\bregister-scheduledtask\b|\bnew-scheduledtask\b|\bset-scheduledtask\b")
    f["has_invoke_method"] = has_pattern(norm, r"\binvoke-(?!webrequest|expression)")
    f["has_call_operator"] = has_pattern(raw, r"[&\.]\s*\(")
    f["has_dot_sourcing_exec"] = has_pattern(raw.lower(), r"\.\s+[\"'\$]")
    f["has_new_item_file"] = has_pattern(norm, r"new-item.*itemtype\s+file")
    f["has_ps_registry_write"] = has_pattern(norm, r"\bset-itemproperty\b|\bnew-itemproperty\b")
    f["has_event_hook"] = has_pattern(norm, r"register-objectevent|\badd_keydown\b|\badd_click\b")
    f["has_destructive_cmd"] = has_pattern(norm, r"(\bremove-item\b(?!.*\btest\b))|\bclear-content\b|\bstop-computer\b|\btaskkill\b|\bdel\b")
    f["has_batch_syntax"] = has_pattern(norm, r"\bgoto\b|\becho\s+off\b")
    f["has_import_module"] = has_pattern(norm, r"import-module")
    f["has_acl_manipulation"] = has_pattern(norm, r"\bget-acl\b|\bset-acl\b|accesscontrol\s+filesystemaccessrule|\btakeown\b|\bicacls\b")
    f["has_recurse_param"] = int(bool(has_pattern(norm, r"-recurse\b")) or bool(has_pattern(raw.lower(), r"\s/r\b|\s/s\b")))
    f["has_get_eventlog"] = has_pattern(norm, r"\bget-eventlog\b|\bget-winevent\b")
    f["has_read_registry"] = has_pattern(norm, r"(get-itemproperty|get-childitem).*\b(hkey|hku|hklm|hkcu)\b")
    f["has_rdp_query"] = has_pattern(norm, r"terminal\s+server\s+client")

    f["behavior_score"] = sum([f[k] > 0 for k in [
        "iex_count", "iwr_count", "start_process", "reg_add", "schtasks", "wmi_query",
        "add_mp_preference", "clear_eventlog", "http_count", "httpsG_count", "ip_count",
        "powershell_exe", "cmd_shell", "reflected_assembly", "num_webclient",
        "num_downloadfile", "has_file_write", "has_add_type", "has_pinvoke",
        "has_virtualalloc", "has_createthread", "has_page_execute", "has_getprocaddress",
        "has_marshal_copy", "has_reflection_emit", "has_unsafe_native", "has_definedynamic",
        "has_tcp_client", "has_stream_io", "has_certutil", "has_tcp_listener",
        "has_webrequest", "has_runspace", "has_user_agent_spoof", "has_credential_cache",
        "has_bitstransfer", "has_persistence", "suspicious_process", "has_get_eventlog",
        "has_read_registry", "has_rdp_query", "has_secure_string", "has_pscredential",
        "has_ntdsutil", "has_admin_check", "has_adsi_query", "has_window_scrape",
        "has_destructive_cmd", "has_acl_manipulation", "has_recurse_param", "has_import_module",
        "has_event_hook", "has_network_recon", "gc_count", "has_IEX_alias",
        "has_ps_registry_write", "has_invoke_method", "has_call_operator", "has_sqlite_access",
        "has_com_execution", "has_cred_dump", "has_ps_scheduled_task", "has_dot_sourcing_exec",
        "has_new_item_file", "has_winforms", "has_batch_syntax", "has_browser_recon"
    ]])

    # === G2.96 combined score ===
    f["risk_score"] = f["obfuscation_score"] + f["payload_score"] + f["behavior_score"]

    has_download = (
        f["num_webclient"] > 0 or f["num_downloadfile"] > 0 or f["iwr_count"] > 0 or
        f["has_bitstransfer"] > 0 or f["has_certutil"] > 0 or f["has_webrequest"] > 0 or
        f["has_tcp_client"] > 0 or f["has_tcp_listener"] > 0
    )

    has_execute = (
        f["iex_count"] > 0 or f["powershell_exe"] > 0 or f["start_process"] > 0 or
        f["cmd_shell"] > 0 or f["reflected_assembly"] > 0
    )

    if has_download and has_execute and f["has_whitelisted_download"] == 0:
        f["risk_score"] += 5.0

    if f["powershell_exe"] > 0 and f["encoded_cmd"] > 0:
        f["risk_score"] += 5.0

    if f["hidden_window"] > 0 and (f["suspicious_process"] > 0 or f["powershell_exe"] > 0):
        f["risk_score"] += 3.0

    has_escalation_intent = f["has_admin_check"] > 0 and (f["has_ntdsutil"] > 0 or f["reg_add"] > 0 or f["schtasks"] > 0)
    if has_escalation_intent:
        f["risk_score"] += 3.0

    f["final_risk_score"] = f["risk_score"] / (f["benign_score"] + 1.0)

    # Runtime-only metadata useful for logs, but not required for ML training.
    f["runtime_source_is_amsi"] = int(event.get("source") == "amsi_cpp_bridge")
    f["runtime_source_is_file"] = int(event.get("source") == "file_sensor")
    f["runtime_source_is_process"] = int(event.get("source") == "process_sensor")
    f["runtime_source_is_eventlog"] = int(event.get("source") == "eventlog_4104_sensor")

    return f


# Backward-compatible name for the rest of the Agent.
def extract_features(script: str, event: dict | None = None) -> dict:
    return extract_features_g296(script, event)


# =====================================================
# G2.96 DATA ANALYSIS
# This replaces the old simple analyzer with tiểu luận-style scoring.
# =====================================================
def analyze_features(features: dict) -> dict:
    score = float(features.get("final_risk_score", 0.0))
    raw_risk = float(features.get("risk_score", 0.0))
    benign_score = float(features.get("benign_score", 0.0))
    reasons = []

    # Payload / obfuscation reasons
    if features.get("encoded_cmd"):
        reasons.append("EncodedCommand indicator")
    if features.get("num_frombase64") or features.get("has_base64_payload"):
        reasons.append("Base64 payload or FromBase64String")
    if features.get("is_high_entropy"):
        reasons.append("High entropy content")
    if features.get("amsi_bypass"):
        reasons.append("AMSI bypass indicator")
    if features.get("hidden_window"):
        reasons.append("Hidden PowerShell window")
    if features.get("bypass_policy"):
        reasons.append("ExecutionPolicy bypass")
    if features.get("noprofile"):
        reasons.append("NoProfile execution")
    if features.get("replace_count") or features.get("join_count") or features.get("xor_count"):
        reasons.append("Obfuscation operators")
    if features.get("has_fromhexstring") or features.get("has_hex_byte_array"):
        reasons.append("Hex payload indicator")

    # Behavior reasons
    if features.get("iex_count") or features.get("has_IEX_alias"):
        reasons.append("Dynamic execution via IEX/Invoke-Expression")
    if features.get("iwr_count") or features.get("num_webclient") or features.get("num_downloadfile"):
        reasons.append("Downloader behavior")
    if features.get("http_count") or features.get("httpsG_count") or features.get("ip_count") or features.get("domain_count"):
        reasons.append("Network indicator present")
    if features.get("has_cred_dump"):
        reasons.append("Credential dumping keyword")
    if features.get("has_persistence") or features.get("reg_add") or features.get("schtasks") or features.get("has_ps_scheduled_task"):
        reasons.append("Persistence behavior")
    if features.get("add_mp_preference"):
        reasons.append("Defender configuration modification")
    if features.get("clear_eventlog"):
        reasons.append("Event log clearing behavior")
    if features.get("has_virtualalloc") or features.get("has_createthread") or features.get("has_getprocaddress"):
        reasons.append("Memory injection style API usage")
    if features.get("suspicious_process"):
        reasons.append("Suspicious LOLBin/process reference")
    if features.get("has_browser_recon"):
        reasons.append("Browser data reconnaissance")
    if features.get("has_read_registry") or features.get("has_ps_registry_write"):
        reasons.append("Registry access or modification")

    # Benign balancing reasons
    if benign_score > 0:
        reasons.append(f"Benign indicators present: {int(benign_score)}")

    if score >= G296_HIGH_RISK_THRESHOLD:
        risk_level = "HIGH"
    elif score >= G296_MEDIUM_RISK_THRESHOLD:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_score": score,
        "raw_risk_score": raw_risk,
        "benign_score": benign_score,
        "risk_level": risk_level,
        "reasons": reasons,
    }

def has_download_execute_chain(features: dict) -> bool:
    has_download = any([
        features.get("num_webclient", 0) > 0,
        features.get("num_downloadfile", 0) > 0,
        features.get("iwr_count", 0) > 0,
        features.get("has_bitstransfer", 0) > 0,
        features.get("has_certutil", 0) > 0,
        features.get("has_webrequest", 0) > 0,
        features.get("has_tcp_client", 0) > 0,
        features.get("has_tcp_listener", 0) > 0,
        features.get("http_count", 0) > 0,
        features.get("httpsG_count", 0) > 0,
    ])

    has_execute = any([
        features.get("iex_count", 0) > 0,
        features.get("has_IEX_alias", 0) > 0,
        features.get("powershell_exe", 0) > 0,
        features.get("start_process", 0) > 0,
        features.get("cmd_shell", 0) > 0,
        features.get("reflected_assembly", 0) > 0,
        features.get("has_assembly_load_b64", 0) > 0,
    ])

    is_whitelisted = features.get("has_whitelisted_download", 0) > 0

    return has_download and has_execute and not is_whitelisted


def has_defense_evasion(features: dict, script: str) -> bool:
    s = normalize_compact(script)

    return any([
        features.get("amsi_bypass", 0) > 0,
        features.get("add_mp_preference", 0) > 0,
        "amsiutils" in s,
        "amsiinitfailed" in s,
        "set-mppreference" in s,
        "disablerealtimemonitoring" in s,
    ])

def make_rule_result(verdict: str = "ALLOW", rule_ids=None, reasons=None) -> dict:
    return {
        "verdict": verdict,
        "rule_ids": rule_ids or [],
        "reasons": reasons or [],
    }


def merge_unique_list(*lists) -> list:
    merged = []
    seen = set()

    for items in lists:
        if not items:
            continue

        for item in items:
            if item is None:
                continue

            item = str(item)
            if item not in seen:
                seen.add(item)
                merged.append(item)

    return merged

# =====================================================
# RULE-BASED BASELINE USING G2.96 FEATURES
# =====================================================
def rule_analyze(script: str, event: dict | None = None, features: dict | None = None) -> dict:
    event = event or {}
    features = features or extract_features(script, event)
    s = normalize_compact(script)

    rule_ids = []
    reasons = []

    # High-confidence post-exploitation / credential theft.
    if features.get("has_cred_dump") or "mimikatz" in s or "sekurlsa" in s or "logonpasswords" in s or "lsadump" in s:
        return make_rule_result(
            verdict="TERMINATE",
            rule_ids=["PY-PS-CRED-001"],
            reasons=["Credential dumping or post-exploitation indicator detected"],
        )

    # Download + Execute chain.
    if has_download_execute_chain(features):
        return make_rule_result(
            verdict="TERMINATE",
            rule_ids=["PY-PS-DOWNLOAD-EXEC-001"],
            reasons=["PowerShell downloads remote content and executes it dynamically"],
        )

    # AMSI bypass / Defender disable / defense evasion.
    if has_defense_evasion(features, script):
        return make_rule_result(
            verdict="TERMINATE",
            rule_ids=["PY-PS-DEFENSE-EVASION-001"],
            reasons=["PowerShell attempts AMSI bypass or Defender configuration modification"],
        )

    # Extremely suspicious runtime combination.
    if features.get("final_risk_score", 0.0) >= G296_TERMINATE_RISK_THRESHOLD:
        if features.get("has_virtualalloc") or features.get("has_createthread") or features.get("has_cred_dump"):
            return make_rule_result(
                verdict="TERMINATE",
                rule_ids=["PY-PS-HIGH-RISK-001"],
                reasons=["High risk score with memory injection or credential theft behavior"],
            )

    # Alert-worthy behavior.
    alert_checks = [
        ("encoded_cmd", "PY-PS-OBF-001", "EncodedCommand indicator"),
        ("iex_count", "PY-PS-DYNAMIC-001", "Dynamic execution via Invoke-Expression"),
        ("has_IEX_alias", "PY-PS-DYNAMIC-002", "Dynamic execution via IEX alias"),
        ("iwr_count", "PY-PS-DOWNLOAD-001", "Web request or downloader command"),
        ("num_webclient", "PY-PS-DOWNLOAD-002", "WebClient downloader behavior"),
        ("num_downloadfile", "PY-PS-DOWNLOAD-003", "DownloadFile or DownloadString behavior"),
        ("num_frombase64", "PY-PS-OBF-002", "FromBase64String indicator"),
        ("has_base64_payload", "PY-PS-OBF-003", "Base64-like payload"),
        ("bypass_policy", "PY-PS-EVASION-001", "ExecutionPolicy bypass"),
        ("hidden_window", "PY-PS-STEALTH-001", "Hidden PowerShell window"),
        ("noprofile", "PY-PS-STEALTH-002", "NoProfile execution"),
        ("clear_eventlog", "PY-PS-EVASION-002", "Event log clearing behavior"),
        ("reg_add", "PY-PS-PERSIST-001", "Registry modification behavior"),
        ("schtasks", "PY-PS-PERSIST-002", "Scheduled task behavior"),
        ("has_ps_registry_write", "PY-PS-PERSIST-003", "PowerShell registry write behavior"),
        ("has_persistence", "PY-PS-PERSIST-004", "Persistence indicator"),
        ("has_certutil", "PY-LOL-001", "Certutil usage"),
        ("suspicious_process", "PY-LOL-002", "Suspicious LOLBin/process reference"),
        ("has_bitstransfer", "PY-PS-DOWNLOAD-004", "BITS transfer behavior"),
        ("has_tcp_client", "PY-PS-NET-001", "TCP client behavior"),
        ("has_tcp_listener", "PY-PS-NET-002", "TCP listener behavior"),
        ("has_webrequest", "PY-PS-NET-003", "WebRequest behavior"),
    ]

    for feature_name, rule_id, reason in alert_checks:
        if features.get(feature_name, 0):
            rule_ids.append(rule_id)
            reasons.append(reason)

    if rule_ids:
        return make_rule_result(
            verdict="ALERT",
            rule_ids=rule_ids,
            reasons=reasons,
        )

    if features.get("final_risk_score", 0.0) >= G296_HIGH_RISK_THRESHOLD:
        return make_rule_result(
            verdict="ALERT",
            rule_ids=["PY-G296-HIGH-RISK-001"],
            reasons=["G2.96 final risk score exceeds high threshold"],
        )

    return make_rule_result()


# =====================================================
# ML PLUGIN LAYER
# ML team only needs:
#   model/random_forest_model.pkl
#   model/feature_columns.pkl
# =====================================================
def load_ml_model():
    global ml_model, feature_columns, ml_enabled

    ml_enabled = False
    ml_model = None
    feature_columns = None

    if joblib is None:
        print("[ML] joblib is not installed. ML disabled.")
        return

    if pd is None:
        print("[ML] pandas is not installed. ML disabled.")
        return

    if not os.path.exists(MODEL_PATH):
        print(f"[ML] Model not found: {MODEL_PATH}. ML disabled.")
        return

    if not os.path.exists(FEATURE_COLUMNS_PATH):
        print(f"[ML] Feature columns file not found: {FEATURE_COLUMNS_PATH}. ML disabled.")
        return

    try:
        ml_model = joblib.load(MODEL_PATH)
        feature_columns = joblib.load(FEATURE_COLUMNS_PATH)

        if not isinstance(feature_columns, list):
            feature_columns = list(feature_columns)

        ml_enabled = True
        print("[ML] Model loaded successfully.")
        print(f"[ML] Feature count: {len(feature_columns)}")

    except Exception as e:
        print("[ML ERROR] Cannot load ML model:", e)
        ml_enabled = False
        ml_model = None
        feature_columns = None


def ml_analyze(features: dict) -> tuple[str, float]:
    if not ml_enabled or ml_model is None or feature_columns is None or pd is None:
        return "UNKNOWN", 0.0

    try:
        row = {col: features.get(col, 0) for col in feature_columns}
        X = pd.DataFrame([row], columns=feature_columns)
        pred = ml_model.predict(X)[0]

        confidence = 0.0
        if hasattr(ml_model, "predict_proba"):
            proba = ml_model.predict_proba(X)[0]
            confidence = float(max(proba))

        pred_str = str(pred).lower()

        if pred_str in ["1", "malicious", "malware", "bad"]:
            return "MALICIOUS", confidence
        if pred_str in ["2", "suspicious"]:
            return "SUSPICIOUS", confidence
        if pred_str in ["0", "benign", "clean", "allow"]:
            return "BENIGN", confidence

        return "UNKNOWN", confidence

    except Exception as e:
        print("[ML ERROR] Prediction failed:", e)
        return "UNKNOWN", 0.0


# =====================================================
# VERDICT COMBINATION
# =====================================================
def combine_verdict(cpp_verdict: str, rule_verdict: str, ml_verdict: str, ml_confidence: float, risk_level: str) -> str:
    cpp_verdict = (cpp_verdict or "ALLOW").upper()
    rule_verdict = (rule_verdict or "ALLOW").upper()
    ml_verdict = (ml_verdict or "UNKNOWN").upper()
    risk_level = (risk_level or "LOW").upper()

    if cpp_verdict == "TERMINATE" or rule_verdict == "TERMINATE":
        return "TERMINATE"

    if ml_verdict == "MALICIOUS" and ml_confidence >= ML_MALICIOUS_CONFIDENCE_THRESHOLD:
        if cpp_verdict == "ALERT" or rule_verdict == "ALERT" or risk_level == "HIGH":
            return "TERMINATE"
        return "ALERT"

    if cpp_verdict == "ALERT" or rule_verdict == "ALERT":
        return "ALERT"

    if ml_verdict in ["MALICIOUS", "SUSPICIOUS"]:
        return "ALERT"

    if risk_level == "HIGH":
        return "ALERT"

    return "ALLOW"


# =====================================================
# LOGGING
# =====================================================
def write_jsonl(event: dict):
    with log_lock:
        with open(EVENT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")


def append_features_csv(features: dict, event: dict):
    if pd is None:
        return

    row = dict(features)
    row["timestamp"] = event.get("received_at_human")
    row["sha256"] = event.get("sha256")
    row["source"] = event.get("source")
    row["pid"] = event.get("pid")
    row["process"] = event.get("process")
    row["event_path"] = event.get("path")
    row["cpp_verdict"] = event.get("local_verdict")
    row["rule_verdict"] = event.get("rule_verdict")
    row["rule_ids"] = "|".join(event.get("rule_ids", []))
    row["reasons"] = "|".join(event.get("reasons", []))
    row["local_rule_ids"] = "|".join(event.get("local_rule_ids", [])) if isinstance(event.get("local_rule_ids"), list) else event.get("local_rule_ids")
    row["local_reasons"] = "|".join(event.get("local_reasons", [])) if isinstance(event.get("local_reasons"), list) else event.get("local_reasons")
    row["ml_enabled"] = event.get("ml_enabled")
    row["ml_verdict"] = event.get("ml_verdict")
    row["ml_confidence"] = event.get("ml_confidence")
    row["risk_level"] = event.get("data_analysis", {}).get("risk_level")
    row["final_verdict"] = event.get("final_verdict")

    df = pd.DataFrame([row])

    with log_lock:
        file_exists = os.path.exists(FEATURE_LOG_PATH)
        df.to_csv(FEATURE_LOG_PATH, mode="a", index=False, header=not file_exists, encoding="utf-8")


# =====================================================
# EVENT PROCESSING
# =====================================================
def is_duplicate(event_hash: str) -> bool:
    with seen_lock:
        if event_hash in seen_hashes:
            return True
        seen_hashes.add(event_hash)
        if len(seen_hashes) > MAX_DEDUP_CACHE:
            seen_hashes.clear()
        return False


def build_detection_result(data: dict) -> dict:
    script = data.get("script", "") or ""
    cpp_verdict = data.get("local_verdict", "ALLOW")
    event_hash = data.get("sha256") or sha256_text(script)

    features = extract_features(script, data)
    analysis = analyze_features(features)
    rule_result = rule_analyze(script, data, features)
    rule_verdict = rule_result.get("verdict", "ALLOW")
    ml_verdict, ml_confidence = ml_analyze(features)

    final_verdict = combine_verdict(
        cpp_verdict=cpp_verdict,
        rule_verdict=rule_verdict,
        ml_verdict=ml_verdict,
        ml_confidence=ml_confidence,
        risk_level=analysis.get("risk_level", "LOW"),
    )
    cpp_rule_ids = data.get("local_rule_ids", [])
    cpp_reasons = data.get("local_reasons", [])

    if not isinstance(cpp_rule_ids, list):
        cpp_rule_ids = [str(cpp_rule_ids)]

    if not isinstance(cpp_reasons, list):
        cpp_reasons = [str(cpp_reasons)]

    combined_rule_ids = merge_unique_list(
        cpp_rule_ids,
        rule_result.get("rule_ids", []),
    )

    combined_reasons = merge_unique_list(
        cpp_reasons,
        rule_result.get("reasons", []),
        analysis.get("reasons", []),
    )

    data["sha256"] = event_hash
    data["received_at"] = time.time()
    data["received_at_human"] = now_ts()
    data["features"] = features
    data["data_analysis"] = analysis
    data["rule_verdict"] = rule_verdict
    data["rule_result"] = rule_result
    data["rule_ids"] = combined_rule_ids
    data["reasons"] = combined_reasons
    data["ml_enabled"] = ml_enabled
    data["ml_verdict"] = ml_verdict
    data["ml_confidence"] = ml_confidence
    data["final_verdict"] = final_verdict

    return data


def submit_event(event: dict, dedup: bool = True) -> dict | None:
    script = event.get("script", "") or ""
    if not script:
        return None

    if is_trivial_noise(script):
        return None

    event.setdefault("source", "unknown")
    event.setdefault("local_verdict", "ALLOW")

    result_event = build_detection_result(event)

    if dedup and is_duplicate(result_event.get("sha256", "")):
        return result_event

    event_queue.put(result_event)
    return result_event


def worker():
    while True:
        event = event_queue.get()
        try:
            print("\n========== PYTHON EDR AGENT ==========")
            print("TIME:", event.get("received_at_human"))
            print("SOURCE:", event.get("source"))
            print("PID:", event.get("pid"))
            print("PROCESS:", event.get("process"))
            if event.get("path"):
                print("PATH:", event.get("path"))
            print("C++ LOCAL:", event.get("local_verdict"))
            print("RULE:", event.get("rule_verdict"))
            print("ML ENABLED:", event.get("ml_enabled"))
            print("ML:", event.get("ml_verdict"), "CONF:", event.get("ml_confidence"))
            print("RISK:", event.get("data_analysis", {}).get("risk_level"), event.get("data_analysis", {}).get("risk_score"))
            print("RAW RISK:", event.get("data_analysis", {}).get("raw_risk_score"), "BENIGN:", event.get("data_analysis", {}).get("benign_score"))
            print("RULE IDS:", ", ".join(event.get("rule_ids", [])))
            print("REASONS:", ", ".join(event.get("reasons", [])))
            print("FINAL:", event.get("final_verdict"))
            print("SCRIPT:", truncate(event.get("script", "")))
            write_jsonl(event)
            append_features_csv(event.get("features", {}), event)
        except Exception as e:
            print("[WORKER ERROR]", e)


# =====================================================
# SENSOR 1: PROCESS SENSOR
# =====================================================
def process_sensor():
    if psutil is None:
        print("[PROCESS SENSOR] psutil not installed. Sensor disabled.")
        return

    print("[SENSOR] Process Sensor started.")
    seen_pids = set()
    try:
        for proc in psutil.process_iter(["pid"]):
            seen_pids.add(proc.info["pid"])
        print(f"[PROCESS SENSOR] Baseline existing processes: {len(seen_pids)}")
    except Exception as e:
        print("[PROCESS SENSOR INIT ERROR]", e)

    while True:
        try:
            for proc in psutil.process_iter(["pid", "ppid", "name", "cmdline"]):
                try:
                    info = proc.info
                    pid = info.get("pid")
                    name = info.get("name") or ""
                    lower_name = name.lower()
                    if pid in seen_pids:
                        continue
                    if lower_name not in SUSPICIOUS_PROCESS_NAMES:
                        continue
                    seen_pids.add(pid)
                    cmdline_list = info.get("cmdline") or []
                    cmdline = " ".join(cmdline_list)
                    cmdline_lower = cmdline.lower().strip()
                    if cmdline_lower.endswith("powershell.exe") or cmdline_lower.endswith("pwsh.exe"):
                        continue
                    if not cmdline.strip():
                        continue
                    event = {
                        "source": "process_sensor",
                        "pid": pid,
                        "ppid": info.get("ppid"),
                        "process": name,
                        "parent_process": "",
                        "script": cmdline,
                        "local_verdict": "ALLOW",
                    }
                    submit_event(event)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            print("[PROCESS SENSOR ERROR]", e)
        time.sleep(1)


# =====================================================
# SENSOR 2: FILE SENSOR
# =====================================================
class ScriptFileHandler(FileSystemEventHandler):
    def on_created(self, event):
        self.handle_event(event)

    def on_modified(self, event):
        self.handle_event(event)

    def handle_event(self, event):
        if getattr(event, "is_directory", False):
            return
        path = getattr(event, "src_path", "")
        if not path.lower().endswith(SCRIPT_EXTENSIONS):
            return
        try:
            time.sleep(0.2)
            if not os.path.exists(path):
                return
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            if not content.strip():
                return
            event_data = {
                "source": "file_sensor",
                "pid": 0,
                "ppid": 0,
                "process": "file_system",
                "parent_process": "",
                "path": path,
                "script": content,
                "local_verdict": "ALLOW",
            }
            submit_event(event_data)
        except Exception as e:
            print("[FILE SENSOR ERROR]", e)


def file_sensor():
    if Observer is None:
        print("[FILE SENSOR] watchdog not installed. Sensor disabled.")
        return
    print("[SENSOR] File Sensor started.")
    observer = Observer()
    handler = ScriptFileHandler()
    watched_any = False
    for path in WATCH_PATHS:
        if os.path.exists(path):
            observer.schedule(handler, path, recursive=True)
            watched_any = True
            print("[FILE SENSOR] Watching:", path)
    if not watched_any:
        print("[FILE SENSOR] No valid watch paths. Sensor disabled.")
        return
    observer.start()
    try:
        while True:
            time.sleep(1)
    except Exception:
        observer.stop()
    observer.join()


# =====================================================
# SENSOR 3: EVENT LOG 4104 SENSOR
# =====================================================
def get_latest_4104_record_id():
    if win32evtlog is None:
        return 0

    try:
        query = "*[System[(EventID=4104)]]"

        handle = win32evtlog.EvtQuery(
            POWERSHELL_EVENT_LOG,
            win32evtlog.EvtQueryReverseDirection,
            query
        )

        events = win32evtlog.EvtNext(handle, 1)

        if not events:
            return 0

        xml = win32evtlog.EvtRender(events[0], win32evtlog.EvtRenderEventXml)

        record_match = re.search(r"<EventRecordID>(\d+)</EventRecordID>", xml)
        if not record_match:
            return 0

        return int(record_match.group(1))

    except Exception as e:
        print("[EVENTLOG SENSOR INIT ERROR]", e)
        return 0

def eventlog_4104_sensor():
    print("[SENSOR] Event Log 4104 Sensor started.")

    if win32evtlog is None:
        print("[EVENTLOG SENSOR] pywin32 not installed. Sensor disabled.")
        return

    last_record_id = get_latest_4104_record_id()
    print(f"[EVENTLOG SENSOR] Starting from RecordID: {last_record_id}")

    query = "*[System[(EventID=4104)]]"

    while True:
        try:
            handle = win32evtlog.EvtQuery(
                POWERSHELL_EVENT_LOG,
                win32evtlog.EvtQueryReverseDirection,
                query
            )

            events = win32evtlog.EvtNext(handle, 20)
            batch = []

            for ev in events:
                xml = win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml)

                record_match = re.search(r"<EventRecordID>(\d+)</EventRecordID>", xml)
                if not record_match:
                    continue

                record_id = int(record_match.group(1))
                if record_id <= last_record_id:
                    continue

                script_blocks = re.findall(
                    r"<Data Name=['\"]ScriptBlockText['\"]>(.*?)</Data>",
                    xml,
                    flags=re.DOTALL
                )

                if not script_blocks:
                    # Fallback: sometimes payload is in generic Data fields
                    script_blocks = re.findall(
                        r"<Data[^>]*>(.*?)</Data>",
                        xml,
                        flags=re.DOTALL
                    )

                message = "\n".join(script_blocks)

                # XML escape cleanup
                message = (
                    message.replace("&lt;", "<")
                    .replace("&gt;", ">")
                    .replace("&amp;", "&")
                    .replace("&quot;", '"')
                    .replace("&apos;", "'")
                )

                if not message.strip():
                    continue

                batch.append((record_id, message))

            batch.sort(key=lambda x: x[0])

            for record_id, message in batch:
                last_record_id = max(last_record_id, record_id)

                event = {
                    "source": "eventlog_4104_sensor",
                    "pid": 0,
                    "ppid": 0,
                    "process": "powershell_eventlog",
                    "parent_process": "",
                    "event_id": 4104,
                    "record_id": record_id,
                    "script": message,
                    "local_verdict": "ALLOW",
                }

                submit_event(event)

        except Exception as e:
            print("[EVENTLOG SENSOR ERROR]", e)

        time.sleep(2)


# =====================================================
# HTTP API
# =====================================================
@app.route("/telemetry", methods=["POST"])
def telemetry():
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"status": "bad_json", "verdict": "ALLOW"}), 400

    if not isinstance(data, dict):
        return jsonify({"status": "invalid_payload", "verdict": "ALLOW"}), 400

    script = data.get("script", "") or ""
    if not script:
        return jsonify({"status": "empty_script", "verdict": "ALLOW"}), 200

    result_event = submit_event(data, dedup=True)
    if result_event is None:
        return jsonify({"status": "ignored_noise", "verdict": "ALLOW"}), 200

    return jsonify({
        "status": "received",
        "verdict": result_event.get("final_verdict", "ALLOW"),
        "rule_verdict": result_event.get("rule_verdict", "ALLOW"),
        "rule_ids": result_event.get("rule_ids", []),
        "reasons": result_event.get("reasons", []),
        "ml_enabled": result_event.get("ml_enabled", False),
        "ml_verdict": result_event.get("ml_verdict", "UNKNOWN"),
        "ml_confidence": result_event.get("ml_confidence", 0.0),
        "risk_level": result_event.get("data_analysis", {}).get("risk_level", "LOW"),
        "risk_score": result_event.get("data_analysis", {}).get("risk_score", 0),
        "raw_risk_score": result_event.get("data_analysis", {}).get("raw_risk_score", 0),
        "benign_score": result_event.get("data_analysis", {}).get("benign_score", 0),
    }), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "running",
        "ml_enabled": ml_enabled,
        "model_path": MODEL_PATH,
        "feature_columns_path": FEATURE_COLUMNS_PATH,
        "feature_version": "G2.96",
        "process_sensor": ENABLE_PROCESS_SENSOR and psutil is not None,
        "file_sensor": ENABLE_FILE_SENSOR and Observer is not None,
        "eventlog_4104_sensor": ENABLE_EVENTLOG_4104_SENSOR and win32evtlog is not None,
    }), 200


@app.route("/reload-model", methods=["POST"])
def reload_model():
    load_ml_model()
    return jsonify({"status": "reloaded", "ml_enabled": ml_enabled}), 200


@app.route("/", methods=["GET"])
def home():
    return "Python EDR Agent Multi-Sensor G2.96 ML-Ready Running", 200


# =====================================================
# MAIN
# =====================================================
if __name__ == "__main__":
    ensure_dirs()
    load_ml_model()

    threading.Thread(target=worker, daemon=True).start()

    if ENABLE_PROCESS_SENSOR:
        threading.Thread(target=process_sensor, daemon=True).start()
    if ENABLE_FILE_SENSOR:
        threading.Thread(target=file_sensor, daemon=True).start()
    if ENABLE_EVENTLOG_4104_SENSOR:
        threading.Thread(target=eventlog_4104_sensor, daemon=True).start()

    print(f"[+] Python EDR Agent listening on http://{HOST}:{PORT}")
    print(f"[+] Feature Extraction: G2.96")
    print(f"[+] Logs: {LOG_DIR}")
    print(f"[+] ML model path: {MODEL_PATH}")
    print(f"[+] Feature columns path: {FEATURE_COLUMNS_PATH}")

    app.run(host=HOST, port=PORT)
