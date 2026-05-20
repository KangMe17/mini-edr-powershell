
from flask import Flask, request, jsonify

import os
import re
import json
import time
import math
import queue
import hashlib
import threading
import html
import shutil
from collections import Counter
from xml.etree import ElementTree as ET

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
    from watchdog.observers.polling import PollingObserver
    from watchdog.events import FileSystemEventHandler
except ImportError:
    Observer = None
    PollingObserver = None
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
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")

EVENT_LOG_PATH = os.path.join(LOG_DIR, "edr_events.jsonl")
FEATURE_LOG_PATH = os.path.join(LOG_DIR, "edr_features_g296.csv")
QUARANTINE_INDEX_PATH = os.path.join(LOG_DIR, "quarantine_index.jsonl")

MODEL_PATH = os.path.join(MODEL_DIR, "random_forest_model.pkl")
FEATURE_COLUMNS_PATH = os.path.join(MODEL_DIR, "feature_columns.pkl")

ENABLE_PROCESS_SENSOR = True
ENABLE_FILE_SENSOR = True
ENABLE_EVENTLOG_4104_SENSOR = True
ENABLE_RESPONSE = os.environ.get("EDR_ENABLE_RESPONSE", "0").strip().lower() in {"1", "true", "yes", "on"}

def build_watch_paths():
    env_value = os.environ.get("EDR_WATCH_PATHS", "").strip()
    if env_value:
        candidates = [
            os.path.expandvars(os.path.expanduser(path.strip()))
            for path in env_value.split(";")
            if path.strip()
        ]
    else:
        user_home = os.path.expanduser("~")
        candidates = [
            os.path.join(user_home, "Desktop"),
            os.path.join(user_home, "Downloads"),
            os.path.join(user_home, "Documents"),
            os.path.join(user_home, "OneDrive", "Documents"),
            os.path.join(user_home, "OneDrive", "Desktop"),
        ]

    result = []
    seen = set()
    for path in candidates:
        normalized = os.path.normpath(path)
        key = os.path.normcase(normalized)
        if key not in seen:
            result.append(normalized)
            seen.add(key)
    return result


WATCH_PATHS = build_watch_paths()

SCRIPT_EXTENSIONS = (
    ".ps1", ".psm1", ".psd1",
    ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta",
    ".bat", ".cmd"
)

SUSPICIOUS_PROCESS_NAMES = {
    "powershell.exe",
    "pwsh.exe",
    "powershell_ise.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "reg.exe",
    "schtasks.exe",
}

PROTECTED_PROCESS_NAMES = {
    "system",
    "system idle process",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "explorer.exe",
    "python.exe",
    "pythonw.exe",
}

PROTECTED_COMMANDLINE_SUBSTRINGS = (
    "pythonagent.py",
    "start_python_agent.ps1",
    "stop_python_agent.ps1",
    "status_python_agent.ps1",
    "run_response_tests.ps1",
)

POWERSHELL_EVENT_LOG = "Microsoft-Windows-PowerShell/Operational"
POWERSHELL_EVENT_ID = 4104

MAX_FILE_READ_BYTES = 1024 * 1024
FILE_READ_RETRY_COUNT = 5
FILE_READ_RETRY_DELAY_SECONDS = 0.2
FILE_STABLE_READS_REQUIRED = 2
FILE_EMPTY_MODIFIED_GRACE_SECONDS = 1.0
SENSOR_POLL_INTERVAL_SECONDS = 0.5
EVENTLOG_READ_BATCH_SIZE = max(1, int(os.environ.get("EDR_EVENTLOG_BATCH_SIZE", "64")))

MAX_DEDUP_CACHE = 5000
MAX_SCRIPT_LOG_CHARS = 900
ML_MALICIOUS_CONFIDENCE_THRESHOLD = 0.90
EVENT_QUEUE_MAX_SIZE = max(1, int(os.environ.get("EDR_EVENT_QUEUE_MAX_SIZE", "2048")))
EVENT_WORKER_COUNT = max(1, int(os.environ.get("EDR_EVENT_WORKERS", "2")))
TELEMETRY_RESULT_TIMEOUT_SECONDS = float(os.environ.get("EDR_TELEMETRY_RESULT_TIMEOUT_SECONDS", "0.9"))

# Risk thresholds based on G2.96 final_risk_score.
# These thresholds are intentionally conservative for runtime EDR usage.
G296_MEDIUM_RISK_THRESHOLD = 1.0
G296_HIGH_RISK_THRESHOLD = 3.0
G296_TERMINATE_RISK_THRESHOLD = 8.0

# ================= GLOBAL STATE =================
event_queue = queue.Queue(maxsize=EVENT_QUEUE_MAX_SIZE)
seen_hashes = set()
seen_lock = threading.Lock()
log_lock = threading.Lock()
console_lock = threading.Lock()
response_lock = threading.Lock()
queue_stats_lock = threading.Lock()
quarantined_paths = set()
queue_stats = {
    "submitted": 0,
    "processed": 0,
    "duplicates": 0,
    "dropped": 0,
    "errors": 0,
    "reply_timeouts": 0,
}

ml_model = None
feature_columns = None
ml_enabled = False


# =====================================================
# BASIC UTILS
# =====================================================
def ensure_dirs():
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(MODEL_DIR, exist_ok=True)
    os.makedirs(QUARANTINE_DIR, exist_ok=True)


def now_ts():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def sha256_text(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="ignore")).hexdigest()


def normalize_compact(text: str) -> str:
    return "".join((text or "").lower().split())


def truncate(text: str, limit: int = MAX_SCRIPT_LOG_CHARS) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return text[:limit] + " ...[truncated]"


def safe_console_text(text: str) -> str:
    return (text or "").encode("ascii", errors="backslashreplace").decode("ascii")


def safe_mean(values):
    if not values:
        return 0.0
    if np is not None:
        return float(np.mean(values))
    return sum(values) / len(values)


def bump_queue_stat(name: str, amount: int = 1):
    with queue_stats_lock:
        queue_stats[name] = queue_stats.get(name, 0) + amount


def queue_snapshot() -> dict:
    with queue_stats_lock:
        snapshot = dict(queue_stats)
    snapshot["size"] = event_queue.qsize()
    snapshot["max_size"] = EVENT_QUEUE_MAX_SIZE
    snapshot["workers"] = EVENT_WORKER_COUNT
    snapshot["telemetry_wait_timeout_seconds"] = TELEMETRY_RESULT_TIMEOUT_SECONDS
    return snapshot


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


def tokenize_ps(text: str) -> list[str]:
    if not text:
        return []
    return re.findall(r"[A-Za-z_][A-Za-z0-9_-]{1,}|\$[A-Za-z_][A-Za-z0-9_]*", text.lower())


def count_base64_strings(text: str, min_len: int = 40) -> int:
    if not text:
        return 0
    pattern = rf"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{{{min_len},}}={{0,2}})(?![A-Za-z0-9+/=])"
    return len(re.findall(pattern, text))


def has_ascii_char_sequence(text: str) -> int:
    if not text:
        return 0
    patterns = [
        r'(?:\[char\]\s*"?\d{1,3}"?\s*(?:\+|,)?\s*){3,}',
        r"(?:\[char\]\s*0x[0-9a-f]{1,2}\s*(?:\+|,)?\s*){3,}",
    ]
    return int(any(re.search(p, text, flags=re.IGNORECASE) for p in patterns))


def compute_token_tfidf_features(tokens: list[str], vocab=None, idf=None, prefix: str = "token_tfidf_") -> dict:
    vocab = vocab or {}
    idf = idf or {}

    if not tokens:
        return {
            f"{prefix}nonzero": 0,
            f"{prefix}total": 0.0,
            f"{prefix}max": 0.0,
        }

    counts = Counter(tokens)
    total = sum(counts.values()) or 1
    token_weights = {}

    if vocab and idf:
        for tok, cnt in counts.items():
            if tok in vocab:
                token_weights[tok] = (cnt / total) * float(idf.get(tok, 1.0))
    else:
        for tok, cnt in counts.items():
            token_weights[tok] = cnt / total

    return {
        f"{prefix}nonzero": sum(1 for w in token_weights.values() if w > 0),
        f"{prefix}total": float(sum(token_weights.values())),
        f"{prefix}max": float(max(token_weights.values()) if token_weights else 0.0),
    }


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
        suspicious = any(k in s for k in [
            "-encodedcommand", "-enc", "iex", "invoke-expression",
            "downloadstring", "frombase64string", "mimikatz", "amsiutils",
            "set-mppreference", "disablerealtimemonitoring"
        ])
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

    # === 1b. Token / structure features ===
    tokens = tokenize_ps(raw)
    token_counter = Counter(tokens)
    total_tokens = len(tokens)
    unique_tokens = len(token_counter)
    f["unique_token_ratio"] = (unique_tokens / total_tokens) if total_tokens else 0
    f["max_token_length"] = max((len(t) for t in tokens), default=0)
    f["long_token_count"] = sum(1 for t in tokens if len(t) > 30)

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
    f["base64_string_count"] = count_base64_strings(raw)

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
    f["encoded_cmd"] = has_pattern(norm, r"-(e|ec|enc|enco|encod|encode|encodedcommand)\b")
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
    f["ascii_char_sequence"] = has_ascii_char_sequence(raw)

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
    f["has_IEX_alias"] = has_pattern(raw.lower(), r"\biex\b|i\s*`\s*e\s*`\s*x")
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

    has_download = (
        f["num_webclient"] > 0 or f["num_downloadfile"] > 0 or f["iwr_count"] > 0 or
        f["has_bitstransfer"] > 0 or f["has_certutil"] > 0 or f["has_webrequest"] > 0 or
        f["has_tcp_client"] > 0 or f["has_tcp_listener"] > 0
    )

    has_execute = (
        f["iex_count"] > 0 or f["powershell_exe"] > 0 or f["start_process"] > 0 or
        f["cmd_shell"] > 0 or f["reflected_assembly"] > 0 or
        f["has_call_operator"] > 0 or f["has_dot_sourcing_exec"] > 0
    )

    has_decode = (
        f["num_frombase64"] > 0 or f["has_fromhexstring"] > 0 or
        f["base64_string_count"] > 0 or f["has_base64_payload"] > 0 or
        f["has_hex_string"] > 0 or f["has_hex_byte_array"] > 0
    )

    f["download_execute_chain"] = int(has_download and has_execute and f["has_whitelisted_download"] == 0)
    f["decode_execute_chain"] = int(has_decode and has_execute)
    f.update(compute_token_tfidf_features(tokens))

    # === G2.96 combined score ===
    f["risk_score"] = f["obfuscation_score"] + f["payload_score"] + f["behavior_score"]

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


# =====================================================
# RULE-BASED BASELINE USING G2.96 FEATURES
# =====================================================
def rule_analyze(script: str, event: dict | None = None, features: dict | None = None) -> str:
    event = event or {}
    features = features or extract_features(script, event)
    s = normalize_compact(script)

    # High-confidence post-exploitation / credential theft.
    if features.get("has_cred_dump") or "mimikatz" in s or "sekurlsa" in s or "logonpasswords" in s or "lsadump" in s:
        return "TERMINATE"

    # Extremely suspicious runtime combination.
    if features.get("final_risk_score", 0.0) >= G296_TERMINATE_RISK_THRESHOLD:
        if features.get("amsi_bypass") or features.get("has_virtualalloc") or features.get("has_createthread") or features.get("has_cred_dump"):
            return "TERMINATE"

    # Alert-worthy behavior.
    alert_flags = [
        "encoded_cmd", "iex_count", "has_IEX_alias", "iwr_count", "num_webclient", "num_downloadfile",
        "num_frombase64", "has_base64_payload", "bypass_policy", "hidden_window", "noprofile",
        "amsi_bypass", "add_mp_preference", "clear_eventlog", "reg_add", "schtasks",
        "has_ps_registry_write", "has_persistence", "has_certutil", "suspicious_process",
        "has_bitstransfer", "has_tcp_client", "has_tcp_listener", "has_webrequest"
    ]

    if any(features.get(k, 0) for k in alert_flags):
        return "ALERT"

    if features.get("final_risk_score", 0.0) >= G296_HIGH_RISK_THRESHOLD:
        return "ALERT"

    return "ALLOW"


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

        if hasattr(ml_model, "n_jobs"):
            ml_model.n_jobs = 1

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
# RESPONSE ENGINE
# Opt-in runtime enforcement. Only TERMINATE verdicts are acted on.
# =====================================================
def response_result(action: str, success: bool, reason: str, **extra) -> dict:
    result = {
        "response_enabled": ENABLE_RESPONSE,
        "response_action": action,
        "response_success": bool(success),
        "response_reason": reason,
    }
    result.update(extra)
    return result


def is_path_under_watch(path: str) -> bool:
    if not path:
        return False

    try:
        target = os.path.normcase(os.path.abspath(path))
        for watch_path in WATCH_PATHS:
            watch_abs = os.path.normcase(os.path.abspath(watch_path))
            if os.path.exists(watch_abs) and os.path.commonpath([target, watch_abs]) == watch_abs:
                return True
    except Exception:
        return False

    return False


def safe_quarantine_name(path: str, event_hash: str) -> str:
    base_name = os.path.basename(path) or "quarantined_script"
    base_name = re.sub(r"[^A-Za-z0-9._-]+", "_", base_name)
    stamp = time.strftime("%Y%m%d_%H%M%S", time.localtime())
    hash_part = (event_hash or sha256_text(path))[:12]
    return f"{stamp}_{hash_part}_{base_name}"


def write_quarantine_index(record: dict):
    with log_lock:
        with open(QUARANTINE_INDEX_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


def terminate_process_response(event: dict) -> dict:
    if psutil is None:
        return response_result("TERMINATE_PROCESS", False, "psutil_unavailable")

    pid = safe_int(event.get("pid"), 0)
    if pid <= 0:
        return response_result("TERMINATE_PROCESS", False, "missing_pid")

    if pid == os.getpid():
        return response_result("TERMINATE_PROCESS", False, "refuse_to_terminate_self", target_pid=pid)

    try:
        proc = psutil.Process(pid)
        process_name = (proc.name() or event.get("process") or "").lower()
        try:
            cmdline = " ".join(proc.cmdline()).lower()
        except Exception:
            cmdline = (event.get("script") or "").lower()

        if process_name in PROTECTED_PROCESS_NAMES:
            return response_result(
                "TERMINATE_PROCESS",
                False,
                "protected_process",
                target_pid=pid,
                target_process=process_name,
            )

        if any(token in cmdline for token in PROTECTED_COMMANDLINE_SUBSTRINGS):
            return response_result(
                "TERMINATE_PROCESS",
                False,
                "protected_commandline",
                target_pid=pid,
                target_process=process_name,
            )

        proc.terminate()
        try:
            proc.wait(timeout=3)
            method = "terminate"
        except psutil.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
            method = "kill"

        return response_result(
            "TERMINATE_PROCESS",
            True,
            "final_verdict_TERMINATE",
            target_pid=pid,
            target_process=process_name,
            response_method=method,
        )

    except psutil.NoSuchProcess:
        return response_result("TERMINATE_PROCESS", False, "process_not_running", target_pid=pid)
    except psutil.AccessDenied:
        return response_result("TERMINATE_PROCESS", False, "access_denied", target_pid=pid)
    except Exception as e:
        return response_result("TERMINATE_PROCESS", False, f"error:{type(e).__name__}:{e}", target_pid=pid)


def quarantine_file_response(event: dict) -> dict:
    path = event.get("path") or ""
    if not path:
        return response_result("QUARANTINE_FILE", False, "missing_path")

    original_path = os.path.abspath(path)
    original_key = os.path.normcase(original_path)
    if not os.path.isfile(original_path):
        with response_lock:
            if original_key in quarantined_paths:
                return response_result("QUARANTINE_FILE", True, "already_quarantined", original_path=original_path)
        return response_result("QUARANTINE_FILE", False, "file_not_found", original_path=original_path)

    if not is_path_under_watch(original_path):
        return response_result("QUARANTINE_FILE", False, "path_outside_watch_scope", original_path=original_path)

    try:
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        quarantine_name = safe_quarantine_name(original_path, event.get("sha256", ""))
        quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_name)

        counter = 1
        while os.path.exists(quarantine_path):
            root, ext = os.path.splitext(quarantine_name)
            quarantine_path = os.path.join(QUARANTINE_DIR, f"{root}_{counter}{ext}")
            counter += 1

        shutil.move(original_path, quarantine_path)
        with response_lock:
            quarantined_paths.add(original_key)

        record = {
            "time": now_ts(),
            "sha256": event.get("sha256", ""),
            "source": event.get("source", ""),
            "final_verdict": event.get("final_verdict", ""),
            "original_path": original_path,
            "quarantine_path": quarantine_path,
        }
        write_quarantine_index(record)

        return response_result(
            "QUARANTINE_FILE",
            True,
            "final_verdict_TERMINATE",
            original_path=original_path,
            quarantine_path=quarantine_path,
        )

    except PermissionError:
        return response_result("QUARANTINE_FILE", False, "permission_denied", original_path=original_path)
    except Exception as e:
        return response_result("QUARANTINE_FILE", False, f"error:{type(e).__name__}:{e}", original_path=original_path)


def enforce_response(event: dict) -> dict:
    if not ENABLE_RESPONSE:
        return response_result("DISABLED", False, "response_disabled")

    if (event.get("final_verdict") or "ALLOW").upper() != "TERMINATE":
        return response_result("NONE", False, "verdict_not_terminate")

    source = event.get("source") or "unknown"

    if source == "process_sensor":
        return terminate_process_response(event)

    if source == "file_sensor":
        return quarantine_file_response(event)

    if source == "eventlog_4104_sensor":
        return response_result("LOG_ONLY", True, "eventlog_4104_has_no_reliable_pid")

    if source == "amsi_cpp_bridge":
        return response_result("DELEGATED_TO_CPP_AGENT", True, "amsi_response_handled_by_cpp_bridge")

    return response_result("NONE", False, "unsupported_source")


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
    row["ml_enabled"] = event.get("ml_enabled")
    row["ml_verdict"] = event.get("ml_verdict")
    row["ml_confidence"] = event.get("ml_confidence")
    row["risk_level"] = event.get("data_analysis", {}).get("risk_level")
    row["final_verdict"] = event.get("final_verdict")
    row["response_enabled"] = event.get("response_enabled")
    row["response_action"] = event.get("response_action")
    row["response_success"] = event.get("response_success")
    row["response_reason"] = event.get("response_reason")

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
    rule_verdict = rule_analyze(script, data, features)
    ml_verdict, ml_confidence = ml_analyze(features)

    final_verdict = combine_verdict(
        cpp_verdict=cpp_verdict,
        rule_verdict=rule_verdict,
        ml_verdict=ml_verdict,
        ml_confidence=ml_confidence,
        risk_level=analysis.get("risk_level", "LOW"),
    )

    data["sha256"] = event_hash
    data["received_at"] = time.time()
    data["received_at_human"] = now_ts()
    data["features"] = features
    data["data_analysis"] = analysis
    data["rule_verdict"] = rule_verdict
    data["ml_enabled"] = ml_enabled
    data["ml_verdict"] = ml_verdict
    data["ml_confidence"] = ml_confidence
    data["final_verdict"] = final_verdict

    return data


def result_from_unprocessed_event(event: dict, status: str, reason: str = "") -> dict:
    local_verdict = (event.get("local_verdict") or "ALLOW").upper()
    if local_verdict not in {"ALLOW", "ALERT", "TERMINATE"}:
        local_verdict = "ALLOW"

    return {
        "queue_status": status,
        "queue_reason": reason,
        "source": event.get("source", "unknown"),
        "pid": event.get("pid", 0),
        "process": event.get("process", ""),
        "local_verdict": local_verdict,
        "rule_verdict": "PENDING" if status == "queued_timeout" else "ALLOW",
        "ml_enabled": ml_enabled,
        "ml_verdict": "PENDING" if status == "queued_timeout" else "UNKNOWN",
        "ml_confidence": 0.0,
        "data_analysis": {
            "risk_level": "PENDING" if status == "queued_timeout" else "LOW",
            "risk_score": 0,
            "raw_risk_score": 0,
            "benign_score": 0,
            "reasons": [reason] if reason else [],
        },
        "final_verdict": local_verdict,
    }


def submit_event(event: dict, dedup: bool = True, wait: bool = False, timeout: float | None = None) -> dict | None:
    script = event.get("script", "") or ""
    if not script:
        return None

    if is_trivial_noise(script):
        return None

    event.setdefault("source", "unknown")
    event.setdefault("local_verdict", "ALLOW")

    reply_queue = queue.Queue(maxsize=1) if wait else None
    envelope = {
        "event": dict(event),
        "dedup": dedup,
        "reply_queue": reply_queue,
    }

    try:
        event_queue.put_nowait(envelope)
        bump_queue_stat("submitted")
    except queue.Full:
        bump_queue_stat("dropped")
        return result_from_unprocessed_event(event, "queue_full", "event_queue_full")

    if not wait:
        return {
            "queue_status": "queued",
            "source": event.get("source", "unknown"),
            "pid": event.get("pid", 0),
        }

    try:
        wait_timeout = TELEMETRY_RESULT_TIMEOUT_SECONDS if timeout is None else timeout
        return reply_queue.get(timeout=wait_timeout)
    except queue.Empty:
        bump_queue_stat("reply_timeouts")
        return result_from_unprocessed_event(event, "queued_timeout", "analysis_queued")


def log_processed_event(event: dict):
    with console_lock:
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
        print("REASONS:", ", ".join(event.get("data_analysis", {}).get("reasons", [])))
        print("FINAL:", event.get("final_verdict"))
        print("SCRIPT:", safe_console_text(truncate(event.get("script", ""))))

    response = enforce_response(event)
    event.update(response)

    with console_lock:
        print("RESPONSE:", event.get("response_action"), event.get("response_success"), event.get("response_reason"))

    write_jsonl(event)
    append_features_csv(event.get("features", {}), event)


def process_event_envelope(envelope: dict) -> dict:
    raw_event = envelope.get("event") or {}
    dedup = bool(envelope.get("dedup", True))
    result_event = build_detection_result(raw_event)

    if dedup and is_duplicate(result_event.get("sha256", "")):
        result_event["queue_status"] = "duplicate"
        bump_queue_stat("duplicates")
        return result_event

    result_event["queue_status"] = "processed"
    log_processed_event(result_event)
    bump_queue_stat("processed")
    return result_event


def worker(worker_id: int = 0):
    while True:
        envelope = event_queue.get()
        reply_queue = envelope.get("reply_queue") if isinstance(envelope, dict) else None
        result_event = None
        try:
            result_event = process_event_envelope(envelope)
        except Exception as e:
            bump_queue_stat("errors")
            print(f"[WORKER {worker_id} ERROR]", e)
            raw_event = envelope.get("event", {}) if isinstance(envelope, dict) else {}
            result_event = result_from_unprocessed_event(raw_event, "worker_error", f"{type(e).__name__}:{e}")
        finally:
            if reply_queue is not None and result_event is not None:
                try:
                    reply_queue.put_nowait(result_event)
                except queue.Full:
                    pass
            event_queue.task_done()


# =====================================================
# SENSOR 1: PROCESS SENSOR
# =====================================================
def process_sensor():
    if psutil is None:
        print("[PROCESS SENSOR] psutil not installed. Sensor disabled.")
        return

    print("[SENSOR] Process Sensor started.")
    try:
        seen_pids = set(psutil.pids())
        print(f"[PROCESS SENSOR] Baseline existing processes: {len(seen_pids)}")
    except Exception as e:
        print("[PROCESS SENSOR INIT ERROR]", e)
        seen_pids = set()

    while True:
        try:
            current_pids = set(psutil.pids())
            new_pids = current_pids - seen_pids
            seen_pids = current_pids

            for pid in sorted(new_pids):
                try:
                    proc = psutil.Process(pid)
                    name = proc.name() or ""
                    lower_name = name.lower()

                    cmdline_list = proc.cmdline()
                    cmdline = " ".join(cmdline_list).strip()
                    cmdline_lower = cmdline.lower()

                    if lower_name not in SUSPICIOUS_PROCESS_NAMES and not re.search(r"\b(powershell|pwsh)\b", cmdline_lower):
                        continue

                    if cmdline_lower.endswith("powershell.exe") or cmdline_lower.endswith("pwsh.exe") or cmdline_lower.endswith("powershell_ise.exe"):
                        continue

                    if not cmdline:
                        continue

                    parent_process = ""
                    executable_path = ""
                    try:
                        parent = proc.parent()
                        parent_process = parent.name() if parent else ""
                    except Exception:
                        parent_process = ""
                    try:
                        executable_path = proc.exe()
                    except Exception:
                        executable_path = ""

                    event = {
                        "source": "process_sensor",
                        "pid": pid,
                        "ppid": proc.ppid(),
                        "process": name,
                        "parent_process": parent_process,
                        "executable_path": executable_path,
                        "script": cmdline,
                        "local_verdict": "ALLOW",
                    }
                    submit_event(event)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception as e:
            print("[PROCESS SENSOR ERROR]", e)
        time.sleep(SENSOR_POLL_INTERVAL_SECONDS)


# =====================================================
# SENSOR 2: FILE SENSOR
# =====================================================
class ScriptFileHandler(FileSystemEventHandler):
    def __init__(self):
        self.state_lock = threading.Lock()
        self.last_emitted_content = {}
        self.known_paths = set()

    def on_created(self, event):
        self.handle_event(event, "created")

    def on_modified(self, event):
        self.handle_event(event, "modified")

    def on_moved(self, event):
        if getattr(event, "is_directory", False):
            return
        self.handle_path(getattr(event, "dest_path", ""), "moved")

    def handle_event(self, event, event_type):
        if getattr(event, "is_directory", False):
            return
        path = getattr(event, "src_path", "")
        self.handle_path(path, event_type)

    def handle_path(self, path, event_type):
        if not path.lower().endswith(SCRIPT_EXTENSIONS):
            return

        normalized_event_type = self.normalize_event_type(path, event_type)
        content = self.read_content_for_event(path, normalized_event_type)
        if content is None or not content.strip():
            return

        if not self.should_emit(path, content, normalized_event_type):
            return

        try:
            event_data = {
                "source": "file_sensor",
                "pid": 0,
                "ppid": 0,
                "process": "file_system",
                "parent_process": "",
                "path": path,
                "file_event_type": normalized_event_type,
                "script": content,
                "local_verdict": "ALLOW",
            }
            submit_event(event_data)
            with self.state_lock:
                self.last_emitted_content[path] = content
                self.known_paths.add(path)
        except Exception as e:
            print("[FILE SENSOR ERROR]", e)

    def normalize_event_type(self, path, event_type):
        if event_type == "moved":
            return "moved"

        with self.state_lock:
            seen_before = path in self.known_paths

        if seen_before:
            return "modified"
        return "created"

    def should_emit(self, path, content, event_type):
        with self.state_lock:
            previous_content = self.last_emitted_content.get(path)

        if event_type == "modified" and previous_content == content:
            return False
        return True

    def read_content_for_event(self, path, event_type):
        if event_type == "created":
            return self.read_created_content(path)
        return self.read_stable_content(path, event_type)

    def read_created_content(self, path):
        for _ in range(FILE_READ_RETRY_COUNT):
            try:
                if not os.path.exists(path):
                    time.sleep(FILE_READ_RETRY_DELAY_SECONDS)
                    continue
                if os.path.getsize(path) > MAX_FILE_READ_BYTES:
                    print("[FILE SENSOR] Skip large file:", path)
                    return None
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                if not content:
                    time.sleep(FILE_READ_RETRY_DELAY_SECONDS)
                    continue
                return content
            except (FileNotFoundError, PermissionError):
                time.sleep(FILE_READ_RETRY_DELAY_SECONDS)
            except Exception as e:
                print("[FILE SENSOR READ ERROR]", e)
                return None
        print("[FILE SENSOR] Cannot read created file after retries:", path)
        return None

    def read_stable_content(self, path, event_type):
        last_content = None
        stable_reads = 0

        for _ in range(FILE_READ_RETRY_COUNT):
            try:
                if not os.path.exists(path):
                    time.sleep(FILE_READ_RETRY_DELAY_SECONDS)
                    continue
                if os.path.getsize(path) > MAX_FILE_READ_BYTES:
                    print("[FILE SENSOR] Skip large file:", path)
                    return None
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                if event_type == "modified" and not content:
                    time.sleep(FILE_EMPTY_MODIFIED_GRACE_SECONDS)
                    continue

                if content == last_content:
                    stable_reads += 1
                else:
                    last_content = content
                    stable_reads = 1

                if stable_reads >= FILE_STABLE_READS_REQUIRED:
                    return content

                time.sleep(FILE_READ_RETRY_DELAY_SECONDS)
            except (FileNotFoundError, PermissionError):
                time.sleep(FILE_READ_RETRY_DELAY_SECONDS)
            except Exception as e:
                print("[FILE SENSOR READ ERROR]", e)
                return None

        print("[FILE SENSOR] Cannot read stable file after retries:", path)
        return None


def file_sensor():
    if Observer is None:
        print("[FILE SENSOR] watchdog not installed. Sensor disabled.")
        return
    print("[SENSOR] File Sensor started.")
    try:
        observer = Observer()
        print("[FILE SENSOR] Observer:", type(observer).__name__)
    except Exception as e:
        if PollingObserver is None:
            print("[FILE SENSOR] Cannot create observer. Sensor disabled.", e)
            return
        observer = PollingObserver()
        print("[FILE SENSOR] Fallback observer:", type(observer).__name__)
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
def safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def xml_text(node):
    return node.text if node is not None and node.text is not None else ""


def close_event_handle(handle):
    if handle is None or win32evtlog is None:
        return
    try:
        win32evtlog.EvtClose(handle)
    except Exception:
        pass


def parse_4104_event_xml(xml):
    result = {
        "record_id": 0,
        "event_id": 0,
        "event_time": "",
        "computer": "",
        "script_block_text": "",
        "path": "",
        "message_number": "",
        "message_total": "",
    }

    try:
        root = ET.fromstring(xml)
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

        system = root.find("e:System", ns)
        if system is not None:
            result["event_id"] = safe_int(xml_text(system.find("e:EventID", ns)), 0)
            result["record_id"] = safe_int(xml_text(system.find("e:EventRecordID", ns)), 0)
            result["computer"] = xml_text(system.find("e:Computer", ns))

            time_created = system.find("e:TimeCreated", ns)
            if time_created is not None:
                result["event_time"] = time_created.attrib.get("SystemTime", "")

        event_data = root.find("e:EventData", ns)
        if event_data is not None:
            for item in event_data.findall("e:Data", ns):
                name = item.attrib.get("Name", "")
                value = html.unescape(xml_text(item))
                if name == "ScriptBlockText":
                    result["script_block_text"] = value
                elif name == "Path":
                    result["path"] = value
                elif name == "MessageNumber":
                    result["message_number"] = value
                elif name == "MessageTotal":
                    result["message_total"] = value

        if not result["script_block_text"]:
            fallback_blocks = re.findall(
                r"<Data[^>]*>(.*?)</Data>",
                xml,
                flags=re.DOTALL
            )
            result["script_block_text"] = "\n".join(html.unescape(x) for x in fallback_blocks)

    except Exception as e:
        print("[EVENTLOG XML PARSE ERROR]", e)

    return result


def get_latest_4104_record_id():
    if win32evtlog is None:
        return 0

    handle = None
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
        return parse_4104_event_xml(xml).get("record_id", 0)

    except Exception as e:
        print("[EVENTLOG SENSOR INIT ERROR]", e)
        return 0
    finally:
        close_event_handle(handle)

def eventlog_4104_sensor():
    print("[SENSOR] Event Log 4104 Sensor started.")

    if win32evtlog is None:
        print("[EVENTLOG SENSOR] pywin32 not installed. Sensor disabled.")
        return

    last_record_id = get_latest_4104_record_id()
    print(f"[EVENTLOG SENSOR] Starting from RecordID: {last_record_id}")

    query = "*[System[(EventID=4104)]]"

    while True:
        handle = None
        try:
            handle = win32evtlog.EvtQuery(
                POWERSHELL_EVENT_LOG,
                win32evtlog.EvtQueryReverseDirection,
                query
            )

            batch = []
            reached_known_record = False

            while True:
                events = win32evtlog.EvtNext(handle, EVENTLOG_READ_BATCH_SIZE)
                if not events:
                    break

                for ev in events:
                    xml = win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml)
                    parsed = parse_4104_event_xml(xml)

                    record_id = parsed.get("record_id", 0)
                    if not record_id:
                        continue

                    if record_id <= last_record_id:
                        reached_known_record = True
                        break

                    message = parsed.get("script_block_text", "")

                    if not message.strip():
                        continue

                    batch.append((record_id, message, parsed))

                if reached_known_record:
                    break

            batch.sort(key=lambda x: x[0])

            for record_id, message, parsed in batch:
                last_record_id = max(last_record_id, record_id)

                event = {
                    "source": "eventlog_4104_sensor",
                    "pid": 0,
                    "ppid": 0,
                    "process": "powershell_eventlog",
                    "parent_process": "",
                    "event_id": 4104,
                    "record_id": record_id,
                    "event_time": parsed.get("event_time", ""),
                    "computer": parsed.get("computer", ""),
                    "path": parsed.get("path", ""),
                    "message_number": parsed.get("message_number", ""),
                    "message_total": parsed.get("message_total", ""),
                    "script": message,
                    "local_verdict": "ALLOW",
                }

                submit_event(event)

        except Exception as e:
            print("[EVENTLOG SENSOR ERROR]", e)
        finally:
            close_event_handle(handle)

        time.sleep(SENSOR_POLL_INTERVAL_SECONDS)


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

    result_event = submit_event(
        data,
        dedup=True,
        wait=True,
        timeout=TELEMETRY_RESULT_TIMEOUT_SECONDS,
    )
    if result_event is None:
        return jsonify({"status": "ignored_noise", "verdict": "ALLOW"}), 200

    return jsonify({
        "status": result_event.get("queue_status", "received"),
        "verdict": result_event.get("final_verdict", "ALLOW"),
        "rule_verdict": result_event.get("rule_verdict", "ALLOW"),
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
        "response_enabled": ENABLE_RESPONSE,
        "quarantine_path": QUARANTINE_DIR,
        "quarantine_index_path": QUARANTINE_INDEX_PATH,
        "agent_pid": os.getpid(),
        "queue": queue_snapshot(),
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

    for worker_id in range(EVENT_WORKER_COUNT):
        threading.Thread(target=worker, args=(worker_id,), daemon=True).start()

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
    print(f"[+] Response enabled: {ENABLE_RESPONSE}")
    print(f"[+] Quarantine: {QUARANTINE_DIR}")
    print(f"[+] Event queue: max={EVENT_QUEUE_MAX_SIZE} workers={EVENT_WORKER_COUNT}")

    app.run(host=HOST, port=PORT)
