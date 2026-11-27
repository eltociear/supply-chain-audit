#!/usr/bin/env python3
"""gomod-audit - scan Go modules for MALICIOUS code before you import, build or `go generate` them.

A Go dependency runs code in your program the moment it is imported: every `func init()` and
every package-level `var x = f()` executes before `main`. Its `//go:generate` lines run on a
developer's or CI machine, and cgo preambles compile and link C into your binary. `govulncheck`
answers "is there a known vulnerability on a path I call?"; the checksum database only proves
everyone gets the same bytes, including the same backdoor (one typosquat sat in the module proxy
cache for ~3 years). This is a deterministic (no LLM) static scan of the module zip for
download-and-execute loaders, string-array / concatenation-obfuscated shell commands, disk
wipers, reverse shells, environment and SSH-key exfiltration, persistence writes and droppers -
weighted by WHEN the code runs.

Precision-tuned: what popular modules do every day (exec of git/go/uname, HTTP clients reading
~/.aws or ~/.kube/config, InsecureSkipVerify options, `cmd.Env = os.Environ()`, help text that
prints `curl ... | sh`) is informational context and never inflates the risk score. Risk comes
from combinations, decoded payloads and import-time context.

Nothing is built, fetched with `go get`, or executed: the module zip comes from the module proxy
(https://proxy.golang.org) into memory and is read as text.

Usage:
  python gomod_audit.py <module>[@version] [...]   # fetch from proxy.golang.org and scan
  python gomod_audit.py <dir|file.go|module.zip>   # scan a local module / file / zip
  python gomod_audit.py --gomod go.mod             # scan every required module
  python gomod_audit.py --gosum go.sum             # scan every module version in go.sum
  python gomod_audit.py --text "some go code"      # scan a string (treated as import-time code)
  add --json for machine-readable output, --verbose to print INFO context,
  --no-tests to skip _test.go files (only code your build imports)

Exit code 2 if any target is HIGH or CRITICAL (CI-friendly).
No dependencies beyond the standard library. MIT licensed.
"""
import base64
import binascii
import bisect
import io
import json
import os
import posixpath
import re
import sys
import time
import urllib.error
import urllib.request
import struct
import zipfile
import zlib

__version__ = "0.2.0"

PROXY = os.environ.get("GOMOD_AUDIT_PROXY", "https://proxy.golang.org").rstrip("/")
GO_EXT = (".go",)
C_EXT = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".m", ".mm")
MAX_FILE = 2000000      # bytes; larger files are generated tables - skipped
MAX_TOTAL = int(os.environ.get("GOMOD_AUDIT_MAX_TOTAL", "96000000"))  # bytes of Go scanned per module
SKIP_TESTS = bool(os.environ.get("GOMOD_AUDIT_SKIP_TESTS"))  # --no-tests: only importable code
MAX_ZIP = 500000000     # proxy limit

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------
# Endpoints legitimate modules essentially never hard-code, but stealers love. Chat/webhook APIs
# are matched separately: notification libraries call them with the USER's token, so only a
# hard-coded token / webhook id makes them a collector.
EXFIL_HOST = (
    r"(?:\bwebhook\.site\b|\bpipedream\.net\b|\brequestbin\.(?:com|net|io)\b|\brequestb\.in\b|\brequestcatcher\.com\b|"
    r"\bbeeceptor\.com\b|\bpastebin\.com/(?:api|raw)|\bpaste\.ee/|\bhastebin\.com/|\btransfer\.sh/|\bfile\.io/|"
    r"\.trycloudflare\.com\b|\bserveo\.net\b|\bloca\.lt\b|\boastify\.com\b|\boast\.(?:fun|me|pro|live|site|online)\b|"
    r"\binteract\.sh\b|\bburpcollaborator\.net\b|\bdnslog\.cn\b|\bceye\.io\b|\brequestrepo\.com\b|"
    r"\bdpaste\.(?:com|org)/api|\bpaste\.rs\b|\brentry\.(?:co|org)/api|\btermbin\.com\b|\b0x0\.st\b|\bix\.io\b|\bghostbin\.)"
)
HARDCODED_CHAT = (r"(?:api\.telegram\.org/bot\d{6,}:[\w-]{20,}|discord(?:app)?\.com/api/webhooks/\d{6,}/[\w-]{20,}|"
                  r"hooks\.slack\.com/services/T\w{6,}/B\w{6,}/\w{10,})")
_PRIVATE_IP = r"(?:\d{1,3}(?:\.\d{1,3}){3}:53\b|1\.0\.0\.1\b|8\.26\.56\.26\b|149\.112\.112\.112\b|208\.67\.22[02]\.22[02]\b|64\.6\.6[45]\.6\b|94\.140\.1[45]\.1[45]\b|76\.76\.(?:2|10)\.0\b|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|127\.|0\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|2(?:2[4-9]|[3-5]\d)\.|1\.1\.1\.1\b|8\.8\.[48]\.[48]\b|9\.9\.9\.9\b)"
RAW_IP_URL = r"\b(?:https?|tcp|ws)://(?!" + _PRIVATE_IP + r")(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[\w./?=&%-]*)?"
RAW_IP_PORT = r"[\"'](?!" + _PRIVATE_IP + r")(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}[\"']"
NET_SEND = (
    r"(?:\bhttp\.(?:Get|Post|PostForm|Head|NewRequest(?:WithContext)?)\s*\(|\bnet\.Dial(?:Timeout|TCP|UDP|IP|Unix)?\s*\(|"
    r"\.DialContext\s*\(|\bnet\.Dialer\s*\{|\.Dial\s*\(\s*\"(?:tcp|udp)\w*\"|\btls\.Dial\s*\(|\bnet\.Lookup(?:Host|TXT|IP|Addr|CNAME|MX)\s*\(|\.Lookup(?:Host|TXT|IPAddr)\s*\(|"
    r"\bwebsocket\.(?:Dial|DefaultDialer)|\bhttp\.(?:DefaultClient|Client\s*\{)|\.Do\s*\(\s*req\b|\bresty\.New\s*\(|"
    r"\bexec\.Command(?:Context)?\s*\([^)\n]{0,40}\"(?:curl|wget)\")"
)
EXEC_SINK = r"(?:\bexec\.Command(?:Context)?\s*\(|\bsyscall\.(?:Exec|ForkExec|StartProcess)\s*\(|\bos\.StartProcess\s*\(|\bunix\.Exec\s*\()"
CHECKSUM = r"(?:sha256\.|sha512\.|sha1\.|blake2|blake3|md5\.|checksum|Checksum|VerifySignature|minisign|cosign|\bverify\w*\()"

# payload regexes - applied to code, string literals AND decoded / reassembled strings
PAYLOAD = {
    "download_execute": [
        r"\bcurl\s+[^\n|;\"`]{0,300}\|\s*(?:sudo\s+)?(?:/(?:usr/)?bin/)?(?:ba|z|da)?sh\b",
        r"\bwget\s+[^\n|;\"`]{0,300}\|\s*(?:sudo\s+)?(?:/(?:usr/)?bin/)?(?:ba|z|da)?sh\b",
        r"\bwget\s+(?:-[a-zA-Z]+\s+)*-O\s*-\s+[^\n|]{0,300}\|\s*(?:/(?:usr/)?bin/)?(?:ba|z)?sh\b",
        r"\b(?:ba|z)?sh\s*<\s*\(\s*(?:curl|wget)\b",
        r"\b(?:curl|wget)\s+[^\n|;\"`]{0,300}\|\s*(?:python3?|perl|ruby|node)\b",
        r"(?:\biex|Invoke-Expression)\s*\(?\s*\(?\s*(?:New-Object\s+(?:System\.)?Net\.WebClient|iwr|Invoke-WebRequest|irm|Invoke-RestMethod)",
        r"\bpowershell(?:\.exe)?[^\n]{0,60}\s-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}",
        r"\b(?:curl|wget)\s+[^\n;|]{0,300}(?:-o|-O)\s*(/tmp/[\w.-]+)[^\n]{0,80}(?:&&|;)\s*(?:chmod\s+\+?[0-7x]+\s+\1\s*(?:&&|;)\s*)?\1\b",
    ],
    "reverse_shell": [
        r"/dev/tcp/[\w.\-]+/\d+",
        r"\bbash\s+-i\s*>&",
        r"\bnc(?:at)?\s+(?:-\w+\s+)*-e\s+/bin/(?:ba)?sh",
        r"\bsocat\s+[^\n]{0,80}exec:[\"']?(?:/bin/)?(?:ba)?sh",
        r"\bmkfifo\s+[^\n]{0,60}\|\s*(?:/bin/)?(?:ba)?sh\s+-i",
    ],
    "destructive": [
        r"\bdd\s+if=/dev/(?:zero|u?random)\s+of=/dev/(?:sd[a-z]|nvme\d|hd[a-z]|vd[a-z]|xvd[a-z]|mmcblk\d|disk\d)",
        r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+(?:--no-preserve-root\s+)?(?:~/?|\$HOME/?|/\*?)(?=[\s\"'`;&|)]|$)",
        r"\bmkfs(?:\.\w+)?\s+(?:-\w+\s+)*/dev/(?:sd[a-z]|nvme\d|hd[a-z]|vd[a-z])",
        r"\bshred\s+[^\n]{0,40}/dev/(?:sd[a-z]|nvme\d)",
        r"\bformat\s+[cC]:\s*/[qQyY]",
    ],
}
PAYLOAD["worm_propagation"] = [r"\btrufflehog\s+(?:filesystem|github|git)\b[^\n]{0,120}(?:--json|--only-verified|--results)"]
PAYLOAD_NAMES = {"worm_propagation": ("Secret Harvesting (worm)", "Runs TruffleHog over the machine / org to harvest secrets"),
                 "download_execute": ("Download & Execute", "Fetches remote content and pipes it into a shell/interpreter"),
                 "reverse_shell": ("Reverse Shell", "Binds an interactive shell to a network socket"),
                 "destructive": ("Destructive Payload", "Wipes a disk, the filesystem or the home directory")}

PATTERNS = {
    "critical": [
        {"id": "destructive_go", "name": "Destructive Payload",
         "desc": "Opens a raw block device for writing / removes the filesystem root or home directory",
         "regexes": [
             r"\bos\.(?:OpenFile|Create)\s*\(\s*\"/dev/(?:sd[a-z]|nvme\d\w*|hd[a-z]|vd[a-z]|xvd[a-z]|mmcblk\d|disk\d)\"[^\n]{0,80}(?:O_WRONLY|O_RDWR|\))",
             r"\bos\.RemoveAll\s*\(\s*(?:\"/\"|\"~\"|\"C:\\\\\\\\?\"|os\.Getenv\s*\(\s*\"(?:HOME|USERPROFILE)\"\s*\))\s*\)",
         ]},
    ],
    "high": [
        {"id": "exfil_host", "name": "Exfiltration Endpoint",
         "desc": "Hard-codes a webhook / paste / tunnel / OAST collector, or a chat webhook WITH its token",
         "regexes": [EXFIL_HOST, HARDCODED_CHAT]},
        {"id": "persistence_write", "name": "Persistence Write",
         "desc": "Writes shell rc files, authorized_keys, LaunchAgents, autostart, cron or Run keys",
         "regexes": [
             r"(?:WriteFile|OpenFile|Create|AppendFile)\s*\([^\n]{0,160}(?:\.bashrc|\.zshrc|\.bash_profile|\.zprofile|/\.profile\b|authorized_keys|LaunchAgents|LaunchDaemons|\.config/autostart|/etc/cron|/etc/rc\.local|/etc/systemd/system)",
             r"\bcrontab\s+-[^l\s\"]",
             r"\\\\CurrentVersion\\\\Run\b",
         ]},
        {"id": "wallet_theft", "name": "Wallet / Browser Data Theft",
         "desc": "Targets wallet extension stores, browser credential databases or the macOS Keychain",
         "regexes": [
             r"nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|hnfanknocfeofbddgcijnmhnfnkdnaad|ibnejdfjmmkpcnlpebklmnkoeoihofec|egjidjbpglichdcondbcbdnbeeppgdph",
             r"(?:Exodus|atomic|Electrum)[/\\\\]+(?:exodus\.wallet|Local Storage|wallets)",
             r"\bsecurity\"?\s*,\s*\"find-generic-password",
             r"\b(?:wallet\.dat|seed\.seco)\b",
         ]},
        {"id": "dns_exfil", "name": "DNS Exfiltration",
         "desc": "Encodes host/user data into a DNS lookup (dependency-confusion beacon)",
         "regexes": [
             r"\.?Lookup(?:Host|TXT|IP|IPAddr|CNAME)\s*\([^\n]{0,40}Sprintf\s*\(\s*\"%[sxv]\.[\w.-]+\"\s*,[^\n]{0,80}(?:hostname|Hostname|user|User|Getenv|whoami)",
         ]},
    ],
    "medium": [
        {"id": "raw_ip_url", "name": "Raw-IP Endpoint",
         "desc": "Contacts a public IP address directly instead of a hostname",
         "regexes": [RAW_IP_URL, RAW_IP_PORT]},
        {"id": "cgo_plugin_flag", "name": "Suspicious cgo Flag",
         "desc": "#cgo directive loads a compiler/linker plugin or spec file (runs code at build time)",
         "regexes": [r"^\s*#cgo\b[^\n]*(?:-fplugin|-Wl,-?-plugin|--plugin|-specs=|-B\s*/|-wrapper)"]},
    ],
    "low": [],
    # Context: reported, never scored. Capabilities popular modules use daily.
    "info": [
        {"id": "credential_read", "name": "Credential Store Reference",
         "desc": "References ~/.ssh keys, ~/.aws, ~/.docker, ~/.kube, ~/.netrc, git credentials",
         "regexes": [r"\.ssh[\"/\\\\][^\n]{0,30}id_(?:rsa|dsa|ecdsa|ed25519)", r"\"\.ssh\"\s*,\s*\"id_\w+\"", r"\.aws[\"/\\\\]+credentials",
                     r"\.git-credentials", r"\.docker[\"/\\\\]+config\.json", r"\.kube[\"/\\\\]+config", r"\"\.netrc\"|/\.netrc\b",
                     r"\.npmrc\b", r"solana[\"/\\\\]+id\.json", r"\.config[\"/\\\\]+gh[\"/\\\\]+hosts\.yml",
                     r"(?:Login Data|Local Extension Settings|Cookies)\"?[^\n]{0,30}(?:Chrome|Brave|Edge)|(?:Chrome|BraveSoftware|Microsoft/Edge)[^\n]{0,60}(?:Login Data|Local Extension Settings)"]},
        {"id": "env_dump", "name": "Whole-Environment Serialisation",
         "desc": "Serialises every environment variable (exfil only when it is sent)",
         "regexes": [r"(?:json\.Marshal\w*|strings\.Join|fmt\.Sprint\w*|fmt\.Fprint\w*|\.Write(?:String)?)\s*\([^\n]{0,60}\bos\.Environ\s*\(\s*\)"]},
        {"id": "process_spawn", "name": "Process Spawning", "desc": "Runs external commands", "regexes": [EXEC_SINK]},
        {"id": "network", "name": "Network Access", "desc": "Makes outbound HTTP/DNS/socket calls", "regexes": [NET_SEND]},
        {"id": "env_read", "name": "Environment Access", "desc": "Reads environment variables",
         "regexes": [r"\bos\.(?:Getenv|LookupEnv|Environ)\s*\("]},
        {"id": "unsafe_load", "name": "Dynamic Code Loading", "desc": "plugin.Open / syscall.LoadLibrary / dlopen",
         "regexes": [r"\bplugin\.Open\s*\(", r"\bsyscall\.(?:LoadLibrary|NewLazyDLL|MustLoadDLL)\s*\(", r"\bdlopen\s*\("]},
        {"id": "tls_disabled", "name": "TLS Verification Disabled", "desc": "InsecureSkipVerify: true (an option, in most clients)",
         "regexes": [r"InsecureSkipVerify\s*:\s*true"]},
    ],
}

SEVERITY_SCORE = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "SAFE": 0}
# cheap substring gates: a pattern group only runs on a file containing one of its needles
# (CPython's `re` gets no literal-prefix speedup from `\b(?:a|b|c)` alternations)
NEEDLES = {
    "destructive_go": ("RemoveAll", "/dev/"),
    "exfil_host": ("webhook.site", "pipedream", "requestbin", "requestb.in", "requestcatcher", "beeceptor", "pastebin",
                   "paste.ee", "hastebin", "transfer.sh", "file.io", "trycloudflare", "serveo", "loca.lt", "oastify",
                   "oast.", "interact.sh", "burpcollaborator", "dnslog", "ceye.io", "requestrepo", "telegram.org/bot",
                   "/api/webhooks/", "hooks.slack.com", "dpaste", "paste.rs", "rentry", "termbin", "0x0.st",
                   "ix.io", "ghostbin"),
    "persistence_write": (".bashrc", ".zshrc", ".bash_profile", ".zprofile", ".profile", "authorized_keys", "LaunchAgents",
                          "LaunchDaemons", "autostart", "/etc/cron", "rc.local", "/etc/systemd", "crontab", "CurrentVersion"),
    "wallet_theft": ("nkbih", "bfnael", "hnfank", "ibnejd", "egjidj", "Exodus", "atomic", "Electrum",
                     "find-generic-password", "wallet.dat", "seed.seco"),
    "dns_exfil": ("Sprintf",), "cgo_plugin_flag": ("#cgo",),
    "credential_read": (".ssh", ".aws", ".git-credentials", ".docker", ".kube", ".netrc", ".npmrc", "solana", "hosts.yml",
                        "Login Data", "Local Extension Settings", "Cookies"),
    "env_dump": ("Environ",), "process_spawn": ("exec.Command", "syscall.", "StartProcess", "unix.Exec"),
    "network": ("http.", "net.", "Dial", "Lookup", "websocket", ".Do(", "resty"),
    "env_read": ("os.Getenv", "os.LookupEnv", "os.Environ"), "unsafe_load": ("plugin.Open", "syscall.", "dlopen"),
    "tls_disabled": ("InsecureSkipVerify",), "raw_ip_url": ("://", ":"),
}
_COMPILED = [(sev, pg, re.compile(rx, re.M)) for sev, groups in PATTERNS.items() for pg in groups for rx in pg["regexes"]]


_ALL_NEEDLES = sorted({n for v in NEEDLES.values() for n in v}, key=len, reverse=True)
_NEEDLE_RE = re.compile("|".join(re.escape(n) for n in _ALL_NEEDLES))


def needles_in(text):
    """One pass: the set of pattern ids whose needles occur in text."""
    found = set(_NEEDLE_RE.findall(text))
    # findall is non-overlapping; recover needles hidden inside a longer match
    for f in list(found):
        for n in _ALL_NEEDLES:
            if n != f and n in f:
                found.add(n)
    return {pid for pid, nd in NEEDLES.items() if any(n in found for n in nd)}


def _has(text, pid, present=None):
    if pid not in NEEDLES:
        return True
    if present is not None:
        return pid in present
    return any(n in text for n in NEEDLES[pid])


_PAYLOAD_RE = [(pid, re.compile(rx, re.I)) for pid, rxs in PAYLOAD.items() for rx in rxs]
PAYLOAD_NEEDLES = ("trufflehog", "curl", "wget", "/dev/", "bash", "nc ", "ncat", "socat", "mkfifo", "rm -", "mkfs", "shred", "iex",
                   "invoke-", "powershell", "format ")
NET_RE = re.compile(NET_SEND)
EXEC_RE = re.compile(EXEC_SINK)
EXFIL_RE = re.compile(EXFIL_HOST + "|" + HARDCODED_CHAT, re.I)
RAWIP_RE = re.compile(RAW_IP_URL + "|" + RAW_IP_PORT)
CHECKSUM_RE = re.compile(CHECKSUM)
# actual sends (not client construction / references) - used for import-time network
NET_CALL_RE = re.compile(r"\bhttp\.(?:Get|Post|PostForm|Head)\s*\(|\bnet\.Dial(?:Timeout|TCP|UDP)?\s*\(|\btls\.Dial\s*\(|"
                         r"\bnet\.Lookup(?:Host|TXT|IP|Addr|CNAME)\s*\(|\.Do\s*\(\s*req\b|\.(?:Get|Post)\s*\(\s*\"https?://")
CRED_RE = re.compile("|".join(PATTERNS["info"][0]["regexes"]))
ENVDUMP_RE = re.compile(PATTERNS["info"][1]["regexes"][0])
ENV_ITER_RE = re.compile(r"\bos\.Environ\s*\(\s*\)")
CHMOD_RE = re.compile(r"\bos\.Chmod\s*\([^\n]{0,80}0o?[0-7]*[157][0-7]{0,2}\b|\bWriteFile\s*\([^\n]{0,160},\s*0o?7[0-7]{2}\s*\)|\bOpenFile\s*\([^\n]{0,160}0o?7[0-7]{2}\s*\)")
CONN_IO_RE = re.compile(r"\bbufio\.New(?:Reader|Scanner)\s*\(\s*\w*(?:conn|Conn|c|sock|s)\w*\s*\)|\.Stdin\s*=\s*\w*(?:conn|Conn|sock)\w*|\.Stdout\s*=\s*\w*(?:conn|Conn|sock)\w*|\.Read\s*\(\s*buf")
DIAL_RE = re.compile(r"\bnet\.Dial(?:Timeout|TCP)?\s*\(|\btls\.Dial\s*\(|\.Dial(?:Context)?\s*\(\s*(?:ctx\s*,\s*)?\"tcp\"")
# command output written back to the connection it came from
CONN_OUT_RE = re.compile(r"\bfmt\.Fprint\w*\s*\(\s*\w*(?:conn|Conn|sock)\w*\s*,|\b\w*(?:conn|Conn|sock)\w*\.Write\s*\(")
# encrypting what is about to be sent (a collector hiding its loot from the paste service / network)
ENCRYPT_RE = re.compile(r"\baes\.NewCipher\s*\(|\.XORKeyStream\s*\(|\bchacha20\w*\.New\w*\s*\(|\brsa\.EncryptPKCS1v15\s*\(|\bbox\.Seal\s*\(")
HARDCODED_CHAT_RE = re.compile(HARDCODED_CHAT, re.I)
# a fetch of a hard-coded URL (net/http, or bitfield/script's script.Get)
FETCH_LIT_RE = re.compile(r"\b(?:http|script)\.Get\s*\(\s*\"https?://|\bhttp\.NewRequest(?:WithContext)?\s*\([^\n]{0,40}\"GET\"\s*,\s*\"https?://")
FILE_READ_RE = re.compile(r"\bos\.(?:ReadFile|Open|ReadDir)\s*\(|\bioutil\.ReadFile\s*\(|\bfilepath\.(?:Walk|WalkDir|Glob)\s*\(|\bsql\.Open\s*\(")
COLLECT_RE = re.compile(r"\bos\.Hostname\s*\(|\buser\.Current\s*\(|\bos\.ReadFile\s*\([^\n]{0,80}(?:home|Home|HOME)|/etc/passwd|\bnet\.InterfaceAddrs\s*\(")
GOOS_GATE_RE = re.compile(r"runtime\.GOOS\s*(?:==|!=)\s*\"(?:linux|darwin|windows)\"")
SHELLS = {"sh", "bash", "zsh", "dash", "ash", "ksh", "/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash", "/usr/bin/sh",
          "/usr/bin/bash", "/usr/bin/env", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"}
SHELL_FLAGS = {"-c", "/c", "/C", "-Command", "-command", "-lc", "-ec", "-ic", "-NoProfile", "-EncodedCommand", "-enc", "-e"}
LINE_ONCE = ("network", "env_read", "process_spawn", "tls_disabled", "credential_read", "unsafe_load")
STRING_ONLY_OK = re.compile(r"\b(?:fmt\.(?:Print|Sprint|Fprint|Errorf)\w*|log\.\w+|errors\.New|\.(?:Usage|Short|Long|Example|Help|Description)\s*[:=]|"
                            r"(?:Usage|Short|Long|Example|Help|Description)\s*:|t\.(?:Log|Error|Fatal)\w*|"
                            r"(?:Info|Warn|Error|Debug|Fatal|Print)(?:f|ln|w)?\s*\()")


# ---------------------------------------------------------------------------
# Go lexing (comment / string spans) - regex driven, runs in C
# ---------------------------------------------------------------------------
_LEX = re.compile(r"//[^\n]*|/\*.*?\*/|\"(?:[^\"\\\n]|\\.)*\"|`[^`]*`|'(?:[^'\\\n]|\\.)+'", re.S)
_ESC = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", "\"": "\"", "'": "'", "a": "\a", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}


def go_unquote(lit):
    if lit.startswith("`"):
        return lit[1:-1]
    body = lit[1:-1]
    if "\\" not in body:
        return body
    out, i = [], 0
    while i < len(body):
        c = body[i]
        if c != "\\" or i + 1 >= len(body):
            out.append(c)
            i += 1
            continue
        n = body[i + 1]
        try:
            if n == "x":
                out.append(chr(int(body[i + 2:i + 4], 16)))
                i += 4
                continue
            if n == "u":
                out.append(chr(int(body[i + 2:i + 6], 16)))
                i += 6
                continue
            if n == "U":
                out.append(chr(int(body[i + 2:i + 10], 16)))
                i += 10
                continue
            if n in "01234567" and i + 3 < len(body) + 1 and re.match(r"[0-7]{3}", body[i + 1:i + 4]):
                out.append(chr(int(body[i + 1:i + 4], 8)))
                i += 4
                continue
        except ValueError:
            pass
        out.append(_ESC.get(n, n))
        i += 2
    return "".join(out)


class GoFile(object):
    """Lexed view of one Go file: comments blanked (cb), comments+strings blanked (fb), spans."""

    def __init__(self, path, text):
        self.path = path
        # A whole file shifted right (every line tab-indented) still compiles, but hides every
        # top-level declaration from `^func` / `^var` anchored parsing (the boltdb-go typosquat
        # did exactly this). Strip the common indent of the package clause from every line.
        self.indented = False
        if not re.search(r"^package\s", text, re.M):
            pm = re.search(r"^([ \t]+)package\s", text, re.M)
            if pm:
                ind = pm.group(1)
                text = "\n".join(l[len(ind):] if l.startswith(ind) else l for l in text.split("\n"))
                self.indented = True
        self.text = text
        cb, fb = [], []
        last = 0
        self.strings = []      # (start, end, value)
        self.comments = []     # (start, end)
        for m in _LEX.finditer(text):
            s, e = m.span()
            tok = m.group(0)
            cb.append(text[last:s])
            fb.append(text[last:s])
            blank = re.sub(r"[^\n]", " ", tok)
            if tok[0] == "/":
                self.comments.append((s, e))
                cb.append(blank)
                fb.append(blank)
            else:
                if tok[0] != "'":
                    self.strings.append((s, e, go_unquote(tok)))
                cb.append(tok)
                fb.append(tok[0] + blank[1:-1] + tok[-1] if len(tok) >= 2 else blank)
            last = e
        cb.append(text[last:])
        fb.append(text[last:])
        self.cb = "".join(cb)
        self.fb = "".join(fb)
        self._nl = [m.start() for m in re.finditer("\n", text)]
        self._sstarts = [s for s, _, _ in self.strings]
        self.package = (re.search(r"^package\s+(\w+)", self.fb, re.M) or [None, ""])[1]
        self.funcs = []        # (name, recv, body_start, body_end)
        self.type_spans = []
        self._parse_structure()

    # -- positions -----------------------------------------------------------------------
    def line_of(self, pos):
        return bisect.bisect_right(self._nl, pos - 1) + 1 if pos > 0 else 1

    def line_text(self, n):
        s = self._nl[n - 2] + 1 if n >= 2 and n - 2 < len(self._nl) else 0
        e = self._nl[n - 1] if n - 1 < len(self._nl) else len(self.text)
        return self.text[s:e]

    def string_at(self, pos):
        i = bisect.bisect_right(self._sstarts, pos) - 1
        if i >= 0 and self.strings[i][0] <= pos < self.strings[i][1]:
            return self.strings[i]
        return None

    def func_at(self, pos):
        for f in self.funcs:
            if f[2] <= pos < f[3]:
                return f
        return None

    # -- structure -----------------------------------------------------------------------
    def _parse_structure(self):
        fb = self.fb
        braces = [(m.start(), m.group(0)) for m in re.finditer(r"[{}]", fb)]
        match, stack = {}, []
        for p, c in braces:
            if c == "{":
                stack.append(p)
            elif stack:
                match[stack.pop()] = p
        self._match = match
        opens = sorted(match)
        for m in re.finditer(r"^func\s*(\([^)]*\))?\s*([A-Za-z_]\w*)\s*(?:\[[^\]\n]*\])?\s*\(", fb, re.M):
            # walk past the parameter list and results to the body brace
            i = m.end()
            depth = 1
            n = len(fb)
            while i < n and depth:
                ch = fb[i]
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                i += 1
            j = bisect.bisect_left(opens, i)
            body = None
            while j < len(opens):
                p = opens[j]
                between = fb[i:p]
                if "\nfunc " in between or len(between) > 2000:
                    break
                if re.search(r"(?:interface|struct)\s*$", fb[max(0, p - 12):p]):
                    end = match[p]
                    j = bisect.bisect_left(opens, end + 1)
                    i = end + 1
                    continue
                body = p
                break
            if body is None or body not in match:
                continue
            self.funcs.append((m.group(2), m.group(1) or "", body, match[body] + 1))
        for m in re.finditer(r"^type\s+(?:\w+\s*(?:\[[^\]\n]*\])?\s+(?:struct|interface)\s*\{|\()", fb, re.M):
            s = m.end() - 1
            if fb[s] == "{" and s in match:
                self.type_spans.append((m.start(), match[s] + 1))
            elif fb[s] == "(":
                d, k = 0, s
                while k < len(fb):
                    if fb[k] == "(":
                        d += 1
                    elif fb[k] == ")":
                        d -= 1
                        if not d:
                            break
                    k += 1
                self.type_spans.append((m.start(), k + 1))

    def package_level_code(self):
        """Code outside top-level func bodies and type declarations (it runs during package init)."""
        spans = sorted([(f[2], f[3]) for f in self.funcs] + self.type_spans)
        out, last = [], 0
        for s, e in spans:
            if s > last:
                out.append((last, s))
            last = max(last, e)
        out.append((last, len(self.fb)))
        return out


# ---------------------------------------------------------------------------
# String resolution: literals, concatenations, string-array reassembly, base64/hex/bytes
# ---------------------------------------------------------------------------
_STR_LIT = r"(?:\"(?:[^\"\\\n]|\\.)*\"|`[^`]*`)"
_ARRAY_RE = re.compile(r"\b(\w+)\s*(?::=|=)\s*\[\]string\s*\{((?:\s*" + _STR_LIT + r"\s*,?)+)\s*\}", re.S)
_INTARR_RE = re.compile(r"\b(\w+)\s*(?::=|=)\s*\[\](?:int|byte|uint8)\s*\{([\d\s,xXa-fA-F]+)\}")
_ASSIGN_RE = re.compile(r"(?:^|[;{(]|\bvar\b|\bconst\b)[ \t]*(\w+)[ \t]*(?:[\w.\[\]*]+[ \t]*)?(?::=|=)[ \t]*(?!=)([^\n;]+(?:\+[ \t]*\n[^\n;]+)*)", re.M)
_INDEX_TERM = re.compile(r"^(\w+)\s*\[\s*(\d+)\s*\]$")
_B64_CALL = re.compile(r"base64\.(?:Std|URL|RawStd|RawURL)Encoding\.DecodeString\s*\(\s*(" + _STR_LIT + r")\s*\)")
_HEX_CALL = re.compile(r"hex\.DecodeString\s*\(\s*(" + _STR_LIT + r")\s*\)")
_BYTES_LIT = re.compile(r"string\s*\(\s*\[\]byte\s*\{([\d\s,xXa-fA-F]+)\}\s*\)")


def _split_top(expr, sep):
    out, depth, cur, q = [], 0, [], None
    i = 0
    while i < len(expr):
        c = expr[i]
        if q:
            cur.append(c)
            if c == "\\" and q == '"' and i + 1 < len(expr):
                cur.append(expr[i + 1])
                i += 2
                continue
            if c == q:
                q = None
        elif c in "\"`":
            q = c
            cur.append(c)
        elif c in "([{":
            depth += 1
            cur.append(c)
        elif c in ")]}":
            depth -= 1
            cur.append(c)
        elif c == sep and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    out.append("".join(cur))
    return out


def _trim_expr(expr):
    """Cut an expression where an unbalanced closer ends the enclosing block / call."""
    depth, q, i = 0, None, 0
    while i < len(expr):
        c = expr[i]
        if q:
            if c == "\\" and q == '"':
                i += 2
                continue
            if c == q:
                q = None
        elif c in "\"`":
            q = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth < 0:
                return expr[:i]
        i += 1
    return expr


def _ints(body):
    out = []
    for t in body.split(","):
        t = t.strip()
        if not t:
            continue
        try:
            out.append(int(t, 0))
        except ValueError:
            return None
    return out


class Resolver(object):
    """Best-effort constant folding over one file's simple string assignments."""

    def __init__(self, gf):
        self.gf = gf
        self.env = {}
        self.arrays = {}
        self.intarrays = {}
        self.obf = {}          # var -> how it was built ("array", "base64", ...)
        self.reassembled = []  # (pos, value, kind)
        cb = gf.cb
        if "exec.Command" not in cb and "DecodeString" not in cb and "[]byte{" not in cb:
            return
        if "[]string" in cb and "[" in cb:
            for m in _ARRAY_RE.finditer(cb):
                elems = [go_unquote(x.group(0)) for x in re.finditer(_STR_LIT, m.group(2))]
                self.arrays[m.group(1)] = elems
        if "[]int" in cb or "[]byte" in cb:
            for m in _INTARR_RE.finditer(cb):
                v = _ints(m.group(2))
                if v is not None:
                    self.intarrays[m.group(1)] = v
        for m in (_ASSIGN_RE.finditer(cb) if "exec.Command" in cb or self.arrays else ()):
            name, expr = m.group(1), _trim_expr(m.group(2)).strip()
            if name in ("_", "err") or expr.startswith(("[]string", "func", "map[", "&", "struct")):
                continue
            val, kind = self.resolve(expr)
            if val is not None:
                self.env[name] = val
                if kind:
                    self.obf[name] = kind
                    self.reassembled.append((m.start(2), val, kind))
        # `for _, i := range IDX { s += ARR[i] }` reassembly
        for m in re.finditer(r"range\s+(\w+)\s*\{\s*(\w+)\s*\+=\s*(\w+)\s*\[\s*\w+\s*\]", cb):
            idx, acc, arr = m.group(1), m.group(2), m.group(3)
            if idx in self.intarrays and arr in self.arrays:
                a = self.arrays[arr]
                if all(0 <= i < len(a) for i in self.intarrays[idx]):
                    v = "".join(a[i] for i in self.intarrays[idx])
                    self.env[acc] = v
                    self.obf[acc] = "array"
                    self.reassembled.append((m.start(), v, "array"))
        for rx, kind in ((_B64_CALL, "base64"), (_HEX_CALL, "hex")):
            if "DecodeString" in cb:
                for m in rx.finditer(cb):
                    v = self._decode(kind, go_unquote(m.group(1)))
                    if v:
                        self.reassembled.append((m.start(), v, kind))
        if "[]byte{" in cb:
            for m in _BYTES_LIT.finditer(cb):
                b = _ints(m.group(1))
                if b and all(0 <= x < 256 for x in b):
                    self.reassembled.append((m.start(), bytes(b).decode("latin-1"), "bytes"))

    @staticmethod
    def _decode(kind, s):
        try:
            raw = base64.b64decode(s + "=" * (-len(s) % 4), altchars=b"-_" if ("-" in s or "_" in s) else None) \
                if kind == "base64" else binascii.unhexlify(s)
        except (binascii.Error, ValueError):
            return None
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def resolve(self, expr, depth=0):
        """-> (value or None, obfuscation-kind or '')."""
        expr = expr.strip()
        if depth > 6 or not expr:
            return None, ""
        terms = _split_top(expr, "+")
        vals, kinds, nidx = [], set(), 0
        for t in terms:
            t = t.strip()
            if not t:
                return None, ""
            if re.match(r"^" + _STR_LIT + r"$", t, re.S):
                vals.append(go_unquote(t))
                continue
            m = _INDEX_TERM.match(t)
            if m and m.group(1) in self.arrays:
                a = self.arrays[m.group(1)]
                k = int(m.group(2))
                if k >= len(a):
                    return None, ""
                vals.append(a[k])
                nidx += 1
                continue
            m = re.match(r"^string\s*\(\s*(\w+)\s*\[\s*(\d+)\s*\]\s*\)$", t)
            if m and m.group(1) in self.arrays:
                a = self.arrays[m.group(1)]
                k = int(m.group(2))
                if k >= len(a):
                    return None, ""
                vals.append(a[k])
                nidx += 1
                continue
            if re.match(r"^\w+$", t) and t in self.env:
                vals.append(self.env[t])
                if t in self.obf:
                    kinds.add(self.obf[t])
                continue
            m = _B64_CALL.match(t) or re.match(r"^string\s*\(\s*(?:\w+\s*\(\s*)?" + _B64_CALL.pattern + r"\s*\)?\s*\)$", t)
            if m:
                v = self._decode("base64", go_unquote(m.group(1)))
                if v is None:
                    return None, ""
                vals.append(v)
                kinds.add("base64")
                continue
            m = _BYTES_LIT.match(t)
            if m:
                b = _ints(m.group(1))
                if not b or not all(0 <= x < 256 for x in b):
                    return None, ""
                vals.append(bytes(b).decode("latin-1"))
                kinds.add("bytes")
                continue
            if t.startswith("(") and t.endswith(")"):
                v, k = self.resolve(t[1:-1], depth + 1)
                if v is None:
                    return None, ""
                vals.append(v)
                if k:
                    kinds.add(k)
                continue
            return None, ""
        if nidx >= 3:
            kinds.add("array")
        if len(terms) >= 6 and sum(1 for v in vals if len(v) <= 6) >= len(terms) * 0.6:
            kinds.add("fragments")
        return "".join(vals), ",".join(sorted(kinds))


# ---------------------------------------------------------------------------
# File scan
# ---------------------------------------------------------------------------
def _item(sev, pid, name, desc, path, n, matched, ctx, **kw):
    d = {"severity": sev, "id": pid, "name": name, "description": desc, "file": path,
         "line": n, "matched": (matched or "")[:120], "context": (ctx or "").strip()[:200]}
    d.update(kw)
    return d


def file_kind(path):
    """'ignored' (testdata/_dir/.dir: the go tool never compiles them), 'test', or 'code'."""
    parts = path.split("/")
    if any(p == "testdata" or (p[:1] in ("_", ".") and p not in (".", "..")) for p in parts[:-1]):
        return "ignored"
    if path.endswith("_test.go"):
        return "test"
    return "code"


_BUILD_TAG = re.compile(r"^//go:build\s+(.+)$|^// \+build\s+(.+)$", re.M)
_OS_NAMES = r"(?:linux|darwin|windows|freebsd|openbsd|netbsd|android|ios|solaris|illumos|aix|plan9|dragonfly|js|wasip1)"
_OS_SUFFIX = re.compile(r"_" + _OS_NAMES + r"(?:_(?:amd64|arm64|386|arm|mips\w*|ppc64\w*|riscv64|s390x|wasm|loong64))?\.go$")


def build_constraint(gf):
    head = gf.text[:4000]
    m = _BUILD_TAG.search(head)
    tag = (m.group(1) or m.group(2)).strip() if m else ""
    if not tag:
        sm = _OS_SUFFIX.search(gf.path)
        tag = sm.group(0)[1:-3] if sm else ""
    return tag


def cgo_preamble(gf):
    """The comment immediately preceding `import "C"` (C code compiled into the package)."""
    m = re.search(r"^import\s+\"C\"|^import\s*\([^)]*\"C\"", gf.cb, re.M)
    if not m:
        return None
    if m.group(0).startswith("import\t") or m.group(0).startswith("import \""):
        pass
    cands = [c for c in gf.comments if c[1] <= m.start() and not gf.cb[c[1]:m.start()].strip()]
    if not cands:
        # a run of // comments: walk back over consecutive comments
        return ("", m.start())
    s, e = cands[-1]
    # merge consecutive // lines
    i = gf.comments.index((s, e))
    while i > 0 and not gf.text[gf.comments[i - 1][1]:gf.comments[i][0]].strip():
        i -= 1
    s = gf.comments[i][0]
    raw = gf.text[s:e]
    raw = re.sub(r"^\s*//", "", raw, flags=re.M)
    raw = raw.replace("/*", "  ").replace("*/", "  ")
    return (raw, s)


# a shell / interpreter invocation from C (a constructor re-exec'ing /proc/self/exe or a helper binary
# is how container runtimes set up namespaces - not this)
C_EXEC_RE = re.compile(r"\b(?:system|popen)\s*\(|\bexec(?:l|lp|le|v|vp|ve)\s*\(\s*\"(?:/(?:usr/)?bin/)?(?:ba|z|da)?sh\"")
C_CTOR_RE = re.compile(r"__attribute__\s*\(\s*\(\s*constructor|#pragma\s+init|\.init_array")
CALL_NAME = re.compile(r"(?<![\w.])([A-Za-z_]\w*)\s*\(")


def _payload_hits(s):
    low = s.lower()
    if not any(n in low for n in PAYLOAD_NEEDLES):
        return []
    out = []
    for pid, rx in _PAYLOAD_RE:
        m = rx.search(s)
        if m:
            out.append((pid, m))
    return out


class PkgIndex(object):
    """Per-directory index of top-level functions, to follow init()/var-initialiser call chains."""

    def __init__(self, gfs):
        self.funcs = {}
        for gf in gfs:
            for f in gf.funcs:
                if not f[1]:  # plain functions only (methods are reached via values)
                    self.funcs.setdefault(f[0], []).append((gf, f))

    def import_time_regions(self, gfs):
        """{path: [(start, end, why)]} - code that executes when the package is imported."""
        regions = {gf.path: [] for gf in gfs}
        todo = []
        for gf in gfs:
            for f in gf.funcs:
                if f[0] == "init" and not f[1]:
                    for r in _strip_func_literals(gf, f[2], f[3], "init()"):
                        regions[gf.path].append(r)
                        todo.append((gf, r[0], r[1], 0))
            for s, e in gf.package_level_code():
                seg = gf.fb[s:e]
                if "=" not in seg:
                    continue
                # only `var` declarations: skip imports/consts and func-signature leftovers
                for vm in re.finditer(r"^var\s*(?:\(|[\w, ]+(?:\s+[\w.*\[\]]+)?\s*=)", seg, re.M):
                    vs = s + vm.start()
                    ve = self._var_end(gf, vs, e)
                    for r in _strip_func_literals(gf, vs, ve, "package var initialiser"):
                        regions[gf.path].append(r)
                        todo.append((gf, r[0], r[1], 0))
        seen = set()
        while todo:
            gf, s, e, d = todo.pop()
            if d >= 4:
                continue
            for cm in CALL_NAME.finditer(gf.fb, s, e):
                name = cm.group(1)
                if name in ("init", "func") or name not in self.funcs:
                    continue
                for ogf, f in self.funcs[name]:
                    key = (ogf.path, f[2])
                    if key in seen:
                        continue
                    seen.add(key)
                    for r in _strip_func_literals(ogf, f[2], f[3], "called from import-time code (%s)" % name):
                        regions.setdefault(ogf.path, []).append(r)
                        todo.append((ogf, r[0], r[1], d + 1))
        return regions

    @staticmethod
    def _var_end(gf, vs, limit):
        fb = gf.fb
        if fb[vs:vs + 8].replace(" ", "").startswith("var("):
            k = fb.index("(", vs)
            d = 0
            while k < limit:
                if fb[k] in "({[":
                    d += 1
                elif fb[k] in ")}]":
                    d -= 1
                    if d == 0:
                        return k + 1
                k += 1
            return limit
        # single var: up to the newline at depth 0
        d, k = 0, vs
        while k < limit:
            c = fb[k]
            if c in "({[":
                d += 1
            elif c in ")}]":
                d -= 1
            elif c == "\n" and d <= 0 and not fb[max(vs, k - 2):k].rstrip().endswith(("+", ",", "(")):
                return k
            k += 1
        return limit


def _strip_func_literals(gf, s, e, why):
    """Split [s, e) into sub-regions, cutting out `func(...) {...}` bodies not invoked in place."""
    fb, match = gf.fb, gf._match
    out, cur = [], s
    for m in re.finditer(r"\bfunc\s*\(", fb[s:e]):
        p = s + m.start()
        if p < cur:
            continue
        b = fb.find("{", p, e)
        if b < 0 or b not in match:
            continue
        end = match[b] + 1
        if fb[end:end + 3].lstrip().startswith("("):
            continue  # func(){...}() - runs now
        out.append((cur, b, why))
        cur = end
    out.append((cur, e, why))
    return [r for r in out if r[1] > r[0]]


def _in_regions(regions, pos):
    for s, e, why in regions:
        if s <= pos < e:
            return why
    return None


def _exec_calls(gf, res):
    """Yield (pos, end, prog, args[list of (value|None)], kinds:set) for exec.Command(...) calls."""
    for m in re.finditer(r"\bexec\.Command(Context)?\s*\(", gf.fb):
        i, d = m.end(), 1
        while i < len(gf.fb) and d:
            if gf.fb[i] == "(":
                d += 1
            elif gf.fb[i] == ")":
                d -= 1
            i += 1
        inner = gf.cb[m.end():i - 1]
        if len(inner) > 6000:
            continue
        parts = [p.strip() for p in _split_top(inner, ",")]
        if m.group(1) and parts:
            parts = parts[1:]
        vals, kinds = [], set()
        for p in parts:
            if p.endswith("..."):
                vals.append(None)
                continue
            v, k = res.resolve(p) if p else (None, "")
            vals.append(v)
            if k:
                kinds.update(k.split(","))
        if vals:
            yield m.start(), i, vals[0], vals[1:], kinds, gf.cb[i:i + 12]


def scan_go_file(gf, findings, info, regions, kind, res=None):
    path = gf.path
    local = []
    seen = set()
    text = gf.cb  # comments blanked, strings intact
    constraint = build_constraint(gf)

    def ctx_of(pos):
        why = _in_regions(regions, pos)
        if why == "package var initialiser" and pos is not None and gf.string_at(pos):
            ln = gf.line_text(gf.line_of(pos))
            if not (NET_CALL_RE.search(ln) or EXEC_RE.search(ln)):
                return ("runtime", None)  # a literal in a table is data, not import-time execution
        return ("import", why) if why else ("runtime", None)

    def add(sev, pid, name, desc, pos, matched, **kw):
        n = gf.line_of(pos) if pos is not None and pos >= 0 else 0
        key = (pid, n)
        if key in seen:
            return None
        seen.add(key)
        it = _item(sev, pid, name, desc, path, n, matched, gf.line_text(n) if n else "file-level", **kw)
        it["_pos"] = pos
        local.append(it)
        return it

    # 1. pattern pass over code (comments blanked)
    present = needles_in(text)
    for sev, pg, rx in _COMPILED:
        if pg["id"] in LINE_ONCE and (pg["id"], -1) in seen or not _has(text, pg["id"], present):
            continue
        for m in rx.finditer(text):
            it = add(sev.upper(), pg["id"], pg["name"], pg["desc"], m.start(), m.group(0))
            if it and pg["id"] in LINE_ONCE:
                seen.add((pg["id"], -1))
                break
    # 2. payload regexes over every string literal + decoded/reassembled strings
    if res is None:
        res = Resolver(gf)
    tlow = gf.text.lower()
    plain_ok = any(n in tlow for n in PAYLOAD_NEEDLES)
    strs = [(s, v, "") for s, e, v in gf.strings if len(v) >= 8] if plain_ok else []
    # folded concatenations of adjacent literals ("wget -O" + " - h" + "ttps" ...)
    run, prev_end = [], -1
    for s, e, v in (gf.strings if plain_ok or "\"+\"" in text.replace(" ", "") else []) + [(len(text) + 1, len(text) + 1, "")]:
        if run and re.match(r"^\s*\+\s*$", gf.fb[prev_end:s]):
            run.append((s, v))
        else:
            if len(run) >= 2:
                strs.append((run[0][0], "".join(x for _, x in run), "fragments" if len(run) >= 6 else ""))
            run = [(s, v)]
        prev_end = e
    strs += [(p, v, k) for p, v, k in res.reassembled]
    for pos, val, kinds in strs:
        for pid, m in _payload_hits(val):
            name, desc = PAYLOAD_NAMES[pid]
            obf = bool(kinds and kinds != "fragments") or "fragments" in kinds.split(",") and len(val) < 400
            it = add("CRITICAL", pid, name, desc + (" [decoded from %s]" % kinds if obf else ""), pos, m.group(0))
            if it is not None:
                it["_string"] = True
                it["_decoded"] = obf
    # 3. exec.Command analysis
    exec_info, exec_inners = [], []
    if "exec.Command" in text:
        for pos, end, prog, args, kinds, tail in _exec_calls(gf, res):
            exec_info.append((pos, prog, args, kinds))
            exec_inners.append(text[pos:end])
            base = (prog or "").rsplit("/", 1)[-1].lower() if prog else None
            shell = prog is not None and (prog in SHELLS or base in SHELLS)
            cmdarg = None
            if shell and args and args[0] in SHELL_FLAGS and len(args) >= 2:
                cmdarg = args[1]
            elif shell and base == "env" and len(args) >= 3 and args[1] in SHELL_FLAGS:
                cmdarg = args[2]
            obf = bool(kinds - {"fragments"}) or "fragments" in kinds
            if cmdarg is not None:
                for pid, m in _payload_hits(cmdarg):
                    name, desc = PAYLOAD_NAMES[pid]
                    it = add("CRITICAL", pid, name, desc + " - passed to %s -c%s" % (
                        prog, " [decoded from %s]" % ",".join(sorted(kinds)) if obf else ""), pos, m.group(0))
                    if it is not None:
                        it["_exec"] = True
                        it["_decoded"] = obf
            if shell and obf:
                add("HIGH", "obfuscated_exec", "Obfuscated Shell Command",
                    "Builds the shell command from %s and hands it to %s" % (",".join(sorted(kinds)), prog), pos,
                    (cmdarg or "")[:120])
            elif prog is None and kinds:
                add("HIGH", "obfuscated_exec", "Obfuscated Exec Target",
                    "The program path itself is reassembled from %s" % ",".join(sorted(kinds)), pos, "")
            if shell and len(args) >= 2 and args[0] in SHELL_FLAGS and args[1] is None:
                exec_info[-1] = exec_info[-1] + ("dynamic-shell",)
    # 4. string-array obfuscation shape (many 1-char elements reassembled by index)
    for name, elems in res.arrays.items():
        if len(elems) >= 20 and sum(1 for e in elems if len(e) <= 2) >= 0.8 * len(elems):
            refs = len(re.findall(r"\b%s\s*\[\s*\d+\s*\]" % re.escape(name), text))
            if refs >= 15:
                m = re.search(r"\b%s\s*(?::=|=)\s*\[\]string" % re.escape(name), text)
                add("HIGH" if EXEC_RE.search(text) else "MEDIUM", "string_array_obfuscation", "String-Array Obfuscation",
                    "%d single-character strings reassembled by %d index lookups%s" % (
                        len(elems), refs, " in a file that executes commands" if EXEC_RE.search(text) else ""),
                    m.start() if m else 0, name)
    # 5. go:generate directives (run by `go generate` on developer / CI machines)
    if "//go:generate" in gf.text:
        for m in re.finditer(r"^//go:generate\s+(.+)$", gf.text, re.M):
            cmd = m.group(1)
            for pid, pm in _payload_hits(cmd):
                name, desc = PAYLOAD_NAMES[pid]
                add("CRITICAL", pid, name, desc + " [//go:generate]", m.start(), pm.group(0), _ctx="go:generate")
            if EXFIL_RE.search(cmd):
                add("HIGH", "exfil_host", "Exfiltration Endpoint", "go:generate contacts a collector host", m.start(), cmd)
            if re.search(r"\b(?:curl|wget)\s+[^\n]*https?://", cmd):
                add("LOW", "generate_download", "Download in go:generate",
                    "go:generate fetches a remote resource (runs on the developer / CI machine)", m.start(), cmd)
    # 6. cgo preamble (C compiled into the package; constructors run at load time)
    pre = cgo_preamble(gf) if "\"C\"" in gf.cb else None
    if pre and pre[0]:
        ptxt, pbase = pre
        for pid, pm in _payload_hits(ptxt):
            name, desc = PAYLOAD_NAMES[pid]
            it = add("CRITICAL" if C_EXEC_RE.search(ptxt) else "MEDIUM", pid, name, desc + " [cgo preamble]",
                     pbase + pm.start(), pm.group(0), _ctx="cgo")
        for sev, pg, rx in _COMPILED:
            if pg["id"] == "cgo_plugin_flag":
                for pm in rx.finditer(ptxt):
                    add("MEDIUM", pg["id"], pg["name"], pg["desc"], pbase + pm.start(), pm.group(0))
        if C_CTOR_RE.search(ptxt) and C_EXEC_RE.search(ptxt):
            pm = C_EXEC_RE.search(ptxt)
            add("CRITICAL", "cgo_constructor_exec", "C Constructor Runs a Command",
                "cgo preamble defines a load-time constructor and calls system()/exec*() [runs at import]",
                pbase + pm.start(), pm.group(0))

    # ---- combination rules (per function, then per file) -------------------------------
    has_net = _has(text, "network", present) and bool(NET_RE.search(text))
    funcs_text = {}

    def region_text(pos):
        f = gf.func_at(pos) if pos is not None else None
        if f is None:
            return text
        k = f[2]
        if k not in funcs_text:
            funcs_text[k] = text[f[2]:f[3]]
        return funcs_text[k]

    for it in list(local):
        pid = it["id"]
        pos = it.get("_pos")
        if pid == "exfil_host" and not has_net and "curl" not in text and "wget" not in text:
            it["severity"] = "INFO"
        elif pid == "exfil_host" and ctx_of(pos)[0] == "import" and it.get("_ctx") != "go:generate" \
                and not NET_CALL_RE.search(region_text(pos)):
            it["severity"] = "INFO"  # init() storing a config value; nothing is sent from here
            it["description"] += " [no network call in the same function]"
        elif pid == "exfil_host" and ctx_of(pos)[0] != "import" and it.get("_ctx") != "go:generate":
            # API clients / secret detectors call paste & file services legitimately; a collector
            # is the endpoint plus something worth stealing gathered in the same function
            body = region_text(pos)
            sends = NET_CALL_RE.search(body) or re.search(r"\.Do\s*\(", body)
            if HARDCODED_CHAT_RE.search(it["matched"]) and sends:
                it["description"] += " [the module's own bot token / webhook, sent to from this function]"
            elif ENCRYPT_RE.search(body) and sends:
                it["description"] += " [data encrypted before it is sent]"
            elif not (CRED_RE.search(body) or ENV_ITER_RE.search(body) or COLLECT_RE.search(body)):
                it["severity"] = "INFO"
                it["description"] += " [no data collection in the same function]"
        if pid == "raw_ip_url":
            ctxk = ctx_of(pos)[0]
            body = region_text(pos)
            if not (ctxk == "import" and NET_CALL_RE.search(body) or
                    (CRED_RE.search(body) or ENV_ITER_RE.search(body)) and NET_RE.search(body)):
                it["severity"] = "INFO"
        if pid == "wallet_theft":
            body = region_text(pos)
            if not (FILE_READ_RE.search(body) and has_net) and not (EXEC_RE.search(body) and "find-generic-password" in it["matched"]):
                it["severity"] = "INFO"
                it["description"] += " [no file read + network]"
        if pid in ("persistence_write", "wallet_theft", "dns_exfil") and it["severity"] != "INFO":
            body = region_text(pos)
            if ctx_of(pos)[0] != "import" and not (EXFIL_RE.search(text) or RAWIP_RE.search(text)):
                it["severity"] = "INFO" if pid != "dns_exfil" or not NET_RE.search(body) else it["severity"]
        if pid in PAYLOAD and it.get("_string") and not it.get("_exec") and not it.get("_decoded"):
            # a pipe-to-shell that only sits in a string (install hint, help text, error message)
            # is shown to the user, not run - unless the same function executes commands
            line = gf.line_text(it["line"]) if it["line"] else ""
            body = region_text(pos)
            am = re.match(r"^\s*(?:(?:var|const)\s+)?(\w+)\s*(?:[\w.\[\]*]+\s*)?(?::=|=)", line)
            flows = bool(am) and any(re.search(r"\b%s\b" % re.escape(am.group(1)), inner) for inner in exec_inners)
            imp_exec = ctx_of(pos)[0] == "import" and EXEC_RE.search(text)
            if STRING_ONLY_OK.search(line) or not (flows or imp_exec or EXEC_RE.search(line)):
                it["severity"] = "INFO"
                it["description"] += " [string only: not passed to exec]"
        if pid in PAYLOAD and not it.get("_string") and not it.get("_exec") and it.get("_ctx") not in ("go:generate", "cgo"):
            # matched in Go code outside a string literal (e.g. inside a raw-string template we didn't
            # lex): keep, but only when the file can execute something
            if not EXEC_RE.search(text) and not gf.path.endswith(C_EXT):
                it["severity"] = "INFO"
        if pid in ("download_execute", "destructive") and it["severity"] == "CRITICAL" and not it.get("_decoded") \
                and it.get("_ctx") not in ("go:generate", "cgo") \
                and (ctx_of(pos)[0] != "import" or it.get("_string") and ctx_of(pos)[1] == "package var initialiser") \
                and not (RAWIP_RE.search(it["matched"]) or EXFIL_RE.search(it["matched"])):
            # a plain-literal installer command in runtime code (a CLI offering `curl ... | sh` when the
            # user asks it to install something): worth a look, not an attack shape on its own
            it["severity"] = "MEDIUM"
            it["description"] += " [runtime, plain literal]"
            it["_plainstr"] = True
    # env dump / credential read + network in the same function (or import-time code)
    for f in (gf.funcs if has_net else []):
        body = text[f[2]:f[3]]
        if not NET_RE.search(body):
            continue
        imp = _in_regions(regions, f[2])
        cred = CRED_RE.search(body)
        envd = ENVDUMP_RE.search(body) or (imp and ENV_ITER_RE.search(body))
        exfil = EXFIL_RE.search(body) or RAWIP_RE.search(body)
        if cred and (exfil or imp):
            add("CRITICAL", "credential_exfil", "Credential Exfiltration",
                "Reads a credential store (%s) and sends over the network in the same function%s" % (
                    cred.group(0)[:40], " [runs at import]" if imp else ""), f[2] + cred.start(), cred.group(0))
        if envd and (exfil or imp or ENVDUMP_RE.search(body)):
            add("CRITICAL" if (imp or exfil) else "HIGH", "env_exfil", "Environment Exfiltration",
                "Serialises the whole environment and sends over the network in the same function%s" % (
                    " [runs at import]" if imp else ""), f[2] + envd.start(), envd.group(0))
        # reverse shell: dial out + shell exec with a non-literal command + conn I/O, one function
        if DIAL_RE.search(body) and CONN_IO_RE.search(body):
            for e in exec_info:
                if f[2] <= e[0] < f[3] and len(e) > 4:
                    add("CRITICAL", "reverse_shell", "Reverse Shell / C2 Loop",
                        "Dials out, reads commands from the connection and runs them with %s -c" % e[1], e[0], "")
                    break
                if f[2] <= e[0] < f[3] and e[1] is None and CONN_OUT_RE.search(body):
                    # exec.Command(args[0], args[1:]...) on a line read from the socket, output sent back
                    add("CRITICAL", "reverse_shell", "Reverse Shell / C2 Loop",
                        "Dials out, runs the program named by each line read from the connection and writes "
                        "the output back", e[0], "")
                    break
    # remote script: fetch a hard-coded URL and hand the (computed) text to sh -c, one function
    if exec_info and FETCH_LIT_RE.search(text):
        for f in gf.funcs:
            body = text[f[2]:f[3]]
            fm = FETCH_LIT_RE.search(body)
            if fm and not gf.string_at(f[2] + fm.start()):
                e = next((e for e in exec_info if f[2] <= e[0] < f[3] and len(e) > 4), None)
                if e:
                    # a command's own `upgrade` / `install` subcommand runs the vendor's installer in the
                    # user's terminal (package main, stdio wired to os.Std*); a library doing it detached
                    # from an ordinary API call (qmgo's NewClient -> .Start()) is the attack
                    interactive = gf.package == "main" or re.search(r"\.Std(?:out|in|err)\s*=\s*os\.Std", body)
                    add("LOW" if interactive else "HIGH", "remote_script_exec", "Remote Script Execution",
                        "Fetches a hard-coded URL and runs the computed text with %s -c in the same function%s" % (
                            e[1], " [interactive installer in a command, not a library]" if interactive else ""),
                        e[0], fm.group(0))
    # dropper: download + chmod +x + exec of a non-literal path, one function
    if has_net and CHMOD_RE.search(text) and exec_info:
        for f in gf.funcs:
            body = text[f[2]:f[3]]
            if NET_RE.search(body) and CHMOD_RE.search(body) and any(f[2] <= e[0] < f[3] and e[1] is None for e in exec_info):
                imp = _in_regions(regions, f[2])
                sev = "CRITICAL" if imp else ("INFO" if CHECKSUM_RE.search(text) else "MEDIUM")
                add(sev, "dropper", "Download & Execute (dropper)",
                    "Downloads a file, marks it executable and runs it%s" % (
                        " [runs at import]" if imp else "" if sev != "INFO" else " (checksum verified)"), f[2], "")
                break
    # shell with a dynamic command in import-time code
    for e in exec_info:
        why = _in_regions(regions, e[0])
        if why:
            if len(e) > 4:
                add("HIGH", "import_shell_exec", "Shell Exec at Import Time",
                    "Runs %s -c <computed command> from %s" % (e[1], why), e[0], "")
            else:
                add("LOW", "import_exec", "Process Spawn at Import Time",
                    "Runs an external program from %s" % why, e[0], str(e[1])[:60])
    for m in (NET_CALL_RE.finditer(text) if has_net and regions else ()):
        why = _in_regions(regions, m.start())
        if why and not gf.string_at(m.start()):  # sample code inside a string literal isn't a call
            add("MEDIUM", "import_network", "Network I/O at Import Time",
                "Makes a network call from %s" % why, m.start(), m.group(0))
            break

    # ---- context escalation / demotion -------------------------------------------------
    for it in local:
        pos = it.pop("_pos", None)
        flags = {k: it.pop(k, None) for k in ("_string", "_exec", "_decoded", "_ctx")}
        it["_plainstr"] = it.get("_plainstr") or (flags["_string"] and not flags["_decoded"] and not flags["_exec"])
        if it["severity"] == "INFO":
            continue
        ck, why = ctx_of(pos) if pos else ("runtime", None)
        if why == "package var initialiser" and it.get("_plainstr"):
            ck, why = "runtime", None
        if gf.path.endswith(C_EXT) and C_CTOR_RE.search(gf.text):
            ck, why = "import", "C constructor"
        it["context_kind"] = ck
        if constraint:
            it["build_constraint"] = constraint
        if kind == "ignored":
            it["severity"] = "INFO"
            it["description"] += " [testdata/_ dir: never compiled]"
            continue
        if kind == "test" and ck != "import":
            it["severity"] = "INFO"
            it["description"] += " [_test.go]"
            continue
        if kind == "test":
            if SEV_ORDER[it["severity"]] < SEV_ORDER["HIGH"]:
                it["severity"] = "INFO"
            it["description"] += " [test init(): runs under go test]"
            continue
        if ck == "import":
            if it["severity"] == "HIGH" and it["id"] not in ("string_array_obfuscation",):
                it["severity"] = "CRITICAL"
                it["description"] += " [runs at import: %s]" % why
            elif it["severity"] == "MEDIUM" and it["id"] in ("raw_ip_url", "string_array_obfuscation"):
                it["severity"] = "HIGH"
                it["description"] += " [runs at import: %s]" % why
    for it in local:
        it.pop("_plainstr", None)
        (info if it["severity"] == "INFO" else findings).append(it)
    return gf


def scan_c_file(path, text, findings, info, kind):
    """C sources in a cgo package are compiled and linked into the binary."""
    local = []
    ctor = bool(C_CTOR_RE.search(text))
    lines_nl = [m.start() for m in re.finditer("\n", text)]

    def ln(p):
        return bisect.bisect_right(lines_nl, p - 1) + 1
    for pid, m in _payload_hits(text):
        name, desc = PAYLOAD_NAMES[pid]
        local.append(_item("CRITICAL", pid, name, desc + " [C source]", path, ln(m.start()), m.group(0), ""))
    m = C_EXEC_RE.search(text)
    if ctor and m:
        local.append(_item("CRITICAL", "cgo_constructor_exec", "C Constructor Runs a Command",
                           "C source defines a load-time constructor and calls system()/exec*() [runs at import]",
                           path, ln(m.start()), m.group(0), ""))
    e = EXFIL_RE.search(text)
    if e:
        local.append(_item("HIGH", "exfil_host", "Exfiltration Endpoint", "C source hard-codes a collector host",
                           path, ln(e.start()), e.group(0), ""))
    for it in local:
        if kind != "code":
            it["severity"] = "INFO"
        (info if it["severity"] == "INFO" else findings).append(it)


# ---------------------------------------------------------------------------
# Module scan
# ---------------------------------------------------------------------------
def module_path_of(files):
    gm = files.get("go.mod", "")
    m = re.search(r"^module\s+\"?([^\s\"]+)", gm, re.M)
    return m.group(1) if m else ""


def scan_module(files, label=""):
    """files: {relative_path: text}. Returns an audit result dict."""
    findings, info = [], []
    total = 0
    by_dir = {}
    cgo_dirs = set()
    stats = {"go_files": 0, "init_funcs": 0, "import_time_pkgs": 0, "cgo_pkgs": 0, "go_generate": 0,
             "os_gated_files": 0, "test_files": 0, "vendored": 0}
    for path in sorted(files):
        if not path.endswith(GO_EXT) or SKIP_TESTS and path.endswith("_test.go"):
            continue
        t = files[path]
        total += len(t)
        if total > MAX_TOTAL:
            info.append(_item("INFO", "truncated", "Scan Truncated", "Module exceeds %d bytes of Go" % MAX_TOTAL,
                              path, 0, "", ""))
            break
        by_dir.setdefault(posixpath.dirname(path), []).append(path)
    for d in sorted(by_dir):
        gfs, kinds = [], {}
        for p in by_dir[d]:
            try:
                gf = GoFile(p, files[p])
            except RecursionError:
                continue
            gfs.append(gf)
            kinds[p] = file_kind(p)
            stats["go_files"] += 1
            stats["test_files"] += kinds[p] == "test"
            stats["vendored"] += p.startswith("vendor/") or "/vendor/" in p
            stats["go_generate"] += "//go:generate" in gf.text
            stats["os_gated_files"] += bool(build_constraint(gf) and re.search(_OS_NAMES, build_constraint(gf)))
            if "\"C\"" in gf.cb and re.search(r"^import\s+\"C\"|^import\s*\([^)]*\"C\"", gf.cb, re.M):
                cgo_dirs.add(d)
        # test files belong to separate test binaries; index them separately so a test's
        # init() is not treated as part of the importable package
        main_gfs = [g for g in gfs if kinds[g.path] != "test"]
        test_gfs = [g for g in gfs if kinds[g.path] == "test"]
        regions = {}
        if main_gfs:
            regions.update(PkgIndex(main_gfs).import_time_regions(main_gfs))
        if test_gfs:
            tr = PkgIndex(test_gfs + main_gfs).import_time_regions(test_gfs)
            regions.update({g.path: tr.get(g.path, []) for g in test_gfs})
        n_init = sum(1 for g in main_gfs for f in g.funcs if f[0] == "init" and not f[1])
        stats["init_funcs"] += n_init
        stats["import_time_pkgs"] += bool(n_init)
        for gf in gfs:
            scan_go_file(gf, findings, info, regions.get(gf.path, []), kinds[gf.path])
    stats["cgo_pkgs"] = len(cgo_dirs)
    for path in sorted(files):
        if path.endswith(C_EXT) and posixpath.dirname(path) in cgo_dirs and len(files[path]) <= MAX_FILE:
            k = file_kind(path)
            scan_c_file(path, files[path], findings, info, "ignored" if k == "ignored" else "code")
    r = _summarise(findings, info, label)
    r["module"] = module_path_of(files)
    r["stats"] = stats
    return r


def _summarise(findings, info, label):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    score = 0
    for f in findings:
        counts[f["severity"]] += 1
        score += SEVERITY_SCORE[f["severity"].lower()]
    level = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[s]), "SAFE")
    findings.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f["file"], f["line"]))
    parts = ["%d %s" % (counts[s], s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[s]]
    return {"target": label, "risk_score": min(score, 100), "risk_level": level,
            "summary": ", ".join(parts) or "No issues found",
            "findings": findings, "info": info,
            "total_findings": len(findings), "info_count": len(info)}


def scan(content, label="<text>", import_time=True):
    """Scan a bare string of Go code. Treated as import-time code by default (the conservative case)."""
    if not re.search(r"^package\s+\w+", content, re.M):
        content = "package x\n" + content
    findings, info = [], []
    gf = GoFile(label, content)
    regions = PkgIndex([gf]).import_time_regions([gf])[label]
    if import_time:
        regions = regions + [(0, len(content), "--text input")]
    scan_go_file(gf, findings, info, regions, "code")
    return _summarise(findings, info, label)


# ---------------------------------------------------------------------------
# Loading targets (never builds, `go get`s or executes module code)
# ---------------------------------------------------------------------------
if os.environ.get("GOMOD_AUDIT_IPV4"):  # networks with a broken IPv6 route
    import socket
    _gai = socket.getaddrinfo
    socket.getaddrinfo = lambda host, port, family=0, *a, **k: _gai(host, port, socket.AF_INET, *a, **k)
UA = {"User-Agent": "gomod-audit/%s (+https://github.com/eltociear/gomod-audit)" % __version__}


def _get(url, timeout=30, tries=5):
    for i in range(tries):
        try:
            return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout).read()
        except urllib.error.HTTPError as e:
            if e.code in (404, 410) or i == tries - 1:
                raise
        except Exception:
            if i == tries - 1:
                raise
        time.sleep(2 * (i + 1))


def escape_path(p):
    """Module proxy case-encoding: every uppercase letter becomes '!' + lowercase."""
    return re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), p)


def split_spec(spec):
    name, _, ver = spec.partition("@")
    return name, (ver or "latest")


def resolve_version(mod, version="latest"):
    if version != "latest":
        return version
    try:
        return json.loads(_get("%s/%s/@latest" % (PROXY, escape_path(mod))))["Version"]
    except urllib.error.HTTPError:
        vers = _get("%s/%s/@v/list" % (PROXY, escape_path(mod))).decode().split()
        if not vers:
            raise
        return vers[-1]


def files_from_zip(data):
    out = {}
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for zi in zf.infolist():
            if zi.is_dir() or zi.file_size > MAX_FILE:
                continue
            name = zi.filename
            # module zips: <module>@<version>/<path>
            at = name.find("@")
            if at > 0:
                slash = name.find("/", at)
                name = name[slash + 1:] if slash > 0 else name
            if name != "go.mod" and not name.endswith(GO_EXT + C_EXT):
                continue
            out[name] = zf.read(zi).decode("utf-8", "replace")
    if not out:
        return out
    # a plain zip of a repo with a single top-level folder
    if "go.mod" not in out:
        tops = {n.split("/", 1)[0] for n in out if "/" in n}
        if len(tops) == 1 and not any("/" not in n for n in out):
            top = tops.pop() + "/"
            out = {n[len(top):]: v for n, v in out.items()}
    return out


def files_from_dir(root):
    out = {}
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in (".git", "node_modules")]
        for fn in fns:
            p = os.path.join(dp, fn)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            if rel != "go.mod" and not fn.endswith(GO_EXT + C_EXT):
                continue
            try:
                if os.path.getsize(p) > MAX_FILE:
                    continue
                with open(p, encoding="utf-8", errors="replace") as fh:
                    out[rel] = fh.read()
            except OSError:
                pass
    return out


def _get_range(url, start, end, timeout=30, tries=5):
    """-> (bytes, total_size). end is inclusive; start < 0 means a suffix range."""
    rng = "bytes=%d" % start if start < 0 else "bytes=%d-%d" % (start, end)
    hdr = dict(UA, Range=rng)
    for i in range(tries):
        try:
            resp = urllib.request.urlopen(urllib.request.Request(url, headers=hdr), timeout=timeout)
            data = resp.read()
            cr = resp.headers.get("Content-Range") or ""
            if resp.status != 206 or "/" not in cr:
                raise ValueError("no range support")
            return data, int(cr.rsplit("/", 1)[1])
        except urllib.error.HTTPError as e:
            if e.code in (404, 410, 416) or i == tries - 1:
                raise
        except ValueError:
            raise
        except Exception:
            if i == tries - 1:
                raise
        time.sleep(2 * (i + 1))


def _wanted(name):
    rel = name.split("/", 1)[1] if "@" in name else name
    at = name.find("@")
    if at > 0:
        sl = name.find("/", at)
        rel = name[sl + 1:] if sl > 0 else name
    if SKIP_TESTS and rel.endswith("_test.go"):
        return False
    return rel == "go.mod" or (rel.endswith(GO_EXT + C_EXT) and "/testdata/" not in "/" + rel)


def files_from_remote_zip(url):
    """Read only the source entries of a remote zip with HTTP Range requests (module zips are mostly
    assets, docs and testdata; the Go/C sources are typically ~20% of the bytes)."""
    tail, size = _get_range(url, -65558, 0)
    if size <= 3000000:  # small zip: one more request for the whole thing beats many ranges
        whole = tail if len(tail) == size else _get(url, timeout=60)
        return {k: v for k, v in files_from_zip(whole).items() if _wanted("m@v/" + k)}
    k = tail.rfind(b"PK\x05\x06")
    if k < 0:
        raise ValueError("no EOCD")
    _, _, _, _, n_ent, cd_size, cd_off = struct.unpack("<IHHHHII", tail[k:k + 20])
    if cd_off == 0xFFFFFFFF or n_ent == 0xFFFF:
        raise ValueError("zip64")
    tail_start = size - len(tail)
    cd = tail[cd_off - tail_start:cd_off - tail_start + cd_size] if cd_off >= tail_start else \
        _get_range(url, cd_off, cd_off + cd_size - 1)[0]
    ents, i = [], 0
    while i + 46 <= len(cd) and cd[i:i + 4] == b"PK\x01\x02":
        (method, csize, usize, nlen, xlen, clen, off) = (struct.unpack("<H", cd[i + 10:i + 12])[0],
                                                         struct.unpack("<I", cd[i + 20:i + 24])[0],
                                                         struct.unpack("<I", cd[i + 24:i + 28])[0],
                                                         struct.unpack("<H", cd[i + 28:i + 30])[0],
                                                         struct.unpack("<H", cd[i + 30:i + 32])[0],
                                                         struct.unpack("<H", cd[i + 32:i + 34])[0],
                                                         struct.unpack("<I", cd[i + 42:i + 46])[0])
        name = cd[i + 46:i + 46 + nlen].decode("utf-8", "replace")
        i += 46 + nlen + xlen + clen
        if usize <= MAX_FILE and not name.endswith("/") and _wanted(name):
            ents.append((off, csize, method, name))
    ents.sort()
    # coalesce into few ranges (gap tolerance grows until there are at most 48 requests)
    gap = 32768
    while True:
        spans = []
        for off, csize, method, name in ents:
            end = off + 30 + 1024 + csize  # local header + name/extra slack
            if spans and off - spans[-1][1] <= gap:
                spans[-1][1] = max(spans[-1][1], end)
                spans[-1][2].append((off, csize, method, name))
            else:
                spans.append([off, end, [(off, csize, method, name)]])
        if len(spans) <= 48 or gap > size:
            break
        gap *= 4
    out = {}
    for s0, s1, items in spans:
        blob, _ = _get_range(url, s0, min(s1, size) - 1)
        for off, csize, method, name in items:
            b = off - s0
            if blob[b:b + 4] != b"PK\x03\x04":
                raise ValueError("bad local header")
            nlen, xlen = struct.unpack("<HH", blob[b + 26:b + 30])
            raw = blob[b + 30 + nlen + xlen:b + 30 + nlen + xlen + csize]
            data = zlib.decompressobj(-15).decompress(raw) if method == 8 else raw
            at = name.find("@")
            sl = name.find("/", at) if at > 0 else -1
            out[name[sl + 1:] if sl > 0 else name] = data.decode("utf-8", "replace")
    return out


def module_files(mod, ver):
    url = "%s/%s/@v/%s.zip" % (PROXY, escape_path(mod), escape_path(ver))
    try:
        return files_from_remote_zip(url)
    except urllib.error.HTTPError:
        raise
    except Exception:  # no range support / zip64 / odd layout: fall back to the whole zip
        return files_from_zip(_get(url, timeout=600))


def audit_remote(spec):
    mod, ver = split_spec(spec)
    ver = resolve_version(mod, ver)
    return scan_module(module_files(mod, ver), "%s@%s" % (mod, ver))


def gomod_specs(path):
    """Every `require` of a go.mod (single-line and block form)."""
    specs, block = [], False
    for raw in open(path, encoding="utf-8").read().split("\n"):
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if re.match(r"^require\s*\($", line):
            block = True
            continue
        if block and line == ")":
            block = False
            continue
        m = re.match(r"^require\s+(\S+)\s+(\S+)$", line) or (re.match(r"^(\S+)\s+(v\S+)$", line) if block else None)
        if m:
            specs.append("%s@%s" % (m.group(1), m.group(2)))
    return sorted(set(specs))


def gosum_specs(path):
    specs = set()
    for line in open(path, encoding="utf-8").read().split("\n"):
        p = line.split()
        if len(p) >= 2 and not p[1].endswith("/go.mod"):
            specs.add("%s@%s" % (p[0], p[1]))
    return sorted(specs)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
_ICON = {"CRITICAL": "\U0001F534", "HIGH": "\U0001F7E0", "MEDIUM": "\U0001F7E1",
         "LOW": "\U0001F535", "SAFE": "\U0001F7E2"}


def _print(r, verbose):
    st = r.get("stats") or {}
    tag = []
    if st.get("init_funcs"):
        tag.append("init()x%d" % st["init_funcs"])
    if st.get("cgo_pkgs"):
        tag.append("cgo")
    if st.get("go_generate"):
        tag.append("go:generate")
    print("%s %s  [%s]  score=%d  (%d findings, %d info)%s" % (
        _ICON.get(r["risk_level"], "?"), r["target"], r["risk_level"], r["risk_score"],
        r["total_findings"], r["info_count"], ("  " + ",".join(tag)) if tag else ""))
    for f in r["findings"]:
        print("    %-8s %s  %s:%s%s" % (f["severity"], f["name"], f["file"], f["line"],
                                       "  (%s)" % f["build_constraint"] if f.get("build_constraint") else ""))
        print("             %s" % f["description"][:160])
        if f["context"] and f["line"]:
            print("             > %s" % f["context"][:160])
    if verbose:
        for f in r["info"]:
            print("    info     %s  %s:%s" % (f["name"], f["file"], f["line"]))


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if args[0] == "--version":
        print(__version__)
        return 0
    as_json = "--json" in args
    verbose = "--verbose" in args or "-v" in args
    if "--no-tests" in args:
        global SKIP_TESTS
        SKIP_TESTS = True
    args = [a for a in args if a not in ("--json", "--verbose", "-v", "--no-tests")]
    targets = []
    if args[0] == "--text":
        txt = " ".join(args[1:])
        targets.append(("<text>", lambda: scan(txt)))
    elif args[0] in ("--gomod", "--gosum"):
        fn = gomod_specs if args[0] == "--gomod" else gosum_specs
        for spec in fn(args[1]):
            targets.append((spec, (lambda s=spec: audit_remote(s))))
    else:
        for a in args:
            if os.path.isdir(a):
                targets.append((a, (lambda p=a: scan_module(files_from_dir(p), p))))
            elif os.path.isfile(a):
                if a.endswith(".zip"):
                    targets.append((a, (lambda p=a: scan_module(files_from_zip(open(p, "rb").read()), p))))
                elif os.path.basename(a) == "go.mod":
                    targets.append((a, (lambda p=a: scan_module(files_from_dir(os.path.dirname(p) or "."), p))))
                else:
                    targets.append((a, (lambda p=a: scan_module(
                        {os.path.basename(p): open(p, encoding="utf-8", errors="replace").read()}, p))))
            else:
                targets.append((a, (lambda s=a: audit_remote(s))))
    results, worst = [], "SAFE"
    for label, thunk in targets:
        try:
            r = thunk()
        except Exception as e:  # network errors, 404s, corrupt archives
            r = {"target": label, "risk_level": "SAFE", "risk_score": 0, "error": str(e)[:200],
                 "findings": [], "info": [], "total_findings": 0, "info_count": 0, "summary": "error"}
            if not as_json:
                print("\u26AA %s  [ERROR] %s" % (label, r["error"]))
        else:
            if not as_json:
                _print(r, verbose)
        results.append(r)
        if SEV_ORDER[r["risk_level"]] > SEV_ORDER[worst]:
            worst = r["risk_level"]
    if as_json:
        print(json.dumps(results if len(results) != 1 else results[0], indent=1))
    return 2 if SEV_ORDER[worst] >= SEV_ORDER["HIGH"] else 0


if __name__ == "__main__":
    sys.exit(main())
