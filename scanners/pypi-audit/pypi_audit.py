#!/usr/bin/env python3
"""pypi-audit - scan PyPI packages for MALICIOUS code before `pip install` runs it.

`pip install` can execute third-party code on your machine in four places before you ever
call the library: the sdist's `setup.py` (or an in-tree PEP 517 build backend / build hook)
while the package is built, every `.pth` file in site-packages on EVERY interpreter start,
the package's module top level the first time it is imported, and its console scripts when
you run them. `pip-audit` / `safety` only answer "does this version have a known advisory?".
This fills the gap in between: a deterministic (no LLM) static scan of the published sdist
and wheel for encoded `exec` payloads, environment and credential exfiltration, DNS beacons,
browser / Discord / wallet theft, crypto clippers, droppers and miners, `.pth` startup hooks
and persistence - weighted by WHEN the code runs.

Precision-tuned to near-zero false positives: what popular packages do every day (setup.py
calling a compiler, `exec(open('pkg/version.py').read())`, namespace-package and
`distutils-precedence` .pth files, subprocess, reading ~/.pypirc or ~/.aws/credentials in a
config loader, verify=False as an option) is reported as informational context and never
inflates the risk score. Risk comes from specific COMBINATIONS and sinks.

The package is never installed and none of its code is executed: the sdist and wheel are
downloaded into memory (large wheels are read with HTTP range requests, member by member)
and read as text.

Usage:
  python pypi_audit.py <pkg>[==version] [...]       # fetch sdist + wheel from PyPI and scan
  python pypi_audit.py --requirements requirements.txt
  python pypi_audit.py <dir|setup.py|file.py|x.pth|x.whl|x.tar.gz|x.zip>   # local
  python pypi_audit.py --text "some code"            # scan a string (as module code)
  add --json for machine-readable output, --verbose to print INFO context,
  --build-only to scan only code that runs at install/startup (setup.py, build backends,
  .pth files and the modules they import), --naive to also report the context-free verdict

Exit code 2 if any target is HIGH or CRITICAL (CI-friendly).
No dependencies beyond the standard library (Python 3.9+). MIT licensed.
"""
import bisect
import gzip
import io
import json
import os
import posixpath
import re
import socket
import sys
import tarfile
import time
import tokenize
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor

__version__ = "0.1.0"

INDEX = os.environ.get("PYPI_AUDIT_INDEX", "https://pypi.org/pypi").rstrip("/")
CODE_EXT = (".py", ".pyw", ".sh", ".bash", ".ps1", ".bat", ".cmd")
MAX_FILE = 1500000       # bytes; larger files are generated tables / vendored data - skipped
MAX_TOTAL = 40000000     # bytes of text scanned per distribution
MAX_SDIST = 120000000    # bytes; bigger sdists are skipped (reported)
SDIST_WITH_WHEEL = 8000000   # with a wheel available, bigger sdists are skipped
FULL_WHEEL = 4000000     # wheels up to this size are downloaded whole, bigger ones by range
PARALLEL = 4             # concurrent range requests per file
LONG_LINE = 65536        # lines longer than this are scanned in overlapping windows
WIN, OVERLAP = 8192, 1024

if os.environ.get("PYPI_AUDIT_IPV4"):  # broken IPv6 on some networks
    _gai = socket.getaddrinfo
    socket.getaddrinfo = lambda h, p, f=0, *a, **k: _gai(h, p, socket.AF_INET, *a, **k)

# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------
# Endpoints legitimate packages essentially never hard-code, but stealers love.
EXFIL_HOST = (
    r"(?:discord(?:app)?\.com/api/webhooks/|api\.telegram\.org/bot|hooks\.slack\.com/services/|"
    r"\bwebhook\.site\b|\bpipedream\.net\b|\brequestbin\.(?:com|net|io)\b|\brequestb\.in\b|\brequestcatcher\.com\b|"
    r"\bbeeceptor\.com\b|pastebin\.com/(?:api|raw)|\bpaste\.ee\b|\bhastebin\.com\b|\btransfer\.sh\b|\bfile\.io/|"
    r"\bngrok(?:-free)?\.(?:io|app|dev)\b|\.trycloudflare\.com\b|\bserveo\.net\b|\blocaltunnel\.me\b|"
    r"\boastify\.com\b|\boast\.(?:fun|me|pro|live|site|online)\b|\binteract\.sh\b|\binteractsh\b|"
    r"\bburpcollaborator\.net\b|\bcanarytokens\.com\b|\bdnslog\.cn\b|\bceye\.io\b|\brequestrepo\.com\b)"
)
# Hosts that are fine on their own but are where hobby-grade collectors live (ctx used a
# Heroku app). Only used in combination with an environment / credential read.
SUSPECT_HOST = r"(?:\.herokuapp\.com|\.repl\.co\b|\.glitch\.me\b|\.workers\.dev\b|\.onion\b|\.000webhostapp\.com|\.ngrok)"
RAW_IP_URL = (r"https?://(?!(?:127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|"
              r"192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|2(?:2[4-9]|[3-5]\d)\.|1\.1\.1\.1\b|8\.8\.[48]\.[48]\b))"
              r"\d{1,3}(?:\.\d{1,3}){3}")
# Something that actually SENDS/RECEIVES over the network.
NET_SEND = (
    r"(?:\brequests\.(?:get|post|put|patch|request|head|Session)\s*\(|\burlopen\s*\(|\burllib2\.|"
    r"\burlretrieve\s*\(|HTTPS?Connection\s*\(|\bhttpx\.(?:get|post|put|request|stream|Client|AsyncClient)\s*\(|"
    r"\baiohttp\.ClientSession\b|\burllib3\.(?:PoolManager|request)\b|\bpycurl\.|\bsocket\.(?:create_connection|socket)\s*\(|"
    r"\bgethostbyname(?:_ex)?\s*\(|\bgetaddrinfo\s*\(|\bdns\.resolver\.|\bsmtplib\.SMTP|\bftplib\.FTP\b|"
    r"\bcurl\s+(?:-[a-zA-Z-]+\s+){0,6}['\"]?https?://|\bwget\s+(?:-[a-zA-Z-]+\s+){0,6}['\"]?https?://|"
    r"Invoke-WebRequest|DownloadFile\s*\(|\.sendto\s*\()"
)
EXEC_SINK = (r"(?:\bos\.system\s*\(|\bos\.popen\s*\(|\bsubprocess\.\w+\s*\(|\bPopen\s*\(|\bcheck_output\s*\(|"
             r"\bcheck_call\s*\(|\bcall\s*\(\s*\[|\bexec\s*\(|\beval\s*\(|\bos\.exec\w+\s*\(|\bos\.spawn\w*\s*\(|"
             r"\bpty\.spawn\s*\(|\bgetoutput\s*\(|\bshell\s*=\s*True)")
_DECODE_MOD = r"(?:base64|zlib|marshal|codecs|lzma|bz2|gzip|binascii|pickle)"
_IMPORTED_DECODE = r"(?:__import__\s*\(\s*['\"]%s['\"]\s*\)|%s)" % (_DECODE_MOD, _DECODE_MOD)
_COMPILE = r"(?:(?:__import__\s*\(\s*['\"]builtins['\"]\s*\)\s*\.\s*)?compile\s*\(\s*)?"
_EXEC_FN = r"(?:\bexec|\beval|__import__\s*\(\s*['\"]builtins['\"]\s*\)\s*\.\s*(?:exec|eval)|getattr\s*\(\s*__builtins__\w*\s*,\s*['\"](?:exec|eval)['\"]\s*\))"
CHECKSUM = r"(?:sha256|sha512|sha384|sha1\b|blake2|md5|hexdigest|checksum|expected_hash|hashlib)"

PATTERNS = {
    "critical": [
        {"id": "download_execute", "name": "Download & Execute",
         "desc": "Fetches remote content and runs it (pipe to shell, exec of a downloaded body)",
         "needles": ["curl", "wget", "iex", "invoke-expression", "powershell", "exec", "eval"],
         "regexes": [
             r"curl\s+[^\n|;\"']{0,300}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python[\d.]*)\b",
             r"wget\s+[^\n|;\"']{0,300}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python[\d.]*)\b",
             r"(?:sh|bash|python[\d.]*)\s*<\s*\(\s*(?:curl|wget)",
             _EXEC_FN + r"\s*\(\s*(?:\w+\.)*(?:urlopen|get|urlretrieve)\s*\([^\n]{0,200}\)\s*\.\s*(?:read\s*\(\s*\)|text|content)",
             _EXEC_FN + r"\s*\(\s*requests\.get\s*\(",
             r"(?:iex|Invoke-Expression)\s*\(?\s*\(?\s*(?:New-Object\s+Net\.WebClient|iwr|Invoke-WebRequest)",
             r"powershell[^\n]{0,60}-(?:e|enc|encodedcommand)\s+['\"]?[A-Za-z0-9+/=]{40,}",
         ]},
        {"id": "env_exfil", "name": "Environment Dump",
         "desc": "Serialises the whole os.environ (every token/secret) - exfil when a network sink is present",
         "needles": ["environ"],
         "regexes": [
             r"(?:json\.dumps|\bstr|\brepr|b64encode|urlencode|pickle\.dumps)\s*\(\s*(?:dict\s*\(\s*)?(?:os\.)?environ\s*(?:\.copy\s*\(\s*\)\s*)?\)",
             r"\b(?:data|json|params)\s*=\s*(?:dict\s*\(\s*)?(?:os\.)?environ\s*(?:\.copy\s*\(\s*\)\s*)?\)?\s*[,)]",
             r"f['\"][^'\"\n]{0,200}\{\s*(?:os\.)?environ\s*\}",
         ]},
        {"id": "reverse_shell", "name": "Reverse Shell",
         "desc": "Spawns an interactive shell bound to a network socket",
         "needles": ["/dev/tcp", "bash", "dup2", "/bin/"],
         "regexes": [
             r"/dev/tcp/[\w.\-]+/\d+",
             r"bash\s+-i\s*>&",
             r"\bnc(?:at)?\s+(?:-\w+\s+)*-e\s+/bin/(?:ba)?sh",
         ]},
        {"id": "destructive", "name": "Destructive Payload",
         "desc": "Wipes the home directory / filesystem",
         "needles": ["rm -", "rm\t", "rmtree"],
         "regexes": [
             r"rm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+(?:--no-preserve-root\s+)?(?:~|\$HOME|/)(?:\s|[\"'`;]|$)",
             r"rmtree\s*\(\s*(?:os\.path\.expanduser\s*\(\s*['\"]~['\"]\s*\)|Path\.home\s*\(\s*\)|['\"](?:/|C:\\\\|~)['\"])\s*[,)]",
         ]},
        {"id": "worm_propagation", "name": "Self-Propagation (Worm)",
         "desc": "Uses stolen registry/GitHub tokens to republish packages or harvest more secrets",
         "needles": ["upload.pypi.org", ".pypirc", "pypi_token", "twine_password", "trufflehog"],
         "regexes": [
             r"upload\.pypi\.org/legacy[^\n]{0,200}(?:\.pypirc|PYPI_TOKEN|TWINE_PASSWORD|pypi-Ag)",
             r"(?:\.pypirc|PYPI_TOKEN|TWINE_PASSWORD)[^\n]{0,200}(?:upload\.pypi\.org|twine\s+upload)",
             r"trufflehog[^\n]{0,80}(?:filesystem|github|--json)",
             r"github\.com/trufflesecurity/trufflehog/releases",
         ]},
    ],
    "high": [
        {"id": "exfil_host", "name": "Exfiltration Endpoint",
         "desc": "Hard-codes a webhook / paste / tunnel / OAST collector host",
         "needles": ["discord", "telegram", "slack.com", "webhook.site", "pipedream", "request", "beeceptor",
                     "paste", "hastebin", "transfer.sh", "file.io", "ngrok", "trycloudflare", "serveo", "localtunnel",
                     "oast", "interact", "burpcollaborator", "canarytokens", "dnslog", "ceye", "requestrepo"],
         "regexes": [EXFIL_HOST]},
        {"id": "obfuscated_exec", "name": "Exec of Encoded Payload",
         "desc": "exec/eval of base64 / zlib / marshal / hex / char-code / Fernet-decoded data (W4SP-style)",
         "needles": ["exec", "eval"],
         "regexes": [
             _EXEC_FN + r"\s*\(\s*" + _COMPILE + _IMPORTED_DECODE + r"\s*\.\s*\w+\s*\(",
             _EXEC_FN + r"\s*\(\s*" + _COMPILE + r"(?:b64decode|b85decode|a85decode|b32decode|decompress|unhexlify)\s*\(",
             _EXEC_FN + r"\s*\(\s*" + _COMPILE + r"(?:bytes|bytearray)\.fromhex\s*\(",
             _EXEC_FN + r"\s*\(\s*" + _COMPILE + r"['\"]{2}\s*\.\s*join\s*\(\s*(?:map\s*\(\s*chr|\[?\s*chr\s*\()",
             _EXEC_FN + r"\s*\(\s*" + _COMPILE + r"Fernet\s*\(",
             _EXEC_FN + r"\s*\(\s*" + _COMPILE + r"\w+\s*\.\s*decrypt\s*\(\s*b?['\"]",
             r"\bexec\s*\(\s*(?:compile\s*\(\s*)?['\"]{2}\s*\.\s*join\s*\(",
             _EXEC_FN + r"\s*\(\s*" + _COMPILE + r"['\"](?:\\x[0-9a-fA-F]{2}){20,}",
         ]},
        {"id": "whitespace_hiding", "name": "Whitespace-Hidden Code",
         "desc": "Code pushed hundreds of columns to the right so it is off-screen in an editor (W4SP setup.py trick)",
         "needles": [" " * 100, "\t" * 50],
         "regexes": [r"\S[ \t]{200,};?\s*(?:exec|eval|__import__|import\s|from\s+\w+\s+import|os\.system|subprocess)\b"]},
        {"id": "stealer", "name": "Browser / Discord / Wallet Theft",
         "desc": "Targets browser credential stores, Discord tokens, crypto-wallet storage or the Keychain",
         "needles": ["login data", "local extension settings", "cookies", "discord", "dqw4w9wgxcq", "mfa", "{27}",
                     "exodus", "atomic", "electrum", "ethereum", "wallet.dat", "seed.seco", "bfnaelmomeimhlpmgjnjophhpkkoljpa",
                     "hnfanknocfeofbddgcijnmhnfnkdnaad", "ibnejdfjmmkpcnlpebklmnkoeoihofec", "egjidjbpglichdcondbcbdnbeeppgdph",
                     "solana", "find-generic-password", "nkbihfbeogaeaoehlefnkodbefgpgknn", "cookies", "mfa."],
         "regexes": [
             r"nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|hnfanknocfeofbddgcijnmhnfnkdnaad|ibnejdfjmmkpcnlpebklmnkoeoihofec|egjidjbpglichdcondbcbdnbeeppgdph",
             r"(?:Chrome|BraveSoftware|Microsoft[/\\\\]+Edge|Opera Software|Yandex)[^\n]{0,80}(?:Login Data|Local Extension Settings|Network[/\\\\]+Cookies)",
             r"[dD]iscord(?:canary|ptb)?[/\\\\]+Local Storage[/\\\\]+leveldb",
             r"dQw4w9WgXcQ:",
             r"mfa\\\.\[\\w-\]\{84\}|\[\\w-\]\{24\}\\\.\[\\w-\]\{6\}\\\.\[\\w-\]\{27\}",
             r"(?:Exodus|atomic|Electrum|Ethereum)[/\\\\]+(?:exodus\.wallet|Local Storage|wallets|keystore)",
             r"\.config[/\\\\]+solana[/\\\\]+id\.json",
             r"security\s+find-generic-password",
             r"\b(?:wallet\.dat|seed\.seco)\b",
         ]},
        {"id": "miner", "name": "Cryptominer",
         "desc": "Mining-pool protocol, XMRig flags or a known pool host",
         "needles": ["stratum", "xmrig", "donate-level", "supportxmr", "nanopool", "c3pool", "moneroocean", "minexmr", "2miners"],
         "regexes": [r"stratum\+(?:tcp|ssl|tls)://", r"\bxmrig\b", r"--donate-level", r"\b(?:pool\.)?(?:supportxmr|moneroocean|c3pool|minexmr)\.com\b",
                     r"\b(?:xmr|etc|rvn|eth)\w*\.nanopool\.org\b", r"\b\w+\.2miners\.com\b"]},
        {"id": "dns_exfil", "name": "DNS Exfiltration",
         "desc": "Encodes host / user / file data into a DNS name (dependency-confusion beacon, torchtriton shape)",
         "needles": ["gethostbyname", "getaddrinfo", "resolver."],
         "regexes": [
             r"(?:gethostbyname(?:_ex)?|getaddrinfo|dns\.resolver\.(?:resolve|query)|resolver\.(?:resolve|query))\s*\((?=[^\n]{0,300}['\"]\.[\w-]+\.[\w.-]+['\"])[^\n]{0,200}(?:gethostname\s*\(|getuser\s*\(|getlogin\s*\(|uname\s*\(|node\s*\(\s*\)|hexlify|\.hex\s*\(|b32encode|b64encode|b16encode|environ)",
             r"(?:gethostbyname(?:_ex)?|getaddrinfo|dns\.resolver\.(?:resolve|query))\s*\(\s*f?['\"][^'\"\n]{0,40}\{[^}\n]{1,80}\}\.[\w-]+\.[\w.-]+['\"]",
         ]},
        {"id": "credential_exfil", "name": "Credential Exfiltration",
         "desc": "Reads a credential store AND names an external destination on the same line",
         "needles": [".ssh", ".aws", ".pypirc", ".git-credentials", ".docker", ".kube", ".netrc"],
         "regexes": [
             r"(?:\.pypirc|\.ssh[/\\\\]+id_|\.aws[/\\\\]+credentials|\.git-credentials|\.docker[/\\\\]+config\.json|\.kube[/\\\\]+config|\.netrc)[^\n]{0,200}(?:https?://(?!(?:upload\.)?pypi\.org|test\.pypi\.org|files\.pythonhosted)|" + EXFIL_HOST + r")",
         ]},
        {"id": "persistence_pth", "name": ".pth Startup Hook Write",
         "desc": "Writes a .pth file into site-packages: it will run on every interpreter start",
         "needles": [".pth"],
         "regexes": [
             r"(?:getsitepackages|getusersitepackages|site-packages|purelib|get_python_lib|sysconfig\.get_path)[^\n]{0,200}\.pth['\"]",
             r"\.pth['\"][^\n]{0,200}(?:getsitepackages|getusersitepackages|site-packages|purelib|get_python_lib)",
         ]},
    ],
    "medium": [
        {"id": "raw_ip_url", "name": "Raw-IP URL",
         "desc": "Contacts a public IP address directly instead of a hostname",
         "needles": ["http"], "regexes": [RAW_IP_URL]},
        {"id": "persistence_write", "name": "Persistence Write",
         "desc": "Writes shell rc files, authorized_keys, autostart, cron, LaunchAgents or the Run registry key",
         "needles": ["bashrc", "zshrc", "bash_profile", "zprofile", "authorized_keys", "launchagents", "autostart", "crontab", "/etc/cron",
                     "currentversion\\\\run", "currentversion\\run", "startup", "systemd"],
         "regexes": [
             r"(?:open|write_text|copy\w*|rename|move)\s*\([^\n]{0,160}(?:\.bashrc|\.zshrc|\.bash_profile|\.zprofile|authorized_keys|LaunchAgents|\.config[/\\\\]+autostart|systemd[/\\\\]+user|/etc/cron|Start Menu[/\\\\]+Programs[/\\\\]+Startup)",
             r"CurrentVersion\\\\+Run\b",
             r"crontab\s+-[^l\s]",
         ]},
        {"id": "tls_disabled", "name": "TLS Verification Disabled",
         "desc": "Turns certificate checking off",
         "needles": ["unverified", "verify", "cert_none", "insecure", "no-check-certificate"],
         "regexes": [r"_create_unverified_context\b", r"\bverify\s*=\s*False\b", r"CERT_NONE\b",
                     r"\bcurl\s+[^\n]{0,200}(?:\s-k\b|--insecure)", r"wget\s+[^\n]{0,200}--no-check-certificate"]},
    ],
    "low": [],
    # Context: reported, never scored. Capabilities popular packages use daily.
    "info": [
        {"id": "credential_read", "name": "Credential Store Reference",
         "desc": "References ~/.pypirc, ~/.ssh, ~/.aws, ~/.netrc ... (config loaders and CLIs read their own auth)",
         "needles": [".pypirc", ".ssh", ".aws", ".git-credentials", ".docker", ".netrc", ".kube", "etc/passwd", ".gitconfig"],
         "regexes": [r"\.pypirc\b", r"\.ssh[/\\\\]+(?:id_\w+|known_hosts)\b", r"\.aws[/\\\\]+credentials", r"\.git-credentials",
                     r"\.docker[/\\\\]+config\.json", r"(?<![\w-])\.netrc\b", r"\.kube[/\\\\]+config", r"/etc/passwd\b",
                     r"(?<![\w.-])\.gitconfig\b"]},
        {"id": "process_spawn", "name": "Process Spawning",
         "desc": "subprocess / os.system (compilers, git, CLIs, binary wrappers)",
         "needles": ["subprocess", "os.system", "os.popen", "popen"],
         "regexes": [r"\bsubprocess\.\w+\s*\(", r"\bos\.system\s*\(", r"\bos\.popen\s*\(", r"\bPopen\s*\("]},
        {"id": "network", "name": "Network Access",
         "desc": "Makes outbound HTTP / DNS / socket calls",
         "needles": ["requests.", "urlopen", "urllib2", "urlretrieve", "connection", "httpx", "aiohttp", "urllib3",
                     "pycurl", "socket.", "gethostbyname", "getaddrinfo", "dns.resolver", "smtplib", "ftplib", "curl", "wget",
                     "invoke-webrequest", "downloadfile", "sendto"],
         "regexes": [NET_SEND]},
        {"id": "env_walk", "name": "Environment Walk",
         "desc": "Iterates over every environment variable",
         "needles": ["environ"],
         "regexes": [r"for\s+\w+(?:\s*,\s*\w+)?\s+in\s+(?:os\.)?environ(?:\.items\s*\(\s*\)|\.keys\s*\(\s*\)|\.values\s*\(\s*\))?\s*:"]},
        {"id": "dynamic_exec", "name": "Dynamic exec/compile",
         "desc": "exec/eval of a non-literal (version files, templating, REPLs)",
         "needles": ["exec", "eval"],
         "regexes": [r"\bexec\s*\(\s*(?!['\"])\w"]},
        {"id": "pyarmor", "name": "PyArmor-Protected Code",
         "desc": "Commercially obfuscated module (vendor licensing) - opaque to static review",
         "needles": ["pyarmor"],
         "regexes": [r"__pyarmor__|pyarmor_runtime"]},
        {"id": "clipboard", "name": "Clipboard Access",
         "desc": "Reads or writes the clipboard",
         "needles": ["clipboard", "pyperclip", "pbpaste", "pbcopy", "xclip"],
         "regexes": [r"\bpyperclip\.(?:paste|copy)\s*\(", r"win32clipboard\.\w+", r"\bclipboard_(?:get|append)\s*\(",
                     r"\bGetClipboardData\b|\bSetClipboardData\b", r"\bpbpaste\b|\bpbcopy\b|xclip\s+-selection"]},
    ],
}

SEVERITY_SCORE = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "SAFE": 0}
_CASE = {"stealer", "whitespace_hiding"}  # case-sensitive groups (Windows paths, the Discord marker)
_GROUPS = []
for _sev, _gs in PATTERNS.items():
    for _pg in _gs:
        _GROUPS.append((_sev, _pg, [re.compile(rx, 0 if _pg["id"] in _CASE else re.IGNORECASE) for rx in _pg["regexes"]]))
NET_RE = re.compile(NET_SEND)
EXEC_SINK_RE = re.compile(EXEC_SINK)
EXFIL_RE = re.compile(EXFIL_HOST, re.IGNORECASE)
SUSPECT_RE = re.compile(SUSPECT_HOST, re.IGNORECASE)
RAWIP_RE = re.compile(RAW_IP_URL)
CHECKSUM_RE = re.compile(CHECKSUM, re.IGNORECASE)
B64ENC_RE = re.compile(r"\bb64encode\s*\(|\bb32encode\s*\(|\bhexlify\s*\(|\.hex\s*\(\s*\)")
BLOB_RE = re.compile(r"[A-Za-z0-9+/=_\-]{4096,}")
CHMOD_RE = re.compile(r"\bchmod\s*\([^\n]{0,80}(?:0o?7\d\d|0o?5\d\d|S_IX|S_IEXEC|\|\s*0o?1\b|0o?111)|\bchmod\s+\+?[0-7]*x|\bchmod\s+[0-7]?7[0-7]{2}\b", re.IGNORECASE)
DOWNLOAD_RE = re.compile(r"\burlretrieve\s*\(|\burlopen\s*\(|\brequests\.get\s*\(|\bhttpx\.get\s*\(|\bwget\s|\bcurl\s", re.IGNORECASE)
# exec of a computed path: subprocess.Popen([path, ...]) / os.system(var) etc, not a literal tool name
DYN_EXEC_RE = re.compile(r"(?:subprocess\.\w+|Popen|os\.system|os\.startfile|os\.exec\w+)\s*\(\s*\[?\s*(?!['\"\[]|sys\.executable|cmd\b|args\b|command\b)[\w.]+")
CLIP_SET_RE = re.compile(r"\bpyperclip\.copy\s*\(|SetClipboardData|\bclipboard_append\s*\(|\bpbcopy\b|xclip\s+-selection")
ADDR_RE = re.compile(r"(?:\^?\(?\??(?:bc1|\[13\]|1\|3)[^\n]{0,40}\[a-[zA-Z][^\n]{0,20}\]\{2[0-9],|0x\[a-fA-F0-9\]\{40\}|\[48\]\[0-9AB\]|T\[A-Za-z1-9\]\{33\}|\[LM3\]\[a-km-zA-HJ-NP-Z1-9\])")
SOCK_CONNECT_RE = re.compile(r"\.connect\s*\(\s*\(|socket\.create_connection\s*\(")
DUP2_RE = re.compile(r"os\.dup2\s*\(\s*(\w+)\.fileno\s*\(\s*\)\s*,\s*[012]\s*\)")
SHELL_SPAWN_RE = re.compile(r"pty\.spawn\s*\(|['\"]/bin/(?:ba|z)?sh['\"]|['\"](?:ba)?sh['\"]\s*,\s*['\"]-i['\"]|cmd\.exe")
TEST_PATH_RE = re.compile(r"(?:^|/)(?:tests?|testing|__tests__|examples?|docs?|doc_src|benchmarks?|demos?|samples?)/|"
                          r"(?:^|/)(?:test_[^/]*|[^/]*_test|conftest)\.py$", re.IGNORECASE)
PLACEHOLDER_RE = re.compile(r"(?:\b(?:your|my)[-_]|xxxx|<[\w-]+>|\{[\w-]+\}|\b123456\b|example|\.\.\.)", re.IGNORECASE)
CHAT_API_RE = re.compile(r"api\.telegram\.org/bot|discord(?:app)?\.com/api/webhooks/|hooks\.slack\.com/services/", re.IGNORECASE)
HARDCODED_CHAT_RE = re.compile(r"api\.telegram\.org/bot\d{5,}:[\w-]{20,}|discord(?:app)?\.com/api/webhooks/\d{4,}/[\w-]{10,}|"
                               r"hooks\.slack\.com/services/T\w+/B\w+/\w+", re.IGNORECASE)
LINE_ONCE = {"network", "process_spawn", "credential_read", "dynamic_exec", "pyarmor", "clipboard", "env_walk"}
# ids whose match in a str literal of a .py file is only text (an install hint / help message)
NEED_EXEC_ON_LINE = {"download_execute"}
BRANDS = ("ngrok", "telegram", "discord", "slack", "pastebin", "localtunnel", "cloudflare", "pipedream",
          "webhook", "requestbin", "interactsh", "canary", "burp", "xmrig", "stratum", "miner")
# what pip/importlib/python treat as "runs automatically"
CTX_INSTALL, CTX_STARTUP, CTX_IMPORT = "install", "startup", "import"


def _item(sev, pid, name, desc, path, n, matched, ctx):
    return {"severity": sev, "id": pid, "name": name, "description": desc, "file": path,
            "line": n, "matched": matched[:120], "context": ctx.strip()[:200]}


# ---------------------------------------------------------------------------
# Python source model: comments/docstrings masked, top-level (import-time) lines
# ---------------------------------------------------------------------------
def _mask_python(text):
    """Return (masked_text, toplevel) where comments and bare-string statements (docstrings) are
    blanked to spaces (offsets and line numbers preserved) and toplevel is a list of
    (first_line, kind) for each statement at module level ('code', 'def', 'main')."""
    lines = text.splitlines(True)
    starts = [0]
    for ln in lines:
        starts.append(starts[-1] + len(ln))
    spans, top = [], []
    depth, logical, first = 0, [], None
    paren = 0
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            tt = tok.type
            if tt == tokenize.COMMENT:
                spans.append((tok.start, tok.end))
                continue
            if tt == tokenize.INDENT:
                depth += 1
                continue
            if tt == tokenize.DEDENT:
                depth -= 1
                continue
            if tt in (tokenize.NL, tokenize.ENCODING):
                continue
            if tt == tokenize.NEWLINE or tt == tokenize.ENDMARKER:
                if logical and all(t.type == tokenize.STRING for t in logical):
                    spans.append((logical[0].start, logical[-1].end))
                logical, first, paren = [], None, 0
                continue
            if not logical:
                first = tok
                if depth == 0:
                    s = tok.string
                    if s in ("def", "class", "@", "async"):
                        kind = "def"
                    elif s == "if" and re.match(r"\s*if\s+__name__\s*==", lines[tok.start[0] - 1] if tok.start[0] <= len(lines) else ""):
                        kind = "main"
                    else:
                        kind = "code"
                    top.append((tok.start[0], kind))
            logical.append(tok)
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        return _mask_fallback(text)
    if not spans:
        return text, top
    out, pos = [], 0
    for (sr, sc), (er, ec) in sorted(spans):
        a = starts[sr - 1] + sc
        b = starts[er - 1] + ec
        if a < pos:
            continue
        out.append(text[pos:a])
        out.append(re.sub(r"[^\n]", " ", text[a:b]))
        pos = b
    out.append(text[pos:])
    return "".join(out), top


def _mask_fallback(text):
    """Untokenizable source (Python 2, broken files): blank `#` comment lines, top level by indent."""
    out, top = [], []
    for n, ln in enumerate(text.split("\n"), 1):
        s = ln.lstrip()
        if s.startswith("#"):
            out.append(" " * len(ln))
            continue
        out.append(ln)
        if ln and not ln[0].isspace() and not s.startswith((")", "]", "}", "'''", '"""')):
            w = s.split(None, 1)[0] if s else ""
            kind = "def" if w in ("def", "class", "async") or s.startswith("@") else (
                "main" if re.match(r"if\s+__name__\s*==", s) else "code")
            top.append((n, kind))
    return "\n".join(out), top


def _toplevel_lines(top, nlines):
    """Set of 1-based line numbers that execute at import (module-level code, not def/class/__main__)."""
    run = set()
    for i, (ln, kind) in enumerate(top):
        end = top[i + 1][0] if i + 1 < len(top) else nlines + 1
        if kind == "code":
            run.update(range(ln, end))
    return run


def _prep(text):
    """Strip >=4 KB encoded blobs (keep a marker) and window very long lines."""
    blobs = 0
    if len(text) > 4096 and BLOB_RE.search(text):
        text, blobs = BLOB_RE.subn("BLOB", text)
    if len(text) > LONG_LINE and any(len(ln) > LONG_LINE for ln in text.split("\n")):
        out = []
        for ln in text.split("\n"):
            if len(ln) > LONG_LINE:
                ln = "\x00".join(ln[i:i + WIN] for i in range(0, len(ln), WIN - OVERLAP))
            out.append(ln)
        text = "\n".join(out)
    return text, blobs


# ---------------------------------------------------------------------------
# File scan
# ---------------------------------------------------------------------------
SUSPECT_NEEDLES = ("herokuapp", "repl.co", "glitch.me", "workers.dev", ".onion", "000webhost", ".ngrok")


def _newlines(text):
    return [m.start() for m in re.finditer("\n", text)]


def _matches(text, low, nl, groups):
    """Yield (sev, group, rxs, line_no, line_text, match) for every regex hit, scanning only the
    lines that contain one of the group's needles (all regexes are line-bounded). Python's re has
    no literal-prefix speedup for big case-insensitive alternations; this keeps it linear-ish."""
    nlen = len(nl)
    cand_cache = {}
    for sev, pg, rxs in groups:
        lines = set()
        for nd in pg["needles"]:
            hit = cand_cache.get(nd)
            if hit is None:
                hit = []
                i = low.find(nd)
                while i >= 0:
                    li = bisect.bisect_left(nl, i)
                    hit.append(li)
                    if li >= nlen:
                        break
                    i = low.find(nd, nl[li] + 1)
                cand_cache[nd] = hit
            lines.update(hit)
        for li in sorted(lines):
            a = nl[li - 1] + 1 if li >= 1 else 0
            b = nl[li] if li < nlen else len(text)
            line = text[a:b]
            for rx in rxs:
                m = rx.search(line)
                if m:
                    yield sev, pg, rxs, li + 1, line, m


def _near(text, rxs, span):
    """True if every regex matches and some choice of one match each fits within `span` lines
    (download, chmod and exec in one code path, not scattered across a 2,000-line CLI)."""
    hits = []
    for rx in rxs:
        lines = sorted({text.count("\n", 0, m.start()) for m in rx.finditer(text)})
        if not lines:
            return False
        hits.append(lines)
    for anchor in hits[0]:
        if all(any(abs(x - anchor) <= span for x in h) for h in hits[1:]):
            lo = min([anchor] + [min(x for x in h if abs(x - anchor) <= span) for h in hits[1:]])
            hi = max([anchor] + [max(x for x in h if abs(x - anchor) <= span) for h in hits[1:]])
            if hi - lo <= span:
                return True
    return False


def _scan_text(text, path, findings, info, ctx=None, pkg=""):
    """Scan one file. ctx: None (runtime module) | 'install' | 'startup' (whole file runs
    automatically) | 'import' (module whose top-level code runs on import) |
    'startup-module' (a module a .pth imports: its top level runs at interpreter start)."""
    text, blobs = _prep(text)
    low = text.lower()
    is_py = path.endswith((".py", ".pyw", ".pth")) or "." not in posixpath.basename(path)
    if blobs:
        info.append(_item("INFO", "embedded_blob", "Embedded Encoded Blob",
                          "%d encoded run(s) of 4 KB or more (data, fonts, wheels-in-wheels)" % blobs, path, 0, "", ""))
    groups = _GROUPS
    top = []
    masked = text
    if is_py and not path.endswith(".pth"):
        # tokenizing is the expensive part: only when a scored signature hits the raw text
        scored = [g for g in _GROUPS if g[0] != "info"]
        if next(_matches(text, low, _newlines(text), scored), None) is not None:
            masked, top = _mask_python(text)
    nl = _newlines(masked)
    local, seen = [], set()
    for sev, pg, rxs, n, line, m in _matches(masked, low, nl, groups):
        pid = pg["id"]
        if (pid, n) in seen or (pid, 0) in seen:
            continue
        seen.add((pid, n))
        if pid in LINE_ONCE:
            seen.add((pid, 0))
        ctxt = line if len(line) <= 400 else line[max(0, m.start() - 100):m.start() + 200]
        local.append(_item(sev.upper(), pid, pg["name"], pg["desc"], path, n, m.group(0), ctxt))
    if not local:
        return
    ids = {f["id"] for f in local}
    has_net = "network" in ids
    auto = ctx in (CTX_INSTALL, CTX_STARTUP)

    def demote(pid, why, cond=lambda f: True):
        for f in local:
            if f["id"] == pid and f["severity"] != "INFO" and cond(f):
                f["severity"] = "INFO"
                f["description"] += " [%s]" % why

    def line_of(f):
        if not f["line"]:
            return ""
        a = nl[f["line"] - 2] + 1 if f["line"] >= 2 else 0
        b = nl[f["line"] - 1] if f["line"] - 1 < len(nl) else len(masked)
        return masked[a:b]

    run_lines = None
    if ctx in (CTX_IMPORT, "startup-module", "install-module") and top:
        run_lines = _toplevel_lines(top, masked.count("\n") + 1)

    # ---- demotions: text that is shown, not run --------------------------------------
    if is_py:
        for pid in NEED_EXEC_ON_LINE & ids:
            demote(pid, "string only: not passed to exec/subprocess", lambda f: not EXEC_SINK_RE.search(line_of(f)))
    # a shell script shipped inside a package (dataset fetchers, CI templates) runs only when a
    # person runs it: pipe-to-shell there is MEDIUM, not a finding that fails CI.
    if "download_execute" in ids and not is_py and ctx not in (CTX_INSTALL, CTX_STARTUP):
        for f in local:
            if f["id"] == "download_execute" and f["severity"] == "CRITICAL":
                f["severity"] = "MEDIUM"
                f["description"] += " [shipped shell script, runs only when invoked by hand]"
    if "env_exfil" in ids and not has_net:
        demote("env_exfil", "no network sink in file")
    if "exfil_host" in ids:
        if not has_net and not auto:
            demote("exfil_host", "no network sink in file")
        brand = re.sub(r"[^a-z]", "", pkg.lower())
        demote("exfil_host", "the package is an integration for this service",
               lambda f: brand and any(b in brand and b in f["matched"].lower() for b in BRANDS))
        demote("exfil_host", "chat API called with the caller's own token",
               lambda f: CHAT_API_RE.search(f["matched"]) and not HARDCODED_CHAT_RE.search(line_of(f)))
        demote("exfil_host", "placeholder / help-text URL", lambda f: PLACEHOLDER_RE.search(f["context"]))
    if "miner" in ids:
        brand = re.sub(r"[^a-z]", "", pkg.lower())
        if brand and any(b in brand for b in ("miner", "mining", "xmr", "stratum", "pool", "crypto", "monero")):
            demote("miner", "the package is mining software")
    if "raw_ip_url" in ids and not (auto or "credential_read" in ids or "env_exfil" in ids):
        demote("raw_ip_url", "runtime code, no credential/env read")
    if "tls_disabled" in ids and not auto:
        demote("tls_disabled", "runtime option")
    # virtualenv / editable installs / coverage write .pth files into the environment they are
    # creating, from a function you call. Only a write that happens on its own is persistence.
    if "persistence_pth" in ids and not auto:
        demote("persistence_pth", "environment / install tool, called explicitly",
               lambda f: run_lines is None or f["line"] not in run_lines)
    if "persistence_write" in ids and not auto:
        demote("persistence_write", "runtime installer (completions, PATH setup)")
    if "stealer" in ids:
        brand = re.sub(r"[^a-z]", "", pkg.lower())
        demote("stealer", "the package is a browser-cookie / wallet library",
               lambda f: brand and any(b in brand for b in ("cookie", "browser", "wallet", "keyring", "keychain")))

    # ---- combinations ---------------------------------------------------------------
    live = {f["id"] for f in local if f["severity"] != "INFO"}
    suspect = any(h in low for h in SUSPECT_NEEDLES) and bool(SUSPECT_RE.search(masked))
    exfil_dest = "exfil_host" in ids or suspect
    if "credential_read" in ids and has_net and (exfil_dest or "raw_ip_url" in ids or
                                                 (auto and "dns_exfil" in live)):
        local.append(_item("CRITICAL", "credential_exfil", "Credential Exfiltration",
                           "Reads a credential store and sends to a collector / raw IP in the same file",
                           path, 0, "", "file-level combination"))
    if "env_walk" in ids and has_net and "env_exfil" not in live and (exfil_dest or (B64ENC_RE.search(masked) and
                                                                                     (auto or ctx == CTX_STARTUP or suspect))):
        local.append(_item("CRITICAL", "env_exfil", "Environment Exfiltration",
                           "Walks every environment variable, encodes it and sends it to a collector (ctx shape)",
                           path, 0, "", "file-level combination"))
    # socket wired onto stdin/stdout/stderr + a shell: the classic python reverse shell. dup2 of a
    # temp file onto fd 2 alone is output capture (test harnesses, compilers).
    if ("reverse_shell" not in live and "dup2" in low and SOCK_CONNECT_RE.search(masked) and DUP2_RE.search(masked)
            and SHELL_SPAWN_RE.search(masked)):
        local.append(_item("CRITICAL", "reverse_shell", "Reverse Shell",
                           "Connects a socket, dup2()s it onto stdio and spawns a shell", path, 0, "", "file-level combination"))
    if "dns_exfil" in live and "credential_read" in ids:
        local.append(_item("CRITICAL", "credential_exfil", "Credential Exfiltration over DNS",
                           "Reads a credential store and encodes data into DNS lookups (torchtriton shape)",
                           path, 0, "", "file-level combination"))
    if "clipboard" in ids and CLIP_SET_RE.search(masked) and ADDR_RE.search(masked):  # gated: rare
        local.append(_item("HIGH", "clipper", "Crypto Clipper",
                           "Watches the clipboard and rewrites cryptocurrency addresses",
                           path, 0, "", "file-level combination"))
    if (has_net and "chmod" in low and "process_spawn" in ids and not CHECKSUM_RE.search(masked)
            and _near(masked, (DOWNLOAD_RE, CHMOD_RE, DYN_EXEC_RE), 30)):
        sev = "CRITICAL" if "miner" in live else "HIGH"
        local.append(_item(sev, "dropper", "Download & Execute Binary (dropper)",
                           "Downloads a file, marks it executable and runs it, with no checksum check" +
                           (" - a cryptominer" if sev == "CRITICAL" else ""), path, 0, "", "file-level combination"))
    if auto and ctx == CTX_INSTALL and has_net and not any(
            f["id"] in ("dropper", "credential_exfil", "env_exfil", "download_execute") and f["severity"] != "INFO" for f in local):
        if not CHECKSUM_RE.search(masked):
            local.append(_item("MEDIUM", "install_network", "Unverified Install-Time Download",
                               "setup.py / build backend performs network I/O with no checksum verification in the file",
                               path, 0, "", "file-level"))

    # ---- context escalation ---------------------------------------------------------
    for f in local:
        if f["severity"] == "INFO":
            continue
        when = None
        if auto:
            when = ctx
        elif run_lines is not None and (f["line"] in run_lines or (f["line"] == 0 and False)):
            when = {"startup-module": CTX_STARTUP, "install-module": CTX_INSTALL}.get(ctx, CTX_IMPORT)
        if not when:
            continue
        f["runs_at"] = when
        if f["severity"] == "HIGH":
            f["severity"] = "CRITICAL"
            f["description"] += " [runs at %s time]" % when
        elif f["severity"] == "MEDIUM" and f["id"] == "raw_ip_url":
            f["severity"] = "HIGH"
            f["description"] += " [runs at %s time]" % when
    for f in local:
        (info if f["severity"] == "INFO" else findings).append(f)


# .pth: lines starting with "import" are exec()'d by site.py at every interpreter start.
PTH_IMPORT_RE = re.compile(r"^import[ \t]")
PTH_DANGER_RE = re.compile(
    r"b64decode|b85decode|\bzlib\b|\bmarshal\b|\burlopen\b|\burllib\b|\brequests\b|\bsocket\b|\bsubprocess\b|"
    r"\bos\.system\b|\bpopen\b|bytes\.fromhex|codecs\.decode|\bexec\s*\(\s*(?!['\"])|\beval\s*\(\s*(?!['\"])|"
    r"\bcompile\s*\(\s*(?!['\"])|__import__\s*\(\s*['\"](?:base64|zlib|marshal|subprocess|socket|urllib|requests|codecs)['\"]")
PTH_WRITE_RE = re.compile(r"\bshutil\.(?:copy\w*|move|rmtree)\b|\bos\.(?:replace|rename|remove|unlink)\b|\bcopy2\b|open\s*\([^)]{0,80}['\"][wa]b?['\"]")
PTH_MOD_RE = re.compile(r"(?:^import[ \t]+|;\s*import[ \t]+|__import__\s*\(\s*['\"])([A-Za-z_][\w]*)")


def _scan_pth(text, path, findings, info, pkg=""):
    """Returns the module names the .pth imports (their top level runs at every start)."""
    mods = set()
    for n, line in enumerate(text.split("\n"), 1):
        if not PTH_IMPORT_RE.match(line):
            continue
        for m in PTH_MOD_RE.finditer(line):
            if m.group(1) not in ("os", "sys", "site", "types", "importlib", "warnings"):
                mods.add(m.group(1))
        info.append(_item("INFO", "pth_exec", ".pth Startup Code",
                          "An `import` line in a .pth file runs on every Python start", path, n, line[:120], line))
        d = PTH_DANGER_RE.search(line)
        if d:
            findings.append(_item("CRITICAL", "pth_payload", ".pth Startup Payload",
                                  "A .pth line decodes / execs / spawns / talks to the network on every interpreter start",
                                  path, n, d.group(0), line))
            findings[-1]["runs_at"] = CTX_STARTUP
        elif PTH_WRITE_RE.search(line):
            w = PTH_WRITE_RE.search(line)
            findings.append(_item("MEDIUM", "pth_fs_write", ".pth Startup File Write",
                                  "A .pth line copies / replaces / deletes files on every interpreter start "
                                  "(package-override shims do this; so would persistence)", path, n, w.group(0), line))
            findings[-1]["runs_at"] = CTX_STARTUP
    sub_f, sub_i = [], []
    _scan_text(text, path, sub_f, sub_i, CTX_STARTUP, pkg)
    findings.extend(f for f in sub_f if not any(g["line"] == f["line"] and g["id"] == "pth_payload" for g in findings))
    info.extend(sub_i)
    return mods


# ---------------------------------------------------------------------------
# Distribution model: which files run when
# ---------------------------------------------------------------------------
def _toml_value(text, section, key):
    """Tiny TOML subset (py3.9 has no tomllib): string or list-of-strings value of key in [section]."""
    sec = None
    for raw in text.split("\n"):
        ln = raw.strip()
        if ln.startswith("["):
            sec = ln.strip("[] \t")
            continue
        if sec == section:
            m = re.match(r"([\w.\-\"']+)\s*=\s*(.+)$", ln)
            if m and m.group(1).strip("\"'") == key:
                v = m.group(2).strip()
                if v.startswith("["):
                    return re.findall(r"['\"]([^'\"]+)['\"]", v)
                mm = re.match(r"['\"]([^'\"]*)['\"]", v)
                return mm.group(1) if mm else v
    return None


SETUP_IMPORT_RE = re.compile(r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))", re.M)
SETUP_EXECFILE_RE = re.compile(r"(?:exec\s*\(\s*open\s*\(|run_path\s*\(|execfile\s*\()\s*(?:os\.path\.join\s*\()?\s*['\"]([^'\"]+\.py)['\"]")


def build_time_files(files):
    """{path: ctx} for files in a source tree that run during `pip install` / `pip wheel`."""
    out = {}

    def mod_file(dotted, base=""):
        p = posixpath.join(base, *dotted.split("."))
        for cand in (p + ".py", posixpath.join(p, "__init__.py")):
            if cand in files:
                return cand
        return None

    for setup in [p for p in files if posixpath.basename(p) == "setup.py" and p.count("/") == 0]:
        out[setup] = CTX_INSTALL
        txt = files[setup]
        for m in SETUP_IMPORT_RE.finditer(txt):
            mod = (m.group(1) or m.group(2)).split(".")[0]
            f = mod_file(mod) or mod_file(mod, "src")
            if f and f not in out:
                out[f] = "install-module"  # imported by setup.py: its top level runs at build time
        for m in SETUP_EXECFILE_RE.finditer(txt):
            p = posixpath.normpath(m.group(1))
            if p in files:
                out[p] = CTX_INSTALL
    pp = files.get("pyproject.toml") or ""
    if pp:
        backend = _toml_value(pp, "build-system", "build-backend") or ""
        bpath = _toml_value(pp, "build-system", "backend-path") or []
        if isinstance(bpath, str):
            bpath = [bpath]
        for d in bpath:
            d = posixpath.normpath(d).lstrip("./") if d not in (".", "./") else ""
            if backend:
                f = mod_file(backend.split(":")[0], d)
                if f:
                    out[f] = CTX_INSTALL
            if d:
                for p in files:  # on sys.path during the build: their top level runs if imported
                    if p.startswith(d + "/") and p.endswith(".py"):
                        out.setdefault(p, "install-module")
        for sec, key, default in (("tool.hatch.build.hooks.custom", "path", "hatch_build.py"),
                                  ("tool.hatch.build.targets.wheel.hooks.custom", "path", "hatch_build.py"),
                                  ("tool.pdm.build", "custom-hook", "pdm_build.py")):
            if ("[" + sec + "]") in pp:
                f = _toml_value(pp, sec, key) or default
                if isinstance(f, str) and f in files:
                    out[f] = CTX_INSTALL
        for key in ("script", "build"):
            f = _toml_value(pp, "tool.poetry.build", key) if key == "script" else _toml_value(pp, "tool.poetry", "build")
            if isinstance(f, str) and f in files:
                out[f] = CTX_INSTALL
    for f in ("hatch_build.py", "pdm_build.py"):
        if f in files and "build-backend" in pp and ("hatch" in pp or "pdm" in pp):
            out.setdefault(f, CTX_INSTALL)
    return out


def scan_distribution(sdist=None, wheel=None, label="", name="", build_only=False):
    """sdist / wheel: {relative_path: text} (either may be None). Returns an audit result."""
    findings, info = [], []
    total = 0
    notes = {"sdist": sdist is not None, "wheel": wheel is not None, "build_files": [], "pth_files": [],
             "entry_points": []}

    def budget(path, text):
        nonlocal total
        total += len(text)
        if total > MAX_TOTAL:
            info.append(_item("INFO", "truncated", "Scan Truncated", "Distribution exceeds %d bytes of text" % MAX_TOTAL,
                              path, 0, "", ""))
            return False
        return True

    def scan_tree(files, prefix, ctx_map, scan_runtime):
        startup_mods = set()
        for p in sorted(files):
            if p.endswith(".pth"):
                notes["pth_files"].append(prefix + p)
                startup_mods |= _scan_pth(files[p], prefix + p, findings, info, name)
        for p in sorted(files):
            text = files[p]
            if p.endswith(".pth") or not p.endswith(CODE_EXT) and "/scripts/" not in p:
                if posixpath.basename(p) == "entry_points.txt":
                    notes["entry_points"] = re.findall(r"^\s*([\w.\-]+)\s*=", text.split("[gui_scripts]")[0]
                                                       .split("[console_scripts]")[-1], re.M)[:20] if "[console_scripts]" in text else []
                continue
            ctx = ctx_map.get(p)
            top_mod = p.split("/")[0][:-3] if p.count("/") == 0 else p.split("/")[0]
            if prefix == "wheel:" and ".data/" in p.split("/")[0] + "/":
                parts = p.split("/")
                top_mod = parts[2].rsplit(".", 1)[0] if len(parts) > 2 else ""
            if ctx is None and startup_mods and top_mod in startup_mods and (
                    p.endswith("__init__.py") and p.count("/") == 1 or p.count("/") == 0):
                ctx = "startup-module"
            if ctx is None:
                if not scan_runtime:
                    continue
                if TEST_PATH_RE.search(p):
                    sub_f, sub_i = [], []
                    if not budget(p, text):
                        return
                    _scan_text(text, prefix + p, sub_f, sub_i, None, name)
                    for f in sub_f:
                        f["severity"] = "INFO"
                        f["description"] += " [test/example/docs file]"
                    info.extend(sub_f + sub_i)
                    continue
                ctx = CTX_IMPORT if p.endswith((".py", ".pyw")) else None
            if not budget(p, text):
                return
            _scan_text(text, prefix + p, findings, info, ctx, name)

    if sdist is not None:
        bt = build_time_files(sdist)
        notes["build_files"] = ["sdist:" + p for p in sorted(bt)]
        for p, c in sorted(bt.items()):
            info.append(_item("INFO", "build_hook", "Install-Time Code", "Runs while pip builds the package (%s)" % c,
                              "sdist:" + p, 0, "", ""))
        # with a wheel, only the sdist's build-time code matters (package code is scanned from the wheel)
        scan_tree(sdist, "sdist:", bt, scan_runtime=(wheel is None and not build_only))
    if wheel is not None:
        scan_tree(wheel, "wheel:", {}, scan_runtime=not build_only)
    r = _summarise(findings, info, label)
    r.update(notes)
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
    del info[400:]
    return {"target": label, "risk_score": min(score, 100), "risk_level": level,
            "summary": ", ".join(parts) or "No issues found",
            "findings": findings, "info": info, "total_findings": len(findings), "info_count": len(info)}


def scan(content, label="<text>", ctx=CTX_IMPORT):
    """Scan a bare string as Python module code (ctx='install' to treat it as setup.py)."""
    findings, info = [], []
    if label.endswith(".pth"):
        _scan_pth(content, label, findings, info)
    else:
        _scan_text(content, label, findings, info, ctx)
    return _summarise(findings, info, label)


# ---------------------------------------------------------------------------
# Naive (context-free) verdict - what a scanner without the context model would say
# ---------------------------------------------------------------------------
_NAIVE_EXTRA = [re.compile(r) for r in (
    r"\.pypirc\b|\.ssh[/\\]+id_\w+|\.aws[/\\]+credentials|\.git-credentials|(?<![\w-])\.netrc\b",
    r"\bexec\s*\(\s*(?!['\"])\w")]


def naive_verdict(sdist=None, wheel=None):
    """Flag if any scored signature matches anywhere (comments, docstrings, tests, strings),
    a credential-store path or a dynamic exec appears, setup.py/the build backend spawns a
    process or uses the network, or a .pth file has an executable line."""
    reasons = set()
    trees = []
    if sdist is not None:
        bt = build_time_files(sdist)
        trees.append((sdist, bt))
    if wheel is not None:
        trees.append((wheel, {}))
    for files, bt in trees:
        for p, text in files.items():
            if p.endswith(".pth"):
                if any(PTH_IMPORT_RE.match(ln) for ln in text.split("\n")):
                    reasons.add("pth_exec")
                continue
            if not p.endswith(CODE_EXT):
                continue
            if files is sdist and wheel is not None and p not in bt:
                continue
            t = text[:3000000]
            low = t.lower()
            gs = [g for g in _GROUPS if g[0] not in ("info", "low") and any(nd in low for nd in g[1]["needles"])]
            for sev, pg, rxs, n, line, m in _matches(t, low, _newlines(t), gs):
                reasons.add(pg["id"])
            for rx in _NAIVE_EXTRA:
                if rx.search(t):
                    reasons.add("credential_or_exec")
            if p in bt and (re.search(r"\bsubprocess\.\w+\s*\(|\bos\.system\s*\(", t) or NET_RE.search(t)):
                reasons.add("install_exec_or_network")
    return sorted(reasons)


# ---------------------------------------------------------------------------
# Loading targets (never installs or executes package code)
# ---------------------------------------------------------------------------
UA = {"User-Agent": "pypi-audit/%s (+https://github.com/eltociear/pypi-audit)" % __version__}


def _get(url, timeout=60, tries=4, headers=None):
    h = dict(UA)
    h.update(headers or {})
    for i in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=timeout) as r:
                data = r.read()
                if r.headers.get("Content-Encoding") == "gzip":
                    data = gzip.decompress(data)
                return data
        except urllib.error.HTTPError as e:
            if e.code < 500 or i == tries - 1:
                raise
        except Exception:
            if i == tries - 1:
                raise
        time.sleep(2 * (i + 1))


class RangeFile(io.RawIOBase):
    """Seekable read-only view of a remote file over HTTP Range requests (block-cached), so a
    500 MB wheel can be listed and its .py/.pth members read without downloading the binaries."""
    BLOCK = 1 << 18

    def __init__(self, url, size):
        self.url, self.size, self.pos, self.cache, self.fetched = url, size, 0, {}, 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.pos

    def seek(self, off, whence=0):
        self.pos = off if whence == 0 else (self.pos + off if whence == 1 else self.size + off)
        return self.pos

    def _block(self, i):
        if i not in self.cache:
            a = i * self.BLOCK
            b = min(self.size, a + self.BLOCK) - 1
            data = _get(self.url, timeout=90, headers={"Range": "bytes=%d-%d" % (a, b)})
            if len(data) != b - a + 1:
                raise IOError("server ignored Range request")
            self.fetched += len(data)
            self.cache[i] = data
        return self.cache[i]

    def prefetch(self, spans, workers=PARALLEL):
        """Fetch the blocks covering [(start, end), ...] concurrently (per-connection throughput
        is the bottleneck on lossy links, so a few parallel ranges are much faster)."""
        need = sorted({i for a, b in spans for i in range(a // self.BLOCK, min(b, self.size - 1) // self.BLOCK + 1)}
                      - set(self.cache))
        if need:
            with ThreadPoolExecutor(workers) as ex:
                list(ex.map(self._block, need))

    def read(self, n=-1):
        if n is None or n < 0:
            n = self.size - self.pos
        n = max(0, min(n, self.size - self.pos))
        out = []
        while n > 0:
            i, off = divmod(self.pos, self.BLOCK)
            chunk = self._block(i)[off:off + n]
            out.append(chunk)
            self.pos += len(chunk)
            n -= len(chunk)
        return b"".join(out)

    def readinto(self, b):
        d = self.read(len(b))
        b[:len(d)] = d
        return len(d)


def _want(name):
    low = name.lower()
    base = posixpath.basename(low)
    return (low.endswith(CODE_EXT) or low.endswith(".pth") or base in ("entry_points.txt", "pyproject.toml", "setup.cfg")
            or "/scripts/" in low and "." not in base)


def files_from_zip(fileobj, strip_top=False):
    out = {}
    with zipfile.ZipFile(fileobj) as zf:
        if isinstance(fileobj, RangeFile):
            fileobj.prefetch([(zi.header_offset, zi.header_offset + 30 + len(zi.filename) + 2048 + zi.compress_size)
                              for zi in zf.infolist() if not zi.is_dir() and zi.file_size <= MAX_FILE and _want(zi.filename)])
        for zi in zf.infolist():
            if zi.is_dir() or zi.file_size > MAX_FILE:
                continue
            name = zi.filename
            if strip_top and "/" in name:
                name = name.split("/", 1)[1]
            if not name or not _want(name) or name.lower().endswith(".pyi"):
                continue
            try:
                out[name] = zf.read(zi).decode("utf-8", "replace")
            except Exception:
                continue
    return out


def files_from_tar(data):
    out = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        for m in tf:
            if not m.isfile() or m.size > MAX_FILE:
                continue
            name = m.name.split("/", 1)[1] if "/" in m.name else m.name
            if not name or not _want(name) or name.lower().endswith(".pyi"):
                continue
            f = tf.extractfile(m)
            if f:
                out[name] = f.read().decode("utf-8", "replace")
    return out


def files_from_archive(data, filename):
    low = filename.lower()
    if low.endswith(".whl"):
        return files_from_zip(io.BytesIO(data))
    if low.endswith(".zip"):
        return files_from_zip(io.BytesIO(data), strip_top=True)
    return files_from_tar(data)


SKIP_DIRS = {".git", "node_modules", "__pycache__", ".tox", ".nox", ".venv", "venv", ".mypy_cache", ".eggs"}


def files_from_dir(root):
    out = {}
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        for fn in fns:
            p = os.path.join(dp, fn)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            if not _want(rel) or rel.endswith(".pyi"):
                continue
            try:
                if os.path.getsize(p) > MAX_FILE:
                    continue
                with open(p, encoding="utf-8", errors="replace") as fh:
                    out[rel] = fh.read()
            except OSError:
                pass
    return out


def split_spec(spec):
    m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(?:(?:==|@)\s*([\w.!+-]+))?", spec)
    if not m:
        raise ValueError("bad package spec: %r" % spec)
    return m.group(1), m.group(2)


def pypi_meta(name, version=None):
    url = "%s/%s/json" % (INDEX, urllib.parse.quote(name)) if not version else \
        "%s/%s/%s/json" % (INDEX, urllib.parse.quote(name), urllib.parse.quote(version))
    return json.loads(_get(url, headers={"Accept-Encoding": "gzip"}))


def _wheel_rank(fn):
    f = fn.lower()
    if "-none-any.whl" in f:
        return 0
    if "manylinux" in f and "x86_64" in f:
        return 1 if "cp312" in f or "abi3" in f else 2
    if "linux" in f:
        return 3
    return 4


def pick_files(meta):
    urls = [u for u in meta.get("urls") or [] if not u.get("yanked")]
    sd = [u for u in urls if u.get("packagetype") == "sdist"]
    wh = sorted([u for u in urls if u.get("packagetype") == "bdist_wheel"], key=lambda u: (_wheel_rank(u["filename"]), u["size"]))
    return (sd[0] if sd else None), (wh[0] if wh else None)


def load_remote(u):
    """Download one distribution file into memory (range-read big wheels). Returns {path: text}."""
    fn, size = u["filename"], int(u.get("size") or 0)
    if fn.lower().endswith(".whl") and size > FULL_WHEEL:
        return files_from_zip(RangeFile(u["url"], size))
    if size > MAX_SDIST:
        raise IOError("%s is %d MB (> %d MB cap)" % (fn, size >> 20, MAX_SDIST >> 20))
    return files_from_archive(_get_parallel(u["url"], size), fn)


def _get_parallel(url, size):
    """Whole-file download; files over 1 MB are fetched as PARALLEL concurrent ranges."""
    if size <= (1 << 20):
        return _get(url, timeout=180)
    rf = RangeFile(url, size)
    rf.BLOCK = -(-size // PARALLEL)
    rf.prefetch([(0, size - 1)])
    return b"".join(rf.cache[i] for i in range(len(rf.cache)))


def fetch_pypi(spec):
    """-> (name, version, sdist_files|None, wheel_files|None, {"sdist","wheel"} filenames, errors).
    PYPI_AUDIT_CACHE=<dir> keeps the extracted text (gzip JSON) so a corpus can be re-scanned offline."""
    name, ver = split_spec(spec)
    cache = os.environ.get("PYPI_AUDIT_CACHE")
    cpath = os.path.join(cache, "%s%s.json.gz" % (name.lower(), "==" + ver if ver else "")) if cache else None
    if cpath and os.path.exists(cpath):
        with gzip.open(cpath, "rt", encoding="utf-8") as fh:
            c = json.load(fh)
        return c["name"], c["version"], c["sdist"], c["wheel"], c["files"], c["errors"]
    meta = pypi_meta(name, ver)
    version = meta["info"]["version"]
    sd, wh = pick_files(meta)
    sdist = wheel = None
    errs = []
    if sd and wh and int(sd.get("size") or 0) > SDIST_WITH_WHEEL:
        errs.append("sdist: skipped, %d MB and a wheel exists (pip installs the wheel)" % (int(sd["size"]) >> 20))
    elif sd:
        try:
            sdist = load_remote(sd)
        except Exception as e:
            errs.append("sdist: %s" % str(e)[:160])
    if wh:
        try:
            wheel = load_remote(wh)
        except Exception as e:
            errs.append("wheel: %s" % str(e)[:160])
    if sdist is None and wheel is None:
        raise IOError("; ".join(errs) or "no files on PyPI for %s %s" % (name, version))
    files = {"sdist": sd and sd["filename"], "wheel": wh and wh["filename"]}
    if cpath and not any("timed out" in e or "Connection" in e for e in errs):
        os.makedirs(cache, exist_ok=True)
        with gzip.open(cpath + ".tmp", "wt", encoding="utf-8") as fh:
            json.dump({"name": meta["info"]["name"], "version": version, "sdist": sdist, "wheel": wheel,
                       "files": files, "errors": errs}, fh)
        os.replace(cpath + ".tmp", cpath)
    return meta["info"]["name"], version, sdist, wheel, files, errs


def audit_pypi(spec, build_only=False, naive=False):
    name, version, sdist, wheel, files, errs = fetch_pypi(spec)
    r = scan_distribution(sdist, wheel, "%s==%s" % (name, version), name, build_only)
    r["files"] = files
    if errs:
        r["fetch_errors"] = errs
    if naive:
        r["naive"] = naive_verdict(sdist, wheel)
    return r


def audit_local(path, build_only=False, naive=False):
    low = path.lower()
    name = re.split(r"[-_.](?=\d)", posixpath.basename(path.rstrip("/")))[0]
    sdist = wheel = None
    if os.path.isdir(path):
        sdist = files_from_dir(path)
        if not any(posixpath.basename(p) in ("setup.py", "pyproject.toml") for p in sdist):
            wheel, sdist = sdist, None  # an installed tree / plain directory: no build step
    elif low.endswith(".whl"):
        wheel = files_from_zip(path)
    elif low.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".zip", ".tar")):
        with open(path, "rb") as fh:
            sdist = files_from_archive(fh.read(), path)
    else:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        base = os.path.basename(path)
        if base == "setup.py":
            sdist = {"setup.py": text}
        elif base.endswith(".pth"):
            wheel = {base: text}
        else:
            r = scan(text, path)
            r["naive"] = naive_verdict(wheel={base: text}) if naive else None
            return r
    r = scan_distribution(sdist, wheel, path, name, build_only)
    if naive:
        r["naive"] = naive_verdict(sdist, wheel)
    return r


def requirements_specs(path, seen=None):
    seen = seen or set()
    specs = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = fh.read().split("\n")
    for raw in lines:
        ln = raw.split("#", 1)[0].strip()
        if not ln:
            continue
        m = re.match(r"^-r\s+(\S+)|^--requirement[ =](\S+)", ln)
        if m:
            sub = os.path.join(os.path.dirname(path), m.group(1) or m.group(2))
            if sub not in seen:
                seen.add(sub)
                specs += requirements_specs(sub, seen)
            continue
        if ln.startswith("-") or "://" in ln or ln.startswith((".", "/")):
            continue
        ln = ln.split(";", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(?:===?\s*([\w.!+-]+))?", ln)
        if m:
            specs.append(m.group(1) + ("==" + m.group(2) if m.group(2) else ""))
    return list(dict.fromkeys(specs))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
_ICON = {"CRITICAL": "\U0001F534", "HIGH": "\U0001F7E0", "MEDIUM": "\U0001F7E1", "LOW": "\U0001F535", "SAFE": "\U0001F7E2"}


def _print(r, verbose):
    print("%s %s  [%s]  score=%d  (%d findings, %d info)" % (
        _ICON.get(r["risk_level"], "?"), r["target"], r["risk_level"], r["risk_score"], r["total_findings"], r["info_count"]))
    for k in ("build_files", "pth_files"):
        if r.get(k):
            print("    %-9s %s" % ("build" if k == "build_files" else ".pth", ", ".join(r[k][:6])))
    for f in r["findings"]:
        print("    %-8s %s  %s:%s%s" % (f["severity"], f["name"], f["file"], f["line"],
                                       "  (runs at %s)" % f["runs_at"] if f.get("runs_at") else ""))
        if f["context"]:
            print("             %s" % f["context"][:160])
    if r.get("naive") is not None and r.get("naive"):
        print("    naive    would flag: %s" % ", ".join(r["naive"]))
    if verbose:
        for f in r["info"]:
            print("    info     %s  %s:%s  %s" % (f["name"], f["file"], f["line"], f["matched"][:60]))


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if args[0] == "--version":
        print(__version__)
        return 0
    flags = {"--json", "--verbose", "-v", "--build-only", "--naive"}
    as_json = "--json" in args
    verbose = "--verbose" in args or "-v" in args
    build_only = "--build-only" in args
    naive = "--naive" in args
    args = [a for a in args if a not in flags]
    targets = []
    if args and args[0] == "--text":
        txt = " ".join(args[1:])
        targets.append(("<text>", lambda: scan(txt)))
    elif args and args[0] in ("--requirements", "-r"):
        for spec in requirements_specs(args[1]):
            targets.append((spec, (lambda s=spec: audit_pypi(s, build_only, naive))))
    else:
        for a in args:
            if os.path.exists(a):
                targets.append((a, (lambda p=a: audit_local(p, build_only, naive))))
            else:
                targets.append((a, (lambda s=a: audit_pypi(s, build_only, naive))))
    results, worst = [], "SAFE"
    for label, thunk in targets:
        try:
            r = thunk()
        except Exception as e:  # network errors, 404s, corrupt archives
            r = {"target": label, "risk_level": "SAFE", "risk_score": 0, "error": "%s: %s" % (type(e).__name__, str(e)[:200]),
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
