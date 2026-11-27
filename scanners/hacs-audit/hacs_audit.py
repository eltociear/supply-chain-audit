#!/usr/bin/env python3
"""hacs-audit - scan Home Assistant custom integrations and HACS frontend cards for MALICIOUS code.

A custom integration is arbitrary Python that Home Assistant imports into its own process: it runs
with the same privileges as Home Assistant itself, next to `secrets.yaml`, the `.storage/` files
that hold every other integration's credentials and every user's refresh tokens, and with network
access to your whole home. Its `manifest.json` `requirements` are pip-installed for it. A HACS
frontend plugin (a Lovelace card) is JavaScript that runs inside every logged-in user's browser
session, where `hass.auth` holds a live access token for the whole instance.

This is a deterministic (no LLM) static scan for the shapes that turn that into theft or a
backdoor: reading Home Assistant's secret / auth / config-entry storage and sending it to a
collector, minting long-lived tokens and reporting them, front-end code exfiltrating `hass.auth`
tokens, download-and-execute, exec of fetched or decoded code, reverse shells, persistence
(cron, systemd, authorized_keys), writes to /etc, global TLS-verification kill switches,
cryptominers, shadow wheels / typosquats / custom indexes in `requirements`, and HTTP views that
hand request data to a shell - weighted by WHEN the code runs (module import and
`async_setup*` run as soon as Home Assistant loads the integration).

Precision-tuned to near-zero false positives: what integrations do every day (talking to the
device's own cloud or LAN API, running ffmpeg / ping, reading their own config entry, using the
`hass.auth` token to call Home Assistant's own API from a card, CDN-hosted front-end libraries)
is reported as informational context and never inflates the risk score. Risk comes from specific
COMBINATIONS and sinks. No code from the integration or card is ever imported or executed.

Usage:
  python hacs_audit.py <repo_or_component_dir> [...]     # scan a checkout / custom_components/<domain>
  python hacs_audit.py --ha-config <config_dir>           # scan every custom_components/* and www/community/*
  python hacs_audit.py --github owner/repo[@ref]          # fetch the repo tarball and scan
  python hacs_audit.py --hacs-default [integration|plugin] [--limit N]   # bulk-scan HACS' default lists
  python hacs_audit.py --text "some code"                 # scan a string (as import-time Python)
  add --json for machine-readable output, --verbose to print INFO context

Exit code 2 if any target is HIGH or CRITICAL (CI-friendly).
No dependencies beyond the standard library. MIT licensed.
"""
import bisect
import io
import json
import os
import re
import sys
import tarfile
import time
import urllib.error
import urllib.request
import zipfile

__version__ = "0.1.0"

PY_EXT = (".py",)
JS_EXT = (".js", ".mjs", ".cjs")
SH_EXT = (".sh", ".bat", ".cmd", ".ps1")
MAX_FILE = 8000000       # bytes; HACS cards ship as one bundled file, so allow big bundles
MAX_TOTAL = 40000000     # bytes of text scanned per target
SEG = 8192               # regex window for very long (minified) lines
SEG_OVERLAP = 1024
LONG_LINE = 20000
MAX_HITS = 25          # findings kept per signature per file
BUNDLE_BYTES = 200000    # a front-end file this big is a bundle (app code + vendored libraries)
HACS_DEFAULT = "https://raw.githubusercontent.com/hacs/default/master/%s"

# Hard-coded collectors: stealers ship these; legitimate integrations take webhook URLs from the user.
STRONG_EXFIL = (
    r"(?:discord(?:app)?\.com/api/webhooks/\d{17,20}/[\w-]{20,}|api\.telegram\.org/bot\d{6,}:[\w-]{30,}|"
    r"hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/\w{10,}|"
    r"\bwebhook\.site/[0-9a-f-]{8,}|\.m\.pipedream\.net|requestbin\.(?:com|net|io)|\brequestb\.in\b|"
    r"requestcatcher\.com|beeceptor\.com|oastify\.com|\boast\.(?:fun|me|pro|live|site|online)\b|"
    r"\binteract\.sh\b|interactsh|burpcollaborator\.net|canarytokens\.com|dnslog\.cn|\bceye\.io\b|requestrepo\.com)"
)
# Tunnels / paste hosts: legitimate for remote-access helpers and docs; only meaningful in combinations.
SOFT_HOST = (r"(?:ngrok(?:-free)?\.(?:io|app|dev)|\.trycloudflare\.com|serveo\.net|localtunnel\.me|loca\.lt\b|"
             r"pastebin\.com/raw|paste\.ee/r|hastebin\.com/raw|\btransfer\.sh\b|\bfile\.io/|"
             r"raw\.githubusercontent\.com/[\w.-]+/[\w.-]+/(?:main|master)/[\w./-]+\.(?:py|txt|sh|ps1))")
RAW_IP_URL = (r"https?://(?!(?:127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|"
              r"2(?:2[4-9]|[3-5]\d)\.))\d{1,3}(?:\.\d{1,3}){3}")
NET_SEND = (r"(?:\brequests\.(?:get|post|put|request|Session)\b|\burllib\.request\.(?:urlopen|Request|urlretrieve)\b|"
            r"\burlopen\s*\(|\burlretrieve\s*\(|\bhttpx\.(?:get|post|Client|AsyncClient|request)\b|"
            r"\baiohttp\.ClientSession\b|async_get_clientsession\s*\(|async_create_clientsession\s*\(|"
            r"\bhttp\.client\.HTTPS?Connection\b|\bsocket\.(?:socket|create_connection)\b|"
            r"\bsmtplib\.SMTP|\bftplib\.FTP|\bpycurl\b|\bsession\.(?:get|post|put|request)\s*\(|"
            r"\bfetch\s*\(|XMLHttpRequest|navigator\.sendBeacon|new\s+WebSocket\s*\(|"
            r"\bcurl\s+(?:-[a-zA-Z]+\s+)*https?://|\bwget\s+(?:-[a-zA-Z-]+\s+)*https?://|Invoke-WebRequest|\biwr\b|DownloadFile\s*\()")
CRED_PATHS = (
    r"(?:(?-i:(?:[/\\\\]|['\"],\s{0,4}['\"])(?:Login Data|Local State|Cookies|Web Data)\b)|Local Extension Settings|"
    r"nkbihfbeogaeaoehlefnkodbefgpgknn|\bExodus[/\\\\]|exodus\.wallet|Electrum[/\\\\]wallets|atomic[/\\\\]Local Storage|"
    r"wallet\.dat\b|\.ssh[/\\\\]id_(?:rsa|ed25519|ecdsa)|\.aws[/\\\\]credentials|\.git-credentials|"
    r"\.docker[/\\\\]config\.json|discord[/\\\\]Local Storage[/\\\\]leveldb|Telegram Desktop[/\\\\]tdata|"
    r"CryptUnprotectData|\bwin32crypt\b|browser_cookie3|\bfind-generic-password\b|logins\.json['\"]|key4\.db)"
)
# Home Assistant's own secret stores: secrets.yaml, and the .storage files holding users,
# refresh tokens, and every integration's config-entry credentials.
HA_SECRET = (
    r"(?:open|\.path|join|Path|load_yaml(?:_dict)?|read_text|read_bytes|aiofiles\.open|async_load_yaml)\s{0,4}\("
    r"[^\n]{0,160}?(?:['\"/\\\\]secrets\.yaml['\"]|"
    r"\.storage['\"]?\s{0,4}(?:,|/|\\\\|\+)\s{0,4}['\"]?/?(?:auth(?:_provider\.homeassistant)?|core\.config_entries|"
    r"http\.auth|onboarding)\b)"
)
# Pure-Python packages: nobody needs a custom-built wheel of these. A direct URL to one off
# PyPI is the "shadow wheel" shape: a trojaned copy of a well-known library.
PURE_PY = {
    "requests", "httpx", "paho-mqtt", "voluptuous", "xmltodict", "beautifulsoup4", "python-dateutil", "pytz",
    "aiofiles", "async-timeout", "websocket-client", "openai", "anthropic", "google-generativeai",
    "google-genai", "boto3", "tenacity", "backoff", "attrs", "click", "jinja2", "requests-oauthlib",
    "oauthlib", "pyjwt", "certifi", "idna", "urllib3", "six", "packaging", "setuptools", "pip", "icalendar",
    "geopy", "tzlocal", "colorama", "tqdm", "pydantic", "ollama", "gitpython", "slugify", "python-slugify",
    "awesomeversion", "dacite", "mashumaro", "aiohttp-retry", "pysnmp", "pymodbus", "pyserial",
}
POPULAR = PURE_PY | {
    "aiohttp", "numpy", "pillow", "pyyaml", "cryptography", "pycryptodome", "pycryptodomex", "websockets",
    "bleak", "bleak-retry-connector", "bluetooth-data-tools", "zeroconf", "homeassistant", "orjson",
    "lxml", "protobuf", "grpcio", "pandas", "scipy", "matplotlib", "opencv-python", "pyatv", "pychromecast",
    "netifaces", "psutil", "pyopenssl", "ujson", "msgpack", "aiodns", "dnspython", "paramiko", "asyncssh",
    "pysnmplib", "aiomqtt", "asyncio-mqtt", "pyusb", "pyudev", "smbus2", "rpi-gpio", "gpiozero",
    "bellows", "zigpy", "zha-quirks", "pyatmo", "pytuya", "tinytuya", "miio", "python-miio", "pyhomematic",
    "aioesphomeapi", "pymetno", "astral", "hass-nabucasa", "selenium", "playwright", "yt-dlp", "ffmpeg-python",
    "simplejson", "regex", "chardet", "charset-normalizer", "multidict", "yarl", "frozenlist", "pyotp",
    "qrcode", "pyqrcode", "segno", "authlib", "pyjwt", "scapy", "pynacl", "ecdsa", "rsa", "pyasn1", "aiozoneinfo", "unidecode", "toml",
}
# Releases publicly known to be malicious.
KNOWN_BAD = {"ultralytics": {"8.3.41", "8.3.42", "8.3.45", "8.3.46"}}
# Index / wheel hosts that are normal.
OK_HOSTS = (r"(?:files\.pythonhosted\.org|pypi\.org|pypi\.python\.org|wheels\.home-assistant\.io|"
            r"piwheels\.org|www\.piwheels\.org|download\.pytorch\.org|mirrors\.aliyun\.com|"
            r"pypi\.tuna\.tsinghua\.edu\.cn|mirrors\.cloud\.tencent\.com)")
CDN_HOSTS = (r"(?:cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|esm\.sh|cdn\.skypack\.dev|"
             r"fonts\.googleapis\.com|ajax\.googleapis\.com|code\.jquery\.com|cdn\.tailwindcss\.com|"
             r"fonts\.gstatic\.com|esm\.run|ga\.jspm\.io|cdn\.plot\.ly|stackpath\.bootstrapcdn\.com|"
             r"cdnjs\.buymeacoffee\.com|www\.gstatic\.com|maps\.googleapis\.com|api\.mapbox\.com|"
             r"cdn\.amcharts\.com|cdn\.materialdesignicons\.com)")

PATTERNS = {
    "critical": [
        {"id": "download_execute", "name": "Download & Execute",
         "desc": "Pipes a downloaded script straight into a shell / interpreter",
         "regexes": [
             r"\b(?:curl|wget)\s[^\n|;]{0,200}?https?://[^\n|;]{1,200}?\|\s{0,4}(?:sudo\s+)?(?:ba|z|da)?sh\b",
             r"\b(?:curl|wget)\s[^\n|;]{0,200}?https?://[^\n|;]{1,200}?\|\s{0,4}(?:python3?|perl|node)\b",
             r"\b(?:iex|Invoke-Expression)\s{0,4}\(?\s{0,4}(?:\(\s{0,4})?(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|"
             r"\(?New-Object\s+(?:System\.)?Net\.WebClient\)?\.DownloadString)",
             r"(?<![.\w])exec\s{0,4}\(\s{0,4}(?:requests\.get|urllib\.request\.urlopen|urlopen|httpx\.get)\s{0,4}\(",
             r"(?<![.\w])eval\s{0,4}\(\s{0,4}(?:requests\.get|urllib\.request\.urlopen|urlopen|httpx\.get)\s{0,4}\(",
             r"(?:(?<![.\w])eval|new\s+Function)\s{0,4}\(\s{0,4}await\s+(?:\(\s{0,4}await\s+)?fetch\s{0,4}\(",
         ]},
        {"id": "obfuscated_exec", "name": "Obfuscated Code Execution",
         "desc": "exec/eval of base64 / zlib / marshal / hex-decoded content",
         "regexes": [
             r"(?<![.\w])(?:exec|eval)\s{0,4}\(\s{0,4}(?:compile\s{0,4}\(\s{0,4})?(?:base64\.b(?:64|32|85)decode|zlib\.decompress|"
             r"lzma\.decompress|bz2\.decompress|gzip\.decompress|marshal\.loads|codecs\.decode|bytes\.fromhex|"
             r"binascii\.(?:a2b_base64|unhexlify)|__import__\s{0,4}\(\s{0,4}['\"](?:base64|zlib|marshal|codecs)['\"])",
             r"(?<![.\w])(?:exec|eval)\s{0,4}\(\s{0,4}['\"]{0,3}\s{0,4}\)?\s{0,4}\.join\s{0,4}\(\s{0,4}(?:chr|map\s{0,4}\(\s{0,4}chr)",
             r"(?<![.\w])(?:exec|eval)\s{0,4}\(\s{0,4}(?:b['\"])?(?:\\x[0-9a-fA-F]{2}){16,}",
             r"(?<![.\w])eval\s{0,4}\(\s{0,4}atob\s{0,4}\(|new\s+Function\s{0,4}\(\s{0,4}atob\s{0,4}\(",
             r"(?<![.\w])exec\s{0,4}\(\s{0,4}\w{1,40}\s{0,4}\(\s{0,4}['\"][A-Za-z0-9+/=]{200,}",
         ]},
        {"id": "reverse_shell", "name": "Reverse Shell",
         "desc": "Wires a network socket into an interactive shell",
         "regexes": [
             r"os\.dup2\s{0,4}\(\s{0,4}\w{1,30}\.fileno\s{0,4}\(\s{0,4}\)\s{0,4},\s{0,4}[012]\s{0,4}\)",
             r"pty\.spawn\s{0,4}\(\s{0,4}['\"](?:/bin/)?(?:ba|z)?sh['\"]",
             r"\bbash\s+-i\s+>&\s{0,4}/dev/tcp/",
             r"\bnc(?:at)?\s+(?:-\w+\s+){0,4}-e\s+/bin/(?:ba)?sh",
             r"stdin\s{0,4}=\s{0,4}\w{1,30}\.fileno\s{0,4}\(\s{0,4}\)\s{0,4},\s{0,4}stdout\s{0,4}=\s{0,4}\w{1,30}\.fileno",
         ]},
        {"id": "destructive", "name": "Destructive Operation",
         "desc": "Deletes the home directory, the config directory or the filesystem root",
         "regexes": [
             r"shutil\.rmtree\s{0,4}\(\s{0,4}(?:os\.path\.expanduser\s{0,4}\(\s{0,4}['\"]~['\"]\s{0,4}\)|['\"](?:/|~|/config/?)['\"]|"
             r"Path\.home\s{0,4}\(\s{0,4}\)\s{0,4}\)|hass\.config\.config_dir\s{0,4}\))",
             r"\brm\s+-[a-zA-Z]{0,4}r[a-zA-Z]{0,4}\s+(?:--no-preserve-root\s+)?(?:~|\$HOME|/|/config/?)(?:\s|['\"`;]|$)",
         ]},
    ],
    "high": [
        {"id": "exfil_host", "name": "Hard-coded Collector Endpoint",
         "desc": "A hard-coded webhook / request-catcher / OAST endpoint (stealers report here)",
         "regexes": [STRONG_EXFIL]},
        {"id": "credential_read", "name": "Credential Store Access",
         "desc": "Reads browser passwords/cookies, wallets, SSH/AWS/git/docker credentials or OS secret stores",
         "regexes": [CRED_PATHS]},
        {"id": "ha_secret_read", "name": "Home Assistant Secret Store Access",
         "desc": "Reads secrets.yaml or Home Assistant's auth / config-entry storage (other integrations' "
                 "credentials, users' refresh tokens)",
         "regexes": [HA_SECRET]},
        {"id": "env_dump", "name": "Environment Dump",
         "desc": "Serialises the whole environment",
         "regexes": [
             r"(?:json\.dumps|str|repr|pickle\.dumps|yaml\.(?:safe_)?dump)\s{0,4}\(\s{0,4}(?:dict\s{0,4}\(\s{0,4})?"
             r"os\.environ(?:\.copy\s{0,4}\(\s{0,4}\))?\s{0,4}\)?\s{0,4}[,)]",
             r"JSON\.stringify\s{0,4}\(\s{0,4}process\.env\b",
         ]},
        {"id": "persistence", "name": "Persistence",
         "desc": "Installs itself to run at boot / login / on a schedule, or adds an SSH key",
         "regexes": [
             r"\bcrontab\s+-[l]?\s{0,4}[|;]|\(crontab -l|['\"]/etc/cron\.(?:d|hourly|daily)/",
             r"['\"]/etc/systemd/system/[^'\"]{1,80}\.service['\"]",
             # only a LOCAL shell sink: integrations that manage a remote box over SSH run systemctl there
             r"(?:subprocess\.\w{1,16}|os\.system|os\.popen|create_subprocess_\w{1,8})\s{0,4}\([^\n]{0,80}systemctl['\"]?\s{0,4},?\s{0,4}['\"]?enable\b",
             r"authorized_keys['\"][^\n]{0,60}['\"]a",
             r"(?:open|write_text|append)\s{0,4}\([^\n]{0,80}(?:\.bashrc|\.zshrc|\.bash_profile|\.profile)['\"][^\n]{0,40}['\"]a",
             r"Library/LaunchAgents|/Library/LaunchDaemons|CurrentVersion\\\\{1,2}Run\b",
         ]},
        {"id": "etc_write", "name": "System File Write",
         "desc": "Writes under /etc (hosts, sudoers, resolv.conf, ld.so.preload, ...)",
         "regexes": [
             r"open\s{0,4}\(\s{0,4}['\"]/etc/[^'\"]{1,80}['\"]\s{0,4},\s{0,4}['\"](?:w|a|r\+)",
             r"['\"]/etc/(?:sudoers|ld\.so\.preload|hosts|resolv\.conf|passwd|shadow)['\"][^\n]{0,40}\.write",
         ]},
        {"id": "cryptominer", "name": "Cryptominer",
         "desc": "Mining pool / miner binary reference",
         "regexes": [r"stratum\+(?:tcp|ssl|tls)://", r"\b(?:xmrig|minexmr|nanopool\.org|supportxmr|nicehash\.com/miner|"
                     r"cryptonight|moneroocean)\b"]},
        {"id": "exec_route", "name": "HTTP View Executes Request Data",
         "desc": "An HTTP view / route passes request data into a shell / exec / eval (remote code execution endpoint)",
         "regexes": [
             r"(?:subprocess\.(?:run|call|Popen|check_output|check_call)|os\.system|os\.popen|\bexec|\beval)\s{0,4}\("
             r"[^\n]{0,120}\b(?:request\.(?:query|match_info|rel_url|args|form)|await\s+request\.(?:json|post|text)\s{0,4}\(|"
             r"json_data\[|post\[|body\[)",
         ]},
        {"id": "ha_token_send", "name": "Home Assistant Token Sent Off-instance",
         "desc": "Front-end code sends the hass.auth access token / stored hassTokens to an absolute external URL",
         "regexes": [
             r"(?:fetch|sendBeacon|\.open|axios\.(?:get|post))\s{0,4}\(\s{0,4}[`'\"]https?://(?!localhost|127\.|homeassistant\.local)"
             r"[^\n]{0,240}(?:hassTokens|auth\.data\.access_token|accessToken\s{0,4}\})",
         ]},
    ],
    "medium": [
        {"id": "raw_ip_url", "name": "Raw-IP URL",
         "desc": "Talks to a hard-coded public IP address instead of a domain",
         "regexes": [RAW_IP_URL + r"[:/][^\s'\"]{0,40}"]},
        {"id": "remote_script_js", "name": "Remote Script in Front-end",
         "desc": "Front-end code loads executable script from a non-CDN remote origin",
         "regexes": [
             r"\.src\s{0,4}=\s{0,4}['\"`]https?://(?!" + CDN_HOSTS + r")[^'\"`\s]{4,200}\.m?js\b",
             r"\bimport\s{0,4}\(\s{0,4}['\"`]https?://(?!" + CDN_HOSTS + r")[^'\"`\s]{4,200}",
         ]},
        {"id": "tls_global_off", "name": "Global TLS Verification Kill-switch",
         "desc": "Disables certificate verification for the WHOLE Home Assistant process, not just this integration",
         "regexes": [
             r"ssl\._create_default_https_context\s{0,4}=\s{0,4}ssl\._create_unverified_context",
             r"os\.environ\s{0,4}\[\s{0,4}['\"](?:PYTHONHTTPSVERIFY|CURL_CA_BUNDLE|REQUESTS_CA_BUNDLE)['\"]\s{0,4}\]\s{0,4}=\s{0,4}['\"]0?['\"]",
         ]},
        {"id": "config_write", "name": "configuration.yaml Write",
         "desc": "Writes Home Assistant's configuration.yaml (changes what the whole instance loads)",
         "regexes": [
             r"open\s{0,4}\([^\n]{0,120}configuration\.yaml['\"][^\n]{0,60}['\"](?:w|a|r\+)b?['\"]",
             r"configuration\.yaml['\"][^\n]{0,80}\.(?:write_text|write)\s{0,4}\(",
         ]},
    ],
    "info": [
        {"id": "network", "name": "Network Access", "desc": "Makes network requests", "regexes": [NET_SEND]},
        {"id": "subprocess", "name": "Process Execution", "desc": "Spawns processes",
         "regexes": [r"\bsubprocess\.(?:run|call|Popen|check_output|check_call)\b|\bos\.system\s{0,4}\(|\bos\.popen\s{0,4}\(|"
                     r"asyncio\.create_subprocess_(?:exec|shell)\b"]},
        {"id": "pip_install", "name": "Runtime pip install", "desc": "pip-installs packages from code",
         "regexes": [r"['\"]pip['\"]\s{0,4},\s{0,4}['\"]install['\"]|pip\s+install\b|pip\._internal|\bpip\.main\s{0,4}\(|"
                     r"async_process_requirements|pkg_util\.install_package"]},
        {"id": "self_update", "name": "Self-update", "desc": "Pulls new code for itself at runtime (git pull / clone)",
         "regexes": [r"['\"]git['\"]\s{0,4},\s{0,4}['\"](?:pull|clone|fetch)['\"]|git\s+(?:pull|clone)\b|\bgit\.Repo\b[^\n]{0,60}\.(?:pull|clone_from)"]},
        {"id": "dynamic_code", "name": "Dynamic Code", "desc": "exec/eval/compile with non-literal input",
         "regexes": [r"(?<![.\w])(?:exec|eval)\s{0,4}\(\s{0,4}(?!['\"])[\w.]{1,60}"]},
        {"id": "pickle_load", "name": "Unsafe Deserialisation", "desc": "pickle.load / torch.load without weights_only",
         "regexes": [r"\bpickle\.loads?\s{0,4}\(|\btorch\.load\s{0,4}\((?![^\n]{0,200}weights_only\s{0,4}=\s{0,4}True)"]},
        {"id": "tls_off", "name": "TLS Verification Disabled", "desc": "verify=False / unverified SSL context for a request",
         "regexes": [r"verify\s{0,4}=\s{0,4}False\b|verify_ssl\s{0,4}=\s{0,4}False\b|ssl\s{0,4}=\s{0,4}False\b|"
                     r"_create_unverified_context|CERT_NONE"]},
        {"id": "soft_host", "name": "Tunnel / Paste Host", "desc": "ngrok / cloudflared tunnel or paste/raw-file host",
         "regexes": [SOFT_HOST]},
        {"id": "env_read", "name": "Environment Read", "desc": "Reads environment variables",
         "regexes": [r"\bos\.environ\b|\bos\.getenv\s{0,4}\(|process\.env\b"]},
        {"id": "token_mint", "name": "Token Minting", "desc": "Creates users / refresh / access tokens on the instance",
         "regexes": [r"hass\.auth\.async_create_(?:refresh_token|access_token|system_user|user)\b|async_create_refresh_token\b"]},
        {"id": "other_entries", "name": "Other Integrations' Config Entries",
         "desc": "Enumerates every config entry on the instance (not just its own domain)",
         "regexes": [r"config_entries\.async_entries\s{0,4}\(\s{0,4}\)"]},
        {"id": "ha_token", "name": "Front-end Token Access", "desc": "Front-end code reads hass.auth tokens",
         "regexes": [r"\bhassTokens\b|auth\.data\.access_token|\bhass\.auth\.accessToken\b|\.auth\.data\.refresh_token"]},
        {"id": "browser_storage", "name": "Browser Storage", "desc": "Front-end reads localStorage / cookies",
         "regexes": [r"\blocalStorage\.getItem\b|\bdocument\.cookie\b|\bsessionStorage\.getItem\b"]},
        {"id": "embedded_blob", "name": "Embedded Blob", "desc": "Large base64/hex blob (images, fonts, wasm)",
         "regexes": [r"<blob:\d+>"]},
    ],
}
SEVERITY_SCORE = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "SAFE": 0}
_CASE_SENSITIVE = {"embedded_blob"}
_COMPILED = [(sev, pg, re.compile(rx, re.M | (0 if pg["id"] in _CASE_SENSITIVE else re.IGNORECASE)))
             for sev, groups in PATTERNS.items() for pg in groups for rx in pg["regexes"]]
# Cheap literal prefilter: a signature group only runs on a file containing one of its needles.
NEEDLES = {
    "download_execute": ("curl", "wget", "iex", "invoke-expression", "exec", "eval"),
    "obfuscated_exec": ("exec", "eval", "function"),
    "reverse_shell": ("dup2", "pty.spawn", "/dev/tcp", "nc ", "ncat", "fileno"),
    "destructive": ("rmtree", "rm -"),
    "exfil_host": ("discord", "telegram", "slack", "webhook.site", "pipedream", "requestb", "requestcatcher",
                   "beeceptor", "oast", "interact", "burpcollaborator", "canarytokens", "dnslog", "ceye", "requestrepo"),
    "credential_read": ("login data", "local state", "cookies", "web data", "extension settings", "nkbihf",
                        "exodus", "electrum", "atomic", "wallet.dat", ".ssh", ".aws", "git-credentials", ".docker",
                        "leveldb", "tdata", "cryptunprotect", "win32crypt", "browser_cookie3", "generic-password",
                        "logins.json", "key4.db"),
    "ha_secret_read": ("secrets.yaml", ".storage"),
    "env_dump": ("os.environ", "process.env"),
    "persistence": ("crontab", "/etc/cron", "systemd", "systemctl", "authorized_keys", "bashrc", "zshrc",
                    "bash_profile", ".profile", "launchagents", "launchdaemons", "currentversion"),
    "etc_write": ("/etc/",),
    "cryptominer": ("stratum", "xmrig", "minexmr", "nanopool", "supportxmr", "nicehash", "cryptonight", "moneroocean"),
    "exec_route": ("request",),
    "ha_token_send": ("hasstokens", "access_token", "accesstoken"),
    "raw_ip_url": ("http",),
    "remote_script_js": (".src", "import("),
    "tls_global_off": ("_create_default_https_context", "pythonhttpsverify", "ca_bundle"),
    "config_write": ("configuration.yaml",),
    "network": ("requests.", "urllib", "urlopen", "urlretrieve", "httpx", "aiohttp", "clientsession", "http.client",
                "socket.", "smtplib", "ftplib", "pycurl", "session.", "fetch", "xmlhttprequest", "sendbeacon",
                "websocket", "curl ", "wget ", "invoke-webrequest", "iwr", "downloadfile"),
    "subprocess": ("subprocess", "os.system", "os.popen", "create_subprocess"),
    "pip_install": ("pip", "async_process_requirements", "install_package"),
    "self_update": ("git",),
    "dynamic_code": ("exec", "eval"),
    "pickle_load": ("pickle", "torch.load"),
    "tls_off": ("verify", "ssl", "unverified", "cert_none"),
    "soft_host": ("ngrok", "trycloudflare", "serveo", "localtunnel", "loca.lt", "pastebin", "paste.ee", "hastebin",
                  "transfer.sh", "file.io", "raw.githubusercontent"),
    "env_read": ("environ", "getenv", "process.env"),
    "token_mint": ("async_create_",),
    "other_entries": ("async_entries",),
    "ha_token": ("hasstokens", "access_token", "accesstoken", "refresh_token"),
    "browser_storage": ("localstorage", "cookie", "sessionstorage"),
    "embedded_blob": ("<blob:",),
}
LINE_ONCE = {"network", "subprocess", "pip_install", "self_update", "dynamic_code", "pickle_load", "tls_off",
             "env_read", "browser_storage", "embedded_blob", "soft_host", "token_mint", "other_entries", "ha_token"}
NET_RE = re.compile(NET_SEND, re.IGNORECASE)
STRONG_RE = re.compile(STRONG_EXFIL, re.IGNORECASE)
SOFT_RE = re.compile(SOFT_HOST, re.IGNORECASE)
RAWIP_RE = re.compile(RAW_IP_URL)
BLOB_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{4096,}|(?:\\x[0-9a-fA-F]{2}){1024,}")
EXEC_VAR_RE = re.compile(r"(?<![.\w])(?:exec|eval)\s{0,4}\(\s{0,4}(?!['\"])(?:compile\s{0,4}\(\s{0,4})?[\w.\[\]'\"]{1,60}\s{0,4}[,)]")
FETCH_BODY_RE = re.compile(r"\.(?:text|content)\b|\.read\s{0,4}\(\s{0,4}\)|\.decode\s{0,4}\(")
CHMOD_RE = re.compile(r"os\.chmod\s{0,4}\([^\n]{0,80}0o7|stat\.S_IEXEC|stat\.S_IXUSR|chmod\s+\+?[0-7]*x|chmod\s+7[0-7]{2}")
BIN_DL_RE = re.compile(r"https?://[^\s'\"]{4,200}\.(?:exe|dll|scr|msi|so|dylib|bin|elf)['\"]", re.IGNORECASE)
KEY_RE = re.compile(r"\[1-9A-HJ-NP-Za-km-z\]\{(?:8[78]|4[34])\}|0x\[0-9a-fA-F\]\{64\}|\[0-9a-fA-F\]\{64\}|"
                    r"(?:sk-|sk_live_|AKIA)\[?[A-Za-z0-9]")
NEAR_OK = {"pyatmo", "pytuya", "tinytuya", "aiotuya", "pymiio"}
SHELL_SINK = re.compile(r"os\.system|os\.popen|subprocess\.(?:run|call|Popen|check_output|check_call|getoutput|getstatusoutput)\s{0,4}\(|shell\s{0,4}=\s{0,4}True|Popen|\bexec(?:Sync|File)?\s{0,4}\(|"
                        r"create_subprocess_(?:exec|shell)|child_process|\bspawn\s{0,4}\(|['\"](?:ba|z)?sh['\"]\s{0,4},\s{0,4}['\"]-c['\"]|"
                        r"Start-Process|\biex\b|Invoke-Expression|\beval\b")
# Functions Home Assistant calls as soon as it loads / sets up the integration.
SETUP_FUNCS = {"async_setup", "async_setup_entry", "setup", "setup_entry", "async_setup_platform",
               "setup_platform", "async_migrate_entry"}


def _item(sev, pid, name, desc, path, n, matched, ctx):
    return {"severity": sev, "id": pid, "name": name, "description": desc, "file": path,
            "line": n, "matched": matched[:120], "context": ctx.strip()[:200]}


def _strip_blobs(text):
    return BLOB_RE.sub(lambda m: "<blob:%d>" % len(m.group(0)), text)


def _py_contexts(lines):
    """Per-line flag: True if the line runs as soon as HA loads the module - module/class body, or
    directly inside an async_setup* / setup* function."""
    out = []
    stack = []  # (indent, kind, name)
    in_str = None
    for line in lines:
        s = line.strip()
        if in_str:
            out.append(False)
            if s.count(in_str) % 2 == 1:
                in_str = None
            continue
        if not s or s.startswith("#"):
            out.append(not stack)
            continue
        ind = len(line) - len(line.lstrip())
        while stack and stack[-1][0] >= ind:
            stack.pop()
        defs = [(i, nm) for i, k, nm in stack if k == "def"]
        classes = any(k == "class" for _i, k, _n in stack)
        # module body, or directly inside a MODULE-LEVEL async_setup*/setup* (HA's entry points);
        # a class method that happens to be called setup() is not one
        out.append(not defs or (len(defs) == 1 and not classes and defs[0][0] == 0 and defs[0][1] in SETUP_FUNCS))
        m = re.match(r"(?:async\s+)?def\s+(\w+)", s)
        if m:
            stack.append((ind, "def", m.group(1)))
        elif s.startswith("class "):
            stack.append((ind, "class", ""))
        for q in ('"""', "'''"):
            if s.count(q) % 2 == 1:
                in_str = q
                break
    return out


def _windows(line):
    if len(line) <= LONG_LINE:
        yield line
        return
    pos = 0
    while pos < len(line):
        yield line[pos:pos + SEG]
        pos += SEG - SEG_OVERLAP


def file_kind(path):
    low = path.lower()
    if low.endswith(PY_EXT):
        return "python"
    if low.endswith(JS_EXT):
        return "frontend"
    if low.endswith(SH_EXT):
        return "script"
    return None


def _scan_text(text, path, findings, info, kind):
    """Line pass + file-level combination rules. kind: python|frontend|script."""
    text = _strip_blobs(text)
    lines = text.split("\n")
    loadtime = _py_contexts(lines) if kind == "python" else [False] * len(lines)
    nls = [m.start() for m in re.finditer("\n", text)]
    seen = set()
    local = []
    low = text.lower()
    for sev, pg, rx in _COMPILED:
        pid = pg["id"]
        if pid in LINE_ONCE and (pid, 0) in seen:
            continue
        nd = NEEDLES.get(pid)
        if nd is not None and not any(x in low for x in nd):
            continue
        hits = 0
        for m in rx.finditer(text):
            n = bisect.bisect_right(nls, m.start()) + 1
            line = lines[n - 1]
            s = line.lstrip()
            if sev != "info" and (s.startswith("#") or s.startswith("//") or s.startswith("* ")):
                continue  # comments describe; they don't execute
            if (pid, n) in seen:
                continue
            seen.add((pid, n))
            it = _item(sev.upper(), pid, pg["name"], pg["desc"], path, n, m.group(0), line if len(line) < 400 else m.group(0))
            it["loadtime"] = bool(loadtime[n - 1]) if n - 1 < len(loadtime) else False
            local.append(it)
            hits += 1
            if pid in LINE_ONCE:
                seen.add((pid, 0))
                break
            if hits >= MAX_HITS:
                break
    # a pipe-to-shell inside a Python/JS string is only executed if a shell sink is next to it;
    # otherwise it is an install hint in an error message / docstring / UI text
    if kind in ("python", "frontend"):
        file_sink = bool(SHELL_SINK.search(text))
        for f in local:
            if f["id"] != "download_execute" or f["severity"] == "INFO":
                continue
            near = "\n".join(lines[max(0, f["line"] - 4):f["line"]])
            if SHELL_SINK.search(near) and not re.match(r"\s*(?:iex|Invoke-Expression)\b", f["matched"], re.I) \
                    or re.search(r"(?<![.\w])(?:exec|eval)\s{0,4}\(|new\s+Function", f["matched"]):
                continue
            if file_sink:
                f["severity"] = "MEDIUM"
                f["description"] += " [in a string; a shell sink exists elsewhere in the file]"
            else:
                f["severity"] = "INFO"
                f["description"] += " [string only: shown to the user, never executed]"
    ids = {f["id"] for f in local}
    has_net = "network" in ids          # the network signature already ran over the whole file
    collector = bool(STRONG_RE.search(text) or SOFT_RE.search(text) or RAWIP_RE.search(text))

    def demote(pids, to="INFO", why=""):
        for f in local:
            if f["id"] in pids and SEV_ORDER[f["severity"]] > SEV_ORDER[to]:
                f["severity"] = to
                if why:
                    f["description"] += why

    def add(sev, pid, name, desc):
        local.append(_item(sev, pid, name, desc, path, 0, "", "file-level combination"))
        ids.add(pid)

    # ---- combination rules ---------------------------------------------------------------
    if "exfil_host" in ids and not has_net:
        demote({"exfil_host"})              # collector URL in a file that never sends: docs / test data
    if "env_dump" in ids and not has_net:
        demote({"env_dump"})                # env dump with no sink: debug print
    if "raw_ip_url" in ids and not ({"credential_read", "env_dump", "ha_secret_read"} & ids):
        demote({"raw_ip_url"})              # device / self-hosted server defaults
    if kind == "frontend":
        demote({"credential_read"})         # browser JS cannot open "Login Data" / ~/.ssh: a string, not a read
        ids.discard("credential_read")
    if "credential_read" in ids:
        if has_net and collector:
            add("CRITICAL", "credential_exfil", "Credential Exfiltration",
                "Reads a credential store and sends to a collector / tunnel / raw-IP endpoint in the same file")
        else:
            demote({"credential_read"}, "MEDIUM")
    if "ha_secret_read" in ids:
        if has_net and collector:
            add("CRITICAL", "ha_secret_exfil", "Home Assistant Secret Exfiltration",
                "Reads secrets.yaml / .storage auth or config entries and talks to a collector / tunnel / raw-IP "
                "endpoint in the same file")
        else:
            # backup / config-editor integrations legitimately read these; reviewable, not an attack
            demote({"ha_secret_read"}, "MEDIUM", " [no collector endpoint in the file]")
    if "token_mint" in ids and has_net and collector:
        add("CRITICAL", "ha_token_exfil", "Token Minted and Reported",
            "Creates Home Assistant users / tokens and talks to a collector / tunnel / raw-IP endpoint")
    if kind == "frontend" and ({"ha_token", "browser_storage"} & ids) and has_net and \
            (STRONG_RE.search(text) or RAWIP_RE.search(text)):
        add("CRITICAL", "ha_token_exfil" if "ha_token" in ids else "browser_exfil",
            "Front-end Token Exfiltration" if "ha_token" in ids else "Front-end Data Exfiltration",
            "Front-end code reads hass.auth tokens / browser storage and talks to a hard-coded collector")
    if "env_dump" in ids and has_net and (STRONG_RE.search(text) or RAWIP_RE.search(text)):
        add("CRITICAL", "env_exfil", "Environment Exfiltration",
            "Serialises the environment and sends it to a hard-coded collector")
    # exec(<var>) of something fetched over the network in the same file
    if kind != "frontend" and has_net and EXEC_VAR_RE.search(text) and FETCH_BODY_RE.search(text) and \
            re.search(r"(?<![.\w])(?:exec|eval)\s{0,4}\(\s{0,4}(?:compile\s{0,4}\(\s{0,4})?(?:\w{1,30}\.(?:text|content|read\s{0,4}\(\s{0,4}\))|"
                      r"(?:code|payload|script|src|resp(?:onse)?|r|res|data|body|content)\b)", text):
        if collector or "pastebin" in low:
            add("CRITICAL", "remote_code_exec", "Remote Code Execution",
                "Fetches code from a paste / raw / tunnel / raw-IP host and exec()s it")
        elif "download_execute" not in ids:
            add("HIGH", "remote_code_exec", "Remote Code Execution",
                "Fetches content over the network and passes it to exec/eval in the same file")
    # download a native binary, make it executable, run it
    if has_net and BIN_DL_RE.search(text) and (CHMOD_RE.search(text) or "subprocess" in ids):
        if not re.search(r"ffmpeg|ffprobe|go2rtc|cloudflared|ngrok|frpc|esphome|"
                         r"github\.com/[\w.-]+/[\w.-]+/releases/download", low):
            add("HIGH", "dropper", "Binary Dropper",
                "Downloads a native executable from a non-release URL, marks it executable and runs it")
    # secret-key regex + network: the faster_log / clipboard-stealer shape
    if KEY_RE.search(text) and has_net and (STRONG_RE.search(text) or RAWIP_RE.search(text)):
        add("CRITICAL", "key_harvest", "Private-Key Harvest",
            "Scans text for secret-key patterns and sends matches to a hard-coded collector")

    # ---- load-time escalation --------------------------------------------------------------
    for f in local:
        if f["severity"] == "HIGH" and f["id"] not in ("exec_route", "dropper", "ha_token_send") and f.get("loadtime"):
            f["severity"] = "CRITICAL"
            f["description"] += " [runs as soon as Home Assistant loads the integration]"
    for f in local:
        f["kind"] = kind
        (info if f["severity"] == "INFO" else findings).append(f)


# ---------------------------------------------------------------------------
# manifest.json requirements / requirements.txt
# ---------------------------------------------------------------------------
def _norm(name):
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def _dl1(a, b):
    """Damerau-Levenshtein distance <= 1?"""
    if a == b:
        return True
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        diff = [i for i in range(la) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
    if la > lb:
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    return a[i:] == b[i + 1:]


def _req_lines(text):
    for n, raw in enumerate(text.split("\n"), 1):
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        yield n, line


def scan_requirements(text, path, findings, info):
    for n, line in _req_lines(text):
        low = line.lower()
        if low.startswith(("--extra-index-url", "--index-url", "-i ", "--find-links", "-f ")):
            url = line.split(None, 1)[1] if " " in line else line.split("=", 1)[-1]
            if not re.search(OK_HOSTS, url, re.IGNORECASE):
                findings.append(_item("MEDIUM", "custom_index", "Custom Package Index",
                                      "Installs from a non-standard package index (dependency-confusion risk)",
                                      path, n, line, line))
            else:
                info.append(_item("INFO", "custom_index", "Custom Package Index", "Known index host", path, n, line, line))
            continue
        if low.startswith(("-r ", "-c ", "-e ", "--")):
            continue
        m = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$", line)
        url = re.search(r"(?:git\+)?https?://\S+", line)
        name = _norm(m.group(1)) if m and not line.lower().startswith(("http", "git+")) else None
        if url and not name:
            wm = re.search(r"/([A-Za-z0-9_.]+?)-\d[^/]*\.whl", url.group(0)) or \
                re.search(r"#egg=([A-Za-z0-9_.-]+)", url.group(0))
            name = _norm(wm.group(1)) if wm else None
        if url:
            host_ok = re.search(OK_HOSTS, url.group(0), re.IGNORECASE)
            archive = re.search(r"\.(?:whl|zip|tar\.gz|tgz)(?:[#?]|$)", url.group(0), re.IGNORECASE)
            if name in PURE_PY and archive and not host_ok:
                findings.append(_item("HIGH", "shadow_wheel", "Shadow Wheel of a Pure-Python Package",
                                      "Pins a pure-Python package (%s) to a direct archive URL off PyPI" % name,
                                      path, n, url.group(0), line))
            elif not host_ok:
                info.append(_item("INFO", "direct_url_dep", "Direct-URL Dependency",
                                  "Dependency installed from a URL / git, not PyPI (forks of device libraries)",
                                  path, n, url.group(0), line))
            continue
        if not name:
            continue
        ver = re.search(r"==\s*([\w.]+)", line)
        if name in KNOWN_BAD and ver and ver.group(1) in KNOWN_BAD[name]:
            findings.append(_item("HIGH", "known_bad_version", "Known-Malicious Release",
                                  "%s==%s is a release publicly known to be malicious" % (name, ver.group(1)),
                                  path, n, line, line))
        if name not in POPULAR and name not in NEAR_OK and len(name) >= 5:
            for p in POPULAR:
                if len(p) >= 5 and _dl1(name, p) and not name.startswith(p) and not p.startswith(name):
                    findings.append(_item("MEDIUM", "typosquat", "Possible Typosquat",
                                          "'%s' is one edit away from the popular package '%s'" % (name, p),
                                          path, n, line, line))
                    break


def _manifest_reqs(text):
    try:
        d = json.loads(text)
    except ValueError:
        return ""
    reqs = d.get("requirements") if isinstance(d, dict) else None
    if not isinstance(reqs, list):
        return ""
    return "\n".join(r for r in reqs if isinstance(r, str))


# ---------------------------------------------------------------------------
# Target-level scan
# ---------------------------------------------------------------------------
SKIP_DIRS = re.compile(r"(?:^|/)(?:tests?|__tests__|e2e|demos?|docs?|examples?|scripts|fixtures|mocks|__mocks__|cypress|playwright|coverage|benchmarks?|stories|\.storybook|\.github|\.devcontainer|\.vscode|\.circleci|\.gitlab|"
                       r"ci|node_modules|site-packages|venv|\.venv|src)/", re.IGNORECASE)


SKIP_DIRS_NOSRC = re.compile(SKIP_DIRS.pattern.replace("|src)/", ")/"), re.IGNORECASE)


def _inner(low):
    """Path below custom_components/<domain>/ (the domain itself may be named anything, even 'demo')."""
    if "custom_components/" in low:
        rest = low.split("custom_components/", 1)[1]
        return rest.split("/", 1)[1] if "/" in rest else rest
    return low


PY_SKIP = re.compile(r"(?:^|/)(?:tests?|e2e|demos?|docs?|examples?|scripts|fixtures|benchmarks?|\.github|"
                     r"\.devcontainer|venv|\.venv)/")


def _in_scope(path, has_cc, has_built=True):
    """What Home Assistant (or the browser) actually runs. With a custom_components/ dir, Python
    outside it is dev tooling (setup.py, scripts/) that HA never imports. Front-end sources in
    src/ only count when the repo ships no built bundle (dist/ or a release asset)."""
    low = path.lower()
    kind = file_kind(path)
    if kind == "python":
        if has_cc and "custom_components/" not in low:
            return False
        return not PY_SKIP.search(_inner(low))
    if kind == "frontend":
        # TypeScript/ESM sources (src/) are compiled into dist/; the release asset / dist bundle is what runs
        if low.startswith("release/"):
            return True
        if "custom_components/" in low:
            return not SKIP_DIRS.search(_inner(low))
        skip = SKIP_DIRS if has_built else SKIP_DIRS_NOSRC
        return not skip.search(low) and not re.search(r"(?:^|/)(?:rollup|webpack|vite|babel|eslint|jest|"
                                                          r"karma|gulpfile|gruntfile|prettier|release|commitlint|postcss|tailwind|tsup|svelte|lint-staged|"
                                                          r"stylelint|vitest|playwright|wdio)[\w.-]*\.(?:config\.)?[mc]?js$", low)
    if kind == "script":
        return "custom_components/" in low
    return False


def scan_target(files, label=""):
    """files: {relative_path: text}. Returns an audit result dict."""
    findings, info = [], []
    total = 0
    scanned = 0
    has_cc = any("custom_components/" in p.lower() for p in files)
    has_built = any(re.match(r"(?:release|dist)/", p.lower()) and p.lower().endswith(JS_EXT) for p in files)
    py_blob = "\n".join(t for p, t in files.items() if p.lower().endswith(PY_EXT)).lower()
    for path in sorted(files, key=lambda p: (p.count("/"), p)):
        low = path.lower()
        base = low.rsplit("/", 1)[-1]
        if base == "manifest.json" and ("custom_components/" in low or not has_cc):
            reqs = _manifest_reqs(files[path])
            if reqs:
                scan_requirements(reqs, path, findings, info)
            continue
        if base.startswith("requirements") and base.endswith(".txt") and "custom_components/" in low:
            scan_requirements(files[path], path, findings, info)
            continue
        kind = file_kind(path)
        if not kind or not _in_scope(path, has_cc, has_built):
            continue
        bundle = kind == "frontend" and (len(files[path]) > BUNDLE_BYTES or low.endswith(".min.js") or
                                         re.search(r"(?:^|/)(?:lib|libs|vendor|third_party)/", low))
        total += len(files[path])
        if total > MAX_TOTAL:
            info.append(_item("INFO", "truncated", "Scan Truncated", "Target exceeds %d bytes of text" % MAX_TOTAL,
                              path, 0, "", ""))
            break
        before = len(findings)
        scanned += 1
        _scan_text(files[path], path, findings, info, kind)
        if kind == "script" and base not in py_blob:
            for f in findings[before:]:
                if SEV_ORDER[f["severity"]] > SEV_ORDER["MEDIUM"]:
                    f["severity"] = "MEDIUM"
                    f["description"] += " [shell script not invoked by the integration's Python]"
        if bundle:
            # bundled cards ship lit / chart.js / leaflet etc. inline: keep only genuinely malicious shapes
            keep = {"download_execute", "obfuscated_exec", "exfil_host", "browser_exfil", "cryptominer",
                    "credential_exfil", "env_exfil", "key_harvest", "remote_code_exec", "ha_token_exfil",
                    "ha_token_send"}
            moved = [f for f in findings[before:] if f["id"] not in keep]
            for f in moved:
                findings.remove(f)
                f["severity"] = "INFO"
                info.append(f)
    r = _summarise(findings, info, label)
    r["scanned_files"] = scanned
    if not scanned:
        # e.g. a card whose code only exists as a release asset that could not be fetched, or a
        # TypeScript-only checkout: SAFE would be a lie
        r["incomplete"] = True
        r["summary"] = "Nothing scannable (no Python/JS that Home Assistant or the browser would run)"
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
    caps = sorted({f["id"] for f in info})
    return {"target": label, "risk_score": min(score, 100), "risk_level": level,
            "summary": ", ".join(parts) or "No issues found", "capabilities": caps,
            "findings": findings, "info": info,
            "total_findings": len(findings), "info_count": len(info)}


def scan(content, label="<text>", kind="python"):
    """Scan a bare string. Python is treated as module-level (import-time) code."""
    findings, info = [], []
    if label.lower().endswith(".txt"):
        scan_requirements(content, label, findings, info)
    elif label.lower().endswith("manifest.json"):
        scan_requirements(_manifest_reqs(content), label, findings, info)
    else:
        _scan_text(content, label, findings, info, kind)
    return _summarise(findings, info, label)


# ---------------------------------------------------------------------------
# Loading targets (code is never imported or executed)
# ---------------------------------------------------------------------------
UA = {"User-Agent": "hacs-audit/%s (+https://github.com/eltociear/hacs-audit)" % __version__}
KEEP_EXT = PY_EXT + JS_EXT + SH_EXT + (".txt", ".json")


def _get(url, timeout=90, tries=4):
    last = None
    for i in range(tries):
        try:
            return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout).read()
        except urllib.error.HTTPError as e:
            if e.code in (404, 410, 451):
                raise
            last = e
        except Exception as e:  # flaky networks: retry with backoff
            last = e
        time.sleep(2 * (i + 1))
    raise last


def _keep(rel, size):
    low = rel.lower()
    if "/node_modules/" in "/" + low or size > MAX_FILE:
        return False
    if low.endswith(".json"):
        return low.rsplit("/", 1)[-1] in ("manifest.json", "hacs.json")
    return low.endswith(KEEP_EXT)


def files_from_tarball(data, strip=1, prefix=""):
    files = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        for m in tf:
            if not m.isreg():
                continue
            parts = m.name.split("/")[strip:]
            if not parts or any(p in ("", ".", "..") for p in parts):
                continue
            rel = "/".join(parts)
            if _keep(rel, m.size):
                files[prefix + rel] = tf.extractfile(m).read().decode("utf-8", "replace")
    return files


def files_from_zip(data, prefix=""):
    files = {}
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for zi in zf.infolist():
            parts = zi.filename.split("/")
            if zi.is_dir() or any(p in ("..",) for p in parts):
                continue
            if _keep(zi.filename, zi.file_size):
                files[prefix + zi.filename] = zf.read(zi).decode("utf-8", "replace")
    return files


def files_from_dir(root):
    files = {}
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in (".git", "node_modules", "__pycache__", ".venv", "venv")]
        for fn in fns:
            p = os.path.join(dp, fn)
            if os.path.islink(p):
                continue
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            try:
                if _keep(rel, os.path.getsize(p)):
                    with open(p, encoding="utf-8", errors="replace") as fh:
                        files[rel] = fh.read()
            except OSError:
                continue
    return files


def _component_dir_files(path, domain=None):
    """A bare custom_components/<domain> directory: present it as the repo layout."""
    files = files_from_dir(path)
    d = domain or os.path.basename(os.path.normpath(path))
    if any(p.lower().startswith("custom_components/") for p in files):
        return files
    if "manifest.json" in files or any(p.endswith(".py") for p in files):
        return {"custom_components/%s/%s" % (d, p): t for p, t in files.items()}
    return files


def fetch_repo(repo, ref=None, release=True):
    """Repo tarball + (for zip_release integrations and plugins) the latest release's assets,
    which is what HACS actually installs."""
    files = files_from_tarball(_get("https://codeload.github.com/%s/tar.gz/%s" % (repo, ref or "HEAD")))
    if not release:
        return files
    hj = {}
    try:
        hj = json.loads(files.get("hacs.json", "{}"))
    except ValueError:
        pass
    try:
        rel = json.loads(_get("https://api.github.com/repos/%s/releases/latest" % repo, tries=4))
    except urllib.error.HTTPError as e:
        if e.code != 404:   # 404 = no releases: HACS installs from the repository itself
            files["\0release-error"] = "HTTP %d" % e.code
        return files
    except Exception as e:
        files["\0release-error"] = str(e)[:120]
        return files
    want = hj.get("filename")
    for a in rel.get("assets", [])[:30]:
        name = a.get("name", "")
        if a.get("size", 0) > MAX_FILE * 2:
            continue
        lname = name.lower()
        if lname.endswith(JS_EXT) or (lname.endswith(".zip") and (hj.get("zip_release") or name == want)):
            try:
                data = _get(a["browser_download_url"])
            except Exception:
                continue
            if lname.endswith(".zip"):
                files.update(files_from_zip(data, "release/"))
            elif len(data) <= MAX_FILE:
                files["release/" + name] = data.decode("utf-8", "replace")
    return files


def audit_github(spec):
    repo, _, ref = spec.partition("@")
    repo = re.sub(r"^https?://github\.com/", "", repo).strip("/")
    if repo.endswith(".git"):
        repo = repo[:-4]
    files = fetch_repo(repo, ref or None)
    err = files.pop("\0release-error", None)
    r = scan_target(files, repo + ("@" + ref if ref else ""))
    if err:
        r["release_error"] = err
        r["incomplete"] = True
    return r


def hacs_default(category):
    return json.loads(_get(HACS_DEFAULT % category).decode("utf-8"))


_ICON = {"CRITICAL": "\U0001F534", "HIGH": "\U0001F7E0", "MEDIUM": "\U0001F7E1",
         "LOW": "\U0001F535", "SAFE": "\U0001F7E2"}


def _print(r, verbose):
    if r.get("incomplete") and not r["findings"]:
        print("\u26AA %s  [INCOMPLETE]  %s" % (r["target"], r["summary"]))
        if r.get("release_error"):
            print("    latest release could not be fetched: %s" % r["release_error"])
        return
    print("%s %s  [%s]  score=%d  (%d findings, %d info)" % (
        _ICON.get(r["risk_level"], "?"), r["target"], r["risk_level"], r["risk_score"],
        r["total_findings"], r["info_count"]))
    if r.get("release_error"):
        print("    note: latest release could not be fetched (%s); scanned the repository only" % r["release_error"])
    for f in r["findings"]:
        print("    %-8s %s  %s:%s" % (f["severity"], f["name"], f["file"], f["line"]))
        if f["context"] and f["line"]:
            print("             %s" % f["context"][:160])
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
    args = [a for a in args if a not in ("--json", "--verbose", "-v")]
    limit = None
    if "--limit" in args:
        i = args.index("--limit")
        limit = int(args[i + 1])
        del args[i:i + 2]
    targets = []
    if args[0] == "--text":
        txt = " ".join(args[1:])
        targets.append(("<text>", lambda: scan(txt)))
    elif args[0] == "--github":
        for spec in args[1:]:
            targets.append((spec, (lambda s=spec: audit_github(s))))
    elif args[0] == "--hacs-default":
        cats = [a for a in args[1:] if a in ("integration", "plugin")] or ["integration", "plugin"]
        for cat in cats:
            repos = hacs_default(cat)
            for repo in (repos[:limit] if limit else repos):
                targets.append((repo, (lambda s=repo: audit_github(s))))
    elif args[0] == "--ha-config":
        root = args[1]
        cc = os.path.join(root, "custom_components")
        if os.path.isdir(cc):
            for d in sorted(os.listdir(cc)):
                p = os.path.join(cc, d)
                if os.path.isdir(p) and not d.startswith((".", "__")):
                    targets.append(("custom_components/" + d, (lambda p=p, d=d: scan_target(
                        _component_dir_files(p, d), "custom_components/" + d))))
        www = os.path.join(root, "www", "community")
        if os.path.isdir(www):
            for d in sorted(os.listdir(www)):
                p = os.path.join(www, d)
                if os.path.isdir(p) and not d.startswith("."):
                    targets.append(("www/community/" + d, (lambda p=p, d=d: scan_target(
                        {"release/" + k: v for k, v in files_from_dir(p).items()}, "www/community/" + d))))
        if not targets:
            print("no custom_components/ or www/community/ under %s" % root, file=sys.stderr)
            return 1
    else:
        for a in args:
            if os.path.isdir(a):
                targets.append((a, (lambda p=a: scan_target(_component_dir_files(p), p))))
            elif os.path.isfile(a):
                if a.endswith((".tar.gz", ".tgz", ".tar")):
                    targets.append((a, (lambda p=a: scan_target(files_from_tarball(open(p, "rb").read()), p))))
                elif a.endswith(".zip"):
                    targets.append((a, (lambda p=a: scan_target(files_from_zip(open(p, "rb").read()), p))))
                else:
                    targets.append((a, (lambda p=a: scan(open(p, encoding="utf-8", errors="replace").read(), p,
                                                         file_kind(p) or "python"))))
            else:
                targets.append((a, (lambda s=a: audit_github(s))))
    results, worst = [], "SAFE"
    for label, thunk in targets:
        try:
            r = thunk()
        except Exception as e:  # network errors, 404s, corrupt archives
            r = {"target": label, "risk_level": "SAFE", "risk_score": 0, "error": str(e)[:200],
                 "findings": [], "info": [], "total_findings": 0, "info_count": 0, "summary": "error"}
            if not as_json:
                print("⚪ %s  [ERROR] %s" % (label, r["error"]))
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
