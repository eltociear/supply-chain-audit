#!/usr/bin/env python3
"""comfyui-audit - scan ComfyUI custom nodes for MALICIOUS code before you install them.

A ComfyUI custom node is arbitrary Python that runs with your user's full privileges the
moment ComfyUI starts: `install.py` runs when ComfyUI-Manager installs it, `prestartup_script.py`
runs before the server boots, every module's top-level code runs on import, and the files in
`web/` run as JavaScript inside your browser tab. Its `requirements.txt` is pip-installed too.
In 2024 a node (ComfyUI_LLMVISION) pinned "openai" and "anthropic" to wheels on an attacker's
GitHub that stole browser passwords and cards and posted them to a Discord webhook; the same
year the Ultralytics PyPI release that many nodes depend on shipped a cryptominer.

This is a deterministic (no LLM) static scan for those shapes: download-and-execute, exec of
fetched or decoded code, credential / browser / wallet theft to a collector, environment
exfiltration, reverse shells, persistence, Defender tampering, miners, shadow wheels of
pure-Python packages, typosquatted and known-bad dependency pins, and HTTP routes that hand
request data to a shell - weighted by WHEN the code runs.

Precision-tuned to near-zero false positives: what nodes do every day (pip-installing their
dependencies, downloading models from Hugging Face / Civitai, `git pull` self-updates, tunnels
for Colab, CDN-hosted front-end libraries, user-supplied webhook URLs) is reported as
informational context and never inflates the risk score. Risk comes from specific
COMBINATIONS and sinks. No code from the node is ever imported or executed.

Usage:
  python comfyui_audit.py <node_dir> [...]              # scan a custom node checkout
  python comfyui_audit.py --comfyui-dir <ComfyUI>        # scan every node in custom_nodes/
  python comfyui_audit.py --github owner/repo[@ref]      # fetch the repo tarball and scan
  python comfyui_audit.py --registry [--limit N]         # bulk-scan ComfyUI-Manager's node list
  python comfyui_audit.py --text "some code"             # scan a string (as import-time Python)
  add --json (family schema) or --sarif (SARIF 2.1.0) for machine-readable output,
  --fail-on {critical,high,medium,low,never}, --version, --verbose to print INFO context

Exit code 2 if any target reaches --fail-on (default HIGH; CI-friendly), 1 on usage errors.
No dependencies beyond the standard library. MIT licensed.
"""
import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request

__version__ = "0.2.0"

PY_EXT = (".py",)
JS_EXT = (".js", ".mjs", ".cjs")
SH_EXT = (".sh", ".bat", ".cmd", ".ps1")
MAX_FILE = 2000000       # bytes; bigger files are vendored bundles / data - skipped
MAX_TOTAL = 40000000     # bytes of text scanned per node
SEG = 8192               # regex window for very long (minified) lines
SEG_OVERLAP = 1024
LONG_LINE = 20000
REGISTRY = "https://raw.githubusercontent.com/ltdrdata/ComfyUI-Manager/main/custom-node-list.json"

# Hard-coded collectors: stealers ship these; legitimate nodes take webhook URLs from the user.
STRONG_EXFIL = (
    r"(?:discord(?:app)?\.com/api/webhooks/\d{17,20}/[\w-]{20,}|api\.telegram\.org/bot\d{6,}:[\w-]{30,}|"
    r"hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/\w{10,}|"
    r"\bwebhook\.site/[0-9a-f-]{8,}|\.m\.pipedream\.net|requestbin\.(?:com|net|io)|\brequestb\.in\b|"
    r"requestcatcher\.com|beeceptor\.com|oastify\.com|\boast\.(?:fun|me|pro|live|site|online)\b|"
    r"\binteract\.sh\b|interactsh|burpcollaborator\.net|canarytokens\.com|dnslog\.cn|\bceye\.io\b|requestrepo\.com)"
)
# Tunnels / paste hosts: normal for Colab sharing and docs; only meaningful in combinations.
SOFT_HOST = (r"(?:ngrok(?:-free)?\.(?:io|app|dev)|\.trycloudflare\.com|serveo\.net|localtunnel\.me|loca\.lt\b|"
             r"pastebin\.com/raw|paste\.ee/r|hastebin\.com/raw|\btransfer\.sh\b|\bfile\.io/|workers\.dev/|"
             r"raw\.githubusercontent\.com/[\w.-]+/[\w.-]+/(?:main|master)/[\w./-]+\.(?:py|txt|sh|ps1))")
RAW_IP_URL = (r"https?://(?!(?:127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|"
              r"2(?:2[4-9]|[3-5]\d)\.))\d{1,3}(?:\.\d{1,3}){3}")
NET_SEND = (r"(?:\brequests\.(?:get|post|put|request|Session)\b|\burllib\.request\.(?:urlopen|Request|urlretrieve)\b|"
            r"\burlopen\s*\(|\burlretrieve\s*\(|\bhttpx\.(?:get|post|Client|AsyncClient|request)\b|"
            r"\baiohttp\.ClientSession\b|\bhttp\.client\.HTTPS?Connection\b|\bsocket\.(?:socket|create_connection)\b|"
            r"\bsmtplib\.SMTP|\bftplib\.FTP|\bwget\.download\s*\(|\bpycurl\b|"
            r"\bfetch\s*\(|XMLHttpRequest|navigator\.sendBeacon|new\s+WebSocket\s*\(|"
            r"\bcurl\s+(?:-[a-zA-Z]+\s+)*https?://|\bwget\s+(?:-[a-zA-Z-]+\s+)*https?://|Invoke-WebRequest|\biwr\b|DownloadFile\s*\()")
CRED_PATHS = (
    r"(?:(?-i:(?:[/\\\\]|['\"],\s{0,4}['\"])(?:Login Data|Local State|Cookies|Web Data)\b)|Local Extension Settings|"
    r"nkbihfbeogaeaoehlefnkodbefgpgknn|\bExodus[/\\\\]|exodus\.wallet|Electrum[/\\\\]wallets|atomic[/\\\\]Local Storage|"
    r"wallet\.dat\b|\.ssh[/\\\\]id_(?:rsa|ed25519|ecdsa)|\.aws[/\\\\]credentials|\.git-credentials|"
    r"\.docker[/\\\\]config\.json|discord[/\\\\]Local Storage[/\\\\]leveldb|Telegram Desktop[/\\\\]tdata|"
    r"CryptUnprotectData|\bwin32crypt\b|browser_cookie3|\bfind-generic-password\b|logins\.json['\"]|key4\.db)"
)
# Pure-Python packages: nobody needs a custom-built wheel of these. A direct URL to one off
# PyPI is the LLMVISION "shadow wheel" shape.
PURE_PY = {
    "openai", "anthropic", "requests", "httpx", "groq", "mistralai", "cohere", "replicate", "fal-client",
    "google-generativeai", "google-genai", "huggingface-hub", "transformers", "diffusers", "accelerate",
    "gitpython", "beautifulsoup4", "langchain", "ollama", "fastapi", "uvicorn", "boto3", "websocket-client",
    "packaging", "setuptools", "pip", "colorama", "rich", "click", "tqdm", "einops", "omegaconf", "timm",
    "peft", "ftfy", "piexif", "lark", "spandrel", "segment-anything", "open-clip-torch", "pydub", "openai-whisper",
}
POPULAR = PURE_PY | {
    "torch", "torchvision", "torchaudio", "numpy", "opencv-python", "opencv-contrib-python",
    "opencv-python-headless", "pillow", "safetensors", "onnxruntime", "onnxruntime-gpu", "insightface",
    "mediapipe", "scipy", "scikit-image", "scikit-learn", "xformers", "kornia", "matplotlib", "pandas",
    "pyyaml", "aiohttp", "imageio", "imageio-ffmpeg", "moviepy", "ultralytics", "numba", "librosa",
    "soundfile", "sentencepiece", "tokenizers", "protobuf", "rembg", "color-matcher", "bitsandbytes",
    "triton", "gradio", "pydantic", "llama-cpp-python", "tiktoken", "jsonschema", "psutil", "gputil",
    "py-cpuinfo", "pynvml", "nvidia-ml-py", "deepspeed", "flash-attn", "sageattention", "decord", "av",
    "ffmpeg-python", "yt-dlp", "selenium", "playwright", "lxml", "websockets", "cryptography",
    "pycryptodome", "dill", "cloudpickle", "joblib", "numexpr", "filelock", "wheel", "trimesh", "simpleeval",
    "addict", "yapf", "fvcore", "iopath", "pycocotools", "albumentations", "basicsr", "facexlib", "gfpgan",
    "realesrgan", "clip-interrogator", "torchsde", "kornia-rs", "piq", "lpips", "pyloudnorm",
    "dghs-imgutils", "huggingface", "pymatting", "watchdog", "toml", "tomli", "regex", "colour-science",
}
# Releases publicly known to be malicious.
KNOWN_BAD = {"ultralytics": {"8.3.41", "8.3.42", "8.3.45", "8.3.46"}}
# Index / wheel hosts that are normal for the ComfyUI ecosystem.
OK_HOSTS = (r"(?:download\.pytorch\.org|files\.pythonhosted\.org|pypi\.org|pypi\.python\.org|pypi\.nvidia\.com|"
            r"pypi\.ngc\.nvidia\.com|abetlen\.github\.io|huggingface\.co|hf\.co|mirrors\.aliyun\.com|"
            r"pypi\.tuna\.tsinghua\.edu\.cn|mirrors\.cloud\.tencent\.com|repo\.huaweicloud\.com|"
            r"mirror\.baidu\.com|pypi\.mirrors\.ustc\.edu\.cn|mirrors\.bfsu\.edu\.cn|pypi\.doubanio\.com|"
            r"download\.openmmlab\.com|data\.pyg\.org|developer\.download\.nvidia\.com)")
CDN_HOSTS = (r"(?:cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|esm\.sh|cdn\.skypack\.dev|"
             r"fonts\.googleapis\.com|ajax\.googleapis\.com|code\.jquery\.com|cdn\.tailwindcss\.com|"
             r"fonts\.gstatic\.com|esm\.run|ga\.jspm\.io|cdn\.plot\.ly|stackpath\.bootstrapcdn\.com|"
             r"js\.stripe\.com|cdnjs\.buymeacoffee\.com)")

PATTERNS = {
    "critical": [
        {"id": "download_execute", "name": "Download & Execute",
         "desc": "Pipes a downloaded script straight into a shell / interpreter",
         "regexes": [
             r"\b(?:curl|wget)\s[^\n|;]{0,200}?https?://[^\n|;]{1,200}?\|\s{0,4}(?:sudo\s+)?(?:ba|z|da)?sh\b",
             r"\b(?:curl|wget)\s[^\n|;]{0,200}?https?://[^\n|;]{1,200}?\|\s{0,4}(?:python3?|perl|node)\b",
             r"\b(?:iex|Invoke-Expression)\s{0,4}\(?\s{0,4}(?:\(\s{0,4})?(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|"
             r"\(?New-Object\s+(?:System\.)?Net\.WebClient\)?\.DownloadString)",
             r"\bexec\s{0,4}\(\s{0,4}(?:requests\.get|urllib\.request\.urlopen|urlopen|httpx\.get)\s{0,4}\(",
             r"\beval\s{0,4}\(\s{0,4}(?:requests\.get|urllib\.request\.urlopen|urlopen|httpx\.get)\s{0,4}\(",
             r"(?:\beval|new\s+Function)\s{0,4}\(\s{0,4}await\s+(?:\(\s{0,4}await\s+)?fetch\s{0,4}\(",
         ]},
        {"id": "obfuscated_exec", "name": "Obfuscated Code Execution",
         "desc": "exec/eval of base64 / zlib / marshal / hex-decoded content",
         "regexes": [
             r"\b(?:exec|eval)\s{0,4}\(\s{0,4}(?:compile\s{0,4}\(\s{0,4})?(?:base64\.b(?:64|32|85)decode|zlib\.decompress|"
             r"lzma\.decompress|bz2\.decompress|gzip\.decompress|marshal\.loads|codecs\.decode|bytes\.fromhex|"
             r"binascii\.(?:a2b_base64|unhexlify)|__import__\s{0,4}\(\s{0,4}['\"](?:base64|zlib|marshal|codecs)['\"])",
             r"\b(?:exec|eval)\s{0,4}\(\s{0,4}['\"]{0,3}\s{0,4}\)?\s{0,4}\.join\s{0,4}\(\s{0,4}(?:chr|map\s{0,4}\(\s{0,4}chr)",
             r"\b(?:exec|eval)\s{0,4}\(\s{0,4}(?:b['\"])?(?:\\x[0-9a-fA-F]{2}){16,}",
             r"\beval\s{0,4}\(\s{0,4}atob\s{0,4}\(|new\s+Function\s{0,4}\(\s{0,4}atob\s{0,4}\(",
             r"\bexec\s{0,4}\(\s{0,4}\w{1,40}\s{0,4}\(\s{0,4}['\"][A-Za-z0-9+/=]{200,}",
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
         "desc": "Deletes the home directory or filesystem root",
         "regexes": [
             r"shutil\.rmtree\s{0,4}\(\s{0,4}(?:os\.path\.expanduser\s{0,4}\(\s{0,4}['\"]~['\"]\s{0,4}\)|['\"](?:/|~|C:\\\\\\\\?)['\"]|"
             r"Path\.home\s{0,4}\(\s{0,4}\)\s{0,4}\))",
             r"\brm\s+-[a-zA-Z]{0,4}r[a-zA-Z]{0,4}\s+(?:--no-preserve-root\s+)?(?:~|\$HOME|/)(?:\s|['\"`;]|$)",
             r"\b(?:Remove-Item|rd|rmdir)\s+[^\n]{0,30}(?:\$env:USERPROFILE|C:\\\\\s)[^\n]{0,30}-(?:Recurse|s\b)",
         ]},
    ],
    "high": [
        {"id": "exfil_host", "name": "Hard-coded Collector Endpoint",
         "desc": "A hard-coded webhook / request-catcher / OAST endpoint (stealers report here)",
         "regexes": [STRONG_EXFIL]},
        {"id": "credential_read", "name": "Credential Store Access",
         "desc": "Reads browser passwords/cookies, wallets, SSH/AWS/git/docker credentials or OS secret stores",
         "regexes": [CRED_PATHS]},
        {"id": "env_dump", "name": "Environment Dump",
         "desc": "Serialises the whole environment (every API key you have)",
         "regexes": [
             r"(?:json\.dumps|str|repr|pickle\.dumps|yaml\.(?:safe_)?dump)\s{0,4}\(\s{0,4}(?:dict\s{0,4}\(\s{0,4})?"
             r"os\.environ(?:\.copy\s{0,4}\(\s{0,4}\))?\s{0,4}\)?\s{0,4}[,)]",
             r"JSON\.stringify\s{0,4}\(\s{0,4}process\.env\b",
         ]},
        {"id": "persistence", "name": "Persistence",
         "desc": "Installs itself to run at login / on a schedule",
         "regexes": [
             r"CurrentVersion\\\\{1,2}Run\b",
             r"\bschtasks(?:\.exe)?['\"]?\s{0,4},?\s{0,4}['\"]?/create",
             r"Library/LaunchAgents|/Library/LaunchDaemons",
             r"Start Menu\\\\{1,2}Programs\\\\{1,2}Startup|shell:startup",
             r"\bcrontab\s+-[l]?\s{0,4}[|;]|\(crontab -l",
             r"(?:open|write_text|append)\s{0,4}\([^\n]{0,80}(?:\.bashrc|\.zshrc|\.bash_profile|\.profile)['\"][^\n]{0,40}['\"]a",
         ]},
        {"id": "defender_tamper", "name": "Security Tool Tampering",
         "desc": "Adds antivirus exclusions or disables real-time protection / Gatekeeper",
         "regexes": [
             r"Add-MpPreference\s+[^\n]{0,40}-Exclusion(?:Path|Process|Extension)",
             r"Set-MpPreference\s+[^\n]{0,40}-Disable(?:RealtimeMonitoring|BehaviorMonitoring|IOAVProtection)",
             r"spctl\s+--master-disable",
         ]},
        {"id": "cryptominer", "name": "Cryptominer",
         "desc": "Mining pool / miner binary reference",
         "regexes": [r"stratum\+(?:tcp|ssl|tls)://", r"\b(?:xmrig|minexmr|nanopool\.org|supportxmr|nicehash\.com/miner|"
                     r"cryptonight|moneroocean)\b"]},
        {"id": "exec_route", "name": "HTTP Route Executes Request Data",
         "desc": "A server route passes request data into a shell / exec / eval (remote code execution endpoint)",
         "regexes": [
             r"(?:subprocess\.(?:run|call|Popen|check_output|check_call)|os\.system|os\.popen|\bexec|\beval)\s{0,4}\("
             r"[^\n]{0,120}\b(?:request\.(?:query|match_info|rel_url|args|form)|await\s+request\.(?:json|post|text)\s{0,4}\(|"
             r"json_data\[|post\[|body\[)",
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
    ],
    "info": [
        {"id": "network", "name": "Network Access", "desc": "Makes network requests", "regexes": [NET_SEND]},
        {"id": "subprocess", "name": "Process Execution", "desc": "Spawns processes",
         "regexes": [r"\bsubprocess\.(?:run|call|Popen|check_output|check_call)\b|\bos\.system\s{0,4}\(|\bos\.popen\s{0,4}\("]},
        {"id": "pip_install", "name": "Runtime pip install", "desc": "pip-installs packages from code",
         "regexes": [r"['\"]pip['\"]\s{0,4},\s{0,4}['\"]install['\"]|pip\s+install\b|pip\._internal|\bpip\.main\s{0,4}\("]},
        {"id": "self_update", "name": "Self-update", "desc": "Pulls new code for itself at runtime (git pull / clone)",
         "regexes": [r"['\"]git['\"]\s{0,4},\s{0,4}['\"](?:pull|clone|fetch)['\"]|git\s+(?:pull|clone)\b|\bgit\.Repo\b[^\n]{0,60}\.(?:pull|clone_from)|\.remotes\.origin\.pull"]},
        {"id": "model_download", "name": "Model Download", "desc": "Downloads model weights (Hugging Face / Civitai / GitHub releases)",
         "regexes": [r"hf_hub_download|snapshot_download|huggingface\.co/[\w.-]+/[\w.-]+/resolve|civitai\.com/api/download|load_file_from_url|torch\.hub\.download_url_to_file"]},
        {"id": "dynamic_code", "name": "Dynamic Code", "desc": "exec/eval/compile with non-literal input",
         "regexes": [r"\b(?:exec|eval)\s{0,4}\(\s{0,4}(?!['\"])[\w.]{1,60}"]},
        {"id": "pickle_load", "name": "Unsafe Deserialisation", "desc": "torch.load / pickle.load without weights_only",
         "regexes": [r"\bpickle\.loads?\s{0,4}\(|\btorch\.load\s{0,4}\((?![^\n]{0,200}weights_only\s{0,4}=\s{0,4}True)"]},
        {"id": "tls_off", "name": "TLS Verification Disabled", "desc": "verify=False / unverified SSL context",
         "regexes": [r"verify\s{0,4}=\s{0,4}False\b|_create_unverified_context|ssl\._create_default_https_context\s{0,4}=|CERT_NONE"]},
        {"id": "soft_host", "name": "Tunnel / Paste Host", "desc": "ngrok / cloudflared tunnel or paste/raw-file host",
         "regexes": [SOFT_HOST]},
        {"id": "env_read", "name": "Environment Read", "desc": "Reads environment variables / API keys",
         "regexes": [r"\bos\.environ\b|\bos\.getenv\s{0,4}\(|process\.env\b"]},
        {"id": "browser_storage", "name": "Browser Storage", "desc": "Front-end reads localStorage / cookies",
         "regexes": [r"\blocalStorage\.getItem\b|\bdocument\.cookie\b|\bsessionStorage\.getItem\b"]},
        {"id": "embedded_blob", "name": "Embedded Blob", "desc": "Large base64/hex blob (images, fonts, wasm, weights)",
         "regexes": [r"<blob:\d+>"]},
    ],
}
SEVERITY_SCORE = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "SAFE": 0}
_CASE_SENSITIVE = {"embedded_blob"}
_COMPILED = [(sev, pg, re.compile(rx, 0 if pg["id"] in _CASE_SENSITIVE else re.IGNORECASE))
             for sev, groups in PATTERNS.items() for pg in groups for rx in pg["regexes"]]
# Cheap literal prefilter: a signature group only runs on a file containing one of its needles.
NEEDLES = {
    "download_execute": ("curl", "wget", "iex", "invoke-expression", "exec", "eval"),
    "obfuscated_exec": ("exec", "eval", "function"),
    "reverse_shell": ("dup2", "pty.spawn", "/dev/tcp", "nc ", "ncat", "fileno"),
    "destructive": ("rmtree", "rm -", "remove-item", "rmdir", "rd "),
    "exfil_host": ("discord", "telegram", "slack", "webhook.site", "pipedream", "requestb", "requestcatcher",
                   "beeceptor", "oast", "interact", "burpcollaborator", "canarytokens", "dnslog", "ceye", "requestrepo"),
    "credential_read": ("login data", "local state", "cookies", "web data", "extension settings", "nkbihf",
                        "exodus", "electrum", "atomic", "wallet.dat", ".ssh", ".aws", "git-credentials", ".docker",
                        "leveldb", "tdata", "cryptunprotect", "win32crypt", "browser_cookie3", "generic-password",
                        "logins.json", "key4.db"),
    "env_dump": ("os.environ", "process.env"),
    "persistence": ("currentversion", "schtasks", "launchagents", "launchdaemons", "startup", "crontab", "bashrc",
                    "zshrc", "bash_profile", ".profile"),
    "defender_tamper": ("mppreference", "spctl"),
    "cryptominer": ("stratum", "xmrig", "minexmr", "nanopool", "supportxmr", "nicehash", "cryptonight", "moneroocean"),
    "exec_route": ("request",),
    "raw_ip_url": ("http",),
    "remote_script_js": (".src", "import("),
    "subprocess": ("subprocess", "os.system", "os.popen"),
    "pip_install": ("pip",),
    "self_update": ("git",),
    "model_download": ("hf_hub_download", "snapshot_download", "huggingface.co", "civitai", "load_file_from_url",
                       "download_url_to_file"),
    "dynamic_code": ("exec", "eval"),
    "pickle_load": ("pickle", "torch.load"),
    "tls_off": ("verify", "unverified", "https_context", "cert_none"),
    "soft_host": ("ngrok", "trycloudflare", "serveo", "localtunnel", "loca.lt", "pastebin", "paste.ee", "hastebin",
                  "transfer.sh", "file.io", "workers.dev", "raw.githubusercontent"),
    "env_read": ("environ", "getenv", "process.env"),
    "browser_storage": ("localstorage", "cookie", "sessionstorage"),
    "embedded_blob": ("<blob:",),
}
LINE_ONCE = {"network", "subprocess", "pip_install", "self_update", "model_download", "dynamic_code",
             "pickle_load", "tls_off", "env_read", "browser_storage", "embedded_blob", "soft_host"}
NET_RE = re.compile(NET_SEND, re.IGNORECASE)
STRONG_RE = re.compile(STRONG_EXFIL, re.IGNORECASE)
SOFT_RE = re.compile(SOFT_HOST, re.IGNORECASE)
RAWIP_RE = re.compile(RAW_IP_URL)
CRED_RE = re.compile(CRED_PATHS, re.IGNORECASE)
BLOB_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{4096,}|(?:\\x[0-9a-fA-F]{2}){1024,}")
EXEC_VAR_RE = re.compile(r"\b(?:exec|eval)\s{0,4}\(\s{0,4}(?!['\"])(?:compile\s{0,4}\(\s{0,4})?[\w.\[\]'\"]{1,60}\s{0,4}[,)]")
FETCH_BODY_RE = re.compile(r"\.(?:text|content)\b|\.read\s{0,4}\(\s{0,4}\)|\.decode\s{0,4}\(")
CHMOD_RE = re.compile(r"os\.chmod\s{0,4}\([^\n]{0,80}0o7|stat\.S_IEXEC|stat\.S_IXUSR|chmod\s+\+?[0-7]*x|chmod\s+7[0-7]{2}")
BIN_DL_RE = re.compile(r"https?://[^\s'\"]{4,200}\.(?:exe|dll|scr|msi|so|dylib|bin|elf)['\"]", re.IGNORECASE)
KEY_RE = re.compile(r"\[1-9A-HJ-NP-Za-km-z\]\{(?:8[78]|4[34])\}|0x\[0-9a-fA-F\]\{64\}|\[0-9a-fA-F\]\{64\}|"
                    r"(?:sk-|sk_live_|AKIA)\[?[A-Za-z0-9]")
# A real typosquat check needs the registry; these are known, legitimate neighbours of popular names.
NEAR_OK = {"torchode"}
# Things that actually execute a shell command (for download_execute in source files).
SHELL_SINK = re.compile(r"os\.system|os\.popen|subprocess\.(?:run|call|Popen|check_output|check_call|getoutput|getstatusoutput)\s{0,4}\(|shell\s{0,4}=\s{0,4}True|Popen|\bexec(?:Sync|File)?\s{0,4}\(|"
                        r"child_process|\bspawn\s{0,4}\(|['\"](?:ba|z)?sh['\"]\s{0,4},\s{0,4}['\"]-c['\"]|Start-Process|"
                        r"\biex\b|Invoke-Expression|\beval\b")
EXFIL_IDS = {"credential_exfil", "env_exfil", "remote_code_exec", "dropper"}


def _item(sev, pid, name, desc, path, n, matched, ctx):
    return {"severity": sev, "id": pid, "name": name, "description": desc, "file": path,
            "line": n, "matched": matched[:120], "context": ctx.strip()[:200]}


def _strip_blobs(text):
    return BLOB_RE.sub(lambda m: "<blob:%d>" % len(m.group(0)), text)


def _py_contexts(lines):
    """Per-line flag: True if the line runs at import (module or class body, not inside a def)."""
    out = []
    stack = []  # (indent, kind)
    in_str = None
    for line in lines:
        s = line.strip()
        if in_str:
            out.append(False)
            if s.count(in_str) % 2 == 1:
                in_str = None
            continue
        if not s or s.startswith("#"):
            out.append(bool(stack) is False)
            continue
        ind = len(line) - len(line.lstrip())
        while stack and stack[-1][0] >= ind:
            stack.pop()
        top = not any(k == "def" for _i, k in stack)
        out.append(top)
        if re.match(r"(?:async\s+)?def\s", s):
            stack.append((ind, "def"))
        elif s.startswith("class "):
            stack.append((ind, "class"))
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
    base = path.rsplit("/", 1)[-1].lower()
    low = path.lower()
    if base == "install.py" or base == "setup.py":
        return "install"
    if base == "prestartup_script.py":
        return "startup"
    if low.endswith(PY_EXT):
        return "python"
    if low.endswith(JS_EXT):
        return "frontend"
    if low.endswith(SH_EXT):
        return "script"
    return None


def _scan_text(text, path, findings, info, kind):
    """Line pass + file-level combination rules. kind: install|startup|python|frontend|script."""
    text = _strip_blobs(text)
    lines = text.split("\n")
    loadtime = _py_contexts(lines) if kind == "python" else [kind in ("install", "startup")] * len(lines)
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
        for n, line in enumerate(lines, 1):
            s = line.lstrip()
            if sev != "info" and (s.startswith("#") or s.startswith("//") or s.startswith("* ")):
                continue  # comments describe; they don't execute
            m = None
            for w in _windows(line):
                m = rx.search(w)
                if m:
                    break
            if not m:
                continue
            if (pid, n) in seen:
                continue
            seen.add((pid, n))
            it = _item(sev.upper(), pid, pg["name"], pg["desc"], path, n, m.group(0), line if len(line) < 400 else m.group(0))
            it["loadtime"] = bool(loadtime[n - 1]) if n - 1 < len(loadtime) else False
            local.append(it)
            if pid in LINE_ONCE:
                seen.add((pid, 0))
                break
    # a pipe-to-shell inside a Python/JS string is only executed if a shell sink is next to it;
    # otherwise it is an install hint in an error message / docstring / UI text
    if kind in ("python", "install", "startup", "frontend"):
        file_sink = bool(SHELL_SINK.search(text))
        for f in local:
            if f["id"] != "download_execute" or f["severity"] == "INFO":
                continue
            near = "\n".join(lines[max(0, f["line"] - 4):f["line"]])
            if SHELL_SINK.search(near) and not re.match(r"\s*(?:iex|Invoke-Expression)\b", f["matched"], re.I) \
                    or re.search(r"\b(?:exec|eval)\s{0,4}\(|new\s+Function", f["matched"]):
                continue
            if file_sink:
                f["severity"] = "MEDIUM"
                f["description"] += " [in a string; a shell sink exists elsewhere in the file]"
            else:
                f["severity"] = "INFO"
                f["description"] += " [string only: shown to the user, never executed]"
    ids = {f["id"] for f in local}
    has_net = bool(NET_RE.search(text))

    def demote(pids):
        for f in local:
            if f["id"] in pids:
                f["severity"] = "INFO"

    def add(sev, pid, name, desc):
        local.append(_item(sev, pid, name, desc, path, 0, "", "file-level combination"))
        ids.add(pid)

    # ---- combination rules ---------------------------------------------------------------
    if "exfil_host" in ids and not has_net:
        demote({"exfil_host"})              # collector URL in a file that never sends: docs / test data
    if "env_dump" in ids and not has_net:
        demote({"env_dump"})                # env dump with no sink: debug print
    if "raw_ip_url" in ids and not ({"credential_read", "env_dump"} & ids):
        demote({"raw_ip_url"})              # self-hosted server defaults
    if "credential_read" in ids:
        if has_net and (STRONG_RE.search(text) or SOFT_RE.search(text) or RAWIP_RE.search(text)):
            add("CRITICAL", "credential_exfil", "Credential Exfiltration",
                "Reads a credential store and sends to a collector / tunnel / raw-IP endpoint in the same file")
        else:
            # reading cookies for a site's own login (e.g. browser_cookie3 for a gallery downloader) is a
            # capability; without a collector in the file it stays a reviewable MEDIUM
            for f in local:
                if f["id"] == "credential_read" and f["severity"] == "HIGH":
                    f["severity"] = "MEDIUM"
    if "env_dump" in ids and has_net and (STRONG_RE.search(text) or RAWIP_RE.search(text)):
        add("CRITICAL", "env_exfil", "Environment Exfiltration",
            "Serialises the environment and sends it to a hard-coded collector")
    # exec(<var>) of something fetched over the network in the same file
    if kind != "frontend" and has_net and EXEC_VAR_RE.search(text) and FETCH_BODY_RE.search(text) and \
            re.search(r"\b(?:exec|eval)\s{0,4}\(\s{0,4}(?:compile\s{0,4}\(\s{0,4})?(?:\w{1,30}\.(?:text|content|read\s{0,4}\(\s{0,4}\))|"
                      r"(?:code|payload|script|src|resp(?:onse)?|r|res|data|body|content)\b)", text):
        if SOFT_RE.search(text) or STRONG_RE.search(text) or RAWIP_RE.search(text) or "pastebin" in low:
            add("CRITICAL", "remote_code_exec", "Remote Code Execution",
                "Fetches code from a paste / raw / tunnel / raw-IP host and exec()s it")
        elif "download_execute" not in ids:
            add("HIGH", "remote_code_exec", "Remote Code Execution",
                "Fetches content over the network and passes it to exec/eval in the same file")
    # download a native binary, make it executable, run it
    if has_net and BIN_DL_RE.search(text) and (CHMOD_RE.search(text) or "subprocess" in ids or "os.startfile" in text):
        if not re.search(r"ffmpeg|ffprobe|realesrgan|7z|aria2|cloudflared|ngrok|frpc|gifski|exiftool|"
                         r"github\.com/[\w.-]+/[\w.-]+/releases/download", low):
            add("HIGH", "dropper", "Binary Dropper",
                "Downloads a native executable from a non-release URL, marks it executable and runs it")
    # secret-key regex + network: the faster_log / clipboard-stealer shape
    if KEY_RE.search(text) and has_net and (STRONG_RE.search(text) or RAWIP_RE.search(text)):
        add("CRITICAL", "key_harvest", "Private-Key Harvest",
            "Scans text for secret-key patterns and sends matches to a hard-coded collector")
    if kind == "frontend" and "browser_storage" in ids and has_net and STRONG_RE.search(text):
        add("CRITICAL", "browser_exfil", "Front-end Data Exfiltration",
            "Front-end code reads localStorage/cookies and talks to a hard-coded collector")

    # ---- load-time escalation --------------------------------------------------------------
    for f in local:
        if f["severity"] == "HIGH" and f["id"] not in ("exec_route", "dropper") and (
                kind in ("install", "startup") or f.get("loadtime") or f["line"] == 0 and kind != "frontend"):
            if f["line"] == 0 and kind == "python":
                continue  # file-level rule in a module: can't tell when it runs
            f["severity"] = "CRITICAL"
            f["description"] += {"install": " [runs at install]", "startup": " [runs before ComfyUI starts]"}.get(
                kind, " [runs at import]")
    for f in local:
        f["kind"] = kind
        (info if f["severity"] == "INFO" else findings).append(f)


# ---------------------------------------------------------------------------
# requirements.txt / pyproject dependencies
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
            wm = re.search(r"/([A-Za-z0-9_.]+?)-\d[^/]*\.whl", url.group(0))
            name = _norm(wm.group(1)) if wm else None
        if url:
            host_ok = re.search(OK_HOSTS, url.group(0), re.IGNORECASE)
            archive = re.search(r"\.(?:whl|zip|tar\.gz|tgz)(?:[#?]|$)", url.group(0), re.IGNORECASE)
            if name in PURE_PY and archive and not host_ok:
                findings.append(_item("HIGH", "shadow_wheel", "Shadow Wheel of a Pure-Python Package",
                                      "Pins a pure-Python package (%s) to a direct URL off PyPI - the "
                                      "ComfyUI_LLMVISION stealer shape" % name, path, n, url.group(0), line))
            elif not host_ok:
                info.append(_item("INFO", "direct_url_dep", "Direct-URL Dependency",
                                  "Dependency installed from a URL, not PyPI (prebuilt wheels / git installs)",
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


def _pyproject_deps(text):
    m = re.search(r"(?ms)^\s*dependencies\s*=\s*\[(.*?)\]", text)
    if not m:
        return ""
    return "\n".join(re.findall(r"['\"]([^'\"]+)['\"]", m.group(1)))


# ---------------------------------------------------------------------------
# Node-level scan
# ---------------------------------------------------------------------------
def scan_node(files, label=""):
    """files: {relative_path: text}. Returns an audit result dict."""
    findings, info = [], []
    total = 0
    py_blob = "\n".join(t for p, t in files.items() if p.lower().endswith(PY_EXT)).lower()
    order = sorted(files, key=lambda p: (file_kind(p) not in ("install", "startup"), p.count("/"), p))
    for path in order:
        low = path.lower()
        base = low.rsplit("/", 1)[-1]
        if re.search(r"(?:^|/)(?:tests?|docs?|examples?|\.github|\.buildkite|\.circleci|\.gitlab|ci|"
                     r"node_modules|site-packages|venv|\.venv)/", low):
            continue
        if base.startswith("requirements") and base.endswith(".txt"):
            scan_requirements(files[path], path, findings, info)
            continue
        if base == "pyproject.toml":
            deps = _pyproject_deps(files[path])
            if deps:
                scan_requirements(deps, path, findings, info)
            continue
        kind = file_kind(path)
        if not kind:
            continue
        if kind == "frontend" and re.search(r"(?:^|/)(?:lib|libs|vendor|third_party|dist|assets)/|\.min\.js$", low):
            kind_note = "vendored"
        else:
            kind_note = None
        total += len(files[path])
        if total > MAX_TOTAL:
            info.append(_item("INFO", "truncated", "Scan Truncated", "Node exceeds %d bytes of text" % MAX_TOTAL,
                              path, 0, "", ""))
            break
        before = len(findings)
        _scan_text(files[path], path, findings, info, kind)
        if kind == "script" and base not in py_blob:
            # a shell script nothing in the node invokes: a manual installer for humans, not code
            # ComfyUI runs. Reviewable, never scored above MEDIUM.
            for f in findings[before:]:
                if SEV_ORDER[f["severity"]] > SEV_ORDER["MEDIUM"]:
                    f["severity"] = "MEDIUM"
                    f["description"] += " [shell script not invoked by the node's Python]"
        if kind_note:
            # vendored / minified front-end libraries: keep only genuinely malicious shapes
            keep = {"download_execute", "obfuscated_exec", "exfil_host", "browser_exfil", "cryptominer",
                    "credential_exfil", "env_exfil", "key_harvest", "remote_code_exec"}
            moved = [f for f in findings[before:] if f["id"] not in keep]
            for f in moved:
                findings.remove(f)
                f["severity"] = "INFO"
                info.append(f)
    return _summarise(findings, info, label)


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


def scan(content, label="<text>", kind="startup"):
    """Scan a bare string. Treated as load-time Python by default (the conservative case)."""
    findings, info = [], []
    if label.lower().endswith(".txt"):
        scan_requirements(content, label, findings, info)
    else:
        _scan_text(content, label, findings, info, kind)
    return _summarise(findings, info, label)


# ---------------------------------------------------------------------------
# Loading targets (node code is never imported or executed)
# ---------------------------------------------------------------------------
UA = {"User-Agent": "comfyui-audit/%s (+https://github.com/eltociear/comfyui-audit)" % __version__}
KEEP_EXT = PY_EXT + JS_EXT + SH_EXT + (".txt", ".toml")


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
    return low.endswith(KEEP_EXT) and size <= MAX_FILE and "/node_modules/" not in "/" + low


def files_from_tarball(data):
    files, budget = {}, ArchiveBudget()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        for m in tf:
            name = safe_member(m.name)
            if not m.isreg() or not name:   # links, devices, FIFOs, traversal / absolute names
                continue
            parts = name.split("/")[1:]  # strip the <repo>-<sha>/ prefix
            if not parts:
                continue
            rel = "/".join(parts)
            if _keep(rel, m.size) and budget.take(m.size):
                files[rel] = tf.extractfile(m).read(MAX_FILE).decode("utf-8", "replace")
    return files


def files_from_dir(root):
    files = {}
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in (".git", "node_modules", "__pycache__", ".venv", "venv")]
        for fn in fns:
            p = os.path.join(dp, fn)
            if not regular_file(p):   # symlinks, FIFOs, devices: never opened
                continue
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            try:
                if _keep(rel, os.path.getsize(p)):
                    with open(p, encoding="utf-8", errors="replace") as fh:
                        files[rel] = fh.read()
            except OSError:
                continue
    return files


def _read_file(p, cap=MAX_FILE):
    with open(p, "rb") as fh:
        return fh.read(cap).decode("utf-8", "replace")


def _read_blob(p, cap=500000000):
    with open(p, "rb") as fh:
        return fh.read(cap)


def audit_github(spec):
    repo, _, ref = spec.partition("@")
    repo = re.sub(r"^https?://github\.com/", "", repo).strip("/")
    if repo.endswith(".git"):
        repo = repo[:-4]
    data = _get("https://codeload.github.com/%s/tar.gz/%s" % (repo, ref or "HEAD"))
    return scan_node(files_from_tarball(data), repo + ("@" + ref if ref else ""))


def registry_repos(limit=None):
    nodes = json.loads(_get(REGISTRY).decode("utf-8"))["custom_nodes"]
    out, seen = [], set()
    for n in nodes:
        ref = (n.get("reference") or "").rstrip("/")
        m = re.match(r"https://github\.com/([\w.-]+/[\w.-]+?)(?:\.git)?$", ref)
        if n.get("install_type") == "git-clone" and m and m.group(1).lower() not in seen:
            seen.add(m.group(1).lower())
            out.append(m.group(1))
    return out[:limit] if limit else out


_ICON = {"CRITICAL": "\U0001F534", "HIGH": "\U0001F7E0", "MEDIUM": "\U0001F7E1",
         "LOW": "\U0001F535", "SAFE": "\U0001F7E2"}


def _print(r, verbose):
    print("%s %s  [%s]  score=%d  (%d findings, %d info)" % (
        _ICON.get(r["risk_level"], "?"), r["target"], r["risk_level"], r["risk_score"],
        r["total_findings"], r["info_count"]))
    for f in r["findings"]:
        print("    %-8s %s  %s:%s" % (f["severity"], f["name"], f["file"], f["line"]))
        if f["context"] and f["line"]:
            print("             %s" % f["context"][:160])
    if verbose:
        for f in r["info"]:
            print("    info     %s  %s:%s" % (f["name"], f["file"], f["line"]))


# ---------------------------------------------------------------------------
# Pipeline output shared by the eltociear/*-audit family: --json / --sarif / --fail-on
# (this block is kept identical across the family; see "Output formats" in the README)
# ---------------------------------------------------------------------------
FAMILY_SCHEMA = "eltociear-audit/1"
TOOL_NAME = "comfyui-audit"
TOOL_URI = "https://github.com/eltociear/comfyui-audit"
FAIL_ON_CHOICES = ("critical", "high", "medium", "low", "never")
_FAM_RANK = {"SAFE": 0, "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_FAM_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
_FAM_SEC_SEV = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "3.0", "INFO": "0.0"}


def family_args(args):
    """Strip the shared output flags from argv. Returns (remaining_args, opts)."""
    opts = {"json": False, "sarif": False, "fail_on": "high"}
    rest, i = [], 0
    while i < len(args):
        a = args[i]
        if a == "--json":
            opts["json"] = True
        elif a == "--sarif":
            opts["sarif"] = True
        elif a == "--fail-on" or a.startswith("--fail-on="):
            if "=" in a:
                v = a.split("=", 1)[1]
            else:
                v = args[i + 1] if i + 1 < len(args) else ""
                i += 1
            if v.lower() not in FAIL_ON_CHOICES:
                sys.stderr.write("%s: --fail-on must be one of %s\n" % (TOOL_NAME, ", ".join(FAIL_ON_CHOICES)))
                raise SystemExit(1)
            opts["fail_on"] = v.lower()
        else:
            rest.append(a)
        i += 1
    return rest, opts


def _fam_sev(s):
    s = str(s or "").upper()
    return s if s in _FAM_RANK else "INFO"


def _fam_line(v):
    try:
        n = int(v)
    except (TypeError, ValueError):
        m = re.search(r"(\d+)\s*$", str(v or ""))
        n = int(m.group(1)) if m else 0
    return n if n > 0 else 0


def family_finding(f, target):
    out = dict(f) if isinstance(f, dict) else {"name": str(f)}
    rid = str(out.get("id") or out.get("rule_id") or out.get("pattern") or "finding")
    out.update({"rule_id": rid, "severity": _fam_sev(out.get("severity")),
                "name": str(out.get("name") or rid), "description": str(out.get("description") or ""),
                "file": str(out.get("file") or out.get("path") or ""), "line": _fam_line(out.get("line")),
                "matched": str(out.get("matched") or ""), "context": str(out.get("context") or "")})
    return out


def family_result(r):
    out = dict(r)
    target = str(out.get("target") or "")
    findings = [family_finding(f, target) for f in (out.get("findings") or [])]
    info = [family_finding(f, target) for f in (out.get("info") or [])]
    worst = max([_FAM_RANK[f["severity"]] for f in findings] + [_FAM_RANK.get(str(out.get("risk_level") or "").upper(), 0)])
    level = next(k for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE") if _FAM_RANK[k] == worst)
    counts = {k: sum(1 for f in findings if f["severity"] == k) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    out.update({"target": target, "risk_level": level, "risk_score": int(out.get("risk_score") or 0),
                "error": out.get("error") or None, "counts": counts, "findings": findings, "info": info})
    return out


def family_exit(results, fail_on="high"):
    """0 = below the threshold, 2 = a target reached it. Default threshold HIGH (the historic behaviour)."""
    if fail_on == "never":
        return 0
    worst = max([_FAM_RANK[family_result(r)["risk_level"]] for r in results] or [0])
    return 2 if worst >= _FAM_RANK[fail_on.upper()] else 0


def family_json(results, fail_on="high"):
    res = [family_result(r) for r in results]
    worst = max([_FAM_RANK[r["risk_level"]] for r in res] or [0])
    return {"schema": FAMILY_SCHEMA, "tool": {"name": TOOL_NAME, "version": __version__},
            "fail_on": fail_on, "exit_code": family_exit(results, fail_on),
            "max_severity": next(k for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE") if _FAM_RANK[k] == worst),
            "errors": sum(1 for r in res if r["error"]), "results": res}


def _fam_uri(target, file):
    """Repo-relative URI when the target is a local path, else the in-package path."""
    file = (file or "").replace("\\", "/")
    t = target or ""
    if t and os.path.isdir(t):
        p = os.path.normpath(os.path.join(t, file)) if file else os.path.normpath(t)
        parts = file.split("/")
        for k in range(1, len(parts)):   # scanner-side prefixes (e.g. custom_components/<d>/) not on disk
            if not os.path.exists(p) and os.path.exists(os.path.join(t, *parts[k:])):
                p = os.path.normpath(os.path.join(t, *parts[k:]))
    elif t and os.path.isfile(t) and (not file or file == t or file == os.path.basename(t)):
        p = os.path.normpath(t)
    elif t and os.path.isfile(t):
        p = os.path.normpath(t).replace("\\", "/") + "/" + file  # member of a local archive
    else:
        p = file or t or "unknown"
    p = p.replace("\\", "/")
    if os.path.isabs(p):
        try:
            rel = os.path.relpath(p)
        except ValueError:
            rel = None
        if rel is not None and not rel.startswith(".."):
            p = rel.replace("\\", "/")
        else:
            return "file://" + urllib.parse.quote(p, safe="/:")
    parts = [s for s in p.split("/") if s not in ("", ".", "..")]
    return urllib.parse.quote("/".join(parts) or "unknown", safe="/@+,;=-._~")


def family_sarif(results):
    rules, index, out, notes = [], {}, [], []
    for r in (family_result(x) for x in results):
        if r["error"]:
            notes.append({"level": "error", "message": {"text": "%s: %s" % (r["target"], r["error"])}})
        for f in r["findings"]:
            sev, rid = f["severity"], f["rule_id"]
            if rid not in index:
                index[rid] = len(rules)
                rules.append({"id": rid, "name": "".join(w.capitalize() for w in re.split(r"[^A-Za-z0-9]+", rid) if w) or "Finding",
                              "shortDescription": {"text": f["name"]},
                              "fullDescription": {"text": f["description"] or f["name"]},
                              "helpUri": TOOL_URI + "#readme",
                              "defaultConfiguration": {"level": _FAM_SARIF_LEVEL[sev]},
                              "properties": {"tags": ["security", TOOL_NAME], "security-severity": _FAM_SEC_SEV[sev]}})
            else:
                rule = rules[index[rid]]
                if float(_FAM_SEC_SEV[sev]) > float(rule["properties"]["security-severity"]):
                    rule["properties"]["security-severity"] = _FAM_SEC_SEV[sev]
                    rule["defaultConfiguration"]["level"] = _FAM_SARIF_LEVEL[sev]
            phys = {"artifactLocation": {"uri": _fam_uri(r["target"], f["file"])}}
            if f["line"]:
                phys["region"] = {"startLine": f["line"]}
                if f["context"]:
                    phys["region"]["snippet"] = {"text": f["context"]}
            msg = "%s: %s%s" % (sev, f["description"] or f["name"], (" [%s]" % f["matched"]) if f["matched"] else "")
            fp = "%s|%s|%s|%s" % (r["target"], rid, f["file"], f["matched"] or f["line"])
            out.append({"ruleId": rid, "ruleIndex": index[rid], "level": _FAM_SARIF_LEVEL[sev],
                        "message": {"text": msg}, "locations": [{"physicalLocation": phys}],
                        "partialFingerprints": {"auditFinding/v1": hashlib.sha256(fp.encode("utf-8", "replace")).hexdigest()[:32]},
                        "properties": {"severity": sev, "target": r["target"]}})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": TOOL_NAME, "version": __version__, "semanticVersion": __version__,
                                          "informationUri": TOOL_URI, "rules": rules}},
                      "invocations": [{"executionSuccessful": not notes, "toolExecutionNotifications": notes}],
                      "results": out}]}


def family_emit(results, opts):
    """Print --json / --sarif output (if requested) and return the process exit code."""
    if opts.get("sarif"):
        print(json.dumps(family_sarif(results), indent=1, ensure_ascii=False))
    elif opts.get("json"):
        print(json.dumps(family_json(results, opts["fail_on"]), indent=1, ensure_ascii=False))
    return family_exit(results, opts["fail_on"])


# ---------------------------------------------------------------------------
# Untrusted-input hygiene shared by the family (nothing is ever extracted to disk)
# ---------------------------------------------------------------------------
MAX_MEMBERS = 50000             # archive entries considered per target
MAX_ARCHIVE_TOTAL = 300000000   # decompressed bytes read per archive (zip/tar bomb budget)


def safe_member(name):
    """Normalise an archive member name; None for traversal (../), absolute, drive or NUL paths."""
    n = (name or "").replace("\\", "/")
    if "\x00" in n or n.startswith("/") or re.match(r"^[A-Za-z]:", n):
        return None
    parts = [p for p in n.split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        return None
    return "/".join(parts)


def regular_file(path):
    """True only for a real regular file (no symlinks, FIFOs, devices or sockets)."""
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False


class ArchiveBudget:
    """Caps entries and total decompressed bytes read from one archive."""

    def __init__(self, total=None, members=None):
        self.left = MAX_ARCHIVE_TOTAL if total is None else total
        self.members = MAX_MEMBERS if members is None else members
        self.truncated = False

    def take(self, size):
        self.members -= 1
        if self.members < 0 or size > self.left:
            self.truncated = True
            return False
        self.left -= size
        return True


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if args[0] == "--version":
        print(TOOL_NAME, __version__)
        return 0
    args, fam = family_args(args)
    as_json = fam["json"] or fam["sarif"]
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
    elif args[0] == "--registry":
        for repo in registry_repos(limit):
            targets.append((repo, (lambda s=repo: audit_github(s))))
    elif args[0] == "--comfyui-dir":
        root = args[1]
        cn = os.path.join(root, "custom_nodes") if os.path.isdir(os.path.join(root, "custom_nodes")) else root
        for d in sorted(os.listdir(cn)):
            p = os.path.join(cn, d)
            if os.path.isdir(p) and not d.startswith((".", "__")):
                targets.append((d, (lambda p=p, d=d: scan_node(files_from_dir(p), d))))
            elif d.endswith(".py") and regular_file(p):
                targets.append((d, (lambda p=p, d=d: scan(_read_file(p), d, "python"))))
    else:
        for a in args:
            if os.path.isdir(a):
                targets.append((a, (lambda p=a: scan_node(files_from_dir(p), p))))
            elif os.path.isfile(a):
                if a.endswith((".tar.gz", ".tgz", ".tar")):
                    targets.append((a, (lambda p=a: scan_node(files_from_tarball(_read_blob(p)), p))))
                else:
                    targets.append((a, (lambda p=a: scan(_read_file(p), p,
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
                print("\u26AA %s  [ERROR] %s" % (label, r["error"]))
        else:
            if not as_json:
                _print(r, verbose)
        results.append(r)
        if SEV_ORDER[r["risk_level"]] > SEV_ORDER[worst]:
            worst = r["risk_level"]
    return family_emit(results, fam)


if __name__ == "__main__":
    sys.exit(main())
