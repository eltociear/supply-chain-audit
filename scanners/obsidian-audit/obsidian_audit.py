#!/usr/bin/env python3
"""obsidian-audit - scan Obsidian community plugins for MALICIOUS patterns before you enable them.

On desktop, an Obsidian community plugin is a JavaScript bundle (main.js) running inside
Electron with full Node.js access: it can read any file your user account can read, spawn
processes, and talk to any host. Obsidian reviews a plugin when it is first submitted, but
later releases are published straight from the author's GitHub repo and are not re-reviewed.
This is a deterministic (no LLM) static scan of the published main.js for the things that
matter: remote code loading, credential and browser/wallet theft, exfiltration endpoints,
vault contents sent to collectors, obfuscated code, client-side telemetry, crypto miners,
reverse shells and wipers.

Precision-tuned to near-zero false positives on the real plugin directory: capabilities that
popular plugins use every day (child_process for git/pandoc, fs reads outside the vault,
network sync, bundled libraries' `new Function("return this")`) are reported as INFO context
and never inflate the risk score. Risk comes from specific sinks and COMBINATIONS
(downloaded text -> eval, credential read + collector host, vault read + collector host).

Plugin code is never executed: files are read as text.

Usage:
  python obsidian_audit.py <plugin-dir|main.js> [...]   # scan local plugin(s)
  python obsidian_audit.py --vault ~/Notes               # every plugin in <vault>/.obsidian/plugins
  python obsidian_audit.py --plugin dataview [...]       # fetch the latest release by plugin id
  python obsidian_audit.py --repo owner/name             # fetch the latest release of a repo
  python obsidian_audit.py --all [--limit N]             # the whole community directory, by downloads
  python obsidian_audit.py --text "some code"            # scan a string
  add --json (family schema) or --sarif (SARIF 2.1.0) for machine-readable output,
  --fail-on {critical,high,medium,low,never}, --version, --verbose to print INFO context

Exit code 2 if any target reaches --fail-on (default HIGH; CI-friendly), 1 on usage errors.
No dependencies beyond the standard library. MIT licensed.
"""
import bisect
import hashlib
import json
import os
import re
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

__version__ = "0.2.0"

RELEASES = "https://raw.githubusercontent.com/obsidianmd/obsidian-releases/HEAD/"
MAX_FILE = 256000000    # bytes; the largest main.js in the directory is ~128 MB (embedded wasm)
MAX_HITS = 20         # findings kept per signature per file
SEG = 8192            # regex window (bytes); minified bundles are one multi-MB line
SEG_OVERLAP = 1024    # overlap between windows of a cut line (longest signature span < 1 KB)

# Endpoints that legitimate plugins essentially never hard-code, but stealers love:
# chat webhooks, paste sites, request bins, tunnels and out-of-band (OAST) collectors.
# Only HARD-CODED collector URLs count: a webhook with its id+token baked in, a bot token in
# the URL, a tunnel/OAST *subdomain*. A Telegram plugin calling api.telegram.org/bot${token}
# with the user's own token, or a dev-server allow-list containing the bare string "ngrok.io",
# is not exfiltration (both appear in popular plugins).
EXFIL_HOST = (
    r"(?:discord(?:app)?\.com/api/webhooks/\d{15,}/[\w-]{20,}|api\.telegram\.org/bot\d{6,}:[\w-]{30,}|"
    r"hooks\.slack\.com/services/T\w{6,}/B\w{6,}/\w{12,}|webhook\.site/[0-9a-f]{8}-|"
    r"https?://[\w-]+\.(?:m\.pipedream\.net|requestcatcher\.com|free\.beeceptor\.com|requestbin\.(?:net|com))|"
    r"requestb\.in/\w{6,}|pastebin\.com/api/api_post|paste\.ee/api|hastebin\.com/documents|"
    r"https?://[\w-]+\.(?:ngrok(?:-free)?\.(?:io|app|dev)|trycloudflare\.com|serveo\.net|loca\.lt|localtunnel\.me)|"
    r"[\w-]{6,}\.(?:oastify\.com|oast\.(?:fun|me|pro|live|site|online)|interact\.sh|burpcollaborator\.net|dnslog\.cn|ceye\.io|requestrepo\.com)|"
    r"canarytokens\.com/\w+/\w{10,})"
)
# Cheap substring pre-filter per pattern group (lower-cased bundle). A group whose needles
# never occur is skipped without running its regexes: most of a 5 MB bundle is irrelevant.
NEEDLES = {
    "download_execute": ("curl", "wget", "iex", "invoke-expression", "powershell"),
    "remote_code_load": ("eval", "new function"),
    "env_exfil": ("process.env",),
    "reverse_shell": ("/dev/tcp", "bash -i", "nc ", "ncat", ".pipe("),
    "destructive": ("rm ", "rmsync", "rmdirsync", "rimraf"),
    "cryptominer": ("stratum", "coinhive", "cryptonight", "xmrig", "minexmr", "nanopool", "supportxmr"),
    "exfil_host": ("discord", "telegram.org", "hooks.slack", "webhook.site", "pipedream", "requestcatcher",
                   "beeceptor", "requestbin", "requestb.in", "pastebin", "paste.ee", "hastebin", "ngrok",
                   "trycloudflare", "serveo", "loca.lt", "localtunnel", "oast", "interact.sh", "burpcollab",
                   "dnslog", "ceye", "requestrepo", "canarytokens"),
    "wallet_browser_theft": ("nkbihfbeog", "bfnaelmome", "hnfanknocf", "ibnejdfjmm", "egjidjbpgl", "login data",
                             "web data", "cookies", "local state", "exodus", "atomic", "electrum", "ethereum",
                             "solana", "wallet.dat", "seed.seco"),
    "obfuscation": ("eval", "new function"),
    "dns_exfil": ("dns.",),
    "auth_bypass": ("node_tls_reject_unauthorized",),
    "raw_ip_url": ("http",),
    "telemetry": ("google-analytics", "googletagmanager", "segment.io", "mixpanel", "posthog", "amplitude",
                  "plausible", "umami", "sentry", "bugsnag", "datadoghq", "lr-ingest", "aptabase",
                  "telemetrydeck", "clarity.ms", "hotjar", "countly"),
    "keychain_read": ("find-generic-password", "find-internet-password", "cmdkey", "get-storedcredential"),
    "credential_read": (".ssh", ".aws", ".npmrc", ".git-credentials", ".docker", ".kube"),
    "other_vaults": ("obsidian.json",),
    "plugin_write": ("plugins/",),
    "obfuscation_lite": ("\\x",),
    "tls_off": ("rejectunauthorized",),
    "electron": ("electron",),
    "child_process": ("child_process", "execsync", "spawnsync"),
    "node_fs": ('fs"', "fs'", "fs/promises"),
    "network": ("request", "fetch", "axios", "xmlhttprequest", "net.", "websocket", "sendbeacon", "dns."),
    "dynamic_code": ("eval", "new function"),
    "outside_vault": ("homedir", "process.env", "getpath"),
    "vault_enum": (".vault.",),
}
# A pipe-to-shell string is only an attack when it is handed to a process spawner.
EXEC_NEAR = re.compile(r"(?:\bexec(?:Sync|File|FileSync)?|\bspawn(?:Sync)?)\s*\(|shell\s*:\s*(?:!0|true)|[\"']-c[\"']")
# javascript-obfuscator "string array" calls with RC4 keys: Pt(1082,"8F&P")
RC4_CALL = re.compile(r"\b[\w$]{1,3}\(\s{0,4}(?:0x[0-9a-f]{1,8}|\d{2,4})\s{0,4},\s{0,4}[\"'](?=[^\"'\n]{0,3}[^\w\s\"'])[^\"'\\\n]{4}[\"']\s{0,4}\)")
RAW_IP_URL = (r"https?://(?!(?:127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|"
              r"1\.1\.1\.1|8\.8\.8\.8|255\.))\d{1,3}(?:\.\d{1,3}){3}[:/]")
NET_SEND = (r"(?:\brequestUrl\s*\(|\brequest\s*\(\s*\{|\.(?:requestUrl|request|fetch)\s*\)\s*\(|https?\.request\s*\(|https?\.get\s*\(|\bfetch\s*\(|"
            r"axios(?:\.\w+)?\s*\(|XMLHttpRequest|net\.connect|new\s+net\.Socket|new\s+WebSocket\s*\(|"
            r"navigator\.sendBeacon|dns\.(?:lookup|resolve\w*)\s*\()")
# Client-side analytics / telemetry SDK endpoints. Obsidian's developer policies do not allow
# client-side telemetry; a disclosed one is LOW, an undisclosed one MEDIUM.
TELEMETRY_HOST = (
    r"(?:google-analytics\.com/(?:g/)?collect|www\.googletagmanager\.com/gtag|api\.segment\.io|"
    r"api(?:-js)?\.mixpanel\.com|(?:us|eu|app)\.i?\.?posthog\.com|api2?\.amplitude\.com|plausible\.io/api/event|"
    r"cloud\.umami\.is|api-gateway\.umami\.dev|\.ingest(?:\.us|\.de)?\.sentry\.io|sessions\.bugsnag\.com|"
    r"browser-intake-datadoghq|r\.lr-ingest\.io|api\.aptabase\.com|nom\.telemetrydeck\.com|"
    r"\.clarity\.ms/collect|static\.hotjar\.com|api\.countly|eu\.posthog\.com|us\.posthog\.com|app\.posthog\.com)"
)
TELEMETRY_WORDS = re.compile(r"telemetry|analytics|tracking|usage (?:data|statistics|stats)|anonymous(?:ly)? (?:usage|data|statistics)|"
                             r"posthog|mixpanel|segment|amplitude|plausible|umami|sentry|crash report|error report|aptabase|telemetrydeck",
                             re.IGNORECASE)

PATTERNS = {
    "critical": [
        {"id": "download_execute", "name": "Download & Execute",
         "desc": "Fetches remote content and pipes it straight into a shell/interpreter",
         "regexes": [
             r"curl\s+[^\n|;\"'`]{0,200}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?|node)\b(?!\s*-c\s*[\"'][^\"']{0,200}\$\()",
             r"wget\s+[^\n|;\"'`]{0,200}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?|node)\b",
             r"(?:sh|bash|python3?|node)\s*<\s*\(\s*(?:curl|wget)\s",
             r"(?:iex|Invoke-Expression)\s*\(?\s*\(?\s*(?:New-Object\s+Net\.WebClient|iwr\s|Invoke-WebRequest)",
             r"powershell[^\n]{0,40}\s-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{60,}",
         ]},
        {"id": "remote_code_load", "name": "Remote Code Load",
         "desc": "Evaluates code it just downloaded (fetch/requestUrl -> eval / new Function)",
         "regexes": [
             r"(?:\beval|new\s+Function)\s*\(\s*(?:await\s+)?\(?\s*(?:await\s+)?(?:\(\s*await\s+)?(?:requestUrl|fetch|request)\s*\(",
             r"(?:requestUrl|fetch)\s*\([^\n]{0,300}?\)\s*(?:\)\s*)?\.(?:text|json)\b[^\n]{0,200}?\.then\s*\(\s*(?:\(\s*)?\w+\s*\)?\s*=>\s*(?:\beval|new\s+Function)\s*\(",
             r"(?:requestUrl\s*\([^\n]{0,300}?\)\s*\)?\s*\.text|await\s+\w+\.text\s*\(\s*\))[^\n]{0,160}?;\s*(?:\w+\s*=\s*)?(?:\beval|new\s+Function)\s*\(",
         ]},
        {"id": "env_exfil", "name": "Environment Dump",
         "desc": "Serialises the whole process.env (every token/secret)",
         "regexes": [
             r"JSON\.stringify\s*\(\s*process\.env\s*[,)]",
             r"Buffer\.from\s*\(\s*JSON\.stringify\s*\(\s*process\.env",
             r"querystring\.stringify\s*\(\s*process\.env",
         ]},
        {"id": "reverse_shell", "name": "Reverse Shell",
         "desc": "Spawns an interactive shell bound to a network socket",
         "regexes": [
             r"/dev/tcp/[\w.\-]+/\d+",
             r"bash\s+-i\s*>&",
             r"\bnc(?:at)?\s+(?:-\w+\s+){0,4}-e\s+/bin/(?:ba)?sh",
             r"spawn\s*\(\s*[\"'](?:/bin/)?(?:ba|z)?sh[\"'][^\n]{0,200}\.pipe\s*\(\s*(?:client|socket|sock|conn)\b",
             r"\b(?:client|socket|sock|conn)\.pipe\s*\(\s*\w+\.stdin\s*\)",
         ]},
        {"id": "destructive", "name": "Destructive Payload",
         "desc": "Wipes the home directory / filesystem",
         "regexes": [
             r"rm\s+-[a-zA-Z]{0,8}r[a-zA-Z]{0,8}\s+(?:--no-preserve-root\s+)?(?:~|\$HOME|/)(?:\s|[\"'`;]|$)",
             r"(?:rmSync|rmdirSync|rimraf\w*)\s*\(\s*(?:\w+\.)?homedir\s*\(\s*\)\s*[,)]",
             r"(?:rmSync|rmdirSync)\s*\(\s*[\"']/[\"']",
         ]},
        {"id": "cryptominer", "name": "Crypto Miner",
         "desc": "Mining pool / miner payload references",
         "regexes": [
             r"stratum\+(?:tcp|ssl)://",
             r"\b(?:coinhive|cryptonight|xmrig|minexmr|nanopool\.org|supportxmr)\b",
         ]},
    ],
    "high": [
        {"id": "exfil_host", "name": "Exfiltration Endpoint",
         "desc": "Hard-codes a webhook / paste / tunnel / OAST collector host",
         "regexes": [EXFIL_HOST]},
        {"id": "wallet_browser_theft", "name": "Wallet / Browser Data Theft",
         "desc": "Targets crypto-wallet extension storage, browser credential stores or the Keychain",
         "regexes": [
             r"nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|hnfanknocfeofbddgcijnmhnfnkdnaad|ibnejdfjmmkpcnlpebklmnkoeoihofec|egjidjbpglichdcondbcbdnbeeppgdph",
             r"[\"'](?:Login Data|Web Data|Cookies|Local State)[\"'][^\n]{0,120}(?:Chrome|Brave|Edge|Opera|Chromium|readFile|copyFile)",
             r"(?:Google/Chrome|BraveSoftware|Microsoft/Edge|Opera Software)[^\n]{0,80}(?:Login Data|Local Extension Settings|Cookies)",
             r"(?:Exodus|atomic|Electrum|Ethereum)[/\\\\](?:exodus\.wallet|Local Storage|wallets|keystore)",
             r"\.config[/\\\\]solana[/\\\\]id\.json",
             r"\b(?:wallet\.dat|seed\.seco)\b",
         ]},
        {"id": "obfuscation", "name": "Obfuscated Code",
         "desc": "eval of decoded strings, packed eval, long escape blobs (obfuscation is against Obsidian's developer policies)",
         "regexes": [
             r"(?:\beval|new\s+Function)\s*\(\s*(?:atob|unescape|decodeURIComponent)\s*\(",
             r"(?:\beval|new\s+Function)\s*\(\s*Buffer\.from\s*\([^)]{0,900},\s*[\"'](?:base64|hex)[\"']",
             r"(?:\beval|new\s+Function)\s*\(\s*[\"'](?:\\x[0-9a-fA-F]{2}){20,}",
             r"(?:\beval|new\s+Function)\s*\(\s*String\.fromCharCode\s*\(",
             r"\beval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)",
         ]},
        {"id": "dns_exfil", "name": "DNS Exfiltration",
         "desc": "Encodes host/user data into a DNS lookup",
         "regexes": [
             r"dns\.(?:lookup|resolve\w*)\s*\([^\n]{0,160}(?:hostname\s*\(|userInfo\s*\(|homedir\s*\(|process\.env|toString\s*\(\s*[\"']hex)",
         ]},
        {"id": "auth_bypass", "name": "TLS Verification Disabled Globally",
         "desc": "Sets NODE_TLS_REJECT_UNAUTHORIZED=0 for the whole Electron process",
         "regexes": [r"NODE_TLS_REJECT_UNAUTHORIZED[\"']?\s*\]?\s*=\s*[\"']?0"]},
    ],
    "medium": [
        {"id": "raw_ip_url", "name": "Raw-IP URL",
         "desc": "Contacts a public IP address directly instead of a hostname",
         "regexes": [RAW_IP_URL]},
        {"id": "keychain_read", "name": "Keychain Secret Read",
         "desc": "Reads another app's secret from the macOS Keychain / Windows Credential Manager (CRITICAL with a collector endpoint)",
         "regexes": [r"security\s+find-(?:generic|internet)-password\s", r"\bcmdkey\s+/list", r"Get-StoredCredential\b"]},
        {"id": "telemetry", "name": "Client-Side Telemetry",
         "desc": "Sends analytics/telemetry to a third-party SDK endpoint",
         "regexes": [TELEMETRY_HOST]},
    ],
    "low": [],
    # Context: reported, never scored. Popular plugins do all of these legitimately.
    "info": [
        {"id": "child_process", "name": "Process Spawning",
         "desc": "Uses child_process (git, pandoc, shell-command plugins all do)",
         "regexes": [r"require\s*\(\s*[\"'](?:node:)?child_process[\"']\s*\)", r"\bexecSync\s*\(", r"\bspawnSync\s*\("]},
        {"id": "node_fs", "name": "Raw Filesystem Access",
         "desc": "Uses Node's fs module directly (can reach files outside the vault)",
         "regexes": [r"require\s*\(\s*[\"'](?:node:)?fs(?:/promises)?[\"']\s*\)"]},
        {"id": "outside_vault", "name": "Outside-Vault Path",
         "desc": "Builds paths from the home directory / OS app-data dirs",
         "regexes": [r"\bhomedir\s*\(\s*\)", r"process\.env\.(?:HOME|USERPROFILE|APPDATA|LOCALAPPDATA)\b",
                     r"\.getPath\s*\(\s*[\"'](?:home|appData|userData|desktop|documents|downloads)[\"']"]},
        {"id": "credential_read", "name": "Credential Store Reference",
         "desc": "References ~/.ssh, ~/.aws, ~/.npmrc, .git-credentials (git plugins do this legitimately)",
         "regexes": [r"\.ssh[/\\\\]id_\w+", r"\.aws[/\\\\]credentials", r"\.npmrc\b", r"\.git-credentials",
                     r"\.docker[/\\\\]config\.json", r"\.kube[/\\\\]config"]},
        {"id": "other_vaults", "name": "Vault Registry Access",
         "desc": "References obsidian.json, the list of all your vaults",
         "regexes": [r"obsidian[/\\\\]obsidian\.json", r"[\"']obsidian\.json[\"']"]},
        {"id": "vault_enum", "name": "Whole-Vault Read",
         "desc": "Enumerates and reads every note",
         "regexes": [r"\.vault\.(?:getMarkdownFiles|getFiles|getAllLoadedFiles)\s*\(\s*\)"]},
        {"id": "plugin_write", "name": "Plugin Directory Write",
         "desc": "Writes into .obsidian/plugins (plugin managers/updaters do this)",
         "regexes": [r"(?:configDir|\.obsidian)[^\n]{0,40}[\"'/]plugins/[^\n]{0,120}(?:main\.js|manifest\.json)[^\n]{0,120}(?:write|adapter\.write|writeFile)",
                     r"(?:write|writeFile)\w*\s*\([^\n]{0,160}plugins/[^\n]{0,80}main\.js"]},
        {"id": "network", "name": "Network Access",
         "desc": "Makes outbound HTTP/WebSocket/DNS calls",
         "regexes": [NET_SEND]},
        {"id": "dynamic_code", "name": "Dynamic Code",
         "desc": "eval / new Function on a non-literal (bundlers and template engines do this)",
         "regexes": [r"\beval\s*\(\s*(?![\"'`)])", r"new\s+Function\s*\(\s*(?![\"'`)]\s*return\s+this)"]},
        {"id": "obfuscation_lite", "name": "Encoded Strings",
         "desc": "Long escape/base64 blobs without an eval sink (fonts, wasm, images)",
         "regexes": [r"(?:\\x[0-9a-fA-F]{2}){24,}"]},
        {"id": "tls_off", "name": "TLS Verification Disabled (per request)",
         "desc": "rejectUnauthorized:false (self-hosted servers with self-signed certs)",
         "regexes": [r"rejectUnauthorized\s*:\s*(?:false|!1)"]},
        {"id": "electron", "name": "Electron Internals",
         "desc": "Uses electron remote / session / webContents APIs",
         "regexes": [r"require\s*\(\s*[\"']electron[\"']\s*\)", r"@electron/remote"]},
    ],
}

SEVERITY_SCORE = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "SAFE": 0}
_UNBOUNDED = [(r"\s*", r"\s{0,16}"), (r"\s+", r"\s{1,16}"), (r"\w*", r"\w{0,40}"), (r"\w+", r"\w{1,64}"),
              (r"[\w-]+", r"[\w-]{1,63}"), (r"[\w.\-]+", r"[\w.\-]{1,253}"), (r"\d+", r"\d{1,12}")]


def _bound(rx):
    """Rewrite every open-ended repeat into a bounded one, so no signature can backtrack
    super-linearly even on pathological input (e.g. a multi-KB whitespace run inside a
    window). Signatures stay readable in source; the compiled form is fully bounded."""
    for a, b in _UNBOUNDED:
        rx = rx.replace(a, b)
    return rx


_COMPILED = [(sev, pg, re.compile(_bound(rx), re.IGNORECASE if pg["id"] not in ("obfuscation",) else 0))
             for sev, groups in PATTERNS.items() for pg in groups for rx in pg["regexes"]]
ONCE_PER_FILE = {"network", "child_process", "node_fs", "outside_vault", "electron", "dynamic_code",
                 "vault_enum", "obfuscation_lite", "tls_off"}
OBF_IDENT = re.compile(r"\b_0x[0-9a-f]{4,6}\b")
RAWIP_RE = re.compile(RAW_IP_URL)


def _stmt_before(text, pos):
    """The current statement up to pos: back to the previous ; { } or newline (max 160 chars)."""
    seg = text[max(0, pos - 160):pos]
    cut = max(seg.rfind(c) for c in ";{}\n")
    return seg[cut + 1:]


def _item(sev, pid, name, desc, path, line, matched="", context=""):
    return {"severity": sev, "id": pid, "name": name, "description": desc, "file": path,
            "line": line, "matched": matched[:120], "context": context[:200]}


# Long base64 / hex / escape runs are embedded data (wasm, fonts, images): 71% of the largest
# bundle in the directory is such runs. They can never contain a signature, so they are
# collapsed to a placeholder before matching. The text around them (e.g. `eval(atob("<blob>"))`
# or `Buffer.from("<blob>", "base64")`) is kept, so decode->eval detection still works.
BLOB_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{4096,}|(?<!\\x[0-9a-fA-F]{2})(?:\\x[0-9a-fA-F]{2}){1024,}|"
                     r"(?<!\\u[0-9a-fA-F]{4})(?:\\u[0-9a-fA-F]{4}){1024,}|(?<!%[0-9a-fA-F]{2})(?:%[0-9a-fA-F]{2}){1024,}")


def _strip_blobs(text):
    count = [0, 0]

    def rep(m):
        count[0] += 1
        count[1] += len(m.group(0))
        return "<blob:%d>" % len(m.group(0))
    if len(text) < 4096:
        return text, 0, 0
    out = BLOB_RE.sub(rep, text)
    return out, count[0], count[1]


def _segments(text):
    """Cut text into bounded windows: whole lines packed up to SEG bytes, and any single line
    longer than SEG (minified bundles are one multi-MB line) split into SEG windows that
    overlap by SEG_OVERLAP so a match straddling a cut is still seen. Yields (offset, line, s).
    Every regex therefore runs on <= SEG bytes at a time: worst-case cost is bounded per
    window no matter how a bundle is laid out."""
    pos, line, n = 0, 1, len(text)
    while pos < n:
        end = min(n, pos + SEG)
        if end < n:
            nl = text.rfind("\n", pos, end)
            if nl > pos:
                end = nl + 1
        seg = text[pos:end]
        yield pos, line, seg
        line += seg.count("\n")
        if end < n and not seg.endswith("\n"):
            # mid-line cut: step back for overlap, line number unchanged
            pos = end - SEG_OVERLAP
            line -= seg[-SEG_OVERLAP:].count("\n")
        else:
            pos = end


def _scan_text(text, path, findings, info):
    """Windowed pass over the bundle (see _segments); each signature is also bounded
    ([^\\n]{0,N}, no nested quantifiers), so a scan is linear in bundle size."""
    seen = set()
    text, nblobs, blob_bytes = _strip_blobs(text)
    if nblobs:
        info.append(_item("INFO", "embedded_blob", "Embedded Binary Blobs",
                          "%d base64/hex blob(s) of >= 4 KB (%d bytes: wasm, fonts, images) - data, replaced "
                          "by placeholders before pattern matching" % (nblobs, blob_bytes), path, 0))
    low = text.lower()
    # Needle positions, found once per bundle with str.find (C speed, cost ~ #occurrences);
    # a window is only matched against a signature group if one of its needles lies inside.
    npos = {}
    for nd in NEEDLES.values():
        for nee in nd:
            if nee in npos:
                continue
            ps, i = [], low.find(nee)
            while i >= 0:
                ps.append(i)
                i = low.find(nee, i + 1)
            npos[nee] = ps
    active = []
    for sev, pg, rx in _COMPILED:
        nd = NEEDLES.get(pg["id"])
        nd = None if nd is None else tuple(n for n in nd if npos[n])
        if nd is None or nd:
            active.append((sev, pg, rx, nd))

    def near(nd, a, b):
        for nee in nd:
            ps = npos[nee]
            j = bisect.bisect_left(ps, a)
            if j < len(ps) and ps[j] < b:
                return True
        return False
    hits = {}
    done = set()
    for off, line0, seg in _segments(text):
        end = off + len(seg)
        for sev, pg, rx, nd in active:
            pid = pg["id"]
            if pid in done or (nd is not None and not near(nd, off, end)):
                continue
            for m in rx.finditer(seg):
                a = off + m.start()
                n = line0 + seg.count("\n", 0, m.start())
                key = (pid, n, a // 4096)
                if key in seen or (pid, a) in seen:
                    continue
                seen.add(key)
                seen.add((pid, a))
                if pid == "download_execute" and not EXEC_NEAR.search(_stmt_before(text, a)):
                    # pipe-to-shell shown to the user (install hint, docs string), not run
                    sev_eff = "medium" if "child_process" in low else "info"
                else:
                    sev_eff = sev
                ls = seg.rfind("\n", 0, m.start()) + 1
                le = seg.find("\n", m.end())
                le = len(seg) if le < 0 else le
                ctx = seg[max(ls, m.start() - 70):min(le, m.end() + 70)] if le - ls > 300 else seg[ls:le]
                desc = pg["desc"] if sev_eff == sev else pg["desc"] + " [string only: not passed to exec/spawn]"
                (info if sev_eff == "info" else findings).append(
                    _item(sev_eff.upper(), pid, pg["name"], desc, path, n, m.group(0), ctx.strip()))
                hits[pid] = hits.get(pid, 0) + 1
                if pid in ONCE_PER_FILE or hits[pid] >= MAX_HITS:
                    done.add(pid)
                    break
    ids = {k[0] for k in seen}
    has_net = "network" in ids

    def demote(pid):
        for f in [f for f in findings if f["id"] == pid and f["file"] == path]:
            findings.remove(f)
            f["severity"] = "INFO"
            info.append(f)

    # Combination rules ---------------------------------------------------------------
    if "env_exfil" in ids and not has_net:
        demote("env_exfil")            # env dump with no network sink = debug print
    if "exfil_host" in ids and not has_net:
        demote("exfil_host")           # collector URL in a file that never sends anything
    if "raw_ip_url" in ids and not ({"credential_read", "env_exfil"} & ids):
        demote("raw_ip_url")           # self-hosted server / LAN defaults are normal
    if "exfil_host" in ids and has_net:
        if "credential_read" in ids or "keychain_read" in ids:
            findings.append(_item("CRITICAL", "credential_exfil", "Credential Exfiltration",
                                  "References a credential store and a collector endpoint in the same bundle",
                                  path, 0, context="file-level combination"))
        if "vault_enum" in ids or "other_vaults" in ids:
            findings.append(_item("CRITICAL", "vault_exfil", "Vault Exfiltration",
                                  "Reads the whole vault (or the vault registry) and names a collector endpoint",
                                  path, 0, context="file-level combination"))
    obf = len(OBF_IDENT.findall(text[:5000000])) if "_0x" in text else 0
    rc4 = len(RC4_CALL.findall(text[:5000000]))
    if obf >= 25 or rc4 >= 150:
        why = "%d _0x identifiers" % obf if obf >= 25 else "%d string-array decoder calls" % rc4
        findings.append(_item("HIGH", "obfuscation", "Obfuscated Code",
                              "javascript-obfuscator style code (%s)" % why,
                              path, 0, context="file-level"))
        ids.add("obfuscation")
    return ids


def _disclosed(manifest, readme):
    blob = " ".join([str((manifest or {}).get("description") or ""), readme or ""])
    return bool(TELEMETRY_WORDS.search(blob))


def scan_plugin(files, label="", readme=None):
    """files: {relative_path: text} (main.js, manifest.json, any extra .js). Returns a result dict."""
    findings, info = [], []
    manifest = None
    if "manifest.json" in files:
        try:
            manifest = json.loads(files["manifest.json"])
        except ValueError:
            manifest = None
    if readme is None:
        readme = files.get("README.md") or files.get("readme.md") or ""
    ids = set()
    for path, text in sorted(files.items()):
        if not path.endswith((".js", ".cjs", ".mjs")):
            continue
        ids |= _scan_text(text, path, findings, info)
    # Telemetry: undisclosed -> MEDIUM; disclosed in the manifest description / README -> LOW
    if any(f["id"] == "telemetry" for f in findings) and _disclosed(manifest, readme):
        for f in findings:
            if f["id"] == "telemetry":
                f["severity"] = "LOW"
                f["description"] += " (disclosed in README/description)"
    if manifest is not None and not manifest.get("isDesktopOnly") and ({"child_process", "node_fs"} & ids):
        info.append(_item("INFO", "mobile_node", "Node API without isDesktopOnly",
                          "Uses Node modules but is not marked desktop-only (will break on mobile)",
                          "manifest.json", 0))
    return _summarise(findings, info, label, manifest)


def _summarise(findings, info, label, manifest=None):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    score = 0
    for f in findings:
        counts[f["severity"]] += 1
        score += SEVERITY_SCORE[f["severity"].lower()]
    level = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[s]), "SAFE")
    findings.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f["file"], f["line"]))
    parts = ["%d %s" % (counts[s], s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[s]]
    m = manifest or {}
    return {"target": label, "plugin": {k: m.get(k) for k in ("id", "name", "version", "author", "isDesktopOnly")},
            "risk_score": min(score, 100), "risk_level": level,
            "summary": ", ".join(parts) or "No issues found",
            "findings": findings, "info": info,
            "capabilities": sorted({f["id"] for f in info}),
            "total_findings": len(findings), "info_count": len(info)}


def scan(content, label="<text>"):
    findings, info = [], []
    _scan_text(content, label, findings, info)
    return _summarise(findings, info, label)


# ---------------------------------------------------------------------------
# Loading targets (never executes plugin code)
# ---------------------------------------------------------------------------
UA = {"User-Agent": "obsidian-audit/%s (+https://github.com/eltociear/obsidian-audit)" % __version__}


def _get(url, timeout=60, tries=4):
    for i in range(tries):
        try:
            return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout).read()
        except urllib.error.HTTPError as e:
            if e.code in (403, 404, 410) or i == tries - 1:
                raise
        except Exception:
            if i == tries - 1:
                raise
        time.sleep(2 * (i + 1))


def _read_file(p):
    with open(p, "rb") as fh:
        return fh.read(MAX_FILE).decode("utf-8", "replace")


def files_from_dir(root):
    out = {}
    for fn in sorted(os.listdir(root)):
        p = os.path.join(root, fn)
        if not regular_file(p) or not fn.endswith((".js", ".cjs", ".mjs", ".json", ".md")):
            continue
        if fn.endswith(".json") and fn != "manifest.json":
            continue
        try:
            if os.path.getsize(p) > MAX_FILE:
                continue
            with open(p, encoding="utf-8", errors="replace") as fh:
                out[fn] = fh.read()
        except OSError:
            pass
    return out


def directory():
    """community-plugins.json joined with download counts, most-downloaded first."""
    plugins = json.loads(_get(RELEASES + "community-plugins.json"))
    try:
        stats = json.loads(_get(RELEASES + "community-plugin-stats.json"))
    except Exception:
        stats = {}
    for p in plugins:
        p["downloads"] = (stats.get(p["id"]) or {}).get("downloads", 0)
    plugins.sort(key=lambda p: -p["downloads"])
    return plugins


def audit_repo(repo, label=None, with_readme=True):
    files = {}
    for fn in ("manifest.json", "main.js"):
        try:
            files[fn] = _get("https://github.com/%s/releases/latest/download/%s" % (repo, fn),
                             timeout=120).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            if fn == "main.js":
                raise RuntimeError("no main.js in the latest release of %s (HTTP %d)" % (repo, e.code))
    readme = ""
    if with_readme:
        for name in ("README.md", "readme.md", "Readme.md"):
            try:
                readme = _get("https://raw.githubusercontent.com/%s/HEAD/%s" % (repo, name), tries=2).decode("utf-8", "replace")
                break
            except Exception:
                continue
    r = scan_plugin(files, label or repo, readme)
    r["repo"] = repo
    return r


def resolve(plugin_id, plugins=None):
    for p in plugins or directory():
        if p["id"] == plugin_id:
            return p
    raise RuntimeError("plugin id %r is not in the community directory" % plugin_id)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
_ICON = {"CRITICAL": "\U0001F534", "HIGH": "\U0001F7E0", "MEDIUM": "\U0001F7E1",
         "LOW": "\U0001F535", "SAFE": "\U0001F7E2"}


def _print(r, verbose):
    print("%s %s  [%s]  score=%d  (%d findings, %d info)" % (
        _ICON.get(r["risk_level"], "?"), r["target"], r["risk_level"], r["risk_score"],
        r["total_findings"], r["info_count"]))
    for f in r["findings"]:
        print("    %-8s %s  %s:%s" % (f["severity"], f["name"], f["file"], f["line"]))
        if f["context"]:
            print("             %s" % f["context"][:160])
    if verbose:
        for f in r["info"]:
            print("    info     %s  %s:%s  %s" % (f["name"], f["file"], f["line"], f["matched"][:60]))
    elif r["capabilities"]:
        print("    context  " + ", ".join(r["capabilities"]))


def _opt(args, name, default=None):
    if name in args:
        i = args.index(name)
        v = args[i + 1] if i + 1 < len(args) else default
        del args[i:i + 2]
        return v
    return default


# ---------------------------------------------------------------------------
# Pipeline output shared by the eltociear/*-audit family: --json / --sarif / --fail-on
# (this block is kept identical across the family; see "Output formats" in the README)
# ---------------------------------------------------------------------------
FAMILY_SCHEMA = "eltociear-audit/1"
TOOL_NAME = "obsidian-audit"
TOOL_URI = "https://github.com/eltociear/obsidian-audit"
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
    limit = int(_opt(args, "--limit", "0") or 0)
    targets = []  # (label, thunk)
    if args[0] == "--text":
        txt = " ".join(args[1:])
        targets.append(("<text>", lambda: scan(txt)))
    elif args[0] == "--vault":
        root = os.path.join(os.path.expanduser(args[1]), ".obsidian", "plugins")
        for d in sorted(os.listdir(root)):
            full = os.path.join(root, d)
            if os.path.isdir(full):
                targets.append((d, (lambda f=full, s=d: scan_plugin(files_from_dir(f), s))))
    elif args[0] == "--plugin":
        plugins = directory()
        for pid in args[1:]:
            targets.append((pid, (lambda i=pid: (lambda p: audit_repo(p["repo"], "%s (%s)" % (i, p["repo"])))(resolve(i, plugins)))))
    elif args[0] == "--repo":
        for repo in args[1:]:
            targets.append((repo, (lambda r=repo: audit_repo(r))))
    elif args[0] == "--all":
        plugins = directory()
        for p in plugins[:limit or None]:
            targets.append((p["id"], (lambda p=p: audit_repo(p["repo"], "%s (%s)" % (p["id"], p["repo"]), with_readme=False))))
    else:
        for a in args:
            a = os.path.expanduser(a)
            if os.path.isdir(a):
                targets.append((a, (lambda p=a: scan_plugin(files_from_dir(p), p))))
            elif os.path.isfile(a):
                targets.append((a, (lambda p=a: scan_plugin(
                    {os.path.basename(p) if p.endswith((".js", ".json")) else "main.js": _read_file(p)}, p))))
            else:
                print("not a file or directory: %s (use --plugin <id> or --repo owner/name)" % a, file=sys.stderr)
                return 1
    results, worst = [], "SAFE"
    for label, thunk in targets:
        try:
            r = thunk()
        except Exception as e:
            r = {"target": label, "risk_level": "SAFE", "risk_score": 0, "error": str(e)[:200],
                 "findings": [], "info": [], "capabilities": [], "total_findings": 0, "info_count": 0,
                 "summary": "error"}
            if not as_json:
                print("⚪ %s  [ERROR] %s" % (label, r["error"]))
        else:
            if not as_json:
                _print(r, verbose)
        results.append(r)
        if SEV_ORDER[r["risk_level"]] > SEV_ORDER[worst]:
            worst = r["risk_level"]
    return family_emit(results, fam)


if __name__ == "__main__":
    sys.exit(main())
