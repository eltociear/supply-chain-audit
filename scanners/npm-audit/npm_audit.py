#!/usr/bin/env python3
"""npm-audit - scan npm packages for MALICIOUS patterns before you install them.

`npm audit` only answers "does this version have a known CVE?". It says nothing about a
package published yesterday whose postinstall script ships your environment variables to a
Discord webhook. That is the gap this fills: a deterministic (no LLM) static scan of the
published tarball for install-time attacks, credential theft, exfiltration endpoints,
obfuscated payloads, reverse shells and worm-style self-propagation.

Precision-tuned to near-zero false positives: capabilities that popular packages use every
day (prebuilt-binary downloads in install scripts, child_process, reading ~/.npmrc or
~/.aws/credentials in a config loader) are reported as informational context and never
inflate the risk score. Risk comes from specific COMBINATIONS (credential read + external
destination, env dump + network, install script + suspicious host) and specific sinks.

The package is never installed and none of its code is executed: the tarball is downloaded
into memory and read as text.

Usage:
  python npm_audit.py <pkg>[@version] [...]        # fetch from registry.npmjs.org and scan
  python npm_audit.py <dir|package.json|file.js>   # scan a local package / file
  python npm_audit.py --lockfile package-lock.json # scan every dependency in a lockfile
  python npm_audit.py --node-modules ./node_modules  # scan each installed package
  python npm_audit.py --text "some code"           # scan a string
  python npm_audit.py --keyword n8n-community-node-package --limit 500  # bulk: registry search
  add --n8n / --node-red to force host-specific rules (auto-detected from package.json)
  add --json for machine-readable output, --verbose to print INFO context

Exit code 2 if any target is HIGH or CRITICAL (CI-friendly).
No dependencies beyond the standard library. MIT licensed.
"""
import io
import json
import os
import re
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request

__version__ = "0.1.0"

REGISTRY = os.environ.get("NPM_AUDIT_REGISTRY", "https://registry.npmjs.org").rstrip("/")
LIFECYCLE = ("preinstall", "install", "postinstall")  # run automatically on `npm install`
SCAN_EXT = (".js", ".cjs", ".mjs", ".jsx", ".ts", ".cts", ".mts", ".sh", ".py", ".json", ".html")
MAX_FILE = 1500000      # bytes; larger files are bundles - skipped (reported as info)
MAX_TOTAL = 12000000    # bytes of text scanned per package
MAX_LINE = 20000        # per-line regex window (minified bundles have megabyte lines)

# Endpoints that legitimate packages essentially never hard-code, but stealers love:
# chat webhooks, paste sites, request bins, tunnels and out-of-band (OAST) collectors.
EXFIL_HOST = (
    r"(?:discord(?:app)?\.com/api/webhooks/|api\.telegram\.org/bot|hooks\.slack\.com/services/|"
    r"webhook\.site|pipedream\.net|requestbin\.(?:com|net|io)|requestb\.in|requestcatcher\.com|beeceptor\.com|"
    r"pastebin\.com/api|paste\.ee|hastebin|transfer\.sh|file\.io|"
    r"ngrok(?:-free)?\.(?:io|app|dev)|\.trycloudflare\.com|serveo\.net|localtunnel\.me|"
    r"oastify\.com|oast\.(?:fun|me|pro|live|site|online)|interact\.sh|interactsh|"
    r"burpcollaborator\.net|canarytokens\.com|dnslog\.cn|ceye\.io|requestrepo\.com)"
)
RAW_IP_URL = r"https?://(?!(?:127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.))\d{1,3}(?:\.\d{1,3}){3}"
NET_SEND = (r"(?:https?\.request|https?\.get|require\s*\(\s*[\"'](?:node:)?(?:https?|net|dns)[\"']\s*\)\s*\.\s*\w+\s*\(|\bfetch\s*\(|axios(?:\.\w+)?\s*\(|\.post\s*\(|"
            r"XMLHttpRequest|net\.connect|new\s+net\.Socket|dns\.(?:lookup|resolve\w*)\s*\(|"
            r"\bcurl\b|\bwget\b|request\s*\(\s*\{)")

PATTERNS = {
    "critical": [
        {"id": "download_execute", "name": "Download & Execute",
         "desc": "Fetches remote content and pipes it straight into a shell/interpreter",
         "regexes": [
             r"curl\s+[^\n|;]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?|node)\b",
             r"wget\s+[^\n|;]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?|node)\b",
             r"wget\s+[^\n]*-O-?\s*-\s*\|\s*(?:sh|bash)",
             r"(?:sh|bash|python3?|node)\s*<\s*\(\s*(?:curl|wget)",
             r"eval\s*\(\s*(?:await\s+)?(?:\(\s*await\s+)?fetch\s*\(",
             r"(?:iex|Invoke-Expression)\s*\(?\s*\(?\s*(?:New-Object\s+Net\.WebClient|iwr|Invoke-WebRequest)",
             r"powershell[^\n]{0,40}-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}",
         ]},
        {"id": "env_exfil", "name": "Environment Dump",
         "desc": "Serialises the whole process.env (every token/secret) - exfil when a network sink is present",
         "regexes": [
             r"JSON\.stringify\s*\(\s*process\.env\s*[,)]",
             r"Buffer\.from\s*\(\s*JSON\.stringify\s*\(\s*process\.env",
             r"(?:Object\.(?:entries|keys)|for\s*\(\s*(?:const|let|var)\s+\w+\s+in)\s*\(?\s*process\.env\s*\)?[^\n]{0,80}(?:join|push|stringify|encodeURIComponent)",
             r"querystring\.stringify\s*\(\s*process\.env",
             r"\benv\s*:\s*process\.env\s*[,}][^\n]{0,200}(?:hostname|homedir|userInfo)",
         ]},
        {"id": "reverse_shell", "name": "Reverse Shell",
         "desc": "Spawns an interactive shell bound to a network socket",
         "regexes": [
             r"/dev/tcp/[\w.\-]+/\d+",
             r"bash\s+-i\s*>&",
             r"\bnc(?:at)?\s+(?:-\w+\s+)*-e\s+/bin/(?:ba)?sh",
             r"spawn\s*\(\s*[\"'](?:/bin/)?(?:ba)?sh[\"'][^\n]{0,200}\.pipe\s*\(\s*(?:client|socket|sock|conn)",
             r"(?:client|socket|sock|conn)\.pipe\s*\(\s*\w+\.stdin\s*\)",
         ]},
        {"id": "destructive", "name": "Destructive Payload",
         "desc": "Wipes the home directory / filesystem (protestware, wiper)",
         "regexes": [
             r"rm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+(?:--no-preserve-root\s+)?(?:~|\$HOME|/)(?:\s|[\"'`;]|$)",
             r"(?:rmSync|rmdirSync|rimraf\w*)\s*\(\s*(?:os\.)?homedir\s*\(\s*\)",
             r"(?:rmSync|rmdirSync)\s*\(\s*[\"']/[\"']",
             r"del\s+/[fsq]\s+/[fsq]\s+[\"']?C:\\\\",
         ]},
        {"id": "worm_propagation", "name": "Self-Propagation (Worm)",
         "desc": "Uses stolen npm/GitHub tokens to republish packages or push repos (Shai-Hulud style)",
         "regexes": [
             r"npm\s+publish[^\n]{0,120}(?:--access|NPM_TOKEN|_authToken|npm_token)",
             r"(?:NPM_TOKEN|npm_token|_authToken)[^\n]{0,200}npm\s+publish",
             r"registry\.npmjs\.org/-/(?:whoami|v1/search\?text=maintainer:)",
             r"trufflehog[^\n]{0,80}(?:filesystem|github|--json)",
             r"github\.com/trufflesecurity/trufflehog/releases",
             r"api\.github\.com/user/repos[^\n]{0,200}(?:private|Shai|migration)",
         ]},
    ],
    "high": [
        {"id": "exfil_host", "name": "Exfiltration Endpoint",
         "desc": "Hard-codes a webhook / paste / tunnel / OAST collector host",
         "regexes": [EXFIL_HOST]},
        {"id": "wallet_browser_theft", "name": "Wallet / Browser Data Theft",
         "desc": "Targets crypto-wallet extension storage, browser credential stores or Keychain",
         "regexes": [
             r"nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|hnfanknocfeofbddgcijnmhnfnkdnaad|ibnejdfjmmkpcnlpebklmnkoeoihofec|egjidjbpglichdcondbcbdnbeeppgdph",
             r"(?:Login Data|Web Data|Local State)[\"'][^\n]{0,120}(?:Chrome|Brave|Edge|Opera|Chromium|readFile|copyFile)",
             r"(?:Chrome|BraveSoftware|Microsoft/Edge|Opera Software)[^\n]{0,80}(?:Login Data|Local Extension Settings)",
             r"(?:Exodus|atomic|Electrum|Ethereum)[/\\\\](?:exodus\.wallet|Local Storage|wallets|keystore)",
             r"\.config[/\\\\]solana[/\\\\]id\.json",
             r"security\s+find-generic-password",
             r"\b(?:wallet\.dat|seed\.seco|passphrase\.json)\b",
         ]},
        {"id": "obfuscation", "name": "Obfuscated Payload",
         "desc": "javascript-obfuscator style identifiers, eval of decoded strings, long escape blobs",
         "regexes": [
             r"(?:eval|Function)\s*\(\s*(?:atob|unescape|decodeURIComponent)\s*\(",
             r"(?:eval|new\s+Function)\s*\(\s*Buffer\.from\s*\([^)]{0,4000},\s*[\"'](?:base64|hex)[\"']",
             r"(?:eval|new\s+Function)\s*\(\s*[\"'](?:\\x[0-9a-fA-F]{2}){20,}",
             r"(?:eval|new\s+Function)\s*\(\s*String\.fromCharCode\s*\(",
         ]},
        {"id": "dns_exfil", "name": "DNS Exfiltration",
         "desc": "Encodes host/user data into a DNS lookup (dependency-confusion beacon)",
         "regexes": [
             r"dns\.(?:lookup|resolve\w*)\s*\([^\n]{0,160}(?:hostname\s*\(|userInfo\s*\(|homedir\s*\(|process\.env|toString\s*\(\s*[\"']hex)",
             r"(?:hostname\s*\(\s*\)|userInfo\s*\(\s*\)\.username)[^\n]{0,160}dns\.(?:lookup|resolve)",
         ]},
        {"id": "credential_exfil", "name": "Credential Exfiltration",
         "desc": "Reads a credential store AND names an external destination on the same line",
         "regexes": [
             r"(?:\.npmrc|\.ssh[/\\\\]id_|\.aws[/\\\\]credentials|\.git-credentials|\.docker[/\\\\]config\.json|\.kube[/\\\\]config)[^\n]{0,200}(?:https?://(?!(?:registry\.npmjs\.org|registry\.yarnpkg\.com))|" + EXFIL_HOST + r")",
         ]},
        {"id": "auth_bypass", "name": "TLS Verification Disabled",
         "desc": "Turns off certificate checking globally",
         "regexes": [
             r"NODE_TLS_REJECT_UNAUTHORIZED[\"']?\s*\]?\s*=\s*[\"']?0",
         ]},
    ],
    "medium": [
        {"id": "raw_ip_url", "name": "Raw-IP URL",
         "desc": "Contacts a public IP address directly instead of a hostname",
         "regexes": [RAW_IP_URL]},
    ],
    "low": [],
    # Context: reported, never scored. These are capabilities popular packages use daily.
    "info": [
        {"id": "credential_read", "name": "Credential Store Reference",
         "desc": "References ~/.npmrc, ~/.ssh, ~/.aws etc. (config loaders do this legitimately)",
         "regexes": [r"\.npmrc\b", r"\.ssh[/\\\\]id_\w+", r"\.aws[/\\\\]credentials", r"\.git-credentials",
                     r"\.docker[/\\\\]config\.json"]},
        {"id": "child_process", "name": "Process Spawning",
         "desc": "Uses child_process (build tools, CLIs and binary wrappers all do)",
         "regexes": [r"child_process", r"\bexecSync\s*\(", r"\bspawnSync\s*\("]},
        {"id": "network", "name": "Network Access",
         "desc": "Makes outbound HTTP/DNS/socket calls",
         "regexes": [NET_SEND]},
        {"id": "obfuscation_lite", "name": "Encoded Strings",
         "desc": "Base64/hex decoding or escape blobs without an eval sink",
         "regexes": [r"(?:\\x[0-9a-fA-F]{2}){24,}", r"Buffer\.from\s*\([\"'][A-Za-z0-9+/=]{200,}[\"']"]},
        {"id": "env_read", "name": "Environment Access",
         "desc": "Reads environment variables",
         "regexes": [r"process\.env\b"]},
    ],
}

SEVERITY_SCORE = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "SAFE": 0}
_COMPILED = [(sev, pg, re.compile(rx, re.IGNORECASE))
             for sev, groups in PATTERNS.items() for pg in groups for rx in pg["regexes"]]
OBF_IDENT = re.compile(r"\b_0x[0-9a-f]{4,6}\b")
NET_RE = re.compile(NET_SEND, re.IGNORECASE)
EXFIL_RE = re.compile(EXFIL_HOST, re.IGNORECASE)
RAWIP_RE = re.compile(RAW_IP_URL)
TOKEN_WORD_RE = re.compile(r"NPM_TOKEN|npm_token|_authToken", re.IGNORECASE)
COMMENT_BLIND = {"worm_propagation", "download_execute", "destructive", "env_exfil", "auth_bypass", "exfil_host"}
COMMENT_LINE_RE = re.compile(r"^\s*(?://|/?\*|#(?!!))")
JS_EXT = (".js", ".cjs", ".mjs", ".jsx", ".ts", ".cts", ".mts", ".html")
EXEC_SINK_RE = re.compile(r"(?:\bexec(?:Sync|File|FileSync)?|\bspawn(?:Sync)?|\bexeca(?:Sync|Command)?|"
                          r"\bshell\.exec|\beval|\bFunction|\bsystem|\bexecSh|\brun(?:Command|Shell)?)\s*\(|"
                          r"shell\s*:\s*true")
_RECON = r"(?:whoami|id|hostname|uname(?:\s+-[a-z]+)?|cat\s+/etc/(?:passwd|os-release|hostname)|ifconfig|ip\s+a(?:ddr)?)"
RECON_CHAIN_RE = re.compile(r"\b%s\s*(?:&&|;|\|\|)\s*%s\s*(?:&&|;|\|\|)\s*%s\b" % (_RECON, _RECON, _RECON))
# Chat / webhook APIs that integrations call with the user's own token: only a literal,
# hard-coded token or webhook id makes them a collector.
CHAT_API_RE = re.compile(r"api\.telegram\.org/bot|discord(?:app)?\.com/api/webhooks/|hooks\.slack\.com/services/", re.IGNORECASE)
HARDCODED_CHAT_RE = re.compile(r"api\.telegram\.org/bot\d{5,}:[\w-]{20,}|discord(?:app)?\.com/api/webhooks/\d{4,}/[\w-]{10,}|"
                               r"hooks\.slack\.com/services/T\w+/B\w+/\w+", re.IGNORECASE)
SCRIPT_FILE_RE = re.compile(r"(?:^|[\s;&|(])(?:node|sh|bash|python3?)\s+(?:-\w+\s+)*[\"']?([\w./\\-]+\.(?:c?js|mjs|sh|py))")
INLINE_NODE_RE = re.compile(r"\bnode\s+(?:-e|--eval|-p)\s")
# Ordinary lifecycle commands seen across the top of the registry: native builds,
# prebuilt-binary fetchers, git hooks, funding banners. Context, not risk.
BENIGN_SCRIPT = re.compile(
    r"^\s*(?:node-gyp(?:-build)?(?:\s+rebuild)?|prebuild-install(?:\s.*)?|node-pre-gyp\s+install.*|"
    r"husky(?:\s+install)?|patch-package|opencollective(?:-postinstall)?.*|is-ci\s*\|\|.*|"
    r"tsc|npm\s+run\s+[\w:-]+|yarn\s+[\w:-]+|cmake-js.*|napi\s+.*|electron-rebuild.*)\s*$")


def _scan_text(text, path, findings, info, install_ctx):
    """Line-oriented pattern pass plus file-level combination rules."""
    lines = text.split("\n")
    seen = set()
    for sev, pg, rx in _COMPILED:
        for n, line in enumerate(lines, 1):
            if pg["id"] in ("network", "env_read", "child_process") and (pg["id"], 0) in seen:
                break  # one context hit per file is enough
            m = rx.search(line[:MAX_LINE])
            if not m:
                continue
            if pg["id"] in COMMENT_BLIND and COMMENT_LINE_RE.match(line):
                continue  # "// To publish: npm publish --access public" is documentation
            key = (pg["id"], n)
            if key in seen:
                continue
            seen.add(key)
            if pg["id"] in ("network", "env_read", "child_process"):
                seen.add((pg["id"], 0))
            item = {"severity": sev.upper(), "id": pg["id"], "name": pg["name"],
                    "description": pg["desc"], "file": path, "line": n,
                    "matched": m.group(0)[:120], "context": line.strip()[:200]}
            (info if sev == "info" else findings).append(item)

    ids = {k[0] for k in seen}
    has_net = bool(NET_RE.search(text))
    # A `curl ... | sh` that only sits in a JS string (an install hint in an error message or
    # help text) is shown to the user, not run. It is a finding only when the same line hands
    # it to an exec/spawn sink, when the file is a shell script, or at install time.
    if "download_execute" in ids and not install_ctx and path.endswith(JS_EXT):
        for f in findings:
            if (f["id"] == "download_execute" and f["file"] == path and f["line"]
                    and not EXEC_SINK_RE.search(lines[f["line"] - 1][:MAX_LINE])):
                f["severity"] = "INFO"
                f["description"] += " [string only: not passed to exec/spawn]"
        _demote(findings, info)
    # `npm publish --access public` alone is a maintainer's release script (shipped .sh, Makefile,
    # docs). The worm shape uses a stolen token, the -/whoami probe, or execs publish from JS.
    if "worm_propagation" in ids and not install_ctx:
        for f in findings:
            if (f["id"] == "worm_propagation" and f["file"] == path
                    and re.match(r"npm\s+publish", f["matched"]) and not TOKEN_WORD_RE.search(f["matched"])
                    and not (path.endswith(JS_EXT) and f["line"]
                             and EXEC_SINK_RE.search(lines[f["line"] - 1][:MAX_LINE]))):
                f["severity"] = "INFO"
                f["description"] += " [release script, no token]"
        _demote(findings, info)
    # Combination rules ----------------------------------------------------------------
    # env dump with no network sink anywhere in the file is a debug print, not exfil.
    if "env_exfil" in ids and not has_net:
        for f in findings:
            if f["id"] == "env_exfil" and f["file"] == path:
                f["severity"] = "INFO"
        _demote(findings, info)
    # an exfil host in a file that never sends anything is a URL in a comment/README-ish string
    if "exfil_host" in ids and not has_net and not install_ctx:
        for f in findings:
            if f["id"] == "exfil_host" and f["file"] == path:
                f["severity"] = "INFO"
        _demote(findings, info)
    # raw-IP URLs only matter at install time or next to a credential/env read
    if "raw_ip_url" in ids and not (install_ctx or "env_exfil" in ids or "credential_read" in ids):
        for f in findings:
            if f["id"] == "raw_ip_url" and f["file"] == path:
                f["severity"] = "INFO"
        _demote(findings, info)
    # credential store read + exfil host / raw IP in the same file -> credential theft
    if "credential_read" in ids and (EXFIL_RE.search(text) or (install_ctx and has_net and RAWIP_RE.search(text))):
        findings.append({"severity": "CRITICAL", "id": "credential_exfil", "name": "Credential Exfiltration",
                         "description": "Reads a credential store and sends to an exfil endpoint in the same file",
                         "file": path, "line": 0, "matched": "", "context": "file-level combination"})
    # host-recon beacon: a chain of identity commands (id && hostname && whoami && uname -a)
    # handed to exec in a file that also sends data - the dependency-confusion / RCE-proof shape
    m = RECON_CHAIN_RE.search(text) if has_net else None
    if m:
        ln = text.count("\n", 0, m.start())
        if EXEC_SINK_RE.search(lines[ln][:MAX_LINE]):
            findings.append({"severity": "HIGH", "id": "recon_beacon", "name": "Host Recon Beacon",
                             "description": "Runs a chain of host-identity commands and sends data out in the same file",
                             "file": path, "line": ln + 1, "matched": m.group(0)[:120],
                             "context": lines[ln].strip()[:200]})
            if install_ctx:
                findings[-1]["severity"] = "CRITICAL"
    # javascript-obfuscator output: dozens of _0x identifiers
    obf = len(OBF_IDENT.findall(text[:3000000]))
    if obf >= 25:
        findings.append({"severity": "HIGH", "id": "obfuscation", "name": "Obfuscated Payload",
                         "description": "javascript-obfuscator style code (%d _0x identifiers)" % obf,
                         "file": path, "line": 0, "matched": "", "context": "file-level"})
    # Install-time escalation: anything HIGH that runs automatically on `npm install` is CRITICAL
    if install_ctx:
        for f in findings:
            if f["file"] == path and f["severity"] in ("HIGH", "MEDIUM") and f["id"] != "auth_bypass":
                f["severity"] = "CRITICAL"
                f["description"] += " [runs at install time]"


def _demote(findings, info):
    for f in [f for f in findings if f["severity"] == "INFO"]:
        findings.remove(f)
        info.append(f)


def _lifecycle(pkg_json, files, findings, info):
    """Inspect package.json lifecycle scripts; return the set of files they execute."""
    scripts = (pkg_json or {}).get("scripts") or {}
    run_files = set()
    for hook in LIFECYCLE:
        cmd = scripts.get(hook)
        if not isinstance(cmd, str) or not cmd.strip():
            continue
        info.append({"severity": "INFO", "id": "install_script", "name": "Install Script",
                     "description": "Runs automatically on npm install", "file": "package.json",
                     "line": 0, "matched": hook, "context": "%s: %s" % (hook, cmd[:180])})
        tmp = []
        _scan_text(cmd, "package.json#scripts.%s" % hook, tmp, info, True)
        findings.extend(tmp)
        if INLINE_NODE_RE.search(cmd) and NET_RE.search(cmd):
            findings.append({"severity": "CRITICAL", "id": "inline_install_network",
                             "name": "Inline Install-Time Network Code",
                             "description": "`node -e` in a lifecycle script that performs network I/O",
                             "file": "package.json#scripts.%s" % hook, "line": 0,
                             "matched": cmd[:120], "context": cmd[:200]})
        elif (re.search(r"\b(?:curl|wget)\b", re.sub(r"\b(?:echo|printf)\s+(['\"]).*?\1", "", cmd, flags=re.S))
              and not BENIGN_SCRIPT.match(cmd)):
            findings.append({"severity": "HIGH", "id": "install_fetch", "name": "Install-Time Fetch",
                             "description": "Lifecycle script shells out to curl/wget",
                             "file": "package.json#scripts.%s" % hook, "line": 0,
                             "matched": cmd[:120], "context": cmd[:200]})
        for m in SCRIPT_FILE_RE.finditer(cmd):
            p = os.path.normpath(m.group(1).replace("\\", "/")).lstrip("./")
            run_files.add(p)
    return run_files


# ---------------------------------------------------------------------------
# Ecosystem context: n8n community nodes and Node-RED nodes
# ---------------------------------------------------------------------------
# Both are ordinary npm packages, but they run inside an automation server that holds the
# credentials of every service its workflows touch. A node is meant to read *its own*
# credentials (n8n: this.getCredentials('<declared type>'); Node-RED: this.credentials).
# Reaching for the server's own secrets - n8n's encryption key / database, Node-RED's
# flows_cred.json / credentialSecret - or exposing credential lookups through an
# unauthenticated admin endpoint is the attack surface specific to these hosts.
ECO_N8N, ECO_NODE_RED = "n8n", "node-red"

N8N_INTERNAL_RE = re.compile(
    r"(?:\.n8n[/\\](?:config\b|database\.sqlite|crash\.journal|binaryData)|"
    r"process\.env(?:\.|\[\s*['\"])N8N_ENCRYPTION_KEY\b|\bUserSettings\s*\.\s*getEncryptionKey\s*\(|"
    r"instanceSettings\s*\)?\s*\.\s*encryptionKey|\bcredentials_entity\b|"
    r"\bCredentialsRepository\b|\bSharedCredentialsRepository\b|['\"]@n8n/db['\"]|"
    r"require\s*\(\s*['\"]n8n(?:/[\w./-]+)?['\"]\s*\)|from\s+['\"]n8n(?:/[\w./-]+)?['\"])")
N8N_GETCRED_RE = re.compile(r"\bgetCredentials\s*(?:<[^>]{0,80}>)?\s*\(\s*(['\"])([\w.-]{1,80})\1")
N8N_DECLARED_RE = re.compile(r"\bname\s*[:=]\s*['\"]([\w.-]{1,80})['\"]")
# credential types that ship with n8n itself and may be requested by any node
N8N_BUILTIN_CREDS = {"httpBasicAuth", "httpDigestAuth", "httpHeaderAuth", "httpQueryAuth",
                     "httpCustomAuth", "oAuth1Api", "oAuth2Api", "httpSslAuth", "httpBearerAuth"}
NR_CRED_STORE_RE = re.compile(
    r"(?:readFile\w*|createReadStream|readJson\w*|path\s*\.\s*(?:join|resolve))\s*\([^;\n]{0,160}?"
    r"(?:flows?_cred\w*\.json|\.config\.(?:runtime|users)\.json|\.node-red[/\\](?:flows|\.config))")
NR_SECRET_RE = re.compile(r"settings\s*(?:\.\s*|\[\s*['\"])_?credentialSecret\b")
PLACEHOLDER_RE = re.compile(r"(?:\b(?:your|my)[-_]|xxxx|<[\w-]+>|\{[\w-]+\}|\b123456\b|example)", re.IGNORECASE)
TEST_PATH_RE = re.compile(r"(?:^|/)(?:tests?|__tests__|spec|examples?|docs?|demo)/", re.IGNORECASE)
NR_GETCRED_RE = re.compile(r"\bRED\s*\.\s*nodes\s*\.\s*getCredentials\s*\(\s*([^)]{1,80})\)")
NR_ADMIN_RE = re.compile(r"\bRED\s*\.\s*httpAdmin\s*\.\s*(get|post|put|delete|patch|all|use)\s*\(")
NR_ADMIN_SENSITIVE_RE = re.compile(
    r"getCredentials|\.credentials\b|child_process|\bexec(?:Sync|File)?\s*\(|\bspawn(?:Sync)?\s*\(|"
    r"writeFile(?:Sync)?\s*\(|unlink(?:Sync)?\s*\(|rmSync\s*\(")
CALLBACK_KEY_RE = re.compile(r"(?:callback|notify|notification|return|redirect)\w{0,12}['\"]?\s*[:=]\s*['\"`]?(?:https?://)?[\w.-]{0,40}$",
                             re.IGNORECASE)
CRED_USE_RE = re.compile(r"\bgetCredentials\s*\(|\bthis\.credentials\b|\bnode\.credentials\b")


def detect_ecosystem(pkg_json):
    """'n8n', 'node-red' or None, from the package.json the host itself reads."""
    pj = pkg_json if isinstance(pkg_json, dict) else {}
    kws = {str(k).lower() for k in (pj.get("keywords") or []) if isinstance(k, str)}
    if isinstance(pj.get("n8n"), dict) or "n8n-community-node-package" in kws:
        return ECO_N8N
    if isinstance(pj.get("node-red"), dict):
        return ECO_NODE_RED
    return None


def _eco_item(sev, pid, name, desc, path, text, pos, matched):
    line = text.count("\n", 0, pos) + 1
    ls = text.rfind("\n", 0, pos) + 1
    le = text.find("\n", pos)
    le = len(text) if le < 0 else le
    ctx = text[max(ls, pos - 80):min(le, pos + 120)]
    return {"severity": sev, "id": pid, "name": name, "description": desc, "file": path,
            "line": line, "matched": matched[:120], "context": ctx.strip()[:200]}


def _declared_n8n(files, pkg_json):
    names = set(N8N_BUILTIN_CREDS)
    for path, text in files.items():
        if path.endswith((".js", ".cjs", ".mjs", ".ts")):
            names.update(N8N_DECLARED_RE.findall(text))
    return names


def _eco_scan(eco, path, text, findings, info, declared):
    """Ecosystem-specific signals for one file. One hit per signal per file (bounded cost)."""
    has_net = bool(NET_RE.search(text))
    exfil = bool(EXFIL_RE.search(text))
    if eco == ECO_N8N:
        m = N8N_INTERNAL_RE.search(text)
        if m:
            sev = "CRITICAL" if (exfil and has_net) else "HIGH"
            findings.append(_eco_item(sev, "n8n_internal_secrets", "n8n Instance Secrets",
                                      "Reaches into the n8n instance itself (encryption key, credential "
                                      "database, ~/.n8n, n8n internals) instead of the node's own credentials",
                                      path, text, m.start(), m.group(0)))
        for m in N8N_GETCRED_RE.finditer(text):
            if m.group(2) not in declared:
                findings.append(_eco_item("MEDIUM", "n8n_undeclared_credential", "Undeclared Credential Type",
                                          "getCredentials() for a type this package never declares",
                                          path, text, m.start(), m.group(0)))
                break
    elif eco == ECO_NODE_RED:
        m = NR_CRED_STORE_RE.search(text)
        if m:
            sev = "CRITICAL" if (exfil and has_net) else ("HIGH" if has_net else "MEDIUM")
            findings.append(_eco_item(sev, "nodered_credential_store", "Node-RED Credential Store",
                                      "Reads the runtime's credential store file (flows_cred.json, "
                                      ".config.*.json, ~/.node-red)" +
                                      (" in a file that also does network I/O" if has_net else ""),
                                      path, text, m.start(), m.group(0)))
        m = NR_SECRET_RE.search(text)
        if m:
            if exfil and has_net:
                findings.append(_eco_item("CRITICAL", "nodered_secret_exfil", "Credential Secret Exfiltration",
                                          "Reads settings.credentialSecret and names a collector endpoint",
                                          path, text, m.start(), m.group(0)))
            else:
                info.append(_eco_item("INFO", "nodered_credential_secret", "Reads credentialSecret",
                                      "Uses the runtime's credentialSecret (e.g. as a salt or key)",
                                      path, text, m.start(), m.group(0)))
        for m in NR_GETCRED_RE.finditer(text):
            arg = m.group(1).strip()
            if arg.startswith(("req.", "request.")):
                findings.append(_eco_item("MEDIUM", "nodered_request_credentials", "Credentials by Request Id",
                                          "RED.nodes.getCredentials() with a node id taken from an HTTP request",
                                          path, text, m.start(), m.group(0)))
                break
        for m in NR_ADMIN_RE.finditer(text):
            head = text[m.end():m.end() + 400]
            cut = re.search(r"function\b|=>", head)
            args = head[:cut.start()] if cut else head[:200]
            mw = re.sub(r"^\s*(['\"`])[^'\"`]{0,200}\1\s*,?", "", args)  # drop the route path ('/oauth2/...')
            if "needsPermission" in mw or re.search(r"auth|permission|guard|protect", mw, re.IGNORECASE):
                continue
            verb = m.group(1).lower()
            body = text[m.end():m.end() + 1500]
            if verb == "get" and not NR_ADMIN_SENSITIVE_RE.search(body):
                info.append(_eco_item("INFO", "nodered_admin_get", "Unauthenticated Admin GET",
                                      "RED.httpAdmin GET route without RED.auth.needsPermission (static/UI data)",
                                      path, text, m.start(), m.group(0)))
                continue
            findings.append(_eco_item("MEDIUM", "nodered_admin_noauth", "Unauthenticated Admin Route",
                                      "RED.httpAdmin.%s route without RED.auth.needsPermission%s" % (
                                          verb, " that touches credentials, files or processes"
                                          if NR_ADMIN_SENSITIVE_RE.search(body) else ""),
                                      path, text, m.start(), m.group(0)))
            break
    # either host: the node's own credentials + a hard-coded collector endpoint + a send.
    # A Telegram/Discord/Slack node calling the API with the user's own bot token is the
    # integration itself; only a literal token/webhook id baked into the code is a collector.
    # A collector passed as a callback/notify URL to a vendor API leaks results, not credentials.
    m = None
    for mm in EXFIL_RE.finditer(text):
        if CHAT_API_RE.match(mm.group(0)) and not HARDCODED_CHAT_RE.match(text, mm.start()):
            continue
        if CALLBACK_KEY_RE.search(text[max(0, mm.start() - 80):mm.start()]):
            continue
        m = mm
        break
    if m and has_net and CRED_USE_RE.search(text):
        findings.append(_eco_item("CRITICAL", "automation_credential_exfil", "Workflow Credential Exfiltration",
                                  "Reads workflow credentials and names a collector endpoint (webhook, paste "
                                  "site, tunnel, OAST) in a file that sends data", path, text, m.start(), m.group(0)))


def scan_package(files, label="", ecosystem=None):
    """files: {relative_path: text}. Returns an audit result dict.
    ecosystem: 'n8n' / 'node-red' to force host-specific rules; default auto-detects."""
    findings, info = [], []
    pkg_json = None
    if "package.json" in files:
        try:
            pkg_json = json.loads(files["package.json"])
        except ValueError:
            pkg_json = None
    eco = ecosystem or detect_ecosystem(pkg_json)
    declared = _declared_n8n(files, pkg_json) if eco == ECO_N8N else set()
    run_files = _lifecycle(pkg_json, files, findings, info)
    total = 0
    for path, text in sorted(files.items()):
        if path == "package.json" or path.endswith((".d.ts", ".map")):
            continue
        if path.endswith(".json"):
            continue  # data files: only package.json scripts matter
        if path.endswith(".html") and (eco != ECO_NODE_RED or (path[:-5] + ".js") not in files):
            continue  # a Node-RED editor template sits next to its node .js; other HTML is docs/demo pages
        total += len(text)
        if total > MAX_TOTAL:
            info.append({"severity": "INFO", "id": "truncated", "name": "Scan Truncated",
                         "description": "Package exceeds %d bytes of text" % MAX_TOTAL,
                         "file": path, "line": 0, "matched": "", "context": ""})
            break
        _scan_text(text, path, findings, info, path in run_files)
        if (eco and path.endswith((".js", ".cjs", ".mjs", ".ts", ".html")) and not TEST_PATH_RE.search(path)
                and not (path.endswith(".html") and (path[:-5] + ".js") not in files)):
            n_info = len(info)
            _eco_scan(eco, path, text, findings, info, declared)
            del info[n_info + 20:]  # bound per-file context noise
    if eco:
        brand = re.sub(r"[^a-z]", "", (pkg_json or {}).get("name", "").lower()) if isinstance(pkg_json, dict) else ""
        for f in findings:
            if TEST_PATH_RE.search(f["file"]) and f["file"] not in run_files:
                f["severity"] = "INFO"
                f["description"] += " [test/example/docs file]"
            elif (f["id"] == "exfil_host" and brand and any(
                    b in brand and b in f["matched"].lower() for b in ("ngrok", "telegram", "discord", "slack",
                                                                         "pastebin", "localtunnel", "cloudflare",
                                                                         "pipedream", "webhook"))):
                f["severity"] = "INFO"
                f["description"] += " [the package is an integration for this service]"
            elif (f["id"] == "exfil_host" and CHAT_API_RE.search(f["matched"])
                    and not HARDCODED_CHAT_RE.search(f["context"])):
                f["severity"] = "INFO"
                f["description"] += " [chat API called with the user's own credential]"
            elif f["id"] == "exfil_host" and PLACEHOLDER_RE.search(f["context"]):
                f["severity"] = "INFO"
                f["description"] += " [placeholder / help-text URL]"
        _demote(findings, info)
    r = _summarise(findings, info, label, pkg_json)
    r["ecosystem"] = eco
    return r


def _summarise(findings, info, label, pkg_json=None):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    score = 0
    for f in findings:
        counts[f["severity"]] += 1
        score += SEVERITY_SCORE[f["severity"].lower()]
    level = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[s]), "SAFE")
    findings.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f["file"], f["line"]))
    parts = ["%d %s" % (counts[s], s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[s]]
    scripts = ((pkg_json or {}).get("scripts") or {})
    return {"target": label, "risk_score": min(score, 100), "risk_level": level,
            "summary": ", ".join(parts) or "No issues found",
            "install_scripts": {k: scripts[k] for k in LIFECYCLE if k in scripts},
            "findings": findings, "info": info,
            "total_findings": len(findings), "info_count": len(info)}


def scan(content, label="<text>"):
    """Scan a bare string (treated as install-time code if it looks like a script)."""
    findings, info = [], []
    _scan_text(content, label, findings, info, False)
    return _summarise(findings, info, label)


# ---------------------------------------------------------------------------
# Loading targets (never executes package code)
# ---------------------------------------------------------------------------
UA = {"User-Agent": "npm-audit/%s (+https://github.com/eltociear/npm-audit)" % __version__}


def _get(url, timeout=60, tries=3):
    for i in range(tries):
        try:
            return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout).read()
        except urllib.error.HTTPError:
            raise
        except Exception:
            if i == tries - 1:
                raise
            time.sleep(2 * (i + 1))


def split_spec(spec):
    if spec.startswith("@"):
        i = spec.find("@", 1)
    else:
        i = spec.find("@")
    return (spec, "latest") if i <= 0 else (spec[:i], spec[i + 1:] or "latest")


def fetch_manifest(name, version="latest"):
    q = urllib.parse.quote(name, safe="@")
    return json.loads(_get("%s/%s/%s" % (REGISTRY, q, urllib.parse.quote(version, safe=""))))


def files_from_tarball(data):
    out = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        for m in tf.getmembers():
            if not m.isfile():
                continue
            name = m.name.split("/", 1)[1] if "/" in m.name else m.name
            low = name.lower()
            if not (low.endswith(SCAN_EXT) or "/" not in name and "." not in name):
                continue
            if low.endswith(".json") and name != "package.json":
                continue
            if m.size > MAX_FILE:
                continue
            f = tf.extractfile(m)
            if f:
                out[name] = f.read().decode("utf-8", "replace")
    return out


def files_from_dir(root):
    out = {}
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in ("node_modules", ".git")]
        for fn in fns:
            p = os.path.join(dp, fn)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            if not fn.lower().endswith(SCAN_EXT) or (fn.endswith(".json") and rel != "package.json"):
                continue
            try:
                if os.path.getsize(p) > MAX_FILE:
                    continue
                with open(p, encoding="utf-8", errors="replace") as fh:
                    out[rel] = fh.read()
            except OSError:
                pass
    return out


def audit_registry(spec, ecosystem=None):
    name, ver = split_spec(spec)
    man = fetch_manifest(name, ver)
    files = files_from_tarball(_get(man["dist"]["tarball"], timeout=120))
    # the registry manifest is authoritative for scripts (tarball package.json can differ)
    pj = json.loads(files.get("package.json") or "{}")
    if man.get("scripts"):
        pj["scripts"] = man["scripts"]
    files["package.json"] = json.dumps(pj)
    return scan_package(files, "%s@%s" % (name, man.get("version", ver)), ecosystem)


def search_keyword(keyword, limit=250):
    """Registry search by keyword -> [name@version], most-downloaded first (search pages of 250)."""
    out, frm = [], 0
    while len(out) < limit:
        size = min(250, limit - len(out))
        d = json.loads(_get("%s/-/v1/search?text=keywords:%s&size=%d&from=%d" % (
            REGISTRY, urllib.parse.quote(keyword), size, frm)))
        objs = d.get("objects") or []
        for o in objs:
            p = o["package"]
            out.append(((o.get("downloads") or {}).get("monthly", 0), "%s@%s" % (p["name"], p["version"])))
        frm += len(objs)
        if not objs or frm >= d.get("total", 0):
            break
    return [s for _, s in sorted(out, key=lambda t: -t[0])]


def lockfile_specs(path):
    lock = json.load(open(path, encoding="utf-8"))
    specs = []
    for key, meta in (lock.get("packages") or {}).items():
        if not key or "node_modules/" not in key or meta.get("link"):
            continue
        name = meta.get("name") or key.rsplit("node_modules/", 1)[1]
        if meta.get("version"):
            specs.append("%s@%s" % (name, meta["version"]))

    def walk(deps):
        for name, meta in (deps or {}).items():
            if meta.get("version") and not meta["version"].startswith(("file:", "git", "http")):
                specs.append("%s@%s" % (name, meta["version"]))
            walk(meta.get("dependencies"))
    if not specs:
        walk(lock.get("dependencies"))
    return sorted(set(specs))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
_ICON = {"CRITICAL": "\U0001F534", "HIGH": "\U0001F7E0", "MEDIUM": "\U0001F7E1",
         "LOW": "\U0001F535", "SAFE": "\U0001F7E2"}


def _print(r, verbose):
    print("%s %s  [%s]  score=%d  (%d findings, %d info)" % (
        _ICON.get(r["risk_level"], "?"), r["target"], r["risk_level"], r["risk_score"],
        r["total_findings"], r["info_count"]))
    for k, v in r.get("install_scripts", {}).items():
        print("    script   %s: %s" % (k, v[:120]))
    for f in r["findings"]:
        print("    %-8s %s  %s:%s" % (f["severity"], f["name"], f["file"], f["line"]))
        if f["context"]:
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
    eco = ECO_N8N if "--n8n" in args else (ECO_NODE_RED if "--node-red" in args else None)
    limit = 250
    if "--limit" in args:
        i = args.index("--limit")
        limit = int(args[i + 1])
        del args[i:i + 2]
    args = [a for a in args if a not in ("--json", "--verbose", "-v", "--n8n", "--node-red")]
    if not args:
        print(__doc__)
        return 0
    targets = []  # (label, thunk)
    if args[0] == "--text":
        txt = " ".join(args[1:])
        targets.append(("<text>", lambda: scan(txt)))
    elif args[0] == "--lockfile":
        for spec in lockfile_specs(args[1]):
            targets.append((spec, (lambda s=spec: audit_registry(s, eco))))
    elif args[0] == "--keyword":
        for spec in search_keyword(args[1], limit):
            targets.append((spec, (lambda s=spec: audit_registry(s, eco))))
    elif args[0] == "--node-modules":
        root = args[1]
        for d in sorted(os.listdir(root)):
            ds = [os.path.join(d, s) for s in sorted(os.listdir(os.path.join(root, d)))] if d.startswith("@") else [d]
            for sub in ds:
                full = os.path.join(root, sub)
                if os.path.isfile(os.path.join(full, "package.json")):
                    targets.append((sub, (lambda f=full, s=sub: scan_package(files_from_dir(f), s, eco))))
    else:
        for a in args:
            if os.path.isdir(a):
                targets.append((a, (lambda p=a: scan_package(files_from_dir(p), p, eco))))
            elif os.path.isfile(a):
                if os.path.basename(a) == "package.json":
                    targets.append((a, (lambda p=a: scan_package(files_from_dir(os.path.dirname(p) or "."), p, eco))))
                else:
                    targets.append((a, (lambda p=a: scan_package({os.path.basename(p): open(p, encoding="utf-8", errors="replace").read()}, p, eco))))
            else:
                targets.append((a, (lambda s=a: audit_registry(s, eco))))
    results, worst = [], "SAFE"
    for label, thunk in targets:
        try:
            r = thunk()
        except Exception as e:  # network errors, 404s, corrupt tarballs
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
