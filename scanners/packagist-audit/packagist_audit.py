#!/usr/bin/env python3
"""packagist-audit - scan PHP Composer packages for MALICIOUS code before `composer install` runs it.

Composer runs third-party PHP on your machine and your servers in more places than people
assume:

  * composer-plugin packages: their plugin class runs INSIDE Composer on every install/update,
    as your user, with your auth.json, your environment and the network - before any of your
    own code runs.
  * autoload.files: required by vendor/autoload.php on EVERY request / CLI run of your app.
  * Laravel auto-discovered service providers and Symfony bundles: run at framework boot.
  * composer.json scripts: run only for the ROOT package (your project, or `create-project`).
  * everything else: plain classes, which only run when your code uses them.

`composer audit` only answers "does this version have a known advisory?". This fills the gap:
a deterministic (no LLM) static scan of the published dist for webshells, eval-of-decoded
payloads, environment / .env / cloud-key exfiltration, droppers, reverse shells, C2 command
loops and persistence - weighted by WHEN the code runs.

Precision-tuned to near-zero false positives: what popular packages do every day (HTTP
clients, Process wrappers, getenv(), template engines that eval compiled templates, plugins
that download recipes) is informational context and never inflates the score. Risk comes
from specific COMBINATIONS and sinks.

Nothing is installed or executed: the dist zip is downloaded into memory and read as text.

Usage:
  python packagist_audit.py <vendor/package>[@version] [...]   # fetch from Packagist and scan
  python packagist_audit.py <dir|composer.json|file.php|x.zip>  # scan a local package / file
  python packagist_audit.py <project-dir-with-vendor/>          # every installed package in vendor/
  python packagist_audit.py --lockfile composer.lock            # every locked dependency (dist refs)
  python packagist_audit.py --text '<?php eval(base64_decode($x));'
  add --json for machine-readable output, --verbose to print INFO context,
  --exec-only to scan only code that runs without being called (plugins, autoload files,
  providers/bundles, scripts)

Exit code 2 if any target is HIGH or CRITICAL (CI-friendly).
No dependencies beyond the standard library. MIT licensed.
"""
import bisect
import io
import json
import os
import posixpath
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

__version__ = "0.1.0"

REPO = os.environ.get("PACKAGIST_AUDIT_REPO", "https://repo.packagist.org").rstrip("/")
SCAN_EXT = (".php", ".phtml", ".inc", ".module", ".php5", ".php7", ".phps")
MAX_FILE = 1500000      # bytes; larger files are generated data tables - skipped
MAX_TOTAL = 24000000    # bytes of text scanned per package
MAX_ZIP = 150000000     # bytes downloaded per dist
SKIP_DIR = re.compile(r"(?:^|/)(?:tests?|Tests?|spec|specs|examples?|Examples?|docs?|Docs?|fixtures?|Fixtures?|"
                      r"stubs?|Stubs?|benchmarks?|Benchmarks?|\.github|vendor|node_modules)/")
# test harnesses and fixtures outside a tests/ dir: run-tests.php, ruleset-test.inc, FooTest.php
SKIP_NAME = re.compile(r"(?:^|/)(?:(?i:(?:[^/]*[-_.])?tests?(?:[-_.][^/]*)?\.(?:php|inc|phpt))|[^/]+Test\.(?:php|inc))$")

# ---------------------------------------------------------------------------
# Building blocks
# ---------------------------------------------------------------------------
EXFIL_HOST = (
    r"(?:discord(?:app)?\.com/api/webhooks/|api\.telegram\.org/bot|hooks\.slack\.com/services/|"
    r"\bwebhook\.site\b|\bpipedream\.net\b|requestbin\.(?:com|net|io)|\brequestb\.in\b|\brequestcatcher\.com\b|\bbeeceptor\.com\b|"
    r"pastebin\.com/(?:api|raw)|\bpaste\.ee\b|\bhastebin\.com\b|\btransfer\.sh\b|\bfile\.io/|"
    r"\bngrok(?:-free)?\.(?:io|app|dev)\b|\.trycloudflare\.com\b|\bserveo\.net\b|\blocaltunnel\.me\b|"
    r"\boastify\.com\b|\boast\.(?:fun|me|pro|live|site|online)\b|\binteract\.sh\b|\binteractsh\b|"
    r"\bburpcollaborator\.net\b|\bcanarytokens\.com\b|\bdnslog\.cn\b|\bceye\.io\b|\brequestrepo\.com\b|"
    r"\.workers\.dev\b)"
)
# Free app hosts: fine in general, but a classic drop for stolen keys (phpass/ctx 2022 used Heroku).
FREE_HOST = (r"(?:\.herokuapp\.com|\.glitch\.me|\.repl\.co|\.replit\.dev|\.onrender\.com|\.vercel\.app|"
             r"\.netlify\.app|\.pages\.dev|\.000webhostapp\.com|\.ngrok\.\w+|\.deno\.dev|\.fly\.dev)\b")
RAW_IP_URL = (r"(?:https?|tcp|ssl|tls|udp)://(?!(?:127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|"
              r"169\.254\.|2(?:2[4-9]|[3-5]\d)\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.))\d{1,3}(?:\.\d{1,3}){3}\b")
# "A global function call, not ->exec() / ::exec() / function exec(". Checked in Python after the
# match (see _nb_ok): a leading lookbehind would stop sre from skipping ahead to the first letter.
_NB = r"(?#nb)"
EXEC_SINK = (_NB + r"(?:exec|shell_exec|system|passthru|popen|proc_open|pcntl_exec)\s*\(|"
             r"`[^`\n]*\$[^`\n]*`|Process::fromShellCommandline\s*\(|new\s+\\?(?:Symfony\\Component\\Process\\)?Process\s*\(")
NET_SEND = (
    _NB + r"(?:curl_exec|curl_multi_exec|fsockopen|pfsockopen|stream_socket_client|socket_connect|socket_sendto)\s*\(|"
    + _NB + r"(?:file_get_contents|fopen|readfile|file|copy|get_headers|simplexml_load_file)\s*\(\s*['\"](?:https?|ftp)://|"
    + _NB + r"file_get_contents\s*\([^,\n;]{1,120},\s*(?:false|0|true|null)\s*,\s*\$\w*(?:ctx|context|opts|stream)\w*|"
    r"\bGuzzleHttp\\\\?Client\b|\bnew\s+Client\s*\(\s*\[\s*['\"]base_uri|\bHttp::(?:post|get|put|withHeaders|asForm|send|withToken)\s*\(|"
    r"\bHttpClient::create\s*\(|->httpDownloader->|\bwp_remote_(?:post|get|request)\s*\(|\bcurl_init\s*\(\s*['\"]https?://"
)
CHECKSUM = r"(?:hash_file|sha1_file|md5_file|hash_equals|openssl_verify|sodium_crypto_sign_verify|checksum|shasum|sha256|sha384|sha512|signature)"
SUPERGLOBAL = r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b"
DECODER = r"(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|hex2bin|convert_uudecode|rawurldecode|urldecode|pack|gzinflate|bzdecompress)"

PATTERNS = {
    "critical": [
        {"id": "webshell", "name": "Webshell (request input executed)",
         "desc": "Passes HTTP request input ($_GET/$_POST/$_REQUEST/$_COOKIE) to eval/assert/system/exec or calls it as a function",
         "view": "skel", "needles": ["$_"],
         "regexes": [
             _NB + r"(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|create_function|"
             r"call_user_func(?:_array)?)\s*\(\s*(?:@?\s*[\w\\]+\s*\(\s*){0,3}@?\s*" + SUPERGLOBAL,
             r"(?<![\w$])@?" + SUPERGLOBAL + r"\s*\[[^\]\n]{1,40}\]\s*\(",
             r"`\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[",
         ]},
        {"id": "eval_decode", "name": "Eval of Decoded Payload",
         "desc": "eval()/assert() of base64_decode/gzinflate/str_rot13/hex2bin output - the classic PHP backdoor loader",
         "view": "skel", "needles": ["eval", "assert"],
         "regexes": [_NB + r"(?:eval|assert)\s*\(\s*(?:['\"][^'\"\n]{0,4}['\"]\s*\.\s*)?@?\s*(?:" + DECODER + r"\s*\(\s*@?\s*)+"]},
        {"id": "remote_code", "start_in_code": True, "name": "Remote Code Execution",
         "desc": "include/require of a URL or data:/php://input stream, or eval() of fetched content",
         "view": "code", "needles": ["include", "require", "eval", "assert"],
         "regexes": [
             _NB + r"(?:include|require)(?:_once)?\s*\(?\s*['\"](?:(?:https?|ftp|expect)://|php://input|"
             r"data:(?://)?[\w/+.-]*(?:;base64)?,[A-Za-z0-9+/=%]{8,})",
             _NB + r"(?:eval|assert)\s*\(\s*(?:['\"]\?>['\"]\s*\.\s*)?@?\s*(?:file_get_contents|curl_exec|stream_get_contents|fread|fgets)\s*\(\s*['\"]?(?:https?|ftp)://",
         ]},
        {"id": "download_execute", "name": "Download & Execute",
         "desc": "Fetches remote content and pipes it straight into a shell/interpreter",
         "view": "code", "needles": ["curl", "wget", "iex", "invoke-", "powershell", "sh <"],
         "regexes": [
             r"curl\s+[^\n|;\"']*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|php|python3?|perl)\b",
             r"wget\s+[^\n|;\"']*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|php|python3?|perl)\b",
             r"wget\s+[^\n]*-O-?\s*-\s*\|\s*(?:sh|bash)",
             r"(?:sh|bash|php|python3?)\s*<\s*\(\s*(?:curl|wget)",
             r"(?:iex|Invoke-Expression)\s*\(?\s*\(?\s*(?:New-Object\s+Net\.WebClient|iwr|Invoke-WebRequest)",
             r"powershell[^\n]{0,60}-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}",
         ]},
        {"id": "env_exfil", "name": "Environment Dump",
         "desc": "Serialises the whole environment ($_ENV / $_SERVER / getenv()) - exfil when a network sink is present",
         "view": "skel", "needles": ["$_env", "$_server", "getenv"],
         "regexes": [
             _NB + r"(?:json_encode|serialize|http_build_query|var_export|print_r|base64_encode|implode)\s*\(\s*(?:['\"][^'\"\n]*['\"]\s*,\s*)?"
             r"(?:\$_ENV|\$_SERVER|getenv\s*\(\s*\))\s*(?:,\s*(?:true|1)\s*)?\)",
         ]},
        {"id": "reverse_shell", "name": "Reverse Shell",
         "desc": "Spawns an interactive shell bound to a network socket",
         "view": "code", "needles": ["/dev/tcp", "bash -i", "nc ", "ncat", "<&"],
         "regexes": [
             r"/dev/tcp/[\w.\-]+/\d+",
             r"\bbash\s+-i\s*>&",
             r"\bnc(?:at)?\s+(?:-\w+\s+)*-e\s+/bin/(?:ba)?sh",
             r"/bin/(?:ba)?sh\s+-i\s*<&\s*\d\s*>&\s*\d",
         ]},
        {"id": "destructive", "name": "Destructive Payload",
         "desc": "Wipes the home directory / filesystem",
         "view": "code", "needles": ["rm "],
         "regexes": [r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+(?:--no-preserve-root\s+)?(?:~|\$HOME|/)(?:\s|[\"'`;]|$)"]},
        {"id": "worm_propagation", "name": "Self-Propagation (Worm)",
         "desc": "Uses stolen registry / GitHub tokens to publish packages or harvest secrets at scale",
         "view": "code", "needles": ["trufflehog", "packagist.org/api/create"],
         "regexes": [
             r"trufflehog[^\n]{0,80}(?:filesystem|github|--json)",
             r"github\.com/trufflesecurity/trufflehog/releases",
             r"packagist\.org/api/create-package",
         ]},
    ],
    "high": [
        {"id": "exfil_host", "name": "Exfiltration Endpoint",
         "desc": "Hard-codes a webhook / paste / tunnel / OAST collector host",
         "view": "code", "needles": ["discord", "telegram", "slack", "webhook", "pipedream", "request", "beeceptor",
                                     "paste", "hastebin", "transfer.sh", "file.io", "ngrok", "trycloudflare", "serveo",
                                     "localtunnel", "oast", "interact", "burp", "canarytokens", "dnslog", "ceye", "workers.dev"],
         "regexes": [EXFIL_HOST]},
        {"id": "persistence_write", "start_in_code": True, "name": "Persistence Write",
         "desc": "Writes shell rc files, authorized_keys, crontab, autostart, or a PHP auto_prepend_file backdoor",
         "view": "code", "needles": ["bashrc", "zshrc", "profile", "authorized_keys", "crontab", "launchagents",
                                     "autostart", "/etc/cron", "auto_prepend_file", "user.ini"],
         "regexes": [
             r"(?:file_put_contents|fopen|fwrite|copy|rename|symlink)\s*\([^\n]{0,160}(?:\.bashrc|\.zshrc|\.bash_profile|\.zprofile|"
             r"[\"'/]\.profile\b|authorized_keys|LaunchAgents|LaunchDaemons|\.config/autostart|systemd/user|/etc/cron|\.user\.ini)",
             r"crontab\s+-[^l\s]",
             r"auto_prepend_file\s*=\s*[^\n]{0,80}\.php",
         ]},
        {"id": "wallet_theft", "name": "Wallet / Browser Data Theft",
         "desc": "Targets wallet keystores, browser credential stores or the macOS Keychain",
         "view": "code", "needles": ["nkbih", "bfnael", "hnfank", "ibnejd", "egjidj", "login data", "local extension",
                                     "exodus", "electrum", "find-generic-password", "wallet.dat", "seed.seco"],
         "regexes": [
             r"nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|hnfanknocfeofbddgcijnmhnfnkdnaad|ibnejdfjmmkpcnlpebklmnkoeoihofec|egjidjbpglichdcondbcbdnbeeppgdph",
             r"(?:Chrome|BraveSoftware|Microsoft/Edge|Opera Software)[^\n]{0,80}(?:Login Data|Local Extension Settings)",
             r"(?:Exodus|atomic|Electrum)[/\\\\](?:exodus\.wallet|Local Storage|wallets)",
             r"find-generic-password",
             r"\b(?:wallet\.dat|seed\.seco)\b",
         ]},
        {"id": "dns_exfil", "start_in_code": True, "name": "DNS Exfiltration",
         "desc": "Encodes host/user/env data into a DNS lookup (dependency-confusion beacon)",
         "view": "code", "needles": ["gethostbyname", "dns_get_record", "checkdnsrr"],
         "regexes": [
             _NB + r"(?:gethostbyname|gethostbynamel|dns_get_record|checkdnsrr)\s*\([^\n;]{0,160}(?:gethostname\s*\(|php_uname\s*\(|"
             r"get_current_user\s*\(|getenv\s*\(|\$_SERVER|\$_ENV|whoami|bin2hex\s*\(|base64_encode\s*\()[^\n;]{0,120}\.\s*['\"]\.[\w-]+\.",
         ]},
        {"id": "webshell_marker", "name": "Known Webshell Marker",
         "desc": "Strings from well-known PHP webshell kits (FilesMan, c99, r57, b374k, WSO, IndoXploit)",
         "view": "code", "needles": ["filesman", "c99", "r57", "b374k", "wso_", "wsosetcookie", "indoxploit", "alfa_"],
         "regexes": [r"\b(?:FilesMan|c99shell|c99_buff_prepare|r57shell|b374k|wso_version|WSOsetcookie|IndoXploit|Alfa_?Shell|alfa_ex)\b"]},
        {"id": "preg_e", "start_in_code": True, "name": "preg_replace /e Code Execution",
         "desc": "preg_replace with the /e modifier evaluates the replacement as PHP (removed in PHP 7; a backdoor idiom)",
         "view": "code", "needles": ["preg_replace"],
         "regexes": [_NB + r"preg_replace\s*\(\s*(['\"])([^\w\s\\'\"])[^\n]{0,300}?\2[imsxuADSUXJ]*e[imsxuADSUXJ]*\1\s*,"]},
    ],
    "medium": [
        {"id": "raw_ip_url", "name": "Raw-IP URL",
         "desc": "Contacts a public IP address directly instead of a hostname",
         "view": "code", "needles": ["://"], "regexes": [RAW_IP_URL]},
        {"id": "tls_disabled", "name": "TLS Verification Disabled",
         "desc": "Turns off certificate checking",
         "view": "code", "needles": ["verifypeer", "verify_peer", "verifyhost", "'verify'", "insecure", "no-check-cert"],
         "regexes": [r"CURLOPT_SSL_VERIFYPEER\s*(?:=>|,)\s*(?:false|0)\b", r"['\"]verify_peer['\"]\s*=>\s*false",
                     r"\bcurl\s+[^\n]*(?:-k\b|--insecure)", r"wget\s+[^\n]*--no-check-certificate"]},
    ],
    "low": [],
    # Context: reported, never scored. Capabilities popular packages use daily.
    "info": [
        {"id": "credential_read", "name": "Credential Store Reference",
         "desc": "References .env, auth.json, ~/.ssh, ~/.aws, wp-config.php, .git-credentials",
         "view": "code", "needles": [".env", "auth.json", ".ssh", ".aws", "git-credentials", "wp-config", "composer_auth", ".npmrc", ".pgpass"],
         "regexes": [r"['\"/]\.env(?:\.local|\.production)?['\"]", r"\bauth\.json\b", r"COMPOSER_AUTH", r"\.ssh/id_\w+",
                     r"\.aws/credentials", r"\.git-credentials", r"wp-config\.php", r"\.npmrc", r"\.pgpass", r"\.docker/config\.json"]},
        {"id": "secret_env", "name": "Secret Environment Variable",
         "desc": "Reads a secret-named environment variable (AWS keys, *_TOKEN, *_SECRET, *_PASSWORD)",
         "view": "code", "needles": ["getenv", "$_env", "$_server", "env("],
         "regexes": [r"(?:getenv\s*\(|\$_ENV\s*\[|\$_SERVER\s*\[|(?<![\w>:$])env\s*\()\s*['\"](?:AWS_(?:SECRET_ACCESS_KEY|ACCESS_KEY_ID|SECRET_KEY|ACCESS_KEY|SESSION_TOKEN)|"
                     r"GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|COMPOSER_AUTH|DB_PASSWORD|DATABASE_URL|STRIPE_SECRET\w*|[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY)[A-Z0-9_]*)['\"]"]},
        {"id": "process_spawn", "name": "Process Spawning",
         "desc": "Runs external commands (exec/shell_exec/proc_open/Process)",
         "view": "skel", "needles": ["exec", "system", "passthru", "popen", "proc_open", "process", "`"], "regexes": [EXEC_SINK]},
        {"id": "network", "name": "Network Access",
         "desc": "Makes outbound HTTP/socket calls",
         "view": "code", "needles": ["curl", "sock", "http", "ftp", "client", "downloader", "wp_remote", "context"], "regexes": [NET_SEND]},
        {"id": "env_read", "name": "Environment Access",
         "desc": "Reads environment variables",
         "view": "skel", "needles": ["getenv", "$_env", "putenv"], "regexes": [_NB + r"getenv\s*\(", r"\$_ENV\b"]},
        {"id": "eval_use", "name": "eval() Use",
         "desc": "Calls eval() (template engines, code generators, proxies do this legitimately)",
         "view": "skel", "needles": ["eval"], "regexes": [_NB + r"eval\s*\("]},
        {"id": "decode_use", "name": "Decoder Use",
         "desc": "base64_decode/gzinflate/str_rot13 - common data handling, risky only beside eval/exec",
         "view": "skel", "needles": ["base64_decode", "gzinflate", "gzuncompress", "str_rot13", "hex2bin"],
         "regexes": [_NB + r"(?:base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin|convert_uudecode)\s*\("]},
        {"id": "create_function", "name": "create_function()",
         "desc": "Deprecated eval wrapper (removed in PHP 8)", "view": "skel", "needles": ["create_function"],
         "regexes": [_NB + r"create_function\s*\("]},
    ],
}

SEVERITY_SCORE = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "SAFE": 0}
DEMOTE = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "INFO", "INFO": "INFO"}
_COMPILED = [(sev, pg, [re.compile(rx, re.IGNORECASE if pg["id"] not in ("secret_env",) else 0) for rx in pg["regexes"]])
             for sev, groups in PATTERNS.items() for pg in groups]
_ALL_NEEDLES = sorted({n for _, pg, _ in _COMPILED for n in pg["needles"]}, key=len, reverse=True)
_NEEDLE_RE = re.compile("|".join(re.escape(n) for n in _ALL_NEEDLES))
NET_RE = re.compile(NET_SEND, re.I)
EXEC_RE = re.compile(EXEC_SINK, re.I)
EXFIL_RE = re.compile(EXFIL_HOST, re.I)
FREE_RE = re.compile(FREE_HOST, re.I)
RAWIP_RE = re.compile(RAW_IP_URL, re.I)
CHECKSUM_RE = re.compile(CHECKSUM, re.I)
CHMOD_RE = re.compile(_NB + r"chmod\s*\(\s*[^,\n]+,\s*0?[0-7]*[1357][0-7]{0,2}\s*\)|chmod\s+\+?[0-7]*x|chmod\s+[0-7]*[1357][0-7]{2}\b", re.I)
WRITE_RE = re.compile(_NB + r"(?:file_put_contents|fwrite|fputs|copy|move_uploaded_file|stream_copy_to_stream)\s*\(", re.I)
DYN_EXEC_RE = re.compile(_NB + r"(?:exec|shell_exec|system|passthru|popen|proc_open|pcntl_exec)\s*\(\s*(?:escapeshellarg\s*\(\s*|escapeshellcmd\s*\(\s*)?\$", re.I)
SOCK_RE = re.compile(_NB + r"(?:fsockopen|pfsockopen|stream_socket_client|socket_connect)\s*\(", re.I)
SOCK_READ_RE = re.compile(_NB + r"(?:fgets|fread|socket_read|socket_recv|stream_get_line|stream_get_contents)\s*\(\s*\$", re.I)
SHELL_LIT_RE = re.compile(r"['\"][^'\"\n]{0,80}(?:/bin/)?(?:ba|z)?sh\s+-i\b|['\"](?:cmd\.exe|powershell\.exe)['\"]", re.I)
SOCK_DESC_RE = re.compile(r"(?:array\s*\(|\[)\s*0\s*=>\s*\$(?:sock(?:et)?|s|conn(?:ection)?|client|fp)\s*,", re.I)
CRED_READ_RE = re.compile(_NB + r"(?:file_get_contents|fopen|file|parse_ini_file|readfile|parse_ini_string)\s*\([^;\n]{0,160}"
                          r"(?:\.ssh/|\.aws/|\.git-credentials|auth\.json|\.env['\"])", re.I)
PROC_OPEN_RE = re.compile(_NB + r"(?:proc_open|popen)\s*\(", re.I)
DYN_CALL_RE = re.compile(r"(?#nbs)\$\w+\s*\(|\$\{\s*['\"][^'\"]+['\"]\s*\}\s*\(|\$\w+\s*\[\s*[^\]\n]{1,20}\]\s*\(", re.I)
CALLER_RE = re.compile(_NB + r"(?:eval|assert|create_function|call_user_func(?:_array)?|array_map|array_filter|usort|uasort|register_shutdown_function|"
                       r"register_tick_function|ob_start|preg_replace_callback|array_walk)\s*\(\s*\$", re.I)
HEX_STR_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){6,}")
OCT_STR_RE = re.compile(r"(?:\\[0-7]{3}){6,}")
CHR_CHAIN_RE = re.compile(r"(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){3,}chr\s*\(\s*\d+\s*\)", re.I)
CONCAT_RE = re.compile(r"(?:['\"][a-z0-9_]{1,12}['\"]\s*\.\s*){1,7}['\"][a-z0-9_]{1,12}['\"]", re.I)
_PIECE_RE = re.compile(r"['\"]([a-z0-9_]{1,12})['\"]", re.I)
BLOB_RE = re.compile(r"[A-Za-z0-9+/]{4096,}={0,2}")
DANGEROUS_FN = ("system", "exec", "shell_exec", "passthru", "popen", "proc_open", "pcntl_exec", "eval", "assert",
                "base64_decode", "gzinflate", "gzuncompress", "str_rot13", "create_function", "call_user_func",
                "file_put_contents", "fsockopen", "stream_socket_client", "curl_exec", "move_uploaded_file")


def _nb_ok(view, i, strict=False):
    """True if the match at i is a plain function call (not a method, static call, variable or
    declaration). strict: also reject a namespace backslash (used for $var( calls)."""
    if i:
        c = view[i - 1]
        if c.isalnum() or c in "_>:$" or (strict and c == "\\"):
            return False
        if view[max(0, i - 9):i] == "function ":
            return False
    return True


def _nb_kind(rx):
    src = rx.pattern
    return "nbs" if "(?#nbs)" in src else ("nb" if "(?#nb)" in src else None)


def _finditer(rx, view, kind=None):
    if kind is None:
        kind = _nb_kind(rx)
    for m in rx.finditer(view):
        if kind is None or _nb_ok(view, m.start(), kind == "nbs"):
            yield m


def _search(rx, view, kind=None):
    for m in _finditer(rx, view, kind):
        return m
    return None


def _rot13(s):
    return s.translate(str.maketrans("abcdefghijklmnopqrstuvwxyz", "nopqrstuvwxyzabcdefghijklm"))


def _encoded_names():
    import base64
    out = {}
    for fn in DANGEROUS_FN:
        for label, enc in (("base64", base64.b64encode(fn.encode()).decode().rstrip("=")),
                           ("rot13", _rot13(fn)), ("reversed", fn[::-1])):
            if enc != fn:
                out[enc.lower()] = (label, fn)
    return out


ENCODED_NAMES = _encoded_names()
ENC_LIT_RE = re.compile(r"['\"](" + "|".join(re.escape(k) for k in sorted(ENCODED_NAMES, key=len, reverse=True)) + r")=*['\"]", re.I)
LINE_ONCE = ("network", "env_read", "process_spawn", "eval_use", "decode_use", "credential_read", "secret_env", "create_function")

CTX_NOTE = {"plugin": "runs inside Composer at install/update",
            "autoload-files": "runs on every request (autoload.files)",
            "boot": "runs at framework boot (auto-discovered provider / bundle)",
            "root-script": "composer script: runs only when this package is the root project"}
ESCALATING = ("plugin", "autoload-files", "boot")


# ---------------------------------------------------------------------------
# PHP lexing: blank comments (and, for the skeleton view, string contents)
# ---------------------------------------------------------------------------
_OPEN_RE = re.compile(r"<\?(?:php\b|=|(?=\s))", re.I)
_TOK_RE = re.compile(r"//|#(?!\[)|/\*|'|\"|<<<|\?>|`")
_SQ_RE = re.compile(r"'[^'\\]*(?:\\[\s\S][^'\\]*)*'")
_DQ_RE = re.compile(r"\"[^\"\\]*(?:\\[\s\S][^\"\\]*)*\"")
_BQ_RE = re.compile(r"`[^`\\]*(?:\\[\s\S][^`\\]*)*`")
_HEREDOC_RE = re.compile(r"<<<[ \t]*(['\"]?)([A-Za-z_]\w*)\1\r?\n")


def _nl(s):
    return " " + "\n" * s.count("\n")


_NOT_NL = re.compile(r"[^\n]")


def _same(s):
    """Blank s, keeping its length and newlines (keeps code/skel offsets aligned)."""
    return _NOT_NL.sub(" ", s)


def php_views(text, raw_php=False):
    """Return (code, skel). code: comments and inline HTML blanked. skel: also string contents
    blanked, same length as code, so an offset in one view is the same place in the other."""
    code, skel = [], []
    pos, n = 0, len(text)
    in_php = raw_php
    while pos < n:
        if not in_php:
            m = _OPEN_RE.search(text, pos)
            if not m:
                b = _nl(text[pos:])
                code.append(b)
                skel.append(b)
                break
            b = _nl(text[pos:m.start()])
            code.append(b)
            skel.append(b)
            code.append(" ")
            skel.append(" ")
            pos = m.end()
            in_php = True
            continue
        m = _TOK_RE.search(text, pos)
        if not m:
            code.append(text[pos:])
            skel.append(text[pos:])
            break
        seg = text[pos:m.start()]
        code.append(seg)
        skel.append(seg)
        t = m.group(0)
        pos = m.start()
        if t in ("//", "#"):
            nl = text.find("\n", pos)
            cl = text.find("?>", pos)
            end = min(x for x in (nl, cl, n) if x >= 0)
            b = _nl(text[pos:end])
            code.append(b)
            skel.append(b)
            pos = end
        elif t == "/*":
            end = text.find("*/", pos + 2)
            end = n if end < 0 else end + 2
            b = _nl(text[pos:end])
            code.append(b)
            skel.append(b)
            pos = end
        elif t in ("'", '"', "`"):
            rx = {"'": _SQ_RE, '"': _DQ_RE, "`": _BQ_RE}[t]
            sm = rx.match(text, pos)
            end = sm.end() if sm else n
            s = text[pos:end]
            code.append(s)
            if t == "`":
                skel.append(s)
            else:
                skel.append(t + _same(s[1:-1]) + t if len(s) >= 2 else s)
            pos = end
        elif t == "<<<":
            hm = _HEREDOC_RE.match(text, pos)
            if not hm:
                code.append(t)
                skel.append(t)
                pos += 3
                continue
            em = re.compile(r"^[ \t]*" + re.escape(hm.group(2)) + r"\b", re.M).search(text, hm.end())
            end = em.end() if em else n
            s = text[pos:end]
            code.append(s)
            skel.append(_same(s))
            pos = end
        else:  # ?>
            code.append(" ")
            skel.append(" ")
            pos += 2
            in_php = False
    return "".join(code), "".join(skel)


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------
def _item(sev, pid, name, desc, path, n, matched, ctx):
    return {"severity": sev, "id": pid, "name": name, "description": desc, "file": path,
            "line": n, "matched": matched[:120], "context": ctx.strip()[:200], "ctx": "runtime"}


def _demote_ids(findings, ids):
    for f in findings:
        if f["id"] in ids:
            f["severity"] = "INFO"


def _decode_escapes(m):
    s = m.group(0)
    try:
        if s.startswith("\\x"):
            return bytes(int(h, 16) for h in re.findall(r"\\x([0-9a-fA-F]{2})", s)).decode("latin-1")
        return bytes(int(o, 8) & 0xFF for o in re.findall(r"\\([0-7]{3})", s)).decode("latin-1")
    except ValueError:
        return ""


_HIDDEN_TEXT_RE = re.compile(r"(?:" + "|".join(DANGEROUS_FN) + r"|https?://|/bin/|/dev/tcp|\$_(?:GET|POST|REQUEST|COOKIE))", re.I)


def _encoded_name_hits(code):
    hits = []
    for rx in (HEX_STR_RE, OCT_STR_RE):
        for m in rx.finditer(code):
            dec = _decode_escapes(m)
            hm = _HIDDEN_TEXT_RE.search(dec)
            if hm:
                hits.append((m.start(), "escaped string spelling %r" % hm.group(0)))
    if "chr" in code:
        for m in CHR_CHAIN_RE.finditer(code):
            dec = "".join(chr(int(x) & 0xFF) for x in re.findall(r"\d+", m.group(0)))
            hm = _HIDDEN_TEXT_RE.search(dec)
            if hm:
                hits.append((m.start(), "chr() chain spelling %r" % hm.group(0)))
    for m in ENC_LIT_RE.finditer(code):
        label, fn = ENCODED_NAMES[m.group(1).lower()]
        hits.append((m.start(), "%s of %s()" % (label, fn)))
    for m in CONCAT_RE.finditer(code):
        joined = "".join(_PIECE_RE.findall(m.group(0))).lower()
        if joined in DANGEROUS_FN:
            hits.append((m.start(), "split string forming %s()" % joined))
    return hits


_SOCK_VAR_RE = re.compile(r"\$(\w+)\s*\.?=\s*(?:@\s*)?(?:(?:trim|rtrim|base64_decode|gzinflate)\s*\(\s*)*"
                          r"(?:fgets|fread|socket_read|socket_recv|stream_get_line|stream_get_contents)\s*\(", re.I)


def _socket_to_exec(skel):
    """A variable read from a socket is passed straight to a command sink (C2 data flow)."""
    for v in set(_SOCK_VAR_RE.findall(skel)):
        if re.search(r"(?<![\w>:$])(?:exec|shell_exec|system|passthru|popen|proc_open|pcntl_exec|eval)\s*\(\s*"
                     r"(?:(?:base64_decode|trim)\s*\(\s*)?\$" + re.escape(v) + r"\b", skel, re.I):
            return True
    return False


def _match_rule(sev, pg, rx, view, code, skel, kind, path, lines, line_of, seen, local):
    pid = pg["id"]
    once = pid in LINE_ONCE
    if once and (pid, 0) in seen:
        return
    sic = pg.get("start_in_code") and kind == "php"
    for m in _finditer(rx, view):
        if sic and skel[m.start()] != code[m.start()]:
            continue  # the call is quoted inside a string (a code sample / doc), not made
        n = line_of(m.start())
        if (pid, n) in seen:
            continue
        seen.add((pid, n))
        line = lines[n - 1] if n - 1 < len(lines) else ""
        local.append(_item(sev.upper(), pid, pg["name"], pg["desc"], path, n, m.group(0), line))
        if once:
            seen.add((pid, 0))
            return


class _Gated(object):
    """A regex that is only run when one of its literal needles occurs in the (lowercased) file."""
    def __init__(self, rx, needles):
        self.rx, self.needles, self.kind = rx, needles, _nb_kind(rx)

    def __call__(self, view, low):
        return any(n in low for n in self.needles) and _search(self.rx, view, self.kind)


_EXFIL_NEEDLES = next(pg["needles"] for pg in PATTERNS["high"] if pg["id"] == "exfil_host")
_G = {"NET_RE": _Gated(NET_RE, ['curl', 'sock', 'http', 'ftp', 'client', 'downloader', 'wp_remote', 'context']), "EXEC_RE": _Gated(EXEC_RE, ['exec', 'system', 'passthru', 'popen', 'proc_open', 'process', '`']), "EXFIL_RE": _Gated(EXFIL_RE, _EXFIL_NEEDLES), "FREE_RE": _Gated(FREE_RE, ['herokuapp', 'glitch', 'repl', 'onrender', 'vercel', 'netlify', 'pages.dev', '000webhost', 'ngrok', 'deno.dev', 'fly.dev']), "RAWIP_RE": _Gated(RAWIP_RE, ['://']), "SOCK_RE": _Gated(SOCK_RE, ['sockopen', 'stream_socket_client', 'socket_connect']), "PROC_OPEN_RE": _Gated(PROC_OPEN_RE, ['popen', 'proc_open']), "SHELL_LIT_RE": _Gated(SHELL_LIT_RE, ['sh', 'cmd', 'powershell']), "SOCK_READ_RE": _Gated(SOCK_READ_RE, ['fgets', 'fread', 'socket_re', 'stream_get']), "DYN_EXEC_RE": _Gated(DYN_EXEC_RE, ['exec', 'system', 'passthru', 'popen', 'proc_open']), "WRITE_RE": _Gated(WRITE_RE, ['file_put_contents', 'fwrite', 'fputs', 'copy', 'move_uploaded_file', 'stream_copy']), "CHMOD_RE": _Gated(CHMOD_RE, ['chmod']), "CALLER_RE": _Gated(CALLER_RE, ['eval', 'assert', 'create_function', 'call_user_func', 'array_', 'usort', 'uasort', 'register_', 'ob_start', 'preg_replace_callback']), "DYN_CALL_RE": _Gated(DYN_CALL_RE, ['$']), "CHR_CHAIN_RE": _Gated(CHR_CHAIN_RE, ['chr']), "CRED_READ_RE": _Gated(CRED_READ_RE, ['.ssh/', '.aws/', 'git-credentials', 'auth.json', '.env'])}


def _scan_text(text, path, findings, info, ctx, kind="php", ptype=""):
    """Line pass + file-level combination rules.
    ctx: None | 'plugin' | 'autoload-files' | 'boot' | 'root-script'.  kind: 'php' | 'shell'."""
    blob = len(text) > 4096 and bool(BLOB_RE.search(text))
    if blob:
        text = BLOB_RE.sub("B64BLOB", text)
    if kind == "php":
        code, skel = php_views(text)
    else:
        code = skel = text
    if not code.strip():
        return
    nl_idx = [m.start() for m in re.finditer("\n", code)]
    lines = code.split("\n")
    low = code.lower()
    seen = set()
    local = []

    def line_of(off):
        return bisect.bisect_right(nl_idx, off) + 1

    present = set()
    for nd in _ALL_NEEDLES:     # one substring pass per needle, not one per regex
        if nd in low:
            present.add(nd)
    for sev, pg, rxs in _COMPILED:
        if present.isdisjoint(pg["needles"]):
            continue
        view = skel if pg["view"] == "skel" else code
        for rx in rxs:
            _match_rule(sev, pg, rx, view, code, skel, kind, path, lines, line_of, seen, local)
    ids = {f["id"] for f in local}
    memo = {}

    def lazy(key, fn):
        if key not in memo:
            memo[key] = bool(fn())
        return memo[key]
    net = lambda: lazy("net", lambda: _G['NET_RE'](code, low))                         # noqa: E731
    has_exec = lambda: lazy("exec", lambda: kind == "shell" or _G['EXEC_RE'](skel, low))  # noqa: E731
    url_bad = lambda: lazy("url", lambda: _G['EXFIL_RE'](code, low) or _G['FREE_RE'](code, low)  # noqa: E731
                           or _G['RAWIP_RE'](code, low))

    def add(sev, pid, name, desc, n=0, matched="", context="file-level combination"):
        local.append(_item(sev, pid, name, desc, path, n, matched, context))
        ids.add(pid)

    # ---- demotions: capability without a sink -------------------------------------------
    if "env_exfil" in ids and not net():
        _demote_ids(local, {"env_exfil"})       # debug pages / error handlers render $_SERVER locally
    if "exfil_host" in ids and not net():
        _demote_ids(local, {"exfil_host"})      # a URL in a string / docs / notifier config
    if "webshell_marker" in ids and not (has_exec() or "eval_use" in ids or _G['DYN_CALL_RE'](skel, low)):
        _demote_ids(local, {"webshell_marker"})  # signature lists in malware scanners / WAFs
    if "download_execute" in ids and not has_exec():
        _demote_ids(local, {"download_execute"})  # an install hint printed to the user, never run
    if "raw_ip_url" in ids and not (ctx in ESCALATING or "credential_read" in ids or "secret_env" in ids
                                    or "env_exfil" in ids or _G['SOCK_RE'](code, low)):
        _demote_ids(local, {"raw_ip_url"})
    if ctx not in ESCALATING:
        # installers / deploy tools write crontabs; HTTP clients expose verify=false as an option
        _demote_ids(local, {"persistence_write", "tls_disabled"})

    # ---- combinations --------------------------------------------------------------------
    if ("credential_read" in ids or "secret_env" in ids) and url_bad() and net():
        add("CRITICAL", "credential_exfil", "Credential Exfiltration",
            "Reads a secret (env key / .env / auth.json / ssh / aws) and sends to a webhook, free-host or raw-IP endpoint in the same file")
    elif "credential_read" in ids and ctx == "plugin" and _G['CRED_READ_RE'](code, low) and net():
        add("CRITICAL", "credential_exfil", "Credential Exfiltration",
            "A Composer plugin reads ~/.ssh / ~/.aws / .env and talks to the network")
    # reverse shell: socket + process wired to it + a shell literal
    # (an OAuth loopback server that opens a browser has the socket + proc_open, not the shell)
    if "reverse_shell" not in ids and _G['SOCK_RE'](code, low) and _G['PROC_OPEN_RE'](skel, low) and \
            (_G['SHELL_LIT_RE'](code, low) or SOCK_DESC_RE.search(skel)) and _G['SOCK_READ_RE'](code, low):
        add("CRITICAL", "reverse_shell", "Reverse Shell",
            "Opens a socket and pipes it through a spawned shell")
    # C2 loop: socket / HTTP polling whose payload reaches a command sink
    elif _G['SOCK_RE'](code, low) and _G['SOCK_READ_RE'](code, low) and _G['DYN_EXEC_RE'](skel, low) and \
            re.search(r"\bwhile\s*\(\s*(?:true|1|!\s*feof)", code, re.I) and _socket_to_exec(skel):
        add("HIGH", "c2_loop", "Remote Command Loop",
            "Reads commands from a socket in a loop and executes them (RAT shape)")
    # dropper: (network | embedded blob | decoder) + write file + chmod + exec of a non-literal path
    if _G['CHMOD_RE'](code, low) and _G['DYN_EXEC_RE'](skel, low) and _G['WRITE_RE'](skel, low) and \
            (blob or "decode_use" in ids or net()):
        add("CRITICAL" if ctx in ESCALATING else "HIGH", "dropper", "Download/Unpack & Execute (dropper)",
            "Fetches or decodes a payload, writes it, marks it executable and runs it")
    # obfuscation: encoded dangerous names / hex strings / chr chains / blobs feeding a dynamic call
    strong_dyn = "eval_use" in ids or "create_function" in ids or _G['CALLER_RE'](skel, low) or _G['DYN_EXEC_RE'](skel, low)
    dyn = strong_dyn or _G['DYN_CALL_RE'](skel, low)
    enc = _encoded_name_hits(code) if dyn else []
    obf = enc or (blob and "decode_use" in ids and strong_dyn)
    if obf and "eval_decode" not in ids and "webshell" not in ids:
        where = enc[0][1] if enc else ("embedded base64 blob" if blob else "escaped / chr()-built strings")
        n = line_of(enc[0][0]) if enc else 0
        add("HIGH", "obfuscation", "Obfuscated Payload",
            "Hides code or function names (%s) and calls them dynamically" % where, n,
            context=(lines[n - 1] if n else "file-level combination"))
    # webshell-in-a-blob: decoder + eval on the same file + request input anywhere
    if "eval_decode" in ids and re.search(SUPERGLOBAL, code, re.I) and "webshell" not in ids:
        add("CRITICAL", "webshell", "Webshell (request input executed)",
            "Decodes and evals a payload in a file that reads request input")

    # ---- context: when does this file run? ------------------------------------------------
    for f in local:
        if f["severity"] == "INFO":
            continue
        if ctx in ESCALATING:
            if f["severity"] == "HIGH":
                f["severity"] = "CRITICAL"
                f["description"] += " [%s]" % CTX_NOTE[ctx]
            f["context_kind"] = ctx
        elif ctx == "root-script":
            f["context_kind"] = ctx
            if ptype == "project":
                if f["severity"] == "HIGH":
                    f["severity"] = "CRITICAL"
                f["description"] += " [runs on composer create-project]"
            else:  # never runs for dependents: at most MEDIUM
                if SEV_ORDER[f["severity"]] > SEV_ORDER["MEDIUM"]:
                    f["severity"] = "MEDIUM"
                f["description"] += " [%s]" % CTX_NOTE[ctx]
    for f in local:
        f["ctx"] = ctx or "runtime"
        (info if f["severity"] == "INFO" else findings).append(f)


# ---------------------------------------------------------------------------
# composer.json: which files run without being called?
# ---------------------------------------------------------------------------
def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _norm(p):
    p = posixpath.normpath(p.replace("\\", "/").lstrip("./") if p not in (".", "./", "") else ".")
    return "" if p == "." else p


def resolve_class(cls, auto, files):
    """Map a PHP class name to a file via psr-4 / psr-0, falling back to a declaration search."""
    cls = (cls or "").lstrip("\\")
    if not cls:
        return None
    for prefix, dirs in sorted((auto.get("psr-4") or {}).items(), key=lambda kv: -len(kv[0])):
        if cls.startswith(prefix):
            rel = cls[len(prefix):].replace("\\", "/") + ".php"
            for d in _as_list(dirs):
                p = _norm(posixpath.join(_norm(d), rel))
                if p in files:
                    return p
    for prefix, dirs in (auto.get("psr-0") or {}).items():
        if cls.startswith(prefix):
            ns, _, short = cls.rpartition("\\")
            rel = (ns.replace("\\", "/") + "/" if ns else "") + short.replace("_", "/") + ".php"
            for d in _as_list(dirs):
                p = _norm(posixpath.join(_norm(d), rel))
                if p in files:
                    return p
    ns, _, short = cls.rpartition("\\")
    decl = re.compile(r"^\s*(?:final\s+|abstract\s+|readonly\s+)*class\s+" + re.escape(short) + r"\b", re.M)
    cands = [p for p in files if p.endswith(".php") and decl.search(files[p])]
    for p in cands:
        if not ns or re.search(r"namespace\s+" + re.escape(ns) + r"\s*[;{]", files[p]):
            return p
    return cands[0] if cands else None


def _autoload_roots(auto):
    roots = []
    for key in ("psr-4", "psr-0"):
        for dirs in (auto.get(key) or {}).values():
            roots += [_norm(d) for d in _as_list(dirs)]
    roots += [_norm(d) for d in _as_list(auto.get("classmap"))]
    return roots


def _under(path, roots):
    return any(r == "" or path == r or path.startswith(r.rstrip("/") + "/") for r in roots)


SCRIPT_EVENTS = ("pre-install-cmd", "post-install-cmd", "pre-update-cmd", "post-update-cmd", "post-autoload-dump",
                 "pre-autoload-dump", "post-root-package-install", "post-create-project-cmd", "pre-package-install",
                 "post-package-install", "pre-package-update", "post-package-update", "pre-archive-cmd", "post-archive-cmd")


def exec_contexts(files, comp):
    """Return ({path: ctx}, summary) for code that runs without being called."""
    ctx, summary = {}, {"type": comp.get("type") or "library"}
    auto = comp.get("autoload") or {}
    roots = _autoload_roots(auto)
    for f in _as_list(auto.get("files")):
        p = _norm(f)
        if p in files:
            ctx[p] = "autoload-files"
    summary["autoload_files"] = sorted(p for p, c in ctx.items() if c == "autoload-files")
    extra = comp.get("extra") or {}
    if not isinstance(extra, dict):
        extra = {}
    if summary["type"] == "composer-plugin":
        classes = _as_list(extra.get("class"))
        entry = [resolve_class(c, auto, files) for c in classes if isinstance(c, str)]
        summary["plugin_classes"] = [c for c in classes if isinstance(c, str)]
        summary["plugin_files"] = sorted(p for p in entry if p)
        for p in summary["plugin_files"]:
            ctx[p] = "plugin"
        # a plugin's whole autoloaded code base is loaded into the Composer process
        for p in files:
            if p.endswith(SCAN_EXT) and p not in ctx and _under(p, roots) and not SKIP_DIR.search(p):
                ctx[p] = "plugin"
    lar = extra.get("laravel") if isinstance(extra.get("laravel"), dict) else {}
    provs = [c for c in _as_list(lar.get("providers")) if isinstance(c, str)]
    summary["providers"] = provs
    for c in provs:
        p = resolve_class(c, auto, files)
        if p and p not in ctx:
            ctx[p] = "boot"
    bundle_re = re.compile(r"class\s+\w+\s+extends\s+\\?(?:[\w\\]*\\)?(?:Abstract)?Bundle\b")
    bundles = []
    for p in files:
        if p.endswith(".php") and p not in ctx and _under(p, roots) and not SKIP_DIR.search(p) \
                and p.endswith("Bundle.php") and bundle_re.search(files[p]):
            ctx[p] = "boot"
            bundles.append(p)
    summary["bundles"] = sorted(bundles)
    scripts = comp.get("scripts") if isinstance(comp.get("scripts"), dict) else {}
    summary["scripts"] = sorted(k for k in scripts if k in SCRIPT_EVENTS)
    for ev, cmds in scripts.items():
        for c in _as_list(cmds):
            if not isinstance(c, str):
                continue
            m = re.match(r"^\s*([\w\\]+)::\w+\s*$", c)
            if m:
                p = resolve_class(m.group(1), auto, files)
                if p and p not in ctx:
                    ctx[p] = "root-script"
            for m in re.finditer(r"(?:@php|php|bash|sh)\s+(?:-\w+\s+)*([\w./-]+\.(?:php|sh))", c):
                p = _norm(m.group(1))
                if p in files and p not in ctx:
                    ctx[p] = "root-script"
    return ctx, summary


def scan_package(files, label="", exec_only=False):
    """files: {relative_path: text} (composer.json included). Returns an audit result dict."""
    findings, info = [], []
    try:
        comp = json.loads(files.get("composer.json") or "{}")
        if not isinstance(comp, dict):
            comp = {}
    except ValueError:
        comp = {}
    ctx, summary = exec_contexts(files, comp)
    ptype = summary["type"]
    excl = [_norm(x).replace("*", "") for x in _as_list((comp.get("autoload") or {}).get("exclude-from-classmap"))]
    scripts = comp.get("scripts") if isinstance(comp.get("scripts"), dict) else {}
    cmds = [c for v in scripts.values() for c in _as_list(v) if isinstance(c, str) and not re.match(r"^\s*@?[\w\\]+::\w+\s*$", c)]
    if cmds:
        _scan_text("\n".join(cmds), "composer.json#scripts", findings, info, "root-script", "shell", ptype)
    total = 0
    phars = []
    for path in sorted(files, key=lambda p: (p not in ctx, p)):
        if path.endswith(".phar"):
            phars.append(path)
            continue
        c = ctx.get(path)
        is_php = path.endswith(SCAN_EXT) or (c and path.endswith(".sh"))
        if not is_php:
            continue
        if exec_only and not c:
            continue
        if c is None and (SKIP_DIR.search(path) or SKIP_NAME.search(path) or any(e and path.startswith(e) for e in excl)):
            continue  # tests / docs / examples: not loaded by dependents
        total += len(files[path])
        if total > MAX_TOTAL:
            info.append(_item("INFO", "truncated", "Scan Truncated", "Package exceeds %d bytes of text" % MAX_TOTAL,
                              path, 0, "", ""))
            break
        _scan_text(files[path], path, findings, info, c, "shell" if path.endswith(".sh") else "php", ptype)
    for p in phars:
        info.append(_item("INFO", "bundled_phar", "Bundled PHAR", "Ships a .phar archive (not unpacked by this scan)",
                          p, 0, "", ""))
    r = _summarise(findings, info, label)
    r["exec_context"] = summary
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


def scan(content, label="<text>", ctx="plugin"):
    """Scan a bare string. Treated as install-time (plugin) code by default - the conservative case."""
    findings, info = [], []
    kind = "php" if "<?" in content else "shell"
    if kind == "shell" and re.search(r"\$\w+\s*=|\w+\s*\(.*\)\s*;", content):
        content = "<?php " + content
        kind = "php"
    _scan_text(content, label, findings, info, ctx, kind)
    return _summarise(findings, info, label)


# ---------------------------------------------------------------------------
# Packagist metadata checks (account-takeover shapes)
# ---------------------------------------------------------------------------
def expand_minified(versions):
    """Expand Packagist composer/2.0 minified version lists."""
    out, prev = [], {}
    for v in versions:
        cur = dict(prev)
        for k, val in v.items():
            if val == "__unset":
                cur.pop(k, None)
            else:
                cur[k] = val
        out.append(cur)
        prev = cur
    return out


def _repo_id(v):
    for k in ("source", "dist"):
        u = ((v.get(k) or {}).get("url") or "").lower()
        m = re.search(r"(?:github\.com|gitlab\.com|bitbucket\.org)[/:]([^/]+)/([^/.]+)", u) or \
            re.search(r"api\.github\.com/repos/([^/]+)/([^/]+)/", u)
        if m:
            return "%s/%s" % (m.group(1), m.group(2))
        if u:
            return urllib.parse.urlparse(u).netloc or u
    return ""


_PRE = re.compile(r"(?:dev|alpha|beta|rc|a\d|b\d|pre|snapshot|patch)", re.I)


def pick_version(versions, want="latest"):
    if want != "latest":
        for v in versions:
            if v.get("version") in (want, "v" + want) or v.get("version_normalized") == want:
                return v
        raise LookupError("version %s not found" % want)
    for v in versions:
        if not _PRE.search(v.get("version", "")) or re.match(r"^v?\d+(?:\.\d+)*$", v.get("version", "")):
            return v
    return versions[0] if versions else None


def _ts(s):
    try:
        return time.mktime(time.strptime((s or "")[:19], "%Y-%m-%dT%H:%M:%S"))
    except ValueError:
        return 0


def metadata_checks(versions, chosen):
    """versions: expanded list (newest first). Flags a release whose source repo changed hands
    or that revives a long-dormant package - the 2023 Packagist account-takeover shape."""
    out = []
    if not chosen:
        return out
    idx = next((i for i, v in enumerate(versions) if v is chosen or v.get("version") == chosen.get("version")), 0)
    older = [v for v in versions[idx + 1:] if not _PRE.search(v.get("version", "")) or
             re.match(r"^v?\d+(?:\.\d+)*$", v.get("version", ""))]
    cur = _repo_id(chosen)
    if older and cur:
        prev = _repo_id(older[0])
        prev_owners = {_repo_id(v).split("/")[0] for v in older[:20] if _repo_id(v)}
        gap = _ts(chosen.get("time")) - _ts(older[0].get("time"))
        dormant = gap > 3 * 365 * 86400 and _ts(older[0].get("time"))
        if prev and cur.split("/")[0] != prev.split("/")[0] and cur.split("/")[0] not in prev_owners:
            out.append(_item("HIGH" if dormant else "MEDIUM", "source_repo_changed", "Source Repository Changed Hands",
                             "This release points at %s; every earlier release came from %s%s "
                             "(account-takeover / repo-hijack shape - verify the transfer)"
                             % (cur, prev, ", and it revives a package dormant for %.1f years" % (gap / 31557600.0)
                                if dormant else ""),
                             "packagist-metadata", 0, cur, "%s -> %s" % (prev, cur)))
        if dormant:
            out.append(_item("INFO", "dormant_revival", "Release After Long Dormancy",
                             "Released %.1f years after the previous release" % (gap / 31557600.0),
                             "packagist-metadata", 0, chosen.get("version", ""), ""))
    if chosen.get("abandoned"):
        out.append(_item("INFO", "abandoned", "Abandoned Package",
                         "Marked abandoned on Packagist (abandoned packages were the 2023 takeover targets)",
                         "packagist-metadata", 0, str(chosen.get("abandoned")), ""))
    return out


# ---------------------------------------------------------------------------
# Loading targets (never installs or executes package code)
# ---------------------------------------------------------------------------
UA = {"User-Agent": "packagist-audit/%s (+https://github.com/eltociear/packagist-audit)" % __version__}
_ipv4 = [False]
_dns = {}
_orig_getaddrinfo = socket.getaddrinfo


def _getaddrinfo(host, port, family=0, *a, **k):
    """Memoised resolver: one bulk run hits the same few hosts thousands of times, and a flaky
    resolver should not cost a lookup (and a timeout) per download."""
    if _ipv4[0]:
        family = socket.AF_INET
    key = (host, port, family) + tuple(a) + tuple(sorted(k.items()))
    if key not in _dns:
        _dns[key] = _orig_getaddrinfo(host, port, family, *a, **k)
    return _dns[key]


socket.getaddrinfo = _getaddrinfo


def _force_ipv4():
    if not _ipv4[0]:
        _ipv4[0] = True
        _dns.clear()


if os.environ.get("PACKAGIST_AUDIT_IPV4"):
    _force_ipv4()


def _get(url, timeout=30, tries=6, limit=None):
    for i in range(tries):
        try:
            resp = urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout)
            data = resp.read(limit + 1) if limit else resp.read()
            if limit and len(data) > limit:
                raise ValueError("download exceeds %d bytes" % limit)
            return data
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504) and i < tries - 1:
                time.sleep(3 * (i + 1))
                continue
            raise
        except ValueError:
            raise
        except Exception as e:
            if "unreachable" in str(e).lower() or "No route" in str(e) or "nodename" in str(e):
                _force_ipv4()
            if i == tries - 1:
                raise
            time.sleep(2 * (i + 1))


def split_spec(spec):
    name, _, ver = spec.partition("@")
    if ":" in name and "@" not in spec:
        name, _, ver = spec.partition(":")
    return name.strip().lower(), (ver.strip() or "latest")


def dist_url(dist):
    """GitHub API zipball URLs are rate-limited for anonymous clients; codeload serves the same zip."""
    u = (dist or {}).get("url") or ""
    m = re.match(r"https://api\.github\.com/repos/([^/]+)/([^/]+)/zipball/(.+)$", u)
    if m:
        return "https://codeload.github.com/%s/%s/legacy.zip/%s" % m.groups()
    return u


def fetch_metadata(name, version="latest"):
    path = "%s~dev" % name if version.startswith("dev-") else name
    d = json.loads(_get("%s/p2/%s.json" % (REPO, path), timeout=15))
    versions = expand_minified(d["packages"].get(name) or [])
    if not versions:
        raise LookupError("no versions for %s" % name)
    return versions, pick_version(versions, version)


def files_from_zip(data):
    out = {}
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        names = [i for i in zf.infolist() if not i.is_dir()]
        tops = {i.filename.split("/", 1)[0] for i in names}
        strip = len(tops) == 1 and all("/" in i.filename for i in names)
        for i in names:
            name = i.filename.split("/", 1)[1] if strip else i.filename
            if name.endswith(".phar"):
                out[name] = ""
                continue
            if i.file_size > MAX_FILE:
                continue
            if name != "composer.json" and not name.endswith(SCAN_EXT + (".sh",)):
                continue
            out[name] = zf.read(i).decode("utf-8", "replace")
    return out


def files_from_dir(root):
    out = {}
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in (".git", "node_modules", "vendor")]
        for fn in fns:
            p = os.path.join(dp, fn)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            if fn.endswith(".phar"):
                out[rel] = ""
                continue
            if rel != "composer.json" and not fn.endswith(SCAN_EXT + (".sh",)):
                continue
            try:
                if os.path.getsize(p) > MAX_FILE:
                    continue
                with open(p, encoding="utf-8", errors="replace") as fh:
                    out[rel] = fh.read()
            except OSError:
                pass
    return out


def installed_packages(root):
    """vendor/composer/installed.json -> [(name, dir)] for a project that already ran composer."""
    p = os.path.join(root, "vendor", "composer", "installed.json")
    try:
        d = json.load(open(p, encoding="utf-8"))
    except (OSError, ValueError):
        return []
    pkgs = d.get("packages", d) if isinstance(d, dict) else d
    out = []
    for pkg in pkgs or []:
        name = pkg.get("name")
        if not name:
            continue
        rel = pkg.get("install-path")
        path = os.path.normpath(os.path.join(root, "vendor", "composer", rel)) if rel else os.path.join(root, "vendor", name)
        if os.path.isdir(path):
            out.append((name, path))
    return out


def audit_registry(spec, exec_only=False):
    name, ver = split_spec(spec)
    versions, chosen = fetch_metadata(name, ver)
    url = dist_url(chosen.get("dist"))
    if not url:
        raise LookupError("%s@%s has no dist archive" % (name, chosen.get("version")))
    files = files_from_zip(_get(url, timeout=180, limit=MAX_ZIP))
    r = scan_package(files, "%s@%s" % (name, chosen.get("version")), exec_only)
    meta = metadata_checks(versions, chosen)
    if meta:
        ec = r["exec_context"]
        r = _summarise(r["findings"] + [m for m in meta if m["severity"] != "INFO"],
                       r["info"] + [m for m in meta if m["severity"] == "INFO"], r["target"])
        r["exec_context"] = ec
    return r


def lockfile_specs(path):
    """Every package in a composer.lock as (label, dist_url)."""
    with open(path, encoding="utf-8") as fh:
        d = json.load(fh)
    out = []
    for pkg in (d.get("packages") or []) + (d.get("packages-dev") or []):
        url = dist_url(pkg.get("dist"))
        if pkg.get("name") and url:
            out.append(("%s@%s" % (pkg["name"], pkg.get("version", "?")), url))
    return out


def audit_dist(label, url, exec_only=False):
    return scan_package(files_from_zip(_get(url, timeout=180, limit=MAX_ZIP)), label, exec_only)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
_ICON = {"CRITICAL": "\U0001F534", "HIGH": "\U0001F7E0", "MEDIUM": "\U0001F7E1",
         "LOW": "\U0001F535", "SAFE": "\U0001F7E2"}


def _print(r, verbose):
    ec = r.get("exec_context") or {}
    tag = []
    if ec.get("type") == "composer-plugin":
        tag.append("composer-plugin")
    if ec.get("autoload_files"):
        tag.append("autoload.files")
    if ec.get("providers") or ec.get("bundles"):
        tag.append("provider/bundle")
    print("%s %s  [%s]  score=%d  (%d findings, %d info)%s" % (
        _ICON.get(r["risk_level"], "?"), r["target"], r["risk_level"], r["risk_score"],
        r["total_findings"], r["info_count"], ("  runs-unasked: " + ",".join(tag)) if tag else ""))
    for f in r["findings"]:
        print("    %-8s %s  %s:%s" % (f["severity"], f["name"], f["file"], f["line"]))
        if f["context"] and (f["line"] or f["file"] == "packagist-metadata"):
            print("             %s" % f["context"][:160])
    if verbose:
        for f in r["info"]:
            print("    info     %s  %s:%s" % (f["name"], f["file"], f["line"]))


def _local_targets(a, exec_only):
    if os.path.isdir(a):
        inst = installed_packages(a)
        if inst:
            return [(n, (lambda p=p, n=n: scan_package(files_from_dir(p), n, exec_only))) for n, p in inst]
        return [(a, (lambda p=a: scan_package(files_from_dir(p), p, exec_only)))]
    if os.path.basename(a) == "composer.json":
        return [(a, (lambda p=a: scan_package(files_from_dir(os.path.dirname(p) or "."), p, exec_only)))]
    if a.endswith(".zip"):
        return [(a, (lambda p=a: scan_package(files_from_zip(open(p, "rb").read()), p, exec_only)))]
    return [(a, (lambda p=a: scan(open(p, encoding="utf-8", errors="replace").read(), p, None)))]


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
    exec_only = "--exec-only" in args
    args = [a for a in args if a not in ("--json", "--verbose", "-v", "--exec-only")]
    targets = []
    if args[0] == "--text":
        txt = " ".join(args[1:])
        targets.append(("<text>", lambda: scan(txt)))
    elif args[0] == "--lockfile":
        for label, url in lockfile_specs(args[1]):
            targets.append((label, (lambda l=label, u=url: audit_dist(l, u, exec_only))))
    else:
        for a in args:
            if os.path.exists(a):
                targets += _local_targets(a, exec_only)
            else:
                targets.append((a, (lambda s=a: audit_registry(s, exec_only))))
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
