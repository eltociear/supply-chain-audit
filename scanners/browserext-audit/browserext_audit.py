#!/usr/bin/env python3
"""browserext-audit - scan Chrome / Chromium / Firefox extensions for MALICIOUS patterns.

A browser extension with broad host permissions sees every page you load, every cookie
(including the httpOnly session cookies a page's own JavaScript cannot read), every form you
type into, and can rewrite requests on the fly. Store review is a point-in-time check: the
December 2024 Cyberhaven compromise and the dozens of hijacked extensions found alongside it
were trusted, reviewed, popular extensions until one malicious update was pushed to every user.

This is a deterministic (no LLM) static scan of the .crx / .xpi package for: remote code
execution (eval / new Function / executeScript of fetched code - banned in Manifest V3),
cookie and session-token harvesting sent to collector hosts, password-field keylogging,
crypto clipboard swapping, affiliate-link and search hijacking, blockchain- and calendar-hosted
C2 lookups, invisible-Unicode payloads and obfuscated loaders.

Precision-tuned on the most-used Firefox add-ons and Chrome Web Store extensions: powerful
permissions (cookies, webRequest, <all_urls>, scripting, debugger, nativeMessaging), network
calls, password-field access (every password manager does it) and analytics are reported as
informational context and never inflate the risk score. Risk comes from specific sinks and
COMBINATIONS: a bulk cookie read next to a webhook, a fetched string handed to eval.

The extension is never installed and none of its code runs: the package (a zip) is read as text.

Usage:
  python browserext_audit.py <file.crx|file.xpi|file.zip|unpacked-dir> [...]
  python browserext_audit.py --chrome <extension-id> [...]   # download from the Chrome Web Store
  python browserext_audit.py --firefox <slug-or-guid> [...]  # download from addons.mozilla.org
  python browserext_audit.py --installed                     # scan Chrome/Brave/Edge/Firefox profiles
  python browserext_audit.py --text "some code"              # scan a string
  add --json (family schema) or --sarif (SARIF 2.1.0) for machine-readable output,
  --fail-on {critical,high,medium,low,never}, --version, --verbose to print INFO context

Exit code 2 if any target reaches --fail-on (default HIGH; CI-friendly), 1 on usage errors.
No dependencies beyond the standard library. MIT licensed.
"""
import bisect
import glob
import hashlib
import io
import json
import os
import re
import stat
try:
    import re._parser as _sre_parse  # 3.11+
except ImportError:  # pragma: no cover
    import sre_parse as _sre_parse
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

__version__ = "0.2.0"

SCAN_EXT = (".js", ".cjs", ".mjs", ".jsx", ".html", ".htm")
BINARY_EXT = (".wasm", ".exe", ".dll", ".so", ".dylib", ".node")
MAX_FILE = 16000000     # bytes; extensions ship multi-MB webpack bundles
MAX_TOTAL = 60000000    # bytes of text scanned per extension
BLOB_RE = re.compile(r"[A-Za-z0-9+/=_-]{4096,}")  # embedded fonts / wasm / images: data, not code

EXFIL_HOST = (
    r"(?:discord(?:app)?\.com/api/webhooks/|api\.telegram\.org/bot|hooks\.slack\.com/services/|"
    r"webhook\.site|pipedream\.net|requestbin\.(?:com|net|io)|requestb\.in|requestcatcher\.com|beeceptor\.com|"
    r"pastebin\.com/(?:api|raw)|paste\.ee/|hastebin\.com|transfer\.sh|file\.io/|"
    r"ngrok(?:-free)?\.(?:io|app|dev)|\.trycloudflare\.com|serveo\.net|localtunnel\.me|"
    r"oastify\.com|oast\.(?:fun|me|pro|live|site|online)|interact\.sh|interactsh|"
    r"burpcollaborator\.net|canarytokens\.com|dnslog\.cn|ceye\.io|requestrepo\.com)"
)
RAW_IP_URL = (r"(?:https?|wss?)://(?!(?:127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|"
              r"1\.1\.1\.1\b|1\.0\.0\.1\b|8\.8\.8\.8\b|8\.8\.4\.4\b|9\.9\.9\.9\b))\d{1,3}(?:\.\d{1,3}){3}")
NET_SEND = (r"(?:\bfetch\s*\(|XMLHttpRequest|\.open\s*\(\s*[\"'](?:POST|GET|PUT)[\"']|axios(?:\.\w+)?\s*\(|"
            r"\.post\s*\(|\$\.ajax\s*\(|navigator\.sendBeacon\s*\(|new\s+WebSocket\s*\(|new\s+Image\s*\(\s*\)\.src|"
            r"\.src\s*=\s*[\"'`]https?://[^\"'`\n]{0,200}[?&][^\"'`\n]{0,40}=)")
INVISIBLE_RUN = re.compile("[\ufe00-\ufe0f\U000e0100-\U000e01ef\U000e0000-\U000e007f]{24,}")
PUA_RUN = re.compile("[\ue000-\uf8ff]{200,}")
EVAL_SINK = re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(|(?<![\w.$])Function\s*\(\s*[\"'`]|set(?:Timeout|Interval)\s*\(\s*[\"'`]")
SOLANA_RE = re.compile(r"getSignaturesForAddress|api\.mainnet-beta\.solana\.com|solana-mainnet|\bspl-memo\b|MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr", re.I)
DECODE_RE = re.compile(r"atob\s*\(|decodeURIComponent\s*\(\s*escape|String\.fromCharCode\s*\(", re.I)
COOKIE_BULK = (r"(?:chrome|browser)\.cookies\.getAll\s*\(\s*\{\s*\}|(?:chrome|browser)\.cookies\.getAll\s*\(\s*\{\s*(?:url|domain)\s*:\s*[\"'](?:https?://)?\.?(?:www\.)?(?:google|facebook|instagram|tiktok|twitter|x|roblox|discord|amazon|paypal|binance|coinbase|steamcommunity|linkedin|github|microsoft|live|outlook|chatgpt|openai)\.[a-z.]+|"
               r"Network\.getAllCookies|Storage\.getCookies")
DOC_COOKIE = r"document\.cookie(?!\s*=[^=])"
PASSWORD_FIELD = (r"(?:type\s*=\s*\\?[\"']?password|\[type=\\?[\"']?password|\.type\s*===?\s*[\"']password[\"']|"
                  r"input\[type\*?=\\?[\"']?password)")
KEY_LISTENER = r"addEventListener\s*\(\s*[\"'](?:keydown|keypress|keyup|input|change|blur|submit)[\"']"
CLIP_WRITE = r"(?:navigator\.clipboard\.writeText\s*\(|execCommand\s*\(\s*[\"']copy[\"']|clipboardData\.setData\s*\()"
CRYPTO_ADDR_RX = (r"(?:\(\?:?bc1\||bc1\|\[13\]|\^\(?bc1|\^\(?\[13\]|\^0x\[a-fA-F0-9\]\{40\}|0x\[0-9a-fA-F\]\{40\}|"
                  r"\[13\]\[a-km-zA-HJ-NP-Z1-9\]\{2[0-9],3[0-9]\}|T\[A-Za-z1-9\]\{33\})")
CRYPTO_ADDR_LIT = r"[\"'`](?:bc1q[02-9ac-hj-np-z]{38,58}|0x[0-9a-fA-F]{40}|T[1-9A-HJ-NP-Za-km-z]{33})[\"'`]"
AFFILIATE = (r"(?:[?&]|[\"'`])(?:tag|affid|aff_id|affiliate_id|affiliate|aff_sub|clickref|afsrc|irclickid|ranMID|ranEAID|"
             r"subid|camref|awinmid|awinaffid)=")
REDIRECT_SINK = (r"(?:redirectUrl|redirect\s*:\s*\{|location\.(?:href|replace|assign)|tabs\.update\s*\(|"
                 r"\.href\s*=|regexSubstitution|transform\s*:\s*\{)")
FB_TOKEN = r"EAA(?:[A-Z][A-Za-z0-9]{0,4})?[\[\\(][^\n]{0,30}?[\]+*]|[\"']EAA[A-Z]?[\"']|access_token=EAA"
CLIP_READ = r"(?:navigator\.clipboard\.readText\s*\(|addEventListener\s*\(\s*[\"'](?:copy|cut)[\"']|clipboardData\.getData\s*\(|\boncopy\b)"

PATTERNS = {
    "critical": [
        {"id": "remote_code_eval", "name": "Remote Code Execution",
         "desc": "Fetches code and evaluates it (eval / new Function) - banned in Manifest V3",
         "regexes": [
             r"eval\s*\(\s*(?:await\s+)?\(?\s*(?:await\s+)?fetch\s*\(",
             r"(?:eval|new\s+Function)\s*\(\s*(?:await\s+)?\(?\s*(?:await\s+)?(?:\(\s*await\s+)?(?:axios\.get|fetch)\s*\([^\n]{0,200}\)\s*\)?\s*\.(?:text|data)",
             r"\.then\s*\(\s*\(?\s*(\w+)\s*\)?\s*=>\s*(?-i:\beval|\bnew\s+Function|(?<![\w.$])Function)\s*\(\s*\1\s*\)(?!\s*\{)",
             r"\.then\s*\(\s*(?:window\.)?eval\s*\)",
         ]},
    ],
    "high": [
        {"id": "exfil_host", "name": "Exfiltration Endpoint",
         "desc": "Hard-codes a webhook / paste / tunnel / OAST collector host",
         "regexes": [EXFIL_HOST]},
        {"id": "remote_config_exec", "name": "Remote-Config Code Execution",
         "desc": "Evaluates a code/script field of fetched data (dynamic C2 config)",
         "regexes": [r"(?-i:\beval|\bnew\s+Function)\s*\(\s*(?:\w+\.){1,3}(?:code|script|payload|js|cmd|exec)\b\s*\)"]},
        {"id": "remote_code_inject", "name": "Remote Code Injection",
         "desc": "executeScript / userScripts with a code string built at runtime (fetched code into pages)",
         "regexes": [r"(?:chrome|browser)\.tabs\.executeScript\s*\([^\n]{0,200}?\bcode\s*:\s*(?![\"'`])(?P<var>[a-z_$][\w$]*)",
                     r"(?:chrome|browser)\.userScripts\.register\s*\([^\n]{0,300}?\bcode\s*:\s*(?![\"'`])(?P<var>[a-z_$][\w$]*)"]},
        {"id": "obfuscation", "name": "Obfuscated Payload",
         "desc": "eval of decoded strings / escape blobs",
         "regexes": [
             r"(?-i:\beval|(?<![\w.$])Function)\s*\(\s*(?:atob|unescape)\s*\(",
             r"(?-i:\beval|\bnew\s+Function)\s*\(\s*[\"'](?:\\x[0-9a-fA-F]{2}){20,}",
             r"(?-i:\beval|\bnew\s+Function)\s*\(\s*String\.fromCharCode\s*\(",
         ]},
    ],
    "medium": [
        {"id": "cookie_bulk", "name": "Bulk Cookie / Session Read",
         "desc": "Reads every cookie, or the session cookies of a high-value site (HIGH+ next to a collector host)",
         "regexes": [COOKIE_BULK]},
        {"id": "affiliate_rewrite", "name": "Affiliate-Link Rewriting",
         "desc": "Injects affiliate/tracking parameters into navigations (coupon/cashback extensions do this)",
         "regexes": [AFFILIATE]},
        {"id": "search_redirect", "name": "Search Redirect",
         "desc": "Redirects web searches to another search endpoint",
         "regexes": [r"(?:google|bing|yahoo|duckduckgo)\.[a-z.]{2,6}/search[^\n]{0,200}(?:redirectUrl|regexSubstitution|location\.replace)",
                     r"(?:redirectUrl|regexSubstitution)[^\n]{0,200}(?:google|bing|yahoo)\.[a-z.]{2,6}/search"]},
        {"id": "raw_ip_url", "name": "Raw-IP URL",
         "desc": "Contacts a public IP address directly instead of a hostname",
         "regexes": [RAW_IP_URL]},
        {"id": "calendar_c2", "name": "Calendar-Hosted Pointer",
         "desc": "Google Calendar short link in code (GlassWorm backup C2 channel)",
         "regexes": [r"calendar\.app\.google/[A-Za-z0-9]+"]},
        {"id": "remote_script", "name": "Remote Script Injected Into Pages",
         "desc": "A content script appends a <script src=https://...> to the page (remote code; MV3 bans it)",
         "regexes": [r"createElement\s*\(\s*[\"']script[\"']\s*\)[^\n]{0,300}?\.src\s*=\s*[\"'`]https?://(?!(?:localhost|127\.))[^\"'`\n]{4,}"]},
    ],
    "low": [],
    # Context: reported, never scored. Capabilities popular extensions use daily.
    "info": [
        {"id": "network", "name": "Network Access",
         "desc": "Makes outbound HTTP/WebSocket/beacon calls", "regexes": [NET_SEND]},
        {"id": "doc_cookie", "name": "document.cookie Read",
         "desc": "Reads the page's (non-httpOnly) cookies", "regexes": [DOC_COOKIE]},
        {"id": "password_field", "name": "Password-Field Access",
         "desc": "Touches password inputs (every password manager / autofill does)", "regexes": [PASSWORD_FIELD]},
        {"id": "execute_script", "name": "Script Injection API",
         "desc": "Uses scripting.executeScript / tabs.executeScript / userScripts",
         "regexes": [r"(?:chrome|browser)\.(?:scripting|tabs)\.executeScript\s*\(", r"(?:chrome|browser)\.userScripts\.register\s*\("]},
        {"id": "debugger_api", "name": "Debugger API",
         "desc": "Attaches the Chrome DevTools protocol to tabs", "regexes": [r"(?:chrome|browser)\.debugger\.attach\s*\("]},
        {"id": "wallet_ext_ref", "name": "Wallet Extension Reference",
         "desc": "References a crypto-wallet extension ID (dapp connectors do; stealers target their storage)",
         "regexes": [r"nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|hnfanknocfeofbddgcijnmhnfnkdnaad|egjidjbpglichdcondbcbdnbeeppgdph|aholpfdialjgjfhomihkjbmgjidlcdno|acmacodkjbdgmoleebolmdjonilkdbch"]},
        {"id": "management_api", "name": "Extension Management",
         "desc": "Enables/disables/uninstalls other extensions", "regexes": [r"(?:chrome|browser)\.management\.(?:setEnabled|uninstall)\s*\("]},
        {"id": "solana_rpc", "name": "Blockchain RPC",
         "desc": "Solana RPC / memo access (wallet tooling does this; GlassWorm used it as C2)",
         "regexes": [SOLANA_RE.pattern]},
        {"id": "fb_token", "name": "Facebook Access-Token Pattern",
         "desc": "Matches Facebook EAA access tokens (ad tools do; Cyberhaven-style payloads harvested them)",
         "regexes": [FB_TOKEN]},
    ],
}
CONTEXT_ONCE = {"network", "doc_cookie", "password_field", "execute_script", "debugger_api", "wallet_ext_ref",
                "management_api", "solana_rpc", "fb_token"}

# ---- literal prefilter ----------------------------------------------------------------
# Python's re is slow on IGNORECASE alternations over 15 MB webpack bundles. Each regex gets
# an any-of set of lowercase literals derived from its parse tree; at least one must occur in
# the lowercased text for a match to be possible, and the regex then only runs in windows
# around those literal hits.
def _lits(parsed):
    """Return a set of literals at least one of which every match must contain, or None."""
    best, run = None, ""

    def consider(cand):
        nonlocal best
        if cand and all(len(c) >= 3 for c in cand):
            if best is None or min(map(len, cand)) > min(map(len, best)):
                best = cand
    for op, av in list(parsed):
        name = str(op)
        if name == "LITERAL":
            run += chr(av).lower()
            continue
        consider({run} if run else None)
        run = ""
        if name == "SUBPATTERN":
            consider(_lits(av[-1]))
        elif name == "BRANCH":
            subs = [_lits(b) for b in av[1]]
            if all(x is not None for x in subs):
                consider(set().union(*subs))
        elif name in ("MAX_REPEAT", "MIN_REPEAT") and av[0] >= 1:
            consider(_lits(av[2]))
    consider({run} if run else None)
    return best


def _prefilter(pattern):
    try:
        return _lits(_sre_parse.parse(pattern))
    except Exception:
        return None


_ASCII_LOWER = {c: c + 32 for c in range(65, 91)}


def _lower(text):
    """ASCII-only lowercase: keeps offsets aligned with the original text."""
    return text.lower() if text.isascii() else text.translate(_ASCII_LOWER)


def _possible(lits, lowered):
    return lits is None or any(l in lowered for l in lits)


def _finditer(rx, lits, text, low, before=400, after=800, cap=4000):
    """rx.finditer(text), but only search windows around the regex's required literals."""
    if lits is None or len(low) != len(text):
        yield from rx.finditer(text)
        return
    pos = []
    for lit in lits:
        i = low.find(lit)
        while i != -1:
            pos.append(i)
            if len(pos) > cap:  # literal is everywhere: a full scan is cheaper
                yield from rx.finditer(text)
                return
            i = low.find(lit, i + 1)
    end = -1
    for p in sorted(pos):
        if p < end:
            continue
        m = rx.search(text, max(0, p - before, end), p + after)
        if m:
            end = m.end()
            yield m


def _search(rx, lits, text, low, lo=0, hi=None):
    hi = len(text) if hi is None else hi
    if lits is not None and len(low) == len(text) and not any(l in low[lo:hi] for l in lits):
        return None
    for m in _finditer(rx, lits, text[lo:hi], low[lo:hi]):
        return m
    return None


SEVERITY_SCORE = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "SAFE": 0}
_COMPILED = [(sev, pg, re.compile(rx, re.IGNORECASE if pg["id"] not in ("fb_token",) else 0), _prefilter(rx))
             for sev, groups in PATTERNS.items() for pg in groups for rx in pg["regexes"]]
OBF_IDENT = re.compile(r"\b_0x[0-9a-f]{4,6}\b")
NET_RE = re.compile(NET_SEND, re.IGNORECASE)
EXFIL_RE = re.compile(EXFIL_HOST, re.IGNORECASE)
RAWIP_RE = re.compile(RAW_IP_URL)
COOKIE_RE = re.compile(COOKIE_BULK + "|" + DOC_COOKIE, re.I)
PW_RE = re.compile(PASSWORD_FIELD, re.I)
KEY_RE = re.compile(KEY_LISTENER, re.I)
CLIP_RE = re.compile(CLIP_WRITE, re.I)
ADDR_RX_RE = re.compile(CRYPTO_ADDR_RX)
ADDR_LIT_RE = re.compile(CRYPTO_ADDR_LIT)
REDIR_RE = re.compile(REDIRECT_SINK, re.I)
CLIPR_RE = re.compile(CLIP_READ, re.I)
FB_RE = re.compile(FB_TOKEN)
_COMBO_LITS = {"net": _prefilter(NET_SEND), "eval": _prefilter(EVAL_SINK.pattern),
               "decode": _prefilter(DECODE_RE.pattern), "exfil": _prefilter(EXFIL_HOST),
               "cookie": _prefilter(COOKIE_RE.pattern), "solana": _prefilter(SOLANA_RE.pattern),
               "pw": _prefilter(PASSWORD_FIELD), "key": _prefilter(KEY_LISTENER),
               "clip": _prefilter(CLIP_WRITE), "clipr": _prefilter(CLIP_READ), "addr_rx": None, "addr_lit": None,
               "redir": _prefilter(REDIRECT_SINK), "fb": None, "rawip": _prefilter(RAW_IP_URL)}
_COMBO_RX = {"net": NET_RE, "eval": EVAL_SINK, "decode": DECODE_RE, "exfil": EXFIL_RE, "cookie": COOKIE_RE,
             "solana": SOLANA_RE, "pw": PW_RE, "key": KEY_RE, "clip": CLIP_RE, "clipr": CLIPR_RE, "addr_rx": ADDR_RX_RE,
             "addr_lit": ADDR_LIT_RE, "redir": REDIR_RE, "fb": FB_RE, "rawip": RAWIP_RE}
DOMAIN_STR = re.compile(r"[\"'][*.]?[a-z0-9-]+(?:\.[a-z0-9-]+)+[\"']", re.I)
NEAR = 1500  # chars: in a bundle "same file" is meaningless, so sinks must be nearby
COMMENT_LINE = re.compile(r"^\s*(?://|/\*|\*|<!--)")
TELEGRAM_HARDCODED = re.compile(r"api\.telegram\.org/bot\d{6,}:[A-Za-z0-9_-]{30,}")
# Tracker / ad-block filter lists and URL-cleaning rule tables name affiliate parameters
# in order to STRIP them (uBlock, ClearURLs, Privacy Badger ship thousands).
STRIP_CTX = re.compile(r"(?:remov\w*|strip\w*|clean\w*|delete\w*|queryTransform|tracking[_ -]?param\w*|"
                       r"\$removeparam|redirect-rule)", re.I)


def _item(sev, pid, name, desc, path, line, matched, context):
    return {"severity": sev, "id": pid, "name": name, "description": desc, "file": path,
            "line": line, "matched": matched[:120], "context": context[:200]}


def _strip_blobs(text):
    """Collapse >= 4 KB base64/hex-ish runs (embedded fonts, wasm, images) to a placeholder.
    They are data; scanning them is what made multi-MB bundles slow. Code that decodes and
    runs a blob is still caught by the eval/decode sinks around the placeholder."""
    if len(text) < 4096:
        return text, 0
    n = [0]

    def rep(m):
        n[0] += 1
        return "\"<blob:%d>\"" % len(m.group(0))
    return BLOB_RE.sub(rep, text), n[0]


def _scan_text(text, path, findings, info, ctx=None):
    """Pattern pass plus file-level combination rules.
    ctx: {"content": bool (file runs inside web pages), "perms": set(manifest permissions)}"""
    ctx = ctx or {}
    text, blobs = _strip_blobs(text)
    if blobs:
        info.append(_item("INFO", "embedded_blob", "Embedded Data Blob",
                          "%d base64/hex run(s) >= 4 KB (fonts, wasm, images) skipped as data" % blobs,
                          path, 0, "", ""))
    starts, acc = [0], 0
    nl = text.find("\n")
    while nl != -1:
        starts.append(nl + 1)
        nl = text.find("\n", nl + 1)

    def line_of(pos):
        return bisect.bisect_right(starts, pos)  # 1-based

    def line_text(n):
        a = starts[n - 1]
        b = starts[n] - 1 if n < len(starts) else len(text)
        return text[a:b]
    seen = set()
    local = []
    low = _lower(text)
    for sev, pg, rx, lits in _COMPILED:
        pid = pg["id"]
        once = pid in CONTEXT_ONCE
        if (once and pid in seen) or not _possible(lits, low):
            continue
        hits = 0
        for m in _finditer(rx, lits, text, low):
            n = line_of(m.start())
            if (pid, n, m.start() // 2000) in seen:
                continue
            seen.add((pid, n, m.start() // 2000))
            s = m.start()
            ctxt = text[max(starts[n - 1], s - 60):s + 140].split("\n")[0].strip()
            it = _item(sev.upper(), pid, pg["name"], pg["desc"], path, n, m.group(0), ctxt)
            it["_pos"] = m.start()
            if "var" in rx.groupindex:
                it["_var"] = m.group("var")
            local.append(it)
            hits += 1
            if once:
                seen.add(pid)
                break
            if hits >= 25:
                break
    ids = {f["id"] for f in local}
    may = {k: _possible(v, low) for k, v in _COMBO_LITS.items()}

    def near(key, pos, span=NEAR):
        return may[key] and bool(_search(_COMBO_RX[key], _COMBO_LITS[key], text, low,
                                         max(0, pos - span), pos + span))
    has_eval = may["eval"] and bool(_search(EVAL_SINK, _COMBO_LITS["eval"], text, low))
    has_decode = may["decode"] and bool(_search(DECODE_RE, _COMBO_LITS["decode"], text, low))
    has_exfil = may["exfil"] and bool(_search(EXFIL_RE, _COMBO_LITS["exfil"], text, low))

    def collector_near(pos, span=3000):
        """A hard-coded collector (webhook/paste/tunnel/OAST) or raw public IP nearby."""
        if near("exfil", pos, span):
            m = _search(EXFIL_RE, _COMBO_LITS["exfil"], text, low, max(0, pos - span), pos + span)
            if m and "telegram" in m.group(0).lower():
                a = max(0, pos - span) + m.start()
                return bool(TELEGRAM_HARDCODED.search(text, a, a + 120))
            return True
        return near("rawip", pos, span)

    # ---- per-finding context rules -------------------------------------------------------
    for f in local:
        if f["severity"] == "INFO" or not f["line"]:
            continue
        pos = f.get("_pos", 0)
        if COMMENT_LINE.match(line_text(f["line"])):
            f["severity"] = "INFO"
            f["description"] += " [in a comment]"
            continue
        if f["id"] == "exfil_host":
            if "telegram" in f["matched"].lower() and not TELEGRAM_HARDCODED.search(text, pos, pos + 120):
                f["severity"] = "INFO"
                f["description"] += " [user-configured bot token]"
            elif not near("net", pos) or len(DOMAIN_STR.findall(text, max(0, pos - 300), pos + 300)) >= 8:
                f["severity"] = "INFO"
                f["description"] += " [no nearby send / domain list]"
            elif re.match(r"(?:pastebin\.com/raw|paste\.ee/|hastebin\.com)", f["matched"], re.I) and \
                    not re.search(r"method\s*:\s*[\"']POST|\.post\s*\(|sendBeacon", text[pos:pos + 600], re.I):
                f["severity"], f["id"], f["name"] = "MEDIUM", "paste_hosted_config", "Paste-Site-Hosted Config"
                f["description"] = "Downloads configuration from a paste site (mutable by whoever controls the paste)"
        elif f["id"] == "cookie_bulk":
            if collector_near(pos):
                f["severity"], f["id"], f["name"] = "CRITICAL", "cookie_exfil", "Cookie / Session Exfiltration"
                f["description"] = "Reads cookies in bulk and a collector host / raw IP sits next to it"
            elif not near("net", pos, 3000):
                f["severity"] = "INFO"
                f["description"] += " [no send nearby: cookie manager / local use]"
        elif f["id"] == "affiliate_rewrite":
            # a parameter table used to STRIP tracking (ad-blockers, URL cleaners) is the opposite
            if STRIP_CTX.search(text, max(0, pos - 200), pos + 200) or \
                    re.search(r"href\s*[*^$~|]?=\s*\\?[\"']?[^\"'\]\n]{0,80}$", text[max(0, pos - 100):pos + 1]) or \
                    len(re.findall(AFFILIATE, text[max(0, pos - 400):pos + 400])) >= 6 or \
                    not near("redir", pos, 600):
                f["severity"] = "INFO"
                f["description"] += " [parameter list / no redirect sink]"
        elif f["id"] == "raw_ip_url":
            if not (near("cookie", pos) or near("eval", pos) or near("pw", pos)):
                f["severity"] = "INFO"
        elif f["id"] == "remote_config_exec":
            if not near("net", pos, 3000):
                f["severity"] = "INFO"
                f["description"] += " [no fetch nearby]"
        elif f["id"] == "remote_code_inject":
            # HIGH only when the injected variable is itself a fetched response; MV2 tools
            # (userscript managers, page savers, screenshotters) build code strings locally.
            var = f.get("_var")
            src = text[max(0, pos - 2000):pos]
            fetched = var and re.search(
                r"\b%s\s*=\s*(?:await\s*)?\(?\s*(?:await\s+)?(?:fetch|axios(?:\.get)?|\$\.get)\s*\(|"
                r"\.text\s*\(\s*\)\s*\)?\s*\.then\s*\(\s*(?:async\s*)?\(?\s*%s\b|"
                r"\b%s\s*=\s*\w+\.responseText\b" % ((re.escape(var),) * 3), src)
            if not fetched:
                f["severity"] = "INFO"
                f["description"] += " [code string not taken from a fetch]"
        elif f["id"] in ("remote_code_eval", "obfuscation") and (
                re.search(r"[\"'`]\s*(?:new\s+)?$", text[max(0, pos - 8):pos])):
            f["severity"] = "INFO"
            f["description"] += " [inside a string literal: filter / detection rule]"
        elif f["id"] == "remote_script":
            if not ctx.get("content"):
                f["severity"] = "INFO"
                f["description"] += " [extension page, not injected into sites]"
    # calendar short link is only a C2 pointer if something decodes and runs code.
    for f in local:
        if f["id"] == "calendar_c2" and f["severity"] != "INFO":
            f["severity"] = "HIGH" if (has_eval and has_decode) else "INFO"

    # ---- file-level combination rules ----------------------------------------------------
    # keylogger: password-field listener + network + collector host / raw IP.
    if may["pw"] and may["key"] and may["net"]:
        for m in _finditer(PW_RE, _COMBO_LITS["pw"], text, low):
            p = m.start()
            if near("key", p, 800) and near("net", p, 2000) and collector_near(p):
                local.append(_item("CRITICAL", "password_keylogger", "Password Keylogger",
                                   "Listens on password fields and sends to a collector host / raw IP",
                                   path, line_of(p), m.group(0), "file-level combination"))
                break
    # clipboard swap: reads/intercepts the clipboard, matches crypto addresses and writes the
    # clipboard back; HIGH with a hard-coded replacement address nearby. (Wallets validate an
    # address and copy it, but do not intercept what the user copied.)
    if may["clip"] and may["clipr"] and ("bc1" in low or "0x" in low or "[13]" in low):
        for m in _finditer(CLIP_RE, _COMBO_LITS["clip"], text, low):
            p = m.start()
            if near("addr_rx", p, 1200) and near("clipr", p, 1500):
                hard = near("addr_lit", p, 1200)
                local.append(_item("HIGH" if hard else "MEDIUM", "clipboard_swap", "Crypto Clipboard Swap",
                                   "Matches crypto addresses and rewrites the clipboard%s" %
                                   (" with a hard-coded address" if hard else ""),
                                   path, line_of(p), m.group(0), "file-level combination"))
                break
    # Facebook access-token harvest (Cyberhaven Dec 2024) sent to a collector.
    if "eaa" in low:
        for m in FB_RE.finditer(text):
            if collector_near(m.start()):
                local.append(_item("CRITICAL", "token_exfil", "Session-Token Exfiltration",
                                   "Harvests Facebook EAA access tokens next to a collector host / raw IP",
                                   path, line_of(m.start()), m.group(0), "file-level combination"))
                break
    # blockchain-memo C2: reads transaction memos AND evals decoded content (GlassWorm)
    if has_eval and has_decode and may["solana"] and "memo" in low and any(
            near("eval", m.start(), NEAR) and near("decode", m.start(), NEAR) and "memo" in low[max(0, m.start() - 3000):m.start() + 3000]
            for m in _finditer(SOLANA_RE, _COMBO_LITS["solana"], text, low)):
        local.append(_item("CRITICAL", "blockchain_c2", "Blockchain-Hosted C2",
                           "Reads Solana transaction memos and evals decoded content (GlassWorm C2 pattern)",
                           path, 0, "", "file-level combination"))
    # invisible-Unicode payload (GlassWorm): a long run of variation selectors / tag chars
    if not text.isascii():
        for rx, label in ((INVISIBLE_RUN, "variation-selector / tag-character"), (PUA_RUN, "private-use")):
            m = rx.search(text)
            if m:
                sev = "CRITICAL" if has_eval or has_decode else "HIGH"
                local.append(_item(sev, "invisible_unicode", "Invisible-Unicode Payload",
                                   "%d consecutive invisible %s code points (hidden byte stream)" % (len(m.group(0)), label),
                                   path, line_of(m.start()), "", "U+%04X x%d" % (ord(m.group(0)[0]), len(m.group(0)))))
                break
    # javascript-obfuscator output: dozens of _0x identifiers. Store policies (Chrome, AMO)
    # forbid obfuscation; it is a payload shape with a collector or raw IP in the same file.
    obf = len(OBF_IDENT.findall(text[:6000000])) if "_0x" in low else 0
    if obf >= 25:
        if has_exfil or RAWIP_RE.search(text):
            sev = "HIGH"
        else:
            sev = "MEDIUM" if (has_eval and may["net"]) else "INFO"
        local.append(_item(sev, "obfuscation_heavy", "Heavily Obfuscated Code",
                           "javascript-obfuscator style code (%d _0x identifiers; store policies forbid obfuscation)" % obf,
                           path, 0, "", "file-level"))
    for f in local:
        f.pop("_pos", None)
        f.pop("_var", None)
        (info if f["severity"] == "INFO" else findings).append(f)


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------
BROAD_HOST = re.compile(r"^(?:<all_urls>|\*://\*/\*|https?://\*/\*|\*://\*\.[^/]*/\*|file:///\*)$")
POWER_PERMS = ("cookies", "webRequest", "webRequestBlocking", "declarativeNetRequest", "scripting", "debugger",
               "nativeMessaging", "management", "history", "clipboardRead", "proxy", "privacy", "userScripts",
               "downloads", "webNavigation", "tabs", "<all_urls>")


def _manifest(man, findings, info):
    """Manifest context. Returns (content_script_files, perms)."""
    perms = set()
    for k in ("permissions", "optional_permissions", "host_permissions", "optional_host_permissions"):
        v = man.get(k) or []
        if isinstance(v, list):
            perms.update(p for p in v if isinstance(p, str))
    content = set()
    for cs in man.get("content_scripts") or []:
        if not isinstance(cs, dict):
            continue
        for js in cs.get("js") or []:
            if isinstance(js, str):
                content.add(js.lstrip("/"))
        for mt in cs.get("matches") or []:
            if isinstance(mt, str):
                perms.add("content:" + mt)
    broad = any(BROAD_HOST.match(p.replace("content:", "")) for p in perms)
    power = [p for p in POWER_PERMS if p in perms]
    if broad:
        power.append("broad-host")
    if power:
        info.append(_item("INFO", "powerful_permissions", "Powerful Permissions",
                          "Requests %s" % ", ".join(power), "manifest.json", 0, "", ", ".join(power)))
    csp = man.get("content_security_policy")
    csp_s = json.dumps(csp) if not isinstance(csp, str) else csp
    if csp_s and "unsafe-eval" in csp_s:
        info.append(_item("INFO", "csp_unsafe_eval", "CSP Allows eval",
                          "content_security_policy permits 'unsafe-eval'", "manifest.json", 0, "", csp_s[:200]))
    upd = man.get("update_url")
    if isinstance(upd, str) and "google.com/" not in upd and "googleapis.com" not in upd:
        info.append(_item("INFO", "off_store_update", "Off-Store Update URL",
                          "Updates from a self-hosted server (sideloaded / enterprise)", "manifest.json", 0, "", upd))
    so = (man.get("chrome_settings_overrides") or {})
    sp = so.get("search_provider") if isinstance(so, dict) else None
    if isinstance(sp, dict) and sp.get("search_url"):
        info.append(_item("INFO", "search_override", "Default Search Override",
                          "Replaces the browser's default search engine (declared, user-visible)",
                          "manifest.json", 0, "", str(sp.get("search_url"))[:200]))
    ec = man.get("externally_connectable") or {}
    if isinstance(ec, dict) and any(isinstance(m, str) and BROAD_HOST.match(m) for m in ec.get("matches") or []):
        info.append(_item("INFO", "externally_connectable_all", "Any Site Can Message It",
                          "externally_connectable matches every site", "manifest.json", 0, "", ""))
    return content, perms


def scan_extension(files, label="", binaries=(), skipped=()):
    """files: {path relative to the extension root: text}. Returns an audit result dict."""
    findings, info = [], []
    man = {}
    if "manifest.json" in files:
        try:
            man = json.loads(files["manifest.json"].lstrip("\ufeff"))
        except ValueError:
            man = {}
    content, perms = _manifest(man, findings, info) if isinstance(man, dict) else (set(), set())
    for b in sorted(binaries)[:20]:
        info.append(_item("INFO", "native_binary", "Bundled Binary / WASM",
                          "Ships compiled code that cannot be text-scanned", b, 0, "", ""))
    for s in sorted(skipped)[:20]:
        info.append(_item("INFO", "file_skipped", "File Too Large",
                          "Over %d bytes; not scanned" % MAX_FILE, s, 0, "", ""))
    total = 0
    for path, text in sorted(files.items()):
        if path.endswith((".json", ".map")):
            continue
        total += len(text)
        if total > MAX_TOTAL:
            info.append(_item("INFO", "truncated", "Scan Truncated",
                              "Extension exceeds %d bytes of text" % MAX_TOTAL, path, 0, "", ""))
            break
        _scan_text(text, path, findings, info, {"content": path in content, "perms": perms})
    r = _summarise(findings, info, label)
    if isinstance(man, dict):
        r["name"] = man.get("name")
        r["version"] = man.get("version")
        r["manifest_version"] = man.get("manifest_version")
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


def scan(content, label="<text>", content_script=True):
    """Scan a bare string (treated as a content script unless told otherwise)."""
    findings, info = [], []
    _scan_text(content, label, findings, info, {"content": content_script})
    return _summarise(findings, info, label)


# ---------------------------------------------------------------------------
# Loading targets (never executes extension code)
# ---------------------------------------------------------------------------
UA = {"User-Agent": "browserext-audit/%s (+https://github.com/eltociear/browserext-audit)" % __version__}
CHROME_PRODVERSION = "131.0.0.0"


def _get(url, timeout=120, tries=4):
    for i in range(tries):
        try:
            return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout).read()
        except urllib.error.HTTPError as e:
            if e.code < 500 or i == tries - 1:
                raise
        except Exception:
            if i == tries - 1:
                raise
        time.sleep(2 * (i + 1))


def crx_to_zip(data):
    """Strip a CRX2/CRX3 header; return the embedded zip bytes (zip/xpi pass through)."""
    if data[:4] != b"Cr24":
        return data
    ver = struct.unpack("<I", data[4:8])[0]
    if ver == 3:
        hlen = struct.unpack("<I", data[8:12])[0]
        return data[12 + hlen:]
    if ver == 2:
        klen, slen = struct.unpack("<II", data[8:16])
        return data[16 + klen + slen:]
    raise ValueError("unknown CRX version %d" % ver)


def _add(out, bins, skipped, rel, raw_size, read):
    low = rel.lower()
    if low.endswith(BINARY_EXT):
        bins.append(rel)
        return
    if not (low.endswith(SCAN_EXT) or rel == "manifest.json"):
        return
    if raw_size > MAX_FILE:
        skipped.append(rel)
        return
    out[rel] = read().decode("utf-8", "replace")


def files_from_zip(data):
    out, bins, skipped = {}, [], []
    body = crx_to_zip(data)
    if body[:2] != b"PK":
        raise ValueError("not an extension package (%d bytes returned; the store may have delisted it)" % len(data))
    budget = ArchiveBudget()
    with zipfile.ZipFile(io.BytesIO(body)) as z:
        for zi in z.infolist():
            name = safe_member(zi.filename)
            if not name or zi.is_dir() or name.startswith("META-INF/") or name.startswith("_metadata/"):
                continue
            if stat.S_ISLNK(zi.external_attr >> 16):   # a symlink entry is a path, not code
                continue
            _add(out, bins, skipped, name, zi.file_size,
                 lambda zi=zi: z.read(zi) if budget.take(zi.file_size) else b"")
    if budget.truncated:
        skipped.append("<archive budget exceeded: %d bytes / %d members>" % (MAX_ARCHIVE_TOTAL, MAX_MEMBERS))
    return out, bins, skipped


def files_from_dir(root):
    out, bins, skipped = {}, [], []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in (".git", "_metadata", "node_modules")]
        for fn in fns:
            p = os.path.join(dp, fn)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            if not regular_file(p):   # symlinks, FIFOs, devices: never opened
                continue
            try:
                _add(out, bins, skipped, rel, os.path.getsize(p), lambda p=p: _read_blob(p, MAX_FILE))
            except OSError:
                pass
    return out, bins, skipped


def chrome_url(ext_id):
    if not re.match(r"^[a-p]{32}$", ext_id):
        raise ValueError("expected a 32-char Chrome extension id (a-p), got %r" % ext_id)
    x = urllib.parse.quote("id=%s&uc" % ext_id)
    return ("https://clients2.google.com/service/update2/crx?response=redirect&prodversion=%s"
            "&acceptformat=crx2,crx3&x=%s" % (CHROME_PRODVERSION, x))


def firefox_url(slug):
    meta = json.loads(_get("https://addons.mozilla.org/api/v5/addons/addon/%s/" % urllib.parse.quote(slug), timeout=60))
    cv = meta.get("current_version") or {}
    return cv["file"]["url"], "%s@%s" % (meta.get("slug", slug), cv.get("version", "?"))


def _read_blob(p, cap=500000000):
    with open(p, "rb") as fh:
        return fh.read(cap)


def audit_bytes(data, label):
    files, bins, skipped = files_from_zip(data)
    return scan_extension(files, label, bins, skipped)


def audit_dir(root, label):
    files, bins, skipped = files_from_dir(root)
    return scan_extension(files, label, bins, skipped)


def installed_dirs():
    """(label, path, kind) for Chromium-family and Firefox profiles on macOS / Linux / Windows."""
    home = os.path.expanduser("~")
    chromium = [
        ("chrome", "Library/Application Support/Google/Chrome"), ("chrome", ".config/google-chrome"),
        ("chrome", "AppData/Local/Google/Chrome/User Data"),
        ("chromium", "Library/Application Support/Chromium"), ("chromium", ".config/chromium"),
        ("brave", "Library/Application Support/BraveSoftware/Brave-Browser"), ("brave", ".config/BraveSoftware/Brave-Browser"),
        ("brave", "AppData/Local/BraveSoftware/Brave-Browser/User Data"),
        ("edge", "Library/Application Support/Microsoft Edge"), ("edge", ".config/microsoft-edge"),
        ("edge", "AppData/Local/Microsoft/Edge/User Data"),
        ("arc", "Library/Application Support/Arc/User Data"), ("vivaldi", "Library/Application Support/Vivaldi"),
        ("opera", "Library/Application Support/com.operasoftware.Opera"),
    ]
    out = []
    for name, rel in chromium:
        base = os.path.join(home, rel)
        for ext_root in glob.glob(os.path.join(base, "*", "Extensions")) + glob.glob(os.path.join(base, "Extensions")):
            prof = os.path.basename(os.path.dirname(ext_root))
            for eid in sorted(os.listdir(ext_root)):
                vers = sorted(glob.glob(os.path.join(ext_root, eid, "*", "manifest.json")))
                if vers:
                    out.append(("%s/%s/%s" % (name, prof, eid), os.path.dirname(vers[-1]), "dir"))
    for base in ("Library/Application Support/Firefox/Profiles", ".mozilla/firefox", "AppData/Roaming/Mozilla/Firefox/Profiles"):
        for xpi in sorted(glob.glob(os.path.join(home, base, "*", "extensions", "*.xpi"))):
            prof = os.path.basename(os.path.dirname(os.path.dirname(xpi)))
            out.append(("firefox/%s/%s" % (prof, os.path.basename(xpi)), xpi, "file"))
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
_ICON = {"CRITICAL": "\U0001F534", "HIGH": "\U0001F7E0", "MEDIUM": "\U0001F7E1",
         "LOW": "\U0001F535", "SAFE": "\U0001F7E2"}


def _print(r, verbose):
    name = " (%s)" % r["name"] if r.get("name") and not str(r["name"]).startswith("__MSG_") else ""
    print("%s %s%s  [%s]  score=%d  (%d findings, %d info)" % (
        _ICON.get(r["risk_level"], "?"), r["target"], name, r["risk_level"], r["risk_score"],
        r["total_findings"], r["info_count"]))
    for f in r["findings"]:
        print("    %-8s %s  %s:%s" % (f["severity"], f["name"], f["file"], f["line"]))
        if f["context"]:
            print("             %s" % f["context"][:160])
    if verbose:
        for f in r["info"]:
            print("    info     %s  %s:%s  %s" % (f["name"], f["file"], f["line"], f["context"][:80]))


# ---------------------------------------------------------------------------
# Pipeline output shared by the eltociear/*-audit family: --json / --sarif / --fail-on
# (this block is kept identical across the family; see "Output formats" in the README)
# ---------------------------------------------------------------------------
FAMILY_SCHEMA = "eltociear-audit/1"
TOOL_NAME = "browserext-audit"
TOOL_URI = "https://github.com/eltociear/browserext-audit"
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
    targets = []  # (label, thunk)
    if args[0] == "--text":
        txt = " ".join(args[1:])
        targets.append(("<text>", lambda: scan(txt)))
    elif args[0] == "--installed":
        for label, p, kind in installed_dirs():
            if kind == "dir":
                targets.append((label, (lambda p=p, l=label: audit_dir(p, l))))
            else:
                targets.append((label, (lambda p=p, l=label: audit_bytes(_read_blob(p), l))))
        if not targets and not as_json:
            print("no installed browser extensions found")
    elif args[0] == "--chrome":
        for eid in args[1:]:
            targets.append((eid, (lambda e=eid: audit_bytes(_get(chrome_url(e), timeout=300), "chrome:" + e))))
    elif args[0] == "--firefox":
        for slug in args[1:]:
            def thunk(slug=slug):
                url, label = firefox_url(slug)
                return audit_bytes(_get(url, timeout=300), "firefox:" + label)
            targets.append((slug, thunk))
    else:
        for a in args:
            if os.path.isdir(a):
                targets.append((a, (lambda a=a: audit_dir(a, a))))
            elif os.path.isfile(a) and a.lower().endswith((".crx", ".xpi", ".zip")):
                targets.append((a, (lambda p=a: audit_bytes(_read_blob(p), p))))
            elif os.path.isfile(a):
                targets.append((a, (lambda p=a: scan(_read_blob(p, MAX_FILE).decode("utf-8", "replace"), p))))
            else:
                print("not a file or directory: %s (use --chrome <id> / --firefox <slug> for store IDs)" % a,
                      file=sys.stderr)
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
