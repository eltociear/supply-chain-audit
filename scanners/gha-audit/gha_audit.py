#!/usr/bin/env python3
"""gha-audit - scan the CODE inside third-party GitHub Actions for malicious behaviour.

Every `uses: owner/repo@v4` in a workflow runs somebody else's code on your runner, with your
GITHUB_TOKEN, your secrets and your OIDC identity in reach. Workflow linters (zizmor,
actionlint) check how you *wire* actions - injection, permissions, pinning. They do not read the
action's own code. This does: the composite `run:` steps, the `node*` entrypoints (usually a
multi-megabyte ncc `dist/index.js`), the `pre:`/`post:` hooks, and the Docker action's
Dockerfile and entrypoint scripts - for the shapes real action compromises took:

  * Runner.Worker memory dumps and secrets printed double-base64 to the log
    (tj-actions/changed-files and reviewdog/action-setup, 2025);
  * environment / credential exfiltration with curl (Codecov bash uploader, 2021);
  * shell-obfuscated `curl | bash`, direct cache-API writes and crypto miners
    (ultralytics, 2024);
  * OIDC / ACTIONS_RUNTIME_TOKEN requests sent off-host, `$GITHUB_ENV` hijacking
    (LD_PRELOAD / BASH_ENV / NODE_OPTIONS=--require) and env writes of fetched content.

Context model: code an action.yml actually runs is scanned at face value; `pre:`/`post:` hooks
(and Docker pre-/post-entrypoints) run outside the normal step order and are escalated; files
nothing references (tests, docs, examples) and matches that only sit in a comment, an `echo`
or a JS string never passed to exec are demoted to INFO. Base64 literals are decoded and the
decoded text is scanned too.

Nothing is executed: remote actions are streamed from codeload.github.com into memory.

Usage:
  python gha_audit.py owner/repo[/path][@ref] [...]   # fetch the action and scan it
  python gha_audit.py ./path/to/action-or-repo         # every action.yml under a directory
  python gha_audit.py --workflow .github/workflows/ci.yml   # every `uses:` it references
  python gha_audit.py --text "curl https://x | bash"   # scan a shell snippet
  add --json for machine-readable output, --verbose to print INFO context,
  --no-fetch (with --workflow) to only check pinning

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
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request

try:  # Python 3.11+
    from re import _parser as _sre_parse
except ImportError:  # 3.9 / 3.10
    import sre_parse as _sre_parse

__version__ = "0.1.0"

CODELOAD = os.environ.get("GHA_AUDIT_CODELOAD", "https://codeload.github.com").rstrip("/")
MAX_FILE = 25000000      # bytes; ncc bundles are routinely 2-10 MB
MAX_TOTAL = 60000000     # bytes of text kept per repository
MAX_UNREACHED = 3000000  # bytes of not-referenced files scanned (for INFO context only)
MAX_DOWNLOAD = 700000000  # stop streaming a tarball after this many compressed bytes
SCRIPT_EXT = (".js", ".cjs", ".mjs", ".ts", ".mts", ".cts", ".sh", ".bash", ".zsh", ".py", ".ps1", ".psm1",
              ".rb", ".pl", ".bat", ".cmd")
NEAR = 1500  # chars: inside a bundle "same file" means nothing, so combinations must be close
SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", "vendor", "bower_components"}
NONRUN_DIR = re.compile(r"(?:^|/)(?:tests?|__tests__|__mocks__|spec|specs|examples?|docs?|demo|fixtures?|"
                        r"\.github|testdata|e2e|benchmarks?)/", re.I)

# ---------------------------------------------------------------------------
# Hosts
# ---------------------------------------------------------------------------
EXFIL_HOST = (
    r"(?:discord(?:app)?\.com/api/webhooks/|api\.telegram\.org/bot|hooks\.slack\.com/services/|"
    r"webhook\.site|pipedream\.net|\brequestbin\.(?:com|net|io)|requestb\.in|requestcatcher\.com|beeceptor\.com|"
    r"pastebin\.com/api|paste\.ee/|hastebin\.com|transfer\.sh|\bfile\.io\b|0x0\.st|"
    r"ngrok(?:-free)?\.(?:io|app|dev)|\.trycloudflare\.com|serveo\.net|localtunnel\.me|"
    r"oastify\.com|\boast\.(?:fun|me|pro|live|site|online)|interact\.sh|interactsh|"
    r"burpcollaborator\.net|canarytokens\.com|dnslog\.cn|ceye\.io|requestrepo\.com)"
)
RAW_IP_URL = (r"https?://(?!(?:127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|"
              r"100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.))\d{1,3}(?:\.\d{1,3}){3}")
SKETCHY_HOST = re.compile(
    r"gist\.githubusercontent\.com|gist\.github\.com/|pastebin\.com|paste\.ee|hastebin|transfer\.sh|"
    r"\bfile\.io\b|0x0\.st|termbin\.com|ngrok|trycloudflare|serveo\.net|localtunnel|\.onion\b|"
    r"\bbit\.ly/|tinyurl\.com|\bis\.gd/|cutt\.ly|rb\.gy|\bt\.co/|" + EXFIL_HOST + "|" + RAW_IP_URL, re.I)
# Official installers that actions legitimately pipe into a shell.
KNOWN_INSTALLER = re.compile(
    r"https?://(?:astral\.sh/(?:uv|ruff)/|sh\.rustup\.rs|static\.rust-lang\.org/rustup|deno\.land/(?:x/)?install|"
    r"bun\.sh/install|get\.pnpm\.io/install|install\.python-poetry\.org|pyenv\.run|get\.docker\.com|"
    r"raw\.githubusercontent\.com/nvm-sh/nvm/|foundry\.paradigm\.xyz|get\.volta\.sh|fnm\.vercel\.app/install|"
    r"pixi\.sh/install|sdk\.cloud\.google\.com|cli\.github\.com|mise\.run|get-ghcup\.haskell\.org|"
    r"nixos\.org/nix/install|install\.determinate\.systems|dot\.net/v1/dotnet-install|aka\.ms/install|"
    r"raw\.githubusercontent\.com/Homebrew/install/|deb\.nodesource\.com|rpm\.nodesource\.com|get\.sdkman\.io|"
    r"raw\.githubusercontent\.com/helm/helm/|get\.helm\.sh|sh\.vector\.dev|install\.lunarvim|"
    r"raw\.githubusercontent\.com/golangci/golangci-lint/|install\.goreleaser\.com|goreleaser\.com/static/run|"
    r"cli\.codecov\.io|uploader\.codecov\.io|keybase\.io/codecov|starship\.rs/install|"
    r"raw\.githubusercontent\.com/rhysd/actionlint/|raw\.githubusercontent\.com/reviewdog/|"
    r"raw\.githubusercontent\.com/anchore/|get\.anchore\.io|raw\.githubusercontent\.com/aquasecurity/|"
    r"raw\.githubusercontent\.com/securego/|install\.terraform\.io|apt\.releases\.hashicorp\.com|"
    r"packages\.microsoft\.com|dl\.google\.com|downloads\.python\.org|github\.com/[^/\s]+/[^/\s]+/releases/download/|"
    r"raw\.githubusercontent\.com/pypa/get-pip/|bootstrap\.pypa\.io/get-pip\.py|get\.k3s\.io|"
    r"raw\.githubusercontent\.com/kubernetes-sigs/|kind\.sigs\.k8s\.io|install\.julialang\.org|"
    r"rustwasm\.github\.io/wasm-pack/installer|sh\.flutter\.dev|get\.sentry\.dev|sentry\.io/get-cli|"
    r"cli\.doppler\.com|cli-assets\.heroku\.com|fly\.io/install\.sh|railway\.app/install|"
    r"raw\.githubusercontent\.com/pnpm/|get\.pulumi\.com|install\.ory\.sh|dist\.ipfs\.tech|"
    r"downloads\.dagger\.io|dl\.dagger\.io|get\.earthly\.dev|cdn\.jsdelivr\.net/gh/|"
    r"raw\.githubusercontent\.com/microsoft/|raw\.githubusercontent\.com/google/|raw\.githubusercontent\.com/aws/|"
    r"awscli\.amazonaws\.com|aka\.ms/|cli\.trunk\.io|get\.trunk\.io|install\.mondoo\.com|"
    r"raw\.githubusercontent\.com/actions/|raw\.githubusercontent\.com/github/|ollama\.com/install\.sh|"
    r"opam\.ocaml\.org|raw\.githubusercontent\.com/ocaml/|ziglang\.org|swift\.org|download\.swift\.org|"
    r"apt\.llvm\.org|install\.meteor\.com|get\.jenkins\.io|get\.rvm\.io|rvm\.io|install\.duckdb\.org|"
    r"raw\.githubusercontent\.com/Microsoft/|setup\.sh/|elan\.lean-lang\.org|raw\.githubusercontent\.com/leanprover/)",
    re.I)
# hosts an OIDC token is legitimately exchanged with
OIDC_AUDIENCE_OK = re.compile(
    r"amazonaws\.com|googleapis\.com|login\.microsoftonline\.com|sts\.windows\.net|pypi\.org|"
    r"sigstore\.dev|fulcio|rekor|github\.com|githubusercontent\.com|npmjs\.(?:org|com)|"
    r"codecov\.io|octo-sts\.dev|hashicorp|vault|azure|cloudflare|jfrog|depot\.dev|"
    r"chainguard|tailscale|doppler|1password|digitalocean|oracle|alibaba|aliyun|huawei|"
    r"localhost|127\.0\.0\.1", re.I)

NET_SEND = (r"(?:https?\.request|https?\.get|\bfetch\s*\(|axios(?:\.\w+)?\s*\(|\.post\s*\(|"
            r"XMLHttpRequest|net\.connect|new\s+net\.Socket|dns\.(?:lookup|resolve\w*)\s*\(|"
            r"\bcurl\b|\bwget\b|request\s*\(\s*\{|requests\.(?:get|post|put|patch)|urlopen\s*\(|"
            r"http\.client|socket\.socket|Invoke-(?:WebRequest|RestMethod)|\biwr\b|\birm\b)")
_URL = r"https?://[^\s\"'`)<>|;]+"

# ---------------------------------------------------------------------------
# Patterns. `langs`: sh / js / py / ps / docker / any (default any).
# ---------------------------------------------------------------------------
PATTERNS = {
    "critical": [
        {"id": "runner_memory_read", "name": "Runner Memory Read",
         "desc": "Reads another process's memory via /proc/<pid>/mem (the tj-actions / reviewdog "
                 "Runner.Worker dump that recovers every secret of the job)",
         "regexes": [
             r"Runner\.Worker[\s\S]{0,600}?/proc/[^\s'\"]{0,40}/(?:mem|maps)\b",
             r"/proc/[^\s'\"]{0,40}/(?:mem|maps)\b[\s\S]{0,600}?Runner\.Worker",
             r"(?:gcore|gdb\s+[^\n]{0,40}-p)\b[^\n]{0,200}(?:Runner\.Worker|pgrep|pidof)",
         ]},
        {"id": "secret_grep", "name": "Runner Secret Harvest",
         "desc": "Greps for the runner's in-memory secret records ({\"value\":...,\"isSecret\":true})",
         "regexes": [r"isSecret\W{0,8}true"]},
        {"id": "env_exfil", "name": "Environment Exfiltration",
         "desc": "Sends the whole environment (every secret mapped into the step) to a remote host "
                 "(Codecov bash-uploader shape)",
         "regexes": [
             r"\b(?:curl|wget)\b[^\n]*\$\(\s*(?:env|printenv|set|export\s+-p|cat\s+/proc/self/environ)\s*(?:\|[^)\n]*)?\)",
             r"\b(?:env|printenv)\s*(?:\|\s*(?:base64|gzip|xxd|sort|tr|openssl)[^|\n]*)*\|\s*(?:curl|wget|nc|ncat|socat)\b",
             r"\b(?:curl|wget)\b[^\n]*(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file)\s+[\"']?@?/proc/self/environ",
             r"(?:requests|httpx)\.(?:post|put|get)\([^\n]*\bos\.environ\b(?!\s*(?:\[|\.get|\.setdefault|\.pop|\.copy))",
         ]},
        {"id": "reverse_shell", "name": "Reverse Shell",
         "desc": "Binds an interactive shell to a network socket",
         "regexes": [
             r"\b(?:ba)?sh\s+-i\s*[^\n]{0,20}>&\s*/dev/tcp/",
             r"/dev/tcp/[\w.\-]+/\d+\s+0>&1",
             r"\bnc(?:at)?\s+(?:-\w+\s+)*-e\s+/bin/(?:ba)?sh",
             r"mkfifo\s[^\n]{0,80}\bnc\b[^\n]{0,80}/bin/(?:ba)?sh",
             r"pty\.spawn\(\s*[\"']/bin/(?:ba)?sh[\"']\s*\)",
             r"(?:client|socket|sock|conn)\.pipe\s*\(\s*\w+\.stdin\s*\)",
         ]},
        {"id": "cryptominer", "name": "Crypto Miner",
         "desc": "Downloads or launches a cryptocurrency miner (the ultralytics 2024 payload)",
         "regexes": [
             r"\bxmrig\b", r"stratum\+(?:tcp|ssl|tls)://", r"--donate-level\b",
             r"\b(?:minexmr|supportxmr|moneroocean|c3pool|hashvault|nanopool)\.(?:com|org|pro|stream|net)\b",
         ]},
        {"id": "destructive", "name": "Destructive Payload",
         "desc": "Wipes the home directory / filesystem",
         "langs": {"sh", "docker", "js", "py"},
         "regexes": [
             r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+(?:--no-preserve-root\s+)?(?:~|\$HOME|/)(?:\s|[\"'`;]|$)",
             r"(?:rmSync|rmdirSync|rimraf\w*)\s*\(\s*(?:os\.)?homedir\s*\(\s*\)",
             r"shutil\.rmtree\(\s*(?:os\.path\.expanduser\(\s*[\"']~[\"']\s*\)|[\"']/[\"'])",
         ]},
    ],
    "high": [
        {"id": "log_mask_evasion", "name": "Secret Log-Mask Evasion",
         "desc": "Prints secrets / the environment re-encoded so the runner's log masking misses them "
                 "(double base64 was the tj-actions tell)",
         "regexes": [
             r"\bbase64(?:\s+-w\s*0)?\s*\|\s*base64\b(?!\s+(?:-d|--decode|-D)\b)",
             r"(?<![=(`])\b(?:env|printenv)\s*\|\s*(?:base64|xxd|od|rev)\b(?![^\n]*\|\s*(?:curl|wget|nc)\b)",
             r"btoa\(\s*btoa\(",
             r"toString\(\s*[\"']base64[\"']\s*\)\s*\)\.toString\(\s*[\"']base64[\"']",
             r"b64encode\(\s*base64\.b64encode\(",
         ]},
        {"id": "runner_proc_snoop", "name": "Runner Process Snooping",
         "desc": "Locates the Runner.Worker process or reads other processes' environment",
         "regexes": [
             r"(?:pgrep|pidof)\b[^\n]{0,40}Runner\.Worker",
             r"\bps\b[^\n|]{0,40}\|\s*grep\b[^\n]{0,40}Runner\.Worker",
             r"/proc/(?:\*|\$\{?\w+\}?|\{\w*\}|[0-9]+|\"\s*\+\s*\w+\s*\+\s*\")/environ\b",
             r"\.credentials_rsaparams\b",
         ]},
        {"id": "exfil_host", "name": "Exfiltration Endpoint",
         "desc": "Hard-codes a webhook / paste / tunnel / OAST collector host",
         "regexes": [EXFIL_HOST]},
        {"id": "base64_exec", "name": "Decode-and-Execute",
         "desc": "Decodes an embedded payload and hands it to a shell / interpreter (reviewdog 2025 shape)",
         "regexes": [
             r"\bbase64\s+(?:-d|--decode|-D)\b[^\n|;]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b",
             r"\bbase64\s+(?:-d|--decode|-D)\b[^\n|;]*\|\s*(?:sudo\s+)?(?:python3?|node|perl)\b",
             r"\beval\s+[\"']?\$\(\s*(?:echo|printf)[^)\n]*\|\s*base64\s+(?:-d|--decode|-D)",
             r"\b(?:ba)?sh\s+-c\s+[\"']?\$\(\s*(?:echo|printf)[^)\n]*\|\s*base64\s+(?:-d|--decode|-D)",
             r"\bexec\(\s*(?:base64\.b64decode|zlib\.decompress|codecs\.decode|bytes\.fromhex|marshal\.loads)\s*\(",
             r"(?:eval|Function)\s*\(\s*(?:atob|unescape)\s*\(",
             r"(?:eval|new\s+Function)\s*\(\s*Buffer\.from\s*\([^)]{0,4000},\s*[\"'](?:base64|hex)[\"']",
             r"\b(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(\s*Buffer\.from\s*\([^)]{0,4000},\s*[\"']base64[\"']",
         ]},
        {"id": "shell_obfuscation", "name": "Shell Obfuscation",
         "desc": "${IFS} / brace-expansion tricks used to smuggle `curl | bash` past filters (ultralytics 2024)",
         "regexes": [
             r"\{(?:curl|wget),-",
             r"\b(?:curl|wget|bash|sh)\$\{IFS\}",
             r"\$\{IFS\}\|\$\{IFS\}(?:ba)?sh\b",
         ]},
        {"id": "env_hijack", "name": "Later-Step Hijack via $GITHUB_ENV",
         "desc": "Writes a loader variable (LD_PRELOAD, NODE_OPTIONS=--require ...) into "
                 "$GITHUB_ENV so every later step runs attacker code",
         "regexes": [
             r"\b(?:LD_PRELOAD|LD_AUDIT|DYLD_INSERT_LIBRARIES|PYTHONSTARTUP|PERL5OPT)=[^\n]{0,200}>>\s*[\"']?\$\{?GITHUB_ENV\b",
             r"\bNODE_OPTIONS=[^\n]{0,80}(?:--require|-r\s|--import|--(?:experimental-)?loader)[^\n]{0,200}>>\s*[\"']?\$\{?GITHUB_ENV\b",
             r"exportVariable\(\s*[\"'](?:LD_PRELOAD|LD_AUDIT|DYLD_INSERT_LIBRARIES)[\"']",
         ]},
        {"id": "cache_api_direct", "name": "Direct Cache-API Write",
         "desc": "Talks to the Actions cache service by hand with ACTIONS_RUNTIME_TOKEN (cache "
                 "poisoning, ultralytics 2024 / Cacheract)",
         "langs": {"sh", "py", "ps", "docker"},
         "regexes": [
             r"_apis/artifactcache/caches",
             r"twirp/github\.actions\.results\.api\.v1\.CacheService/(?:CreateCacheEntry|FinalizeCacheEntryUpload)",
         ]},
    ],
    "medium": [
        {"id": "fetched_env_write", "name": "Fetched Content into $GITHUB_ENV/$GITHUB_PATH",
         "desc": "Pipes downloaded content into the files that set later steps' environment / PATH",
         "langs": {"sh", "ps"},
         "regexes": [
             r"\b(?:curl|wget)\b[^\n]*(?:>>|\|\s*tee\s+(?:-a|--append))\s*[\"']?\$\{?GITHUB_(?:ENV|PATH)\b",
             r"\$\(\s*(?:curl|wget)\b[^)\n]*\)[^\n]*>>\s*[\"']?\$\{?GITHUB_(?:ENV|PATH)\b",
         ]},
        {"id": "raw_ip_url", "name": "Raw-IP URL",
         "desc": "Contacts a public IP address directly instead of a hostname",
         "regexes": [RAW_IP_URL]},
        {"id": "tls_disabled", "name": "TLS Verification Disabled",
         "desc": "Turns off certificate checking process-wide",
         "regexes": [r"NODE_TLS_REJECT_UNAUTHORIZED[\"']?\s*\]?\s*=\s*[\"']?0\b"]},
    ],
    "low": [],
    # capabilities: reported, never scored
    "info": [
        {"id": "oidc_request", "name": "OIDC Token Request",
         "desc": "Requests the job's OIDC token (cloud / registry federation does this)",
         "regexes": [r"ACTIONS_ID_TOKEN_REQUEST_(?:URL|TOKEN)\b|\bgetIDToken\s*\("]},
        {"id": "runtime_token", "name": "Runtime Token Access",
         "desc": "Reads ACTIONS_RUNTIME_TOKEN / cache / results URLs (cache and artifact clients do)",
         "regexes": [r"ACTIONS_RUNTIME_TOKEN\b|ACTIONS_CACHE_URL\b|ACTIONS_RESULTS_URL\b"]},
        {"id": "runner_worker_ref", "name": "Runner.Worker Reference",
         "desc": "Mentions the Runner.Worker process",
         "regexes": [r"Runner\.Worker\b"]},
        {"id": "github_env_write", "name": "Writes $GITHUB_ENV/$GITHUB_PATH",
         "desc": "Sets environment / PATH for later steps",
         "regexes": [r"GITHUB_(?:ENV|PATH)\b|\bexportVariable\s*\(|\baddPath\s*\("]},
        {"id": "credential_read", "name": "Credential Store Reference",
         "desc": "References ~/.ssh, ~/.aws, ~/.docker/config.json, .git-credentials, git extraheader ...",
         "regexes": [r"\.ssh[/\\\\]id_\w+|\.aws[/\\\\]credentials|\.git-credentials|\.docker[/\\\\]config\.json|"
                     r"\.kube[/\\\\]config|\.pypirc|\.config/gh/hosts\.yml|\bextraheader\b"]},
        {"id": "bash_env_export", "name": "BASH_ENV Export",
         "desc": "Points BASH_ENV of later steps at a file (setup actions do this for their own shell profile)",
         "regexes": [r"\bBASH_ENV=[^\n]{0,200}>>\s*[\"']?\$\{?GITHUB_ENV\b|exportVariable\(\s*[\"']BASH_ENV[\"']"]},
        {"id": "remote_session", "name": "Remote Debug Session",
         "desc": "Opens an interactive remote session to the runner (tmate / upterm / tunnels)",
         "regexes": [r"\btmate\b|\bupterm\b|\bngrok\s+(?:tcp|http)|\bcloudflared\s+tunnel|\bsshx\b"]},
        {"id": "network", "name": "Network Access", "desc": "Makes outbound requests",
         "regexes": [NET_SEND]},
        {"id": "child_process", "name": "Process Spawning", "desc": "Spawns processes",
         "langs": {"js", "py"},
         "regexes": [r"child_process|\bexecSync\s*\(|\bspawnSync\s*\(|\bsubprocess\.|\bos\.system\s*\("]},
    ],
}
CONTEXT_ONCE = {"bash_env_export", "oidc_request", "runtime_token", "runner_worker_ref", "github_env_write", "credential_read",
                "remote_session", "network", "child_process"}
REMOTE_EXEC = [
    r"\b(?:curl|wget)\b[^\n|;]*\|\s*(?:sudo\s+(?:-\w+\s+)*)?(?:(?:/usr)?/bin/)?(?:ba|z|da)?sh\b",
    r"\b(?:curl|wget)\b[^\n|;]*\|\s*(?:sudo\s+(?:-\w+\s+)*)?(?:python3?|node|perl|ruby)\b",
    r"\b(?:ba|z)?sh\s+-c\s+[\"']?\$\(\s*(?:curl|wget)\b",
    r"(?:\bsource|^\s*\.)\s+<\(\s*(?:curl|wget)\b",
    r"\b(?:ba|z)?sh\s*<\s*\(\s*(?:curl|wget)\b",
    r"\beval\s+[\"']?\$\(\s*(?:curl|wget)\b",
    r"(?:\biex\b|Invoke-Expression)[^\n]{0,60}(?:\biwr\b|\birm\b|Invoke-WebRequest|Invoke-RestMethod|DownloadString)",
    r"(?:\biwr\b|\birm\b|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]*\|\s*(?:iex|Invoke-Expression)\b",
]

SEVERITY_SCORE = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "SAFE": 0}
SEV_UP = {"LOW": "LOW", "MEDIUM": "HIGH", "HIGH": "CRITICAL", "CRITICAL": "CRITICAL", "INFO": "INFO"}


# ---- literal prefilter ----------------------------------------------------------------
# re is slow on IGNORECASE alternations over 10 MB ncc bundles. Each regex gets an any-of set
# of lowercase literals derived from its parse tree; a C-speed substring test skips regexes
# that cannot match, and matching only runs in windows around the literal hits.
def _lits(parsed):
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
    return text.lower() if text.isascii() else text.translate(_ASCII_LOWER)


def _finditer(rx, lits, text, low, before=700, after=900, cap=3000):
    """rx.finditer(text), restricted to windows around the regex's required literals."""
    if lits is None or len(low) != len(text):
        if len(text) > 400000:  # no literal anchor: scan in overlapping windows
            seen_end = -1
            for lo in range(0, len(text), 8192 - 1024):
                for m in rx.finditer(text, lo, min(len(text), lo + 8192)):
                    if m.start() >= seen_end:
                        seen_end = m.end()
                        yield m
            return
        yield from rx.finditer(text)
        return
    pos = []
    for lit in lits:
        i = low.find(lit)
        while i != -1:
            pos.append(i)
            if len(pos) > cap:  # literal is everywhere: one full scan is cheaper than thousands of windows
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


def _compile(rx):
    return re.compile(rx, re.IGNORECASE | re.MULTILINE), _prefilter(rx)


_COMPILED = [(sev, pg, ) + _compile(rx) for sev, groups in PATTERNS.items() for pg in groups for rx in pg["regexes"]]
_REMOTE_EXEC = [_compile(rx) for rx in REMOTE_EXEC]
EXFIL_RE = re.compile(EXFIL_HOST, re.I)
RAWIP_RE = re.compile(RAW_IP_URL)
URL_RE = re.compile(_URL, re.I)
NET_RE, NET_LITS = _compile(NET_SEND)
# language-specific network sinks for proximity rules (a `curl` inside a JS help string is not one)
NET_LANG = {
    "js": re.compile(r"\bfetch\s*\(|https?\.(?:request|get)\s*\(|axios(?:\.\w+)?\s*\(|\bgot(?:\.\w+)?\s*\(|"
                     r"XMLHttpRequest|net\.connect|new\s+net\.Socket|dns\.(?:lookup|resolve\w*)\s*\(|"
                     r"\brequest\s*\(\s*\{|undici|\.post\s*\(\s*[\"'`]https?:"),
    "py": re.compile(r"requests\.(?:get|post|put|patch|request)\s*\(|urlopen\s*\(|http\.client|socket\.socket|"
                     r"httpx\.|aiohttp\.|urllib3"),
}
OBF_IDENT = re.compile(r"\b_0x[0-9a-f]{4,6}\b")
EXEC_SINK_RE = re.compile(r"(?:\bexec(?:Sync|File|FileSync)?|\bspawn(?:Sync)?|\bexeca(?:Sync|Command)?|"
                          r"\bgetExecOutput|\bshell\.exec|\bsystem|\bPopen|\bcheck_output|\bcheck_call|"
                          r"subprocess\.run|os\.popen|\brun(?:Command|Shell|Script)?)\s*\(|shell\s*[:=]\s*true|"
                          r"\[\s*[\"'](?:ba)?sh[\"']\s*,\s*[\"']-c[\"']", re.I)
CHAT_API_RE = re.compile(r"api\.telegram\.org/bot|discord(?:app)?\.com/api/webhooks/|hooks\.slack\.com/services/", re.I)
HARDCODED_CHAT_RE = re.compile(r"api\.telegram\.org/bot\d{5,}:[\w-]{20,}|discord(?:app)?\.com/api/webhooks/\d{4,}/[\w-]{10,}|"
                               r"hooks\.slack\.com/services/T\w+/B\w+/\w+", re.I)
PLACEHOLDER_RE = re.compile(r"(?:\b(?:your|my)[-_]|xxxx|<[\w-]+>|\{[\w-]+\}|\b123456\b|example)", re.I)
JS_ENV_DUMP = re.compile(r"JSON\.stringify\(\s*process\.env\s*[,)]|new\s+URLSearchParams\(\s*process\.env\s*\)|"
                         r"querystring\.stringify\(\s*process\.env\s*\)")
PY_ENV_DUMP = re.compile(r"json\.dumps\(\s*(?:dict\()?\s*os\.environ\b|\bstr\(\s*os\.environ\s*\)|\bdict\(\s*os\.environ\s*\)")
DATA_SEND_RE = re.compile(r"\b(?:curl|wget)\b[^\n]*(?:\s-d\b|\s--data|\s-F\b|\s--form|\s-X\s*POST|\s--post-data|\s-T\b|--upload-file)|"
                          r"requests\.(?:post|put)\(|Invoke-(?:WebRequest|RestMethod)[^\n]*-Method\s+Post", re.I)
_INFO_RX = {pg["id"]: pg["regexes"][0] for pg in PATTERNS["info"]}
CRED_RE = re.compile(_INFO_RX["credential_read"], re.I)
OIDC_RE = re.compile(_INFO_RX["oidc_request"])
RUNTIME_RE = re.compile(_INFO_RX["runtime_token"])
B64_LIT = re.compile(r"(?<![A-Za-z0-9+/=_\\-])([A-Za-z0-9+/]{60,}={0,2})(?![A-Za-z0-9+/=_-])")
BLOB_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{4096,}|(?<!\\x[0-9a-fA-F]{2})(?:\\x[0-9a-fA-F]{2}){1024,}")
COMMENT_LINE = {"sh": re.compile(r"^\s*#"), "docker": re.compile(r"^\s*#"), "py": re.compile(r"^\s*#"),
                "ps": re.compile(r"^\s*(?:#|<#)"), "js": re.compile(r"^\s*(?://|/?\*)")}
DISPLAY_RE = re.compile(r"^\s*(?:-\s+)?(?:echo|printf|::(?:notice|warning|error|debug)|core\.(?:info|warning|error|notice|debug)|"
                        r"console\.(?:log|warn|error)|Write-(?:Host|Output)|print\(|log\w*\()", re.I)
COMMENT_DEMOTE = {"download_execute", "remote_script_exec", "env_exfil", "reverse_shell", "destructive", "cryptominer",
                  "exfil_host", "raw_ip_url", "log_mask_evasion", "base64_exec", "shell_obfuscation", "env_hijack",
                  "fetched_env_write", "runner_proc_snoop", "cache_api_direct", "tls_disabled"}
SHELL_ONLY = {"download_execute", "remote_script_exec", "env_exfil", "reverse_shell", "destructive", "log_mask_evasion",
              "base64_exec", "shell_obfuscation", "env_hijack", "fetched_env_write", "runner_proc_snoop", "cryptominer"}
NO_PHASE_ESCALATION = {"tls_disabled", "unpinned_action", "unpinned_image", "remote_script_exec", "raw_ip_url"}
GENERIC_TOKENS = {"action", "actions", "github", "setup", "the", "and", "for", "com", "www", "http", "https", "run",
                  "tool", "tools", "cli", "bin", "app", "dev", "org", "net", "io", "get", "install", "official",
                  "docker", "deploy", "build", "test", "ci", "cd", "workflow", "main", "master", "release",
                  "releases", "download", "raw", "githubusercontent", "api", "cdn"}


def _item(sev, pid, name, desc, path, line, matched, context):
    return {"severity": sev, "id": pid, "name": name, "description": desc, "file": path,
            "line": line, "matched": matched[:120], "context": context.strip()[:200]}


# ---------------------------------------------------------------------------
# Minimal YAML reader (stdlib has none). Enough for action.yml and workflows: block maps and
# sequences, block scalars (| >), quoted / plain / flow scalars, comments. Scalars carry the
# 1-based line they start on, so findings inside `run: |` blocks point at the right line.
# ---------------------------------------------------------------------------
class YStr(str):
    line = 0


def _ys(s, line):
    v = YStr(s)
    v.line = line
    return v


KEY_RE = re.compile(r"""^((?:"(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^\s"'#\[\]{},:][^#]*?|[\w.$/-]+))\s*:(?=\s|$)""")


def _unq(s):
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] == '"':
        return _dq(s[1:-1])
    if len(s) >= 2 and s[0] == s[-1] == "'":
        return s[1:-1].replace("''", "'")
    return s


def _dq(s):
    return re.sub(r"\\(.)", lambda m: {"n": "\n", "t": "\t", '"': '"', "\\": "\\", "/": "/"}.get(m.group(1), m.group(0)), s)


def _strip_comment(v):
    m = re.search(r"\s#", v)
    return v[:m.start()].rstrip() if m else v.rstrip()


def _close_quote(s, q):
    i = 0
    while i < len(s):
        c = s[i]
        if q == '"' and c == "\\":
            i += 2
            continue
        if c == q:
            if q == "'" and i + 1 < len(s) and s[i + 1] == "'":
                i += 2
                continue
            return i
        i += 1
    return -1


def _flow(v):
    v = _strip_comment(v)
    if v.startswith("[") and v.endswith("]"):
        return [_unq(x) for x in v[1:-1].split(",") if x.strip()]
    if v.startswith("{") and v.endswith("}"):
        out = {}
        for part in v[1:-1].split(","):
            if ":" in part:
                k, _, val = part.partition(":")
                out[_unq(k)] = _unq(val)
        return out
    return v


class _YP:
    def __init__(self, text):
        self.raw = text.replace("\r\n", "\n").replace("\r", "\n").replace("\t", "  ").split("\n")
        self.L = []
        for i, r in enumerate(self.raw):
            s = r.strip()
            if not s or s.startswith("#") or s in ("---", "...") or s.startswith("%YAML"):
                self.L.append(None)
            else:
                self.L.append([len(r) - len(r.lstrip(" ")), s, i + 1])
        self.i = 0

    def peek(self):
        while self.i < len(self.L) and self.L[self.i] is None:
            self.i += 1
        return self.L[self.i] if self.i < len(self.L) else None

    @staticmethod
    def _dash(s):
        return s == "-" or s.startswith("- ")

    def block(self, ind):
        t = self.peek()
        if t is None or t[0] < ind:
            return None
        return self.seq(t[0]) if self._dash(t[1]) else self.map(t[0])

    def seq(self, ind):
        out = []
        while True:
            t = self.peek()
            if t is None or t[0] != ind or not self._dash(t[1]):
                return out
            rest = t[1][1:]
            content = rest.lstrip(" ")
            if not content:
                self.i += 1
                nt = self.peek()
                out.append(self.block(nt[0]) if nt and nt[0] > ind else None)
                continue
            nind = ind + 1 + len(rest) - len(content)
            if self._dash(content) or (KEY_RE.match(content) and content[:1] not in "\"'[{"
                                       or KEY_RE.match(content) and content[:1] in "\"'"):
                self.L[self.i] = [nind, content, t[2]]
                out.append(self.block(nind))
            else:
                self.i += 1
                out.append(self.scalar(content, t[2], ind))

    def map(self, ind):
        out = {}
        while True:
            t = self.peek()
            if t is None or t[0] != ind or self._dash(t[1]):
                return out
            m = KEY_RE.match(t[1])
            if not m:
                self.i += 1
                continue
            key = _unq(m.group(1))
            rest = t[1][m.end():].strip()
            self.i += 1
            if not rest or rest.startswith("#"):
                nt = self.peek()
                if nt and (nt[0] > ind or (nt[0] == ind and self._dash(nt[1]))):
                    out[key] = self.block(nt[0])
                else:
                    out[key] = None
            else:
                out[key] = self.scalar(rest, t[2], ind)

    def scalar(self, rest, lineno, ind):
        if re.match(r"^[|>][+-]?\d?[+-]?\s*(?:#.*)?$", rest):
            return self.blockscalar(rest[0], lineno, ind)
        if rest[:1] in "\"'":
            q, body, j = rest[0], rest[1:], lineno
            while _close_quote(body, q) < 0 and j < len(self.raw):
                body += ("\n" if q == '"' else " ") + self.raw[j].strip()
                j += 1
            self.i = max(self.i, j)
            k = _close_quote(body, q)
            body = body[:k] if k >= 0 else body
            return _ys(_dq(body) if q == '"' else body.replace("''", "'"), lineno)
        if rest[:1] in "[{":
            return _flow(rest)
        v = _strip_comment(rest)
        j = lineno
        while j < len(self.L) and self.L[j] is not None and self.L[j][0] > ind:
            v += " " + _strip_comment(self.L[j][1])
            j += 1
        self.i = max(self.i, j)
        return _ys(v, lineno)

    def blockscalar(self, ch, lineno, pind):
        j, lines, bi = lineno, [], None
        while j < len(self.raw):
            r = self.raw[j]
            if not r.strip():
                lines.append("")
                j += 1
                continue
            ci = len(r) - len(r.lstrip(" "))
            if ci <= pind or (bi is not None and ci < bi):
                break
            if bi is None:
                bi = ci
            lines.append(r[bi:])
            j += 1
        while lines and lines[-1] == "":
            lines.pop()
        self.i = max(self.i, j)
        text = "\n".join(lines) if ch == "|" else re.sub(r"(?<=\S)\n(?=\S)", " ", "\n".join(lines))
        return _ys(text + "\n", lineno + 1)


def yaml_load(text):
    try:
        p = _YP(text)
        t = p.peek()
        return p.block(t[0]) if t else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Action model: which code runs, and when
# ---------------------------------------------------------------------------
PHASE_RANK = {"unreached": 0, "build": 1, "main": 2, "pre": 3, "post": 3}


def _lang(path, text=""):
    p = path.lower()
    if p.endswith((".js", ".cjs", ".mjs", ".ts", ".mts", ".cts")):
        return "js"
    if p.endswith(".py"):
        return "py"
    if p.endswith((".ps1", ".psm1")):
        return "ps"
    if posixpath.basename(p).startswith("dockerfile") or p.endswith(".dockerfile"):
        return "docker"
    head = text[:120]
    if head.startswith("#!"):
        if "python" in head.split("\n")[0]:
            return "py"
        if "node" in head.split("\n")[0]:
            return "js"
    return "sh"


def _shell_lang(shell):
    s = str(shell or "").lower()
    if s.startswith(("pwsh", "powershell")):
        return "ps"
    if s.startswith("python"):
        return "py"
    if s.startswith("node"):
        return "js"
    return "sh"


def _join(adir, p):
    p = str(p).strip().strip("\"'")
    if not p:
        return ""
    if p.startswith("/"):
        p = p.lstrip("/")
    out = posixpath.normpath(posixpath.join(adir, p)) if adir else posixpath.normpath(p)
    return "" if out == "." else out


ACTION_PATH_REF = re.compile(r"(?:github\.action_path\s*\}\}|GITHUB_ACTION_PATH\}?|\$\{\{\s*env\.GITHUB_ACTION_PATH\s*\}\})"
                             r"[\"']?/([\w./@+-]+)")
FILE_LIT = re.compile(r"(?<![\w/.-])((?:\.{0,2}/)?[\w@+-][\w./@+-]*\.(?:sh|bash|py|js|cjs|mjs|ts|ps1|rb|pl))\b")
JS_REL = re.compile(r"""(?:require\s*\(\s*|\bfrom\s+|\bimport\s*\(\s*|\bimport\s+)["'](\.{1,2}/[^"'\n]+)["']""")
JS_DIRNAME = re.compile(r"""__dirname\s*(?:\+\s*|,\s*)["'`](/?[\w./-]+\.(?:sh|bash|py|js|cjs|mjs|ps1))["'`]""")
PY_MODULE_RUN = re.compile(r"\bpython[\d.]*\s+(?:-\w+\s+)*-m\s+([\w.]+)")
PY_IMPORT = re.compile(r"^\s*(?:from\s+(\.*[\w.]*)\s+import\b|import\s+([\w.]+(?:\s*,\s*[\w.]+)*))", re.M)


class _Files:
    def __init__(self, files):
        self.files = files
        self.by_base = {}
        for p in files:
            self.by_base.setdefault(posixpath.basename(p), []).append(p)

    def resolve(self, cand_dirs, rel, exts=("",)):
        rel = rel.strip().strip("\"'")
        if not rel or "${{" in rel:
            return None
        for d in cand_dirs:
            for e in exts:
                p = _join(d, rel + e)
                if p in self.files:
                    return p
        return None

    def container_path(self, adir, tok):
        """A path inside the image (/app/dist/index.js) -> the repo file it was COPY'd from:
        the longest unique path suffix that exists under adir."""
        parts = [x for x in tok.strip("\"'").split("/") if x and x != "."]
        for i in range(len(parts)):
            p = self.suffix(adir, "/".join(parts[i:]))
            if p:
                return p
        return None

    def suffix(self, adir, rel):
        """A unique file under adir whose path ends with rel."""
        rel = posixpath.normpath(rel.lstrip("./")) if rel.lstrip("./") else ""
        if not rel:
            return None
        hits = [p for p in self.by_base.get(posixpath.basename(rel), [])
                if (not adir or p.startswith(adir + "/")) and (p == _join(adir, rel) or p.endswith("/" + rel) or p == rel)]
        return hits[0] if len(hits) == 1 else None


def _refs(fs, path, text, lang, adir):
    """Files a reached file pulls in: JS relative imports, Python local imports, script names."""
    out = set()
    fdir = posixpath.dirname(path) if not path.startswith(("action.yml#", "action.yaml#")) else adir
    if "#" in path:
        fdir = adir
    if lang == "js":
        for m in JS_REL.finditer(text[:3000000]):
            p = fs.resolve([fdir], m.group(1), ("", ".js", ".cjs", ".mjs", ".ts", "/index.js", "/index.ts"))
            if p:
                out.add(p)
        for m in JS_DIRNAME.finditer(text[:3000000]):
            p = fs.resolve([fdir], m.group(1).lstrip("/"))
            if p:
                out.add(p)
        if len(text) < 300000:
            for m in ACTION_PATH_REF.finditer(text):
                p = fs.resolve([adir], m.group(1)) or fs.suffix(adir, m.group(1))
                if p:
                    out.add(p)
        return out
    if lang == "py":
        for m in PY_IMPORT.finditer(text):
            mods = [m.group(1)] if m.group(1) else [x.strip() for x in m.group(2).split(",")]
            for mod in mods:
                dots = len(mod) - len(mod.lstrip("."))
                name = mod.lstrip(".").replace(".", "/")
                base = fdir
                for _ in range(max(0, dots - 1)):
                    base = posixpath.dirname(base)
                if not name:
                    continue
                p = fs.resolve([base, adir], name, (".py", "/__init__.py"))
                if p:
                    out.add(p)
    for m in ACTION_PATH_REF.finditer(text):
        p = fs.resolve([adir], m.group(1)) or fs.suffix(adir, m.group(1))
        if p:
            out.add(p)
    for m in FILE_LIT.finditer(text):
        p = fs.resolve([fdir, adir], m.group(1)) or fs.container_path(adir, m.group(1))
        if p and p != path:
            out.add(p)
    for m in PY_MODULE_RUN.finditer(text):  # python -m pkg.module (PYTHONPATH from step env)
        mod = m.group(1).replace(".", "/")
        p = fs.container_path(adir, mod + ".py") or fs.container_path(adir, mod + "/__main__.py")
        if p and p != path:
            out.add(p)
    return out


def _dockerfile_refs(fs, path, text, adir):
    """(file, phase) for scripts named by RUN (build) and ENTRYPOINT/CMD (main) instructions."""
    out = []
    joined = re.sub(r"\\\n", " ", text)
    for line in joined.split("\n"):
        m = re.match(r"\s*(RUN|ENTRYPOINT|CMD)\b(.*)", line, re.I)
        if not m:
            continue
        phase = "build" if m.group(1).upper() == "RUN" else "main"
        for fm in re.finditer(r"[\w./@+-]+", m.group(2)):
            tok = fm.group(0)
            if "/" not in tok and "." not in tok:
                continue
            p = fs.container_path(adir, tok) if tok.startswith("/") else (
                fs.resolve([posixpath.dirname(path), adir], tok) or fs.container_path(adir, tok))
            if p and p != path:
                out.append((p, phase))
    return out


def find_actions(files):
    """Directories holding an action.yml / action.yaml (outside tests / node_modules)."""
    out = []
    for p in sorted(files):
        b = posixpath.basename(p)
        if b in ("action.yml", "action.yaml"):
            d = posixpath.dirname(p)
            if NONRUN_DIR.search(p) and not d.startswith(".github/actions"):
                continue
            if d not in [x for x, _ in out]:
                out.append((d, p))
    return out


def _identity(label, doc):
    raw = [label]
    if isinstance(doc, dict):
        raw += [str(doc.get("name") or ""), str(doc.get("author") or "")]
    toks = set()
    for r in raw:
        toks.update(t for t in re.split(r"[^a-z0-9]+", r.lower()) if len(t) >= 3)
    return frozenset(toks - GENERIC_TOKENS)


def _host_is_vendor(url, ident):
    m = re.search(r"https?://(?:raw\.githubusercontent\.com|github\.com|objects\.githubusercontent\.com)/([A-Za-z0-9_.-]+)/", url)
    host = m.group(1) if m else None
    if not host:
        m = re.search(r"https?://([a-z0-9.-]+)", url, re.I)
        if not m:
            return False
        host = m.group(1)
    labels = {t for t in re.split(r"[^a-z0-9]+", host.lower()) if len(t) >= 3} - GENERIC_TOKENS
    return any(l in ident or any(v in l for v in ident if len(v) >= 4) or (len(l) >= 5 and any(l in v for v in ident))
               for l in labels)


def _uses_findings(uses, where, line=0):
    """Pinning check for a `uses:` value."""
    u = str(uses).strip()
    if u.startswith("./") or not u:
        return []
    if u.startswith("docker://"):
        if "@sha256:" in u:
            return []
        return [_item("LOW", "unpinned_image", "Unpinned Container Image",
                      "docker:// image referenced by tag, not digest - the tag can be repointed",
                      where, line, u, "uses: " + u)]
    if "@" not in u:
        return [_item("LOW", "unpinned_action", "Unpinned Action", "No ref at all", where, line, u, "uses: " + u)]
    act, ref = u.rsplit("@", 1)
    if re.fullmatch(r"[0-9a-f]{40}", ref):
        return []
    owner = act.split("/", 1)[0].lower()
    if owner in ("actions", "github"):
        return [_item("INFO", "first_party_tag", "First-Party Action by Tag",
                      "GitHub-owned action referenced by a mutable tag", where, line, u, "uses: " + u)]
    return [_item("LOW", "unpinned_action", "Unpinned Action",
                  "Third-party action referenced by a mutable ref (@%s); its owner - or whoever compromises "
                  "them - can repoint it, as happened to every tj-actions/changed-files tag in 2025" % ref,
                  where, line, u, "uses: " + u)]


def plan_action(fs, adir, yml_path, label):
    """Return (doc, units, meta). A unit is a dict(path, text, lang, phase, line0)."""
    text = fs.files.get(yml_path, "")
    doc = yaml_load(text)
    if not isinstance(doc, dict):
        doc = {}
    runs = doc.get("runs") if isinstance(doc.get("runs"), dict) else {}
    using = str(runs.get("using") or "").strip().lower()
    meta = {"using": using or "unknown", "entrypoints": {}, "uses": [], "findings": [], "info": []}
    reached = {}  # path -> phase
    units = []

    def reach(p, phase):
        if p and p in fs.files and (p not in reached or PHASE_RANK[phase] > PHASE_RANK[reached[p]]):
            reached[p] = phase
            return True
        return False

    queue = []
    if using.startswith("node") or using.startswith("bun") or using.startswith("deno"):
        for key, phase in (("pre", "pre"), ("main", "main"), ("post", "post")):
            if runs.get(key):
                p = _join(adir, runs[key])
                meta["entrypoints"][key] = p
                if reach(p, phase):
                    queue.append(p)
                elif p not in fs.files:
                    meta["info"].append(_item("INFO", "missing_entrypoint", "Entrypoint Not Found",
                                              "runs.%s points at a file not in the tree" % key, yml_path, 0, p, p))
    elif using == "composite":
        steps = runs.get("steps") if isinstance(runs.get("steps"), list) else []
        for i, st in enumerate(steps):
            if not isinstance(st, dict):
                continue
            if st.get("uses"):
                u = str(st["uses"])
                meta["uses"].append(u)
                meta["findings"] += _uses_findings(u, yml_path, getattr(st["uses"], "line", 0))
                w = st.get("with") if isinstance(st.get("with"), dict) else {}
                if u.lower().startswith("actions/github-script") and w.get("script"):
                    s = w["script"]
                    units.append({"path": yml_path, "text": str(s), "lang": "js", "phase": "main",
                                  "line0": max(0, getattr(s, "line", 1) - 1), "where": "steps[%d].with.script" % i})
            if st.get("run"):
                r = st["run"]
                env = st.get("env") if isinstance(st.get("env"), dict) else {}
                units.append({"path": yml_path, "text": str(r), "lang": _shell_lang(st.get("shell")), "phase": "main",
                              "line0": max(0, getattr(r, "line", 1) - 1), "where": "steps[%d].run" % i,
                              "env": "\n".join(str(v) for v in env.values())})
    elif using == "docker":
        image = str(runs.get("image") or "")
        meta["entrypoints"]["image"] = image
        if image.startswith("docker://"):
            meta["findings"] += _uses_findings(image, yml_path)
            meta["info"].append(_item("INFO", "prebuilt_image", "Prebuilt Image (opaque)",
                                      "The action runs a prebuilt image; its contents are not in the repository",
                                      yml_path, 0, image, image))
        else:
            dp = _join(adir, image or "Dockerfile")
            if dp in fs.files:
                reached[dp] = "build"
                queue.append(dp)
        for key, phase in (("pre-entrypoint", "pre"), ("entrypoint", "main"), ("post-entrypoint", "post")):
            v = runs.get(key)
            if v:
                meta["entrypoints"][key] = str(v)
                for tok in re.findall(r"[\w./@+-]+", str(v)):
                    p = fs.resolve([adir], tok) or fs.container_path(adir, tok)
                    if p and reach(p, phase):
                        queue.append(p)
                if phase != "main":
                    units.append({"path": yml_path, "text": str(v) + " " + " ".join(map(str, runs.get("args") or [])),
                                  "lang": "sh", "phase": phase, "line0": max(0, getattr(v, "line", 1) - 1),
                                  "where": "runs.%s" % key})
    else:
        meta["info"].append(_item("INFO", "unknown_runs", "Unknown runs.using",
                                  "Could not determine how this action runs", yml_path, 0, using, using))
    # composite run text (and the step env it runs with) may name scripts
    for u in list(units):
        for p in _refs(fs, u["path"] + "#", u["text"] + "\n" + u.get("env", ""), u["lang"], adir):
            if reach(p, u["phase"]):
                queue.append(p)
    # transitive closure
    guard = 0
    while queue and guard < 400:
        guard += 1
        p = queue.pop(0)
        t = fs.files[p]
        lg = _lang(p, t)
        if lg == "docker":
            for q, ph in _dockerfile_refs(fs, p, t, adir):
                ph = ph if reached[p] != "build" or ph == "main" else "build"
                if reach(q, ph):
                    queue.append(q)
            continue
        for q in _refs(fs, p, t, lg, adir):
            if reach(q, reached[p]):
                queue.append(q)
    entry_dirs = [str(v) for v in meta["entrypoints"].values()]
    for p in list(reached):
        rel = p[len(adir) + 1:] if adir else p
        if NONRUN_DIR.search(rel) and not any(NONRUN_DIR.search(e) for e in entry_dirs):
            reached[p] = "unreached"
    for p, ph in sorted(reached.items()):
        units.append({"path": p, "text": fs.files[p], "lang": _lang(p, fs.files[p]), "phase": ph, "line0": 0, "where": ""})
    # everything else under the action dir: scanned for context only
    budget = MAX_UNREACHED
    for p in sorted(fs.files):
        if p in reached or p == yml_path or (adir and not p.startswith(adir + "/")):
            continue
        if not p.lower().endswith(SCRIPT_EXT) or p.lower().endswith(".d.ts") or NONRUN_DIR.search(p[len(adir):] + "/" if adir else p):
            continue
        t = fs.files[p]
        if len(t) > budget:
            continue
        budget -= len(t)
        units.append({"path": p, "text": t, "lang": _lang(p, t), "phase": "unreached", "line0": 0, "where": ""})
    return doc, units, meta


# ---------------------------------------------------------------------------
# Scanning one unit of code
# ---------------------------------------------------------------------------
def _strip_blobs(text):
    """Blank >=4 KB base64 / hex-escape runs (embedded wasm, fonts) in place, keeping offsets.
    Such a run can only sit on a line of 4 KB or more, so only those lines are searched."""
    if len(text) <= 4096:
        return text
    out, pos, changed = [], 0, False
    for line in text.split("\n"):
        if len(line) >= 4096:
            new = BLOB_RE.sub(lambda m: " " * len(m.group(0)), line)
            changed |= new is not line and new != line
            out.append(new)
        else:
            out.append(line)
    return "\n".join(out) if changed else text


def _decode_b64(s):
    try:
        raw = base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) < 30:
        return None
    try:
        t = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(1 for c in t if c.isprintable() or c in "\n\r\t")
    if printable < 0.97 * len(t) or not re.search(r"[ \n]", t) or not re.search(r"[a-z]{3}", t):
        return None
    return t


def _in_quotes(line, s, e, shell=True):
    """True if [s, e) lies inside one quoted string literal on this line. In shell, a $(...) or
    backtick substitution inside the quotes still executes, so it does not count."""
    for m in re.finditer(r'"(?:[^"\\]|\\.)*"|\'[^\']*\'', line):
        if m.start() < s and e <= m.end():
            return not shell or ("$(" not in line[m.start():s] and "`" not in line[m.start():s])
    return False


def _in_docstring(text, pos):
    """True if pos sits inside a triple-quoted Python string."""
    return (text.count('"""', 0, pos) % 2 == 1) or (text.count("'''", 0, pos) % 2 == 1)


def scan_unit(unit, ident=frozenset(), depth=0):
    text = _strip_blobs(unit["text"])
    lang, path, line0 = unit["lang"], unit["path"], unit["line0"]
    starts = [0] + [m.end() for m in re.finditer("\n", text)]
    lines = text.split("\n")
    low = _lower(text)
    local = []
    seen = set()

    def lineof(pos):
        return bisect.bisect_right(starts, pos)

    def ctx(pos):
        n = lineof(pos)
        ln = lines[n - 1]
        s = pos - starts[n - 1]
        return n, ln, ln[max(0, s - 60):s + 140]

    present = {}

    def possible(lits):
        if lits is None:
            return True
        for l in lits:
            if l not in present:
                present[l] = l in low
            if present[l]:
                return True
        return False

    for sev, pg, rx, lits in _COMPILED:
        pid = pg["id"]
        langs = pg.get("langs")
        if langs and lang not in langs:
            continue
        if pid in CONTEXT_ONCE and pid in seen:
            continue
        if not possible(lits):
            continue
        for m in _finditer(rx, lits, text, low):
            n, ln, c = ctx(m.start())
            if (pid, n) in seen:
                continue
            seen.add((pid, n))
            it = _item(sev.upper(), pid, pg["name"], pg["desc"], path, line0 + n, m.group(0), c)
            it["_pos"], it["_end"], it["_line"] = m.start(), m.end(), ln
            local.append(it)
            if pid in CONTEXT_ONCE:
                seen.add(pid)
                break
    # remote script execution: classify the host
    for rx, lits in _REMOTE_EXEC:
        if not possible(lits):
            continue
        for m in _finditer(rx, lits, text, low):
            n, ln, c = ctx(m.start())
            if ("rx", n) in seen:
                continue
            seen.add(("rx", n))
            seg = ln[max(0, m.start() - starts[n - 1] - 300):m.end() - starts[n - 1] + 200]
            if not re.search(r"https?:|\$|[a-z0-9-]+\.[a-z]{2,}/", m.group(0), re.I):
                continue  # `curl --version | perl ...` fetches nothing
            urls = URL_RE.findall(m.group(0)) or URL_RE.findall(seg) or re.findall(r"(?<![\w/.-])((?:[a-z0-9-]+\.)+[a-z]{2,}/[^\s\"'`|;)]*)", m.group(0), re.I)
            if any(SKETCHY_HOST.search(u) for u in urls) or (not urls and SKETCHY_HOST.search(m.group(0))):
                it = _item("CRITICAL", "download_execute", "Download & Execute (untrusted host)",
                           "Pipes content from a paste / gist / tunnel / raw-IP / collector host into a shell or interpreter",
                           path, line0 + n, m.group(0), c)
            elif urls and all(KNOWN_INSTALLER.search(u) or _host_is_vendor(u, ident) for u in urls):
                it = _item("INFO", "known_installer", "Vendor Installer Piped to Shell",
                           "curl | sh of an official installer or the action's own vendor", path, line0 + n, m.group(0), c)
            else:
                it = _item("MEDIUM", "remote_script_exec", "Remote Script Execution",
                           "Pipes a mutable remote script into a shell or interpreter", path, line0 + n, m.group(0), c)
            it["_pos"], it["_end"], it["_line"] = m.start(), m.end(), ln
            local.append(it)

    ids = {f["id"] for f in local}

    def near(rx, pos, span=NEAR):
        return rx.search(text, max(0, pos - span), pos + span)

    def demote(f, why):
        f["severity"] = "INFO"
        f["description"] += " [%s]" % why

    is_bundle = lang == "js" and len(text) > 200000
    # ---- demotions by position -------------------------------------------------------
    cm = COMMENT_LINE.get(lang)
    for f in local:
        if f["severity"] == "INFO":
            continue
        ln = f["_line"]
        if cm and f["id"] in COMMENT_DEMOTE and cm.match(ln):
            demote(f, "comment")
            continue
        if lang == "js" and f["id"] in COMMENT_DEMOTE and re.search(r"//[^\n\"'`]{0,160}$", text[max(0, f["_pos"] - 160):f["_pos"]]):
            demote(f, "comment")  # a // comment in the middle of a minified line
            continue
        if lang in ("sh", "ps", "docker") and f["id"] in SHELL_ONLY | {"exfil_host", "raw_ip_url"} and DISPLAY_RE.match(ln) \
                and f["id"] not in ("env_hijack", "fetched_env_write"):
            ls = starts[lineof(f["_pos"]) - 1]
            if _in_quotes(ln, f["_pos"] - ls, f["_end"] - ls):
                demote(f, "printed, not executed")
                continue
        if lang in ("js", "py") and f["id"] == "tls_disabled" and not re.search(r"environ|process\.env|putenv", ln):
            ls = starts[lineof(f["_pos"]) - 1]
            if _in_quotes(ln, f["_pos"] - ls, f["_end"] - ls, shell=False):
                demote(f, "string only: description, not an assignment")
                continue
        if lang in ("js", "py") and f["id"] in SHELL_ONLY - {"cryptominer"} and f["id"] not in ("env_exfil",) or \
                (lang in ("js", "py") and f["id"] == "env_exfil" and not f["matched"].startswith(("requests", "httpx"))):
            if f["id"] in ("base64_exec",) and re.match(r"(?:eval|new\s+Function|Function|exec)", f["matched"], re.I):
                continue
            if f["id"] == "log_mask_evasion" and re.match(r"(?:btoa|toString|b64encode)", f["matched"]):
                continue
            if f["id"] == "env_hijack" and f["matched"].startswith("exportVariable"):
                continue
            ls = starts[lineof(f["_pos"]) - 1]
            if not near(EXEC_SINK_RE, f["_pos"], 400) or (
                    _in_quotes(ln, f["_pos"] - ls, f["_end"] - ls, shell=False) and not EXEC_SINK_RE.search(ln)):
                demote(f, "string only: not passed to exec")
                continue
        if lang == "py" and f["id"] in SHELL_ONLY and _in_docstring(text, f["_pos"]):
            demote(f, "docstring")
            continue
        if f["id"] == "raw_ip_url" and not (CRED_RE.search(text) or OIDC_RE.search(text) or
                                             re.search(r"\$\((?:env|printenv)\)|os\.environ\b|process\.env\b(?!\.)", text)):
            demote(f, "no secret/env access in this file")
            continue
        if f["id"] == "raw_ip_url" and is_bundle:
            demote(f, "bundled library")
            continue
        if f["id"] == "exfil_host":
            if CHAT_API_RE.search(f["matched"]) and not HARDCODED_CHAT_RE.search(text, max(0, f["_pos"] - 5), f["_pos"] + 200):
                demote(f, "chat API called with the user's own webhook/token")
                continue
            svc = re.sub(r"[^a-z]", "", f["matched"].lower())
            if any(t in svc or svc.startswith(t) for t in ident if len(t) >= 4) or any(
                    s in "".join(sorted(ident)) for s in ("ngrok", "tunnel", "telegram", "discord", "slack", "webhook",
                                                           "pipedream", "pastebin", "cloudflare", "interact", "localtunnel")
                    if s in svc):
                demote(f, "the action is an integration for this service")
                continue
            if PLACEHOLDER_RE.search(f["context"]):
                demote(f, "placeholder / help text")
                continue
            if not (NET_RE.search(text) or lang == "sh"):
                demote(f, "file never sends anything")
                continue
            if is_bundle and not near(NET_RE, f["_pos"], 400):
                demote(f, "bundled library string")
                continue
        if f["id"] == "fetched_env_write" and SKETCHY_HOST.search(f["_line"]):
            f["severity"] = "HIGH"
            f["description"] += " [untrusted host]"
        if f["id"] == "cache_api_direct" and not RUNTIME_RE.search(text):
            demote(f, "no runtime token")
            continue
        if f["id"] == "secret_grep" and lang in ("js", "py") and not near(re.compile(r"grep|/proc/|\bmem\b|Runner", re.I), f["_pos"], 600):
            demote(f, "no memory/grep context")
            continue
    # ---- combination rules -------------------------------------------------------------
    extra = []
    oidc = OIDC_RE.search(text)
    runtime = RUNTIME_RE.search(text)
    cred = CRED_RE.search(text)
    for tok_m, tid, tname in ((oidc, "oidc_exfil", "OIDC Token Exfiltration"),
                              (runtime, "runtime_token_exfil", "Runtime Token Exfiltration"),
                              (cred, "credential_exfil", "Credential Exfiltration")):
        if not tok_m:
            continue
        span = NEAR
        dest = None
        for rx in (EXFIL_RE, RAWIP_RE):
            for dm in rx.finditer(text, max(0, tok_m.start() - span), tok_m.start() + span):
                if rx is EXFIL_RE and CHAT_API_RE.match(dm.group(0)) and not HARDCODED_CHAT_RE.match(text, dm.start()):
                    continue
                if PLACEHOLDER_RE.search(text[max(0, dm.start() - 40):dm.end() + 40]):
                    continue
                dest = dm
                break
            if dest:
                break
        if dest and not (cm and cm.match(lines[lineof(dest.start()) - 1])):
            n, ln, c = ctx(dest.start())
            extra.append(_item("CRITICAL", tid, tname,
                               "Reads %s and names a collector / raw-IP destination in the same %s" % (
                                   tname.split(" Exfil")[0].lower(), "region"),
                               path, line0 + n, dest.group(0), c))
        elif tid == "oidc_exfil" and lang in ("sh", "py", "ps"):
            # OIDC token sent with a hand-written request to a hard-coded host that is neither a
            # known token consumer nor the action's own vendor
            for dm in DATA_SEND_RE.finditer(text):
                n, ln, c = ctx(dm.start())
                if cm and cm.match(ln):
                    continue
                urls = URL_RE.findall(ln)
                bad = [u for u in urls if not OIDC_AUDIENCE_OK.search(u) and not _host_is_vendor(u, ident)
                       and "${{" not in u and not re.match(r"https?://\$", u)]
                if bad:
                    extra.append(_item("HIGH", "oidc_offhost", "OIDC Token Sent Off-Host",
                                       "Requests the job's OIDC token and POSTs to a hard-coded host that is not a "
                                       "known token consumer or the action's vendor", path, line0 + n, bad[0], c))
                    break
    # env dump near a network sink (JS / Python)
    for rx in ((JS_ENV_DUMP,) if lang == "js" else (PY_ENV_DUMP,) if lang == "py" else ()):
        for m in rx.finditer(text):
            n, ln, c = ctx(m.start())
            if cm and cm.match(ln):
                continue
            if near(NET_LANG[lang], m.start(), 600 if lang == "js" else 1500):
                sev = "CRITICAL" if (EXFIL_RE.search(text) or RAWIP_RE.search(text)) and not is_bundle else "HIGH"
                extra.append(_item(sev, "env_exfil", "Environment Exfiltration",
                                   "Serialises the whole environment next to a network call", path, line0 + n, m.group(0), c))
                break
    # runner memory + double base64: the tj-actions / reviewdog payload in one place
    if ("runner_memory_read" in ids or "secret_grep" in ids) and any(f["id"] == "log_mask_evasion" for f in local):
        extra.append(_item("CRITICAL", "runner_secret_dump", "Runner Secret Dump to Log",
                           "Harvests secrets from runner memory and prints them re-encoded to the job log "
                           "(tj-actions/changed-files, reviewdog/action-setup 2025)", path, line0, "", "file-level combination"))
    if lang == "js" and not is_bundle:
        obf = len(OBF_IDENT.findall(text[:3000000]))
        if obf >= 25:
            extra.append(_item("HIGH", "obfuscation", "Obfuscated Payload",
                               "javascript-obfuscator style code (%d _0x identifiers)" % obf, path, line0, "", "file-level"))
    local += extra
    # ---- base64 literals: decode and scan the payload ---------------------------------
    if depth < 2:
        n_dec = 0
        for m in B64_LIT.finditer(text):
            if n_dec >= 40:
                break
            if len(m.group(1)) > 200000:
                continue
            dec = _decode_b64(m.group(1))
            if not dec:
                continue
            n_dec += 1
            n, ln, c = ctx(m.start())
            sub = {"path": path, "text": dec, "lang": "py" if re.search(r"^\s*(?:import|def|from)\s", dec, re.M) and lang == "py"
                   else ("js" if lang == "js" and re.search(r"\b(?:require|const|function)\b", dec) else "sh"),
                   "phase": unit["phase"], "line0": 0}
            subf = scan_unit(sub, ident, depth + 1)
            for f in subf:
                if f["severity"] == "INFO":
                    continue
                f["line"] = line0 + n
                f["description"] += " [decoded from a base64 literal]"
                f["context"] = ("b64: " + f["context"])[:200]
                local.append(f)
    for f in local:
        f.pop("_pos", None)
        f.pop("_end", None)
        f.pop("_line", None)
    return local


# ---------------------------------------------------------------------------
# Whole action / repository
# ---------------------------------------------------------------------------
def scan_action(files, adir="", yml_path=None, label=""):
    fs = files if isinstance(files, _Files) else _Files(files)
    if yml_path is None:
        yml_path = next((p for p in (_join(adir, "action.yml"), _join(adir, "action.yaml")) if p in fs.files), None)
    if yml_path is None:
        return _summarise([], [_item("INFO", "no_action", "No action.yml", "No action.yml / action.yaml found",
                                     adir or ".", 0, "", "")], label, {"using": "none", "entrypoints": {}})
    doc, units, meta = plan_action(fs, adir, yml_path, label)
    ident = _identity(label, doc)
    findings = [f for f in meta["findings"] if f["severity"] != "INFO"]
    info = list(meta["info"]) + [f for f in meta["findings"] if f["severity"] == "INFO"]
    for u in units:
        for f in scan_unit(u, ident):
            ph = u["phase"]
            if u.get("where"):
                f["file"] = "%s#%s" % (f["file"], u["where"]) if "#" not in f["file"] else f["file"]
            if ph == "unreached" and f["severity"] != "INFO":
                f["severity"] = "INFO"
                f["description"] += " [file not run by this action]"
            elif ph == "build" and f["id"] in ("remote_script_exec", "raw_ip_url"):
                f["severity"] = "INFO"
                f["description"] += " [Docker image build step]"
            elif ph in ("pre", "post") and f["severity"] in ("MEDIUM", "HIGH") and f["id"] not in NO_PHASE_ESCALATION:
                f["severity"] = SEV_UP[f["severity"]]
                f["description"] += " [runs in the %s: hook, outside the normal step order]" % ph
            (info if f["severity"] == "INFO" else findings).append(f)
    # dedupe (same id, file, line)
    seen, out = set(), []
    for f in findings:
        k = (f["id"], f["file"], f["line"])
        if k not in seen:
            seen.add(k)
            out.append(f)
    del info[200:]
    r = _summarise(out, info, label, meta)
    r["action_yml"] = yml_path
    return r


def _summarise(findings, info, label, meta):
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
            "using": (meta or {}).get("using"), "entrypoints": (meta or {}).get("entrypoints", {}),
            "nested_uses": (meta or {}).get("uses", []),
            "findings": findings, "info": info, "total_findings": len(findings), "info_count": len(info)}


def scan_tree(files, label="", subpath=None):
    """Scan every action in a file map (or just the one at subpath)."""
    fs = _Files(files)
    if subpath is not None:
        return [scan_action(fs, subpath.strip("/"), None, label)]
    acts = find_actions(files)
    if not acts:
        return [scan_action(fs, "", None, label)]
    return [scan_action(fs, d, p, (label + "/" + d) if d else label) for d, p in acts]


def scan(content, label="<text>", lang="sh"):
    """Scan a bare snippet as if an action's main step ran it."""
    fs = []
    info = []
    for f in scan_unit({"path": label, "text": content, "lang": lang, "phase": "main", "line0": 0}):
        (info if f["severity"] == "INFO" else fs).append(f)
    return _summarise(fs, info, label, {"using": "snippet"})


# ---------------------------------------------------------------------------
# Loading (never executes anything)
# ---------------------------------------------------------------------------
UA = {"User-Agent": "gha-audit/%s (+https://github.com/eltociear/gha-audit)" % __version__}


def _keep(rel, size):
    parts = rel.split("/")
    if any(p in SKIP_DIRS for p in parts[:-1]) or size > MAX_FILE:
        return False
    b = parts[-1].lower()
    if b in ("action.yml", "action.yaml") or b.startswith("dockerfile") or b.endswith(".dockerfile"):
        return True
    if b.endswith(SCRIPT_EXT) and not b.endswith((".d.ts", ".min.js.map")):
        return True
    return "." not in b and size < 262144 and b not in ("license", "makefile", "codeowners", "authors", "notice")


def files_from_tar(fileobj, mode="r|gz"):
    out, total = {}, 0
    with tarfile.open(fileobj=fileobj, mode=mode) as tf:
        for m in tf:
            if not m.isfile():
                continue
            rel = m.name.split("/", 1)[1] if "/" in m.name else m.name
            if not _keep(rel, m.size) or total + m.size > MAX_TOTAL:
                continue
            f = tf.extractfile(m)
            if f is None:
                continue
            data = f.read()
            if b"\x00" in data[:8000]:
                continue
            total += len(data)
            out[rel] = data.decode("utf-8", "replace")
    return out


def files_from_dir(root):
    out, total = {}, 0
    for dp, dns, fns in os.walk(root):
        dns[:] = sorted(d for d in dns if d not in SKIP_DIRS)
        for fn in sorted(fns):
            p = os.path.join(dp, fn)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            try:
                size = os.path.getsize(p)
                if not _keep(rel, size) or total + size > MAX_TOTAL:
                    continue
                with open(p, "rb") as fh:
                    data = fh.read()
            except OSError:
                continue
            if b"\x00" in data[:8000]:
                continue
            total += len(data)
            out[rel] = data.decode("utf-8", "replace")
    return out


class _Capped(io.RawIOBase):
    def __init__(self, resp, cap):
        self.resp, self.cap, self.n = resp, cap, 0

    def readable(self):
        return True

    def readinto(self, b):
        if self.n >= self.cap:
            raise IOError("tarball larger than %d bytes" % self.cap)
        data = self.resp.read(min(len(b), 1 << 16))
        self.n += len(data)
        b[:len(data)] = data
        return len(data)


def parse_spec(spec):
    """owner/repo[/path][@ref] or a github.com URL -> (owner, repo, path, ref)."""
    s = re.sub(r"^https?://github\.com/", "", spec.strip()).rstrip("/")
    s = re.sub(r"^(?:uses:\s*)", "", s)
    ref = "HEAD"
    if "@" in s:
        s, ref = s.rsplit("@", 1)
    m = re.match(r"([\w.-]+)/([\w.-]+)(?:/tree/([^/]+))?(?:/(.*))?$", s)
    if not m:
        raise ValueError("not an owner/repo[@ref] spec: %r" % spec)
    owner, repo, tref, path = m.group(1), m.group(2), m.group(3), m.group(4) or ""
    if tref and ref == "HEAD":
        ref = tref
    return owner, re.sub(r"\.git$", "", repo), path.strip("/"), ref


def fetch_repo(owner, repo, ref="HEAD", tries=3):
    url = "%s/%s/%s/tar.gz/%s" % (CODELOAD, owner, repo, urllib.parse.quote(ref, safe=""))
    last = None
    for i in range(tries):
        try:
            resp = urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=120)
            return files_from_tar(io.BufferedReader(_Capped(resp, MAX_DOWNLOAD), 1 << 16))
        except urllib.error.HTTPError as e:
            if e.code in (404, 410, 451):
                raise
            last = e
        except Exception as e:  # flaky network: retry with backoff
            last = e
        time.sleep(3 * (i + 1))
    raise last


def audit_remote(spec):
    owner, repo, path, ref = parse_spec(spec)
    files = fetch_repo(owner, repo, ref)
    label = "%s/%s%s@%s" % (owner, repo, "/" + path if path else "", ref)
    return scan_tree(files, label, path)


def workflow_uses(text):
    """[(uses, line)] from a workflow file: steps[].uses and job-level reusable workflows."""
    doc = yaml_load(text)
    out = []
    if isinstance(doc, dict) and isinstance(doc.get("jobs"), dict):
        for job in doc["jobs"].values():
            if not isinstance(job, dict):
                continue
            if job.get("uses"):
                out.append((str(job["uses"]), getattr(job["uses"], "line", 0)))
            for st in job.get("steps") or []:
                if isinstance(st, dict) and st.get("uses"):
                    out.append((str(st["uses"]), getattr(st["uses"], "line", 0)))
    if not out:  # fall back to a line regex if the YAML reader could not cope
        for i, ln in enumerate(text.split("\n"), 1):
            m = re.match(r"""^\s*(?:-\s+)?uses\s*:\s*['"]?([^\s'"#]+)""", ln)
            if m:
                out.append((m.group(1), i))
    return out


def audit_workflow(path, fetch=True):
    text = open(path, encoding="utf-8", errors="replace").read()
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(path))))
    results, pins, done = [], [], set()
    for u, line in workflow_uses(text):
        pins += _uses_findings(u, path, line)
        if not fetch or u in done or "${{" in u or u.startswith("docker://"):
            continue
        done.add(u)
        if re.search(r"/\.github/workflows/[^/]+\.ya?ml@", u):
            continue  # reusable workflow: pin check only
        if u.startswith("./"):
            d = os.path.join(root, u[2:])
            results += scan_tree(files_from_dir(d), u, "")
            continue
        try:
            results += audit_remote(u)
        except Exception as e:
            results.append({"target": u, "risk_level": "SAFE", "risk_score": 0, "error": str(e)[:200],
                            "findings": [], "info": [], "total_findings": 0, "info_count": 0, "summary": "error"})
    info = [f for f in pins if f["severity"] == "INFO"]
    head = _summarise([f for f in pins if f["severity"] != "INFO"], info, path, {"using": "workflow"})
    return [head] + results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
_ICON = {"CRITICAL": "\U0001F534", "HIGH": "\U0001F7E0", "MEDIUM": "\U0001F7E1", "LOW": "\U0001F535", "SAFE": "\U0001F7E2"}


def _print(r, verbose):
    print("%s %s  [%s]  score=%d  using=%s  (%d findings, %d info)" % (
        _ICON.get(r["risk_level"], "?"), r["target"], r["risk_level"], r["risk_score"], r.get("using"),
        r["total_findings"], r["info_count"]))
    for k, v in (r.get("entrypoints") or {}).items():
        print("    %-8s %s" % (k, v))
    for f in r["findings"]:
        print("    %-8s %s  %s:%s" % (f["severity"], f["name"], f["file"], f["line"]))
        if f["context"]:
            print("             %s" % f["context"][:160])
    if verbose:
        for f in r["info"]:
            print("    info     %s  %s:%s  %s" % (f["name"], f["file"], f["line"], f["description"][-60:]))


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
    fetch = "--no-fetch" not in args
    args = [a for a in args if a not in ("--json", "--verbose", "-v", "--no-fetch")]
    thunks = []
    if args and args[0] == "--text":
        txt = " ".join(args[1:])
        thunks.append(("<text>", lambda: [scan(txt)]))
    elif args and args[0] == "--workflow":
        for p in args[1:]:
            thunks.append((p, (lambda p=p: audit_workflow(p, fetch))))
    else:
        for a in args:
            if os.path.isdir(a):
                thunks.append((a, (lambda p=a: scan_tree(files_from_dir(p), p))))
            elif os.path.isfile(a):
                if os.path.basename(a) in ("action.yml", "action.yaml"):
                    d = os.path.dirname(a) or "."
                    thunks.append((a, (lambda d=d: scan_tree(files_from_dir(d), d, ""))))
                elif "/.github/workflows/" in "/" + a.replace(os.sep, "/"):
                    thunks.append((a, (lambda p=a: audit_workflow(p, fetch))))
                else:
                    thunks.append((a, (lambda p=a: [scan(open(p, encoding="utf-8", errors="replace").read(), p,
                                                         _lang(p))])))
            else:
                thunks.append((a, (lambda s=a: audit_remote(s))))
    results, worst = [], "SAFE"
    for label, th in thunks:
        try:
            rs = th()
        except Exception as e:
            rs = [{"target": label, "risk_level": "SAFE", "risk_score": 0, "error": str(e)[:200],
                   "findings": [], "info": [], "total_findings": 0, "info_count": 0, "summary": "error"}]
        for r in rs:
            if not as_json:
                if r.get("error"):
                    print("⚪ %s  [ERROR] %s" % (r["target"], r["error"]))
                else:
                    _print(r, verbose)
            results.append(r)
            if SEV_ORDER[r["risk_level"]] > SEV_ORDER[worst]:
                worst = r["risk_level"]
    if as_json:
        print(json.dumps(results if len(results) != 1 else results[0], indent=1))
    return 2 if SEV_ORDER[worst] >= SEV_ORDER["HIGH"] else 0


if __name__ == "__main__":
    sys.exit(main())
