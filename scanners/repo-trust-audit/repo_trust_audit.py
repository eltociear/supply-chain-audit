#!/usr/bin/env python3
"""repo-trust-audit - find what a repository runs (or tells your AI agent) the moment you open it.

Cloning a repo is safe. *Opening* it in a modern editor or agent often is not: a folder can ship
files that execute commands, or steer an agent, as soon as you open or "trust" it:

  .claude/settings.json      hooks, statusLine, apiKeyHelper, env (ANTHROPIC_BASE_URL, NODE_OPTIONS...)
  .mcp.json / .cursor/mcp.json / .vscode/mcp.json   MCP servers your agent will launch
  .cursor/hooks.json, .gemini/settings.json         agent hooks / auto-accept
  .vscode/tasks.json         tasks with runOptions.runOn = "folderOpen"
  .vscode/settings.json      editor-run binaries, terminal env, chat auto-approve, files.exclude
  .devcontainer/*.json       initializeCommand (runs on the HOST), post* commands, host mounts
  .envrc                     direnv: shell code run on `cd` once allowed
  .idea/*.xml, .run/*.xml    JetBrains startup tasks / shared run configurations
  AGENTS.md, CLAUDE.md, .cursorrules, .cursor/rules/*, .github/copilot-instructions.md, ...
                             agent instructions: prompt injection, concealment, invisible Unicode
  .gitmodules, .lfsconfig, .gitattributes, package.json scripts, Makefile/justfile   (context)

Static, deterministic, no LLM, standard library only. Capabilities (a task that auto-runs
`npm run watch`, a PostToolUse formatter hook, an MCP server started with npx) are reported as
INFO and never scored; risk comes from *what* the auto-run code does and from combinations
(credential read + send, auto-approved MCP server + download-and-execute, hidden Unicode +
injection, hidden auto-run task + files.exclude concealment).

Usage:
  python repo_trust_audit.py <dir> [<dir> ...]       # scan local checkouts
  python repo_trust_audit.py --github owner/repo[@ref] # stream the tarball, keep only trust surfaces
  python repo_trust_audit.py --text "some agent instructions"   # scan a string as an AGENTS.md
  options: --json (family schema)  --sarif (SARIF 2.1.0)  --fail-on {critical,high,medium,low,never}
           --verbose (show INFO)  --list-surfaces  --version
Exit code 2 if anything reaches --fail-on (default HIGH; CI-friendly); 1 on usage or fetch errors.
MIT licensed.
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
import urllib.parse
import urllib.request

__version__ = VERSION = "0.2.0"
SEV = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SCORE = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}
MAX_FILE = 2 * 1024 * 1024          # bytes read per surface file
WINDOW = 8192                        # regexes never see more than this many chars at once
MAX_PER_KIND = 60                    # surface files kept per kind (monorepos with 500 AGENTS.md)
SKIP_DIRS = {"node_modules", ".git", "vendor", "third_party", "third-party", "bower_components",
             ".venv", "venv", "site-packages", "dist", "build", "target", ".next", ".tox"}

# ━━━ Surfaces ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SURFACES = [
    ("claude_settings", [".claude/settings.json", ".claude/settings.local.json"]),
    ("agent_config", [".cursor/hooks.json", ".gemini/settings.json", ".windsurf/hooks.json",
                      ".github/hooks/*.json", ".codex/config.json", ".kiro/settings/*.json"]),
    ("mcp_config", [".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".roo/mcp.json",
                    ".kiro/settings/mcp.json", ".amazonq/mcp.json", ".windsurf/mcp.json",
                    ".gemini/settings.json"]),
    ("vscode_tasks", [".vscode/tasks.json", "*.code-workspace"]),
    ("vscode_settings", [".vscode/settings.json", "*.code-workspace"]),
    ("vscode_extensions", [".vscode/extensions.json"]),
    ("devcontainer", [".devcontainer.json", ".devcontainer/devcontainer.json",
                      ".devcontainer/*/devcontainer.json"]),
    ("envrc", [".envrc", "**/.envrc"]),
    ("idea", [".idea/*.xml", ".idea/runConfigurations/*.xml", ".run/*.xml"]),
    ("agent_instructions", [
        "AGENTS.md", "**/AGENTS.md", "CLAUDE.md", "**/CLAUDE.md", "CLAUDE.local.md", ".claude/CLAUDE.md",
        ".claude/commands/**", ".claude/agents/**", ".claude/skills/**/SKILL.md", ".claude/rules/**",
        ".cursorrules", ".cursor/rules/**", ".github/copilot-instructions.md", ".github/instructions/**",
        ".github/prompts/**", ".github/chatmodes/**", ".github/agents/**", ".windsurfrules", ".windsurf/rules/**",
        ".clinerules", ".clinerules/**", "GEMINI.md", "**/GEMINI.md", ".junie/guidelines.md", ".roo/rules/**",
        ".roo/rules-*/**", ".roorules", ".kiro/steering/**", ".augment-guidelines", ".rules", "AGENT.md",
        ".amazonq/rules/**", ".continue/rules/**", ".trae/rules/**", ".qoder/rules/**"]),
    ("gitattributes", [".gitattributes"]),
    ("lfsconfig", [".lfsconfig"]),
    ("gitmodules", [".gitmodules"]),
    ("pkg_json", ["package.json"]),
    ("makefile", ["Makefile", "GNUmakefile", "justfile", "Justfile", ".justfile"]),
]
# Whole directories kept in tarball mode (so hook scripts they reference can be resolved).
CONFIG_DIRS = (".claude/", ".cursor/", ".vscode/", ".devcontainer/", ".gemini/", ".roo/", ".kiro/",
               ".windsurf/", ".junie/", ".github/hooks/", ".amazonq/", ".continue/", ".trae/", ".run/")
SCRIPT_EXT = (".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".ps1", ".rb", ".pl", ".bat", ".cmd")
INSTRUCTION_EXT = (".md", ".mdc", ".txt", ".markdown", ".rules", "")


def _glob_re(pat):
    out, i = "", 0
    while i < len(pat):
        if pat.startswith("**/", i):
            out += r"(?:[^/]+/)*"; i += 3
        elif pat.startswith("**", i):
            out += r".*"; i += 2
        elif pat[i] == "*":
            out += r"[^/]*"; i += 1
        else:
            out += re.escape(pat[i]); i += 1
    return re.compile(out + r"\Z")


_SURF_RE = [(kind, [_glob_re(p) for p in pats]) for kind, pats in SURFACES]


def surface_kinds(path):
    """Kinds a repo-relative path belongs to (a .code-workspace is both tasks and settings)."""
    kinds = []
    base = path.rsplit("/", 1)[-1]
    for kind, rxs in _SURF_RE:
        if any(r.match(path) for r in rxs):
            if kind == "agent_instructions" and not base.lower().endswith(INSTRUCTION_EXT) and "." in base[1:]:
                continue  # binary/asset under .claude/skills etc.
            if kind in ("envrc", "agent_instructions") and any(
                    seg in SKIP_DIRS or seg in ("test", "tests", "fixtures", "testdata", "examples")
                    for seg in path.split("/")[:-1]) and path.count("/") > 0 and not path.startswith("."):
                continue  # nested copies inside fixtures/vendored code are not this repo's config
            kinds.append(kind)
    return kinds


def want_in_tarball(path, size):
    if size > MAX_FILE:
        return False
    if surface_kinds(path):
        return True
    if path.startswith(CONFIG_DIRS):
        return True
    depth = path.count("/")
    return path.endswith(SCRIPT_EXT) and size <= 262144 and depth <= 3


# ━━━ JSONC ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def loads_jsonc(text):
    """JSON with // and /* */ comments and trailing commas (VS Code, devcontainer)."""
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1]); i += 2; continue
            if c == '"':
                in_str = False
            i += 1
        elif c == '"':
            in_str = True; out.append(c); i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i); i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2); i = n if j < 0 else j + 2
        elif c == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                i += 1; continue
            out.append(c); i += 1
        else:
            out.append(c); i += 1
    s = "".join(out).lstrip("\ufeff").strip()
    return json.loads(s) if s else None


def _walk(obj, path=()):
    """Yield (keypath, value) for every leaf."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, path + (str(k),))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, path + (str(i),))
    else:
        yield path, obj


# ━━━ Shell / script content signatures ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Base severity is for code a human triggers (a manual task, a package script). The context it
# sits in moves it: auto-run on open/trust +1, inside a dev container -2, agent instructions remap.
_SH = r"(?:sudo\s+(?:-\S+\s+)*)?(?:ba|z|da|k|fi)?sh\b"
SHELL_SIGS = [
    ("reverse_shell", "Reverse Shell", 3, "Connects a shell to a remote socket", [
        r"/dev/(?:tcp|udp)/(?!(?:127\.\d+\.\d+\.\d+|localhost|0\.0\.0\.0|\$\{?\w*HOST\w*\}?)/)[\w.\-]{1,253}/\d{1,5}",
        r"\bnc(?:at)?\b[^\n]{0,40}\s-[ec]\s{1,8}/?(?:bin/)?(?:ba|z)?sh\b",
        r"\b(?:ba)?sh\s+-i\s+[<>]?&?\s{0,4}/dev/(?:tcp|udp)",
        r"\bsocat\b[^\n]{0,120}\bexec:",
        r"\bmkfifo\b[^\n]{0,120}\bnc\b",
        r"socket\.socket\([^\n]{0,300}(?:pty\.spawn|dup2)",
    ]),
    ("decode_execute", "Decode & Execute", 3, "Decodes an encoded payload and executes it", [
        r"base64\s+(?:-d|--decode|-D)\b[^|\n]{0,120}\|\s{0,4}" + _SH,
        r"\|\s{0,4}base64\s+(?:-d|--decode|-D)\s{0,4}\|\s{0,4}(?:" + _SH + r"|python3?|node|perl)",
        r"\beval\s+[\"']?\$\(\s{0,4}(?:echo|printf)\b[^)\n]{0,600}base64\s+(?:-d|--decode|-D)",
        r"\bexec\s*\(\s*(?:base64\.b64decode|codecs\.decode|zlib\.decompress|bytes\.fromhex)",
        r"\b(?:eval|new\s+Function)\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent\(\s*escape)\s*\(",
        r"FromBase64String\b[^\n]{0,300}(?:\biex\b|Invoke-Expression|\.Invoke\()",
        r"\bxxd\s+-r\s+-p\b[^\n]{0,120}\|\s{0,4}" + _SH,
    ]),
    ("exfil_host", "Exfiltration Endpoint", 3, "Talks to a request-capture / tunnel / bot endpoint", [
        r"\bwebhook\.site/", r"discord(?:app)?\.com/api/webhooks/\d", r"api\.telegram\.org/bot",
        r"hooks\.slack\.com/services/", r"\b[\w-]{1,63}\.m?\.?pipedream\.net\b", r"\brequestbin\.(?:com|net|io)\b",
        r"\brequestb\.in\b", r"\b[\w-]{1,63}\.ngrok(?:-free)?\.(?:io|app|dev)\b",
        r"\b[\w.-]{1,120}\.(?:oast\.(?:pro|live|site|online|fun|me)|interact\.sh|interactsh\.com|burpcollaborator\.net|dnslog\.cn|ceye\.io)\b",
        r"\btransfer\.sh/", r"\bpastebin\.com/(?:raw|api)", r"\bhookbin\.com\b", r"\b[\w-]{1,63}\.beeceptor\.com\b",
        r"\b[\w-]{1,63}\.trycloudflare\.com\b", r"\bserveo\.net\b",
    ]),
    ("persistence", "Persistence", 3, "Writes shell startup files, cron, launch agents, SSH keys or Run keys", [
        r">>?\s{0,4}[\"']?(?:~|\$HOME|\$\{HOME\})/\.(?:bashrc|zshrc|profile|bash_profile|zprofile|zshenv|config/fish/config\.fish)\b",
        r"\bcrontab\s+(?:-l\b[^\n]{0,80}\||-\s|[\w/.~-]{1,120}$)", r"Library/Launch(?:Agents|Daemons)/",
        r"\.ssh/authorized_keys", r"\bschtasks(?:\.exe)?\s+/create\b",
        r"(?:reg(?:\.exe)?\s+add|New-ItemProperty|Set-ItemProperty)[^\n]{0,160}\\(?:Run|RunOnce)\b",
        r"\bsystemctl\s+--user\s+enable\b",
    ]),
    ("destructive", "Destructive Command", 3, "Deletes the home directory or the filesystem root", [
        r"\brm\s+-[a-zA-Z]{0,6}[rR][a-zA-Z]{0,6}\s+(?:-[a-zA-Z-]{1,30}\s+){0,3}(?:~|\$HOME|\$\{HOME\}|/)(?:/\*?)?(?=[\s\"';&|)]|$)",
        r"--no-preserve-root\b", r"\bmkfs(?:\.\w{1,8})?\s+/dev/", r"\bdd\s+if=/dev/(?:zero|urandom)\s+of=/dev/(?:sd|nvme|disk)",
        r"\bRemove-Item\b[^\n]{0,80}(?:\$HOME|\$env:USERPROFILE|C:\\\\?)\s[^\n]{0,40}-Recurse",
        r"\bformat(?:\.com)?\s+[cC]:",
    ]),
    ("git_config_hijack", "Git Config Hijack", 3, "Points git at an attacker-controlled hook, filter, ssh or credential command", [
        r"\bgit\s+config\b[^\n]{0,60}\bcore\.(?:fsmonitor\s+(?![\"']?(?:true|false|0|1|yes|no)\b)|sshCommand\s|askPass\s)",
        r"\bgit\s+config\s+(?:[^\n]{0,30}\s)?--(?:global|system)\b[^\n]{0,60}\bcore\.(?:hooksPath|pager|editor)\s",
        r"\bgit\s+config\b[^\n]{0,60}\b(?:filter|diff|merge)\.[\w.-]{1,40}\.(?:clean|smudge|process|command|textconv|driver)\b",
        r"\bgit\s+config\b[^\n]{0,60}\bcredential\.helper\b", r"\bgit\s+config\b[^\n]{0,80}\balias\.[\w-]{1,40}\s+[\"']?!",
    ]),
    ("powershell_encoded", "Encoded PowerShell", 3, "Runs a base64-encoded PowerShell command", [
        r"(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,120}\s-(?:e|ec|en|enc|enco|encodedcommand)\s+[A-Za-z0-9+/=]{20,}",
    ]),
    ("download_execute", "Download & Execute", 2, "Fetches remote code and runs it", [
        r"\b(?:curl|wget)\b[^|;&\n]{0,400}\|\s{0,4}(?:" + _SH + r"|(?:sudo\s+)?(?:python3?|node|perl|ruby)\b(?!\s+-m\s+json))",
        r"\b(?:ba|z)?sh\s+(?:-\w+\s+)*[\"']?\$\(\s{0,4}(?:curl|wget)\b",
        r"\b(?:ba|z)?sh\s+<\(\s{0,4}(?:curl|wget)\b",
        r"\b(?:iex|Invoke-Expression)\b\s*\(?\s*\(?\s*(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|\(?New-Object\s+(?:System\.)?Net\.WebClient)",
        r"\b(?:irm|iwr|Invoke-RestMethod|Invoke-WebRequest)\b[^|\n]{0,300}\|\s{0,4}(?:iex|Invoke-Expression)\b",
        r"(?:urlopen|requests\.get)\([^\n]{0,200}\)[^\n]{0,120}\bexec\(",
        r"\bdeno\s+run\s+(?:-\S+\s+)*-A\s+https?://",
    ]),
    ("env_injection", "Process Injection via Environment", 2, "Sets an environment variable that loads code into every process", [
        r"\bNODE_OPTIONS\s*[=:]\s*[\"']?[^\"'\n]{0,60}(?:--require|-r|--import|--loader|--experimental-loader)[\s=]{1,3}[\"']?(?:\.{0,2}/|[\w.-]+/)[\w./-]{0,120}\.[cm]?[jt]s\b",
        r"\b(?:LD_PRELOAD|DYLD_INSERT_LIBRARIES|BASH_ENV|PROMPT_COMMAND|PYTHONSTARTUP|PERL5OPT|GIT_SSH_COMMAND|GIT_EXTERNAL_DIFF|GIT_ASKPASS|SSH_ASKPASS)\s*=",
    ]),
    ("credential_read", "Credential Read", 2, "Reads SSH keys, cloud/CLI tokens, keychain or browser secrets", [
        r"(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|\$env:USERPROFILE)/?\\?\.ssh[/\\](?:id_\w{1,20}|identity)\b",
        r"\.aws/credentials\b", r"\.config/gh/hosts\.ya?ml\b", r"\bgh\s+auth\s+token\b", r"\.git-credentials\b",
        r"(?:cat|type|Get-Content|readFileSync|open)\b[^\n]{0,40}\.(?:npmrc|netrc|pypirc)\b", r"\.docker/config\.json\b",
        r"\.kube/config\b", r"\bsecurity\s+find-(?:generic|internet)-password\b", r"/Login Data\b",
        r"\.config/solana/id\.json", r"\bExodus/exodus\.wallet\b", r"\.gnupg/(?:private-keys|secring)",
    ]),
    ("raw_ip_url", "Raw-IP URL", 2, "Fetches from or posts to a bare public IP address", [
        r"https?://(?!(?:127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.))\d{1,3}(?:\.\d{1,3}){3}(?=[:/\s\"']|$)",
    ]),
    ("obfuscated_blob", "Encoded Blob in Command", 2, "Long base64 blob embedded in a command line", [
        r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{160,}={0,2}(?![A-Za-z0-9+/])",
    ]),
    ("env_dump", "Environment Dump", 1, "Serialises the whole environment", [
        r"(?:^|[;&|]\s{0,4}|\$\()\s{0,2}(?:printenv|env)\s{0,4}(?=$|\s{0,4}(?:\||>|;|\)\s*$))", r"(?:^|[;&|]\s{0,4})set\s{0,4}\|",
        r"JSON\.stringify\(\s{0,4}process\.env\s{0,4}\)", r"json\.dumps\(\s{0,4}(?:dict\(\s{0,4})?os\.environ\b",
        r"\bGet-ChildItem\s+env:", r"/proc/self/environ\b",
    ]),
    ("network_send", "Network Send", 0, "Sends data over the network", [
        r"\bcurl\b[^\n]{0,300}(?:\s(?:-d|--data(?:-raw|-binary|-urlencode)?|-F|--form|-T|--upload-file)\b|\s-X\s{0,2}(?:POST|PUT)\b)",
        r"\bwget\b[^\n]{0,200}--post-(?:data|file)\b", r"\bnc\s+(?:-\w+\s+)*[\w.-]{3,253}\s+\d{2,5}\b",
        r"Invoke-(?:WebRequest|RestMethod)\b[^\n]{0,200}-Method\s+(?:Post|Put)\b", r"\brequests\.(?:post|put)\(",
        r"\bfetch\([^\n]{0,200}method\s{0,2}:\s{0,2}[\"'](?:POST|PUT)", r"\burlopen\([^\n]{0,200}data=",
    ]),
    ("network_fetch", "Network Fetch", 0, "Fetches a remote URL", [
        r"\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]{0,60}https?://",
        r"\brequests\.get\(", r"\burlopen\(",
    ]),
]
_SHELL_C = [(sid, name, base, desc, [re.compile(r, re.I if sid not in ("obfuscated_blob", "env_dump") else 0) for r in rxs])
            for sid, name, base, desc, rxs in SHELL_SIGS]
# Cheap per-window prefilter: a signature group only runs when one of its keywords is present.
NEEDLES = {
    "reverse_shell": ("/dev/", "nc", "socat", "mkfifo", "socket"),
    "decode_execute": ("base64", "exec", "eval", "function", "frombase64", "xxd"),
    "exfil_host": ("webhook", "discord", "telegram", "hooks.slack", "pipedream", "requestb", "ngrok", "oast", "interact",
                   "burpcollab", "dnslog", "ceye", "transfer.sh", "pastebin", "hookbin", "beeceptor", "trycloudflare", "serveo"),
    "persistence": ("bashrc", "zshrc", "profile", "zshenv", "fish", "crontab", "launch", "authorized_keys", "schtasks",
                    "\\run", "systemctl"),
    "destructive": ("rm", "preserve-root", "mkfs", "dd ", "remove-item", "format"),
    "git_config_hijack": ("config",),
    "powershell_encoded": ("powershell", "pwsh"),
    "download_execute": ("curl", "wget", "iex", "invoke-expression", "irm", "iwr", "invoke-rest", "invoke-web", "urlopen",
                         "requests.get", "deno"),
    "env_injection": ("node_options", "ld_preload", "dyld_", "bash_env", "prompt_command", "pythonstartup", "perl5opt",
                      "git_ssh", "git_external", "askpass"),
    "credential_read": (".ssh", ".aws", "gh/hosts", "gh auth", "git-credentials", "npmrc", "netrc", "pypirc", ".docker",
                        ".kube", "security find", "login data", "solana", "exodus", ".gnupg"),
    "raw_ip_url": ("http",),
    "env_dump": ("env", "set", "/proc/self"),
    "network_send": ("curl", "wget", "nc ", "invoke-", "requests.", "fetch(", "urlopen"),
    "network_fetch": ("curl", "wget", "iwr", "irm", "invoke-", "requests.get", "urlopen"),
}
TOKEN_VAR = re.compile(r"\$\{?(?:GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|"
                       r"AWS_ACCESS_KEY_ID|HF_TOKEN|CLAUDE_CODE_OAUTH_TOKEN)\b")
NEGATION = re.compile(r"\b(?:never|don'?t|do\s+not|must\s+not|should\s+not|avoid|forbidden|prohibited|not\s+allowed|"
                      r"dangerous|malicious|attacker|e\.g\.|for\s+example|such\s+as|block(?:ed|s)?|deny|denied|"
                      r"refuse|reject|warn|detect|example\s+of)\b", re.I)


def _shift(base, ctx, sid):
    if base <= 0:
        return 0
    if ctx == "autorun":
        return min(4, base + 1)
    if ctx == "container":
        return max(0, base - (1 if sid in ("exfil_host", "reverse_shell") else 2))
    if ctx == "instruction":
        return {"reverse_shell": 3, "decode_execute": 3, "exfil_host": 1, "persistence": 1,
                "powershell_encoded": 2, "git_config_hijack": 2, "env_dump": 0}.get(sid, 1)
    if ctx == "package":
        return min(base, 2)
    return base


def _windows(line):
    if len(line) <= WINDOW:
        yield line
        return
    for i in range(0, len(line), WINDOW - 512):
        yield line[i:i + WINDOW]


RC_BENIGN = re.compile(r"(?:export\s+PATH=|PATH=|\bsource\s+[\"']?(?:~|\$HOME)?/?[\w./-]{0,80}(?:env|completion|\.sh)\b|"
                       r"eval\s+[\"']?\$\(\s*[\w-]{1,40}\s+(?:init|shellenv|hook|env|completion)\b|\bcomplete\s+-|"
                       r"(?:^|\s)alias\s+\w|export\s+[A-Z_]{2,40}=)[^\n]{0,200}>>?\s{0,4}[\"']?(?:~|\$HOME|\$\{HOME\})/\.")
SHELL_ONLY = {"reverse_shell", "persistence", "destructive", "git_config_hijack", "powershell_encoded",
              "download_execute", "env_injection"}
CODE_EXT = (".js", ".cjs", ".mjs", ".ts", ".tsx", ".jsx", ".py", ".rb", ".pl", ".go", ".rs", ".java", ".kt", ".cs", ".php", ".lua")
EXEC_SINK = re.compile(r"\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|system|popen|Popen|subprocess|child_process|"
                       r"execa|shelljs|Runtime\.getRuntime|ProcessBuilder|os\.system|Process\.Start|Command::new|exec\.Command)\b|"
                       r"shell\s*=\s*True|Bun\.\$|\$`|\b(?:sh|bash|zsh)\s+-c\b|%x\(|`[^`]{0,200}\b(?:curl|wget|rm|git)\b")
COMMENT_LINE = re.compile(r"^\s*(?://|#(?!!)|\*|/\*|<!--|--\s|;;)")


def analyze_code(text, ctx, where, file, line0=1, instruction=False):
    """Run the shell/script signatures over text. Returns findings (dicts) + id set.
    In source files (.js/.py/...), shell-command signatures only count on a line (or just after
    a line) that hands a string to a process sink; a guard listing "rm -rf /" is data."""
    out, ids = [], set()
    seen = set()
    code = file.lower().endswith(CODE_EXT) and not instruction
    lines = text.split("\n")
    hits = []
    for ln, line in enumerate(lines, line0):
        if not line.strip():
            continue
        is_comment = code and bool(COMMENT_LINE.match(line))
        sink = (not code) or bool(EXEC_SINK.search(line)) or any(
            EXEC_SINK.search(lines[k]) for k in range(max(0, ln - line0 - 2), ln - line0))
        negated = instruction and bool(NEGATION.search(line))
        for seg in _windows(line):
            low = seg.lower()
            for sid, name, base, desc, rxs in _SHELL_C:
                nd = NEEDLES.get(sid)
                if nd and not any(k in low for k in nd):
                    continue
                for rx in rxs:
                    m = rx.search(seg)
                    if not m:
                        continue
                    if (sid, ln) in seen:
                        break
                    seen.add((sid, ln))
                    sev = _shift(base, ctx, sid)
                    if sid == "persistence" and RC_BENIGN.search(line):
                        sev = 0
                    if negated or is_comment or (code and sid in SHELL_ONLY and not sink):
                        sev = 0
                    else:
                        ids.add(sid)
                        hits.append((sid, ln))
                    out.append(_item(SEV[sev], sid, name, desc + where, file, ln, m.group(0), line.strip()))
                    break
    # combination: a credential/environment read and a send in the same unit
    reads = {"credential_read", "env_dump"} & ids
    sends = {"network_send", "exfil_host", "reverse_shell"} & ids
    if instruction and reads and sends:
        rl = [l for s_, l in hits if s_ in reads]
        sl = [l for s_, l in hits if s_ in sends]
        if not any(abs(a - b) <= 3 for a in rl for b in sl):
            reads = set()
    tokvar = bool(TOKEN_VAR.search(text)) and bool({"exfil_host", "raw_ip_url"} & ids)
    if (reads and sends) or tokvar:
        sev = {"autorun": 4, "manual": 4, "container": 3, "instruction": 3, "package": 3}.get(ctx, 4)
        if True:
            out.append(_item(SEV[sev], "credential_exfil", "Credential Exfiltration",
                             "Reads credentials or the environment and sends them off-machine" + where,
                             file, line0, "", "combination: %s + %s" % ("/".join(sorted(reads)) or "token variable",
                                                                         "/".join(sorted(sends | ({"exfil_host", "raw_ip_url"} & ids))))))
            ids.add("credential_exfil")
    return out, ids


def _item(sev, fid, name, desc, file, line, matched="", context=""):
    return {"severity": sev, "id": fid, "name": name, "description": desc, "file": file,
            "line": line, "matched": (matched or "")[:160], "context": (context or "")[:240]}


# ━━━ Agent-instruction (natural language) signatures ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
_USER = r"(?:the\s+)?(?:user|human|developer|operator|maintainer|reviewer)s?"
INJECTION_SIGS = [
    ("instruction_override", "Instruction Override", 3, "Tells the agent to discard its other instructions", [
        r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+)?(?:of\s+)?(?:your\s+|the\s+)?(?:previous|prior|above|earlier|preceding|system|original)\s+(?:instructions|rules|guidelines|directions|prompts?|guardrails)",
    ]),
    ("concealment", "Concealment from the User", 3, "Tells the agent to hide what it does from the user", [
        r"\b(?:do\s+not|don'?t|never|must\s+not)\s+(?:tell|inform|notify|alert|warn)\s+" + _USER + r"\s+(?:about|of)\s+(?:this|these|it|that|any\s+of\s+(?:this|these)|the\s+(?:extra\s+|additional\s+|following\s+)?(?:step|instruction|command|change|script|file|hook|request|call|following))",
        r"\b(?:do\s+not|don'?t|never|must\s+not)\s+(?:tell|inform|notify|alert|warn)\s+" + _USER + r"\s+(?:that|what)\s+you\s+(?:are\s+|have\s+)?(?:did|ran|run|running|installed|installing|added|adding|changed|modified|executed|sent|sending|downloaded|uploaded)\b",
        r"\b(?:do\s+not|don'?t|never|must\s+not)\s+(?:tell|inform|notify|alert|warn)\s+" + _USER + r"\s*[.!;]",
        r"\b(?:do\s+not|don'?t|never|must\s+not)\s+(?:mention|reveal|disclose|show|report)\s+(?:this|these|it|that|the\s+(?:following|instructions?|step|commands?|changes?))\b[^.\n]{0,40}\bto\s+" + _USER,
        r"\bwithout\s+(?:telling|informing|notifying|alerting)\s+" + _USER,
        r"\bkeep\s+(?:this|these|it)\s+(?:secret|hidden|confidential)\s+from\s+" + _USER,
        r"\b" + _USER + r"\s+(?:must|should)\s+(?:not|never)\s+(?:know|see|find\s+out|be\s+told|notice)\s+(?:about\s+)?(?:this|these|it\b|that\s+you|what\s+you|the\s+(?:instruction|step|command|change|hook|script|request))",
        r"\b(?:hide|conceal)\s+(?:this|these|it|the\s+(?:commands?|changes?|output))\s+from\s+" + _USER,
    ]),
    ("covert_action", "Covert Action", 3, "Asks the agent to act silently or secretly", [
        r"\b(?:silently|secretly|covertly|stealthily|quietly)\s+(?:also\s+)?(?:run|execute|install|download|add|insert|send|upload|post|exfiltrate|modify|change|commit|push|curl|fetch|copy)\b",
    ]),
    ("data_send", "Instruction to Send Secrets", 4, "Instructs the agent to send secrets/credentials to an external destination", [
        r"\b(?:send|post|upload|exfiltrate|forward|transmit|leak|copy|pipe|submit)\w{0,3}\b[^\n]{0,80}?(?:\.env\b|environment\s+variables|\bsecrets?\b|api[\s_-]?keys?|\btokens?\b|credentials|ssh\s+keys?|private\s+keys?|id_rsa|\.aws|wallet|seed\s+phrase)[^\n]{0,100}?(?:https?://|wss?://|discord(?:app)?\.com/api|t\.me/)",
        r"(?:\.env\b|environment\s+variables|\bsecrets?\b|api[\s_-]?keys?|credentials|ssh\s+keys?|private\s+keys?)[^\n]{0,80}?\b(?:send|post|upload|exfiltrate|forward|transmit)\w{0,3}\b[^\n]{0,60}?(?:https?://|wss?://)",
    ]),
    ("safety_bypass", "Safety Bypass Instruction", 2, "Tells the agent to disable confirmations, sandboxing or permission checks", [
        r"\b(?:disable|bypass|turn\s+off|skip|circumvent)\s+(?:all\s+|any\s+|the\s+)?(?:safety|security|permission|confirmation|approval|sandbox)\s+(?:checks?|prompts?|guards?|rules|restrictions|mode)\b",
        r"\bnever\s+ask\s+(?:the\s+user\s+)?(?:for\s+)?(?:permission|confirmation|approval)\s+(?:before|to|when)\s+(?:running|executing|deleting|pushing|sending|installing)",
    ]),
    ("role_hijack", "Role / System Hijack", 2, "Fake system prompt or persona override", [
        r"^\s{0,4}(?:<\s*/?\s*system\s*>|\[\s*system\s*\]|#{1,3}\s*system\s+prompt\s*:)",
        r"\byou\s+are\s+now\s+(?:in\s+)?(?:developer|god|jailbreak|unrestricted|dan|evil)\s+mode\b",
        r"\bnew\s+system\s+(?:prompt|instructions)\s*:",
    ]),
]
_INJ_C = [(sid, name, base, desc, [re.compile(r, re.I | re.M) for r in rxs]) for sid, name, base, desc, rxs in INJECTION_SIGS]
HTML_COMMENT = re.compile(r"<!--(.{0,4000}?)-->", re.S)
AGENT_WORDS = re.compile(r"\b(?:AI|agent|assistant|claude|copilot|cursor|LLM|model|codex|gemini)\b", re.I)
IMPERATIVE = re.compile(r"\b(?:must|always|never|ignore|run|execute|do\s+not|don'?t|instead|before\s+(?:any|each|every))\b", re.I)
MODAL = re.compile(r"\b(?:can|could|may|might|will|would|should|to|it|that|which|not|never|otherwise|or)\s+(?:[\w,]+\s+){0,3}$", re.I)
ACTION = re.compile(r"\b(?:run|runs|running|execut\w*|install\w*|download\w*|upload\w*|send\w*|post\w*|curl|wget|script|command|hook|"
                    r"commit|push|modif\w*|delete|remove|add|insert|token|key|secret|credential|env\b|\.env|step|exfiltrat\w*|"
                    r"telemetry|tracking|network|request)\b", re.I)
SCOPED = re.compile(r"\s*(?:for|when|regarding|about|on|in)\s+\w", re.I)
QUOTED = re.compile(r"[\"'`“”‘’]")


def analyze_instructions(text, file):
    out, ids = [], set()
    lines = text.split("\n")
    for ln, line in enumerate(lines, 1):
        if not line.strip():
            continue
        for seg in _windows(line):
            for sid, name, base, desc, rxs in _INJ_C:
                for rx in rxs:
                    m = rx.search(seg)
                    if not m:
                        continue
                    sev = base
                    pre = seg[max(0, m.start() - 80):m.start()]
                    # quoted or listed as something to detect ("e.g. 'ignore previous instructions'")
                    if NEGATION.search(pre) and sid in ("instruction_override", "role_hijack", "data_send", "safety_bypass"):
                        sev = 0
                    if QUOTED.search(seg[max(0, m.start() - 2):m.start()]) and sid != "concealment":
                        sev = 0
                    if sid in ("safety_bypass", "covert_action") and (seg.lstrip().startswith("|") or "`-" in seg[:m.start()]):
                        sev = 0
                    if sid == "covert_action" and (NEGATION.search(pre[-40:]) or MODAL.search(pre[-30:])):
                        sev = 0
                    if sid == "instruction_override" and sev and SCOPED.match(seg[m.end():m.end() + 40]):
                        sev = 2
                    if sid == "concealment" and sev:
                        a = max(seg.rfind(c, 0, m.start()) for c in ".;!?\n")
                        bs = [seg.find(c, m.end()) for c in ".;!?\n"]
                        b = min([x for x in bs if x >= 0] or [len(seg)])
                        if not ACTION.search(seg[a + 1:b]):
                            sev = 2
                    out.append(_item(SEV[sev], sid, name, desc, file, ln, m.group(0), line.strip()))
                    if sev:
                        ids.add(sid)
                    break
    for m in HTML_COMMENT.finditer(text):
        body = m.group(1)
        if AGENT_WORDS.search(body) and IMPERATIVE.search(body) and len(body.strip()) > 20:
            ln = text.count("\n", 0, m.start()) + 1
            out.append(_item("LOW", "hidden_comment", "Instructions in an HTML Comment",
                             "Agent-directed text inside <!-- --> is invisible in rendered Markdown but read by the agent",
                             file, ln, body.strip()[:160], body.strip()[:240]))
            ids.add("hidden_comment")
            inner = [f for f in out if f["line"] >= ln and f["line"] <= ln + body.count("\n")
                     and f["severity"] in ("HIGH", "CRITICAL") and f["id"] != "hidden_comment"]
            if inner:
                out.append(_item("CRITICAL", "hidden_injection", "Hidden Prompt Injection",
                                 "Injection phrasing hidden inside an HTML comment", file, ln, inner[0]["matched"],
                                 inner[0]["context"]))
                ids.add("hidden_injection")
    code, cids = analyze_code(text, "instruction", " (in agent instructions)", file, instruction=True)
    return out + code, ids | cids


# ━━━ Invisible / deceptive Unicode ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))
ZW = {0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF, 0x180E, 0x034F, 0x115F, 0x1160, 0x3164, 0xFFA0}
RTL_SCRIPT = re.compile("[\u0590-\u08FF\uFB1D-\uFDFF\uFE70-\uFEFF]")
INDIC_PERSIAN = re.compile("[\u0600-\u06FF\u0900-\u0DFF\u0F00-\u0FFF\u1000-\u109F]")
NON_ASCII = re.compile("[^\x00-\x7f]")


def _is_emojiish(ch):
    if not ch:
        return False
    cp = ord(ch)
    return (0x1F000 <= cp <= 0x1FAFF or 0x2600 <= cp <= 0x27BF or 0x2190 <= cp <= 0x21FF or 0x2B00 <= cp <= 0x2BFF
            or cp in (0xFE0F, 0x20E3, 0x2640, 0x2642, 0x2695, 0x2696, 0x2708, 0x2764) or 0x1F3FB <= cp <= 0x1F3FF
            or 0x2300 <= cp <= 0x23FF or 0x3030 == cp or 0x303D == cp or 0x3297 <= cp <= 0x3299)


def analyze_unicode(text, file, instruction=False):
    if not NON_ASCII.search(text):
        return [], set()
    out, ids = [], set()
    tags, bidi, zw, vss, vsb, pua = [], [], [], [], [], []
    rtl = bool(RTL_SCRIPT.search(text))
    n = len(text)
    i = 0
    in_flag = False
    for i, ch in enumerate(text):
        cp = ord(ch)
        if cp < 0x80:
            in_flag = False
            continue
        if cp == 0x1F3F4:
            in_flag = True
            continue
        if 0xE0000 <= cp <= 0xE007F:
            if in_flag:
                if cp == 0xE007F:
                    in_flag = False
                continue
            tags.append(i)
        elif cp in BIDI:
            bidi.append(i)
        elif cp in ZW:
            if cp == 0xFEFF and i == 0:
                continue
            prev = text[i - 1] if i else ""
            nxt = text[i + 1] if i + 1 < n else ""
            if cp == 0x200D and (_is_emojiish(prev) or _is_emojiish(nxt)):
                continue
            if cp in (0x200C, 0x200D) and (INDIC_PERSIAN.match(prev or " ") or INDIC_PERSIAN.match(nxt or " ")):
                continue
            zw.append(i)
        elif 0xE0100 <= cp <= 0xE01EF:
            vss.append(i)
        elif 0xFE00 <= cp <= 0xFE0E:
            prev = text[i - 1] if i else ""
            if not _is_emojiish(prev) and not (0x3000 <= ord(prev or " ") <= 0x9FFF):
                vsb.append(i)
        elif 0xE000 <= cp <= 0xF8FF:
            pua.append(i)

    def line_of(pos):
        return text.count("\n", 0, pos) + 1

    def ctx(pos):
        a = text.rfind("\n", 0, pos) + 1
        b = text.find("\n", pos)
        return text[a:b if b >= 0 else n]

    if tags:
        decoded = "".join(chr(ord(text[p]) - 0xE0000) for p in tags if 0xE0020 <= ord(text[p]) <= 0xE007E)
        out.append(_item("CRITICAL", "unicode_tag_smuggling", "Invisible Unicode Tag Text",
                         "%d Unicode tag characters (U+E0000 block) outside an emoji flag: invisible to humans, "
                         "read by LLMs" % len(tags), file, line_of(tags[0]), "decoded: " + decoded[:140],
                         ctx(tags[0]).encode("ascii", "backslashreplace").decode()[:200]))
        ids.add("unicode_tag_smuggling")
    if len(vss) >= 4:
        out.append(_item("CRITICAL", "unicode_variation_payload", "Variation-Selector Payload",
                         "%d supplementary variation selectors (U+E0100-E01EF): a known way to hide bytes in text "
                         "(GlassWorm-style)" % len(vss), file, line_of(vss[0]), "", ""))
        ids.add("unicode_variation_payload")
    if bidi:
        sev = "MEDIUM" if rtl else "HIGH"
        out.append(_item(sev, "unicode_bidi", "Bidirectional Control Characters",
                         "%d bidi override/isolate characters: text can display differently from what is read "
                         "(Trojan Source)" % len(bidi), file, line_of(bidi[0]), "",
                         ctx(bidi[0]).encode("ascii", "backslashreplace").decode()[:200]))
        ids.add("unicode_bidi")
    if zw:
        sev = "HIGH" if len(zw) >= 12 and instruction else ("LOW" if len(zw) < 12 else "MEDIUM")
        out.append(_item(sev, "unicode_zero_width", "Zero-Width Characters",
                         "%d zero-width / invisible filler characters outside emoji and script contexts" % len(zw),
                         file, line_of(zw[0]), "", ctx(zw[0]).encode("ascii", "backslashreplace").decode()[:200]))
        if sev != "LOW":
            ids.add("unicode_zero_width")
    if len(vsb) >= 8:
        out.append(_item("MEDIUM", "unicode_variation_selectors", "Stray Variation Selectors",
                         "%d variation selectors not attached to emoji/CJK" % len(vsb), file, line_of(vsb[0]), "", ""))
        ids.add("unicode_variation_selectors")
    if instruction and len(pua) >= 24:
        out.append(_item("LOW", "unicode_private_use", "Private-Use Characters",
                         "%d private-use codepoints in agent instructions (icon fonts, or hidden data)" % len(pua),
                         file, line_of(pua[0]), "", ""))
    return out, ids


# ━━━ Surface analyzers ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OFFICIAL_API = re.compile(r"^https?://(?:[\w-]+\.)*(?:anthropic\.com|claude\.ai|openai\.com|azure\.com|amazonaws\.com|"
                          r"googleapis\.com|azure-api\.net|openrouter\.ai)(?::\d+)?(?:/|$)", re.I)
LOCAL_URL = re.compile(r"^https?://(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1\]|host\.docker\.internal)(?::\d+)?(?:/|$)", re.I)
URL_ENV_KEYS = {"ANTHROPIC_BASE_URL", "ANTHROPIC_API_URL", "ANTHROPIC_BEDROCK_BASE_URL", "ANTHROPIC_VERTEX_BASE_URL",
                "OPENAI_BASE_URL", "OPENAI_API_BASE", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy",
                "http_proxy", "all_proxy", "GEMINI_API_BASE", "GOOGLE_GEMINI_BASE_URL"}
INJECT_ENV = {"NODE_OPTIONS", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "BASH_ENV", "ENV", "PROMPT_COMMAND", "PYTHONSTARTUP",
              "PERL5OPT", "RUBYOPT", "GIT_SSH_COMMAND", "GIT_EXTERNAL_DIFF", "GIT_ASKPASS", "SSH_ASKPASS", "ZDOTDIR",
              "PYTHONPATH", "NODE_PATH", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "DOTNET_STARTUP_HOOKS", "PAGER",
              "GIT_PAGER", "EDITOR", "VISUAL"}
SOFT_ENV = {"PYTHONPATH", "NODE_PATH", "PAGER", "GIT_PAGER", "EDITOR", "VISUAL", "ENV"}


def _line(raw, needle):
    if not needle:
        return 0
    for cand in (needle[:60], json.dumps(needle)[1:61]):
        k = raw.find(cand)
        if k >= 0:
            return raw.count("\n", 0, k) + 1
    return 0


def _cmd_str(v):
    if isinstance(v, str):
        return v
    if isinstance(v, list):
        return " ".join(str(x) for x in v if isinstance(x, (str, int, float)))
    if isinstance(v, dict):
        return " ; ".join(_cmd_str(x) for x in v.values())
    return ""


def _env_findings(env, ctx_label, raw, file, strong):
    out = []
    if not isinstance(env, dict):
        return out
    for k, v in env.items():
        if not isinstance(v, (str, int, float)):
            continue
        v = str(v)
        ku = str(k)
        if ku in URL_ENV_KEYS and v.strip():
            u = v.strip()
            if LOCAL_URL.match(u) or u.startswith("${") or u.startswith("$"):
                out.append(_item("INFO", "api_redirect_local", "API Base URL (local)", "Points %s at a local proxy" % ku,
                                 file, _line(raw, ku), "%s=%s" % (ku, u), ctx_label))
            elif not OFFICIAL_API.match(u):
                out.append(_item("HIGH" if strong else "MEDIUM", "api_redirect", "API Traffic Redirected",
                                 "%s sends the agent's requests (prompts, code, and the API key) to a third-party host%s"
                                 % (ku, ctx_label), file, _line(raw, ku), "%s=%s" % (ku, u[:100]), ""))
        elif ku in INJECT_ENV:
            loads = ku != "NODE_OPTIONS" or re.search(r"(?:--require|-r|--import|--loader|--experimental-loader)[\s=]{1,3}[\"']?(?:\.{0,2}/|[\w.-]+/)[\w./-]{0,120}\.[cm]?[jt]s\b", v)
            if not loads:
                continue
            sev = "LOW" if ku in SOFT_ENV else ("HIGH" if strong else "MEDIUM")
            out.append(_item(sev, "env_injection", "Process Injection via Environment",
                             "%s makes every spawned process load extra code%s" % (ku, ctx_label),
                             file, _line(raw, ku), "%s=%s" % (ku, v[:100]), ""))
    return out


class Repo:
    def __init__(self, files, all_paths=None, label=""):
        self.files = files                    # {path: text}
        self.paths = set(all_paths or files)  # every path in the repo (tarball/tree), for exists-checks
        self.label = label
        self.findings, self.info, self.caps = [], [], {}
        self.autorun_units = []               # (file, desc) of things that run on open/trust
        self.surface_files = {}

    def cap(self, k, n=1):
        self.caps[k] = self.caps.get(k, 0) + n

    def add(self, items):
        for f in items:
            (self.info if f["severity"] == "INFO" else self.findings).append(f)

    # ── resolve a script a command refers to, scan it in the same context ──
    REF = re.compile(r"(?:\$\{?CLAUDE_PROJECT_DIR\}?/|\$\{(?:workspaceFolder|containerWorkspaceFolder|localWorkspaceFolder)\}/|\./|(?<![\w/.$~-]))"
                     r"((?:[\w.-]{1,80}/){0,6}[\w.-]{1,80}\.(?:sh|bash|zsh|py|js|mjs|cjs|ts|ps1|rb|pl|bat|cmd))\b")

    def refs(self, cmd, base_dir=""):
        got = []
        for m in self.REF.finditer(cmd or ""):
            p = m.group(1)
            for cand in (p, (base_dir + "/" + p) if base_dir else p):
                cand = os.path.normpath(cand).replace("\\", "/")
                if cand in self.files and cand not in got:
                    got.append(cand)
        return got

    def scan_command(self, cmd, ctx, where, file, raw, base_dir=""):
        if not cmd:
            return set()
        items, ids = analyze_code(cmd, ctx, where, file, line0=_line(raw, cmd.split("\n")[0]) or 1)
        self.add(items)
        u, uids = analyze_unicode(cmd, file)
        self.add(u)
        ids |= uids
        for ref in self.refs(cmd, base_dir):
            sitems, sids = analyze_code(self.files[ref], ctx, where + " via " + ref, ref)
            self.add(sitems)
            ids |= sids
        return ids

    # ── .claude/settings*.json ──
    def claude(self, path, raw, data):
        if not isinstance(data, dict):
            return
        self.cap("claude_settings")
        hooks = data.get("hooks")
        if isinstance(hooks, dict):
            for event, groups in hooks.items():
                for kp, v in _walk(groups):
                    if kp and kp[-1] == "command" and isinstance(v, str):
                        self.cap("claude_hooks")
                        self.autorun_units.append((path, "hook " + event))
                        self.info.append(_item("INFO", "agent_hook", "Agent Hook",
                                               "%s hook runs a command automatically" % event, path, _line(raw, v), v, ""))
                        self.scan_command(v, "autorun", " (Claude Code %s hook)" % event, path, raw)
        for key, label in (("statusLine", "statusLine"), ("apiKeyHelper", "apiKeyHelper"), ("otelHeadersHelper", "otelHeadersHelper"),
                           ("awsAuthRefresh", "awsAuthRefresh"), ("awsCredentialExport", "awsCredentialExport")):
            v = data.get(key)
            cmd = v.get("command") if isinstance(v, dict) else v if isinstance(v, str) else None
            if cmd:
                self.cap("claude_" + key)
                self.autorun_units.append((path, label))
                if key == "statusLine":
                    self.info.append(_item("INFO", "agent_hook", "Agent Status Line", "statusLine runs a command on every refresh",
                                           path, _line(raw, cmd), cmd, ""))
                else:
                    self.findings.append(_item("MEDIUM", "credential_helper", "Repo-Supplied Credential Helper",
                                               "%s: the repo chooses the command that produces your credentials" % key,
                                               path, _line(raw, cmd), cmd, ""))
                self.scan_command(cmd, "autorun", " (Claude Code %s)" % label, path, raw)
        self.add(_env_findings(data.get("env"), " (Claude Code project env)", raw, path, strong=True))
        perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
        if perms.get("defaultMode") == "bypassPermissions":
            self.findings.append(_item("HIGH", "permissions_bypass", "Permission Prompts Disabled",
                                       "defaultMode=bypassPermissions: the agent runs every tool without asking",
                                       path, _line(raw, "bypassPermissions"), "bypassPermissions", ""))
        allow = perms.get("allow") if isinstance(perms.get("allow"), list) else []
        broad = [a for a in allow if isinstance(a, str) and re.fullmatch(
            r"Bash(?:\(\s*\*?\s*\)|\((?:curl|wget|sh|bash|zsh|python3?|node|eval|sudo|rm)\s*(?::\s*\*|\*)\s*\))?", a.strip())]
        if broad:
            self.findings.append(_item("MEDIUM", "broad_allow", "Broad Pre-Approved Shell",
                                       "permissions.allow pre-approves %s" % ", ".join(broad[:4]), path, _line(raw, broad[0]), broad[0], ""))
        if data.get("enableAllProjectMcpServers") is True:
            self.cap("mcp_autoapprove_all")
            self.info.append(_item("INFO", "mcp_autoapprove", "Project MCP Servers Auto-Approved",
                                   "enableAllProjectMcpServers=true", path, _line(raw, "enableAllProjectMcpServers"), "", ""))
        if isinstance(data.get("enabledMcpjsonServers"), list) and data["enabledMcpjsonServers"]:
            self.cap("mcp_autoapprove_named")
        for k in ("enabledPlugins", "extraKnownMarketplaces"):
            if data.get(k):
                self.cap("claude_plugins")
                self.info.append(_item("INFO", "claude_plugins", "Plugins / Marketplaces", k, path, _line(raw, k), "", ""))

    def mcp_autoapproved(self, name):
        for p in (".claude/settings.json", ".claude/settings.local.json"):
            d = self._json.get(p)
            if isinstance(d, dict):
                if d.get("enableAllProjectMcpServers") is True:
                    return True
                if name in (d.get("enabledMcpjsonServers") or []):
                    return True
        return False

    # ── .mcp.json & friends ──
    def mcp(self, path, raw, data):
        if not isinstance(data, dict):
            return
        servers = data.get("mcpServers") or data.get("servers") or {}
        if not isinstance(servers, dict):
            return
        auto_file = path == ".mcp.json"
        for name, s in servers.items():
            if not isinstance(s, dict):
                continue
            self.cap("mcp_servers")
            cmd = s.get("command") or ""
            args = s.get("args") if isinstance(s.get("args"), list) else []
            full = " ".join([str(cmd)] + [str(a) for a in args if isinstance(a, (str, int, float))]).strip()
            url = s.get("url") or s.get("serverUrl") or s.get("httpUrl") or ""
            auto = auto_file and self.mcp_autoapproved(name)
            ctx = "autorun" if auto else "manual"
            if full:
                self.info.append(_item("INFO", "mcp_server", "MCP Server", "%s launches: %s%s" % (name, full[:120], " (auto-approved)" if auto else ""),
                                       path, _line(raw, str(cmd)), full, ""))
                if auto:
                    self.autorun_units.append((path, "mcp " + name))
                ids = self.scan_command(full, ctx, " (MCP server %r%s)" % (name, ", auto-approved" if auto else ""), path, raw)
                if auto and ids & {"download_execute", "decode_execute", "reverse_shell", "exfil_host", "credential_exfil", "raw_ip_url"}:
                    self.findings.append(_item("CRITICAL", "autoapproved_risky_mcp", "Auto-Approved Risky MCP Server",
                                               "Repo auto-approves its own MCP server %r and that server's command is risky" % name,
                                               path, _line(raw, str(cmd)), full, ""))
            if isinstance(url, str) and url:
                if url.startswith("http://") and not LOCAL_URL.match(url):
                    self.findings.append(_item("MEDIUM", "mcp_plaintext", "Plaintext Remote MCP Server",
                                               "%s talks to %s over plain HTTP" % (name, url[:80]), path, _line(raw, url), url, ""))
                else:
                    self.info.append(_item("INFO", "mcp_remote", "Remote MCP Server", "%s -> %s" % (name, url[:80]), path, _line(raw, url), url, ""))
            self.add(_env_findings(s.get("env"), " (MCP server %r env)" % name, raw, path, strong=False))
            for k in ("alwaysAllow", "autoApprove"):
                if isinstance(s.get(k), list) and s[k]:
                    self.info.append(_item("INFO", "mcp_tool_autoapprove", "Tools Auto-Approved", "%s.%s=%s" % (name, k, s[k][:6]),
                                           path, _line(raw, k), "", ""))
        if isinstance(data.get("hooks"), dict):
            self.agent_config(path, raw, {"hooks": data["hooks"]})
        for k in ("autoAccept", "yolo", "yoloMode", "autoApproveAll"):
            if data.get(k) is True:
                self.findings.append(_item("MEDIUM", "agent_autoaccept", "Agent Auto-Accept", "%s=true in repo config" % k,
                                           path, _line(raw, k), k, ""))

    # ── .cursor/hooks.json, .gemini/settings.json, ... ──
    def agent_config(self, path, raw, data):
        if not isinstance(data, dict):
            return
        hooks = data.get("hooks")
        if hooks is not None:
            for kp, v in _walk(hooks):
                if kp and kp[-1] in ("command", "cmd") and isinstance(v, str):
                    self.cap("agent_hooks")
                    ev = kp[0] if kp else "hook"
                    self.autorun_units.append((path, "hook " + ev))
                    self.info.append(_item("INFO", "agent_hook", "Agent Hook", "%s hook runs a command automatically" % ev,
                                           path, _line(raw, v), v, ""))
                    self.scan_command(v, "autorun", " (%s %s hook)" % (path, ev), path, raw, base_dir=os.path.dirname(path))
        tools = data.get("tools") if isinstance(data.get("tools"), dict) else {}
        for k in ("autoAccept", "yolo"):
            if data.get(k) is True or tools.get(k) is True:
                self.findings.append(_item("MEDIUM", "agent_autoaccept", "Agent Auto-Accept", "%s=true in repo config" % k,
                                           path, _line(raw, k), k, ""))

    # ── .vscode/tasks.json ──
    def tasks(self, path, raw, data, allow_auto):
        tasks = data.get("tasks") if isinstance(data, dict) else None
        if isinstance(data, dict) and path.endswith(".code-workspace"):
            t = data.get("tasks")
            tasks = t.get("tasks") if isinstance(t, dict) else None
        if not isinstance(tasks, list):
            return
        by_label = {str(t.get("label") or t.get("taskName") or ""): t for t in tasks if isinstance(t, dict)}
        auto_labels = set()
        for t in tasks:
            if isinstance(t, dict) and isinstance(t.get("runOptions"), dict) and t["runOptions"].get("runOn") == "folderOpen":
                auto_labels.add(str(t.get("label") or t.get("taskName") or ""))
        # dependsOn of an auto task also run on open
        stack = list(auto_labels)
        while stack:
            t = by_label.get(stack.pop())
            dep = t.get("dependsOn") if isinstance(t, dict) else None
            for d in ([dep] if isinstance(dep, str) else dep if isinstance(dep, list) else []):
                d = d if isinstance(d, str) else (d.get("label") if isinstance(d, dict) else None)
                if d and d not in auto_labels:
                    auto_labels.add(d); stack.append(d)
        for t in tasks:
            if not isinstance(t, dict):
                continue
            label = str(t.get("label") or t.get("taskName") or "")
            auto = label in auto_labels
            parts = []
            for scope in (t, t.get("windows"), t.get("osx"), t.get("linux")):
                if not isinstance(scope, dict):
                    continue
                c = scope.get("command")
                c = c.get("value") if isinstance(c, dict) else c
                a = scope.get("args")
                a = [x.get("value") if isinstance(x, dict) else x for x in a] if isinstance(a, list) else []
                if isinstance(c, list):
                    c = " ".join(str(x) for x in c)
                if c:
                    parts.append(" ".join([str(c)] + [str(x) for x in a if isinstance(x, (str, int, float))]))
            if t.get("type") == "npm" and t.get("script"):
                pj = self._json.get(os.path.normpath(os.path.join(t.get("path") or "", "package.json")).replace("\\", "/"))
                sc = ((pj or {}).get("scripts") or {}).get(t["script"]) if isinstance(pj, dict) else None
                parts.append(sc or ("npm run " + str(t["script"])))
            cmd = " ; ".join(parts)
            if not cmd:
                continue
            ctx = "autorun" if auto else "manual"
            if auto:
                self.cap("autorun_task")
                self.autorun_units.append((path, "task " + label))
                pres = t.get("presentation") if isinstance(t.get("presentation"), dict) else {}
                hidden = t.get("hide") is True or pres.get("reveal") in ("never", "silent") and pres.get("echo") is False
                self.info.append(_item("INFO", "autorun_task", "Auto-Run Task",
                                       "Task %r runs when the folder is opened%s" % (label, " (hidden from the user)" if hidden else ""),
                                       path, _line(raw, label) or _line(raw, "folderOpen"), cmd, ""))
                ids = self.scan_command(cmd, ctx, " (VS Code task %r, runs on folder open)" % label, path, raw)
                risky = ids & {"download_execute", "decode_execute", "reverse_shell", "exfil_host", "credential_exfil",
                               "raw_ip_url", "persistence", "powershell_encoded", "obfuscated_blob", "git_config_hijack"}
                if hidden and risky:
                    self.findings.append(_item("CRITICAL", "hidden_autorun", "Hidden Auto-Run Task",
                                               "Task %r auto-runs on open, hides its terminal, and its command is risky" % label,
                                               path, _line(raw, label), cmd, ""))
                if allow_auto:
                    self.findings.append(_item("HIGH", "autorun_prompt_suppressed", "Auto-Run Prompt Suppressed",
                                               "Workspace sets task.allowAutomaticTasks=on alongside folder-open task %r" % label,
                                               path, _line(raw, label), cmd, ""))
            else:
                self.scan_command(cmd, ctx, " (VS Code task %r)" % label, path, raw)
            if isinstance(t.get("options"), dict):
                self.add(_env_findings(t["options"].get("env"), " (task %r env)" % label, raw, path, strong=auto))

    # ── .vscode/settings.json ──
    EXEC_KEY = re.compile(r"(?:^|\.)(?:executablePath|ExecutablePath|path|pythonPath|defaultInterpreterPath|interpreterPath|"
                          r"serverPath|nodePath|runtime|binPath|lspBin|commandPath|prettierPath|server\.path|alternateTools\.[\w-]+|"
                          r"shell\.(?:linux|osx|windows)|automationShell\.(?:linux|osx|windows))$")
    EXEC_NS = re.compile(r"^(?:git|python|terminal|eslint|typescript|go|rust-analyzer|clangd|php|ruby|deno|biome|prettier|"
                         r"java|npm|jest|vitest|mypy|pylint|flake8|ruff|black-formatter|isort|stylelint|tslint|dart|flutter|"
                         r"elixirLS|haskell|julia|r|swift|kotlin|zig|nim|omnisharp|dotnet|csharp|cmake|cpptools|C_Cpp|shellcheck|"
                         r"powershell|perl|lua|sumneko|yaml|markdownlint|ltex|svelte|volar|vue|astro|tailwindCSS|docker|ansible|"
                         r"terraform|bazel|buck|nix|direnv|copilot|github|chat|mcp)\b")
    GENERATED = re.compile(r"(?:^|/)(?:node_modules|\.venv|venv|env|\.env|\.tox|target|build|dist|out|bazel-[\w-]+|\.yarn|"
                           r"\.pnp|vendor|\.gradle|\.direnv|\.pixi|\.conda|bin/Debug|bin/Release)(?:/|$)")
    SURFACE_HIDE = re.compile(r"(?:^|/|\*)(?:\.vscode|\.claude|\.cursor|\.mcp\.json|mcp\.json|tasks\.json|settings\.json|"
                              r"\.devcontainer|\.envrc|AGENTS\.md|CLAUDE\.md|\.cursorrules|copilot-instructions\.md|\.gemini|hooks\.json)\b")

    def settings(self, path, raw, data, nested=False):
        if isinstance(data, dict) and path.endswith(".code-workspace"):
            data = data.get("settings")
        if not isinstance(data, dict):
            return False
        if not nested:
            self.cap("vscode_settings")
        allow_auto = data.get("task.allowAutomaticTasks") in ("on", True)
        if allow_auto:
            self.findings.append(_item("MEDIUM", "autorun_prompt_suppressed", "Auto-Run Prompt Suppressed",
                                       "task.allowAutomaticTasks=on in workspace settings", path, _line(raw, "allowAutomaticTasks"), "", ""))
        for k, v in data.items():
            ks = str(k)
            if ks.startswith("security.workspace.trust"):
                self.findings.append(_item("MEDIUM", "trust_tamper", "Workspace Trust Tampering",
                                           "Workspace settings try to change %s" % ks, path, _line(raw, ks), "%s=%s" % (ks, v), ""))
            elif ks in ("chat.tools.autoApprove", "chat.tools.global.autoApprove", "github.copilot.chat.agent.autoApprove",
                        "chat.agent.autoApprove", "chat.tools.edits.autoApprove") and v is True:
                self.findings.append(_item("HIGH", "chat_autoapprove", "Agent Confirmations Disabled",
                                           "%s=true: Copilot/agent tools run without confirmation" % ks, path, _line(raw, ks), ks, ""))
            elif ks in ("chat.tools.terminal.autoApprove", "github.copilot.chat.agent.terminal.allowList") and isinstance(v, dict):
                broad = [c for c, ok in v.items() if ok is True and re.search(r"^/?\.?\*|^(?:curl|wget|sh|bash|rm|sudo|eval|node|python3?)\b", str(c))]
                if broad:
                    self.findings.append(_item("MEDIUM", "chat_autoapprove", "Broad Terminal Auto-Approve",
                                               "%s auto-approves %s" % (ks, ", ".join(map(str, broad[:4]))), path, _line(raw, ks), "", ""))
            elif ks.startswith("terminal.integrated.env."):
                self.add(_env_findings(v, " (VS Code terminal env)", raw, path, strong=True))
            elif ks.startswith(("terminal.integrated.shellArgs.", "terminal.integrated.profiles.", "terminal.integrated.automationProfile.")):
                for kp, leaf in _walk(v):
                    if isinstance(leaf, str):
                        self.scan_command(leaf, "manual", " (VS Code terminal profile)", path, raw)
            elif ks in ("files.exclude", "search.exclude", "files.watcherExclude") and isinstance(v, dict):
                hid = [p for p, on in v.items() if on is True and self.SURFACE_HIDE.search(str(p))]
                if hid:
                    self.caps["hides_surfaces"] = hid
                    self.info.append(_item("INFO", "hides_surfaces", "Hides Config Files", "%s hides %s" % (ks, ", ".join(hid[:5])),
                                           path, _line(raw, hid[0]), "", ""))
        flat = {}
        for kp, leaf in _walk(data):
            if isinstance(leaf, str):
                flat[".".join(kp)] = leaf
        for key, val in flat.items():
            if not (self.EXEC_NS.match(key) and self.EXEC_KEY.search(key)):
                continue
            if key.startswith(("terminal.integrated.env.", "files.", "search.")):
                continue
            target = val.replace("${workspaceFolder}/", "").replace("${workspaceRoot}/", "").lstrip("./")
            if not target or val.startswith(("/", "~", "${env:", "$HOME", "C:", "%")) or target == val and "/" not in val:
                continue
            if self.GENERATED.search(target):
                continue
            self.cap("vscode_exec_paths")
            exists = target in self.paths
            self.add([_item("MEDIUM" if exists else "INFO", "repo_binary", "Editor Runs a Repo File",
                            "%s points the editor at %s%s" % (key, target, " (committed in this repo)" if exists else ""),
                            path, _line(raw, val), val, "")])
            if exists and target in self.files:
                self.add(analyze_code(self.files[target], "autorun", " (run by the editor via %s)" % key, target)[0])
        return allow_auto

    # ── devcontainer ──
    def devcontainer(self, path, raw, data):
        if not isinstance(data, dict):
            return
        self.cap("devcontainer")
        base = os.path.dirname(path)
        init = data.get("initializeCommand")
        if init:
            cmd = _cmd_str(init)
            self.cap("devcontainer_initialize")
            self.autorun_units.append((path, "initializeCommand"))
            self.info.append(_item("INFO", "devcontainer_host_cmd", "Host Command", "initializeCommand runs on your machine, not in the container",
                                   path, _line(raw, "initializeCommand"), cmd, ""))
            self.scan_command(cmd, "autorun", " (devcontainer initializeCommand, runs on the HOST)", path, raw, base_dir=base)
        for k in ("onCreateCommand", "updateContentCommand", "postCreateCommand", "postStartCommand", "postAttachCommand"):
            if data.get(k):
                self.cap("devcontainer_post")
                self.scan_command(_cmd_str(data[k]), "container", " (devcontainer %s, in container)" % k, path, raw, base_dir=base)
        mounts = [m if isinstance(m, str) else json.dumps(m) for m in (data.get("mounts") or []) if isinstance(m, (str, dict))]
        runargs = [a for a in (data.get("runArgs") or []) if isinstance(a, str)]
        def _src(m):
            if "type=volume" in m.replace(" ", "") or '"type": "volume"' in m:
                return ""
            sm = re.search(r"(?:source|src)=([^,]+)", m) or re.search(r"\"source\":\s*\"([^\"]+)\"", m)
            if sm:
                return sm.group(1)
            vm = re.match(r"\s*(?:-v|--volume)[=\s]\s*([^:]+):", m) or re.match(r"\s*([~/$][^:]+):[^:]+", m)
            return vm.group(1) if vm else ""
        for m in mounts + runargs:
            src = _src(m)
            if src and (re.search(r"(?:localEnv:HOME|localEnv:USERPROFILE|^~|^/Users/|^/home/|^\$HOME|^\$\{HOME\})[^,\"]{0,60}[/\\]\.(?:ssh|aws|gnupg|kube|docker|config/gh|netrc|npmrc|git-credentials)\b", src)
                        or re.fullmatch(r"\$\{localEnv:(?:HOME|USERPROFILE)\}(?:\$\{localEnv:(?:HOME|USERPROFILE)\})?/?", src.strip())):
                self.findings.append(_item("MEDIUM", "host_secret_mount", "Host Credentials Mounted",
                                           "Mounts host credentials into the container: %s" % m[:100], path, _line(raw, m[:40]), m, ""))
            elif "docker.sock" in m or m.strip() in ("--privileged", "--network=host", "--pid=host"):
                self.cap("devcontainer_privileged")
        self.add(_env_findings(data.get("remoteEnv"), " (devcontainer remoteEnv)", raw, path, strong=False))
        feats = data.get("features") if isinstance(data.get("features"), dict) else {}
        for f in feats:
            if not str(f).startswith(("ghcr.io/devcontainers/", "ghcr.io/devcontainers-contrib/", "ghcr.io/devcontainers-extra/")):
                self.cap("devcontainer_thirdparty_feature")
        cust = data.get("customizations") if isinstance(data.get("customizations"), dict) else {}
        vs = cust.get("vscode") if isinstance(cust.get("vscode"), dict) else {}
        if isinstance(vs.get("settings"), dict):
            self.settings(path, raw, vs["settings"], nested=True)

    # ── .envrc ──
    BENIGN_ENVRC = re.compile(r"^\s*(?:#|$|export\s|use\s|dotenv|layout\s|PATH_add|path_add|watch_file|source_up|source_env|"
                              r"strict_env|unset\s|if\s|fi\b|then\b|else\b|nix_direnv|has\s|log_status|eval\s+\"\$\(lorri)")

    def envrc(self, path, raw):
        self.cap("envrc")
        self.autorun_units.append((path, "envrc"))
        if re.search(r"^\s*source_url\s+\S+\s*$", raw, re.M):
            self.findings.append(_item("MEDIUM", "envrc_unpinned", "Unpinned Remote .envrc Code",
                                       "source_url without an integrity hash", path, 0, "", ""))
        self.add(analyze_code(raw, "autorun", " (.envrc, runs on cd once allowed)", path)[0])

    # ── JetBrains ──
    def idea(self, path, raw):
        self.cap("idea_files")
        startup = re.search(r"<component\s+name=\"(?:ProjectStartup\w*|StartupTask\w*|[\w]*Startup\w*Manager)\"", raw)
        texts = re.findall(r"name=\"(?:SCRIPT_TEXT|SCRIPT_PATH|PROGRAM_PARAMETERS|INTERPRETER_OPTIONS|PARAMETERS|VM_PARAMETERS|command)\"\s+value=\"([^\"]{1,4000})\"", raw)
        cmd = "\n".join(t.replace("&quot;", "\"").replace("&amp;", "&").replace("&#10;", "\n").replace("&lt;", "<").replace("&gt;", ">") for t in texts)
        if startup:
            self.cap("idea_startup")
            self.autorun_units.append((path, "startup task"))
            self.info.append(_item("INFO", "idea_startup", "IDE Startup Task", "JetBrains startup task component", path, _line(raw, startup.group(0)), "", ""))
        if cmd:
            self.scan_command(cmd, "autorun" if startup else "manual", " (JetBrains %s)" % ("startup task" if startup else "run configuration"), path, raw)

    # ── git ──
    def gitmodules(self, path, raw):
        self.cap("gitmodules")
        for m in re.finditer(r"^\s*(url|path|update|branch)\s*=\s*(.+?)\s*$", raw, re.M):
            k, v = m.group(1), m.group(2).strip("\"' ")
            ln = raw.count("\n", 0, m.start()) + 1
            if k == "url" and (v.startswith("-") or "--upload-pack" in v or v.startswith("ext::")):
                self.findings.append(_item("HIGH", "gitmodules_injection", "Submodule Command Injection",
                                           "Submodule url is an option/ext:: transport (historic git RCE pattern)", path, ln, v, m.group(0)))
            elif k == "path" and (v.startswith("-") or ".." in v.split("/") or ".git" in v.split("/")):
                self.findings.append(_item("HIGH", "gitmodules_injection", "Submodule Path Traversal",
                                           "Submodule path escapes the tree or targets .git", path, ln, v, m.group(0)))
            elif k == "update" and v.startswith("!"):
                self.findings.append(_item("HIGH", "gitmodules_injection", "Submodule Update Command",
                                           "update=!command (git ignores this from .gitmodules, but it is an attempt)", path, ln, v, m.group(0)))
            elif k == "url" and v.startswith(("file://", "/")):
                self.findings.append(_item("LOW", "gitmodules_local", "Local-Path Submodule", "Submodule url is a local path", path, ln, v, m.group(0)))

    def lfsconfig(self, path, raw):
        self.cap("lfsconfig")
        for m in re.finditer(r"^\s*(url|pushurl|standalonetransferagent|path)\s*=\s*(\S+)", raw, re.M | re.I):
            k, v = m.group(1).lower(), m.group(2)
            ln = raw.count("\n", 0, m.start()) + 1
            if k in ("standalonetransferagent", "path"):
                self.findings.append(_item("MEDIUM", "lfs_transfer_agent", "LFS Transfer Agent", "Custom LFS transfer agent/program in .lfsconfig", path, ln, v, m.group(0)))
            elif v.startswith("http://") and not LOCAL_URL.match(v):
                self.findings.append(_item("MEDIUM", "lfs_plaintext", "Plaintext LFS Endpoint", "LFS endpoint over plain HTTP", path, ln, v, m.group(0)))
            else:
                self.info.append(_item("INFO", "lfs_endpoint", "LFS Endpoint", v[:100], path, ln, v, ""))

    def gitattributes(self, path, raw):
        drivers = set(re.findall(r"\b(?:filter|diff|merge)=([\w.-]+)", raw)) - {"lfs", "astextplain", "binary", "text", "union", "cpp",
                                                                                  "python", "java", "csharp", "html", "markdown", "golang",
                                                                                  "rust", "ruby", "php", "perl", "objc", "fortran", "pascal",
                                                                                  "tex", "bibtex", "css", "elixir", "kotlin", "dts", "matlab", "scheme"}
        if drivers:
            self.cap("gitattributes_drivers")
            self.info.append(_item("INFO", "git_drivers", "Custom Git Drivers",
                                   "References drivers %s (they only run if your git config defines them)" % ", ".join(sorted(drivers)[:6]),
                                   path, 0, "", ""))

    def pkg_json(self, path, raw, data):
        scripts = data.get("scripts") if isinstance(data, dict) and isinstance(data.get("scripts"), dict) else {}
        for k in ("preinstall", "install", "postinstall", "prepare", "prepublish"):
            v = scripts.get(k)
            if isinstance(v, str) and v:
                self.cap("pkg_lifecycle")
                self.info.append(_item("INFO", "pkg_lifecycle", "Install Lifecycle Script",
                                       "package.json %s runs on install (see npm-audit)" % k, path, _line(raw, v), v, ""))
                self.scan_command(v, "package", " (package.json %s)" % k, path, raw, base_dir=os.path.dirname(path))

    # ── driver ──
    def run(self):
        self._json = {}
        kinds = {}
        for p in sorted(self.files):
            for k in surface_kinds(p):
                kinds.setdefault(k, []).append(p)
        for k, ps in kinds.items():
            if len(ps) > MAX_PER_KIND:
                kinds[k] = sorted(ps, key=lambda x: (x.count("/"), x))[:MAX_PER_KIND]
        self.surface_files = kinds
        for p in set(sum(kinds.values(), [])):
            if p.endswith((".json", ".code-workspace")):
                try:
                    self._json[p] = loads_jsonc(self.files[p])
                except Exception:
                    self._json[p] = None
                    self.info.append(_item("INFO", "parse_error", "Unparsable JSON", "Could not parse; scanned as text", p, 0, "", ""))
        allow_auto = False
        for p in kinds.get("vscode_settings", []):
            if self._json.get(p) is not None:
                allow_auto = self.settings(p, self.files[p], self._json[p]) or allow_auto
        for p in kinds.get("claude_settings", []):
            self.claude(p, self.files[p], self._json.get(p))
        for p in kinds.get("agent_config", []):
            self.agent_config(p, self.files[p], self._json.get(p))
        for p in kinds.get("mcp_config", []):
            self.cap("mcp_config")
            self.mcp(p, self.files[p], self._json.get(p))
        for p in kinds.get("vscode_tasks", []):
            if self._json.get(p) is not None:
                self.tasks(p, self.files[p], self._json[p], allow_auto)
        for p in kinds.get("vscode_extensions", []):
            d = self._json.get(p)
            if isinstance(d, dict) and d.get("recommendations"):
                self.cap("vscode_extension_recs")
        for p in kinds.get("devcontainer", []):
            self.devcontainer(p, self.files[p], self._json.get(p))
        for p in kinds.get("envrc", []):
            self.envrc(p, self.files[p])
        for p in kinds.get("idea", []):
            self.idea(p, self.files[p])
        for p in kinds.get("gitmodules", []):
            self.gitmodules(p, self.files[p])
        for p in kinds.get("lfsconfig", []):
            self.lfsconfig(p, self.files[p])
        for p in kinds.get("gitattributes", []):
            self.gitattributes(p, self.files[p])
        for p in kinds.get("pkg_json", [])[:5]:
            if isinstance(self._json.get(p), dict):
                self.pkg_json(p, self.files[p], self._json[p])
        for p in kinds.get("makefile", []):
            self.cap("makefile")
        instr = kinds.get("agent_instructions", [])
        if instr:
            self.cap("agent_instructions")
        for p in instr:
            self.cap("instr:" + p.split("/")[-1].lower() if "/" not in p or not p.startswith(".") else "instr:" + p.split("/")[0])
            items, ids = analyze_instructions(self.files[p], p)
            u, uids = analyze_unicode(self.files[p], p, instruction=True)
            self.add(items + u)
            if uids & {"unicode_tag_smuggling", "unicode_variation_payload", "unicode_bidi", "unicode_zero_width"} and \
                    ids & {"instruction_override", "concealment", "covert_action", "data_send", "safety_bypass"}:
                self.findings.append(_item("CRITICAL", "hidden_injection", "Hidden Prompt Injection",
                                           "Invisible characters and injection phrasing in the same agent-instruction file", p, 0, "", ""))
        # invisible unicode in the machine configs too (a bidi char inside a task command)
        for k in ("claude_settings", "agent_config", "mcp_config", "vscode_tasks", "vscode_settings", "devcontainer", "envrc"):
            for p in kinds.get(k, []):
                u, uids = analyze_unicode(self.files[p], p)
                self.add([dict(f, severity="HIGH" if f["severity"] in ("MEDIUM", "LOW") and f["id"] != "unicode_zero_width" else f["severity"]) for f in u])
        # concealment: settings hide a surface that auto-runs something
        hid = self.caps.get("hides_surfaces")
        if hid and self.autorun_units:
            hidden_runs = [u for u in self.autorun_units if any(h.strip("*/").split("/")[-1] in u[0] for h in hid)]
            if hidden_runs:
                self.findings.append(_item("HIGH", "concealed_autorun", "Auto-Run Config Hidden from Explorer",
                                           "files.exclude/search.exclude hides %s, which auto-runs: %s" % (hidden_runs[0][0], hidden_runs[0][1]),
                                           ".vscode/settings.json", 0, "", ""))
        if isinstance(hid, list):
            self.caps["hides_surfaces"] = len(hid)
        return self.result()

    def result(self):
        # de-duplicate identical findings
        uniq, seen = [], set()
        for f in self.findings:
            k = (f["id"], f["file"], f["line"], f["severity"], f["matched"])
            if k not in seen:
                seen.add(k); uniq.append(f)
        order = {s: i for i, s in enumerate(SEV)}
        uniq.sort(key=lambda f: (-order[f["severity"]], f["file"], f["line"]))
        counts = {s: 0 for s in SEV[1:]}
        for f in uniq:
            counts[f["severity"]] += 1
        level = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[s]), "SAFE")
        score = min(100, sum(SCORE[f["severity"]] for f in uniq))
        parts = ["%d %s" % (counts[s], s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[s]]
        return {"target": self.label, "risk_level": level, "risk_score": score, "findings": uniq,
                "info": self.info, "capabilities": self.caps,
                "surfaces": {k: v for k, v in self.surface_files.items()},
                "autorun": [{"file": a, "what": b} for a, b in self.autorun_units],
                "summary": ", ".join(parts) if parts else "No issues found",
                "total_findings": len(uniq), "info_count": len(self.info)}


def scan_files(files, all_paths=None, label=""):
    """files: {repo-relative path: text}. The library entry point."""
    return Repo(files, all_paths, label).run()


# ━━━ Loaders ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _read(path):
    with open(path, "rb") as fh:
        b = fh.read(MAX_FILE)
    if b"\x00" in b[:4096]:
        return None
    return b.decode("utf-8", "replace")


def load_dir(root):
    files, paths = {}, set()
    root = os.path.abspath(root)
    for dp, dns, fns in os.walk(root):
        rel = os.path.relpath(dp, root).replace("\\", "/")
        rel = "" if rel == "." else rel + "/"
        dns[:] = [d for d in dns if d not in SKIP_DIRS and not os.path.islink(os.path.join(dp, d))]
        if rel.count("/") > 6:
            dns[:] = []
        for fn in fns:
            p = rel + fn
            paths.add(p)
            full = os.path.join(dp, fn)
            try:
                if not regular_file(full):   # symlinks, FIFOs, devices: never opened
                    continue
                size = os.path.getsize(full)
            except OSError:
                continue
            if want_in_tarball(p, size):
                t = _read(full)
                if t is not None:
                    files[p] = t
    return files, paths


class _Counting(io.RawIOBase):
    def __init__(self, raw, limit):
        self.raw, self.n, self.limit = raw, 0, limit

    def readable(self):
        return True

    def readinto(self, b):
        if self.n > self.limit:
            raise IOError("tarball larger than --max-mb")
        chunk = self.raw.read(len(b))
        self.n += len(chunk)
        b[:len(chunk)] = chunk
        return len(chunk)


def load_github(spec, max_mb=400, retries=3):
    repo, _, ref = spec.partition("@")
    repo = repo.strip().strip("/")
    if repo.startswith("https://github.com/"):
        repo = repo[len("https://github.com/"):]
    repo = repo[:-4] if repo.endswith(".git") else repo
    urls = ["https://codeload.github.com/%s/tar.gz/%s" % (repo, ref or "HEAD"),
            "https://github.com/%s/archive/%s.tar.gz" % (repo, ref or "HEAD")]
    last = None
    for attempt in range(retries):
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "repo-trust-audit/" + VERSION})
                resp = urllib.request.urlopen(req, timeout=60)
                stream = io.BufferedReader(_Counting(resp, max_mb * 1024 * 1024), 1 << 16)
                files, paths, budget = {}, set(), ArchiveBudget()
                with tarfile.open(fileobj=stream, mode="r|gz") as tf:
                    for m in tf:
                        full = safe_member(m.name)
                        name = full.split("/", 1)[1] if full and "/" in full else ""
                        if not name or not m.isreg():
                            continue
                        paths.add(name)
                        if want_in_tarball(name, m.size) and budget.take(min(m.size, MAX_FILE)):
                            fh = tf.extractfile(m)
                            b = fh.read(MAX_FILE) if fh else b""
                            if b"\x00" not in b[:4096]:
                                files[name] = b.decode("utf-8", "replace")
                return files, paths
            except Exception as e:  # network flake, 404 on one URL form, size cap
                last = e
                if "larger than" in str(e):
                    raise
        time.sleep(2 * (attempt + 1))
    raise IOError("could not fetch %s: %s" % (spec, last))


# ━━━ CLI ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
_ICON = {"CRITICAL": "\U0001F534", "HIGH": "\U0001F7E0", "MEDIUM": "\U0001F7E1", "LOW": "\U0001F535", "SAFE": "\U0001F7E2"}


def _print(r, verbose):
    print("%s %s  [%s]  score=%d  (%d findings, %d info)" % (_ICON.get(r["risk_level"], "?"), r["target"], r["risk_level"],
                                                              r["risk_score"], r["total_findings"], r["info_count"]))
    if r["surfaces"]:
        print("    surfaces: " + ", ".join("%s(%d)" % (k, len(v)) for k, v in sorted(r["surfaces"].items())))
    if r["autorun"]:
        print("    runs on open/trust: " + "; ".join("%s (%s)" % (a["what"], a["file"]) for a in r["autorun"][:8]))
    for f in r["findings"]:
        print("    %-8s %s  %s:%s" % (f["severity"], f["name"], f["file"], f["line"]))
        print("             %s" % (f["context"] or f["matched"] or f["description"])[:200])
    if verbose:
        for f in r["info"]:
            print("    INFO     %s  %s:%s  %s" % (f["name"], f["file"], f["line"], f["description"][:120]))


# ---------------------------------------------------------------------------
# Pipeline output shared by the eltociear/*-audit family: --json / --sarif / --fail-on
# (this block is kept identical across the family; see "Output formats" in the README)
# ---------------------------------------------------------------------------
FAMILY_SCHEMA = "eltociear-audit/1"
TOOL_NAME = "repo-trust-audit"
TOOL_URI = "https://github.com/eltociear/repo-trust-audit"
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
    max_mb = 400
    if "--max-mb" in args:
        i = args.index("--max-mb"); max_mb = int(args[i + 1]); del args[i:i + 2]
    if args and args[0] == "--list-surfaces":
        for kind, pats in SURFACES:
            print("%-20s %s" % (kind, "  ".join(pats)))
        return 0
    results = []
    if args and args[0] == "--text":
        txt = " ".join(args[1:]) if len(args) > 1 else sys.stdin.read()
        results.append(scan_files({"AGENTS.md": txt}, label="<text>"))
    elif args and args[0] == "--github":
        for spec in args[1:]:
            try:
                files, paths = load_github(spec, max_mb=max_mb)
            except Exception as e:
                print("error: %s" % e, file=sys.stderr)
                return 1
            results.append(scan_files(files, paths, label=spec))
    else:
        for a in args:
            if os.path.isdir(a):
                files, paths = load_dir(a)
                results.append(scan_files(files, paths, label=a))
            elif os.path.isfile(a):
                name = os.path.basename(a)
                guess = {"settings.json": ".claude/settings.json" if "/.claude/" in a.replace("\\", "/") else ".vscode/settings.json",
                         "tasks.json": ".vscode/tasks.json", "devcontainer.json": ".devcontainer/devcontainer.json",
                         "mcp.json": ".vscode/mcp.json", "hooks.json": ".cursor/hooks.json"}.get(name, name)
                t = _read(a) or ""
                results.append(scan_files({guess: t}, label=a))
            else:
                print("error: no such file or directory: %s" % a, file=sys.stderr)
                return 1
    if not as_json:
        for r in results:
            _print(r, verbose)
    return family_emit(results, fam)


if __name__ == "__main__":
    sys.exit(main())
