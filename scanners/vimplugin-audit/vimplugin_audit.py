#!/usr/bin/env python3
"""vimplugin-audit - scan Vim and Neovim plugins for MALICIOUS code before your editor sources it.

A Vim / Neovim plugin is arbitrary code that runs with your user's privileges, environment and
network the moment the editor starts: every file under `plugin/`, `after/plugin/` and `ftdetect/`
is sourced at EVERY startup, `autoload/` and `lua/` modules run on first use, `ftplugin/` on the
first buffer of a filetype, and plugin managers run `build =` / `do:` / `run =` hooks (and the
plugin's own `build.lua`, `Makefile`, `install.sh`, `package.json` lifecycle scripts) at install
time. Nobody reviews any of it - the plugin manager clones HEAD and the next `nvim` runs it.

This is a deterministic (no LLM) static scan for the shapes that turn that into theft or a
backdoor: download-and-execute (`curl | sh`, auto-updaters that fetch code and `:source` /
`dofile` / `load()` it), obfuscated `loadstring(base64...)` / `string.char` payloads, reading
`~/.ssh` / cloud / git credentials or API-key environment variables and sending them off-host,
whole-environment dumps, reverse shells, persistence (shell rc files, authorized_keys, cron,
LaunchAgents), modeline expression exploits (the CVE-2019-12735 shape), turning `modelineexpr` /
`exrc` back on or overriding `vim.secure`, and AI-assistant plugins that send the user's API key to a
host other than the service it belongs to - weighted by WHEN the code runs (startup and install
time -> CRITICAL).

Precision-tuned to near-zero false positives: what plugins do every day (`system('git ...')`,
`jobstart` of linters and LSP servers, `io.popen`, `vim.uv.spawn`, installers that download a
release binary from GitHub, AI plugins sending buffer text to the API whose key the user gave them,
`loadstring` of a session cache) is reported as informational context and never inflates the risk
score. Risk comes from specific COMBINATIONS and sinks. Nothing from the plugin is ever sourced,
required or executed.

Usage:
  python vimplugin_audit.py <plugin_dir> [...]          # scan a checkout
  python vimplugin_audit.py owner/repo[@ref] [...]      # fetch the GitHub tarball and scan
  python vimplugin_audit.py --installed                 # scan every plugin lazy.nvim / packer /
                                                        #   vim-plug / native packages installed
  python vimplugin_audit.py --list plugins.txt          # one owner/repo per line (# comments ok)
  python vimplugin_audit.py --text "some vimscript"     # scan a string (as startup Vimscript)
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
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request

__version__ = "0.2.0"

VIM_EXT = (".vim", ".vim9", ".vimrc")
LUA_EXT = (".lua", ".fnl", ".moon")
PY_EXT = (".py",)
JS_EXT = (".ts", ".js", ".mjs", ".cjs")
SH_EXT = (".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd")
TEXT_EXT = (".txt", ".md", ".markdown", ".rst", ".jax", ".cnx")
MAX_FILE = 3000000      # bytes; larger files are generated tables / vendored bundles
MAX_TOTAL = 30000000    # bytes of text scanned per plugin
SEG = 8192
SEG_OVERLAP = 1024
LONG_LINE = 20000
MAX_HITS = 25

# Hard-coded collectors: stealers ship these; legitimate plugins take webhook URLs from the user.
STRONG_EXFIL = (
    r"(?:discord(?:app)?\.com/api/webhooks/\d{6,20}/[\w-]{10,}|api\.telegram\.org/bot[\w:-]{8,}/send|"
    r"hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/\w{10,}|"
    r"\bwebhook\.site/|\.m\.pipedream\.net|\beo[\w]{10,}\.m\.pipedream|requestbin\.(?:com|net|io)|\brequestb\.in\b|"
    r"requestcatcher\.com|beeceptor\.com|oastify\.com|\boast\.(?:fun|me|pro|live|site|online)\b|"
    r"\binteract\.sh\b|interactsh|burpcollaborator\.net|canarytokens\.com|dnslog\.cn|\bceye\.io\b|requestrepo\.com)"
)
# Tunnels / paste / free-hosting: legitimate in docs and for self-hosted proxies; meaningful in combinations.
SOFT_HOST = (r"(?:ngrok(?:-free)?\.(?:io|app|dev)|\.trycloudflare\.com|serveo\.net|localtunnel\.me|\bloca\.lt\b|"
             r"pastebin\.com/raw|paste\.ee/r|hastebin\.com/raw|\btransfer\.sh\b|\bfile\.io/|"
             r"[\w-]+\.workers\.dev\b|[\w-]+\.repl\.co\b|[\w-]+\.glitch\.me\b|[\w-]+\.duckdns\.org\b|"
             r"[\w-]+\.ddns\.net\b|[\w-]+\.no-ip\.\w+)")
RAW_IP_URL = (r"https?://(?!(?:127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|"
              r"100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|2(?:2[4-9]|[3-5]\d)\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.))"
              r"\d{1,3}(?:\.\d{1,3}){3}")
# A shell / process sink in Vimscript, Lua, Python, TS or shell.
SHELL_SINK = (r"(?:\bsystem(?:list)?\s{0,4}\(|\bjobstart\s{0,4}\(|\bjob_start\s{0,4}\(|\btermopen\s{0,4}\(|"
              r"\bvim\.system\s{0,4}\(|\b(?:vim\.loop|vim\.uv|uv|luv|loop)\.spawn\s{0,4}\(|\bio\.popen\s{0,4}\(|"
              r"\bos\.execute\s{0,4}\(|\bterm_start\s{0,4}\(|^\s*(?:silent!?\s+|exe(?:cute)?\s+['\"])?!|"
              r"\bexe(?:cute)?\s+['\"]!|\bsubprocess\.|\bos\.system\s{0,4}\(|\bos\.popen\s{0,4}\(|"
              r"Deno\.(?:Command|run)\b|child_process|\bexecSync\b|\bspawnSync?\s{0,4}\()")
# Something that actually SENDS / RECEIVES over the network.
NET_SEND = (r"(?:['\"\[{,(]\s{0,4}(?:curl|wget)\b|\bcurl\s+(?:-[\w-]+\s+)*['\"]?(?:https?:|\$|\w)|"
            r"\bwget\s+(?:-[\w-]+\s+)*['\"]?https?:|plenary\.curl|require\s*\(?\s*['\"](?:plenary\.curl|socket\.http|ssl\.https|http\.request|"
            r"resty\.http|curl|lcurl)['\"]|\bvim\.net\.request\b|\bnew_tcp\s*\(|\bsockconnect\s*\(|\bch_open\s*\(|"
            r"\burllib\.request\b|\burlopen\s*\(|\brequests\.(?:get|post|put|request|Session)\b|http\.client\.HTTPS?Connection|"
            r"\bsocket\.(?:socket|create_connection)\b|\bfetch\s*\(|XMLHttpRequest|\bInvoke-WebRequest\b|\biwr\b|"
            r"DownloadString|DownloadFile|\bNread\b|\bnetrw#NetRead)")
CHECKSUM = r"(?:sha256|sha512|sha1sum|shasum|checksum|blake3|b2sum|md5sum|digest|minisign|gpg\s+--verify)"
# Environment variables that hold credentials for a specific service.
KEY_ENV = (r"(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|CLAUDE_API_KEY|GEMINI_API_KEY|GOOGLE_API_KEY|MISTRAL_API_KEY|"
           r"GROQ_API_KEY|DEEPSEEK_API_KEY|OPENROUTER_API_KEY|COHERE_API_KEY|HUGGINGFACE\w*TOKEN|HF_TOKEN|"
           r"AZURE_OPENAI_API_KEY|PERPLEXITY_API_KEY|XAI_API_KEY|TOGETHER_API_KEY|FIREWORKS_API_KEY|"
           r"CODEIUM_API_KEY|TABNINE\w*KEY|GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|NPM_TOKEN|AWS_SECRET_ACCESS_KEY|"
           r"AWS_SESSION_TOKEN|SLACK_TOKEN|DISCORD_TOKEN)")
# Hosts that a credential-holding plugin legitimately talks to (provider APIs, proxies users configure,
# GitHub / GitLab). A key sent elsewhere is the review signal.
OK_HOSTS = (r"(?:openai\.com|anthropic\.com|claude\.ai|googleapis\.com|google\.com|azure\.com|microsoft\.com|"
            r"mistral\.ai|groq\.com|deepseek\.com|openrouter\.ai|cohere\.(?:ai|com)|huggingface\.co|hf\.co|"
            r"perplexity\.ai|x\.ai|together\.(?:ai|xyz)|fireworks\.ai|codeium\.com|windsurf\.com|tabnine\.com|"
            r"github\.com|githubusercontent\.com|githubcopilot\.com|gitlab\.com|bitbucket\.org|sourcegraph\.com|"
            r"amazonaws\.com|aws\.amazon\.com|cloudflare\.com|ollama\.(?:ai|com)|localhost|127\.0\.0\.1|0\.0\.0\.0|"
            r"supermaven\.com|codegeex\.cn|bigmodel\.cn|moonshot\.cn|dashscope\.aliyuncs\.com|baidu\.com|"
            r"replicate\.com|cerebras\.ai|novita\.ai|deepinfra\.com|lmstudio\.ai|phind\.com|tavily\.com|"
            r"serper\.dev|kagi\.com|jina\.ai|voyageai\.com|qwen|siliconflow\.cn|volces\.com|minimax|"
            r"example\.(?:com|org)|npmjs\.org|slack\.com|discord\.com)")

PATTERNS = {
    "critical": [
        {"id": "download_execute", "name": "Download & Execute",
         "desc": "Fetches remote content and pipes it straight into a shell / interpreter",
         "regexes": [
             r"curl\s+[^\n|;\"']{0,200}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?|perl|ruby|node)\b",
             r"wget\s+[^\n|;\"']{0,200}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?|perl)\b",
             r"wget\s+[^\n]{0,120}-O-?\s*-\s*\|\s*(?:sh|bash)",
             r"(?:sh|bash|zsh|python3?)\s*<\s*\(\s*(?:curl|wget)",
             r"(?:iex|Invoke-Expression)\s*\(?\s*\(?\s*(?:New-Object\s+Net\.WebClient|iwr|Invoke-WebRequest|irm\b)",
             r"\birm\s+[^\n|]{0,160}\|\s*iex\b",
         ]},
        {"id": "obfuscated_exec", "name": "Obfuscated Code Execution",
         "desc": "Decodes base64 / char-code / hex text and executes it (load, loadstring, execute, luaeval, exec)",
         "regexes": [
             r"(?<![\w.])(?:loadstring|load)\s*\(\s*(?:(?:vim\.base64\.decode|vim\.fn\.base64\w*|base64\w*\.decode|from_base64|b64dec\w*|"
             r"dec(?:ode)?64|unb64)\s*\(\s*['\"][A-Za-z0-9+/]{24,}={0,2}['\"]|string\.char\s*\(\s*(?:\d{1,3}\s*,\s*){24,}|string\.char\s*\(\s*(?:table\.)?unpack|"
             r"\(?\s*['\"][A-Za-z0-9+/]{120,}={0,2}['\"]\s*\)?\s*:\s*gsub|['\"](?:\\\d{1,3}){40,})",
             r"(?<![\w.])(?:loadstring|load)\s*\(\s*\w{1,20}\s*\(\s*['\"][A-Za-z0-9+/]{160,}={0,2}['\"]",
             r"\bexe(?:cute)?\s+(?:py3eval|pyeval|luaeval)\s*\(\s*['\"][^\n]{0,80}(?:b64decode|base64|decode\s*\()",
             r"\bexe(?:cute)?\s+[^\n]{0,40}(?:base64_decode|blob2str\s*\(\s*base64|base64#decode)",
             r"\bpy(?:thon)?3?(?:do)?\s+exec\s*\(\s*(?:__import__\s*\(\s*['\"]base64|base64\.b64decode|zlib\.decompress|bytes\.fromhex|codecs\.decode)",
             r"\bluaeval\s*\(\s*['\"](?:loadstring|load)\s*\(\s*(?:vim\.base64|string\.char)",
             r"(?<![\w.])(?:exec|eval)\s*\(\s*(?:__import__\s*\(\s*['\"](?:base64|zlib|marshal)|base64\.b64decode|zlib\.decompress|marshal\.loads|bytes\.fromhex)",
             r"\beval\s*\(\s*atob\s*\(|new\s+Function\s*\(\s*atob\s*\(",
         ]},
        {"id": "reverse_shell", "name": "Reverse Shell",
         "desc": "Spawns an interactive shell bound to a network socket",
         "regexes": [
             r"/dev/tcp/[\w.\-]+/\d+",
             r"bash\s+-i\s*>&",
             r"\bnc(?:at)?\s+(?:-\w+\s+)*-e\s+/bin/(?:ba)?sh",
             r"\bmkfifo\s+[^\n]{0,60}\bnc\s",
             r"os\.dup2\s*\(\s*\w+\.fileno\s*\(\s*\)\s*,\s*[012]\s*\)",
             r"pty\.spawn\s*\(\s*['\"]/bin/(?:ba)?sh",
         ]},
        {"id": "destructive", "name": "Destructive Payload",
         "desc": "Wipes the home directory / filesystem",
         "regexes": [
             r"rm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+(?:--no-preserve-root\s+)?(?:~/?|\$HOME/?|/|\$\{HOME\}/?)(?:\s|[\"'`;)\]]|$)",
             r"delete\s*\(\s*(?:expand\s*\(\s*)?['\"](?:~|\$HOME)/?['\"]\s*\)?\s*,\s*['\"]rf['\"]",
             r"vim\.fn\.delete\s*\(\s*(?:os\.getenv\s*\(\s*['\"]HOME['\"]\s*\)|vim\.env\.HOME|vim\.fn\.expand\s*\(\s*['\"]~['\"]\s*\))\s*,\s*['\"]rf['\"]",
             r"shutil\.rmtree\s*\(\s*(?:os\.path\.expanduser\s*\(\s*['\"]~['\"]|Path\.home\s*\(\s*\))",
         ]},
        {"id": "modeline_exploit", "name": "Modeline Expression Exploit",
         "desc": "A modeline sets an expression option that runs commands when the file is opened (CVE-2019-12735 shape)",
         "regexes": [
             r"(?:^|\s)(?:vi|vim|Vim|ex)(?:[<=>]?\d+)?:[^\n]{0,200}?\b(?:fde|foldexpr|inex|includeexpr|fex|formatexpr|inde|indentexpr|"
             r"fdt|foldtext|tfu|tagfunc|ofu|omnifunc|cfu|completefunc|kp|keywordprg|stl|statusline|tal|tabline|"
             r"ccv|charconvert|pex|patchexpr|dex|diffexpr|qftf|quickfixtextfunc|ofu)\s*=[^\n]{0,200}?"
             r"(?:assert_fails|system\s*\(|systemlist|execute\s*\(|source|libcall|luaeval|py3?eval|perleval|rubyeval|"
             r"job_start|jobstart|term_start|feedkeys|\\!|\bcall\s|:!)",
         ]},
        {"id": "worm_propagation", "name": "Self-Propagation (Worm)",
         "desc": "Uses stolen registry / GitHub tokens to republish packages or push repositories",
         "regexes": [
             r"trufflehog[^\n]{0,80}(?:filesystem|github|--json)",
             r"github\.com/trufflesecurity/trufflehog/releases",
             r"npm\s+publish[^\n]{0,120}(?:NPM_TOKEN|_authToken)",
             r"(?:NPM_TOKEN|_authToken)[^\n]{0,200}npm\s+publish",
         ]},
    ],
    "high": [
        {"id": "exfil_host", "name": "Exfiltration Endpoint",
         "desc": "Hard-codes a webhook / OAST / request-bin collector host",
         "regexes": [STRONG_EXFIL]},
        {"id": "persistence", "name": "Persistence Write",
         "desc": "Writes shell rc files, authorized_keys, cron, LaunchAgents, autostart or systemd units",
         "regexes": [
             r"(?:writefile|io\.open|vim\.fn\.writefile|open\s*\(|>>?\s*)[^\n]{0,160}(?:\.bashrc|\.zshrc|\.bash_profile|\.zprofile|\.zshenv|"
             r"[\"'/]\.profile\b|authorized_keys|LaunchAgents/|LaunchDaemons/|\.config/autostart|systemd/user/|/etc/cron|/etc/rc\.local)",
             r"(?:\.bashrc|\.zshrc|\.bash_profile|\.zprofile|\.zshenv|authorized_keys|LaunchAgents/|\.config/autostart|systemd/user/)[^\n]{0,160}(?:writefile|\bw\+?b?['\"]|\ba\+?['\"]|['\"]a['\"]|:write\s*\()",
             r"crontab\s+-(?!l\b)[a-z]?\s*-?\s*(?:\S+)?|\(\s*crontab\s+-l[^\n]{0,80}\|\s*crontab\s+-",
             r"\bschtasks\s+/create|\bCurrentVersion\\\\Run\b|reg\s+add\s+[^\n]{0,60}\\Run\b",
         ]},
        {"id": "secure_bypass", "name": "Security Feature Bypass",
         "desc": "Re-enables modeline expressions, overrides vim.secure / trust prompts, or disables 'secure'",
         "regexes": [
             r"^\s*(?:se(?:t|tg|tglobal|tl)?|let\s+&(?:g:|l:)?)\s*(?:[\w&:]+\s+)*(?:modelineexpr|mle)(?:\s*=\s*1|\b(?!\s*=\s*0))",
             r"vim\.o(?:pt|pt_global)?\.(?:modelineexpr|mle)\s*=\s*true|vim\.opt\.modelineexpr\s*:\s*\w+\s*\(\s*true|"
             r"nvim_set_option(?:_value)?\s*\(\s*['\"](?:modelineexpr|mle)['\"]\s*,\s*(?:true|1)",
             r"vim\.secure\.(?:read|trust)\s*=\s*(?:function|\w)",
             r"vim\.secure\s*=\s*(?:\{|nil|function)",
             r"\brawset\s*\(\s*vim\.secure\s*,",
         ]},
        {"id": "credential_send", "name": "Credential Sent Off-Host",
         "desc": "Reads an SSH / cloud / git credential file and names an external destination on the same line",
         "regexes": [
             r"(?:\.ssh/id_\w+|\.aws/credentials|\.git-credentials|\.netrc\b|\.docker/config\.json|\.kube/config|gh/hosts\.yml|"
             r"\.npmrc|\.pypirc|\.config/gcloud|github-copilot/(?:hosts|apps)\.json)[^\n]{0,240}"
             r"(?:" + STRONG_EXFIL + r"|" + SOFT_HOST + r"|" + RAW_IP_URL + r")",
         ]},
    ],
    "medium": [
        {"id": "raw_ip_url", "name": "Raw-IP URL",
         "desc": "Contacts a public IP address directly instead of a hostname",
         "regexes": [RAW_IP_URL]},
        {"id": "tls_disabled", "name": "TLS Verification Disabled",
         "desc": "Turns off certificate checking for a download",
         "regexes": [r"\bcurl\s+[^\n]{0,120}(?:\s-k\b|\s-[a-zA-Z]*k[a-zA-Z]*\s|--insecure)", r"wget\s+[^\n]*--no-check-certificate",
                     r"verify\s*=\s*False", r"rejectUnauthorized\s*:\s*false", r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"]},
        {"id": "credential_read", "name": "Private Credential Read",
         "desc": "Reads SSH private keys, cloud / git / registry credentials or another tool's token file",
         "regexes": [r"\.ssh/id_(?:rsa|dsa|ecdsa|ed25519)\b(?!\.pub)", r"\.aws/credentials", r"\.git-credentials",
                     r"[~/]\.netrc\b", r"\.docker/config\.json", r"gh/hosts\.yml", r"\.pypirc", r"\.config/gcloud/(?:credentials|application_default)",
                     r"(?:\.kube/config)\b", r"\bkeychain\b[^\n]{0,40}find-(?:generic|internet)-password|security\s+find-(?:generic|internet)-password",
                     r"\bLogin Data\b|Local Extension Settings|cookies\.sqlite|key4\.db|logins\.json",
                     r"nkbihfbeogaeaoehlefnkodbefgpgknn|wallet\.dat|Exodus/exodus\.wallet"]},
        {"id": "editor_config_write", "name": "Editor Config Write",
         "desc": "Writes the user's vimrc / init.lua / another plugin's files (persistence inside the editor)",
         "regexes": [
             r"(?:writefile|io\.open|vim\.fn\.writefile)\s*\([^\n]{0,160}(?:\$MYVIMRC|['\"/]\.vimrc['\"]|['\"/]_vimrc['\"]|nvim/init\.(?:lua|vim)['\"]|stdpath\s*\(\s*['\"]config['\"]\s*\)\s*\.\.\s*['\"]/init\.(?:lua|vim))",
             r"(?:\$MYVIMRC|vim\.env\.MYVIMRC)[^\n]{0,80}(?:writefile|['\"]a['\"]\s*\)|['\"]w['\"]\s*\))",
         ]},
        {"id": "exrc_enable", "name": "exrc Enabled",
         "desc": "Turns on 'exrc' so project-local .vimrc / .nvim.lua files run (vim.secure prompts in Neovim)",
         "regexes": [r"^\s*(?:se(?:t|tg|tglobal)?)\s+(?:[\w&:]+\s+)*(?:exrc|ex)\b(?!\s*=\s*0|\?|&)(?!\w)",
                     r"vim\.o(?:pt)?\.exrc\s*=\s*true", r"^\s*(?:se(?:t|tg)?)\s+(?:[\w&:]+\s+)*nosecure\b"]},
        {"id": "encoded_payload", "name": "Encoded Payload",
         "desc": "A long char-code / escaped-byte literal (obfuscation; alone it may be a table or icon set)",
         "regexes": [r"string\.char\s*\(\s*(?:\d{1,3}\s*,\s*){60,}", r"['\"](?:\\\d{2,3}){120,}['\"]",
                     r"(?:nr2char\s*\(\s*\d+\s*\)\s*\.\s*){30,}"]},
    ],
    "low": [],
    # Context: reported, never scored. Capabilities popular plugins use daily.
    "info": [
        {"id": "process_spawn", "name": "Process Spawning",
         "desc": "Runs external commands (git, linters, LSP servers, formatters...)",
         "regexes": [SHELL_SINK]},
        {"id": "network", "name": "Network Access",
         "desc": "Makes outbound HTTP / socket calls (curl, plenary.curl, vim.net, sockets)",
         "regexes": [NET_SEND]},
        {"id": "dynamic_code", "name": "Dynamic Code",
         "desc": "load / loadstring / dofile / luaeval / execute of a computed string",
         "regexes": [r"(?<![\w.])(?:loadstring|load|loadfile|dofile)\s*\(", r"\bluaeval\s*\(", r"\bexe(?:cute)?\s+[a-z]:\w+",
                     r"\b(?:py3?eval|pyxeval|rubyeval|perleval)\s*\(", r"(?<![\w.])(?:exec|eval)\s*\("]},
        {"id": "env_read", "name": "Environment Access",
         "desc": "Reads environment variables",
         "regexes": [r"\bos\.getenv\s*\(", r"\bvim\.env\.\w+", r"\$[A-Z_]{3,}\b", r"\benviron\s*\(\s*\)", r"os\.environ", r"Deno\.env"]},
        {"id": "api_key_env", "name": "API Key From Environment",
         "desc": "Reads a service API key / token from the environment (AI assistants, GitHub clients)",
         "regexes": [KEY_ENV]},
        {"id": "ssh_config", "name": "SSH Config / Known Hosts",
         "desc": "Reads ~/.ssh/config or known_hosts (remote-editing and host-picker plugins)",
         "regexes": [r"\.ssh/(?:config|known_hosts)\b", r"\.ssh/id_\w+\.pub"]},
        {"id": "binary_download", "name": "Binary Download",
         "desc": "Downloads a prebuilt binary / release asset (installers for native helpers)",
         "regexes": [r"github\.com/[\w.-]+/[\w.-]+/releases/(?:download|latest)", r"api\.github\.com/repos/[\w.-]+/[\w.-]+/releases"]},
        {"id": "soft_host", "name": "Tunnel / Paste / Free-Hosting Host",
         "desc": "Names a tunnel, paste, or free-hosting domain (self-hosted proxies, docs)",
         "regexes": [SOFT_HOST]},
        {"id": "script_interface", "name": "Script Interface",
         "desc": "Uses :python3 / :ruby / :perl / :lua heredocs or remote-plugin hosts",
         "regexes": [r"^\s*(?:py(?:thon)?3?|pyx|rub(?:y)?|perl|lua)\s*<<", r"^\s*(?:py3|python3|pyx)file\s"]},
        {"id": "secure_option", "name": "Security Option Touched",
         "desc": "Sets modeline / modelines / secure / exrc in a way that does not weaken them",
         "regexes": [r"\b(?:modelineexpr|nomodeline|modelines\s*=\s*0|vim\.secure\.(?:read|trust)\s*\()"]},
    ],
}

SEVERITY_SCORE = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "SAFE": 0}
_CASE_SENSITIVE = {"env_read", "api_key_env", "obfuscated_exec", "modeline_exploit", "secure_bypass", "exrc_enable"}
_COMPILED = [(sev, pg, re.compile(rx, re.M | (0 if pg["id"] in _CASE_SENSITIVE else re.IGNORECASE)))
             for sev, groups in PATTERNS.items() for pg in groups for rx in pg["regexes"]]
NEEDLES = {
    "download_execute": ("curl", "wget", "iex", "invoke-expression", "irm "),
    "obfuscated_exec": ("load", "exe", "py", "exec", "eval", "function"),
    "reverse_shell": ("/dev/tcp", "bash -i", "nc ", "ncat", "mkfifo", "dup2", "pty.spawn"),
    "destructive": ("rm -", "delete", "rmtree"),
    "modeline_exploit": ("vi:", "vim:", "ex:", "vim<", "vim=", "vim>", "vim7", "vim8", "vim9"),
    "worm_propagation": ("trufflehog", "npm publish"),
    "exfil_host": ("discord", "telegram", "slack", "webhook.site", "pipedream", "requestb", "requestcatcher",
                   "beeceptor", "oast", "interact", "burpcollaborator", "canarytokens", "dnslog", "ceye", "requestrepo"),
    "persistence": ("bashrc", "zshrc", "bash_profile", "zprofile", "zshenv", ".profile", "authorized_keys",
                    "launchagents", "launchdaemons", "autostart", "systemd/user", "/etc/cron", "rc.local", "crontab",
                    "schtasks", "currentversion", "reg add"),
    "secure_bypass": ("modelineexpr", "mle", "vim.secure"),
    "credential_send": (".ssh/id_", ".aws/", "git-credentials", ".netrc", ".docker/", ".kube/", "hosts.yml",
                        ".npmrc", ".pypirc", "gcloud", "github-copilot"),
    "raw_ip_url": ("http",),
    "tls_disabled": ("-k", "insecure", "no-check-certificate", "verify", "rejectunauthorized", "tls_reject"),
    "credential_read": (".ssh/id_", ".aws/credentials", "git-credentials", ".netrc", ".docker/config", "hosts.yml",
                        ".pypirc", "gcloud", ".kube/config", "find-generic", "find-internet", "login data",
                        "extension settings", "cookies.sqlite", "key4.db", "logins.json", "nkbihf", "wallet.dat", "exodus"),
    "editor_config_write": ("vimrc", "init.lua", "init.vim"),
    "exrc_enable": ("exrc", "nosecure"),
    "encoded_payload": ("string.char", "\\", "nr2char"),
    "process_spawn": ("system", "jobstart", "job_start", "termopen", "spawn", "popen", "execute", "!", "subprocess",
                      "deno.", "child_process", "execsync", "term_start"),
    "network": ("curl", "wget", "vim.net", "new_tcp", "sockconnect", "ch_open", "urllib", "urlopen", "requests.",
                "http.client", "socket", "fetch", "xmlhttprequest", "invoke-webrequest", "iwr", "download", "nread",
                "netrw", "http"),
    "dynamic_code": ("load", "dofile", "luaeval", "exe", "eval", "exec"),
    "env_read": ("getenv", "vim.env", "$", "environ", "deno.env"),
    "api_key_env": ("_KEY", "_TOKEN"),
    "ssh_config": (".ssh/",),
    "binary_download": ("/releases",),
    "soft_host": ("ngrok", "trycloudflare", "serveo", "localtunnel", "loca.lt", "pastebin", "paste.ee", "hastebin",
                  "transfer.sh", "file.io", "workers.dev", "repl.co", "glitch.me", "duckdns", "ddns.net", "no-ip"),
    "script_interface": ("<<", "file "),
    "secure_option": ("modeline", "vim.secure"),
}
LINE_ONCE = {"process_spawn", "network", "dynamic_code", "env_read", "api_key_env", "ssh_config", "binary_download",
             "soft_host", "script_interface", "secure_option"}
NET_RE = re.compile(NET_SEND, re.IGNORECASE)
SINK_RE = re.compile(SHELL_SINK, re.IGNORECASE | re.M)
STRONG_RE = re.compile(STRONG_EXFIL, re.IGNORECASE)
SOFT_RE = re.compile(SOFT_HOST, re.IGNORECASE)
RAWIP_RE = re.compile(RAW_IP_URL)
KEY_ENV_RE = re.compile(KEY_ENV)
RAWIP_HINT = re.compile(r"://\d")
URL_RE = re.compile(r"https?://([A-Za-z0-9.-]+)(?::\d+)?[^\s'\"`)\]]*")
OK_HOST_RE = re.compile(OK_HOSTS + r"$", re.IGNORECASE)
BLOB_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{4096,}")
ENV_DUMP_RE = re.compile(r"\benviron\s*\(\s*\)|pairs\s*\(\s*vim\.fn\.environ\s*\(\s*\)\s*\)|vim\.fn\.environ\s*\(\s*\)|"
                         r"\benv\s*\|\s*(?:base64|curl|nc)|\bprintenv\b[^\n]{0,40}\|\s*(?:curl|nc|base64)|"
                         r"json\.dumps\s*\(\s*dict\s*\(\s*os\.environ|Deno\.env\.toObject\s*\(|JSON\.stringify\s*\(\s*process\.env\s*\)")
# Fetched-code execution: a fetch whose result is loaded / sourced in the same file.
LOAD_FETCHED_RE = re.compile(
    r"(?<![\w.])(?:loadstring|load)\s*\(\s*(?:res(?:ponse|p|ult)?|body|data|code|payload|script|out(?:put)?|content|chunk|src|lines|text)\b"
    r"(?:\s*\.\s*(?:body|stdout|text|data))?|(?<![\w.])(?:loadstring|load)\s*\(\s*\w+\.(?:body|stdout)\b|"
    r"(?<![\w.])(?:loadstring|load)\s*\(\s*(?:vim\.fn\.system|io\.popen|table\.concat\s*\(\s*vim\.fn\.systemlist)\s*\(|"
    r"\bexe(?:cute)?\s+(?:system|join\s*\(\s*systemlist)\s*\(|\bexe(?:cute)?\s+(?:s:|l:)?(?:res(?:ponse)?|body|code|payload|script|out|content)\b|"
    r"(?<![\w.])(?:dofile|loadfile)\s*\(\s*(?:tmp|tmpfile|tempfile|path|file|f|fname|dest|target|out)\w*\s*\)|"
    r"\bvim\.cmd\.?(?:source)?\s*\(?\s*\(?\s*['\"]source\s+['\"]?\s*\.\.\s*(?:tmp|path|file|dest|target)\w*|"
    r"\b(?:so(?:urce)?|luafile|runtime)\s+(?:`|\$TMP|/tmp/)|\bexe(?:cute)?\s+['\"](?:so(?:urce)?|luafile)\s+['\"]\s*\.\s*(?:s:|l:)?(?:tmp|path|file|dest|target)\w*")
REMOTE_CODE_URL_RE = re.compile(r"https?://[^\s'\"]{4,200}\.(?:lua|vim|sh|py|ps1)(?:\?[^\s'\"]*)?['\"]|"
                                r"gist\.githubusercontent\.com|raw\.githubusercontent\.com|pastebin\.com|paste\.ee|hastebin", re.I)


def _item(sev, pid, name, desc, path, n, matched, ctx):
    return {"severity": sev, "id": pid, "name": name, "description": desc, "file": path,
            "line": n, "matched": matched[:120], "context": ctx.strip()[:200]}


def _strip_blobs(text):
    return BLOB_RE.sub(lambda m: "<blob:%d>" % len(m.group(0)), text)


# ---------------------------------------------------------------------------
# Execution context: WHEN does the editor run this file?
# ---------------------------------------------------------------------------
DEV_DIR = re.compile(r"(?:^|/)(?:tests?|spec|specs|testdata|test_data|__tests__|e2e|fixtures?|examples?|demos?|docs?|"
                     r"\.github|\.gitlab|\.circleci|\.devcontainer|\.vscode|benchmarks?|bench|ci|\.ci|scripts|tools|"
                     r"node_modules|vendor/bundle|\.tests|t|minimal|\.busted|screenshots?|assets|media|samples?)/", re.I)
DEV_FILE = re.compile(r"(?:^|/)(?:minimal(?:_init|_config|[-_]?vimrc)?|repro(?:duce)?|init_spec|test_?init|[\w-]+_spec|[\w-]+_test|"
                      r"\.?luacheckrc|stylua|selene|\.?busted|Rakefile|conftest|noxfile|tasks)\.(?:lua|vim|py|toml|rb)$", re.I)
DEV_FILE2 = re.compile(r"\.(?:test|spec)\.[cm]?[jt]sx?$|(?:^|/)test_[\w-]+\.py$|_test\.py$", re.I)
STARTUP_RE = re.compile(r"^(?:after/)?(?:plugin|ftdetect)/|^denops/[^/]+/main\.[jt]s$", re.I)
USE_RE = re.compile(r"^(?:after/)?(?:autoload|lua|ftplugin|syntax|indent|colors|compiler|keymap|import|"
                    r"rplugin|python3?|pythonx|ruby|perl|denops|fnl|teal|node|plugin)/", re.I)
INSTALL_NAMES = re.compile(r"^(?:build\.lua|build/[\w.-]+\.lua|install\.(?:sh|ps1|bat|cmd|py)|build\.(?:sh|ps1|bat|cmd|py)|"
                           r"setup\.(?:sh|ps1)|bootstrap\.sh|makefile|gnumakefile|justfile|[\w.-]+\.rockspec|package\.json)$", re.I)
# Hooks a plugin manager runs after cloning: lazy.nvim build=, packer run=, vim-plug do:, dein build:, pckr/mini.deps
HOOK_RE = re.compile(r"""(?:\bbuild\s*=\s*|\brun\s*=\s*|['"]?do['"]?\s*:\s*|['"]build['"]\s*:\s*|\bhook_post_update\s*=\s*|post_checkout\s*=\s*)
                         (?:\{\s*)?(['"])((?:(?!\1).){1,300})\1""", re.X)


def file_kind(path):
    low = path.lower()
    base = low.rsplit("/", 1)[-1]
    if low.endswith(VIM_EXT) or base in ("vimrc", "_vimrc", "gvimrc"):
        return "vim"
    if low.endswith(LUA_EXT):
        return "lua"
    if low.endswith(PY_EXT):
        return "python"
    if low.endswith(JS_EXT) and not low.endswith(".d.ts"):
        return "js"
    if low.endswith(SH_EXT) or base in ("makefile", "gnumakefile", "justfile"):
        return "shell"
    if base == "package.json":
        return "package"
    if base.endswith(".rockspec"):
        return "lua"
    if low.endswith(TEXT_EXT) or "/doc/" in "/" + low:
        return "text"
    return None


def context_of(path, hook_files=()):
    """startup | use | install | dev | unused"""
    low = path.lower()
    if path in hook_files:
        return "install"
    if DEV_FILE.search(low) or DEV_FILE2.search(low):
        return "dev"
    if STARTUP_RE.search(low) and not DEV_DIR.search(low):
        return "startup"
    if INSTALL_NAMES.match(low):
        return "install"
    if DEV_DIR.search(low):
        return "dev"
    if USE_RE.search(low):
        return "use"
    return "unused"


def readme_hooks(files):
    """Build commands a README / doc recommends for plugin managers (lazy build=, plug do:, packer run=)."""
    out = []
    for p, t in files.items():
        low = p.lower()
        if not (re.match(r"(?:readme[\w.-]*|doc/[\w.-]+\.txt)$", low)):
            continue
        for m in HOOK_RE.finditer(t):
            cmd = m.group(2).strip()
            if not cmd or cmd.startswith((":", "<")) and not cmd.startswith(":!") or len(cmd) < 3:
                continue
            if re.match(r"^[\w.-]+/[\w.-]+$", cmd):      # a plugin name, not a command
                continue
            n = t.count("\n", 0, m.start()) + 1
            out.append((p, n, cmd))
    return out


def _windows(line):
    if len(line) <= LONG_LINE:
        yield line
        return
    pos = 0
    while pos < len(line):
        yield line[pos:pos + SEG]
        pos += SEG - SEG_OVERLAP


def _is_comment(s, kind):
    if kind == "vim":
        return s.startswith('"') and not re.match(r'"[^"\n]*"\s*[,)\]]', s) or s.startswith("#") and not s.startswith("#{")
    if kind == "lua":
        return s.startswith("--")
    if kind in ("python", "shell"):
        return s.startswith("#") and not s.startswith("#!")
    if kind == "js":
        return s.startswith("//") or s.startswith("* ") or s.startswith("/*")
    return False


MSG_RE = re.compile(r"^\s*(?:echo(?:m|msg|err|errmsg|n|hl|w|window)?\b|call\s+(?:s:|\w+#)*(?:warn|error|echo|notify|log|msg)\w*\s*\(|"
                    r"(?:vim\.)?(?:notify|print|error|warn|log\w*)\s*\(|vim\.api\.nvim_(?:echo|err_write\w*|out_write)\s*\(|"
                    r"(?:local\s+)?\w*(?:msg|message|hint|help|usage|instructions?|text|desc(?:ription)?)\w*\s*=|console\.\w+\s*\(|"
                    r"-?\s*['\"]|\[\[|let\s+[gslb]:\w*(?:msg|message|hint|help|usage)\w*\s*=)", re.I)


BUNDLE_BYTES = 200000
# In a bundled / vendored JS file (a language server shipped inside the plugin) only the
# unambiguous attack shapes are run: the rest is lodash / node internals and costs seconds per file.
BUNDLE_KEEP = {"download_execute", "obfuscated_exec", "reverse_shell", "exfil_host", "credential_send",
               "worm_propagation", "network", "process_spawn"}


def _is_bundle(path, text, kind):
    low = path.lower()
    return (kind == "js" and (len(text) > BUNDLE_BYTES or low.endswith(".min.js") or
                              re.search(r"(?:^|/)(?:dist|build|out|lib|vendor|bundle)/", low) is not None)) or \
        len(text) > 1500000


def _own_re(label):
    """github.com/<owner>/<repo> and raw.githubusercontent.com/<owner>/<repo> of the plugin being scanned."""
    m = re.match(r"^([\w.-]+)/([\w.-]+?)(?:\.git)?(?:@.*)?$", label or "")
    if not m:
        return None
    return re.compile(r"(?:github\.com|githubusercontent\.com)/%s/%s\b" % (re.escape(m.group(1)), re.escape(m.group(2))), re.I)


SH_MSG_RE = re.compile(r"^\s*(?:echo|printf|print|say|info|warn|log|msg|die|error|Write-(?:Host|Output))\b", re.I)


def _in_quotes(line, col):
    """Is column col inside a quoted string on this line (outermost quote type)?"""
    q = None
    i = 0
    while i < col and i < len(line):
        c = line[i]
        if c == "\\" and q == '"':
            i += 2
            continue
        if q is None and c in "\"'":
            q = c
        elif c == q:
            q = None
        i += 1
    return q is not None


def _scan_text(text, path, findings, info, kind, ctx, own=None):
    """Line pass + file-level combination rules. ctx: startup|use|install|dev|unused|hook."""
    bundle = _is_bundle(path, text, kind)
    text = _strip_blobs(text)
    lines = text.split("\n")
    nls = [m.start() for m in re.finditer("\n", text)]
    seen = set()
    local = []
    low = text.lower()
    for sev, pg, rx in _COMPILED:
        pid = pg["id"]
        if kind == "text" and pid != "modeline_exploit":
            continue
        if bundle and pid not in BUNDLE_KEEP:
            continue
        if pid in LINE_ONCE and (pid, 0) in seen:
            continue
        nd = NEEDLES.get(pid)
        if nd is not None and not any(x in (text if pid in _CASE_SENSITIVE and pid != "obfuscated_exec" else low) for x in nd):
            continue
        hits = 0
        for m in rx.finditer(text):
            n = bisect.bisect_right(nls, m.start()) + 1
            line = lines[n - 1]
            s = line.lstrip()
            if sev != "info" and pid != "modeline_exploit" and _is_comment(s, kind):
                continue  # comments describe; they don't execute
            if (pid, n) in seen:
                continue
            seen.add((pid, n))
            it = _item(sev.upper(), pid, pg["name"], pg["desc"], path, n, m.group(0),
                       line if len(line) < 400 else m.group(0))
            if sev != "info" and pid != "modeline_exploit" and len(line) < 2000 and \
                    (SH_MSG_RE.match(line) or (kind != "shell" and MSG_RE.match(line))) and \
                    _in_quotes(line, m.start() - (nls[n - 2] + 1 if n > 1 else 0)):
                it["severity"] = "INFO"
                it["description"] += " [inside a printed message]"
            local.append(it)
            hits += 1
            if pid in LINE_ONCE:
                seen.add((pid, 0))
                break
            if hits >= MAX_HITS:
                break
    ids = {f["id"] for f in local}
    has_net = "network" in ids
    has_sink = "process_spawn" in ids
    def has(pid):
        return any(x in low for x in NEEDLES[pid])
    strong = has("exfil_host") and bool(STRONG_RE.search(text))
    rawip = bool(RAWIP_HINT.search(text)) and bool(RAWIP_RE.search(text))
    collector = strong or rawip or (has("soft_host") and bool(SOFT_RE.search(text)))
    env_dump = ("environ" in low or "printenv" in low or "env |" in low or "toobject" in low or "process.env" in low) \
        and bool(ENV_DUMP_RE.search(text))

    def demote(pids, to="INFO", why=""):
        for f in local:
            if f["id"] in pids and SEV_ORDER[f["severity"]] > SEV_ORDER[to]:
                f["severity"] = to
                if why:
                    f["description"] += why

    def add(sev, pid, name, desc, n=0, matched="", context="file-level combination"):
        local.append(_item(sev, pid, name, desc, path, n, matched, context))
        ids.add(pid)

    # a pipe-to-shell inside a message / string is only executed if a shell sink is near it
    if kind in ("vim", "lua", "python", "js"):
        file_sink = has_sink
        for f in local:
            if f["id"] not in ("download_execute", "destructive", "reverse_shell") or f["severity"] == "INFO":
                continue
            near = "\n".join(lines[max(0, f["line"] - 4):f["line"] + 1])
            line = lines[f["line"] - 1]
            if SINK_RE.search(near) and not MSG_RE.match(line):
                continue
            if re.search(r"\biex\b|Invoke-Expression", f["matched"], re.I) and SINK_RE.search(near):
                continue
            if f["id"] != "download_execute" and file_sink:
                f["severity"] = "MEDIUM"
                f["description"] += " [a string with no shell sink next to it; the file does run commands elsewhere]"
                continue
            f["severity"] = "INFO"
            f["description"] += " [in a message / string with no shell sink next to it: shown to the user]"
    # ---- combination rules ---------------------------------------------------------------
    if "exfil_host" in ids and not (has_net or has_sink):
        demote({"exfil_host"}, why=" [no network sink in the file]")
    if "raw_ip_url" in ids and not ({"credential_read", "api_key_env"} & ids or env_dump):
        demote({"raw_ip_url"})          # LAN devices, self-hosted servers, docs
    if "credential_read" in ids:
        if (has_net or has_sink) and collector:
            add("CRITICAL", "credential_exfil", "Credential Exfiltration",
                "Reads a private credential store and talks to a collector / tunnel / raw-IP endpoint in the same file")
        elif not (has_net or has_sink):
            demote({"credential_read"}, why=" [never sent anywhere in this file]")
    if env_dump and (has_net or has_sink) and collector:
        add("CRITICAL", "env_exfil", "Environment Exfiltration",
            "Serialises the whole environment and talks to a collector / tunnel / raw-IP endpoint")
    # API key sent somewhere other than the service it belongs to
    if "api_key_env" in ids and (has_net or has_sink):
        hosts = sorted({h.lower().rstrip(".") for h in URL_RE.findall(text)})
        bad = [h for h in hosts if STRONG_RE.search(h + "/") or SOFT_RE.search(h) or RAWIP_RE.match("http://" + h)]
        if strong or bad:
            add("CRITICAL", "api_key_exfil", "API Key Sent to Third-Party Host",
                "Reads a service API key / token from the environment and talks to a collector / tunnel / raw-IP host "
                "(%s) - not the service the key belongs to" % ", ".join(bad[:3] or ["collector"]))
        else:
            odd = [h for h in hosts if "." in h and not OK_HOST_RE.search(h) and not re.search(r"\.(?:invalid|test|local|lan|internal)$", h)]
            for km in KEY_ENV_RE.finditer(text):
                n = bisect.bisect_right(nls, km.start()) + 1
                ln = lines[n - 1]
                hit = [h for h in odd if h in ln.lower()]
                if hit and not _is_comment(ln.lstrip(), kind):
                    add("MEDIUM", "api_key_offhost", "API Key Next to Unknown Host",
                        "An API-key variable is used on the same line as a hard-coded host that is not a known API "
                        "provider (%s) - check where the key goes" % hit[0], n, km.group(0), ln)
                    break
    # fetched code executed: auto-updater / loader shape
    def live(rx):
        """First match of rx that is not on a comment line."""
        for m in rx.finditer(text):
            n = bisect.bisect_right(nls, m.start()) + 1
            if not _is_comment(lines[n - 1].lstrip(), kind):
                return m, n
        return None, 0

    m, n = live(LOAD_FETCHED_RE) if (has_net or has_sink) else (None, 0)
    if m and (live(REMOTE_CODE_URL_RE)[0] or collector) and live(NET_RE)[0]:
        sev = "CRITICAL" if collector or re.search(r"pastebin|paste\.ee|hastebin|gist\.githubusercontent", low) else "HIGH"
        desc = "Downloads a script and loads / sources / executes it (fetch-and-exec auto-updater shape)"
        urls = [u.group(0) for u in REMOTE_CODE_URL_RE.finditer(text)]
        if sev == "HIGH" and own and urls and all(own.search(u) or "raw.githubusercontent.com" == u.lower() for u in urls) \
                and any(own.search(u) for u in urls):
            sev = "MEDIUM"          # a self-updater pulling the plugin's own file from its own repository
            desc += " [from the plugin's own repository: a self-updater, review only]"
        if sev == "HIGH" and re.search(r"(?<![\w.])load\s*\([^\n]{0,80},\s*['\"]t['\"]\s*,\s*\{\s*\}\s*\)", lines[n - 1]):
            sev = "MEDIUM"          # load(text, name, "t", {}): text-only chunk with an EMPTY environment (no os / io)
            desc += " [loaded as text with an empty environment: data, not code with library access]"
        add(sev, "remote_code_exec", "Fetched Code Executed", desc, n, m.group(0), lines[n - 1])
    # binary download made executable and run, from a non-release URL, without checksum
    if (has_net or has_sink) and re.search(r"chmod\s+\+?[0-7]*x|setfperm\s*\([^\n]{0,60}x|uv\.fs_chmod|vim\.loop\.fs_chmod", text) and \
            re.search(r"https?://[^\s'\"]{4,200}\.(?:exe|bin|elf|run|appimage)['\"]|" + RAW_IP_URL, text, re.I) and \
            not re.search(CHECKSUM, text, re.I) and not re.search(r"github\.com/[\w.-]+/[\w.-]+/releases/", text):
        add("HIGH", "dropper", "Binary Dropper",
            "Downloads a native executable from a non-release URL, marks it executable and runs it (no checksum)")
    # encoded payload fed to a loader in the same file
    if "encoded_payload" in ids and re.search(r"(?<![\w.])(?:loadstring|load)\s*\(|\bexe(?:cute)?\s", text):
        for f in local:
            if f["id"] == "encoded_payload":
                near = "\n".join(lines[max(0, f["line"] - 6):f["line"] + 6])
                if re.search(r"(?<![\w.])(?:loadstring|load)\s*\(|\bexe(?:cute)?\s", near):
                    f["severity"] = "HIGH"
                    f["description"] += " [next to load()/execute]"
    # ---- context: when does it run? ------------------------------------------------------------
    for f in local:
        if f["severity"] == "INFO":
            continue
        if f["id"] == "modeline_exploit":
            continue                      # fires when the FILE is opened, wherever it lives
        if ctx in ("dev", "unused") or kind == "text":
            if SEV_ORDER[f["severity"]] > SEV_ORDER["MEDIUM"]:
                f["severity"] = "MEDIUM" if ctx == "unused" and f["id"] not in ("download_execute",) else "INFO"
                f["description"] += " [%s: not sourced by the editor]" % ("test/doc/dev file" if ctx == "dev" else "not on the runtimepath")
            elif ctx == "dev":
                f["severity"] = "INFO"
        elif ctx in ("startup", "install", "hook") and f["severity"] == "HIGH" and f["id"] not in ("dropper",):
            f["severity"] = "CRITICAL"
            f["description"] += " [%s]" % ("sourced at EVERY editor startup" if ctx == "startup"
                                         else "runs at plugin install / update")
    for f in local:
        f["kind"] = kind
        f["exec_context"] = ctx
        (info if f["severity"] == "INFO" else findings).append(f)


def _package_scripts(text):
    try:
        d = json.loads(text)
    except ValueError:
        return ""
    sc = d.get("scripts") if isinstance(d, dict) else None
    if not isinstance(sc, dict):
        return ""
    return "\n".join("%s" % v for k, v in sc.items()
                     if k in ("preinstall", "install", "postinstall", "prepare", "prepublish") and isinstance(v, str))


MK_TARGET = re.compile(r"^([A-Za-z0-9_./%-][^:=\n]*?)\s*::?(?!=)\s*([^\n#;]*)", re.M)


def _makefile_default(text):
    """Only what plain `make` runs: the default goal, its prerequisites (recursively) and their
    recipes; variable assignments are kept. A `test:` target that curls a CI script never runs."""
    rules = {}
    order = []
    cur = None
    keep_vars = []
    for ln in text.split("\n"):
        if ln.startswith("\t") and cur is not None:
            for t in cur:
                rules[t][1].append(ln)
            continue
        m = MK_TARGET.match(ln)
        if m and not ln.startswith((" ", "\t")) and "=" not in m.group(1):
            names = m.group(1).split()
            cur = names
            for t in names:
                rules.setdefault(t, ([], []))
                rules[t][0].extend(m.group(2).split())
                if not t.startswith(".") and "%" not in t:
                    order.append(t)
            continue
        if re.match(r"^\s*[\w.-]+\s*[:?+!]?=", ln):
            keep_vars.append(ln)
        cur = None if ln.strip() else cur
    m = re.search(r"^\.DEFAULT_GOAL\s*:?=\s*(\S+)", text, re.M)
    goal = m.group(1) if m else (order[0] if order else None)
    out, todo, done = list(keep_vars), [goal] if goal else [], set()
    while todo:
        t = todo.pop()
        if t in done or t not in rules:
            continue
        done.add(t)
        out.extend(rules[t][1])
        todo.extend(rules[t][0])
    return "\n".join(out)


def scan_target(files, label=""):
    """files: {relative_path: text}. Returns an audit result dict."""
    findings, info = [], []
    total = 0
    scanned = 0
    hooks = readme_hooks(files)
    own = _own_re(label)
    code_blob = "\n".join(t for p, t in files.items() if file_kind(p) in ("vim", "lua", "python", "js")).lower()
    hook_files = set()
    for _p, _n, cmd in hooks:
        for p in files:
            base = p.rsplit("/", 1)[-1]
            if (p in cmd or ("./" + p) in cmd or (base in cmd and len(base) > 6)) and file_kind(p) in ("shell", "python", "lua", "js"):
                hook_files.add(p)
        if re.search(r"\bmake\b", cmd):
            hook_files.update(p for p in files if p.lower() in ("makefile", "gnumakefile"))
    for p, n, cmd in hooks:
        before = len(findings)
        _scan_text(cmd, p, findings, info, "shell", "hook")
        for f in findings[before:] + info:
            if f["file"] == p and f["line"] == 1 and f.get("exec_context") == "hook":
                f["line"] = n
                f["context"] = "README build hook: " + cmd[:160]
    for path in sorted(files, key=lambda p: (p.count("/"), p)):
        kind = file_kind(path)
        if not kind:
            continue
        text = files[path]
        if kind == "package":
            text = _package_scripts(text)
            kind = "shell"
            if not text:
                continue
        ctx = context_of(path, hook_files)
        low = path.lower()
        if ctx == "install" and low in ("makefile", "gnumakefile", "justfile") and path not in hook_files:
            ctx = "unused"          # nobody runs `make` unless a build hook says so
        if ctx == "install" and low in ("makefile", "gnumakefile"):
            text = _makefile_default(text)
        if kind == "shell" and ctx in ("use", "startup") and low.rsplit("/", 1)[-1] not in code_blob:
            ctx = "unused"          # the editor never sources .sh; nothing in the plugin calls this one
        if ctx == "install" and low.endswith(".py") and path not in hook_files:
            ctx = "unused"
        total += len(text)
        if total > MAX_TOTAL:
            info.append(_item("INFO", "truncated", "Scan Truncated", "Target exceeds %d bytes of text" % MAX_TOTAL,
                              path, 0, "", ""))
            break
        if kind != "text":
            scanned += 1
        _scan_text(text, path, findings, info, kind, ctx, own)
    r = _summarise(findings, info, label)
    r["scanned_files"] = scanned
    r["build_hooks"] = [c for _p, _n, c in hooks][:10]
    if not scanned:
        r["incomplete"] = True
        r["summary"] = "Nothing scannable (no Vimscript / Lua / Python / TS the editor would run)"
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


def scan(content, label="<text>", kind=None, ctx="startup"):
    """Scan a bare string. By default it is treated as Vimscript sourced at startup."""
    findings, info = [], []
    k = kind or file_kind(label) or "vim"
    _scan_text(content, label, findings, info, k, ctx)
    return _summarise(findings, info, label)


# ---------------------------------------------------------------------------
# Loading targets (plugin code is never sourced or executed)
# ---------------------------------------------------------------------------
UA = {"User-Agent": "vimplugin-audit/%s (+https://github.com/eltociear/vimplugin-audit)" % __version__}


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
    if size > MAX_FILE or "/node_modules/" in "/" + low or "/.git/" in "/" + low:
        return False
    k = file_kind(rel)
    if k == "text":
        return size <= 1000000 and (low.startswith(("readme", "doc/")) or "/doc/" in low or low.endswith(".txt"))
    return k is not None


def files_from_tarball(data, strip=1):
    files, budget = {}, ArchiveBudget()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        for m in tf:
            name = safe_member(m.name)
            if not m.isreg() or not name:   # links, devices, FIFOs, traversal / absolute names
                continue
            parts = name.split("/")[strip:]
            if not parts:
                continue
            rel = "/".join(parts)
            if _keep(rel, m.size) and budget.take(m.size):
                files[rel] = tf.extractfile(m).read(MAX_FILE).decode("utf-8", "replace")
    return files


def files_from_dir(root):
    files = {}
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in (".git", "node_modules", "__pycache__", ".venv", "venv", "target")]
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


def _read_blob(p, cap=500000000):
    with open(p, "rb") as fh:
        return fh.read(cap)


def fetch_repo(repo, ref=None):
    return files_from_tarball(_get("https://codeload.github.com/%s/tar.gz/%s" % (repo, ref or "HEAD")))


def audit_github(spec):
    repo, _, ref = spec.partition("@")
    repo = re.sub(r"^(?:https?://github\.com/|git@github\.com:)", "", repo).strip("/")
    if repo.endswith(".git"):
        repo = repo[:-4]
    return scan_target(fetch_repo(repo, ref or None), repo + ("@" + ref if ref else ""))


def installed_dirs():
    """Plugin directories of the common managers (Neovim and Vim, Unix and Windows layouts)."""
    home = os.path.expanduser("~")
    data = os.environ.get("XDG_DATA_HOME") or os.path.join(home, ".local", "share")
    roots = []
    for app in ("nvim", "lvim", "astronvim", "lazyvim", "nvchad"):
        d = os.path.join(data, app)
        roots += glob.glob(os.path.join(d, "lazy", "*"))
        roots += glob.glob(os.path.join(d, "site", "pack", "*", "*", "*"))
        roots += glob.glob(os.path.join(d, "plugged", "*"))
        roots += glob.glob(os.path.join(d, "dein", "repos", "*", "*", "*"))
    roots += glob.glob(os.path.join(home, ".vim", "plugged", "*"))
    roots += glob.glob(os.path.join(home, ".vim", "pack", "*", "*", "*"))
    roots += glob.glob(os.path.join(home, ".vim", "bundle", "*"))
    roots += glob.glob(os.path.join(home, "vimfiles", "pack", "*", "*", "*"))
    roots += glob.glob(os.path.join(os.environ.get("LOCALAPPDATA", "/nonexistent"), "nvim-data", "lazy", "*"))
    return sorted({r for r in roots if os.path.isdir(r)})


_ICON = {"CRITICAL": "\U0001F534", "HIGH": "\U0001F7E0", "MEDIUM": "\U0001F7E1",
         "LOW": "\U0001F535", "SAFE": "\U0001F7E2"}


def _print(r, verbose):
    if r.get("incomplete") and not r["findings"]:
        print("⚪ %s  [INCOMPLETE]  %s" % (r["target"], r["summary"]))
        return
    print("%s %s  [%s]  score=%d  (%d findings, %d info)" % (
        _ICON.get(r["risk_level"], "?"), r["target"], r["risk_level"], r["risk_score"],
        r["total_findings"], r["info_count"]))
    for f in r["findings"]:
        print("    %-8s %s  %s:%s  (%s)" % (f["severity"], f["name"], f["file"], f["line"], f.get("exec_context", "")))
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
TOOL_NAME = "vimplugin-audit"
TOOL_URI = "https://github.com/eltociear/vimplugin-audit"
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
    targets = []
    if args and args[0] == "--text":
        txt = " ".join(args[1:])
        targets.append(("<text>", lambda: scan(txt)))
    elif args and args[0] == "--installed":
        for d in installed_dirs():
            targets.append((d, (lambda p=d: scan_target(files_from_dir(p), p))))
        if not targets:
            print("no installed plugins found (lazy / packer / vim-plug / dein / native packages)", file=sys.stderr)
            return 1
    elif args and args[0] == "--list":
        with open(args[1], encoding="utf-8") as fh:
            for ln in fh:
                ln = ln.split("#", 1)[0].strip()
                if ln:
                    targets.append((ln, (lambda s=ln: audit_github(s))))
    else:
        for a in args:
            if os.path.isdir(a):
                targets.append((a, (lambda p=a: scan_target(files_from_dir(p), p))))
            elif os.path.isfile(a):
                if a.endswith((".tar.gz", ".tgz", ".tar")):
                    targets.append((a, (lambda p=a: scan_target(files_from_tarball(_read_blob(p)), p))))
                else:
                    targets.append((a, (lambda p=a: scan(_read_blob(p, MAX_FILE).decode("utf-8", "replace"), p,
                                                         ctx=context_of(p)))))
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
    return family_emit(results, fam)


if __name__ == "__main__":
    sys.exit(main())
