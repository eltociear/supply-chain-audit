#!/usr/bin/env python3
"""aur-audit - security-scan AUR packages (PKGBUILD, .install scriptlets, alpm hooks and the
scripts bundled in the package repo) before you build or install them.

The AUR is user-submitted shell. `makepkg` runs prepare()/build()/package() as you, and pacman
runs the .install scriptlet (post_install, post_upgrade, ...) and any alpm hook **as root**. In
June 2026 attackers adopted orphaned AUR packages and added a single line - `npm install
atomic-lockfile` / `bun install js-digest` - to .install files; in July 2025 "-bin" browser
packages pulled a git repo that dropped a RAT. Neither is a CVE, so nothing that checks CVEs
would catch it. This scanner looks for what such packages do:

  pipe-to-shell, decoded-then-executed payloads, reverse shells, package-manager installs and
  network fetches inside root install hooks, persistence (systemd units, cron, shell rc,
  sudoers, PAM, ld.so.preload, authorized_keys), security tooling switched off, log wiping,
  credential exfiltration, sources served from pastebins / file hosts / Discord CDN,
  unverified plaintext sources, "-bin" packages that build from an unrelated git repo, and the
  published indicators of the June 2026 campaign.

It is bash-aware: every line is classified by where it runs - PKGBUILD top level (runs whenever
any tool *sources* the PKGBUILD), prepare/build/check/package/pkgver (makepkg, as you), install
scriptlet functions (pacman, as root), remove scriptlets, alpm hook Exec lines, systemd unit
Exec lines, heredoc bodies written into the package, and user-facing echo/msg text - so an
`npm install` inside build() is context while the same line in post_install() is a finding.
Deterministic, no LLM, zero dependencies, nothing is built or executed.

Usage:
  python3 aur_audit.py <PKGBUILD|dir> [...]        # local package dir (skips src/ and pkg/)
  python3 aur_audit.py --aur yay paru              # fetch + scan AUR packages (snapshot tarball)
  python3 aur_audit.py --installed-foreign         # every foreign package (pacman -Qqm)
  python3 aur_audit.py --text "post_install() { curl -s x | sh; }"
  add --json (family schema) or --sarif (SARIF 2.1.0) for machine-readable output,
  --fail-on {critical,high,medium,low,never}, --version, --all to also list SAFE packages, --verbose for INFO
  exit code 2 if any package reaches --fail-on (default HIGH; use it to gate builds), 1 on usage errors

MIT licensed. https://github.com/eltociear/aur-audit
"""
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import time
import urllib.parse
import urllib.request

__version__ = "0.2.0"

UA = {"User-Agent": "aur-audit/%s (github.com/eltociear/aur-audit)" % __version__}

# ---------------------------------------------------------------------------
# Contexts: where a line runs decides whether a match is risk or context.
#   top     : PKGBUILD top level - executed every time the PKGBUILD is sourced
#   build   : prepare/build/check/package/pkgver and helpers - makepkg, as the user
#   hook    : pre/post_install, pre/post_upgrade, .install top level, alpm hook Exec - root
#   remove  : pre/post_remove - root, but deleting the package's own files is cleanup
#   unit    : systemd unit Exec*= lines shipped in the repo
#   aux     : scripts shipped in the repo / heredoc bodies written into the package
#   message : echo/printf/msg text shown to the user (advice, not execution)
#   meta    : pkgdesc, url, arrays, comments-ish metadata
# ---------------------------------------------------------------------------
RUN = {"top", "build", "hook", "remove", "unit", "aux"}
ROOT = {"hook", "remove", "unit"}

FILE_HOSTS_HIGH = (r"cdn\.discordapp\.com|media\.discordapp\.net|discord(?:app)?\.com/api/webhooks|"
                   r"pastebin\.com|paste\.ee|hastebin\.com|ghostbin\.\w+|rentry\.co|dpaste\.\w+|"
                   r"temp\.sh|transfer\.sh|file\.io|0x0\.st|anonfiles?\.\w+|gofile\.io|catbox\.moe|"
                   r"litterbox\.catbox|bashupload\.com|oshi\.at|ufile\.io|"
                   r"[\w-]+\.ngrok(?:-free)?\.(?:io|app|dev)|[\w-]+\.trycloudflare\.com|"
                   r"webhook\.site|[\w-]+\.oast\.\w+|[\w-]+\.interact\.sh|[\w-]+\.burpcollaborator\.net|"
                   r"pipedream\.net|requestbin\.(?:com|net)|api\.telegram\.org/bot|[a-z2-7]{56}\.onion")
FILE_HOSTS_MED = (r"mega(?:\.co)?\.nz/(?:file/|folder/|#!|#F!)|mediafire\.com/(?:file|download|folder)/|"
                  r"drive\.google\.com/(?:file/|uc\b|open\b|drive/folders/)|docs\.google\.com/uc\b|"
                  r"dropbox\.com/(?:s|scl|sh)/|dl\.dropboxusercontent\.com|1drv\.ms|onedrive\.live\.com/(?:download|redir)")
FETCH = r"(?:\bcurl\b|\bwget2?\b|\baria2c\b|\bfetch\s+-o\b|\bhttpie\b|\bxh\s+get\b)"
SHELLS = r"(?:sudo\s+(?:-\w+\s+)*)?(?:/usr)?(?:/bin/)?(?:ba|z|da|k|fi)?sh\b|python[23]?\b|perl\b|ruby\b|node\b|bun\b"
PKGMGR = (r"\b(?:npm|pnpm|yarn|bun|npx|bunx|pnpx)\s+(?:-\S+\s+)*(?:i|install|add|ci|exec|x|dlx|create)\b|"
          r"\b(?:npx|bunx|pnpx)\s+[\w@]|\bpip[23]?(?:\.\d+)?\s+install\b|\bpython[23]?(?:\.\d+)?\s+-m\s+pip\s+install\b|"
          r"\bpipx\s+(?:install|run)\b|\buv\s+(?:pip\s+install|tool\s+install|run)\b|\bcargo\s+install\b|"
          r"\bgem\s+install\b|\bgo\s+(?:install|get)\b|\bcomposer\s+(?:require|global)\b")
NETFETCH = FETCH + r"|\bgit\s+(?:clone|pull|fetch)\b|\bsvn\s+(?:co|checkout)\b|urllib\.request|requests\.get|\bnc\s+\S+\s+\d+\s*<"

PATTERNS = {
    "critical": [
        {"id": "download_execute", "name": "Download & Execute",
         "desc": "Fetches remote content and pipes/feeds it straight into an interpreter",
         "ctx": RUN,
         "regexes": [
             FETCH + r"[^|;&\n]*\|\s*(?:" + SHELLS + r")",
             r"(?:" + SHELLS + r")\s*(?:-\w+\s+)*<\s*\(\s*" + FETCH,
             r"(?:" + SHELLS + r")\s+-c\s+[\"']?\$\(\s*" + FETCH,
             r"\b(?:eval|source|\.)\s+[\"']?(?:\$\(|<\()\s*" + FETCH,
             r"python[23]?\s+-c\s+[\"'][^\"']*(?:urlopen|requests\.get)[^\"']*exec\s*\(",
         ]},
        {"id": "decoded_exec", "name": "Decoded Payload Execution",
         "desc": "Decodes base64/hex/xor data and executes it",
         "ctx": RUN,
         "regexes": [
             r"\bbase(?:64|32)\s+(?:-\w+\s+)*(?:-d|--decode|-D)\b[^|;\n]*\|\s*(?:" + SHELLS + r")",
             r"\b(?:eval|source)\s+[\"']?\$\([^)\n]*\bbase(?:64|32)\s+(?:-\w+\s+)*(?:-d|--decode)",
             r"\bxxd\s+-r\b[^|;\n]*\|\s*(?:" + SHELLS + r")",
             r"\bopenssl\s+(?:enc\s+)?(?:-\w+\s+)*-d\b[^|;\n]*\|\s*(?:" + SHELLS + r")",
             r"exec\s*\(\s*(?:base64\.b64decode|bytes\.fromhex|zlib\.decompress|codecs\.decode)",
             r"\beval\s+[\"']?\$\(\s*printf\s+[\"'](?:\\x[0-9a-fA-F]{2}|\\[0-7]{3}){6,}",
         ]},
        {"id": "reverse_shell", "name": "Reverse Shell",
         "desc": "Connects a shell to a remote socket",
         "ctx": RUN,
         "regexes": [
             r"/dev/(?:tcp|udp)/[\w.\-$]+/\d+",
             r"\bn(?:c|cat)\s+(?:-\w+\s+)*-[ec]\s+/bin/(?:ba)?sh",
             r"\bsocat\b[^\n]*\bexec:[\"']?(?:/bin/)?(?:ba)?sh",
             r"\b(?:ba)?sh\s+-i\s+[<>]&",
             r"socket\.socket\([^\n]*\bconnect\([^\n]*(?:pty\.spawn|subprocess\.call\(\[[\"']/bin/(?:ba)?sh)",
             r"\bmkfifo\b[^\n]*\|\s*(?:/bin/)?(?:ba)?sh\s+-i[^\n]*\bn(?:c|cat)\b",
         ]},
        {"id": "campaign_ioc", "name": "Known Campaign Indicator",
         "desc": "Matches a published indicator of the June 2026 AUR campaign (injected npm/bun packages, C2)",
         "ctx": RUN | {"message", "meta"},
         "regexes": [
             r"(?<![\w.-])(?:atomic-lockfile|lockfile-js|js-digest|nextfile-js)(?![\w.-])",
             r"olrh4mibs62l6kkuvvjyc5lrercqg5tz543r",
         ]},
        {"id": "destructive", "name": "Destructive Command",
         "desc": "Recursively deletes the filesystem root, a home directory or a top-level system dir",
         "ctx": RUN,
         "regexes": [
             r"\brm\s+(?:-\w+\s+)*-\w*[rR]\w*\s+(?:-\w+\s+)*(?:--no-preserve-root\s+)?[\"']?(?:/|/\*|~/?|~/\*|\$\{?HOME\}?/?\*?|/home/?\*?|/etc/?|/usr/?|/boot/?)[\"']?(?=\s|$|;|&|\|)",
             r"\bdd\s+[^\n]*\bof=/dev/(?:sd[a-z]|nvme\d|vd[a-z]|mmcblk\d)(?!\w*p?\d)",
             r"\bmkfs(?:\.\w+)?\s+(?:-\w+\s+)*/dev/(?:sd[a-z]|nvme\d|vd[a-z])",
         ]},
        {"id": "preload_inject", "name": "Dynamic Linker Preload Injection",
         "desc": "Writes /etc/ld.so.preload - every process on the system loads the library (rootkit technique)",
         "ctx": RUN,
         "regexes": [
             r"(?:>>?\s*|\btee\s+(?:-a\s+)?|\bcp\s+\S+\s+|\binstall\s+[^\n]*\s|\bln\s+-s\w*\s+\S+\s+|\bsed\s+-i[^\n]*\s)[\"']?(?:\$\{?pkgdir\}?)?/etc/ld\.so\.preload\b",
         ]},
        {"id": "credential_exfil", "name": "Credential Exfiltration",
         "desc": "Reads a credential store and sends it to a non-upstream host (file-level combination)",
         "ctx": RUN, "regexes": []},
    ],
    "high": [
        {"id": "pkgmgr_in_hook", "name": "Package-Manager Install in Root Hook",
         "desc": "Runs npm/bun/pip/cargo/... install from a root install scriptlet or hook - unpinned code outside makepkg's checksums (the June 2026 injection shape)",
         "ctx": ROOT,
         "regexes": [PKGMGR]},
        {"id": "fetch_in_hook", "name": "Network Fetch in Root Hook",
         "desc": "Downloads from the network inside a root install scriptlet or hook - bypasses source=() checksums",
         "ctx": {"hook", "unit"},
         "regexes": [NETFETCH]},
        {"id": "exfil_endpoint", "name": "Collector / File-Host Endpoint",
         "desc": "Talks to a paste site, anonymous file host, tunnel, webhook collector, Telegram bot or onion service",
         "ctx": RUN | {"source"},  # source=() entries are scored by source_checks only
         "regexes": [r"(?:https?://|wss?://|//|@)(?:[\w-]+\.)*(?:" + FILE_HOSTS_HIGH + r")",
                     r"\b(?:discord(?:app)?\.com/api/webhooks/|api\.telegram\.org/bot|[a-z2-7]{56}\.onion\b)"]},
        {"id": "persistence", "name": "Persistence from Install Hook",
         "desc": "A root scriptlet writes a systemd unit, cron job, autostart entry, shell rc or profile script on the live system",
         "ctx": ROOT,
         "regexes": [
             r"(?:>>?\s*|\btee\s+(?:-a\s+)?|\bcp\s+(?:-\w+\s+)*\S+\s+|\bmv\s+\S+\s+|\binstall\s+[^\n]*\s|\bln\s+-s\w*\s+\S+\s+|\bsed\s+-i\w*\s+[^\n]*\s)[\"']?(?:/etc/systemd/(?:system|user)/|/usr/lib/systemd/(?:system|user)/[^\s\"']*\.(?:service|timer)|~?/?[\w$/{}.-]*\.config/systemd/user/|/etc/cron|/var/spool/cron|/etc/xdg/autostart/|~?[\w$/{}.-]*\.config/autostart/|/etc/profile|/etc/bash\.bashrc|/etc/zsh/|/etc/environment|/etc/rc\.local|/root/\.|/home/[^\s/]+/\.|~/\.|\$\{?HOME\}?/\.)",
             r"\bcrontab\s+(?:-u\s+\S+\s+)?(?:-|\S+\.txt|/tmp/)",
             r"\|\s*crontab\b",
             r"\bsystemctl\s+(?:--user\s+|--global\s+)?(?:link|edit)\b",
         ]},
        {"id": "privileged_tamper", "name": "Privilege / Auth Tampering",
         "desc": "Edits sudoers, PAM, SSH authorized_keys or account privileges",
         "ctx": RUN - {"aux"},
         "regexes": [
             r"(?:>>?\s*|\btee\s+(?:-a\s+)?|\bsed\s+-i\w*\s+[^\n]*\s|\bcp\s+\S+\s+|\binstall\s+[^\n]*\s)[\"']?(?:/etc/sudoers(?:\.d)?|/etc/pam\.d/|/etc/security/|/etc/shadow|/etc/passwd)\b",
             r"(?:>>?\s*|\btee\s+(?:-a\s+)?|\bcp\s+\S+\s+|\binstall\s+[^\n]*\s)[\"']?[^\s\"']*\.ssh/authorized_keys2?\b",
             r"\busermod\s+[^\n]*-a?G\s*[\"']?(?:wheel|sudo|root|adm)\b",
             r"\bgpasswd\s+-a\s+\S+\s+(?:wheel|sudo|root)\b",
             r"\bchpasswd\b|\bpasswd\s+-d\b|\buseradd\s+[^\n]*-o\s+[^\n]*-u\s*0\b",
             r"NOPASSWD\s*:\s*ALL",
         ]},
        {"id": "security_off", "name": "Security Controls Disabled",
         "desc": "Turns off a firewall, MAC framework, audit daemon or kernel hardening",
         "ctx": RUN - {"aux"},
         "regexes": [
             r"\bsetenforce\s+0\b",
             r"\bsystemctl\s+(?:stop|disable|mask)\s+(?:--now\s+)?(?:apparmor|firewalld|ufw|auditd|nftables|iptables|fail2ban|clamav\w*)\b",
             r"\bufw\s+disable\b|\biptables\s+-F\b|\bnft\s+flush\s+ruleset\b",
             r"\bsysctl\s+(?:-w\s+)?kernel\.(?:yama\.ptrace_scope|kptr_restrict|randomize_va_space|dmesg_restrict|modules_disabled)\s*=\s*0",
             r"\baa-(?:disable|teardown)\b",
         ]},
        {"id": "anti_forensics", "name": "Log / History Wiping",
         "desc": "Clears shell history or system logs",
         "ctx": RUN - {"aux"},
         "regexes": [
             r"\bhistory\s+-c\b|\bunset\s+HISTFILE\b|\bHISTFILE=/dev/null\b|\bHISTSIZE=0\b",
             r"\brm\s+(?:-\w+\s+)*[^\n]*\.(?:bash|zsh)_history\b",
             r"(?:>\s*|\btruncate\s+-s\s*0\s+|\bshred\s+[^\n]*)\s*[\"']?/var/log/(?:wtmp|btmp|lastlog|auth\.log|secure|messages|pacman\.log|journal)",
             r"\bjournalctl\s+--(?:vacuum-\w+|rotate)\b",
         ]},
    ],
    "medium": [
        {"id": "file_host_source", "name": "Source on a Personal File Host",
         "desc": "Downloads from Google Drive / Mega / MediaFire / Dropbox / OneDrive - no release provenance",
         "ctx": RUN | {"source"},  # source=() entries are scored by source_checks only
         "regexes": [r"https?://(?:[\w-]+\.)*(?:" + FILE_HOSTS_MED + r")/"]},
        {"id": "parse_time_exec", "name": "Command Runs When PKGBUILD Is Sourced",
         "desc": "Network/exec at PKGBUILD top level runs on every `source PKGBUILD` (AUR helpers, .SRCINFO generation), before you review or build",
         "ctx": {"top"},
         "regexes": [r"\$\(\s*(?:" + FETCH + r"|\bgit\s+ls-remote\b)", r"`\s*" + FETCH, r"^\s*(?:" + FETCH + r")\s"]},
        {"id": "sudo_in_build", "name": "Privilege Escalation in Build",
         "desc": "makepkg refuses to run as root; a PKGBUILD that calls sudo/pkexec/su escalates behind its back",
         "ctx": {"top", "build"},
         "regexes": [r"(?:^\s*|[;&|(`]\s*|\$\(\s*)(?:sudo|pkexec|doas)\s+(?!-v\b|-l\b|--version\b)\S", r"(?:^\s*|[;&|]\s*)su\s+-c\b"]},
        {"id": "obfuscation", "name": "Obfuscated Content",
         "desc": "Long base64 blob or escape-sequence chain inside the build recipe",
         "ctx": {"top", "build", "hook", "remove"},
         "regexes": [
             r"[\"'=](?=[A-Za-z0-9+/]{240,}={0,2}[\"'\s]?)(?=[^\"'\s]*[a-z])(?=[^\"'\s]*[A-Z])(?=[^\"'\s]*\d)[A-Za-z0-9+/]{240,}={0,2}",
             r"(?:\\x[0-9a-fA-F]{2}){24,}",
             r"\$'(?:\\x[0-9a-fA-F]{2}|\\[0-7]{3}){12,}'",
         ]},
        {"id": "hook_setuid", "name": "Setuid Set from Hook",
         "desc": "A root scriptlet sets the setuid/setgid bit or world-writable perms on the live system",
         "ctx": ROOT,
         "regexes": [r"\bchmod\s+(?:-\w+\s+)*(?:[ugoa]*\+[rwx]*s|[4-7][0-7]{3}|0?777)\b"]},
        {"id": "unverified_plaintext", "name": "Unverified Plaintext Source",
         "desc": "http:// source with SKIP / no checksum - anyone on the path can swap the bytes",
         "ctx": RUN | {"source"}, "regexes": []},
        {"id": "bin_vcs_source", "name": "'-bin' Package Built from an Unrelated Git Repo",
         "desc": "A -bin package should repackage upstream release binaries; this one clones a git repo whose owner is not the upstream (the July 2025 CHAOS RAT shape)",
         "ctx": RUN | {"source"}, "regexes": []},
        {"id": "remote_exec_message", "name": "Pipe-to-Shell Advised to the User",
         "desc": "Tells the user to run a downloaded script (shown, not executed)",
         "ctx": {"message"}, "regexes": []},
    ],
    "low": [
        {"id": "insecure_url", "name": "Plaintext Source (checksummed)",
         "desc": "http:// source, but pinned by a checksum",
         "ctx": RUN | {"source"}, "regexes": []},
        {"id": "hook_service_enable", "name": "Service Enabled from Install Hook",
         "desc": "systemctl enable/start in a scriptlet (Arch packaging guidelines leave this to the user)",
         "ctx": ROOT,
         "regexes": [r"\bsystemctl\s+(?:--\w+\s+)*(?:enable|start|restart|reenable)\b",
                     r"\bln\s+-s\w*\s+[\"']?/usr/lib/systemd/(?:system|user)/\S+\s+[\"']?/etc/systemd/(?:system|user)/[\w@.-]+\.wants/"]},
    ],
    "info": [
        {"id": "pkgmgr_in_build", "name": "Language Package Manager in Build",
         "desc": "npm/pip/cargo/go fetch during makepkg (normal for many ecosystems, but outside source=() checksums)",
         "ctx": {"top", "build"}, "regexes": [PKGMGR]},
        {"id": "fetch_in_build", "name": "Network Fetch in Build",
         "desc": "curl/wget/git during prepare/build/package",
         "ctx": {"build"}, "regexes": [NETFETCH]},
        {"id": "skip_checksum", "name": "SKIP Checksum on a Release Source",
         "desc": "Non-VCS source with checksum SKIP (unpinned 'latest' download)",
         "ctx": RUN | {"source"}, "regexes": []},
        {"id": "user_account", "name": "Creates Users/Groups",
         "desc": "useradd/groupadd in a scriptlet (sysusers.d is preferred)",
         "ctx": ROOT, "regexes": [r"\b(?:useradd|groupadd|adduser)\b"]},
        {"id": "setuid_packaged", "name": "Setuid Binary Packaged",
         "desc": "Installs a setuid/setgid file into the package",
         "ctx": {"build"}, "regexes": [r"\b(?:install|chmod)\s+(?:-\w+\s+)*(?:-m\s*)?(?:[ugoa]*\+[rwx]*s|[4-7][0-7]{3})\b"]},
        {"id": "packaged_auth_config", "name": "Ships Auth Configuration",
         "desc": "Packages a sudoers.d / PAM / polkit file (normal packaging, review the content)",
         "ctx": {"build"}, "regexes": [r"\$\{?pkgdir\}?[\"']?/etc/(?:sudoers\.d|pam\.d|polkit-1)\b"]},
    ],
}

SEVERITY_SCORE = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "SAFE": 0}
_COMPILED = [(sev, pg, [re.compile(r, re.I) for r in pg["regexes"]])
             for sev, groups in PATTERNS.items() for pg in groups if pg["regexes"]]
# Cheap literal prefilter: a pattern's regexes only run on lines containing one of its needles.
_FETCH_N = ("curl", "wget", "aria2c", "fetch", "http", "xh ", "git ", "svn ", "urllib", "requests", "nc ")
_PKG_N = ("npm", "pnpm", "yarn", "bun", "npx", "pip", "uv ", "cargo", "gem ", "go ", "composer")
NEEDLES = {
    "download_execute": ("curl", "wget", "aria2c", "fetch", "httpie", "xh ", "urlopen", "requests"),
    "decoded_exec": ("base64", "base32", "xxd", "openssl", "exec", "printf"),
    "reverse_shell": ("/dev/tcp", "/dev/udp", "nc ", "ncat", "socat", " -i", "socket", "mkfifo"),
    "campaign_ioc": ("lockfile", "js-digest", "nextfile", "olrh4mibs"),
    "destructive": ("rm ", "dd ", "mkfs"),
    "preload_inject": ("ld.so.preload",),
    "pkgmgr_in_hook": _PKG_N, "pkgmgr_in_build": _PKG_N,
    "fetch_in_hook": _FETCH_N, "fetch_in_build": _FETCH_N,
    "parse_time_exec": ("curl", "wget", "aria2c", "fetch", "httpie", "xh ", "ls-remote"),
    "persistence": ("/etc/", "systemd", "cron", "autostart", "/root/", "/home/", "~/", "home", "systemctl"),
    "privileged_tamper": ("/etc/", "authorized_keys", "usermod", "gpasswd", "passwd", "useradd", "nopasswd"),
    "security_off": ("setenforce", "systemctl", "ufw", "iptables", "nft ", "sysctl", "aa-"),
    "anti_forensics": ("hist", "_history", "/var/log", "journalctl"),
    "sudo_in_build": ("sudo", "pkexec", "doas", "su "),
    "hook_setuid": ("chmod",), "setuid_packaged": ("chmod", "install"),
    "hook_service_enable": ("systemctl", ".wants/"), "user_account": ("useradd", "groupadd", "adduser"),
    "packaged_auth_config": ("pkgdir",),
    "exfil_endpoint": ("discord", "paste", "hastebin", "ghostbin", "rentry", "temp.sh", "transfer.sh", "file.io",
                       "0x0.st", "anonfile", "gofile", "catbox", "bashupload", "oshi.at", "ufile", "ngrok",
                       "trycloudflare", "webhook.site", "oast", "interact.sh", "burpcollaborator", "pipedream",
                       "requestbin", "telegram", ".onion"),
    "file_host_source": ("mega.", "mediafire", "google.com", "dropbox", "1drv", "onedrive"),
}

CRED_TERM = re.compile(
    r"\.ssh/(?:id_\w+|identity)|\.aws/credentials|\.npmrc|\.git-credentials|\.netrc|\.docker/config\.json|"
    r"\.config/(?:discord|google-chrome|chromium|BraveSoftware|gh/hosts\.yml)|\.mozilla/firefox|Login Data|"
    r"\bwallet\.dat\b|\.gnupg/|\.kube/config|\.vault-token|/etc/shadow|"
    r"\$\{?(?:GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID)\b", re.I)
SEND = re.compile(
    r"\bcurl\b[^\n]*(?:\s-d\b|\s--data|\s-F\b|\s--form|\s-T\b|--upload-file|-X\s*POST|--request\s+POST)|"
    r"\bwget\b[^\n]*--post-(?:data|file)|\bnc\s+\S+\s+\d+|/dev/tcp/|\bscp\s+\S+\s+\S+@|\brsync\s+[^\n]*\S+@\S+:", re.I)
HOST = re.compile(r"(?:https?|ftp)://(?:[^@/\s\"']*@)?([A-Za-z0-9.-]+)")

FUNC = re.compile(r"^\s*(?:function\s+)?([A-Za-z_][\w.-]*)\s*\(\s*\)\s*(\{)?\s*(?:#.*)?$|^\s*function\s+([A-Za-z_][\w.-]*)\s*(\{)?\s*$")
HEREDOC = re.compile(r"<<-?\s*\\?([\"']?)([A-Za-z_][A-Za-z0-9_]*)\1")
MSG_CMD = re.compile(r"^\s*(?:(?:/usr)?/bin/)?(?:echo|printf|msg2?|plain|warning|error|note|info|cat\s+<<)\b")
BUILD_FUNCS = re.compile(r"^(?:prepare|build|check|package(?:_[\w.+-]+)?|pkgver|_\w*|[\w.-]+)$")
HOOK_FUNCS = {"pre_install", "post_install", "pre_upgrade", "post_upgrade"}
REMOVE_FUNCS = {"pre_remove", "post_remove"}
VCS_SCHEMES = ("git+", "git://", "svn+", "svn://", "hg+", "bzr+", "fossil+")
SKIP_EXT = (".patch", ".diff", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".xpm", ".ttf",
            ".otf", ".woff", ".woff2", ".pdf", ".asc", ".sig", ".gpg", ".pub", ".key", ".pem", ".crt")
SKIP_NAMES = {".SRCINFO", ".gitignore", ".nvchecker.toml", "LICENSE", "LICENCE", "COPYING", "REUSE.toml",
              ".editorconfig", "nvchecker.toml", ".gitattributes", "CHANGELOG", "CHANGELOG.md"}


def _strip_comment(line):
    """Drop a trailing # comment that is not inside quotes (good enough for shell recipes)."""
    if "#" not in line:
        return line
    q = None
    for i, ch in enumerate(line):
        if q:
            if ch == q and line[i - 1] != "\\":
                q = None
        elif ch in "\"'":
            q = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t;"):
            return line[:i]
    return line


META_ASSIGN = re.compile(r"^\s*(?:pkg(?:name|base|ver|rel|desc)|epoch|url|arch|license|groups|depends|"
                         r"makedepends|checkdepends|optdepends|provides|conflicts|replaces|backup|"
                         r"options|install|changelog|source\w*|noextract|validpgpkeys|"
                         r"(?:md5|sha1|sha224|sha256|sha384|sha512|b2|ck)sums\w*)\+?=")


def _parens(code):
    code = re.sub(r"\"(?:[^\"\\]|\\.)*\"|'[^']*'", "", code)
    return code.count("(") - code.count(")")


def _braces(code):
    code = re.sub(r"\"(?:[^\"\\]|\\.)*\"|'[^']*'", "", code)
    return code.count("{") - code.count("}")


ENABLE_LINK = re.compile(r"\bln\s+-s\w*\s+[\"']?/usr/lib/systemd/(?:system|user)/\S+\s+[\"']?/etc/systemd/(?:system|user)/[\w@.-]+\.wants/")


def _open_quote(code):
    """Quote char left open at the end of this line (multi-line echo "...), else None."""
    q, i = None, 0
    while i < len(code):
        ch = code[i]
        if q:
            if ch == "\\" and q == '"':
                i += 2
                continue
            if ch == q:
                q = None
        elif ch == "\\":
            i += 2
            continue
        elif ch in "\"'":
            q = ch
        elif ch == "#" and (i == 0 or code[i - 1] in " \t;"):
            break
        i += 1
    return q


def classify(lines, kind):
    """Context label per physical line. kind: PKGBUILD | install | hook | unit | aux | doc."""
    if kind == "aux":
        return ["aux"] * len(lines)
    if kind == "doc":
        return ["doc"] * len(lines)
    if kind == "unit":
        return ["unit" if re.match(r"^\s*Exec\w*\s*=", l) else "meta" for l in lines]
    if kind == "hook":
        return ["hook" if re.match(r"^\s*Exec\s*=", l) else "meta" for l in lines]
    top = "top" if kind == "PKGBUILD" else "hook"
    ctx, depth, cur, pending, heredoc, hlabel, arr, alabel = [], 0, None, None, None, "aux", 0, "meta"
    mquote = None
    for line in lines:
        s = line.strip()
        if heredoc is not None:
            ctx.append(hlabel)
            if s == heredoc:
                heredoc = None
            continue
        if mquote is not None:      # inside a multi-line echo/printf string
            ctx.append("message")
            if line.count(mquote) % 2 == 1:
                mquote = None
            continue
        code = _strip_comment(line)
        if cur is None and pending is None and not arr:
            m = FUNC.match(line)
            if m:
                name = m.group(1) or m.group(3)
                brace = m.group(2) or m.group(4)
                if name in HOOK_FUNCS:
                    lab = "hook"
                elif name in REMOVE_FUNCS:
                    lab = "remove"
                else:
                    lab = "hook" if kind == "install" else "build"
                if brace:
                    cur, depth = lab, max(1, _braces(code))
                else:
                    pending = lab
                ctx.append(lab)
                continue
            m = re.match(r"^\s*(?:function\s+)?([A-Za-z_][\w.-]*)\s*\(\s*\)\s*\{(.*)\}\s*;?\s*$", line)
            if m:  # one-liner function body
                name = m.group(1)
                lab = "hook" if name in HOOK_FUNCS or kind == "install" else "remove" if name in REMOVE_FUNCS else "build"
                ctx.append(lab)
                continue
        if pending is not None and cur is None:
            if s.startswith("{"):
                cur, depth, pending = pending, 0, None
            elif s:
                pending = None
        if cur is None:
            if arr:
                ctx.append(alabel)
                arr = max(0, arr + _parens(code))
                continue
            if META_ASSIGN.match(line):
                alabel = "source" if re.match(r"^\s*source\w*\+?=", line) else "meta"
                ctx.append(alabel)
                if "=(" in code and _parens(code) > 0:
                    arr = _parens(code)
                continue
            lab = "message" if _is_message(line) else top
            ctx.append(lab)
        else:
            lab = "message" if _is_message(line) else cur
            ctx.append(lab)
            if not s.startswith("#"):
                depth += _braces(code)
                if depth <= 0:
                    cur, depth = None, 0
        if ctx and ctx[-1] == "message" and MSG_CMD.match(line):
            mquote = _open_quote(code)
        h = HEREDOC.search(re.sub(r"\"(?:[^\"\\]|\\.)*\"|'[^']*'", "", code))
        if h and not s.startswith("#"):
            heredoc = h.group(2)
            hlabel = "message" if re.match(r"^\s*(?:cat|echo|printf)\s+<<", line) else "aux"
    return ctx


def _is_message(line):
    if not MSG_CMD.match(line):
        return False
    if re.match(r"^\s*cat\s+<<", line):
        return True
    bare = re.sub(r"\"(?:[^\"\\]|\\.)*\"|'[^']*'", "", line)
    bare = re.split(r"[\"']", bare, 1)[0]          # an unclosed quote runs to end of line
    return not re.search(r"[|>;`]|&&|\$\(", bare)


def _logical(lines):
    """Join backslash-continued lines; yield (first_index, text)."""
    i, n = 0, len(lines)
    while i < n:
        start, buf = i, lines[i]
        while buf.rstrip().endswith("\\") and i + 1 < n and len(buf) < 20000:
            i += 1
            buf = buf.rstrip()[:-1] + " " + lines[i].lstrip()
        yield start, buf
        i += 1


# ---------------------------------------------------------------------------
# PKGBUILD array parsing (sources / checksums)
# ---------------------------------------------------------------------------
ARRAY = re.compile(r"^[ \t]*((?:source|(?:md5|sha1|sha224|sha256|sha384|sha512|b2|ck)sums)(?:_[\w]+)?)\+?=\((.*?)\)",
                   re.M | re.S)
SCALAR = re.compile(r"^[ \t]*([A-Za-z_]\w*)=([\"']?)([^\"'\n()$`]*(?:\$\{?\w+\}?[^\"'\n()$`]*)*)\2[ \t]*(?:#.*)?$", re.M)


def _vars(text):
    v = {}
    for m in SCALAR.finditer(text):
        v.setdefault(m.group(1), m.group(3))
    return v


def _expand(s, v, depth=0):
    if depth > 4 or "$" not in s:
        return s
    return _expand(re.sub(r"\$\{?(\w+)\}?", lambda m: v.get(m.group(1), m.group(0)), s), v, depth + 1)


def _items(body):
    out = []
    for m in re.finditer(r"\"((?:[^\"\\]|\\.)*)\"|'([^']*)'|([^\s\"'#]+)|#[^\n]*", body):
        if m.group(0).startswith("#"):
            continue
        out.append(m.group(1) if m.group(1) is not None else m.group(2) if m.group(2) is not None else m.group(3))
    return out


def _regdomain(host):
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "ac", "gov") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _owner(u):
    m = re.match(r"(?:\w+\+)?\w+://(?:[^@/]*@)?([^/:]+)[:/]+([^/#?]+)", u)
    return (m.group(1).lower(), m.group(2).lower()) if m else (None, None)


def source_checks(text, pkgbase, add, line_of):
    v = _vars(text)
    arrays = {}
    for m in ARRAY.finditer(text):
        arrays.setdefault(m.group(1), []).extend(_items(m.group(2)))
    upstream = _expand(v.get("url", ""), v)
    up_host, up_owner = _owner(upstream) if "://" in upstream else (None, None)
    up_dom = _regdomain(up_host) if up_host else None
    stats = {"sources": 0, "remote": 0, "vcs": 0, "skip_nonvcs": 0}
    for key, srcs in arrays.items():
        if not key.startswith("source"):
            continue
        suffix = key[len("source"):]
        sums = [arrays.get(alg + "sums" + suffix, []) for alg in ("md5", "sha1", "sha224", "sha256", "sha384", "sha512", "b2", "ck")]
        sums = [s for s in sums if s]
        for idx, raw in enumerate(srcs):
            stats["sources"] += 1
            u = _expand(raw.split("::", 1)[1] if "::" in raw else raw, v)
            if "://" not in u:
                continue
            stats["remote"] += 1
            vcs = u.startswith(VCS_SCHEMES) or bool(re.match(r"\w+://[^#]+\.git(?:#|$)", u))
            if vcs:
                stats["vcs"] += 1
            verified = any(idx < len(s) and s[idx].upper() != "SKIP" for s in sums)
            ln = line_of(raw)
            host = (_owner(u)[0] or "")
            own = bool(up_dom) and _regdomain(host) == up_dom      # the vendor's own host
            tail = u.split("://", 1)[1]
            if re.search(r"(?:^|\.)(?:" + FILE_HOSTS_HIGH + r")", tail) and not own:
                add(None, "exfil_endpoint", ln, u, "source")
            elif re.search(r"(?:^|\.)(?:" + FILE_HOSTS_MED + r")", tail) and not own:
                add(None, "file_host_source", ln, u, "source")
            is_sig = bool(re.search(r"\.(?:sig|asc|gpg|sign|sha\d*sums?|sha\d+|md5)(?:$|[?#])", u, re.I))
            if u.startswith("http://") and not vcs and is_sig:
                add("info", "insecure_url", ln, u, "source")
            elif u.startswith("http://") and not vcs:
                if verified:
                    add(None, "insecure_url", ln, u, "source")
                else:
                    add(None, "unverified_plaintext", ln, u, "source")
            elif not vcs and not verified:
                stats["skip_nonvcs"] += 1
                add("info", "skip_checksum", ln, u, "source")
            if vcs and pkgbase.endswith("-bin"):
                h, o = _owner(u.split("+", 1)[1] if "+" in u.split("://", 1)[0] else u)
                forges = ("github.com", "gitlab.com", "codeberg.org", "git.sr.ht", "bitbucket.org", "gitee.com")
                related = bool(h) and (
                    (o and up_owner and o == up_owner and h == up_host)
                    or (up_dom and _regdomain(h) == up_dom and h not in forges)
                    or (o and (o in pkgbase.lower() or o in upstream.lower())))
                if not related:
                    add(None, "bin_vcs_source", ln, u, "source")
    return stats


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------
def _by_id(pid):
    for sev, groups in PATTERNS.items():
        for pg in groups:
            if pg["id"] == pid:
                return sev, pg
    raise KeyError(pid)


CI_FILE = re.compile(r"(?:^|/)(?:\.github/|\.circleci/|\.gitlab-ci\.ya?ml$|\.travis\.ya?ml$|\.drone\.ya?ml$|"
                     r"\.woodpecker(?:/|\.ya?ml$)|Jenkinsfile$|azure-pipelines\.ya?ml$|appveyor\.ya?ml$|"
                     r"\.pre-commit-config\.ya?ml$|\.cirrus\.ya?ml$|bitbucket-pipelines\.ya?ml$)")


def kind_of(path, text=""):
    """CI configs run on the CI service, never on the user's machine: reported as docs."""
    base = os.path.basename(path)
    if CI_FILE.search(path.replace("\\", "/")):
        return "doc"
    if base == "PKGBUILD":
        return "PKGBUILD"
    if base.endswith(".install"):
        return "install"
    if base.endswith(".hook") and "[Action]" in text:
        return "hook"
    if re.search(r"\.(?:service|timer|socket|path)$", base):
        return "unit"
    if re.match(r"(?i)^(?:readme|news|changes|changelog|todo|authors|install)(?:\.\w+)?$", base) or \
            re.search(r"(?i)\.(?:md|markdown|rst|txt|html?|adoc|org|1|5|8|man)$", base):
        return "doc"
    return "aux"


def scan_file(text, path="PKGBUILD", pkgbase="", kind=None):
    kind = kind or kind_of(path, text)
    lines = text.split("\n")
    ctxs = classify(lines, kind)
    findings, info, seen = [], [], set()

    def add(sev, pid, ln, matched, ctx, line=None):
        key = (pid, ln)
        if key in seen:
            return
        seen.add(key)
        s, pg = _by_id(pid)
        sev = sev or s
        line = lines[ln - 1] if line is None and 0 < ln <= len(lines) else (line or "")
        it = {"severity": sev.upper(), "id": pid, "name": pg["name"], "description": pg["desc"],
              "file": path, "line": ln, "context_block": ctx, "matched": matched[:120], "context": line.strip()[:200]}
        if sev == "info" or ctx not in pg["ctx"]:
            it["severity"] = "INFO"
            info.append(it)
            return
        findings.append(it)

    stats = None
    if kind == "PKGBUILD":
        def line_of(raw):
            for n, l in enumerate(lines, 1):
                if raw and raw in l:
                    return n
            return 0
        stats = source_checks(text, pkgbase, add, line_of)

    for i, logical in _logical(lines):
        ctx = ctxs[i]
        s = logical.lstrip()
        if s.startswith("#"):
            continue
        code = _strip_comment(logical)
        low = code.lower()
        for sev, pg, regs in _COMPILED:
            nd = NEEDLES.get(pg["id"])
            if nd is not None and not any(n in low for n in nd):
                continue
            for rx in regs:
                m = rx.search(code)
                if not m:
                    continue
                pid, c = pg["id"], ("srcline" if ctx == "source" else ctx)
                if pid == "persistence" and ENABLE_LINK.search(code):
                    break
                if c == "message" and pid == "download_execute":
                    add("medium", "remote_exec_message", i + 1, m.group(0), "message", logical)
                elif c in ("message", "doc") and pid not in ("campaign_ioc",) or c == "doc":
                    add("info", pid, i + 1, m.group(0), c, logical)
                else:
                    add(None if sev != "info" else "info", pid, i + 1, m.group(0), c, logical)
                break

    # credential exfiltration: credential term + send primitive + foreign host within +-6 lines
    sev, pg = _by_id("credential_exfil")
    for i, line in enumerate(lines):
        if ctxs[i] not in RUN or line.lstrip().startswith("#") or not CRED_TERM.search(line):
            continue
        lo, hi = max(0, i - 6), min(len(lines), i + 7)
        window = [l for l in lines[lo:hi] if not l.lstrip().startswith("#")]
        if not any(SEND.search(l) for l in window):
            continue
        hosts = [h for l in window for h in HOST.findall(l)]
        foreign = [h for h in hosts if not re.search(r"(?:^|\.)(?:archlinux\.org|localhost|127\.0\.0\.1)$", h)]
        if foreign or any(re.search(r"/dev/tcp/|\bnc\s+\S+\s+\d+", l) for l in window):
            add(None, "credential_exfil", i + 1, CRED_TERM.search(line).group(0), ctxs[i])

    return findings, info, stats


def _summarize(findings, info, extra=None):
    total, counts = 0, {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        total += SEVERITY_SCORE[f["severity"].lower()]
        counts[f["severity"]] += 1
    level = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[s]), "SAFE")
    findings.sort(key=lambda f: (-SEVERITY_RANK[f["severity"]], f["file"], f["line"]))
    parts = ["%d %s" % (counts[s], s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[s]]
    out = {"risk_score": min(total, 100), "risk_level": level, "findings": findings, "info": info,
           "summary": ", ".join(parts) if parts else "No issues found",
           "total_findings": len(findings), "info_count": len(info)}
    if extra:
        out.update(extra)
    return out


def scan_package(files, pkgbase=""):
    """files: {relative_path: text}. Returns one result for the whole package repo."""
    findings, info, stats = [], [], {}
    if not pkgbase and "PKGBUILD" in files:
        m = re.search(r"^\s*pkgbase=[\"']?([^\s\"']+)", files["PKGBUILD"], re.M) or \
            re.search(r"^\s*pkgname=\(?[\"']?([^\s\"')]+)", files["PKGBUILD"], re.M)
        pkgbase = m.group(1) if m else ""
    for rel, text in sorted(files.items()):
        base = os.path.basename(rel)
        if base in SKIP_NAMES or base.lower().endswith(SKIP_EXT) or len(text) > 400000:
            continue
        f, i, st = scan_file(text, rel, pkgbase)
        findings += f
        info += i
        if st:
            stats = st
    return _summarize(findings, info, {"package": pkgbase, "files_scanned": len(files), "sources": stats})


def scan(text):
    """Scan a single PKGBUILD-ish string (convenience for --text and tests)."""
    kind = "install" if re.search(r"^\s*(?:pre|post)_(?:install|upgrade|remove)\s*\(", text, re.M) and \
        not re.search(r"^\s*(?:pkgname|source)=", text, re.M) else "PKGBUILD"
    f, i, st = scan_file(text, "PKGBUILD" if kind == "PKGBUILD" else "x.install", "", kind)
    return _summarize(f, i, {"sources": st})


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------
def _fetch(url, binary=False, tries=4):
    err = None
    for i in range(tries):
        try:
            data = urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=45).read()
            return data if binary else data.decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            err = e
        except Exception as e:  # network is flaky; back off and retry
            err = e
        time.sleep(1.5 * (i + 1))
    print("aur-audit: fetch failed %s (%s)" % (url, err), file=sys.stderr)
    return None


def files_from_tar(raw):
    out = {}
    budget = ArchiveBudget()
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as t:
        for m in t:
            name = safe_member(m.name)
            if not m.isreg() or m.size > 1000000 or not name:
                continue
            rel = name.split("/", 1)[1] if "/" in name else name
            if not rel or not budget.take(m.size):
                continue
            data = t.extractfile(m).read(1000000)
            if b"\x00" in data[:4096]:
                continue
            out[rel] = data.decode("utf-8", "replace")
    return out


def pkgbase_of(name):
    js = _fetch("https://aur.archlinux.org/rpc/v5/info?arg[]=" + urllib.parse.quote(name))
    try:
        res = json.loads(js or "{}").get("results") or []
        return res[0]["PackageBase"] if res else None
    except (ValueError, KeyError):
        return None


def from_aur(name):
    base = pkgbase_of(name) or name
    raw = _fetch("https://aur.archlinux.org/cgit/aur.git/snapshot/%s.tar.gz" % urllib.parse.quote(base), binary=True)
    if not raw:
        print("aur-audit: %r not found on the AUR" % name, file=sys.stderr)
        return []
    return [("aur/" + base, files_from_tar(raw), base)]


def from_installed_foreign():
    try:
        names = subprocess.run(["pacman", "-Qqm"], capture_output=True, text=True, check=True).stdout.split()
    except (OSError, subprocess.CalledProcessError):
        print("aur-audit: `pacman -Qqm` unavailable (not an Arch system?)", file=sys.stderr)
        return []
    out = []
    for n in names:
        out += from_aur(n)
    return out


def from_path(p):
    if os.path.isdir(p):
        files = {}
        for root, dirs, fns in os.walk(p):
            dirs[:] = [d for d in dirs if d not in (".git", "src", "pkg") and not d.startswith(".")]
            for fn in fns:
                full = os.path.join(root, fn)
                if not regular_file(full):   # symlinks, FIFOs, devices: never opened
                    continue
                if ".pkg.tar" in fn or ".src.tar" in fn or os.path.getsize(full) > 1000000:
                    continue
                with open(full, "rb") as fh:
                    data = fh.read(1000000)
                if b"\x00" in data[:4096]:
                    continue
                files[os.path.relpath(full, p)] = data.decode("utf-8", "replace")
        return [(p, files, "")]
    if p != "-" and not os.path.isfile(p):
        raise ValueError("not a regular file: %s" % p)
    if p == "-":
        text = sys.stdin.read(4000000)
    else:
        with open(p, "rb") as fh:
            text = fh.read(4000000).decode("utf-8", "replace")
    rel = "PKGBUILD" if p == "-" else os.path.basename(p)
    return [(p, {rel: text}, "")]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
_ICON = {"CRITICAL": "\U0001F534", "HIGH": "\U0001F7E0", "MEDIUM": "\U0001F7E1",
         "LOW": "\U0001F535", "SAFE": "\U0001F7E2"}


# ---------------------------------------------------------------------------
# Pipeline output shared by the eltociear/*-audit family: --json / --sarif / --fail-on
# (this block is kept identical across the family; see "Output formats" in the README)
# ---------------------------------------------------------------------------
FAMILY_SCHEMA = "eltociear-audit/1"
TOOL_NAME = "aur-audit"
TOOL_URI = "https://github.com/eltociear/aur-audit"
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
    quiet = fam["json"] or fam["sarif"]
    flags = {a for a in args if a in ("--all", "--verbose")}
    args = [a for a in args if a not in flags]
    targets, mode, i, local = [], None, 0, False
    while i < len(args):
        a = args[i]
        if a == "--aur":
            mode = "aur"
        elif a == "--installed-foreign":
            targets += from_installed_foreign()
        elif a == "--text":
            targets.append(("<text>", None, args[i + 1] if i + 1 < len(args) else ""))
            i += 1
        elif mode == "aur":
            targets += from_aur(a)
        elif os.path.exists(a) or a == "-":
            local = True
            try:
                targets += from_path(a)
            except (OSError, ValueError) as e:
                print("aur-audit: %s" % e, file=sys.stderr)
        else:
            targets += from_aur(a)
        i += 1
    if not targets:
        print("aur-audit: nothing to scan", file=sys.stderr)
        if not local:
            return 1
    results, worst = [], "SAFE"
    tally = {k: 0 for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE")}
    for label, files, base in targets:
        r = scan(base) if files is None else scan_package(files, base)
        tally[r["risk_level"]] += 1
        if SEVERITY_RANK[r["risk_level"]] > SEVERITY_RANK[worst]:
            worst = r["risk_level"]
        results.append({"target": label, **r})
        if quiet:
            continue
        if r["risk_level"] == "SAFE" and "--all" not in flags and len(targets) > 1:
            continue
        print(f"{_ICON[r['risk_level']]} {label}  [{r['risk_level']}]  score={r['risk_score']}  "
              f"({r['total_findings']} findings, {r['info_count']} info)")
        for f in r["findings"]:
            print(f"    {f['severity']:8} {f['name']} ({f['file']}:{f['line']}, {f['context_block']})")
            print(f"             {f['context']}")
        if "--verbose" in flags:
            for f in r["info"]:
                print(f"    INFO     {f['name']} ({f['file']}:{f['line']}, {f['context_block']})")
    if not quiet:
        print(f"\nscanned {len(targets)}: " + ", ".join(f"{v} {k}" for k, v in tally.items() if v))
    return family_emit(results, fam)


if __name__ == "__main__":
    sys.exit(main())
