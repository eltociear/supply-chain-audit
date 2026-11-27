#!/usr/bin/env python3
"""rubygems-audit - scan Ruby gems for MALICIOUS install-time and load-time code before it runs.

`gem install` / `bundle install` run third-party Ruby on your machine before you ever call the
library: every native extension's `extconf.rb` (or Rakefile extension) runs at install, a gem's
`rubygems_plugin.rb` is loaded by EVERY later `gem` command, Bundler evaluates the `.gemspec` of
git-sourced gems, and `require` runs a library's top-level code. `bundle audit` only answers "does
this version have a known advisory?". This fills the gap: a deterministic (no LLM) static scan of
the published .gem for remote-code eval, download-and-execute, environment and credential
exfiltration, cookie/param-triggered eval backdoors, disguised executables, clipboard hijacking,
API-proxy token theft, persistence, reverse shells and worm-style republishing - weighted by WHEN
the code runs.

Precision-tuned to near-zero false positives: what popular gems do every day (mkmf probes,
`pkg-config`, mini_portile downloads with a checksum, `git ls-files` in a gemspec, class_eval
metaprogramming, `VERIFY_NONE` options, release tasks that `gem push`) is informational context
and never inflates the score. Risk comes from specific COMBINATIONS and sinks.

The gem is never installed and none of its code runs: the .gem (a tar holding metadata.gz and
data.tar.gz) is downloaded into memory and read as text. metadata.gz is parsed with a tiny YAML
subset reader, so there are no dependencies.

Usage:
  python rubygems_audit.py <gem>[@version] [...]   # fetch from rubygems.org and scan
  python rubygems_audit.py --lockfile Gemfile.lock # every rubygems.org gem in a lockfile
  python rubygems_audit.py <dir|x.gem|file.rb>     # scan a local gem / unpacked gem / file
  python rubygems_audit.py --text "some ruby"      # scan a string (as install-time code)
  add --json for machine-readable output, --verbose to print INFO context,
  --install-only to scan only code that runs at install / on every gem command

Exit code 2 if any target is HIGH or CRITICAL (CI-friendly).
No dependencies beyond the standard library. MIT licensed.
"""
import bisect
import gzip
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

__version__ = "0.1.0"

API = os.environ.get("RUBYGEMS_AUDIT_API", "https://rubygems.org/api/v1").rstrip("/")
DL = os.environ.get("RUBYGEMS_AUDIT_DL", "https://rubygems.org/downloads").rstrip("/")
RUBY_EXT = (".rb", ".rake", ".gemspec", ".ru", ".thor")
SHELL_EXT = (".sh", ".bash", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".py", ".pl")
RUBY_NAMES = ("Rakefile", "rakefile", "Gemfile", "mkrf_conf", "Thorfile")
# files whose first bytes we inspect for a disguised executable
DISGUISE_EXT = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".txt", ".dat", ".log", ".pdf", ".css",
                ".svg", ".ttf", ".woff", ".mp3", ".wav", ".md", ".json", ".yml", ".yaml", ".csv", ".xml", ".html")
EXE_MAGIC = (b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe")
SKIP_TOP = {"test", "tests", "spec", "specs", "features", "example", "examples", "benchmark", "benchmarks",
            "bench", "fixtures", "sample", "samples", "demo", "doc", "docs", "vendor"}
MAX_FILE = 2000000      # bytes per text member; bigger is generated data - skipped
MAX_TOTAL = 24000000    # bytes of text per gem
MAX_HITS = 20           # findings kept per signature per file

# Endpoints legitimate gems essentially never hard-code, but stealers love.
EXFIL_HOST = (
    r"(?:discord(?:app)?\.com/api/webhooks/|api\.telegram\.org/bot|hooks\.slack\.com/services/|"
    r"pastebin\.com/(?:raw|api)\b|\bpaste\.ee/|\bhastebin\.com\b|\bghostbin\.|\btransfer\.sh\b|\bfile\.io/|"
    r"\b0x0\.st\b|webhook\.site\b|requestbin\.(?:com|net|io)\b|requestb\.in\b|requestcatcher\.com|beeceptor\.com|"
    r"pipedream\.net\b|ngrok(?:-free)?\.(?:io|app|dev)\b|\.trycloudflare\.com\b|serveo\.net\b|localtunnel\.me|\.loca\.lt\b|"
    r"\boast\.(?:fun|me|pro|live|site|online)\b|oastify\.com|\binteract\.sh\b|\binteractsh\b|"
    r"burpcollaborator\.net|canarytokens\.com|dnslog\.cn|\bceye\.io\b|requestrepo\.com|"
    r"\.workers\.dev\b|\bzzz\.com\.ua\b)"
)
RAW_IP_URL = (r"https?://(?!(?:127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|"
              r"192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|2(?:2[4-9]|[3-5]\d)\.))\d{1,3}(?:\.\d{1,3}){3}")
# something that actually SENDS / FETCHES over the network (Ruby + shell)
NET_SEND = (
    r"(?:\bNet::HTTP(?:::(?:Get|Post|Put|Patch)\.new|\.(?:get|get_response|post|post_form|start|new|request)\b)|"
    r"\.(?:post_form|get_response|request_post|request_get)\s*\(|"
    r"\bURI\.open\b|\bURI(?:\.parse)?\s*\([^\n)]{0,200}\)\.read\b|\bopen\s*\(\s*['\"]https?://|"
    r"\b(?:HTTParty|RestClient|Faraday|Excon|Typhoeus|HTTPX|HTTPClient)\.(?:get|post|put|patch|request|new)\b|"
    r"\bHTTP\.(?:get|post|put|headers|auth)\b|\bCurl::Easy|\bCurl\.(?:get|post)\b|"
    r"\b(?:TCPSocket|UDPSocket|SSLSocket)\.(?:new|open)\b|\bSocket\.tcp\b|\bNet::FTP\.(?:new|open)\b|"
    r"\bResolv(?:::DNS)?(?:\.new)?\.(?:getaddress|getaddresses|getresource)\b|"
    r"\b(?:curl|wget)\s+(?:-[a-zA-Z-]+\s+)*['\"]?https?://|Invoke-WebRequest|DownloadFile\s*\(|DownloadString\s*\()"
)
CHECKSUM = (r"(?:Digest::(?:SHA256|SHA512|SHA2|SHA1|MD5)|OpenSSL::Digest|sha256|sha512|SHA256|checksum|"
            r"hexdigest|expected_hash|verify_checksum|integrity|MiniPortile)")
CRED_PATHS = (
    r"(?:\.gem/credentials|\.local/share/gem/credentials|rubygems_api_key|\.ssh/id_\w+|\.aws/credentials|"
    r"\.git-credentials|\.docker/config\.json|\.kube/config|\.npmrc\b|\.pypirc\b|\.netrc\b|"
    r"\.config/gcloud|\.azure/accessTokens|solana/id\.json|\.bundle/config|"
    r"Login Data\b|\bwallet\.dat\b|Exodus[\\/]|Electrum[\\/]wallets)"
)
EVAL = r"\b(?:eval|instance_eval|class_eval|module_eval|Kernel\.eval|binding\.eval|TOPLEVEL_BINDING\.eval)"
REMOTE_SRC = (r"(?:Net::HTTP\.get(?:_response)?\b|URI\.open\b|(?:Kernel\.)?open\s*\(\s*['\"]https?://|"
              r"URI(?:\.parse)?\s*\([^\n)]{0,200}\)\.read\b|(?:HTTParty|RestClient|Faraday|Excon|HTTP|HTTPX)\.get\b|"
              r"open-uri)")

PATTERNS = {
    "critical": [
        {"id": "download_execute", "name": "Download & Execute",
         "desc": "Fetches remote content and pipes it straight into a shell / interpreter",
         "regexes": [
             r"\b(?:curl|wget)(?:\.exe)?\s[^\n|;\"]{0,300}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|ruby|python3?|perl|node)\b",
             r"\b(?:sh|bash|ruby|python3?)\s*<\s*\(\s*(?:curl|wget)",
             r"wget\s+[^\n]{0,200}-O-?\s*-\s*\|\s*(?:sh|bash|ruby)",
             r"(?:iex|Invoke-Expression)\s*\(?\s*\(?\s*(?:New-Object\s+(?:System\.)?Net\.WebClient|iwr\b|Invoke-WebRequest)",
             r"powershell(?:\.exe)?[^\n]{0,60}\s-(?:e|enc|encodedcommand)\s+[\"']?[A-Za-z0-9+/=]{40,}",
         ]},
        {"id": "remote_eval", "name": "Remote Code Eval",
         "desc": "Evaluates Ruby fetched from the network (rest-client / strong_password 2019 shape)",
         "regexes": [EVAL + r"\s*\(?\s*(?:[\w:]+\.(?:new|parse)\s*\([^\n)]{0,80}\)\s*\.)?" + REMOTE_SRC,
                     EVAL + r"\s*\(?\s*[^\n]{0,40}\b(?:Net::HTTP\.get|URI\.open)\s*\("]},
        {"id": "request_eval", "name": "Request-Triggered Eval Backdoor",
         "desc": "Evaluates code taken from an HTTP cookie / param / header (bootstrap-sass 2019 shape)",
         "regexes": [r"\beval\s*\(?\s*(?:[\w:]+\.\w+\s*\(\s*){0,3}(?:(?:request|req)\.)?(?:cookies|params|headers)\s*\[",
                     r"\beval\s*\(?\s*(?:[\w:]+\.\w+\s*\(\s*){0,3}(?:request|req)\.(?:body|env|query_string|cookies|params)\b",
                     r"\beval\s*\(?\s*(?:[\w:]+\.\w+\s*\(\s*){0,3}env\s*\[\s*['\"]HTTP_"]},
        {"id": "env_exfil", "name": "Environment Dump",
         "desc": "Serialises the whole environment (every token/secret) - exfil when a network sink is present",
         "regexes": [
             r"(?:JSON\.(?:generate|dump|pretty_generate)|Marshal\.dump|YAML\.dump|Base64\.\w*encode64|encode_www_form)\s*\(\s*ENV\b(?:\.to_h(?:ash)?)?\s*\)",
             r"\bENV\.(?:to_h(?:ash)?\.)?(?:to_json|to_yaml)\b",
             r"\bENV\.(?:to_h(?:ash)?|to_a)\.(?:inspect|to_s)\b|\bENV\.inspect\b",
             r"(?:post_form|set_form_data|\.post|\.body\s*=|\.write|send_data|\.puts)\s*\(?[^\n]{0,160}\bENV\.(?:to_h(?:ash)?|to_a|inspect|map)\b(?!\.merge|\.select|\.reject|\.slice|\.except)",
         ]},
        {"id": "reverse_shell", "name": "Reverse Shell",
         "desc": "Spawns an interactive shell bound to a network socket",
         "regexes": [
             r"/dev/tcp/[\w.\-]{1,253}/\d{1,5}",
             r"bash\s+-i\s*>&",
             r"\bnc(?:at)?\s+(?:-\w{1,10}\s+){0,4}-e\s+/bin/(?:ba)?sh",
             r"\b(?:exec|spawn|system)\s*\(?\s*['\"](?:/bin/)?(?:ba|z)?sh(?:\s+-i)?['\"][^\n]{0,80}(?:\[\s*:in|:in\s*=>|\bin:\s*\w)",
         ]},
        {"id": "destructive", "name": "Destructive Payload",
         "desc": "Wipes the home directory / filesystem",
         "regexes": [
             r"\brm\s+-[a-zA-Z]{0,4}r[a-zA-Z]{0,4}\s+(?:--no-preserve-root\s+)?(?:~|\$HOME|/)(?:\s|[\"'`;&]|$)",
             r"FileUtils\.rm_r[f]?\s*\(?\s*(?:Dir\.home\b|ENV\[\s*['\"](?:HOME|USERPROFILE)['\"]\s*\]\s*[,)\s]|['\"]~/?['\"]|File\.expand_path\(\s*['\"]~/?['\"]\s*\)\s*[,)\s]|['\"]/['\"]|['\"]C:[\\/]{1,2}['\"])",
         ]},
        {"id": "worm_propagation", "name": "Self-Propagation (Worm)",
         "desc": "Republishes gems with a harvested API key, or runs a secret scanner",
         "regexes": [
             r"\bgem\s+push\b[^\n]{0,160}(?:--key|GEM_HOST_API_KEY|api_key)",
             r"rubygems\.org/api/v1/gems['\"]\s*[,)][^\n]{0,200}(?:Authorization|api_key)",
             r"trufflehog[^\n]{0,80}(?:filesystem|github|--json)",
             r"github\.com/trufflesecurity/trufflehog/releases",
         ]},
    ],
    "high": [
        {"id": "exfil_host", "name": "Exfiltration Endpoint",
         "desc": "Hard-codes a webhook / paste / tunnel / OAST / Workers collector host",
         "regexes": [EXFIL_HOST]},
        {"id": "encoded_eval", "name": "Encoded Payload Eval",
         "desc": "Evaluates a base64 / zlib / packed / reversed string (obfuscated payload)",
         "regexes": [EVAL + r"\s*\(?\s*(?:Base64\.\w*decode64|Zlib(?:::Inflate)?\.inflate|Zlib::GzipReader|"
                     r"\[[\d,\s]{40,}\]\.pack|['\"][A-Za-z0-9+/=]{60,}['\"]\.unpack1?|[\w@]+\.unpack1?\s*\(\s*['\"]m|"
                     r"\[\s*['\"][0-9a-fA-F]{40,}['\"]\s*\]\.pack|['\"][^'\"\n]{40,}['\"]\.reverse\b)"]},
        {"id": "disguised_executable", "name": "Disguised Executable",
         "desc": "Renames / copies a file with an image or text extension to an executable name",
         "regexes": [r"(?:File\.rename|FileUtils\.(?:mv|cp|copy|move|copy_file|install)|IO\.copy_stream|\bmove\b|\bcopy\b|\bren(?:ame)?\b)\s*\(?[^\n]{0,160}\.(?:png|jpe?g|gif|bmp|ico|txt|dat|log|pdf|css|svg|ttf|woff|mp3|wav)['\"][^\n]{0,160}\.(?:exe|dll|scr|bat|cmd|vbs|ps1|com|msi)['\"]"]},
        {"id": "token_proxy", "name": "API Token Proxy",
         "desc": "Sends Telegram bot-API calls (bot token in the path) to a host that is not api.telegram.org",
         "regexes": [r"https?://(?!api\.telegram\.org)[\w.\-]{3,253}(?::\d{1,5})?/bot(?:#\{|['\"]\s*\+|%s|\{)"]},
        {"id": "persistence_write", "name": "Persistence Write",
         "desc": "Writes shell rc files, authorized_keys, autostart / Startup folder, Run keys, cron or ~/.gemrc",
         "regexes": [
             r"(?:File\.(?:write|open|new|binwrite)|IO\.write|FileUtils\.(?:cp|mv|copy|install|ln_s?|touch)|>>)[^\n]{0,160}(?:\.bashrc|\.zshrc|\.bash_profile|\.zprofile|authorized_keys|LaunchAgents|LaunchDaemons|\.config/autostart|systemd/user|/etc/cron|Start Menu[\\/]{1,2}Programs[\\/]{1,2}Startup|\.gemrc\b)",
             r"(?:\.bashrc|\.zshrc|\.bash_profile|\.zprofile|authorized_keys|LaunchAgents|\.config/autostart|Start Menu[\\/]{1,2}Programs[\\/]{1,2}Startup)['\"]?\s*\)?[^\n]{0,80}(?:File\.(?:write|open)|['\"]a['\"]|\.write\b|<<\s*['\"]|\bputs\b)",
             r"\breg(?:\.exe)?\s+add\s+[^\n]{0,80}CurrentVersion[\\/]{1,2}Run",
             r"\bschtasks(?:\.exe)?\s+/create\b",
             r"\bcrontab\s+-(?!l)\w",
         ]},
        {"id": "wallet_theft", "name": "Wallet / Browser Data Theft",
         "desc": "Targets wallet keystores, browser credential stores or the macOS Keychain",
         "regexes": [
             r"nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|hnfanknocfeofbddgcijnmhnfnkdnaad|ibnejdfjmmkpcnlpebklmnkoeoihofec|egjidjbpglichdcondbcbdnbeeppgdph",
             r"(?:Google[\\/]Chrome|BraveSoftware|Microsoft[\\/]Edge|Opera Software)[^\n]{0,80}(?:Login Data|Local Extension Settings|Cookies)",
             r"(?:Exodus|atomic|Electrum)[\\/](?:exodus\.wallet|Local Storage|wallets)",
             r"security\s+find-generic-password\s+[^\n]{0,40}-w",
         ]},
        {"id": "dns_exfil", "name": "DNS Exfiltration",
         "desc": "Encodes host / user / env data into a DNS lookup (dependency-confusion beacon)",
         "regexes": [
             r"(?:getaddress(?:es)?|getresources?|gethostbyname)\s*\(\s*['\"][^'\"\n]{0,40}#\{[^}\n]{0,80}(?:hostname|Etc\.getlogin|whoami|ENV\[|\.unpack)",
             r"['\"]#\{[^}\n]{1,80}\}\.[\w-]{1,60}\.(?:oast\.\w+|oastify\.com|burpcollaborator\.net|dnslog\.cn|interact\.sh)",
         ]},
        {"id": "credential_exfil", "name": "Credential Exfiltration",
         "desc": "Reads a credential store AND names an external destination on the same line",
         "regexes": [r"(?:File\.(?:read|open|readlines|binread|foreach)|IO\.read|\bopen|\bcat)\s*\(?[^\n]{0,80}" + CRED_PATHS + r"[^\n]{0,200}(?:https?://(?!(?:rubygems\.org|api\.rubygems\.org|github\.com|localhost|127\.))|" + EXFIL_HOST + r")"]},
    ],
    "medium": [
        {"id": "raw_ip_url", "name": "Raw-IP URL",
         "desc": "Contacts a public IP address directly instead of a hostname",
         "regexes": [RAW_IP_URL]},
        {"id": "tls_disabled", "name": "TLS Verification Disabled",
         "desc": "Turns off certificate checking in code that runs at install / load time",
         "regexes": [r"verify_mode\s*=\s*OpenSSL::SSL::VERIFY_NONE", r"\bcurl\s+[^\n]{0,200}(?:\s-k\b|--insecure)",
                     r"wget\s+[^\n]{0,200}--no-check-certificate"]},
        {"id": "load_time_network", "name": "Network Call at Load Time",
         "desc": "Top-level code (not inside a method) makes a network request when the gem is required / loaded",
         "regexes": [r"\bNet::HTTP\.(?:get|get_response|post|post_form|start)\b|\bURI\.open\b|"
                     r"\b(?:HTTParty|RestClient|Faraday|Excon)\.(?:get|post)\b|\bTCPSocket\.(?:new|open)\b|"
                     r"\bopen\s*\(\s*['\"]https?://"]},
    ],
    "low": [],
    # Context: reported, never scored. Capabilities popular gems use daily.
    "info": [
        {"id": "credential_read", "name": "Credential Store Reference",
         "desc": "References ~/.gem/credentials, ~/.ssh, ~/.aws, ~/.netrc ... (CLIs read their own auth)",
         "regexes": [CRED_PATHS, r"\bGEM_HOST_API_KEY\b", r"Gem\.configuration\.rubygems_api_key"]},
        {"id": "process_spawn", "name": "Process Spawning",
         "desc": "Runs external commands (make, pkg-config, git, xcrun ...)",
         "regexes": [r"\b(?:system|spawn|exec)\s*\(|\bIO\.popen\b|\bOpen3\.\w+|%x[\(\[{]|`[^`\n]{2,200}`"]},
        {"id": "network", "name": "Network Access",
         "desc": "Makes outbound HTTP / DNS / socket calls",
         "regexes": [NET_SEND]},
        {"id": "native_build", "name": "Native Build",
         "desc": "mkmf / mini_portile / cmake / rake-compiler steps",
         "regexes": [r"\bcreate_makefile\b", r"\bMiniPortile\w*\.new\b", r"\brequire\s+['\"]mkmf['\"]",
                     r"\bfind_library\b|\bhave_header\b|\bpkg_config\s*\(", r"\bcmake\b", r"Rake::ExtensionTask"]},
        {"id": "env_read", "name": "Environment Access",
         "desc": "Reads environment variables",
         "regexes": [r"\bENV\s*\[|\bENV\.fetch\b|\bENV\.key\?"]},
        {"id": "env_gate", "name": "Environment Gate",
         "desc": "Branches on production / CI / OS (Rails.env, RAILS_ENV, CI, host_os)",
         "regexes": [r"Rails\.env(?:\.production\?|\s*\[|\s*==)|\bENV\[\s*['\"](?:RAILS_ENV|RACK_ENV|CI|GITHUB_ACTIONS|GITLAB_CI)['\"]\s*\]",
                     r"host_os['\"]?\]?\s*=~\s*/[^/\n]{0,30}(?:mswin|mingw)|Gem\.win_platform\?"]},
        {"id": "dynamic_eval", "name": "Dynamic Eval",
         "desc": "eval / instance_eval of a non-literal (metaprogramming, config DSLs)",
         "regexes": [EVAL + r"\s*\(?\s*(?![\s'\"<%])[\w@$]"]},
        {"id": "install_hook", "name": "RubyGems Install Hook",
         "desc": "Registers Gem.pre_install / post_install / done_installing hooks (run for every gem install)",
         "regexes": [r"\bGem\.(?:pre_install|post_install|pre_uninstall|post_uninstall|done_installing|post_build|pre_reset|post_reset)\b"]},
        {"id": "gem_install", "name": "Installs Gems at Install Time",
         "desc": "Gem::DependencyInstaller / `gem install` from extension code (the mkrf_conf trick)",
         "regexes": [r"Gem::DependencyInstaller|\bgem\s+install\b"]},
        {"id": "base64_decode", "name": "Base64 Decode",
         "desc": "Decodes base64 (assets, tokens, protocols)",
         "regexes": [r"Base64\.\w*decode64|\.unpack1?\s*\(\s*['\"]m"]},
        {"id": "clipboard", "name": "Clipboard Access",
         "desc": "Reads or writes the clipboard (copy-to-clipboard helpers)",
         "regexes": [r"\b(?:pbcopy|pbpaste|xclip|xsel|clip\.exe|Set-Clipboard|Get-Clipboard|SetClipboardData|GetClipboardData|clipboardData)\b|\bClipboard\.(?:copy|paste|set|get)|htmlfile[^\n]{0,60}clipboard"]},
        {"id": "crypto_address", "name": "Crypto-Address Pattern",
         "desc": "A regex for Bitcoin / Ethereum / other wallet addresses (wallet libs and validators have one)",
         "regexes": [r"\[13\]\s*\[a-km-zA-HJ-NP-Z1-9\]|\^?\(?\[13\]|\bbc1\[|0x\[a-fA-F0-9\]\{40\}|\[0-9a-fA-F\]\{40\}\b|\[48\]\[0-9AB\]"]},
        {"id": "post_install_message", "name": "Post-Install Message",
         "desc": "Text printed after install (never executed)",
         "regexes": []},
    ],
}

# literal needles: a signature only runs on a file containing one of its needles
NEEDLES = {
    "download_execute": ("curl", "wget", "iex", "invoke-expression", "powershell"),
    "remote_eval": ("eval",),
    "request_eval": ("eval",),
    "env_exfil": ("(env", "env.to_", "env.inspect", "env.map"),
    "reverse_shell": ("/dev/tcp", "bash -i", "nc ", "ncat", "sh'", "sh\"", "sh -i"),
    "destructive": ("rm ", "rm_r"),
    "worm_propagation": ("push", "api/v1/gems", "trufflehog"),
    "exfil_host": ("discord", "api.telegram", "hooks.slack", "pastebin", "paste.ee", "hastebin", "ghostbin",
                   "transfer.sh", "file.io", "0x0.st", "webhook.site", "requestb", "requestcatcher", "beeceptor",
                   "pipedream", "ngrok", "trycloudflare", "serveo", "localtunnel", "loca.lt", "oast.", "oastify",
                   "interact.sh", "interactsh", "burpcollaborator", "canarytokens", "dnslog", "ceye.io",
                   "requestrepo", "workers.dev", "zzz.com.ua"),
    "encoded_eval": ("eval",),
    "disguised_executable": (".exe", ".dll", ".scr", ".bat", ".cmd", ".vbs", ".ps1", ".com", ".msi"),
    "token_proxy": ("/bot",),
    "persistence_write": ("bashrc", "zshrc", "bash_profile", "zprofile", "authorized_keys", "launchagents",
                          "launchdaemons", "autostart", "systemd/user", "cron", "startup", "currentversion",
                          "schtasks", "gemrc"),
    "wallet_theft": ("nkbihf", "bfnaelm", "hnfankn", "ibnejdf", "egjidjb", "login data", "local extension",
                     "cookies", "exodus", "atomic", "electrum", "find-generic-password"),
    "dns_exfil": ("getaddress", "getresource", "gethostbyname", "oast", "burpcollaborator", "dnslog", "interact.sh"),
    "credential_exfil": ("credentials", "api_key", ".ssh", ".aws", ".git-cred", ".docker", ".kube", ".npmrc",
                         ".pypirc", ".netrc", "gcloud", ".azure", "solana", ".bundle", "login data", "wallet",
                         "exodus", "electrum"),
    "raw_ip_url": ("http",),
    "tls_disabled": ("verify_none", "curl", "wget"),
    "load_time_network": ("net::http", "uri.open", "httparty", "restclient", "faraday", "excon", "tcpsocket",
                          "open("),
    "credential_read": ("credentials", "api_key", ".ssh", ".aws", ".git-cred", ".docker", ".kube", ".npmrc",
                        ".pypirc", ".netrc", "gcloud", ".azure", "solana", ".bundle", "login data", "wallet",
                        "exodus", "electrum"),
    "process_spawn": ("system", "spawn", "exec", "popen", "open3", "%x", "`"),
    "network": ("net::http", "uri.open", ").read", "open(", "httparty", "restclient", "faraday", "excon",
                "typhoeus", "httpx", "httpclient", "http.", "curl", "socket", "net::ftp", "resolv", "wget",
                "invoke-webrequest", "downloadfile", "downloadstring", "post_form", "get_response",
                "request_post", "request_get"),
    "native_build": ("makefile", "miniportile", "mkmf", "find_library", "have_header", "pkg_config", "cmake",
                     "extensiontask"),
    "env_read": ("env",),
    "env_gate": ("rails.env", "rails_env", "rack_env", "ci", "github_actions", "gitlab_ci", "host_os",
                 "win_platform"),
    "dynamic_eval": ("eval",),
    "install_hook": ("gem.pre_", "gem.post_", "done_installing"),
    "gem_install": ("dependencyinstaller", "gem install"),
    "base64_decode": ("decode64", "unpack"),
    "clipboard": ("pbcopy", "pbpaste", "xclip", "xsel", "clip.exe", "clipboard"),
    "crypto_address": ("[13]", "bc1[", "a-fa-f0-9", "0-9a-fa-f", "[48]"),
}

SEVERITY_SCORE = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "SAFE": 0}
_CASE_SENSITIVE = ("crypto_address", "dynamic_eval", "remote_eval", "request_eval", "encoded_eval",
                   "env_exfil", "load_time_network", "network")
_COMPILED = [(sev, pg, re.compile(rx, 0 if pg["id"] in _CASE_SENSITIVE else re.IGNORECASE))
             for sev, groups in PATTERNS.items() for pg in groups for rx in pg["regexes"]]
NET_RE = re.compile(NET_SEND)
EXFIL_RE = re.compile(EXFIL_HOST, re.IGNORECASE)
RAWIP_RE = re.compile(RAW_IP_URL)
CHECKSUM_RE = re.compile(CHECKSUM)
SOCK_RE = re.compile(r"\b(?:TCPSocket|Socket)\.(?:new|open|tcp)\b")
FD_STDIO_RE = re.compile(r"\$?(?:stdin|STDIN)\.reopen\s*\(|\[\s*:in\s*,\s*:out|:in\s*=>\s*\w|\bin:\s*\w+\s*,\s*out:")
SHELL_LIT_RE = re.compile(r"['\"](?:/bin/(?:ba|z)?sh|sh -i|bash -i|cmd(?:\.exe)?|powershell(?:\.exe)?)['\"]")
CLIP_WRITE_RE = re.compile(r"\b(?:pbcopy|xclip|xsel|clip\.exe|Set-Clipboard|SetClipboardData)\b|clipboardData\.setData|"
                           r"\bClipboard\.(?:copy|set)|htmlfile[^\n]{0,60}clipboard|ClipboardData|['\"]clip['\"]|\|\s*clip(?:\.exe)?\b", re.I)
PERSIST_PATH_RE = re.compile(r"\.bashrc|\.zshrc|\.bash_profile|\.zprofile|authorized_keys|LaunchAgents|LaunchDaemons|"
                             r"\.config/autostart|systemd/user|Start Menu[\\/]{1,2}Programs[\\/]{1,2}Startup|"
                             r"['\"]Startup['\"]|CurrentVersion[\\/]{1,2}Run\b", re.I)
FILE_WRITE_RE = re.compile(r"\bFile\.(?:write|binwrite)\s*\(|\bIO\.write\s*\(|\bFile\.open\s*\([^\n]{0,120}['\"][wa]b?\+?['\"]|"
                           r"\bFileUtils\.(?:cp|copy|install|mv)\b")
CRYPTO_RX_RE = re.compile(r"\[13\]\s*\[a-km-zA-HJ-NP-Z1-9\]|\bbc1\[|0x\[a-fA-F0-9\]\{40\}|\[48\]\[0-9AB\]")
# Remote-source assignment + later eval of that variable (multi-line remote eval)
REMOTE_ASSIGN_RE = re.compile(r"(?m)^[ \t]*(@{0,2}\w+)\s*=\s*[^\n]{0,120}?" + REMOTE_SRC + r"[^\n]{0,200}$")
REQ_ASSIGN_RE = re.compile(r"(?m)(?:^|;)[ \t]*(@{0,2}\w+)\s*=\s*(?:(?:request|req)\.)?(?:cookies|params|headers)\s*\[[^\n]{0,80}$|"
                           r"(?:^|;)[ \t]*(@{0,2}\w+)\s*=\s*env\s*\[\s*['\"]HTTP_[^\n]{0,80}$")
WIN_EXE_RUN_RE = re.compile(r"(?:\b(?:system|spawn|exec)\s*\(?|IO\.popen\s*\(|`|%x\()[^\n]{0,160}?([\w.\-]{1,80}\.exe)\b", re.I)
TOOLCHAIN_EXE = re.compile(r"^(?:cl|nmake|link|lib|gcc|g\+\+|make|mingw32-make|cmake|msbuild|devenv|vcvars\w*|where|cmd|"
                           r"powershell|pwsh|ridk|pacman|bash|sh|git|pkg-config|ruby|rake|gem|bundle|cc|ld|ar|strip|"
                           r"windres|dlltool|nasm|yasm|perl|python\w*|reg|tar|7z|unzip|curl|wget|signtool|mt|rc|"
                           r"cygpath|uname)\.exe$", re.I)
EXEC_SINK_RE = re.compile(r"\b(?:system|exec|spawn|sh|run|popen|capture[23]\w*|popen[23]\w*)\s*[\(\s'\"]|`|%x[\(\[{]|\bOpen3\.|IO\.popen|Kernel\.(?:system|exec|spawn)")
SCRIPT_RE = re.compile(r"(?m)^(?:\w+\s*=\s*)?OptionParser\.new\b|^[^\s#][^\n]*\bARGV\b|^ARGV\b")
DEFERRED_RE = re.compile(r"\b(?:proc|lambda|Proc\.new|define_method|define_singleton_method)\s*(?:\([^)]*\))?\s*(?:\{|do\b)|->\s*(?:\([^)]*\))?\s*\{")
MSG_LINE_RE = re.compile(
    r"^\s*(?:puts|print|p|pp|warn|abort|raise|fail|say|desc|\$stderr\.|\$stdout\.|STDERR\.|STDOUT\.|"
    r"(?:\w+\.)?(?:logger|log|ui|UI|shell)\.(?:info|warn|debug|error|fatal|message|important|success|say|puts|"
    r"user_error!|crash!|header)|Kernel\.(?:warn|abort|puts)|(?:message|msg|summary|description|banner|help)\s*[:=]|"
    r"s\.post_install_message|spec\.post_install_message)\b")
LINE_ONCE = ("network", "env_read", "process_spawn", "native_build", "credential_read", "base64_decode",
             "dynamic_eval", "env_gate", "clipboard", "crypto_address", "install_hook", "gem_install")
MSG_DEMOTE_EXEMPT = ("remote_eval", "request_eval", "encoded_eval")

# ctx kinds (when the code runs)
#   install  : extension entry (extconf.rb / Rakefile / mkrf_conf.rb) and what it loads - runs at `gem install`
#   plugin   : rubygems_plugin.rb and its top-level requires - runs on EVERY `gem` command once installed
#   gemspec  : the .gemspec - evaluated by Bundler for git / path sources and by `gem build`
#   require  : top-level (non-method) code in require_paths - runs at `require`
#   runtime  : method bodies, bin/ executables - runs only when called
#   aux      : dev Rakefile, tasks/, scripts nothing references - capped at MEDIUM
#   message  : post_install_message text - INFO only
ESCALATE = {"install", "plugin", "gemspec", "require"}
EARLY = {"install", "plugin", "gemspec"}


def _item(sev, pid, name, desc, path, n, matched="", ctx=""):
    return {"severity": sev, "id": pid, "name": name, "description": desc, "file": path,
            "line": n, "matched": (matched or "")[:120], "context": (ctx or "").strip()[:200]}


class _Lines:
    """Offset -> line number with bisect (never text.count per match)."""

    def __init__(self, text):
        self.nl = [m.start() for m in re.finditer("\n", text)]

    def line(self, off):
        return bisect.bisect_right(self.nl, off) + 1 if off >= 0 else 0


# ---------------------------------------------------------------------------
# Ruby source model: comments, heredocs, method nesting (crude but linear)
# ---------------------------------------------------------------------------
_HEREDOC_RE = re.compile(r"<<([~-]?)(['\"`]?)([A-Za-z_]\w*)\2")
_STR_RE = re.compile(r"\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'|%[wWiIqQ]?([\[({<|!/])")
_PAIR = {"[": "]", "(": ")", "{": "}", "<": ">"}
_KW_RE = re.compile(r"(?<![\w.:@$?!])(def|class|module|if|unless|while|until|case|begin|for|do|end)(?![\w?!]|:(?!:))")
_STMT_PREFIX = re.compile(r"(?:^|[;=(,|&!\[{]|\b(?:return|then|else|do|begin|not|and|or|in))\s*$")
_ENDLESS_DEF = re.compile(r"\bdef\s+(?:self\.)?[\w?!]+(?:\s*\([^)]*\))?\s+=(?![=~>])|\bdef\s+(?:self\.)?[\w?!]+\([^)]*\)\s*=(?![=~>])")
_DEFLIKE_BLOCK = re.compile(r"\b(?:define_method|define_singleton_method|lambda|proc|Proc\.new|task|rule|initializer|"
                            r"on_load|to_prepare|after_initialize|before|after|around|included|extended|prepended|"
                            r"class_methods|helpers|get|post|put|patch|delete|let|it|describe|context|namespace|"
                            r"method_missing|configure|setup|run|command|action)\b[^\n]*$|->\s*(?:\([^)]*\))?\s*$")


def _blank(s):
    return re.sub(r"[^\n]", " ", s)


def _mask_strings(line):
    """Replace string-literal contents on one line with spaces (keeps offsets)."""
    out, i = [], 0
    while True:
        m = _STR_RE.search(line, i)
        if not m:
            out.append(line[i:])
            break
        out.append(line[i:m.start()])
        if m.group(1):  # %w[ ... ] style
            close = _PAIR.get(m.group(1), m.group(1))
            z = line.find(close, m.end())
            z = len(line) if z < 0 else z + 1
            out.append(" " * (z - m.start()))
            i = z
        else:
            out.append(m.group(0)[0] + " " * (len(m.group(0)) - 2) + m.group(0)[-1])
            i = m.end()
    return "".join(out)


def ruby_model(text):
    """Return (code, in_def, msg_lines) where `code` is text with comments blanked (same
    offsets), in_def[i] is True when line i+1 sits inside a method / deferred block, and
    msg_lines is the set of 1-based line numbers inside the body of a heredoc or multi-line
    string opened by a message / doc line (desc, puts, raise, banner = ...)."""
    lines = text.split("\n")
    out = []
    in_def = []
    heredoc = set()
    stack = []
    pending = []          # heredoc terminators opened on the current line
    msg_lines = set()
    mstr = None           # (quote, is_msg) while inside a multi-line string literal
    in_block_comment = False
    data_section = False
    for idx, raw in enumerate(lines):
        if data_section:
            out.append(_blank(raw))
            in_def.append(True)
            continue
        if pending:
            heredoc.add(idx + 1)
            out.append(raw)
            in_def.append(any(k in ("def", "deflike") for k in stack))
            term, squiggly, is_msg = pending[0]
            if is_msg:
                msg_lines.add(idx + 1)
            if (raw.strip() if squiggly else raw.rstrip()) == term:
                pending.pop(0)
            continue
        if mstr:
            out.append(raw)
            in_def.append(any(k in ("def", "deflike") for k in stack))
            if mstr[1]:
                msg_lines.add(idx + 1)
            if re.search(r"(?<!\\)" + re.escape(mstr[0]), raw):
                mstr = None
            continue
        if in_block_comment:
            out.append(_blank(raw))
            in_def.append(any(k in ("def", "deflike") for k in stack))
            if raw.startswith("=end"):
                in_block_comment = False
            continue
        if raw.startswith("=begin"):
            in_block_comment = True
            out.append(_blank(raw))
            in_def.append(any(k in ("def", "deflike") for k in stack))
            continue
        if raw.rstrip() == "__END__":
            data_section = True
            out.append(_blank(raw))
            in_def.append(True)
            continue
        masked = _mask_strings(raw)
        # trailing / full-line comment: first '#' outside a string that isn't interpolation
        h = masked.find("#")
        while h >= 0 and h + 1 < len(masked) and masked[h + 1] == "{":
            h = masked.find("#", h + 1)
        code_line = raw
        if h >= 0 and not (h > 0 and masked[h - 1] in "?$"):
            code_line = raw[:h] + " " * (len(raw) - h)
            masked = masked[:h]
        out.append(code_line)
        is_msg = bool(MSG_LINE_RE.match(raw))
        for m in _HEREDOC_RE.finditer(masked):
            # skip `a << b` style shifts: heredoc ids are usually UPPER or quoted
            if m.group(1) or m.group(2) or m.group(3).isupper():
                pending.append((m.group(3), bool(m.group(1)), is_msg))
        # an unterminated quote opens a multi-line string literal
        if masked.count('"') % 2 == 1:
            mstr = ('"', is_msg)
        elif masked.count("'") % 2 == 1 and "?'" not in masked:
            mstr = ("'", is_msg)
        start_in = any(k in ("def", "deflike") for k in stack)
        opened_def = False
        loop_open = False
        for km in _KW_RE.finditer(masked):
            kw = km.group(1)
            prefix = masked[:km.start()]
            if kw == "end":
                if stack:
                    stack.pop()
                continue
            if kw == "def":
                if _ENDLESS_DEF.search(masked[km.start():]):
                    opened_def = True
                    continue
                stack.append("def")
                opened_def = True
            elif kw in ("class", "module"):
                nxt = masked[km.end():km.end() + 3]
                if re.match(r"\s+[A-Z<:]|\s*<<", nxt + " "):
                    stack.append(kw)
            elif kw in ("if", "unless", "while", "until", "case", "for"):
                if _STMT_PREFIX.search(prefix):
                    stack.append(kw)
                    if kw in ("while", "until", "for"):
                        loop_open = True
            elif kw == "begin":
                stack.append(kw)
            elif kw == "do":
                if loop_open:
                    loop_open = False
                    continue
                stack.append("deflike" if _DEFLIKE_BLOCK.search(prefix) else "do")
        in_def.append(start_in or opened_def)
    return "\n".join(out), in_def, msg_lines


def _decomment_shell(text, path):
    p = path.lower()
    if p.endswith((".bat", ".cmd")):
        return re.sub(r"(?mi)^\s*(?:@?rem\b|::)[^\n]*", lambda m: _blank(m.group(0)), text)
    if p.endswith(".vbs"):
        return re.sub(r"(?m)^\s*'[^\n]*", lambda m: _blank(m.group(0)), text)
    return re.sub(r"(?m)^\s*#(?!!)[^\n]*", lambda m: _blank(m.group(0)), text)


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------
def _demote(f, why):
    f["severity"] = "INFO"
    f["demoted"] = why


def _scan_text(text, path, findings, info, ctx, gem_files=None):
    """ctx: a ctx kind, or 'lib' (per-line require/runtime from the method model)."""
    is_ruby = not path.lower().endswith(SHELL_EXT)
    if is_ruby:
        code, in_def, msg_lines = ruby_model(text)
    else:
        code, in_def, msg_lines = _decomment_shell(text, path), None, set()
    if not code.strip():
        return
    if ctx == "lib" and SCRIPT_RE.search(code):
        ctx = "bin"   # a command script kept under lib/ (top-level ARGV / OptionParser): runs when invoked
    lower = code.lower()
    lines = _Lines(code)
    src_lines = code.split("\n")
    local, seen = [], set()
    needle_lines = {}

    def lines_for(needle):
        """1-based line numbers containing needle (str.find loop: C speed, no regex)."""
        got = needle_lines.get(needle)
        if got is None:
            got = set()
            i = lower.find(needle)
            while i >= 0:
                got.add(lines.line(i))
                e = lower.find("\n", i)
                if e < 0:
                    break
                i = lower.find(needle, e)
            needle_lines[needle] = got
        return got

    def candidates(needles, src=None):
        """(subtext, linemap): only the lines that hold a needle, so long generated files cost
        one substring search per needle instead of a full regex pass per signature."""
        cand = set()
        for x in needles:
            cand |= lines_for(x)
        if not cand:
            return "", []
        src = src_lines if src is None else src
        order = sorted(cand)
        return "\n".join(src[n - 1] for n in order if n - 1 < len(src)), order

    def line_ctx(n):
        if ctx == "lib":
            return "runtime" if in_def and 0 < n <= len(in_def) and in_def[n - 1] else "require"
        if ctx == "plugin-lib":
            return "runtime" if in_def and 0 < n <= len(in_def) and in_def[n - 1] else "plugin"
        return ctx

    for sev, pg, rx in _COMPILED:
        pid = pg["id"]
        if not pg["regexes"] or (pid, 0) in seen:
            continue
        sub, lmap = candidates(NEEDLES[pid])
        if not lmap:
            continue
        sl = _Lines(sub)
        hits = 0
        for m in rx.finditer(sub):
            k = sl.line(m.start())
            n = lmap[k - 1]
            key = (pid, n)
            if key in seen:
                continue
            seen.add(key)
            ltxt = src_lines[n - 1] if n - 1 < len(src_lines) else ""
            if len(ltxt) > 400:
                off = m.start() - (sl.nl[k - 2] + 1 if k > 1 else 0)
                ltxt = ltxt[max(0, off - 150):off + 150]
            f = _item(sev.upper(), pid, pg["name"], pg["desc"], path, n, m.group(0), ltxt)
            f["ctx"] = line_ctx(n)
            if sev != "info" and pid not in MSG_DEMOTE_EXEMPT and (n in msg_lines or MSG_LINE_RE.match(src_lines[n - 1])):
                _demote(f, "message / doc text")
            local.append(f)
            hits += 1
            if pid in LINE_ONCE:
                seen.add((pid, 0))
                break
            if hits >= MAX_HITS:
                break
    live = {f["id"] for f in local if f["severity"] != "INFO" or f["id"] in LINE_ONCE}
    # message lines (puts / abort / raise / desc ...) describe; they don't send
    sub, lmap = candidates(NEEDLES["network"])
    has_net = False
    if lmap:
        has_net = bool(NET_RE.search("\n".join("" if MSG_LINE_RE.match(src_lines[n - 1]) else src_lines[n - 1]
                                                for n in lmap)))

    def nomsg():
        return "\n".join(_blank(ln) if MSG_LINE_RE.match(ln) else ln for ln in src_lines)

    def has_exfil():
        return bool(EXFIL_RE.search(candidates(NEEDLES["exfil_host"])[0]))

    def has_rawip():
        return bool(RAWIP_RE.search(candidates(("http",))[0]))
    ctxs = {f["ctx"] for f in local}
    early = bool(ctxs & EARLY) or ctx in EARLY

    def add(sev, pid, name, desc, n=0, matched="", context="file-level combination", c=None):
        f = _item(sev, pid, name, desc, path, n, matched, context)
        f["ctx"] = c or (line_ctx(n) if n else (ctx if ctx not in ("lib", "plugin-lib") else
                                                ("plugin" if ctx == "plugin-lib" else "require")))
        local.append(f)
        return f

    def demote_ids(idset, why):
        for f in local:
            if f["id"] in idset and f["severity"] != "INFO":
                _demote(f, why)

    # ---- combination rules ----------------------------------------------------------
    if "env_exfil" in live and not has_net:
        demote_ids({"env_exfil"}, "no network sink in file")
    if "exfil_host" in live and not has_net:
        demote_ids({"exfil_host"}, "no network sink in file")
    if "raw_ip_url" in live and not (early or "credential_read" in live or "env_exfil" in live):
        demote_ids({"raw_ip_url"}, "runtime code")
    if "tls_disabled" in live and not early:
        demote_ids({"tls_disabled"}, "runtime option")
    # persistence / worm in method bodies are CLI features (completions installers, release tools)
    for f in local:
        if f["id"] in ("persistence_write", "worm_propagation") and f["severity"] != "INFO" \
                and f["ctx"] in ("runtime", "aux", "require") and not early:
            if not (f["id"] == "persistence_write" and f["ctx"] == "require" and has_net):
                _demote(f, "runs only when a command is invoked")
    # a pipe-to-shell string in library code that no spawn call on the line runs is a command
    # template (deploy tools, installers' help); it only runs if something executes it later
    for f in local:
        if f["id"] == "download_execute" and f["severity"] != "INFO" and f["ctx"] in ("require", "runtime", "bin"):
            ln = src_lines[f["line"] - 1] if 0 < f["line"] <= len(src_lines) else ""
            if not EXEC_SINK_RE.search(ln):
                f["severity"] = "MEDIUM"
                f["ctx"] = "runtime"
                f["description"] += " [command string; no spawn call on the line]"
    # load-time network only counts outside method bodies and deferred blocks
    for f in local:
        if f["id"] == "load_time_network" and f["severity"] != "INFO":
            ln = src_lines[f["line"] - 1] if 0 < f["line"] <= len(src_lines) else ""
            if f["ctx"] not in ("require", "plugin", "gemspec") or DEFERRED_RE.search(ln.split(f["matched"][:20])[0]):
                _demote(f, "inside a method / deferred block, not load-time")
    # multi-line remote eval: x = Net::HTTP.get(...) ... eval(x)
    if "remote_eval" not in live and "eval" in code:
        for m in REMOTE_ASSIGN_RE.finditer(code):
            var = m.group(1)
            em = re.search(EVAL + r"\s*\(?\s*(?:[\w:]+\.\w+\s*\(\s*)?" + re.escape(var) + r"\b(?!\s*=[^=~])", code[m.end():])
            if em:
                n = lines.line(m.end() + em.start())
                add("CRITICAL", "remote_eval", "Remote Code Eval",
                    "Fetches Ruby from the network into a variable and evaluates it", n, em.group(0),
                    src_lines[n - 1] if n - 1 < len(src_lines) else "")
                break
    # cookie / param / header assigned then eval'd: bootstrap-sass 3.2.0.3 shape
    if "request_eval" not in live and "eval" in code:
        for m in REQ_ASSIGN_RE.finditer(code):
            var = m.group(1) or m.group(2)
            em = re.search(r"\beval\s*\(?\s*(?:[\w:]+\.\w+\s*\(\s*){0,3}" + re.escape(var) + r"\b", code[m.end():m.end() + 2000])
            if em:
                n = lines.line(m.end() + em.start())
                add("CRITICAL", "request_eval", "Request-Triggered Eval Backdoor",
                    "Takes a cookie / param / header value and evaluates it as Ruby", n, em.group(0),
                    src_lines[n - 1] if n - 1 < len(src_lines) else "")
                break
    # credential store + exfil host / raw IP (anywhere), or + any network in early code
    if "credential_read" in live and (has_exfil() or (early and has_net) or (has_net and has_rawip())):
        add("CRITICAL", "credential_exfil", "Credential Exfiltration",
            "Reads a credential store and talks to the network in the same file")
    # reverse shell across lines: socket + stdio wiring + shell literal
    if "reverse_shell" not in live and "socket" in lower and SOCK_RE.search(code) and FD_STDIO_RE.search(code) \
            and SHELL_LIT_RE.search(text):
        add("CRITICAL", "reverse_shell", "Reverse Shell",
            "Opens a socket and wires it into a spawned shell's stdio")
    # persistence path held in a variable, then written (path and write on different lines)
    if early and "persistence_write" not in live and PERSIST_PATH_RE.search(code) and FILE_WRITE_RE.search(nomsg()):
        m = PERSIST_PATH_RE.search(code)
        n = lines.line(m.start())
        add("HIGH", "persistence_write", "Persistence Write",
            "Builds a shell-rc / autostart / Startup-folder path and writes a file in install-time code", n,
            m.group(0), src_lines[n - 1] if n - 1 < len(src_lines) else "")
    # clipboard hijack: crypto-address regex + clipboard write (atlas-client family)
    if "crypto_address" in live and CRYPTO_RX_RE.search(text) and CLIP_WRITE_RE.search(text):
        add("HIGH", "clipboard_hijack", "Clipboard Crypto-Address Hijack",
            "Matches wallet addresses and writes the clipboard in the same file")
    # Windows executable run from install-time code (not a toolchain binary)
    if early:
        for m in WIN_EXE_RUN_RE.finditer(code):
            exe = posixpath.basename(m.group(1).replace("\\", "/"))
            if TOOLCHAIN_EXE.match(exe):
                continue
            n = lines.line(m.start())
            if MSG_LINE_RE.match(src_lines[n - 1] if n - 1 < len(src_lines) else ""):
                continue
            add("HIGH", "install_runs_exe", "Install-Time Executable Run",
                "Runs a bundled / dropped .exe from code that runs at install", n, m.group(0),
                src_lines[n - 1] if n - 1 < len(src_lines) else "")
            break
    # disguised binary shipped in the gem and referenced by this file
    for dp in (gem_files or {}).get("__disguised__", ()):
        b = posixpath.basename(dp)
        if b and b in text:
            n = lines.line(code.find(b)) if b in code else 0
            add("HIGH", "disguised_executable", "Disguised Executable",
                "References %s, which is an executable with a non-executable extension" % b, n, b,
                src_lines[n - 1] if n and n - 1 < len(src_lines) else "")
            break
    # telegram proxy + exfil host = token exfiltration (fastlane-plugin 2025 shape)
    if "token_proxy" in live and has_net and has_exfil():
        add("CRITICAL", "token_exfil", "Bot-Token Exfiltration",
            "Routes bot-API calls (token in the URL) through a tunnel / Workers / collector host")
    # install-time network: prebuilt-library fetchers are normal IF they verify a checksum
    if ctx == "install" and has_net and not CHECKSUM_RE.search(code) and not any(
            f["id"] in ("download_execute", "remote_eval", "credential_exfil", "env_exfil") and f["severity"] != "INFO"
            for f in local):
        add("MEDIUM", "unverified_download", "Unverified Install-Time Download",
            "extension code fetches over the network with no checksum verification in the file")

    # ---- context: escalate early code, cap code nothing runs -------------------------
    for f in local:
        if f["severity"] == "INFO":
            continue
        c = f.get("ctx")
        if c in ESCALATE and f["severity"] == "HIGH":
            f["severity"] = "CRITICAL"
            f["description"] += " [runs at %s]" % {"install": "gem install", "plugin": "every gem command",
                                                     "gemspec": "bundle / gem build", "require": "require"}[c]
        elif c == "aux" and SEV_ORDER[f["severity"]] > SEV_ORDER["MEDIUM"]:
            f["severity"] = "MEDIUM"
            f["description"] += " [in a file nothing installs or loads]"
        elif c == "message":
            _demote(f, "post-install message")
    for f in local:
        (info if f["severity"] == "INFO" else findings).append(f)


# ---------------------------------------------------------------------------
# metadata.gz (YAML gemspec) - tiny subset reader, no PyYAML
# ---------------------------------------------------------------------------
def _yscalar(v):
    v = v.strip()
    if v in ("", "~", "null"):
        return None
    if v == "[]":
        return []
    if v == "{}":
        return {}
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        s = v[1:-1]
        if v[0] == '"':
            try:
                return json.loads('"' + s.replace("\t", "\\t") + '"')
            except ValueError:
                return s
        return s.replace("''", "'")
    if v.startswith("!ruby/object:Gem::Version"):
        return None
    return v


def parse_metadata(yaml_text):
    """Return the gemspec fields we use from a RubyGems YAML gemspec."""
    meta = {"name": "", "version": "", "platform": "ruby", "extensions": [], "executables": [],
            "require_paths": ["lib"], "bindir": "bin", "post_install_message": None, "files": []}
    lines = yaml_text.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r"^([a-z_]+):(?:\s(.*))?$", line)
        if not m:
            i += 1
            continue
        key, val = m.group(1), (m.group(2) or "")
        i += 1
        if key == "version":
            # !ruby/object:Gem::Version\n  version: 1.2.3
            while i < len(lines) and lines[i].startswith(" "):
                mm = re.match(r"^\s+version:\s*(.+)$", lines[i])
                if mm:
                    meta["version"] = str(_yscalar(mm.group(1)))
                i += 1
            if not meta["version"] and val and not val.startswith("!"):
                meta["version"] = str(_yscalar(val))
            continue
        if key in ("extensions", "executables", "require_paths", "files"):
            if val.strip() and val.strip() != "[]":
                meta[key] = [x for x in (_yscalar(t) for t in val.strip("[] ").split(",")) if x]
                continue
            items = []
            while i < len(lines) and lines[i].startswith("- "):
                items.append(_yscalar(lines[i][2:]))
                i += 1
            meta[key] = [x for x in items if isinstance(x, str)]
            if key == "require_paths" and not meta[key]:
                meta[key] = ["lib"]
            continue
        if key == "post_install_message":
            v = val.strip()
            if v.startswith(("|", ">")):
                body = []
                while i < len(lines) and (lines[i].startswith(" ") or not lines[i].strip()):
                    body.append(lines[i].strip())
                    i += 1
                meta[key] = "\n".join(body).strip()
            elif v.startswith(("'", '"')) and not (len(v) > 1 and v[-1] == v[0]):
                body = [v]
                while i < len(lines) and lines[i].startswith(" "):
                    body.append(lines[i].strip())
                    i += 1
                meta[key] = _yscalar(" ".join(body))
            else:
                meta[key] = _yscalar(v)
            continue
        if key in ("name", "platform", "bindir"):
            sv = _yscalar(val)
            if isinstance(sv, str):
                meta[key] = sv
    return meta


def gemspec_meta(text):
    """Best-effort fields from a Ruby .gemspec (local directories have no metadata.gz)."""
    meta = {"name": "", "version": "", "platform": "ruby", "extensions": [], "executables": [],
            "require_paths": ["lib"], "bindir": "bin", "post_install_message": None, "files": []}
    m = re.search(r"\.name\s*=\s*['\"]([^'\"]+)", text)
    if m:
        meta["name"] = m.group(1)
    m = re.search(r"\.version\s*=\s*['\"]([^'\"]+)", text)
    if m:
        meta["version"] = m.group(1)
    for m in re.finditer(r"\.extensions\s*(?:=|<<|\+=|\.concat)\s*\(?\s*(?:%w[\[(]([^\])]*)[\])]|\[([^\]]*)\]|['\"]([^'\"]+)['\"])", text):
        if m.group(1):
            meta["extensions"] += m.group(1).split()
        elif m.group(2):
            meta["extensions"] += re.findall(r"['\"]([^'\"]+)['\"]", m.group(2))
        elif m.group(3):
            meta["extensions"].append(m.group(3))
    m = re.search(r"\.require_paths\s*=\s*(?:%w[\[(]([^\])]*)[\])]|\[([^\]]*)\])", text)
    if m:
        meta["require_paths"] = (m.group(1) or "").split() or re.findall(r"['\"]([^'\"]+)['\"]", m.group(2) or "") or ["lib"]
    m = re.search(r"\.bindir\s*=\s*['\"]([^'\"]+)", text)
    if m:
        meta["bindir"] = m.group(1)
    m = re.search(r"\.post_install_message\s*=\s*(?:<<[~-]?['\"]?(\w+)['\"]?\n(.*?)\n\s*\1|['\"]([^'\"]*)['\"])", text, re.S)
    if m:
        meta["post_install_message"] = m.group(2) or m.group(3)
    return meta


# ---------------------------------------------------------------------------
# Which files run when
# ---------------------------------------------------------------------------
def _norm(p):
    p = posixpath.normpath(p.replace("\\", "/"))
    return p[2:] if p.startswith("./") else p


def _resolve_requires(files, entry, out, require_paths, follow_lib=True):
    """Follow require_relative / load / require File.join(__dir__,..) / require 'x' (when x is
    inside this gem's require paths) from entry. Returns the set of files reached."""
    if entry in out or entry not in files:
        return
    out.add(entry)
    text = files[entry]
    base = posixpath.dirname(entry)
    for m in re.finditer(r"\brequire_relative\s*\(?\s*['\"]([^'\"#]+)['\"]", text):
        cand = _norm(posixpath.join(base, m.group(1)))
        for c in (cand, cand + ".rb"):
            if c in files:
                _resolve_requires(files, c, out, require_paths, follow_lib)
                break
    for m in re.finditer(r"\b(?:load|require)\s*\(?\s*File\.(?:join|expand_path)\s*\(\s*(?:__dir__|File\.dirname\(\s*__FILE__\s*\))\s*,\s*['\"]([^'\"#]+)['\"]", text):
        cand = _norm(posixpath.join(base, m.group(1)))
        for c in (cand, cand + ".rb"):
            if c in files:
                _resolve_requires(files, c, out, require_paths, follow_lib)
                break
    for m in re.finditer(r"\bload\s*\(?\s*['\"]([^'\"#]+\.(?:rb|rake))['\"]", text):
        cand = _norm(posixpath.join(base, m.group(1)))
        if cand in files:
            _resolve_requires(files, cand, out, require_paths, follow_lib)
    if follow_lib:
        for m in re.finditer(r"(?m)^\s*require\s*\(?\s*['\"]([\w/\-.]+)['\"]", text):
            for rp in require_paths:
                c = _norm(posixpath.join(rp, m.group(1) + ".rb"))
                if c in files:
                    _resolve_requires(files, c, out, require_paths, follow_lib)
                    break


def run_contexts(files, meta):
    """Return {path: ctx} for code with a known run-time."""
    ctx = {}
    rps = [_norm(r) for r in (meta.get("require_paths") or ["lib"])] or ["lib"]
    # install: declared extensions; for local dirs without metadata also any ext/**/extconf.rb
    exts = [_norm(e) for e in meta.get("extensions") or []]
    if meta.get("_local") and not exts:
        exts = [p for p in files if re.match(r"^ext/(?:.*/)?(?:extconf\.rb|mkrf_conf\.rb|Rakefile)$", p)]
    for e in exts:
        reach = set()
        _resolve_requires(files, e, reach, rps, follow_lib=False)
        if posixpath.basename(e).lower() in ("rakefile", "rakefile.rb") or e.endswith(".rake"):
            d = posixpath.dirname(e)
            for p in files:
                if p.endswith(".rake") and (posixpath.dirname(p) == d or p.startswith(posixpath.join(d, "rakelib/"))):
                    _resolve_requires(files, p, reach, rps, follow_lib=False)
        for p in reach:
            ctx[p] = "install"
    # plugin: rubygems_plugin.rb in a require path (loaded by every `gem` command)
    for rp in rps:
        pp = _norm(posixpath.join(rp, "rubygems_plugin.rb"))
        if pp in files:
            reach = set()
            _resolve_requires(files, pp, reach, rps)
            for p in reach:
                ctx.setdefault(p, "plugin-lib")
            ctx[pp] = "plugin-lib"
    for p in files:
        if p in ctx:
            continue
        if "/" not in p and p.endswith(".gemspec"):
            ctx[p] = "gemspec"
    return ctx


def classify(path, meta, ctxmap):
    """ctx for one file, or None to skip."""
    if path in ctxmap:
        return ctxmap[path]
    top = path.split("/", 1)[0]
    if "/" in path and top in SKIP_TOP:
        return None
    base = posixpath.basename(path)
    rps = [_norm(r) for r in (meta.get("require_paths") or ["lib"])]
    bindir = _norm(meta.get("bindir") or "bin")
    if path.startswith(bindir + "/") or path.startswith("exe/"):
        return "bin"
    in_rp = any(path.startswith(rp + "/") for rp in rps if rp != ".")
    if in_rp and path.endswith(".rb"):
        if re.search(r"/templates?/|/generators?/[^/]+/templates/|/skeleton/|/fixtures?/|/spec/|/test/", path):
            return "aux"
        return "lib"
    if in_rp and path.endswith(".rake"):
        return "runtime"   # lib/tasks/*.rake run only when a rake task is invoked
    if path.endswith(RUBY_EXT) or base in RUBY_NAMES or path.endswith(SHELL_EXT):
        return "aux"
    return None


def scan_gem(files, meta=None, label="", install_only=False, heads=None):
    """files: {relative_path: text}. meta: parse_metadata() dict. heads: {path: first bytes}
    for non-text members (disguised-executable check). Returns an audit result dict."""
    meta = meta or {}
    if not meta.get("name"):
        gs = [p for p in files if "/" not in p and p.endswith(".gemspec")]
        if gs:
            gm = gemspec_meta(files[gs[0]])
            gm["_local"] = meta.get("_local", True)
            for k, v in meta.items():
                if v:
                    gm[k] = v
            meta = gm
        else:
            meta = dict({"require_paths": ["lib"], "bindir": "bin", "extensions": [], "_local": True}, **meta)
    findings, info = [], []
    disguised = []
    for p, b in (heads or {}).items():
        if p.lower().endswith(DISGUISE_EXT) and b[:4].startswith(EXE_MAGIC):
            disguised.append(p)
    for p in disguised:
        findings.append(dict(_item("HIGH", "disguised_binary", "Disguised Binary",
                                   "Ships an executable (PE / ELF / Mach-O header) under a non-executable extension",
                                   p, 0, "", "file header"), ctx="data"))
    ctxmap = run_contexts(files, meta)
    total = 0
    order = sorted(files, key=lambda p: (p not in ctxmap, p))
    gf = {"__disguised__": disguised}
    for path in order:
        c = classify(path, meta, ctxmap)
        if c is None:
            continue
        if install_only and c not in ("install", "plugin-lib", "gemspec"):
            continue
        total += len(files[path])
        if total > MAX_TOTAL:
            info.append(_item("INFO", "truncated", "Scan Truncated", "Gem exceeds %d bytes of text" % MAX_TOTAL,
                              path, 0, "", ""))
            break
        _scan_text(files[path], path, findings, info, c, gf)
    # an install-context reference to a disguised binary is the atlas-client shape
    for f in findings:
        if f["id"] == "disguised_binary" and any(g["id"] == "disguised_executable" and g.get("ctx") in EARLY
                                                 for g in findings):
            f["severity"] = "CRITICAL"
            f["description"] += " [referenced from install-time code]"
    pim = meta.get("post_install_message")
    if pim:
        info.append(dict(_item("INFO", "post_install_message", "Post-Install Message",
                               "Text printed after install (never executed)", "metadata", 0, "", str(pim)[:200]),
                         ctx="message"))
        _scan_text(str(pim), "post_install_message", findings, info, "message")
    r = _summarise(findings, info, label or ("%s@%s" % (meta.get("name"), meta.get("version"))))
    r["run_time"] = {
        "extensions": sorted(p for p, k in ctxmap.items() if k == "install"),
        "declared_extensions": meta.get("extensions") or [],
        "rubygems_plugin": sorted(p for p, k in ctxmap.items() if k == "plugin-lib"),
        "gemspec": sorted(p for p, k in ctxmap.items() if k == "gemspec"),
        "platform": meta.get("platform") or "ruby",
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
            "summary": ", ".join(parts) or "No issues found",
            "findings": findings, "info": info,
            "total_findings": len(findings), "info_count": len(info)}


def scan(content, label="<text>", ctx="install"):
    """Scan a bare string. Treated as install-time code by default (the conservative case)."""
    findings, info = [], []
    _scan_text(content, label, findings, info, ctx)
    return _summarise(findings, info, label)


# ---------------------------------------------------------------------------
# Loading targets (never installs or executes gem code)
# ---------------------------------------------------------------------------
UA = {"User-Agent": "rubygems-audit/%s (+https://github.com/eltociear/rubygems-audit)" % __version__}
_last_api = [0.0]


def _get(url, timeout=90, tries=4, api=False):
    for i in range(tries):
        if api:  # rubygems.org API rate limit is 10 req/s; stay well under it
            wait = 0.25 - (time.time() - _last_api[0])
            if wait > 0:
                time.sleep(wait)
            _last_api[0] = time.time()
        try:
            return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout).read()
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504) and i < tries - 1:
                time.sleep(3 * (i + 1))
                continue
            raise
        except Exception:
            if i == tries - 1:
                raise
            time.sleep(2 * (i + 1))


def split_spec(spec):
    name, _, ver = spec.partition("@")
    return name, (ver or "latest")


def resolve_version(name, version="latest"):
    """Return (version, platform) for the .gem file to fetch."""
    if version != "latest":
        return version, None
    d = json.loads(_get("%s/gems/%s.json" % (API, urllib.parse.quote(name)), api=True))
    plat = d.get("platform") or "ruby"
    return d["version"], (None if plat == "ruby" else plat)


def _wanted(name):
    base = posixpath.basename(name)
    return name.endswith(RUBY_EXT + SHELL_EXT) or base in RUBY_NAMES or "." not in base


def files_from_gem(data):
    """Read a .gem (outer tar: metadata.gz + data.tar.gz) in memory.
    Returns (meta, files {path: text}, heads {path: first 8 bytes})."""
    meta_text, files, heads = "", {}, {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as outer:
        inner = None
        for m in outer.getmembers():
            if m.name == "metadata.gz":
                meta_text = gzip.decompress(outer.extractfile(m).read()).decode("utf-8", "replace")
            elif m.name == "metadata":
                meta_text = outer.extractfile(m).read().decode("utf-8", "replace")
            elif m.name == "data.tar.gz":
                inner = outer.extractfile(m).read()
        if inner is not None:
            with tarfile.open(fileobj=io.BytesIO(inner), mode="r:*") as tf:
                for m in tf.getmembers():
                    if not m.isfile():
                        continue
                    name = _norm(m.name)
                    low = name.lower()
                    if low.endswith(DISGUISE_EXT):
                        fh = tf.extractfile(m)
                        if fh:
                            heads[name] = fh.read(8)
                        continue
                    if m.size > MAX_FILE or not _wanted(name):
                        continue
                    fh = tf.extractfile(m)
                    if fh:
                        raw = fh.read()
                        if b"\x00" in raw[:4096]:
                            heads[name] = raw[:8]
                            continue
                        files[name] = raw.decode("utf-8", "replace")
    meta = parse_metadata(meta_text) if meta_text else {}
    meta["_local"] = False
    return meta, files, heads


def files_from_dir(root):
    files, heads = {}, {}
    meta = {}
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in (".git", "node_modules", "tmp", "pkg")]
        for fn in fns:
            p = os.path.join(dp, fn)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            try:
                if rel in ("metadata", "metadata.gz", "metadata.yml"):
                    with open(p, "rb") as fh:
                        raw = fh.read()
                    meta = parse_metadata((gzip.decompress(raw) if rel.endswith(".gz") else raw).decode("utf-8", "replace"))
                    continue
                if rel.lower().endswith(DISGUISE_EXT):
                    with open(p, "rb") as fh:
                        heads[rel] = fh.read(8)
                    continue
                if not _wanted(rel) or os.path.getsize(p) > MAX_FILE:
                    continue
                with open(p, "rb") as fh:
                    raw = fh.read()
                if b"\x00" in raw[:4096]:
                    heads[rel] = raw[:8]
                    continue
                files[rel] = raw.decode("utf-8", "replace")
            except OSError:
                pass
    meta["_local"] = not meta.get("name")
    return meta, files, heads


def audit_registry(spec, install_only=False):
    name, ver = split_spec(spec)
    ver, plat = resolve_version(name, ver)
    fn = "%s-%s%s.gem" % (name, ver, ("-" + plat) if plat else "")
    data = _get("%s/%s" % (DL, urllib.parse.quote(fn)), timeout=180)
    meta, files, heads = files_from_gem(data)
    return scan_gem(files, meta, "%s@%s" % (name, ver + (("-" + plat) if plat else "")), install_only, heads)


def lockfile_specs(path):
    """Every rubygems.org-sourced gem in a Gemfile.lock (GEM sections only; GIT/PATH skipped)."""
    specs, section, remote_ok, in_specs = [], None, False, False
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    for line in text.split("\n"):
        if line and not line.startswith(" "):
            section = line.strip()
            remote_ok, in_specs = False, False
            continue
        if section != "GEM":
            continue
        m = re.match(r"^  remote:\s*(\S+)", line)
        if m:
            remote_ok = "rubygems.org" in m.group(1)
            continue
        if line.startswith("  specs:"):
            in_specs = True
            continue
        m = re.match(r"^    ([A-Za-z0-9_.\-]+) \(([^)]+)\)\s*$", line)
        if m and in_specs and remote_ok:
            specs.append("%s@%s" % (m.group(1), m.group(2)))
    return sorted(set(specs))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
_ICON = {"CRITICAL": "\U0001F534", "HIGH": "\U0001F7E0", "MEDIUM": "\U0001F7E1",
         "LOW": "\U0001F535", "SAFE": "\U0001F7E2"}


def _print(r, verbose):
    rt = r.get("run_time") or {}
    tag = []
    if rt.get("extensions"):
        tag.append("extension")
    if rt.get("rubygems_plugin"):
        tag.append("rubygems_plugin")
    print("%s %s  [%s]  score=%d  (%d findings, %d info)%s" % (
        _ICON.get(r["risk_level"], "?"), r["target"], r["risk_level"], r["risk_score"],
        r["total_findings"], r["info_count"], ("  runs-at-install: " + ",".join(tag)) if tag else ""))
    for f in r["findings"]:
        print("    %-8s %s  %s:%s  (%s)" % (f["severity"], f["name"], f["file"], f["line"], f.get("ctx", "")))
        if f["context"] and f["line"]:
            print("             %s" % f["context"][:160])
    if verbose:
        for f in r["info"]:
            print("    info     %s  %s:%s%s" % (f["name"], f["file"], f["line"],
                                               ("  [demoted: %s]" % f["demoted"]) if f.get("demoted") else ""))


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
    install_only = "--install-only" in args
    args = [a for a in args if a not in ("--json", "--verbose", "-v", "--install-only")]
    targets = []
    if args and args[0] == "--text":
        txt = " ".join(args[1:])
        targets.append(("<text>", lambda: scan(txt)))
    elif args and args[0] == "--lockfile":
        for spec in lockfile_specs(args[1]):
            targets.append((spec, (lambda s=spec: audit_registry(s, install_only))))
    else:
        for a in args:
            if os.path.isdir(a):
                targets.append((a, (lambda p=a: (lambda m, f, h: scan_gem(f, m, p, install_only, h))(*files_from_dir(p)))))
            elif os.path.isfile(a):
                if a.endswith(".gem"):
                    targets.append((a, (lambda p=a: (lambda m, f, h: scan_gem(f, m, p, install_only, h))(
                        *files_from_gem(open(p, "rb").read())))))
                elif os.path.basename(a) == "Gemfile.lock":
                    for spec in lockfile_specs(a):
                        targets.append((spec, (lambda s=spec: audit_registry(s, install_only))))
                else:
                    b = os.path.basename(a)
                    c = "install" if b in ("extconf.rb", "mkrf_conf.rb") else "plugin" if b == "rubygems_plugin.rb" \
                        else "gemspec" if b.endswith(".gemspec") else "lib"
                    targets.append((a, (lambda p=a, c=c: scan(open(p, encoding="utf-8", errors="replace").read(), p, c))))
            else:
                targets.append((a, (lambda s=a: audit_registry(s, install_only))))
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
    if as_json:
        print(json.dumps(results if len(results) != 1 else results[0], indent=1))
    return 2 if SEV_ORDER[worst] >= SEV_ORDER["HIGH"] else 0


if __name__ == "__main__":
    sys.exit(main())
