#!/usr/bin/env python3
"""crate-audit - scan Rust crates for MALICIOUS build-time code before `cargo build` runs it.

`cargo build` executes two kinds of third-party code on your machine before you ever run your
program: every dependency's build script (`build.rs`) and every procedural macro. Both run
with your user's full privileges, environment and network. `cargo audit` only answers "does
this version have a known advisory?"; `cargo vet` / `cargo crev` rely on humans having
reviewed it. This fills the gap in between: a deterministic (no LLM) static scan of the
published .crate for download-and-execute, environment and credential exfiltration,
persistence writes outside OUT_DIR, droppers, private-key harvesting, reverse shells and
worm-style republishing - weighted by WHEN the code runs.

Precision-tuned to near-zero false positives: what build scripts do every day (cc / cmake /
pkg-config / bindgen builds, `cargo:rerun-if-*`, OUT_DIR writes, running rustc, *-sys crates
fetching prebuilt libraries and verifying a checksum) is reported as informational context
and never inflates the risk score. Risk comes from specific COMBINATIONS and sinks.

The crate is never built and none of its code is executed: the .crate (a gzip tar) is
downloaded into memory and read as text.

Usage:
  python crate_audit.py <crate>[@version] [...]    # fetch from crates.io and scan
  python crate_audit.py <dir|Cargo.toml|file.rs>   # scan a local crate / file
  python crate_audit.py --lockfile Cargo.lock      # scan every crates.io dependency
  python crate_audit.py --text "some code"         # scan a string
  add --json for machine-readable output, --verbose to print INFO context,
  --build-only to scan only build-time code (build scripts + proc-macros)

Exit code 2 if any target is HIGH or CRITICAL (CI-friendly).
No dependencies beyond the standard library. MIT licensed.
"""
import base64
import binascii
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

__version__ = "0.2.0"

API = os.environ.get("CRATE_AUDIT_API", "https://crates.io/api/v1").rstrip("/")
STATIC = os.environ.get("CRATE_AUDIT_STATIC", "https://static.crates.io/crates").rstrip("/")
SCAN_EXT = (".rs", ".sh", ".ps1", ".py", ".bat", ".cmd")
MAX_FILE = 1500000      # bytes; larger files are generated tables - skipped
MAX_TOTAL = 16000000    # bytes of text scanned per crate
MAX_LINE = 20000

# Endpoints legitimate crates essentially never hard-code, but stealers love.
EXFIL_HOST = (
    r"(?:discord(?:app)?\.com/api/webhooks/|api\.telegram\.org/bot|hooks\.slack\.com/services/|"
    r"webhook\.site|pipedream\.net|requestbin\.(?:com|net|io)|requestb\.in|requestcatcher\.com|beeceptor\.com|"
    r"pastebin\.com/(?:api|raw)|\bpaste\.ee\b|\bhastebin\.com\b|\btransfer\.sh\b|\bfile\.io/|"
    r"ngrok(?:-free)?\.(?:io|app|dev)|\.trycloudflare\.com|serveo\.net|localtunnel\.me|"
    r"oastify\.com|oast\.(?:fun|me|pro|live|site|online)|interact\.sh|interactsh|"
    r"burpcollaborator\.net|canarytokens\.com|dnslog\.cn|\bceye\.io\b|requestrepo\.com|"
    r"workers\.dev/)"
)
RAW_IP_URL = r"https?://(?!(?:127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|2(?:2[4-9]|[3-5]\d)\.))\d{1,3}(?:\.\d{1,3}){3}"
# Something that actually SENDS/RECEIVES over the network (used by combination rules).
NET_SEND = (
    r"(?:\breqwest::|\bureq::(?:get|post|put|request|agent|Agent|AgentBuilder|builder|http)\b|\battohttpc::|\bminreq::|"
    r"\bcurl::easy\b|\bisahc::|\bsurf::|\bhyper::Client|\bhttp_req::|\bwait_timeout_http\b|"
    r"TcpStream::connect|UdpSocket::bind|\.send_to\s*\(|lookup_host\s*\(|"
    r"Command::new\s*\(\s*\"(?:curl|wget|Invoke-WebRequest|iwr)(?:\.exe)?\"|"
    r"\bcurl\s+(?:-[a-zA-Z]+\s+)*https?://|\bwget\s+(?:-[a-zA-Z-]+\s+)*https?://|Invoke-WebRequest|DownloadFile\s*\()"
)
CHECKSUM = r"(?:sha2\b|Sha256|Sha512|sha256|sha512|sha1|Sha1|blake3|blake2|md5|digest|checksum|integrity|expected_hash|verify_hash|hash_file|SHA256)"

PATTERNS = {
    "critical": [
        {"id": "download_execute", "name": "Download & Execute",
         "desc": "Fetches remote content and pipes it straight into a shell/interpreter",
         "regexes": [
             r"curl\s+[^\n|;\"]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?|perl)\b",
             r"wget\s+[^\n|;\"]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?|perl)\b",
             r"wget\s+[^\n]*-O-?\s*-\s*\|\s*(?:sh|bash)",
             r"(?:sh|bash|python3?)\s*<\s*\(\s*(?:curl|wget)",
             r"(?:iex|Invoke-Expression)\s*\(?\s*\(?\s*(?:New-Object\s+Net\.WebClient|iwr|Invoke-WebRequest)",
             r"powershell[^\n]{0,60}-(?:e|enc|encodedcommand)\s*\"?,?\s*\"?[A-Za-z0-9+/=]{40,}",
         ]},
        {"id": "env_exfil", "name": "Environment Dump",
         "desc": "Serialises the whole environment (every token/secret) - exfil when a network sink is present",
         "regexes": [
             r"env::vars(?:_os)?\s*\(\s*\)\s*\.(?:collect|map|fold|for_each)",
             r"(?:format!|println!|write!|writeln!|to_string|to_vec|json!)\s*\([^\n]{0,80}env::vars(?:_os)?\s*\(\s*\)",
             r"serde_json::to_(?:string|vec)\w*\s*\(\s*&?\s*(?:std::)?env::vars",
             r"for\s*\(\s*\w+\s*,\s*\w+\s*\)\s+in\s+(?:std::)?env::vars(?:_os)?\s*\(\s*\)",
         ]},
        {"id": "reverse_shell", "name": "Reverse Shell",
         "desc": "Spawns an interactive shell bound to a network socket",
         "regexes": [
             r"/dev/tcp/[\w.\-]+/\d+",
             r"bash\s+-i\s*>&",
             r"\bnc(?:at)?\s+(?:-\w+\s+)*-e\s+/bin/(?:ba)?sh",
             r"from_raw_fd\s*\(\s*\w+\.as_raw_fd\s*\(\s*\)\s*\)[^\n]{0,200}(?:stdin|stdout)",
             r"Stdio::from\s*\(\s*(?:stream|sock|socket|conn|tcp)\w*",
         ]},
        {"id": "destructive", "name": "Destructive Payload",
         "desc": "Wipes the home directory / filesystem",
         "regexes": [
             r"rm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+(?:--no-preserve-root\s+)?(?:~|\$HOME|/)(?:\s|[\"'`;]|$)",
             r"remove_dir_all\s*\(\s*(?:&\s*)?(?:dirs::)?home_dir\s*\(",
             r"remove_dir_all\s*\(\s*\"(?:/|C:\\\\|~)\"",
         ]},
        {"id": "worm_propagation", "name": "Self-Propagation (Worm)",
         "desc": "Uses stolen registry/GitHub tokens to republish crates or push repos",
         "regexes": [
             r"crates\.io/api/v1/crates/new",
             r"\"publish\"[^\n]{0,120}(?:--token|CARGO_REGISTRY_TOKEN)",
             r"(?:CARGO_REGISTRY_TOKEN|--token)[^\n]{0,200}\"publish\"",
             r"trufflehog[^\n]{0,80}(?:filesystem|github|--json)",
             r"github\.com/trufflesecurity/trufflehog/releases",
         ]},
    ],
    "high": [
        {"id": "exfil_host", "name": "Exfiltration Endpoint",
         "desc": "Hard-codes a webhook / paste / tunnel / OAST collector host",
         "regexes": [EXFIL_HOST]},
        {"id": "persistence_write", "name": "Persistence Write",
         "desc": "Writes shell rc files, authorized_keys, ~/.cargo config/bin, autostart or cron",
         "regexes": [
             r"(?:fs::write|File::create|OpenOptions|fs::copy|fs::rename|\.append\s*\(\s*true)[^\n]{0,160}(?:\.bashrc|\.zshrc|\.bash_profile|\.zprofile|[\"/]\.profile\b|authorized_keys|\.cargo/bin/|\.cargo/config|LaunchAgents|LaunchDaemons|\.config/autostart|systemd/user|/etc/cron|crontab)",
             r"(?:\.bashrc|\.zshrc|\.bash_profile|\.zprofile|authorized_keys|LaunchAgents|\.config/autostart)[^\n]{0,160}(?:fs::write|File::create|OpenOptions|\.append\s*\(\s*true|write_all)",
             r"crontab\s+-[^l\s]",
         ]},
        {"id": "wallet_theft", "name": "Wallet / Browser Data Theft",
         "desc": "Targets wallet keystores, browser credential stores or the macOS Keychain",
         "regexes": [
             r"nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|hnfanknocfeofbddgcijnmhnfnkdnaad|ibnejdfjmmkpcnlpebklmnkoeoihofec|egjidjbpglichdcondbcbdnbeeppgdph",
             r"(?:Chrome|BraveSoftware|Microsoft/Edge|Opera Software)[^\n]{0,80}(?:Login Data|Local Extension Settings)",
             r"(?:Exodus|atomic|Electrum)[/\\\\](?:exodus\.wallet|Local Storage|wallets)",
             r"security\s*\"?,?\s*\"?find-generic-password",
             r"\b(?:wallet\.dat|seed\.seco)\b",
             r"(?:Telegram Desktop|TelegramDesktop)[/\\\\]+tdata",
         ]},
        {"id": "dns_exfil", "name": "DNS Exfiltration",
         "desc": "Encodes host/user data into a DNS lookup (dependency-confusion beacon)",
         "regexes": [
             r"(?:lookup_host|to_socket_addrs)\s*\([^\n]{0,160}(?:hostname|whoami|username|env::var|USER|COMPUTERNAME)",
             r"format!\s*\(\s*\"\{\}\.[\w-]+\.(?:oast|burpcollaborator|dnslog|interact)",
         ]},
        {"id": "credential_exfil", "name": "Credential Exfiltration",
         "desc": "Reads a credential store AND names an external destination on the same line",
         "regexes": [
             r"(?:\.cargo/credentials|\.ssh/id_|\.aws/credentials|\.git-credentials|\.docker/config\.json|\.kube/config|solana/id\.json)[^\n]{0,200}(?:https?://(?!(?:crates\.io|static\.crates\.io|index\.crates\.io|github\.com/rust-lang))|" + EXFIL_HOST + r")",
         ]},
    ],
    "medium": [
        {"id": "raw_ip_url", "name": "Raw-IP URL",
         "desc": "Contacts a public IP address directly instead of a hostname",
         "regexes": [RAW_IP_URL]},
        {"id": "tls_disabled", "name": "TLS Verification Disabled",
         "desc": "Turns off certificate checking",
         "regexes": [r"danger_accept_invalid_certs\s*\(\s*true", r"\bcurl\s+[^\n]*(?:-k\b|--insecure)",
                     r"wget\s+[^\n]*--no-check-certificate"]},
    ],
    "low": [],
    # Context: reported, never scored. Capabilities popular crates use daily.
    "info": [
        {"id": "credential_read", "name": "Credential Store Reference",
         "desc": "References ~/.cargo/credentials, ~/.ssh, ~/.aws etc. (CLIs read their own auth)",
         "regexes": [r"\.cargo/credentials", r"credentials\.toml", r"\.ssh/id_\w+", r"\.aws/credentials",
                     r"\.git-credentials", r"\.docker/config\.json", r"solana/id\.json", r"\bkeystore\b"]},
        {"id": "process_spawn", "name": "Process Spawning",
         "desc": "Runs external commands (rustc, git, cc, pkg-config...)",
         "regexes": [r"Command::new\s*\("]},
        {"id": "network", "name": "Network Access",
         "desc": "Makes outbound HTTP/DNS/socket calls",
         "regexes": [NET_SEND]},
        {"id": "native_build", "name": "Native Build",
         "desc": "cc / cmake / pkg-config / bindgen / vcpkg build steps",
         "regexes": [r"\bcc::Build\b", r"\bcmake::(?:Config|build)\b", r"\bpkg_config::", r"\bbindgen::", r"\bvcpkg::",
                     r"\bautotools::", r"\bcxx_build::"]},
        {"id": "env_read", "name": "Environment Access",
         "desc": "Reads environment variables",
         "regexes": [r"env::var(?:_os)?\s*\(", r"\benv!\s*\("]},
        {"id": "ci_gate", "name": "CI Environment Check",
         "desc": "Branches on CI-only variables (GITLAB_CI, GITHUB_ACTIONS...)",
         "regexes": [r"env::var(?:_os)?\s*\(\s*\"(?:GITLAB_CI|GITHUB_ACTIONS|CI|TRAVIS|CIRCLECI|JENKINS_URL|BUILDKITE)\""]},
        {"id": "key_pattern", "name": "Private-Key Pattern",
         "desc": "A regex for 64-hex / base58 secret keys (key scanners and wallet libs both have one)",
         "regexes": [r"Regex::new\s*\(\s*r?#*\"[^\n\"]*(?:\{64\}|\{86,88\}|\{87,88\}|\{87\}|\{88\}|\{43,44\}|\[1-9A-HJ-NP-Za-km-z\])"]},
        {"id": "byte_blob", "name": "Embedded Byte Blob",
         "desc": "Long numeric byte-array literal or include_bytes! (tables, test vectors, firmware)",
         "regexes": [r"(?:\b0x[0-9a-fA-F]{2}\s*,\s*){48,}", r"(?:\b\d{1,3}\s*,\s*){120,}", r"include_bytes!\s*\("]},
        {"id": "outside_write", "name": "Write Outside OUT_DIR",
         "desc": "Writes to a home-directory path",
         "regexes": [r"(?:home_dir\s*\(\s*\)|env::var\s*\(\s*\"(?:HOME|USERPROFILE)\"\s*\))[^\n]{0,120}(?:join|push)"]},
    ],
}

SEVERITY_SCORE = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "SAFE": 0}
_COMPILED = [(sev, pg, re.compile(rx, re.IGNORECASE if pg["id"] not in ("key_pattern",) else 0))
             for sev, groups in PATTERNS.items() for pg in groups for rx in pg["regexes"]]
NET_RE = re.compile(NET_SEND)
EXFIL_RE = re.compile(EXFIL_HOST, re.IGNORECASE)
RAWIP_RE = re.compile(RAW_IP_URL)
CHECKSUM_RE = re.compile(CHECKSUM)
CHMOD_RE = re.compile(r"set_permissions|PermissionsExt|set_mode\s*\(|\.mode\s*\(\s*0o7|\bchmod\b")
DYN_EXEC_RE = re.compile(r"Command::new\s*\(\s*(?!\")(?:&\s*)?[\w.:]+(?:\s*\(\s*\))?\s*\)")
XOR_RE = re.compile(r"\^\s*(?:key|k|KEY|xor\w*)\b|\bxor\w*\s*\(|\.wrapping_sub\s*\(\s*\w+\s*\)\s*\^")
EXEC_MEM_RE = re.compile(r"PROT_EXEC|PAGE_EXECUTE|transmute::<[^>]*fn\s*\(|memfd_create")
# command / env-var name computed from a numeric byte-array literal by a helper (rustdecimal:
# Command::new(Decimal::parse_fn(&vec![73,127,...])) with an XOR key loop)
ENC_ARG_RE = re.compile(r"(?:Command::new|\.args?|env::var(?:_os)?)\s*\(\s*(?:&\s*)?[\w:]+\s*\(\s*&?\s*(?:vec!\s*)?\[\s*\d{1,3}\s*,\s*\d{1,3}\s*,")
XOR_INDEX_RE = re.compile(r"\^\s*\w+\s*\[\s*\w+\s*(?:%\s*\w+(?:\.len\(\))?\s*)?\]")
# URL / file opener spawned from a proc-macro (better-macro: xdg-open at macro expansion)
OPENER_RE = re.compile(r"Command::new\s*\(\s*\"(?:xdg-open|open|explorer(?:\.exe)?|start|rundll32(?:\.exe)?)\"")
# a downloaded payload saved / renamed as a script or executable, then run through a shell
SCRIPT_EXT_RE = re.compile(r"\"[\w.\-]*\.(?:bat|cmd|ps1|vbs|exe|scr|sh|command)\"")
SHELL_RUN_RE = re.compile(r"Command::new\s*\(\s*\"(?:cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh|(?:/bin/)?(?:ba|z)?sh|wscript|cscript)\"")
B64_LIT_RE = re.compile(r"\"([A-Za-z0-9+/]{16,}={0,2})\"")
CMD_FNCALL_RE = re.compile(r"Command::new\s*\(\s*[\w:]+\s*\(\s*\w+\.as_slice\s*\(\s*\)")
BYTE_ARR_RE = re.compile(r"\[u8;\s*\d+\]\s*=\s*\[\s*0x[0-9a-fA-F]{2}\s*,")
STR_OBF_RE = re.compile(r"\bobfstr!\s*\(|\bobfstr::|\blitcrypt::|\blc!\s*\(|\bcryptify::|\bxorstr!\s*\(")
SECRET_ENV_RE = re.compile(r"(?:PRIVATE_KEY|MNEMONIC|SEED_PHRASE|SECRET_KEY|WALLET_KEY)")
SECRET_ENV_LIT_RE = re.compile(r"env::var(?:_os)?\s*\(\s*\"[A-Z0-9_]*(?:PRIVATE_KEY|MNEMONIC|SEED_PHRASE|WALLET_KEY)[A-Z0-9_]*\"")
HARD_URL_RE = re.compile(r"\"https?://(?!localhost|127\.|0\.0\.0\.0|\[::1\]|example\.)[\w.-]+\.[a-z]{2,}[^\"]*\"")
POST_RE = re.compile(r"\.post\s*\(|Command::new\s*\(\s*\"curl\"")
WALLET_DIR_RE = re.compile(r"\\?\"(?:Local Extension Settings|exodus\.wallet|Exodus/exodus\.wallet|Electrum/wallets|tdata)\\?\"")
SWEEP_RE = re.compile(r"\bWalkDir::new\s*\(|\bfs::read_dir\s*\(|\bglob\s*\(")
RECON_CMD_RE = re.compile(r"Command::new\s*\(\s*\"(?:whoami|hostname|id)\"")
CARGO_INSTALL_RE = re.compile(r"Command::new\s*\(\s*\"cargo\"\s*\)[^;]{0,200}\"install\"", re.S)
HIDDEN_LAUNCH_RE = re.compile(r"\bsetsid\b|\"-WindowStyle\"\s*,\s*\"Hidden\"|-WindowStyle\s+Hidden|\bnohup\b[^\n]{0,80}&")


# The 300 most-downloaded crates (crates.io, 2026-11). A dependency that differs from one of these
# only by its trailing version digit (proc-macro1 for proc-macro2) or by dropped separators
# (serdejson) is a typosquat shape. General edit distance 1 is too noisy (pastey/paste,
# adler32/adler2, matches/matchers are all real crates).
TOP_CRATES = frozenset((
    "hashbrown syn getrandom bitflags rand_core rand base64 libc quote proc-macro2 windows-sys "
    "indexmap thiserror-impl thiserror itertools cfg-if memchr unicode-ident serde regex-syntax "
    "rand_chacha itoa serde_derive serde_json heck autocfg log once_cell cc regex-automata socket2 "
    "smallvec rustix digest regex aho-corasick block-buffer ryu linux-raw-sys clap cpufeatures "
    "parking_lot_core windows_x86_64_msvc bytes parking_lot strsim mio pin-project-lite http sha2 "
    "windows_x86_64_gnu num-traits version_check windows-targets windows_aarch64_msvc either "
    "windows_i686_msvc windows_i686_gnu semver crypto-common tokio winnow lock_api "
    "windows_aarch64_gnullvm windows_x86_64_gnullvm anyhow lazy_static futures-core zerocopy idna "
    "toml futures-util scopeguard slab futures-task hyper typenum fastrand miniz_oxide rustls "
    "crossbeam-utils shlex percent-encoding generic-array http-body futures-channel futures-sink "
    "equivalent time ppv-lite86 url errno tracing-core toml_datetime clap_lex tracing toml_edit "
    "rustc-hash futures-io tempfile uuid form_urlencoded rustls-webpki tokio-macros nix chrono "
    "rustversion untrusted h2 unicode-width futures-macro fnv tokio-util pkg-config byteorder tokio- "
    "rustls futures clap_builder webpki-roots synstructure darling_core darling darling_macro "
    "tracing-attributes clap_derive reqwest anstyle rustc_version tinyvec ring futures-executor "
    "signal-hook-registry ahash httparse nom zeroize serde_core wasi subtle crc32fast "
    "stable_deref_trait flate2 foldhash redox_syscall num-integer time-macros tower anstream "
    "thread_local memoffset anstyle-parse iana-time-zone time-core crossbeam-epoch async-trait "
    "sync_wrapper hyper-rustls colorchoice spin hex anstyle-query tinystr tower-service yoke "
    "displaydoc want yoke-derive litemap zerovec icu_properties_data icu_provider try-lock "
    "icu_properties zerovec-derive phf_shared icu_collections strum_macros writeable walkdir "
    "zerocopy-derive icu_normalizer_data strum crossbeam-deque icu_normalizer utf8parse serde_spanned "
    "deranged hmac zerofrom pin-utils mime zerofrom-derive num-bigint same-file tinyvec_macros "
    "openssl-probe tracing-subscriber ipnet idna_adapter bumpalo httpdate phf glob zmij find-msvc- "
    "tools num-conv object prost powerfmt siphasher crossbeam-channel serde_urlencoded utf8_iter "
    "unicode-xid arrayvec jobserver rustls-pki-types windows_i686_gnullvm prost-derive sha1 "
    "cfg_aliases rustls-native-certs adler2 unicode-segmentation pin-project-internal pin-project "
    "unicode-normalization is_terminal_polyfill sharded-slab tower-layer tracing-log rayon schemars "
    "proc-macro-crate wasm-bindgen const-oid wasm-bindgen-macro-support wasm-bindgen-macro num_cpus "
    "wasm-bindgen-shared nu-ansi-term rayon-core convert_case hyper-util atomic-waker event-listener "
    "encoding_rs libloading minimal-lexical tower-http http-body-util gimli rustc-demangle allocator- "
    "api2 js-sys env_logger hermit-abi petgraph prettyplease static_assertions paste fixedbitset "
    "matchers zerotrie icu_locale_core libm potential_utf portable-atomic derive_more axum vcpkg bit- "
    "vec axum-core der tokio-stream ident_case rustls-pemfile unicode-bidi windows-link phf_generator "
    "winapi addr2line half termcolor matchit core-foundation quick-xml signature simd-adler32 "
    "windows-core prost-types ordered-float backtrace data-encoding spki bit-set r-efi base64ct bstr "
    "openssl-sys "
).split())


def _squat_of(n, t):
    """True if dependency name n imitates top crate t (both normalised to '-')."""
    if n == t:
        return False
    if t[-1].isdigit() and n[:-1] == t[:-1] and n[-1].isdigit():
        return True  # proc-macro1 / proc-macro2
    return n.replace("-", "") == t.replace("-", "")  # serdejson / serde-json


def typosquat_deps(cargo_toml):
    """[(dependency, looks_like)] for declared dependencies that typosquat a top crate."""
    deps = set()
    for sec, kv in _toml_sections(cargo_toml or "").items():
        m = re.match(r"^(?:target\..+\.)?(?:dev-|build-)?dependencies(?:\.(.+))?$", sec)
        if not m:
            continue
        if m.group(1):
            deps.add(str(kv.get("package") or m.group(1)).strip('"'))
        else:
            for k, v in kv.items():
                pm = re.search(r"package\s*=\s*\"([^\"]+)\"", v) if isinstance(v, str) else None
                deps.add(pm.group(1) if pm else k)
    out = []
    top = {t.lower().replace("_", "-") for t in TOP_CRATES}
    for d in sorted(deps):
        n = d.lower().replace("_", "-")
        if n in top or len(n) < 5:
            continue
        hit = next((t for t in sorted(top) if len(t) >= 5 and _squat_of(n, t)), None)
        if hit:
            out.append((d, hit))
    return out


HEX_ESC_RE = re.compile(r"\"((?:\\x[0-9a-fA-F]{2}){6,})\"")
BYTE_LIST_RE = re.compile(r"\[\s*((?:0x[0-9a-fA-F]{2}\s*,\s*){7,}0x[0-9a-fA-F]{2})\s*,?\s*\]")
SSH_KEY_RE = re.compile(r"\"ssh-(?:rsa|ed25519|dss) AAAA[0-9A-Za-z+/]{40,}")
DECODED_BAD_RE = re.compile(EXFIL_HOST + r"|" + RAW_IP_URL + r"|(?:GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|CARGO_REGISTRY_TOKEN|AWS_SECRET_ACCESS_KEY|"
                            r"CLAUDE_CODE_OAUTH_TOKEN|PRIVATE_KEY|MNEMONIC)\b|\.ssh/|authorized_keys", re.I)


def _hidden_literals(text):
    """Plain-ASCII strings written as \\xNN escapes or 0x.. byte lists (decoded statically)."""
    out = []
    for m in HEX_ESC_RE.finditer(text):
        try:
            out.append((m.start(), bytes.fromhex(m.group(1).replace("\\x", "")).decode("ascii")))
        except (ValueError, UnicodeDecodeError):
            pass
    for m in BYTE_LIST_RE.finditer(text):
        b = bytes(int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", m.group(1)))
        if all(32 <= c < 127 for c in b):
            out.append((m.start(), b.decode("ascii")))
    return out


def _b64_urls(text):
    """Endpoints hidden as base64 string literals (decoded statically, never executed)."""
    out = []
    for m in B64_LIT_RE.finditer(text):
        lit = m.group(1)
        if len(lit) % 4:
            continue
        try:
            dec = base64.b64decode(lit, validate=True).decode("ascii")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if re.match(r"^(?:https?|wss?)://(?:[\w.-]+\.[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})", dec):
            out.append((m.start(), dec))
    return out


BASE64_DEC_RE = re.compile(r"(?:base64::decode|STANDARD\.decode|general_purpose::\w+\.decode|from_base64)\s*\(")
SOCK_RE = re.compile(r"TcpStream::connect|UnixStream::connect")
FD_STDIO_RE = re.compile(r"Stdio::from_raw_fd|Stdio::from\s*\(\s*(?:stream|sock|socket|conn|tcp)\w*")
SHELL_CMD_RE = re.compile(r"Command::new\s*\(\s*\"(?:/bin/)?(?:ba|z)?sh\"|Command::new\s*\(\s*\"(?:cmd|powershell)(?:\.exe)?\"")
LINE_ONCE = ("network", "env_read", "process_spawn", "native_build", "byte_blob", "credential_read")
# Commands that are ordinary in build scripts.
BENIGN_CMD = re.compile(r"Command::new\s*\(\s*(?:\"(?:git|rustc|cargo|make|cmake|pkg-config|cc|gcc|clang|ar|xcrun|python3?|perl|nasm|yasm|protoc|uname|sh|cmd|xcode-select|ld|lld|link)(?:\.exe)?\"|&?\s*(?:rustc|cargo|cc|cxx|make|cmake|compiler)\b)")


def _item(sev, pid, name, desc, path, n, matched, ctx):
    return {"severity": sev, "id": pid, "name": name, "description": desc, "file": path,
            "line": n, "matched": matched[:120], "context": ctx.strip()[:200]}


def _demote_ids(findings, path, ids):
    for f in findings:
        if f["file"] == path and f["id"] in ids:
            f["severity"] = "INFO"


def _scan_text(text, path, findings, info, ctx):
    """Line pass + file-level combination rules. ctx: None | 'build' | 'proc-macro'."""
    if path.endswith(".py"):
        # docstrings describe; blank them line-for-line so line numbers stay right
        text = re.sub(r'(?s)("""|\'\'\').*?\1', lambda m: "\n" * m.group(0).count("\n"), text)
    lines = text.split("\n")
    hash_comments = path.endswith((".py", ".sh", ".ps1"))
    seen = set()
    local = []
    for sev, pg, rx in _COMPILED:
        if pg["id"] in LINE_ONCE and (pg["id"], 0) in seen:
            continue
        for n, line in enumerate(lines, 1):
            s = line.lstrip()
            if s.startswith(("//", "///", "//!", "* ", "/*")) and sev != "info":
                continue  # comments and doc-comments describe; they don't execute
            if hash_comments and s.startswith("#") and not s.startswith("#!") and sev != "info":
                continue
            m = rx.search(line[:MAX_LINE])
            if not m:
                continue
            key = (pg["id"], n)
            if key in seen:
                continue
            seen.add(key)
            local.append(_item(sev.upper(), pg["id"], pg["name"], pg["desc"], path, n, m.group(0), line))
            if pg["id"] in LINE_ONCE:
                seen.add((pg["id"], 0))
                break
    ids = {f["id"] for f in local}
    has_net = bool(NET_RE.search(text))
    build = ctx is not None

    # ---- combination rules -------------------------------------------------------------
    # an environment walk with no network sink anywhere in the file is feature detection
    if "env_exfil" in ids and not has_net:
        _demote_ids(local, path, {"env_exfil"})
    # an exfil host in a file that never sends is a URL in a string / docs
    if "exfil_host" in ids and not has_net:
        _demote_ids(local, path, {"exfil_host"})
    # raw-IP URLs only matter at build time or beside a credential/env read
    if "raw_ip_url" in ids and not (build or "credential_read" in ids or "env_exfil" in ids):
        _demote_ids(local, path, {"raw_ip_url"})
    if "dns_exfil" in ids and not build and "env_exfil" not in ids:
        pass  # kept: hostname-in-DNS-query is rare enough to report everywhere
    # persistence writes in runtime code are installers' job (completions, `x install`):
    # only build-time code writing there is an attack.
    if "persistence_write" in ids and not build:
        _demote_ids(local, path, {"persistence_write"})
    if "tls_disabled" in ids and not build:
        _demote_ids(local, path, {"tls_disabled"})
    # credential store read + exfil host / (build-time network) in the same file
    if "credential_read" in ids and (EXFIL_RE.search(text) or (build and has_net) or
                                     (has_net and RAWIP_RE.search(text))):
        local.append(_item("CRITICAL", "credential_exfil", "Credential Exfiltration",
                           "Reads a credential store and talks to the network in the same file",
                           path, 0, "", "file-level combination"))
    # private-key regex + network in the same file: faster_log / async_println shape
    if "key_pattern" in ids and has_net:
        local.append(_item("CRITICAL", "key_harvest", "Private-Key Harvest",
                           "Scans text for secret-key patterns and sends over the network in the same file",
                           path, 0, "", "file-level combination"))
    # socket fd handed to a spawned shell's stdio, across lines
    if "reverse_shell" not in ids and SOCK_RE.search(text) and FD_STDIO_RE.search(text) and SHELL_CMD_RE.search(text):
        local.append(_item("CRITICAL", "reverse_shell", "Reverse Shell",
                           "Connects a socket and wires its file descriptor into a spawned shell",
                           path, 0, "", "file-level combination"))
    # dropper: (download or embedded blob or base64) + chmod + exec of a non-literal path
    blob = "include_bytes!" in text or BASE64_DEC_RE.search(text)
    dyn_exec = [m for m in DYN_EXEC_RE.finditer(text)]
    if (has_net or blob) and CHMOD_RE.search(text) and dyn_exec and not BENIGN_CMD.search(dyn_exec[0].group(0)):
        sev = "CRITICAL" if "ci_gate" in ids else "HIGH"
        local.append(_item(sev, "dropper", "Download/Unpack & Execute (dropper)",
                           "Fetches or decodes a payload, marks it executable and runs it"
                           + (" - gated on a CI variable" if sev == "CRITICAL" else ""),
                           path, 0, "", "file-level combination"))
    # Windows-style dropper: download, save as .bat/.ps1/.exe, run through cmd / powershell
    if has_net and SCRIPT_EXT_RE.search(text) and SHELL_RUN_RE.search(text) and \
            re.search(r"File::create|fs::write|fs::rename|fs::copy|write_all", text) and \
            not any(f["id"] == "dropper" for f in local):
        local.append(_item("HIGH", "dropper", "Download/Unpack & Execute (dropper)",
                           "Downloads content, saves it as a script/executable and runs it through a shell",
                           path, 0, "", "file-level combination"))
    # command or env-var names decoded at runtime from byte arrays (XOR) = hidden behaviour
    em = ENC_ARG_RE.search(text)
    if not (em and XOR_INDEX_RE.search(text)) and len(BYTE_ARR_RE.findall(text)) >= 3 and "^" in text:
        em = CMD_FNCALL_RE.search(text)  # rpc-check: Command::new(d(cmd.as_slice(), K)) over XOR-ed [u8; N] arrays
    elif not XOR_INDEX_RE.search(text):
        em = None
    if em and "Command::new" in text:
        n = text.count("\n", 0, em.start()) + 1
        local.append(_item("HIGH", "obfuscation", "Obfuscated Command",
                           "Runs a command whose name/arguments are decoded at runtime from XOR-ed byte arrays",
                           path, n, em.group(0)[:80], lines[n - 1] if n <= len(lines) else ""))
    # endpoint hidden as a base64 literal and decoded at runtime (sha-rust, microsoftsystem64)
    if "decode" in text:
        hid = _b64_urls(text)
        if hid and (BASE64_DEC_RE.search(text) or re.search(r"\.decode\s*\(", text)):
            pos, url = hid[0]
            n = text.count("\n", 0, pos) + 1
            local.append(_item("HIGH", "hidden_endpoint", "Base64-Hidden Endpoint",
                               "A network endpoint is stored base64-encoded and decoded at runtime (%s)" % url[:60],
                               path, n, url[:80], lines[n - 1][:200] if n <= len(lines) else ""))
    # wallet / signing secret read from the environment, obfuscated strings, and a network send
    plain = SECRET_ENV_LIT_RE.search(text)
    if plain and HARD_URL_RE.search(text) and POST_RE.search(text):
        local.append(_item("HIGH", "secret_env_exfil", "Secret Exfiltration",
                           "Reads a wallet/signing secret from the environment and POSTs to a hard-coded URL in the same file",
                           path, text.count("\n", 0, plain.start()) + 1, plain.group(0), ""))
    elif has_net and STR_OBF_RE.search(text) and SECRET_ENV_RE.search(text):
        sm = SECRET_ENV_RE.search(text)
        local.append(_item("HIGH", "secret_env_exfil", "Obfuscated Secret Exfiltration",
                           "Reads a wallet/signing secret (%s) behind string obfuscation and sends over the network" % sm.group(0),
                           path, text.count("\n", 0, sm.start()) + 1, sm.group(0), ""))
    if build:
        # build script collecting identity (whoami / hostname) and sending it out (jfrog_quotes shape)
        if RECON_CMD_RE.search(text) and has_net:
            local.append(_item("HIGH", "recon_exfil", "Host Recon + Network at Build Time",
                               "build script runs whoami/hostname and talks to the network",
                               path, 0, "", "file-level combination"))
        # build script installing and launching another binary (pretty-changelog-logger shape)
        cm = CARGO_INSTALL_RE.search(text)
        if cm:
            local.append(_item("HIGH", "build_install", "cargo install from a Build Script",
                               "build script runs `cargo install` (pulls and builds another crate outside the dependency graph)",
                               path, text.count("\n", 0, cm.start()) + 1, cm.group(0)[:80], ""))
        hm = HIDDEN_LAUNCH_RE.search(text)
        if hm and "Command::new" in text:
            local.append(_item("HIGH", "hidden_launch", "Detached / Hidden Launch at Build Time",
                               "build script starts a process detached or with a hidden window (%s)" % hm.group(0),
                               path, text.count("\n", 0, hm.start()) + 1, hm.group(0), ""))
    # collector host / token name spelled as \\xNN escapes or a byte list (env-test-guard)
    if "\\x" in text or "0x" in text:
        for pos, dec in _hidden_literals(text):
            bm = DECODED_BAD_RE.search(dec)
            if bm:
                n = text.count("\n", 0, pos) + 1
                local.append(_item("HIGH", "hidden_endpoint", "Escape-Encoded Secret / Endpoint",
                                   "A string literal hidden as hex escapes / bytes decodes to `%s`" % dec[:60],
                                   path, n, dec[:80], ""))
                break
    # wallet / extension-store directories swept and sent (hesk)
    wm = WALLET_DIR_RE.search(text)
    if wm and has_net and SWEEP_RE.search(text) and not any(f["id"] == "wallet_theft" for f in local):
        local.append(_item("HIGH", "wallet_theft", "Wallet / Browser Data Theft",
                           "Walks the filesystem for %s and talks to the network in the same file" % wm.group(0),
                           path, text.count("\n", 0, wm.start()) + 1, wm.group(0), ""))
    # a hard-coded SSH public key next to authorized_keys: a planted backdoor login (logs-update)
    km = SSH_KEY_RE.search(text)
    if km and "authorized_keys" in text:
        local.append(_item("HIGH", "ssh_backdoor", "Hard-Coded SSH Key for authorized_keys",
                           "Embeds an SSH public key and writes/handles authorized_keys",
                           path, text.count("\n", 0, km.start()) + 1, km.group(0)[:40], ""))
    # a proc-macro that launches a browser / file opener while your code compiles
    if ctx == "proc-macro":
        om = OPENER_RE.search(text)
        if om:
            local.append(_item("HIGH", "macro_spawn", "Process Launch at Macro Expansion",
                               "A procedural macro opens a URL / program (%s) while your code compiles" % om.group(0),
                               path, text.count("\n", 0, om.start()) + 1, om.group(0), ""))
    # XOR/byte-blob decode + exec / executable memory = obfuscated payload
    if ("byte_blob" in ids or blob) and XOR_RE.search(text) and (EXEC_MEM_RE.search(text) or dyn_exec or
                                                                    "Command::new" in text and build):
        local.append(_item("HIGH", "obfuscation", "Obfuscated Payload",
                           "Decodes an embedded byte blob (XOR) and executes it",
                           path, 0, "", "file-level combination"))
    if build:
        # network at build time: prebuilt-library fetchers are normal IF they verify a checksum
        if has_net and not any(f["id"] in ("dropper", "credential_exfil", "env_exfil", "key_harvest", "recon_exfil")
                               and f["severity"] != "INFO" for f in local):
            if ctx == "proc-macro":
                local.append(_item("HIGH", "macro_network", "Network Access at Macro Expansion",
                                   "A procedural macro performs network I/O while your code compiles",
                                   path, 0, "", "file-level"))
            elif not CHECKSUM_RE.search(text):
                local.append(_item("MEDIUM", "unverified_download", "Unverified Build-Time Download",
                                   "build script fetches over the network with no checksum verification in the file",
                                   path, 0, "", "file-level"))
        # Build-time escalation: anything HIGH that runs on `cargo build` is CRITICAL
        for f in local:
            if f["severity"] == "HIGH" and f["id"] not in ("macro_network", "macro_spawn"):
                f["severity"] = "CRITICAL"
                f["description"] += " [runs at cargo build]"
            if f["severity"] != "INFO":
                f["context_kind"] = ctx
    for f in local:
        (info if f["severity"] == "INFO" else findings).append(f)


# ---------------------------------------------------------------------------
# Cargo.toml / Cargo.lock (tiny TOML subset - stdlib only, py3.9 has no tomllib)
# ---------------------------------------------------------------------------
def _toml_sections(text):
    sec, out = "", {}
    for raw in text.split("\n"):
        line = raw.split("#", 1)[0].strip() if not raw.strip().startswith("#") else ""
        if not line:
            continue
        m = re.match(r"^\[\[?\s*([^\]]+?)\s*\]\]?$", line)
        if m:
            sec = m.group(1).strip()
            out.setdefault(sec, {})
            continue
        m = re.match(r"^([\w.\-\"]+)\s*=\s*(.+)$", line)
        if m:
            k = m.group(1).strip('"')
            v = m.group(2).strip()
            if v.startswith('"') and v.endswith('"'):
                v = v[1:-1]
            elif v in ("true", "false"):
                v = v == "true"
            out.setdefault(sec, {})[k] = v
    return out


def manifest_info(cargo_toml):
    t = _toml_sections(cargo_toml or "")
    pkg = t.get("package", {})
    lib = t.get("lib", {})
    return {"name": pkg.get("name", ""), "version": pkg.get("version", ""),
            "build": pkg.get("build"), "links": pkg.get("links"),
            "proc_macro": bool(lib.get("proc-macro") or lib.get("proc_macro")),
            "lib_path": lib.get("path") or "src/lib.rs"}


def _resolve_mods(files, entry, out):
    """Follow `mod x;`, #[path], include!() from a build script to the files it compiles in."""
    if entry in out or entry not in files:
        return
    out.add(entry)
    text = files[entry]
    base = posixpath.dirname(entry)
    stem = posixpath.splitext(posixpath.basename(entry))[0]
    moddir = base if stem in ("build", "main", "mod", "lib") or entry.count("/") == 0 else posixpath.join(base, stem)
    for m in re.finditer(r"#\[path\s*=\s*\"([^\"]+)\"\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*;", text):
        _resolve_mods(files, posixpath.normpath(posixpath.join(base, m.group(1))), out)
    for m in re.finditer(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;", text, re.M):
        for cand in (posixpath.join(moddir, m.group(1) + ".rs"), posixpath.join(moddir, m.group(1), "mod.rs"),
                     posixpath.join(base, m.group(1) + ".rs"), posixpath.join(base, m.group(1), "mod.rs")):
            if cand in files:
                _resolve_mods(files, posixpath.normpath(cand), out)
                break
    for m in re.finditer(r"include!\s*\(\s*\"([^\"]+\.rs)\"", text):
        _resolve_mods(files, posixpath.normpath(posixpath.join(base, m.group(1))), out)


def build_time_files(files, mi):
    """Return {path: 'build'|'proc-macro'} for code that runs during `cargo build`."""
    ctx = {}
    b = mi.get("build")
    entries = []
    if b is False:
        pass
    elif isinstance(b, str) and b:
        entries.append(posixpath.normpath(b))
    elif "build.rs" in files:
        entries.append("build.rs")
    got = set()
    for e in entries:
        _resolve_mods(files, e, got)
    for p in got:
        ctx[p] = "build"
    if mi.get("proc_macro"):
        for p in files:
            if p.endswith(".rs") and (p.startswith("src/") or p == mi.get("lib_path")) and p not in ctx:
                ctx[p] = "proc-macro"
    return ctx


def scan_crate(files, label="", build_only=False):
    """files: {relative_path: text} (Cargo.toml included). Returns an audit result dict."""
    findings, info = [], []
    mi = manifest_info(files.get("Cargo.toml", ""))
    ctx = build_time_files(files, mi)
    total = 0
    for path in sorted(files, key=lambda p: (p not in ctx, p)):
        if not path.endswith(SCAN_EXT):
            continue
        c = ctx.get(path)
        if build_only and not c:
            continue
        if c is None and re.match(r"(?:tests?|benches|examples|fuzz)/", path):
            continue  # not compiled into dependents
        total += len(files[path])
        if total > MAX_TOTAL:
            info.append(_item("INFO", "truncated", "Scan Truncated", "Crate exceeds %d bytes of text" % MAX_TOTAL,
                              path, 0, "", ""))
            break
        _scan_text(files[path], path, findings, info, c)
    for dep, like in typosquat_deps(files.get("Cargo.toml", "")):
        findings.append(_item("MEDIUM", "typosquat_dependency", "Typosquat-Shaped Dependency",
                              "Depends on `%s`, one edit away from the popular crate `%s`" % (dep, like),
                              "Cargo.toml", 0, dep, ""))
    r = _summarise(findings, info, label)
    r["build_time"] = {"build_script": sorted(p for p, k in ctx.items() if k == "build"),
                       "proc_macro": mi.get("proc_macro", False), "links": mi.get("links")}
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


def scan(content, label="<text>", ctx="build"):
    """Scan a bare string. Treated as build-script code by default (the conservative case)."""
    findings, info = [], []
    _scan_text(content, label, findings, info, ctx)
    return _summarise(findings, info, label)


# ---------------------------------------------------------------------------
# Loading targets (never builds or executes crate code)
# ---------------------------------------------------------------------------
UA = {"User-Agent": "crate-audit/%s (+https://github.com/eltociear/crate-audit)" % __version__}
_last_api = [0.0]


def _get(url, timeout=60, tries=3, api=False):
    for i in range(tries):
        if api:  # crates.io crawler policy: max 1 request per second
            wait = 1.0 - (time.time() - _last_api[0])
            if wait > 0:
                time.sleep(wait)
            _last_api[0] = time.time()
        try:
            return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout).read()
        except urllib.error.HTTPError:
            raise
        except Exception:
            if i == tries - 1:
                raise
            time.sleep(2 * (i + 1))


def split_spec(spec):
    name, _, ver = spec.partition("@")
    return name, (ver or "latest")


def resolve_version(name, version="latest"):
    if version != "latest":
        return version
    d = json.loads(_get("%s/crates/%s" % (API, urllib.parse.quote(name)), api=True))
    c = d["crate"]
    return c.get("default_version") or c.get("max_stable_version") or c["max_version"]


def files_from_crate(data):
    out = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        for m in tf.getmembers():
            if not m.isfile() or m.size > MAX_FILE:
                continue
            name = m.name.split("/", 1)[1] if "/" in m.name else m.name
            if name != "Cargo.toml" and not name.endswith(SCAN_EXT):
                continue
            f = tf.extractfile(m)
            if f:
                out[name] = f.read().decode("utf-8", "replace")
    return out


def files_from_dir(root):
    out = {}
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in ("target", ".git", "node_modules")]
        for fn in fns:
            p = os.path.join(dp, fn)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            if rel != "Cargo.toml" and not fn.endswith(SCAN_EXT):
                continue
            try:
                if os.path.getsize(p) > MAX_FILE:
                    continue
                with open(p, encoding="utf-8", errors="replace") as fh:
                    out[rel] = fh.read()
            except OSError:
                pass
    return out


def audit_registry(spec, build_only=False):
    name, ver = split_spec(spec)
    ver = resolve_version(name, ver)
    data = _get("%s/%s/%s-%s.crate" % (STATIC, urllib.parse.quote(name), urllib.parse.quote(name), urllib.parse.quote(ver)),
                timeout=120)
    return scan_crate(files_from_crate(data), "%s@%s" % (name, ver), build_only)


def lockfile_specs(path):
    """Every crates.io-sourced [[package]] in a Cargo.lock."""
    specs, cur = [], {}
    for line in open(path, encoding="utf-8").read().split("\n") + ["[[package]]"]:
        line = line.strip()
        if line == "[[package]]" or line.startswith("[") and not line.startswith("[["):
            if cur.get("name") and cur.get("version") and "crates.io-index" in cur.get("source", "") \
                    or cur.get("source", "").startswith("sparse+https://index.crates.io"):
                specs.append("%s@%s" % (cur["name"], cur["version"]))
            cur = {}
            continue
        m = re.match(r'^(name|version|source)\s*=\s*"([^"]*)"', line)
        if m:
            cur[m.group(1)] = m.group(2)
    return sorted(set(specs))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
_ICON = {"CRITICAL": "\U0001F534", "HIGH": "\U0001F7E0", "MEDIUM": "\U0001F7E1",
         "LOW": "\U0001F535", "SAFE": "\U0001F7E2"}


def _print(r, verbose):
    bt = r.get("build_time") or {}
    tag = []
    if bt.get("build_script"):
        tag.append("build.rs")
    if bt.get("proc_macro"):
        tag.append("proc-macro")
    print("%s %s  [%s]  score=%d  (%d findings, %d info)%s" % (
        _ICON.get(r["risk_level"], "?"), r["target"], r["risk_level"], r["risk_score"],
        r["total_findings"], r["info_count"], ("  runs-at-build: " + ",".join(tag)) if tag else ""))
    for f in r["findings"]:
        print("    %-8s %s  %s:%s" % (f["severity"], f["name"], f["file"], f["line"]))
        if f["context"] and f["line"]:
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
    build_only = "--build-only" in args
    args = [a for a in args if a not in ("--json", "--verbose", "-v", "--build-only")]
    targets = []
    if args[0] == "--text":
        txt = " ".join(args[1:])
        targets.append(("<text>", lambda: scan(txt)))
    elif args[0] == "--lockfile":
        for spec in lockfile_specs(args[1]):
            targets.append((spec, (lambda s=spec: audit_registry(s, build_only))))
    else:
        for a in args:
            if os.path.isdir(a):
                targets.append((a, (lambda p=a: scan_crate(files_from_dir(p), p, build_only))))
            elif os.path.isfile(a):
                if os.path.basename(a) == "Cargo.toml":
                    targets.append((a, (lambda p=a: scan_crate(files_from_dir(os.path.dirname(p) or "."), p, build_only))))
                elif a.endswith(".crate"):
                    targets.append((a, (lambda p=a: scan_crate(files_from_crate(open(p, "rb").read()), p, build_only))))
                else:
                    targets.append((a, (lambda p=a: scan(open(p, encoding="utf-8", errors="replace").read(), p,
                                                         "build" if os.path.basename(p) == "build.rs" else None))))
            else:
                targets.append((a, (lambda s=a: audit_registry(s, build_only))))
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
