#!/usr/bin/env python3
"""hf-code-audit - scan the Python that Hugging Face runs under trust_remote_code=True.

`AutoModel.from_pretrained(repo, trust_remote_code=True)` downloads the repo's modeling_*.py /
configuration_*.py / tokenization_*.py (whatever config.json's `auto_map` points at), IMPORTS
it and instantiates its classes - arbitrary code from the model repo, running with your user's
privileges, environment and network. Weight scanners (picklescan, modelscan, fickling) cover
the serialized tensors; nothing covers this code. This does.

It parses each file with Python's own `ast` (no regex guessing about what is code) and weights
every finding by WHEN it runs:
  import  - module level or class body: runs the moment transformers imports the file
  init    - __init__ / post_init / from_pretrained ...: runs when the model is built
  runtime - any other function: runs on forward / generate / preprocessing
  unloaded- a .py the auto_map never reaches (training/convert scripts): downgraded one level

Signals: process execution (os.system, subprocess, pty) - escalated when the command is built
at runtime or runs at import; network at import/init outside the Hub; credential and
environment reads combined with a network send; decode-then-exec (base64 / zlib / marshal /
bytes.fromhex into exec / eval / compile); reverse shells; writes to persistence locations
(~/.bashrc, ~/.ssh, crontab, LaunchAgents, sitecustomize / .pth); runtime `pip install`
(MEDIUM; HIGH from a URL or git); hard-coded collector hosts; `auto_map` entries that pull code
from ANOTHER repo ("org/repo--modeling_x.Cls").

Precision first: what real remote-code models do every day (hf_hub_download / snapshot_download,
loading an image from a URL handed in by the caller, flash-attn import probes, `nvidia-smi` /
`git` probes, torch.utils.cpp_extension builds) is reported as informational context and never
inflates the risk score. Nothing is imported or executed: files are read as text and parsed.

Usage:
  python hf_code_audit.py <dir|file.py> [...]       # scan a local snapshot / file
  python hf_code_audit.py --hf org/model[@rev]      # fetch .py + config JSON only (never weights)
  python hf_code_audit.py --hf org/model --auto-map # also fetch + scan cross-repo auto_map code
  python hf_code_audit.py --text "python source"    # scan a string
  add --json (family schema) or --sarif (SARIF 2.1.0) for machine-readable output,
  --fail-on {critical,high,medium,low,never}, --version, --verbose to print INFO context

Exit code 2 if any target reaches --fail-on (default HIGH; CI-friendly), 1 on usage errors.
No dependencies beyond the standard library. MIT licensed.
"""
import ast
import hashlib
import json
import os
import re
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

__version__ = "0.2.0"

HUB = os.environ.get("HF_CODE_AUDIT_ENDPOINT", "https://huggingface.co").rstrip("/")
CONFIG_JSONS = ("config.json", "tokenizer_config.json", "preprocessor_config.json",
                "processor_config.json", "feature_extractor_config.json",
                "image_processor_config.json", "video_preprocessor_config.json")
MAX_FILE = 2000000
LOADED_PREFIX = ("modeling_", "configuration_", "tokenization_", "processing_",
                 "image_processing_", "feature_extraction_", "video_processing_")
INIT_FUNCS = {"__init__", "__new__", "__post_init__", "post_init", "from_pretrained",
              "_from_config", "init_weights", "_init_weights", "__init_subclass__"}
WHEN_RANK = {"import": 3, "init": 2, "runtime": 1, "main": 0, "unloaded": 0}

EXFIL_HOST = re.compile(
    r"(?:discord(?:app)?\.com/api/webhooks/\d|api\.telegram\.org/bot\w|hooks\.slack\.com/services/T|"
    r"webhook\.site/[0-9a-f]{8}|pipedream\.net|requestbin\.(?:com|net|io)\b|requestb\.in\b|"
    r"\bngrok(?:-free)?\.(?:io|app|dev)\b|\binteractsh\.com\b|\boast\.(?:fun|me|live|site|online|pro)\b|"
    r"burpcollaborator\.net|\bpastebin\.com/raw|transfer\.sh/|\bserveo\.net|\.trycloudflare\.com)",
    re.IGNORECASE)
RAW_IP_URL = re.compile(
    r"https?://(?!(?:127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|"
    r"192\.0\.2\.|198\.51\.100\.|203\.0\.113\.))\d{1,3}(?:\.\d{1,3}){3}")
HUB_HOSTS = re.compile(r"huggingface\.co|hf\.co\b|hf-mirror\.com|cdn-lfs|modelscope\.cn")
CRED_PATH = re.compile(
    r"(?:\.ssh/(?:id_|authorized_keys|known_hosts|config)|\.aws/credentials|\.cache/huggingface/token|"
    r"huggingface/token\b|\.netrc\b|\.git-credentials|\.docker/config\.json|\.kube/config|"
    r"\.config/gcloud|application_default_credentials|\.npmrc\b|\.pypirc\b|Login Data|Local State|keychain|wallet\.dat|\.bash_history)",
    re.IGNORECASE)
PERSIST_PATH = re.compile(
    r"(?:\.bashrc|\.zshrc|\.bash_profile|\.profile\b|\.ssh/authorized_keys|/etc/cron|crontab|"
    r"LaunchAgents|LaunchDaemons|/etc/systemd|\.config/autostart|sitecustomize\.py|usercustomize\.py|"
    r"\.pth\b|/etc/rc\.local|/etc/profile|Start Menu\\\\Programs\\\\Startup|CurrentVersion\\\\Run)",
    re.IGNORECASE)
SECRET_ENV = re.compile(
    r"^(?:HF_TOKEN|HUGGING_FACE_HUB_TOKEN|HUGGINGFACE_TOKEN|HF_API_TOKEN|AWS_SECRET_ACCESS_KEY|"
    r"AWS_ACCESS_KEY_ID|AWS_SESSION_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|GITHUB_TOKEN|GH_TOKEN|"
    r"WANDB_API_KEY|GOOGLE_APPLICATION_CREDENTIALS|AZURE_\w*KEY\w*|\w*SECRET\w*|\w*PASSWORD\w*|"
    r"\w*API_KEY)$")
# credentials that belong to a DIFFERENT service than the code calls (a stealer's targets)
CROSS_SECRET = re.compile(
    r"^(?:AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|AWS_SESSION_TOKEN|GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|"
    r"NPM_TOKEN|PYPI_TOKEN|TWINE_PASSWORD|DOCKER_PASSWORD|GOOGLE_APPLICATION_CREDENTIALS|AZURE_CLIENT_SECRET|"
    r"KAGGLE_KEY|SSH_AUTH_SOCK|DATABASE_URL|HF_TOKEN|HUGGING_FACE_HUB_TOKEN)$")
CLOUD_METADATA = re.compile(r"169\.254\.169\.254|metadata\.google\.internal|fd00:ec2::254|100\.100\.100\.200|"
                            r"/latest/meta-data/iam|/computeMetadata/v1/|instance/service-accounts")
PIP_RE = re.compile(r"\bpip3?\b[^\n]{0,40}\binstall\b|-m\s*pip\b|ensurepip")
PIP_REMOTE = re.compile(r"git\+|https?://|\.whl\b|--index-url|--extra-index-url|-i\s+http")
SHELL_NAMES = re.compile(r"^(?:/bin/|/usr/bin/)?(?:ba|z|da|k)?sh$|^cmd(?:\.exe)?$|^powershell(?:\.exe)?$|^pwsh$")
BENIGN_CMDS = re.compile(
    r"^(?:nvidia-smi|nvcc|git|uname|lscpu|hostname|which|where|rocm-smi|rocminfo|hipcc|"
    r"ninja|cmake|make|gcc|g\+\+|clang|c\+\+|ldconfig|nproc|free|df|ls|python3?|"
    r"sys\.executable|ffmpeg|ffprobe|sox|espeak(?:-ng)?|tesseract|mecab|java|javac|node|npm|"
    r"pdftoppm|pdfinfo|gs|convert|magick|libreoffice|soffice|xvfb-run|wkhtmltopdf)$")
DL_URL_LITERAL = re.compile(r"""^https?://""")

NET_CALLS = {
    "requests.get", "requests.post", "requests.put", "requests.patch", "requests.request",
    "requests.Session", "requests.head", "requests.delete",
    "urllib.request.urlopen", "urllib.request.urlretrieve", "urllib.request.Request",
    "urllib.urlopen", "urllib2.urlopen", "httpx.get", "httpx.post", "httpx.Client",
    "httpx.AsyncClient", "aiohttp.ClientSession", "http.client.HTTPConnection",
    "http.client.HTTPSConnection", "socket.socket", "socket.create_connection",
    "ftplib.FTP", "smtplib.SMTP", "smtplib.SMTP_SSL", "websocket.create_connection",
    "websockets.connect", "wget.download", "paramiko.SSHClient", "telnetlib.Telnet",
    "dns.resolver.resolve", "socket.gethostbyname", "socket.getaddrinfo",
}
SEND_CALLS = {"requests.post", "requests.put", "requests.patch", "httpx.post", "smtplib.SMTP",
              "smtplib.SMTP_SSL", "ftplib.FTP", "urllib.request.Request", "socket.socket",
              "socket.create_connection", "websocket.create_connection", "websockets.connect",
              "http.client.HTTPConnection", "http.client.HTTPSConnection", "requests.request",
              "dns.resolver.resolve", "socket.gethostbyname", "paramiko.SSHClient"}
HUB_CALLS = ("hf_hub_download", "snapshot_download", "cached_file", "cached_path", "get_file_from_repo",
             "hf_hub_url", "list_repo_files", "HfApi", "try_to_load_from_cache", "get_checkpoint_shard_files")
EXEC_CALLS = {"os.system", "os.popen", "os.execv", "os.execve", "os.execl", "os.execlp", "os.execvp",
              "os.spawnl", "os.spawnv", "os.spawnlp", "os.spawnvp", "os.posix_spawn", "os.startfile",
              "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
              "subprocess.Popen", "subprocess.getoutput", "subprocess.getstatusoutput",
              "commands.getoutput", "pty.spawn", "asyncio.create_subprocess_shell",
              "asyncio.create_subprocess_exec", "pexpect.spawn", "sh.Command"}
DECODE_CALLS = {"base64.b64decode", "base64.b32decode", "base64.b85decode", "base64.a85decode",
                "base64.decodebytes", "base64.urlsafe_b64decode", "zlib.decompress", "gzip.decompress",
                "bz2.decompress", "lzma.decompress", "marshal.loads", "codecs.decode", "bytes.fromhex",
                "binascii.unhexlify", "binascii.a2b_base64", "pickle.loads", "dill.loads"}
DYN_EXEC = {"exec", "eval", "compile", "builtins.exec", "builtins.eval", "execfile"}

PATTERN_DOC = [
    # (id, severity at its strongest, name, description) - documentation + README table
    ("decode_exec", "CRITICAL", "Decode-then-Execute", "exec/eval/compile of base64/zlib/marshal/hex-decoded data"),
    ("reverse_shell", "CRITICAL", "Reverse Shell", "socket wired to a shell (dup2 / pty.spawn / stdin=socket)"),
    ("credential_exfil", "CRITICAL", "Credential Exfiltration", "reads a token/credential store and sends data off-host"),
    ("env_exfil", "CRITICAL", "Environment Exfiltration", "serialises os.environ and sends it"),
    ("persistence_write", "CRITICAL", "Persistence Write", "writes shell rc / authorized_keys / crontab / LaunchAgents / .pth"),
    ("download_execute", "CRITICAL", "Download & Execute", "fetches a URL and runs it (curl|sh, exec(requests.get().text))"),
    ("exfil_host", "HIGH", "Collector Endpoint", "hard-coded webhook / bot / tunnel / OAST host"),
    ("shell_exec", "HIGH", "Shell Execution", "os.system / shell=True / popen with a command built at runtime, or any exec at import"),
    ("dynamic_exec", "HIGH", "Dynamic Code Execution", "exec / eval / compile of a non-literal string (HIGH at import; MEDIUM on model output / arguments)"),
    ("import_network", "MEDIUM", "Network at Import", "network call at module import / model init to a non-Hub host (unpinned)"),
    ("obfuscation", "HIGH", "Obfuscated Code", "__import__('os'/'subprocess'/'socket'...) chains, getattr(builtins, 'exec'), split-literal hosts with a send"),
    ("raw_ip", "MEDIUM", "Raw-IP Endpoint", "network call to a public raw IP address"),
    ("pip_install", "MEDIUM", "Runtime pip install", "installs packages when the model loads (HIGH from a URL / git)"),
    ("cross_repo_code", "LOW", "Cross-Repo Code", "auto_map pulls unpinned code from a repo in another namespace"),
    ("secret_env_read", "LOW", "Secret Env Read", "reads a secret-looking env var (escalates with a send)"),
    ("process_exec", "INFO", "Process Execution", "literal command / probe (nvidia-smi, git, ninja ...)"),
    ("network", "INFO", "Network Use", "HTTP / socket use at runtime, Hub downloads"),
    ("native_build", "INFO", "Native Extension Build", "torch.utils.cpp_extension.load / ctypes.CDLL"),
    ("pickle_load", "INFO", "Pickle Load", "pickle / torch.load(weights_only=False) of downloaded files"),
    ("same_ns_code", "INFO", "Same-Namespace Code", "auto_map pulls code from another repo of the same owner"),
    ("embedded_blob", "INFO", "Embedded Blob", "long base64/hex string literal not fed to a decoder"),
]
SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "SAFE": 0}
SEV_SCORE = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}
_NAMES = {p[0]: p[2] for p in PATTERN_DOC}
_DESCS = {p[0]: p[3] for p in PATTERN_DOC}
MALICE_SHAPES = {"decode_exec", "reverse_shell", "credential_exfil", "env_exfil", "persistence_write",
                 "download_execute", "exfil_host", "obfuscation"}
DOWN = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "INFO", "INFO": "INFO"}


# ---------------------------------------------------------------------------------------------
# AST analysis
# ---------------------------------------------------------------------------------------------

def _str_consts(node, limit=40):
    """All string constants under node (f-string pieces included)."""
    out = []
    for n in ast.walk(node):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            out.append(n.value)
            if len(out) >= limit:
                break
    return out


def _is_literal_str(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, (ast.List, ast.Tuple)):
        return all(isinstance(e, ast.Constant) for e in node.elts)
    return False


class _Visitor(ast.NodeVisitor):
    def __init__(self, src, path):
        self.src = src
        self.path = path
        self.alias = {}        # local name -> dotted module path
        self.ctx = []          # stack of function names
        self.main_guard = 0
        self.calls = []        # (dotted, node, when, func_name)
        self.envs = []         # (key_or_None, node, when) os.environ / getenv access
        self.strings = []      # (value, node)
        self.opens = []        # (node, when, path_strings, mode)
        self.has_dup2 = False
        self.import_tricks = []  # __import__("os").system(...) chains
        self.cfg_names = set()   # local names assigned from a config expression
        self.docstrings = set()  # id() of docstring / bare-string-statement constants
        self.split_literals = 0  # "ab" + "c" + "d" literal concatenations (evasion tell)
        self.benign_cmd_names = set()  # names assigned a command string for a known tool

    # -- imports -------------------------------------------------------------------------------
    def visit_Import(self, node):
        for a in node.names:
            self.alias[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        mod = node.module or ""
        for a in node.names:
            if a.name == "*":
                continue
            self.alias[a.asname or a.name] = (mod + "." + a.name) if mod else a.name
        self.generic_visit(node)

    # -- context -------------------------------------------------------------------------------
    def _fn(self, node):
        self.ctx.append(node.name)
        self.generic_visit(node)
        self.ctx.pop()

    visit_FunctionDef = _fn
    visit_AsyncFunctionDef = _fn

    def visit_Lambda(self, node):
        self.ctx.append("<lambda>")
        self.generic_visit(node)
        self.ctx.pop()

    def visit_If(self, node):
        t = node.test
        is_main = (isinstance(t, ast.Compare) and isinstance(t.left, ast.Name) and t.left.id == "__name__"
                   and any(isinstance(c, ast.Constant) and c.value == "__main__" for c in t.comparators))
        if is_main and not self.ctx:
            self.visit(node.test)
            self.main_guard += 1
            for n in node.body:
                self.visit(n)
            self.main_guard -= 1
            for n in node.orelse:
                self.visit(n)
            return
        self.generic_visit(node)

    def when(self):
        if self.main_guard:
            return "main"
        if not self.ctx:
            return "import"
        if any(f in INIT_FUNCS for f in self.ctx):
            return "init"
        return "runtime"

    # -- names ---------------------------------------------------------------------------------
    def dotted(self, node):
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        elif isinstance(node, ast.Call):
            inner = self.dotted(node.func)
            if inner == "__import__" and node.args and isinstance(node.args[0], ast.Constant):
                self.import_tricks.append(node)
                parts.append(str(node.args[0].value))
            elif inner:
                parts.append(inner + "()")
            else:
                return None
        else:
            return None
        parts.reverse()
        head = self.alias.get(parts[0], parts[0])
        return ".".join([head] + parts[1:])

    # -- calls ---------------------------------------------------------------------------------
    def visit_Call(self, node):
        d = self.dotted(node.func)
        if d:
            self.calls.append((d, node, self.when(), self.ctx[-1] if self.ctx else ""))
            if d in ("os.getenv", "os.environ.get", "os.environ.__getitem__", "os.environ.pop"):
                k = node.args[0].value if node.args and isinstance(node.args[0], ast.Constant) else None
                self.envs.append((k, node, self.when()))
            if d in ("os.dup2",):
                self.has_dup2 = True
            if d in ("open", "io.open", "builtins.open", "codecs.open", "pathlib.Path.write_text",
                     "pathlib.Path.write_bytes", "shutil.copy", "shutil.copyfile", "shutil.move",
                     "os.symlink", "os.rename", "os.replace"):
                mode = ""
                if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                    mode = str(node.args[1].value)
                for kw in node.keywords:
                    if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                        mode = str(kw.value.value)
                self.opens.append((node, self.when(), _str_consts(node), mode, d))
        # Path(...).write_text / .open("w") - attribute calls on arbitrary expressions
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("write_text", "write_bytes"):
            self.opens.append((node, self.when(), _str_consts(node.func.value) + _str_consts(node), "w", "write"))
        self.generic_visit(node)

    def visit_Assign(self, node):
        try:
            txt = ast.dump(node.value)
        except Exception:
            txt = ""
        lead = None
        val = node.value
        if isinstance(val, ast.Call) and isinstance(val.func, ast.Attribute) and val.func.attr == "format":
            val = val.func.value
        if isinstance(val, ast.Constant) and isinstance(val.value, str):
            lead = val.value.split()[0] if val.value.split() else None
        elif isinstance(val, ast.JoinedStr) and val.values and isinstance(val.values[0], ast.Constant):
            lead = str(val.values[0].value).split()[0] if str(val.values[0].value).split() else None
        if lead and BENIGN_CMDS.match(os.path.basename(lead)):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self.benign_cmd_names.add(t.id)
        if "config" in txt.lower():
            for t in node.targets:
                for n in ast.walk(t):
                    if isinstance(n, ast.Name):
                        self.cfg_names.add(n.id)
        self.generic_visit(node)

    def visit_Subscript(self, node):
        d = self.dotted(node.value)
        if d == "os.environ":
            sl = node.slice
            if isinstance(sl, ast.Index):  # py3.8 compat
                sl = sl.value
            k = sl.value if isinstance(sl, ast.Constant) else None
            self.envs.append((k, node, self.when()))
        self.generic_visit(node)

    def visit_Expr(self, node):
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            self.docstrings.add(id(node.value))
        self.generic_visit(node)

    def visit_BinOp(self, node):
        # fold "http://16" + "9" + ".254.169.254" style split literals so evasion by
        # concatenation is seen as the joined string
        if isinstance(node.op, ast.Add) and not getattr(node, "_folded", False):
            parts, ok = [], True
            stack = [node]
            while stack:
                n = stack.pop()
                if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
                    n._folded = True
                    stack.append(n.right)
                    stack.append(n.left)
                elif isinstance(n, ast.Constant) and isinstance(n.value, str):
                    parts.append(n.value)
                elif isinstance(n, ast.JoinedStr):
                    parts.append("".join(v.value for v in n.values if isinstance(v, ast.Constant)))
                else:
                    ok = False
                    parts.append("")
            joined = "".join(parts)
            if len(parts) > 1 and len(joined) >= 8:
                self.strings.append((joined, node))
                self.split_literals += 1 if ok and len(parts) >= 3 else 0
        self.generic_visit(node)

    def visit_Constant(self, node):
        if isinstance(node.value, str) and len(node.value) >= 8 and id(node) not in self.docstrings:
            self.strings.append((node.value, node))


def _line(src_lines, n):
    i = getattr(n, "lineno", 0)
    return i, (src_lines[i - 1].strip()[:200] if 0 < i <= len(src_lines) else "")


def _cmd_info(call):
    """For an exec-style call: (literal_cmd_or_None, shell_flag, dynamic)."""
    shell = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in call.keywords)
    if not call.args:
        return None, shell, False
    a = call.args[0]
    if isinstance(a, ast.Constant) and isinstance(a.value, str):
        return a.value, shell, False
    if isinstance(a, (ast.List, ast.Tuple)) and a.elts:
        first = a.elts[0]
        lit = None
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            lit = first.value
        elif isinstance(first, ast.Attribute) and isinstance(first.value, ast.Name) and first.attr == "executable":
            lit = "sys.executable"
        rest = " ".join(str(e.value) for e in a.elts if isinstance(e, ast.Constant))
        dyn = not all(isinstance(e, ast.Constant) for e in a.elts[1:])
        return ((lit or "") + " " + rest).strip() or None, shell, dyn and lit is None
    return None, shell, True


def _has_decoder(node, vis):
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            d = vis.dotted(n.func) or ""
            if d in DECODE_CALLS or d.endswith((".b64decode", ".decompress", ".fromhex", ".unhexlify")) \
                    or (d.endswith(".decode") and n.args and isinstance(n.args[0], ast.Constant)
                        and str(n.args[0].value).lower() in ("rot13", "rot_13", "base64", "hex", "zlib")):
                return d
    return None


SENSITIVE_MODS = {"os", "subprocess", "socket", "builtins", "ctypes", "base64", "zlib", "marshal",
                  "pty", "urllib", "requests", "codecs", "pickle"}


def hosts_pre(v):
    return any(EXFIL_HOST.search(s) or CLOUD_METADATA.search(s) for s, _ in v.strings)


def _has_env(node, vis):
    for n in ast.walk(node):
        if isinstance(n, ast.Call) and (vis.dotted(n.func) or "") in ("os.getenv", "os.environ.get"):
            return True
        if isinstance(n, ast.Subscript) and (vis.dotted(n.value) or "") == "os.environ":
            return True
    return False


def _has_net(node, vis):
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            d = vis.dotted(n.func) or ""
            if d in NET_CALLS or d.split(".")[-1] in ("urlopen", "urlretrieve"):
                return d
            if d.endswith((".get", ".post")) and d.split(".")[0] in ("requests", "httpx", "session", "s"):
                return d
    return None


def scan_source(src, path, loaded=True):
    """Scan one Python file. Returns (findings, info, facts)."""
    findings, info = [], []
    facts = {"exec_import": False, "net_import": False, "pip": False, "net": False, "exec": False,
             "parse_error": False}
    lines = src.splitlines()
    try:
        tree = ast.parse(src, filename=path)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        facts["parse_error"] = True
        return _scan_regex(src, path, loaded, findings, info, facts)
    v = vv = _Visitor(src, path)
    try:
        v.visit(tree)
    except RecursionError:
        facts["parse_error"] = True
        return _scan_regex(src, path, loaded, findings, info, facts)

    def add(pid, sev, node, when, matched="", extra=""):
        n, ctx = _line(lines, node) if node is not None else (0, extra)
        sev_eff = sev
        if not loaded:
            # a script trust_remote_code never imports only runs if the user runs it: malicious
            # shapes drop one level, capability-style findings two
            sev_eff = DOWN[sev] if pid in MALICE_SHAPES else DOWN[DOWN[sev]]
            when = "unloaded"
        if when == "main" and sev_eff not in ("CRITICAL",):
            sev_eff = DOWN[sev_eff]
        item = {"severity": sev_eff, "id": pid, "name": _NAMES[pid], "description": _DESCS[pid],
                "file": path, "line": n, "when": when, "matched": matched[:120], "context": ctx}
        (info if sev_eff == "INFO" else findings).append(item)

    file_has_send = False
    file_net_nonhub = False
    send_nodes = []
    hub_only_hosts = True
    for d, call, when, fn in v.calls:
        short = d.split(".")[-1]
        # ---------------- network ----------------
        is_net = d in NET_CALLS or short in ("urlopen", "urlretrieve")
        if is_net:
            facts["net"] = True
            strs = _str_consts(call)
            url_lits = [s for s in strs if DL_URL_LITERAL.match(s)]
            nonhub = [u for u in url_lits if not HUB_HOSTS.search(u)]
            if d in SEND_CALLS or (d.endswith("request") and any(s.upper() in ("POST", "PUT") for s in strs)):
                file_has_send = True
                send_nodes.append(call)
            if any(RAW_IP_URL.search(u) for u in url_lits):
                add("raw_ip", "MEDIUM", call, when, d)
            if when in ("import", "init") and (nonhub or d.startswith("socket.")):
                facts["net_import"] = True
                file_net_nonhub = True
                # fetching DATA (a font, a vocab) at import is an unpinned dependency, not an attack;
                # running what was fetched is download_execute (CRITICAL) below
                add("import_network", "MEDIUM" if when == "import" else "LOW", call, when, d)
            else:
                add("network", "INFO", call, when, d)
            continue
        if short in HUB_CALLS:
            add("network", "INFO", call, when, d)
            continue
        # ---------------- process execution ----------------
        if d in EXEC_CALLS or (short in ("system", "popen") and d.startswith("os")):
            facts["exec"] = True
            lit, shell, dyn = _cmd_info(call)
            text = " ".join(_str_consts(call))
            if PIP_RE.search(text):
                facts["pip"] = True
                sev = "HIGH" if PIP_REMOTE.search(text) else "MEDIUM"
                add("pip_install", sev, call, when, text[:120])
                continue
            if re.search(r"\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|"
                         r"\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]{0,200}\|\s*iex\b", text, re.I):
                add("download_execute", "CRITICAL", call, when, text[:120])
                continue
            if v.has_dup2 or d == "pty.spawn":
                if d == "pty.spawn" or (lit and SHELL_NAMES.match(lit.split()[0] if lit.split() else "")):
                    if any(c[0].startswith("socket.") for c in v.calls):
                        add("reverse_shell", "CRITICAL", call, when, d)
                        continue
            stdin_sock = any(kw.arg in ("stdin", "stdout") and isinstance(kw.value, ast.Call)
                             and (v.dotted(kw.value.func) or "").endswith("fileno") for kw in call.keywords)
            if stdin_sock and any(c[0].startswith("socket.") for c in v.calls):
                add("reverse_shell", "CRITICAL", call, when, d)
                continue
            first = (lit or "").split()[0] if (lit or "").split() else ""
            benign = bool(first) and bool(BENIGN_CMDS.match(os.path.basename(first)))
            if not lit and call.args and isinstance(call.args[0], ast.Name) and call.args[0].id in v.benign_cmd_names:
                benign, dyn, lit = True, False, call.args[0].id
            dynamic = dyn or lit is None
            if when == "import" and not benign:
                facts["exec_import"] = True
                add("shell_exec", "HIGH", call, when, (lit or d)[:120])
            elif dynamic and not benign and (shell or d in ("os.system", "os.popen", "subprocess.getoutput",
                                             "subprocess.getstatusoutput", "asyncio.create_subprocess_shell")):
                add("shell_exec", "HIGH" if when in ("import", "init") else "MEDIUM", call, when, d)
            else:
                add("process_exec", "INFO", call, when, (lit or d)[:120])
            continue
        # ---------------- dynamic code ----------------
        if d in DYN_EXEC:
            if not call.args:
                continue
            a = call.args[0]
            dec = _has_decoder(a, v)
            if dec:
                add("decode_exec", "CRITICAL", call, when, "%s(%s(...))" % (d, dec))
                continue
            if _has_net(a, v):
                add("download_execute", "CRITICAL", call, when, d + "(<network response>)")
                continue
            if _is_literal_str(a):
                continue
            # eval of a config value / attribute name is common (e.g. eval(f"torch.{dtype}")).
            consts = " ".join(_str_consts(a))
            if d in ("eval",) and re.match(r"^\s*(?:torch|nn|np|math|F)\.", consts or ""):
                add("process_exec", "INFO", call, when, "eval(<dtype/attr name>)")
                continue
            # eval of a value from the repo's own config: the config ships with the code, so it
            # grants nothing the code doesn't already have - context, not risk.
            names = [n.id for n in ast.walk(a) if isinstance(n, ast.Name)]
            cfgish = any("config" in (vv.dotted(n) or "").lower() for n in ast.walk(a) if isinstance(n, ast.Attribute)) \
                or any(n in vv.cfg_names for n in names)
            if cfgish and all(n in ("self", "config", "str", "int", "float") or n in vv.cfg_names or "config" in n.lower()
                              for n in names):
                add("process_exec", "INFO", call, when, "eval(<config value>)")
                continue
            if _has_env(a, vv):
                add("dynamic_exec", "LOW", call, when, "eval(<environment variable>)")
                continue
            add("dynamic_exec", "HIGH" if when == "import" else "MEDIUM", call, when, d)
            continue
        if d == "__import__" and call.args and not isinstance(call.args[0], ast.Constant):
            add("obfuscation", "MEDIUM", call, when, "__import__(<dynamic>)")
            continue
        if d == "__import__" and call.args and isinstance(call.args[0], ast.Constant):
            v.import_tricks.append(call)
            continue
        if d.startswith("__import__()") or d in ("getattr",) and call.args and \
                (v.dotted(call.args[0]) or "") in ("builtins", "__builtins__") and len(call.args) > 1 and \
                isinstance(call.args[1], ast.Constant) and call.args[1].value in ("exec", "eval", "compile", "__import__"):
            add("obfuscation", "HIGH", call, when, d)
            continue
        if d in ("torch.utils.cpp_extension.load", "torch.utils.cpp_extension.load_inline",
                 "ctypes.CDLL", "ctypes.cdll.LoadLibrary", "ctypes.WinDLL"):
            add("native_build", "INFO", call, when, d)
            continue
        if d in ("pickle.load", "pickle.loads", "dill.load", "joblib.load", "torch.load", "cloudpickle.load"):
            add("pickle_load", "INFO", call, when, d)
            continue
        if d in ("pip.main", "pip._internal.main", "pip._internal.cli.main.main"):
            facts["pip"] = True
            add("pip_install", "MEDIUM", call, when, d)
            continue

    trick_ids = {id(n) for n in v.import_tricks if str(n.args[0].value).split(".")[0] in SENSITIVE_MODS}
    risky = []
    for d, call, when, fn in v.calls:
        if any(id(n) in trick_ids for n in ast.walk(call.func)):
            if d in EXEC_CALLS or d in NET_CALLS or d in DECODE_CALLS or d.split(".")[-1] in (
                    "system", "popen", "urlopen", "b64decode", "loads", "connect", "socket", "exec", "eval",
                    "Popen", "run", "check_output", "call", "spawn", "getoutput"):
                risky.append(call)
    if risky:
        add("obfuscation", "HIGH", risky[0], "runtime", "__import__('%s') chain" % risky[0].args[0].value)

    # ---------------- secrets / environment ----------------
    secret_reads = []
    for k, node, when in v.envs:
        if k and SECRET_ENV.match(str(k)):
            secret_reads.append((k, node, when))
    env_dump = []
    for d, call, when, fn in v.calls:
        if d in ("json.dumps", "str", "repr", "pickle.dumps", "urllib.parse.urlencode", "base64.b64encode") and call.args:
            a0 = call.args[0]
            inner = v.dotted(a0.func) if isinstance(a0, ast.Call) else v.dotted(a0)
            if (inner or "") in ("os.environ", "os.environ.items", "os.environ.copy", "dict") and \
                    (inner != "dict" or (a0.args and (v.dotted(a0.args[0]) or "") == "os.environ" and not a0.keywords)):
                env_dump.append((call, when))
        elif d in ("os.environ.copy", "os.environ.items") and fn:
            pass
    cred_files = []
    for s, node in v.strings:
        if CLOUD_METADATA.search(s):
            cred_files.append((s, node))
            continue
        if CRED_PATH.search(s) and s.count(" ") <= 3 and len(s) < 300:   # a path, not prose
            cred_files.append((s, node))
    # Exfil hosts in string constants
    hosts = [(s, node) for s, node in v.strings if EXFIL_HOST.search(s)]
    for s, node in hosts[:5]:
        add("exfil_host", "HIGH", node, "runtime", EXFIL_HOST.search(s).group(0))
    lits = " ".join(x for x, _ in v.strings).lower()

    def first_party(k):
        # a service's own key sent to that service's API (MOONDREAM_API_KEY -> api.moondream.ai)
        k = str(k).upper()
        if k.startswith(("HF_", "HUGGING")):
            return True
        pre = re.split(r"_(?:API_?KEY|API_?TOKEN|TOKEN|KEY|SECRET\w*|PASSWORD)$", k)[0].lower().replace("_", "")
        return bool(pre) and len(pre) >= 3 and pre in lits.replace("-", "").replace("_", "")
    foreign = [(k, n, w) for k, n, w in secret_reads if CROSS_SECRET.match(str(k)) and not first_party(k)]
    if (cred_files or foreign) and (file_has_send or hosts):
        node = (cred_files[0][1] if cred_files else foreign[0][1])
        add("credential_exfil", "CRITICAL", node, "runtime",
            cred_files[0][0] if cred_files else str(foreign[0][0]))
    elif secret_reads:
        for k, node, when in secret_reads[:3]:
            add("secret_env_read", "INFO" if first_party(k) or not foreign else "LOW", node, when, str(k))
    if env_dump and (file_has_send or hosts):
        add("env_exfil", "CRITICAL", env_dump[0][0], env_dump[0][1], "os.environ -> network")

    if v.split_literals >= 3 and (cred_files or hosts_pre(v)) and file_has_send:
        add("obfuscation", "HIGH", None, "runtime", "%d split string literals hiding hosts/paths" % v.split_literals,
            extra="file-level: literals assembled from fragments")

    # ---------------- persistence writes ----------------
    for node, when, strs, mode, d in v.opens:
        writes = d not in ("open", "io.open", "builtins.open", "codecs.open") or any(c in mode for c in "wax+")
        if not writes:
            continue
        hit = next((s for s in strs if PERSIST_PATH.search(s)), None)
        if hit:
            add("persistence_write", "CRITICAL", node, when, hit)

    # ---------------- blobs ----------------
    for s, node in v.strings:
        if len(s) >= 2048 and re.fullmatch(r"[A-Za-z0-9+/=\s]+|[0-9a-fA-F\s]+", s[:4096]):
            add("embedded_blob", "INFO", node, "runtime", "%d-char encoded literal" % len(s))
            break
    return findings, info, facts


_RX = [
    ("decode_exec", "CRITICAL", re.compile(r"\b(?:exec|eval)\s*\(\s*(?:\w+\.)*(?:b64decode|decompress|loads|fromhex|unhexlify)\s*\(")),
    ("download_execute", "CRITICAL", re.compile(r"\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b")),
    ("download_execute", "CRITICAL", re.compile(r"\b(?:exec|eval)\s*\(\s*(?:requests\.get|urlopen)\s*\(")),
    ("reverse_shell", "CRITICAL", re.compile(r"os\.dup2\s*\([^\n]{0,80}fileno\s*\(")),
    ("persistence_write", "CRITICAL", re.compile(r"open\s*\([^\n]{0,120}(?:\.bashrc|\.zshrc|authorized_keys|sitecustomize\.py|LaunchAgents)[^\n]{0,40}['\"][wa]")),
    ("pip_install", "MEDIUM", re.compile(r"(?:os\.system|subprocess\.\w+)\s*\([^\n]{0,120}\bpip3?\b[^\n]{0,40}\binstall\b")),
    ("shell_exec", "MEDIUM", re.compile(r"\bos\.system\s*\(\s*(?!['\"])")),
]


def _scan_regex(src, path, loaded, findings, info, facts):
    """Fallback for files Python 3.9's parser rejects (match statements, newer syntax)."""
    lines = src.splitlines()
    for i, ln in enumerate(lines, 1):
        if len(ln) > 20000:
            ln = ln[:20000]
        for pid, sev, rx in _RX:
            m = rx.search(ln)
            if m:
                s = sev if loaded else DOWN[sev]
                (info if s == "INFO" else findings).append({
                    "severity": s, "id": pid, "name": _NAMES[pid], "description": _DESCS[pid] + " [regex fallback]",
                    "file": path, "line": i, "when": "unknown" if loaded else "unloaded",
                    "matched": m.group(0)[:120], "context": ln.strip()[:200]})
                if pid == "pip_install":
                    facts["pip"] = True
        m = EXFIL_HOST.search(ln)
        if m:
            s = "HIGH" if loaded else "MEDIUM"
            findings.append({"severity": s, "id": "exfil_host", "name": _NAMES["exfil_host"],
                             "description": _DESCS["exfil_host"], "file": path, "line": i, "when": "unknown",
                             "matched": m.group(0), "context": ln.strip()[:200]})
    return findings, info, facts


# ---------------------------------------------------------------------------------------------
# Repo-level: which files does trust_remote_code actually load?
# ---------------------------------------------------------------------------------------------

def auto_map_refs(files):
    """Collect auto_map / custom_pipelines references from config JSONs.
    Returns (local_modules, remote_refs) - remote_refs are ('org/repo', 'module')."""
    local, remote = set(), set()

    def walk(o):
        if isinstance(o, dict):
            for k, val in o.items():
                if k in ("auto_map",) and isinstance(val, dict):
                    for ref in val.values():
                        for r in (ref if isinstance(ref, list) else [ref]):
                            if isinstance(r, str):
                                _ref(r)
                elif k == "custom_pipelines" and isinstance(val, dict):
                    for p in val.values():
                        if isinstance(p, dict) and isinstance(p.get("impl"), str):
                            local.add(p["impl"].rsplit(".", 0)[0].replace(".py", ""))
                else:
                    walk(val)
        elif isinstance(o, list):
            for x in o:
                walk(x)

    def _ref(r):
        if "--" in r:
            repo, mod = r.split("--", 1)
            remote.add((repo, mod.rsplit(".", 1)[0]))
        else:
            local.add(r.rsplit(".", 1)[0])

    for name, text in files.items():
        if os.path.basename(name) in CONFIG_JSONS:
            try:
                walk(json.loads(text))
            except (ValueError, RecursionError):
                pass
    return local, remote


_REL_IMPORT = re.compile(r"^\s*from\s+(\.+)([\w.]*)\s+import\s+([\w, ()*]+)", re.M)


def loaded_set(files, local_mods):
    """Files trust_remote_code imports: auto_map modules + handler.py + their relative imports."""
    py = {n: t for n, t in files.items() if n.endswith(".py")}
    by_mod = {}
    for n in py:
        by_mod[n[:-3].replace("/", ".")] = n
        by_mod.setdefault(os.path.basename(n)[:-3], n)
    start = set()
    for m in local_mods:
        if m in by_mod:
            start.add(by_mod[m])
    for n in py:
        if os.path.basename(n) in ("handler.py", "pipeline.py") and "/" not in n:
            start.add(n)
    if not start:
        start = {n for n in py if os.path.basename(n).startswith(LOADED_PREFIX)}
    seen, stack = set(), list(start)
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        base = os.path.dirname(n)
        for dots, mod, names in _REL_IMPORT.findall(py[n]):
            d = base
            for _ in range(len(dots) - 1):
                d = os.path.dirname(d)
            cands = []
            if mod:
                cands.append(os.path.join(d, mod.replace(".", "/")) + ".py")
                cands.append(os.path.join(d, mod.replace(".", "/"), "__init__.py"))
            else:
                for nm in re.split(r"[,\s()]+", names):
                    if nm:
                        cands.append(os.path.join(d, nm) + ".py")
            for c in cands:
                c = os.path.normpath(c).lstrip("./") if c.startswith("./") else os.path.normpath(c)
                if c in py and c not in seen:
                    stack.append(c)
    return seen


def scan_repo(files, label="", repo_id=None):
    """files: {relative_path: text}. Returns a result dict."""
    findings, info = [], []
    local, remote = auto_map_refs(files)
    loaded = loaded_set(files, local)
    facts = {"py_files": 0, "loaded_files": len(loaded), "exec_import": False, "net_import": False,
             "pip": False, "net": False, "exec": False, "parse_errors": 0, "cross_repo": [],
             "auto_map": bool(local or remote)}
    owner = (repo_id or label or "").split("/")[0].lower() if "/" in (repo_id or label or "") else None
    for repo, mod in sorted(remote):
        same = owner and repo.split("/")[0].lower() == owner
        pid, sev = ("same_ns_code", "INFO") if same else ("cross_repo_code", "LOW")
        item = {"severity": sev, "id": pid, "name": _NAMES[pid], "description": _DESCS[pid],
                "file": "config.json", "line": 0, "when": "import", "matched": "%s--%s" % (repo, mod),
                "context": "auto_map -> %s/%s.py" % (repo, mod)}
        (info if sev == "INFO" else findings).append(item)
        facts["cross_repo"].append(repo)
    for name in sorted(files):
        if not name.endswith(".py"):
            continue
        facts["py_files"] += 1
        f, i, fx = scan_source(files[name], name, loaded=name in loaded)
        findings += f
        info += i
        if name in loaded:
            for k in ("exec_import", "net_import", "pip", "net", "exec"):
                facts[k] = facts[k] or fx.get(k, False)
        facts["parse_errors"] += 1 if fx.get("parse_error") else 0
    return _summarise(findings, info, label, facts)


def _summarise(findings, info, label, facts=None):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    score = 0
    for f in findings:
        counts[f["severity"]] += 1
        score += SEV_SCORE[f["severity"]]
    level = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[s]), "SAFE")
    findings.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f["file"], f["line"]))
    parts = ["%d %s" % (counts[s], s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[s]]
    return {"target": label, "risk_level": level, "risk_score": min(score, 100), "findings": findings,
            "info": info, "summary": ", ".join(parts) or "No issues found",
            "total_findings": len(findings), "info_count": len(info), "facts": facts or {}}


def scan(content, label="<text>"):
    f, i, fx = scan_source(content, label, loaded=True)
    return _summarise(f, i, label, fx)


# ---------------------------------------------------------------------------------------------
# Fetching (never weights)
# ---------------------------------------------------------------------------------------------
UA = {"User-Agent": "hf-code-audit/%s (+https://github.com/eltociear/hf-code-audit)" % __version__}


def _get(url, timeout=60, tries=4):
    hdr = dict(UA)
    tok = os.environ.get("HF_CODE_AUDIT_TOKEN")
    if tok:
        hdr["Authorization"] = "Bearer " + tok
    last = None
    for i in range(tries):
        try:
            return urllib.request.urlopen(urllib.request.Request(url, headers=hdr), timeout=timeout).read()
        except urllib.error.HTTPError as e:
            if e.code in (401, 403, 404):
                raise
            last = e
            time.sleep((10 if e.code == 429 else 2) * (i + 1))
        except Exception as e:  # network flake
            last = e
            time.sleep(2 * (i + 1))
    raise last


def fetch_repo(spec):
    """spec: org/model[@rev]. Returns ({path: text}, repo_id, sha)."""
    repo, _, rev = spec.partition("@")
    meta = json.loads(_get("%s/api/models/%s%s?blobs=true" % (HUB, repo, "/revision/" + urllib.parse.quote(rev, safe="") if rev else "")))
    sha = meta.get("sha") or rev or "main"
    files = {}
    for s in meta.get("siblings", []):
        n = s.get("rfilename", "")
        if not (n.endswith(".py") or os.path.basename(n) in CONFIG_JSONS):
            continue
        if (s.get("size") or 0) > MAX_FILE:
            continue
        try:
            b = _get("%s/%s/resolve/%s/%s" % (HUB, repo, sha, urllib.parse.quote(n)))
        except Exception:
            continue
        files[n] = b.decode("utf-8", "replace")
    return files, repo, sha


def _read_text(p):
    with open(p, "rb") as fh:
        return fh.read(MAX_FILE).decode("utf-8", "replace")


def files_from_dir(root):
    if os.path.isfile(root):
        return {os.path.basename(root): _read_text(root)}
    if not os.path.isdir(root):
        raise ValueError("not a regular file or directory: %s" % root)
    out = {}
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if not d.startswith(".")]
        for fn in fns:
            if fn.endswith(".py") or fn in CONFIG_JSONS:
                p = os.path.join(dp, fn)
                if not regular_file(p) or os.path.getsize(p) > MAX_FILE:  # symlinks / FIFOs / devices never opened
                    continue
                out[os.path.relpath(p, root).replace(os.sep, "/")] = _read_text(p)
    return out


# ---------------------------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------------------------
_ICON = {"CRITICAL": "\U0001F534", "HIGH": "\U0001F7E0", "MEDIUM": "\U0001F7E1",
         "LOW": "\U0001F535", "SAFE": "\U0001F7E2"}


def _print(r, verbose):
    print("%s %s  [%s]  score=%d  (%d findings, %d info)" % (
        _ICON.get(r["risk_level"], "?"), r["target"], r["risk_level"], r["risk_score"],
        r["total_findings"], r["info_count"]))
    for f in r["findings"] + (r["info"] if verbose else []):
        print("    %-8s %s  %s:%d  [%s]" % (f["severity"], f["name"], f["file"], f["line"], f["when"]))
        if f["context"]:
            print("             %s" % f["context"][:160])


# ---------------------------------------------------------------------------
# Pipeline output shared by the eltociear/*-audit family: --json / --sarif / --fail-on
# (this block is kept identical across the family; see "Output formats" in the README)
# ---------------------------------------------------------------------------
FAMILY_SCHEMA = "eltociear-audit/1"
TOOL_NAME = "hf-code-audit"
TOOL_URI = "https://github.com/eltociear/hf-code-audit"
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
    verbose = "--verbose" in args
    follow = "--auto-map" in args
    args = [a for a in args if a not in ("--json", "--verbose", "--auto-map")]
    results = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--text":
            results.append(scan(args[i + 1] if i + 1 < len(args) else "", "<text>"))
            i += 2
            continue
        if a == "--hf":
            spec = args[i + 1]
            i += 2
            try:
                files, repo, sha = fetch_repo(spec)
            except Exception as e:
                print("error: could not fetch %s: %s" % (spec, e), file=sys.stderr)
                results.append({"target": spec, "risk_level": "ERROR", "findings": [], "info": [],
                                "risk_score": 0, "total_findings": 0, "info_count": 0, "error": str(e)})
                continue
            r = scan_repo(files, "%s@%s" % (repo, sha[:12]), repo_id=repo)
            results.append(r)
            if follow:
                for ref in sorted(set(r["facts"].get("cross_repo", []))):
                    try:
                        f2, repo2, sha2 = fetch_repo(ref)
                        results.append(scan_repo(f2, "%s@%s (auto_map of %s)" % (repo2, sha2[:12], repo), repo_id=repo2))
                    except Exception as e:
                        print("error: could not fetch auto_map repo %s: %s" % (ref, e), file=sys.stderr)
            continue
        if not os.path.exists(a):
            print("error: no such file or directory: %s (use --hf org/model for the Hub)" % a, file=sys.stderr)
            return 1
        try:
            results.append(scan_repo(files_from_dir(a), a))
        except (OSError, ValueError) as e:
            results.append({"target": a, "risk_level": "SAFE", "findings": [], "info": [], "risk_score": 0,
                            "total_findings": 0, "info_count": 0, "error": str(e)[:200]})
        i += 1
    if not as_json:
        for r in results:
            _print(r, verbose)
    return family_emit(results, fam)


if __name__ == "__main__":
    sys.exit(main())
