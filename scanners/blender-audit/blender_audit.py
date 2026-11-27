#!/usr/bin/env python3
"""blender-audit - scan Blender add-ons / extensions (and .blend files) for malicious patterns.

An enabled Blender add-on is ordinary Python running with your user's full privileges: its
module body and register() run on every Blender start, its app handlers fire on every file
load / save / frame change, and nothing sandboxes any of it. A .blend file can carry Python
too (Text datablocks registered as modules, driver expressions) that runs as soon as "Auto Run
Python Scripts" is on. This scanner reads that code as text - nothing is imported, enabled or
executed - and reports what would run, and WHEN:

  import   - module level: runs when the add-on is enabled and on every Blender start
  register - register() and anything it calls (and module-level calls): same timing
  handler  - functions hooked into bpy.app.handlers / bpy.app.timers / msgbus: run
             automatically on load, save, depsgraph and frame events
  runtime  - operators (execute / invoke / modal), panels and other functions: run when the
             user clicks something
  unloaded - .py outside the add-on package (tests, docs, build scripts): downgraded

Signals: credential / browser / wallet / environment reads combined with a network send;
decode-then-exec; download-and-execute; reverse shells; writes to persistence locations
(shell rc, LaunchAgents, Blender's own scripts/startup folder); switching on "Auto Run Python
Scripts" from code; app handlers that exec() Text datablocks of every .blend you open;
runtime `pip install` (HIGH from a URL or git at register time); hard-coded collector hosts;
obfuscation; requirement / wheel pins (shadow wheels, typosquats, known-bad releases);
network use an extension does not declare in blender_manifest.toml.

Precision first: what popular add-ons really do every day (auto-updaters that download their
own release zip from GitHub, Run Script operators, ffmpeg / git probes, online asset browsers)
is reported as informational context and never inflates the risk score.

Usage:
  python blender_audit.py <dir|file.py|addon.zip|file.blend> [...]
  python blender_audit.py --extensions <id>          # extensions.blender.org (ranged download)
  python blender_audit.py --github owner/repo[@ref]  # GitHub tarball, text sources only
  python blender_audit.py --installed                # every add-on/extension in Blender's user dirs
  python blender_audit.py --text "python source"
  add --json for machine-readable output, --verbose to print INFO context,
  --strict-blend to score .blend-embedded code at full severity

Exit code 2 if any target is HIGH or CRITICAL (CI-friendly).
No dependencies beyond the standard library. MIT licensed.
"""
import ast
import glob
import gzip
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

__version__ = "0.1.0"

EXT_API = os.environ.get("BLENDER_AUDIT_EXT_API", "https://extensions.blender.org/api/v1/extensions/")
MAX_FILE = 2000000          # per .py / text file
MAX_BLEND = 20000000        # per .blend
MAX_ITEM = 60000000         # per target, all kept bytes
TEXT_EXT = (".py", ".toml", ".txt", ".cfg", ".pyi")
REQ_NAMES = re.compile(r"(?:^|/)(?:requirements[\w.-]*\.txt|pyproject\.toml|setup\.cfg)$", re.I)
WHEN_RANK = {"import": 3, "register": 3, "handler": 2, "runtime": 1, "main": 0, "unloaded": 0}
AUTO_WHEN = ("import", "register")

EXFIL_HOST = re.compile(
    r"(?:discord(?:app)?\.com/api/webhooks/\d|api\.telegram\.org/bot\w|hooks\.slack\.com/services/T|"
    r"webhook\.site/[0-9a-f]{8}|pipedream\.net|requestbin\.(?:com|net|io)\b|requestb\.in\b|"
    r"\bngrok(?:-free)?\.(?:io|app|dev)\b|\binteractsh\.com\b|\boast\.(?:fun|me|live|site|online|pro)\b|"
    r"burpcollaborator\.net|\bpastebin\.com/raw|transfer\.sh/|\bserveo\.net|\.trycloudflare\.com|"
    r"\.workers\.dev/(?:collect|exfil|upload|c2|log)\b)",
    re.IGNORECASE)
RAW_IP_URL = re.compile(
    r"https?://(?!(?:127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|"
    r"192\.0\.2\.|198\.51\.100\.|203\.0\.113\.))\d{1,3}(?:\.\d{1,3}){3}")
CRED_PATH = re.compile(
    r"(?:\.ssh/(?:id_|authorized_keys|known_hosts)|\.aws/credentials|\.netrc\b|\.git-credentials|"
    r"\.docker/config\.json|\.kube/config|\.config/gcloud|application_default_credentials|\.npmrc\b|"
    r"\.pypirc\b|Login Data|Local State|Cookies\b|logins\.json|key4\.db|wallet\.dat|Exodus|Electrum|"
    r"MetaMask|nkbihfbeogaeaoehlefnkodbefgpgknn|Telegram Desktop|tdata\b|discord[/\\\\]Local Storage|"
    r"\.bash_history|keychain|find-generic-password|CryptUnprotectData|win32crypt|browser_cookie3)",
    re.IGNORECASE)
PERSIST_PATH = re.compile(
    r"(?:\.bashrc|\.zshrc|\.bash_profile|\.profile\b|\.ssh/authorized_keys|/etc/cron|crontab|"
    r"LaunchAgents|LaunchDaemons|/etc/systemd|\.config/autostart|sitecustomize\.py|usercustomize\.py|"
    r"/etc/rc\.local|/etc/profile|Start Menu\\\\Programs\\\\Startup|CurrentVersion\\\\Run)",
    re.IGNORECASE)
STARTUP_LIT = re.compile(r"(?:^|[/\\])startup(?:[/\\]|$)|^startup$")
SECRET_ENV = re.compile(
    r"^(?:AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|AWS_SESSION_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|"
    r"GITHUB_TOKEN|GH_TOKEN|HF_TOKEN|HUGGING_FACE_HUB_TOKEN|GOOGLE_APPLICATION_CREDENTIALS|"
    r"AZURE_\w*KEY\w*|\w*SECRET\w*|\w*PASSWORD\w*|\w*API_KEY)$")
CROSS_SECRET = re.compile(
    r"^(?:AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|AWS_SESSION_TOKEN|GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|"
    r"NPM_TOKEN|PYPI_TOKEN|TWINE_PASSWORD|DOCKER_PASSWORD|GOOGLE_APPLICATION_CREDENTIALS|AZURE_CLIENT_SECRET|"
    r"SSH_AUTH_SOCK|DATABASE_URL|HF_TOKEN|HUGGING_FACE_HUB_TOKEN)$")
CLOUD_METADATA = re.compile(r"169\.254\.169\.254|metadata\.google\.internal|fd00:ec2::254|100\.100\.100\.200|"
                            r"/latest/meta-data/iam|/computeMetadata/v1/|instance/service-accounts")
PIP_RE = re.compile(r"\bpip3?\b[^\n]{0,40}\binstall\b|-m\s*pip\b|ensurepip")
PIP_REMOTE = re.compile(r"git\+|https?://|\.whl\b|--index-url|--extra-index-url|-i\s+http")
SHELL_NAMES = re.compile(r"^(?:/bin/|/usr/bin/)?(?:ba|z|da|k)?sh$|^cmd(?:\.exe)?$|^powershell(?:\.exe)?$|^pwsh$")
BENIGN_CMDS = re.compile(
    r"^(?:nvidia-smi|nvcc|git|uname|lscpu|hostname|which|where|whereis|type|command|explorer(?:\.exe)?|open|xdg-open|start|"
    r"ninja|cmake|make|gcc|g\+\+|clang|c\+\+|nproc|ls|python3?|sys\.executable|bpy\.app\.binary_path|"
    r"ffmpeg|ffprobe|magick|convert|oiiotool|maketx|txmake|blender(?:\.exe)?|nautilus|dolphin|thunar|"
    r"osascript|pbcopy|pbpaste|xclip|xsel|wl-copy|wl-paste|clip(?:\.exe)?|powershell(?:\.exe)?|"
    r"gimp|krita|inkscape|photoshop|code|subl|notepad(?:\.exe)?|tasklist|taskkill|ps|kill|"
    r"colmap|meshlab|instant-meshes|COLMAP|realitycapture|steam|unreal|ue4editor)$", re.IGNORECASE)
DL_URL_LITERAL = re.compile(r"""^https?://""")
# literal commands that fetch, tunnel or hide - worth HIGH when run at enable time
SUSPECT_CMD = re.compile(r"\b(?:curl|wget|powershell|pwsh|certutil|bitsadmin|mshta|rundll32|regsvr32|nc|ncat|"
                         r"socat|scp|sftp|ftp|tftp|osascript\s+-e|launchctl|crontab|schtasks|reg\s+add)\b|https?://",
                         re.IGNORECASE)

NET_CALLS = {
    "requests.get", "requests.post", "requests.put", "requests.patch", "requests.request",
    "requests.Session", "requests.head", "requests.delete",
    "urllib.request.urlopen", "urllib.request.urlretrieve", "urllib.request.Request",
    "urllib.urlopen", "urllib2.urlopen", "httpx.get", "httpx.post", "httpx.Client",
    "httpx.AsyncClient", "aiohttp.ClientSession", "http.client.HTTPConnection",
    "http.client.HTTPSConnection", "socket.socket", "socket.create_connection",
    "ftplib.FTP", "smtplib.SMTP", "smtplib.SMTP_SSL", "websocket.create_connection",
    "websockets.connect", "wget.download", "paramiko.SSHClient", "telnetlib.Telnet",
    "dns.resolver.resolve", "socket.gethostbyname",
}
SEND_CALLS = {"requests.post", "requests.put", "requests.patch", "httpx.post", "smtplib.SMTP",
              "smtplib.SMTP_SSL", "ftplib.FTP", "urllib.request.Request", "socket.socket",
              "socket.create_connection", "websocket.create_connection", "websockets.connect",
              "http.client.HTTPConnection", "http.client.HTTPSConnection", "requests.request",
              "dns.resolver.resolve", "socket.gethostbyname", "paramiko.SSHClient"}
EXEC_CALLS = {"os.system", "os.popen", "os.execv", "os.execve", "os.execl", "os.execlp", "os.execvp",
              "os.spawnl", "os.spawnv", "os.spawnlp", "os.spawnvp", "os.posix_spawn",
              "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
              "subprocess.Popen", "subprocess.getoutput", "subprocess.getstatusoutput",
              "commands.getoutput", "pty.spawn", "asyncio.create_subprocess_shell",
              "asyncio.create_subprocess_exec", "pexpect.spawn"}
DECODE_CALLS = {"base64.b64decode", "base64.b32decode", "base64.b85decode", "base64.a85decode",
                "base64.decodebytes", "base64.urlsafe_b64decode", "zlib.decompress", "gzip.decompress",
                "bz2.decompress", "lzma.decompress", "marshal.loads", "codecs.decode", "bytes.fromhex",
                "binascii.unhexlify", "binascii.a2b_base64", "pickle.loads", "dill.loads"}
DYN_EXEC = {"exec", "eval", "compile", "builtins.exec", "builtins.eval", "execfile"}
HANDLER_LISTS = re.compile(r"(?:^|\.)app\.handlers\.\w+\.(?:append|insert)$")
TIMER_REG = re.compile(r"(?:^|\.)app\.timers\.register$|(?:^|\.)msgbus\.subscribe_rna$")
REGISTER_FUNCS = {"register", "unregister"}

PATTERN_DOC = [
    # (id, strongest severity, name, description)
    ("decode_exec", "CRITICAL", "Decode-then-Execute", "exec/eval/compile of base64/zlib/marshal/hex-decoded data"),
    ("reverse_shell", "CRITICAL", "Reverse Shell", "socket wired to a shell (dup2 / pty.spawn / stdin=socket)"),
    ("credential_exfil", "CRITICAL", "Credential Exfiltration", "reads a token / browser / wallet store and sends data off-host"),
    ("env_exfil", "CRITICAL", "Environment Exfiltration", "serialises os.environ and sends it"),
    ("persistence_write", "CRITICAL", "Persistence Write", "writes shell rc / authorized_keys / crontab / LaunchAgents / sitecustomize"),
    ("download_execute", "CRITICAL", "Download & Execute", "fetches a URL and runs it (curl|sh, exec(requests.get().text))"),
    ("startup_persist", "HIGH", "Blender Startup Persistence", "writes into Blender's scripts/startup folder (runs on every launch, outside the add-on)"),
    ("auto_exec_enable", "HIGH", "Auto Run Enabled from Code", "sets use_scripts_auto_execute = True: every .blend's embedded scripts then run"),
    ("blend_autorun", "HIGH", "Handler Runs .blend Text", "an app handler exec()s Text datablocks of loaded files, bypassing Auto Run"),
    ("exfil_host", "HIGH", "Collector Endpoint", "hard-coded webhook / bot / tunnel / OAST host"),
    ("shell_exec", "HIGH", "Shell Execution", "os.system / shell=True with a command built at runtime, or exec at enable time"),
    ("dynamic_exec", "MEDIUM", "Dynamic Code Execution", "exec / eval / compile of an opaque (non-literal, non-template) value at enable time"),
    ("obfuscation", "HIGH", "Obfuscated Code", "__import__('os'...) chains, getattr(builtins,'exec'), split-literal hosts with a send"),
    ("pip_install", "HIGH", "Runtime pip install", "installs packages from code (HIGH from URL/git at enable time; MEDIUM at enable; LOW in an operator)"),
    ("shadow_wheel", "HIGH", "Shadow Wheel", "pure-Python package pinned to a direct URL off PyPI"),
    ("known_bad_version", "HIGH", "Known-Malicious Release", "pins a release publicly known to be malicious"),
    ("import_network", "MEDIUM", "Network at Enable Time", "network call to a non-Blender host at import / register"),
    ("raw_ip", "MEDIUM", "Raw-IP Endpoint", "network call to a public raw IP address"),
    ("custom_index", "MEDIUM", "Custom Package Index", "installs from a non-standard package index"),
    ("typosquat", "MEDIUM", "Possible Typosquat", "dependency / wheel one edit away from a popular package"),
    ("blend_payload", "MEDIUM", "Code in .blend", "a malicious shape inside a .blend's embedded Python (runs once Auto Run is on)"),
    ("undeclared_network", "LOW", "Undeclared Network Permission", "extension uses the network but blender_manifest.toml has no network permission"),
    ("secret_env_read", "LOW", "Secret Env Read", "reads another service's credential env var"),
    ("process_exec", "INFO", "Process Execution", "literal command / tool probe"),
    ("network", "INFO", "Network Use", "HTTP / socket use in operators, updaters, asset browsers"),
    ("blend_script", "INFO", "Embedded .blend Script", "a .blend carries Python text (rig UI, drivers, setup scripts)"),
    ("blend_compressed", "INFO", "Compressed .blend", "zstd-compressed .blend not inspected (zstd CLI missing)"),
    ("run_text", "INFO", "Run Text Datablock", "an operator runs a Text datablock on user request"),
    ("addon_install", "INFO", "Installs Add-on Code", "installs / updates add-on files (auto-updater shape)"),
    ("wheel_bundled", "INFO", "Bundled Wheel", "wheels listed in blender_manifest.toml"),
    ("native_lib", "INFO", "Native Library", "ctypes.CDLL / bundled binaries"),
    ("pickle_load", "INFO", "Pickle Load", "pickle / torch.load of files"),
    ("embedded_blob", "INFO", "Embedded Blob", "long base64/hex string literal not fed to a decoder"),
    ("direct_url_dep", "INFO", "Direct-URL Dependency", "dependency installed from a URL, not PyPI"),
]
SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "SAFE": 0}
SEV_SCORE = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}
_NAMES = {p[0]: p[2] for p in PATTERN_DOC}
_STRONG = {p[0]: p[1] for p in PATTERN_DOC}
_DESCS = {p[0]: p[3] for p in PATTERN_DOC}
MALICE_SHAPES = {"decode_exec", "reverse_shell", "credential_exfil", "env_exfil", "persistence_write",
                 "download_execute", "exfil_host", "obfuscation", "startup_persist", "auto_exec_enable",
                 "blend_autorun"}
DOWN = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "INFO", "INFO": "INFO"}

# Pure-Python packages nobody needs a custom-built wheel of (the "shadow wheel" shape).
PURE_PY = {
    "openai", "anthropic", "requests", "httpx", "huggingface-hub", "transformers", "diffusers",
    "gitpython", "beautifulsoup4", "langchain", "ollama", "boto3", "websocket-client", "packaging",
    "setuptools", "pip", "colorama", "rich", "click", "tqdm", "pydantic", "certifi", "urllib3",
    "idna", "charset-normalizer", "six", "toml", "tomli", "pyyaml", "jinja2", "markupsafe",
}
POPULAR = PURE_PY | {
    "numpy", "scipy", "pillow", "opencv-python", "opencv-contrib-python", "opencv-python-headless",
    "torch", "torchvision", "onnxruntime", "matplotlib", "pandas", "trimesh", "shapely", "pyproj",
    "imageio", "mathutils", "bpy", "fake-bpy-module", "pygltflib", "openexr", "pymeshlab", "open3d",
    "scikit-image", "scikit-learn", "numba", "lxml", "psutil", "cryptography", "pycryptodome",
    "websockets", "aiohttp", "protobuf", "zstandard", "msgpack", "networkx", "sympy", "triangle",
    "pyopengl", "glfw", "mediapipe", "ultralytics", "rembg", "pyserial", "python-osc", "mido",
}
KNOWN_BAD = {"ultralytics": {"8.3.41", "8.3.42", "8.3.45", "8.3.46"}}
NEAR_OK = {"pyglm", "numpy-stl", "triangles", "openexr-python"}
OK_INDEX = re.compile(r"(?:download\.pytorch\.org|files\.pythonhosted\.org|pypi\.org|pypi\.python\.org|"
                      r"pypi\.nvidia\.com)", re.I)


# ---------------------------------------------------------------------------------------------
# AST analysis
# ---------------------------------------------------------------------------------------------

def _str_consts(node, limit=40):
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


def _simple_name(node):
    """Name of a function reference: f, self.f, module.f -> 'f'."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _dotted_plain(n):
    parts = []
    while isinstance(n, ast.Attribute):
        parts.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        parts.append(n.id)
    return ".".join(reversed(parts))


class _CallGraph(ast.NodeVisitor):
    """One pass: function defs, the simple names each one calls, handler / timer / msgbus hooks,
    @persistent functions, and calls made from the module body (outside a __main__ guard)."""

    def __init__(self):
        self.defs, self.calls_in, self.handler, self.module_calls = set(), {}, set(), set()
        self.stack = []
        self.main = 0

    def _fn(self, node):
        self.defs.add(node.name)
        for dec in node.decorator_list:
            if _dotted_plain(dec.func if isinstance(dec, ast.Call) else dec).split(".")[-1] == "persistent":
                self.handler.add(node.name)
        self.stack.append(node.name)
        self.calls_in.setdefault(node.name, set())
        for n in node.body:
            self.visit(n)
        self.stack.pop()

    visit_FunctionDef = _fn
    visit_AsyncFunctionDef = _fn

    def visit_ClassDef(self, node):
        for n in node.body:
            self.visit(n)

    def visit_If(self, node):
        t = node.test
        if not self.stack and isinstance(t, ast.Compare) and isinstance(t.left, ast.Name) and t.left.id == "__name__":
            self.main += 1
            self.generic_visit(node)
            self.main -= 1
            return
        self.generic_visit(node)

    def visit_Call(self, node):
        nm = node.func.id if isinstance(node.func, ast.Name) else None
        if nm:
            if self.stack:
                self.calls_in[self.stack[-1]].add(nm)
            elif not self.main:
                self.module_calls.add(nm)
        d = _dotted_plain(node.func)
        if d and (HANDLER_LISTS.search(d) or TIMER_REG.search(d)):
            for a in list(node.args) + [k.value for k in node.keywords if k.arg in ("notify", "function")]:
                h = _simple_name(a)
                if h:
                    self.handler.add(h)
                if isinstance(a, ast.Call):
                    for aa in a.args[:1]:
                        h = _simple_name(aa)
                        if h:
                            self.handler.add(h)
        self.generic_visit(node)


def _auto_funcs(tree):
    """Which function names run without a user action: register()/unregister(), anything hooked
    into app handlers / timers / msgbus, @persistent functions, and (transitively, by simple
    name, 4 levels) whatever those - or the module body - call."""
    g = _CallGraph()
    g.visit(tree)
    defs = g.defs

    def closure(seed, depth=4):
        out, frontier = set(seed), set(seed)
        for _ in range(depth):
            nxt = set()
            for f in frontier:
                for c in g.calls_in.get(f, ()):
                    if c in defs and c not in out and c not in REGISTER_FUNCS:
                        nxt.add(c)
            out |= nxt
            frontier = nxt
        return out
    reg = closure((REGISTER_FUNCS & defs) | (g.module_calls & defs)) - g.handler
    hnd = closure(g.handler & defs) - reg
    return reg, hnd


class _Visitor(ast.NodeVisitor):
    def __init__(self, src, path, reg_funcs=(), handler_funcs=()):
        self.src = src
        self.path = path
        self.reg_funcs = set(reg_funcs)
        self.handler_funcs = set(handler_funcs)
        self.alias = {}
        self.ctx = []
        self.main_guard = 0
        self.calls = []        # (dotted, node, when, func_name)
        self.envs = []
        self.strings = []
        self.opens = []
        self.assigns = []      # (target_dotted, value_node, when)
        self.has_dup2 = False
        self.import_tricks = []
        self.docstrings = set()
        self.split_literals = 0
        self.benign_cmd_names = set()
        self.net_vars = set()    # names holding a network response (data = urlopen(u).read())
        self.template_vars = set()  # names holding a code template (name = f"bpy.types.{n}")
        self.var_skel = {}          # name -> literal text of what was assigned (command strings)
        self.list_cmds = {}         # name -> literal command list assigned to it

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

    def _fn(self, node):
        self.ctx.append(node.name)
        for d in node.decorator_list:
            self.visit(d)
        for n in node.body:
            self.visit(n)
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
        if any(f in self.handler_funcs for f in self.ctx):
            return "handler"
        if any(f in self.reg_funcs for f in self.ctx):
            return "register"
        return "runtime"

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
        elif isinstance(node, ast.Subscript):
            inner = self.dotted(node.value)
            if not inner:
                return None
            parts.append(inner + "[]")
        else:
            return None
        parts.reverse()
        head = self.alias.get(parts[0], parts[0])
        return ".".join([head] + parts[1:])

    def visit_Call(self, node):
        d = self.dotted(node.func)
        if d:
            self.calls.append((d, node, self.when(), self.ctx[-1] if self.ctx else ""))
            if d in ("os.getenv", "os.environ.get", "os.environ.pop"):
                k = node.args[0].value if node.args and isinstance(node.args[0], ast.Constant) else None
                self.envs.append((k, node, self.when()))
            if d == "os.dup2":
                self.has_dup2 = True
            if d in ("open", "io.open", "builtins.open", "codecs.open", "shutil.copy", "shutil.copyfile",
                     "shutil.copy2", "shutil.move", "shutil.copytree", "os.symlink", "os.rename", "os.replace"):
                mode = ""
                if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                    mode = str(node.args[1].value)
                for kw in node.keywords:
                    if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                        mode = str(kw.value.value)
                self.opens.append((node, self.when(), _str_consts(node), mode, d))
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("write_text", "write_bytes"):
            self.opens.append((node, self.when(), _str_consts(node.func.value) + _str_consts(node), "w", "write"))
        self.generic_visit(node)

    def visit_Assign(self, node):
        val = node.value
        if isinstance(val, ast.Call) and isinstance(val.func, ast.Attribute) and val.func.attr == "format":
            val = val.func.value
        lead = None
        if isinstance(val, ast.Constant) and isinstance(val.value, str):
            lead = val.value.split()[0] if val.value.split() else None
        elif isinstance(val, ast.JoinedStr) and val.values and isinstance(val.values[0], ast.Constant):
            lead = str(val.values[0].value).split()[0] if str(val.values[0].value).split() else None
        if lead and BENIGN_CMDS.match(os.path.basename(lead)):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self.benign_cmd_names.add(t.id)
        for t in node.targets:
            td = self.dotted(t) if isinstance(t, (ast.Attribute, ast.Name)) else None
            if td:
                self.assigns.append((td, node.value, self.when(), node))
        lc = self._literal_cmds(node.value)
        if lc:
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self.list_cmds[t.id] = lc
        sk = " ".join(_str_consts(node.value, limit=20))
        if sk:
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self.var_skel[t.id] = (self.var_skel.get(t.id, "") + " " + sk)[-2000:]
        if _code_template(node.value):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self.template_vars.add(t.id)
        used = {n.id for n in ast.walk(node.value) if isinstance(n, ast.Name)}
        if _has_net(node.value, self) or (used & self.net_vars):
            for t in node.targets:
                for n in ast.walk(t):
                    if isinstance(n, ast.Name):
                        self.net_vars.add(n.id)
        self.generic_visit(node)

    @staticmethod
    def _literal_cmds(it):
        """[["where", "python"], "which python"] -> (first tokens, joined text) or None."""
        if not isinstance(it, (ast.List, ast.Tuple)) or not it.elts:
            return None
        firsts, skel = [], []
        for e in it.elts:
            if isinstance(e, ast.Constant) and isinstance(e.value, str):
                firsts.append(e.value.split()[0] if e.value.split() else "")
                skel.append(e.value)
            elif isinstance(e, (ast.List, ast.Tuple)) and e.elts and all(
                    isinstance(x, ast.Constant) and isinstance(x.value, str) for x in e.elts):
                firsts.append(e.elts[0].value)
                skel.append(" ".join(x.value for x in e.elts))
            else:
                return None
        return firsts, skel

    def visit_For(self, node):
        # for cmd in [["where", "python"], ["which", "python"]]: run(cmd, shell=True)
        it = node.iter
        lc = self._literal_cmds(it)
        if lc is None and isinstance(it, ast.Name):
            lc = self.list_cmds.get(it.id)
        if lc and isinstance(node.target, ast.Name):
            firsts, skel = lc
            if True:
                name = node.target.id
                self.var_skel[name] = (self.var_skel.get(name, "") + " " + " ".join(skel))[-2000:]
                if all(f and BENIGN_CMDS.match(os.path.basename(f)) for f in firsts):
                    self.benign_cmd_names.add(name)
        self.generic_visit(node)

    def visit_Subscript(self, node):
        d = self.dotted(node.value)
        if d == "os.environ":
            sl = node.slice
            if isinstance(sl, ast.Index):
                sl = sl.value
            k = sl.value if isinstance(sl, ast.Constant) else None
            self.envs.append((k, node, self.when()))
        self.generic_visit(node)

    def visit_Expr(self, node):
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            self.docstrings.add(id(node.value))
        self.generic_visit(node)

    def visit_BinOp(self, node):
        strish = (ast.Constant, ast.JoinedStr, ast.BinOp)
        if isinstance(node.op, ast.Add) and not getattr(node, "_folded", False) and (
                (isinstance(node.left, strish) and not (isinstance(node.left, ast.Constant) and not isinstance(node.left.value, str)))
                or (isinstance(node.right, ast.Constant) and isinstance(node.right.value, str))):
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
        if isinstance(node.value, str) and len(node.value) >= 6 and id(node) not in self.docstrings:
            self.strings.append((node.value, node))


def _line(src_lines, n):
    i = getattr(n, "lineno", 0)
    return i, (src_lines[i - 1].strip()[:200] if 0 < i <= len(src_lines) else "")


def _cmd_info(call):
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
        elif isinstance(first, ast.Attribute) and first.attr in ("executable", "binary_path", "python_executable"):
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


def _has_net(node, vis):
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            d = vis.dotted(n.func) or ""
            if d in NET_CALLS or d.split(".")[-1] in ("urlopen", "urlretrieve"):
                return d
            if d.endswith((".get", ".post")) and d.split(".")[0] in ("requests", "httpx"):
                return d
    return None


def _has_env(node, vis):
    for n in ast.walk(node):
        if isinstance(n, ast.Call) and (vis.dotted(n.func) or "") in ("os.getenv", "os.environ.get"):
            return True
        if isinstance(n, ast.Subscript) and (vis.dotted(n.value) or "") == "os.environ":
            return True
    return False


def _code_template(node):
    """f-string / str.format / %-format whose literal skeleton is itself code."""
    skel = ""
    if isinstance(node, ast.JoinedStr):
        skel = "".join(v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str))
    elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format" \
            and isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str):
        skel = node.func.value.value
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) and isinstance(node.left, ast.Constant) \
            and isinstance(node.left.value, str):
        skel = node.left.value
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        skel = "".join(n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str))
    return bool(re.search(r"\b(?:import|from|def|class|for|in|return|bpy|props|append|register_class|=)\b|[=:(.]", skel)) \
        and not re.search(r"https?://|base64|b64decode|urlopen|requests|socket|subprocess|os\.system", skel)


def _reads_blend_text(node, vis):
    for n in ast.walk(node):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "as_string":
            return True
        if isinstance(n, ast.Attribute) and (vis.dotted(n) or "").endswith("data.texts"):
            return True
    return False


SENSITIVE_MODS = {"os", "subprocess", "socket", "builtins", "ctypes", "base64", "zlib", "marshal",
                  "pty", "urllib", "requests", "codecs", "pickle"}


def scan_source(src, path, loaded=True):
    """Scan one Python file. Returns (findings, info, facts)."""
    findings, info = [], []
    facts = {"exec_import": False, "net_auto": False, "pip": False, "net": False, "exec": False,
             "handlers": 0, "online_check": False, "parse_error": False, "updater": False}
    lines = src.splitlines()
    try:
        tree = ast.parse(src, filename=path)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        facts["parse_error"] = True
        return _scan_regex(src, path, loaded, findings, info, facts)
    try:
        reg, hnd = _auto_funcs(tree)
        v = _Visitor(src, path, reg, hnd)
        v.visit(tree)
    except RecursionError:
        facts["parse_error"] = True
        return _scan_regex(src, path, loaded, findings, info, facts)
    facts["handlers"] = len(hnd)
    facts["online_check"] = "online_access" in src
    low_src = src.lower()
    facts["updater"] = "addon_updater" in low_src or "updater" in os.path.basename(path).lower()

    def add(pid, sev, node, when, matched="", extra="", naive=None):
        n, ctx = _line(lines, node) if node is not None else (0, extra)
        sev_eff = sev
        if not loaded:
            # a file the add-on never imports (dev scripts, vendored site-packages, docs): still
            # shown for review, but it does not run when the add-on is enabled
            sev_eff = DOWN[DOWN[sev]]
            when = "unloaded"
        if when == "main" and sev_eff != "CRITICAL":
            sev_eff = DOWN[sev_eff]
        item = {"severity": sev_eff, "id": pid, "name": _NAMES[pid], "description": _DESCS[pid],
                "file": path, "line": n, "when": when, "matched": str(matched)[:120], "context": ctx,
                # what a context-blind scanner would score this signature (baseline measurement)
                "naive": _STRONG.get(naive or pid, naive or "INFO")}
        (info if sev_eff == "INFO" else findings).append(item)

    file_has_send = False
    for d, call, when, fn in v.calls:
        short = d.split(".")[-1]
        auto = when in AUTO_WHEN
        # ---------------- network ----------------
        is_net = d in NET_CALLS or short in ("urlopen", "urlretrieve")
        if is_net:
            facts["net"] = True
            strs = _str_consts(call)
            url_lits = [s for s in strs if DL_URL_LITERAL.match(s)]
            if d in SEND_CALLS or (d.endswith("request") and any(s.upper() in ("POST", "PUT") for s in strs)):
                file_has_send = True
            if any(RAW_IP_URL.search(u) for u in url_lits):
                add("raw_ip", "MEDIUM", call, when, d)
            nonblender = [u for u in url_lits if not re.search(
                r"blender\.org|github\.com|githubusercontent\.com|gitlab\.com|//(?:127\.0\.0\.1|localhost|\[::1\])[:/]", u)]
            if auto and (nonblender or d.startswith("socket.")):
                facts["net_auto"] = True
                add("import_network", "MEDIUM" if when == "import" else "LOW", call, when, d)
            else:
                if auto:
                    facts["net_auto"] = True
                add("network", "INFO", call, when, d, naive="import_network")
            continue
        # ---------------- process execution ----------------
        if d in EXEC_CALLS or (short in ("system", "popen") and d.startswith("os")):
            facts["exec"] = True
            lit, shell, dyn = _cmd_info(call)
            text = " ".join(_str_consts(call))
            if call.args:
                text += " " + " ".join(v.var_skel.get(n.id, "") for n in ast.walk(call.args[0]) if isinstance(n, ast.Name))
            if PIP_RE.search(text) or (lit or "").startswith("sys.executable -m pip"):
                facts["pip"] = True
                remote = bool(PIP_REMOTE.search(text))
                if auto or when == "handler":
                    sev = "HIGH" if remote else "MEDIUM"
                else:
                    sev = "MEDIUM" if remote else "LOW"
                add("pip_install", sev, call, when, text[:120])
                continue
            if re.search(r"\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|"
                         r"\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]{0,200}\|\s*iex\b|"
                         r"\b(?:IEX|Invoke-Expression)\b[^\n]{0,40}(?:DownloadString|iwr|irm|Invoke-WebRequest)", text, re.I):
                add("download_execute", "CRITICAL", call, when, text[:120])
                continue
            if re.search(r"\bpowershell(?:\.exe)?\b[^\n]{0,80}\s-(?:e|en|enc|EncodedCommand)\b", text, re.I) and \
                    any(c[0] in NET_CALLS or c[0].split(".")[-1] in ("urlopen", "urlretrieve") for c in v.calls):
                add("obfuscation", "HIGH", call, when, "powershell -EncodedCommand in a file that uses the network")
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
            benign = bool(first) and bool(BENIGN_CMDS.match(os.path.basename(first.strip("\"'"))))
            if not lit and call.args and isinstance(call.args[0], ast.Name) and call.args[0].id in v.benign_cmd_names:
                benign, dyn, lit = True, False, call.args[0].id
            dynamic = dyn or lit is None
            if when == "import" and not benign and not dynamic and SUSPECT_CMD.search(text):
                facts["exec_import"] = True
                add("shell_exec", "HIGH", call, when, (lit or d)[:120])
            elif dynamic and not benign and (shell or d in ("os.system", "os.popen", "subprocess.getoutput",
                                             "subprocess.getstatusoutput", "asyncio.create_subprocess_shell")):
                add("shell_exec", "HIGH" if auto else "INFO", call, when, d, naive="shell_exec")
            else:
                add("process_exec", "INFO", call, when, (lit or d)[:120], naive="shell_exec")
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
            if _has_net(a, v) or ({n.id for n in ast.walk(a) if isinstance(n, ast.Name)} & v.net_vars):
                add("download_execute", "CRITICAL", call, when, d + "(<network response>)")
                continue
            if _is_literal_str(a):
                continue
            if _reads_blend_text(a, v):
                if when == "handler" or auto:
                    add("blend_autorun", "HIGH", call, when, d + "(<Text datablock>)")
                else:
                    add("run_text", "INFO", call, when, d + "(<Text datablock>)", naive="blend_autorun")
                continue
            if _has_env(a, v):
                add("dynamic_exec", "LOW", call, when, "eval(<environment variable>)")
                continue
            if _code_template(a) or (isinstance(a, ast.Name) and a.id in v.template_vars):
                # exec(f"from . import {name}") / exec(f"{prop}: bpy.props.BoolProperty(...)"):
                # the code skeleton is a literal in the add-on, only names are substituted
                add("process_exec", "INFO", call, when, d + "(<code template>)", naive="HIGH")
                continue
            if auto:
                add("dynamic_exec", "MEDIUM", call, when, d)
            else:
                # operators eval user-typed expressions, property paths, presets: context
                add("process_exec", "INFO", call, when, d + "(<non-literal>)", naive="HIGH")
            continue
        if d == "__import__" and call.args and not isinstance(call.args[0], ast.Constant):
            continue
        if d == "__import__" and call.args and isinstance(call.args[0], ast.Constant):
            v.import_tricks.append(call)
            continue
        if d == "getattr" and len(call.args) > 1 and (v.dotted(call.args[0]) or "") in ("builtins", "__builtins__") \
                and isinstance(call.args[1], ast.Constant) and call.args[1].value in ("exec", "eval", "compile"):
            add("obfuscation", "HIGH", call, when, d)
            continue
        if d in ("ctypes.CDLL", "ctypes.cdll.LoadLibrary", "ctypes.WinDLL"):
            add("native_lib", "INFO", call, when, d)
            continue
        if d in ("pickle.load", "pickle.loads", "dill.load", "joblib.load", "torch.load"):
            add("pickle_load", "INFO", call, when, d)
            continue
        if d in ("pip.main", "pip._internal.main", "pip._internal.cli.main.main"):
            facts["pip"] = True
            add("pip_install", "MEDIUM" if auto else "LOW", call, when, d)
            continue
        if re.search(r"(?:^|\.)ops\.(?:preferences\.addon_install|extensions\.package_install(?:_files)?)$", d):
            add("addon_install", "INFO", call, when, d)
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
        mods = [str(n.args[0].value) for n in ast.walk(risky[0].func) if id(n) in trick_ids]
        add("obfuscation", "HIGH", risky[0], "runtime", "__import__('%s') chain" % (mods[0] if mods else "?"))

    # ---------------- Auto Run switched on from code ----------------
    for td, val, when, node in v.assigns:
        if td.endswith("use_scripts_auto_execute") and isinstance(val, ast.Constant) and val.value is True:
            add("auto_exec_enable", "HIGH", node, when, td + " = True")

    # ---------------- secrets / environment ----------------
    secret_reads = [(k, node, when) for k, node, when in v.envs if k and SECRET_ENV.match(str(k))]
    env_dump = []
    for d, call, when, fn in v.calls:
        if d in ("json.dumps", "str", "repr", "pickle.dumps", "urllib.parse.urlencode", "base64.b64encode") and call.args:
            a0 = call.args[0]
            inner = v.dotted(a0.func) if isinstance(a0, ast.Call) else v.dotted(a0)
            if (inner or "") in ("os.environ", "os.environ.items", "os.environ.copy", "dict") and \
                    (inner != "dict" or (isinstance(a0, ast.Call) and a0.args
                                         and (v.dotted(a0.args[0]) or "") == "os.environ" and not a0.keywords)):
                env_dump.append((call, when))
    cred_files = []
    hosts_early = any(EXFIL_HOST.search(x) for x, _ in v.strings)
    for s, node in v.strings:
        if CLOUD_METADATA.search(s):
            # cloud render managers read their own instance metadata; only with a collector host
            # or split-literal hiding is it the credential-harvest shape
            if hosts_early or v.split_literals >= 3:
                cred_files.append((s, node))
            continue
        if CRED_PATH.search(s) and s.count(" ") <= 3 and len(s) < 300:
            cred_files.append((s, node))
    hosts = [(s, node) for s, node in v.strings if EXFIL_HOST.search(s)]
    for s, node in hosts[:5]:
        add("exfil_host", "HIGH", node, "runtime", EXFIL_HOST.search(s).group(0))
    lits = " ".join(x for x, _ in v.strings).lower()

    def first_party(k):
        k = str(k).upper()
        pre = re.split(r"_(?:API_?KEY|API_?TOKEN|TOKEN|KEY|SECRET\w*|PASSWORD)$", k)[0].lower().replace("_", "")
        return bool(pre) and len(pre) >= 3 and pre in lits.replace("-", "").replace("_", "")
    foreign = [(k, n, w) for k, n, w in secret_reads if CROSS_SECRET.match(str(k)) and not first_party(k)]
    if (cred_files or foreign) and (file_has_send or hosts):
        node = (cred_files[0][1] if cred_files else foreign[0][1])
        add("credential_exfil", "CRITICAL", node, "runtime", cred_files[0][0] if cred_files else str(foreign[0][0]))
    elif foreign:
        for k, node, when in foreign[:3]:
            add("secret_env_read", "LOW", node, when, str(k))
    if env_dump and (file_has_send or hosts):
        add("env_exfil", "CRITICAL", env_dump[0][0], env_dump[0][1], "os.environ -> network")
    if v.split_literals >= 3 and (cred_files or hosts) and file_has_send:
        add("obfuscation", "HIGH", None, "runtime", "%d split string literals hiding hosts/paths" % v.split_literals,
            extra="file-level: literals assembled from fragments")

    # ---------------- persistence writes ----------------
    startup_ref = any(STARTUP_LIT.search(s) for s, _ in v.strings) and \
        not any("bl_app_templates" in s for s, _ in v.strings) and \
        any(d.split(".")[-1] in ("user_resource", "script_path_user", "script_paths", "script_path_pref")
            for d, _, _, _ in v.calls)
    for node, when, strs, mode, d in v.opens:
        writes = d not in ("open", "io.open", "builtins.open", "codecs.open") or any(c in mode for c in "wax+")
        if not writes:
            continue
        hit = next((s for s in strs if PERSIST_PATH.search(s)), None)
        if hit:
            add("persistence_write", "CRITICAL", node, when, hit)
            continue
        if startup_ref and (any(STARTUP_LIT.search(s) for s in strs) or d.startswith("shutil.")
                            or d == "write"):
            add("startup_persist", "HIGH", node, when, "scripts/startup")
            startup_ref = False   # once per file

    # ---------------- blobs ----------------
    for s, node in v.strings:
        if len(s) >= 2048 and re.fullmatch(r"[A-Za-z0-9+/=\s]+|[0-9a-fA-F\s]+", s[:4096]):
            add("embedded_blob", "INFO", node, "runtime", "%d-char encoded literal" % len(s))
            break
    return findings, info, facts


_RX = [
    ("decode_exec", "CRITICAL", re.compile(r"\b(?:exec|eval)\s*\(\s*(?:\w+\.)*(?:b64decode|decompress|loads|fromhex|unhexlify)\s*\(")),
    ("download_execute", "CRITICAL", re.compile(r"\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b")),
    ("download_execute", "CRITICAL", re.compile(r"\b(?:exec|eval)\s*\(\s*(?:requests\.get|urlopen|urllib\.request\.urlopen)\s*\(")),
    ("reverse_shell", "CRITICAL", re.compile(r"os\.dup2\s*\([^\n]{0,80}fileno\s*\(")),
    ("persistence_write", "CRITICAL", re.compile(r"open\s*\([^\n]{0,120}(?:\.bashrc|\.zshrc|authorized_keys|sitecustomize\.py|LaunchAgents)[^\n]{0,40}['\"][wa]")),
    ("obfuscation", "HIGH", re.compile(r"__import__\s*\(\s*['\"](?:os|subprocess|socket|base64|zlib|marshal)['\"]\s*\)\s*\.\s*(?:system|popen|Popen|run|b64decode|decompress|loads|socket)\s*\(")),
    ("auto_exec_enable", "HIGH", re.compile(r"use_scripts_auto_execute\s*=\s*True")),
]


def _scan_regex(src, path, loaded, findings, info, facts):
    """Fallback for files Python 3.9's parser rejects (match statements, newer syntax, fragments)."""
    for i, ln in enumerate(src.splitlines(), 1):
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
        m = EXFIL_HOST.search(ln)
        if m:
            s = "HIGH" if loaded else "MEDIUM"
            findings.append({"severity": s, "id": "exfil_host", "name": _NAMES["exfil_host"],
                             "description": _DESCS["exfil_host"] + " [regex fallback]", "file": path, "line": i,
                             "when": "unknown", "matched": m.group(0), "context": ln.strip()[:200]})
    return findings, info, facts


# ---------------------------------------------------------------------------------------------
# requirements / manifest
# ---------------------------------------------------------------------------------------------

def _norm(n):
    return re.sub(r"[-_.]+", "-", n).lower()


def _dl1(a, b):
    """Damerau-Levenshtein distance exactly 1 (one edit or one adjacent swap)."""
    la, lb = len(a), len(b)
    if abs(la - lb) > 1 or a == b:
        return False
    if la == lb:
        diff = [i for i in range(la) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
    if la > lb:
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    return a[i:] == b[i + 1:]


def _item(sev, pid, path, line, matched="", context="", desc=None):
    return {"severity": sev, "id": pid, "name": _NAMES[pid], "description": desc or _DESCS[pid], "file": path,
            "line": line, "when": "install", "matched": str(matched)[:120], "context": str(context)[:200],
            "naive": sev}


def _check_name(name, path, n, line, findings):
    if name not in POPULAR and name not in NEAR_OK and len(name) >= 5:
        for p in POPULAR:
            if len(p) >= 5 and _dl1(name, p) and not name.startswith(p) and not p.startswith(name):
                findings.append(_item("MEDIUM", "typosquat", path, n, line, line,
                                      "'%s' is one edit away from the popular package '%s'" % (name, p)))
                return


def scan_requirements(text, path, findings, info):
    for n, raw in enumerate(text.split("\n"), 1):
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        low = line.lower()
        if low.startswith(("--extra-index-url", "--index-url", "-i ", "--find-links", "-f ")):
            url = line.split(None, 1)[1] if " " in line else line.split("=", 1)[-1]
            (findings if not OK_INDEX.search(url) else info).append(
                _item("MEDIUM" if not OK_INDEX.search(url) else "INFO", "custom_index", path, n, line, line))
            continue
        if low.startswith(("-r ", "-c ", "-e ", "--")):
            continue
        m = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$", line)
        url = re.search(r"(?:git\+)?https?://\S+", line)
        name = _norm(m.group(1)) if m and not low.startswith(("http", "git+")) else None
        if url and not name:
            wm = re.search(r"/([A-Za-z0-9_.]+?)-\d[^/]*\.whl", url.group(0))
            name = _norm(wm.group(1)) if wm else None
        if url:
            host_ok = OK_INDEX.search(url.group(0))
            archive = re.search(r"\.(?:whl|zip|tar\.gz|tgz)(?:[#?]|$)", url.group(0), re.I)
            if name in PURE_PY and archive and not host_ok:
                findings.append(_item("HIGH", "shadow_wheel", path, n, url.group(0), line,
                                      "Pins a pure-Python package (%s) to a direct URL off PyPI" % name))
            elif not host_ok:
                info.append(_item("INFO", "direct_url_dep", path, n, url.group(0), line))
            continue
        if not name:
            continue
        ver = re.search(r"==\s*([\w.]+)", line)
        if name in KNOWN_BAD and ver and ver.group(1) in KNOWN_BAD[name]:
            findings.append(_item("HIGH", "known_bad_version", path, n, line, line,
                                  "%s==%s is a release publicly known to be malicious" % (name, ver.group(1))))
        _check_name(name, path, n, line, findings)


def parse_manifest(text):
    """Minimal blender_manifest.toml reader (id, version, permissions, wheels, platforms)."""
    out = {"id": None, "version": None, "permissions": {}, "wheels": [], "platforms": []}
    m = re.search(r'(?m)^\s*id\s*=\s*["\']([^"\']+)', text)
    out["id"] = m.group(1) if m else None
    m = re.search(r'(?m)^\s*version\s*=\s*["\']([^"\']+)', text)
    out["version"] = m.group(1) if m else None
    m = re.search(r"(?ms)^\s*wheels\s*=\s*\[(.*?)\]", text)
    if m:
        out["wheels"] = re.findall(r"['\"]([^'\"]+)['\"]", m.group(1))
    m = re.search(r"(?ms)^\s*platforms\s*=\s*\[(.*?)\]", text)
    if m:
        out["platforms"] = re.findall(r"['\"]([^'\"]+)['\"]", m.group(1))
    sec = re.search(r"(?ms)^\s*\[permissions\]\s*$(.*?)(?=^\s*\[|\Z)", text)
    if sec:
        for k, val in re.findall(r"(?m)^\s*(\w+)\s*=\s*(.+)$", sec.group(1)):
            out["permissions"][k] = val.strip().strip("\"'")
    inline = re.search(r"(?m)^\s*permissions\s*=\s*(\{.*?\}|\[.*?\])", text)
    if inline:
        for k in re.findall(r"(\w+)\s*=|['\"](\w+)['\"]", inline.group(1)):
            key = k[0] or k[1]
            if key:
                out["permissions"].setdefault(key, "")
    return out


# ---------------------------------------------------------------------------------------------
# .blend files: extract embedded Python without executing anything
# ---------------------------------------------------------------------------------------------
_CSTR = re.compile(rb"[\t\x20-\x7e]{1,4096}\x00")
_PYLIKE = re.compile(r"(?m)^\s*(?:import \w|from [\w.]+ import |def \w+\(|class \w+[(:])")


def _blend_bytes(data):
    """Return (raw .blend bytes or None, note)."""
    if data[:2] == b"\x1f\x8b":
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as g:
                return g.read(200000000), "gzip"
        except Exception as e:
            return None, "gzip error: %s" % e
    if data[:4] == b"\x28\xb5\x2f\xfd":
        exe = shutil.which("zstd")
        if not exe:
            return None, "zstd"
        try:
            p = subprocess.run([exe, "-dc", "--no-progress"], input=data, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, timeout=60)
            return p.stdout[:200000000], "zstd"
        except Exception as e:
            return None, "zstd error: %s" % e
    return data, "raw"


def _trim_to_parse(lines):
    """Neighbouring non-script strings (ID names, paths) can sit at either end of a group of
    Text lines; drop up to 3 from each end until the text parses."""
    for a in range(4):
        for b in range(4):
            t = "\n".join(lines[a:len(lines) - b if b else None])
            try:
                ast.parse(t)
                return t
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                continue
    return "\n".join(lines)


def _walk_blocks(raw):
    """Yield (code, data_offset, length) for each file block, or return None if the layout is
    not understood. Handles the classic header (BLENDER-v402: pointer size, endianness, version)
    and the large-block header of newer files (BLENDER17-01v0500)."""
    import struct
    if raw[7:9].isdigit():
        try:
            pos = int(raw[7:9])
        except ValueError:
            return None
        fmt, size = "<4siQqq", 32
        order = ("code", "sdna", "old", "len", "nr")
    else:
        ptr = 8 if raw[7:8] == b"-" else 4
        end = "<" if raw[8:9] == b"v" else ">"
        fmt = end + "4si" + ("Q" if ptr == 8 else "I") + "ii"
        size = struct.calcsize(fmt)
        pos = 12
        order = ("code", "len", "old", "sdna", "nr")
    out, n = [], len(raw)
    while pos + size <= n:
        vals = dict(zip(order, struct.unpack_from(fmt, raw, pos)))
        ln = vals["len"]
        if ln < 0 or pos + size + ln > n:
            return None
        out.append((vals["code"], pos + size, ln))
        if vals["code"] == b"ENDB":
            break
        pos += size + ln
        if len(out) > 5000000:
            return None
    return out


_PRINT = re.compile(rb"^[\t\x20-\x7e]+$")


def _groups_from_blocks(raw, blocks):
    """Text datablock lines are written as [TextLine struct][line chars] pairs right after the
    Text ID block, so consecutive small printable DATA blocks (with at most two small binary
    blocks between them) form one script."""
    groups, cur, gap, last_tx = [], [], 0, None
    for code, off, ln in blocks:
        if code[:2] == b"TX":
            if cur:
                groups.append((last_tx, cur))
            cur, gap = [], 0
            m = re.search(rb"TX([\w .-]{1,63})\x00", raw[off:off + min(ln, 512)])
            last_tx = m.group(1).decode("ascii", "replace") if m else None
            continue
        s = None
        if code == b"DATA" and 1 <= ln <= 65536:
            body = raw[off:off + ln]
            stripped = body.rstrip(b"\x00")
            if not stripped and ln <= 8:
                s = ""
            elif stripped and b"\x00" not in stripped and _PRINT.match(stripped):
                s = stripped.decode("ascii", "replace")
        if s is not None:
            cur.append(s)
            gap = 0
            continue
        if code == b"DATA" and ln <= 256 and cur and gap < 2:
            gap += 1
            continue
        if cur:
            groups.append((last_tx, cur))
        cur, gap = [], 0
        if code[:2] not in (b"DA",):
            last_tx = last_tx if code[:2] == b"TX" else None
    if cur:
        groups.append((last_tx, cur))
    return groups


def blend_scripts(data):
    """Embedded Python in a .blend (Text datablocks; driver / expression one-liners), read as
    bytes - the file is never opened by Blender. Returns (list of (name, source), note)."""
    raw, note = _blend_bytes(data)
    if raw is None:
        return [], note
    if not raw.startswith(b"BLENDER"):
        return [], "not a .blend"
    blocks = _walk_blocks(raw)
    if blocks is not None:
        groups = _groups_from_blocks(raw, blocks)
    else:
        note += ", block walk failed: string fallback"
        groups, cur, last_end = [], [], -1
        for m in _CSTR.finditer(raw):
            st = m.group(0)[:-1]
            if last_end >= 0 and m.start() - last_end > 160:
                if cur:
                    groups.append((None, cur))
                cur = []
            if len(st) > 5 or st.strip():
                cur.append(st.decode("ascii", "replace"))
            last_end = m.end()
        if cur:
            groups.append((None, cur))
    res = []
    for name, g in groups:
        text = "\n".join(g)
        if len(text) >= 60 and len(_PYLIKE.findall(text)) >= 2:
            res.append((name or "text_%d.py" % (len(res) + 1), _trim_to_parse(g)))
    exprs = [m.group(0)[:-1].decode("ascii", "replace") for m in _CSTR.finditer(raw)
             if re.search(rb"__import__|\bexec\s*\(|os\.system|subprocess\.|urlopen|b64decode", m.group(0))]
    in_scripts = "\n".join(t for _, t in res)
    exprs = [e for e in exprs if e.strip() and e.strip() not in in_scripts]
    if exprs:
        res.append(("<expressions>", "\n".join(exprs[:200])))
    return res, note


def scan_blend(data, path, strict=False):
    findings, info = [], []
    scripts, note = blend_scripts(data)
    if note.startswith("zstd") and not scripts:
        info.append(_item("INFO", "blend_compressed", path, 0, note, "install the zstd CLI to inspect"))
        return findings, info
    for name, src in scripts:
        label = "%s::%s" % (path, name)
        info.append(_item("INFO", "blend_script", path, 0, name, "%d lines of embedded Python" % src.count("\n")))
        f, i, _ = scan_source(src, label, loaded=True)
        for x in f + i:
            x["when"] = "blend"
            if strict or x["severity"] == "INFO":
                (findings if x["severity"] != "INFO" else info).append(x)
                continue
            if x["id"] in MALICE_SHAPES and SEV_ORDER[x["severity"]] >= SEV_ORDER["HIGH"]:
                x["description"] = x["description"] + " [embedded in .blend: runs if Auto Run Python Scripts is on]"
                x["severity"] = "MEDIUM"
                x["name"] = _NAMES["blend_payload"] + ": " + x["name"]
                x["id"] = "blend_payload"
                findings.append(x)
            else:
                x["severity"] = "INFO"
                info.append(x)
    return findings, info


# ---------------------------------------------------------------------------------------------
# Package-level: which files does Blender actually load?
# ---------------------------------------------------------------------------------------------
NON_RUNTIME = re.compile(r"(?:^|/)(?:tests?|testing|docs?|examples?|\.github|ci|build_tools|benchmarks?)/|"
                         r"(?:^|/)(?:setup\.py|conftest\.py|noxfile\.py|fabfile\.py|build(?:_\w+)?\.py|"
                         r"make_\w+\.py|test_\w+\.py|\w+_test\.py)$")


def addon_roots(files):
    roots = set()
    for p, t in files.items():
        b = os.path.basename(p)
        d = os.path.dirname(p)
        if b == "blender_manifest.toml":
            roots.add(d)
        elif b == "__init__.py" and re.search(r"(?m)^\s*bl_info\s*=", t or ""):
            roots.add(d)
        elif p.endswith(".py") and b != "__init__.py" and re.search(r"(?m)^bl_info\s*=", t or ""):
            roots.add(p)          # single-file add-on
    return roots


_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_DYN_IMPORT = re.compile(r"importlib\.import_module\s*\(\s*(?![\"'])|__import__\s*\(\s*(?![\"'])|pkgutil\.|"
                         r"iter_modules|auto_load|walk_packages|importlib\.util\.spec_from_file_location|"
                         r"\bimp\.load_source|exec\s*\(\s*f?[\"']from \.|exec\s*\(\s*f?[\"']import ")


def _importable(rel):
    parts = rel.split("/")
    return all(_IDENT.match(p) for p in parts[:-1]) and _IDENT.match(parts[-1][:-3] or "_")


def _imports_of(path, text, pkg_files, root):
    """Files in pkg_files that `path` imports (relative imports, and absolute imports through the
    package's own name). Returns (set_of_paths, dynamic_flag)."""
    out, dyn = set(), bool(_DYN_IMPORT.search(text))
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return out, True
    base = os.path.dirname(path)
    pkg = os.path.basename(root) if root else ""

    def resolve(d, mod):
        p = os.path.normpath(os.path.join(d, mod.replace(".", "/"))) if mod else d
        for c in (p + ".py", os.path.join(p, "__init__.py")):
            c = c.lstrip("./") if c.startswith("./") else c
            if c in pkg_files:
                out.add(c)
                return True
        return False
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom):
            if n.level:
                d = base
                for _ in range(n.level - 1):
                    d = os.path.dirname(d)
            elif pkg and (n.module or "").split(".")[0] == pkg:
                d = os.path.dirname(root) if root else ""
            else:
                continue
            mod = n.module or ""
            resolve(d, mod)
            for a in n.names:
                resolve(d, (mod + "." if mod else "") + a.name)
        elif isinstance(n, ast.Import) and pkg:
            for a in n.names:
                if a.name.split(".")[0] == pkg:
                    resolve(os.path.dirname(root) if root else "", a.name)
    return out, dyn


def loaded_set(files, roots):
    """The .py files Blender actually runs: everything reachable by imports from each add-on's
    __init__.py (or the single-file add-on). If the package loads modules dynamically
    (auto_load / pkgutil / importlib with a computed name), every importable module counts."""
    py = [p for p in files if p.endswith(".py")]
    if not roots:
        return {p for p in py if not NON_RUNTIME.search(p) and _importable(p)}
    out = set()
    for r in roots:
        if r.endswith(".py"):
            out.add(r)
            continue
        pkg_files = {p for p in py if (r == "" or p.startswith(r + "/"))}
        rel = lambda p: p[len(r) + 1:] if r else p
        pkg_files = {p for p in pkg_files if _importable(rel(p)) and not NON_RUNTIME.search(rel(p))}
        start = os.path.join(r, "__init__.py") if r else "__init__.py"
        if start not in pkg_files:
            out |= pkg_files
            continue
        seen, stack, dynamic = set(), [start], False
        while stack:
            f = stack.pop()
            if f in seen:
                continue
            seen.add(f)
            # a package's __init__ runs whenever any of its submodules is imported
            d = os.path.dirname(f)
            while d and d != r and (r == "" or d.startswith(r)):
                init = os.path.join(d, "__init__.py")
                if init in pkg_files and init not in seen:
                    stack.append(init)
                d = os.path.dirname(d)
            got, dyn = _imports_of(f, files[f], pkg_files, r)
            dynamic = dynamic or dyn
            stack.extend(got - seen)
        out |= pkg_files if dynamic else seen
    return out


def scan_package(files, label="", blends=None, strict_blend=False, manifest_meta=None):
    """files: {relative_path: text}; blends: {relative_path: bytes}. Returns a result dict."""
    findings, info = [], []
    roots = addon_roots(files)
    loaded = loaded_set(files, roots)
    facts = {"py_files": 0, "loaded_files": len(loaded), "roots": len(roots), "exec_import": False,
             "net_auto": False, "pip": False, "net": False, "exec": False, "handlers": 0,
             "online_check": False, "parse_errors": 0, "manifest": False, "declares_network": None,
             "wheels": 0, "blends": 0, "blend_scripts": 0, "updater": False}
    manifests = {p: t for p, t in files.items() if os.path.basename(p) == "blender_manifest.toml"}
    perms = {}
    for p, t in manifests.items():
        facts["manifest"] = True
        m = parse_manifest(t)
        perms.update(m["permissions"])
        for w in m["wheels"]:
            facts["wheels"] += 1
            info.append(_item("INFO", "wheel_bundled", p, 0, w, w))
            wm = re.match(r"(?:.*/)?([A-Za-z0-9_.]+?)-\d", w)
            if wm:
                _check_name(_norm(wm.group(1)), p, 0, w, findings)
    if manifest_meta and isinstance(manifest_meta.get("permissions"), dict):
        perms.update(manifest_meta["permissions"])
    if facts["manifest"]:
        facts["declares_network"] = "network" in perms
    for name in sorted(files):
        if REQ_NAMES.search(name):
            if name.endswith(".txt"):
                scan_requirements(files[name], name, findings, info)
            else:
                m = re.search(r"(?ms)^\s*dependencies\s*=\s*\[(.*?)\]", files[name])
                if m:
                    scan_requirements("\n".join(re.findall(r"['\"]([^'\"]+)['\"]", m.group(1))), name, findings, info)
        if not name.endswith(".py"):
            continue
        facts["py_files"] += 1
        f, i, fx = scan_source(files[name], name, loaded=name in loaded)
        findings += f
        info += i
        if name in loaded:
            for k in ("exec_import", "net_auto", "pip", "net", "exec", "online_check", "updater"):
                facts[k] = facts[k] or fx.get(k, False)
            facts["handlers"] += fx.get("handlers", 0)
        facts["parse_errors"] += 1 if fx.get("parse_error") else 0
    if facts["manifest"] and facts["net"] and not facts["declares_network"]:
        findings.append(_item("LOW", "undeclared_network", "blender_manifest.toml", 0, "network", "permissions"))
    for name, data in sorted((blends or {}).items()):
        facts["blends"] += 1
        f, i = scan_blend(data, name, strict=strict_blend)
        facts["blend_scripts"] += sum(1 for x in i if x["id"] == "blend_script")
        findings += f
        info += i
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
# Input readers (nothing is extracted to disk, imported or executed)
# ---------------------------------------------------------------------------------------------
UA = {"User-Agent": "blender-audit/%s (+https://github.com/eltociear/blender-audit)" % __version__}


def _want(name, size):
    low = name.lower()
    if "/__pycache__/" in "/" + low or "/.git/" in "/" + low:
        return None
    if low.endswith(".blend"):
        return "blend" if size <= MAX_BLEND else None
    if low.endswith(TEXT_EXT) and size <= MAX_FILE:
        if low.endswith(".txt") and not REQ_NAMES.search(low):
            return None
        return "text"
    return None


def _collect(entries):
    """entries: iterable of (name, size, read_fn). Returns (files, blends)."""
    files, blends, total = {}, {}, 0
    for name, size, read in entries:
        kind = _want(name, size)
        if not kind or total + size > MAX_ITEM:
            continue
        try:
            data = read()
        except Exception:
            continue
        total += len(data)
        if kind == "blend":
            blends[name] = data
        else:
            files[name] = data.decode("utf-8", "replace")
    return files, blends


def read_zip(fileobj):
    with zipfile.ZipFile(fileobj) as z:
        infos = [i for i in z.infolist() if not i.is_dir()]
        return _collect((i.filename, i.file_size, (lambda i=i: z.read(i))) for i in infos)


def read_path(path):
    if os.path.isfile(path):
        low = path.lower()
        if low.endswith(".zip"):
            with open(path, "rb") as f:
                return read_zip(f)
        if low.endswith((".tar.gz", ".tgz", ".tar")):
            return read_tar(open(path, "rb"))
        if low.endswith(".blend"):
            return {}, {os.path.basename(path): open(path, "rb").read(MAX_BLEND + 1)[:MAX_BLEND]}
        return {os.path.basename(path): open(path, encoding="utf-8", errors="replace").read()}, {}
    entries = []
    for dp, dns, fns in os.walk(path):
        dns[:] = [d for d in dns if not d.startswith(".") and d != "__pycache__"]
        for fn in fns:
            p = os.path.join(dp, fn)
            try:
                size = os.path.getsize(p)
            except OSError:
                continue
            entries.append((os.path.relpath(p, path).replace(os.sep, "/"), size,
                            (lambda p=p: open(p, "rb").read())))
    return _collect(entries)


def read_tar(fileobj):
    files, blends, total = {}, {}, 0
    with tarfile.open(fileobj=fileobj, mode="r|*") as t:
        for m in t:
            if not m.isfile():
                continue
            name = m.name.split("/", 1)[1] if "/" in m.name else m.name
            kind = _want(name, m.size)
            if not kind or total + m.size > MAX_ITEM:
                continue
            f = t.extractfile(m)
            if f is None:
                continue
            data = f.read()
            total += len(data)
            if kind == "blend":
                blends[name] = data
            else:
                files[name] = data.decode("utf-8", "replace")
    return files, blends


def _get(url, timeout=60, tries=4, headers=None):
    hdr = dict(UA)
    hdr.update(headers or {})
    last = None
    for i in range(tries):
        try:
            return urllib.request.urlopen(urllib.request.Request(url, headers=hdr), timeout=timeout).read()
        except urllib.error.HTTPError as e:
            if e.code in (401, 403, 404, 416):
                raise
            last = e
            time.sleep((10 if e.code == 429 else 2) * (i + 1))
        except Exception as e:
            last = e
            time.sleep(2 * (i + 1))
    raise last


class RangeFile(io.RawIOBase):
    """Seekable read-only view of a remote file via HTTP Range requests, so zipfile can read the
    central directory and only the members we want from a 100 MB extension archive."""
    BLOCK = 262144

    def __init__(self, url, size):
        self.url, self.size, self.pos, self.cache = url, size, 0, {}

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.pos

    def seek(self, off, whence=0):
        self.pos = off if whence == 0 else (self.pos + off if whence == 1 else self.size + off)
        return self.pos

    def _block(self, b):
        if b not in self.cache:
            lo = b * self.BLOCK
            hi = min(self.size, lo + self.BLOCK) - 1
            self.cache[b] = _get(self.url, headers={"Range": "bytes=%d-%d" % (lo, hi)})
            if len(self.cache) > 64:
                self.cache.pop(next(iter(self.cache)))
        return self.cache[b]

    def read(self, n=-1):
        if n is None or n < 0:
            n = self.size - self.pos
        out = bytearray()
        while n > 0 and self.pos < self.size:
            b, o = divmod(self.pos, self.BLOCK)
            chunk = self._block(b)[o:o + n]
            if not chunk:
                break
            out += chunk
            self.pos += len(chunk)
            n -= len(chunk)
        return bytes(out)

    def readinto(self, buf):
        data = self.read(len(buf))
        buf[:len(data)] = data
        return len(data)


_EXT_INDEX = None


def extensions_index():
    global _EXT_INDEX
    if _EXT_INDEX is None:
        _EXT_INDEX = json.loads(_get(EXT_API, timeout=120))
    return _EXT_INDEX


def pick_entry(entries):
    """One archive per extension id: platform-independent first, else the smallest build."""
    entries = sorted(entries, key=lambda e: (bool(e.get("platforms")), e.get("archive_size") or 0))
    return entries[0]


def fetch_extension(ext_id, entry=None):
    if entry is None:
        idx = extensions_index()
        cands = [e for e in idx.get("data", []) if e.get("id") == ext_id]
        if not cands:
            raise ValueError("no extension %r on %s" % (ext_id, EXT_API))
        entry = pick_entry(cands)
    url, size = entry["archive_url"], int(entry.get("archive_size") or 0)
    if size and size > 4000000:
        files, blends = read_zip(RangeFile(url, size))
    else:
        files, blends = read_zip(io.BytesIO(_get(url, timeout=120)))
    return files, blends, entry


def fetch_github(spec):
    repo, _, ref = spec.partition("@")
    url = "https://codeload.github.com/%s/tar.gz/%s" % (repo, urllib.parse.quote(ref or "HEAD", safe=""))
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=120) as r:
        return read_tar(r)


def installed_dirs():
    home = os.path.expanduser("~")
    bases = [os.path.join(home, "Library", "Application Support", "Blender"),
             os.path.join(home, ".config", "blender"),
             os.path.join(os.environ.get("APPDATA", os.path.join(home, "AppData", "Roaming")), "Blender Foundation", "Blender")]
    out = []
    for b in bases:
        for ver in sorted(glob.glob(os.path.join(b, "*"))):
            for sub in ("scripts/addons", "scripts/startup"):
                d = os.path.join(ver, sub)
                if os.path.isdir(d):
                    for e in sorted(os.listdir(d)):
                        if e.startswith((".", "__pycache__")) or e == "modules":
                            continue
                        out.append(os.path.join(d, e))
            for d in glob.glob(os.path.join(ver, "extensions", "*", "*")):
                if os.path.isdir(d) and not os.path.basename(d).startswith("."):
                    out.append(d)
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


def _err(target, e):
    print("error: %s: %s" % (target, e), file=sys.stderr)
    return {"target": target, "risk_level": "ERROR", "findings": [], "info": [], "risk_score": 0,
            "total_findings": 0, "info_count": 0, "error": str(e)}


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    as_json = "--json" in args
    verbose = "--verbose" in args
    strict = "--strict-blend" in args
    args = [a for a in args if a not in ("--json", "--verbose", "--strict-blend")]
    results = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--text":
            results.append(scan(args[i + 1] if i + 1 < len(args) else "", "<text>"))
            i += 2
            continue
        if a == "--extensions":
            ext = args[i + 1]
            i += 2
            try:
                files, blends, entry = fetch_extension(ext)
                results.append(scan_package(files, "%s@%s" % (ext, entry.get("version")), blends, strict, entry))
            except Exception as e:
                results.append(_err(ext, e))
            continue
        if a == "--github":
            spec = args[i + 1]
            i += 2
            try:
                files, blends = fetch_github(spec)
                results.append(scan_package(files, spec, blends, strict))
            except Exception as e:
                results.append(_err(spec, e))
            continue
        if a == "--installed":
            i += 1
            dirs = installed_dirs()
            if not dirs:
                print("no Blender user add-on / extension folders found", file=sys.stderr)
            for d in dirs:
                files, blends = read_path(d)
                results.append(scan_package(files, d, blends, strict))
            continue
        if not os.path.exists(a):
            print("error: no such file or directory: %s" % a, file=sys.stderr)
            return 1
        files, blends = read_path(a)
        results.append(scan_package(files, a, blends, strict))
        i += 1
    if as_json:
        print(json.dumps(results if len(results) != 1 else results[0], indent=1))
    else:
        for r in results:
            _print(r, verbose)
    worst = max((SEV_ORDER.get(r["risk_level"], 0) for r in results), default=0)
    if worst >= SEV_ORDER["HIGH"]:
        return 2
    return 1 if any(r["risk_level"] == "ERROR" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
