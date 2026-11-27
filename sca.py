#!/usr/bin/env python3
"""sca - supply-chain-audit: one CLI over the eltociear/*-audit scanner family.

Every scanner is a single-file, zero-dependency Python script vendored under scanners/.
sca never imports them: each one runs in its own `python -I` subprocess, and sca turns
its --json output into one normalised report (JSON or SARIF 2.1.0).

Usage:
  sca scan <dir|file> [...]            auto-detect every ecosystem present and run the matching scanners
      --deps                           also resolve lockfiles / manifests against the registries (network)
      --only npm,pypi  --skip repo-trust
      --dry-run                        print what would run, scan nothing
  sca <ecosystem> <target> [scanner args]    run one scanner (args pass through unchanged)
      --raw                            exec the scanner with its native output and exit code
  sca list                             the ecosystems, their scanners and pinned commits
  sca help <ecosystem>                 the scanner's own usage text

Output options (any command):
  --json            the normalised report (schema/sca-report.schema.json)
  --sarif           SARIF 2.1.0, one run per scanner
  -o FILE           write the report to FILE instead of stdout
  --fail-on LEVEL   exit 2 if anything reaches LEVEL: low|medium|high|critical|none (default high)
  --timeout SEC     per-scanner timeout (default 600)
  -j N              concurrent scanner processes for `scan` (default 2)
  -v, --verbose     list every finding (text mode) and show the commands run

Exit codes: 2 something reached --fail-on (wins over errors), 1 usage error / no scanner
could run / any scanner returned an error, 0 otherwise. Scanner errors are fail-closed, even
when other scanners completed successfully and even with --fail-on none.

Zero dependencies, Python 3.9+. MIT licensed. https://github.com/eltociear/supply-chain-audit
"""
import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

__version__ = "0.1.0"
HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER_DIR = os.path.join(HERE, "scanners")
SCHEMA_URL = "https://github.com/eltociear/supply-chain-audit/blob/main/schema/sca-report.schema.json"

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
RANK = {"SAFE": 0, "NONE": 0, "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4, "ERROR": -1}

# ── Adapter table ─────────────────────────────────────────────────────────────
# One row per scanner: where it lives, how to call it, and the quirks of its CLI / JSON.
# Common contract (true for every row unless a quirk says otherwise): `--json` anywhere on
# the command line; output is one object for one target or a list for several; each object
# has target, risk_level (SAFE|LOW|MEDIUM|HIGH|CRITICAL), risk_score, findings[] and info[];
# each finding has severity, id, name, description, file, line, matched, context; scan
# errors come back as risk_level SAFE plus an "error" key; exit code 2 on HIGH+.
ADAPTERS = {
    "aur": dict(repo="aur-audit", script="aur_audit.py", title="Arch User Repository (PKGBUILD)",
                runs="PKGBUILD top level, prepare/build/package (as you), .install scriptlets + alpm hooks (as root)",
                quirks=["bare words that are not paths are fetched from the AUR",
                        "`--all` means 'also list SAFE' (not 'all packages')"]),
    "blender": dict(repo="blender-audit", script="blender_audit.py", title="Blender add-ons / extensions",
                    runs="register() and module top level when the add-on is enabled; .blend-embedded scripts",
                    quirks=["unreadable targets come back with risk_level ERROR (not SAFE+error)",
                            "a missing path makes the whole run exit 1 with no JSON"]),
    "browserext": dict(repo="browserext-audit", script="browserext_audit.py", title="Browser extensions (Chrome / Firefox)",
                       runs="background service worker / content scripts on every matching page",
                       quirks=["`--chrome` / `--firefox` take store ids; `--text` joins all remaining args"]),
    "comfyui": dict(repo="comfyui-audit", script="comfyui_audit.py", title="ComfyUI custom nodes",
                    runs="__init__.py at ComfyUI start, install.py / requirements via ComfyUI-Manager",
                    quirks=["a non-existent path is treated as a GitHub owner/repo and fetched"]),
    "crate": dict(repo="crate-audit", script="crate_audit.py", title="Rust crates (crates.io)",
                  runs="build.rs and proc-macros at `cargo build`", aliases=["cargo", "rust"],
                  quirks=["a non-existent path is treated as a crates.io name and fetched"],
                  deps=[("Cargo.lock", ["--lockfile"])]),
    "gha": dict(repo="gha-audit", script="gha_audit.py", title="GitHub Actions (actions + workflows)",
                runs="action pre/main/post steps with the job's secrets and GITHUB_TOKEN",
                aliases=["actions", "github-actions"],
                quirks=["a workflow file fetches every referenced action unless --no-fetch; sca adds "
                        "--no-fetch in `scan` unless --deps",
                        "one target can expand into several results (one per action)"]),
    "gomod": dict(repo="gomod-audit", script="gomod_audit.py", title="Go modules",
                  runs="init() of every imported package; go:generate / cgo directives", aliases=["go"],
                  quirks=["a non-existent path is treated as a module path and fetched from the proxy"],
                  deps=[("go.mod", ["--gomod"])]),
    "hacs": dict(repo="hacs-audit", script="hacs_audit.py", title="Home Assistant (HACS integrations + cards)",
                 runs="integration import + async_setup inside Home Assistant; frontend cards in every dashboard",
                 aliases=["homeassistant"],
                 quirks=["a non-existent path is treated as a GitHub owner/repo and fetched"]),
    "hf": dict(repo="hf-code-audit", script="hf_code_audit.py", title="Hugging Face trust_remote_code models",
               runs="auto_map modeling/config/tokenizer code under trust_remote_code=True",
               aliases=["huggingface", "hf-code"],
               quirks=["local targets must exist (no fallback); fetch errors come back as risk_level ERROR"]),
    "homebrew": dict(repo="homebrew-audit", script="homebrew_audit.py", title="Homebrew formulae / casks / taps",
                     runs="install / post_install / caveats / preflight / postflight blocks", aliases=["brew"],
                     quirks=["findings have no `file` (one formula per result) - sca uses the target",
                             "owner/tap or a bare name is fetched; `--all` means 'also list SAFE'"]),
    "mcp": dict(repo="mcp-audit", script="mcp_audit.py", title="MCP servers (tool descriptions + entry code)",
                runs="tool descriptions read by the agent; server entry code run by the MCP client",
                quirks=["older builds have no directory mode: for a directory sca then picks the entry files "
                        "itself (manifests, package.json main/bin, *server*/*tool*/index/main sources, max 10) - "
                        "the same selection mcp-audit uses for --github; builds that scan <dir> get the dir",
                        "no --help: `sca help mcp` prints the module docstring",
                        "--json output is a bare list in older builds (exit 0 or 2, never 1)"]),
    "npm": dict(repo="npm-audit", script="npm_audit.py", title="npm packages (incl. n8n / Node-RED nodes)",
                runs="preinstall / install / postinstall / prepare scripts; n8n + Node-RED node load",
                aliases=["node", "n8n", "node-red"],
                quirks=["a non-existent path is treated as a registry package name and fetched"],
                deps=[("package-lock.json", ["--lockfile"]), ("npm-shrinkwrap.json", ["--lockfile"])]),
    "nuget": dict(repo="nuget-audit", script="nuget_audit.py", title="NuGet packages (.nupkg / MSBuild)",
                  runs="build/*.props|targets imported into every build; tools/install.ps1 / init.ps1",
                  aliases=["dotnet"],
                  quirks=["a .csproj / packages.lock.json target resolves PackageReferences on nuget.org "
                          "(network) - sca only does that with --deps"],
                  deps=[("*.csproj", ["--project"]), ("*.fsproj", ["--project"]), ("*.vbproj", ["--project"]),
                        ("packages.lock.json", ["--packages-lock"])]),
    "obsidian": dict(repo="obsidian-audit", script="obsidian_audit.py", title="Obsidian community plugins",
                     runs="main.js onload() inside the desktop app with full Node access",
                     quirks=["a missing path makes the whole run exit 1 with no JSON"]),
    "packagist": dict(repo="packagist-audit", script="packagist_audit.py", title="Composer / Packagist (PHP)",
                      runs="composer plugins + scripts, autoload `files`, service providers / bundles",
                      aliases=["composer", "php"],
                      quirks=["a project dir with vendor/ scans every installed package (several results)"],
                      deps=[("composer.lock", ["--lockfile"])]),
    "pypi": dict(repo="pypi-audit", script="pypi_audit.py", title="PyPI packages",
                 runs="setup.py / build backends at install, .pth files at every interpreter start",
                 aliases=["pip", "python"],
                 quirks=["error strings are prefixed with the exception type"],
                 deps=[("requirements*.txt", ["--requirements"])]),
    "repo-trust": dict(repo="repo-trust-audit", script="repo_trust_audit.py", title="Repository trust surfaces",
                       runs="what opening / trusting a checkout runs: .vscode tasks, devcontainer, .envrc, "
                            "agent instructions + MCP/agent configs, git hooks/filters",
                       aliases=["repo", "trust"],
                       quirks=["a missing path makes the whole run exit 1 with no JSON",
                               "no total_findings when there are none"]),
    "rubygems": dict(repo="rubygems-audit", script="rubygems_audit.py", title="RubyGems",
                     runs="extconf.rb / Rakefile native-extension builds at `gem install`; rubygems_plugin.rb on every gem command",
                     aliases=["gem", "ruby"],
                     quirks=["a non-existent path is treated as a gem name and fetched"],
                     deps=[("Gemfile.lock", ["--lockfile"])]),
    "terraform": dict(repo="terraform-audit", script="terraform_audit.py", title="Terraform modules / providers",
                      runs="local-exec / external data sources / http data sources at plan and apply",
                      aliases=["tf", "opentofu"],
                      quirks=["examples/ and tests/ are skipped unless --all"]),
    "userscript": dict(repo="userscript-audit", script="userscript_audit.py", title="Userscripts (Tampermonkey / Greasemonkey)",
                       runs="the script on every matching page, with GM_* privileges and @require code",
                       aliases=["greasyfork", "tampermonkey"],
                       quirks=["--json output is always a list; no total_findings / info_count",
                               "fetch errors are printed to stderr and the target is dropped (no error entry)"]),
    "vimplugin": dict(repo="vimplugin-audit", script="vimplugin_audit.py", title="Vim / Neovim plugins",
                      runs="plugin/ + ftdetect/ at startup, build hooks of lazy.nvim / packer / vim-plug",
                      aliases=["vim", "nvim", "neovim"],
                      quirks=["a non-existent path is treated as a GitHub owner/repo and fetched"]),
    "vsix": dict(repo="vsix-audit", script="vsix_audit.py", title="VS Code / Open VSX extensions",
                 runs="activate() on activationEvents (often `*` / onStartupFinished) with full Node access",
                 aliases=["vscode", "openvsx", "cursor"],
                 quirks=["for an unpacked dir it scans <dir>/extension when that exists"]),
    "winpkg": dict(repo="winpkg-audit", script="winpkg_audit.py", title="Windows package managers (Scoop / winget / Chocolatey)",
                   runs="Scoop pre/post_install + installer scripts, winget installer switches, chocolateyInstall.ps1 (as admin)",
                   aliases=["scoop", "winget", "choco", "chocolatey"],
                   quirks=["finding `line` is a string 'file.ps1:L12' for Chocolatey packages - sca splits it",
                           "a directory expands into one result per manifest / package",
                           "`--all` means 'also list SAFE'"]),
    "wordpress": dict(repo="wordpress-audit", script="wordpress_audit.py", title="WordPress plugins",
                      runs="the main plugin file and everything it includes on every page load",
                      aliases=["wp"],
                      quirks=["no total_findings / info_count keys; extra naive_flags / vendor_hosts keys",
                              "a non-existent path is treated as a wordpress.org slug and fetched"]),
}
ALIASES = {}
for _eco, _a in ADAPTERS.items():
    ALIASES[_eco] = _eco
    ALIASES[_a["repo"]] = _eco
    ALIASES[_a["repo"][:-len("-audit")]] = _eco
    for _x in _a.get("aliases", []):
        ALIASES[_x] = _eco


def versions():
    try:
        with open(os.path.join(SCANNER_DIR, "VERSIONS.json"), encoding="utf-8") as fh:
            return json.load(fh).get("scanners", {})
    except (OSError, ValueError):
        return {}


def script_path(eco):
    a = ADAPTERS[eco]
    return os.path.join(SCANNER_DIR, a["repo"], a["script"])


# ── Running a scanner ─────────────────────────────────────────────────────────
SCANNER_PYTHON_ARGS = ["-I", "-X", "utf8"]


def _cmd(eco, args):
    # Force UTF-8 even for --raw, where the child inherits the caller's streams.
    # This avoids UnicodeEncodeError on Windows code-page consoles when scanners
    # print emoji or other non-ASCII output.  -I otherwise ignores env settings.
    return [sys.executable] + SCANNER_PYTHON_ARGS + [script_path(eco)] + list(args)


def _display_command(cmd):
    script_index = 1 + len(SCANNER_PYTHON_ARGS)
    return [os.path.basename(cmd[script_index])] + cmd[script_index + 1:]


def run_scanner(eco, args, timeout=600, cwd=None, label=None):
    """Run one scanner with --json and return a list of normalised results."""
    args = list(args)
    if "--json" not in args:
        args.append("--json")
    cmd = _cmd(eco, args)
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, cwd=cwd, env=env)
        out, err, rc = p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace"), p.returncode
    except subprocess.TimeoutExpired:
        return [_error_result(eco, label or " ".join(args), "timeout after %ss" % timeout, cmd)]
    except OSError as e:
        return [_error_result(eco, label or " ".join(args), "could not start scanner: %s" % e, cmd)]
    secs = round(time.time() - t0, 2)
    raw = _parse_json(out)
    if raw is None:
        msg = (err.strip() or out.strip() or "no output")[-400:]
        return [_error_result(eco, label or " ".join(a for a in args if a != "--json"),
                              "scanner exited %s without JSON: %s" % (rc, msg), cmd)]
    if isinstance(raw, dict) and str(raw.get("schema", "")).startswith("eltociear-audit/") \
            and isinstance(raw.get("results"), list):
        items = raw["results"]  # the family envelope (schema eltociear-audit/1), being rolled out per repo
    else:
        items = raw if isinstance(raw, list) else [raw]
    res = [normalise(eco, it) for it in items if isinstance(it, dict)]
    if not res:  # e.g. userscript drops targets it could not fetch
        res = [_error_result(eco, label or " ".join(a for a in args if a != "--json"),
                             "scanner returned no results" + (": " + err.strip()[-300:] if err.strip() else ""), cmd)]
    for r in res:
        r["command"] = _display_command(cmd)
        r["seconds"] = secs
        r["scanner_exit_code"] = rc
        if err.strip() and not r.get("error"):
            r.setdefault("stderr", err.strip()[-400:])
    return res


def _parse_json(out):
    out = out.strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except ValueError:
        pass
    # some modes print a text line before the JSON document: take the last top-level JSON value
    for opener in ("\n[", "\n{"):
        i = out.find(opener)
        if i >= 0:
            try:
                return json.loads(out[i + 1:])
            except ValueError:
                pass
    return None


def _tool(eco):
    a = ADAPTERS[eco]
    v = versions().get(a["repo"], {})
    return a["repo"], v.get("commit")


def _error_result(eco, target, msg, cmd=None):
    tool, commit = _tool(eco)
    r = {"tool": tool, "tool_commit": commit, "ecosystem": eco, "target": target, "verdict": "ERROR",
         "max_severity": "SAFE", "risk_score": 0, "findings": [], "info_count": 0, "error": msg}
    if cmd:
        r["command"] = _display_command(cmd)
    return r


_LINE_IN_STR = re.compile(r"^(?P<file>.*?):L(?P<line>\d+)$")


def normalise_finding(eco, f, target):
    sev = str(f.get("severity", "")).upper()
    if sev not in SEVERITIES:
        sev = "MEDIUM" if sev else "INFO"
    file_, line = f.get("file"), f.get("line")
    if isinstance(line, str):  # winpkg-audit: "chocolateyInstall.ps1:L12"
        m = _LINE_IN_STR.match(line)
        if m:
            file_ = file_ or m.group("file")
            line = int(m.group("line"))
        else:
            line = int(line) if line.isdigit() else None
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        line = None
    name, desc = f.get("name") or f.get("id") or "", f.get("description") or ""
    msg = "%s: %s" % (name, desc) if name and desc else (name or desc)
    known = {"severity", "id", "rule_id", "name", "description", "file", "line", "matched", "context"}
    out = {"severity": sev, "rule": f.get("id") or f.get("rule_id") or re.sub(r"\W+", "_", name.lower()) or "unknown",
           "name": name, "file": file_ if file_ else None, "line": line, "message": msg,
           "context": _clip(f.get("context")), "matched": _clip(f.get("matched"))}
    extra = {k: v for k, v in f.items() if k not in known and isinstance(v, (str, int, float, bool))}
    if extra:
        out["extra"] = extra
    return out


def _clip(s, n=300):
    if s is None:
        return None
    s = str(s).replace("\r", "")
    return s if len(s) <= n else s[:n] + "..."


def normalise(eco, r):
    tool, commit = _tool(eco)
    target = str(r.get("target") or r.get("package") or r.get("plugin") or "?")
    verdict = str(r.get("risk_level", "")).upper() or "SAFE"
    err = r.get("error")
    if err:
        verdict = "ERROR"
    elif verdict not in RANK:
        verdict = "ERROR"
        err = "unknown risk_level %r" % r.get("risk_level")
    findings = [normalise_finding(eco, f, target) for f in (r.get("findings") or []) if isinstance(f, dict)]
    top = max([RANK[f["severity"]] for f in findings] + [max(RANK.get(verdict, 0), 0)])
    info = r.get("info") or []
    return {"tool": tool, "tool_commit": commit, "ecosystem": eco, "target": target, "verdict": verdict,
            "max_severity": _level_name(top), "risk_score": r.get("risk_score", 0), "findings": findings,
            "info_count": r.get("info_count", len(info) if isinstance(info, list) else 0),
            "summary": r.get("summary"), "error": str(err)[:400] if err else None}


def _level_name(rank):
    return {0: "SAFE", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}[rank]


# ── Auto-detection ────────────────────────────────────────────────────────────
PRUNE = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache",
         ".pytest_cache", ".terraform", "bower_components", "vendor", ".gradle", ".idea_modules", "target"}
MAX_DEPTH = 8
MAX_SNIFF = 4096
TRUST_MARKERS = (".claude", ".vscode", ".cursor", ".devcontainer", ".devcontainer.json", ".envrc", ".gitmodules",
                 ".gitattributes", ".lfsconfig", ".mcp.json", "AGENTS.md", "CLAUDE.md", "GEMINI.md", "AGENT.md",
                 ".cursorrules", ".windsurfrules", ".clinerules", ".roo", ".kiro", ".gemini", ".windsurf",
                 ".codex", ".idea", ".run", ".continue", ".amazonq", "Makefile", "justfile", "package.json")
VIM_DIRS = ("plugin", "autoload", "ftplugin", "rplugin", "denops", "ftdetect", "after")
MCP_DEP = re.compile(r"@modelcontextprotocol/sdk|\"fastmcp\"|\"mcp\"|(?:^|[\s\"'])(?:fastmcp|mcp)(?:\[[^\]]*\])?\s*(?:[<>=~!]|[\"',]|$)",
                     re.M)


def _sniff(path, n=MAX_SNIFF):
    try:
        with open(path, "rb") as fh:
            return fh.read(n).decode("utf-8", "replace")
    except OSError:
        return ""


def _json(path, limit=512 * 1024):
    try:
        if os.path.getsize(path) > limit:
            return None
        with open(path, encoding="utf-8-sig", errors="replace") as fh:
            j = json.load(fh)
        return j if isinstance(j, dict) else None
    except (OSError, ValueError):
        return None


def _has_ext(d, names, exts):
    return any(n.lower().endswith(exts) for n in names)


def _subdir_has(d, sub, exts):
    p = os.path.join(d, sub)
    if not os.path.isdir(p):
        return False
    for _r, _ds, fs in os.walk(p):
        if any(f.lower().endswith(exts) for f in fs):
            return True
    return False


def detect(root, deps=False, skipped=None):
    """Return [{ecosystem, target, args, reason, network}] for everything under root (a dir or a file).

    Dependency manifests (lockfiles, go.mod requires, *.csproj ...) are only resolved against the
    registries with deps=True; otherwise they are appended to `skipped` (when given) so the
    report can say what --deps would add."""
    root = os.path.normpath(root)
    found = []

    def add(eco, target, reason, args=None, network=False):
        if network and not deps:
            if skipped is not None:
                skipped.append({"ecosystem": eco, "target": target, "reason": reason + " - needs --deps"})
            return
        found.append({"ecosystem": eco, "target": target, "args": list(args) if args else [target],
                      "reason": reason, "network": network})

    if os.path.isfile(root):
        _detect_file(root, add, deps, single=True)
        return _dedupe(found)
    if not os.path.isdir(root):
        return []
    if any(os.path.exists(os.path.join(root, m)) for m in TRUST_MARKERS) or \
            os.path.isfile(os.path.join(root, ".github", "copilot-instructions.md")):
        add("repo-trust", root, "trust surfaces at the checkout root")
    hacs_roots = []
    for d, dirs, files in os.walk(root):
        rel = os.path.relpath(d, root)
        depth = 0 if rel == "." else rel.count(os.sep) + 1
        dirs[:] = sorted(x for x in dirs if x not in PRUNE and not (x.startswith(".") and x not in (".github",)))
        if depth >= MAX_DEPTH:
            dirs[:] = []
        F = set(files)
        low = {f.lower(): f for f in files}
        pkg = _json(os.path.join(d, "package.json")) if "package.json" in F else None
        manifest = _json(os.path.join(d, "manifest.json")) if "manifest.json" in F else None
        # npm / vsix
        if pkg is not None:
            engines = pkg.get("engines") if isinstance(pkg.get("engines"), dict) else {}
            if "vscode" in engines:
                add("vsix", d, "package.json with engines.vscode")
            else:
                add("npm", d, "package.json")
            alld = {}
            for k in ("dependencies", "devDependencies", "peerDependencies"):
                if isinstance(pkg.get(k), dict):
                    alld.update(pkg[k])
            if "@modelcontextprotocol/sdk" in alld or "fastmcp" in alld:
                _add_mcp(d, add, "package.json depends on the MCP SDK")
        for name in ("package-lock.json", "npm-shrinkwrap.json"):
            if name in F:
                add("npm", os.path.join(d, name), name + " (registry)", ["--lockfile", os.path.join(d, name)], True)
        # python
        py_markers = [m for m in ("setup.py", "pyproject.toml", "setup.cfg") if m in F]
        if py_markers:
            add("pypi", d, ", ".join(py_markers))
            txt = "".join(_sniff(os.path.join(d, m), 65536) for m in py_markers if m != "setup.py")
            if MCP_DEP.search(txt):
                _add_mcp(d, add, "Python project depends on mcp / fastmcp")
            if "[tool.comfy]" in txt:
                add("comfyui", d, "pyproject.toml [tool.comfy]")
        for f in files:
            if f.lower().endswith((".whl", ".pth")) or re.search(r"\.tar\.gz$", f) and "PKG-INFO" in F:
                add("pypi", os.path.join(d, f), f.rsplit(".", 1)[-1] + " file")
            elif re.match(r"requirements.*\.txt$", f, re.I):
                if MCP_DEP.search(_sniff(os.path.join(d, f), 65536)):
                    _add_mcp(d, add, f + " lists mcp / fastmcp")
                add("pypi", os.path.join(d, f), f + " (registry)", ["--requirements", os.path.join(d, f)], True)
        if "server.json" in F or "smithery.yaml" in F or "smithery.yml" in F:
            _add_mcp(d, add, "MCP server manifest (server.json / smithery.yaml)")
        # ruby
        if any(f.endswith(".gemspec") for f in files):
            add("rubygems", d, ".gemspec")
        for f in files:
            if f.endswith(".gem"):
                add("rubygems", os.path.join(d, f), ".gem file")
        if "Gemfile.lock" in F:
            add("rubygems", os.path.join(d, "Gemfile.lock"), "Gemfile.lock (registry)",
                ["--lockfile", os.path.join(d, "Gemfile.lock")], True)
        # go / php / rust
        if "go.mod" in F:
            add("gomod", d, "go.mod")
            add("gomod", os.path.join(d, "go.mod"), "go.mod requires (proxy)", ["--gomod", os.path.join(d, "go.mod")], True)
        if "composer.json" in F:
            add("packagist", d, "composer.json")
        if "composer.lock" in F:
            add("packagist", os.path.join(d, "composer.lock"), "composer.lock (dist)",
                ["--lockfile", os.path.join(d, "composer.lock")], True)
        if "Cargo.toml" in F:
            add("crate", d, "Cargo.toml")
        for f in files:
            if f.endswith(".crate"):
                add("crate", os.path.join(d, f), ".crate file")
        if "Cargo.lock" in F:
            add("crate", os.path.join(d, "Cargo.lock"), "Cargo.lock (crates.io)",
                ["--lockfile", os.path.join(d, "Cargo.lock")], True)
        # terraform
        if any(f.endswith((".tf", ".tf.json")) for f in files):
            add("terraform", d, "*.tf")
        # GitHub Actions
        if "action.yml" in F or "action.yaml" in F:
            add("gha", d, "action.yml")
        if d.replace(os.sep, "/").endswith(".github/workflows"):
            for f in sorted(files):
                if f.endswith((".yml", ".yaml")):
                    p = os.path.join(d, f)
                    add("gha", p, "workflow (uses: pinning%s)" % ("" if deps else ", offline"),
                        ["--workflow", p] + ([] if deps else ["--no-fetch"]), deps)
        # browser extension / obsidian / HACS
        if manifest is not None:
            if "minAppVersion" in manifest and "id" in manifest:
                add("obsidian", d, "Obsidian manifest.json (minAppVersion)")
            elif "manifest_version" in manifest:
                add("browserext", d, "WebExtension manifest.json (manifest_version)")
            elif "domain" in manifest and any(k in manifest for k in ("iot_class", "codeowners", "config_flow",
                                                                       "integration_type", "requirements")):
                if not any(d.startswith(h + os.sep) or d == h for h in hacs_roots):
                    add("hacs", d, "Home Assistant integration manifest.json (domain)")
        if "hacs.json" in F:
            hacs_roots.append(d)
            found[:] = [x for x in found if not (x["ecosystem"] == "hacs" and x["target"].startswith(d + os.sep))]
            add("hacs", d, "hacs.json")
        for f in files:
            if f.lower().endswith((".crx", ".xpi")):
                add("browserext", os.path.join(d, f), f.rsplit(".", 1)[-1] + " file")
            elif f.lower().endswith(".vsix"):
                add("vsix", os.path.join(d, f), ".vsix file")
        # Blender / ComfyUI (python packages with host-specific entry points)
        if "blender_manifest.toml" in F:
            add("blender", d, "blender_manifest.toml")
        if "__init__.py" in F:
            head = _sniff(os.path.join(d, "__init__.py"), 65536)
            if re.search(r"^\s*bl_info\s*=", head, re.M) and "blender_manifest.toml" not in F:
                add("blender", d, "__init__.py defines bl_info")
            if re.search(r"NODE_CLASS_MAPPINGS", head):
                add("comfyui", d, "__init__.py exports NODE_CLASS_MAPPINGS")
        # userscripts
        for f in files:
            if f.endswith(".user.js"):
                add("userscript", os.path.join(d, f), ".user.js")
            elif f.endswith(".js") and "==UserScript==" in _sniff(os.path.join(d, f), 1024):
                add("userscript", os.path.join(d, f), "// ==UserScript== header")
        # AUR / Homebrew / Windows package managers
        if "PKGBUILD" in F:
            add("aur", d, "PKGBUILD")
        base = os.path.basename(d)
        rbs = [f for f in files if f.endswith(".rb")]
        if base in ("Formula", "Casks", "HomebrewFormula") and rbs:
            add("homebrew", d, "%s/ directory" % base)
        else:
            for f in rbs:
                head = _sniff(os.path.join(d, f))
                if re.search(r"^\s*class\s+\w+\s*<\s*Formula\b|^\s*cask\s+[\"']", head, re.M):
                    add("homebrew", os.path.join(d, f), "Homebrew formula / cask")
        if base == "tools" and any(re.match(r"chocolatey(install|uninstall|beforemodify)\.ps1$", f, re.I) for f in files):
            add("winpkg", os.path.dirname(d), "tools/chocolateyInstall.ps1")
        for f in files:
            lf = f.lower()
            p = os.path.join(d, f)
            if lf.endswith(".json") and lf not in ("package.json", "package-lock.json", "manifest.json", "composer.json",
                                                   "composer.lock", "tsconfig.json", "hacs.json", "server.json",
                                                   "config.json", "renovate.json") and not lf.startswith("."):
                j = _json(p, 256 * 1024)
                if j and "version" in j and ("url" in j or "architecture" in j) and \
                        any(k in j for k in ("hash", "checkver", "autoupdate", "bin", "installer", "shortcuts", "extract_dir")):
                    add("winpkg", p, "Scoop manifest")
            elif lf.endswith((".yaml", ".yml")) and not d.replace(os.sep, "/").endswith(".github/workflows"):
                head = _sniff(p, 16384)
                if re.search(r"^PackageIdentifier:", head, re.M) and re.search(r"^ManifestVersion:", head, re.M):
                    add("winpkg", p, "winget manifest")
        # NuGet
        nuspecs = [f for f in files if f.lower().endswith(".nuspec")]
        is_choco = os.path.isdir(os.path.join(d, "tools")) and any(
            re.match(r"chocolatey(install|uninstall|beforemodify)\.ps1$", f, re.I)
            for f in os.listdir(os.path.join(d, "tools")))
        if nuspecs and not is_choco:
            add("nuget", d, ".nuspec")
        for f in files:
            lf = f.lower()
            if lf.endswith(".nupkg"):
                add("nuget", os.path.join(d, f), ".nupkg file")
            elif (lf.endswith((".csproj", ".fsproj", ".vbproj")) or lf == "packages.lock.json"):
                flag = "--packages-lock" if lf == "packages.lock.json" else "--project"
                add("nuget", os.path.join(d, f), f + " (nuget.org)", [flag, os.path.join(d, f)], True)
        if not nuspecs and base in ("build", "buildTransitive") and _has_ext(d, files, (".props", ".targets")):
            parent = os.path.dirname(d)
            if not any(x["ecosystem"] == "nuget" and x["target"] == parent for x in found):
                add("nuget", parent, "build/*.props|targets (MSBuild package layout)")
        # WordPress
        for f in files:
            if f.lower().endswith(".php"):
                head = _sniff(os.path.join(d, f), 8192)
                if re.search(r"^[\s/*#@]*Plugin Name\s*:", head, re.M | re.I):
                    add("wordpress", d, "%s has a Plugin Name: header" % f)
                    break
        # Vim / Neovim
        vim_sub = [s for s in VIM_DIRS if s in dirs or os.path.isdir(os.path.join(d, s))]
        if any(_subdir_has(d, s, (".vim", ".lua", ".py", ".ts", ".js")) for s in vim_sub if s in
               ("plugin", "autoload", "ftplugin", "rplugin", "denops")) or \
                (os.path.isdir(os.path.join(d, "lua")) and _subdir_has(d, "lua", (".lua",)) and
                 (vim_sub or os.path.isdir(os.path.join(d, "doc")))):
            if "PKGBUILD" not in F:
                add("vimplugin", d, "Vim plugin layout (%s)" % ", ".join(vim_sub or ["lua", "doc"]))
        # Hugging Face trust_remote_code
        if "config.json" in F:
            j = _json(os.path.join(d, "config.json"), 4 * 1024 * 1024)
            if j and isinstance(j.get("auto_map"), dict):
                add("hf", d, "config.json with auto_map")
        for f in ("tokenizer_config.json", "preprocessor_config.json", "processor_config.json"):
            if f in F and "config.json" not in F:
                j = _json(os.path.join(d, f), 4 * 1024 * 1024)
                if j and isinstance(j.get("auto_map"), (dict, list)):
                    add("hf", d, "%s with auto_map" % f)
    return _dedupe(found)


def _detect_file(p, add, deps, single=False):
    b = os.path.basename(p)
    lb = b.lower()
    d = os.path.dirname(p) or "."
    table = [
        (lambda: lb.endswith(".vsix"), "vsix", ".vsix file"),
        (lambda: lb.endswith((".crx", ".xpi")), "browserext", "extension package"),
        (lambda: lb.endswith(".nupkg"), "nuget", ".nupkg file"),
        (lambda: lb.endswith(".nuspec"), "nuget", ".nuspec"),
        (lambda: lb.endswith((".props", ".targets")), "nuget", "MSBuild file"),
        (lambda: lb.endswith((".whl", ".pth")) or b in ("setup.py", "pyproject.toml"), "pypi", "Python package file"),
        (lambda: lb.endswith(".gem") or lb.endswith(".gemspec"), "rubygems", "gem file"),
        (lambda: lb.endswith(".crate") or b in ("build.rs", "Cargo.toml"), "crate", "crate file"),
        (lambda: b == "go.mod" or lb.endswith(".go"), "gomod", "Go file"),
        (lambda: b == "composer.json", "packagist", "composer.json"),
        (lambda: lb.endswith((".tf", ".tf.json")), "terraform", "Terraform file"),
        (lambda: b in ("action.yml", "action.yaml"), "gha", "action.yml"),
        (lambda: b == "PKGBUILD" or lb.endswith(".install"), "aur", "PKGBUILD / .install"),
        (lambda: lb.endswith(".user.js"), "userscript", ".user.js"),
        (lambda: b == "package.json", "npm", "package.json"),
        (lambda: lb.endswith(".blend"), "blender", ".blend file"),
    ]
    for cond, eco, why in table:
        if cond():
            add(eco, p, why)
            return
    if d.replace(os.sep, "/").endswith(".github/workflows") and lb.endswith((".yml", ".yaml")):
        add("gha", p, "workflow", ["--workflow", p] + ([] if deps else ["--no-fetch"]), deps)
        return
    head = _sniff(p, 16384)
    if lb.endswith(".rb") and re.search(r"<\s*Formula\b|^\s*cask\s+[\"']", head, re.M):
        add("homebrew", p, "Homebrew formula / cask")
    elif lb.endswith(".php") and re.search(r"Plugin Name\s*:", head, re.I):
        add("wordpress", p, "Plugin Name: header")
    elif lb.endswith(".js") and "==UserScript==" in head[:1024]:
        add("userscript", p, "// ==UserScript== header")
    elif lb.endswith((".yaml", ".yml")) and re.search(r"^PackageIdentifier:", head, re.M):
        add("winpkg", p, "winget manifest")
    elif lb.endswith(".ps1") and re.match(r"chocolatey", lb):
        add("winpkg", p, "Chocolatey script")
    elif lb.endswith(".json"):
        j = _json(p)
        if j and "minAppVersion" in j:
            add("obsidian", d, "Obsidian manifest.json")
        elif j and "manifest_version" in j:
            add("browserext", d, "WebExtension manifest.json")
        elif j and isinstance(j.get("auto_map"), dict):
            add("hf", d, "config.json with auto_map")
        elif j and "version" in j and ("url" in j or "architecture" in j):
            add("winpkg", p, "Scoop manifest")
    elif lb.endswith((".vim", ".lua")):
        add("vimplugin", p, "Vim / Lua file")


SKIP_SRC = re.compile(
    r"(?:^|/)(?:node_modules|dist|build|out|vendor|\.venv|venv|test|tests|__tests__|spec|examples?|"
    r"docs?|fixtures?|benchmarks?|\.github|coverage|target)/|\.(?:min|d|test|spec)\.\w+$|_test\.\w+$|"
    r"(?:^|/)test_\w+\.py$", re.I)
SRC_EXT = re.compile(r"\.(?:ts|mts|js|mjs|cjs|py|go|rs)$")
ENTRY_NAME = re.compile(r"(?:^|/)(?:index|server|main|app|cli|__main__|mcp|tools?|handlers?)\.\w+$|tool", re.I)
MCP_MANIFESTS = ("server.json", "manifest.json", "smithery.yaml", "package.json", "pyproject.toml", "README.md")


def mcp_entry_files(d, cap=10, cap_bytes=300000):
    """mcp-audit has no directory mode; mirror its --github entry-file selection on a local tree."""
    paths = {}
    for r, ds, fs in os.walk(d):
        ds[:] = [x for x in ds if x not in PRUNE and not x.startswith(".")]
        for f in fs:
            full = os.path.join(r, f)
            rel = os.path.relpath(full, d).replace(os.sep, "/")
            try:
                paths[rel] = os.path.getsize(full)
            except OSError:
                pass
        if len(paths) > 20000:
            break
    chosen = [p for m in MCP_MANIFESTS for p in paths if p.lower() == m.lower()]
    pkg = _json(os.path.join(d, "package.json")) if "package.json" in paths else None
    if pkg:
        bins = pkg.get("bin") or {}
        for t in [pkg.get("main")] + ([bins] if isinstance(bins, str) else list(bins.values()) if isinstance(bins, dict) else []):
            t = re.sub(r"^\./", "", t or "") if isinstance(t, str) else ""
            if not t:
                continue
            cands = [t]
            for a, b in (("dist/", "src/"), ("build/", "src/"), ("lib/", "src/")):
                if t.startswith(a):
                    s = b + t[len(a):]
                    cands += [re.sub(r"\.(?:c|m)?js$", e, s) for e in (".ts", ".mts", ".js")]
            chosen += [c for c in cands if c in paths]
    srcs = sorted((p for p, sz in paths.items() if SRC_EXT.search(p) and not SKIP_SRC.search(p)
                   and sz < cap_bytes and ENTRY_NAME.search(p)), key=lambda p: (p.count("/"), len(p)))
    out = []
    for p in chosen + srcs:
        if p not in out:
            out.append(p)
    return [os.path.join(d, p) for p in out[:cap]]


def mcp_has_dir_mode():
    """Newer mcp-audit builds scan a directory themselves (same entry-file pick as --github)."""
    try:
        with open(script_path("mcp"), encoding="utf-8") as fh:
            return "_local_entry_files" in fh.read()
    except OSError:
        return False


def _add_mcp(d, add, why):
    if mcp_has_dir_mode():
        add("mcp", d, why)
        return
    files = mcp_entry_files(d)
    if files:
        add("mcp", d, why, files)


def _dedupe(found):
    seen, out = set(), []
    for x in found:
        k = (x["ecosystem"], tuple(x["args"]))
        if k not in seen:
            seen.add(k)
            out.append(x)
    return out


# ── Reports ───────────────────────────────────────────────────────────────────
def build_report(results, root, fail_on, detected=None, mode="scan", skipped=None):
    by = {}
    top = 0
    for r in results:
        by[r["verdict"]] = by.get(r["verdict"], 0) + 1
        top = max(top, RANK.get(r["max_severity"], 0))
    gate = RANK.get(fail_on.upper(), 99) if fail_on.lower() != "none" else 99
    failed = top >= gate
    rep = {"$schema": SCHEMA_URL, "schema_version": 1, "sca_version": __version__,
           "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "mode": mode, "root": root,
           "summary": {"results": len(results), "by_verdict": by, "max_severity": _level_name(top),
                       "fail_on": fail_on.upper(), "failed": failed,
                       "errors": sum(1 for r in results if r["verdict"] == "ERROR"),
                       "ecosystems": sorted({r["ecosystem"] for r in results})},
           "results": results}
    if detected is not None:
        rep["detected"] = [{k: v for k, v in x.items() if k != "args"} for x in detected]
    if skipped:
        rep["skipped"] = skipped
    return rep


SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
SEC_SEV = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.0", "LOW": "2.0", "INFO": "0.0"}


def _uri(path):
    p = path.replace(os.sep, "/")
    return re.sub(r"^\./", "", p)


def _artifact(r, f):
    target = r["target"]
    file_ = f.get("file")
    if file_:
        file_ = re.split(r"[#]", re.sub(r"^(?:wheel|sdist):", "", str(file_)), 1)[0]
    if file_ and os.path.isabs(file_):
        return _uri(file_)
    if os.path.isdir(target):
        return _uri(os.path.join(target, file_)) if file_ else _uri(target)
    if os.path.isfile(target):
        return _uri(target)
    return _uri(file_ or target)


def to_sarif(report):
    runs = {}
    for r in report["results"]:
        run = runs.get(r["tool"])
        if run is None:
            info = ADAPTERS[r["ecosystem"]]
            run = runs[r["tool"]] = {
                "tool": {"driver": {"name": r["tool"], "version": (r.get("tool_commit") or "unknown")[:12],
                                    "informationUri": "https://github.com/eltociear/%s" % r["tool"], "rules": []}},
                "automationDetails": {"id": "supply-chain-audit/%s/" % r["ecosystem"]},
                "results": [], "invocations": [], "properties": {"ecosystem": r["ecosystem"],
                                                                 "runs_at": info.get("runs"), "targets": []}}
            run["_rules"] = {}
        run["properties"]["targets"].append({"target": r["target"], "verdict": r["verdict"],
                                             "max_severity": r["max_severity"], "risk_score": r.get("risk_score")})
        run["invocations"].append({"executionSuccessful": r["verdict"] != "ERROR",
                                   "commandLine": " ".join(r.get("command") or []),
                                   **({"toolExecutionNotifications": [{"level": "error", "message": {"text": r["error"]}}]}
                                      if r.get("error") else {})})
        for f in r["findings"]:
            rid = f["rule"]
            if rid not in run["_rules"]:
                run["_rules"][rid] = len(run["tool"]["driver"]["rules"])
                run["tool"]["driver"]["rules"].append({
                    "id": rid, "name": re.sub(r"\W+", "", (f.get("name") or rid).title()) or rid,
                    "shortDescription": {"text": f.get("name") or rid},
                    "fullDescription": {"text": f.get("message") or f.get("name") or rid},
                    "defaultConfiguration": {"level": SARIF_LEVEL[f["severity"]]},
                    "properties": {"security-severity": SEC_SEV[f["severity"]], "tags": ["security", "supply-chain"]}})
            loc = {"physicalLocation": {"artifactLocation": {"uri": _artifact(r, f)}}}
            if f.get("line"):
                loc["physicalLocation"]["region"] = {"startLine": f["line"]}
                if f.get("context"):
                    loc["physicalLocation"]["region"]["snippet"] = {"text": f["context"]}
            run["results"].append({
                "ruleId": rid, "ruleIndex": run["_rules"][rid], "level": SARIF_LEVEL[f["severity"]],
                "message": {"text": "%s [%s] in %s" % (f.get("message") or rid, f["severity"], r["target"])},
                "locations": [loc],
                "properties": {"severity": f["severity"], "target": r["target"], "ecosystem": r["ecosystem"],
                               **({"context": f["context"]} if f.get("context") else {})}})
    out = []
    for run in runs.values():
        run.pop("_rules", None)
        out.append(run)
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": out}


_ICON = {"CRITICAL": "\U0001F534", "HIGH": "\U0001F7E0", "MEDIUM": "\U0001F7E1", "LOW": "\U0001F535",
         "SAFE": "\U0001F7E2", "ERROR": "⚪"}


def to_text(report, verbose=False):
    lines = []
    if report.get("detected") is not None:
        lines.append("detected %d target(s) in %s:" % (len(report["detected"]), report["root"]))
        for x in report["detected"]:
            lines.append("  %-11s %s  (%s)" % (x["ecosystem"], x["target"], x["reason"]))
        for x in report.get("skipped") or []:
            lines.append("  %-11s %s  (skipped: %s)" % (x["ecosystem"], x["target"], x["reason"]))
        lines.append("")
    for r in report["results"]:
        icon = _ICON.get(r["verdict"], "")
        if r["verdict"] == "ERROR":
            lines.append("%s %-11s %s  [ERROR] %s" % (icon, r["ecosystem"], r["target"], r.get("error")))
            continue
        lines.append("%s %-11s %s  [%s]  score=%s  (%d findings)" % (
            icon, r["ecosystem"], r["target"], r["verdict"], r.get("risk_score"), len(r["findings"])))
        shown = r["findings"] if verbose else [f for f in r["findings"] if RANK[f["severity"]] >= 2][:12]
        for f in shown:
            loc = "%s:%s" % (f.get("file") or "", f.get("line") or "") if f.get("file") or f.get("line") else ""
            lines.append("    %-8s %s %s" % (f["severity"], f["rule"], ("(" + loc + ")") if loc else ""))
            if f.get("context"):
                lines.append("             " + f["context"][:160].replace("\n", " "))
        if not verbose and len(shown) < len(r["findings"]):
            lines.append("    ... %d more (use -v)" % (len(r["findings"]) - len(shown)))
        if verbose and r.get("command"):
            lines.append("    $ " + " ".join(r["command"]))
    s = report["summary"]
    lines.append("")
    lines.append("%d result(s): %s | max %s | fail-on %s -> %s" % (
        s["results"], ", ".join("%d %s" % (v, k) for k, v in sorted(s["by_verdict"].items(), key=lambda kv: -RANK.get(kv[0], -1))),
        s["max_severity"], s["fail_on"], "FAIL" if s["failed"] else "pass"))
    return "\n".join(lines)


# ── CLI ───────────────────────────────────────────────────────────────────────
def _pop_opts(argv):
    """Split sca's own options out of argv; everything else is returned in order."""
    opts = {"json": False, "sarif": False, "out": None, "fail_on": "high", "timeout": 600, "jobs": 2,
            "verbose": False, "deps": False, "only": None, "skip": set(), "dry_run": False, "raw": False}
    rest, i = [], 0
    takes = {"-o": "out", "--output": "out", "--fail-on": "fail_on", "--timeout": "timeout", "-j": "jobs",
             "--jobs": "jobs", "--only": "only", "--skip": "skip"}
    flags = {"--json": "json", "--sarif": "sarif", "--deps": "deps", "--dry-run": "dry_run", "--raw": "raw",
             "-v": "verbose", "--verbose": "verbose"}
    while i < len(argv):
        a = argv[i]
        key, val = (a.split("=", 1) + [None])[:2] if a.startswith("--") and "=" in a else (a, None)
        if key in takes:
            if val is None:
                if i + 1 >= len(argv):
                    raise SystemExit("sca: %s needs a value" % key)
                val = argv[i + 1]
                i += 1
            name = takes[key]
            if name in ("timeout", "jobs"):
                val = int(val)
            elif name in ("only", "skip"):
                val = {ALIASES.get(x.strip(), x.strip()) for x in val.split(",") if x.strip()}
            opts[name] = val
        elif key in flags:
            opts[flags[key]] = True
        else:
            rest.append(a)
        i += 1
    if opts["fail_on"].lower() not in ("low", "medium", "high", "critical", "none"):
        raise SystemExit("sca: --fail-on must be low|medium|high|critical|none")
    return opts, rest


def _emit(report, opts):
    if opts["sarif"]:
        text = json.dumps(to_sarif(report), indent=1)
    elif opts["json"]:
        text = json.dumps(report, indent=1)
    else:
        text = to_text(report, opts["verbose"])
    if opts["out"]:
        with open(opts["out"], "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        if not (opts["json"] or opts["sarif"]):
            print(text)
    else:
        try:
            print(text)
        except UnicodeEncodeError:
            sys.stdout.buffer.write((text + "\n").encode("utf-8", "replace"))


def _exit_code(report):
    # A finding at or above --fail-on always wins (exit 2), even when another scanner
    # errored: an incomplete scan must not hide malware that *was* found. Otherwise an
    # incomplete scan never passes CI (exit 1), even in a mixed report with SAFE results.
    if report["summary"]["failed"]:
        return 2
    if not report["results"] or any(r["verdict"] == "ERROR" for r in report["results"]):
        return 1
    return 0


def cmd_list(opts):
    vs = versions()
    rows = []
    for eco in sorted(ADAPTERS):
        a = ADAPTERS[eco]
        v = vs.get(a["repo"], {})
        rows.append({"ecosystem": eco, "scanner": a["repo"], "title": a["title"], "commit": (v.get("commit") or "")[:12],
                     "aliases": a.get("aliases", []), "runs_at": a["runs"], "vendored": os.path.isfile(script_path(eco))})
    if opts["json"]:
        print(json.dumps(rows, indent=1))
    else:
        for r in rows:
            print("%-11s %-17s %-12s %s" % (r["ecosystem"], r["scanner"], r["commit"] or "-", r["title"]))
        print("\n%d ecosystems. `sca help <ecosystem>` for a scanner's own options." % len(rows))
    return 0


def cmd_help(eco):
    eco = ALIASES.get(eco)
    if not eco:
        print(__doc__)
        return 0
    # mcp-audit has no --help: with no arguments it prints its usage
    args = [] if eco == "mcp" else ["--help"]
    p = subprocess.run(_cmd(eco, args), capture_output=True, text=True, timeout=60)
    print(p.stdout or p.stderr)
    a = ADAPTERS[eco]
    print("sca adapter quirks for %s:" % a["repo"])
    for q in a.get("quirks", []):
        print("  - " + q)
    return 0


def cmd_scan(paths, opts):
    if not paths:
        print("sca scan: give a directory or file", file=sys.stderr)
        return 1
    detected, skipped = [], []
    for p in paths:
        if not os.path.exists(p):
            print("sca scan: no such file or directory: %s" % p, file=sys.stderr)
            return 1
        detected += detect(p, deps=opts["deps"], skipped=skipped)
    if opts["only"]:
        detected = [x for x in detected if x["ecosystem"] in opts["only"]]
    detected = [x for x in detected if x["ecosystem"] not in opts["skip"]]
    if opts["dry_run"]:
        for x in detected:
            print("%-11s %s  (%s)\n            $ %s" % (x["ecosystem"], x["target"], x["reason"],
                                                     " ".join([ADAPTERS[x["ecosystem"]]["script"]] + x["args"] + ["--json"])))
        print("%d scanner run(s) planned" % len(detected))
        return 0
    if not detected:
        rep = build_report([], ",".join(paths), opts["fail_on"], detected, skipped=skipped)
        _emit(rep, opts)
        if not (opts["json"] or opts["sarif"]):
            print("nothing recognised (see `sca list`)", file=sys.stderr)
        return 1

    def job(x):
        return run_scanner(x["ecosystem"], x["args"], opts["timeout"], label=x["target"])

    results = []
    with ThreadPoolExecutor(max_workers=max(1, min(opts["jobs"], 8))) as ex:
        for rs, x in zip(ex.map(job, detected), detected):
            for r in rs:
                r["detected_by"] = x["reason"]
            results += rs
    rep = build_report(results, ",".join(paths), opts["fail_on"], detected, skipped=skipped)
    _emit(rep, opts)
    return _exit_code(rep)


def cmd_one(eco, args, opts):
    if not args:
        return cmd_help(eco)
    if opts["raw"]:
        return subprocess.call(_cmd(eco, args))
    # mcp-audit: point it at a directory and sca picks the entry files (it has no dir mode)
    if eco == "mcp" and not mcp_has_dir_mode():
        expanded = []
        for a in args:
            expanded += (mcp_entry_files(a) or [a]) if os.path.isdir(a) else [a]
        args = expanded
    results = run_scanner(eco, args, opts["timeout"], label=" ".join(args))
    rep = build_report(results, " ".join(args), opts["fail_on"], mode="single")
    _emit(rep, opts)
    return _exit_code(rep)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if argv[0] == "--version":
        print("sca " + __version__)
        return 0
    cmd = argv[0]
    if cmd == "help":
        return cmd_help(argv[1] if len(argv) > 1 else "")
    if cmd in ADAPTERS or cmd in ALIASES:
        # pass-through: only sca's output/gate options are consumed, everything else goes to the scanner
        try:
            opts, args = _split_passthrough(argv[1:])
        except SystemExit as e:
            print(e, file=sys.stderr)
            return 1
        return cmd_one(ALIASES[cmd], args, opts)
    try:
        opts, rest = _pop_opts(argv[1:])
    except SystemExit as e:
        print(e, file=sys.stderr)
        return 1
    if cmd == "list":
        return cmd_list(opts)
    if cmd == "scan":
        return cmd_scan(rest, opts)
    print("sca: unknown command or ecosystem %r (try `sca list`)" % cmd, file=sys.stderr)
    return 1


def _split_passthrough(argv):
    """`sca <eco> ...`: take sca's own options out, pass everything else to the scanner unchanged."""
    opts, _ = _pop_opts([])
    flags = {"--json": "json", "--sarif": "sarif", "--raw": "raw"}
    takes = {"--fail-on": "fail_on", "-o": "out", "--output": "out", "--timeout": "timeout"}
    rest, i = [], 0
    while i < len(argv):
        a = argv[i]
        key, val = (a.split("=", 1) if a.startswith("--") and "=" in a else (a, None))
        if key in flags:
            opts[flags[key]] = True
        elif key in takes:
            if val is None:
                if i + 1 >= len(argv):
                    raise SystemExit("sca: %s needs a value" % key)
                val = argv[i + 1]
                i += 1
            opts[takes[key]] = int(val) if key == "--timeout" else val
        else:
            rest.append(a)
        i += 1
    if opts["fail_on"].lower() not in ("low", "medium", "high", "critical", "none"):
        raise SystemExit("sca: --fail-on must be low|medium|high|critical|none")
    if opts["raw"] and opts["json"]:
        rest.append("--json")
    return opts, rest


if __name__ == "__main__":
    sys.exit(main())
