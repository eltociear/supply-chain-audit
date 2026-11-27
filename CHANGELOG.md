# Changelog

All notable changes to supply-chain-audit (`sca`). Versions follow `sca.__version__`; the
vendored scanners are pinned separately in [`scanners/VERSIONS.json`](scanners/VERSIONS.json).

## [0.2.0] - 2026-11-28

Not yet released to PyPI or tagged; see [RELEASING.md](RELEASING.md).

### Added
- **PyPI packaging** as `supply-chain-audit` with the console script `sca`
  (`pipx install supply-chain-audit` / `uvx --from supply-chain-audit sca` after release).
  Pure Python, zero dependencies, Python >= 3.9. The vendored scanners ship as package data
  (`sca_scanners/`); their test trees (inert canaries) are not packaged.
- `sca` finds its scanners in a checkout (`scanners/`), an installed package
  (`sca_scanners/`) or `$SCA_SCANNER_DIR`.
- **GitHub Action** (`action.yml`, composite, no Docker): inputs `path`, `fail-on`,
  `sarif-file`, `deps`, `extra-args`, `upload-sarif`, `python-version`; outputs `exit-code`,
  `max-severity`, `sarif-file`. All actions it uses are pinned by commit SHA; the SARIF upload
  degrades to a warning without `security-events: write`.
- `scripts/gen_stats.py` + `scripts/family_sources.json`: every number in `family_stats.json`
  and in the README family / recall tables is extracted from the scanners' FINDINGS.md /
  RECALL.md at the vendored commit through literal quotes, and generation fails when a doc no
  longer matches.
- README **Recall on real malware** section: blind held-out recall for npm (58.8% -> 73.4% of
  distinct payloads), pypi (54.1% -> 75.7%), crate (15/38 -> 15/38), vsix (3/17 -> 4/17),
  gha, gomod, rubygems and packagist incident replays, with tuned-on numbers labelled as not
  recall estimates and the benign re-check beside each.
- `scripts/smoke_installed.py` and a CI job that builds sdist + wheel, checks their contents,
  installs the wheel into a fresh venv and runs version / list / scan / a 48-case canary
  subset (Ubuntu 3.9 + 3.14, Windows 3.12).
- `.github/workflows/action-selftest.yml`: the action on a benign fixture (must pass), an inert
  canary (must fail with exit 2) and `fail-on: none`.
- `tests/test_stats.py`: README number sections stay in step with `family_stats.json`.
- `RELEASING.md`: build, upload, tag and Marketplace steps (all manual).

### Changed
- Re-vendored all 24 scanners after the wave-5 improvements (real-malware recall for npm,
  pypi and vsix; incident replays for gha, gomod, crate, rubygems and packagist;
  family-wide `--json` / `--sarif` / `--fail-on` / `--version` and hardening), last vsix-audit
  at `7b82c36`. The replay now covers 414 malicious canaries and 258 benign controls (was
  372 / 246).
- vsix-audit's family-table row now reports its fresh held-out set 3 with the frozen v0.2.0
  engine: 10/893 HIGH+, 7 (0.8%) false positives (was 17/595 with v0.1.0). Pooled over 21
  scanners: 41 alerts / 23 misfires on 16,809 never-seen packages.
- `sync.py --help` prints usage instead of syncing.

## [0.1.0] - 2026-11-27

### Added
- `sca`: one CLI over the 24 eltociear/*-audit scanners, each run in its own `python -I`
  subprocess; marker-based auto-detection (`sca scan`), pass-through (`sca <ecosystem> ...`),
  `--raw`, `sca list`, `sca help`.
- One normalised JSON report (`schema/sca-report.schema.json`) and SARIF 2.1.0 output;
  `--fail-on` exit codes, fail-closed on scanner errors (findings win over errors).
- `scripts/sync.py` to re-vendor the scanners at pinned commits; canary replay of every
  scanner's own tests through sca; CI on Ubuntu / macOS / Windows x Python 3.9 / 3.12 / 3.14.
