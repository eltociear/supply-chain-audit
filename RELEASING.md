# Releasing

Nothing here is automated: no workflow publishes to PyPI, creates tags or touches the
Marketplace. A maintainer does each step by hand.

## 1. Prepare

```sh
git pull
python3 scripts/sync.py --check            # vendored scanners current? if not: python3 scripts/sync.py
python3 scripts/gen_stats.py --check       # numbers current? if not: python3 scripts/gen_stats.py
python3 -m unittest discover -s tests      # full offline suite
```

Bump `__version__` in `sca.py` (the package version is read from it), add the release to
`CHANGELOG.md`, update the `uses: eltociear/supply-chain-audit@vX.Y.Z` example in README.md,
commit, push, and wait for CI (`Tests` and `Action self-test`) to be green on `main`.

## 2. Build and check the distributions

Build in a throwaway environment; `dist/` is git-ignored and must never be committed.

```sh
rm -rf dist
uv build                                   # or: python3 -m pip install build && python3 -m build
ls -l dist                                 # supply_chain_audit-X.Y.Z.tar.gz + supply_chain_audit-X.Y.Z-py3-none-any.whl
uvx twine check dist/*                     # metadata / README rendering

# smoke-test the wheel exactly as CI does
python3 -m venv /tmp/sca-rel && /tmp/sca-rel/bin/pip install dist/*.whl
python3 scripts/smoke_installed.py --sca /tmp/sca-rel/bin/sca --python /tmp/sca-rel/bin/python
```

## 3. Upload to PyPI (your own token)

The project name is `supply-chain-audit` (free on pypi.org as of 2026-11-28). The first upload
creates the project under the account that owns the token. Use an API token scoped to this
project once it exists (an account-wide token is needed only for the very first upload).

```sh
# optional dry run on TestPyPI first
uvx twine upload --repository testpypi dist/*

# the real upload; twine prompts for the token (user name: __token__)
uvx twine upload dist/*
```

Or, with the token in the environment instead of a prompt:

```sh
TWINE_USERNAME=__token__ TWINE_PASSWORD=pypi-XXXXXXXX uvx twine upload dist/*
```

Then check `pipx install supply-chain-audit && sca --version` from a clean machine.

## 4. Tag and GitHub release

```sh
git tag -s vX.Y.Z -m "supply-chain-audit X.Y.Z"   # -a if you do not sign tags
git push origin vX.Y.Z
gh release create vX.Y.Z --title "vX.Y.Z" --notes-file <(sed -n '/^## \[X.Y.Z\]/,/^## \[/p' CHANGELOG.md | sed '$d') \
  dist/supply_chain_audit-X.Y.Z.tar.gz dist/supply_chain_audit-X.Y.Z-py3-none-any.whl
```

Optionally keep a moving major tag for the GitHub Action (`git tag -f v0 vX.Y.Z && git push -f origin v0`).
Users should still pin the full commit SHA (`gh api repos/eltociear/supply-chain-audit/commits/vX.Y.Z --jq .sha`).

## 5. GitHub Marketplace (optional)

The repository root `action.yml` makes it listable. To publish the listing:

1. Make sure `action.yml` has a unique `name`, a `description`, and `branding` (icon + color).
2. Accept the GitHub Marketplace Developer Agreement (once per account).
3. On github.com, open *Releases → Draft a new release* (or edit the release from step 4), tick
   **Publish this Action to the GitHub Marketplace**, choose a primary category (Security) and
   publish. GitHub validates `action.yml` at that point.

Listing is optional: `uses: eltociear/supply-chain-audit@<sha>` works without it.
