#!/usr/bin/env python3
"""Smoke-test an *installed* sca (wheel / pipx / uvx) against this checkout's fixtures.

  python3 scripts/smoke_installed.py --sca /path/to/venv/bin/sca [--python /path/to/venv/bin/python]

Checks, running the installed console script from a temp cwd so the checkout cannot be imported:
  1. `sca --version` matches this checkout's sca.__version__;
  2. the installed sca resolves its scanners from the installed package, not from a checkout;
  3. `sca list --json` lists every ecosystem, each scanner vendored;
  4. `sca scan tests/fixtures/detect/monorepo --json` exits 0 with SAFE results and no errors;
  5. a canary replay subset: one malicious canary and one benign control per ecosystem (the
     first of each in tests/canaries.py order), through the installed `sca <eco> ... --json`.
Exit 0 when all pass. Zero dependencies.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
import sca as checkout_sca  # noqa: E402  (only for the version, adapters and severity ranks)
import canaries  # noqa: E402

FAIL = []


def check(ok, what):
    print("%s %s" % ("ok  " if ok else "FAIL", what))
    if not ok:
        FAIL.append(what)


def run(cmd, cwd):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=600)
    return p.returncode, p.stdout, p.stderr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sca", required=True, help="the installed sca console script")
    ap.add_argument("--python", help="the installed environment's python (for the path check)")
    a = ap.parse_args()
    a.sca = os.path.abspath(a.sca) if os.sep in a.sca or (os.altsep and os.altsep in a.sca) else a.sca
    a.python = os.path.abspath(a.python) if a.python else None
    tmp = tempfile.mkdtemp(prefix="sca-smoke-")
    sca_cmd = [a.sca]

    rc, out, err = run(sca_cmd + ["--version"], tmp)
    check(rc == 0 and out.strip() == "sca " + checkout_sca.__version__,
          "sca --version -> %r (want sca %s)" % (out.strip() or err.strip()[-200:], checkout_sca.__version__))

    if a.python:
        rc, out, err = run([a.python, "-c", "import sca, os; print(sca.SCANNER_DIR); print(os.path.abspath(sca.__file__))"], tmp)
        lines = out.split()
        inside = rc == 0 and len(lines) == 2 and not os.path.abspath(lines[0]).startswith(ROOT + os.sep) \
            and os.path.basename(lines[0]) == "sca_scanners"
        check(inside, "scanners resolved from the installed package: %s" % (lines[:1] or err.strip()[-200:]))

    rc, out, err = run(sca_cmd + ["list", "--json"], tmp)
    try:
        rows = json.loads(out)
    except ValueError:
        rows = []
    ecos = sorted(r.get("ecosystem") for r in rows)
    check(rc == 0 and ecos == sorted(checkout_sca.ADAPTERS) and all(r.get("vendored") for r in rows),
          "sca list --json: %d ecosystems, all vendored" % len(ecos))

    target = os.path.join(ROOT, "tests", "fixtures", "detect", "monorepo")
    rc, out, err = run(sca_cmd + ["scan", target, "--json"], tmp)
    try:
        rep = json.loads(out)
        summ = rep["summary"]
        ok = rc == 0 and summ["results"] > 0 and summ["errors"] == 0 and summ["max_severity"] == "SAFE"
        desc = "%d results, %s, %d errors" % (summ["results"], summ["max_severity"], summ["errors"])
    except (ValueError, KeyError):
        ok, desc = False, (err.strip() or out.strip())[-300:]
    check(ok, "sca scan <monorepo fixture> --json (rc %d): %s" % (rc, desc))

    picked, seen = [], set()
    for case in canaries.cases():
        eco, name, kind = case[0], case[1], case[2]
        if (eco, kind) not in seen and case[3]:
            seen.add((eco, kind))
            picked.append(case)
    for eco, name, kind, args, level, ids, ceiling in picked:
        rc, out, err = run(sca_cmd + [eco] + list(args) + ["--json", "--fail-on", "none"], tmp)
        try:
            rep = json.loads(out)
            got = rep["summary"]["max_severity"]
            errs = rep["summary"]["errors"]
        except (ValueError, KeyError):
            check(False, "%s %s (%s): no JSON report (%s)" % (eco, name, kind, err.strip()[-200:]))
            continue
        r = checkout_sca.RANK.get(got, 0)
        if kind == "malicious":
            ok = r >= checkout_sca.RANK[level] and not errs
            want = ">= " + level
        else:
            ok = r <= checkout_sca.RANK[ceiling] and not errs
            want = "<= " + ceiling
        check(ok, "canary %s %s (%s): %s, want %s" % (eco, name, kind, got, want))

    print("%d checks failed" % len(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
