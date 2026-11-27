"""Replay every vendored scanner's own canaries through sca's adapters.

The expectations are read (with ast.literal_eval, never imported) from each scanner's
own test file - the EXPECT table {fixture: (min level, rule id or {rule ids})} that every
repo in the family keeps, plus mcp-audit's CANARIES / BENIGN string lists - so when
scripts/sync.py pulls a newer scanner, its newer canaries are replayed automatically.

Used by tests/test_canaries.py; `python3 tests/canaries.py` prints the full table.
"""
import ast
import atexit
import shutil
import tempfile
import glob
import os
import sys
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import sca  # noqa: E402

RANK = sca.RANK
BENIGN_PREFIXES = ("ok-", "ben-", "benign")


def _literal_tables(path):
    """{NAME: value} for every module-level NAME = <literal> in a test file."""
    out = {}
    try:
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
    except (OSError, SyntaxError):
        return out
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                out[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, SyntaxError, TypeError):
                pass
    return out


def _resolve(tests_dir, name):
    for sub in ("fixtures", "canaries", "benign", ""):
        base = os.path.join(tests_dir, sub, name) if sub else os.path.join(tests_dir, name)
        if os.path.exists(base):
            return base
        hits = sorted(glob.glob(glob.escape(base) + ".*"))
        if hits:
            return hits[0]
    return None


TMP = tempfile.mkdtemp(prefix="sca-canaries-")
atexit.register(shutil.rmtree, TMP, True)


def _layout(path):
    """Turn a fixture into the sca arguments a user would pass for the real thing.

    Two fixture conventions in the family are test-harness layouts, not package layouts:
      * <fixture>/sdist + <fixture>/wheel (pypi-audit): the two distributions, scanned as two targets;
      * X.canary files (repo-trust-audit): dotfiles GitHub's push-time fsck would reject
        (e.g. a malicious .gitmodules) ship renamed - copy the fixture and restore the name.
    """
    if not path:
        return None
    if os.path.isdir(path):
        subs = [os.path.join(path, s) for s in ("sdist", "wheel") if os.path.isdir(os.path.join(path, s))]
        if subs and not [n for n in os.listdir(path) if n not in ("sdist", "wheel")]:
            return subs
        canaries = [n for n in os.listdir(path) if n.endswith(".canary")]
        if canaries:
            dst = os.path.join(TMP, os.path.basename(path))
            if not os.path.isdir(dst):
                shutil.copytree(path, dst)
                for n in canaries:
                    os.rename(os.path.join(dst, n), os.path.join(dst, "." + n[:-len(".canary")]))
            return [dst]
    return [path]


def cases():
    """[(eco, case_name, kind, sca_args, min_level, rule_ids, ceiling)]"""
    out = []
    for eco in sorted(sca.ADAPTERS):
        repo = sca.ADAPTERS[eco]["repo"]
        tdir = os.path.join(sca.SCANNER_DIR, repo, "tests")
        tables = {}
        for f in sorted(glob.glob(os.path.join(tdir, "*.py"))):
            for k, v in _literal_tables(f).items():
                tables.setdefault(k, v)  # first definition wins (test_calibration.py before test_family.py)
        expect = tables.get("EXPECT") if isinstance(tables.get("EXPECT"), dict) else {}
        for name, v in sorted(expect.items()):
            level, ids = (v[0], v[1]) if isinstance(v, (tuple, list)) and len(v) >= 2 else (v, None)
            ids = set(ids) if isinstance(ids, (set, frozenset, list, tuple)) else ({ids} if ids else set())
            path = _resolve(tdir, name)
            out.append((eco, name, "malicious", _layout(path), str(level).upper(), ids, None))
        # extra MEDIUM tables some repos keep: {fixture: rule}
        for tname in ("MEDIUM",):
            t = tables.get(tname)
            if isinstance(t, dict):
                for name, rid in sorted(t.items()):
                    path = _resolve(tdir, name)
                    out.append((eco, name, "malicious", _layout(path), "MEDIUM",
                                {rid} if isinstance(rid, str) else set(), None))
        # mcp-audit keeps string canaries
        for item in tables.get("CANARIES") or []:
            if isinstance(item, (tuple, list)) and len(item) >= 2:
                out.append((eco, item[0][:50], "malicious", ["--text", item[0]], str(item[1]).upper(),
                            {item[2]} if len(item) > 2 else set(), None))
        for item in tables.get("BENIGN") or []:
            if isinstance(item, str):
                out.append((eco, item[:50], "benign", ["--text", item], None, set(), "MEDIUM"))
        # benign controls: every ok-*/ben-* fixture and everything under tests/benign
        allowed_high = set()
        for t in tables.values():  # PARTIAL / CEILING / NOT_SAFE_OK style allowances
            if isinstance(t, dict):
                for k, v in t.items():
                    lvl = v[0] if isinstance(v, (tuple, list)) and v else v
                    if isinstance(k, str) and k.startswith(BENIGN_PREFIXES) and str(lvl).upper() in RANK:
                        allowed_high.add(k)
        seen = set()
        for sub in ("fixtures", "benign"):
            d = os.path.join(tdir, sub)
            if not os.path.isdir(d):
                continue
            for n in sorted(os.listdir(d)):
                stem = n.split(".")[0]
                if (sub == "benign" or n.startswith(BENIGN_PREFIXES)) and stem not in expect and stem not in seen:
                    seen.add(stem)
                    ceiling = "HIGH" if stem in allowed_high else "MEDIUM"
                    out.append((eco, stem, "benign", _layout(os.path.join(d, n)), None, set(), ceiling))
    return out


def run_case(case):
    eco, name, kind, args, level, ids, ceiling = case
    if not args:
        return dict(eco=eco, name=name, kind=kind, ok=False, why="fixture not found", got=None, rules=[])
    res = sca.run_scanner(eco, args, timeout=300)
    top = max([RANK.get(r["max_severity"], 0) for r in res] or [0])
    got = sca._level_name(top)
    rules = sorted({f["rule"] for r in res for f in r["findings"]})
    errs = [r["error"] for r in res if r["verdict"] == "ERROR"]
    if kind == "malicious":
        ok = top >= RANK[level] and not errs
        why = "" if ok else ("error: %s" % errs[0] if errs else "got %s < %s" % (got, level))
        rule_ok = (not ids) or bool(ids & set(rules))
    else:
        ok = top <= RANK[ceiling] and not errs
        why = "" if ok else ("error: %s" % errs[0] if errs else "benign got %s > %s" % (got, ceiling))
        rule_ok = True
    return dict(eco=eco, name=name, kind=kind, ok=ok, why=why, got=got, want=level or ("<=" + ceiling),
                rule_ok=rule_ok, want_rules=sorted(ids), rules=rules)


def run_all(jobs=3):
    cs = cases()
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        return list(ex.map(run_case, cs))


if __name__ == "__main__":
    rows = run_all()
    bad = [r for r in rows if not r["ok"]]
    norule = [r for r in rows if r["ok"] and not r.get("rule_ok", True)]
    per = {}
    for r in rows:
        p = per.setdefault(r["eco"], [0, 0, 0, 0])
        p[0 if r["kind"] == "malicious" else 2] += 1
        p[1 if r["kind"] == "malicious" else 3] += int(r["ok"])
    print("%-11s %10s %10s" % ("ecosystem", "malicious", "benign"))
    for eco, (m, mo, b, bo) in sorted(per.items()):
        print("%-11s %5d/%-4d %5d/%-4d" % (eco, mo, m, bo, b))
    for r in bad:
        print("FAIL %s %s (%s): %s" % (r["eco"], r["name"], r["kind"], r["why"]))
    for r in norule:
        print("RULE %s %s: wanted %s, got %s" % (r["eco"], r["name"], r["want_rules"], r["rules"]))
    print("%d cases, %d failed, %d rule-id mismatches" % (len(rows), len(bad), len(norule)))
    sys.exit(1 if bad else 0)
