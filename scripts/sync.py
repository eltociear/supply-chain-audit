#!/usr/bin/env python3
"""Re-vendor every scanner from GitHub at its latest commit.

  python3 scripts/sync.py              # all scanners, default branch HEAD
  python3 scripts/sync.py npm pypi     # just these (ecosystem names or repo names)
  python3 scripts/sync.py --check      # report which vendored copies are behind, change nothing
  python3 scripts/sync.py --from DIR   # copy from existing local clones DIR/<repo> (records their HEAD)

For each scanner it copies the single-file scanner, its LICENSE and its tests/ tree (the
self-written inert canaries + benign controls that tests/test_canaries.py replays through sca)
into scanners/<repo>/, and records repo, commit SHA, sha256 of the scanner and the sync time
in scanners/VERSIONS.json. Needs git; zero Python dependencies. Network: HTTPS first, SSH
(git@github.com) as fallback, 3 attempts each.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import sca  # noqa: E402  (zero-dep, only for the adapter table)

OWNER = "eltociear"
VERSIONS = os.path.join(sca.SCANNER_DIR, "VERSIONS.json")
SKIP_IN_TESTS = {"__pycache__", ".pytest_cache"}


def _git(args, cwd=None, timeout=300):
    return subprocess.run(["git"] + args, cwd=cwd, capture_output=True, text=True, timeout=timeout,
                          env=dict(os.environ, GIT_TERMINAL_PROMPT="0"))


def remote_head(repo):
    for url in ("https://github.com/%s/%s.git" % (OWNER, repo), "git@github.com:%s/%s.git" % (OWNER, repo)):
        for attempt in range(3):
            p = _git(["ls-remote", url, "HEAD"], timeout=60)
            if p.returncode == 0 and p.stdout.strip():
                return p.stdout.split()[0], url
            time.sleep(2 * (attempt + 1))
    raise RuntimeError("could not reach %s" % repo)


def clone(repo, dest):
    last = ""
    for url in ("https://github.com/%s/%s.git" % (OWNER, repo), "git@github.com:%s/%s.git" % (OWNER, repo)):
        for attempt in range(3):
            shutil.rmtree(dest, ignore_errors=True)
            p = _git(["clone", "-q", "--depth", "1", url, dest])
            if p.returncode == 0:
                return url
            last = p.stderr.strip()
            time.sleep(2 * (attempt + 1))
    raise RuntimeError("clone failed for %s: %s" % (repo, last[-200:]))


def vendor_from(src, eco):
    a = sca.ADAPTERS[eco]
    repo = a["repo"]
    dst = os.path.join(sca.SCANNER_DIR, repo)
    script = os.path.join(src, a["script"])
    if not os.path.isfile(script):
        raise RuntimeError("%s: %s not found in the repo" % (repo, a["script"]))
    commit = _git(["rev-parse", "HEAD"], cwd=src).stdout.strip()
    shutil.rmtree(dst, ignore_errors=True)
    os.makedirs(dst)
    shutil.copy2(script, os.path.join(dst, a["script"]))
    if os.path.isfile(os.path.join(src, "LICENSE")):
        shutil.copy2(os.path.join(src, "LICENSE"), os.path.join(dst, "LICENSE"))
    if os.path.isdir(os.path.join(src, "tests")):
        shutil.copytree(os.path.join(src, "tests"), os.path.join(dst, "tests"),
                        ignore=lambda d, names: [n for n in names if n in SKIP_IN_TESTS or n.endswith(".pyc")])
    with open(os.path.join(dst, "VENDORED.md"), "w", encoding="utf-8") as fh:
        fh.write("Vendored from https://github.com/%s/%s at commit %s by scripts/sync.py.\n"
                 "Do not edit here: change the upstream repo, then re-run `python3 scripts/sync.py %s`.\n"
                 "License: see LICENSE (MIT, Copyright the upstream authors).\n" % (OWNER, repo, commit, eco))
    with open(os.path.join(dst, a["script"]), "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    return {"repo": "%s/%s" % (OWNER, repo), "url": "https://github.com/%s/%s" % (OWNER, repo),
            "commit": commit, "script": a["script"], "sha256": digest,
            "synced_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def load_versions():
    try:
        with open(VERSIONS, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {"scanners": {}}


def main(argv):
    if {"-h", "--help"} & set(argv):
        print(__doc__.strip())
        return 0
    unknown = [a for a in argv if a.startswith("-") and a not in ("--check", "--from")]
    if unknown:
        print("unknown option(s): %s (see --help)" % " ".join(unknown), file=sys.stderr)
        return 2
    check = "--check" in argv
    src_dir = None
    if "--from" in argv:
        i = argv.index("--from")
        src_dir = argv[i + 1]
        del argv[i:i + 2]
    names = [a for a in argv if not a.startswith("--")]
    ecos = sorted(sca.ADAPTERS) if not names else []
    for n in names:
        e = sca.ALIASES.get(n)
        if not e:
            print("unknown scanner %r" % n, file=sys.stderr)
            return 1
        ecos.append(e)
    data = load_versions()
    data.setdefault("scanners", {})
    failed, changed = [], []
    tmp = tempfile.mkdtemp(prefix="sca-sync-")
    try:
        for eco in ecos:
            repo = sca.ADAPTERS[eco]["repo"]
            old = data["scanners"].get(repo, {}).get("commit")
            try:
                if check:
                    head, _ = remote_head(repo)
                    print("%-18s %s  %s" % (repo, (old or "-")[:12], "up to date" if head == old else "BEHIND -> " + head[:12]))
                    if head != old:
                        changed.append(repo)
                    continue
                if src_dir:
                    src = os.path.join(src_dir, repo)
                else:
                    src = os.path.join(tmp, repo)
                    clone(repo, src)
                entry = vendor_from(src, eco)
                data["scanners"][repo] = entry
                print("%-18s %s -> %s" % (repo, (old or "-")[:12], entry["commit"][:12]))
                if entry["commit"] != old:
                    changed.append(repo)
            except Exception as e:  # keep going: one unreachable repo must not block the rest
                failed.append(repo)
                print("%-18s FAILED: %s" % (repo, e), file=sys.stderr)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if not check:
        data["synced_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        data["scanners"] = dict(sorted(data["scanners"].items()))
        with open(VERSIONS, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1)
            fh.write("\n")
    print("%d changed, %d failed%s" % (len(changed), len(failed), (": " + ", ".join(failed)) if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
