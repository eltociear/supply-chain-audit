#!/usr/bin/env python3
"""Canary + control tests.

Every mal-* fixture must reach its expected level AND fire its expected pattern; every ok-*
fixture (patterns real remote-code models use) must scan below HIGH with no scored finding.
Fixtures are inert: hosts are reserved (.invalid / TEST-NET), credentials are fake, and
nothing here is ever imported or executed.

    python tests/run.py
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import hf_code_audit as ha  # noqa: E402

EXPECT = {
    "mal-import-exec": ("HIGH", "shell_exec"),
    "mal-decode-exec": ("CRITICAL", "decode_exec"),
    "mal-cred-exfil": ("CRITICAL", "credential_exfil"),
    "mal-env-exfil": ("CRITICAL", "env_exfil"),
    "mal-revshell": ("CRITICAL", "reverse_shell"),
    "mal-persist": ("CRITICAL", "persistence_write"),
    "mal-download-exec": ("CRITICAL", "download_execute"),
    "mal-pip-git": ("HIGH", "pip_install"),
    "mal-obfuscated": ("HIGH", "obfuscation"),
    "mal-webhook": ("HIGH", "exfil_host"),
    "mal-cross-repo": ("LOW", "cross_repo_code"),
    "mal-split-imds": ("CRITICAL", "credential_exfil"),
}

TEXT_CASES = [
    # (source, expected id or None, min level)
    ("import os\nos.system(input())\n", "shell_exec", "HIGH"),
    ("def f(x):\n    return eval(x)\n", "dynamic_exec", "MEDIUM"),
    ("x = eval('1+1')\n", None, "SAFE"),
    ("import subprocess\ndef f():\n    subprocess.run(['git', 'rev-parse', 'HEAD'])\n", None, "SAFE"),
    ("match = 1\nmatch x:\n    case 1: pass\n", None, "SAFE"),   # py3.10 syntax -> regex fallback, no crash
]


def main():
    fails = 0
    root = os.path.join(HERE, "fixtures")
    for name in sorted(os.listdir(root)):
        r = ha.scan_repo(ha.files_from_dir(os.path.join(root, name)), "fixture-owner/" + name, repo_id="fixture-owner/" + name)
        ids = sorted({f["id"] for f in r["findings"]})
        if name.startswith("mal-"):
            want, fid = EXPECT[name]
            ok = ha.SEV_ORDER[r["risk_level"]] >= ha.SEV_ORDER[want] and fid in ids
        else:
            ok = r["risk_level"] in ("SAFE", "LOW") and not name.startswith("mal-")
        fails += not ok
        print("%s %-22s %-8s %s" % ("PASS" if ok else "FAIL", name, r["risk_level"], ",".join(ids)))
    for src, fid, lvl in TEXT_CASES:
        r = ha.scan(src)
        ids = {f["id"] for f in r["findings"]}
        ok = (fid in ids and ha.SEV_ORDER[r["risk_level"]] >= ha.SEV_ORDER[lvl]) if fid else r["risk_level"] == lvl
        fails += not ok
        print("%s --text %-40r %s" % ("PASS" if ok else "FAIL", src[:40], r["risk_level"]))
    # performance: a 3 MB generated file must scan quickly
    big = "x = [\n" + ",\n".join("%d" % i for i in range(400000)) + "]\n"
    t0 = time.time()
    ha.scan(big)
    dt = time.time() - t0
    ok = dt < 20
    fails += not ok
    print("%s perf 3MB literal list %.1fs" % ("PASS" if ok else "FAIL", dt))
    print("\n%d failure(s)" % fails)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
