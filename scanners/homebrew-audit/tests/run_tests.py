#!/usr/bin/env python3
"""Canary + benign regression tests. Run: python3 tests/run_tests.py"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import homebrew_audit as ha

EXPECT = {  # canary -> (min level, pattern id that must fire)
    "pipe-to-shell.rb": ("CRITICAL", "pipe_to_shell"),
    "quarantine.rb": ("CRITICAL", "quarantine_strip"),
    "gatekeeper.rb": ("CRITICAL", "gatekeeper_disable"),
    "exfil.rb": ("CRITICAL", "credential_exfil"),
    "keychain.rb": ("HIGH", "credential_access"),
    "decoded.rb": ("CRITICAL", "decoded_exec"),
    "remote-eval.rb": ("CRITICAL", "remote_eval"),
    "launchd.rb": ("HIGH", "launchd_persistence"),
    "shellrc.rb": ("HIGH", "shell_rc_tamper"),
    "sudoers.rb": ("CRITICAL", "privileged_tamper"),
    "plaintext.rb": ("HIGH", "unverified_plaintext"),
    "tls.rb": ("HIGH", "tls_bypass"),
}
fail = 0
for name, (lvl, pid) in EXPECT.items():
    r = ha.scan(open(os.path.join(HERE, "canaries", name)).read())
    ids = {f["id"] for f in r["findings"]}
    ok = ha.SEVERITY_RANK[r["risk_level"]] >= ha.SEVERITY_RANK[lvl] and pid in ids
    fail += not ok
    print(("PASS" if ok else "FAIL"), name, r["risk_level"], sorted(ids))
for name in sorted(os.listdir(os.path.join(HERE, "benign"))):
    r = ha.scan(open(os.path.join(HERE, "benign", name)).read())
    ok = r["risk_level"] == "SAFE"
    fail += not ok
    print(("PASS" if ok else "FAIL"), name, r["risk_level"], [(f["id"], f["line"]) for f in r["findings"]])
print("\n%d failed" % fail)
sys.exit(1 if fail else 0)
