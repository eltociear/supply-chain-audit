#!/usr/bin/env python3
"""Canary + control tests.

Every mal-* fixture must reach its expected level AND fire its expected pattern; every ok-*
fixture (things popular extensions really do) must scan SAFE; med-* fixtures must land exactly
at MEDIUM. The fixtures are inert: hosts are reserved (.invalid / TEST-NET-3 203.0.113.0/24),
tokens are not in any provider's real format, payloads are console.log strings, and nothing
here is executed.

    python tests/run.py
"""
import io
import os
import sys
import time
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import browserext_audit as ba  # noqa: E402

EXPECT = {
    "mal-cookie-exfil": ("CRITICAL", "cookie_exfil"),
    "mal-telegram-cookies": ("CRITICAL", "cookie_exfil"),
    "mal-debugger-cookies": ("CRITICAL", "cookie_exfil"),
    "mal-remote-eval": ("CRITICAL", "remote_code_eval"),
    "mal-remote-config": ("HIGH", "remote_config_exec"),
    "mal-executescript": ("HIGH", "remote_code_inject"),
    "mal-keylogger": ("CRITICAL", "password_keylogger"),
    "mal-clipboard-swap": ("HIGH", "clipboard_swap"),
    "mal-fb-token": ("CRITICAL", "token_exfil"),
    "mal-glassworm": ("CRITICAL", "invisible_unicode"),
    "mal-obfuscated": ("HIGH", "obfuscation"),
    "mal-solana-c2": ("CRITICAL", "blockchain_c2"),
}
MEDIUM = {"med-affiliate": "affiliate_rewrite", "med-remote-script": "remote_script",
          "med-cookie-sync": "cookie_bulk", "med-search-redirect": "search_redirect"}


def check(name, ok, detail):
    print("%s %-26s %s" % ("PASS" if ok else "FAIL", name, detail))
    return not ok


def main():
    fails = 0
    root = os.path.join(HERE, "fixtures")
    for name in sorted(os.listdir(root)):
        r = ba.audit_dir(os.path.join(root, name), name)
        ids = sorted({f["id"] for f in r["findings"]})
        if name.startswith("mal-"):
            want, fid = EXPECT[name]
            ok = ba.SEV_ORDER[r["risk_level"]] >= ba.SEV_ORDER[want] and fid in ids
        elif name.startswith("med-"):
            want, fid = "MEDIUM", MEDIUM[name]
            ok = r["risk_level"] == "MEDIUM" and fid in ids
        else:
            want, fid = "SAFE", "-"
            ok = r["risk_level"] == "SAFE"
        fails += check(name, ok, "got=%-8s want=%-8s %-20s %s" % (r["risk_level"], want, fid, ids))
    # .crx round trip: wrap a canary in a CRX3 header and scan the archive bytes
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        d = os.path.join(root, "mal-remote-eval")
        for fn in os.listdir(d):
            z.write(os.path.join(d, fn), fn)
    hdr = b"\x08\x01\x12\x00"
    crx = b"Cr24" + (3).to_bytes(4, "little") + len(hdr).to_bytes(4, "little") + hdr + buf.getvalue()
    r = ba.audit_bytes(crx, "crx3")
    fails += check("crx3 round trip", r["risk_level"] == "CRITICAL", r["risk_level"])
    r = ba.audit_bytes(buf.getvalue(), "xpi")
    fails += check("xpi/zip round trip", r["risk_level"] == "CRITICAL", r["risk_level"])
    # --text input
    r = ba.scan("fetch(u).then(r=>r.text()).then(x=>eval(x))")
    fails += check("--text malicious", r["risk_level"] == "CRITICAL", r["risk_level"])
    r = ba.scan("document.body.textContent = 'hello'")
    fails += check("--text benign", r["risk_level"] == "SAFE", r["risk_level"])
    fails += check("chrome id validation", _raises(lambda: ba.chrome_url("not-an-id")), "ValueError")
    # performance: a 6 MB single-line minified bundle with a 3 MB embedded blob must scan fast
    big = ("var a=function(b){return b+1};" * 100000) + '"' + ("QUJD" * 750000) + '"' + (";x=fetch(y)" * 20000)
    t0 = time.time()
    ba.scan(big, "big.js", content_script=False)
    dt = time.time() - t0
    fails += check("6 MB single-line bundle", dt < 8, "%.2fs" % dt)
    print("\n%d failure(s)" % fails)
    return 1 if fails else 0


def _raises(fn):
    try:
        fn()
    except ValueError:
        return True
    return False


if __name__ == "__main__":
    sys.exit(main())
