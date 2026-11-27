"""Auto-detection: every fixture dir under tests/fixtures/detect maps to exactly these targets."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import sca  # noqa: E402

B = os.path.join(HERE, "fixtures", "detect")

EXPECTED = {  # fixture dir -> {(ecosystem, target relative to the fixture)}
    "aur": {("aur", ".")},
    "blender": {("blender", ".")},
    "blender-ext": {("blender", ".")},
    "browserext": {("browserext", ".")},
    "comfyui": {("comfyui", ".")},
    "crate": {("crate", ".")},
    "gha": {("gha", ".")},
    "gha-workflow": {("gha", ".github/workflows/ci.yml")},
    "gomod": {("gomod", ".")},
    "hacs": {("hacs", ".")},                       # hacs.json root absorbs custom_components/*
    "hacs-component": {("hacs", ".")},
    "hf": {("hf", ".")},
    "homebrew": {("homebrew", "Formula")},
    "homebrew-single": {("homebrew", "demo.rb")},
    "mcp": {("mcp", "."), ("npm", "."), ("repo-trust", ".")},
    "mcp-py": {("mcp", "."), ("pypi", ".")},
    "monorepo": {("repo-trust", "."), ("npm", "."), ("gha", ".github/workflows/ci.yml"), ("terraform", "infra"),
                 ("pypi", "services/api"), ("gomod", "tools/cli")},  # node_modules/ is pruned
    "none": set(),
    "npm": {("npm", "."), ("repo-trust", ".")},
    "nuget": {("nuget", ".")},
    "nuget-csproj": set(),                         # PackageReferences need --deps
    "obsidian": {("obsidian", ".")},
    "packagist": {("packagist", ".")},
    "pypi": {("pypi", ".")},
    "repo-trust": {("repo-trust", ".")},
    "rubygems": {("rubygems", ".")},
    "terraform": {("terraform", ".")},
    "userscript": {("userscript", "demo.user.js")},
    "vimplugin": {("vimplugin", ".")},
    "vimplugin-lua": {("vimplugin", ".")},
    "vsix": {("vsix", "."), ("repo-trust", ".")},  # engines.vscode: not handed to npm-audit
    "winpkg-choco": {("winpkg", ".")},             # chocolateyInstall.ps1 wins over the .nuspec
    "winpkg-scoop": {("winpkg", "demo.json")},
    "winpkg-winget": {("winpkg", "Demo.Demo.installer.yaml")},
    "wordpress": {("wordpress", "demo")},
}


def got(name, deps=False, skipped=None):
    root = os.path.join(B, name)
    return {(x["ecosystem"], os.path.relpath(x["target"], root).replace(os.sep, "/"))
            for x in sca.detect(root, deps=deps, skipped=skipped)}


class Detect(unittest.TestCase):
    def test_every_fixture_has_an_expectation(self):
        self.assertEqual(set(os.listdir(B)), set(EXPECTED))

    def test_fixtures(self):
        for name, want in sorted(EXPECTED.items()):
            with self.subTest(name):
                self.assertEqual(got(name), want)

    def test_every_ecosystem_is_detectable(self):
        seen = {e for w in EXPECTED.values() for e, _ in w}
        self.assertEqual(seen, set(sca.ADAPTERS))

    def test_deps_are_skipped_offline_and_listed(self):
        skipped = []
        got("monorepo", skipped=skipped)
        self.assertEqual({(x["ecosystem"], os.path.basename(x["target"])) for x in skipped},
                         {("npm", "package-lock.json"), ("gomod", "go.mod")})
        skipped = []
        self.assertEqual(got("nuget-csproj", skipped=skipped), set())
        self.assertEqual([x["ecosystem"] for x in skipped], ["nuget"])

    def test_deps_mode_adds_registry_runs(self):
        root = os.path.join(B, "monorepo")
        net = {(x["ecosystem"], tuple(a if not os.path.isabs(a) and not a.startswith(B) else os.path.basename(a)
                                      for a in x["args"]))
               for x in sca.detect(root, deps=True) if x["network"]}
        self.assertIn(("npm", ("--lockfile", "package-lock.json")), net)
        self.assertIn(("gomod", ("--gomod", "go.mod")), net)
        self.assertIn(("gha", ("--workflow", "ci.yml")), net)  # actions are fetched with --deps
        offline = [x for x in sca.detect(root) if x["ecosystem"] == "gha"]
        self.assertIn("--no-fetch", offline[0]["args"])
        csproj = sca.detect(os.path.join(B, "nuget-csproj"), deps=True)
        self.assertEqual([(x["ecosystem"], x["args"][0]) for x in csproj], [("nuget", "--project")])

    def test_single_files(self):
        cases = {
            "userscript/demo.user.js": "userscript", "homebrew-single/demo.rb": "homebrew",
            "terraform/main.tf": "terraform", "gha/action.yml": "gha", "aur/PKGBUILD": "aur",
            "winpkg-winget/Demo.Demo.installer.yaml": "winpkg", "winpkg-scoop/demo.json": "winpkg",
            "nuget/Demo.nuspec": "nuget", "nuget/build/Demo.targets": "nuget", "wordpress/demo/demo.php": "wordpress",
            "obsidian/manifest.json": "obsidian", "browserext/manifest.json": "browserext", "hf/config.json": "hf",
            "gha-workflow/.github/workflows/ci.yml": "gha", "crate/Cargo.toml": "crate", "gomod/go.mod": "gomod",
        }
        for rel, eco in sorted(cases.items()):
            with self.subTest(rel):
                d = sca.detect(os.path.join(B, rel))
                self.assertEqual([x["ecosystem"] for x in d], [eco])

    def test_mcp_entry_selection_mirrors_mcp_audit(self):
        files = [os.path.relpath(p, os.path.join(B, "mcp")).replace(os.sep, "/")
                 for p in sca.mcp_entry_files(os.path.join(B, "mcp"))]
        self.assertEqual(files[0], "package.json")
        self.assertIn("src/index.ts", files)  # main: dist/index.js mapped back to src/


if __name__ == "__main__":
    unittest.main()
