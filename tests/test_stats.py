"""The README's generated number sections must match family_stats.json (offline check).

Regenerate both with `python3 scripts/gen_stats.py` (reads the scanners' docs at the vendored
commits); this test only re-renders the README from the committed JSON.
"""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.path.insert(0, ROOT)
import gen_stats  # noqa: E402
import sca  # noqa: E402


class StatsTest(unittest.TestCase):
    def test_readme_matches_family_stats(self):
        st = json.load(open(gen_stats.STATS, encoding="utf-8"))
        text = open(gen_stats.README, encoding="utf-8").read()
        self.assertEqual(gen_stats.render_readme(text, st), text,
                         "README number sections are stale: run python3 scripts/gen_stats.py --render-only")

    def test_sources_cover_every_scanner(self):
        src = json.load(open(gen_stats.SOURCES, encoding="utf-8"))["repos"]
        self.assertEqual(sorted(src), sorted(a["repo"] for a in sca.ADAPTERS.values()))
        for repo, s in src.items():
            self.assertIn("calibration_n", s["quotes"], repo)

    def test_family_stats_at_vendored_commits(self):
        st = json.load(open(gen_stats.STATS, encoding="utf-8"))
        vers = sca.versions()
        for r in st["repos"]:
            self.assertEqual(r["docs_commit"], vers[r["repo"]]["commit"],
                             "%s: family_stats.json is from another commit than the vendored scanner; "
                             "run python3 scripts/gen_stats.py" % r["repo"])

    def test_quote_extraction(self):
        class D:
            def get(self, repo, commit, name):
                return "| Calibration (1,375) | Held-out (800) |\nfound **two**\nsum 3 and\n  4 here"
        ex = lambda q: gen_stats.extract(q, "r", "c" * 40, D(), "FINDINGS.md", "f")  # noqa: E731
        self.assertEqual(ex("Calibration ({#}) | Held-out"), 1375)
        self.assertEqual(ex("sum {#} and {#} here"), 7)
        self.assertEqual(ex(["Calibration ({#})", "Held-out ({#})"]), 2175)
        self.assertEqual(ex({"q": "found **two**", "value": 2}), 2)
        with self.assertRaises(gen_stats.Drift):
            ex("Calibration ({#}) | Tuning")


if __name__ == "__main__":
    unittest.main()
