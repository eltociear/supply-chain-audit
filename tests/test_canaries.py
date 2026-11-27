"""Every vendored scanner's own malicious canaries, replayed through sca, must come out with
max_severity >= the level the scanner's own test suite expects; every benign control must stay
at or below its ceiling (MEDIUM, or HIGH where the upstream suite explicitly allows it)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import canaries  # noqa: E402


class Canaries(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = canaries.run_all(jobs=int(os.environ.get("SCA_TEST_JOBS", "3")))

    def test_every_scanner_has_canaries(self):
        mal = {r["eco"] for r in self.rows if r["kind"] == "malicious"}
        self.assertEqual(mal, set(canaries.sca.ADAPTERS))

    def test_malicious_reach_expected_level(self):
        for r in self.rows:
            if r["kind"] == "malicious":
                with self.subTest("%s/%s" % (r["eco"], r["name"])):
                    self.assertTrue(r["ok"], r["why"])

    def test_expected_rule_survives_normalisation(self):
        for r in self.rows:
            if r["kind"] == "malicious" and r["ok"]:
                with self.subTest("%s/%s" % (r["eco"], r["name"])):
                    self.assertTrue(r["rule_ok"], (r["want_rules"], r["rules"]))

    def test_benign_controls_stay_quiet(self):
        for r in self.rows:
            if r["kind"] == "benign":
                with self.subTest("%s/%s" % (r["eco"], r["name"])):
                    self.assertTrue(r["ok"], r["why"])


if __name__ == "__main__":
    unittest.main()
