"""Install-script reference following must not depend on the host path separator.

Package paths are always "/"-separated; with ntpath (Windows) the old code built
"src\\postinstall.js", never matched, and mal-spawned-payload dropped from CRITICAL to
HIGH. Simulate Windows by swapping ntpath in while the package is analysed.
"""
import ntpath
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import npm_audit as na  # noqa: E402


class WindowsPaths(unittest.TestCase):
    def test_spawned_payload_stays_critical_with_ntpath(self):
        d = os.path.join(HERE, "fixtures", "mal-spawned-payload")
        files = na.files_from_dir(d)
        base = na.scan_package(files, d)
        with mock.patch.object(na.os, "path", ntpath):
            win = na.scan_package(files, d)
        self.assertEqual(base["risk_level"], "CRITICAL")
        self.assertEqual(win["risk_level"], "CRITICAL", [f.get("id") for f in win["findings"]])


if __name__ == "__main__":
    unittest.main()
