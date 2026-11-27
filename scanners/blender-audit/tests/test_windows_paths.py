"""Import-graph resolution must not depend on the host's path separator.

Scanned paths are always "/"-separated, so on Windows `os.path` (ntpath) used to build
"core\\sync.py" and never matched "core/sync.py", hiding a submodule stealer. Simulate
Windows by swapping ntpath in while the package is analysed.
"""
import ntpath
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import blender_audit as ba  # noqa: E402


class WindowsPaths(unittest.TestCase):
    def test_submodule_stealer_found_with_ntpath(self):
        got = ba.read_path(os.path.join(HERE, "fixtures", "mal-submodule-stealer"))
        files = got[0] if isinstance(got, tuple) else got
        with mock.patch.object(ba.os, "path", ntpath):
            r = ba.scan_package(files, "mal-submodule-stealer")
        self.assertEqual(r["risk_level"], "CRITICAL", [f.get("id") for f in r["findings"]])


if __name__ == "__main__":
    unittest.main()
