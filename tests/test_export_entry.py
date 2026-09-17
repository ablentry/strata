"""A caller that has only a filesystem handle -- not a full listdir() entry
-- must still get a correctly read, correctly recorded export. The bulk
"export tagged items" action in the UI is the one in-app case: a tagged
item is stored by handle (engine.casedb tagged_items), and the client used
to send only part/node/name/path, dropping deleted/modified/... on the way
back to engine.server._export_one.

Issue #85 (carried roadmap item): the export manifest's `modified` came out
blank for a node-only export. Following it further: engine.fs.fat.FatFS
(and ext4) read a *deleted* entry differently from a live one, so dropping
`deleted` the same way did not just leave a manifest field blank -- it read
a deleted, fragmented FAT file as if it were live, silently truncating it
to its first cluster.
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import imagebuild_fat as build                                    # noqa: E402
from test_fs_fat import ImageFiles, by_name, open_first_volume     # noqa: E402
from engine import server                                          # noqa: E402


class FakeCase:
    """The two Case members _export_one touches, without a real case db."""
    examiner = "tester"

    def __init__(self):
        self.logged = []

    def log(self, action, detail=None):
        self.logged.append((action, detail))


class FakeSession:
    def __init__(self):
        self.case = FakeCase()


class ExportByNodeAlone(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.files = ImageFiles()
        cls.image = cls.files.open(build.build_fat(16))
        cls.layout, cls.part, cls.fs = open_first_volume(cls.image)
        cls.root = by_name(cls.fs.listdir(0))

    @classmethod
    def tearDownClass(cls):
        cls.files.close()

    def setUp(self):
        self.out_dir = tempfile.mkdtemp(prefix="strata-export-test-")
        self.addCleanup(shutil.rmtree, self.out_dir, ignore_errors=True)
        self.session = FakeSession()

    def test_entry_from_body_carries_metadata_through(self):
        e = self.root["_ELETED.TXT"]
        body = {"node": e["start_cluster"], "name": e["name"],
               "path": e["path"], "size": e["size"], "deleted": True,
               "modified": e["modified"], "accessed": e["accessed"],
               "created": e["created"]}
        got = server._entry_from_body(self.fs, body)
        self.assertEqual(got["start_cluster"], e["start_cluster"])
        self.assertEqual(got["size"], e["size"])
        self.assertTrue(got["deleted"])
        self.assertEqual(got["modified"], e["modified"])
        self.assertEqual(got["accessed"], e["accessed"])
        self.assertEqual(got["created"], e["created"])

    def test_deleted_flag_missing_reads_live_and_truncates(self):
        # What the bulk export used to send: no deleted flag at all. Kept as
        # a regression guard on _entry_from_body's default, not a defence of
        # this behaviour -- it silently truncates a deleted, fragmented FAT
        # file to its first cluster, exactly the bug #85 led to.
        e = self.root["_ELETED.TXT"]
        body = {"node": e["start_cluster"], "name": e["name"],
               "path": e["path"], "size": e["size"]}
        entry = server._entry_from_body(self.fs, body)
        self.assertFalse(entry["deleted"])
        rec, path, written = server._export_one(
            self.fs, entry, self.out_dir, self.session, manifest=False)
        self.assertLess(written, e["size"])
        self.assertIsNone(rec["modified"])

    def test_deleted_flag_forwarded_exports_full_content(self):
        e = self.root["_ELETED.TXT"]
        body = {"node": e["start_cluster"], "name": e["name"],
               "path": e["path"], "size": e["size"], "deleted": True,
               "modified": e["modified"]}
        entry = server._entry_from_body(self.fs, body)
        rec, path, written = server._export_one(
            self.fs, entry, self.out_dir, self.session, manifest=False)
        self.assertEqual(written, e["size"])
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), self.fs.read_file(e))
        self.assertEqual(rec["modified"], e["modified"])
        self.assertTrue(rec["deleted"])


if __name__ == "__main__":
    unittest.main()
