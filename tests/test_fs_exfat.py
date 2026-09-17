"""Unit tests for the exFAT parser (engine.fs.exfat).

The image comes from tests/imagebuild_fat.build_exfat() and is opened the
way the server opens evidence: ewf.open_image -> volume.scan -> OffsetReader
-> ntfs.open_fs (the filesystem dispatcher).
"""

import os
import random
import struct
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import imagebuild_fat as build                                   # noqa: E402
from test_fs_fat import BytesImage, ImageFiles, by_name, \
    open_first_volume                                            # noqa: E402
from engine import volume                                        # noqa: E402
from engine.ewf import OffsetReader                              # noqa: E402
from engine.fs import exfat, ntfs                                # noqa: E402
from engine.fs.streams import UnsupportedStream                  # noqa: E402

C = build.EXFAT_CLUSTER
L = build.EXFAT_LAYOUT


class Exfat(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.files = ImageFiles()
        cls.data = build.build_exfat()
        cls.image = cls.files.open(cls.data)
        cls.layout, cls.part, cls.fs = open_first_volume(cls.image)
        cls.root = by_name(cls.fs.listdir(0))

    @classmethod
    def tearDownClass(cls):
        cls.files.close()

    # -- boot record and volume metadata ---------------------------------

    def test_dispatcher_and_probe(self):
        self.assertIsInstance(self.fs, exfat.ExfatFS)
        self.assertEqual(volume.identify_fs(self.image, 0), "exFAT")
        self.assertEqual(self.part["detected"], "exFAT")
        self.assertEqual(self.part["label"], build.EXFAT_LABEL)

    def test_boot_record_fields(self):
        info = self.fs.info()
        self.assertEqual(info["bytes_per_sector"], 512)
        self.assertEqual(info["sectors_per_cluster"], 2)
        self.assertEqual(info["cluster_size"], C)
        self.assertEqual(info["cluster_count"], build.EXFAT_CLUSTERS)
        self.assertEqual(info["fat_count"], 1)
        self.assertEqual(info["first_data_offset"],
                         build.EXFAT_HEAP_OFFSET * 512)
        self.assertEqual(info["root_cluster"], L["root"][0])
        self.assertEqual(info["serial"], "%08X" % build.EXFAT_SERIAL)
        self.assertEqual(info["revision"], "1.0")
        self.assertEqual(info["percent_in_use"], 30)
        self.assertFalse(info["volume_dirty"])
        self.assertEqual(info["label"], build.EXFAT_LABEL)

    def test_allocation_bitmap(self):
        self.assertEqual(self.fs._bitmap_start, L["bitmap"])
        bitmap = self.fs._load_bitmap()
        self.assertEqual(len(bitmap), (build.EXFAT_CLUSTERS + 7) // 8)

        def allocated(c):
            return bool(bitmap[(c - 2) // 8] >> ((c - 2) % 8) & 1)

        for c in (L["bitmap"], L["upcase"], L["hello"]["cluster"],
                  L["contiguous"]["cluster"] + 2, L["subdir"]["cluster"] + 1):
            self.assertTrue(allocated(c), c)
        self.assertFalse(allocated(L["deleted"]["cluster"]))
        self.assertFalse(allocated(40))
        # The bitmap's own cluster is reported as allocated space.
        off = self.fs.cluster_offset(L["bitmap"])
        self.assertIn((off, off + C), self.fs.allocated_extents())

    def test_up_case_table_is_metadata_not_a_file(self):
        # The up-case entry sits between the bitmap entry and the files;
        # it must neither appear as a file nor stop the root scan.
        names = set(self.root)
        self.assertFalse(any("upcase" in n.lower() for n in names))
        self.assertIn("Hello.txt", names)
        table = self.fs.source.read_at(self.fs.cluster_offset(L["upcase"]),
                                       256)
        self.assertEqual(table, build.upcase_table())

    # -- directory listing ------------------------------------------------

    def test_root_listing(self):
        self.assertEqual(set(self.root), {
            "Hello.txt", "Fragmented file.bin", "Contiguous.dat",
            "Deleted file.txt", "Timezone.txt", "Empty.txt",
            build.EXFAT_LONG_NAME, "Subdir", "Tail.txt"})
        # Directories sort first.
        self.assertEqual(self.fs.listdir(0)[0]["name"], "Subdir")
        self.assertTrue(self.root["Subdir"]["is_dir"])
        self.assertTrue(self.root["Subdir"]["contiguous"])

    def test_root_directory_follows_its_fat_chain(self):
        self.assertEqual(self.fs.chain(L["root"][0]), list(L["root"]))
        tail = self.root["Tail.txt"]           # entry set straddles clusters
        self.assertEqual(self.fs.read_file(tail), b"tail")

    def test_three_part_file_name(self):
        e = self.root[build.EXFAT_LONG_NAME]
        self.assertEqual(e["path"], "/" + build.EXFAT_LONG_NAME)
        self.assertEqual(self.fs.read_file(e), b"long name\n")

    def test_timestamps_and_attributes(self):
        e = self.root["Hello.txt"]
        self.assertEqual(e["modified"], "2023-11-05T08:30:44Z")
        self.assertEqual(e["accessed"], "2023-11-05T08:30:44Z")
        self.assertEqual(e["attributes"], ["archive"])

    # The offset bytes (spec 7.4.10) now shift the local timestamp into UTC:
    # 10:00 at +12:00 is 22:00 UTC the previous day.
    def test_timestamp_honours_utc_offset(self):
        self.assertEqual(self.root["Timezone.txt"]["created"],
                         "2024-05-31T22:00:00Z")

    def test_subdirectory_first_cluster(self):
        sub = self.root["Subdir"]
        inner = by_name(self.fs.listdir(sub["start_cluster"], "/Subdir"))
        self.assertIn("Inner.txt", inner)
        self.assertEqual(inner["Inner.txt"]["path"], "/Subdir/Inner.txt")
        self.assertEqual(self.fs.read_file(inner["Inner.txt"]), b"inner\n")

    # Bug: exfat.py listdir() always walks the FAT; a NoFatChain directory's
    # FAT entries are zero, so only its first cluster is read and entries
    # in later clusters (here Second.txt in cluster 18) are never listed.
    @unittest.expectedFailure
    def test_contiguous_subdirectory_second_cluster_listed(self):
        sub = self.root["Subdir"]
        inner = by_name(self.fs.listdir(sub["start_cluster"], "/Subdir"))
        self.assertIn("Second.txt", inner)

    # -- file content ------------------------------------------------------

    def test_fat_chain_stream(self):
        e = self.root["Fragmented file.bin"]
        self.assertFalse(e["contiguous"])
        want = build.exfat_fragmented_content()
        self.assertEqual(self.fs.read_file(e), want)
        self.assertEqual(self.fs.read_file(e, max_bytes=1500), want[:1500])
        self.assertEqual(self.fs.read_range(e, 1000, 1100), want[1000:2100])
        runs = self.fs.runs(e)
        self.assertEqual([(r["cluster"], r["clusters"], r["used"])
                          for r in runs], [(7, 1, C), (9, 1, C), (8, 1, 452)])

    def test_no_fat_chain_contiguous_stream(self):
        e = self.root["Contiguous.dat"]
        self.assertTrue(e["contiguous"])
        # Nothing in the FAT describes this file; the extent comes from the
        # stream extension alone.
        c0 = L["contiguous"]["cluster"]
        for c in range(c0, c0 + L["contiguous"]["count"]):
            self.assertEqual(self.fs._fat_entry(c), 0)
        want = build.exfat_contiguous_content()
        self.assertEqual(self.fs.read_file(e), want)
        self.assertEqual(self.fs.read_range(e, 2000, 2000), want[2000:])
        runs = self.fs.runs(e)
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["offset"], self.fs.cluster_offset(c0))
        self.assertEqual(runs[0]["length"], 3 * C)
        self.assertEqual(runs[0]["used"], 3000)
        self.assertTrue(self.fs.stat(e)["contiguous"])

    def test_empty_file(self):
        e = self.root["Empty.txt"]
        self.assertEqual(self.fs.read_file(e), b"")
        self.assertEqual(self.fs.read_range(e, 0, 10), b"")
        self.assertIsNone(self.fs.slack(e))
        self.assertEqual(self.fs.runs(e), [])

    def test_named_streams_are_refused(self):
        with self.assertRaises(UnsupportedStream):
            self.fs.read_file(self.root["Hello.txt"], stream="ads")

    def test_deleted_entry(self):
        e = self.root["Deleted file.txt"]
        self.assertTrue(e["deleted"])
        self.assertTrue(e["contiguous"])
        self.assertEqual(e["size"], 100)
        self.assertEqual(self.fs.read_file(e), build.pattern(100, 13))
        self.assertIn("contiguous", self.fs.stat(e)["recovery"])
        # Deleted files are not allocated space.
        off = self.fs.cluster_offset(L["deleted"]["cluster"])
        self.assertNotIn(off, {s for s, _ in self.fs.allocated_extents()})

    def test_slack(self):
        e = self.root["Hello.txt"]
        n = len(build.EXFAT_HELLO)
        slack = self.fs.slack(e)
        self.assertEqual(slack, {
            "offset": self.fs.cluster_offset(L["hello"]["cluster"]) + n,
            "length": C - n})
        self.assertEqual(self.fs.source.read_at(slack["offset"],
                                                slack["length"]),
                         build.fill(C - n, build.SLACK_MARK))
        self.assertEqual(self.fs.stat(e)["slack"], slack)

        cont = self.fs.slack(self.root["Contiguous.dat"])
        self.assertEqual(cont, {
            "offset": self.fs.cluster_offset(L["contiguous"]["cluster"] + 2)
            + (3000 - 2 * C),
            "length": 3 * C - 3000})
        self.assertIsNone(self.fs.slack(self.root["Subdir"]))


class ExfatRobustness(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.good = build.build_exfat()

    def open_bytes(self, data):
        return ntfs.open_fs(OffsetReader(BytesImage(data), 0, len(data)))

    def test_truncated_to_boot_sector(self):
        files = ImageFiles()
        self.addCleanup(files.close)
        image = files.open(self.good[:512])
        try:
            fs = ntfs.open_fs(OffsetReader(image, 0, image.size))
        except ValueError:
            return
        self.assertEqual(fs.listdir(0), [])

    def test_truncated_mid_heap(self):
        fs = self.open_bytes(self.good[:self.good.index(b"Hello, exFAT")])
        for e in fs.listdir(0):
            self.assertIsInstance(fs.read_file(e), bytes)

    def test_implausible_shifts_rejected(self):
        for at, value in ((108, 0), (108, 20), (109, 40)):
            data = bytearray(self.good)
            data[at] = value
            with self.subTest(offset=at, value=value):
                with self.assertRaises(ValueError):
                    exfat.ExfatFS(BytesImage(data))

    def test_signature_only_is_not_exfat(self):
        data = bytearray(self.good)
        data[3:11] = b"EXFAX   "
        with self.assertRaises(ValueError):
            exfat.ExfatFS(BytesImage(data))

    def fat_offset(self, cluster):
        return build.EXFAT_FAT_OFFSET * 512 + cluster * 4

    def test_root_chain_loop_terminates(self):
        data = bytearray(self.good)
        struct.pack_into("<I", data, self.fat_offset(L["root"][1]),
                         L["root"][0])
        fs = exfat.ExfatFS(BytesImage(data))
        self.assertEqual(fs.chain(L["root"][0]), list(L["root"]))
        self.assertEqual(len(fs.listdir(0)), 9)

    def test_absurd_secondary_count(self):
        data = bytearray(self.good)
        # Tail.txt's set straddles root clusters 4 and 15; its File entry is
        # the last entry of cluster 4.
        file_entry = (build.EXFAT_HEAP_OFFSET * 512
                      + (L["root"][0] - 2) * C + C - 32)
        self.assertEqual(data[file_entry], 0x85)
        data[file_entry + 1] = 0xFF
        fs = exfat.ExfatFS(BytesImage(data))
        self.assertIsInstance(fs.listdir(0), list)

    def test_random_entry_header_damage_does_not_crash(self):
        # Damage confined to each entry's type, secondary-count, flag and
        # name-length bytes. Length fields are left alone: a huge
        # NoFatChain length is the unbounded case tested separately below.
        root = build.EXFAT_HEAP_OFFSET * 512 + (L["root"][0] - 2) * C
        rng = random.Random(4321)
        for trial in range(40):
            data = bytearray(self.good)
            for _ in range(12):
                data[root + rng.randrange(0, C // 32) * 32
                     + rng.randrange(0, 4)] = rng.getrandbits(8)
            with self.subTest(trial=trial):
                fs = exfat.ExfatFS(BytesImage(data))
                for e in fs.listdir(0):
                    if not e["is_dir"] and e["size"] <= 1 << 20:
                        fs.read_file(e, max_bytes=1 << 16)
                        fs.stat(e)

    # Bug: exfat.py chain() (line 86) expands a NoFatChain stream into one
    # list element per cluster from the untrusted length, unbounded by the
    # cluster count, so a corrupt length of 2^50 means a 2^40-element list
    # (hang / MemoryError) on any read. Kept small here: 64 MiB, 65536 items.
    def test_contiguous_run_bounded_by_cluster_heap(self):
        data = bytearray(self.good)
        stream = self.good.index("Contiguous.dat".encode("utf-16-le")) - 34
        self.assertEqual(data[stream], 0xC0)
        struct.pack_into("<Q", data, stream + 24, 64 << 20)
        fs = exfat.ExfatFS(BytesImage(data))
        e = by_name(fs.listdir(0))["Contiguous.dat"]
        heap_end = fs.cluster_offset(fs.cluster_count + 2)
        for r in fs.runs(e):
            self.assertLessEqual(r["offset"] + r["length"], heap_end)

    def test_random_garbage_is_not_exfat(self):
        rng = random.Random(5)
        junk = bytes(rng.getrandbits(8) for _ in range(16384))
        with self.assertRaises(ValueError):
            exfat.ExfatFS(BytesImage(junk))


if __name__ == "__main__":
    unittest.main()
