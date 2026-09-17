"""Unit tests for hosted sparse VMDK extents (engine.vmdk): monolithicSparse
and streamOptimized, fed images from imagebuild_vmdk. The flat extent's
confinement to its descriptor's folder is covered in test_vmdk_extent.py."""

import hashlib
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import imagebuild_vmdk as build                                   # noqa: E402
from engine import ewf, vmdk                                      # noqa: E402

G = build.GRAIN
MEDIA = build.media()


class VmdkCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="strata-vmdk-test-")
        self.addCleanup(self._tmp.cleanup)

    def open(self, data, name="disk.vmdk"):
        path = os.path.join(self._tmp.name, name)
        with open(path, "wb") as fh:
            fh.write(data)
        img = ewf.open_image(path)
        self.addCleanup(img.close)
        return img

    def stream(self, mutator):
        return self.open(build.build_stream_optimized(mutator)[0])


class Sparse(VmdkCase):
    def setUp(self):
        super(Sparse, self).setUp()
        self.img = self.open(build.build_sparse())

    def test_opens_as_sparse_vmdk(self):
        self.assertIsInstance(self.img, vmdk.VmdkImage)
        info = self.img.info()
        self.assertEqual(info["format"], "VMware VMDK (sparse)")
        self.assertEqual(info["size"], len(MEDIA))
        self.assertEqual(info["chunk_size"], G)
        self.assertEqual(info["acquisition"]["create type"],
                         "monolithicSparse")
        self.assertEqual(info["acquisition"]["adapter"], "lsilogic")
        self.assertEqual(info["acquisition"]["grain tables present"],
                         "2 of 2")
        self.assertEqual(self.img.findings, [])

    def test_reads_back_with_unallocated_grains_as_zeros(self):
        self.assertEqual(self.img.read_at(0, len(MEDIA)), MEDIA)
        self.assertEqual(self.img.read_at(2 * G, G), bytes(G))

    def test_reads_across_grain_and_table_boundaries(self):
        for off, n in ((G - 7, 20), (4 * G - 100, 200), (3 * G, 3 * G),
                       (len(MEDIA) - 5, 50)):
            self.assertEqual(self.img.read_at(off, n), MEDIA[off:off + n])
        self.assertEqual(self.img.read_at(len(MEDIA), 10), b"")

    def test_verify_hashes_the_virtual_disk(self):
        got = self.img.verify()
        self.assertEqual(got["computed_md5"], hashlib.md5(MEDIA).hexdigest())
        self.assertIsNone(got["md5_match"])


class StreamOptimized(VmdkCase):
    def setUp(self):
        super(StreamOptimized, self).setUp()
        self.data, self.offsets = build.build_stream_optimized()
        self.img = self.open(self.data)

    def test_opens_from_the_footer(self):
        info = self.img.info()
        self.assertEqual(info["format"], "VMware VMDK (stream-optimized)")
        self.assertEqual(info["size"], len(MEDIA))
        self.assertEqual(info["acquisition"]["create type"], "streamOptimized")
        self.assertEqual(len(self.img.findings), 1)
        self.assertIn("footer", self.img.findings[0])

    def test_reads_back(self):
        self.assertEqual(self.img.read_at(0, len(MEDIA)), MEDIA)
        self.assertEqual(self.img.verify()["computed_md5"],
                         hashlib.md5(MEDIA).hexdigest())

    def test_cut_before_the_footer_is_refused(self):
        with self.assertRaises(ewf.UnsupportedContainer):
            self.open(self.data[:self.offsets[6]], "cut.vmdk")

    def test_grain_that_will_not_inflate_reads_as_zeros(self):
        def corrupt(g, comp):
            return comp if g != 1 else b"\x00" * len(comp)
        img = self.stream(corrupt)
        got = img.read_at(0, len(MEDIA))
        self.assertEqual(got[G:2 * G], bytes(G))
        self.assertEqual(got[:G] + got[2 * G:], MEDIA[:G] + MEDIA[2 * G:])
        self.assertTrue(any("would not inflate" in f for f in img.findings))

    # Bug: engine/vmdk.py _grain() zero-pads a grain whose compressed stream
    # ends early without a finding, so part-lost data reads as if the disk
    # held zeros there. Offsets are kept; only the report is missing.
    @unittest.expectedFailure
    def test_grain_whose_stream_ends_early_is_reported(self):
        img = self.stream(lambda g, comp: comp[:len(comp) // 2]
                          if g == 1 else comp)
        got = img.read_at(0, len(MEDIA))
        self.assertEqual(got[3 * G:], MEDIA[3 * G:])
        self.assertTrue(any("grain" in f.lower() and "incomplete" in f.lower()
                            for f in img.findings), img.findings)


class Damaged(VmdkCase):
    """Header fields found by the fuzzer (tests/fuzz.py, vmdk targets)."""

    @staticmethod
    def patch(data, at, fmt, value):
        data = bytearray(data)
        struct.pack_into(fmt, data, at, value)
        return bytes(data)

    def assertRefusedOrOpens(self, data):
        try:
            img = self.open(data, "damaged.vmdk")
        except ewf.UnsupportedContainer:
            return
        img.read_at(0, 4 * G)

    # Bug: engine/vmdk.py _read_tables() divides by numGTEsPerGT unchecked.
    @unittest.expectedFailure
    def test_zero_grain_table_size(self):
        self.assertRefusedOrOpens(
            self.patch(build.build_sparse(), 44, "<I", 0))

    # Bug: engine/vmdk.py _read_tables() sizes the grain directory from the
    # capacity alone, so a huge capacity asks for a directory of that size.
    @unittest.expectedFailure
    def test_huge_capacity_in_footer(self):
        data, _ = build.build_stream_optimized()
        footer = len(data) - 2 * build.SECTOR
        self.assertRefusedOrOpens(
            self.patch(data, footer + 12, "<Q", 1 << 62))

    # Bug: engine/vmdk.py _load() reads descriptorSize sectors unchecked.
    @unittest.expectedFailure
    def test_huge_descriptor_size(self):
        self.assertRefusedOrOpens(
            self.patch(build.build_sparse(), 36, "<Q", 1 << 47))


if __name__ == "__main__":
    unittest.main()
