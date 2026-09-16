"""Unit tests for image containers (engine.ewf): EWF v1 segment sets, raw
images, split raw sets and OffsetReader, fed files from imagebuild_ewf."""

import hashlib
import io
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import imagebuild_ewf as build                                    # noqa: E402
from engine import ewf                                            # noqa: E402

MEDIA = build.media()                  # 14 sectors: 3 full chunks + 1 short


class TempDir(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="strata-ewf-test-")
        self.addCleanup(self._tmp.cleanup)
        self.dir = self._tmp.name

    def write(self, name, data):
        path = os.path.join(self.dir, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def write_segments(self, segments, stem="x"):
        paths = [self.write(os.path.basename(n), s) for n, s in
                 zip(build.segment_names(stem, len(segments)), segments)]
        return paths[0]

    def open(self, path):
        img = ewf.open_image(path)
        self.addCleanup(img.close)
        return img


class SingleSegment(TempDir):
    def setUp(self):
        super(SingleSegment, self).setUp()
        self.img = self.open(self.write_segments(build.build_e01()))

    def test_opens_as_ewf(self):
        self.assertIsInstance(self.img, ewf.EwfImage)

    def test_volume_geometry(self):
        info = self.img.info()
        self.assertEqual(info["format"], "EWF v1 (E01)")
        self.assertEqual(info["segments"], ["x.E01"])
        self.assertEqual(info["size"], len(MEDIA))
        self.assertEqual(info["sector_count"], 14)
        self.assertEqual(info["bytes_per_sector"], 512)
        self.assertEqual(info["sectors_per_chunk"], build.SECTORS_PER_CHUNK)
        self.assertEqual(info["chunk_size"], build.CHUNK_SIZE)
        self.assertEqual(info["chunk_count"], 4)
        self.assertEqual(info["compressed_chunks"], 2)
        self.assertEqual(info["media_type"], 1)
        self.assertEqual(info["compression_level"], 1)
        self.assertEqual(info["findings"], [])

    def test_header_section(self):
        acq = self.img.info()["acquisition"]
        self.assertEqual(acq["case_number"], "CASE-1")
        self.assertEqual(acq["evidence_number"], "EV-7")
        self.assertEqual(acq["examiner"], "Examiner")
        self.assertEqual(acq["acquisition_date"], "2026 9 16 10 0 0")

    def test_read_back_mixed_chunks(self):
        self.assertEqual(self.img.read_at(0, len(MEDIA)), MEDIA)
        self.assertEqual(self.img.findings, [])

    def test_read_across_chunk_boundaries(self):
        for off, n in ((2000, 100), (4095, 2), (6000, 5000), (0, 1)):
            self.assertEqual(self.img.read_at(off, n), MEDIA[off:off + n])

    def test_read_past_end(self):
        self.assertEqual(self.img.read_at(len(MEDIA), 10), b"")
        with self.assertRaises(ValueError):
            self.img.read_at(-1, 10)

    def test_file_like_read_and_seek(self):
        self.img.seek(100)
        self.assertEqual(self.img.read(10), MEDIA[100:110])
        self.assertEqual(self.img.seek(5, io.SEEK_CUR), 115)
        self.img.seek(-12, io.SEEK_END)
        self.assertEqual(self.img.read(), MEDIA[-12:])

    def test_stored_md5_and_verify(self):
        md5 = hashlib.md5(MEDIA).hexdigest()
        self.assertEqual(self.img.stored_md5, md5)
        got = self.img.verify()
        self.assertEqual(got["computed_md5"], md5)
        self.assertEqual(got["computed_sha1"], hashlib.sha1(MEDIA).hexdigest())
        self.assertTrue(got["md5_match"])
        self.assertIsNone(got["stored_sha1"])

    def test_all_uncompressed_and_all_compressed(self):
        for name, fn in (("u", lambda i: False), ("c", lambda i: True)):
            path = self.write_segments(build.build_e01(compress=fn), name)
            img = self.open(path)
            self.assertEqual(img.read_at(0, len(MEDIA)), MEDIA)
            self.assertEqual(img.findings, [])


class SplitSegments(TempDir):
    def test_e01_e02_read_back(self):
        segs = build.build_e01(per_segment=2)
        self.assertEqual(len(segs), 2)
        img = self.open(self.write_segments(segs))
        self.assertEqual(img.info()["segments"], ["x.E01", "x.E02"])
        self.assertEqual(len(img.chunks), 4)
        self.assertEqual([c.seg for c in img.chunks], [0, 0, 1, 1])
        self.assertEqual(img.read_at(0, len(MEDIA)), MEDIA)
        self.assertTrue(img.verify()["md5_match"])
        self.assertEqual(img.findings, [])

    def test_three_segments_opened_from_the_middle(self):
        self.write_segments(build.build_e01(per_segment=1), "m")
        img = self.open(os.path.join(self.dir, "m.E02"))
        self.assertEqual(len(img.segment_paths), 4)
        self.assertEqual(img.read_at(0, len(MEDIA)), MEDIA)

    def test_discover_segments_orders_numerically(self):
        for ext in ("E10", "E02", "E01", "E09"):
            self.write("s." + ext, b"")
        self.write("other.E03", b"")
        got = [os.path.basename(p) for p in
               ewf.discover_segments(os.path.join(self.dir, "s.E01"))]
        self.assertEqual(got, ["s.E01", "s.E02", "s.E09", "s.E10"])

    # Engine bug: engine/ewf.py:58-61 the [A-Z]{3} alternative (IGNORECASE)
    # makes any 3-letter sibling such as x.txt part of the segment set.
    @unittest.expectedFailure
    def test_unrelated_sidecar_file_is_not_a_segment(self):
        path = self.write_segments(build.build_e01())
        self.write("x.txt", b"acquisition notes\n")
        img = self.open(path)
        self.assertEqual(img.read_at(0, len(MEDIA)), MEDIA)


class Integrity(TempDir):
    def corrupt(self, index, fn):
        def mutate(i, raw):
            return fn(raw) if i == index else raw
        img = self.open(self.write_segments(
            build.build_e01(chunk_mutator=mutate)))
        return img, img.read_at(0, len(MEDIA))

    @staticmethod
    def flip(pos):
        def fn(raw):
            b = bytearray(raw)
            b[pos] ^= 0x01
            return bytes(b)
        return fn

    def test_uncompressed_chunk_checksum_mismatch_is_reported(self):
        img, data = self.corrupt(1, self.flip(5))
        self.assertNotEqual(data, MEDIA)
        self.assertTrue(any("Chunk 1" in f and "Adler-32" in f
                            for f in img.findings), img.findings)

    def test_corrupt_compressed_chunk_is_reported(self):
        img, data = self.corrupt(0, self.flip(20))
        self.assertEqual(len(data), len(MEDIA))
        self.assertEqual(data[:build.CHUNK_SIZE], bytes(build.CHUNK_SIZE))
        self.assertTrue(any("Chunk 0" in f for f in img.findings))

    def test_verify_detects_mismatch(self):
        img, _data = self.corrupt(1, self.flip(5))
        self.assertFalse(img.verify()["md5_match"])

    # Engine bug: engine/ewf.py:307-318 (with engine/inflate.py) accepts a
    # zlib stream that ends early: the short chunk is returned, no finding.
    @unittest.expectedFailure
    def test_truncated_compressed_chunk_is_reported(self):
        img, data = self.corrupt(0, lambda raw: raw[:len(raw) // 2])
        self.assertTrue(any("Chunk 0" in f for f in img.findings),
                        "short read (%d of %d bytes) with no finding"
                        % (len(data), len(MEDIA)))

    def test_section_descriptor_checksum_mismatch_is_reported(self):
        seg = bytearray(build.build_e01()[0])
        seg[13 + 60] ^= 0xFF                 # padding of the header section
        img = self.open(self.write_segments([bytes(seg)]))
        self.assertTrue(any("descriptor checksum" in f for f in img.findings))
        self.assertEqual(img.read_at(0, len(MEDIA)), MEDIA)

    def test_table_header_checksum_mismatch_is_reported(self):
        seg = bytearray(build.build_e01()[0])
        table = self.find_section(seg, "table")
        seg[table + build.DESC + 4] ^= 0xFF    # padding inside table header
        img = self.open(self.write_segments([bytes(seg)]))
        self.assertTrue(any("Table header checksum" in f
                            for f in img.findings))

    @staticmethod
    def find_section(seg, type_):
        off = 13
        while True:
            name = bytes(seg[off:off + 16]).split(b"\x00")[0].decode()
            if name == type_:
                return off
            off = struct.unpack_from("<Q", seg, off + 16)[0]


class Robustness(TempDir):
    def test_garbage_after_signature(self):
        path = self.write("g.E01", build.EVF_SIG + bytes(500))
        with self.assertRaises(ewf.EwfError):
            ewf.EwfImage(path)

    def test_signature_only(self):
        with self.assertRaises(ewf.EwfError):
            ewf.EwfImage(self.write("s.E01", build.EVF_SIG))

    def test_not_ewf_at_all(self):
        with self.assertRaises(ewf.EwfError):
            ewf.EwfImage(self.write("n.E01", b"hello world" * 100))

    def test_ewf2_is_refused(self):
        with self.assertRaises(ewf.EwfError):
            ewf.open_image(self.write("v2.Ex01", ewf.EVF2_SIG + bytes(100)))

    def test_known_unsupported_container(self):
        with self.assertRaises(ewf.UnsupportedContainer) as cm:
            ewf.open_image(self.write("q.qcow2", b"QFI\xfb" + bytes(100)))
        self.assertIn("QCOW", cm.exception.format)

    def test_truncated_at_every_section_boundary(self):
        seg = build.build_e01()[0]
        cuts = [13 + 38, len(seg) // 3, len(seg) // 2, len(seg) - 200,
                len(seg) - build.DESC - 10]
        for cut in cuts:
            path = self.write("t%d.E01" % cut, seg[:cut])
            try:
                img = ewf.EwfImage(path)
            except ewf.EwfError:
                continue
            try:
                img.read_at(0, len(MEDIA))
                img.info()
            finally:
                img.close()

    def test_truncated_before_hash_still_reads(self):
        seg = build.build_e01()[0]
        hash_at = Integrity.find_section(seg, "hash")
        img = self.open(self.write_segments([seg[:hash_at]]))
        self.assertIsNone(img.stored_md5)
        self.assertEqual(img.read_at(0, len(MEDIA)), MEDIA)
        self.assertFalse(img.verify()["md5_match"])

    def test_non_advancing_section_chain(self):
        seg = bytearray(build.build_e01()[0])
        at = Integrity.find_section(seg, "table2")
        struct.pack_into("<Q", seg, at + 16, at)
        struct.pack_into("<I", seg, at + 72, build.adler(bytes(seg[at:at + 72])))
        img = self.open(self.write_segments([bytes(seg)]))
        self.assertTrue(any("non-advancing" in f for f in img.findings))
        self.assertEqual(img.read_at(0, len(MEDIA)), MEDIA)

    def test_backwards_section_pointer(self):
        seg = bytearray(build.build_e01()[0])
        at = Integrity.find_section(seg, "table2")
        struct.pack_into("<Q", seg, at + 16, 13)
        img = self.open(self.write_segments([bytes(seg)]))
        self.assertTrue(img.findings)

    def test_implausible_table_entry_count(self):
        seg = bytearray(build.build_e01()[0])
        at = Integrity.find_section(seg, "table")
        struct.pack_into("<I", seg, at + build.DESC, 0xFFFFFFFF)
        at2 = Integrity.find_section(seg, "table2")
        struct.pack_into("<I", seg, at2 + build.DESC, 0)
        with self.assertRaises(ewf.EwfError):
            ewf.EwfImage(self.write_segments([bytes(seg)]))

    def test_section_size_beyond_file(self):
        seg = bytearray(build.build_e01()[0])
        at = Integrity.find_section(seg, "table")
        struct.pack_into("<Q", seg, at + 16, 1 << 40)
        img = self.open(self.write_segments([bytes(seg)]))
        self.assertEqual(img.read_at(0, len(MEDIA)), MEDIA)


class Raw(TempDir):
    def test_raw_image(self):
        path = self.write("disk.dd", MEDIA)
        img = self.open(path)
        self.assertIsInstance(img, ewf.RawImage)
        self.assertEqual(img.size, len(MEDIA))
        self.assertEqual(img.read_at(1000, 50), MEDIA[1000:1050])
        self.assertEqual(img.read_at(len(MEDIA) - 5, 50), MEDIA[-5:])
        self.assertEqual(img.read_at(len(MEDIA), 1), b"")
        img.seek(-3, io.SEEK_END)
        self.assertEqual(img.read(), MEDIA[-3:])
        got = img.verify()
        self.assertEqual(got["computed_md5"], hashlib.md5(MEDIA).hexdigest())
        self.assertIsNone(got["md5_match"])
        self.assertEqual(img.info()["format"], "Raw / dd")

    def test_empty_raw_image(self):
        img = self.open(self.write("empty.img", b""))
        self.assertEqual(img.size, 0)
        self.assertEqual(img.read_at(0, 10), b"")

    # Engine bug: engine/ewf.py:538 open_image hands .001 to RawImage, which
    # opens that one file only; README promises split raw sets.
    @unittest.expectedFailure
    def test_split_raw_set(self):
        for i, piece in enumerate(build.split_raw(MEDIA, 3000)):
            self.write("split.%03d" % (i + 1), piece)
        img = self.open(os.path.join(self.dir, "split.001"))
        self.assertEqual(img.size, len(MEDIA))
        self.assertEqual(img.read_at(2990, 20), MEDIA[2990:3010])


class OffsetReaderTests(unittest.TestCase):
    class Mem(object):
        bytes_per_sector = 4096

        def read_at(self, off, n):
            return MEDIA[off:off + n] if off >= 0 else b""

    def setUp(self):
        self.r = ewf.OffsetReader(self.Mem(), 1000, 2000, "p1")

    def test_window(self):
        self.assertEqual(self.r.bytes_per_sector, 4096)
        self.assertEqual(self.r.read_at(0, 10), MEDIA[1000:1010])
        self.assertEqual(self.r.read_at(1990, 100), MEDIA[2990:3000])
        self.assertEqual(self.r.read_at(2000, 1), b"")

    def test_negative_and_empty(self):
        self.assertEqual(self.r.read_at(-10, 20), b"")
        self.assertEqual(self.r.read_at(10, 0), b"")

    def test_read_and_seek(self):
        self.r.seek(-4, io.SEEK_END)
        self.assertEqual(self.r.read(), MEDIA[2996:3000])
        self.r.seek(0)
        self.assertEqual(len(self.r.read()), 2000)


if __name__ == "__main__":
    unittest.main()
