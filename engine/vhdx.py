import io
import os
import struct
import threading
import uuid

from .text import t as _t

SIGNATURE = b"vhdxfile"

HEADER_OFFSETS = (0x10000, 0x20000)
REGION_OFFSETS = (0x30000, 0x40000)

BAT_REGION = uuid.UUID("2DC27766-F623-4200-9D64-115E9BFD4A08")
METADATA_REGION = uuid.UUID("8B7CA206-4790-4B9A-B8FE-575F050F886E")

META_FILE_PARAMETERS = uuid.UUID("CAA16737-FA36-4D43-B3B6-33F0AA44E76B")
META_VIRTUAL_DISK_SIZE = uuid.UUID("2FA54224-CD1B-4876-B211-5DBED83BF4B8")
META_LOGICAL_SECTOR_SIZE = uuid.UUID("8141BF1D-A96F-4709-BA47-F233A8FAAB5F")
META_PHYSICAL_SECTOR_SIZE = uuid.UUID("CDA348C7-445D-4471-9CC9-E9885251C556")
META_PAGE83 = uuid.UUID("BECA12AB-B2E6-4523-93EF-C309E000C746")

NOT_PRESENT = 0
ZERO = 2
UNMAPPED = 3
FULLY_PRESENT = 6
PARTIALLY_PRESENT = 7

class VhdxError(Exception):

    def __init__(self, message, advice=""):
        Exception.__init__(self, message)
        self.message = message
        self.advice = advice

_CRC32C_TABLE = []

def _build_table():
    poly = 0x82F63B78
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ (poly if c & 1 else 0)
        _CRC32C_TABLE.append(c)

_build_table()

def crc32c(data, crc=0):
    crc ^= 0xFFFFFFFF
    for b in data:
        crc = _CRC32C_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF

def _checked(block, csum_at):
    stored, = struct.unpack_from("<I", block, csum_at)
    body = bytearray(block)
    struct.pack_into("<I", body, csum_at, 0)
    return crc32c(bytes(body)) == stored, stored

def _headers(fh):
    out = []
    for off in HEADER_OFFSETS:
        fh.seek(off)
        raw = fh.read(4096)
        if len(raw) < 80 or raw[:4] != b"head":
            continue
        ok, stored = _checked(raw, 4)
        seq, = struct.unpack_from("<Q", raw, 8)
        log_guid = uuid.UUID(bytes_le=raw[48:64])
        log_version, version = struct.unpack_from("<HH", raw, 64)
        log_length, log_offset = struct.unpack_from("<IQ", raw, 68)
        out.append({
            "offset": off, "sequence": seq, "checksum_ok": ok,
            "version": version, "log_version": log_version,
            "log_guid": log_guid, "log_length": log_length,
            "log_offset": log_offset,
        })
    out.sort(key=lambda h: (h["checksum_ok"], h["sequence"]), reverse=True)
    return out

def _regions(fh):
    findings = []
    for off in REGION_OFFSETS:
        fh.seek(off)
        raw = fh.read(65536)
        if len(raw) < 16 or raw[:4] != b"regi":
            continue
        ok, _stored = _checked(raw, 4)
        if not ok:
            findings.append("A region table copy at 0x%X failed its checksum "
                            "and was not used." % off)
            continue
        count, = struct.unpack_from("<I", raw, 8)
        out = {}
        for i in range(count):
            base = 16 + i * 32
            if base + 32 > len(raw):
                break
            guid = uuid.UUID(bytes_le=raw[base:base + 16])
            f_off, length, required = struct.unpack_from("<QII", raw, base + 16)
            out[guid] = {"offset": f_off, "length": length,
                         "required": bool(required & 1)}
        return out, findings
    return {}, findings

def _metadata(fh, region):
    fh.seek(region["offset"])
    raw = fh.read(min(region["length"], 1 << 20))
    if raw[:8] != b"metadata":
        raise VhdxError(_t("vhdx.metadata_region_does_start"))
    count, = struct.unpack_from("<H", raw, 10)
    items = {}
    for i in range(count):
        base = 32 + i * 32
        if base + 32 > len(raw):
            break
        guid = uuid.UUID(bytes_le=raw[base:base + 16])
        off, length, _flags = struct.unpack_from("<III", raw, base + 16)
        items[guid] = raw[off:off + length]
    return items

class VhdxImage:

    def __init__(self, path):
        self.path = path
        self.segment_paths = [path]
        self.findings = []
        self.header = {}
        self.stored_md5 = None
        self.stored_sha1 = None
        self._pos = 0
        self._io_lock = threading.Lock()
        self._fh = open(path, "rb")

        try:
            self._load()
        except Exception:
            self._fh.close()
            raise

    def _load(self):
        fh = self._fh
        fh.seek(0)
        ident = fh.read(520)
        if ident[:8] != SIGNATURE:
            raise VhdxError(_t("vhdx.vhdx_file_type_identifier"))
        self.creator = ident[8:8 + 512].decode("utf-16-le", "replace")\
            .rstrip("\x00").strip()

        heads = _headers(fh)
        if not heads:
            raise VhdxError(_t("vhdx.neither_vhdx_header_could"))
        live = heads[0]
        if not live["checksum_ok"]:
            raise VhdxError(
                _t("vhdx.both_vhdx_headers_fail"),
                "The file is damaged or truncated. Nothing here can be "
                "trusted to address the right blocks.")
        if len(heads) > 1 and not heads[1]["checksum_ok"]:
            self.findings.append(
                "One of the two VHDX headers fails its checksum; the other "
                "was used. That is a torn write, not necessarily data loss.")
        self._header = live

        if live["log_guid"].int != 0:
            raise VhdxError(
                _t("vhdx.vhdx_active_log_so"),
                "It was not shut down cleanly. Replaying the log is not "
                "implemented, and reading without it would return stale "
                "blocks that parse perfectly and are wrong. Attach it "
                "read-only on a Windows host to let it settle, then image "
                "the result.")

        regions, findings = _regions(fh)
        self.findings.extend(findings)
        if BAT_REGION not in regions or METADATA_REGION not in regions:
            missing = [n for n, g in (("BAT", BAT_REGION),
                                      ("metadata", METADATA_REGION))
                       if g not in regions]
            raise VhdxError(_t("vhdx.vhdx_region_table_names")
                            % " or ".join(missing))
        for guid, r in regions.items():
            if r["required"] and guid not in (BAT_REGION, METADATA_REGION):
                raise VhdxError(
                    _t("vhdx.vhdx_declares_region_strata") % guid,
                    "A required region is one the writer says must be "
                    "understood to read the file correctly.")

        meta = _metadata(fh, regions[METADATA_REGION])
        if META_FILE_PARAMETERS not in meta or META_VIRTUAL_DISK_SIZE not in meta:
            raise VhdxError(_t("vhdx.vhdx_metadata_missing_file"))
        self.block_size, flags = struct.unpack("<II",
                                               meta[META_FILE_PARAMETERS][:8])
        self.leave_allocated = bool(flags & 1)
        self.has_parent = bool(flags & 2)
        self.size, = struct.unpack("<Q", meta[META_VIRTUAL_DISK_SIZE][:8])
        self.bytes_per_sector = 512
        if META_LOGICAL_SECTOR_SIZE in meta:
            self.bytes_per_sector, = struct.unpack(
                "<I", meta[META_LOGICAL_SECTOR_SIZE][:4])
        self.physical_sector_size = None
        if META_PHYSICAL_SECTOR_SIZE in meta:
            self.physical_sector_size, = struct.unpack(
                "<I", meta[META_PHYSICAL_SECTOR_SIZE][:4])
        self.disk_id = None
        if META_PAGE83 in meta and len(meta[META_PAGE83]) >= 16:
            self.disk_id = str(uuid.UUID(bytes_le=meta[META_PAGE83][:16]))

        if self.has_parent:
            raise VhdxError(
                _t("vhdx.differencing_vhdx_holds_only"),
                "The parent file carries the rest and Strata has not been "
                "given it. Merge the chain first, or examine the parent and "
                "this file as separate exhibits knowing neither is whole.")

        if not self.block_size or self.block_size % (1 << 20):
            raise VhdxError(_t("vhdx.implausible_vhdx_block_size")
                            % (self.block_size,))

        self.chunk_ratio = ((1 << 23) * self.bytes_per_sector) // self.block_size
        self.block_count = -(-self.size // self.block_size)

        self._read_bat(regions[BAT_REGION])

    def _read_bat(self, region):
        need = self.block_count + (self.block_count - 1) // self.chunk_ratio + 1
        want = need * 8
        if want > region["length"]:
            self.findings.append(
                "The BAT region is smaller than the disk size implies "
                "(%d bytes for %d entries); blocks past the end read as "
                "zeros." % (region["length"], need))
            want = region["length"]
        self._fh.seek(region["offset"])
        raw = self._fh.read(want)

        self._bat = []
        counts = {}
        for n in range(self.block_count):
            idx = n + n // self.chunk_ratio
            if (idx + 1) * 8 > len(raw):
                self._bat.append((NOT_PRESENT, 0))
                counts[NOT_PRESENT] = counts.get(NOT_PRESENT, 0) + 1
                continue
            entry, = struct.unpack_from("<Q", raw, idx * 8)
            state = entry & 0x7
            offset = (entry >> 20) << 20
            self._bat.append((state, offset))
            counts[state] = counts.get(state, 0) + 1
        self.block_states = counts

        if counts.get(PARTIALLY_PRESENT):
            self.findings.append(
                "%d block(s) are marked partially present, which only has a "
                "meaning on a differencing disk. The sectors they do not hold "
                "read as zeros." % counts[PARTIALLY_PRESENT])

    def read_at(self, offset, length):
        if offset < 0 or offset >= self.size or length <= 0:
            return b""
        length = min(length, self.size - offset)
        out = bytearray()
        pos = offset
        while len(out) < length:
            n = pos // self.block_size
            within = pos - n * self.block_size
            take = min(self.block_size - within, length - len(out))
            state, at = self._bat[n] if n < len(self._bat) else (NOT_PRESENT, 0)
            if state in (FULLY_PRESENT, PARTIALLY_PRESENT):
                with self._io_lock:
                    self._fh.seek(at + within)
                    got = self._fh.read(take)
                if len(got) < take:
                    got = got + bytes(take - len(got))
                    if "truncated" not in "".join(self.findings):
                        self.findings.append(
                            "The BAT points past the end of the file: this "
                            "VHDX is truncated and the missing blocks read "
                            "as zeros.")
                out += got
            else:
                out += bytes(take)
            pos += take
        return bytes(out)

    def read(self, n=-1):
        d = self.read_at(self._pos, self.size - self._pos if n < 0 else n)
        self._pos += len(d)
        return d

    def seek(self, off, whence=io.SEEK_SET):
        if whence == io.SEEK_SET:
            self._pos = off
        elif whence == io.SEEK_CUR:
            self._pos += off
        else:
            self._pos = self.size + off
        return self._pos

    def close(self):
        self._fh.close()

    def verify(self, progress=None):
        import hashlib
        md5, sha1 = hashlib.md5(), hashlib.sha1()
        pos = 0
        while pos < self.size:
            d = self.read_at(pos, 1 << 22)
            if not d:
                break
            md5.update(d)
            sha1.update(d)
            pos += len(d)
            if progress:
                progress(pos / self.size)
        return {"computed_md5": md5.hexdigest(),
                "computed_sha1": sha1.hexdigest(),
                "stored_md5": None, "stored_sha1": None,
                "md5_match": None, "sha1_match": None,
                "note": _t("vhdx.vhdx_stores_acquisition_hash")}

    def info(self):
        present = self.block_states.get(FULLY_PRESENT, 0)
        return {
            "format": "Hyper-V VHDX (%s)" % ("fixed" if self.leave_allocated
                                             else "dynamic"),
            "segments": [os.path.basename(self.path)],
            "size": self.size,
            "bytes_per_sector": self.bytes_per_sector,
            "chunk_size": self.block_size,
            "acquisition": {
                "created_by": self.creator,
                "disk id": self.disk_id,
                "block size": self.block_size,
                "physical sector size": self.physical_sector_size,
                "blocks present": "%d of %d" % (present, self.block_count),
                "container size on disk": os.path.getsize(self.path),
            },
            "findings": list(self.findings),
        }
