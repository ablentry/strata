import datetime
import struct
import zlib

EOCD_SIG = b"PK\x05\x06"
EOCD64_SIG = b"PK\x06\x06"
EOCD64_LOC_SIG = b"PK\x06\x07"
CENTRAL_SIG = b"PK\x01\x02"
LOCAL_SIG = b"PK\x03\x04"

MAX_ENTRY_OUT = 256 << 20
MAX_RATIO = 200

METHODS = {0: "stored", 8: "deflate", 9: "deflate64", 12: "bzip2",
           14: "lzma", 93: "zstd", 95: "xz", 98: "ppmd"}

def _dos_time(dt, tm):
    if not dt:
        return None
    try:
        return datetime.datetime(
            ((dt >> 9) & 0x7F) + 1980, (dt >> 5) & 0x0F, dt & 0x1F,
            (tm >> 11) & 0x1F, (tm >> 5) & 0x3F, (tm & 0x1F) * 2).isoformat()
    except ValueError:
        return None

def _name(raw, flags):
    if flags & 0x800:
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            pass
    for enc in ("utf-8", "cp437", "cp1252"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", "replace")

class Entry:
    __slots__ = ("name", "size", "compressed", "method", "crc", "modified",
                 "local_offset", "flags", "encrypted", "is_dir", "comment",
                 "from_scan", "data_offset", "findings", "external_attr")

    def info(self):
        return {
            "name": self.name, "size": self.size,
            "compressed": self.compressed,
            "method": METHODS.get(self.method, "unknown (%d)" % self.method),
            "method_id": self.method,
            "crc": "%08X" % (self.crc or 0),
            "modified": self.modified, "modified_is_local": True,
            "encrypted": self.encrypted, "is_dir": self.is_dir,
            "offset": self.local_offset, "comment": self.comment or None,
            "recovered_by_scan": self.from_scan,
            "findings": self.findings,
        }

class Zip:

    def __init__(self, data, name=""):
        self.data = bytes(data)
        self.name = name
        self.entries = []
        self.findings = []
        self.comment = None
        self.method_used = None
        self.valid = False
        self._parse()

    def _find_eocd(self):
        tail = self.data[-(65536 + 22):]
        base = len(self.data) - len(tail)
        i = tail.rfind(EOCD_SIG)
        return base + i if i >= 0 else -1

    def _parse(self):
        if len(self.data) < 4:
            self.findings.append("Too short to be an archive.")
            return
        eocd = self._find_eocd()
        if eocd >= 0 and self._parse_central(eocd):
            self.method_used = "central directory"
            self.valid = True
        else:
            if eocd < 0:
                self.findings.append(
                    "No end-of-central-directory record. The archive is "
                    "truncated or its tail was overwritten — normal for one "
                    "recovered from unallocated space. Falling back to a scan "
                    "for local file headers.")
            else:
                self.findings.append(
                    "The central directory did not parse; falling back to a "
                    "scan for local file headers.")
            self._scan_local()
            self.method_used = "local header scan"
            self.valid = bool(self.entries)
        self._cross_check()

    def _parse_central(self, eocd):
        try:
            (_, disk, cd_disk, here, total, cd_size, cd_off, clen) = \
                struct.unpack_from("<IHHHHIIH", self.data, eocd)
        except struct.error:
            return False
        if clen:
            self.comment = self.data[eocd + 22:eocd + 22 + clen].decode(
                "utf-8", "replace")

        if cd_off == 0xFFFFFFFF or total == 0xFFFF:
            loc = self.data.rfind(EOCD64_LOC_SIG, 0, eocd)
            if loc >= 0:
                rel = struct.unpack_from("<Q", self.data, loc + 8)[0]
                if 0 <= rel < len(self.data) and \
                        self.data[rel:rel + 4] == EOCD64_SIG:
                    total, cd_size, cd_off = struct.unpack_from(
                        "<QQQ", self.data, rel + 32)[0], \
                        struct.unpack_from("<Q", self.data, rel + 40)[0], \
                        struct.unpack_from("<Q", self.data, rel + 48)[0]
                    self.findings.append("Zip64 archive.")

        if not (0 <= cd_off < len(self.data)):
            return False
        pos = cd_off
        seen = 0
        while pos + 46 <= len(self.data) and self.data[pos:pos + 4] == CENTRAL_SIG:
            (_, _ver, _need, flags, method, mtime, mdate, crc, csize, usize,
             nlen, elen, clen2, _d, _ia, ea, loff) = struct.unpack_from(
                "<IHHHHHHIIIHHHHHII", self.data, pos)
            nm = self.data[pos + 46:pos + 46 + nlen]
            extra = self.data[pos + 46 + nlen:pos + 46 + nlen + elen]
            cmt = self.data[pos + 46 + nlen + elen:
                            pos + 46 + nlen + elen + clen2]
            e = Entry()
            e.name = _name(nm, flags)
            e.flags = flags
            e.method = method
            e.crc = crc
            e.compressed = csize
            e.size = usize
            e.local_offset = loff
            e.modified = _dos_time(mdate, mtime)
            e.encrypted = bool(flags & 0x01)
            e.comment = cmt.decode("utf-8", "replace") if cmt else None
            e.is_dir = e.name.endswith("/")
            e.from_scan = False
            e.data_offset = None
            e.findings = []
            e.external_attr = ea
            if usize == 0xFFFFFFFF or csize == 0xFFFFFFFF or loff == 0xFFFFFFFF:
                self._zip64_extra(e, extra)
            self.entries.append(e)
            pos += 46 + nlen + elen + clen2
            seen += 1
            if seen > 200000:
                self.findings.append("Stopped after 200,000 entries.")
                break
        if total and seen != total and total != 0xFFFF:
            self.findings.append(
                "The directory declares %d entries; %d were read."
                % (total, seen))
        return bool(self.entries)

    @staticmethod
    def _zip64_extra(e, extra):
        pos = 0
        while pos + 4 <= len(extra):
            hid, hlen = struct.unpack_from("<HH", extra, pos)
            body = extra[pos + 4:pos + 4 + hlen]
            if hid == 0x0001:
                off = 0
                for attr in ("size", "compressed", "local_offset"):
                    if getattr(e, attr) == 0xFFFFFFFF and off + 8 <= len(body):
                        setattr(e, attr, struct.unpack_from("<Q", body, off)[0])
                        off += 8
            pos += 4 + hlen

    def _scan_local(self):
        pos = 0
        n = 0
        while True:
            i = self.data.find(LOCAL_SIG, pos)
            if i < 0 or i + 30 > len(self.data):
                break
            (_, _need, flags, method, mtime, mdate, crc, csize, usize,
             nlen, elen) = struct.unpack_from("<IHHHHHIIIHH", self.data, i)
            if nlen > 4096:
                pos = i + 4
                continue
            nm = self.data[i + 30:i + 30 + nlen]
            e = Entry()
            e.name = _name(nm, flags)
            e.flags = flags
            e.method = method
            e.crc = crc
            e.compressed = csize
            e.size = usize
            e.local_offset = i
            e.data_offset = i + 30 + nlen + elen
            e.modified = _dos_time(mdate, mtime)
            e.encrypted = bool(flags & 0x01)
            e.comment = None
            e.is_dir = e.name.endswith("/")
            e.from_scan = True
            e.external_attr = 0
            e.findings = []
            if flags & 0x08:
                e.findings.append(
                    "Sizes are in a data descriptor after the content, so the "
                    "header values may be zero.")
            self.entries.append(e)
            pos = i + 30 + nlen + elen + (csize if csize else 1)
            n += 1
            if n > 200000:
                break
        if self.entries:
            self.findings.append(
                "%d entr%s recovered by scanning for local headers. Names and "
                "content are readable; anything the central directory would "
                "have added — comments, external attributes, and the archive's "
                "own idea of how many entries it has — is not available."
                % (len(self.entries), "y" if len(self.entries) == 1 else "ies"))

    def _cross_check(self):
        bad = 0
        for e in self.entries:
            if e.from_scan or e.local_offset is None:
                continue
            off = e.local_offset
            if off + 30 > len(self.data) or self.data[off:off + 4] != LOCAL_SIG:
                e.findings.append(
                    "The directory points at offset %d, where there is no "
                    "local file header." % off)
                bad += 1
                continue
            (_, _n, lflags, lmethod, _t, _d, lcrc, lcsize, lusize,
             nlen, elen) = struct.unpack_from("<IHHHHHIIIHH", self.data, off)
            e.data_offset = off + 30 + nlen + elen
            if not (lflags & 0x08):
                for label, a, b in (("compressed size", e.compressed, lcsize),
                                    ("size", e.size, lusize),
                                    ("CRC", e.crc, lcrc)):
                    if a != b and b != 0:
                        e.findings.append(
                            "%s differs between the directory (%s) and the "
                            "local header (%s)." % (label, a, b))
                        bad += 1
            if lmethod != e.method:
                e.findings.append(
                    "Compression method differs between the directory (%d) "
                    "and the local header (%d)." % (e.method, lmethod))
                bad += 1
        if bad:
            self.findings.append(
                "%d discrepanc%s between the central directory and the local "
                "headers. They are two independent descriptions of the same "
                "content, so a difference is worth explaining — an append, a "
                "repair, or deliberate tampering."
                % (bad, "y" if bad == 1 else "ies"))

    def read(self, entry, max_bytes=MAX_ENTRY_OUT):
        if isinstance(entry, dict):
            name = entry.get("name")
            entry = next((e for e in self.entries if e.name == name), None)
        if entry is None:
            return b"", ["No such entry."]
        notes = []
        if entry.encrypted:
            return b"", ["This entry is encrypted; its content cannot be read "
                         "without the password."]
        if entry.is_dir:
            return b"", []
        if entry.data_offset is None:
            return b"", ["The entry's content could not be located."]

        start = entry.data_offset
        avail = len(self.data) - start
        if avail <= 0:
            return b"", ["The entry's content is beyond the end of the data."]
        want = entry.compressed if entry.compressed else avail
        if want > avail:
            notes.append("Declared compressed size %d exceeds what is present "
                         "(%d); reading what there is." % (want, avail))
            want = avail
        blob = self.data[start:start + want]

        if entry.method == 0:
            out = blob[:max_bytes]
        elif entry.method == 8:
            out, note = _inflate(blob, max_bytes, entry.size)
            if note:
                notes.append(note)
        else:
            return b"", ["Compression method %s is not supported."
                         % METHODS.get(entry.method, entry.method)]

        if entry.crc and len(out) == entry.size:
            got = zlib.crc32(out) & 0xFFFFFFFF
            if got != entry.crc:
                notes.append("CRC mismatch: the archive says %08X, the content "
                             "gives %08X. This entry is damaged or was altered."
                             % (entry.crc, got))
        elif entry.size and len(out) < entry.size:
            notes.append("Recovered %d of %d bytes; the rest is missing."
                         % (len(out), entry.size))
        return out, notes

    def info(self):
        real = [e for e in self.entries if not e.is_dir]
        return {
            "type": "zip", "valid": self.valid, "name": self.name,
            "entries": len(self.entries), "files": len(real),
            "read_by": self.method_used,
            "total_size": sum(e.size or 0 for e in real),
            "total_compressed": sum(e.compressed or 0 for e in real),
            "encrypted_entries": sum(1 for e in real if e.encrypted),
            "comment": self.comment,
            "container": _container_kind([e.name for e in self.entries]),
            "findings": self.findings,
            "items": [e.info() for e in self.entries],
        }

def _inflate(blob, max_bytes, expected=None):
    d = zlib.decompressobj(-zlib.MAX_WBITS)
    out = bytearray()
    note = None
    try:
        for i in range(0, len(blob), 65536):
            out += d.decompress(blob[i:i + 65536], max_bytes - len(out))
            if len(out) >= max_bytes:
                note = ("Stopped at %d bytes: the ceiling on how much one "
                        "entry may expand to." % max_bytes)
                break
            if d.eof:
                break
        else:
            out += d.flush()
    except zlib.error as exc:
        note = "Decompression failed after %d bytes: %s" % (len(out), exc)
    if expected and len(out) > max(expected, 1) * MAX_RATIO:
        note = "Expansion ratio is implausible; treated as a decompression bomb."
        return bytes(out[:max_bytes]), note
    return bytes(out), note

_MARKERS = (
    ("word/document.xml", "Word document (.docx)"),
    ("xl/workbook.xml", "Excel workbook (.xlsx)"),
    ("ppt/presentation.xml", "PowerPoint presentation (.pptx)"),
    ("META-INF/MANIFEST.MF", "Java archive (.jar)"),
    ("AndroidManifest.xml", "Android package (.apk)"),
    ("mimetype", "OpenDocument or EPUB"),
    ("[Content_Types].xml", "Office Open XML"),
)

def _container_kind(names):
    have = set(names)
    for marker, label in _MARKERS:
        if marker in have:
            return label
    return None
