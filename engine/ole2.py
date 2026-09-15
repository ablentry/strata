import struct

SIG = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

MAXREGSECT = 0xFFFFFFFA
ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF

EMPTY, STORAGE, STREAM, ROOT = 0, 1, 2, 5

NOSTREAM = 0xFFFFFFFF

MAX_CHAIN = 1 << 22
MAX_DIR = 1 << 16

def looks_like_ole2(head):
    return head[:8] == SIG

def filetime(v):
    if not v:
        return None
    secs, rem = divmod(v - 116444736000000000, 10000000)
    if not -12219292800 < secs < 32503680000:
        return None
    import time as _t
    try:
        return "%s.%06dZ" % (_t.strftime("%Y-%m-%dT%H:%M:%S", _t.gmtime(secs)),
                             rem // 10)
    except (OverflowError, ValueError, OSError):
        return None

class Entry:
    __slots__ = ("name", "kind", "size", "start", "clsid", "created",
                 "modified", "index", "children", "parent")

    def info(self):
        return {"name": self.name,
                "kind": {ROOT: "root", STORAGE: "storage",
                         STREAM: "stream"}.get(self.kind, "empty"),
                "size": self.size, "created": self.created,
                "modified": self.modified,
                "clsid": self.clsid or None}

class Ole2:

    def __init__(self, data, name=""):
        self.data = bytes(data)
        self.name = name
        self.valid = False
        self.findings = []
        self.entries = []
        self.by_name = {}
        self.root = None
        try:
            self._parse()
        except Exception as exc:
            self.findings.append("Structure could not be read (%s)."
                                 % type(exc).__name__)

    def _parse(self):
        d = self.data
        if len(d) < 512 or d[:8] != SIG:
            self.findings.append("Not a compound file.")
            return
        (self.minor, self.major, order, ss, mss) = struct.unpack_from(
            "<HHHHH", d, 24)
        if order != 0xFFFE:
            self.findings.append(
                "Byte-order mark is 0x%04X, not 0xFFFE. Big-endian compound "
                "files are not defined by the specification; not read." % order)
            return
        if ss not in (9, 12) or mss != 6:
            self.findings.append(
                "Sector shift %d / mini shift %d is outside the specification "
                "(9 or 12, and 6)." % (ss, mss))
            return
        self.sector = 1 << ss
        self.mini_sector = 1 << mss

        (self.n_dir_sectors, self.n_fat_sectors, self.first_dir,
         _trans, self.mini_cutoff, self.first_minifat, self.n_minifat,
         self.first_difat, self.n_difat) = struct.unpack_from("<IIIIIIIII", d, 40)

        self.fat = self._read_fat()
        self.minifat = self._chain_values(self.first_minifat, self.fat)
        self._read_directory()
        self.valid = bool(self.entries)

    def _sector_offset(self, n):
        return (n + 1) * self.sector

    def _sector(self, n):
        off = self._sector_offset(n)
        if off < 0 or off + self.sector > len(self.data):
            return b""
        return self.data[off:off + self.sector]

    def _read_fat(self):
        d = self.data
        fat_sectors = list(struct.unpack_from("<109I", d, 76))
        nxt, guard = self.first_difat, 0
        per = self.sector // 4 - 1
        while nxt not in (ENDOFCHAIN, FREESECT) and guard < MAX_CHAIN:
            guard += 1
            blk = self._sector(nxt)
            if len(blk) < self.sector:
                self.findings.append("A DIFAT sector is past the end of the "
                                     "file; the allocation table is partial.")
                break
            vals = struct.unpack_from("<%dI" % (per + 1), blk, 0)
            fat_sectors.extend(vals[:per])
            nxt = vals[per]

        fat = []
        for sec in fat_sectors:
            if sec > MAXREGSECT:
                continue
            blk = self._sector(sec)
            if len(blk) < self.sector:
                continue
            fat.extend(struct.unpack_from("<%dI" % (self.sector // 4), blk, 0))
        return fat

    def _chain(self, start, table):
        out, seen, cur = [], set(), start
        while cur <= MAXREGSECT and len(out) < MAX_CHAIN:
            if cur in seen:
                self.findings.append(
                    "A sector chain loops back on itself; it was followed "
                    "only as far as the repeat.")
                break
            seen.add(cur)
            out.append(cur)
            if cur >= len(table):
                self.findings.append(
                    "A chain runs past the end of the allocation table; the "
                    "file is truncated or the table is damaged.")
                break
            cur = table[cur]
        return out

    def _chain_values(self, start, table):
        out = []
        for sec in self._chain(start, table):
            blk = self._sector(sec)
            if len(blk) < self.sector:
                break
            out.extend(struct.unpack_from("<%dI" % (self.sector // 4), blk, 0))
        return out

    def _read_directory(self):
        raw = b"".join(self._sector(s)
                       for s in self._chain(self.first_dir, self.fat))
        count = len(raw) // 128
        ents = []
        for i in range(min(count, MAX_DIR)):
            o = i * 128
            nlen, = struct.unpack_from("<H", raw, o + 64)
            kind = raw[o + 66]
            nm = ""
            if 2 <= nlen <= 64:
                nm = raw[o:o + nlen - 2].decode("utf-16-le", "replace")
            e = Entry()
            e.index = i
            e.name = nm
            e.kind = kind if kind in (EMPTY, STORAGE, STREAM, ROOT) else EMPTY
            clsid = raw[o + 80:o + 96]
            e.clsid = clsid.hex() if any(clsid) else ""
            ct, mt = struct.unpack_from("<QQ", raw, o + 100)
            e.created, e.modified = filetime(ct), filetime(mt)
            e.start, e.size = struct.unpack_from("<IQ", raw, o + 116)
            e.children = []
            e.parent = None
            ents.append(e)
        self.entries = ents
        if not ents:
            return
        self.root = ents[0] if ents[0].kind == ROOT else None

        self._mini_data = b""
        if self.root is not None and self.root.size:
            self._mini_data = b"".join(
                self._sector(s) for s in self._chain(self.root.start, self.fat))

        def walk(idx, parent, seen):
            stack = [idx]
            while stack:
                i = stack.pop()
                if i == NOSTREAM or i >= len(ents) or i in seen:
                    continue
                seen.add(i)
                e = ents[i]
                e.parent = parent
                parent.children.append(e)
                left, right, child = struct.unpack_from("<III", raw, i * 128 + 68)
                stack.extend([left, right])
                if child != NOSTREAM and e.kind in (STORAGE, ROOT):
                    walk(child, e, seen)

        seen = set()
        if self.root is not None:
            _l, _r, child = struct.unpack_from("<III", raw, 68)
            walk(child, self.root, seen)
        for e in ents:
            if e.kind == STREAM and e.name:
                self.by_name.setdefault(e.name, e)

    def read(self, entry, max_bytes=None):
        if isinstance(entry, str):
            entry = self.by_name.get(entry)
        if entry is None or entry.kind not in (STREAM, ROOT):
            return b""
        size = entry.size if max_bytes is None else min(entry.size, max_bytes)
        if size <= 0:
            return b""
        if entry.size < self.mini_cutoff and entry is not self.root:
            out = bytearray()
            for s in self._chain(entry.start, self.minifat):
                o = s * self.mini_sector
                out += self._mini_data[o:o + self.mini_sector]
                if len(out) >= size:
                    break
            return bytes(out[:size])
        out = bytearray()
        for s in self._chain(entry.start, self.fat):
            out += self._sector(s)
            if len(out) >= size:
                break
        return bytes(out[:size])

    def streams(self):
        out = []
        for e in self.entries:
            if e.kind != STREAM:
                continue
            parts, p = [e.name], e.parent
            while p is not None and p.kind != ROOT:
                parts.append(p.name)
                p = p.parent
            out.append((("/".join(reversed(parts))), e))
        out.sort(key=lambda x: x[0].lower())
        return out

    def info(self):
        return {
            "valid": self.valid,
            "sector_size": getattr(self, "sector", None),
            "mini_cutoff": getattr(self, "mini_cutoff", None),
            "version": "%d.%d" % (getattr(self, "major", 0),
                                  getattr(self, "minor", 0)),
            "entries": len(self.entries),
            "streams": sum(1 for e in self.entries if e.kind == STREAM),
            "storages": sum(1 for e in self.entries if e.kind == STORAGE),
            "root_clsid": (self.root.clsid or None) if self.root else None,
            "findings": self.findings,
        }
