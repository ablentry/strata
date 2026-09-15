import datetime
import struct

SIGNATURE = 0x89ABCDEF
SIGNATURE_OFFSET = 4
PAGE_SIZE_OFFSET = 236

STATE_OFFSET = 52
STATES = {1: "just created", 2: "dirty shutdown", 3: "clean shutdown",
          4: "being converted", 5: "force detach"}

FLAG_ROOT = 0x0001
FLAG_LEAF = 0x0002
FLAG_SPACE_TREE = 0x0020
FLAG_LONG_VALUE = 0x0080

ENTRY_COMMON_KEY = 0x04

TAGGED_FLAGS_FROM = 0x620
TAG_SEPARATED = 0x04
TAG_SEPARATED_ALT = 0x10

CATALOG_OBJID = 2
CATALOG_PAGE = 4

TYPE_TABLE = 1
TYPE_COLUMN = 2
TYPE_INDEX = 3
TYPE_LONG_VALUE = 4
TYPE_CALLBACK = 5
TYPE_NAMES = {TYPE_TABLE: "table", TYPE_COLUMN: "column", TYPE_INDEX: "index",
              TYPE_LONG_VALUE: "long value", TYPE_CALLBACK: "callback"}

COL_OBJID_TABLE = 1
COL_TYPE = 2
COL_ID = 3
COL_COLTYP_OR_FDP = 4
COL_SPACE_USAGE = 5
COL_FLAGS = 6
COL_PAGES_OR_LOCALE = 7
COL_NAME = 128

COLUMN_TYPES = {
    0: "NULL", 1: "Boolean", 2: "Byte", 3: "Short", 4: "Long",
    5: "Currency", 6: "Single", 7: "Double", 8: "DateTime", 9: "Binary",
    10: "Text", 11: "LongBinary", 12: "LongText", 13: "SLV",
    14: "UnsignedLong", 15: "LongLong", 16: "GUID", 17: "UnsignedShort",
}

FIXED_WIDTHS = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 4, 7: 8, 8: 8,
                14: 4, 15: 8, 16: 16, 17: 2}

OLE_EPOCH = datetime.datetime(1899, 12, 30, tzinfo=datetime.timezone.utc)

class NotEse(ValueError):
    pass

class EseError(ValueError):
    pass

def looks_like_ese(head):
    if len(head) < 8:
        return False
    return struct.unpack_from("<I", head, SIGNATURE_OFFSET)[0] == SIGNATURE

def _u16(b, o):
    return struct.unpack_from("<H", b, o)[0]

def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]

def reference_key(raw):
    if not raw or len(raw) < 8:
        return None
    low = int.from_bytes(raw[0:4], "little")
    high = int.from_bytes(raw[4:8], "little")
    return high.to_bytes(4, "big") + low.to_bytes(4, "big")

def decode_value(raw, column_type, codepage=None):
    if raw is None:
        return None
    if isinstance(raw, dict):
        return raw
    if column_type in (11, 12) and len(raw) == 4:
        return {"long_value_id": int.from_bytes(raw, "little")}
    try:
        if column_type == 1:
            return bool(raw[0]) if raw else None
        if column_type == 2:
            return raw[0] if raw else None
        if column_type == 3:
            return struct.unpack("<h", raw[:2])[0]
        if column_type == 17:
            return struct.unpack("<H", raw[:2])[0]
        if column_type == 4:
            return struct.unpack("<i", raw[:4])[0]
        if column_type == 14:
            return struct.unpack("<I", raw[:4])[0]
        if column_type == 15:
            return struct.unpack("<q", raw[:8])[0]
        if column_type == 5:
            return struct.unpack("<q", raw[:8])[0]
        if column_type == 6:
            return struct.unpack("<f", raw[:4])[0]
        if column_type == 7:
            return struct.unpack("<d", raw[:8])[0]
        if column_type == 8:
            days = struct.unpack("<d", raw[:8])[0]
            if not -700000 < days < 700000:
                return None
            when = OLE_EPOCH + datetime.timedelta(days=days)
            return when.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
        if column_type == 16:
            a, b, c = struct.unpack("<IHH", raw[:8])
            return "{%08X-%04X-%04X-%s-%s}" % (
                a, b, c, raw[8:10].hex().upper(), raw[10:16].hex().upper())
        if column_type in (10, 12):
            enc = "utf-16-le" if codepage == 1200 else "cp1252"
            return raw.decode(enc, "replace").rstrip(chr(0))
    except (struct.error, ValueError, IndexError):
        return raw
    return raw

class Page:

    __slots__ = ("number", "raw", "header_size", "big", "prev", "next",
                 "fdp", "free", "used", "tag_count", "flags", "valid")

    def __init__(self, number, raw, header_size):
        self.number = number
        self.raw = raw
        self.header_size = header_size
        self.big = header_size > 40
        self.prev, self.next, self.fdp = struct.unpack_from("<III", raw, 0x10)
        self.free, _uncommitted, self.used, self.tag_count = \
            struct.unpack_from("<HHHH", raw, 0x1C)
        self.flags = _u32(raw, 0x24)
        self.valid = 0 < self.tag_count < len(raw) // 4 and all(
            self.tag(i) is not None for i in range(min(self.tag_count, 8)))

    @property
    def is_leaf(self):
        return bool(self.flags & FLAG_LEAF)

    @property
    def is_root(self):
        return bool(self.flags & FLAG_ROOT)

    @property
    def is_space_tree(self):
        return bool(self.flags & FLAG_SPACE_TREE)

    @property

    def tag(self, i):
        if not 0 <= i < self.tag_count:
            return None
        at = len(self.raw) - 4 * (i + 1)
        raw_size, raw_off = struct.unpack_from("<HH", self.raw, at)
        if self.big:
            size, off, flags = raw_size & 0x7FFF, raw_off & 0x7FFF, 0
        else:
            size, off = raw_size & 0x1FFF, raw_off & 0x1FFF
            flags = raw_off >> 13
        start = self.header_size + off
        if start + size > len(self.raw) - 4 * self.tag_count:
            return None
        return self.raw[start:start + size], flags

    def key_prefix(self):
        if self.is_root:
            return b""
        got = self.tag(0)
        return got[0] if got else b""

    def entries(self):
        prefix = self.key_prefix()
        for i, blob, flags in self.tags():
            if i == 0:
                continue
            local, value, common = split_entry(blob, flags, self.big)
            yield prefix[:common] + local, value

    def tags(self):
        for i in range(self.tag_count):
            got = self.tag(i)
            if got is not None:
                yield i, got[0], got[1]

def split_entry(blob, flags=0, big=False):
    if len(blob) < 2:
        return b"", b"", 0
    first = _u16(blob, 0)
    if big:
        flags = first >> 13
    if flags & ENTRY_COMMON_KEY:
        if len(blob) < 4:
            return b"", b"", 0
        common = first & 0x1FFF
        local = _u16(blob, 2) & 0x1FFF
        at = 4 + local
        key_at = 4
    else:
        common = 0
        local = first & 0x1FFF
        at = 2 + local
        key_at = 2
    if at > len(blob):
        return b"", blob, common
    return blob[key_at:at], blob[at:], common

def _branch_children(page):
    out = []
    for i, blob, _flags in page.tags():
        if i == 0 and page.is_root:
            continue
        if len(blob) < 6:
            continue
        out.append(_u32(blob, len(blob) - 4))
    return out

RECORD_HEADER = 4

class Record:

    __slots__ = ("blob", "last_fixed", "last_variable", "var_offset")

    def __init__(self, blob):
        if len(blob) < 4:
            raise EseError("record shorter than its header")
        self.blob = blob
        self.last_fixed = blob[0]
        self.last_variable = blob[1]
        self.var_offset = _u16(blob, 2)

    def fixed_values(self, widths):
        offsets, at = [], 4
        for cid, w in widths:
            if cid > self.last_fixed or at + w > len(self.blob):
                break
            offsets.append((cid, at, w))
            at += w
        covered = bool(offsets) and offsets[-1][0] >= self.last_fixed
        null = self._null_bits(at) if covered else None
        out = {}
        for cid, start, w in offsets:
            if null is not None and null >> (cid - 1) & 1:
                continue
            out[cid] = self.blob[start:start + w]
        return out

    def _null_bits(self, after_fixed):
        n = (self.last_fixed + 7) // 8
        if not n or after_fixed + n > len(self.blob):
            return None
        return int.from_bytes(self.blob[after_fixed:after_fixed + n], "little")

    def tagged_values(self, strip_flags=False):
        start = self._tagged_start()
        if start is None or start + 4 > len(self.blob):
            return {}
        first = _u16(self.blob, start + 2) & 0x3FFF
        if first < 4 or start + first > len(self.blob) or first % 4:
            return {}
        count = first // 4
        entries = []
        for i in range(count):
            at = start + 4 * i
            if at + 4 > len(self.blob):
                return {}
            cid = _u16(self.blob, at)
            off = _u16(self.blob, at + 2) & 0x3FFF
            entries.append((cid, off))
        out = {}
        for i, (cid, off) in enumerate(entries):
            end = entries[i + 1][1] if i + 1 < len(entries) else \
                len(self.blob) - start
            a, b = start + off, start + end
            if not (start <= a <= b <= len(self.blob)):
                continue
            raw = self.blob[a:b]
            if strip_flags and raw:
                bits, raw = raw[0], raw[1:]
                if bits & (TAG_SEPARATED | TAG_SEPARATED_ALT)                         and len(raw) == 8:
                    out[cid] = {"separated": True, "reference": raw}
                    continue
            out[cid] = raw
        return out

    def _tagged_start(self):
        n = self.last_variable - 127
        if n <= 0:
            return self.var_offset
        base = self.var_offset
        if base + 2 * n > len(self.blob):
            return None
        last_end = 0
        for i in range(n):
            last_end = max(last_end, _u16(self.blob, base + 2 * i) & 0x7FFF)
        return base + 2 * n + last_end

    def variable_values(self):
        n = self.last_variable - 127
        if n <= 0:
            return {}
        base = self.var_offset
        if base + 2 * n > len(self.blob):
            return {}
        data_at = base + 2 * n
        out, prev = {}, 0
        for i in range(n):
            raw = _u16(self.blob, base + 2 * i)
            end = raw & 0x7FFF
            if not raw & 0x8000 and end >= prev and data_at + end <= len(self.blob):
                out[128 + i] = self.blob[data_at + prev:data_at + end]
            prev = end
        return out

class EseDb:

    def __init__(self, data):
        if not looks_like_ese(data[:8]):
            raise NotEse("not an ESE database (no 0x89ABCDEF signature)")
        self.data = data
        self.format_version = _u32(data, 8)
        self.file_type = _u32(data, 12)
        self.page_size = _u32(data, PAGE_SIZE_OFFSET)
        if self.page_size not in (2048, 4096, 8192, 16384, 32768):
            raise EseError("page size %r is not one this format uses"
                           % self.page_size)
        self.header_size = 40 if self.page_size <= 8192 else 80
        state = _u32(data, STATE_OFFSET)
        self.state = state
        self.state_name = STATES.get(state, "unknown (%d)" % state)
        self.clean = state == 3
        self.findings = []
        if not self.clean:
            self.findings.append(
                "The database was not shut down cleanly (%s). Changes since "
                "the last checkpoint are in the transaction logs beside it "
                "and are not in this file." % self.state_name)
        self.tagged_flags = self.format_version >= TAGGED_FLAGS_FROM
        self.page_count = max(0, len(data) // self.page_size - 2)
        if len(data) % self.page_size:
            self.findings.append(
                "The file is not a whole number of %d-byte pages; the last "
                "one is incomplete." % self.page_size)

    def page(self, number):
        if number < 1:
            return None
        off = (number + 1) * self.page_size
        if off + self.page_size > len(self.data):
            return None
        return Page(number, self.data[off:off + self.page_size],
                    self.header_size)

    def leaves(self, root_number, limit=100000):
        seen = set()
        stack = [root_number]
        out = 0
        while stack and out < limit:
            n = stack.pop()
            if n in seen:
                continue
            seen.add(n)
            pg = self.page(n)
            if pg is None or not pg.valid or pg.is_space_tree:
                continue
            if pg.is_leaf:
                out += 1
                yield pg
                nxt = pg.next
                if nxt and nxt not in seen:
                    stack.append(nxt)
                continue
            for child in _branch_children(pg):
                if child and child not in seen:
                    stack.append(child)

    def catalog(self):
        root = self.page(CATALOG_PAGE)
        if root is None or not root.valid:
            raise EseError("no readable catalog at page %d" % CATALOG_PAGE)
        if root.fdp != CATALOG_OBJID:
            raise EseError(
                "page %d is object %d, not the catalog (%d)"
                % (CATALOG_PAGE, root.fdp, CATALOG_OBJID))

        tables, columns, rows = {}, {}, 0
        for pg in self.leaves(CATALOG_PAGE):
            for _key, value in pg.entries():
                rec = _catalog_record(value)
                if rec is None:
                    continue
                rows += 1
                kind = rec.get("type")
                if kind == TYPE_TABLE:
                    tables[rec["id"]] = {
                        "name": rec.get("name"), "objid": rec["id"],
                        "root_page": rec.get("fdp"), "columns": [],
                    }
                elif kind == TYPE_COLUMN:
                    columns.setdefault(rec["objid_table"], []).append({
                        "name": rec.get("name"), "id": rec["id"],
                        "type": rec.get("fdp"),
                        "type_name": COLUMN_TYPES.get(rec.get("fdp"),
                                                      "unknown"),
                        "size": rec.get("space_usage"),
                        "codepage": rec.get("pages_or_locale"),
                    })
        for objid, cols in columns.items():
            if objid in tables:
                tables[objid]["columns"] = sorted(cols, key=lambda c: c["id"])
        out = sorted(tables.values(), key=lambda t: (t["name"] or ""))
        return {"tables": out, "records": rows}

    def long_values(self, root, limit=20000):
        sizes, chunks = {}, {}
        for pg in self.leaves(root):
            if not pg.flags & FLAG_LONG_VALUE:
                continue
            for key, value in pg.entries():
                if len(key) == 8 and len(value) >= 8:
                    _refs, size = struct.unpack("<II", value[:8])
                    sizes[key] = size
                elif len(key) == 12:
                    lid, offset = key[:8], int.from_bytes(key[8:], "big")
                    chunks.setdefault(lid, []).append((offset, value))
            if len(chunks) >= limit:
                break
        out = {}
        for lid, parts in chunks.items():
            parts.sort()
            data = b"".join(v for _o, v in parts)
            want = sizes.get(lid)
            out[lid] = {"data": data, "size": want,
                        "short": want is not None and len(data) < want}
        return out

    def _long_value_root(self, objid):
        for pg in self.leaves(CATALOG_PAGE):
            for i, blob, flags in pg.tags():
                if i == 0:
                    continue
                _k, value, _c = split_entry(blob, flags, pg.big)
                rec = _catalog_record(value)
                if rec and rec["type"] == TYPE_LONG_VALUE \
                        and rec["objid_table"] == objid:
                    return rec["fdp"]
        return None

    def rows(self, table, limit=100000):
        cols = table.get("columns") or []
        widths = [(c["id"], FIXED_WIDTHS[c["type"]]) for c in cols
                  if c["type"] in FIXED_WIDTHS]
        by_id = {c["id"]: c for c in cols}
        root = table.get("root_page")
        if not root:
            return {"rows": [], "read": 0, "skipped": 0, "markers": 0,
                    "note": "the catalog gives this table no root page"}

        lv_cache = {}

        def resolve(ref):
            if not lv_cache:
                page = self._long_value_root(table.get("objid"))
                lv_cache["root"] = page
                lv_cache["values"] = self.long_values(page) if page else {}
            if not lv_cache["root"]:
                return {"inline": ref}
            key = reference_key(ref)
            got = lv_cache["values"].get(key) if key else None
            if got is None:
                return {"long_value": key.hex() if key else None,
                        "resolved": False,
                        "note": "not in this table's long-value tree"}
            return got

        out, skipped, markers = [], 0, 0
        for pg in self.leaves(root):
            for _key, value in pg.entries():
                if len(out) >= limit:
                    break
                if len(value) < RECORD_HEADER:
                    markers += 1
                    continue
                try:
                    rec = Record(value)
                except EseError:
                    skipped += 1
                    continue
                if rec.last_fixed > 127 or rec.var_offset > len(value):
                    skipped += 1
                    continue
                raw = {}
                raw.update(rec.fixed_values(widths))
                raw.update(rec.variable_values())
                raw.update(rec.tagged_values(strip_flags=self.tagged_flags))
                row = {}
                for cid, blob_v in raw.items():
                    col = by_id.get(cid)
                    if col is None:
                        continue
                    if isinstance(blob_v, dict) and blob_v.get("separated"):
                        found = resolve(blob_v.get("reference"))
                        if "inline" in found:
                            blob_v = found["inline"]
                        elif found.get("resolved") is False:
                            row[col["name"] or ("column_%d" % cid)] = found
                            continue
                        else:
                            blob_v = found["data"]
                        if found.get("short"):
                            row[(col["name"] or "column_%d" % cid)
                                + " (truncated)"] = True
                    row[col["name"] or ("column_%d" % cid)] = decode_value(
                        blob_v, col["type"], col.get("codepage"))
                if row:
                    out.append(row)
                else:
                    skipped += 1
        return {"rows": out, "read": len(out), "skipped": skipped,
                "markers": markers, "truncated": len(out) >= limit}

    def table(self, name):
        for t in self.catalog()["tables"]:
            if t["name"] == name:
                return t
        return None

    def info(self):
        out = {
            "format": "ESE database",
            "format_version": "0x%X" % self.format_version,
            "page_size": self.page_size,
            "pages": self.page_count,
            "state": self.state_name,
            "clean": self.clean,
            "findings": list(self.findings),
        }
        try:
            cat = self.catalog()
            out["tables"] = [
                {"name": t["name"], "columns": len(t["columns"]),
                 "objid": t["objid"], "root_page": t["root_page"]}
                for t in cat["tables"]]
            out["catalog_records"] = cat["records"]
        except EseError as exc:
            out["tables"] = []
            out["findings"].append("The catalog could not be read: %s" % exc)
        return out

CATALOG_FIXED = [(COL_OBJID_TABLE, 4), (COL_TYPE, 2), (COL_ID, 4),
                 (COL_COLTYP_OR_FDP, 4), (COL_SPACE_USAGE, 4),
                 (COL_FLAGS, 4), (COL_PAGES_OR_LOCALE, 4),
                 (8, 1), (9, 2), (10, 4), (11, 2)]

CATALOG_FIXED = [(COL_OBJID_TABLE, 4), (COL_TYPE, 2), (COL_ID, 4),
                 (COL_COLTYP_OR_FDP, 4), (COL_SPACE_USAGE, 4),
                 (COL_FLAGS, 4), (COL_PAGES_OR_LOCALE, 4),
                 (8, 1), (9, 2), (10, 4), (11, 2)]

NAME_ENCODINGS = ("ascii", "utf-16-le", "latin-1")

def _text(raw):
    if not raw:
        return None
    for enc in NAME_ENCODINGS:
        try:
            got = raw.decode(enc).rstrip(chr(0))
        except UnicodeDecodeError:
            continue
        if got:
            return got
    return None

def _catalog_record(value):
    try:
        rec = Record(value)
    except EseError:
        return None
    if not rec.last_fixed or rec.var_offset > len(value):
        return None
    fixed = rec.fixed_values(CATALOG_FIXED)

    def num(cid):
        got = fixed.get(cid)
        return int.from_bytes(got, "little") if got else None

    kind, ident = num(COL_TYPE), num(COL_ID)
    if kind not in TYPE_NAMES or ident is None:
        return None
    return {
        "objid_table": num(COL_OBJID_TABLE),
        "type": kind,
        "id": ident,
        "fdp": num(COL_COLTYP_OR_FDP),
        "space_usage": num(COL_SPACE_USAGE),
        "pages_or_locale": num(COL_PAGES_OR_LOCALE),
        "name": _text(rec.variable_values().get(COL_NAME)),
    }

def open_db(data):
    try:
        return EseDb(data)
    except NotEse:
        return None
