import re
import struct

MAGIC = b"SQLite format 3\x00"

PAGE_INTERIOR_INDEX = 0x02
PAGE_INTERIOR_TABLE = 0x05
PAGE_LEAF_INDEX = 0x0A
PAGE_LEAF_TABLE = 0x0D

TEXT_ENCODINGS = {1: "utf-8", 2: "utf-16-le", 3: "utf-16-be"}

def varint(data, pos):
    val = 0
    for i in range(9):
        if pos >= len(data):
            return val, pos
        b = data[pos]
        pos += 1
        if i == 8:
            val = (val << 8) | b
        else:
            val = (val << 7) | (b & 0x7F)
            if not b & 0x80:
                break
    if val >= 1 << 63:
        val -= 1 << 64
    return val, pos

def _rowid_alias(sql):
    if not sql:
        return None
    m = re.search(r"[(,]\s*[\"`\[]?(\w+)[\"`\]]?\s+INTEGER\s+PRIMARY\s+KEY",
                  sql, re.I)
    return m.group(1) if m else None

def _column_names(sql):
    if not sql:
        return []
    m = re.search(r"\((.*)\)\s*(?:WITHOUT\s+ROWID\s*)?$", sql,
                  re.S | re.I)
    if not m:
        return []
    body = m.group(1)
    cols, depth, cur = [], 0, ""
    for ch in body:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            cols.append(cur)
            cur = ""
        else:
            cur += ch
    cols.append(cur)

    out = []
    for c in cols:
        c = c.strip()
        if not c:
            continue
        head = c.split()[0].strip('"`[]')
        if head.upper() in ("PRIMARY", "UNIQUE", "CHECK", "FOREIGN",
                            "CONSTRAINT"):
            continue
        out.append(head)
    return out

class Database:
    def __init__(self, data, wal=None):
        self.data = data
        self.wal = wal
        self.valid = data[:16] == MAGIC
        self.findings = []
        if not self.valid:
            return
        self.page_size = struct.unpack_from(">H", data, 16)[0]
        if self.page_size == 1:
            self.page_size = 65536
        self.reserved = data[20]
        self.page_count = struct.unpack_from(">I", data, 28)[0] or \
            (len(data) // self.page_size)
        self.freelist_head = struct.unpack_from(">I", data, 32)[0]
        self.freelist_count = struct.unpack_from(">I", data, 36)[0]
        enc = struct.unpack_from(">I", data, 56)[0]
        self.encoding = TEXT_ENCODINGS.get(enc, "utf-8")
        self.write_version = data[18]
        if self.write_version == 2:
            self.findings.append(
                "Database is in WAL mode; recent changes may live in the -wal "
                "file rather than here.")
        actual = len(data) // self.page_size
        if actual < self.page_count:
            self.findings.append(
                "Header declares %d pages but the file holds %d — it is "
                "truncated." % (self.page_count, actual))
            self.page_count = actual

    def page(self, n):
        if n < 1 or n > self.page_count:
            return None
        off = (n - 1) * self.page_size
        return self.data[off:off + self.page_size]

    def _page_header(self, buf, page_no):
        base = 100 if page_no == 1 else 0
        if base + 8 > len(buf):
            return None
        ptype = buf[base]
        if ptype not in (PAGE_INTERIOR_INDEX, PAGE_INTERIOR_TABLE,
                         PAGE_LEAF_INDEX, PAGE_LEAF_TABLE):
            return None
        first_free, ncells, content_start = struct.unpack_from(">HHH", buf,
                                                               base + 1)
        if content_start == 0:
            content_start = 65536
        hdr_len = 12 if ptype in (PAGE_INTERIOR_INDEX, PAGE_INTERIOR_TABLE) else 8
        right = None
        if hdr_len == 12:
            right = struct.unpack_from(">I", buf, base + 8)[0]
        return {"type": ptype, "first_free": first_free, "cells": ncells,
                "content_start": content_start, "right": right,
                "cell_array": base + hdr_len}

    def decode_record(self, payload):
        hdr_size, pos = varint(payload, 0)
        if hdr_size <= 0 or hdr_size > len(payload):
            return None
        types = []
        p = pos
        while p < hdr_size:
            t, p = varint(payload, p)
            types.append(t)
        vals = []
        p = hdr_size
        for t in types:
            if t == 0:
                vals.append(None)
            elif t in (1, 2, 3, 4, 5, 6):
                width = {1: 1, 2: 2, 3: 3, 4: 4, 5: 6, 6: 8}[t]
                raw = payload[p:p + width]
                if len(raw) < width:
                    return vals
                v = int.from_bytes(raw, "big", signed=True)
                vals.append(v)
                p += width
            elif t == 7:
                raw = payload[p:p + 8]
                vals.append(struct.unpack(">d", raw)[0] if len(raw) == 8 else None)
                p += 8
            elif t == 8:
                vals.append(0)
            elif t == 9:
                vals.append(1)
            elif t >= 12 and t % 2 == 0:
                n = (t - 12) // 2
                vals.append(payload[p:p + n])
                p += n
            elif t >= 13:
                n = (t - 13) // 2
                raw = payload[p:p + n]
                vals.append(raw.decode(self.encoding, "replace"))
                p += n
            else:
                vals.append(None)
        return vals

    def _payload(self, buf, pos, payload_size):
        usable = self.page_size - self.reserved
        max_local = usable - 35
        if payload_size <= max_local:
            return buf[pos:pos + payload_size], pos + payload_size

        min_local = ((usable - 12) * 32 // 255) - 23
        local = min_local + (payload_size - min_local) % (usable - 4)
        if local > max_local:
            local = min_local
        out = bytearray(buf[pos:pos + local])
        pos += local
        nxt = struct.unpack_from(">I", buf, pos)[0] if pos + 4 <= len(buf) else 0
        pos += 4
        seen = set()
        while nxt and nxt not in seen and len(out) < payload_size:
            seen.add(nxt)
            pg = self.page(nxt)
            if not pg:
                break
            nxt = struct.unpack_from(">I", pg, 0)[0]
            out += pg[4:usable]
        return bytes(out[:payload_size]), pos

    def table_rows(self, root, limit=100000, _seen=None):
        out = []
        stack = [root]
        seen = _seen if _seen is not None else set()
        while stack and len(out) < limit:
            n = stack.pop()
            if n in seen or n < 1:
                continue
            seen.add(n)
            buf = self.page(n)
            if not buf:
                continue
            h = self._page_header(buf, n)
            if not h:
                continue
            ptrs = []
            for i in range(h["cells"]):
                o = h["cell_array"] + i * 2
                if o + 2 > len(buf):
                    break
                ptrs.append(struct.unpack_from(">H", buf, o)[0])

            if h["type"] == PAGE_INTERIOR_TABLE:
                for cp in ptrs:
                    if cp + 4 <= len(buf):
                        stack.append(struct.unpack_from(">I", buf, cp)[0])
                if h["right"]:
                    stack.append(h["right"])
                continue

            if h["type"] == PAGE_INTERIOR_INDEX:
                for cp in ptrs:
                    if cp + 4 > len(buf):
                        continue
                    stack.append(struct.unpack_from(">I", buf, cp)[0])
                    size, p = varint(buf, cp + 4)
                    payload, _ = self._payload(buf, p, size)
                    vals = self.decode_record(payload)
                    if vals is not None:
                        out.append((None, vals))
                if h["right"]:
                    stack.append(h["right"])
                continue

            if h["type"] == PAGE_LEAF_INDEX:
                for cp in ptrs:
                    if cp >= len(buf):
                        continue
                    size, p = varint(buf, cp)
                    payload, _ = self._payload(buf, p, size)
                    vals = self.decode_record(payload)
                    if vals is not None:
                        out.append((None, vals))
                continue

            if h["type"] != PAGE_LEAF_TABLE:
                continue

            for cp in ptrs:
                if cp >= len(buf):
                    continue
                size, p = varint(buf, cp)
                rowid, p = varint(buf, p)
                payload, _ = self._payload(buf, p, size)
                vals = self.decode_record(payload)
                if vals is not None:
                    out.append((rowid, vals))
        return out

    def schema(self):
        tables = []
        for rowid, vals in self.table_rows(1):
            if len(vals) < 5:
                continue
            typ, name, tbl, root, sql = vals[0], vals[1], vals[2], vals[3], vals[4]
            tables.append({
                "type": typ, "name": name, "table": tbl, "root": root,
                "sql": sql,
                "columns": _column_names(sql if isinstance(sql, str) else ""),
                "rowid_alias": _rowid_alias(sql if isinstance(sql, str) else ""),
            })
        return tables

    def tables(self):
        return [t for t in self.schema() if t["type"] == "table" and t["root"]]

    def read_table(self, name, limit=100000):
        t = next((x for x in self.tables() if x["name"] == name), None)
        if not t:
            return None
        rows = self.table_rows(t["root"], limit)
        cols = t["columns"]
        alias = t.get("rowid_alias")
        out = []
        for rowid, vals in rows:
            if cols and len(cols) == len(vals):
                d = dict(zip(cols, vals))
            else:
                d = {("col%d" % i): v for i, v in enumerate(vals)}
            if alias and rowid is not None and d.get(alias) is None:
                d[alias] = rowid
            d["_rowid"] = rowid
            out.append(d)
        return {"name": name, "columns": cols, "rows": out,
                "sql": t.get("sql")}

    def recover(self, limit=20000):
        found = []
        counts = {"freeblock": 0, "freelist": 0, "unallocated": 0}

        for n in range(1, self.page_count + 1):
            if len(found) >= limit:
                break
            buf = self.page(n)
            if not buf:
                continue
            h = self._page_header(buf, n)
            if not h:
                continue

            fb = h["first_free"]
            guard = 0
            while fb and fb + 4 <= len(buf) and guard < 512:
                guard += 1
                nxt, size = struct.unpack_from(">HH", buf, fb)
                blob = buf[fb + 4: fb + max(4, size)]
                for rec in self._carve_records(blob):
                    rec.update({"page": n, "source": "freeblock"})
                    found.append(rec)
                    counts["freeblock"] += 1
                fb = nxt if nxt > fb else 0

            gap_start = h["cell_array"] + h["cells"] * 2
            gap_end = h["content_start"]
            if gap_end > gap_start and gap_end <= len(buf):
                for rec in self._carve_records(buf[gap_start:gap_end]):
                    rec.update({"page": n, "source": "unallocated"})
                    found.append(rec)
                    counts["unallocated"] += 1

        nxt = self.freelist_head
        seen = set()
        while nxt and nxt not in seen and len(found) < limit:
            seen.add(nxt)
            pg = self.page(nxt)
            if not pg:
                break
            nxt = struct.unpack_from(">I", pg, 0)[0]
            for rec in self._carve_records(pg[8:]):
                rec.update({"page": list(seen)[-1], "source": "freelist"})
                found.append(rec)
                counts["freelist"] += 1

        return {"records": found, "counts": counts,
                "freelist_pages": len(seen)}

    def _carve_records(self, blob, min_cols=2):
        out = []
        i = 0
        n = len(blob)
        while i < n - 4:
            hdr_size, p = varint(blob, i)
            if hdr_size < 2 or hdr_size > 0x7FFF or i + hdr_size > n:
                i += 1
                continue
            types = []
            q = p
            ok = True
            while q < i + hdr_size:
                t, q = varint(blob, q)
                if t < 0 or t > 0x7FFFFF:
                    ok = False
                    break
                types.append(t)
            if not ok or len(types) < min_cols or q != i + hdr_size:
                i += 1
                continue
            vals = self.decode_record(blob[i:])
            if not vals or len(vals) < min_cols:
                i += 1
                continue
            useful = [v for v in vals
                      if isinstance(v, (str, bytes)) and len(v) >= 4]
            if not useful:
                i += 1
                continue
            out.append({"values": vals, "deleted": True, "offset": i})
            i += max(1, hdr_size)
        return out

    def info(self):
        return {
            "type": "sqlite", "page_size": self.page_size,
            "pages": self.page_count, "encoding": self.encoding,
            "wal_mode": self.write_version == 2,
            "freelist_pages": self.freelist_count,
            "findings": self.findings,
        }

def open_db(data, wal=None):
    db = Database(data, wal)
    return db if db.valid else None

def looks_like_sqlite(head):
    return head[:16] == MAGIC
