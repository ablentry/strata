import struct

V2_HEAD = 0x3C
V3_HEAD = 0x4C

MAX_RECORD = 0x10000

REASONS = [
    (0x00000001, "data overwrite"),
    (0x00000002, "data extend"),
    (0x00000004, "data truncation"),
    (0x00000010, "named data overwrite"),
    (0x00000020, "named data extend"),
    (0x00000040, "named data truncation"),
    (0x00000100, "created"),
    (0x00000200, "deleted"),
    (0x00000400, "extended attributes changed"),
    (0x00000800, "security changed"),
    (0x00001000, "renamed from"),
    (0x00002000, "renamed to"),
    (0x00004000, "indexable changed"),
    (0x00008000, "basic info changed"),
    (0x00010000, "hard link changed"),
    (0x00020000, "compression changed"),
    (0x00040000, "encryption changed"),
    (0x00080000, "object id changed"),
    (0x00100000, "reparse point changed"),
    (0x00200000, "stream changed"),
    (0x00400000, "transacted change"),
    (0x00800000, "integrity changed"),
    (0x80000000, "closed"),
]

SOURCES = [
    (0x00000001, "data management"),
    (0x00000002, "auxiliary data"),
    (0x00000004, "replication management"),
    (0x00000008, "client replication management"),
]

ATTRS = [
    (0x00000001, "read-only"),
    (0x00000002, "hidden"),
    (0x00000004, "system"),
    (0x00000010, "directory"),
    (0x00000020, "archive"),
    (0x00000040, "device"),
    (0x00000080, "normal"),
    (0x00000100, "temporary"),
    (0x00000200, "sparse"),
    (0x00000400, "reparse point"),
    (0x00000800, "compressed"),
    (0x00001000, "offline"),
    (0x00002000, "not content indexed"),
    (0x00004000, "encrypted"),
]

def _flags(value, table):
    out = [name for bit, name in table if value & bit]
    known = 0
    for bit, _n in table:
        known |= bit
    left = value & ~known
    if left:
        out.append("unknown 0x%08X" % left)
    return out

def filetime(v):
    if not v or v < 0:
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

def journal_info(blob):
    if not blob or len(blob) < 32:
        return {"readable": False,
                "note": "The $Max stream is missing or short, so the journal's "
                        "identity and size cap are unknown. Records in $J may "
                        "still be readable."}
    mx, delta, jid, lowest = struct.unpack_from("<QQQq", blob, 0)
    return {"readable": True, "max_size": mx, "allocation_delta": delta,
            "journal_id": "0x%016X" % jid, "lowest_valid_usn": lowest,
            "note": "Records below the lowest valid USN have been purged; the "
                    "journal id changes if the journal is deleted and "
                    "recreated, and USNs restart when it does."}

def parse_record(buf, off, stream_offset=None):
    if off + 8 > len(buf):
        return None, 0
    length, major, minor = struct.unpack_from("<IHH", buf, off)
    if length == 0:
        return None, 0
    if length < 8 or length > MAX_RECORD or length % 8:
        return None, 0
    if off + length > len(buf):
        return None, 0
    if major == 2:
        head = V2_HEAD
    elif major == 3:
        head = V3_HEAD
    elif major == 4:
        head = 0x20
    else:
        return None, 0
    if length < head:
        return None, 0

    if major == 2:
        (fref, pref, usn, ts, reason, src, sid, attrs,
         nlen, noff) = struct.unpack_from("<QQqQIIIIHH", buf, off + 8)
        mft, seq = fref & ((1 << 48) - 1), fref >> 48
        pmft, pseq = pref & ((1 << 48) - 1), pref >> 48
    elif major == 3:
        fref = buf[off + 8:off + 24]
        pref = buf[off + 24:off + 40]
        (usn, ts, reason, src, sid, attrs,
         nlen, noff) = struct.unpack_from("<qQIIIIHH", buf, off + 40)
        mft = int.from_bytes(fref[:6], "little")
        seq = int.from_bytes(fref[6:8], "little")
        pmft = int.from_bytes(pref[:6], "little")
        pseq = int.from_bytes(pref[6:8], "little")
    else:
        usn, = struct.unpack_from("<q", buf, off + 0x18) if length >= 0x20 else (0,)
        if stream_offset is not None and usn != stream_offset:
            return None, 0
        return {"usn": usn, "version": "%d.%d" % (major, minor),
                "kind": "extent", "name": None, "mft": None, "parent_mft": None,
                "reasons": [], "timestamp": None,
                "note": "A range-tracking extent record: it describes where a "
                        "change landed, not which file it was."}, length

    if stream_offset is not None and usn != stream_offset:
        return None, 0
    if nlen == 0 or nlen % 2 or noff < head or noff + nlen > length:
        return None, 0
    try:
        name = buf[off + noff:off + noff + nlen].decode("utf-16le")
    except UnicodeDecodeError:
        name = buf[off + noff:off + noff + nlen].decode("utf-16le", "replace")

    return {
        "usn": usn,
        "version": "%d.%d" % (major, minor),
        "kind": "record",
        "name": name,
        "mft": mft, "seq": seq,
        "parent_mft": pmft, "parent_seq": pseq,
        "timestamp": filetime(ts),
        "reason_raw": reason,
        "reasons": _flags(reason, REASONS),
        "sources": _flags(src, SOURCES),
        "attributes": _flags(attrs, ATTRS),
        "security_id": sid,
        "is_dir": bool(attrs & 0x10),
    }, length

def find(fs):
    try:
        entries = fs.listdir(11)
    except Exception:
        return None
    ent = next((e for e in entries
                if (e.get("name") or "").lower() == "$usnjrnl"), None)
    if not ent:
        return None
    rec = fs.record(ent["mft"])
    if not rec:
        return None
    j = mx = None
    for a in rec.data_attrs():
        if a.name == "$J":
            j = a
        elif a.name == "$Max":
            mx = a
    if j is None:
        return None
    return ent, j, mx

def read(fs, j_attr, limit=None, progress=None, chunk=1 << 22):
    out = []
    stats = {"bytes_read": 0, "records": 0, "resyncs": 0, "resync_bytes": 0,
             "extents": 0, "sparse_skipped": 0, "truncated": False}

    if j_attr.resident:
        extents = [(0, None, len(j_attr.body or b""))]
    else:
        extents = list(fs.attr_extents(j_attr))
    live = sum(n for _s, _m, n in extents)
    stats["extents"] = len(extents)
    stats["sparse_skipped"] = max(0, (j_attr.real_size or 0) - live)

    done = 0
    for start, _media, span in extents:
        pos = start
        carry = b""
        carry_at = start
        while pos < start + span:
            take = min(chunk, start + span - pos)
            buf = carry + fs.read_attr_range(j_attr, pos, take)
            base = carry_at if carry else pos
            pos += take
            done += take
            stats["bytes_read"] += take
            if progress and live:
                progress(min(1.0, done / live))

            off = 0
            while off < len(buf):
                rec, n = parse_record(buf, off, stream_offset=base + off)
                if rec is None:
                    if buf[off:off + 8] == b"\x00" * 8:
                        off += 8
                        continue
                    if len(buf) - off < MAX_RECORD and pos < start + span:
                        break
                    off += 8
                    stats["resyncs"] += 1
                    stats["resync_bytes"] += 8
                    continue
                out.append(rec)
                stats["records"] += 1
                off += n
                if limit and len(out) >= limit:
                    stats["truncated"] = True
                    return out, stats
            carry = buf[off:]
            carry_at = base + off
            if len(carry) > MAX_RECORD:
                carry = b""
    return out, stats
