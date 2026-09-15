import datetime
import struct
import uuid

VSS_GUID = "3808876b-c176-4e48-b7ae-04046e6cc752"
VOLUME_HEADER_OFFSET = 0x1E00
CATALOG_BLOCK_SIZE = 0x4000
CATALOG_ENTRY_SIZE = 128
ENTRY_END = 0x01
ENTRY_STORE = 0x02
ENTRY_STORE_LOCATION = 0x03

def filetime(v):
    if not v:
        return None
    try:
        return (datetime.datetime(1601, 1, 1)
                + datetime.timedelta(microseconds=v // 10)).isoformat() + "Z"
    except (OverflowError, ValueError):
        return None

def _guid(b):
    try:
        return str(uuid.UUID(bytes_le=b))
    except (ValueError, TypeError):
        return None

def detect(source):
    try:
        hdr = source.read_at(VOLUME_HEADER_OFFSET, 128)
    except Exception:
        return None
    if len(hdr) < 128:
        return None
    if _guid(hdr[0:16]) != VSS_GUID:
        return None
    version, rec_type = struct.unpack_from("<II", hdr, 16)
    current, catalog, maximum = struct.unpack_from("<QQQ", hdr, 24)
    return {
        "present": True, "version": version, "record_type": rec_type,
        "current_offset": current, "catalog_offset": catalog,
        "maximum_size": maximum,
    }

def read_catalog(source, catalog_offset, limit_blocks=64):
    entries = []
    offset = catalog_offset
    seen = set()
    blocks = 0
    while offset and offset not in seen and blocks < limit_blocks:
        seen.add(offset)
        blocks += 1
        try:
            block = source.read_at(offset, CATALOG_BLOCK_SIZE)
        except Exception:
            break
        if len(block) < 128:
            break
        if _guid(block[0:16]) != VSS_GUID:
            break
        nxt = struct.unpack_from("<Q", block, 40)[0]
        pos = 128
        stop = False
        while pos + CATALOG_ENTRY_SIZE <= len(block):
            etype = struct.unpack_from("<Q", block, pos)[0]
            if etype == ENTRY_END:
                stop = True
                break
            if etype in (ENTRY_STORE, ENTRY_STORE_LOCATION):
                entries.append((etype, block[pos:pos + CATALOG_ENTRY_SIZE]))
            pos += CATALOG_ENTRY_SIZE
        if stop:
            break
        offset = nxt
    return entries

def snapshots(source):
    info = detect(source)
    if not info:
        return {"present": False, "snapshots": [], "findings": []}

    raw = read_catalog(source, info["catalog_offset"])
    stores, locations = {}, {}
    order = []
    for etype, e in raw:
        if etype == ENTRY_STORE:
            vol_size = struct.unpack_from("<Q", e, 8)[0]
            gid = _guid(e[16:32])
            created = struct.unpack_from("<Q", e, 32)[0]
            if gid:
                stores[gid] = {"id": gid, "volume_size": vol_size,
                               "created_at": filetime(created)}
                order.append(gid)
        else:
            gid = _guid(e[8:24])
            hdr, blist, brange, bitmap = struct.unpack_from("<QQQQ", e, 24)
            if gid:
                locations[gid] = {"header_offset": hdr,
                                  "block_list_offset": blist,
                                  "block_range_offset": brange,
                                  "bitmap_offset": bitmap}

    findings = []
    out = []
    for gid in order:
        snap = dict(stores[gid])
        loc = locations.get(gid)
        if not loc:
            snap["unsupported"] = ("No location entry in the catalog, so this "
                                   "snapshot's blocks cannot be found.")
            findings.append("Shadow copy %s has no store location entry." % gid[:8])
        else:
            snap.update(loc)
        out.append(snap)

    out.sort(key=lambda s: s.get("created_at") or "", reverse=True)
    return {"present": True, "snapshots": out, "findings": findings,
            "catalog_offset": info["catalog_offset"],
            "volume_maximum": info["maximum_size"]}
