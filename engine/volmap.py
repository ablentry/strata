import struct

BOOT = "boot"
METADATA = "metadata"
JOURNAL = "journal"
BITMAP = "bitmap"
TABLE = "table"
DATA = "data"

def _span(name, offset, length, kind, note=None):
    out = {"name": name, "offset": int(offset), "length": int(length),
           "kind": kind}
    if note:
        out["note"] = note
    return out

NTFS_SYSTEM = {
    0: (METADATA, "the record of every file on the volume"),
    1: (METADATA, "the first four MFT records, mirrored"),
    2: (JOURNAL, "the transaction log"),
    3: (METADATA, "volume name, version and dirty flag"),
    4: (METADATA, "the attribute definitions this volume uses"),
    5: (METADATA, "the root directory"),
    6: (BITMAP, "one bit per cluster: allocated or free"),
    7: (BOOT, "the boot sector and loader"),
    8: (METADATA, "clusters marked bad"),
    9: (METADATA, "security descriptors, shared between files"),
    10: (METADATA, "the uppercase table used for name comparison"),
    11: (METADATA, "the directory holding $UsnJrnl, $Quota and $ObjId"),
}

def _ntfs(fs):
    spans = []
    for number, (kind, note) in NTFS_SYSTEM.items():
        try:
            rec = fs.record(number)
        except Exception:
            continue
        if rec is None:
            continue
        name = rec.best_name() or "MFT record %d" % number
        for attr in rec.data_attrs():
            try:
                extents = list(fs.attr_extents(attr))
            except Exception:
                continue
            for _stream_off, media_off, length in extents:
                if length <= 0:
                    continue
                spans.append(_span(name, media_off, length, kind, note))
    return spans

def _fat(fs):
    bps = getattr(fs, "bytes_per_sector", 0) or 0
    reserved = getattr(fs, "reserved_sectors", 0) or 0
    num_fats = getattr(fs, "num_fats", 0) or 0
    fat_size = getattr(fs, "fat_size", 0) or 0
    if not bps or not reserved or not fat_size:
        return []

    spans = [_span("Reserved region", 0, reserved * bps, BOOT,
                   "boot sector, FS information sector and their spares")]
    for i in range(num_fats):
        off = (reserved + i * fat_size) * bps
        label = ("Primary FAT" if i == 0 else
                 "Backup FAT" if i == 1 and num_fats == 2 else
                 "FAT copy %d" % (i + 1))
        spans.append(_span(label, off, fat_size * bps, TABLE,
                           "the cluster chains for every file"
                           if i == 0 else
                           "a duplicate of the table above, kept in step "
                           "by the driver"))

    root_entries = getattr(fs, "root_entries", 0) or 0
    if root_entries:
        off = (reserved + num_fats * fat_size) * bps
        spans.append(_span("Root directory", off, root_entries * 32, METADATA,
                           "a fixed-size table, unlike every other directory"))

    first_data = getattr(fs, "first_data_sector", 0) or 0
    if first_data:
        spans.append(_span("Data region", first_data * bps, 0, DATA,
                           "clusters begin here"))
    return spans

def _exfat(fs):
    bps = getattr(fs, "bytes_per_sector", 0) or 0
    if not bps:
        return []
    spans = []
    fat_off = getattr(fs, "fat_offset", 0) or 0
    fat_len = getattr(fs, "fat_length", 0) or 0
    if fat_off:
        spans.append(_span("Boot region", 0, fat_off * bps, BOOT,
                           "boot sector, its checksum and the backup copy"))
        spans.append(_span("FAT", fat_off * bps, fat_len * bps, TABLE,
                           "cluster chains, used only where a file is "
                           "fragmented"))
    data = getattr(fs, "data_offset", 0) or 0
    if data:
        spans.append(_span("Cluster heap", data, 0, DATA,
                           "clusters begin here"))
    return spans

MAX_SPANS = 192

def _ext(fs):
    bs = getattr(fs, "block_size", 0) or 0
    if not bs:
        return []

    spans = [_span("Superblock", 1024, 1024, METADATA,
                   "the volume's own parameters, at a fixed 1024 bytes in")]

    groups = getattr(fs, "group_count", 0) or 0
    desc_size = getattr(fs, "desc_size", 0) or 0
    first = getattr(fs, "first_data_block", 0) or 0
    if groups and desc_size:
        spans.append(_span("Group descriptors", (first + 1) * bs,
                           groups * desc_size, TABLE,
                           "where each block group keeps its bitmaps and "
                           "inode table"))

    inum = getattr(fs, "journal_inum", 0) or 0
    if inum:
        try:
            ino = fs.inode(inum)
            for run in (fs.runs(ino) if ino else []):
                if run.get("sparse") or not run.get("length"):
                    continue
                spans.append(_span("Journal", run["offset"], run["length"],
                                   JOURNAL,
                                   "changes are written here before they are "
                                   "written to the filesystem"))
        except Exception:
            pass

    try:
        gds = fs._group_descriptors()
    except Exception:
        gds = []

    ipg = getattr(fs, "inodes_per_group", 0) or 0
    isize = getattr(fs, "inode_size", 0) or 0
    table_len = ipg * isize
    for n, g in enumerate(gds):
        if table_len and g.get("inode_table"):
            spans.append(_span("Inode table %d" % n,
                               g["inode_table"] * bs, table_len, METADATA,
                               "the inodes for this block group", ))
        if n == 0:
            if g.get("block_bitmap"):
                spans.append(_span("Block bitmap (group 0)",
                                   g["block_bitmap"] * bs, bs, BITMAP,
                                   "one bit per block in this group"))
            if g.get("inode_bitmap"):
                spans.append(_span("Inode bitmap (group 0)",
                                   g["inode_bitmap"] * bs, bs, BITMAP,
                                   "one bit per inode in this group"))
    return spans

def _family(name):
    head = name.rsplit(" ", 1)
    if len(head) == 2 and head[1].isdigit():
        return head[0], int(head[1])
    return name, None

def _merge(spans):
    if not spans:
        return spans
    spans = sorted(spans, key=lambda s: (s["offset"], s["name"]))

    def start(sp):
        acc = dict(sp)
        acc["_fam"], acc["_num"] = _family(sp["name"])
        acc["_from"] = acc["_num"]
        return acc

    out = [start(spans[0])]
    open_run = {out[0]["_fam"]: 0}
    for sp in spans[1:]:
        fam, num = _family(sp["name"])
        at = open_run.get(fam)
        prev = out[at] if at is not None else None
        joins = (prev is not None and prev["length"] and sp["length"]
                 and prev["kind"] == sp["kind"]
                 and sp["offset"] <= prev["offset"] + prev["length"])
        if not joins:
            out.append(start(sp))
            open_run[fam] = len(out) - 1
            continue
        end = max(prev["offset"] + prev["length"], sp["offset"] + sp["length"])
        prev["length"] = end - prev["offset"]
        if num is not None:
            lo = prev["_from"] if prev["_from"] is not None else num
            prev["_from"] = lo
            prev["name"] = ("%s %d\u2013%d" % (fam, lo, num) if lo != num
                            else "%s %d" % (fam, num))
    for sp in out:
        for k in ("_fam", "_num", "_from"):
            sp.pop(k, None)
    return out

HFS_FORKS = (
    ("allocation_fork", "Allocation file", BITMAP,
     "one bit per allocation block: used or free"),
    ("extents_fork", "Extents overflow", METADATA,
     "the extents of files too fragmented to fit in their catalog record"),
    ("catalog_fork", "Catalog", METADATA,
     "every file and folder on the volume, as a B-tree"),
    ("attributes_fork", "Attributes", METADATA,
     "extended attributes, where they do not fit inline"),
)

def _hfs(fs):
    bs = getattr(fs, "block_size", 0) or 0
    if not bs:
        return []

    spans = [_span("Volume header", 1024, 512, BOOT,
                   "the volume's own parameters, at a fixed 1024 bytes in")]

    total = getattr(fs, "total_blocks", 0) or 0
    if total:
        spans.append(_span("Alternate volume header", total * bs - 1024, 512,
                           BOOT, "a copy kept near the end of the volume"))

    for attr, name, kind, note in HFS_FORKS:
        fork = getattr(fs, attr, None)
        for start, count in (getattr(fork, "extents", None) or []):
            if not count:
                continue
            spans.append(_span(name, start * bs, count * bs, kind, note))

    jb = getattr(fs, "journal_block", 0) or 0
    if jb:
        spans.append(_span("Journal info block", jb * bs, bs, JOURNAL,
                           "points at the journal itself"))
    return spans

def _apfs(fs):
    c = getattr(fs, "c", None)
    if c is None:
        return []
    bs = getattr(c, "block_size", 0) or 0
    nx = getattr(c, "nx", None) or {}
    if not bs or not nx:
        return []

    spans = [_span("Container superblock", 0, bs, BOOT,
                   "NXSB at block zero; the checkpoint may hold a newer one")]

    desc_base = nx.get("xp_desc_base") or 0
    desc_blocks = nx.get("xp_desc_blocks") or 0
    if desc_base and desc_blocks:
        spans.append(_span("Checkpoint descriptors", desc_base * bs,
                           desc_blocks * bs, TABLE,
                           "a ring of superblocks; the live one is the "
                           "highest transaction id here"))

    try:
        raw = c.source.read_at(0, bs)
        if len(raw) >= 128:
            data_blocks = struct.unpack("<I", raw[108:112])[0]
            data_base = struct.unpack("<Q", raw[120:128])[0]
            if data_base and data_blocks:
                spans.append(_span("Checkpoint data", data_base * bs,
                                   data_blocks * bs, TABLE,
                                   "the ephemeral objects the live "
                                   "checkpoint refers to"))
    except Exception:
        pass

    omap = nx.get("omap_oid") or 0
    if omap:
        spans.append(_span("Container object map", omap * bs, bs, METADATA,
                           "maps each volume's object id to a block"))

    try:
        for vol in c.volumes():
            blk = getattr(vol, "block", 0) or 0
            if not blk:
                continue
            label = getattr(vol, "volume_name", None) or getattr(vol, "label",
                                                                 None)
            name = "Volume superblock" + (" (%s)" % label if label else "")
            spans.append(_span(name, blk * bs, bs, METADATA,
                               "APSB: one volume inside this container"))
            vomap = getattr(vol, "omap_oid", 0) or 0
            if vomap:
                spans.append(_span("Volume object map" +
                                   (" (%s)" % label if label else ""),
                                   vomap * bs, bs, METADATA,
                                   "maps this volume's object ids to blocks"))
    except Exception:
        pass

    return spans

MAPPERS = {
    "NTFS": _ntfs,
    "ext2": _ext, "ext3": _ext, "ext4": _ext,
    "HFS+": _hfs, "HFSX": _hfs,
    "APFS": _apfs,
    "exFAT": _exfat,
    "FAT12": _fat, "FAT16": _fat, "FAT32": _fat, "FAT": _fat,
}

UNMAPPED = ("No structure map for %s yet. The volume's own layout is not "
            "drawn — this is a gap in Strata, not a statement about the "
            "evidence.")

def volume_map(fs, size=None):
    name = (getattr(fs, "name", "") or "").upper()
    fn = None
    for key, mapper in MAPPERS.items():
        if name == key.upper():
            fn = mapper
            break
    if fn is None:
        return {"covered": False, "filesystem": getattr(fs, "name", "") or "",
                "spans": [], "note": UNMAPPED % (getattr(fs, "name", "")
                                                 or "this filesystem")}

    try:
        spans = fn(fs)
    except Exception as exc:
        return {"covered": False,
                "filesystem": getattr(fs, "name", "") or "",
                "spans": [],
                "note": "The structure map could not be read: %s" % exc}

    dropped = 0
    if size:
        keep = []
        for s in spans:
            if s["offset"] < 0 or s["offset"] >= size:
                dropped += 1
                continue
            if s["length"] and s["offset"] + s["length"] > size:
                dropped += 1
                continue
            keep.append(s)
        spans = keep

    if not spans:
        fsname = getattr(fs, "name", "") or "unknown"
        out = {"covered": False, "filesystem": getattr(fs, "name", "") or "",
               "spans": []}
        if dropped:
            out["out_of_range"] = dropped
            out["note"] = ("Every structure this %s volume reported lies "
                           "outside it, so none is drawn. The layout was "
                           "misread." % fsname)
        else:
            out["note"] = ("The layout of this %s volume could not be read, "
                           "so nothing is drawn. That is a failure to parse, "
                           "not an empty volume." % fsname)
        return out

    spans = _merge(spans)
    omitted = 0
    if len(spans) > MAX_SPANS:
        omitted = len(spans) - MAX_SPANS
        spans = spans[:MAX_SPANS]

    spans.sort(key=lambda s: (s["offset"], s["name"]))
    out = {"covered": True, "filesystem": getattr(fs, "name", "") or "",
           "spans": spans}
    if dropped:
        out["out_of_range"] = dropped
    if omitted:
        out["omitted"] = omitted
        out["note"] = ("%d further structures are not drawn; the volume has "
                       "more than the strip can carry." % omitted)
    return out
