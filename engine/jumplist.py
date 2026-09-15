import struct

from . import ole2
from . import lnk as lnk_mod

HEADER = 0x20
ENTRY = 0x80
TAIL = 4
MAX_PATH_CHARS = 4096
MAX_ENTRIES = 1 << 16

LNK_MAGIC = b"\x4c\x00\x00\x00\x01\x14\x02\x00"

FOOTER = bytes([0xAB, 0xFB, 0xBF, 0xBA])

def _hostname(raw):
    txt = raw.split(b"\x00", 1)[0].decode("latin-1", "replace").strip()
    return "".join(c for c in txt if c.isprintable()) or None

def parse_destlist(blob):
    meta = {"entries_declared": None, "pinned": None, "version": None,
            "findings": []}
    if not blob or len(blob) < 16:
        meta["findings"].append(
            "The DestList stream is empty. The Jump List exists but records "
            "no items — normal for an application that was launched and never "
            "opened a file.")
        return [], meta
    version, declared, pinned = struct.unpack_from("<III", blob, 0)
    meta.update({"version": version, "entries_declared": declared,
                 "pinned": pinned})
    if version < 3:
        meta["findings"].append(
            "DestList version %d is the Windows 7 layout, which differs from "
            "the modern one and is not implemented. Nothing was decoded "
            "rather than decoding it wrongly." % version)
        return [], meta
    if version > 16:
        meta["findings"].append(
            "DestList version %d is implausible; the stream is probably not "
            "a DestList. Nothing was decoded." % version)
        return [], meta

    out, off = [], HEADER
    while off + ENTRY + 2 <= len(blob) and len(out) < MAX_ENTRIES:
        plen, = struct.unpack_from("<H", blob, off + ENTRY)
        start = off + ENTRY + 2
        if plen > MAX_PATH_CHARS or start + plen * 2 > len(blob):
            meta["findings"].append(
                "An entry at offset 0x%X declares a %d-character path, which "
                "does not fit. Reading stopped there; %d of %d entries were "
                "recovered." % (off, plen, len(out), declared))
            break
        num, = struct.unpack_from("<I", blob, off + 0x58)
        when, = struct.unpack_from("<Q", blob, off + 0x64)
        pin, = struct.unpack_from("<i", blob, off + 0x6C)
        count, = struct.unpack_from("<I", blob, off + 0x74)
        out.append({
            "entry": num,
            "hostname": _hostname(blob[off + 0x48:off + 0x58]),
            "accessed": ole2.filetime(when),
            "access_count": count,
            "pinned": pin != -1,
            "path": blob[start:start + plen * 2].decode("utf-16-le", "replace"),
        })
        off = start + plen * 2 + TAIL

    if declared and len(out) != declared:
        meta["findings"].append(
            "The header declares %d entries and %d were read. The rest of "
            "the stream did not follow the expected layout and was not "
            "guessed at." % (declared, len(out)))
    meta["entries_read"] = len(out)
    return out, meta

def _lnk_streams(o):
    out = []
    for name, ent in o.streams():
        blob = o.read(ent, 1 << 20)
        if blob[:4] == b"\x4c\x00\x00\x00":
            out.append((name, blob))
    return out

def parse_automatic(data, name=""):
    o = ole2.Ole2(data, name)
    if not o.valid:
        return None
    findings = list(o.findings)
    dest, meta = parse_destlist(o.read(o.by_name.get("DestList"))
                               if "DestList" in o.by_name else b"")
    findings.extend(meta.pop("findings", []))

    targets = {}
    for sname, blob in _lnk_streams(o):
        try:
            got = lnk_mod.parse(blob)
        except Exception:
            continue
        if got:
            targets[sname.lower()] = got

    for row in dest:
        key = "%x" % row["entry"]
        got = targets.get(key)
        if got:
            row["target"] = {
                "path": got.get("target_path"),
                "size": got.get("target_size"),
                "created": got.get("target_created"),
                "modified": got.get("target_modified"),
                "volume_serial": got.get("volume_serial"),
                "volume_label": got.get("volume_label"),
                "drive_type": got.get("drive_type"),
                "machine": got.get("machine_id"),
            }

    return {
        "kind": "automatic",
        "container": o.info(),
        "destlist": meta,
        "entries": dest,
        "lnk_streams": len(targets),
        "orphan_streams": sorted(set(targets) - {"%x" % r["entry"]
                                                 for r in dest}),
        "findings": findings,
        "note": ("The filename is a hash of the application's path, so this "
                 "list outlives the application being uninstalled and is "
                 "often the last record that it was ever present."),
    }

def parse_custom(data, name=""):
    if not data or len(data) < 8:
        return None
    offsets = []
    at = data.find(LNK_MAGIC)
    while at >= 0 and len(offsets) < MAX_ENTRIES:
        offsets.append(at)
        at = data.find(LNK_MAGIC, at + 4)
    if not offsets:
        if FOOTER in data[-16:]:
            return {"kind": "custom", "entries": [], "empty": True,
                    "findings": [],
                    "note": "The list is well formed and holds no shortcuts: "
                            "the application has pinned nothing. That is a "
                            "different statement from the file being "
                            "unreadable."}
        return None
    items, findings = [], []
    for i, start in enumerate(offsets):
        end = offsets[i + 1] if i + 1 < len(offsets) else len(data)
        try:
            got = lnk_mod.parse(data[start:end])
        except Exception:
            findings.append("The item at 0x%X did not parse as a shortcut."
                            % start)
            continue
        if got:
            got["offset"] = start
            items.append(got)
    return {
        "kind": "custom",
        "entries": items,
        "findings": findings,
        "note": ("A custom destinations list has no index and no access "
                 "counts: it is a run of shortcuts the application chose to "
                 "pin or offer. Order is the application's, not a history."),
    }

def parse(data, name=""):
    if not data:
        return None
    low = (name or "").lower()
    if ole2.looks_like_ole2(data[:8]):
        return parse_automatic(data, name)
    if low.endswith(".customdestinations-ms") or data[:4] == b"\x4c\x00\x00\x00":
        return parse_custom(data, name)
    return None
