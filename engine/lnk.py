import datetime
import struct
import uuid

HEADER_SIZE = 0x4C
LINK_CLSID = "00021401-0000-0000-c000-000000000046"

HAS_TARGET_IDLIST = 0x00000001
HAS_LINK_INFO = 0x00000002
HAS_NAME = 0x00000004
HAS_RELATIVE_PATH = 0x00000008
HAS_WORKING_DIR = 0x00000010
HAS_ARGUMENTS = 0x00000020
HAS_ICON_LOCATION = 0x00000040
IS_UNICODE = 0x00000080

FLAG_NAMES = [
    (HAS_TARGET_IDLIST, "target id list"), (HAS_LINK_INFO, "link info"),
    (HAS_NAME, "description"), (HAS_RELATIVE_PATH, "relative path"),
    (HAS_WORKING_DIR, "working dir"), (HAS_ARGUMENTS, "arguments"),
    (HAS_ICON_LOCATION, "icon location"), (IS_UNICODE, "unicode"),
    (0x00002000, "run as user"), (0x00000800, "no link info tracking"),
]

ATTRS = [
    (0x0001, "read-only"), (0x0002, "hidden"), (0x0004, "system"),
    (0x0010, "directory"), (0x0020, "archive"), (0x0080, "normal"),
    (0x0100, "temporary"), (0x0200, "sparse"), (0x0400, "reparse point"),
    (0x0800, "compressed"), (0x1000, "offline"), (0x4000, "encrypted"),
]

SHOW = {1: "normal", 3: "maximised", 7: "minimised"}

DRIVE_TYPES = {0: "unknown", 1: "no root directory", 2: "removable",
               3: "fixed", 4: "remote", 5: "optical", 6: "RAM disk"}

def filetime(v):
    if not v:
        return None
    try:
        return (datetime.datetime(1601, 1, 1)
                + datetime.timedelta(microseconds=v // 10)).isoformat() + "Z"
    except (OverflowError, ValueError):
        return None

def _flags(value, table):
    return [name for bit, name in table if value & bit]

def _sz(data, off, wide):
    if wide:
        end = off
        while end + 1 < len(data) and data[end:end + 2] != b"\x00\x00":
            end += 2
        return data[off:end].decode("utf-16-le", "replace"), end + 2
    end = data.find(b"\x00", off)
    if end < 0:
        end = len(data)
    return data[off:end].decode("latin-1", "replace"), end + 1

def _counted(data, off, wide):
    if off + 2 > len(data):
        return None, off
    n = struct.unpack_from("<H", data, off)[0]
    off += 2
    if wide:
        raw = data[off:off + n * 2]
        return raw.decode("utf-16-le", "replace"), off + n * 2
    raw = data[off:off + n]
    return raw.decode("latin-1", "replace"), off + n

def parse(data):
    out = {"findings": []}
    if len(data) < HEADER_SIZE:
        return None
    size, = struct.unpack_from("<I", data, 0)
    if size != HEADER_SIZE:
        return None
    try:
        clsid = str(uuid.UUID(bytes_le=data[4:20]))
    except ValueError:
        return None
    if clsid != LINK_CLSID:
        return None

    flags, attrs = struct.unpack_from("<II", data, 20)
    created, accessed, written = struct.unpack_from("<QQQ", data, 28)
    file_size, icon_index, show, hotkey = struct.unpack_from("<IiiH", data, 52)

    out.update({
        "flags": flags,
        "flag_names": _flags(flags, FLAG_NAMES),
        "target_attributes": _flags(attrs, ATTRS),
        "target_created": filetime(created),
        "target_accessed": filetime(accessed),
        "target_modified": filetime(written),
        "target_size": file_size,
        "show_command": SHOW.get(show, str(show)),
        "icon_index": icon_index,
        "hotkey": hotkey or None,
    })

    wide = bool(flags & IS_UNICODE)
    pos = HEADER_SIZE

    if flags & HAS_TARGET_IDLIST:
        if pos + 2 > len(data):
            out["findings"].append("Truncated before the target id list.")
            return out
        idlist_size = struct.unpack_from("<H", data, pos)[0]
        pos += 2 + idlist_size
        if pos > len(data):
            out["findings"].append("Target id list runs past the end of the file.")
            return out

    if flags & HAS_LINK_INFO:
        info, consumed = _link_info(data, pos)
        out.update(info)
        if consumed is None:
            out["findings"].append("Link info block is malformed.")
            return out
        pos = consumed

    for bit, key in ((HAS_NAME, "description"),
                     (HAS_RELATIVE_PATH, "relative_path"),
                     (HAS_WORKING_DIR, "working_dir"),
                     (HAS_ARGUMENTS, "arguments"),
                     (HAS_ICON_LOCATION, "icon_location")):
        if not flags & bit:
            continue
        val, pos = _counted(data, pos, wide)
        if val is None:
            out["findings"].append("Truncated inside the string data.")
            return out
        out[key] = val

    out.update(_extra_blocks(data, pos, out))

    out["target_path"] = (out.get("local_base_path")
                          or out.get("network_path")
                          or out.get("relative_path"))
    if out.get("common_path_suffix") and out.get("local_base_path"):
        out["target_path"] = out["local_base_path"] + out["common_path_suffix"]

    if (out["target_path"] and not created and not accessed and not written
            and not file_size):
        out["metadata_zeroed"] = True
        out["findings"].append(
            "Target timestamps and size are all zero in the header. The bytes "
            "really are zero, not unread — some shell-created shortcuts are "
            "written this way.")
    return out

def _link_info(data, pos):
    out = {}
    if pos + 4 > len(data):
        return out, None
    size, = struct.unpack_from("<I", data, pos)
    if size < 0x1C or pos + size > len(data):
        return out, None
    blk = data[pos:pos + size]
    (hdr_size, flags, vol_off, base_off, net_off, suffix_off) = \
        struct.unpack_from("<IIIIII", blk, 4)

    base_uni_off = suffix_uni_off = 0
    if hdr_size >= 0x24:
        base_uni_off, suffix_uni_off = struct.unpack_from("<II", blk, 28)

    if flags & 0x01 and vol_off and vol_off < len(blk):
        vsize, drive_type, serial, label_off = struct.unpack_from("<IIII", blk, vol_off)
        out["drive_type"] = DRIVE_TYPES.get(drive_type, str(drive_type))
        out["volume_serial"] = "%08X" % serial
        if label_off and vol_off + label_off < len(blk):
            label, _ = _sz(blk, vol_off + label_off, False)
            out["volume_label"] = label or None
        if base_off and base_off < len(blk):
            out["local_base_path"] = _sz(blk, base_off, False)[0]
        if base_uni_off and base_uni_off < len(blk):
            out["local_base_path"] = _sz(blk, base_uni_off, True)[0]

    if flags & 0x02 and net_off and net_off + 20 <= len(blk):
        nsize, nflags, share_off = struct.unpack_from("<III", blk, net_off)
        if share_off and net_off + share_off < len(blk):
            out["network_path"] = _sz(blk, net_off + share_off, False)[0]

    if suffix_off and suffix_off < len(blk):
        out["common_path_suffix"] = _sz(blk, suffix_off, False)[0] or None
    if suffix_uni_off and suffix_uni_off < len(blk):
        out["common_path_suffix"] = _sz(blk, suffix_uni_off, True)[0] or None

    return out, pos + size

def _extra_blocks(data, pos, out):
    extra = {}
    seen = []
    while pos + 8 <= len(data):
        size, sig = struct.unpack_from("<II", data, pos)
        if size < 8 or pos + size > len(data):
            break
        blk = data[pos:pos + size]
        seen.append("0x%08X" % sig)

        if sig == 0xA0000003 and size >= 0x60:
            name, _ = _sz(blk, 16, False)
            extra["machine_id"] = name or None
            try:
                extra["droid_volume"] = str(uuid.UUID(bytes_le=blk[32:48]))
                extra["droid_file"] = str(uuid.UUID(bytes_le=blk[48:64]))
                extra["birth_droid_volume"] = str(uuid.UUID(bytes_le=blk[64:80]))
                extra["birth_droid_file"] = str(uuid.UUID(bytes_le=blk[80:96]))
            except (ValueError, IndexError):
                pass
            fid = extra.get("birth_droid_file") or extra.get("droid_file")
            if fid:
                mac = fid.split("-")[-1]
                if len(mac) == 12 and int(fid.split("-")[2][0], 16) == 1:
                    extra["mac_address"] = ":".join(
                        mac[i:i + 2] for i in range(0, 12, 2)).upper()

        elif sig == 0xA0000005 and size >= 0x0C:
            extra["special_folder_id"] = struct.unpack_from("<I", blk, 8)[0]

        elif sig == 0xA0000007:
            extra["has_shim_layer"] = True

        elif sig == 0xA000000C:
            extra["has_known_folder"] = True
            if size >= 0x1C:
                try:
                    extra["known_folder"] = str(uuid.UUID(bytes_le=blk[8:24]))
                except ValueError:
                    pass

        pos += size

    if seen:
        extra["extra_blocks"] = seen
    return extra
