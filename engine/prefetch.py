import datetime
import struct

from . import lzxpress

MAM_MAGIC = b"MAM\x04"
SCCA_MAGIC = b"SCCA"

V_WIN8 = 26
V_WIN10 = 30
V_WIN11 = 31

def decompression_available():
    return lzxpress.available()

def decompress(data, expected):
    try:
        return lzxpress.decompress(data, expected), None
    except lzxpress.CorruptStream as exc:
        return None, str(exc)

def filetime(v):
    if not v or v == 0xFFFFFFFFFFFFFFFF:
        return None
    try:
        return (datetime.datetime(1601, 1, 1)
                + datetime.timedelta(microseconds=v // 10)).isoformat() + "Z"
    except (OverflowError, ValueError):
        return None

def _utf16(data, off, byte_len):
    return data[off:off + byte_len].decode("utf-16-le", "replace").split("\x00")[0]

def parse(data):
    out = {"findings": [], "compressed": False}

    if data[:4] == MAM_MAGIC:
        out["compressed"] = True
        expected = struct.unpack_from("<I", data, 4)[0]
        plain, why = decompress(data[8:], expected)
        if plain is None:
            out["findings"].append(
                "File is MAM/LZXPRESS compressed and the decoder stopped at "
                "%s, so its contents were not read. That is either damage to "
                "the record or a shape this decoder cannot read; the header "
                "is intact enough to say the file claims %s bytes. It has not "
                "been established which."
                % (why or "an unstated point", format(expected, ",")))
            out["undecoded"] = True
            out["undecoded_why"] = why
            return out
        if len(plain) != expected:
            out["findings"].append(
                "Decompressed to %d bytes but the header declares %d."
                % (len(plain), expected))
        data = plain

    if len(data) < 84 or data[4:8] != SCCA_MAGIC:
        return None

    version = struct.unpack_from("<I", data, 0)[0]
    out["version"] = version
    out["name"] = _utf16(data, 16, 60)
    out["path_hash"] = "0x%08X" % struct.unpack_from("<I", data, 76)[0]

    if version == V_WIN10 or version == V_WIN11:
        info = 296
    elif version == V_WIN8:
        info = 296
    elif version == 23:
        info = 156
    elif version == 17:
        info = 84
    else:
        out["findings"].append(
            "Unrecognised prefetch version %d; the header parsed but the file "
            "information section was not read." % version)
        return out

    try:
        if version == 17:
            run_times = [struct.unpack_from("<Q", data, 36 + 8 * 0)[0]]
            out["run_count"] = struct.unpack_from("<I", data, 152)[0]
            last = struct.unpack_from("<Q", data, 120)[0]
            out["run_times"] = [t for t in (filetime(last),) if t]
        else:
            fn_off, fn_len = struct.unpack_from("<II", data, 100)
            vol_off, vol_count, vol_len = struct.unpack_from("<III", data, 108)
            base = 44 if version >= V_WIN10 else 36
            times = []
            for i in range(8):
                t = struct.unpack_from("<Q", data, 128 + i * 8)[0]
                got = filetime(t)
                if got:
                    times.append(got)
            out["run_times"] = times
            rc_off = 0xC8 if version >= V_WIN10 else 0xD0
            out["run_count"] = struct.unpack_from("<I", data, rc_off)[0]
            out["run_count_offset"] = "0x%X" % rc_off

            files = []
            if 0 < fn_off < len(data) and fn_len:
                blob = data[fn_off:fn_off + fn_len]
                for s in blob.decode("utf-16-le", "replace").split("\x00"):
                    if len(s) > 3:
                        files.append(s)
            out["files"] = files
            out["file_count"] = len(files)

            vols = []
            for i in range(min(vol_count, 32)):
                vb = vol_off + i * 96
                if vb + 96 > len(data):
                    break
                dev_off, dev_len, created, serial = struct.unpack_from(
                    "<IIQI", data, vb)
                vols.append({
                    "device": _utf16(data, vol_off + dev_off, dev_len * 2),
                    "created": filetime(created),
                    "serial": "%08X" % serial,
                })
            out["volumes"] = vols
    except struct.error as exc:
        out["findings"].append("Truncated file information section: %s" % exc)

    out["last_run"] = out.get("run_times", [None])[0] if out.get("run_times") else None
    return out
