import struct

SST_MAGIC = 0xDB4775248B80FB57
LOG_BLOCK = 32768

LOG_FULL, LOG_FIRST, LOG_MIDDLE, LOG_LAST = 1, 2, 3, 4

TYPE_DELETION, TYPE_VALUE = 0, 1

def uvarint(data, pos):
    val = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            return val, pos
        shift += 7
        if shift > 63:
            break
    return val, pos

def snappy_decompress(data, max_out=1 << 28):
    length, pos = uvarint(data, 0)
    if length > max_out:
        raise ValueError("snappy block claims %d bytes" % length)
    out = bytearray()
    while pos < len(data) and len(out) < length:
        tag = data[pos]
        pos += 1
        kind = tag & 0x03
        if kind == 0:
            n = tag >> 2
            if n >= 60:
                extra = n - 59
                n = int.from_bytes(data[pos:pos + extra], "little")
                pos += extra
            n += 1
            out += data[pos:pos + n]
            pos += n
            continue
        if kind == 1:
            n = 4 + ((tag >> 2) & 0x07)
            offset = ((tag >> 5) & 0x07) << 8 | data[pos]
            pos += 1
        elif kind == 2:
            n = (tag >> 2) + 1
            offset = int.from_bytes(data[pos:pos + 2], "little")
            pos += 2
        else:
            n = (tag >> 2) + 1
            offset = int.from_bytes(data[pos:pos + 4], "little")
            pos += 4
        if offset == 0 or offset > len(out):
            raise ValueError("snappy copy offset points outside the output")
        start = len(out) - offset
        for i in range(n):
            out.append(out[start + i])
    return bytes(out)

def _block_entries(block):
    if len(block) < 4:
        return []
    restarts = struct.unpack_from("<I", block, len(block) - 4)[0]
    if restarts > (len(block) - 4) // 4:
        return []
    limit = len(block) - 4 - restarts * 4
    out = []
    pos = 0
    key = b""
    while pos < limit:
        shared, pos = uvarint(block, pos)
        unshared, pos = uvarint(block, pos)
        vlen, pos = uvarint(block, pos)
        if shared > len(key) or pos + unshared + vlen > len(block):
            break
        key = key[:shared] + block[pos:pos + unshared]
        pos += unshared
        value = block[pos:pos + vlen]
        pos += vlen
        out.append((key, value))
    return out

def _read_block(data, offset, size):
    raw = data[offset:offset + size]
    ctype = data[offset + size] if offset + size < len(data) else 0
    if ctype == 1:
        return snappy_decompress(raw)
    if ctype == 0:
        return raw
    raise ValueError("unsupported block compression %d" % ctype)

def read_sst(data):
    if len(data) < 48:
        return None
    magic = struct.unpack_from("<Q", data, len(data) - 8)[0]
    if magic != SST_MAGIC:
        return None
    foot = len(data) - 48
    _meta_off, p = uvarint(data, foot)
    _meta_size, p = uvarint(data, p)
    index_off, p = uvarint(data, p)
    index_size, p = uvarint(data, p)

    findings = []
    try:
        index = _read_block(data, index_off, index_size)
    except Exception as exc:
        return {"entries": [], "findings": ["Index block unreadable: %s" % exc]}

    entries = []
    for _key, handle in _block_entries(index):
        off, q = uvarint(handle, 0)
        size, q = uvarint(handle, q)
        try:
            block = _read_block(data, off, size)
        except Exception as exc:
            findings.append("Data block at %d unreadable: %s" % (off, exc))
            continue
        entries += _block_entries(block)
    return {"entries": entries, "findings": findings}

def read_log(data):
    out = []
    findings = []
    pending = bytearray()
    pos = 0
    while pos + 7 <= len(data):
        if LOG_BLOCK - (pos % LOG_BLOCK) < 7:
            pos += LOG_BLOCK - (pos % LOG_BLOCK)
            continue
        _crc, length, rtype = struct.unpack_from("<IHB", data, pos)
        pos += 7
        if length == 0 and rtype == 0:
            pos += LOG_BLOCK - (pos % LOG_BLOCK) if pos % LOG_BLOCK else 0
            continue
        chunk = data[pos:pos + length]
        pos += length
        if rtype == LOG_FULL:
            out += _decode_batch(chunk, findings)
        elif rtype == LOG_FIRST:
            pending = bytearray(chunk)
        elif rtype == LOG_MIDDLE:
            pending += chunk
        elif rtype == LOG_LAST:
            pending += chunk
            out += _decode_batch(bytes(pending), findings)
            pending = bytearray()
        else:
            break
    return {"entries": out, "findings": findings}

def _decode_batch(batch, findings):
    if len(batch) < 12:
        return []
    seq, count = struct.unpack_from("<QI", batch, 0)
    pos = 12
    out = []
    for _ in range(count):
        if pos >= len(batch):
            break
        kind = batch[pos]
        pos += 1
        klen, pos = uvarint(batch, pos)
        key = batch[pos:pos + klen]
        pos += klen
        if kind == TYPE_VALUE:
            vlen, pos = uvarint(batch, pos)
            value = batch[pos:pos + vlen]
            pos += vlen
            out.append((key, value))
        elif kind == TYPE_DELETION:
            out.append((key, None))
        else:
            findings.append("Unknown batch record type %d" % kind)
            break
    return out

def decode_value(value):
    if value is None:
        return None
    if not value:
        return ""
    tag = value[0]
    body = value[1:]
    try:
        if tag == 0:
            return body.decode("utf-16-le", "replace")
        if tag == 1:
            return body.decode("utf-8", "replace")
    except Exception:
        pass
    try:
        return value.decode("utf-8", "replace")
    except Exception:
        return value.hex()

def _split_origin(raw):
    for i, b in enumerate(raw):
        if b < 0x20 or b > 0x7E:
            return raw[:i].decode("utf-8", "replace"), raw[i:].hex()
    return raw.decode("utf-8", "replace"), None

def local_storage(entries):
    out = []
    for key, value in entries:
        if not key:
            continue
        if key[:1] == b"_" and b"\x00\x01" in key:
            raw_origin, _, name = key[1:].partition(b"\x00\x01")
            origin, partition = _split_origin(raw_origin)
            row = {
                "origin": origin,
                "key": name.decode("utf-8", "replace"),
                "value": decode_value(value),
                "deleted": value is None,
            }
            if partition:
                row["partition"] = partition
            out.append(row)
        elif key.startswith(b"META:"):
            origin, partition = _split_origin(key[5:])
            row = {"origin": origin, "key": "(metadata)", "value": None,
                   "meta": True, "deleted": value is None}
            if partition:
                row["partition"] = partition
            out.append(row)
    return out

def summarise(entries, limit=4000):
    out = []
    for key, value in entries[:limit]:
        out.append({
            "key": key.decode("utf-8", "replace") if key else "",
            "value": decode_value(value),
            "deleted": value is None,
            "bytes": 0 if value is None else len(value),
        })
    return out
