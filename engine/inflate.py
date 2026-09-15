import zlib

DEFAULT_MAX = 64 << 20

_FEED = 1 << 16

def inflate_capped(blob, limit=DEFAULT_MAX, wbits=zlib.MAX_WBITS):
    if limit <= 0:
        return b"", bool(blob)
    d = zlib.decompressobj(wbits)
    out = bytearray()
    truncated = False
    try:
        for i in range(0, len(blob), _FEED):
            if len(out) >= limit:
                truncated = True
                break
            out += d.decompress(blob[i:i + _FEED], limit - len(out))
            if d.unconsumed_tail:
                truncated = True
                break
    except zlib.error:
        pass
    return bytes(out), truncated
