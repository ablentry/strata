CHUNK_SIZE = 4096
SIGNATURE = 0x3000

def _split(position):
    length_mask = 0xFFF
    offset_shift = 12
    while position >= 0x10:
        position >>= 1
        length_mask >>= 1
        offset_shift -= 1
    return length_mask, offset_shift

def decompress_chunk(body):
    out = bytearray()
    i = 0
    n = len(body)
    while i < n:
        flags = body[i]
        i += 1
        for bit in range(8):
            if i >= n:
                break
            if not (flags >> bit) & 1:
                out.append(body[i])
                i += 1
                continue
            if i + 1 >= n:
                return bytes(out)
            token = body[i] | (body[i + 1] << 8)
            i += 2
            length_mask, offset_shift = _split(len(out) - 1)
            length = (token & length_mask) + 3
            offset = (token >> offset_shift) + 1
            if offset > len(out):
                return bytes(out)
            for _ in range(length):
                out.append(out[-offset])
    return bytes(out)

def decompress(data, expected_size=None):
    out = bytearray()
    i = 0
    n = len(data)
    while i + 2 <= n:
        header = data[i] | (data[i + 1] << 8)
        i += 2
        if header == 0:
            break
        size = (header & 0x0FFF) + 1
        compressed = bool(header & 0x8000)
        body = data[i:i + size]
        if len(body) < size:
            break
        i += size
        out += decompress_chunk(body) if compressed else body
        if expected_size is not None and len(out) >= expected_size:
            break
    if expected_size is not None:
        if len(out) < expected_size:
            out += b"\x00" * (expected_size - len(out))
        return bytes(out[:expected_size])
    return bytes(out)
