import struct

from .aes import AES

class MacMismatch(Exception):
    pass

def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def _cbc_mac(cipher, b0, blocks):
    y = cipher.encrypt_block(b0)
    for i in range(0, len(blocks), 16):
        chunk = blocks[i:i + 16]
        if len(chunk) < 16:
            chunk = chunk + b"\x00" * (16 - len(chunk))
        y = cipher.encrypt_block(_xor(y, chunk))
    return y

def _ctr_block(nonce, i, L):
    return bytes([L - 1]) + nonce + i.to_bytes(L, "big")

def decrypt(key, nonce, data, mac, aad=b"", mac_len=16):
    cipher = key if isinstance(key, AES) else AES(key)
    L = 15 - len(nonce)
    if not 2 <= L <= 8:
        raise ValueError("bad nonce length %d" % len(nonce))

    out = bytearray()
    for i in range(0, len(data), 16):
        ks = cipher.encrypt_block(_ctr_block(nonce, (i >> 4) + 1, L))
        out += _xor(data[i:i + 16], ks)
    plain = bytes(out)

    s0 = cipher.encrypt_block(_ctr_block(nonce, 0, L))
    want = _xor(mac[:mac_len], s0[:mac_len])

    flags = (0x40 if aad else 0) | (((mac_len - 2) // 2) << 3) | (L - 1)
    b0 = bytes([flags]) + nonce + len(plain).to_bytes(L, "big")
    blocks = b""
    if aad:
        if len(aad) >= 0xFF00:
            raise ValueError("associated data too long for this implementation")
        blocks += struct.pack(">H", len(aad)) + aad
        blocks += b"\x00" * (-len(blocks) % 16)
    blocks += plain
    got = _cbc_mac(cipher, b0, blocks)[:mac_len]

    if got != want:
        raise MacMismatch("CCM tag mismatch")
    return plain
