CHUNK = 65536
MAX_CODE_BITS = 15
TABLE_BITS = MAX_CODE_BITS
SYMBOLS = 512

LEN_ESCAPE = 15
BYTE_ESCAPE = 255
MIN_MATCH = 3

class CorruptStream(ValueError):
    pass

def _u16(data, i):
    if i + 2 > len(data):
        raise CorruptStream("stream ends inside a 16-bit read at %d" % i)
    return data[i] | (data[i + 1] << 8)

class _Bits:

    __slots__ = ("d", "i", "buf", "n")

    def __init__(self, data, pos):
        self.d = data
        self.i = pos
        self.buf = ((_u16(data, pos) << 16) | _u16(data, pos + 2)) & 0xFFFFFFFF
        self.i = pos + 4
        self.n = 32

    def peek15(self):
        return (self.buf >> 17) & 0x7FFF

    def skip(self, k):
        self.buf = (self.buf << k) & 0xFFFFFFFF
        self.n -= k
        if self.n < 16:
            self.buf |= _u16(self.d, self.i) << (16 - self.n)
            self.i += 2
            self.n += 16

    def take(self, k):
        if not k:
            return 0
        v = (self.buf >> (32 - k)) & ((1 << k) - 1)
        self.skip(k)
        return v

    def byte(self):
        if self.i >= len(self.d):
            raise CorruptStream("stream ends where a length byte was expected")
        b = self.d[self.i]
        self.i += 1
        return b

    def word(self):
        v = _u16(self.d, self.i)
        self.i += 2
        return v

    def dword(self):
        lo = self.word()
        return lo | (self.word() << 16)

def _build_table(data, pos):
    if pos + 256 > len(data):
        raise CorruptStream("stream ends inside a Huffman table")
    lengths = [0] * SYMBOLS
    for i in range(256):
        b = data[pos + i]
        lengths[2 * i] = b & 15
        lengths[2 * i + 1] = b >> 4

    table = [0] * (1 << TABLE_BITS)
    code = 0
    for bitlen in range(1, MAX_CODE_BITS + 1):
        span = 1 << (TABLE_BITS - bitlen)
        for sym in range(SYMBOLS):
            if lengths[sym] != bitlen:
                continue
            base = code << (TABLE_BITS - bitlen)
            if base + span > len(table):
                raise CorruptStream("Huffman table is over-subscribed")
            table[base:base + span] = [sym | (bitlen << 9)] * span
            code += 1
        code <<= 1
    return table

def decompress(data, expected):
    if expected <= 0:
        return b""
    out = bytearray()
    pos = 0
    while len(out) < expected:
        table = _build_table(data, pos)
        bits = _Bits(data, pos + 256)
        stop = min(expected, len(out) + CHUNK)
        while len(out) < stop:
            packed = table[bits.peek15()]
            code_len = packed >> 9
            if not code_len:
                raise CorruptStream(
                    "no Huffman code matches at output byte %d" % len(out))
            bits.skip(code_len)
            sym = packed & 0x1FF
            if sym < 256:
                out.append(sym)
                continue

            sym -= 256
            length = sym & 15
            offbits = sym >> 4
            if length == LEN_ESCAPE:
                extra = bits.byte()
                if extra == BYTE_ESCAPE:
                    length = bits.word()
                    if length == 0:
                        length = bits.dword()
                else:
                    length = extra + LEN_ESCAPE
            length += MIN_MATCH

            offset = (1 << offbits) + bits.take(offbits)
            if offset > len(out):
                raise CorruptStream(
                    "match at output byte %d points %d bytes back, before the "
                    "start of the output" % (len(out), offset))
            src = len(out) - offset
            for _ in range(length):
                out.append(out[src])
                src += 1
        pos = bits.i
    return bytes(out[:expected])

def available():
    return "python"
