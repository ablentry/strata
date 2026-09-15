import hashlib
import re

from .bip39_words import WORDS as BIP39_WORDS

BIP39_INDEX = {w: i for i, w in enumerate(BIP39_WORDS)}
VALID_LENGTHS = (12, 15, 18, 21, 24)

def wordlist_status():
    ws = BIP39_WORDS
    prefixes = [w[:4] for w in ws]
    problems = []
    if len(ws) != 2048:
        problems.append("%d words, expected 2048" % len(ws))
    if len(set(ws)) != len(ws):
        problems.append("duplicate words")
    if ws != sorted(ws):
        problems.append("not in alphabetical order")
    if not all(w.isascii() and w.islower() and w.isalpha() for w in ws):
        problems.append("non-alphabetic or non-lowercase entries")
    if not all(3 <= len(w) <= 8 for w in ws):
        problems.append("words outside three to eight letters")
    if len(set(prefixes)) != len(prefixes):
        problems.append("two words share their first four letters")
    return {
        "words": len(ws),
        "ok": not problems,
        "problems": problems,
        "sha256": hashlib.sha256(("\n".join(ws) + "\n").encode()).hexdigest(),
        "note": ("Compare this digest with english.txt from the BIP-39 "
                 "repository. A wrong word cannot invent a phrase — the "
                 "checksum still has to pass — but it can hide one."),
    }

def mnemonic_entropy(words):
    n = len(words)
    if n not in VALID_LENGTHS:
        return None
    try:
        bits = "".join(format(BIP39_INDEX[w], "011b") for w in words)
    except KeyError:
        return None
    ent_len = n * 11 * 32 // 33
    ent_bits, check_bits = bits[:ent_len], bits[ent_len:]
    entropy = int(ent_bits, 2).to_bytes(ent_len // 8, "big")
    want = format(hashlib.sha256(entropy).digest()[0], "08b")[:len(check_bits)]
    return entropy if want == check_bits else None

WORD = re.compile(r"[a-z]{3,8}")

SEPARATOR = re.compile(r"^[\s,;.:)(\[\]|/*_-]{0,12}$|^[\s\d.,;:)(\[\]#-]{0,12}$")

def _runs(text):
    runs, cur, prev_end = [], [], None
    for m in WORD.finditer(text):
        w = m.group(0)
        joins = (prev_end is not None
                 and SEPARATOR.match(text[prev_end:m.start()]) is not None)
        if w in BIP39_INDEX and (not cur or joins):
            cur.append((m.start(), w))
        else:
            if len(cur) >= min(VALID_LENGTHS):
                runs.append(cur)
            cur = [(m.start(), w)] if w in BIP39_INDEX else []
        prev_end = m.end()
    if len(cur) >= min(VALID_LENGTHS):
        runs.append(cur)
    return runs

def find_mnemonics(text, offset=0):
    out = []
    for run in _runs(text.lower()):
        words = [w for _, w in run]
        hits, i = [], 0
        while i + min(VALID_LENGTHS) <= len(words):
            lengths = [n for n in sorted(VALID_LENGTHS, reverse=True)
                       if i + n <= len(words)
                       and mnemonic_entropy(words[i:i + n]) is not None]
            if lengths:
                hits.append((i, lengths[0], lengths[1:]))
                i += lengths[0]
            else:
                i += 1
        if hits:
            for start, n, alts in hits:
                window = words[start:start + n]
                out.append({
                    "offset": offset + run[start][0],
                    "words": n,
                    "valid": True,
                    "alternatives": alts,
                    "phrase": " ".join(window),
                    "redacted": "%s … %s (%d words)%s" % (
                        window[0], window[-1], n,
                        (" · also validates at %s words"
                         % ", ".join(str(a) for a in alts))
                        if alts else ""),
                })
        else:
            out.append({
                "offset": offset + run[0][0],
                "words": len(words),
                "valid": False,
                "phrase": " ".join(words),
                "redacted": "%s … %s (%d words in sequence, no valid "
                            "checksum)" % (words[0], words[-1], len(words)),
            })
    return out

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_INDEX = {c: i for i, c in enumerate(B58)}

def b58check(text):
    if not text or any(c not in B58_INDEX for c in text):
        return None
    num = 0
    for c in text:
        num = num * 58 + B58_INDEX[c]
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big")
    pad = len(text) - len(text.lstrip("1"))
    raw = b"\x00" * pad + raw
    if len(raw) < 5:
        return None
    body, checksum = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] != checksum:
        return None
    return body

B58_VERSIONS = {
    0x00: ("Bitcoin address", "P2PKH"),
    0x05: ("Bitcoin address", "P2SH"),
    0x6F: ("Bitcoin testnet address", "P2PKH"),
    0xC4: ("Bitcoin testnet address", "P2SH"),
    0x30: ("Litecoin address", "P2PKH"),
    0x1E: ("Dogecoin address", "P2PKH"),
    0x80: ("Bitcoin private key", "WIF"),
    0xEF: ("Bitcoin testnet private key", "WIF"),
}

B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_CONST, BECH32M_CONST = 1, 0x2BC830A3

def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk

def bech32_verify(text):
    if not (8 <= len(text) <= 90) or "1" not in text:
        return None
    if text.lower() != text and text.upper() != text:
        return None
    t = text.lower()
    pos = t.rfind("1")
    hrp, body = t[:pos], t[pos + 1:]
    if not hrp or len(body) < 6 or any(c not in B32 for c in body):
        return None
    expand = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    chk = _polymod(expand + [B32.index(c) for c in body])
    if chk == BECH32_CONST:
        return ("bech32", hrp, body[:-6])
    if chk == BECH32M_CONST:
        return ("bech32m", hrp, body[:-6])
    return None

BECH32_HRP = {"bc": "Bitcoin", "tb": "Bitcoin testnet", "ltc": "Litecoin",
              "bcrt": "Bitcoin regtest"}

B58_CANDIDATE = re.compile(r"[1-9A-HJ-NP-Za-km-z]{25,60}")
BECH32_CANDIDATE = re.compile(r"\b(?:bc|tb|ltc|bcrt)1[02-9ac-hj-np-z]{6,87}\b",
                              re.I)
ETH_CANDIDATE = re.compile(r"\b0x[0-9a-fA-F]{40}\b")

def eth_checksum_state(addr):
    body = addr[2:]
    if body == body.lower() or body == body.upper():
        return "no checksum"
    return "unverified"

def find_addresses(text, offset=0):
    out = []
    for m in B58_CANDIDATE.finditer(text):
        body = b58check(m.group(0))
        if body is None:
            continue
        kind, form = B58_VERSIONS.get(body[0],
                                      ("Unrecognised Base58Check payload",
                                       "version 0x%02X" % body[0]))
        out.append({"offset": offset + m.start(), "value": m.group(0),
                    "kind": kind, "form": form,
                    "secret": "private key" in kind.lower()})
    for m in BECH32_CANDIDATE.finditer(text):
        got = bech32_verify(m.group(0))
        if not got:
            continue
        enc, hrp, _ = got
        out.append({"offset": offset + m.start(), "value": m.group(0),
                    "kind": "%s address" % BECH32_HRP.get(hrp, hrp),
                    "form": enc, "secret": False})
    for m in ETH_CANDIDATE.finditer(text):
        out.append({"offset": offset + m.start(), "value": m.group(0),
                    "kind": "Ethereum-style address",
                    "form": "20 hex bytes · %s" % eth_checksum_state(m.group(0)),
                    "secret": False, "unverified": True})
    return out

def identify_wallet(name, head):
    low = (name or "").lower()
    if len(head) >= 16:
        magic = head[12:16]
        if magic in (b"\x00\x05\x31\x62", b"\x62\x31\x05\x00"):
            return ("Bitcoin Core wallet", "Berkeley DB")
    if head[:16] == b"SQLite format 3\x00" and "wallet" in low:
        return ("Bitcoin Core wallet", "SQLite, descriptor era")
    text = head[:512].lstrip()
    if text[:1] in (b"{", b"["):
        blob = text.decode("utf-8", "replace")
        if '"seed_version"' in blob or '"wallet_type"' in blob:
            return ("Electrum wallet", "JSON")
        if ('"ciphertext"' in blob and '"kdf"' in blob) or '"crypto"' in blob \
                or '"Crypto"' in blob:
            return ("Ethereum keystore", "JSON, scrypt or pbkdf2")
        if '"vault"' in blob and '"salt"' in blob:
            return ("Browser extension vault", "JSON")
    return None
