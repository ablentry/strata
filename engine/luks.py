import hashlib
import json
import struct

from .crypto import aes

from .text import t as _t

MAGIC = b"LUKS\xba\xbe"
SLOT_ENABLED = 0x00AC71F3
SECTOR = 512

class Unsupported(Exception):
    pass

def looks_like_luks(head):
    return len(head) >= 6 and head[:6] == MAGIC

def _cstr(b):
    return b.split(b"\x00")[0].decode("ascii", "replace")

def _diffuse(src, size, hashname):
    dsize = hashlib.new(hashname).digest_size
    out = bytearray()
    blocks, padding = divmod(size, dsize)
    for i in range(blocks):
        out += hashlib.new(
            hashname,
            struct.pack(">I", i) + src[i * dsize:(i + 1) * dsize]).digest()
    if padding:
        out += hashlib.new(
            hashname,
            struct.pack(">I", blocks) + src[blocks * dsize:size]).digest()[:padding]
    return bytes(out)

def af_merge(data, blocksize, stripes, hashname):
    d = bytes(blocksize)
    for i in range(stripes - 1):
        chunk = data[i * blocksize:(i + 1) * blocksize]
        d = bytes(x ^ y for x, y in zip(d, chunk))
        d = _diffuse(d, blocksize, hashname)
    last = data[(stripes - 1) * blocksize:stripes * blocksize]
    return bytes(x ^ y for x, y in zip(d, last))

def _decrypt_region(cipher_name, mode, key, data, start_sector=0,
                    sector_size=SECTOR):
    if cipher_name != "aes":
        raise Unsupported(_t("luks.cipher_r_supported_only")
                          % cipher_name)
    out = bytearray()
    if mode.startswith("xts-"):
        half = len(key) // 2
        k1, k2 = aes.AES(key[:half]), aes.AES(key[half:])
        for i in range(0, len(data), sector_size):
            out += aes.xts_decrypt(k1, k2, start_sector + i // sector_size,
                                   data[i:i + sector_size])
        return bytes(out)
    if mode.startswith("cbc-"):
        c = aes.AES(key)
        ivmode = mode.split("-", 1)[1]
        for i in range(0, len(data), sector_size):
            sec = start_sector + i // sector_size
            if ivmode == "plain" or ivmode == "plain64":
                iv = struct.pack("<Q", sec) + b"\x00" * 8 if ivmode == "plain64" \
                    else struct.pack("<I", sec & 0xFFFFFFFF) + b"\x00" * 12
            elif ivmode.startswith("essiv"):
                h = ivmode.split(":", 1)[1] if ":" in ivmode else "sha256"
                salt = hashlib.new(h, key).digest()
                iv = aes.AES(salt).encrypt_block(
                    struct.pack("<Q", sec) + b"\x00" * 8)
            else:
                raise Unsupported(_t("luks.cbc_iv_mode_r") % ivmode)
            out += aes.cbc_decrypt(c, iv, data[i:i + sector_size])
        return bytes(out)
    raise Unsupported(_t("luks.cipher_mode_r_supported") % mode)

class KeySlot:
    def __init__(self, index, active, iterations, salt, offset, stripes):
        self.index = index
        self.active = active == SLOT_ENABLED
        self.iterations = iterations
        self.salt = salt
        self.offset = offset
        self.stripes = stripes

    def info(self):
        return {"slot": self.index, "active": self.active,
                "iterations": self.iterations, "stripes": self.stripes,
                "key_material_offset": self.offset * SECTOR}

class Luks:

    def __init__(self, source, size=None):
        self.source = source
        self.size = size if size is not None else getattr(source, "size", 0)
        self.valid = False
        self.findings = []
        self.slots = []
        self.master_key = None
        self.version = None
        self._parse()

    def _parse(self):
        head = self.source.read_at(0, 4096)
        if not looks_like_luks(head):
            return
        self.version = struct.unpack_from(">H", head, 6)[0]
        if self.version == 1:
            self._parse_v1(head)
        elif self.version == 2:
            self._parse_v2()
        else:
            self.findings.append("Unknown LUKS version %d." % self.version)

    def _parse_v1(self, head):
        self.cipher_name = _cstr(head[8:40])
        self.cipher_mode = _cstr(head[40:72])
        self.hash_spec = _cstr(head[72:104])
        (self.payload_sector, self.key_bytes) = struct.unpack_from(">II", head, 104)
        self.mk_digest = head[112:132]
        self.mk_salt = head[132:164]
        self.mk_iter = struct.unpack_from(">I", head, 164)[0]
        self.uuid = _cstr(head[168:208])
        self.payload_offset = self.payload_sector * SECTOR
        for i in range(8):
            base = 208 + i * 48
            active, iters = struct.unpack_from(">II", head, base)
            salt = head[base + 8:base + 40]
            off, stripes = struct.unpack_from(">II", head, base + 40)
            self.slots.append(KeySlot(i, active, iters, salt, off, stripes))
        try:
            hashlib.new(self.hash_spec)
        except ValueError:
            self.findings.append(
                "Header names hash %r, which this Python's hashlib does not "
                "provide." % self.hash_spec)
        self.valid = True

    def _parse_v2(self):
        blob = self.source.read_at(0, 64 << 10)
        self.uuid = _cstr(blob[168:208])
        hdr_size = struct.unpack_from(">Q", blob, 8)[0] if len(blob) > 16 else 0
        text = blob[4096:min(len(blob), max(8192, hdr_size))]
        end = text.find(b"\x00")
        try:
            meta = json.loads(text[:end if end > 0 else len(text)].decode("utf-8"))
        except Exception:
            self.findings.append("The LUKS2 JSON metadata area did not parse.")
            return
        self.meta = meta
        segs = meta.get("segments") or {}
        seg = next(iter(segs.values()), {})
        self.payload_offset = int(seg.get("offset") or 0)
        enc = seg.get("encryption") or "aes-xts-plain64"
        bits = enc.split("-")
        self.cipher_name = bits[0]
        self.cipher_mode = "-".join(bits[1:]) or "xts-plain64"
        self.sector_size = int(seg.get("sector_size") or SECTOR)

        kdfs = set()
        for sid, slot in sorted((meta.get("keyslots") or {}).items()):
            kdf = (slot.get("kdf") or {}).get("type", "?")
            kdfs.add(kdf)
            area = slot.get("area") or {}
            af = slot.get("af") or {}
            ks = KeySlot(int(sid), SLOT_ENABLED,
                         int((slot.get("kdf") or {}).get("iterations") or 0),
                         _b64(slot.get("kdf", {}).get("salt", "")),
                         int(area.get("offset") or 0) // SECTOR,
                         int(af.get("stripes") or 4000))
            ks.key_bytes = int(slot.get("key_size") or 32)
            ks.kdf = slot.get("kdf") or {}
            ks.af_hash = (af.get("hash") or "sha256")
            ks.area_encryption = area.get("encryption") or "aes-xts-plain64"
            self.slots.append(ks)
        self.key_bytes = max([getattr(s, "key_bytes", 32)
                              for s in self.slots] or [32])
        self.hash_spec = "sha256"
        self.valid = True
        hard = {k for k in kdfs if k.startswith("argon2")}
        if hard:
            self.findings.append(
                "Every key slot on this volume uses %s. That is a memory-hard "
                "function with no implementation in the Python standard "
                "library, so this tool will not attempt it rather than pretend "
                "to try. The volume is identified but cannot be unlocked here; "
                "cryptsetup on a Linux host will do it."
                % ", ".join(sorted(hard))
                if kdfs <= hard else
                "Some key slots use %s, which cannot be attempted here. Slots "
                "using PBKDF2 can still be tried." % ", ".join(sorted(hard)))

    @property
    def unlocked(self):
        return self.master_key is not None

    def unlock(self, password, progress=None):
        if not self.valid:
            return {"unlocked": False, "reason": _t("luks.usable_luks_header")}
        if self.version == 2:
            return self._unlock_v2(password, progress)
        if not password:
            return {"unlocked": False, "reason": _t("luks.password_supplied")}
        active = [s for s in self.slots if s.active]
        if not active:
            return {"unlocked": False,
                    "reason": _t("luks.every_key_slot_volume")}
        for n, slot in enumerate(active):
            if progress:
                progress(n / len(active))
            try:
                mk = self._try_slot_v1(slot, password)
            except Unsupported as exc:
                return {"unlocked": False, "reason": str(exc)}
            if mk is not None:
                self.master_key = mk
                if progress:
                    progress(1.0)
                return {"unlocked": True, "slot": slot.index,
                        "encryption": "%s-%s" % (self.cipher_name,
                                                 self.cipher_mode),
                        "verified": True,
                        "key_bits": self.key_bytes * 8, "reason": None}
        if progress:
            progress(1.0)
        return {"unlocked": False,
                "reason": _t("luks.incorrect_password_all_d")
                          % (len(active), "" if len(active) == 1 else "s")}

    def _try_slot_v1(self, slot, password):
        pk = hashlib.pbkdf2_hmac(self.hash_spec, password.encode("utf-8"),
                                 slot.salt, slot.iterations, self.key_bytes)
        material = self.source.read_at(slot.offset * SECTOR,
                                       self.key_bytes * slot.stripes)
        if len(material) < self.key_bytes * slot.stripes:
            raise Unsupported(_t("luks.key_material_slot_d")
                              % slot.index)
        split = _decrypt_region(self.cipher_name, self.cipher_mode, pk, material)
        mk = af_merge(split, self.key_bytes, slot.stripes, self.hash_spec)
        digest = hashlib.pbkdf2_hmac(self.hash_spec, mk, self.mk_salt,
                                     self.mk_iter, len(self.mk_digest))
        return mk if digest == self.mk_digest else None

    def _unlock_v2(self, password, progress=None):
        usable = [s for s in self.slots
                  if (getattr(s, "kdf", {}) or {}).get("type") == "pbkdf2"]
        if not usable:
            return {"unlocked": False,
                    "reason": _t("luks.all_key_slots_use")}
        return {"unlocked": False,
                "reason": _t("luks.luks2_pbkdf2_slots_parsed")}

    def read(self, offset, length):
        if not self.master_key:
            raise Unsupported(_t("bitlocker.volume_locked"))
        ss = SECTOR
        start = offset - (offset % ss)
        n = ((offset + length) - start + ss - 1) // ss
        raw = self.source.read_at(self.payload_offset + start, n * ss)
        plain = _decrypt_region(self.cipher_name, self.cipher_mode,
                                self.master_key, raw, start // ss)
        head = offset - start
        return plain[head:head + length]

    def info(self):
        active = [s for s in self.slots if s.active]
        return {
            "type": "luks", "valid": self.valid, "version": self.version,
            "uuid": getattr(self, "uuid", None),
            "encryption": "%s-%s" % (getattr(self, "cipher_name", "?"),
                                     getattr(self, "cipher_mode", "?")),
            "hash": getattr(self, "hash_spec", None),
            "key_bits": getattr(self, "key_bytes", 0) * 8,
            "payload_offset": getattr(self, "payload_offset", 0),
            "slots": [s.info() for s in self.slots],
            "active_slots": len(active),
            "recoverable": bool(active) and self.version == 1,
            "accepts": ["password"] if active else [],
            "findings": self.findings + (
                [] if active else
                ["No key slot on this volume holds a key. It cannot be "
                 "unlocked by any password."]),
        }

def _b64(s):
    import base64
    try:
        pad = "=" * (-len(s) % 4)
        return base64.b64decode(s + pad)
    except Exception:
        return b""
