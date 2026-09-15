import datetime
import re
import struct

FAT_LOCAL_FILESYSTEMS = {"FAT", "FAT12", "FAT16", "FAT32", "exFAT"}

TZ_KEY = "ControlSet001\\Control\\TimeZoneInformation"
TZ_KEY_ALT = "CurrentControlSet\\Control\\TimeZoneInformation"

class Rule:

    __slots__ = ("year", "month", "dow", "week", "hour", "minute")

    def __init__(self, blob):
        (self.year, self.month, self.dow, self.week,
         self.hour, self.minute, _sec, _ms) = struct.unpack("<8H", blob)

    @property
    def active(self):
        return self.month != 0

    def occurrence(self, year):
        if not self.active:
            return None
        if self.year:
            return datetime.datetime(self.year, self.month, self.week or 1,
                                     self.hour, self.minute)
        first = datetime.date(year, self.month, 1)
        delta = (self.dow - first.weekday() - 1) % 7
        day = 1 + delta + (self.week - 1) * 7
        last = _days_in_month(year, self.month)
        while day > last:
            day -= 7
        return datetime.datetime(year, self.month, day, self.hour, self.minute)

def _days_in_month(year, month):
    if month == 12:
        return 31
    return (datetime.date(year + (month // 12), (month % 12) + 1, 1)
            - datetime.timedelta(days=1)).day

class TimeZone:

    def __init__(self, name=None, bias=0, standard_bias=0, daylight_bias=0,
                 standard=None, daylight=None, source=None, key_name=None,
                 dst_disabled=False, confidence="medium"):
        self.name = name
        self.key_name = key_name
        self.bias = bias
        self.standard_bias = standard_bias
        self.daylight_bias = daylight_bias
        self.standard = standard
        self.daylight = daylight
        self.source = source
        self.dst_disabled = dst_disabled
        self.confidence = confidence

    @property
    def has_dst(self):
        return bool(self.daylight and self.daylight.active
                    and self.standard and self.standard.active
                    and not self.dst_disabled)

    def offset_minutes(self, when=None):
        total = self.bias + (self.daylight_bias if self.in_dst(when)
                             else self.standard_bias)
        return -total

    def in_dst(self, when=None):
        if not self.has_dst or when is None:
            return False
        local = when + datetime.timedelta(minutes=-(self.bias + self.standard_bias))
        start = self.daylight.occurrence(local.year)
        end = self.standard.occurrence(local.year)
        if start is None or end is None:
            return False
        if start < end:
            return start <= local < end
        return local >= start or local < end

    def label(self, when=None):
        m = self.offset_minutes(when)
        sign = "+" if m >= 0 else "-"
        return "UTC%s%02d:%02d" % (sign, abs(m) // 60, abs(m) % 60)

    @staticmethod
    def _fmt(mins):
        if mins is None:
            return None
        sign = "+" if mins >= 0 else "-"
        return "UTC%s%02d:%02d" % (sign, abs(mins) // 60, abs(mins) % 60)

    def info(self, when=None):
        when = when or datetime.datetime.utcnow()
        rules = getattr(self, "rules_from", None)
        active = getattr(self, "active_bias", None)
        std = -(self.bias + self.standard_bias)
        dl = -(self.bias + self.daylight_bias)
        chosen = self.offset_minutes(when) if rules else (
            -active if active is not None else std)
        return {
            "name": self.name, "key_name": self.key_name,
            "standard_name": getattr(self, "standard_name", None),
            "daylight_name": getattr(self, "daylight_name", None),
            "source": self.source, "confidence": self.confidence,
            "offset_minutes": chosen,
            "offset": self._fmt(chosen),
            "standard_offset_minutes": std,
            "standard_offset": self._fmt(std),
            "daylight_offset_minutes": dl,
            "daylight_offset": self._fmt(dl),
            "active_offset_minutes": (-active) if active is not None else None,
            "active_offset": self._fmt(-active) if active is not None else None,
            "observes_dst": bool(dl != std) and not self.dst_disabled,
            "dst_disabled": self.dst_disabled,
            "dst_rules": rules or None,
            "dst_transitions": ({
                "bias": self.bias,
                "standard_bias": self.standard_bias,
                "daylight_bias": self.daylight_bias,
                "daylight": _rule_info(self.daylight),
                "standard": _rule_info(self.standard),
            } if rules and self.has_dst else None),
            "in_dst_now": self.in_dst(when) if rules else None,
            "resolves_transitions": bool(rules),
            "transition_note": (
                None if rules else
                "This hive records the offsets but not usable daylight-saving "
                "transition rules, so the tool will not compute which side of "
                "a transition a given timestamp falls on. Standard, daylight "
                "and the offset in force when the key was last written are all "
                "offered; pick the one the case supports."),
            "applies_to": "filesystems that record UTC",
            "note": ("FAT and exFAT record local time already, so this offset "
                     "must not be applied to them — doing so shifts those "
                     "timestamps twice."),
        }

def _rule_info(rule):
    if rule is None or not rule.active:
        return None
    return {"year": rule.year, "month": rule.month, "dow": rule.dow,
            "week": rule.week, "hour": rule.hour, "minute": rule.minute}

def _signed32(v):
    if v is None:
        return None
    v = int(v) & 0xFFFFFFFF
    return v - 0x100000000 if v & 0x80000000 else v

def from_registry(hive):
    key = None
    for path in (TZ_KEY, TZ_KEY_ALT, "ControlSet002\\Control\\TimeZoneInformation"):
        try:
            key = hive.open_path(path)
        except Exception:
            key = None
        if key:
            break
    if not key:
        return None

    vals = {}
    for v in hive.values(key):
        vals[(v.get("name") or "").lower()] = v

    def raw(name):
        v = vals.get(name)
        if not v:
            return None
        try:
            return hive.value_bytes(v["offset"])
        except Exception:
            return None

    def text(name):
        v = vals.get(name)
        if not v:
            return None
        got = v.get("value")
        return got.strip("\x00").strip() if isinstance(got, str) else None

    def dword(name):
        v = vals.get(name)
        if not v:
            return None
        got = v.get("value")
        if isinstance(got, int):
            return _signed32(got)
        blob = raw(name)
        if blob and len(blob) >= 4:
            return struct.unpack_from("<i", blob, 0)[0]
        return None

    tzi = raw("tzi")
    bias = std_bias = dl_bias = 0
    std = dl = None
    rules_from = None

    if tzi and len(tzi) >= 44:
        bias, std_bias, dl_bias = struct.unpack_from("<3i", tzi, 0)
        std = Rule(tzi[12:28])
        dl = Rule(tzi[28:44])
        rules_from = "TZI"
    else:
        bias = dword("bias") or 0
        std_bias = dword("standardbias") or 0
        dl_bias = dword("daylightbias") or 0
        if not vals:
            return None

    disabled = False
    v = vals.get("dynamicdaylighttimedisabled")
    if v and v.get("value"):
        disabled = True

    tz = TimeZone(
        name=text("timezonekeyname") or text("standardname"),
        key_name=text("timezonekeyname"),
        bias=bias, standard_bias=std_bias, daylight_bias=dl_bias,
        standard=std, daylight=dl, dst_disabled=disabled,
        source="SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation",
        confidence="high")
    tz.rules_from = rules_from
    tz.active_bias = dword("activetimebias")
    for attr, key in (("standard_name", "standardname"),
                      ("daylight_name", "daylightname")):
        got = text(key)
        setattr(tz, attr, None if (got or "").startswith("@") else got)
    return tz

_IANA_OFFSETS = {
    "UTC": 0, "Etc/UTC": 0, "GMT": 0, "Europe/London": 0, "Europe/Dublin": 0,
    "Europe/Lisbon": 0, "Europe/Paris": 60, "Europe/Berlin": 60,
    "Europe/Madrid": 60, "Europe/Rome": 60, "Europe/Amsterdam": 60,
    "Europe/Brussels": 60, "Europe/Vienna": 60, "Europe/Prague": 60,
    "Europe/Warsaw": 60, "Europe/Stockholm": 60, "Europe/Oslo": 60,
    "Europe/Copenhagen": 60, "Europe/Zurich": 60, "Europe/Athens": 120,
    "Europe/Helsinki": 120, "Europe/Kyiv": 120, "Europe/Kiev": 120,
    "Europe/Bucharest": 120, "Europe/Moscow": 180, "Europe/Istanbul": 180,
    "Asia/Jerusalem": 120, "Asia/Dubai": 240, "Asia/Karachi": 300,
    "Asia/Kolkata": 330, "Asia/Calcutta": 330, "Asia/Dhaka": 360,
    "Asia/Bangkok": 420, "Asia/Jakarta": 420, "Asia/Shanghai": 480,
    "Asia/Hong_Kong": 480, "Asia/Singapore": 480, "Asia/Taipei": 480,
    "Asia/Tokyo": 540, "Asia/Seoul": 540, "Australia/Perth": 480,
    "Australia/Adelaide": 570, "Australia/Brisbane": 600,
    "Australia/Sydney": 600, "Australia/Melbourne": 600,
    "Australia/Hobart": 600, "Australia/Darwin": 570,
    "Pacific/Auckland": 720, "Pacific/Chatham": 765, "Pacific/Fiji": 720,
    "America/St_Johns": -210, "America/Halifax": -240, "America/New_York": -300,
    "America/Toronto": -300, "America/Chicago": -360, "America/Mexico_City": -360,
    "America/Denver": -420, "America/Phoenix": -420, "America/Los_Angeles": -480,
    "America/Vancouver": -480, "America/Anchorage": -540, "Pacific/Honolulu": -600,
    "America/Sao_Paulo": -180, "America/Argentina/Buenos_Aires": -180,
    "America/Bogota": -300, "America/Lima": -300, "America/Santiago": -240,
    "Africa/Cairo": 120, "Africa/Johannesburg": 120, "Africa/Lagos": 60,
    "Africa/Nairobi": 180, "Africa/Casablanca": 60, "Atlantic/Reykjavik": 0,
}

def from_iana(name, source):
    name = (name or "").strip()
    if not name:
        return None
    mins = _IANA_OFFSETS.get(name)
    if mins is None:
        for k, v in _IANA_OFFSETS.items():
            if k.lower() == name.lower():
                mins, name = v, k
                break
    if mins is None:
        return TimeZone(name=name, bias=0, source=source, confidence="name only")
    return TimeZone(name=name, bias=-mins, source=source, confidence="medium")

_AFTER_ZONEINFO = re.compile(rb"zoneinfo/(?:posix/|right/)?"
                             rb"([A-Za-z][A-Za-z_+\-]*(?:/[A-Za-z][A-Za-z_+\-]*)*)")
_ZONE_RE = re.compile(rb"\b([A-Za-z]{3,}/[A-Za-z_+\-]{3,}(?:/[A-Za-z_+\-]+)?)")

def from_localtime_link(target, source):
    raw = target if isinstance(target, bytes) else \
        target.encode("utf-8", "replace")
    m = _AFTER_ZONEINFO.search(raw)
    if not m:
        for cand in _ZONE_RE.findall(raw):
            name = cand.decode("ascii", "replace")
            if name.split("/")[0].lower() in ("usr", "etc", "var", "share",
                                              "lib", "opt", "posix", "right"):
                continue
            return from_iana(name, source)
        return None
    return from_iana(m.group(1).decode("ascii", "replace"), source)

def fs_records_local_time(fs_name):
    return (fs_name or "").upper().replace("-", "") in {
        n.upper().replace("-", "") for n in FAT_LOCAL_FILESYSTEMS}
