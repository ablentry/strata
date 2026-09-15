import codecs
import datetime
import struct

SYSTEM, SOFTWARE, NTUSER, SAM, USRCLASS = (
    "SYSTEM", "SOFTWARE", "NTUSER", "SAM", "USRCLASS")

def _filetime(v):
    if not v:
        return None
    try:
        return (datetime.datetime(1601, 1, 1)
                + datetime.timedelta(microseconds=v // 10)).isoformat() + "Z"
    except (OverflowError, ValueError):
        return None

def _unix(v):
    if not v:
        return None
    try:
        return (datetime.datetime(1970, 1, 1)
                + datetime.timedelta(seconds=v)).isoformat() + "Z"
    except (OverflowError, ValueError):
        return None

def classify(hive, name=""):
    def _leaf(s):
        return (s or "").upper().replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1]

    for probe in (_leaf(getattr(hive, "embedded_name", "")), _leaf(name)):
        if not probe:
            continue
        if probe.startswith("USRCLASS"):
            return USRCLASS
        if probe.startswith("NTUSER"):
            return NTUSER
        if probe == "SYSTEM":
            return SYSTEM
        if probe == "SOFTWARE":
            return SOFTWARE
        if probe == "SAM":
            return SAM
    for path, kind in (("Select", SYSTEM),
                       ("Microsoft\\Windows NT\\CurrentVersion", SOFTWARE),
                       ("SAM\\Domains\\Account", SAM),
                       ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer",
                        NTUSER)):
        try:
            if hive.open_path(path):
                return kind
        except Exception:
            continue
    return None

class Reader:

    def __init__(self, hive):
        self.hive = hive

    def key(self, path):
        try:
            return self.hive.open_path(path)
        except Exception:
            return None

    def values(self, path_or_key):
        k = self.key(path_or_key) if isinstance(path_or_key, str) else path_or_key
        if not k:
            return {}
        out = {}
        try:
            for v in self.hive.values(k):
                out[(v.get("name") or "(default)")] = v
        except Exception:
            return {}
        return out

    def val(self, path, name, default=None):
        v = self.values(path).get(name)
        if not v:
            return default
        got = v.get("value")
        return default if got is None else got

    def raw(self, path, name):
        v = self.values(path).get(name)
        if not v:
            return None
        try:
            return self.hive.value_bytes(v["offset"])
        except Exception:
            return None

    def subkeys(self, path):
        k = self.key(path)
        if not k:
            return []
        try:
            return self.hive.subkeys(k)
        except Exception:
            return []

    def current_control_set(self):
        n = self.val("Select", "Current")
        if isinstance(n, int) and 0 < n < 10:
            return "ControlSet%03d" % n
        return "ControlSet001"

def _rot13(s):
    try:
        return codecs.decode(s, "rot_13")
    except Exception:
        return s

def _system_identity(r):
    cs = r.current_control_set()
    rows = []
    name = r.val("%s\\Control\\ComputerName\\ComputerName" % cs, "ComputerName")
    if name:
        rows.append({"item": "Computer name", "value": name})
    dom = r.val("%s\\Services\\Tcpip\\Parameters" % cs, "Domain")
    host = r.val("%s\\Services\\Tcpip\\Parameters" % cs, "Hostname")
    if host:
        rows.append({"item": "Hostname", "value": host})
    if dom:
        rows.append({"item": "Domain", "value": dom})
    rows.append({"item": "Current control set", "value": cs,
                 "note": "From Select\\Current, not assumed."})
    blob = r.raw("%s\\Control\\Windows" % cs, "ShutdownTime")
    if blob and len(blob) >= 8:
        when = _filetime(struct.unpack_from("<Q", blob, 0)[0])
        if when:
            rows.append({"item": "Last shutdown", "value": when,
                         "note": "The last clean shutdown this control set "
                                 "recorded."})
    return rows, None

def _usb_devices(r):
    cs = r.current_control_set()
    rows = []
    for vendor in r.subkeys("%s\\Enum\\USBSTOR" % cs):
        vname = vendor.get("name") or ""
        for inst in r.hive.subkeys(vendor):
            path = "%s\\Enum\\USBSTOR\\%s\\%s" % (cs, vname, inst.get("name"))
            vals = r.values(path)
            rows.append({
                "device": (vals.get("FriendlyName", {}).get("value")
                           or vname),
                "serial": inst.get("name"),
                "vendor_id": vname,
                "first_seen": _filetime(inst.get("last_written_raw"))
                              or inst.get("last_written"),
                "note": vals.get("DeviceDesc", {}).get("value"),
            })
    note = None
    if not rows and not r.key("%s\\Enum\\USBSTOR" % cs):
        note = ("The USBSTOR key does not exist in this hive, which is not the "
                "same as no USB storage having been attached — it is the key "
                "that would record it being absent.")
    elif not rows:
        note = ("USBSTOR exists but lists no devices: no USB mass storage was "
                "attached while this control set was live.")
    return rows, note

def _mounted(r):
    rows = []
    for name, v in sorted(r.values("MountedDevices").items()):
        if name == "(default)":
            continue
        blob = None
        try:
            blob = r.hive.value_bytes(v["offset"])
        except Exception:
            pass
        target = None
        if blob:
            if len(blob) == 12:
                sig, off = struct.unpack_from("<IQ", blob, 0)
                target = "disk signature %08X at offset %d" % (sig, off)
            else:
                try:
                    target = blob.decode("utf-16-le", "replace").rstrip("\x00")
                except Exception:
                    target = blob[:48].hex(" ")
        rows.append({"mount": name, "target": target})
    return rows, ("Drive letters and volume GUIDs mapped to the disks that "
                  "carried them. A letter here with no matching volume in this "
                  "image is a device that was attached and is not present."
                  if rows else None)

def _os_install(r):
    p = "Microsoft\\Windows NT\\CurrentVersion"
    rows = []
    for label, key in (("Product", "ProductName"),
                       ("Edition", "EditionID"),
                       ("Release", "DisplayVersion"),
                       ("Build", "CurrentBuild"),
                       ("Build number", "CurrentBuildNumber"),
                       ("UBR", "UBR"),
                       ("Registered owner", "RegisteredOwner"),
                       ("Registered organisation", "RegisteredOrganization"),
                       ("Product ID", "ProductId"),
                       ("System root", "SystemRoot")):
        got = r.val(p, key)
        if got not in (None, ""):
            rows.append({"item": label, "value": got})
    when = r.val(p, "InstallDate")
    if isinstance(when, int):
        rows.append({"item": "Installed", "value": _unix(when),
                     "note": "InstallDate, seconds since 1970."})
    blob = r.raw(p, "InstallTime")
    if blob and len(blob) >= 8:
        got = _filetime(struct.unpack_from("<Q", blob, 0)[0])
        if got:
            rows.append({"item": "Installed (precise)", "value": got})
    return rows, None

def _autoruns(r, hive_kind):
    base = ("Microsoft\\Windows\\CurrentVersion" if hive_kind == SOFTWARE
            else "Software\\Microsoft\\Windows\\CurrentVersion")
    rows = []
    for sub in ("Run", "RunOnce", "RunServices", "RunServicesOnce"):
        for name, v in r.values("%s\\%s" % (base, sub)).items():
            if name == "(default)":
                continue
            rows.append({"where": sub, "name": name,
                         "command": v.get("value")})
    return rows, ("Programs started automatically. This covers the Run keys "
                  "only — scheduled tasks, services and startup folders are "
                  "separate mechanisms and are not shown here."
                  if rows else None)

def _networks(r):
    rows = []
    for prof in r.subkeys("Microsoft\\Windows NT\\CurrentVersion\\NetworkList"
                          "\\Profiles"):
        vals = r.values(prof)
        created = vals.get("DateCreated", {})
        rows.append({
            "network": vals.get("ProfileName", {}).get("value") or prof.get("name"),
            "description": vals.get("Description", {}).get("value"),
            "created": _systemtime(created.get("value")),
            "last_connected": _systemtime(
                vals.get("DateLastConnected", {}).get("value")),
            "managed": vals.get("Managed", {}).get("value"),
        })
    return rows, ("Networks this machine joined. The dates are local to the "
                  "machine, as SYSTEMTIME structures, not UTC."
                  if rows else None)

def _systemtime(v):
    if isinstance(v, str):
        try:
            v = bytes.fromhex(v.replace(" ", ""))
        except ValueError:
            return None
    if not isinstance(v, (bytes, bytearray)) or len(v) < 16:
        return None
    y, mo, _dw, d, h, mi, s, _ms = struct.unpack("<8H", bytes(v[:16]))
    try:
        return datetime.datetime(y, mo, d, h, mi, s).isoformat()
    except ValueError:
        return None

def _installed(r):
    rows = []
    for base in ("Microsoft\\Windows\\CurrentVersion\\Uninstall",
                 "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"):
        for k in r.subkeys(base):
            vals = r.values(k)
            name = vals.get("DisplayName", {}).get("value")
            if not name:
                continue
            rows.append({
                "program": name,
                "version": vals.get("DisplayVersion", {}).get("value"),
                "publisher": vals.get("Publisher", {}).get("value"),
                "installed": vals.get("InstallDate", {}).get("value"),
            })
    return rows, None

def _user_activity(r):
    base = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
    rows = []
    for name, v in r.values("%s\\RunMRU" % base).items():
        if name in ("(default)", "MRUList"):
            continue
        rows.append({"kind": "Run dialog", "entry": v.get("value")})
    for name, v in r.values("%s\\TypedPaths" % base).items():
        if name == "(default)":
            continue
        rows.append({"kind": "Typed into Explorer", "entry": v.get("value")})
    for name, v in r.values(
            "Software\\Microsoft\\Internet Explorer\\TypedURLs").items():
        if name == "(default)":
            continue
        rows.append({"kind": "Typed URL", "entry": v.get("value")})
    for k in r.subkeys("%s\\UserAssist" % base):
        for sub in r.hive.subkeys(k):
            if (sub.get("name") or "").lower() != "count":
                continue
            for name, v in r.values(sub).items():
                if name == "(default)":
                    continue
                rows.append({"kind": "Program run (UserAssist)",
                             "entry": _rot13(name)})
    return rows, ("What was typed and what was launched. UserAssist names are "
                  "ROT13 in the hive and are decoded here; the counts and "
                  "timestamps inside those values are not parsed yet."
                  if rows else None)

def _recent_docs(r):
    base = ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs")
    rows = []
    for k in [r.key(base)] + list(r.subkeys(base)):
        if not k:
            continue
        ext = k.get("name") if k.get("name") != "RecentDocs" else "(all)"
        for name, v in r.values(k).items():
            if name in ("(default)", "MRUListEx"):
                continue
            blob = None
            try:
                blob = r.hive.value_bytes(v["offset"])
            except Exception:
                pass
            if not blob:
                continue
            try:
                text = blob.decode("utf-16-le", "replace").split("\x00")[0]
            except Exception:
                continue
            if text.strip():
                rows.append({"type": ext, "document": text})
    return rows, None

def _accounts(r):
    rows = []
    for k in r.subkeys("SAM\\Domains\\Account\\Users\\Names"):
        rows.append({"user": k.get("name")})
    return rows, ("Local accounts by name. Their RIDs, login counts and last "
                  "logon are in the binary F and V values, which are not "
                  "parsed here." if rows else None)

SECTIONS = [
    (SYSTEM, "identity", "Machine identity", _system_identity),
    (SYSTEM, "usb", "USB storage attached", _usb_devices),
    (SYSTEM, "mounted", "Mounted devices", _mounted),
    (SOFTWARE, "os", "Operating system", _os_install),
    (SOFTWARE, "autoruns", "Auto-start programs (machine)",
     lambda r: _autoruns(r, SOFTWARE)),
    (SOFTWARE, "networks", "Networks joined", _networks),
    (SOFTWARE, "installed", "Installed programs", _installed),
    (NTUSER, "user_autoruns", "Auto-start programs (user)",
     lambda r: _autoruns(r, NTUSER)),
    (NTUSER, "activity", "Typed paths, URLs and launched programs",
     _user_activity),
    (NTUSER, "recent", "Recent documents", _recent_docs),
    (SAM, "accounts", "Local accounts", _accounts),
]

def why_unreadable(data, whole=True):
    if not data:
        return "The file is empty — it has no content to read."
    if not data.strip(b"\x00"):
        return (("Every byte of the file is zero. " if whole else
                 "The first %d bytes are all zero, including the header. "
                 % len(data))
                + "It was allocated and never written, so there is nothing "
                  "missing here — Windows leaves service-profile hives in "
                  "this state routinely.")
    if data[:4] != b"regf":
        return ("The file does not begin with the `regf` signature, so it is "
                "not a registry hive whatever its name says.")
    if len(data) >= 12:
        seq1, seq2 = struct.unpack_from("<II", data, 4)
        if seq1 != seq2:
            return ("The header's two sequence numbers disagree (%d and %d): "
                    "the hive was in the middle of a write. Replaying its "
                    "`.LOG` transaction files would be needed, and that is "
                    "not implemented." % (seq1, seq2))
    return ("The header is a valid hive but the body would not parse. This is "
            "damage, not an empty file.")

def report(hive, name="", data=None, whole=True):
    if hive is None:
        why = why_unreadable(data, whole) if data is not None else None
        return {"hive": name, "kind": None, "sections": [], "unreadable": True,
                "empty": data is not None and not (data or b"").strip(b"\x00"),
                "why": why,
                "note": (why + " " if why else
                         "This hive could not be opened, so nothing was "
                         "checked. ")
                        + "That is not the same as finding nothing in it."}
    kind = classify(hive, name)
    if not kind:
        return {"hive": name, "kind": None, "sections": [],
                "note": "This hive is not one of the ones with a known layout."}
    r = Reader(hive)
    out = []
    for want, sid, title, fn in SECTIONS:
        if want != kind:
            continue
        try:
            rows, note = fn(r)
        except Exception as exc:
            out.append({"id": sid, "title": title, "rows": [],
                        "error": "Could not read: %s" % exc})
            continue
        out.append({"id": sid, "title": title, "rows": rows,
                    "count": len(rows), "note": note})
    return {"hive": name, "kind": kind, "sections": out,
            "note": "Sections with no rows mean the key held nothing. Where "
                    "the key itself is missing, the section says so — that is "
                    "a different statement from finding nothing in it."}
