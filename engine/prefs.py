import json
import os
import re
import sys
import tempfile
import threading

ALLOWED = {
    "theme":        ("dark", "light"),
    "tree_width":   (160, 640),
    "inspect_width": (200, 720),
    "preview_split": (0, 100),
    "core_width":   (0, 400),
    "folder_view":  ("list", "gallery"),
    "time_display": ("utc", "local", "both"),
    "offset_mode":  ("logical", "physical"),
    "hex_bpr":      (8, 64),
    "hex_font":     (9, 22),
    "split_hex":    (False, True),
    "language":     "installed-languages",
    "notify":       "notice-channels",
    "carve_types_off": "carve-types",
    "carve_signatures": "carve-signatures",
    "columns":      None,
    "open_sections": None,
}

NOTICE_CHANNELS = ("action", "task", "colleague")

_lock = threading.Lock()
_EXT = re.compile(r"^[a-z0-9]{1,10}$")

def _dir():
    override = os.environ.get("STRATA_CONFIG_DIR")
    if override:
        return override
    if os.name == "nt":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, "Strata")
    if sys.platform == "darwin":
        return os.path.expanduser("~/Library/Application Support/Strata")
    base = os.environ.get("XDG_CONFIG_HOME")
    if base:
        return os.path.join(base, "strata")
    return os.path.expanduser("~/.config/strata")

def path():
    return os.path.join(_dir(), "prefs.json")

def _load_all():
    try:
        with open(path(), "r", encoding="utf-8") as fh:
            got = json.load(fh)
        return got if isinstance(got, dict) else {}
    except (OSError, ValueError):
        return {}

def installed_languages():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    root = os.path.join(here, "web", "strings")
    try:
        return sorted(d for d in os.listdir(root)
                      if os.path.isdir(os.path.join(root, d)))
    except OSError:
        return []

def clean(values):
    out = {}
    for key, rule in ALLOWED.items():
        if key not in values:
            continue
        v = values[key]
        if rule is None:
            if isinstance(v, dict):
                out[key] = v
            continue
        if rule == "installed-languages":
            if isinstance(v, str) and v in installed_languages():
                out[key] = v
            continue
        if rule == "carve-types":
            if isinstance(v, list):
                out[key] = sorted({x for x in v if isinstance(x, str)
                                   and _EXT.match(x)})[:100]
            continue
        if rule == "carve-signatures":
            if isinstance(v, list):
                from . import carve as carve_mod
                keep, seen = [], set()
                for spec in v[:carve_mod.CUSTOM_LIMITS["count"]]:
                    try:
                        _, c = carve_mod.custom_signature(spec)
                    except ValueError:
                        continue
                    if not c.get("id") or c["id"] in seen:
                        continue
                    seen.add(c["id"])
                    keep.append(c)
                out[key] = keep
            continue
        if rule == "notice-channels":
            if isinstance(v, dict):
                out[key] = {k: bool(x) for k, x in v.items()
                            if k in NOTICE_CHANNELS}
            continue
        lo = rule[0]
        if isinstance(lo, bool):
            out[key] = bool(v)
        elif isinstance(lo, str):
            if v in rule:
                out[key] = v
        elif isinstance(v, (int, float)) and not isinstance(v, bool):
            lo, hi = rule
            out[key] = min(hi, max(lo, int(v)))
    return out

def get(examiner):
    who = (examiner or "unattributed").strip() or "unattributed"
    with _lock:
        return dict(_load_all().get(who) or {})

def put(examiner, values):
    who = (examiner or "unattributed").strip() or "unattributed"
    keep = clean(values or {})
    with _lock:
        allp = _load_all()
        cur = dict(allp.get(who) or {})
        cur.update(keep)
        allp[who] = cur
        try:
            os.makedirs(_dir(), exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=_dir(), suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(allp, fh, indent=1, sort_keys=True)
            os.replace(tmp, path())
        except OSError:
            pass
        return cur

def forget(examiner):
    who = (examiner or "unattributed").strip() or "unattributed"
    with _lock:
        allp = _load_all()
        allp.pop(who, None)
        try:
            os.makedirs(_dir(), exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=_dir(), suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(allp, fh, indent=1, sort_keys=True)
            os.replace(tmp, path())
        except OSError:
            pass
        return {}
