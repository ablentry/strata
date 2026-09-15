import json
import os
import threading

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STRINGS = os.path.join(HERE, "web", "strings")
BASE = "en-GB"
FILE = "engine.json"

_lock = threading.Lock()
_cache = None

def _flatten(obj, prefix=""):
    out = {}
    for k, v in obj.items():
        key = prefix + k
        if isinstance(v, dict):
            out.update(_flatten(v, key + "."))
        else:
            out[key] = v
    return out

def _load():
    path = os.path.join(STRINGS, BASE, FILE)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            got = json.load(fh)
        return _flatten(got) if isinstance(got, dict) else {}
    except (OSError, ValueError):
        return {}

def strings():
    global _cache
    with _lock:
        if _cache is None:
            _cache = _load()
        return _cache

def reload():
    global _cache
    with _lock:
        _cache = None
    return strings()

def t(key, *args):
    s = strings().get(key, key)
    if not args:
        return s
    try:
        return s % args
    except (TypeError, ValueError):
        return s
