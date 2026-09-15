import json
import os
import tempfile
import threading
import time

from . import casedb
from . import prefs

MAX = 24

_lock = threading.Lock()

def path():
    return os.path.join(prefs._dir(), "recents.json")

def _key(p):
    return os.path.normcase(os.path.abspath(p))

def _load_all():
    try:
        with open(path(), "r", encoding="utf-8") as fh:
            got = json.load(fh)
        return got if isinstance(got, dict) else {}
    except (OSError, ValueError):
        return {}

def _save_all(allr):
    try:
        os.makedirs(prefs._dir(), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=prefs._dir(), suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(allr, fh, indent=1, sort_keys=True)
        os.replace(tmp, path())
    except OSError:
        pass

def _who(examiner):
    return (examiner or "unattributed").strip() or "unattributed"

def note(examiner, case_path, name=None):
    if not case_path:
        return []
    who = _who(examiner)
    entry = {"path": os.path.abspath(case_path),
             "name": name or os.path.splitext(os.path.basename(case_path))[0],
             "opened_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    with _lock:
        allr = _load_all()
        mine = [e for e in (allr.get(who) or [])
                if isinstance(e, dict) and e.get("path")
                and _key(e["path"]) != _key(case_path)]
        mine.insert(0, entry)
        allr[who] = mine[:MAX]
        _save_all(allr)
        return list(allr[who])

def entries(examiner):
    who = _who(examiner)
    with _lock:
        raw = list(_load_all().get(who) or [])
    out = []
    for e in raw:
        if not isinstance(e, dict) or not e.get("path"):
            continue
        try:
            here = casedb.is_case(e["path"])
        except OSError:
            here = None
        item = dict(e)
        item["exists"] = here
        out.append(item)
    return out

def forget(examiner, case_path=None):
    who = _who(examiner)
    with _lock:
        allr = _load_all()
        if case_path is None:
            allr.pop(who, None)
            _save_all(allr)
            return []
        mine = [e for e in (allr.get(who) or [])
                if isinstance(e, dict) and e.get("path")
                and _key(e["path"]) != _key(case_path)]
        allr[who] = mine
        _save_all(allr)
        return list(mine)
