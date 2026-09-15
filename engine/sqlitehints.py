import datetime

_WEBKIT_OFFSET = 11644473600 * 1000000

def _iso(dt):
    return dt.replace(microsecond=dt.microsecond).isoformat() + "Z"

def unix_seconds(v):
    if not isinstance(v, (int, float)) or not v:
        return None
    try:
        return _iso(datetime.datetime(1970, 1, 1)
                    + datetime.timedelta(seconds=v))
    except (OverflowError, ValueError):
        return None

def unix_micros(v):
    if not isinstance(v, (int, float)) or not v:
        return None
    try:
        return _iso(datetime.datetime(1970, 1, 1)
                    + datetime.timedelta(microseconds=v))
    except (OverflowError, ValueError):
        return None

def unix_millis(v):
    if not isinstance(v, (int, float)) or not v:
        return None
    try:
        return _iso(datetime.datetime(1970, 1, 1)
                    + datetime.timedelta(milliseconds=v))
    except (OverflowError, ValueError):
        return None

def webkit_micros(v):
    if not isinstance(v, (int, float)) or not v:
        return None
    return unix_micros(v - _WEBKIT_OFFSET)

def mac_absolute(v):
    if not isinstance(v, (int, float)) or not v:
        return None
    try:
        return _iso(datetime.datetime(2001, 1, 1) + datetime.timedelta(seconds=v))
    except (OverflowError, ValueError):
        return None

def rev_host(v):
    if not isinstance(v, str) or not v:
        return None
    s = v[:-1] if v.endswith(".") else v
    out = s[::-1]
    return out or None

def _bool(v):
    if v in (0, 1):
        return "true" if v else "false"
    return None

DECODERS = {
    ("moz_places", "rev_host"): ("host", rev_host),
    ("moz_places", "last_visit_date"): ("time", unix_micros),
    ("moz_places", "hidden"): ("flag", _bool),
    ("moz_places", "typed"): ("flag", _bool),
    ("moz_historyvisits", "visit_date"): ("time", unix_micros),
    ("moz_bookmarks", "dateAdded"): ("time", unix_micros),
    ("moz_bookmarks", "lastModified"): ("time", unix_micros),
    ("moz_annos", "dateAdded"): ("time", unix_micros),
    ("moz_annos", "lastModified"): ("time", unix_micros),
    ("moz_origins", "host"): ("host", None),
    ("moz_cookies", "expiry"): ("time", unix_seconds),
    ("moz_cookies", "lastAccessed"): ("time", unix_micros),
    ("moz_cookies", "creationTime"): ("time", unix_micros),
    ("moz_cookies", "isSecure"): ("flag", _bool),
    ("moz_cookies", "isHttpOnly"): ("flag", _bool),
    ("moz_formhistory", "firstUsed"): ("time", unix_micros),
    ("moz_formhistory", "lastUsed"): ("time", unix_micros),
    ("urls", "last_visit_time"): ("time", webkit_micros),
    ("visits", "visit_time"): ("time", webkit_micros),
    ("downloads", "start_time"): ("time", webkit_micros),
    ("downloads", "end_time"): ("time", webkit_micros),
    ("downloads", "last_access_time"): ("time", webkit_micros),
    ("keyword_search_terms", "last_visit_time"): ("time", webkit_micros),
    ("cookies", "creation_utc"): ("time", webkit_micros),
    ("cookies", "expires_utc"): ("time", webkit_micros),
    ("cookies", "last_access_utc"): ("time", webkit_micros),
    ("cookies", "last_update_utc"): ("time", webkit_micros),
    ("cookies", "is_secure"): ("flag", _bool),
    ("cookies", "is_httponly"): ("flag", _bool),
    ("logins", "date_created"): ("time", webkit_micros),
    ("logins", "date_last_used"): ("time", webkit_micros),
    ("logins", "date_password_modified"): ("time", webkit_micros),
    ("autofill", "date_created"): ("time", unix_seconds),
    ("autofill", "date_last_used"): ("time", unix_seconds),
    ("history_items", "visit_count_score"): (None, None),
    ("history_visits", "visit_time"): ("time", mac_absolute),
    ("moz_downloads", "startTime"): ("time", unix_micros),
    ("moz_downloads", "endTime"): ("time", unix_micros),
}

def decoders_for(table, columns):
    name = (table or "").lower()
    out = {}
    for i, col in enumerate(columns or []):
        got = DECODERS.get((name, col)) or DECODERS.get((name, (col or "").lower()))
        if not got:
            for (t, c), v in DECODERS.items():
                if t == name and c.lower() == (col or "").lower():
                    got = v
                    break
        if got and got[1]:
            out[i] = {"column": col, "kind": got[0]}
    return out

def decode_rows(table, columns, rows):
    which = decoders_for(table, columns)
    if not which:
        return {}, {}
    name = (table or "").lower()
    fns = {}
    for meta in which.values():
        col = meta["column"]
        got = DECODERS.get((name, col))
        if not got:
            for (t, c), v in DECODERS.items():
                if t == name and c.lower() == (col or "").lower():
                    got = v
                    break
        if got and got[1]:
            fns[col] = got[1]

    cols = list(columns or [])
    out = {}
    for r, row in enumerate(rows or []):
        got = {}
        for col, fn in fns.items():
            if isinstance(row, dict):
                if col not in row:
                    continue
                raw = row[col]
            else:
                try:
                    raw = row[cols.index(col)]
                except (ValueError, IndexError):
                    continue
            try:
                val = fn(raw)
            except Exception:
                val = None
            if val is not None and str(val) != str(raw):
                got[col] = val
        if got:
            out[r] = got
    return {v["column"]: v for v in which.values()}, out
