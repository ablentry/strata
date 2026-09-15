import datetime

CHROMIUM_EPOCH = datetime.datetime(1601, 1, 1)
UNIX_EPOCH = datetime.datetime(1970, 1, 1)

TRANSITIONS = {
    0: "link", 1: "typed", 2: "auto bookmark", 3: "auto subframe",
    4: "manual subframe", 5: "generated", 6: "start page", 7: "form submit",
    8: "reload", 9: "keyword", 10: "keyword generated",
}

def chromium_time(v):
    if not v:
        return None
    try:
        return (CHROMIUM_EPOCH + datetime.timedelta(microseconds=int(v))
                ).isoformat() + "Z"
    except (OverflowError, ValueError, TypeError):
        return None

def unix_micros(v):
    if not v:
        return None
    try:
        return (UNIX_EPOCH + datetime.timedelta(microseconds=int(v))
                ).isoformat() + "Z"
    except (OverflowError, ValueError, TypeError):
        return None

def unix_millis(v):
    if not v:
        return None
    try:
        return (UNIX_EPOCH + datetime.timedelta(milliseconds=int(v))
                ).isoformat() + "Z"
    except (OverflowError, ValueError, TypeError):
        return None

def identify(db):
    names = {t["name"] for t in db.tables()}
    if {"urls", "visits"} <= names:
        return "chromium_history"
    if {"moz_places", "moz_historyvisits"} <= names:
        return "firefox_places"
    if "cookies" in names:
        return "chromium_cookies"
    if "moz_cookies" in names:
        return "firefox_cookies"
    if "logins" in names:
        return "chromium_logins"
    if {"autofill"} & names:
        return "chromium_webdata"
    if "moz_formhistory" in names:
        return "firefox_formhistory"
    if "downloads" in names:
        return "chromium_downloads"
    return None

def _rows(db, table, limit):
    got = db.read_table(table, limit)
    return got["rows"] if got else []

def history(db, limit=20000):
    kind = identify(db)
    if kind == "chromium_history":
        return _chromium_history(db, limit)
    if kind == "firefox_places":
        return _firefox_history(db, limit)
    return None

def _chromium_history(db, limit):
    urls = {}
    for r in _rows(db, "urls", limit):
        urls[r.get("id")] = r
    out = []
    for v in _rows(db, "visits", limit):
        u = urls.get(v.get("url")) or {}
        trans = v.get("transition") or 0
        out.append({
            "url": u.get("url"), "title": u.get("title"),
            "visited_at": chromium_time(v.get("visit_time")),
            "visit_count": u.get("visit_count"),
            "typed_count": u.get("typed_count"),
            "transition": TRANSITIONS.get(int(trans) & 0xFF, str(trans & 0xFF)),
            "duration_us": v.get("visit_duration"),
            "from_visit": v.get("from_visit"),
            "source": "chromium",
        })
    seen = {o["url"] for o in out}
    for u in urls.values():
        if u.get("url") not in seen:
            out.append({
                "url": u.get("url"), "title": u.get("title"),
                "visited_at": chromium_time(u.get("last_visit_time")),
                "visit_count": u.get("visit_count"),
                "typed_count": u.get("typed_count"),
                "transition": None, "source": "chromium",
                "note": "no visit row; time is last_visit_time from urls",
            })
    out.sort(key=lambda r: r.get("visited_at") or "", reverse=True)
    return out

def _firefox_history(db, limit):
    places = {}
    for r in _rows(db, "moz_places", limit):
        places[r.get("id")] = r
    out = []
    for v in _rows(db, "moz_historyvisits", limit):
        p = places.get(v.get("place_id")) or {}
        out.append({
            "url": p.get("url"), "title": p.get("title"),
            "visited_at": unix_micros(v.get("visit_date")),
            "visit_count": p.get("visit_count"),
            "typed_count": p.get("typed"),
            "transition": str(v.get("visit_type")),
            "from_visit": v.get("from_visit"),
            "source": "firefox",
        })
    seen = {o["url"] for o in out}
    for p in places.values():
        if p.get("url") not in seen:
            out.append({
                "url": p.get("url"), "title": p.get("title"),
                "visited_at": unix_micros(p.get("last_visit_date")),
                "visit_count": p.get("visit_count"),
                "transition": None, "source": "firefox",
                "note": "no visit row; time is last_visit_date from moz_places",
            })
    out.sort(key=lambda r: r.get("visited_at") or "", reverse=True)
    return out

def downloads(db, limit=5000):
    kind = identify(db)
    names = {t["name"] for t in db.tables()}
    out = []
    if "downloads" in names:
        chains = {}
        for c in _rows(db, "downloads_url_chains", limit):
            chains.setdefault(c.get("id"), []).append(c.get("url"))
        for d in _rows(db, "downloads", limit):
            out.append({
                "target": d.get("target_path"),
                "url": (chains.get(d.get("id")) or [None])[-1],
                "started_at": chromium_time(d.get("start_time")),
                "finished_at": chromium_time(d.get("end_time")),
                "bytes": d.get("received_bytes"),
                "total_bytes": d.get("total_bytes"),
                "opened": bool(d.get("opened")),
                "source": "chromium",
            })
    elif kind == "firefox_places":
        attrs = {a.get("id"): a.get("name")
                 for a in _rows(db, "moz_anno_attributes", limit)}
        places = {p.get("id"): p for p in _rows(db, "moz_places", limit)}
        for a in _rows(db, "moz_annos", limit):
            if attrs.get(a.get("anno_attribute_id")) != "downloads/destinationFileURI":
                continue
            p = places.get(a.get("place_id")) or {}
            out.append({
                "target": a.get("content"), "url": p.get("url"),
                "started_at": unix_micros(p.get("last_visit_date")),
                "source": "firefox",
            })
    out.sort(key=lambda r: r.get("started_at") or "", reverse=True)
    return out

def cookies(db, limit=20000):
    kind = identify(db)
    if kind == "chromium_cookies" or "cookies" in {t["name"] for t in db.tables()}:
        return [{
            "host": c.get("host_key"), "name": c.get("name"),
            "path": c.get("path"),
            "created_at": chromium_time(c.get("creation_utc")),
            "expires_at": chromium_time(c.get("expires_utc")),
            "last_access": chromium_time(c.get("last_access_utc")),
            "secure": bool(c.get("is_secure")),
            "http_only": bool(c.get("is_httponly")),
            "encrypted": bool(c.get("encrypted_value")),
            "source": "chromium",
        } for c in _rows(db, "cookies", limit)]
    if "moz_cookies" in {t["name"] for t in db.tables()}:
        return [{
            "host": c.get("host"), "name": c.get("name"), "path": c.get("path"),
            "created_at": unix_micros(c.get("creationTime")),
            "expires_at": unix_millis((c.get("expiry") or 0) * 1000),
            "last_access": unix_micros(c.get("lastAccessed")),
            "secure": bool(c.get("isSecure")),
            "http_only": bool(c.get("isHttpOnly")),
            "value": c.get("value"),
            "source": "firefox",
        } for c in _rows(db, "moz_cookies", limit)]
    return []

def recovered_urls(db, limit=5000):
    rec = db.recover(limit=limit)
    out = []
    for r in rec["records"]:
        text = [v for v in r["values"] if isinstance(v, str)]
        url = next((t for t in text
                    if t.startswith(("http://", "https://", "ftp://", "file://"))),
                   None)
        if not url:
            continue
        title = next((t for t in text if t is not url and len(t) > 3), None)
        stamp = None
        for v in r["values"]:
            if isinstance(v, int) and 1e16 < v < 1.4e17:
                stamp = chromium_time(v)
                break
            if isinstance(v, int) and 1e15 < v < 2e15:
                stamp = unix_micros(v)
                break
        out.append({"url": url, "title": title, "visited_at": stamp,
                    "deleted": True, "page": r.get("page"),
                    "source": r.get("source")})
    return out

PROFILE_HINTS = [
    ("\\google\\chrome\\", "Chrome"), ("\\microsoft\\edge\\", "Edge"),
    ("\\brave", "Brave"), ("\\opera", "Opera"), ("\\vivaldi", "Vivaldi"),
    ("\\mozilla\\firefox\\", "Firefox"), ("\\chromium\\", "Chromium"),
    ("\\microsoft\\olk\\", "Outlook web view"),
    ("microsoftteams", "Teams"), ("\\dropbox\\", "Dropbox"),
]

def product_from_path(path):
    low = (path or "").lower().replace("/", "\\")
    for needle, name in PROFILE_HINTS:
        if needle in low:
            return name
    return None
