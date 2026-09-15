import os
import secrets
import threading
import time

IDLE_TIMEOUT = 12 * 3600

COOKIE = "strata_sid"

class Registry:

    def __init__(self, factory, opener, logical_opener=None):
        self._factory = factory
        self._opener = opener
        self._logical_opener = logical_opener
        self._sessions = {}
        self._images = {}
        self._inflight = {}
        self._filesystems = {}
        self._vaults = {}
        self._lock = threading.RLock()
        self._pending_local = None
        self._default_sid = None

    def get(self, sid):
        if not sid:
            return None
        with self._lock:
            rec = self._sessions.get(sid)
            if rec is None:
                return None
            rec["seen"] = time.time()
            return rec["session"]

    def adopt_local(self, session):
        with self._lock:
            self._pending_local = session

    def create(self):
        sid = secrets.token_urlsafe(24)
        with self._lock:
            adopted = getattr(self, "_pending_local", None)
            self._pending_local = None
            self._sessions[sid] = {"session": adopted or self._factory(),
                                   "seen": time.time(),
                                   "started": time.time(),
                                   "name": None}
            return sid, self._sessions[sid]["session"]

    def default(self):
        with self._lock:
            sid = getattr(self, "_default_sid", None)
            if sid is None or sid not in self._sessions:
                sid, _sess = self.create()
                self._default_sid = sid
                self._sessions[sid]["name"] = None
                self._sessions[sid]["is_default"] = True
            self._sessions[sid]["seen"] = time.time()
            return sid, self._sessions[sid]["session"]

    def name(self, sid, value=None):
        with self._lock:
            rec = self._sessions.get(sid)
            if rec is None:
                return None
            if value is not None:
                rec["name"] = (value or "").strip() or None
            return rec["name"]

    def sweep(self, now=None):
        now = now or time.time()
        dropped = []
        with self._lock:
            for sid, rec in list(self._sessions.items()):
                if rec.get("is_default"):
                    continue
                if now - rec["seen"] > IDLE_TIMEOUT:
                    dropped.append(sid)
                    self._close(rec["session"])
                    del self._sessions[sid]
            self._collect_images()
        return dropped

    def _close(self, session):
        case = getattr(session, "case", None)
        if case is not None:
            try:
                case.close()
            except Exception:
                pass

    def describe(self):
        now = time.time()
        with self._lock:
            out = []
            idle = 0
            for sid, rec in self._sessions.items():
                s = rec["session"]
                case = getattr(s, "case", None)
                if not rec["name"] and case is None:
                    idle += 1
                    continue
                out.append({
                    "name": rec["name"] or "unattributed",
                    "case": (os.path.basename(case.path) if case else None),
                    "exhibits": len(getattr(s, "items", {}) or {}),
                    "idle_seconds": int(now - rec["seen"]),
                    "started": rec["started"],
                })
            out.sort(key=lambda x: ((x["name"] or "").lower(),
                                    x["case"] or ""))
            return {
                "analysts": out,
                "unnamed": idle,
                "note": ("Names are stated by each analyst and are not "
                         "verified — this server does not authenticate "
                         "anyone. The names identify work in the audit log; "
                         "they are not proof of who performed it."),
            }

    @staticmethod
    def _image_key(path, logical=False):
        real = os.path.realpath(path)
        return ("logical\0" + real) if logical else real

    def image(self, path, logical=False):
        key = self._image_key(path, logical)
        with self._lock:
            img = self._images.get(key)
            if img is None:
                opener = self._logical_opener if logical else self._opener
                if opener is None:
                    raise ValueError("No opener for %s" % path)
                img = self._images[key] = opener(path)
            self._inflight[key] = self._inflight.get(key, 0) + 1
            return img

    def shared(self, kind, path, offset, build):
        store = self._filesystems if kind == "fs" else self._vaults
        key = (os.path.realpath(path), int(offset))
        with self._lock:
            got = store.get(key)
            if got is None:
                got = build()
                if got is not None:
                    store[key] = got
            return got

    def drop_shared(self, kind, path, offset):
        store = self._filesystems if kind == "fs" else self._vaults
        with self._lock:
            store.pop((os.path.realpath(path), int(offset)), None)

    def done_opening(self, path, logical=False):
        key = self._image_key(path, logical)
        with self._lock:
            n = self._inflight.get(key, 0) - 1
            if n > 0:
                self._inflight[key] = n
            else:
                self._inflight.pop(key, None)

    def release_images(self):
        with self._lock:
            self._collect_images()

    def _collect_images(self):
        wanted = set(self._inflight)
        holders = [rec["session"] for rec in self._sessions.values()]
        if self._pending_local is not None:
            holders.append(self._pending_local)
        for sess in holders:
            for ev in (getattr(sess, "items", {}) or {}).values():
                p = getattr(ev, "path", None)
                if p:
                    wanted.add(self._image_key(p))
                    wanted.add(self._image_key(p, logical=True))
        for store in (self._filesystems, self._vaults):
            for k in [k for k in store if self._image_key(k[0]) not in wanted]:
                store.pop(k, None)
        for key in list(self._images):
            if key not in wanted:
                img = self._images.pop(key)
                closer = getattr(img, "close", None)
                if callable(closer):
                    try:
                        closer()
                    except Exception:
                        pass

    def stats(self):
        with self._lock:
            return {"sessions": len(self._sessions),
                    "shared_readers": len(self._images),
                    "shared_filesystems": len(self._filesystems),
                    "shared_vaults": len(self._vaults)}

def parse_cookie(header):
    if not header:
        return None
    for part in header.split(";"):
        k, _, v = part.strip().partition("=")
        if k == COOKIE and v:
            return v
    return None

def set_cookie_value(sid):
    return ("%s=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=%d"
            % (COOKIE, sid, IDLE_TIMEOUT))
