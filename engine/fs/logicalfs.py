import datetime
import os
import threading
import stat as stat_mod
import zipfile

from ..text import t as _t
from .streams import UnsupportedStream

MAX_MEMBERS = 500000

MAX_DEPTH = 128

def _iso(ts):
    if not ts:
        return None
    try:
        dt = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    return dt.replace(tzinfo=None).isoformat() + "Z"

def _safe_parts(name):
    out = []
    for part in name.replace("\\", "/").split("/"):
        if part in ("", ".", ".."):
            continue
        out.append(part)
    return out

class FolderTree:

    kind = "folder"

    def __init__(self, path):
        self.root = os.path.abspath(path)
        if not os.path.isdir(self.root):
            raise ValueError("Not a folder: %s" % path)
        self.label = os.path.basename(self.root.rstrip("/\\")) or self.root

    def _real(self, key):
        full = os.path.abspath(os.path.join(self.root, key)) if key \
            else self.root
        root = self.root.rstrip("/\\")
        if full != root and not full.startswith(root + os.sep):
            raise ValueError("Outside the collection: %s" % key)
        return full

    def children(self, key):
        out = []
        try:
            with os.scandir(self._real(key)) as it:
                items = list(it)
        except (OSError, ValueError):
            return out
        for de in items:
            try:
                link = de.is_symlink()
                is_dir = de.is_dir(follow_symlinks=False)
                st = de.stat(follow_symlinks=False)
            except OSError:
                continue
            out.append({
                "key": (key + "/" + de.name) if key else de.name,
                "name": de.name,
                "is_dir": is_dir,
                "link": link,
                "size": 0 if is_dir else st.st_size,
                "modified": _iso(st.st_mtime),
                "created": _iso(getattr(st, "st_birthtime", None)
                                or st.st_ctime),
                "accessed": _iso(st.st_atime),
                "mode": stat_mod.filemode(st.st_mode),
            })
        out.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
        return out

    def read_range(self, key, off, length):
        with open(self._real(key), "rb") as f:
            f.seek(off)
            return f.read(max(0, length))

    def read_all(self, key, max_bytes=None):
        with open(self._real(key), "rb") as f:
            return f.read() if max_bytes is None else f.read(max_bytes)

    def details(self, key):
        try:
            st = os.stat(self._real(key), follow_symlinks=False)
        except OSError:
            return {}
        info = {"host_path": self._real(key), "mode": stat_mod.filemode(
            st.st_mode), "size": st.st_size, "links": st.st_nlink}
        if stat_mod.S_ISLNK(st.st_mode):
            try:
                info["symlink_target"] = os.readlink(self._real(key))
            except OSError:
                pass
        return info

class FileTree(FolderTree):

    kind = "file"

    def __init__(self, path):
        self.file = os.path.abspath(path)
        if not os.path.isfile(self.file):
            raise ValueError("Not a file: %s" % path)
        self.root = os.path.dirname(self.file)
        self.only = os.path.basename(self.file)
        self.label = self.only

    def children(self, key):
        if key:
            return []
        return [e for e in FolderTree.children(self, "")
                if e["name"] == self.only]

class ZipTree:

    kind = "zip"

    def __init__(self, path):
        self.path = os.path.abspath(path)
        self.zip = zipfile.ZipFile(self.path)
        self.label = os.path.basename(self.path)
        self.findings = []
        self._dirs = {"": []}
        self._members = {}
        self._cursor = None
        self._lock = threading.Lock()
        self._build()

    def _ensure_dir(self, key):
        if key in self._dirs:
            return
        self._dirs[key] = []
        parent, _, name = key.rpartition("/")
        self._ensure_dir(parent)
        self._dirs[parent].append({
            "key": key, "name": name, "is_dir": True, "link": False,
            "size": 0, "modified": None, "created": None, "accessed": None,
        })

    def _build(self):
        infos = self.zip.infolist()
        if len(infos) > MAX_MEMBERS:
            self.findings.append(_t("logical.zip_members_capped")
                                 % (len(infos), MAX_MEMBERS))
            infos = infos[:MAX_MEMBERS]
        for zi in infos:
            raw = zi.filename
            unsafe = ("\\" in raw or raw.startswith("/")
                      or ".." in raw.replace("\\", "/").split("/"))
            parts = _safe_parts(raw)
            if not parts:
                continue
            if unsafe:
                self.findings.append(_t("logical.zip_unsafe_name")
                                     % raw[:120])
            key = "/".join(parts)
            if zi.is_dir():
                self._ensure_dir(key)
                continue
            if key in self._members or key in self._dirs:
                base, dot, ext = parts[-1].rpartition(".")
                n = 2
                while key in self._members or key in self._dirs:
                    alt = ("%s (%d)%s%s" % (base, n, dot, ext)) if dot \
                        else "%s (%d)" % (parts[-1], n)
                    key = "/".join(parts[:-1] + [alt])
                    n += 1
                parts = key.split("/")
            parent = key.rpartition("/")[0]
            self._ensure_dir(parent)
            self._members[key] = zi
            self._dirs[parent].append({
                "key": key,
                "name": parts[-1],
                "stored_name": raw if raw != key else None,
                "is_dir": False,
                "link": False,
                "size": zi.file_size,
                "modified": "%04d-%02d-%02dT%02d:%02d:%02d" % zi.date_time
                            if zi.date_time else None,
                "created": None,
                "accessed": None,
                "encrypted": bool(zi.flag_bits & 0x1),
                "method": zi.compress_type,
                "compressed_size": zi.compress_size,
                "crc": zi.CRC,
            })
        for children in self._dirs.values():
            children.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))

    def children(self, key):
        return list(self._dirs.get(key or "", []))

    def _handle(self, key, off):
        cur = self._cursor
        if cur and cur[0] == key and cur[1] <= off:
            fh = cur[2]
            skip = off - cur[1]
            while skip > 0:
                got = fh.read(min(skip, 1 << 20))
                if not got:
                    break
                skip -= len(got)
            return fh, off - skip
        if cur:
            try:
                cur[2].close()
            except Exception:
                pass
        fh = self.zip.open(self._members[key])
        pos = 0
        while pos < off:
            got = fh.read(min(off - pos, 1 << 20))
            if not got:
                break
            pos += len(got)
        return fh, pos

    def read_range(self, key, off, length):
        if key not in self._members:
            return b""
        with self._lock:
            fh, pos = self._handle(key, off)
            if pos < off:
                self._cursor = (key, pos, fh)
                return b""
            out = bytearray()
            while len(out) < length:
                got = fh.read(min(length - len(out), 1 << 20))
                if not got:
                    break
                out += got
            self._cursor = (key, off + len(out), fh)
            return bytes(out)

    def read_all(self, key, max_bytes=None):
        if key not in self._members:
            return b""
        with self._lock:
            with self.zip.open(self._members[key]) as fh:
                return fh.read() if max_bytes is None else fh.read(max_bytes)

    def details(self, key):
        zi = self._members.get(key)
        if zi is None:
            return {}
        return {
            "archive": self.path,
            "stored_name": zi.filename,
            "header_offset": zi.header_offset,
            "compressed_size": zi.compress_size,
            "size": zi.file_size,
            "method": zipfile.compressor_names.get(zi.compress_type,
                                                   str(zi.compress_type)),
            "crc32": "%08X" % (zi.CRC & 0xFFFFFFFF),
            "encrypted": bool(zi.flag_bits & 0x1),
            "created_by": "%d" % zi.create_system,
        }

    def close(self):
        if self._cursor:
            try:
                self._cursor[2].close()
            except Exception:
                pass
            self._cursor = None
        self.zip.close()

def _note():
    return _t("logical.note")

class LogicalFS:

    name = "Logical"
    root_node = 0

    def __init__(self, tree):
        self.tree = tree
        self._keys = {0: ""}
        self._ids = {"": 0}
        self._next = 1
        self._id_lock = threading.Lock()

    def _id(self, key):
        got = self._ids.get(key)
        if got is not None:
            return got
        with self._id_lock:
            got = self._ids.get(key)
            if got is None:
                got = self._next
                self._next += 1
                self._ids[key] = got
                self._keys[got] = key
            return got

    def _key(self, entry):
        oid = entry.get("oid") if isinstance(entry, dict) else entry
        if oid is None:
            return None
        return self._keys.get(oid)

    def listdir(self, node=None, path="/"):
        key = self._keys.get(0 if node in (None,) else node)
        if key is None:
            return []
        base = path.rstrip("/")
        out = []
        for c in self.tree.children(key):
            oid = self._id(c["key"])
            e = {
                "name": c["name"],
                "path": base + "/" + c["name"],
                "is_dir": c["is_dir"],
                "deleted": False,
                "size": c.get("size") or 0,
                "created": c.get("created"),
                "modified": c.get("modified"),
                "accessed": c.get("accessed"),
                "oid": oid,
                "id": "logical:%d" % oid,
                "streams": [],
            }
            for extra in ("link", "stored_name", "encrypted", "mode"):
                if c.get(extra):
                    e[extra] = c[extra]
            out.append(e)
        return out

    def read_file(self, entry, max_bytes=None, stream=""):
        if stream:
            raise UnsupportedStream("Logical", stream)
        key = self._key(entry)
        if key is None or entry.get("is_dir") or entry.get("link"):
            return b""
        try:
            return self.tree.read_all(key, max_bytes)
        except (OSError, ValueError, zipfile.BadZipFile, RuntimeError):
            return b""

    def read_range(self, entry, off, length, stream=""):
        if stream:
            raise UnsupportedStream("Logical", stream)
        key = self._key(entry)
        if key is None or entry.get("is_dir") or entry.get("link"):
            return b""
        size = entry.get("size") or 0
        length = min(length, max(0, size - off)) if size else length
        if length <= 0:
            return b""
        try:
            return self.tree.read_range(key, off, length)
        except (OSError, ValueError, zipfile.BadZipFile, RuntimeError):
            return b""

    def stat(self, entry, stream=""):
        key = self._key(entry)
        if key is None:
            return {}
        info = {
            "filesystem": "Logical (%s)" % self.tree.kind,
            "collection": getattr(self.tree, "path", None)
            or getattr(self.tree, "root", None),
            "relative_path": key,
            "size": entry.get("size") or 0,
            "note": _note(),
        }
        try:
            info.update(self.tree.details(key))
        except Exception:
            pass
        return info

    def info(self):
        return {
            "type": "Logical",
            "label": self.tree.label,
            "logical": True,
            "kind": self.tree.kind,
            "cluster_size": None,
            "bytes_per_sector": None,
            "findings": [_note()] + list(getattr(self.tree, "findings", [])),
        }

    def close(self):
        fn = getattr(self.tree, "close", None)
        if fn is not None:
            fn()

def open_tree(path):
    if os.path.isdir(path):
        return FolderTree(path)
    if zipfile.is_zipfile(path):
        return ZipTree(path)
    return FileTree(path)

def open_logical(path):
    return LogicalFS(open_tree(path))
