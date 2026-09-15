import hashlib
import io
import os
import threading

from .fs import logicalfs
from .text import t as _t

COUNT_CAP = 50000

def looks_logical(path):
    return os.path.isdir(path) or os.path.isfile(path)

def _count_folder(root):
    files = folders = 0
    total = 0
    capped = False
    stack = [(root, 0)]
    while stack:
        here, depth = stack.pop()
        if depth > logicalfs.MAX_DEPTH:
            capped = True
            continue
        try:
            with os.scandir(here) as it:
                items = list(it)
        except OSError:
            continue
        for de in items:
            if files + folders >= COUNT_CAP:
                capped = True
                stack = []
                break
            try:
                if de.is_symlink():
                    files += 1
                    continue
                if de.is_dir(follow_symlinks=False):
                    folders += 1
                    stack.append((de.path, depth + 1))
                else:
                    files += 1
                    total += de.stat(follow_symlinks=False).st_size
            except OSError:
                continue
    return {"files": files, "folders": folders, "bytes": total,
            "counted_fully": not capped}

class LogicalImage:

    logical = True

    def __init__(self, path):
        self.path = os.path.abspath(path)
        self.tree = logicalfs.open_tree(self.path)
        self.filesystem = logicalfs.LogicalFS(self.tree)
        self.kind = self.tree.kind
        self.bytes_per_sector = 512
        self.header = {}
        self.stored_md5 = None
        self.stored_sha1 = None
        self._pos = 0
        self._io_lock = threading.Lock()
        self._fh = None
        self.findings = list(getattr(self.tree, "findings", []))

        if self.kind == "folder":
            self.size = 0
            self.segment_paths = []
            self.summary = _count_folder(self.path)
            self.findings.append(_t("logical.folder_not_image"))
        else:
            self._fh = open(self.path, "rb")
            self.size = os.path.getsize(self.path)
            self.segment_paths = [self.path]
            if self.kind == "zip":
                members = getattr(self.tree, "_members", {})
                self.summary = {
                    "files": len(members),
                    "folders": max(0, len(getattr(self.tree, "_dirs", {})) - 1),
                    "bytes": sum(z.file_size for z in members.values()),
                    "counted_fully": True,
                }
            else:
                self.summary = {"files": 1, "folders": 0, "bytes": self.size,
                                "counted_fully": True}

    def read_at(self, offset, length):
        if self._fh is None or offset >= self.size:
            return b""
        with self._io_lock:
            self._fh.seek(offset)
            return self._fh.read(min(length, self.size - offset))

    def read(self, n=-1):
        d = self.read_at(self._pos, self.size - self._pos if n < 0 else n)
        self._pos += len(d)
        return d

    def seek(self, off, whence=io.SEEK_SET):
        if whence == io.SEEK_SET:
            self._pos = off
        elif whence == io.SEEK_CUR:
            self._pos += off
        else:
            self._pos = self.size + off
        return self._pos

    def close(self):
        try:
            self.filesystem.close()
        except Exception:
            pass
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def verify(self, progress=None):
        if self._fh is None:
            return {"computed_md5": None, "computed_sha1": None,
                    "stored_md5": None, "stored_sha1": None,
                    "md5_match": None, "sha1_match": None,
                    "note": _t("logical.no_container_to_hash")}
        md5, sha1 = hashlib.md5(), hashlib.sha1()
        pos = 0
        while pos < self.size:
            d = self.read_at(pos, 1 << 20)
            if not d:
                break
            md5.update(d)
            sha1.update(d)
            pos += len(d)
            if progress:
                progress(pos / self.size)
        return {"computed_md5": md5.hexdigest(),
                "computed_sha1": sha1.hexdigest(),
                "stored_md5": None, "stored_sha1": None,
                "md5_match": None, "sha1_match": None}

    def info(self):
        s = self.summary
        at_least = "" if s.get("counted_fully") else " (at least)"
        fmt = {"folder": _t("logical.format_folder"),
               "zip": _t("logical.format_zip"),
               "file": _t("logical.format_file")}[self.kind]
        return {
            "format": fmt,
            "logical": True,
            "kind": self.kind,
            "segments": [os.path.basename(self.path)],
            "source_path": self.path,
            "size": self.size,
            "bytes_per_sector": 512,
            "chunk_size": None,
            "acquisition": {},
            "items": s["files"],
            "folders": s["folders"],
            "content_bytes": s["bytes"],
            "counted_fully": s.get("counted_fully", True),
            "summary_text": "%d file%s%s, %d byte%s"
                            % (s["files"], "" if s["files"] == 1 else "s",
                               at_least, s["bytes"],
                               "" if s["bytes"] == 1 else "s"),
            "findings": list(self.findings),
        }

def open_logical(path):
    if not looks_logical(path):
        raise ValueError("Nothing to open at %s" % path)
    return LogicalImage(path)
