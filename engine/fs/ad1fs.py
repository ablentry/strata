from .. import ad1 as ad1_mod
from .streams import UnsupportedStream

CHUNK_MAP_CAP = 16384

class Ad1FS:

    name = "AD1"

    TOP = 0

    def __init__(self, source):
        self.img = ad1_mod.Ad1(source)
        self.root_node = self.TOP
        self.chunk_size = self.img.chunk_size
        self._sources = {sr["at"]: sr for sr in self.img.sources}
        self._cache = {}

    def _entry(self, o, path):
        md = self.img.metadata(o)
        is_dir = o["type"] == ad1_mod.TYPE_DIR
        name = o["name"]
        return {
            "name": name,
            "path": (path.rstrip("/") + "/" + name) if path != "/" or True
                    else name,
            "is_dir": is_dir,
            "deleted": False,
            "size": 0 if is_dir else o["size"],
            "created": md.get("created"),
            "modified": md.get("modified"),
            "accessed": md.get("accessed"),
            "owner": md.get("owner_name"),
            "md5": md.get("md5"),
            "sha1": md.get("sha1"),
            "oid": o["at"],
            "id": "ad1:%d" % o["at"],
            "streams": [],
        }

    def _source_entry(self, sr, path):
        a = sr["attributes"]
        got = sr.get("parsed")
        if got:
            label = "Partition %d" % got["number"]
            if got["volume"]:
                label += " \u201c%s\u201d" % got["volume"]
            slot = "AD1 %d" % got["number"]
        else:
            label, slot = sr["name"] or "(unnamed source)", ""
        return {
            "name": sr["name"] or "(unnamed source)",
            "tree_label": label,
            "tree_slot": slot,
            "source_size": (got or {}).get("size_bytes"),
            "source_size_text": (got or {}).get("size_text"),
            "filesystem": (got or {}).get("filesystem"),
            "path": path.rstrip("/") + "/" + (sr["name"] or "source"),
            "is_dir": True,
            "deleted": False,
            "size": 0,
            "oid": sr["at"],
            "id": "ad1src:%d" % sr["at"],
            "source": True,
            "volume_name": a.get("volume_name"),
            "volume_serial": a.get("volume_serial"),
            "source_os": a.get("source_os"),
            "streams": [],
        }

    def listdir(self, node=None, path="/"):
        if node in (None, self.TOP):
            return [self._source_entry(sr, path) for sr in self.img.sources]

        if node in self._sources:
            objs = self.img.top_level(self._sources[node]["root"])
            out = []
            for o in objs:
                self._cache[o["at"]] = o
                out.append(self._entry(o, path))
            return out

        self._cache[node] = self._cache.get(node) or self.img.object(node)
        out = []
        for child in self.img.children(node):
            self._cache[child["at"]] = child
            out.append(self._entry(child, path))
        out.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
        return out

    def _object_for(self, entry):
        oid = entry.get("oid")
        if oid is None:
            return None
        got = self._cache.get(oid)
        if got is None:
            got = self.img.object(oid)
            if got is not None:
                self._cache[oid] = got
        return got

    def read_file(self, entry, max_bytes=None, stream=""):
        if stream:
            raise UnsupportedStream("AD1", stream)
        o = self._object_for(entry)
        if o is None:
            return b""
        return self.img.read_object(o, max_bytes)

    def read_range(self, entry, off, length, stream=""):
        if stream:
            raise UnsupportedStream("AD1", stream)
        o = self._object_for(entry)
        if o is None:
            return b""
        return self.img.read_range(o, off, length)

    def stat(self, entry, stream=""):
        o = self._object_for(entry)
        if o is None:
            return {}
        md = self.img.metadata(o)
        chunks = []
        try:
            chunks = self.img.chunk_table(o)
        except ad1_mod.Ad1Error:
            chunks = []
        info = {
            "filesystem": "AD1",
            "object_offset": self.img.base + o["at"],
            "size": o["size"],
            "chunks": len(chunks),
            "chunk_size": self.chunk_size,
            "chunk_map": [self.img.base + c[0]
                          for c in chunks[:CHUNK_MAP_CAP]],
            "chunk_map_truncated": len(chunks) > CHUNK_MAP_CAP,
            "recorded": md,
            "note": ("A logical image holds selected files, not media. There "
                     "is no location on disk for this item, no slack and no "
                     "unallocated space around it — the offsets in this "
                     "container are where the compressed copy sits, not where "
                     "the file lived."),
        }
        if md.get("md5") or md.get("sha1"):
            info["stored_hashes"] = {"md5": md.get("md5"),
                                     "sha1": md.get("sha1")}
        return info

    def verify(self, entry):
        o = self._object_for(entry)
        return self.img.verify(o) if o else None

    def info(self):
        a = self.img.attributes
        return {
            "type": "AD1",
            "label": a.get("volume_name") or self.img.label or "",
            "logical": True,
            "cluster_size": None,
            "bytes_per_sector": None,
            "source_volume": a.get("volume_name"),
            "volume_serial": a.get("volume_serial"),
            "source_os": a.get("source_os"),
            "image_label": self.img.label,
            "attributes": a,
            "findings": [
                "A logical image: selected files and their metadata, not a "
                "copy of the media. Nothing here is carved, nothing is "
                "recovered from unallocated space, and the absence of a file "
                "is not evidence it was not on the source.",
            ],
        }

    def allocated_extents(self):
        return []
