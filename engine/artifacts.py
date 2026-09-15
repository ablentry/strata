INSTANT, QUICK, MINUTES, LONG = "instant", "quick", "minutes", "long"

COST_ORDER = {INSTANT: 0, QUICK: 1, MINUTES: 2, LONG: 3}

COST_NOTE = {
    INSTANT: "Already known, or one directory read.",
    QUICK: "Seconds. Reads a handful of files.",
    MINUTES: "A minute or two. Walks the filesystem.",
    LONG: "A full pass over the media. Start it and work elsewhere.",
}

CATALOGUE = [
    {
        "id": "volumes", "label": "Volume layout", "cost": INSTANT,
        "scope": "image", "method": None, "route": None, "per_volume": False,
        "answers": "What partitions exist, what filesystem each really holds, "
                   "and what space no partition claims.",
        "needs": [],
    },
    {
        "id": "encryption", "label": "Encrypted volumes", "cost": INSTANT,
        "scope": "image", "method": "GET", "route": "encryption", "per_volume": True,
        "answers": "Which volumes are locked, and which key protectors could "
                   "be attempted at all.",
        "needs": [],
    },
    {
        "id": "usn", "label": "Change journal", "cost": QUICK,
        "scope": "volume", "method": "POST", "route": "usn", "per_volume": True,
        "answers": "What happened to files — creations, renames, moves and "
                   "deletions — including for files whose MFT records have "
                   "since been reused. Often the only surviving record of a "
                   "deleted file's name.",
        "needs": ["NTFS"],
    },
    {
        "id": "registry", "label": "Well-known registry keys", "cost": MINUTES,
        "scope": "image", "method": "POST", "route": "registry/report", "per_volume": False,
        "answers": "Machine identity, USB devices attached, networks joined, "
                   "auto-start programs, installed software, local accounts "
                   "and user activity.",
        "needs": ["filesystem walk"],
    },
    {
        "id": "prefetch", "label": "Prefetch", "cost": QUICK,
        "scope": "volume", "method": "POST", "route": "prefetch", "per_volume": True,
        "answers": "What was executed, when, how often, and which files each "
                   "program opened at startup.",
        "needs": ["Windows volume"],
    },
    {
        "id": "lnk", "label": "Shortcuts and Jump Lists", "cost": QUICK,
        "scope": "volume", "method": "GET", "route": "lnk", "per_volume": True,
        "answers": "What was opened and from where, including from removable "
                   "media that is no longer present.",
        "needs": ["Windows volume"],
    },
    {
        "id": "recyclebin", "label": "Recycle Bin", "cost": QUICK,
        "scope": "volume", "method": "GET", "route": "recyclebin", "per_volume": True,
        "answers": "What was deleted through the shell, by whom, when, and "
                   "from what original path.",
        "needs": ["Windows volume"],
    },
    {
        "id": "shellbags", "label": "Shellbags", "cost": MINUTES,
        "scope": "volume", "method": "POST", "route": "shellbags", "per_volume": True,
        "answers": "Folders opened in Explorer — including folders that no "
                   "longer exist and drives no longer attached.",
        "needs": ["filesystem walk"],
    },
    {
        "id": "appcompat", "label": "Amcache and ShimCache", "cost": MINUTES,
        "scope": "volume", "method": "POST", "route": "appcompat", "per_volume": True,
        "answers": "Executables the system recorded, with SHA-1 hashes that "
                   "survive the binary being deleted.",
        "needs": ["filesystem walk"],
    },
    {
        "id": "browser", "label": "Browser history", "cost": MINUTES,
        "scope": "volume", "method": "POST", "route": "browser", "per_volume": True,
        "answers": "Sites visited, downloads, searches and form entries, "
                   "including rows deleted from the databases.",
        "needs": ["filesystem walk"],
    },
    {
        "id": "evtx", "label": "Windows event logs", "cost": MINUTES,
        "scope": "volume", "method": "POST", "route": "evtx", "per_volume": True,
        "answers": "Logons, process creation, service installation and system "
                   "state changes.",
        "needs": ["filesystem walk"],
    },
    {
        "id": "filetypes", "label": "File-type verification", "cost": MINUTES,
        "scope": "volume", "method": "POST", "route": "filetypes/scan", "per_volume": False,
        "answers": "Files whose extension disagrees with their content — the "
                   "cheap way to find something deliberately misnamed.",
        "needs": ["filesystem walk"],
    },
    {
        "id": "timeline", "label": "Timeline", "cost": MINUTES,
        "scope": "volume", "method": "POST", "route": "timeline", "per_volume": True,
        "answers": "Every parser's timestamps in one ordered sequence, with "
                   "timestomping checks against the $FILE_NAME set.",
        "needs": ["filesystem walk"],
    },
    {
        "id": "hash", "label": "Hash every file", "cost": LONG,
        "scope": "volume", "method": "POST", "route": "hash", "per_volume": True,
        "answers": "MD5, SHA-1 and SHA-256 for matching against known-good "
                   "and known-bad sets. Bounded by read speed.",
        "needs": ["filesystem walk"],
    },
    {
        "id": "carve", "label": "Signature carving", "cost": LONG,
        "scope": "image", "method": "POST", "route": "carve", "per_volume": True,
        "answers": "Files recoverable from unallocated space by signature, "
                   "with no filesystem involvement.",
        "needs": [],
    },
    {
        "id": "index", "label": "Content index", "cost": LONG,
        "scope": "image", "method": "POST", "route": "search/index", "per_volume": False,
        "answers": "Full-text search across files and, optionally, the whole "
                   "medium including unpartitioned space. The most expensive "
                   "thing here and rarely the first thing needed.",
        "needs": [],
    },
]

TRIAGE = [a["id"] for a in CATALOGUE if a["cost"] in (INSTANT, QUICK)]

def catalogue(available=None):
    out = []
    for a in sorted(CATALOGUE, key=lambda x: (COST_ORDER[x["cost"]],
                                              x["label"])):
        row = dict(a)
        row["cost_note"] = COST_NOTE[a["cost"]]
        row["in_triage"] = a["id"] in TRIAGE
        if available is not None:
            row["available"] = a["id"] in available
        out.append(row)
    return out
