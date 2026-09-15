import json
import re

BUILTIN_VERSION = "14.1"

TACTICS = [
    ("reconnaissance", "Reconnaissance"),
    ("resource-development", "Resource Development"),
    ("initial-access", "Initial Access"),
    ("execution", "Execution"),
    ("persistence", "Persistence"),
    ("privilege-escalation", "Privilege Escalation"),
    ("defense-evasion", "Defence Evasion"),
    ("credential-access", "Credential Access"),
    ("discovery", "Discovery"),
    ("lateral-movement", "Lateral Movement"),
    ("collection", "Collection"),
    ("command-and-control", "Command and Control"),
    ("exfiltration", "Exfiltration"),
    ("impact", "Impact"),
]

BUILTIN = [
    ("T1078",     "Valid Accounts",                        "initial-access"),
    ("T1091",     "Replication Through Removable Media",   "initial-access"),
    ("T1566.001", "Spearphishing Attachment",              "initial-access"),

    ("T1059.001", "PowerShell",                            "execution"),
    ("T1059.003", "Windows Command Shell",                 "execution"),
    ("T1204.002", "User Execution: Malicious File",        "execution"),
    ("T1569.002", "Service Execution",                     "execution"),

    ("T1053.005", "Scheduled Task",                        "persistence"),
    ("T1543.003", "Windows Service",                       "persistence"),
    ("T1546.003", "WMI Event Subscription",                "persistence"),
    ("T1547.001", "Registry Run Keys / Startup Folder",    "persistence"),
    ("T1547.009", "Shortcut Modification",                 "persistence"),

    ("T1548.002", "Bypass User Account Control",           "privilege-escalation"),

    ("T1027",     "Obfuscated Files or Information",       "defense-evasion"),
    ("T1070.001", "Clear Windows Event Logs",              "defense-evasion"),
    ("T1070.004", "File Deletion",                         "defense-evasion"),
    ("T1070.006", "Timestomp",                             "defense-evasion"),
    ("T1112",     "Modify Registry",                       "defense-evasion"),
    ("T1562.001", "Disable or Modify Tools",               "defense-evasion"),

    ("T1003.001", "OS Credential Dumping: LSASS Memory",   "credential-access"),
    ("T1003.002", "OS Credential Dumping: SAM",            "credential-access"),
    ("T1552.001", "Credentials In Files",                  "credential-access"),

    ("T1016",     "System Network Configuration Discovery", "discovery"),
    ("T1057",     "Process Discovery",                     "discovery"),
    ("T1082",     "System Information Discovery",          "discovery"),
    ("T1083",     "File and Directory Discovery",          "discovery"),

    ("T1021.001", "Remote Desktop Protocol",               "lateral-movement"),
    ("T1021.002", "SMB / Windows Admin Shares",            "lateral-movement"),

    ("T1005",     "Data from Local System",                "collection"),
    ("T1113",     "Screen Capture",                        "collection"),
    ("T1114.001", "Local Email Collection",                "collection"),
    ("T1560.001", "Archive via Utility",                   "collection"),

    ("T1071.001", "Application Layer Protocol: Web",       "command-and-control"),
    ("T1105",     "Ingress Tool Transfer",                 "command-and-control"),

    ("T1048",     "Exfiltration Over Alternative Protocol", "exfiltration"),
    ("T1052.001", "Exfiltration over USB",                 "exfiltration"),
    ("T1567.002", "Exfiltration to Cloud Storage",         "exfiltration"),

    ("T1485",     "Data Destruction",                      "impact"),
    ("T1486",     "Data Encrypted for Impact",             "impact"),
    ("T1490",     "Inhibit System Recovery",               "impact"),
]

TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")

def tactic_name(key):
    for k, name in TACTICS:
        if k == key:
            return name
    return key

def _rows(catalogue):
    return [{"id": tid, "name": name, "tactic": tac,
             "tactic_name": tactic_name(tac),
             "parent": tid.split(".")[0] if "." in tid else None}
            for tid, name, tac in catalogue]

def builtin():
    return {"source": "built-in", "version": BUILTIN_VERSION,
            "complete": False,
            "note": ("A curated subset of ATT&CK covering the techniques a "
                     "disk image can evidence. Import MITRE's published "
                     "catalogue for the full matrix."),
            "tactics": [{"id": k, "name": n} for k, n in TACTICS],
            "techniques": _rows(BUILTIN)}

def parse_stix(text):
    data = json.loads(text)
    objects = data.get("objects") if isinstance(data, dict) else data
    if not isinstance(objects, list):
        raise ValueError("Not a STIX bundle: no object list.")

    out, seen = [], set()
    for o in objects:
        if o.get("type") != "attack-pattern":
            continue
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        tid = None
        for ref in o.get("external_references") or []:
            if ref.get("source_name") in ("mitre-attack", "mitre-mobile-attack",
                                          "mitre-ics-attack"):
                tid = ref.get("external_id")
                break
        if not tid or not TECHNIQUE_ID.match(tid) or tid in seen:
            continue
        phases = [p.get("phase_name") for p in o.get("kill_chain_phases") or []
                  if p.get("kill_chain_name", "").startswith("mitre")]
        seen.add(tid)
        out.append((tid, o.get("name") or tid, phases[0] if phases else ""))
    if not out:
        raise ValueError("No ATT&CK techniques found in that bundle.")
    out.sort(key=lambda r: (r[2], r[0]))
    return out

def imported(catalogue, version=None):
    return {"source": "imported", "version": version or "unknown",
            "complete": True,
            "note": "MITRE's published catalogue, imported into this case.",
            "tactics": [{"id": k, "name": n} for k, n in TACTICS],
            "techniques": _rows(catalogue)}

SUGGESTS = {
    "prefetch":   ["T1204.002", "T1059.003"],
    "recyclebin": ["T1070.004"],
    "lnk":        ["T1547.009", "T1204.002"],
    "browser":    ["T1071.001", "T1105", "T1567.002"],
    "appcompat":  ["T1204.002"],
    "shellbags":  ["T1083"],
    "usn":        ["T1070.004", "T1070.006"],
    "mail":       ["T1114.001", "T1566.001"],
    "vss":        ["T1490"],
    "evtx":       ["T1070.001"],
    "registry":   ["T1547.001", "T1112"],
    "leveldb":    ["T1071.001"],
}

def suggestions_for(kind, catalogue=None):
    ids = SUGGESTS.get(kind) or []
    if not ids:
        return []
    known = {t["id"]: t for t in _rows(catalogue or BUILTIN)}
    out = []
    for tid in ids:
        t = known.get(tid)
        if t:
            out.append({**t, "proposed": True,
                        "why": "%s is where this technique is commonly "
                               "recorded — whether it was used here is for "
                               "the examiner to decide." % kind})
    return out
