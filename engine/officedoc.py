import re
import struct
import xml.etree.ElementTree as ET

from . import archive
from . import ole2

MAX_TEXT = 8 << 20
MAX_PART = 64 << 20

_DOCTYPE = re.compile(rb"<!DOCTYPE", re.I)

WORD_PARTS = (
    ("word/document.xml", "document"),
    ("word/footnotes.xml", "footnotes"),
    ("word/endnotes.xml", "endnotes"),
    ("word/comments.xml", "comments"),
)
SLIDE_RE = re.compile(r"^ppt/slides/slide(\d+)\.xml$")
NOTES_RE = re.compile(r"^ppt/notesSlides/notesSlide(\d+)\.xml$")
SHEET_RE = re.compile(r"^xl/worksheets/sheet(\d+)\.xml$")
HEADER_RE = re.compile(r"^word/(header|footer)\d*\.xml$")

CORE_FIELDS = {
    "title": "Title", "subject": "Subject", "creator": "Author",
    "keywords": "Keywords", "description": "Description",
    "lastModifiedBy": "Last saved by", "revision": "Revision",
    "created": "Created", "modified": "Modified",
    "lastPrinted": "Last printed", "category": "Category",
    "contentStatus": "Status",
}
APP_FIELDS = {
    "Application": "Application", "AppVersion": "Application version",
    "Company": "Company", "Manager": "Manager", "Template": "Template",
    "TotalTime": "Editing time (minutes)", "Pages": "Pages", "Words": "Words",
    "Characters": "Characters", "Paragraphs": "Paragraphs",
    "Slides": "Slides", "Notes": "Notes", "HiddenSlides": "Hidden slides",
}
ODF_META = {
    "initial-creator": "Author", "creator": "Last saved by",
    "creation-date": "Created", "date": "Modified",
    "editing-cycles": "Revision", "editing-duration": "Editing time",
    "generator": "Application", "title": "Title", "subject": "Subject",
    "description": "Description", "keyword": "Keywords",
    "printed-by": "Last printed by", "print-date": "Last printed",
}

def _local(tag):
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag

def _xml(blob, findings, part):
    if not blob:
        return None
    if _DOCTYPE.search(blob[:4096]):
        findings.append(
            "%s carries a DOCTYPE declaration. No legitimate Office part has "
            "one, and it is where entity definitions live — the mechanism "
            "behind entity-expansion attacks. The part was not parsed." % part)
        return None
    try:
        return ET.fromstring(blob)
    except ET.ParseError as exc:
        findings.append("%s is not well-formed XML (%s); it was skipped."
                        % (part, exc))
        return None

def _text_of(node, sep=""):
    out = []
    for el in node.iter():
        if el.text:
            out.append(el.text)
    return sep.join(out)

def _word_text(root):
    lines, cur = [], []
    for el in root.iter():
        tag = _local(el.tag)
        if tag == "t" and el.text:
            cur.append(el.text)
        elif tag == "tab":
            cur.append("\t")
        elif tag in ("br", "cr"):
            cur.append("\n")
        elif tag == "p":
            if cur:
                lines.append("".join(cur))
                cur = []
    if cur:
        lines.append("".join(cur))
    return "\n".join(lines)

def _slide_text(root):
    lines, cur = [], []
    for el in root.iter():
        tag = _local(el.tag)
        if tag == "t" and el.text:
            cur.append(el.text)
        elif tag == "p":
            if cur:
                lines.append("".join(cur))
                cur = []
    if cur:
        lines.append("".join(cur))
    return "\n".join(lines)

def _shared_strings(root):
    out = []
    for si in root:
        if _local(si.tag) != "si":
            continue
        parts = [el.text for el in si.iter()
                 if _local(el.tag) == "t" and el.text]
        out.append("".join(parts))
    return out

def _col_key(ref):
    m = re.match(r"([A-Z]+)(\d+)$", ref or "")
    if not m:
        return (0, 0)
    col = 0
    for ch in m.group(1):
        col = col * 26 + (ord(ch) - 64)
    return (int(m.group(2)), col)

def _sheet_text(root, shared):
    rows = []
    for row in root.iter():
        if _local(row.tag) != "row":
            continue
        cells = []
        for c in row:
            if _local(c.tag) != "c":
                continue
            typ = c.get("t")
            val = ""
            if typ == "inlineStr":
                val = "".join(el.text for el in c.iter()
                              if _local(el.tag) == "t" and el.text)
            else:
                v = next((el for el in c if _local(el.tag) == "v"), None)
                if v is not None and v.text is not None:
                    if typ == "s":
                        try:
                            val = shared[int(v.text)]
                        except (ValueError, IndexError):
                            val = ""
                    else:
                        val = v.text
            cells.append((_col_key(c.get("r")), val))
        cells.sort(key=lambda x: x[0])
        line = "\t".join(v for _k, v in cells)
        if line.strip():
            rows.append(line)
    return "\n".join(rows)

def _sheet_names(root):
    out = {}
    for el in root.iter():
        if _local(el.tag) == "sheet":
            out[el.get("sheetId") or el.get("name")] = el.get("name")
    return out

def _core(root, findings):
    out = {}
    for el in root:
        name = _local(el.tag)
        label = CORE_FIELDS.get(name)
        if label and (el.text or "").strip():
            out[label] = el.text.strip()
    return out

def _app(root):
    out = {}
    for el in root:
        label = APP_FIELDS.get(_local(el.tag))
        if label and (el.text or "").strip():
            out[label] = el.text.strip()
    return out

def _odf_meta(root):
    out = {}
    for el in root.iter():
        label = ODF_META.get(_local(el.tag))
        if not label:
            continue
        txt = (el.text or "").strip()
        if not txt and _local(el.tag) == "editing-duration":
            txt = el.get("duration") or ""
        if txt:
            out.setdefault(label, txt)
    return out

def _odf_text(root):
    lines = []
    for el in root.iter():
        tag = _local(el.tag)
        if tag in ("p", "h"):
            txt = _text_of(el)
            if txt.strip():
                lines.append(txt)
        elif tag == "table-row":
            cells = []
            for c in el:
                if _local(c.tag) == "table-cell":
                    cells.append(_text_of(c))
            line = "\t".join(cells)
            if line.strip():
                lines.append(line)
    return "\n".join(lines)

def looks_like_office(head):
    return head[:2] in (b"PK", b"\x50\x4b")

def parse(data, name=""):
    if not data:
        return None
    if ole2.looks_like_ole2(data[:8]):
        return parse_ole2_document(data, name)
    if not looks_like_office(data[:4]):
        return None
    z = archive.Zip(data, name)
    if not z.valid or not z.entries:
        return None
    by_name = {e.name: e for e in z.entries}
    names = set(by_name)

    family = None
    if "word/document.xml" in names:
        family = "word"
    elif "xl/workbook.xml" in names:
        family = "excel"
    elif "ppt/presentation.xml" in names:
        family = "powerpoint"
    elif "content.xml" in names and "meta.xml" in names:
        family = "odf"
    elif "content.xml" in names:
        family = "odf"
    if not family:
        return None

    findings = list(z.findings)

    def part(pname):
        e = by_name.get(pname)
        if e is None:
            return None
        try:
            blob, notes = z.read(e, MAX_PART)
        except Exception as exc:
            findings.append("%s could not be decompressed (%s)."
                            % (pname, type(exc).__name__))
            return None
        for n in notes:
            findings.append("%s: %s" % (pname, n))
        return blob

    meta, sections = {}, []

    if family == "odf":
        m = _xml(part("meta.xml") or b"", findings, "meta.xml")
        if m is not None:
            meta = _odf_meta(m)
        c = _xml(part("content.xml") or b"", findings, "content.xml")
        if c is not None:
            sections.append(("content", _odf_text(c)))
        kind = {"application/vnd.oasis.opendocument.text": "OpenDocument text",
                "application/vnd.oasis.opendocument.spreadsheet":
                    "OpenDocument spreadsheet",
                "application/vnd.oasis.opendocument.presentation":
                    "OpenDocument presentation"}.get(
            (part("mimetype") or b"").decode("latin-1").strip(),
            "OpenDocument")
    else:
        core = _xml(part("docProps/core.xml") or b"", findings,
                    "docProps/core.xml")
        if core is not None:
            meta.update(_core(core, findings))
        app = _xml(part("docProps/app.xml") or b"", findings,
                   "docProps/app.xml")
        if app is not None:
            meta.update(_app(app))

        if family == "word":
            kind = "Word document"
            for pname, label in WORD_PARTS:
                if pname not in names:
                    continue
                root = _xml(part(pname) or b"", findings, pname)
                if root is not None:
                    sections.append((label, _word_text(root)))
            for pname in sorted(n for n in names if HEADER_RE.match(n)):
                root = _xml(part(pname) or b"", findings, pname)
                if root is not None:
                    t = _word_text(root)
                    if t.strip():
                        sections.append((pname.split("/")[-1], t))
        elif family == "excel":
            kind = "Excel workbook"
            shared = []
            if "xl/sharedStrings.xml" in names:
                root = _xml(part("xl/sharedStrings.xml") or b"", findings,
                            "xl/sharedStrings.xml")
                if root is not None:
                    shared = _shared_strings(root)
            wb = _xml(part("xl/workbook.xml") or b"", findings,
                      "xl/workbook.xml")
            titles = _sheet_names(wb) if wb is not None else {}
            ordered = sorted((n for n in names if SHEET_RE.match(n)),
                             key=lambda n: int(SHEET_RE.match(n).group(1)))
            for i, pname in enumerate(ordered, 1):
                root = _xml(part(pname) or b"", findings, pname)
                if root is None:
                    continue
                label = titles.get(str(i)) or ("sheet %d" % i)
                sections.append((label, _sheet_text(root, shared)))
        else:
            kind = "PowerPoint presentation"
            for rx, tmpl in ((SLIDE_RE, "slide %s"),
                             (NOTES_RE, "slide %s notes")):
                got = sorted((n for n in names if rx.match(n)),
                             key=lambda n: int(rx.match(n).group(1)))
                for pname in got:
                    root = _xml(part(pname) or b"", findings, pname)
                    if root is not None:
                        t = _slide_text(root)
                        if t.strip():
                            sections.append(
                                (tmpl % rx.match(pname).group(1), t))

    body, total, truncated = [], 0, False
    for label, txt in sections:
        if not txt.strip():
            continue
        if total + len(txt) > MAX_TEXT:
            txt = txt[:max(0, MAX_TEXT - total)]
            truncated = True
        body.append((label, txt))
        total += len(txt)
        if truncated:
            break
    if truncated:
        findings.append(
            "Text was truncated at %d characters. The document is longer; the "
            "whole of it is still in the evidence." % MAX_TEXT)

    return {
        "kind": kind,
        "family": family,
        "metadata": meta,
        "sections": [{"name": n, "text": t} for n, t in body],
        "text": "\n\n".join(t for _n, t in body),
        "characters": total,
        "parts": len(z.entries),
        "findings": findings,
        "note": ("Document properties are written by the application from "
                 "whatever it was told and can be edited afterwards. They are "
                 "a record of what the file claims, not of what happened."),
    }

PIDSI = {
    2: "Title", 3: "Subject", 4: "Author", 5: "Keywords", 6: "Comments",
    7: "Template", 8: "Last saved by", 9: "Revision",
    10: "Editing time", 11: "Last printed", 12: "Created",
    13: "Modified", 14: "Pages", 15: "Words", 16: "Characters",
    18: "Application", 19: "Security",
}
PIDDSI = {14: "Manager", 15: "Company", 3: "Slides", 5: "Paragraphs"}

def _prop_value(blob, at, findings):
    if at + 4 > len(blob):
        return None, False
    typ, = struct.unpack_from("<I", blob, at)
    v = at + 4
    if typ in (0x1E, 0x1F):
        if v + 4 > len(blob):
            return None, False
        n, = struct.unpack_from("<I", blob, v)
        if n > (1 << 20) or v + 4 + n > len(blob):
            return None, False
        raw = blob[v + 4:v + 4 + n]
        if typ == 0x1F:
            txt = raw.decode("utf-16-le", "replace")
        else:
            txt = raw.decode("latin-1", "replace")
        return txt.split("\x00", 1)[0].strip() or None, True
    if typ == 0x40:
        if v + 8 > len(blob):
            return None, False
        ft, = struct.unpack_from("<Q", blob, v)
        return ole2.filetime(ft), True
    if typ == 0x03:
        return (struct.unpack_from("<i", blob, v)[0], True) if v + 4 <= len(blob) else (None, False)
    if typ == 0x02:
        return (struct.unpack_from("<h", blob, v)[0], True) if v + 2 <= len(blob) else (None, False)
    if typ == 0x0B:
        return (bool(struct.unpack_from("<h", blob, v)[0]), True) if v + 2 <= len(blob) else (None, False)
    if typ == 0x47:
        return None, True
    return None, True

def _property_set(blob, names, findings, label):
    out = {}
    if len(blob) < 48:
        return out
    if blob[:2] != b"\xfe\xff":
        findings.append("%s does not begin with the property-set byte-order "
                        "mark; it was not read." % label)
        return out
    n_sections, = struct.unpack_from("<I", blob, 24)
    if not 0 < n_sections < 16:
        findings.append("%s declares %d sections, which is implausible."
                        % (label, n_sections))
        return out
    for i in range(n_sections):
        base = 28 + i * 20
        if base + 20 > len(blob):
            break
        off, = struct.unpack_from("<I", blob, base + 16)
        if off + 8 > len(blob):
            continue
        _size, count = struct.unpack_from("<II", blob, off)
        if count > 4096:
            findings.append("%s declares %d properties in one section; not "
                            "read." % (label, count))
            continue
        for p in range(count):
            e = off + 8 + p * 8
            if e + 8 > len(blob):
                break
            pid, poff = struct.unpack_from("<II", blob, e)
            name = names.get(pid)
            if not name:
                continue
            val, ok = _prop_value(blob, off + poff, findings)
            if not ok:
                findings.append("%s: property %d could not be decoded and was "
                                "skipped." % (label, pid))
                continue
            if val not in (None, ""):
                if name == "Editing time" and isinstance(val, str):
                    continue
                out[name] = val
    return out

def parse_ole2_document(data, name=""):
    if not ole2.looks_like_ole2(data[:8]):
        return None
    o = ole2.Ole2(data, name)
    if not o.valid:
        return None
    findings = list(o.findings)
    names = {n.lstrip("\x05").lower(): e for n, e in o.streams()}

    meta = {}
    for key, table, label in (
            ("summaryinformation", PIDSI, "SummaryInformation"),
            ("documentsummaryinformation", PIDDSI, "DocumentSummaryInformation")):
        ent = names.get(key)
        if ent is None:
            continue
        meta.update(_property_set(o.read(ent, 1 << 20), table, findings, label))

    kinds = [(("worddocument",), "Word document (legacy .doc)"),
             (("workbook", "book"), "Excel workbook (legacy .xls)"),
             (("powerpoint document",), "PowerPoint presentation (legacy .ppt)"),
             (("__properties_version1.0",), "Outlook message (.msg)")]
    kind = "OLE2 compound document"
    for keys, label in kinds:
        if any(k in names for k in keys):
            kind = label
            break

    return {
        "kind": kind,
        "family": "ole2",
        "metadata": meta,
        "sections": [],
        "text": "",
        "characters": 0,
        "parts": len(o.entries),
        "streams": [n for n, _e in o.streams()][:64],
        "findings": findings,
        "note": ("The body of a legacy Office document is a binary format of "
                 "its own — Word's piece table, Excel's BIFF record stream — "
                 "and is not decoded here, so no text is offered rather than "
                 "text that might be wrong. The properties below are from the "
                 "document's own property set: they are written by the "
                 "application from whatever it was told and can be edited."),
    }
