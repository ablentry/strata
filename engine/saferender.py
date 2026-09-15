import html
import html.parser
import re

CSP = ("default-src 'none'; img-src data: blob:; style-src 'unsafe-inline'; "
       "font-src data:; base-uri 'none'; form-action 'none'; sandbox")

CSP_PDF = ("default-src 'none'; object-src 'self'; script-src 'none'; "
           "base-uri 'none'; form-action 'none'")

HTML_TAGS = {
    "html", "head", "body", "title", "p", "br", "hr", "div", "span", "section",
    "article", "header", "footer", "main", "aside", "nav", "figure",
    "figcaption", "h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol", "li", "dl",
    "dt", "dd", "table", "thead", "tbody", "tfoot", "tr", "td", "th",
    "caption", "col", "colgroup", "b", "i", "u", "s", "em", "strong", "small",
    "sub", "sup", "code", "pre", "kbd", "samp", "var", "blockquote", "q",
    "cite", "abbr", "address", "del", "ins", "mark", "time", "wbr", "center",
    "font", "big", "tt", "strike", "img", "style", "a",
}

HTML_DROP_CONTENT = {"script", "noscript", "template", "iframe", "object",
                     "embed", "applet", "frameset", "frame"}

# Dropped elements that hold no content and get no end tag. Suppressing on one
# of these would never be switched back off, silently swallowing the rest of
# the document — a frameset's <frame> is the common case.
VOID_DROP = {"frame", "embed"}

HTML_ATTRS = {
    "class", "id", "title", "alt", "width", "height", "align", "valign",
    "colspan", "rowspan", "border", "cellpadding", "cellspacing", "color",
    "face", "size", "start", "type", "value", "datetime", "dir", "lang",
    "style", "src", "charset",
}

_CSS_BAD = re.compile(
    r"(?:expression\s*\(|javascript\s*:|vbscript\s*:|@import|behaviou?r\s*:|"
    r"-moz-binding|url\s*\(\s*(?!['\"]?data:image/))", re.I)

def _clean_css(text):
    if not text:
        return "", 0
    hits = len(_CSS_BAD.findall(text))
    if not hits:
        return text, 0
    out = []
    for decl in text.split(";"):
        if not _CSS_BAD.search(decl):
            out.append(decl)
    return ";".join(out), hits

def _safe_src(value):
    v = (value or "").strip().replace("\x00", "")
    if re.match(r"^data:image/(png|jpe?g|gif|bmp|webp|x-icon);base64,", v, re.I):
        return v
    return None

class _HtmlSanitiser(html.parser.HTMLParser):

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out = []
        self.findings = {}
        self._suppress = []
        self._open = []

    def note(self, what):
        self.findings[what] = self.findings.get(what, 0) + 1

    def _enter_suppress(self, tag, self_closing):
        # Only elements that can actually carry content, and that will get an
        # end tag to switch suppression back off, may turn it on.
        if not self_closing and tag not in VOID_DROP:
            self._suppress.append(tag)

    def _leave_suppress(self, tag):
        if tag in self._suppress:
            while self._suppress and self._suppress.pop() != tag:
                pass

    def handle_starttag(self, tag, attrs, self_closing=False):
        if tag in HTML_DROP_CONTENT:
            self._enter_suppress(tag, self_closing)
            self.note("<%s> removed" % tag)
            return
        if self._suppress:
            return
        if tag not in HTML_TAGS:
            self.note("<%s> not on the allowlist" % tag)
            return
        kept = []
        for name, value in attrs:
            name = (name or "").lower()
            if name.startswith("on"):
                self.note("event handler %s= removed" % name)
                continue
            if name not in HTML_ATTRS:
                if name in ("href", "xlink:href", "srcset", "formaction",
                            "background", "ping", "srcdoc", "data",
                            "dynsrc", "lowsrc", "action"):
                    self.note("%s= removed" % name)
                continue
            if name == "src":
                safe = _safe_src(value)
                if safe is None:
                    self.note("src= removed (only inline image data is allowed)")
                    continue
                value = safe
            elif name == "style":
                value, bad = _clean_css(value or "")
                if bad:
                    self.note("style= sanitised")
                if not value.strip():
                    continue
            if value is None:
                kept.append(name)
            else:
                kept.append('%s="%s"' % (name, html.escape(str(value), quote=True)))
        bits = " ".join(kept)
        self.out.append("<%s%s%s>" % (tag, " " + bits if bits else "",
                                      " /" if self_closing else ""))
        if not self_closing:
            self._open.append(tag)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs, self_closing=True)

    def handle_endtag(self, tag):
        if tag in HTML_DROP_CONTENT:
            self._leave_suppress(tag)
            return
        if self._suppress or tag not in HTML_TAGS:
            return
        if tag in self._open:
            while self._open and self._open.pop() != tag:
                pass
            self.out.append("</%s>" % tag)

    def handle_data(self, data):
        if self._suppress:
            return
        if self._open and self._open[-1] == "style":
            cleaned, bad = _clean_css(data)
            if bad:
                self.note("<style> rules sanitised")
            self.out.append(cleaned)
            return
        self.out.append(html.escape(data, quote=False))

    def handle_comment(self, data):
        if "[if" in data.lower() or "<" in data:
            self.note("conditional or markup-bearing comment removed")

    def handle_decl(self, decl):
        pass

    def unknown_decl(self, data):
        self.note("CDATA section removed")

    def handle_pi(self, data):
        self.note("processing instruction removed")

    def result(self):
        while self._open:
            self.out.append("</%s>" % self._open.pop())
        return "".join(self.out)

def sanitise_html(data, is_svg=False):
    text = _decode(data)
    p = _SvgSanitiser() if is_svg else _HtmlSanitiser()
    try:
        p.feed(text)
        p.close()
    except Exception as exc:
        return {"ok": False, "html": "", "findings": ["Could not parse: %s" % exc]}
    body = p.result()
    findings = ["%s (x%d)" % (k, v) if v > 1 else k
                for k, v in sorted(p.findings.items())]
    return {"ok": True, "html": body, "findings": findings}

SVG_TAGS = {
    "svg", "g", "defs", "symbol", "use", "title", "desc", "metadata", "path",
    "rect", "circle", "ellipse", "line", "polyline", "polygon", "text",
    "tspan", "textpath", "marker", "lineargradient", "radialgradient", "stop",
    "clippath", "mask", "pattern", "image", "style", "switch", "filter",
    "fegaussianblur", "feoffset", "feblend", "feflood", "fecomposite",
    "femerge", "femergenode", "fecolormatrix", "view",
}

SVG_DROP_CONTENT = {"script", "foreignobject", "animate", "animatetransform",
                    "animatemotion", "set", "handler", "audio", "video",
                    "iframe", "a"}

_SVG_ATTR_OK = re.compile(
    r"^(?:d|x|y|x1|y1|x2|y2|cx|cy|r|rx|ry|width|height|fill|fill-rule|"
    r"fill-opacity|stroke|stroke-width|stroke-linecap|stroke-linejoin|"
    r"stroke-dasharray|stroke-dashoffset|stroke-opacity|opacity|transform|"
    r"viewbox|preserveaspectratio|points|offset|stop-color|stop-opacity|"
    r"gradientunits|gradienttransform|patternunits|clip-path|clip-rule|mask|"
    r"font-family|font-size|font-weight|font-style|text-anchor|dominant-baseline|"
    r"letter-spacing|word-spacing|id|class|style|version|xmlns|xmlns:xlink|"
    r"marker-end|marker-start|marker-mid|filter|stddeviation|result|in|in2|"
    r"mode|type|values|dx|dy|spreadmethod|fr|fx|fy|display|visibility)$", re.I)

class _SvgSanitiser(_HtmlSanitiser):

    def handle_starttag(self, tag, attrs, self_closing=False):
        low = tag.lower()
        if low in SVG_DROP_CONTENT:
            if low in ("script", "foreignobject", "handler"):
                self._enter_suppress(low, self_closing)
            self.note("<%s> removed" % low)
            return
        if self._suppress:
            return
        if low not in SVG_TAGS:
            self.note("<%s> not on the allowlist" % low)
            return
        kept = []
        for name, value in attrs:
            name = (name or "").lower()
            if name.startswith("on"):
                self.note("event handler %s= removed" % name)
                continue
            if name in ("href", "xlink:href"):
                v = (value or "").strip()
                if low == "use" and v.startswith("#"):
                    kept.append('href="%s"' % html.escape(v, quote=True))
                elif low == "image" and _safe_src(v):
                    kept.append('href="%s"' % html.escape(v, quote=True))
                else:
                    self.note("%s= removed (external reference)" % name)
                continue
            if not _SVG_ATTR_OK.match(name):
                self.note("%s= not on the allowlist" % name)
                continue
            if name == "style":
                value, bad = _clean_css(value or "")
                if bad:
                    self.note("style= sanitised")
                if not value.strip():
                    continue
            kept.append('%s="%s"' % (name, html.escape(str(value or ""),
                                                       quote=True)))
        bits = " ".join(kept)
        self.out.append("<%s%s%s>" % (low, " " + bits if bits else "",
                                      " /" if self_closing else ""))
        if not self_closing:
            self._open.append(low)

    def handle_endtag(self, tag):
        low = tag.lower()
        if low in SVG_DROP_CONTENT:
            if low in ("script", "foreignobject", "handler"):
                self._leave_suppress(low)
            return
        if self._suppress or low not in SVG_TAGS:
            return
        if low in self._open:
            while self._open and self._open.pop() != low:
                pass
            self.out.append("</%s>" % low)

def _decode(data):
    if isinstance(data, str):
        return data
    for enc in ("utf-8-sig", "utf-8", "utf-16", "cp1252", "latin-1"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("latin-1", "replace")
