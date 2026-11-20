"""A static HTML view of a recovered form: boxes where the build put them.

Seeing a form is faster than reading a control table, and the geometry is already
recovered — but the output has to be honest about what it is:

* **It is a visual aid, not an equivalent UI.** Control types map to plain HTML
  elements that *look* like the originals; behaviour, data binding and the VB6
  layout engine are not modelled.
* **The scale is assumed.** Geometry is in twips. The classic 96 dpi factor is 15
  twips per pixel; nothing here measured it for this build, so the factor is
  printed on every page and can be overridden.
* **Every page says where its geometry came from** — the ``.frm`` design text or a
  binary form blob — and whether a blob was available to cross-check it.

The pages carry no JavaScript and no external resource at all, enforced by a
``Content-Security-Policy`` meta tag as well as by there being nothing to load: a
recovered form must be safe to open from ``file://`` on a machine that has never
seen this tool.
"""

from __future__ import annotations

import html
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field

#: The classic 96 dpi factor. Assumed, printed, overridable — see the module docstring.
TWIPS_PER_PX = 15
#: What a control with no recovered rectangle gets: listed, not placed.
NO_GEOMETRY = "no rectangle recovered"

#: Control type -> the HTML element that reads like it. A type that is not here
#: becomes a labelled placeholder box: it is drawn, never silently dropped and
#: never mapped to something it is not.
ELEMENTS: dict[str, tuple[str, str]] = {
    "VB.CommandButton": ("button", "button"),
    "VB.TextBox": ("input", "text"),
    "VB.Label": ("span", "label"),
    "VB.CheckBox": ("input", "checkbox"),
    "VB.OptionButton": ("input", "radio"),
    "VB.ComboBox": ("select", "select"),
    "VB.ListBox": ("select", "list"),
    "VB.Frame": ("fieldset", "frame"),
    "VB.PictureBox": ("div", "picture"),
    "VB.Image": ("div", "image"),
    "VB.Shape": ("div", "shape"),
    "VB.Line": ("div", "line"),
}

CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; "
       "script-src 'none'; connect-src 'none'; font-src 'none'")


def esc(value) -> str:
    """Untrusted text as inert HTML.

    ``html.escape`` handles the tag-opening characters; this also removes control
    characters, which a browser would otherwise inherit into the DOM (and which
    could hide text from a reader).
    """
    out = []
    for ch in str(value):
        if unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp") and ch not in "\n":
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return html.escape("".join(out), quote=True)


def _css_class(type_name: str) -> str:
    return ELEMENTS.get(type_name, ("div", "placeholder"))[1]


@dataclass
class Box:
    """One control as the view needs it: a rectangle in twips, or none."""

    name: str
    type: str
    caption: str | None = None
    left: int | None = None
    top: int | None = None
    width: int | None = None
    height: int | None = None
    visible: bool | None = None
    index: int | None = None
    parent: str | None = None

    @property
    def placed(self) -> bool:
        return None not in (self.left, self.top, self.width, self.height)


@dataclass
class FormView:
    name: str
    source: str                      # ".frm design text" / "binary form blob"
    width: int | None = None
    height: int | None = None
    boxes: list[Box] = field(default_factory=list)
    #: Filled by the caller when a blob exists for this form: how many controls the
    #: two sources agree on, so the page can say whether it was cross-checked.
    crosscheck: tuple[int, int] | None = None
    notes: list[str] = field(default_factory=list)

    def counts(self) -> dict:
        placed = sum(1 for b in self.boxes if b.placed and b.type in ELEMENTS)
        placeholders = sum(1 for b in self.boxes if b.placed and b.type not in ELEMENTS)
        unplaced = sum(1 for b in self.boxes if not b.placed)
        return {"controls": len(self.boxes), "drawn": placed,
                "placeholders": placeholders, "unplaced": unplaced}


def _px(twips: int | None, scale: int) -> str:
    return f"{round((twips or 0) / scale, 1)}px"


def _element(box: Box, scale: int) -> str:
    tag, kind = ELEMENTS.get(box.type, ("div", "placeholder"))
    style = (f"left:{_px(box.left, scale)};top:{_px(box.top, scale)};"
             f"width:{_px(box.width, scale)};height:{_px(box.height, scale)}")
    if box.visible is False:
        style += ";opacity:.45"
    label = esc(box.caption) if box.caption else esc(box.name)
    title = (f"title=\"{esc(box.name)} ({esc(box.type)})\"")
    if tag == "input":
        return f'<input class="{kind}" style="{style}" type="{kind}" disabled {title} value="{label}">'
    if tag == "button":
        return f'<button class="{kind}" style="{style}" disabled {title}>{label}</button>'
    if tag == "select":
        return f'<select class="{kind}" style="{style}" disabled {title}><option>{label}</option></select>'
    if tag == "fieldset":
        return f'<fieldset class="{kind}" style="{style}" {title}><legend>{label}</legend></fieldset>'
    if tag == "span":
        return f'<span class="{kind}" style="{style}" {title}>{label}</span>'
    return f'<div class="{kind}" style="{style}" {title}><span class="t">{label}</span></div>'


def render_form(view: FormView, *, scale: int = TWIPS_PER_PX) -> str:
    counts = view.counts()
    body = []
    for box in view.boxes:
        if box.placed:
            body.append(_element(box, scale))
    unplaced = [b for b in view.boxes if not b.placed]
    crosscheck = ("no binary form blob for this form was supplied, so nothing cross-checked it"
                  if view.crosscheck is None else
                  f"{view.crosscheck[0]} of {view.crosscheck[1]} controls agree with the binary "
                  f"form blob (name, type and rectangle)")
    out = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        f'<meta http-equiv="Content-Security-Policy" content="{CSP}">',
        f"<title>{esc(view.name)} — recovered form</title>",
        "<style>",
        "body{font:14px system-ui,sans-serif;margin:24px;background:#f4f4f5;color:#111}",
        ".canvas{position:relative;background:#fff;border:1px solid #bbb;margin-top:12px}",
        ".box{position:absolute;box-sizing:border-box;overflow:hidden;white-space:nowrap;",
        "text-overflow:ellipsis;border:1px solid #777;background:#e8eef7;padding:2px 4px;",
        "font-size:12px;display:flex;align-items:center}",
        ".button{background:#dfe3e8;justify-content:center}",
        ".label,.span{border:none;background:transparent}",
        ".placeholder{background:repeating-linear-gradient(45deg,#fff,#fff 6px,#f0f0f0 6px,#f0f0f0 12px);",
        "border-style:dashed}",
        ".frame{background:transparent;border:1px solid #555}",
        "table{border-collapse:collapse;margin-top:12px;font-size:13px}",
        "td,th{border:1px solid #ccc;padding:2px 6px;text-align:left}",
        ".note{color:#444;max-width:70ch}",
        "</style></head><body>",
        f"<h1>{esc(view.name)}</h1>",
        ('<p class="note">A visual aid, not an equivalent UI: control types are drawn as plain HTML '
         'elements that read like the originals, and no behaviour, data binding or VB6 layout rule '
         "is modelled. Nothing on this page loads a script or a remote resource.</p>"),
        "<ul>",
        f"<li>geometry source: <strong>{esc(view.source)}</strong></li>",
        (f"<li>scale: <strong>{scale} twips per pixel</strong> (assumed 96 dpi; nothing measured "
         f"it for this build)</li>"),
        f"<li>cross-check: {esc(crosscheck)}</li>",
        (f"<li>controls: {counts['controls']}; drawn as a known type: {counts['drawn']} of "
         f"{counts['controls']}; placeholders: {counts['placeholders']}; "
         f"no rectangle: {counts['unplaced']}</li>"),
        "</ul>",
    ]
    out.extend(f'<p class="note">{esc(note)}</p>' for note in view.notes)
    width = _px(view.width or 0, scale)
    height = _px(view.height or 0, scale)
    out.append(f'<div class="canvas" style="width:{width};height:{height}">')
    out.extend(body)
    out.append("</div>")
    if unplaced:
        out.append("<h2>Controls with no recovered rectangle</h2>")
        out.append('<p class="note">They exist in the design but no complete Left/Top/Width/Height '
                   "was recovered, so placing them would be a guess.</p>")
        out.append("<table><tr><th>Control</th><th>Type</th><th>Caption</th></tr>")
        for box in unplaced:
            out.append(f"<tr><td>{esc(box.name)}</td><td>{esc(box.type)}</td>"
                       f"<td>{esc(box.caption or '-')}</td></tr>")
        out.append("</table>")
    out.append("</body></html>")
    return "\n".join(out) + "\n"


def render_index(views: list[FormView], *, scale: int = TWIPS_PER_PX,
                 links: dict[str, str] | None = None) -> str:
    links = links or {}
    total = sum(v.counts()["controls"] for v in views)
    drawn = sum(v.counts()["drawn"] for v in views)
    placeholders = sum(v.counts()["placeholders"] for v in views)
    out = [
        "<!DOCTYPE html>", '<html lang="en"><head><meta charset="utf-8">',
        f'<meta http-equiv="Content-Security-Policy" content="{CSP}">',
        "<title>Recovered forms</title>",
        ("<style>body{font:14px system-ui,sans-serif;margin:24px}table{border-collapse:collapse}"
         "td,th{border:1px solid #ccc;padding:4px 8px;text-align:left}</style>"),
        "</head><body>",
        "<h1>Recovered forms</h1>",
        (f"<p>{len(views)} forms, {total} controls. Drawn as a known type: {drawn} of {total}; "
         f"placeholders: {placeholders}. Scale: {scale} twips per pixel (assumed 96 dpi).</p>"),
        "<table><tr><th>Form</th><th>Controls</th><th>Geometry source</th><th>Cross-checked</th></tr>",
    ]
    for view in views:
        counts = view.counts()
        link = links.get(view.name)
        name = f'<a href="{esc(link)}">{esc(view.name)}</a>' if link else esc(view.name)
        if view.crosscheck is None:
            checked = "no blob supplied"
        else:
            checked = f"{view.crosscheck[0]} of {view.crosscheck[1]} controls"
        out.append(f"<tr><td>{name}</td><td>{counts['controls']}</td>"
                   f"<td>{esc(view.source)}</td><td>{esc(checked)}</td></tr>")
    out.append("</table></body></html>")
    return "\n".join(out) + "\n"


def summary(views: Iterable[FormView]) -> str:
    """The one stderr line: denominators, never a bare percentage."""
    views = list(views)
    total = sum(v.counts()["controls"] for v in views)
    drawn = sum(v.counts()["drawn"] for v in views)
    placeholders = sum(v.counts()["placeholders"] for v in views)
    unplaced = sum(v.counts()["unplaced"] for v in views)
    return (f"# {len(views)} forms: controls drawn as a known type: {drawn} of {total}; "
            f"placeholders: {placeholders}; no rectangle: {unplaced}")
