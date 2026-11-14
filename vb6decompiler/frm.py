"""VB6 ``.frm`` design-block parser (text only, stdlib only).

A VB6 form file is a text file: a ``VERSION 5.00`` header, a nested design block
opened by ``Begin <Type> <Name>`` and closed by ``End``, then the code section
which starts at ``Attribute VB_Name = "..."``.  This module parses *only* the
design block; it never looks at the code and never touches ``.frx`` blobs.

Five properties of the format decide the shape of this API.  They are not style
choices, they were measured on real decompiled output:

1. **Only non-default properties are written.**  A ``TextBox`` with no ``Locked``
   line is editable; no ``Visible`` line means visible; no ``Enabled`` line means
   enabled.  Therefore an absent property is *never* the same as ``false``.  Every
   boolean the format can omit is exposed as a tri-state: ``True``, ``False`` or
   ``None`` (not written).  :func:`bool_tri_counts` reports the three counts
   separately instead of folding "absent" into ``False``.

2. **Text is CP1254 (Turkish).**  Bytes are decoded with
   ``errors="replace"`` and the raw bytes of every value stay reachable
   (:attr:`Property.raw_bytes`), so a caller can re-decode or hash the original
   without re-reading the file.  Never ``latin-1``: it decodes without error and
   silently produces wrong Turkish (``�`` vs ``ý``/``þ``).

3. **Geometry is in twips.**  Form-level ``ClientWidth``/``ClientHeight`` (and
   ``Width``/``Height``) and every control's ``Left``/``Top``/``Width``/``Height``
   are twips as written.  Nothing is converted on the way in.  Conversion is an
   explicit, opt-in call (:attr:`Control.bounds_px`,
   :func:`twips_to_px`) and rests on the *assumption* of 15 twips per pixel —
   labelled as an assumption everywhere, because the file itself does not state
   a scale.

4. **Control arrays are one type and one name with an ``Index``.**  Elements must
   be grouped by ``(type, name)`` and ordered by ``Index``; they must not be
   merged into a single control and must not be emitted as unrelated siblings
   (:meth:`Form.control_arrays`).

5. **``SSTab`` page ownership comes from the ``Begin``/``End`` nesting.**  A child
   of ``TabDlg.SSTab`` is written *inside* the ``Begin TabDlg.SSTab SSTab1``
   block; there is no parent property on the child.  Page captions, when they are
   written at all, appear on the tab control itself as ``TabCaption(n) = "..."``
   and the selected page as ``Tab = n``.  Page *membership* is not in the text.

Measured on a real target (one decompiled VB6 application, 802 ``.frm`` files —
see ``docs/RULES.md`` §2: a parser ships with its coverage, not with "OK"):

* 369 files carry a design block (368 ``Begin VB.Form`` + 1 ``Begin VB.MDIForm``);
  433 are code-only stubs with no design block at all.  The stubs are reported by
  name, not skipped.
* 30,000 controls inside those 369 forms, 24,970 of them with all four of
  ``Left``/``Top``/``Width``/``Height`` (the rest are ``Line``, ``Menu``,
  ``Timer`` and non-visual OCX controls, which have no rectangle).
* Control arrays: 1,165 groups / 14,268 elements in 126 forms — and exactly
  14,268 ``Index =`` lines in the text, i.e. every array element writes one.
* ``SSTab``: 14 controls with 1,266 nested children, and **0** of them write
  ``Tab`` or ``TabCaption(n)`` — the page data lives in the ``OleObjectBlob``
  inside the matching ``.frx``.  So this parser reports 0 pages for that target
  instead of guessing a page count.
* Only ``Visible = 0 'False`` is ever written (432 lines, never ``Visible = -1``):
  the explicit-``false`` case exists, the explicit-``true`` case does not.  Reading
  absence as ``False`` would flip 29,568 controls.
* One file is truncated mid-control and never closes its design block; it is
  flagged ``complete=False`` with the cut line number, not silently repaired.

Re-run those numbers with :func:`scan_directory` / :func:`format_summary`, or
``python -m vb6decompiler.frm <directory>``.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Iterable, Iterator, Sequence

__all__ = [
    "TWIPS_PER_PX_ASSUMED",
    "FrmError",
    "NoDesignBlock",
    "MalformedForm",
    "ParseWarning",
    "FrxRef",
    "Property",
    "Control",
    "Form",
    "ScanResult",
    "parse_bytes",
    "parse_frm_text",
    "parse_frm",
    "scan_directory",
    "summarize",
    "format_summary",
    "bool_tri_counts",
    "twips_to_px",
    "decode_cp1254",
    "TRUE_EXPLICIT",
    "FALSE_EXPLICIT",
    "ABSENT",
]

#: Assumed device scale for the optional pixel conversion.  **This is an
#: assumption, not a measurement**: a ``.frm`` file stores twips and never states
#: a scale; 15 twips/px is the classic 96 dpi value the downstream tool in this
#: target family uses.  Every function that applies it says so in its name or
#: docstring, and all public geometry fields stay in twips.
TWIPS_PER_PX_ASSUMED = 15

#: Tri-state names.  Strings rather than an ``enum`` so JSON output stays readable.
TRUE_EXPLICIT = "true"    # property written and truthy
FALSE_EXPLICIT = "false"  # property written and falsy
ABSENT = "absent"         # property not written: VB6 default applies, *do not* read as false

#: Encoding of a VB6 ``.frm``'s non-ASCII text.  Measured: Turkish captions in
#: the target decode correctly as CP1254 and incorrectly as latin-1.
FRM_ENCODING = "cp1254"

# --------------------------------------------------------------------------- grammar
# ``Begin VB.TextBox Sutun4`` / ``Begin TabDlg.SSTab SSTab1`` /
# ``Begin MSComctlLib.ProgressBar ProgressBar1``; a licenced OCX may appear as a
# GUID (``Begin {C62A69F0-...} Ctrl1``), which is why the type alternative allows
# braces.
RE_BEGIN = re.compile(r"^(?P<indent>[ \t]*)Begin\s+(?P<type>[A-Za-z_][\w.]*|\{[0-9A-Fa-f-]+\})"
                      r"\s+(?P<name>[A-Za-z_]\w*)\s*$")
#: ``End`` closes a control; ``EndProperty`` closes a ``BeginProperty`` group and
#: must be tested first (it also starts with "End").
RE_END = re.compile(r"^(?P<indent>[ \t]*)End\s*$")
RE_END_PROPERTY = re.compile(r"^(?P<indent>[ \t]*)EndProperty\s*$")
#: ``BeginProperty Font`` groups sit *inside* a control (9,438 occurrences in the
#: measured target, all of them ``Font``).  Their members are flattened to
#: ``Font.Name``, ``Font.Size`` ... so the control keeps a single property map.
RE_BEGIN_PROPERTY = re.compile(r"^(?P<indent>[ \t]*)BeginProperty\s+(?P<type>[A-Za-z_][\w.]*)"
                               r"(?:\s+(?P<name>[A-Za-z_]\w*))?\s*$")
#: ``Name = value``.  The optional ``(n)`` covers indexed properties
#: (``TabCaption(0) = "..."``, ``Item(3) = ...``).
RE_PROP = re.compile(r"^(?P<indent>[ \t]*)(?P<name>[A-Za-z_]\w*)"
                     r"(?:\((?P<param>\d+)\))?\s*=\s*(?P<value>.*?)\s*$")
#: The code section starts here; the design block never continues past it.
RE_CODE_START = re.compile(r"^\s*Attribute\s+VB_")

RE_HEX = re.compile(r"^&[Hh]([0-9A-Fa-f]+)&?$")
RE_INT = re.compile(r"^[-+]?\d+$")
#: VB6 writes non-integral numbers with the authoring machine's decimal
#: separator; the measured target writes ``Size = 8,25`` throughout (9,419
#: occurrences).  A dot never appears in the 368 measured files.
RE_FLOAT_COMMA = re.compile(r"^[-+]?\d+,\d+$")
#: ``OleObjectBlob = "fDemo011.frx":1042`` — a reference into the sibling binary
#: resource file.  The value is *not* text and *not* geometry.
#:
#: The offset is **hexadecimal without a prefix**, and that was measured, not
#: assumed: 1,626 references across the target's 369 design blocks, every one of
#: them an offset below the size of the ``.frx`` it names, zero above; 837 of them
#: are digits-only (``:1042``) and the hex reading is the only one that stays in
#: range for the whole file.  Some are unambiguously hex (``:10AA``, ``:14A4``),
#: so a decimal reading of the digits-only ones would mix two bases in one file.
RE_FRX_REF = re.compile(r'^"((?:[^"]|"")*)"\s*:\s*([0-9A-Fa-f]+)$')

#: Value kinds produced by :func:`_parse_value`.
KIND_STR = "str"
KIND_BOOL = "bool"
KIND_INT = "int"
KIND_FLOAT = "float"
KIND_FRX = "frx"
KIND_UNKNOWN = "unknown"


class FrmError(ValueError):
    """Base class for design-block problems that stop parsing."""


class NoDesignBlock(FrmError):
    """The file has no ``Begin ...Form`` design block (code-only stub).

    Measured: 434 of 802 files in the target directory are in this state.  They
    are raised on purpose rather than returned as an empty form, so a caller
    cannot mistake "no design" for "a form with zero controls".
    """


class MalformedForm(FrmError):
    """The design block opened but could not be closed consistently."""


# --------------------------------------------------------------------------- values
@dataclass(frozen=True)
class FrxRef:
    """A reference into the sibling ``.frx`` binary resource.

    ``"fDemo011.frx":10AA`` means "offset 0x10AA of fDemo011.frx" — the offset is
    hexadecimal (see :data:`RE_FRX_REF` for the measurement).  ``offset_text``
    keeps the digits exactly as written so a caller that disagrees with the hex
    reading still has the evidence.  The bytes are not read here; this module is
    text-only.
    """

    file: str
    offset: int
    offset_text: str = ""

    def __str__(self) -> str:  # pragma: no cover - convenience only
        return f"{self.file}:{self.offset_text or self.offset}"


@dataclass
class Property:
    """One written ``Name = value`` line.

    ``value`` is normalised (``int``/``float``/``bool``/``str``/:class:`FrxRef`);
    ``raw`` is the value text as written with the VB6 type-hint comment removed
    and ``comment`` is that removed part.  Keeping the comment matters: it is the
    only way to tell the boolean ``0 'False`` from the enumeration value
    ``0`` (``BorderStyle = 0 'None``), and VB6 writes booleans as ``-1``/``0``.
    """

    name: str
    value: object
    kind: str
    raw: str
    raw_bytes: bytes
    comment: str | None = None
    param: int | None = None      # index of `Name(n) = ...`, else None
    line: int = 0

    @property
    def is_bool(self) -> bool:
        return self.kind == KIND_BOOL


@dataclass
class ParseWarning:
    """A line the parser could not interpret.  Collected, never swallowed."""

    path: str
    line: int
    text: str
    reason: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.reason}: {self.text!r}"


def decode_cp1254(data: bytes) -> str:
    """Decode VB6 text the way the format requires, keeping a lossy path explicit.

    ``errors="replace"`` is deliberate: a decompiled file may contain bytes that
    are not valid CP1254, and dropping the whole file would lose the other 25,000
    controls.  U+FFFD in the output is a *finding* that :func:`summarize` counts,
    not something to hide.  The raw bytes stay available on
    :attr:`Property.raw_bytes`.
    """
    return data.decode(FRM_ENCODING, "replace")


def _split_comment(text: str) -> tuple[str, str | None]:
    """Split ``-1  'True`` into ``('-1', 'True')``.

    The apostrophe only starts a comment outside a double-quoted string; VB6
    doubles embedded quotes (``""``), which toggles the flag twice and is
    therefore safe here.
    """
    in_str = False
    for i, ch in enumerate(text):
        if ch == '"':
            in_str = not in_str
        elif ch == "'" and not in_str:
            return text[:i].rstrip(), text[i + 1:].strip()
    return text.rstrip(), None


def _unquote(text: str) -> str:
    """Turn ``"a""b"`` into ``a"b`` (VB6 doubles embedded quotes)."""
    body = text[1:-1]
    return body.replace('""', '"')


def _parse_value(text: str, comment: str | None) -> tuple[object, str]:
    """Classify a property value and return ``(value, kind)``.

    The order of the tests is the grammar order, not a preference:

    * an ``.frx`` reference is checked before a plain string because it *starts*
      with a quote too;
    * hex literals (``&HC0C0C0&``) are integers in VB6 and must not fall through
      to ``str``;
    * a ``-1``/``0`` carrying the comment ``'True``/``'False`` is a boolean, while
      the same number with ``'None``/``'Fixed Single`` is an enumeration member.
    """
    if not text:
        return None, KIND_UNKNOWN
    m = RE_FRX_REF.match(text)
    if m:
        return FrxRef(m.group(1).replace('""', '"'), int(m.group(2), 16),
                      m.group(2)), KIND_FRX
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        return _unquote(text), KIND_STR
    m = RE_HEX.match(text)
    if m:
        return int(m.group(1), 16), KIND_INT
    if text in ("True", "False"):
        return text == "True", KIND_BOOL
    if RE_INT.match(text):
        n = int(text)
        if comment in ("True", "False"):
            return bool(n), KIND_BOOL
        return n, KIND_INT
    if RE_FLOAT_COMMA.match(text):
        return float(text.replace(",", ".")), KIND_FLOAT
    return text, KIND_UNKNOWN


# --------------------------------------------------------------------------- nodes
@dataclass
class Control:
    """One ``Begin <type> <name>`` block inside the form.

    ``parent`` is the enclosing control's name (``None`` for a direct child of the
    form).  It is derived from the ``Begin``/``End`` nesting — there is no parent
    property on a VB6 control — which is also how ``SSTab`` ownership is decided
    (see the module docstring, point 5).
    """

    type: str                     # full type as written, e.g. "TabDlg.SSTab"
    name: str
    props: dict[str, Property] = field(default_factory=dict)
    children: list["Control"] = field(default_factory=list)
    parent: str | None = None
    parent_type: str | None = None
    depth: int = 0
    line: int = 0
    indent: int = 0

    # -- naming -------------------------------------------------------------
    @property
    def short_type(self) -> str:
        """``TabDlg.SSTab`` -> ``SSTab`` (lib prefix dropped)."""
        return self.type.rsplit(".", 1)[-1]

    # -- raw property access ------------------------------------------------
    def prop(self, name: str, param: int | None = None) -> Property | None:
        """Written property or ``None``.  ``None`` means *not written*, not false.

        Indexed properties must be asked for with their index
        (``prop("TabCaption", 1)``); without one this returns the plain
        ``Name = ...`` property, else the first indexed variant.
        """
        if param is not None:
            return self.props.get(f"{name}({param})")
        p = self.props.get(name)
        if p is not None:
            return p
        for cand in self.props.values():
            if cand.name == name:
                return cand
        return None

    def has(self, name: str) -> bool:
        return self.prop(name) is not None

    def tri(self, name: str) -> str:
        """Tri-state of a boolean property: ``"true"``/``"false"``/``"absent"``.

        Measured reason for the third state: the target writes only
        ``Visible = 0 'False`` (432 lines) and never ``Visible = -1``; absence is
        the *normal* way to say "at the default, i.e. visible".
        """
        p = self.prop(name)
        if p is None:
            return ABSENT
        if p.kind == KIND_BOOL:
            return TRUE_EXPLICIT if p.value else FALSE_EXPLICIT
        # Written but not a boolean: ``BorderStyle = 0 'None`` and ``Visible = 0``
        # look alike numerically, and only the VB6 type-hint comment separates
        # them.  Guessing here would flip enumerations into "false", so an
        # un-hinted value is reported as absent rather than as a boolean.
        return ABSENT

    def bool_prop(self, name: str) -> bool | None:
        """``True``/``False`` when written, ``None`` when absent (VB6 default)."""
        tri = self.tri(name)
        if tri == TRUE_EXPLICIT:
            return True
        if tri == FALSE_EXPLICIT:
            return False
        return None

    def effective_bool(self, name: str, default: bool) -> bool:
        """Resolve a tri-state against the *caller's* stated default.

        The default is a parameter because this module does not carry a table of
        VB6 per-class defaults; guessing one would be invented data.  Passing
        ``default=True`` for ``Visible`` on a ``TextBox`` is the caller's claim,
        not this parser's.
        """
        v = self.bool_prop(name)
        return default if v is None else v

    def number(self, name: str) -> int | float | None:
        p = self.prop(name)
        if p is None or p.kind not in (KIND_INT, KIND_FLOAT):
            return None
        return p.value

    def twips(self, name: str) -> int | None:
        """A geometry property exactly as written (twips).  ``None`` if absent."""
        p = self.prop(name)
        if p is None:
            return None
        if p.kind == KIND_FLOAT:
            # Fractional twips exist (``Size = 8,25``) but not for geometry;
            # keep the value rather than silently rounding.
            return p.value  # type: ignore[return-value]
        if p.kind == KIND_INT:
            return int(p.value)  # type: ignore[arg-type]
        return None

    def string(self, name: str) -> str | None:
        p = self.prop(name)
        if p is None:
            return None
        return p.value if p.kind == KIND_STR else None

    @property
    def caption(self) -> str | None:
        """``Caption`` as written (CP1254-decoded), or ``None`` if not written."""
        return self.string("Caption")

    @property
    def text(self) -> str | None:
        return self.string("Text")

    @property
    def index(self) -> int | None:
        """Control-array ``Index``, or ``None`` when the control is not in an array."""
        p = self.prop("Index")
        if p is None or not isinstance(p.value, int):
            return None
        return int(p.value)

    @property
    def caption_bytes(self) -> bytes | None:
        """Raw CP1254 bytes of ``Caption``, for callers that must not re-encode."""
        p = self.prop("Caption")
        return p.raw_bytes if p is not None and p.kind == KIND_STR else None

    # -- geometry -----------------------------------------------------------
    @property
    def bounds(self) -> tuple[int, int, int, int] | None:
        """``(left, top, width, height)`` in twips, or ``None`` if any is absent.

        No conversion, no defaulting: a partially written rectangle returns
        ``None`` instead of a guessed 0.
        """
        vals = [self.twips(k) for k in ("Left", "Top", "Width", "Height")]
        if any(v is None for v in vals):
            return None
        return tuple(int(v) for v in vals)  # type: ignore[return-value]

    @property
    def has_bounds(self) -> bool:
        return self.bounds is not None

    def bounds_px(self, twips_per_px: int = TWIPS_PER_PX_ASSUMED) -> tuple[float, ...] | None:
        """Twips converted to pixels with the **assumed** 15 twips/px scale.

        The file carries no scale, so this is a convenience for rendering only;
        nothing in this module calls it implicitly.
        """
        b = self.bounds
        if b is None:
            return None
        return tuple(v / twips_per_px for v in b)

    @property
    def line_coords(self) -> tuple[int, int, int, int] | None:
        """``(X1, Y1, X2, Y2)`` for ``VB.Line`` (twips), which has no Left/Width."""
        vals = [self.twips(k) for k in ("X1", "Y1", "X2", "Y2")]
        if any(v is None for v in vals):
            return None
        return tuple(int(v) for v in vals)  # type: ignore[return-value]

    @property
    def derived_bounds(self) -> tuple[int, int, int, int] | None:
        """Bounding box **derived** from ``X1/Y1/X2/Y2`` (as the downstream tool does).

        Named "derived" on purpose: the file does not contain these four numbers
        for a ``Line``, so they must never be presented as written properties.
        Width/height are clamped to 1 twip so a purely horizontal or vertical line
        still has a drawable rectangle.
        """
        c = self.line_coords
        if c is None:
            return None
        x1, y1, x2, y2 = c
        return (min(x1, x2), min(y1, y2), max(abs(x2 - x1), 1), max(abs(y2 - y1), 1))

    @property
    def font(self) -> dict[str, object]:
        """Flattened ``BeginProperty Font`` members (``{"Name": ..., "Size": ...}``)."""
        out: dict[str, object] = {}
        for key, prop in self.props.items():
            if "." in key:
                out[key.split(".", 1)[1]] = prop.value
        return out

    # -- tab pages ----------------------------------------------------------
    def tab_pages(self) -> list[tuple[int, str | None]]:
        """``[(page_index, caption_or_None), ...]`` from written ``TabCaption(n)``.

        Only what the text contains: pages are sorted by index and a page whose
        caption is empty/absent is reported with ``None``.  An empty list means
        *no page captions are written in this file* — measured on the target, all
        14 ``SSTab`` controls store their page data in the ``.frx``
        ``OleObjectBlob`` and write neither ``Tab`` nor ``TabCaption``, so an
        empty list here is the correct answer, not a parser gap.
        """
        pages: dict[int, str | None] = {}
        for prop in self.props.values():
            if prop.name == "TabCaption" and prop.param is not None:
                pages[prop.param] = prop.value if prop.kind == KIND_STR else None  # type: ignore[assignment]
        return sorted(pages.items())

    @property
    def selected_page(self) -> int | None:
        """``Tab = n`` on the ``SSTab`` itself: the page shown in the designer."""
        p = self.prop("Tab")
        if p is None or not isinstance(p.value, int):
            return None
        return int(p.value)


@dataclass
class Form:
    """A parsed ``.frm`` design block."""

    name: str
    type: str
    props: dict[str, Property] = field(default_factory=dict)
    controls: list[Control] = field(default_factory=list)      # flattened, document order
    roots: list[Control] = field(default_factory=list)         # direct children of the form
    warnings: list[ParseWarning] = field(default_factory=list)
    path: str | None = None
    #: ``False`` when the design block had no closing ``End`` (truncated file).
    #: The controls recovered before the cut are kept; this flag says so.
    complete: bool = True
    incomplete_reason: str | None = None

    # -- form-level ---------------------------------------------------------
    def prop(self, name: str) -> Property | None:
        return self.props.get(name)

    def string(self, name: str) -> str | None:
        p = self.prop(name)
        return p.value if p is not None and p.kind == KIND_STR else None

    @property
    def caption(self) -> str | None:
        return self.string("Caption")

    def twips(self, name: str) -> int | None:
        p = self.prop(name)
        return int(p.value) if p is not None and p.kind == KIND_INT else None

    @property
    def client_size(self) -> tuple[int, int] | None:
        """``(ClientWidth, ClientHeight)`` in twips, or ``None`` if either absent.

        Measured: all 369 parsed design forms write both, and the values match the
        form geometry recovered from the compiled image (the ``--validate`` path of
        the blob extractor this parser was derived from).  A form that omits them
        is reported as ``None``, never as 0 — the two are different facts.
        """
        w, h = self.twips("ClientWidth"), self.twips("ClientHeight")
        if w is None or h is None:
            return None
        return (w, h)

    @property
    def outer_size(self) -> tuple[int, int] | None:
        """``(Width, Height)`` in twips — the whole window, not the client area."""
        w, h = self.twips("Width"), self.twips("Height")
        if w is None or h is None:
            return None
        return (w, h)

    def tri(self, name: str) -> str:
        p = self.prop(name)
        if p is None:
            return ABSENT
        if p.kind == KIND_BOOL:
            return TRUE_EXPLICIT if p.value else FALSE_EXPLICIT
        return ABSENT

    # -- lookups ------------------------------------------------------------
    def control(self, name: str, index: int | None = None) -> Control | None:
        """Find a control by name; for an array pass the ``Index`` too.

        VB6 identifiers are case-insensitive, but this lookup is exact on purpose:
        an approximate match between two different names would be invented data
        (see ``docs/RULES.md`` §4).  Case-fold yourself if that is what you want.
        """
        for c in self.controls:
            if c.name != name:
                continue
            if index is None or c.index == index:
                return c
        return None

    def by_name(self, name: str) -> list[Control]:
        return [c for c in self.controls if c.name == name]

    def control_arrays(self) -> dict[tuple[str, str], list[Control]]:
        """Control arrays grouped by ``(type, name)`` and ordered by ``Index``.

        A VB6 control array is *one* control with one name and one type whose
        elements differ only by ``Index``; each element is its own design record
        with its own geometry.  Merging them loses all but one position; keeping
        them as unrelated siblings loses the fact that they are one object (event
        handlers are ``Sub Sutun4_Change(Index As Integer)``).

        A group counts as an array when at least one member writes ``Index``.
        Measured trap: a same-named pair with *different* types is two scalar
        controls, not an array — ``(type, name)`` is the key for that reason.
        """
        groups: dict[tuple[str, str], list[Control]] = {}
        for c in self.controls:
            groups.setdefault((c.short_type, c.name), []).append(c)
        arrays: dict[tuple[str, str], list[Control]] = {}
        for key, members in groups.items():
            if any(m.index is not None for m in members):
                # Sorted by Index; an element that (illegally) lacks Index sorts
                # last rather than crashing the parse.
                arrays[key] = sorted(members, key=lambda m: (m.index is None, m.index or 0))
        return arrays

    def sstabs(self) -> list[Control]:
        """All ``SSTab`` controls of the form."""
        return [c for c in self.controls if c.short_type == "SSTab"]

    def sstab_children(self, sstab_name: str) -> list[Control]:
        """Direct children of one ``SSTab`` — ownership by nesting, not by property."""
        return [c for c in self.controls if c.parent == sstab_name]

    def sstab_of(self, control: Control) -> str | None:
        """Name of the nearest ``SSTab`` ancestor, walking the parse tree."""
        cur = control.parent
        while cur is not None:
            node = self.control(cur)
            if node is None:
                return None
            if node.short_type == "SSTab":
                return node.name
            cur = node.parent
        return None

    # -- tree ---------------------------------------------------------------
    def walk(self) -> Iterator[Control]:
        """Depth-first walk over ``roots`` (same order as ``controls``)."""
        def rec(nodes: Sequence[Control]) -> Iterator[Control]:
            for n in nodes:
                yield n
                yield from rec(n.children)
        return rec(self.roots)


# --------------------------------------------------------------------------- parser
@dataclass
class _Frame:
    """One open ``Begin`` block or ``BeginProperty`` group during parsing."""

    kind: str                 # "control" | "group" | "form"
    indent: int
    line: int
    control: Control | None = None
    group: str | None = None


def parse_frm_text(text: str, *, path: str | None = None,
                   raw: bytes | None = None) -> Form:
    """Parse a decoded design block.

    ``text`` must already be decoded (see :func:`decode_cp1254`); ``raw`` is the
    matching byte string and is only used to keep :attr:`Property.raw_bytes`
    pointing at the file's own bytes.  When ``raw`` is omitted the raw bytes are
    the CP1254 encoding of ``text``, which is exact for every file this parser
    can read and lossy only in the U+FFFD cases that are reported as warnings.
    """
    if raw is None:
        raw = text.encode(FRM_ENCODING, "replace")
    # Split the decoded text and the raw bytes in lockstep so a property's bytes
    # can be located without re-encoding (CP1254 is single-byte, so byte offsets
    # of ASCII '=' and quotes equal character offsets).
    lines = text.split("\n")
    raw_lines = raw.split(b"\n") if raw.count(b"\n") == len(lines) - 1 else []

    form: Form | None = None
    warnings: list[ParseWarning] = []
    stack: list[_Frame] = []
    all_controls: list[Control] = []
    truncated = False

    def warn(lineno: int, txt: str, reason: str) -> None:
        warnings.append(ParseWarning(path or "<text>", lineno, txt, reason))

    for lineno, raw_line in enumerate(lines, 1):
        line = raw_line.rstrip("\r")
        stripped = line.strip()

        if not stripped:
            continue
        # A decompiler may emit a commented-out property (measured: `'Icon = n/a`).
        # The leading apostrophe is VB6's comment marker, so the line is not data.
        if stripped.startswith("'"):
            continue
        # A design block ends at the first Attribute statement (measured: always
        # `Attribute VB_Name`); anything after it is VB6 code, not design data.
        if RE_CODE_START.match(line):
            break

        m = RE_BEGIN.match(line)
        if m:
            indent = len(m.group("indent").expandtabs(4))
            typ, name = m.group("type"), m.group("name")
            # Indentation is the authoritative nesting signal for the siblings,
            # `End` for closing: pop anything at the same or deeper level so a
            # missing `End` degrades a subtree instead of corrupting the rest.
            while stack and stack[-1].indent >= indent and stack[-1].kind != "form":
                warn(lineno, line, f"'{name}' opened while {stack[-1].kind} "
                                   f"from line {stack[-1].line} still open (unclosed End)")
                stack.pop()
            ctrl = Control(type=typ, name=name, line=lineno, indent=indent)
            parent: Control | None = None
            for frame in reversed(stack):
                if frame.control is not None:
                    parent = frame.control
                    break
            if parent is not None:
                ctrl.parent = parent.name
                ctrl.parent_type = parent.type
                ctrl.depth = parent.depth + 1
                parent.children.append(ctrl)
            else:
                ctrl.depth = 0
            kind = "form" if (form is None and typ.rsplit(".", 1)[-1].endswith("Form")) else "control"
            if kind == "form":
                form = Form(name=name, type=typ, path=path)
                stack.append(_Frame(kind="form", indent=indent, line=lineno))
                continue
            if form is None:
                warn(lineno, line, "control before any form block")
            all_controls.append(ctrl)
            if parent is None and form is not None:
                form.roots.append(ctrl)
            stack.append(_Frame(kind="control", indent=indent, line=lineno, control=ctrl))
            continue

        if RE_END_PROPERTY.match(line):
            indent = len(RE_END_PROPERTY.match(line).group("indent").expandtabs(4))
            if stack and stack[-1].kind == "group":
                stack.pop()
            else:
                warn(lineno, line, "EndProperty without BeginProperty")
            continue

        if RE_BEGIN_PROPERTY.match(line):
            indent = len(RE_BEGIN_PROPERTY.match(line).group("indent").expandtabs(4))
            grp = RE_BEGIN_PROPERTY.match(line)
            stack.append(_Frame(kind="group", indent=indent, line=lineno,
                                group=grp.group("type")))
            continue

        if RE_END.match(line):
            indent = len(RE_END.match(line).group("indent").expandtabs(4))
            if not stack:
                warn(lineno, line, "End without Begin")
                continue
            if stack[-1].kind == "group":
                warn(lineno, line, "End inside BeginProperty group")
                stack.pop()
            # Pop the innermost frame at this indent level.
            while stack and stack[-1].indent > indent:
                warn(lineno, line, f"forced close of {stack[-1].kind} "
                                   f"from line {stack[-1].line}")
                stack.pop()
            closed = stack.pop() if stack else None
            # The root form's `End` is the authoritative end of the design block:
            # measured, the code that follows does not always start with
            # `Attribute VB_Name` (one file continues with `Public mblnAktif As
            # Boolean` and even a disassembly listing), so waiting for the
            # Attribute line would swallow code into the design block.
            if closed is not None and closed.kind == "form":
                break
            continue

        m = RE_PROP.match(line)
        if m:
            if not stack:
                # Header lines before `Begin VB.Form` (`VERSION`, `Object`) are
                # not form properties; ignore them silently.
                continue
            frame = stack[-1]
            base = m.group("name")
            param = int(m.group("param")) if m.group("param") else None
            if frame.kind == "group":
                # `BeginProperty Font ... EndProperty` members belong to the
                # control that owns the group, which is further down the stack.
                owner = next((f.control for f in reversed(stack)
                              if f.kind == "control"), None)
                key = f"{frame.group}.{base}"
            else:
                owner = frame.control if frame.kind == "control" else None
                # Indexed properties (`TabCaption(0)`, `TabCaption(1)`, ...) keep
                # their index in the key: keying by name alone would let page 1
                # overwrite page 0 and report a single page.
                key = base if param is None else f"{base}({param})"
                if frame.kind == "form" and form is not None:
                    owner = None
            value_text, comment = _split_comment(m.group("value"))
            vstart = line.find(m.group("value"))
            vend = vstart + len(value_text) if vstart >= 0 else -1
            if raw_lines and lineno - 1 < len(raw_lines) and vstart >= 0:
                vbytes = raw_lines[lineno - 1][vstart:vend]
            else:
                vbytes = value_text.encode(FRM_ENCODING, "replace")
            value, kind = _parse_value(value_text, comment)
            if kind == KIND_UNKNOWN:
                warn(lineno, line, "unrecognised property value")
            prop = Property(name=base, value=value, kind=kind,
                            raw=value_text, raw_bytes=vbytes, comment=comment,
                            param=param, line=lineno)
            if owner is not None:
                owner.props[key] = prop
            elif frame.kind == "form" and form is not None:
                form.props[key] = prop
            elif frame.kind == "group":
                warn(lineno, line, "property group outside a control")
            continue

        if form is None:
            # Everything before the `Begin VB.Form` line is file header
            # (`VERSION 5.00`, `Object = "{guid}"; "path"`).  It is not design
            # data, so it is skipped without a warning.
            continue
        # A line inside an open form that is neither Begin/End/property/comment
        # means the design block stopped without its closing `End` — a truncated
        # or hand-edited file.  Reported once, with the recovery count, instead of
        # one warning per code line: measured case, `formRec01` ends inside a
        # `Begin VB.PictureBox` and continues straight into `Public mblnAktif As
        # Boolean` and a disassembly listing.
        warn(lineno, line, f"design block ended without closing End at line {lineno}; "
                           f"{len(all_controls)} control(s) recovered before it")
        truncated = True
        break

    if form is None:
        raise NoDesignBlock(f"{path or '<text>'}: no Begin ...Form design block")
    form.complete = not truncated
    if not truncated and any(f.kind != "form" for f in stack):
        # Reaching the end of the text with blocks still open means the closing
        # `End`s are missing; the controls found are kept and the file is flagged.
        form.complete = False
        warn(len(lines), "<eof>", f"{sum(1 for f in stack if f.kind != 'form')} block(s) "
                                   "still open at end of design block")
    form.controls = all_controls
    form.warnings = warnings
    form.incomplete_reason = warnings[-1].reason if (warnings and not form.complete) else None
    return form


def parse_bytes(data: bytes, *, path: str | None = None) -> Form:
    """Decode ``data`` as CP1254 and parse its design block.

    The whole file is decoded, not just the design block: finding the block
    boundary requires scanning to ``Attribute``, and byte offsets must stay in
    step with character offsets (true for a single-byte codec like CP1254).
    """
    return parse_frm_text(decode_cp1254(data), path=path, raw=data)


def parse_frm(path: str) -> Form:
    """Parse one ``.frm`` file from disk.  Raises :class:`NoDesignBlock` if it has none."""
    with open(path, "rb") as fh:
        data = fh.read()
    return parse_bytes(data, path=path)


# --------------------------------------------------------------------------- directory
@dataclass
class ScanResult:
    """Outcome of :func:`scan_directory`.  Nothing is dropped silently.

    * ``forms`` — parsed design blocks.
    * ``no_design`` — files with no design block (code-only stubs).  Listed by
      path, not skipped: "no design block" is a measurement, not a failure of the
      parser, and must not be confused with "form with zero controls".
    * ``failures`` — ``(path, message)`` for files that *did* open a design block
      and could not be finished.
    * ``warnings`` — per-file line-level problems, kept with their file names.
    """

    root: str
    files_seen: int = 0
    forms: list[Form] = field(default_factory=list)
    no_design: list[str] = field(default_factory=list)
    failures: list[tuple[str, str]] = field(default_factory=list)
    warnings: list[ParseWarning] = field(default_factory=list)


def _frm_files(root: str, recursive: bool = False) -> list[str]:
    out: list[str] = []
    if recursive:
        for dirpath, _dirnames, filenames in os.walk(root):
            for fn in filenames:
                if fn.lower().endswith(".frm"):
                    out.append(os.path.join(dirpath, fn))
    else:
        for fn in os.listdir(root):
            p = os.path.join(root, fn)
            if fn.lower().endswith(".frm") and os.path.isfile(p):
                out.append(p)
    return sorted(out)


def scan_directory(root: str, *, recursive: bool = False) -> ScanResult:
    """Parse every ``.frm`` under ``root`` and account for all of them."""
    res = ScanResult(root=root)
    for path in _frm_files(root, recursive):
        res.files_seen += 1
        try:
            form = parse_frm(path)
        except NoDesignBlock:
            res.no_design.append(path)
            continue
        except (FrmError, OSError) as exc:      # MalformedForm / unreadable file
            res.failures.append((path, str(exc)))
            continue
        res.forms.append(form)
        res.warnings.extend(form.warnings)
    return res


# --------------------------------------------------------------------------- reporting
def bool_tri_counts(controls: Iterable[Control], name: str) -> dict[str, int]:
    """Count ``true`` / ``false`` / ``absent`` for one boolean property.

    Three states, three numbers, always summing to the denominator the caller
    supplied.  Collapsing ``absent`` into ``false`` is the single biggest way to
    get a VB6 design wrong, so it has no shorthand here.
    """
    counts = {TRUE_EXPLICIT: 0, FALSE_EXPLICIT: 0, ABSENT: 0}
    for c in controls:
        counts[c.tri(name)] += 1
    return counts


def twips_to_px(value: float, twips_per_px: int = TWIPS_PER_PX_ASSUMED) -> float:
    """Convert twips to pixels using the **assumed** 15 twips/px scale."""
    if twips_per_px <= 0:
        raise ValueError("twips_per_px must be positive")
    return value / twips_per_px


def summarize(res: ScanResult) -> dict[str, object]:
    """Turn a :class:`ScanResult` into counts.  Every count carries its denominator."""
    controls = [c for f in res.forms for c in f.controls]
    by_type: dict[str, int] = {}
    for c in controls:
        by_type[c.short_type] = by_type.get(c.short_type, 0) + 1

    forms_with_arrays = 0
    array_groups = 0
    array_elements = 0
    arrays_with_gaps = 0
    for f in res.forms:
        arrays = f.control_arrays()
        if arrays:
            forms_with_arrays += 1
        array_groups += len(arrays)
        for members in arrays.values():
            array_elements += len(members)
            idx = sorted(m.index for m in members if m.index is not None)
            if idx and idx != list(range(len(idx))):
                arrays_with_gaps += 1

    sstab_controls = [c for c in controls if c.short_type == "SSTab"]
    sstab_forms = [f for f in res.forms if f.sstabs()]
    sstab_children = 0
    pages_with_caption = 0
    pages_without_caption = 0
    selected_written = 0
    for f in res.forms:
        for s in f.sstabs():
            sstab_children += len(f.sstab_children(s.name))
            for _idx, cap in s.tab_pages():
                if cap:
                    pages_with_caption += 1
                else:
                    pages_without_caption += 1
            if s.selected_page is not None:
                selected_written += 1

    replacement_captions = sum(
        1 for c in controls
        if isinstance(c.caption, str) and "\ufffd" in c.caption
    )
    # A Caption whose value is a `.frx` reference (`Caption = "fX.frx":14A4`) is
    # stored as binary, usually a Unicode/exotic caption; the text is not in the
    # design block, so it is counted here instead of being reported as "no caption".
    captions_in_frx = sum(
        1 for c in controls
        if c.prop("Caption") is not None and c.prop("Caption").kind == KIND_FRX  # type: ignore[union-attr]
    )

    client_sizes = sum(1 for f in res.forms if f.client_size is not None)
    incomplete = [f for f in res.forms if not f.complete]

    return {
        "directory": res.root,
        "files_seen": res.files_seen,
        "files_parsed": len(res.forms),
        "files_without_design_block": len(res.no_design),
        "files_without_design_block_paths": list(res.no_design),
        "parse_failures": len(res.failures),
        "parse_failure_details": list(res.failures),
        "controls_total": len(controls),
        "controls_with_bounds": sum(1 for c in controls if c.has_bounds),
        "controls_by_type": dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
        "forms_with_control_arrays": forms_with_arrays,
        "control_array_groups": array_groups,
        "control_array_elements": array_elements,
        "control_arrays_with_index_gaps": arrays_with_gaps,
        "sstab_controls": len(sstab_controls),
        "sstab_forms": len(sstab_forms),
        "sstab_children": sstab_children,
        "sstab_pages_with_caption": pages_with_caption,
        "sstab_pages_without_caption": pages_without_caption,
        "sstab_selected_page_written": selected_written,
        "forms_with_client_size": client_sizes,
        "forms_incomplete": len(incomplete),
        "incomplete_forms": [(f.path, f.incomplete_reason) for f in incomplete],
        "captions_containing_replacement_char": replacement_captions,
        "captions_stored_in_frx": captions_in_frx,
        "bool_tristate": {
            name: bool_tri_counts(controls, name)
            for name in ("Visible", "Enabled", "Locked", "MultiLine")
        },
        "warnings": len(res.warnings),
        "warning_examples": [str(w) for w in res.warnings[:10]],
    }


def format_summary(summary: dict[str, object]) -> str:
    """Render :func:`summarize` output as text with denominators on every line."""
    s = summary
    lines = [
        f"directory: {s['directory']}",
        f"files: {s['files_parsed']} parsed / {s['files_seen']} seen "
        f"({s['files_without_design_block']} without design block, "
        f"{s['parse_failures']} failures)",
        f"controls: {s['controls_total']} "
        f"({s['controls_with_bounds']} with written Left/Top/Width/Height)",
        f"forms with control arrays: {s['forms_with_control_arrays']} / {s['files_parsed']}",
        f"control arrays: {s['control_array_groups']} groups, "
        f"{s['control_array_elements']} elements "
        f"({s['control_arrays_with_index_gaps']} with non-contiguous Index)",
        f"SSTab: {s['sstab_controls']} controls in {s['sstab_forms']} forms, "
        f"{s['sstab_children']} nested children, pages written: "
        f"{s['sstab_pages_with_caption']} with caption + "
        f"{s['sstab_pages_without_caption']} without "
        f"(Tab= written on {s['sstab_selected_page_written']})",
        f"forms writing ClientWidth+ClientHeight: {s['forms_with_client_size']} / {s['files_parsed']}",
        f"incomplete design blocks (no closing End): {s['forms_incomplete']} / {s['files_parsed']}",
        f"captions containing U+FFFD after CP1254 decode: "
        f"{s['captions_containing_replacement_char']} / {s['controls_total']}",
        f"captions stored in .frx (text not in the design block): "
        f"{s['captions_stored_in_frx']} / {s['controls_total']}",
    ]
    tri = s["bool_tristate"]
    for name in ("Visible", "Enabled", "Locked", "MultiLine"):
        c = tri[name]  # type: ignore[index]
        lines.append(
            f"  {name}: true={c[TRUE_EXPLICIT]} false={c[FALSE_EXPLICIT]} "
            f"absent={c[ABSENT]} of {s['controls_total']}"
        )
    if s["parse_failures"]:
        lines.append("parse failures:")
        lines.extend(f"  {p}: {msg}" for p, msg in s["parse_failure_details"])  # type: ignore[union-attr]
    if s["warnings"]:
        lines.append(f"warnings: {s['warnings']} (first {min(10, s['warnings'])})")
        lines.extend(f"  {w}" for w in s["warning_examples"])  # type: ignore[union-attr]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """``python -m vb6decompiler.frm <dir> [--recursive] [--json]`` — coverage report."""
    import argparse
    import json

    ap = argparse.ArgumentParser(description="Parse VB6 .frm design blocks and report coverage.")
    ap.add_argument("directory", help="directory containing .frm files")
    ap.add_argument("--recursive", action="store_true", help="walk subdirectories")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = ap.parse_args(argv)
    res = scan_directory(args.directory, recursive=args.recursive)
    s = summarize(res)
    print(json.dumps(s, indent=1, ensure_ascii=False) if args.json else format_summary(s))
    return 0 if not res.failures else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
