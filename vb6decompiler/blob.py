"""Form-data blob parser for natively compiled VB6 executables.

What a blob is
--------------
A VB6 program compiled to native code keeps the *design-time* description of
every form in the executable's data area.  Each form has one blob: a form
record, the form-level properties, and then one record per control.  This
module locates those blobs in a PE file, decodes the record grammar, and
recovers per-control geometry, captions, control-array indices, the
non-default ``Visible`` flag and ``SSTab`` page titles/membership.

Record grammar (measured; the layout below is what the parser implements)
-----------------------------------------------------------------------
::

    <size:int32> <idx:uint8> <namelen:uint16> <name> 0x00 <class:uint8> <properties...>

* ``size`` is what the record declares about itself.  Measured on a real
  target it is the record's byte length minus one for control records, and for
  the form record it covers only the header/property block, not the control
  records that follow.  The scanner therefore uses it as *evidence* that a
  name-shaped hit is a real record header (and to find array headers), never as
  a way to jump to the next record.  If bit 31 (``0x80000000``) is set the
  control belongs to a **control array** and the header gains a ``uint16``
  array index::

      <size|0x80000000:int32> <idx:uint8> <index:uint16> <namelen:uint16> <name> 0x00 ...

* ``class`` is the VB6 control-class byte (see :data:`CLASS_NAME`).  ``0xFF``
  means an OCX: the class name follows as a length-prefixed string
  (``<len:uint16> "MSComctlLib.ProgressBar" 0x00``).
* Every remaining property is a ``<pid:uint8> <value>`` pair.  The value type
  depends on ``pid``, i.e. on the property's position in that class's property
  table.  Geometry is written as one property holding ``4 x int16``
  (Left, Top, Width, Height) under a class-specific ``pid`` — see
  :data:`GEOM_PID`.
* Geometry widens to ``4 x int32`` when a value does not fit in int16: the
  property is then ``<pid> 0x00 0x80 <4 x int32>`` (the ``0x8000`` marker is a
  uint16 flag after the pid byte).
* Strings are ``<len:uint16> <bytes> 0x00`` in CP1254 (Turkish code page) for
  control properties, and UTF-16LE for ``SSTab`` page data.
* A blob may contain more than one form object (class ``0x0D``): the main form
  plus nested form objects.  Each one opens a segment, and controls belong to
  the segment they appear in.
* Classes that carry no ``Left/Top/Width/Height`` (``VB.Line``, ``VB.Timer``,
  ``VB.Menu``) and non-visual OCXs (``ImageList``, ``CommonDialog``) are not
  emitted as controls.

Two derived facts, both measured against ground truth
-----------------------------------------------------
* ``Visible`` is only stored when it is **not** the default.  A hidden control
  is marked by the class-specific ``<pid> 0x00`` pair immediately after the
  geometry value (:data:`VISIBLE_PID`).  For classes without a calibrated rule
  :attr:`Control.visible` stays ``None`` — unknown, not "visible".
* ``SSTab`` records embed page titles as UTF-16 strings followed by a fixed
  GUID signature; UTF-16 control names without a signature belong to the
  current page.

The form's client rectangle is pid ``0x35`` followed by four int32 values
``(ClientLeft, ClientTop, ClientWidth, ClientHeight)``.  Reading the first one
as a block length (which also "works" on many forms) is wrong: it is
``ClientLeft``, and the misreading rejects every form whose client origin is
larger than the assumed size limit.

What this cannot do
-------------------
* Controls are identified by ``(name, index)`` only.  A control that the blob
  stores twice (the same name and index in two records) yields both records;
  the caller keeps the first.
* ``SSTab`` membership lists the controls the ``SSTab`` record itself names.  A
  ``Frame`` placed on a page owns its children, and those children are not
  listed in the ``SSTab`` record — their page is not recoverable from the blob.
* A form whose compiled blob differs from the ``.frm`` text (rebuilt without
  the sources being in sync) will mismatch; :func:`validate` reports it rather
  than smoothing it over.
* Classes outside :data:`GEOM_PID` and :data:`VISIBLE_PID` are emitted with
  :data:`GEOM_PID_OCX` geometry and ``visible=None``.  That is a calibrated
  default, not a verified fact for a new target: run :func:`validate`.

Calibration
-----------
``GEOM_PID``, ``POST_PIDS``, ``VISIBLE_PID`` and the scan windows were derived
from a real target by comparing the blob output against the ``.frm`` design
text shipped with that program.  They are not guesses and must not be
"tidied": each table's comment names what it was calibrated against.  Run
:func:`validate` against a ``.frm`` directory to re-measure coverage on a new
target before trusting the output; anything not covered is reported, never
filled in.

Usage::

    from vb6decompiler import blob

    forms = blob.extract_forms("APP.EXE")
    report = blob.validate("APP.EXE", "path/to/decompile")
    print(report.controls_matched, "/", report.controls_total)
"""
from __future__ import annotations

import glob
import os
import re
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass, field

# --------------------------------------------------------------------------
# Class tables
# --------------------------------------------------------------------------
#: VB6 control-class byte -> ``.frm`` type name.  The numeric values are the
#: documented VB6 control class ids; ``0x0D`` is the form object itself.
CLASS_NAME = {
    0x00: "VB.PictureBox",
    0x01: "VB.Label",
    0x02: "VB.TextBox",
    0x03: "VB.Frame",
    0x04: "VB.CommandButton",
    0x05: "VB.CheckBox",
    0x06: "VB.OptionButton",
    0x07: "VB.ComboBox",
    0x08: "VB.ListBox",
    0x09: "VB.HScrollBar",
    0x0A: "VB.VScrollBar",
    0x0B: "VB.Timer",
    0x0C: "VB.DriveListBox",
    0x0D: "VB.Form",       # embedded form object: opens a new blob segment
    0x12: "VB.FileListBox",
    0x16: "VB.Shape",
    0x17: "VB.Line",
    0x18: "VB.Image",
    0xFF: None,            # OCX: the class name is a string inside the record
}

#: Class -> pid of the property that carries ``4 x int16`` geometry.
#:
#: Calibrated against the ``.frm`` design blocks of the calibration target:
#: every control of a class used the same pid, so one value per class.  The pid
#: is the class's property-table position, which is why it differs between
#: classes instead of being a fixed field number.
GEOM_PID = {
    "VB.Label": 0x05,
    "VB.PictureBox": 0x05,
    "VB.Frame": 0x05,
    "VB.CheckBox": 0x05,
    "VB.OptionButton": 0x05,
    "VB.ComboBox": 0x05,
    "VB.TextBox": 0x04,
    "VB.CommandButton": 0x04,
    "VB.ListBox": 0x04,
    "VB.FileListBox": 0x04,
    "VB.Shape": 0x04,
    "VB.Image": 0x03,
    "VB.VScrollBar": 0x02,
    "VB.HScrollBar": 0x02,
}

#: Geometry pid used by every OCX (``0xFF``) class.  Measured: the OCX property
#: table is laid out by VB's OLE-control stub, so the pid does not vary with
#: the OCX's own property list.
GEOM_PID_OCX = 0x03

#: Pids that are observed to follow a geometry value when the next property is
#: written.  Used only to reject wrong candidate offsets during the scan; a
#: correct geometry followed by a pid outside this set would be missed, which
#: the validator would show as a missing control rather than a wrong one.
POST_PIDS = {0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0E, 0x0F, 0x11, 0x12, 0x17, 0xFF}

#: Classes that carry no ``Left/Top/Width/Height`` (they use X1/Y1/X2/Y2 or no
#: position at all): excluded from the geometry schema instead of guessed.
SKIP_TYPES = {
    "VB.Form",
    "VB.Line",
    "VB.Timer",
    "VB.Menu",
    "MSComctlLib.ImageList",
    "MSComDlg.CommonDialog",
    "MSComctlLib.CommonDialog",
}

#: Class -> pid of the ``Visible`` property.  A hidden control writes
#: ``<pid> 0x00`` straight after the geometry value; the default (visible) is
#: not written at all, so absence means "default", not "known true".
#:
#: Calibrated against the ``Visible`` values of the calibration target's
#: ``.frm`` blocks with zero false positives where a rule is applied.  Classes
#: not listed (CommandButton, Image, PictureBox, Shape, OptionButton, ...) have
#: no usable marker and are left unknown.
VISIBLE_PID = {
    "VB.Frame": 0x0A,
    "VB.Label": 0x0A,
    "VB.ComboBox": 0x0A,
    "VB.CheckBox": 0x0A,
    "VB.TextBox": 0x09,
    "VB.ListBox": 0x09,
    "MSMask.MaskEdBox": 0x07,
    "MSComctlLib.ProgressBar": 0x07,
}

#: GUID signatures that separate an ``SSTab`` page title from the page's
#: control names in the record's property area (two byte orders are observed
#: in the wild; both are accepted).
SSTAB_SIGNATURES = (
    bytes.fromhex("52e30b918fce119de300aa004bb851"),
    bytes.fromhex("52e30b91918fce119de300aa004bb851"),
)

#: Record names are at most 64 bytes in practice; the upper bound keeps the
#: byte scan from matching arbitrary binary runs.
MAX_NAME_LEN = 64

#: How close to the end of a long record the trailing geometry candidate must
#: sit before it is preferred over the first candidate.  Records that embed an
#: image or OLE payload place the geometry after the payload, and the payload's
#: bytes can contain a pid byte followed by a plausible 4 x int16 by accident.
#: Calibrated on the reference target by sweeping the window and counting
#: geometry mismatches against ``.frm`` ground truth (see ``validate()``).
GEOM_TAIL_WINDOW = 192

_GUI_NAME_RE = re.compile(rb"[\x02-\x40]\x00[A-Za-z][A-Za-z0-9_]{1,40}\x00")


# --------------------------------------------------------------------------
# PE image access
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Section:
    """One PE section mapped into the file."""

    name: str
    virtual_address: int
    virtual_size: int
    raw_pointer: int
    raw_size: int

    @property
    def span(self) -> int:
        return max(self.virtual_size, self.raw_size)


def load_sections(path: str) -> tuple[bytes, tuple[Section, ...]]:
    """Return the whole file plus its PE section table.

    Raises :class:`ValueError` when the file has no sane PE header — the
    caller gets an explicit failure instead of an empty (and therefore
    ambiguous) result.
    """
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError(f"{path}: no MZ header, not a PE file")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise ValueError(f"{path}: no PE signature at 0x{e_lfanew:x}")
    coff = e_lfanew + 4
    nsec, = struct.unpack_from("<H", data, coff + 2)
    opt_size, = struct.unpack_from("<H", data, coff + 16)
    opt = coff + 20
    image_base, = struct.unpack_from("<I", data, opt + 28)
    sections = []
    for i in range(nsec):
        off = opt + opt_size + i * 40
        if off + 40 > len(data):
            raise ValueError(f"{path}: truncated section table")
        raw_name = data[off:off + 8].rstrip(b"\x00")
        v_size, v_addr, r_size, r_ptr = struct.unpack_from("<IIII", data, off + 8)
        sections.append(Section(raw_name.decode("latin-1"), image_base + v_addr,
                                v_size, r_ptr, r_size))
    return data, tuple(sections)


def read_va(data: bytes, sections, va: int, size: int) -> bytes | None:
    """Read ``size`` bytes at virtual address ``va`` (``None`` if unmapped)."""
    for sec in sections:
        if sec.virtual_address <= va < sec.virtual_address + sec.span:
            off = sec.raw_pointer + (va - sec.virtual_address)
            chunk = data[off:off + size]
            return chunk if len(chunk) == size else None
    return None


# --------------------------------------------------------------------------
# Blob discovery
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class FormBlob:
    """A form's design-time blob, already cut to its own segment."""

    name: str
    offset: int          # file offset of the record header
    size: int            # declared size field (measured: record length - 1; metadata only)
    data: bytes          # segment bytes: this form record up to the next one


def find_form_records(data: bytes) -> list[tuple[int, int, str, int]]:
    """Locate form records (class ``0x0D``) in a raw image.

    Returns ``[(record_start, name_pos, name, size)]``.  The scan matches the
    ``namelen``/``name``/``0x00`` shape anywhere in the file, then requires a
    plausible record header in front of it and the form class byte after it,
    so no section name or import table is assumed.  VB6 stores these blobs as
    plain data inside a code or data section depending on the linker.
    """
    out = []
    for m in _GUI_NAME_RE.finditer(data):
        name_pos = m.start()
        namelen, = struct.unpack_from("<H", data, name_pos)
        if namelen != len(m.group(0)) - 3:
            continue
        cls_p = m.end()
        if cls_p >= len(data) or data[cls_p] != 0x0D:
            continue
        start = None
        size = 0
        # Control-array header first (bit 31 set), then the plain header.
        if name_pos >= 7:
            word, = struct.unpack_from("<I", data, name_pos - 7)
            if word & 0x80000000:
                candidate = word & 0x7FFFFFFF
                if 8 <= candidate <= 0x7FFFFFFF:
                    start, size = name_pos - 7, candidate
        if start is None and name_pos >= 5:
            candidate, = struct.unpack_from("<I", data, name_pos - 5)
            if 8 <= candidate <= 0x7FFFFFFF:
                start, size = name_pos - 5, candidate
        if start is None or size < (cls_p - start) + 1:
            continue
        out.append((start, name_pos, m.group(0)[2:-1].decode("ascii"), size))
    return out


def iter_form_blobs(path: str) -> list[FormBlob]:
    """Return every form blob in ``path``, cut to the form's own segment.

    A blob may hold several form objects; a segment ends where the next form
    record starts, which is exactly the region this form's controls live in.
    The declared record ``size`` is used as an upper bound only — the segment
    boundary is the next form record, because nested form objects follow the
    parent record inside the same declared size.
    """
    data, _sections = load_sections(path)
    records = find_form_records(data)
    blobs = []
    for i, (start, _name_pos, name, size) in enumerate(records):
        # A form's region runs to the next form record.  The declared record
        # ``size`` is *not* a reliable length here (it is much smaller than the
        # region that holds the controls), so it is kept as metadata only.
        # Sibling objects living inside the region (DataReport blobs, see
        # ``_is_embedded_object``) are excluded when the records are parsed.
        if i + 1 < len(records):
            end = records[i + 1][0]
        else:
            end = len(data)
        blobs.append(FormBlob(name=name, offset=start, size=size,
                              data=data[start:end]))
    return blobs


# --------------------------------------------------------------------------
# Result types
# --------------------------------------------------------------------------
@dataclass
class Control:
    """One control recovered from a blob.

    ``index`` is the control-array index (``None`` for a plain control).
    ``visible`` is ``True``/``False`` only where a calibrated rule applies and
    the marker is present; ``None`` means unknown, never "visible".
    ``tab_page`` is the 1-based ``SSTab`` page for a control nested inside an
    ``SSTab``, ``None`` when the control is not a tab member.
    ``pages`` holds the page titles for an ``SSTab`` control itself.
    """

    name: str
    type: str
    caption: str | None
    left: int
    top: int
    width: int
    height: int
    index: int | None = None
    visible: bool | None = None
    pages: tuple[str, ...] = ()
    tab_page: int | None = None
    # Filled for SSTab controls only; consumed by extract_form, not exported.
    _sstab_members: dict[str, int] = field(default_factory=dict, repr=False,
                                           compare=False)

    @property
    def key(self) -> tuple[str, int | None]:
        """``(name, index)`` key that identifies a control inside its form."""
        return (self.name, self.index)

    def geometry(self) -> tuple[int, int, int, int]:
        return (self.left, self.top, self.width, self.height)


@dataclass
class Form:
    """A parsed form."""

    name: str
    controls: list[Control] = field(default_factory=list)
    width: int | None = None
    height: int | None = None
    client_left: int | None = None
    client_top: int | None = None


@dataclass
class ValidationReport:
    """Coverage of the parser against ``.frm`` ground truth.

    Every count carries its denominator.  ``forms_total`` counts the ``.frm``
    files that yielded a design block; ``forms_matched`` counts those where
    every ground-truth control matched on type and geometry and no extra
    control was produced.  ``forms_without_blob`` and ``forms_without_records``
    name the forms that could not be compared at all, so a low denominator is
    visible instead of silently absorbed.
    """

    blob_count: int = 0
    truth_forms: int = 0
    forms_matched: int = 0
    controls_total: int = 0
    controls_matched: int = 0
    client_size_total: int = 0
    client_size_matched: int = 0
    visible_checked: int = 0
    visible_matched: int = 0
    visible_false_positive: int = 0
    sstab_members_checked: int = 0
    sstab_members_matched: int = 0
    ground_truth_available: bool = False
    forms_without_blob: list[tuple[str, int]] = field(default_factory=list)
    forms_without_records: list[tuple[str, int]] = field(default_factory=list)
    form_mismatches: list[tuple[str, int, int]] = field(default_factory=list)
    field_diffs: Counter = field(default_factory=Counter)

    @property
    def control_rate(self) -> float:
        return 100.0 * self.controls_matched / self.controls_total if self.controls_total else 0.0

    @property
    def form_rate(self) -> float:
        return 100.0 * self.forms_matched / self.truth_forms if self.truth_forms else 0.0

    def summary(self) -> str:
        lines = [
            f"blobs: {self.blob_count}   ground-truth forms: {self.truth_forms}",
            f"controls matched: {self.controls_matched}/{self.controls_total} "
            f"= {self.control_rate:.2f}%  (type + Left/Top/Width/Height)",
            f"forms fully matched: {self.forms_matched}/{self.truth_forms} = {self.form_rate:.2f}%",
        ]
        if self.client_size_total:
            lines.append(f"client size matched: {self.client_size_matched}/{self.client_size_total}")
        if self.visible_checked:
            lines.append(
                f"visible: {self.visible_matched}/{self.visible_checked} matched, "
                f"{self.visible_false_positive} hidden-claims wrong (FP)")
        if self.sstab_members_checked:
            lines.append(f"sstab members: {self.sstab_members_matched}/"
                         f"{self.sstab_members_checked}")
        if self.field_diffs:
            lines.append(f"field diffs: {self.field_diffs.most_common(10)}")
        if not self.ground_truth_available:
            lines.append("no .frm directory given — coverage NOT measured")
        if self.forms_without_blob:
            lines.append(f"no blob found: {len(self.forms_without_blob)} "
                         f"{[n for n, _ in self.forms_without_blob[:10]]}")
        if self.forms_without_records:
            lines.append(f"blob but no control records: {len(self.forms_without_records)} "
                         f"{[n for n, _ in self.forms_without_records[:10]]}")
        if self.form_mismatches:
            lines.append(f"form mismatches: {len(self.form_mismatches)}, first 10: "
                         f"{self.form_mismatches[:10]}")
        return "\n".join(lines)


# --------------------------------------------------------------------------
# Primitive readers
# --------------------------------------------------------------------------
def read_str(b: bytes, p: int) -> tuple[str | None, int]:
    """Read ``<len16> <bytes> 0x00`` as CP1254; ``(None, p)`` if not one."""
    if p + 2 > len(b):
        return None, p
    n, = struct.unpack_from("<H", b, p)
    if n == 0 or n > 255 or p + 3 + n > len(b):
        return None, p
    raw = b[p + 2:p + 2 + n]
    if b[p + 2 + n] != 0x00:
        return None, p
    if any(c < 0x20 and c != 0x09 for c in raw):
        return None, p
    return raw.decode("cp1254", "replace"), p + 3 + n


def read_utf16(b: bytes, p: int) -> tuple[str | None, int]:
    """Read a UTF-16LE string with a byte-length prefix (``SSTab`` page data)."""
    if p + 2 > len(b):
        return None, p
    n, = struct.unpack_from("<H", b, p)
    if n < 2 or n > 400 or n % 2 or p + 2 + n > len(b):
        return None, p
    try:
        text = b[p + 2:p + 2 + n].decode("utf-16-le")
    except UnicodeDecodeError:
        return None, p
    if not text or any(ord(ch) < 0x20 and ch != "\t" for ch in text):
        return None, p
    return text, p + 2 + n


def plausible(geo) -> bool:
    """Sanity bounds for a geometry tuple.

    Left/Top may be negative (frames, scrolled containers); sizes must be
    positive.  The limits are far outside any real form and only reject
    offsets that landed in unrelated bytes.
    """
    left, top, width, height = geo
    return (-400000 <= left <= 400000 and -400000 <= top <= 400000
            and 0 < width <= 100000 and 0 < height <= 100000)


# --------------------------------------------------------------------------
# Record scanning
# --------------------------------------------------------------------------
def record_starts(b: bytes) -> list[tuple[int, str, int, int | None]]:
    """Find control-record starts structurally inside a blob.

    Returns ``[(name_pos, name, class_pos, array_index)]`` where ``name_pos`` is
    the offset of the ``namelen`` field.  The walk is byte-by-byte on purpose:
    record lengths are not chained reliably (control arrays and OCX records do
    not always agree with their ``size`` field), so the shape of the header is
    the evidence.
    """
    out = []
    n = len(b)
    p = 0
    while p < n - 8:
        namelen, = struct.unpack_from("<H", b, p)
        if 2 <= namelen <= MAX_NAME_LEN and p + 2 + namelen + 1 < n:
            raw = b[p + 2:p + 2 + namelen]
            if (raw[:1].isalpha() and all(0x30 <= c <= 0x7A or c == 0x5F for c in raw)
                    and b[p + 2 + namelen] == 0x00):
                size = None
                index = None
                if p >= 7:
                    word, = struct.unpack_from("<I", b, p - 7)
                    if word & 0x80000000:
                        size = word & 0x7FFFFFFF
                        index, = struct.unpack_from("<H", b, p - 2)
                if size is None and p >= 5:
                    size, = struct.unpack_from("<I", b, p - 5)
                if size is not None and 8 <= size <= 60000:
                    cls_p = p + 3 + namelen
                    if cls_p < n:
                        out.append((p, raw.decode("ascii"), cls_p, index))
                        p = cls_p
                        continue
        p += 1
    return out


def _geometry(b: bytes, start: int, end: int, gpid: int):
    """Find the geometry property at/after ``start``.

    Returns ``(values, value_pos, wide)`` or ``None``.  Three passes, measured:
    a narrow window after the caption (covers the vast majority of controls),
    then the whole record with the post-geometry pid check, then the whole
    record without it (records whose next property is unusual or absent).
    """
    for limit, need_post in ((start + 64, True), (end, True), (end, False)):
        candidates = []
        last_q = -1
        for q in range(start, min(limit, end) - 8):
            if b[q - 1] != gpid:
                continue
            wide = None
            if b[q] == 0x00 and b[q + 1] == 0x80 and q + 18 <= len(b):
                as32 = struct.unpack_from("<iiii", b, q + 2)
                if plausible(as32) and any(abs(v) > 32767 for v in as32[:2]):
                    wide = as32
            if wide is not None:
                if need_post and b[q + 18] not in POST_PIDS:
                    continue
                candidates.append((wide, q, True))
                last_q = q
                continue
            cand = struct.unpack_from("<hhhh", b, q)
            if need_post and b[q + 8] not in POST_PIDS:
                continue
            if plausible(cand):
                candidates.append((cand, q, False))
                last_q = q
        if candidates:
            # Embedded image/OLE data before the geometry pushes the real
            # property towards the end of a long record; when the first
            # candidate is far from both ends, prefer the trailing one.
            chosen = candidates[0]
            if len(candidates) > 1 and (end - start) > 500 and (end - last_q) <= GEOM_TAIL_WINDOW:
                chosen = candidates[-1]
            return chosen
    return None


def _sstab_has_signature(b: bytes, p: int, window: int = 48) -> bool:
    return any(sig in b[p:p + window] for sig in SSTAB_SIGNATURES)


def sstab_region(b: bytes, start: int, end: int) -> tuple[list[str], dict[str, int]]:
    """Return ``(page_titles, {control_name: page_number})`` for one SSTab.

    A page title is a UTF-16 string immediately followed by a GUID signature;
    UTF-16 identifiers without a signature are controls on the current page.
    Page numbers are 1-based to match the ``SSTab.Tab`` semantics.  Reading
    stops at the end of the control's record.
    """
    pages: list[str] = []
    members: dict[str, int] = {}
    current = -1
    p = start
    while p < end:
        text, nxt = read_utf16(b, p)
        if text is None:
            p += 1
            continue
        if _sstab_has_signature(b, nxt):
            current += 1
            pages.append(text)
            p = nxt
            continue
        if current >= 0 and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,40}", text):
            members.setdefault(text, current + 1)
        p = nxt if nxt > p else p + 1
    return pages, members


def _is_embedded_object(type_name: str) -> bool:
    """True for records that are sibling objects, not controls of the form.

    A DataReport is compiled into the same data region as the forms; its record
    carries class ``0xFF`` and a runtime class name whose leaf is
    ``DataReport...``.  It has no Left/Top/Width/Height and is not declared in
    the form's ``.frm``, so emitting it would invent a control.  The same test
    covers the non-visual classes listed in :data:`SKIP_TYPES`.
    """
    if type_name in SKIP_TYPES:
        return True
    return type_name.rsplit(".", 1)[-1].startswith("DataReport")


def _parse_control(b: bytes, name: str, cls_p: int, hdr_index: int | None,
                   end: int) -> Control | None:
    """Decode one control record; ``None`` when it carries no recoverable geometry."""
    cls_byte = b[cls_p]
    p = cls_p + 1
    if cls_byte == 0xFF:
        type_name, p = read_str(b, p)
        if type_name is None:
            return None
    else:
        type_name = CLASS_NAME.get(cls_byte)
        if type_name is None:
            return None
    if _is_embedded_object(type_name):
        return None

    gpid = GEOM_PID.get(type_name, GEOM_PID_OCX)
    caption = None

    # pid 0x01 is Caption on a plain control and decodes as a string; on an
    # array element the same slot can hold the index as a uint16, hence the
    # 3-byte skip when no string shape matches.
    if p < len(b) and b[p] == 0x01:
        cap, nxt = read_str(b, p + 1)
        if cap is not None:
            caption = cap
            p = nxt
        elif p + 3 < len(b):
            p += 3
    # pid 0x02 = Index (uint16); it follows the caption on array elements.
    if (p + 4 < len(b) and b[p] == 0x02 and b[p + 3] == gpid
            and plausible(struct.unpack_from("<hhhh", b, p + 4))):
        p += 3

    found = _geometry(b, p, end, gpid)
    if found is None:
        return None
    (left, top, width, height), geo_pos, wide = found

    # Visible marker sits directly after the geometry value.
    visible: bool | None = None
    rule_pid = VISIBLE_PID.get(type_name)
    post = geo_pos + (16 if wide else 8)
    if rule_pid is not None and post + 1 < len(b):
        if b[post] == rule_pid and b[post + 1] == 0x00:
            visible = False

    pages: tuple[str, ...] = ()
    members: dict[str, int] = {}
    if type_name.rsplit(".", 1)[-1] == "SSTab":
        pages, members = sstab_region(b, post, min(end, len(b)))
        pages = tuple(pages)

    # Page membership is resolved by the caller, which owns the sibling list.
    return Control(name=name, type=type_name, caption=caption, left=left, top=top,
                   width=width, height=height, index=hdr_index, visible=visible,
                   pages=pages, _sstab_members=members)


def _form_client_size(b: bytes, name_pos: int, end: int) -> tuple[int, int, int, int] | None:
    """Recover ``(ClientLeft, ClientTop, ClientWidth, ClientHeight)``.

    The form record writes pid ``0x35`` followed by four int32 values in that
    order.  Bounds are measured from real forms: client left/top 0..20000,
    width/height 200..30000 twips.  Reads as "the first int is a block length"
    match only part of the forms, which is why all four values are required to
    look sane before the block is accepted.
    """
    for p in range(max(0, name_pos), min(end, len(b)) - 17):
        if b[p] != 0x35:
            continue
        left, top, width, height = struct.unpack_from("<iiii", b, p + 1)
        if (0 <= left <= 20000 and 0 <= top <= 20000
                and 200 <= width <= 30000 and 200 <= height <= 30000):
            return (left, top, width, height)
    return None


# --------------------------------------------------------------------------
# Blob -> Form
# --------------------------------------------------------------------------
def extract_form(blob: FormBlob) -> Form | None:
    """Parse one blob into a :class:`Form`; ``None`` if no records are found."""
    b = blob.data
    starts = record_starts(b)
    if not starts:
        return None

    # Segment selection: a blob cut at the next form record normally holds a
    # single segment, but a caller may pass an uncut blob (several form
    # objects).  Keep the segment whose form record carries this blob's name.
    own = None
    seg_start, seg_end = 0, len(b)
    for i, (p, name, cls_p, _idx) in enumerate(starts):
        if b[cls_p] != 0x0D:
            continue
        if own is None and name == blob.name:
            own, seg_start = i, p
        elif own is not None and i > own:
            seg_end = p
            break
    if own is None:
        seg_start, seg_end = 0, len(b)

    controls: list[Control] = []
    for i, (p, name, cls_p, idx) in enumerate(starts):
        if not seg_start <= p < seg_end:
            continue
        end = starts[i + 1][0] if i + 1 < len(starts) else len(b)
        end = min(end, seg_end)
        ctrl = _parse_control(b, name, cls_p, idx, end)
        if ctrl is not None:
            controls.append(ctrl)

    # Attach SSTab page membership to the sibling controls.
    for tab in controls:
        members = getattr(tab, "_sstab_members", None)
        if not members:
            continue
        by_name = {}
        for ctrl in controls:
            by_name.setdefault(ctrl.name, ctrl)
        for member_name, page in members.items():
            target = by_name.get(member_name)
            if target is not None and target is not tab:
                target.tab_page = page

    name_pos = starts[own][0] if own is not None else 0
    size = _form_client_size(b, name_pos, seg_end)
    form = Form(name=blob.name, controls=controls,
                width=size[2] if size else None,
                height=size[3] if size else None,
                client_left=size[0] if size else None,
                client_top=size[1] if size else None)
    return form


def extract_forms(path: str) -> list[Form]:
    """Parse every form blob in ``path`` (one :class:`Form` per blob)."""
    forms = []
    for blob in iter_form_blobs(path):
        form = extract_form(blob)
        if form is not None:
            forms.append(form)
    return forms


# --------------------------------------------------------------------------
# .frm ground truth
# --------------------------------------------------------------------------
_RE_BEGIN = re.compile(r"^(\s*)Begin\s+([\w.]+)\s+([\w]+)\s*$")
_RE_PROP = re.compile(r"^(\s*)(\w+)\s*=\s*(-?\d+|\"[^\"]*\")\s*$")


def _strip_comment(line: str) -> str:
    """Drop a trailing ``' comment`` without touching apostrophes in strings.

    ``.frm`` properties often carry ``Visible =   0   'True``; the value regex
    is anchored, so the comment must go first.  A ``'`` inside a quoted value
    ("Budget's") is not a comment and is preserved.
    """
    in_string = False
    for i, ch in enumerate(line):
        if ch == '"':
            in_string = not in_string
        elif ch == "'" and not in_string:
            return line[:i]
    return line


@dataclass
class TruthControl:
    """A control from ``.frm`` design text."""

    name: str
    type: str
    left: int
    top: int
    width: int
    height: int
    caption: str | None = None
    index: int | None = None
    visible: int | None = None
    parent: str | None = None


def parse_frm(path: str) -> tuple[str | None, list[TruthControl], dict | None]:
    """Parse the design block of a ``.frm`` file.

    Returns ``(form_name, controls, form_props)``.  Only controls that declare
    all of Left/Top/Width/Height are returned, mirroring what the blob schema
    can represent (lines, timers and menus are out of scope on both sides).
    The nesting stack gives each control its parent, which is what ``SSTab``
    membership is derived from.
    """
    stack: list[dict] = []
    flat: list[dict] = []
    form_name = None
    form_props: dict | None = None
    with open(path, encoding="cp1254", errors="replace") as fh:
        for raw_line in fh:
            if raw_line.startswith("Attribute VB_Name"):
                break
            line = _strip_comment(raw_line)
            m = _RE_BEGIN.match(line)
            if m:
                node = {"name": m.group(3), "type": m.group(2), "props": {},
                        "parent": stack[-1]["name"] if stack else None}
                stack.append(node)
                if len(stack) == 1 and m.group(2).endswith("Form"):
                    form_name, form_props = m.group(3), node["props"]
                continue
            if line.strip() == "End":
                if stack:
                    flat.append(stack.pop())
                continue
            mp = _RE_PROP.match(line)
            if mp and stack:
                value = mp.group(3)
                stack[-1]["props"][mp.group(2)] = (
                    value[1:-1] if value.startswith('"') else int(value))

    controls = []
    for node in flat:
        props = node["props"]
        if node["type"].endswith("Form"):
            continue
        if not all(k in props for k in ("Left", "Top", "Width", "Height")):
            continue
        caption = props.get("Caption")
        controls.append(TruthControl(
            name=node["name"], type=node["type"],
            left=props["Left"], top=props["Top"],
            width=props["Width"], height=props["Height"],
            caption=caption if isinstance(caption, str) else None,
            index=props.get("Index"), visible=props.get("Visible"),
            parent=node["parent"]))
    return form_name, controls, form_props


def _sstab_truth(controls: list[TruthControl]) -> dict[str, dict[str, int]]:
    """``{sstab_name: {direct_member_name: 1}}`` from a flat ``.frm`` list.

    Only controls whose parent *is* the ``SSTab`` count: a ``Frame`` placed on a
    page owns its own children, and the blob lists the frame, not the frame's
    children, in the ``SSTab`` record.  Page numbers are not compared — the
    design block does not spell them out per control, and the blob's page order
    is the only source for that.
    """
    tabs = {c.name for c in controls if c.type.rsplit(".", 1)[-1] == "SSTab"}
    out: dict[str, dict[str, int]] = {t: {} for t in tabs}
    for ctrl in controls:
        if ctrl.parent in tabs:
            out[ctrl.parent][ctrl.name] = 1
    return out


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------
def validate(exe_path: str, frm_dir: str | None = None) -> ValidationReport:
    """Measure the parser against ``.frm`` ground truth.

    ``frm_dir`` is the directory holding the ``.frm`` design text of the same
    build.  When it is ``None`` only the blob side is reported (blob and form
    counts, no coverage percentage) — a missing ground truth is reported as
    missing, not as a pass.

    Comparison is per control on ``(name, index)``, case-insensitive because
    VB identifiers are; the compared fields are type and the four geometry
    values.  Captions are counted as a separate diff so a caption mismatch
    cannot hide a correct geometry.
    """
    report = ValidationReport()
    blobs = iter_form_blobs(exe_path)
    report.blob_count = len(blobs)

    by_name: dict[str, list[FormBlob]] = defaultdict(list)
    for blob in blobs:
        by_name[blob.name.lower()].append(blob)

    report.ground_truth_available = frm_dir is not None
    if frm_dir is None:
        return report

    parsed = {}
    for path in sorted(glob.glob(os.path.join(frm_dir, "*.frm"))):
        name, ctrls, props = parse_frm(path)
        if name and ctrls:
            parsed[name.lower()] = (name, ctrls, props)

    report.truth_forms = len(parsed)
    report.ground_truth_available = True
    for key, (name, truth, props) in sorted(parsed.items()):
        candidates = by_name.get(key)
        if not candidates:
            report.forms_without_blob.append((name, len(truth)))
            continue
        form = None
        for blob in sorted(candidates, key=lambda x: len(x.data), reverse=True):
            candidate = extract_form(blob)
            if candidate and candidate.controls:
                form = candidate
                break
        if form is None or not form.controls:
            report.forms_without_records.append((name, len(truth)))
            continue

        got: dict[tuple[str, int | None], Control] = {}
        for ctrl in form.controls:
            got.setdefault((ctrl.name.lower(), ctrl.index), ctrl)

        bad = 0
        for truth_ctrl in truth:
            ctrl = got.get((truth_ctrl.name.lower(), truth_ctrl.index))
            if ctrl is None:
                report.field_diffs["control missing"] += 1
                bad += 1
                continue
            for name_field in ("type", "left", "top", "width", "height"):
                if getattr(ctrl, name_field) != getattr(truth_ctrl, name_field):
                    report.field_diffs[name_field] += 1
            if (truth_ctrl.caption is not None
                    and ctrl.caption != truth_ctrl.caption):
                report.field_diffs["caption"] += 1
            if truth_ctrl.visible is not None:
                # The blob rule only ever claims "hidden"; a claim on a control
                # the .frm says is visible is a false positive and is counted
                # separately so the rule can be pruned per class.
                report.visible_checked += 1
                if truth_ctrl.visible == 0:
                    if ctrl.visible is False:
                        report.visible_matched += 1
                elif ctrl.visible is False:
                    report.visible_false_positive += 1
            if all(getattr(ctrl, f) == getattr(truth_ctrl, f)
                   for f in ("type", "left", "top", "width", "height")):
                report.controls_matched += 1
            else:
                bad += 1
        report.controls_total += len(truth)

        extra = len(form.controls) - len(truth)
        if extra > 0:
            report.field_diffs["extra records"] += extra
        if bad == 0 and extra <= 0:
            report.forms_matched += 1
        else:
            report.form_mismatches.append((name, len(form.controls), len(truth)))

        # Client rectangle, only for forms whose .frm declares it.
        if props is not None and "ClientWidth" in props and "ClientHeight" in props:
            report.client_size_total += 1
            if (form.width == props["ClientWidth"]
                    and form.height == props["ClientHeight"]):
                report.client_size_matched += 1
            for attr, prop in (("client_left", "ClientLeft"),
                               ("client_top", "ClientTop")):
                if prop in props and getattr(form, attr) != props[prop]:
                    report.field_diffs["client " + prop] += 1

        # SSTab membership (names only; page numbers need nesting detail the
        # design block does not spell out for pages after the first).
        truth_tabs = _sstab_truth(truth)
        for tab in form.controls:
            if not tab.pages or tab.name not in truth_tabs:
                continue
            expected = set(truth_tabs[tab.name])
            members = {c.name for c in form.controls
                       if c.tab_page is not None and c.name in expected}
            report.sstab_members_checked += len(expected)
            report.sstab_members_matched += len(members)
    return report


def main(argv: list[str] | None = None) -> int:
    """Command line entry: ``python -m vb6decompiler.blob EXE [--frm DIR]``.

    ``--validate`` and ``--frm-dir`` are accepted as aliases so this module and
    ``vb6d blob`` take the same flags; a tool with two spellings for one thing is a
    trap for whoever reads the docs next.
    """
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("exe", help="path to the VB6 executable")
    parser.add_argument("--frm", "--frm-dir", dest="frm", default=None,
                        help="directory with the matching .frm files (ground truth)")
    parser.add_argument("--validate", action="store_true",
                        help="accepted for parity with `vb6d blob`; validation is the default")
    parser.add_argument("--list", action="store_true",
                        help="print one line per form instead of the report")
    args = parser.parse_args(argv)

    if args.list:
        for form in extract_forms(args.exe):
            print(f"{form.name}\t{len(form.controls)}\t{form.width}x{form.height}")
        return 0
    report = validate(args.exe, args.frm)
    print(report.summary())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "CLASS_NAME", "GEOM_PID", "GEOM_PID_OCX", "POST_PIDS", "SKIP_TYPES",
    "VISIBLE_PID", "SSTAB_SIGNATURES", "Section", "FormBlob", "Control", "Form",
    "ValidationReport", "TruthControl", "load_sections", "read_va",
    "find_form_records", "iter_form_blobs", "record_starts", "read_str",
    "read_utf16", "plausible", "sstab_region", "extract_form", "extract_forms",
    "parse_frm", "validate", "main",
]
