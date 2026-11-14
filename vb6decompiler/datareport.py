"""DataReport designs (``MSDataReportRuntimeLib.DataReport``) inside VB6 report DLLs.

What this recovers, and what it does not
----------------------------------------
A VB6 DataReport designer object is compiled into the host DLL as a *design blob*
next to the object table entry. The blob is not a ``.dsr`` text file and it is not
the same grammar as an ordinary form blob: it is a serialised property stream with
its own string encoding. This module walks that stream and returns, per design, the
ordered list of records (sections and controls) with whatever geometry the stream
actually stores.

It does **not** recover:

* ``DataField`` / ``DataMember`` — not present in the blob at all; the program
  assigns them from code at run time.
* Fonts and GUID blocks — a separate ``len8 + CP1254`` region, outside the layout.
* Any geometry VB6 chose not to serialise (see the property rules below). Those
  fields stay ``None``. An absent integer is reported as unknown, never as 0.

Measured grammar (413 designs, 8 report DLLs of one shipping VB6 install)
------------------------------------------------------------------------
1. **Strings are ``len32 + UTF-16LE``.** The form-blob grammar
   (``len16 + CP1254 + 0x00``, see :mod:`vb6decompiler.blob`) finds *nothing* here;
   feeding a DataReport blob to that reader yields zero records.
2. **A string whose character count is odd is followed by a ``00 00`` alignment
   pad** (measured on 15,032 of 15,120 odd-length events). The scanner must advance
   one byte at a time and resynchronise; a four-byte stride reads the pad as the top
   half of the next length and loses every following event. The pad is not cosmetic:
   dropping it shifts every property array that follows by two bytes, after which
   7,639 of 14,592 "full" records carry a coordinate above 400,000 twips, against 10
   of 13,032 with the pad. It is applied only when the two bytes really are zero, so
   the 88 events without a pad still parse.
3. **Name versus caption is decided by the target's naming convention**, not by
   the property stream: a record name matches
   ``lbl*/txt*/fun*/Label*/Line*/Shape*/Image*`` (DataReport report controls) and a
   section record is ``SectionN``. Everything else is a caption.
4. **A caption is the string immediately after the control's name** and only when
   that string is neither a section nor another control name. VB6 does not
   serialise a property equal to its default, so an empty ``Caption`` is written as
   the control's *own* name repeated. That repetition is kept verbatim in
   ``caption`` and flagged by :attr:`Record.caption_is_default`; it is never
   rewritten into an empty string, and it is never treated as a caption the
   designer wrote.
5. **Properties after the name are plain int32s, up to the next string event.**
   When four or more are present the first four are ``Left, Top, Width, Height``.
   Because of rule 6 some records are shorter; the measured discriminators are
   ``150 <= dword <= 300`` (a font height, ~225 twips) and ``dword in 1..4`` (a
   small enum such as ``Alignment``).
6. **T (and sometimes W) are genuinely missing.** VB6 omits properties equal to the
   default, so two shorter layouts appear:

   * ``(L, W, H, X)`` — ``dword[2]`` is 150..300 and ``dword[3]`` is 1..4. ``Top``
     was not serialised.
   * ``(L, H, X, Y)`` — ``dword[1]`` is 150..300 and ``dword[2]`` is 1..4. Both
     ``Top`` and ``Width`` were not serialised. Measured on 62 records; every one
     of them had ``dword[1] == 225``.

   ``Top`` is filled in **only** where the design itself proves the value: the
   modal ``Top`` of that design's *complete* Detail records (measured mode = 30
   twips). Such a value is flagged as inferred (``top_inferred``) so a consumer can
   tell it apart from a stored one. ``Width`` is never inferred by this module.
7. **Section ownership is positional.** A control belongs to the last section record
   that precedes it. Controls per section, measured over all 437 designs:
   ``Section1`` 4,293 (2,016 ``txt`` + 1,853 ``Text`` data boxes), ``Section2``
   11,890 (4,980 ``Label*``; the page-number fields ``%p``/``%P`` and the page caption
   land here), ``Section3`` **27**, ``Section4`` 136 (66 ``Line`` rules plus the
   company name), ``Section5`` 2,979 (219 captioned totals). The roles follow VB6's
   creation order and the content agrees for four of the five. ``Section3`` =
   PageFooter is the weak one and stays labelled as a default, not a finding: 22 of
   its 27 controls are ``lblNote*`` labels and 20 of them carry a blank caption, and
   the only role-revealing name in the whole corpus is a control called
   ``lblPageEnd`` ("page end") in one report DLL. ``Section1`` measured 227 twips
   high in 329 designs (one text line), and every one of the 413 designs carries all
   five section records.
8. **The design's record extent is self-describing.** The record starts five bytes
   before the ``len16`` name length: ``<size:int32> <idx:uint8> <namelen:uint16>
   <name> 0x00 <class:0xFF> <len16 class name>``. Checked against the designer blobs
   of a VB6 structure dump on 413/413 designs: the ``size`` field is the record's own
   length, the record ends nine bytes before the blob's end, and a 98-byte designer
   header sits in front of it. Scanning the record alone yields the same string
   events as scanning the whole blob, so no blob extent has to be guessed.
9. **A design name is not a design.** Locating designs by the class-name bytes
   alone yields two false positives in every DLL — the class name also occurs in the
   type-library/import region without a record header. The five bytes before the
   name length must agree, otherwise the hit is dropped.
10. **Join key is (file, design name).** Six design names occur in two DLLs with
    different evidence; a dict keyed by name alone silently overwrites one of them.
    :func:`read_paths` keeps every design and :func:`key` exposes the composite key.

Usage::

    python -m vb6decompiler.datareport --validate "C:/path/to/report/dlls"
    python -m vb6decompiler.datareport --csv out.csv rptOrders.dll
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import struct
import sys
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Iterator, Sequence

from . import pe

#: Exact class name of a DataReport designer object in a compiled VB6 binary.
#: Measured byte-for-byte; it is the only reliable anchor for a design record.
DATAREPORT_CLASS = "MSDataReportRuntimeLib.DataReport"

#: Section records. VB6 names them ``SectionN`` in creation order.
SECTION_RE = re.compile(r"^Section\d+$")

#: VB6's default DataReport section roles, confirmed by the content of each block
#: on this target (see rule 7 in the module docstring).
SECTION_ROLE = {
    "Section1": "Detail",
    "Section2": "PageHeader",
    "Section3": "PageFooter",
    "Section4": "rptHeader",
    "Section5": "rptFooter",
}

#: Control-name prefixes of the target's reporting convention. Kept verbatim from
#: the calibration run: the list is what the designer actually produced
#: (``lbl``/``txt`` report fields, ``fun``/``Text`` totals, ``Line``/``Shape``
#: rules, ``Image`` logos). A name outside this list is treated as a caption.
CONTROL_NAME_RE = re.compile(
    r"^(lbl|txt|fun|Text|Function|Line|Shape|Label|Image|Img|shp|lin|chk)\w*$"
)

#: String length limits for ``len32 + UTF-16LE`` events. 200 characters is well
#: above the longest real caption (~60) and low enough that random bytes inside
#: embedded GUID/font blocks fail the range test immediately.
STRING_MIN_CHARS = 1
STRING_MAX_CHARS = 200

#: Font height window used to recognise the sparse property layouts (rule 6).
#: Calibrated on this target: the text height is 225 twips for the shipped fonts,
#: 150..300 covers every font the reports use and excludes real ``Left``/``Top``
#: values, which start above 400.
FONT_HEIGHT_MIN = 150
FONT_HEIGHT_MAX = 300

#: Small-enum window for the trailing dword of a sparse property array
#: (``Alignment``/``Visible``-style flags: measured values 1..4 only).
SMALL_ENUM = (1, 2, 3, 4)

#: A property array longer than this is not a property array. The string scanner
#: skipped a character (usually inside an embedded picture) and the int32s are
#: payload, not properties. Such a record is reported with ``geometry="unreliable"``
#: and no coordinates rather than with invented ones.
MAX_PROPERTY_INTS = 8

#: VB6's default name for the Detail band. Only Detail records get an inferred
#: ``Top`` (see :func:`_classify_geometry`).
DETAIL_SECTION = "Section1"

#: Bytes of a design record header in front of the ``len16`` name length:
#: ``<size:int32> <idx:uint8>``. Measured from the record's size field back to the
#: record start; used to rewrite a located offset into a VA.
_RECORD_HDR_BYTES = 5


# ---------------------------------------------------------------------------
# data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Record:
    """One string event of a design, with the property array that follows it.

    ``kind`` is ``"section"``, ``"control"`` or ``"value"`` (an orphan string that
    followed neither a control name nor a section — normally a caption whose control
    name the scanner could not classify; kept so nothing is silently dropped).
    """

    index: int
    kind: str
    name: str
    caption: str
    section: str
    section_role: str
    left: int | None = None
    top: int | None = None
    width: int | None = None
    height: int | None = None
    geometry: str = "none"
    top_inferred: bool = False
    ints: tuple[int, ...] = ()
    offset: int = 0
    end: int = 0

    @property
    def is_control(self) -> bool:
        return self.kind == "control"

    @property
    def has_full_geometry(self) -> bool:
        """All four coordinates are *known*, i.e. none of them is inferred."""
        return None not in (self.left, self.top, self.width, self.height) and not self.top_inferred

    @property
    def caption_is_default(self) -> bool:
        """True when the "caption" is the control's own name repeated.

        VB6 does not serialise a property equal to its default, so an empty
        ``Caption`` is written as the name again. The raw repetition stays in
        :attr:`caption` (nothing is invented); this flag is how a caller learns that
        the ``.dsr`` caption is empty.
        """
        return bool(self.caption) and self.caption == self.name

    def as_dict(self) -> dict:
        return {
            "index": self.index,
            "kind": self.kind,
            "name": self.name,
            "caption": self.caption,
            "section": self.section,
            "section_role": self.section_role,
            "left": self.left,
            "top": self.top,
            "width": self.width,
            "height": self.height,
            "geometry": self.geometry,
            "top_inferred": self.top_inferred,
            "int_count": len(self.ints),
            "ints": " ".join(str(v) for v in self.ints),
            "offset": hex(self.offset),
            "end": hex(self.end),
        }


@dataclass(frozen=True)
class Design:
    """One DataReport design: a report class plus its parsed records.

    ``va`` is the virtual address of the record's *size field* (the start of the
    record), not of the designer blob that encloses it: a 98-byte designer header
    precedes it and nine bytes follow it. ``header_fields`` are the two int32s
    immediately before the size field, recorded but not interpreted — on the
    measured target the second one equals the width that a VB6 structure dump
    reports for the same design.
    """

    name: str
    path: str
    class_name: str
    va: int
    size: int
    header_fields: tuple[int, int]
    records: tuple[Record, ...] = ()

    @property
    def key(self) -> tuple[str, str]:
        """Composite join key.

        *(lower-cased file name, design name)* — rule 10: six names in this target
        appear in two DLLs, so the file has to be part of the key.
        """
        return (os.path.basename(self.path).lower(), self.name)

    @property
    def sections(self) -> tuple[Record, ...]:
        return tuple(r for r in self.records if r.kind == "section")

    @property
    def controls(self) -> tuple[Record, ...]:
        return tuple(r for r in self.records if r.kind == "control")

    @property
    def values(self) -> tuple[Record, ...]:
        return tuple(r for r in self.records if r.kind == "value")

    def section_heights(self) -> dict[str, int | None]:
        return {r.name: r.height for r in self.sections}

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "path": self.path,
            "class": self.class_name,
            "va": hex(self.va),
            "size": self.size,
            "header_fields": list(self.header_fields),
            "records": [r.as_dict() for r in self.records],
        }


@dataclass(frozen=True)
class DesignHead:
    """A located design record before its string events are parsed."""

    name: str
    va: int
    size: int
    offset: int
    header_fields: tuple[int, int]


# ---------------------------------------------------------------------------
# string events: len32 + UTF-16LE
# ---------------------------------------------------------------------------


def _read_string(buf: bytes, pos: int) -> tuple[str, int] | None:
    """Read a ``len32 + UTF-16LE`` string at ``pos``.

    Returns ``(text, end)`` or ``None`` when the bytes at ``pos`` are not a string.
    The sanity test is deliberately cheap and strict: every character must have a
    zero (or ``0x01``) high byte — GUIDs, font tables and code bytes fail it.
    """
    if pos + 4 > len(buf):
        return None
    n_chars = struct.unpack_from("<I", buf, pos)[0]
    if not (STRING_MIN_CHARS <= n_chars <= STRING_MAX_CHARS):
        return None
    end_of_chars = pos + 4 + 2 * n_chars
    if end_of_chars > len(buf):
        return None
    raw = buf[pos + 4:end_of_chars]
    for i in range(n_chars):
        lo, hi = raw[2 * i], raw[2 * i + 1]
        if hi == 0 and not (0x20 <= lo <= 0xFE or lo == 0x09):
            return None  # control byte: not text
        if hi > 0x01:
            return None  # not a Latin-1-ish UTF-16 code unit
    try:
        text = raw.decode("utf-16-le")
    except UnicodeDecodeError:  # pragma: no cover - defensive
        return None
    end = end_of_chars
    if n_chars % 2 == 1 and buf[end:end + 2] == b"\x00\x00":
        # Alignment pad after an odd character count (rule 2). Without this the
        # next length is read 16 bits too late and the rest of the design is lost.
        end += 2
    return text, end


def iter_string_events(buf: bytes) -> Iterator[tuple[int, str, int]]:
    """Yield ``(offset, text, end)`` for every string event in ``buf``.

    Byte-by-byte resynchronisation is mandatory: an event that starts inside the
    padding of the previous one is not a 4-byte-aligned structure (rule 2).
    """
    out: list[tuple[int, str, int]] = []
    pos = 0
    limit = len(buf)
    while pos < limit - 6:
        got = _read_string(buf, pos)
        if got is None:
            pos += 1
            continue
        text, end = got
        out.append((pos, text, end))
        pos = end
    yield from out


def _int_run(buf: bytes, start: int, end: int) -> tuple[int, ...]:
    """The int32 array between two string events.

    Unsigned on purpose: this reader exists to *sort* property arrays, and signed
    reinterpretation would turn an embedded-picture byte pattern such as
    ``0xFF000000`` into a plausible-looking ``Left``.
    """
    values = []
    pos = start
    while pos + 4 <= end:
        values.append(struct.unpack_from("<I", buf, pos)[0])
        pos += 4
    return tuple(values)


# ---------------------------------------------------------------------------
# locating design records
# ---------------------------------------------------------------------------


def _class_offsets(buf: bytes) -> list[int]:
    """Offsets of every occurrence of the DataReport class name."""
    needle = DATAREPORT_CLASS.encode("ascii") + b"\x00"
    out = []
    pos = buf.find(needle)
    while pos >= 0:
        out.append(pos)
        pos = buf.find(needle, pos + 1)
    return out


def _head_at(buf: bytes, cls_pos: int) -> DesignHead | None:
    """Validate the record header that must precede a class-name occurrence.

    ``... <size:int32> <idx:uint8> <namelen:uint16> <name> 0x00 0xFF <len16><class>``
    — every one of those fields is checked, because the class name alone also
    occurs in the type-library region (rule 9).
    """
    name_len_pos = cls_pos - 4  # class byte at -3, len16 at -2, name NUL at -4
    if name_len_pos < _RECORD_HDR_BYTES + 2:
        return None
    if buf[cls_pos - 3] != 0xFF:
        return None
    if struct.unpack_from("<H", buf, cls_pos - 2)[0] != len(DATAREPORT_CLASS):
        return None
    if buf[cls_pos - 4] != 0x00:
        return None
    # Walk back to the start of the ASCII name.
    end_name = cls_pos - 4
    start_name = end_name
    while start_name > 0 and 0x20 <= buf[start_name - 1] < 0x7F:
        start_name -= 1
    if start_name == end_name:
        return None
    name_len_pos = start_name - 2
    if name_len_pos < 0:
        return None
    if struct.unpack_from("<H", buf, name_len_pos)[0] != end_name - start_name:
        return None
    name = buf[start_name:end_name].decode("ascii", "replace")
    size_pos = name_len_pos - _RECORD_HDR_BYTES
    if size_pos < 0:
        return None
    size = struct.unpack_from("<I", buf, size_pos)[0]
    # A design record is a few hundred bytes to a few hundred kilobytes; anything
    # outside that is a coincidence in unrelated data.
    if not (0x100 <= size <= 0x80000):
        return None
    if size_pos + size > len(buf):
        return None
    header_fields = struct.unpack_from("<II", buf, size_pos - 8) if size_pos >= 8 else (0, 0)
    return DesignHead(
        name=name,
        va=0,
        size=size,
        offset=size_pos,
        header_fields=header_fields,
    )


def find_designs(path: str) -> list[DesignHead]:
    """Locate every DataReport design record in one PE file.

    Returns heads in file order with ``va`` filled in from the section table.
    """
    with open(path, "rb") as fh:
        buf = fh.read()
    image = pe.read(path)
    heads = []
    for cls_pos in _class_offsets(buf):
        head = _head_at(buf, cls_pos)
        if head is None:
            continue
        va = None
        for sec in image.sections:
            if sec.raw_offset <= head.offset < sec.raw_offset + max(sec.raw_size, 0):
                va = image.image_base + sec.virtual_address + (head.offset - sec.raw_offset)
                break
        if va is None:
            continue
        # The whole record must live inside the same section.
        end_off = head.offset + head.size
        if not any(
            sec.raw_offset <= end_off <= sec.raw_offset + max(sec.raw_size, 0)
            for sec in image.sections
        ):
            continue
        heads.append(
            DesignHead(
                name=head.name,
                va=va,
                size=head.size,
                offset=head.offset,
                header_fields=head.header_fields,
            )
        )
    return heads


# ---------------------------------------------------------------------------
# parsing one design record
# ---------------------------------------------------------------------------


def _detail_top_mode(events: Sequence[tuple[int, str, int]], buf: bytes) -> int | None:
    """Modal ``Top`` of this design's *complete* Detail records, or ``None``.

    A complete record is one whose property array is not one of the two sparse
    layouts (rule 6). Used only to fill ``Top`` where the design itself proves it
    (rule 6); the measured mode on this target is 30 twips.
    """
    counts: Counter[int] = Counter()
    section = ""
    total = len(events)
    for i, (_, text, end) in enumerate(events):
        if SECTION_RE.match(text):
            section = text
            continue
        if not CONTROL_NAME_RE.match(text) or section != DETAIL_SECTION:
            continue
        nxt = events[i + 1][0] if i + 1 < total else len(buf)
        ints = _int_run(buf, end, nxt)
        if len(ints) < 4:
            continue
        sparse = ints[3] in SMALL_ENUM and FONT_HEIGHT_MIN <= ints[2] <= FONT_HEIGHT_MAX
        if sparse:
            continue
        top = ints[1]
        if 0 <= top <= 2000:
            counts[top] += 1
    return counts.most_common(1)[0][0] if counts else None


def _classify_geometry(
    ints: tuple[int, ...], section: str, detail_top: int | None
) -> tuple[int | None, int | None, int | None, int | None, str, bool]:
    """Interpret a control's property array.

    Returns ``(left, top, width, height, geometry, top_inferred)``. ``None`` means
    "not serialised by VB6", which is not the same as zero.
    """
    if not ints:
        return None, None, None, None, "none", False
    if len(ints) > MAX_PROPERTY_INTS:
        # The string scanner lost a character; these int32s are payload.
        return None, None, None, None, "unreliable", False
    if len(ints) < 4:
        # Too few int32s to be a property array at all; nothing is claimed.
        return None, None, None, None, "partial", False

    d0, d1, d2, d3 = ints[0], ints[1], ints[2], ints[3]

    # Top is inferred only for Detail records, and only from Detail evidence: the
    # modal Top of this design's complete Detail records is the topmost row of the
    # detail band, which is where a Detail control with an unsaved Top sits. Using it
    # for a PageHeader/PageFooter control would be a guess (header and detail rows sit
    # at different heights), so those keep ``Top = None``.
    inferred_top = detail_top if section == DETAIL_SECTION else None

    if d3 in SMALL_ENUM and FONT_HEIGHT_MIN <= d2 <= FONT_HEIGHT_MAX:
        # (L, W, H, X): Top is not serialised. Evidence on this target: a txt field
        # at L=1816/W=1874 sits right of its header Label at W=1901, so the second
        # dword is a width in the same stream position as the full layout's Width.
        return d0, inferred_top, d1, d2, "sparse_lwhx", inferred_top is not None

    if FONT_HEIGHT_MIN <= d1 <= FONT_HEIGHT_MAX and d2 in SMALL_ENUM:
        # Double skip (L, H, X, Y): neither Top nor Width serialised. Measured on 62
        # records, all Detail, d1 == 225 in 62/62.
        return d0, inferred_top, None, d1, "sparse_lh", inferred_top is not None

    return d0, d1, d2, d3, "full", False


def _make_record(
    index: int,
    kind: str,
    text: str,
    caption: str,
    section: str,
    ints: tuple[int, ...],
    offset: int,
    end: int,
    detail_top: int | None,
) -> Record:
    common = dict(
        index=index,
        kind=kind,
        name=text,
        caption=caption,
        section=section if kind == "control" else text,
        section_role=SECTION_ROLE.get(section if kind == "control" else text, ""),
        ints=ints,
        offset=offset,
        end=end,
    )
    if kind == "control":
        left, top, width, height, note, inferred = _classify_geometry(ints, section, detail_top)
        return Record(left=left, top=top, width=width, height=height,
                      geometry=note, top_inferred=inferred, **common)
    if kind == "section":
        # Section record: the first int32 is the section height in twips.
        height = ints[0] if ints else None
        return Record(height=height, geometry="section", **common)
    return Record(geometry="none", **common)


def parse_design(head: DesignHead, buf: bytes, path: str) -> Design:
    """Split one design record (``buf`` = the record's bytes) into records.

    Classifying a string event (rules 3, 4, 7 of the module docstring):

    * ``SectionN`` -> a section record; it becomes the owner of everything after it;
    * a control-name pattern -> a control; the *next* string is its caption when that
      string is neither a section nor another control name, or is the name itself
      (VB6 writes a default/empty Caption as the name repeated);
    * anything else -> an orphan value record, kept so no string is dropped silently.
    """
    events = list(iter_string_events(buf))
    detail_top = _detail_top_mode(events, buf)
    records: list[Record] = []
    section = ""
    i = 0
    total = len(events)
    while i < total:
        offset, text, end = events[i]
        next_offset = events[i + 1][0] if i + 1 < total else len(buf)
        # The property array runs from the end of the name to the start of the next
        # string event, whatever that event turns out to be.
        ints = _int_run(buf, end, next_offset)
        if SECTION_RE.match(text):
            section = text
            records.append(
                _make_record(len(records) + 1, "section", text, "", section, ints,
                             offset, end, detail_top)
            )
            i += 1
            continue
        if CONTROL_NAME_RE.match(text):
            caption = ""
            rec_end = end
            consumed = 1
            if i + 1 < total:
                following = events[i + 1][1]
                if following == text or not (
                    SECTION_RE.match(following) or CONTROL_NAME_RE.match(following)
                ):
                    # One record spans name + caption, so the caption string is not
                    # emitted again as a value record.
                    caption = following
                    rec_end = events[i + 1][2]
                    consumed = 2
            records.append(
                _make_record(len(records) + 1, "control", text, caption, section, ints,
                             offset, rec_end, detail_top)
            )
            i += consumed
            continue
        records.append(
            _make_record(len(records) + 1, "value", text, "", section, ints,
                         offset, end, detail_top)
        )
        i += 1
    return Design(
        name=head.name,
        path=path,
        class_name=DATAREPORT_CLASS,
        va=head.va,
        size=head.size,
        header_fields=head.header_fields,
        records=tuple(records),
    )


# ---------------------------------------------------------------------------
# public entry points
# ---------------------------------------------------------------------------


def read_designs(path: str) -> list[Design]:
    """Every DataReport design in one file, in file order."""
    with open(path, "rb") as fh:
        buf = fh.read()
    designs = []
    for head in find_designs(path):
        designs.append(parse_design(head, buf[head.offset:head.offset + head.size], path))
    return designs


def read_paths(paths: Iterable[str]) -> list[Design]:
    """Read a list of files, keeping every design (rule 10: no name-keyed dict)."""
    designs: list[Design] = []
    for path in paths:
        designs.extend(read_designs(path))
    return designs


def iter_files(targets: Iterable[str], patterns: Sequence[str] = ("*.dll", "*.ocx", "*.exe")) -> list[str]:
    """Expand files and directories into a sorted file list."""
    out: list[str] = []
    for target in targets:
        if os.path.isdir(target):
            for pattern in patterns:
                out.extend(
                    os.path.join(target, name)
                    for name in sorted(os.listdir(target))
                    if name.lower().endswith(pattern[1:].lower())
                )
        else:
            out.append(target)
    seen: set[str] = set()
    unique = []
    for path in out:
        real = os.path.normcase(os.path.abspath(path))
        if real not in seen:
            seen.add(real)
            unique.append(path)
    return unique


def key(design: Design) -> tuple[str, str]:
    """Composite join key ``(file name, design name)``."""
    return design.key


def summary(designs: Sequence[Design]) -> dict:
    """Coverage counts, always with the denominator they belong to."""
    records = [r for d in designs for r in d.records]
    controls = [r for r in records if r.kind == "control"]
    notes = Counter(r.geometry for r in controls)
    return {
        "designs": len(designs),
        "files": len({os.path.normcase(d.path) for d in designs}),
        "records": len(records),
        "sections": sum(1 for r in records if r.kind == "section"),
        "controls": len(controls),
        "values": sum(1 for r in records if r.kind == "value"),
        "captions": sum(1 for r in controls if r.caption),
        "default_captions": sum(1 for r in controls if r.caption_is_default),
        "full_geometry": sum(1 for r in controls if r.has_full_geometry),
        "top_unknown": sum(1 for r in controls if r.top is None),
        "width_unknown": sum(1 for r in controls if r.width is None),
        "top_inferred": sum(1 for r in controls if r.top_inferred),
        "geometry": dict(sorted(notes.items())),
        "designs_with_section": sum(1 for d in designs if d.sections),
        "designs_with_controls": sum(1 for d in designs if d.controls),
        "unreliable": notes.get("unreliable", 0),
    }


def _pct(part: int, whole: int) -> str:
    return f"{100.0 * part / whole:.1f}%" if whole else "n/a"


def validate(targets: Iterable[str], out=sys.stdout, per_file: bool = True) -> dict:
    """Print the coverage gate for real files and return the counts.

    There is no ``.dsr`` text available for a shipped report DLL, so this gate
    reports coverage and internal consistency instead of a match rate: how many
    designs were found per file, how many records they yielded, how much geometry
    is actually stored, and how much is unknown.
    """
    files = iter_files(targets)
    all_designs: list[Design] = []
    rows = []
    for path in files:
        try:
            designs = read_designs(path)
        except (pe.PEError, OSError) as exc:
            rows.append((path, f"skipped: {exc}"))
            continue
        all_designs.extend(designs)
        if designs:
            rows.append((path, designs))
    stats = summary(all_designs)
    if per_file:
        print("file                              designs  records  sections  controls  unknownTop  unknownW", file=out)
        for path, value in rows:
            if isinstance(value, str):
                print(f"{os.path.basename(path):<32}  {value}", file=out)
                continue
            s = summary(value)
            print(
                f"{os.path.basename(path):<32} {s['designs']:>7} {s['records']:>8} "
                f"{s['sections']:>9} {s['controls']:>9} {s['top_unknown']:>11} {s['width_unknown']:>9}",
                file=out,
            )
    print(
        f"\nfiles with designs: {stats['files']} / {len(files)} read"
        f"   designs: {stats['designs']}   records: {stats['records']}"
        f" (sections {stats['sections']}, controls {stats['controls']},"
        f" orphan values {stats['values']})",
        file=out,
    )
    print(
        f"captions on controls: {stats['captions']} / {stats['controls']}"
        f" = {_pct(stats['captions'], stats['controls'])}"
        f"   of which the name repeated (= empty Caption in the .dsr):"
        f" {stats['default_captions']}",
        file=out,
    )
    print(
        f"geometry stored in full (L,T,W,H, nothing inferred):"
        f" {stats['full_geometry']} / {stats['controls']}"
        f" = {_pct(stats['full_geometry'], stats['controls'])}",
        file=out,
    )
    print(
        f"Top unknown (not serialised, no design evidence either):"
        f" {stats['top_unknown']} / {stats['controls']}"
        f" = {_pct(stats['top_unknown'], stats['controls'])}",
        file=out,
    )
    print(
        f"Top inferred from the design's own Detail mode: {stats['top_inferred']}"
        f" / {stats['controls']} = {_pct(stats['top_inferred'], stats['controls'])}",
        file=out,
    )
    print(
        f"Width unknown (double-skip layout): {stats['width_unknown']} / {stats['controls']}"
        f" = {_pct(stats['width_unknown'], stats['controls'])}",
        file=out,
    )
    print(f"property-array variants: {stats['geometry']}", file=out)
    print(
        f"designs with a section record: {stats['designs_with_section']} / {stats['designs']}"
        f"   with >=1 control: {stats['designs_with_controls']} / {stats['designs']}",
        file=out,
    )
    # Internal consistency: record offsets must be strictly increasing inside a
    # design and every record must sit inside the record extent that located it.
    disorder = 0
    outside = 0
    for design in all_designs:
        last = -1
        for record in design.records:
            if record.offset <= last:
                disorder += 1
            last = record.offset
            if not (0 <= record.offset <= record.end <= design.size):
                outside += 1
    print(
        f"self-check: out-of-order records {disorder} / {stats['records']},"
        f" out-of-extent records {outside} / {stats['records']}",
        file=out,
    )
    return stats


def _write_csv(designs: Sequence[Design], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=["design", "dll"] + list(Record.__dataclass_fields__))
        writer.writeheader()
        for design in designs:
            for record in design.records:
                row = record.as_dict()
                row.pop("int_count", None)
                row["design"] = design.name
                row["dll"] = os.path.basename(design.path)
                row["ints"] = " ".join(str(v) for v in record.ints[:12])
                writer.writerow({k: row.get(k, "") for k in writer.fieldnames})


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read DataReport designs out of compiled VB6 binaries."
    )
    parser.add_argument("targets", nargs="+", help="files or directories to scan")
    parser.add_argument(
        "--validate",
        action="store_true",
        help="print the coverage gate (designs, records, stored vs unknown geometry)",
    )
    parser.add_argument("--csv", help="write one row per record to this CSV file")
    parser.add_argument("--json", help="write the full design tree to this JSON file")
    parser.add_argument("--quiet", action="store_true", help="only report totals")
    args = parser.parse_args(argv)

    if args.validate:
        validate(args.targets, per_file=not args.quiet)
        return 0

    designs = read_paths(iter_files(args.targets))
    stats = summary(designs)
    print(
        f"designs: {stats['designs']} in {stats['files']} files"
        f"   records: {stats['records']}"
        f" (sections {stats['sections']}, controls {stats['controls']},"
        f" orphan values {stats['values']})"
    )
    if args.csv:
        _write_csv(designs, args.csv)
        print(f"wrote {args.csv} ({stats['records']} rows)")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump([d.as_dict() for d in designs], fh, ensure_ascii=False, indent=1)
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
