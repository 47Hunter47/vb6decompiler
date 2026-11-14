"""Text literals in a native VB6 build — including the ones every scanner misses.

Why this exists
---------------
VB6 compiles a string literal to a **BSTR in the data area**: a 4-byte byte-length
prefix, the text as **UTF-16LE**, then a NUL terminator. It is not an ASCII string,
and on the reference target it does not live in ``.data`` at all — that section is
4 KB while ``.text`` is 106 MB, and the literals sit inside ``.text``. Consequences,
both measured on the same 111 MB file:

* A generic engine that scans data sections for ASCII reported **59 strings**, all
  of them noise from ``.rsrc``, and **0 occurrences of a table name that is present
  260 times** in the file. Its own limitation text says "strings are read from data
  sections", which is exactly the wrong place.
* A decompiler-listing scanner that only matched ``push <addr> ; "text"`` missed
  **170,645 literals** (170,555 of them were loaded with ``mov``), because native
  VB6 loads a string address with whichever instruction the register allocator
  chose.

So this module reads two sources and keeps them apart:

1. :func:`scan_binary` — BSTR runs from the image itself, with the length prefix
   checked. That check is what makes a run a literal and not a coincidence.
2. :func:`scan_listings` — ``<addr>h ; "text"`` comments from a decompiler's text
   output, *any* instruction, with the VA and the procedure it belongs to.
3. :func:`merge` — union keyed by (procedure VA, text address), never by text.

Nothing here decides what a literal *means*. SQL detection is a flag, and a flag is
not a table list: see :mod:`vb6decompiler.sqlstitch` for what can and cannot be
closed statically.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from . import pe as pe_mod
from .mask import mask_text

#: A run must be at least this long to be plausible (shorter runs are alignment
#: noise). VB6 allows 1-character literals; this threshold is a precision/recall
#: choice, documented rather than hidden.
MIN_CHARS = 4

#: Longer than this and it is not a literal someone typed; it is a blob.
MAX_CHARS = 400

#: Characters allowed inside a recovered literal. Turkish letters are listed because
#: VB6 stores them as UTF-16 code units above 0x7F: a "high byte must be zero" rule
#: silently drops ``ş``, ``ğ`` and ``İ`` and splits the literal around them.
_ALLOWED = (
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    " _.,;:!?'\"()[]{}<>+-*/=%&|\\@#$^~`\t\r\n"
    "çÇğĞıİöÖşŞüÜâÂîÎûÛéÉàÀ°²³€£½¼¾"
)
_RUN = re.compile("[" + re.escape(_ALLOWED) + "]{%d,%d}" % (MIN_CHARS, MAX_CHARS))

#: SQL verbs. Used as a flag only; a literal with a verb is a *candidate*.
SQL_HINT = re.compile(
    r"\b(SELECT\s|INSERT\s+INTO\b|INSERT\b|UPDATE\s+\w+\s+SET\b|UPDATE\b|"
    r"DELETE\s+FROM\b|DELETE\b|EXEC\b|CREATE\s+TABLE\b|ALTER\s+TABLE\b)",
    re.I,
)

#: Any instruction's literal comment: ``0042C3A0h ; "text"``. The instruction is
#: deliberately not named — that was the measured trap.
LISTING_LITERAL = re.compile(r"([0-9A-Fa-f]{6,8})h\s*;\s*\"([^\"]{1,400})\"")

#: Procedure header in a decompiler listing; the trailing hex is the procedure VA.
LISTING_PROC = re.compile(
    r"^(?:Private|Public|Friend|Static)?\s*"
    r"(?:Sub|Function|Property\s+(?:Get|Let|Set))\s+([A-Za-z_]\w*)?\s*\(?.*?'\s*([0-9A-Fa-f]{6,8})\s*$"
)


@dataclass
class Literal:
    va: int                          # virtual address of the text
    text: str
    encoding: str                    # "utf16", "cp1254" or "listing"
    section: str | None = None
    length_prefix_ok: bool = False   # the 4 bytes before the text equal 2*len(text)
    proc_va: int | None = None       # only known when it came from a listing
    source: str = "binary"           # "binary" or "listing"

    @property
    def is_sql(self) -> bool:
        return bool(SQL_HINT.search(self.text))

    def as_row(self) -> dict:
        return {
            "va": f"{self.va:X}",
            "proc_va": f"{self.proc_va:X}" if self.proc_va else "",
            "encoding": self.encoding,
            "section": self.section or "",
            "bstr": "yes" if self.length_prefix_ok else "no",
            "sql": "yes" if self.is_sql else "no",
            "source": self.source,
            "text": mask_text(self.text),
        }


# ---------------------------------------------------------------------------
# 1. the image itself
# ---------------------------------------------------------------------------


def scan_binary(
    path: str,
    min_chars: int = MIN_CHARS,
    include_cp1254: bool = True,
    sections: tuple[str, ...] | None = None,
) -> list[Literal]:
    """BSTR (UTF-16LE) literals, plus optional ASCII runs, from one binary.

    Both byte alignments are decoded: VB6 does not promise that a literal starts on
    a 2-byte boundary, and one odd-length neighbour shifts everything after it.
    """
    with open(path, "rb") as fh:
        data = fh.read()
    image = pe_mod.read(path)
    out: list[Literal] = []
    for sec in image.sections:
        if sections is not None and sec.name not in sections:
            continue
        if sec.name.lower() in (".rsrc", ".reloc", ".pdata", ".idata"):
            continue
        start = sec.raw_offset
        end = min(len(data), sec.raw_offset + sec.raw_size)
        out.extend(_scan_utf16(data, start, end, image, sec))
        if include_cp1254:
            out.extend(_scan_ascii(data, start, end, image, sec))
    return out


def _va_of(image, section, offset: int) -> int:
    return image.image_base + (offset - section.raw_offset) + section.virtual_address


def _scan_utf16(data: bytes, start: int, end: int, image, section):
    out: list[Literal] = []
    for align in (0, 1):
        chunk = data[start + align : end]
        if len(chunk) % 2:
            chunk = chunk[:-1]
        for m in _RUN.finditer(chunk.decode("utf-16-le", "replace")):
            byte_off = start + align + 2 * m.start()
            prefix_ok = False
            if byte_off >= 4:
                declared = int.from_bytes(data[byte_off - 4 : byte_off], "little")
                prefix_ok = declared == 2 * len(m.group(0))
            out.append(
                Literal(
                    va=_va_of(image, section, byte_off),
                    text=m.group(0),
                    encoding="utf16",
                    section=section.name,
                    length_prefix_ok=prefix_ok,
                )
            )
    return out


_ASCII_RUN = re.compile(rb"[\x20-\x7e]{%d,%d}" % (MIN_CHARS, MAX_CHARS))


def _scan_ascii(data: bytes, start: int, end: int, image, section):
    """ASCII runs terminated by a NUL: connection strings and paths look like this.

    Turkish CP1254 bytes (0x80+) are deliberately excluded here: a literal that
    needs them is a UI message, recovered by the UTF-16 pass instead. Including
    0x80+ in this pass turned dense code bytes into thousands of false strings.
    """
    out: list[Literal] = []
    blob = data[start:end]
    for m in _ASCII_RUN.finditer(blob):
        if m.end() < len(blob) and blob[m.end()] != 0:
            continue  # not NUL-terminated: inside a longer binary run
        out.append(
            Literal(
                va=_va_of(image, section, start + m.start()),
                text=m.group(0).decode("cp1254", "replace"),
                encoding="cp1254",
                section=section.name,
            )
        )
    return out


# ---------------------------------------------------------------------------
# 2. decompiler listings
# ---------------------------------------------------------------------------


def scan_listings(directory: str) -> list[Literal]:
    """Literals from ``.frm/.bas/.cls`` decompiler output, with procedure VAs."""
    out: list[Literal] = []
    for root, _dirs, files in os.walk(directory):
        for name in sorted(files):
            if not name.lower().endswith((".frm", ".bas", ".cls")):
                continue
            current: int | None = None
            with open(os.path.join(root, name), encoding="cp1254", errors="replace") as fh:
                for line in fh:
                    # The procedure header is matched FIRST: it carries no ';', so a
                    # "skip lines without a literal comment" filter placed above it
                    # throws every header away and leaves proc_va None on every
                    # literal (measured: 441,607 literals, 0 procedures).
                    head = LISTING_PROC.match(line)
                    if head:
                        current = int(head.group(2), 16)
                        continue
                    if ";" not in line or '"' not in line:
                        continue
                    for m in LISTING_LITERAL.finditer(line):
                        out.append(
                            Literal(
                                va=int(m.group(1), 16),
                                text=m.group(2),
                                encoding="listing",
                                proc_va=current,
                                source="listing",
                            )
                        )
    return out


# ---------------------------------------------------------------------------
# 3. merge / summary
# ---------------------------------------------------------------------------


def merge(*groups: list[Literal]) -> list[Literal]:
    """Union keyed by (proc_va, va) — never by text.

    The same sentence at two addresses is two literals; an inventory keyed by text
    hides the second one, and any later count built on it is wrong.
    """
    seen: set[tuple[int | None, int]] = set()
    out: list[Literal] = []
    for group in groups:
        for lit in group:
            key = (lit.proc_va, lit.va)
            if key in seen:
                continue
            seen.add(key)
            out.append(lit)
    return out


def summary(literals: list[Literal]) -> dict:
    by_section: dict[str, int] = {}
    for lit in literals:
        key = lit.section or "?"
        by_section[key] = by_section.get(key, 0) + 1
    return {
        "literals": len(literals),
        "sql_candidates": sum(1 for l in literals if l.is_sql),
        "bstr_length_checked": sum(1 for l in literals if l.length_prefix_ok),
        "utf16": sum(1 for l in literals if l.encoding == "utf16"),
        "cp1254": sum(1 for l in literals if l.encoding == "cp1254"),
        "from_listing": sum(1 for l in literals if l.source == "listing"),
        "sections": by_section,
    }


def find(path_or_dir: str, needle: str, case_sensitive: bool = False) -> list[Literal]:
    """Substring search across either source."""
    pool = scan_listings(path_or_dir) if os.path.isdir(path_or_dir) else scan_binary(path_or_dir)
    if case_sensitive:
        return [l for l in pool if needle in l.text]
    low = needle.lower()
    return [l for l in pool if low in l.text.lower()]
