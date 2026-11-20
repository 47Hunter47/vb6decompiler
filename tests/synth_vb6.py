"""One synthetic VB6-like build shared by the end-to-end tests.

SYNTHETIC, and labelled so everywhere: every byte layout below comes from
``docs/formats.md`` (§1 the PE, §2 the ``BSTR``, §3 ``VBHeader``, §4 the object
table, §5 the form blob) or from a builder already measured in ``tests/``.  No
number produced from this target may be quoted as a measurement of a real
program, and every name is a stand-in (``docs/RULES.md`` rule 8).

The target is one executable plus the listing and ``.frm`` text a decompiler
would have written next to it, so every stage has something to accept:

    build(tmp_path) -> SynthTarget   # .exe, listings/, frms/

What the build carries, as counts the tests assert:

* 2 objects (1 module, 1 form), 4 methods, 4 verified procedure entries;
* 4 ``BSTR`` literals, one of them non-ASCII (§2: a high-byte scan splits it);
* 1 form blob with 3 controls whose geometry equals the ``.frm`` text, so
  ``blob --validate`` must match 3 of 3.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

IMAGE_BASE = 0x400000
SECTION_RVA = 0x1000
RAW_PTR = 0x200
FILE_ALIGN = 0x200

#: A method entry only counts as code when the bytes there are this prologue.
PROLOGUE = b"\x55\x8b\xec"
#: Entry stubs are this long, so the four entries are contiguous VAs.
STUB_SIZE = 16

#: (object name, fObjectType, (method names…)) — measured type values, §4.
OBJECTS = (
    ("modSynth01", 0x18001, ("Main", "Helper")),
    ("fSynth01", 0x18083, ("cmdOk_Click", "Form_Load")),
)

#: One static call inside the build, so ``edges`` has an attributed edge to
#: report instead of an empty graph: caller method -> callee method.
CALLS = {"Main": "Helper"}

#: (owner method, text). One non-ASCII literal on purpose; one SQL chain that
#: closes and one that cannot (a run-time value at the end).
LITERALS = (
    ("Main", "SELECT OrderNo FROM tOrder WHERE DepDate = "),
    ("Main", "'E1' AND Kind = 'A'"),
    ("Main", "Kayıt bulunamadı"),
    ("Helper", "SELECT DetailCode FROM tLine WHERE OrderNo = '"),
)

#: (control name, class byte, geometry pid, left, top, width, height) — the same
#: numbers the ``.frm`` text carries, in twips.  ``GEOM_PID`` in blob.py.
CONTROLS = (
    ("txtAd", 0x02, 0x04, 120, 240, 1455, 315),
    ("cmdOk", 0x04, 0x04, 120, 960, 1215, 375),
    ("lblTitle", 0x01, 0x05, 120, 120, 1455, 255),
)
FORM = "fSynth01"
CLIENT = (60, 345, 6000, 3000)

#: LCID 0x41F = Turkish, so the ANSI fields decode as the default page and the
#: ``.frm``/listing text must be written in it.
LCID = 0x41F
CODEPAGE = "cp1254"


@dataclass(frozen=True)
class SynthTarget:
    """A build on disk, plus the counts every end-to-end assertion uses."""

    root: Path
    exe: Path
    listings: Path
    frms: Path
    #: method name -> entry VA, as the object table gave it
    entries: dict[str, int]

    @property
    def last_va(self) -> int:
        return max(self.entries.values())


# ---------------------------------------------------------------------------
# The grammar helpers (form blob: ``<size> <idx> <namelen> <name> 0x00 <cls>``)
# ---------------------------------------------------------------------------
def _s(text: str) -> bytes:
    """An ANSI string in blob form: ``<len16> bytes 0x00``."""
    raw = text.encode(CODEPAGE)
    return struct.pack("<H", len(raw)) + raw + b"\x00"


def _record(name: str, cls: int, body: bytes) -> bytes:
    """One record; the size field is patched to the record's own length."""
    rec = bytearray(b"\x00\x00\x00\x00\x00")
    rec += struct.pack("<H", len(name)) + name.encode("ascii") + b"\x00"
    rec += bytes([cls]) + body
    struct.pack_into("<I", rec, 0, len(rec))
    return bytes(rec)


def _geometry(pid: int, left: int, top: int, width: int, height: int) -> bytes:
    """Geometry property plus the pid of the next property (``0xFF``: none)."""
    return bytes([pid]) + struct.pack("<hhhh", left, top, width, height) + b"\xff\x00"


def _form_blob() -> bytes:
    """The form record, its client rect, then its control records."""
    body = bytes([0x35]) + struct.pack("<I", 12) + struct.pack("<iii", CLIENT[1], *CLIENT[2:])
    # The client rect is written as (block length, Top, Width, Height) in this
    # layout; the reader accepts it only together with a sane Left/Top.
    body = bytes([0x35]) + struct.pack("<iiii", *CLIENT)
    out = _record(FORM, 0x0D, body)
    for name, cls, pid, left, top, width, height in CONTROLS:
        caption = b"\x01" + _s("Kaydet") if name == "lblTitle" else b""
        out += _record(name, cls, caption + _geometry(pid, left, top, width, height))
    return out + b"\x00" * 16


# ---------------------------------------------------------------------------
# The image
# ---------------------------------------------------------------------------
class _Payload:
    """Bytes of the one section, addressed by VA.

    Patches are queued: a pointer can name a structure allocated later in the
    payload, so they are applied once the whole buffer exists.
    """

    def __init__(self) -> None:
        self.buf = bytearray()
        self._patches: list[tuple[int, str, tuple[int, ...]]] = []

    def add(self, data: bytes, align: int = 8) -> int:
        while len(self.buf) % align:
            self.buf.append(0)
        va = IMAGE_BASE + SECTION_RVA + len(self.buf)
        self.buf += data
        return va

    def off(self, va: int) -> int:
        # Buffer-relative: the PE headers are added around this payload later.
        return va - IMAGE_BASE - SECTION_RVA

    def patch(self, va: int, fmt: str, *values: int) -> None:
        self._patches.append((self.off(va), fmt, values))

    def apply(self) -> bytes:
        for offset, fmt, values in self._patches:
            struct.pack_into(fmt, self.buf, offset, *values)
        return bytes(self.buf)


def _imports(p: _Payload) -> int:
    """One import descriptor for ``MSVBVM60.DLL`` (§1: the runtime, nothing else).

    ``pe`` decides a build is VB6 by this import, so a target without it is a PE
    that every other stage would still read but ``pe`` would report as not-VB6.
    """
    dll = p.add(b"MSVBVM60.DLL\x00", align=4)
    names = [p.add(struct.pack("<H", 0) + name + b"\x00", align=2)
             for name in (b"__vbaStrCopy", b"__vbaFreeStr")]
    thunk = p.add(struct.pack("<III", *names, 0), align=4)
    iat = p.add(struct.pack("<III", *names, 0), align=4)
    descriptor = p.add(struct.pack("<IIIII", 0, 0, 0, 0, 0) + b"\x00" * 20, align=4)
    p.patch(descriptor, "<IIIII", thunk - IMAGE_BASE, 0, 0, dll - IMAGE_BASE, iat - IMAGE_BASE)
    return descriptor - IMAGE_BASE


def _pe(payload: bytes, import_rva: int) -> bytes:
    """Headers (0x200) + the section's raw window, section-aligned."""
    raw = bytearray(payload)
    while len(raw) % FILE_ALIGN:
        raw.append(0)
    img = bytearray(RAW_PTR)
    img[0:2] = b"MZ"
    struct.pack_into("<I", img, 0x3C, 0x80)
    img[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    struct.pack_into("<H", img, coff, 0x14C)       # i386
    struct.pack_into("<H", img, coff + 2, 1)       # one section
    struct.pack_into("<H", img, coff + 16, 224)    # optional header size
    struct.pack_into("<H", img, coff + 18, 0x100)  # executable image
    opt = coff + 20
    struct.pack_into("<H", img, opt, 0x10B)        # PE32
    struct.pack_into("<I", img, opt + 16, SECTION_RVA)
    struct.pack_into("<I", img, opt + 28, IMAGE_BASE)
    struct.pack_into("<I", img, opt + 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", img, opt + 36, FILE_ALIGN)
    struct.pack_into("<I", img, opt + 56, SECTION_RVA + len(raw))
    struct.pack_into("<I", img, opt + 60, RAW_PTR)
    struct.pack_into("<I", img, opt + 92, 16)      # NumberOfRvaAndSizes
    # Data directory 1 is the import table; every other directory stays (0, 0).
    struct.pack_into("<II", img, opt + 96 + 8, import_rva, 40)
    sec = opt + 224
    img[sec:sec + 8] = b".text\0\0\0"
    struct.pack_into("<I", img, sec + 8, len(raw))       # VirtualSize
    struct.pack_into("<I", img, sec + 12, SECTION_RVA)   # VirtualAddress
    struct.pack_into("<I", img, sec + 16, len(raw))      # SizeOfRawData
    struct.pack_into("<I", img, sec + 20, RAW_PTR)
    struct.pack_into("<I", img, sec + 36, 0x60000020)    # code | execute | read
    return bytes(img + raw)


def _image() -> tuple[bytes, dict[str, int]]:
    """Build the section and return ``(file bytes, method name -> VA)``."""
    p = _Payload()
    # Reserve the header chain first: its pointers are patched once the parts
    # exist, and ``VBHeader`` is found by searching for its magic (§3).
    vb_header = p.add(b"VB5!" + b"\x00" * 100)
    project_info = p.add(b"\x00" * 0x23C)
    object_table = p.add(b"\x00" * 0x54)
    object_array = p.add(b"\x00" * (0x30 * len(OBJECTS)))

    # Every entry is allocated before any is patched: a call names an entry that
    # is allocated later in the same pass.
    entries: dict[str, int] = {}
    for _name, _vtype, methods in OBJECTS:
        for method in methods:
            entries[method] = p.add(PROLOGUE + b"\x90" * (STUB_SIZE - 4) + b"\xc3", align=16)
    for caller, callee in CALLS.items():
        # ``call rel32``: the displacement is measured from the next instruction.
        p.patch(entries[caller] + 3, "<BI", 0xE8, entries[callee] - (entries[caller] + 8))

    object_rows = []
    for name, vtype, methods in OBJECTS:
        info = p.add(b"\x00" * 0x38)
        method_table = p.add(b"\x00" * (4 * len(methods)))
        name_table = p.add(b"\x00" * (4 * len(methods)))
        for i, method in enumerate(methods):
            name_va = p.add(_cstr(method), align=2)
            p.patch(name_table + 4 * i, "<I", name_va)
            p.patch(method_table + 4 * i, "<I", entries[method])
        object_rows.append((name, vtype, info, method_table, name_table, len(methods)))

    object_names = {row[0]: p.add(_cstr(row[0]), align=2) for row in object_rows}
    project_name = p.add(_cstr("prjSynth"), align=2)
    description = _cstr("synthetic build")
    description_va = p.add(description, align=2)

    for i, (name, vtype, info, method_table, name_table, count) in enumerate(object_rows):
        rec = object_array + i * 0x30
        p.patch(rec + 0x00, "<I", info)
        p.patch(rec + 0x18, "<I", object_names[name])
        p.patch(rec + 0x1C, "<I", count)
        p.patch(rec + 0x20, "<I", name_table)
        p.patch(rec + 0x28, "<I", vtype)
        p.patch(info + 0x20, "<H", count)
        p.patch(info + 0x24, "<I", method_table)

    p.patch(object_table + 0x2A, "<H", len(OBJECTS))
    p.patch(object_table + 0x2C, "<H", len(OBJECTS))
    p.patch(object_table + 0x30, "<I", object_array)
    p.patch(object_table + 0x40, "<I", project_name)
    p.patch(object_table + 0x50, "<I", 0x2)
    p.patch(project_info + 0x00, "<I", 0x1F4)
    p.patch(project_info + 0x04, "<I", object_table)

    for owner, text in LITERALS:
        raw = text.encode("utf-16-le")
        # One literal per ``BSTR``: the length prefix is what makes it a literal
        # and not a coincidence (§2).
        p.add(struct.pack("<I", len(raw)) + raw + b"\x00\x00", align=4)

    import_rva = _imports(p)
    p.add(_form_blob(), align=4)

    p.patch(vb_header + 0x04, "<H", 0x1957)          # runtime build
    p.patch(vb_header + 0x06, "<14s", b"VBA6.DLL\0" + b"\x00" * 5)
    p.patch(vb_header + 0x14, "<14s", b"VBA6.DLL\0" + b"\x00" * 5)
    p.patch(vb_header + 0x22, "<H", 0x000F)
    p.patch(vb_header + 0x24, "<I", LCID)
    p.patch(vb_header + 0x28, "<I", 0x0409)
    p.patch(vb_header + 0x2C, "<I", entries["Main"])
    p.patch(vb_header + 0x30, "<I", project_info)
    p.patch(vb_header + 0x40, "<I", 1)               # thread count
    p.patch(vb_header + 0x44, "<H", len(FORM) and 1)  # form count
    p.patch(vb_header + 0x58, "<I", description_va - vb_header)
    p.patch(vb_header + 0x64, "<I", project_name - vb_header)
    return _pe(p.apply(), import_rva), entries


def _cstr(text: str) -> bytes:
    return text.encode(CODEPAGE) + b"\x00"


# ---------------------------------------------------------------------------
# The text a decompiler would have written next to the build
# ---------------------------------------------------------------------------
def _listing_module(entries: dict[str, int]) -> str:
    lines = ["Attribute VB_Name = \"modSynth01\"", "'SYNTHETIC listing", ""]
    for method in ("Main", "Helper"):
        lines.append(f"Private Sub {method}() '{entries[method]:X}")
        for owner, text in LITERALS:
            if owner == method:
                lines.append(f'  mov eax, {entries[method]:08X}h ; "{text}"')
        lines.append("End Sub")
        lines.append("")
    return "\n".join(lines)


def _listing_form(entries: dict[str, int]) -> str:
    lines = ["VERSION 5.00", "'SYNTHETIC listing", ""]
    for method in ("cmdOk_Click", "Form_Load"):
        lines.append(f"Private Sub {method}() '{entries[method]:X}")
        lines.append("End Sub")
        lines.append("")
    return "\n".join(lines)


def _frm_text() -> str:
    """Design text whose geometry equals the blob, so ``--validate`` matches."""
    out = ["VERSION 5.00", f'Begin VB.Form {FORM}', '   Caption         =   "Synthetic form"',
           f"   ClientHeight    =   {CLIENT[3]}", f"   ClientLeft      =   {CLIENT[0]}",
           f"   ClientTop       =   {CLIENT[1]}", f"   ClientWidth     =   {CLIENT[2]}"]
    captions = {"lblTitle": "Kayıt"}
    for name, _cls, _pid, left, top, width, height in CONTROLS:
        kind = {"txtAd": "VB.TextBox", "cmdOk": "VB.CommandButton", "lblTitle": "VB.Label"}[name]
        out.append(f"   Begin {kind} {name}")
        if name in captions:
            out.append(f'      Caption         =   "{captions[name]}"')
        out += [f"      Height          =   {height}", f"      Left            =   {left}",
                f"      Top             =   {top}", f"      Width           =   {width}", "   End"]
    out.append("End")
    return "\n".join(out) + "\n"


def build(root: Path) -> SynthTarget:
    """Write the build under ``root`` and return it with its measured entries."""
    root = Path(root)
    listings = root / "listings"
    frms = root / "frms"
    listings.mkdir(parents=True, exist_ok=True)
    frms.mkdir(parents=True, exist_ok=True)
    image, entries = _image()
    exe = root / "synth01.exe"
    exe.write_bytes(image)
    (listings / "modSynth01.bas").write_text(_listing_module(entries), encoding=CODEPAGE)
    (listings / "fSynth01.frm").write_text(_listing_form(entries), encoding=CODEPAGE)
    (frms / f"{FORM}.frm").write_text(_frm_text(), encoding=CODEPAGE)
    return SynthTarget(root=root, exe=exe, listings=listings, frms=frms, entries=entries)
