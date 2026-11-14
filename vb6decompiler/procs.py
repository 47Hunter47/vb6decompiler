"""The VB6 procedure table, read from the executable itself.

Why this exists
---------------
A native VB6 executable carries its own metadata: a ``VB5!`` header points at a
``ProjectInfo``, which points at an ``ObjectTable``, which lists every form,
module and class with a pointer to its method table — and each method table entry
is the entry address of compiled code. No symbols, no PDB, no decompiler needed.

Measured on a 111 MB target: **834 objects / 34,415 methods** read from the header
chain in 0.4 s, with zero decompiler involvement. A generic recursive-descent
engine on the same file found 6,875 functions (20 % of the 34,159 entries a
decompiler listing gave) and stopped at its instruction cap; the engine said so
itself.

**A native build does not expose method entry addresses here.** In the same target
the ``ObjectInfo`` block resolves, but its documented ``lpMethods`` slot holds no
table of code addresses (measured: every candidate pointer in the block pointed at
code bytes, not at an array of entry points, and none of the 9 known entries of a
test form appeared anywhere in the block). Object and method *counts* are evidence;
the addresses are not, so :class:`Method` keeps ``address=None`` instead of
inventing one. Entry addresses come from a decompiler listing's ``'VA`` comments —
see :func:`merge_listing_names` — and are marked as such.

Chain (offsets are the documented VB6 layout used by vb6rs and Alex Ionescu's
notes; each was verified by resolving a field twice and comparing):

    VBHeader ("VB5!" — note: VB5 and VB6 share the magic)
      +0x1C  lpProjectData        -> ProjectInfo   (dwVersion 0x1F4)
                                    ProjectInfo+0x04 -> ObjectTable
      ObjectTable+0x2A  total_objects   (u16)
      ObjectTable+0x2C  compiled_objects(u16)
      ObjectTable+0x30  lpObjectArray   -> 0x30-byte records
      ObjectTable+0x40  project name VA
      ObjectTable+0x50  identifier (GUID-ish, hex)
      record+0x00 lpObjectInfo -> ObjectInfo (+0x20 wMethodCount, +0x24 lpMethods,
                                 +0x28 constants count)
      record+0x1C name VA, +0x20 method_count, +0x24 lpMethodNames, +0x28 fObjectType

Addresses inside these structures are VA when ``>= ImageBase``, RVA otherwise, and
occasionally a raw file offset. :func:`_Resolver.read` tries all three in that
order; a field that resolves under two interpretations is a bug in the caller, not
in the file.

What is *not* recoverable: method names for modules (VB6 stores them for classes
and forms only, and only as the designer's names), and the concept of "event
handler" — a form method is just a method whose name happens to look like
``Command1_Click``. Names from a decompiler's listing can be merged in with
:func:`merge_listing_names`; they are hints, not evidence.
"""

from __future__ import annotations

import os
import re
import struct
from dataclasses import dataclass, field

#: fObjectType values measured in one real native build (834 objects). The value is
#: not a small enum: the same build reported 0x18001 for modules, 0x18083 for forms,
#: 0x118003 for a class and 0x1018083 for the 24 embedded DataReport objects, so a
#: bit-mask guess would mislabel them. Unknown values are printed as hex, never
#: mapped to the nearest known type.
OBJECT_TYPES = {
    0x18001: "module",
    0x18083: "form",
    0x118003: "class",
    0x1018083: "datareport",
}

#: A VB6 procedure starts with ``push ebp; mov ebp, esp`` (55 8B EC). The bytes
#: after that vary (``83 EC``, ``6A``, ``E8``). Used to prove that a table entry
#: really is a procedure entry and not a stub or a data pointer.
PROLOGUE = b"\x55\x8b\xec"

#: Header of a procedure in a decompiler listing, e.g.
#: ``Private Sub Command1_Click() '36FB300`` — the trailing hex is the VA and is
#: the only reliable identity (names repeat within a form: one target had 267
#: bodies in a form all labelled ``FisButton_Click``).
LISTING_HEADER = re.compile(
    r"^\s*(?:Private|Public|Friend|Static)?\s*"
    r"(?:Sub|Function|Property\s+(?:Get|Let|Set))\s+([A-Za-z_]\w*)?\s*\(?.*?'\s*([0-9A-Fa-f]{6,8})\s*$"
)


@dataclass
class Method:
    index: int
    address: int | None  # verified entry VA (prologue present); None otherwise
    file_offset: int | None
    in_code: bool
    name: str | None = None
    raw_pointer: int | None = None  # what the table actually held, for diagnostics


@dataclass
class VBObject:
    index: int
    name: str
    object_type: str
    raw_type: int
    method_count: int
    methods: list[Method] = field(default_factory=list)

    @property
    def method_addresses(self) -> list[int]:
        return [m.address for m in self.methods if m.address is not None]


class VBError(Exception):
    """The file has no readable VB6 header."""


class _Resolver:
    """Pointer field -> file bytes, trying VA, then RVA, then raw offset."""

    def __init__(self, data: bytes, image_base: int, sections: list[dict]):
        self.data = data
        self.base = image_base
        self.sections = sections

    def rva_to_off(self, rva: int) -> int | None:
        for s in self.sections:
            span = max(s["vsize"], s["rawsize"])
            if s["rva"] <= rva < s["rva"] + span:
                delta = rva - s["rva"]
                if delta < s["rawsize"]:
                    return s["rawptr"] + delta
                return None
        return None

    def va_to_off(self, va: int) -> int | None:
        if va >= self.base:
            return self.rva_to_off(va - self.base)
        return None

    def read(self, ptr: int, size: int) -> tuple[bytes | None, int | None]:
        for cand in (self.va_to_off(ptr), self.rva_to_off(ptr)):
            if cand is not None and 0 <= cand and cand + size <= len(self.data):
                return self.data[cand : cand + size], cand
        if 0 <= ptr and ptr + size <= len(self.data):
            return self.data[ptr : ptr + size], ptr
        return None, None

    def cstr(self, ptr: int, limit: int = 256) -> str | None:
        raw, _ = self.read(ptr, limit)
        if raw is None:
            return None
        cut = raw.find(b"\0")
        if cut < 0:
            return None
        return decode_cp1254(raw[:cut])


def decode_cp1254(raw: bytes) -> str:
    """VB6 strings are CP1254 (Turkish). Never latin-1: it silently mangles İ/ş/ğ."""
    try:
        return raw.decode("cp1254")
    except UnicodeDecodeError:
        return raw.decode("latin1", "replace")


def _sections(data: bytes) -> tuple[list[dict], int]:
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    coff = pe_off + 4
    machine = struct.unpack_from("<H", data, coff)[0]
    nsec = struct.unpack_from("<H", data, coff + 2)[0]
    optsize = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    is32 = machine == 0x14C
    image_base = (
        struct.unpack_from("<I", data, opt + 28)[0]
        if is32
        else struct.unpack_from("<Q", data, opt + 24)[0]
    )
    out = []
    so = opt + optsize
    for i in range(nsec):
        b = so + i * 40
        name = data[b : b + 8].rstrip(b"\0").decode("latin1", "replace")
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, b + 8)
        out.append({"name": name, "rva": va, "vsize": vsize, "rawptr": rawptr, "rawsize": rawsize})
    return out, image_base


def _vb_header(data: bytes) -> dict | None:
    off = data.find(b"VB5!")
    if off < 0 or off + 104 > len(data):
        return None
    keys = [
        "magic", "runtime_build", "lang_dll", "seclang_dll", "runtime_rev",
        "lcid", "seclcid", "lpSubMain", "lpProjectData", "fMdlIntCtls",
        "fMdlIntCtls2", "thread_flags", "thread_count", "form_count",
        "external_count", "thunk_count", "lpGuiTable", "lpExternalTable",
        "lpComRegisterData", "desc_selfrel", "exe_selfrel", "help_selfrel", "name_selfrel",
    ]
    vals = struct.unpack_from("<4sH14s14sH" + "I" * 8 + "HH" + "I" * 8, data, off)
    hdr = dict(zip(keys, vals))
    hdr["offset"] = off
    return hdr


@dataclass
class VBProject:
    path: str
    image_base: int
    project_name: str | None
    project_description: str | None
    runtime_build: int
    runtime_rev: int
    form_count: int
    object_count: int
    compiled_count: int
    identifier: str
    objects: list[VBObject]

    # -- derived facts ------------------------------------------------------

    @property
    def methods(self) -> list[tuple[VBObject, Method]]:
        return [(o, m) for o in self.objects for m in o.methods]

    def procedure_addresses(self) -> list[int]:
        """Unique method entry addresses *if the build exposed any* (often none)."""
        return sorted({a for o in self.objects for a in o.method_addresses})

    def methods_by_address(self) -> list[tuple[VBObject, "Method"]]:
        """Only the (object, method) pairs whose address a prologue verified."""
        return [(o, m) for o in self.objects for m in o.methods if m.address is not None]

    def object_of(self, va: int) -> VBObject | None:
        for o in self.objects:
            if va in o.method_addresses:
                return o
        return None

    def stats(self) -> dict:
        addrs = self.procedure_addresses()
        return {
            "name": self.project_name,
            "objects": len(self.objects),
            "declared_objects": self.object_count,
            "methods": sum(o.method_count for o in self.objects),
            "method_entries_read": sum(len(o.methods) for o in self.objects),
            "unique_entries": len(addrs),
            "methods_without_address": sum(
                1 for o in self.objects for m in o.methods if m.address is None
            ),
        }


def read(path: str) -> VBProject:
    """Decode the VB6 header chain of one executable or DLL."""
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:2] != b"MZ":
        raise VBError(f"{os.path.basename(path)}: not an MZ image (pass design text to 'vb6d frm', compiled binaries here)")
    try:
        sections, image_base = _sections(data)
    except struct.error as exc:
        # A text file or a stub with junk at 0x3C computes offsets past the buffer;
        # say what the input is, not what unpack_from wanted (same trio as blob.py).
        raise VBError(f"{os.path.basename(path)}: PE header did not parse (truncated, or not a compiled binary)") from exc
    hdr = _vb_header(data)
    if hdr is None:
        raise VBError(f"{os.path.basename(path)}: no 'VB5!' header (not a VB5/VB6 build)")
    res = _Resolver(data, image_base, sections)

    def selfrel(rel: int, limit: int = 400) -> str | None:
        if not rel:
            return None
        o = hdr["offset"] + rel  # bSZ* fields are relative to the VBHeader itself
        if not (0 <= o < len(data)):
            return None
        cut = data.find(b"\0", o, o + limit)
        return decode_cp1254(data[o:cut]) if cut > 0 else None

    raw, _ = res.read(hdr["lpProjectData"], 0x23C)
    if raw is None:
        raise VBError(f"{os.path.basename(path)}: ProjectInfo pointer did not resolve")
    lp_object_table = struct.unpack_from("<I", raw, 4)[0]

    raw, _ = res.read(lp_object_table, 0x54)
    if raw is None:
        raise VBError(f"{os.path.basename(path)}: ObjectTable pointer did not resolve")
    total_objects = struct.unpack_from("<H", raw, 0x2A)[0]
    compiled = struct.unpack_from("<H", raw, 0x2C)[0]
    lp_object_array = struct.unpack_from("<I", raw, 0x30)[0]
    name_va = struct.unpack_from("<I", raw, 0x40)[0]
    identifier = struct.unpack_from("<I", raw, 0x50)[0]

    raw, _ = res.read(lp_object_array, max(1, total_objects) * 0x30)
    if raw is None:
        raise VBError(f"{os.path.basename(path)}: object array did not resolve")

    objects: list[VBObject] = []
    for i in range(total_objects):
        rec = raw[i * 0x30 : (i + 1) * 0x30]
        if len(rec) < 0x30:
            break
        (lp_objinfo, _reserved, _lp_pub, _lp_stat, _lp_modpub, _lp_modstat,
         name_ptr, method_count, method_names_va, _o_stat, f_type, _null) = struct.unpack(
            "<12I", rec
        )
        obj = VBObject(
            index=i,
            name=res.cstr(name_ptr) or f"<object {i}>",
            object_type=OBJECT_TYPES.get(f_type, hex(f_type)),
            raw_type=f_type,
            method_count=method_count,
        )

        info, _ = res.read(lp_objinfo, 0x38)
        method_ptrs: list[int] = []
        if info:
            lp_methods = struct.unpack_from("<I", info, 0x24)[0]
            w_methods = struct.unpack_from("<H", info, 0x20)[0]
            n = method_count or w_methods
            m_raw, _ = res.read(lp_methods, max(1, n) * 4)
            if m_raw:
                for j in range(n):
                    method_ptrs.append(struct.unpack_from("<I", m_raw, j * 4)[0])

        names: list[str | None] = []
        if method_names_va:
            nm, _ = res.read(method_names_va, max(1, method_count) * 4)
            if nm:
                for j in range(method_count):
                    names.append(res.cstr(struct.unpack_from("<I", nm, j * 4)[0], 128))

        for j, ptr in enumerate(method_ptrs):
            off = res.va_to_off(ptr) if ptr else None
            if off is None and ptr:
                off = res.rva_to_off(ptr)
            # A pointer only counts as a method entry if the bytes there are a VB6
            # prologue. In the reference native build the slot holds small integers
            # (0x4, 0x7), which are not addresses at all: accepting them produced
            # 208 "methods" of which 0 were code.
            is_code = bool(
                off is not None
                and 0 <= off < len(data) - 3
                and data[off : off + 3] == PROLOGUE
            )
            obj.methods.append(
                Method(
                    index=j,
                    address=ptr if is_code else None,
                    file_offset=off,
                    in_code=is_code,
                    name=names[j] if j < len(names) else None,
                    raw_pointer=ptr,
                )
            )
        objects.append(obj)

    return VBProject(
        path=path,
        image_base=image_base,
        project_name=res.cstr(name_va),
        project_description=selfrel(hdr["desc_selfrel"]),
        runtime_build=hdr["runtime_build"],
        runtime_rev=hdr["runtime_rev"],
        form_count=hdr["form_count"],
        object_count=total_objects,
        compiled_count=compiled,
        identifier=f"{identifier:08X}",
        objects=objects,
    )


# ---------------------------------------------------------------------------
# verification helpers
# ---------------------------------------------------------------------------


def prologue_report(path: str, project: VBProject | None = None, sample: int | None = None) -> dict:
    """How many table entries really start with the VB6 prologue.

    A table entry that is *not* a prologue is usually a wrapper, a thunk or a
    designer-only method with no code — count it separately, do not call it "code
    we missed".
    """
    project = project or read(path)
    with open(path, "rb") as fh:
        data = fh.read()
    addrs = project.procedure_addresses()
    if sample:
        addrs = addrs[:sample]
    ok, bad = 0, []
    for va in addrs:
        off = va - project.image_base
        if 0 <= off < len(data) - 3 and data[off : off + 3] == PROLOGUE:
            ok += 1
        else:
            bad.append(va)
    return {
        "checked": len(addrs),
        "prologue": ok,
        "not_prologue": len(bad),
        "examples_not_prologue": [hex(a) for a in bad[:10]],
    }


def body_bounds(addresses: list[int]) -> dict[int, int]:
    """Procedure body end = next procedure start in address order.

    This is the honest bound for a *contiguous* method table. It is wrong for any
    code the table does not describe (shared helpers, generated thunks), which is
    why callers must not treat the result as a parsed body: the bytes between two
    entries can belong to a helper that has no table entry.
    """
    ordered = sorted(set(addresses))
    return {va: (ordered[i + 1] if i + 1 < len(ordered) else None) for i, va in enumerate(ordered)}


def parse_listing(path: str) -> tuple[str, dict[int, str]]:
    """Names from a decompiler listing: ``{'obj':..., va: name}``.

    Only the trailing VA is trusted. One measured decompiler gave 267 bodies in a
    single form the same name; keying by name merges them, keying by VA does not.
    """
    obj = os.path.basename(path).rsplit(".", 1)[0]
    names: dict[int, str] = {}
    with open(path, encoding="cp1254", errors="replace") as fh:
        for line in fh:
            m = LISTING_HEADER.match(line)
            if m:
                names.setdefault(int(m.group(2), 16), m.group(1) or f"proc_{m.group(2).lower()}")
    return obj, names


def merge_listing_names(listing_dir: str) -> dict[int, list[str]]:
    """VA -> every name any listing gave it (conflicts are kept, not resolved)."""
    out: dict[int, list[str]] = {}
    for root, _dirs, files in os.walk(listing_dir):
        for name in files:
            if not name.lower().endswith((".frm", ".bas", ".cls")):
                continue
            _obj, names = parse_listing(os.path.join(root, name))
            for va, n in names.items():
                bucket = out.setdefault(va, [])
                if n not in bucket:
                    bucket.append(n)
    return out
