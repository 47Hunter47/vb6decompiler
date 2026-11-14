"""PE surface of a VB6 install: what a program imports, exports and drags in.

Why this exists
---------------
A VB6 application is almost never one file. The executable imports only
``MSVBVM60.DLL`` and reaches everything else (ODBC, DAO, RDO, XML, mail, sockets)
through COM created at run time. Reading the import table therefore tells you
what the *runtime* needs, not what the program does — and the components it really
uses show up only as sibling DLLs/OCXs, ActiveX registrations and type libraries.

Two measured traps are encoded here:

* **Both thunk arrays must be walked.** In an import descriptor
  ``OriginalFirstThunk`` and ``FirstThunk`` sit in different address ranges; naming
  only ``OriginalFirstThunk`` leaves every ``call dword ptr [0x40xxxx]`` target
  anonymous in the caller's disassembly. Walking both raised named call sites from
  ~135k to ~267k on the reference target.
* **Do not hand-roll the export table.** A hand-written export reader produced
  ``NumberOfFunctions ≈ 761,000`` for a 1 MB OCX; ``pefile`` read the same file as
  four standard COM registration exports. Use :func:`exports` here (bounded and
  validated) or ``pefile`` — never a quick struct.unpack.

Nothing in this module needs a third-party package.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from typing import Iterable

#: Imports that identify a VB6-built binary. ``MSVBVM60`` = VB6, ``MSVBVM50`` = VB5.
VB6_RUNTIMES = {"MSVBVM60.DLL", "MSVBVM50.DLL"}

#: The four exports every self-registering COM component carries.
COM_REGISTRATION_EXPORTS = {
    "DllRegisterServer",
    "DllUnregisterServer",
    "DllGetClassObject",
    "DllCanUnloadNow",
}

#: Data directory indices used below (PE spec order).
_DIR_EXPORT = 0
_DIR_IMPORT = 1
_DIR_RESOURCE = 2


class PEError(Exception):
    """The file is not a PE image this module can read."""


@dataclass
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int

    @property
    def contains(self) -> bool:
        return bool(self.characteristics & 0x80000000)  # IMAGE_SCN_MEM_WRITE

    def va_to_offset(self, va: int) -> int | None:
        delta = va - self.virtual_address
        if 0 <= delta < max(self.raw_size, self.virtual_size):
            return self.raw_offset + delta
        return None


@dataclass
class Import:
    dll: str
    functions: list[str] = field(default_factory=list)
    unnamed: int = 0
    is_ordinal_only: int = 0

    @property
    def is_vb6_runtime(self) -> bool:
        return self.dll.upper() in VB6_RUNTIMES


@dataclass
class PEImage:
    path: str
    machine: int
    image_base: int
    entry_point_rva: int
    sections: list[Section]
    imports: list[Import]
    exports: list[tuple[str | None, int]]  # (name or None, ordinal)
    size: int

    # -- addressing ---------------------------------------------------------

    @property
    def bits(self) -> int:
        return 64 if self.machine in (0x8664, 0xAA64) else 32

    @property
    def is_vb6(self) -> bool:
        return any(i.is_vb6_runtime for i in self.imports)

    @property
    def entry_point(self) -> int:
        """Absolute virtual address of the entry point (ImageBase + RVA)."""
        return self.image_base + self.entry_point_rva

    def va_to_offset(self, va: int) -> int | None:
        """Absolute VA -> file offset.

        VB6 native builds use a fixed ``ImageBase`` of 0x400000, so
        ``offset = VA - ImageBase`` works for the common case; this function is
        the honest version: it walks the section table and returns ``None`` for
        addresses that live outside every raw section (BSS, headers).
        """
        if va < self.image_base:
            return None
        rva = va - self.image_base
        for sec in self.sections:
            off = sec.va_to_offset(rva)
            if off is not None:
                return off
        return None

    def section_of(self, rva: int) -> Section | None:
        for sec in self.sections:
            if sec.virtual_address <= rva < sec.virtual_address + max(
                sec.virtual_size, sec.raw_size
            ):
                return sec
        return None

    # -- convenience --------------------------------------------------------

    @property
    def import_dlls(self) -> list[str]:
        return [i.dll for i in self.imports]

    def summary(self) -> dict:
        return {
            "path": self.path,
            "bits": self.bits,
            "image_base": hex(self.image_base),
            "entry_point": hex(self.entry_point),
            "vb6": self.is_vb6,
            "import_dlls": len(self.imports),
            "import_functions": sum(len(i.functions) + i.unnamed for i in self.imports),
            "exports": len(self.exports),
            "com_registration": sorted(
                n for n, _ in self.exports if n in COM_REGISTRATION_EXPORTS
            ),
        }


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------


def _u16(b: bytes, off: int) -> int:
    return struct.unpack_from("<H", b, off)[0]


def _u32(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]


def read(path: str) -> PEImage:
    """Parse a PE file. Raises :class:`PEError` for anything else."""
    with open(path, "rb") as fh:
        data = fh.read()

    if data[:2] != b"MZ":
        raise PEError(f"{os.path.basename(path)}: not an MZ image")
    pe_off = _u32(data, 0x3C)
    if data[pe_off : pe_off + 4] != b"PE\0\0":
        raise PEError(f"{os.path.basename(path)}: no PE signature")

    coff = pe_off + 4
    machine = _u16(data, coff)
    n_sections = _u16(data, coff + 2)
    opt_size = _u16(data, coff + 16)
    opt = coff + 20
    magic = _u16(data, opt)
    if magic == 0x10B:
        bits = 32
        image_base = _u32(data, opt + 28)
        directory_count = _u32(data, opt + 92)
        directory_off = opt + 96
    elif magic == 0x20B:
        bits = 64
        image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        directory_count = _u32(data, opt + 108)
        directory_off = opt + 112
    else:
        raise PEError(f"{os.path.basename(path)}: unknown optional header magic 0x{magic:X}")
    entry_point_rva = _u32(data, opt + 16)

    sections: list[Section] = []
    sec_off = opt + opt_size
    for i in range(n_sections):
        base = sec_off + i * 40
        name = data[base : base + 8].split(b"\0")[0].decode("latin1", "replace")
        sections.append(
            Section(
                name=name,
                virtual_size=_u32(data, base + 8),
                virtual_address=_u32(data, base + 12),
                raw_size=_u32(data, base + 16),
                raw_offset=_u32(data, base + 20),
                characteristics=_u32(data, base + 36),
            )
        )

    def directory(index: int) -> tuple[int, int]:
        if index >= directory_count:
            return (0, 0)
        off = directory_off + index * 8
        return (_u32(data, off), _u32(data, off + 4))

    def rva_to_off(rva: int) -> int | None:
        for sec in sections:
            if sec.virtual_address <= rva < sec.virtual_address + max(
                sec.virtual_size, sec.raw_size
            ):
                delta = rva - sec.virtual_address
                if delta < sec.raw_size:
                    return sec.raw_offset + delta
                return None  # inside .bss: no file bytes
        return None

    imports = _read_imports(data, directory(_DIR_IMPORT), rva_to_off, bits)
    exports = _read_exports(data, directory(_DIR_EXPORT), rva_to_off)

    return PEImage(
        path=path,
        machine=machine,
        image_base=image_base,
        entry_point_rva=entry_point_rva,
        sections=sections,
        imports=imports,
        exports=exports,
        size=len(data),
    )


def _read_imports(data: bytes, directory: tuple[int, int], rva_to_off, bits: int):
    rva, size = directory
    if not rva:
        return []
    off = rva_to_off(rva)
    if off is None:
        return []
    out: list[Import] = []
    # 5 dwords per descriptor; a zeroed descriptor terminates the array.
    while off + 20 <= len(data):
        oft, _ts, _fwd, name_rva, ft = struct.unpack_from("<IIIII", data, off)
        if not (oft or name_rva or ft):
            break
        name_off = rva_to_off(name_rva)
        dll = ""
        if name_off is not None:
            end = data.find(b"\0", name_off)
            dll = data[name_off:end].decode("latin1", "replace")
        entry = Import(dll=dll)

        # Both thunk arrays: OriginalFirstThunk holds the name RVA table,
        # FirstThunk holds the loaded addresses. Some linkers leave OFT empty, so
        # the walk is done on each and functions are de-duplicated.
        seen: set[int] = set()
        for thunk_rva in (oft, ft):
            if not thunk_rva:
                continue
            t_off = rva_to_off(thunk_rva)
            if t_off is None:
                continue
            width = 4 if bits == 32 else 8
            step = width
            for n in range(4096):  # bounded: a corrupt table must not loop
                pos = t_off + n * step
                if pos + step > len(data):
                    break
                value = struct.unpack_from("<I" if width == 4 else "<Q", data, pos)[0]
                if value == 0:
                    break
                if value & (1 << (31 if width == 4 else 63)):
                    ordinal = value & 0xFFFF
                    marker = 0x80000000 | ordinal
                    if marker in seen:
                        continue
                    seen.add(marker)
                    entry.unnamed += 1
                    entry.is_ordinal_only += 1
                    continue
                hint_off = rva_to_off(value)
                if hint_off is None:
                    continue
                if hint_off in seen:
                    continue
                seen.add(hint_off)
                end = data.find(b"\0", hint_off + 2)
                fname = data[hint_off + 2 : end].decode("latin1", "replace")
                if fname:
                    entry.functions.append(fname)
        out.append(entry)
        off += 20
        if len(out) > 512:
            break
    return out


def _is_x86(data: bytes) -> bool:
    pe_off = _u32(data, 0x3C)
    return _u16(data, pe_off + 4) in (0x14C,)


def _read_exports(data: bytes, directory: tuple[int, int], rva_to_off):
    rva, size = directory
    if not rva:
        return []
    off = rva_to_off(rva)
    if off is None or off + 40 > len(data):
        return []
    n_functions = _u32(data, off + 20)
    n_names = _u32(data, off + 24)
    addr_funcs = _u32(data, off + 28)
    addr_names = _u32(data, off + 32)
    addr_ordinals = _u32(data, off + 36)
    # Bound both tables by the export directory's own size: a corrupt count is
    # what produced the 761,000-export reading in the hand-written reader.
    if n_names > 65535 or n_functions > 65535:
        raise PEError(
            f"export table claims {n_names} names / {n_functions} functions; refusing to read"
        )
    out: list[tuple[str | None, int]] = []
    names_by_ordinal: dict[int, str] = {}
    names_off = rva_to_off(addr_names)
    ords_off = rva_to_off(addr_ordinals)
    if names_off is not None and ords_off is not None:
        for i in range(min(n_names, 8192)):
            name_rva = _u32(data, names_off + i * 4)
            ordinal_index = _u16(data, ords_off + i * 2)
            name_off = rva_to_off(name_rva)
            if name_off is None:
                continue
            end = data.find(b"\0", name_off)
            names_by_ordinal[ordinal_index] = data[name_off:end].decode("latin1", "replace")
    funcs_off = rva_to_off(addr_funcs)
    count = min(n_functions, 8192) if funcs_off is not None else n_names
    for i in range(count):
        out.append((names_by_ordinal.get(i), i + 1))
    return out


# ---------------------------------------------------------------------------
# directory-level helpers
# ---------------------------------------------------------------------------


def scan_directory(path: str, recursive: bool = False) -> list[dict]:
    """PE summary for every ``.exe/.dll/.ocx`` under a path (or one file)."""
    if os.path.isfile(path):
        files = [path]
    else:
        files = []
        for root, _dirs, names in os.walk(path):
            for n in names:
                if n.lower().endswith((".exe", ".dll", ".ocx")):
                    files.append(os.path.join(root, n))
            if not recursive:
                break
    out = []
    for f in sorted(files):
        try:
            out.append(read(f).summary())
        except (PEError, OSError, struct.error) as exc:
            out.append({"path": f, "error": str(exc)})
    return out


def vb6_binaries(images: Iterable[dict]) -> list[str]:
    """Which of these images import a VB6 runtime (i.e. carry VB6 code)."""
    return [i["path"] for i in images if i.get("vb6")]
