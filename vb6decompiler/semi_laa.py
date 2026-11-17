#!/usr/bin/env python3
"""Set the LAA (Large Address Aware) bit on a copy of a 32-bit executable.

Why: the VB6 linker never sets ``IMAGE_FILE_LARGE_ADDRESS_AWARE`` (0x0020). A
decompiler built with VB6 therefore runs with a ~2 GB address space however much
RAM the machine has, and dies on big inputs — measured peak private bytes ~1,884 MB
on a 111 MB target.

This script does not touch the original file. It writes a sibling copy with the
``Characteristics`` bit set and reports both hashes. It does **not** fix logic bugs:
an ``Integer`` counter that overflows above 32,767 procedures overflows with 4 GB
of address space just the same.

    python scripts/semi_laa.py path/to/SemiVBDecompiler.exe
    # -> path/to/SemiVBDecompiler_LAA.exe
"""

from __future__ import annotations

import argparse
import hashlib
import os
import struct
import sys

LAA = 0x0020
#: COFF header field offset. The COFF header starts at ``e_lfanew + 4`` and its
#: ``Characteristics`` is the 7th u16: machine(0), sections(2), timestamp(4),
#: symbol pointer(8), symbol count(12), optional-header size(16), characteristics(18).
#: Writing at +22 lands inside the optional header and silently corrupts the linker
#: version fields — measured, and caught only by diffing the two files.
CHARACTERISTICS_OFFSET = 18


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def set_laa(src: str, dst: str) -> dict:
    with open(src, "rb") as fh:
        data = bytearray(fh.read())
    if data[:2] != b"MZ":
        raise SystemExit(f"{src}: not an MZ image")
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off : pe_off + 4] != b"PE\0\0":
        raise SystemExit(f"{src}: no PE signature")
    coff = pe_off + 4
    machine = struct.unpack_from("<H", data, coff)[0]
    if machine != 0x14C:
        raise SystemExit(f"{src}: not a 32-bit x86 image (machine 0x{machine:X})")
    off = coff + CHARACTERISTICS_OFFSET
    before = struct.unpack_from("<H", data, off)[0]
    data[off : off + 2] = struct.pack("<H", before | LAA)
    with open(dst, "wb") as fh:
        fh.write(data)
    return {
        "source": src,
        "copy": dst,
        "characteristics_before": hex(before),
        "characteristics_after": hex(before | LAA),
        "source_sha256": sha256(src),
        "copy_sha256": sha256(dst),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("exe")
    ap.add_argument("-o", "--output", help="default: <name>_LAA.exe beside the original")
    ap.add_argument("--force", action="store_true", help="overwrite an existing copy")
    args = ap.parse_args(argv)
    stem, ext = os.path.splitext(args.exe)
    dst = args.output or f"{stem}_LAA{ext or '.exe'}"
    if os.path.exists(dst) and not args.force:
        raise SystemExit(f"{dst} exists; pass --force to overwrite")
    info = set_laa(args.exe, dst)
    for k, v in info.items():
        print(f"{k}\t{v}")
    print("# the original is unchanged; start the copy from its own folder so it finds its data files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
