"""A synthetic 32-bit PE for CLI tests that need a real, tiny image.

Built by hand instead of checked in as a binary fixture: the parsers only read
headers and the raw section, and the builder can declare extents the file does
not have — the ``truncated=True`` variant says its section needs 0x1000 bytes
when the file stops at 0x300, which a real exe cannot express.
"""

from __future__ import annotations

import struct


def mini_pe(truncated: bool = False) -> bytes:
    img = bytearray(0x300)
    img[0:2] = b"MZ"
    struct.pack_into("<I", img, 0x3C, 0x80)  # e_lfanew
    img[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    struct.pack_into("<H", img, coff, 0x14C)        # machine: i386
    struct.pack_into("<H", img, coff + 2, 1)        # one section
    struct.pack_into("<H", img, coff + 16, 224)     # optional header size (PE32 + 16 dirs)
    struct.pack_into("<H", img, coff + 18, 0x100)   # Characteristics: exe
    opt = coff + 20
    struct.pack_into("<H", img, opt, 0x10B)         # PE32
    struct.pack_into("<I", img, opt + 16, 0x1000)   # entry point RVA
    struct.pack_into("<I", img, opt + 28, 0x400000)  # ImageBase
    struct.pack_into("<I", img, opt + 32, 0x1000)   # SectionAlignment
    struct.pack_into("<I", img, opt + 36, 0x200)    # FileAlignment
    struct.pack_into("<I", img, opt + 56, 0x2000)   # SizeOfImage
    struct.pack_into("<I", img, opt + 60, 0x200)    # SizeOfHeaders
    struct.pack_into("<I", img, opt + 92, 16)       # NumberOfRvaAndSizes
    # every data directory is (0, 0): no imports, no exports
    sec = opt + 224
    img[sec : sec + 8] = b".text\0\0\0"
    struct.pack_into("<I", img, sec + 8, 0x1000)    # VirtualSize
    struct.pack_into("<I", img, sec + 12, 0x1000)   # VirtualAddress (RVA)
    struct.pack_into("<I", img, sec + 16, 0x1000 if truncated else 0x100)  # SizeOfRawData
    struct.pack_into("<I", img, sec + 20, 0x200)    # PointerToRawData
    struct.pack_into("<I", img, sec + 36, 0x60000020)
    return bytes(img)
