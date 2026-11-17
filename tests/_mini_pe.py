"""A synthetic 32-bit PE for CLI tests that need a real, tiny image.

Built by hand instead of checked in as a binary fixture: the parsers only read
headers and the raw section, and the builder can declare extents the file does
not have — the ``truncated=True`` variant says its section needs 0x1000 bytes
when the file stops at 0x300, which a real exe cannot express.
"""

from __future__ import annotations

import struct


def mini_pe(truncated: bool = False, code: bytes = b"", imports: bool = False) -> bytes:
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
    if code:
        assert len(code) <= 0x100, "code must fit the section's raw window"
        img[0x200:0x200 + len(code)] = code  # the decode tests need real bytes
    if imports:
        # one descriptor whose FirstThunk (rva 0x10B0) is the live IAT with two
        # named slots; names and the dll string live right after the table
        struct.pack_into("<IIIII", img, 0x280, 0, 0, 0, 0x10F0, 0x10B0)  # desc @rva 0x1080
        struct.pack_into("<III", img, 0x2B0, 0x10C8, 0x10D0, 0)          # IAT @rva 0x10B0
        img[0x2C8:0x2D0] = b"\x00\x00ProcA\0"
        img[0x2D0:0x2D8] = b"\x00\x00ProcB\0"
        img[0x2F0:0x2F9] = b"kernel32\0"
        struct.pack_into("<II", img, opt + 104, 0x1080, 40)              # Import directory
    return bytes(img)
