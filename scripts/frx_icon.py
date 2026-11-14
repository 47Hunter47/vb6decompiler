#!/usr/bin/env python3
"""Extract the standalone `.ico` hidden at the head of a VB6 `.frx` side file.

Why: a `.frx` written next to a `.frm` starts with a short property-blob header
and, for forms that carry an icon, the next bytes are a complete ICON resource:
`<header> <ICONDIR> <ICONDIRENTRY x N> <image data>`.  Image harvesters that
scan only for JPEG/BMP/GIF signatures miss these entirely.  Measured on the
reference corpus (see docs/formats.md sec. 5): this gate finds icons in 347 of
358 `.frx` files, 10 distinct images among them.

The `imageOffset` field of every ICONDIRENTRY is relative to the ICONDIR start
— the same layout a standalone `.ico` carries — so the slice from the ICONDIR
start to `max(offset + size)` is already a valid `.ico` file; offsets are not
rewritten.  The header length is not fixed (measured: the ICONDIR signature
sits at even offsets up to 32), so the scan searches even offsets in the first
34 bytes.

Structural gates (all measured on the corpus, kept with the explanation, do
not "clean up"):
  * ICONDIR signature `00 00 01 00` (icon) or `00 00 02 00` (cursor group);
  * entry type 1 or 2, entry count 1..20 (larger groups are false hits);
  * every entry offset >= 6 + 16 * count (entries follow the directory);
  * every image fits inside the file.
A file failing any gate is reported as `no_icon` — absence, never an error.

Validation mode (ground truth = the `.frm` text shipped with the same
program): count how many `.frm` files declare `Icon = "<name>.frx":<offset>`,
and cross-check against what was extracted from the bytes.  Coverage with
denominators, not "OK".

Usage:
    frx_icon.py <in_dir_or_single_.frx> <out_dir> [--validate <frm_dir>] [--quiet]

Output: one `.ico` per form into <out_dir>; a summary line with denominators
to stdout; failing files listed by name unless --quiet.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import os
import re
import struct
import sys


def find_icon(data: bytes):
    """Return (icondir_start, ico_bytes) for the leading ICON resource, else None."""
    for hdr in range(0, 34, 2):  # header length varies; measured window is 0..32
        if data[hdr:hdr + 4] in (b"\x00\x00\x01\x00", b"\x00\x00\x02\x00"):
            break
    else:
        return None
    tip, count = struct.unpack_from("<HH", data, hdr + 2)
    if tip not in (1, 2) or not (1 <= count <= 20):
        return None
    end = 0
    for i in range(count):
        e = hdr + 6 + i * 16
        if e + 16 > len(data):
            return None
        size, off = struct.unpack_from("<II", data, e + 8)
        if size == 0 or off < 6 + count * 16:  # entries follow the directory
            return None
        if hdr + off + size > len(data):
            return None
        end = max(end, off + size)
    return hdr, data[hdr:hdr + end]


FRM_ICON_RE = re.compile(rb'Icon\s*=\s*"([^"]+\.frx)"\s*:\s*([0-9a-fA-F]+)', re.I)


def frm_icon_refs(frm_dir: str) -> dict:
    """form name (lower) -> frx file name referenced by the design-time Icon line."""
    out = {}
    for path in sorted(glob.glob(os.path.join(frm_dir, "*.frm"))):
        text = open(path, "rb").read()
        m = FRM_ICON_RE.search(text)
        if m:
            form = os.path.splitext(os.path.basename(path))[0].lower()
            out[form] = m.group(1).decode("cp1254", "replace").lower()
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("src", help="directory of .frx files, or a single .frx")
    ap.add_argument("out", help="output directory for .ico files")
    ap.add_argument("--validate", metavar="FRM_DIR",
                    help="cross-check against .frm Icon references")
    ap.add_argument("--quiet", action="store_true", help="do not list no_icon files")
    args = ap.parse_args(argv)

    if os.path.isdir(args.src):
        files = sorted(glob.glob(os.path.join(args.src, "*.frx")))
    else:
        files = [args.src]
    if not files:
        print("no .frx files found at %r" % args.src, file=sys.stderr)
        return 2
    os.makedirs(args.out, exist_ok=True)

    extracted, no_icon, digests = [], [], {}
    for path in files:
        data = open(path, "rb").read()
        found = find_icon(data)
        form = os.path.splitext(os.path.basename(path))[0]
        if found is None:
            no_icon.append(form)
            continue
        start, ico = found
        digest = hashlib.sha256(ico).hexdigest()
        digests.setdefault(digest, []).append(form)
        with open(os.path.join(args.out, form + ".ico"), "wb") as fh:
            fh.write(ico)
        extracted.append((form, start, len(ico), digest))

    print("icons extracted: %d of %d .frx files scanned" % (len(extracted), len(files)))
    print("distinct icon images: %d" % len(digests))
    if no_icon:
        print("no_icon (absence, not error): %d: %s"
              % (len(no_icon), " ".join(no_icon) if not args.quiet else "-"))
    if args.validate:
        refs = frm_icon_refs(args.validate)
        got = {form.lower() for form, _, _, _ in extracted}
        missing = {form.lower() for form in no_icon}
        both = sum(1 for f in refs if f in got)
        declared_no_bytes = [f for f in refs if f in missing]
        bytes_no_declaration = sorted(got - set(refs))
        print("validate vs .frm: %d of %d .frm files declare an .frx Icon reference"
              % (len(refs), len(glob.glob(os.path.join(args.validate, "*.frm")))))
        print("  extracted AND declared: %d" % both)
        if declared_no_bytes:
            print("  declared but no ICON bytes: %s" % " ".join(sorted(declared_no_bytes)))
        if bytes_no_declaration:
            print("  icon bytes with no .frm declaration: %s" % " ".join(bytes_no_declaration))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
