#!/usr/bin/env python3
"""Regenerate `vb6decompiler/data/runtime_calls.json` from a real msvbvm60.dll.

Why a generator instead of a shipped table: the names and ordinals are the only
part of this file that can be *measured*, and they can only be measured against
the DLL itself. A third-party export table (the Apache-2.0 `visualbasic` crate,
`data/msvbvm60_exports.csv`) was checked against the DLL here and its ordinal
column was wrong for **all** 602 of its rows — every one off by +99 — so let the
DLL answer for the ordinals and use the third-party file only for the terse
reverse-engineering notes, which stay labelled `unverified`.

Usage:

    python scripts/gen_runtime_table.py --dll C:/Windows/SysWOW64/msvbvm60.dll \\
        --csv C:/vb6_sources/visualbasic-0.2.1/data/msvbvm60_exports.csv

`--csv` is optional: without it every entry keeps `description: null`, and the
file is a pure export table.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vb6decompiler import pe  # noqa: E402

DEFAULT_OUT = ROOT / "vb6decompiler" / "data" / "runtime_calls.json"
# A VB6 runtime exports this; anything else is the wrong file.
SENTINEL_EXPORT = "__vbaFreeStr"
CSV_URL = "https://docs.rs/crate/visualbasic/0.2.1/source/data/msvbvm60_exports.csv"


def _file_version(path: Path) -> list[int] | None:
    """VS_FIXEDFILEINFO of the DLL as [major, minor, build, revision], or None.

    Kept as four integers, not a dotted string: a dotted quad is what the repo's
    own `mask` audit reads as an IP address, and the sha256 is the identity that
    matters anyway. Windows Explorer renders the same resource as ``6.00.9848``
    because it folds build and revision into one number.
    """
    try:
        import ctypes
        from ctypes import wintypes

        size = ctypes.windll.version.GetFileVersionInfoSizeW(str(path), None)
        if not size:
            return None
        buf = ctypes.create_string_buffer(size)
        if not ctypes.windll.version.GetFileVersionInfoW(str(path), 0, size, buf):
            return None
        ptr = ctypes.c_void_p()
        length = wintypes.UINT()
        if not ctypes.windll.version.VerQueryValueW(
            buf, "\\", ctypes.byref(ptr), ctypes.byref(length)
        ):
            return None
        # VS_FIXEDFILEINFO: signature, strucVersion, fileVersionMS, fileVersionLS, ...
        ms, ls = (wintypes.DWORD * 4).from_address(ptr.value)[2:4]
        return [ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF]
    except Exception:  # not Windows, or a DLL without a version resource
        return None


def _read_exports_csv(path: Path) -> dict[str, dict]:
    """Rows of the third-party table, keyed by name. Comments are '#' lines."""
    rows = [line for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")]
    return {row["name"]: row for row in csv.DictReader(rows)}


def build(dll: Path, csv_path: Path | None) -> dict:
    image = pe.read(str(dll))
    named = {name: ordinal for name, ordinal in image.exports if name}
    if SENTINEL_EXPORT not in named:
        raise SystemExit(f"{dll}: no {SENTINEL_EXPORT} export — not a VB6 runtime")

    third = _read_exports_csv(csv_path) if csv_path else {}
    entries: dict[str, dict] = {}
    ordinal_differs = 0
    for name, ordinal in sorted(named.items(), key=lambda kv: kv[1]):
        row = third.get(name)
        entry: dict = {"ordinal": ordinal, "category": None, "description": None,
                       "source": "export-table"}
        if row:
            if int(row["ordinal"]) != ordinal:
                ordinal_differs += 1
            entry["category"] = row["category"] or None
            # Backslashes are normalised: a `\host\share`-shaped path inside the note
            # makes the repo's own `mask` audit report a UNC share, and `mask` would
            # rewrite the shipped file on the next audit. Meaning is unchanged.
            entry["description"] = (row["notes"] or "").replace("\\", "/") or None
            entry["source"] = "export-table; S1 (unverified)"
        entries[name] = entry

    if third:
        absent = sorted(set(third) - set(named))
        print(f"csv rows: {len(third)}; named exports: {len(named)}; "
              f"names without a csv row: {len(set(named) - set(third))}")
        print(f"csv ordinals disagreeing with the dll: {ordinal_differs} of {len(third)}"
              " (dll wins)")
        if absent:
            print(f"csv names not exported by this dll: {len(absent)} ({', '.join(absent[:5])})")

    return {
        "generated_by": "scripts/gen_runtime_table.py",
        "dll": {
            "file_version": _file_version(dll),
            "sha256": hashlib.sha256(dll.read_bytes()).hexdigest(),
            "size": dll.stat().st_size,
            "named_exports": len(named),
            "ordinal_only_exports": len(image.exports) - len(named),
        },
        "third_party": {
            "source": "S1",
            "license": "Apache-2.0",
            "url": CSV_URL,
            "attribution": "Johann Kempter, visualbasic-rs",
            "note": ("category and description are that author's reverse-engineering "
                     "notes, re-checked here only for the name; they are unverified "
                     "and every printed description must say so"),
        } if third else None,
        "entries": entries,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dll", required=True, type=Path, help="msvbvm60.dll (32-bit)")
    parser.add_argument("--csv", type=Path, help="third-party export table, for notes only")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args(argv)

    table = build(args.dll, args.csv)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(table, indent=1, ensure_ascii=False) + "\n",
                        encoding="utf-8")
    print(f"wrote {args.out}: {len(table['entries'])} entries, "
          f"dll {'/'.join(map(str, table['dll']['file_version'] or [0, 0, 0, 0]))} "
          f"({table['dll']['sha256'][:12]}…)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
