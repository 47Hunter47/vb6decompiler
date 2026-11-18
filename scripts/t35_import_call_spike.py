"""Spike: per-procedure MSVBVM60 call order from a native x86 decode.

Question
--------
A decompiler listing prints ``call [004010F4h] ; __vbaOnError`` — it already resolved
each import call. If a plain x86 decode over the procedure's own byte range, resolving
the call target through the import address table, reproduces that order, then the
dossier can carry a *measured* call order without a decompiler at all.

How it measures
---------------
Two independent sources, compared per procedure on the IAT **slot address** (the one
identity both share — a name does not, see the ordinal note below):

* listing: every ``call [<8 hex>h]`` line between two ``'VA`` procedure headers;
* decode: capstone over ``[VA, next VA)`` of that procedure, for both
  ``call dword ptr [slot]`` and ``call rel32`` to a ``FF 25 <slot>`` thunk.

Result on one 111 MB native build, 40 listing files (1,750 procedures, 208,668 decoded
call sites, 0x20000 byte provisional body cap): **1,451 sequences identical, 299
identical with extra calls at the end of the range, 0 that ended early, 0 with a
different call or a different order.** The 299 are the documented gap in
``procs.body_bounds``: a procedure's byte range runs to the next method-table entry, and
a helper with no entry of its own can sit inside it, so the decode legitimately sees
more calls than the listing puts in that procedure. Cost 3.5 ms per procedure, so
~2 minutes for 34,000 on one core.

Ordinal imports are the limit, not the decode
---------------------------------------------
The same build imports 75 of its 276 MSVBVM60 slots **by ordinal**, which carry no
name. Naming them needs the exact runtime build: resolving through a different
``msvbvm60.dll`` gave 246 wrong names across 10 slots (3,534 sites agreed, 246 did
not). So a call order is measurable; a *name* is only as good as the DLL it came
from, and must be reported with the DLL it came from.

Usage
-----
    python scripts/t35_import_call_spike.py --exe APP.exe --listings DIR \\
        --dll msvbvm60.dll [--sample 40] [--body-cap 131072]

Needs ``capstone`` (``pip install vb6decompiler[asm]``); the rest of the toolkit does
not. Nothing here is imported by the package: this is a measurement, not a stage.
"""
from __future__ import annotations

import argparse
import collections
import os
import re
import struct
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vb6decompiler import pe

#: Body bound used when the next procedure start is further away than this. Not a
#: measurement of any real procedure: the experiment in the docstring shows "listing
#: longer" falling to 0 at 0x20000, so the default is that and not a tuned value.
DEFAULT_BODY_CAP = 0x20000

HEADER = re.compile(
    r"^\s*(?:Private|Public|Friend|Static)?\s*"
    r"(?:Sub|Function|Property\s+(?:Get|Let|Set))\s+([A-Za-z_]\w*)?\s*\(?.*?'\s*([0-9A-Fa-f]{6,8})\s*$")
SLOT_CALL = re.compile(r"\bcall\s+\[([0-9A-Fa-f]{8})h\]")
#: ``call 00516100h`` — a direct call whose target is a 6-byte ``jmp [slot]`` thunk.
DIRECT_CALL = re.compile(r"\bcall\s+([0-9A-Fa-f]{8})h")


def import_slots(exe_path: str):
    """{slot VA: (dll, name|None, ordinal|None)}, image base, RVA->offset resolver.

    :mod:`vb6decompiler.pe` lists import names but not the address each one is bound
    to, and that address is what ``call dword ptr [imm32]`` carries.
    """
    with open(exe_path, "rb") as fh:
        data = fh.read()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    coff = e_lfanew + 4
    nsec = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    image_base = struct.unpack_from("<I", data, opt + 28)[0]
    dir_rva, _dir_size = struct.unpack_from("<II", data, opt + 96 + 8)  # directory 1

    sections = []
    so = opt + opt_size
    for i in range(nsec):
        b = so + i * 40
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, b + 8)
        sections.append((va, max(vsize, rawsize), rawptr, rawsize))

    def off_of(rva: int):
        for va, span, rawptr, rawsize in sections:
            if va <= rva < va + span:
                delta = rva - va
                return rawptr + delta if delta < rawsize else None
        return None

    out: dict[int, tuple[str, str | None, int | None]] = {}
    pos = off_of(dir_rva)
    while pos is not None:
        oft, _stamp, _fwd, name_rva, first_thunk = struct.unpack_from("<IIIII", data, pos)
        if not (oft or name_rva or first_thunk):
            break
        name_off = off_of(name_rva)
        dll = data[name_off:data.index(b"\x00", name_off)].decode("latin1") if name_off else "?"
        names_off = off_of(oft or first_thunk)
        i = 0
        while True:
            entry = struct.unpack_from("<I", data, names_off + i * 4)[0]
            if entry == 0:
                break
            slot_va = image_base + first_thunk + i * 4
            if entry & 0x80000000:
                out[slot_va] = (dll.upper(), None, entry & 0x7FFFFFFF)
            else:
                hint_off = off_of(entry & 0x7FFFFFFF)
                nm = data[hint_off + 2:data.index(b"\x00", hint_off + 2)].decode("latin1")
                out[slot_va] = (dll.upper(), nm, None)
            i += 1
        pos += 20
    return out, image_base, off_of, data


def thunk_slot(target_va: int, data, image_base: int, off_of) -> int | None:
    """The IAT slot behind a 6-byte ``jmp [slot]`` thunk at ``target_va``, else ``None``."""
    off = off_of(target_va - image_base)
    if off is not None and data[off:off + 2] == bytes((0xFF, 0x25)):
        return struct.unpack_from("<I", data, off + 2)[0]
    return None


def listing_slots(paths: list[str], data, image_base: int, off_of) -> tuple[dict[int, list[int]], dict[int, str], int]:
    """{proc VA: [slot VA, ...]} in listing order, plus the thunk-call count.

    A direct ``call 00516100h`` reaches MSVBVM60 through a ``jmp [slot]`` thunk, so it
    is resolved to its slot here: leaving it out made the listing look shorter than the
    decode in 102 of 1,750 procedures, which was an artefact of this extractor and not
    a difference between the two sources.
    """
    seqs: dict[int, list[int]] = {}
    order: dict[int, str] = {}
    thunk_calls = 0
    for path in paths:
        cur = None
        with open(path, encoding="cp1254", errors="replace") as fh:
            for line in fh:
                m = HEADER.match(line)
                if m:
                    cur = int(m.group(2), 16)
                    seqs.setdefault(cur, [])
                    order[cur] = os.path.basename(path)
                    continue
                if cur is None or "call" not in line:
                    continue
                sm = SLOT_CALL.search(line)
                if sm:
                    seqs[cur].append(int(sm.group(1), 16))
                    continue
                dm = DIRECT_CALL.search(line)
                if dm:
                    slot = thunk_slot(int(dm.group(1), 16), data, image_base, off_of)
                    if slot is not None:
                        seqs[cur].append(slot)
                        thunk_calls += 1
    return seqs, order, thunk_calls


def decode_slots(md, start_va: int, end_va: int, data, image_base: int,
                 slots: dict, off_of) -> list[int]:
    """Slot VAs of the MSVBVM60 calls in ``[start_va, end_va)``, in address order."""
    off = off_of(start_va - image_base)
    if off is None:
        return []
    out = []
    span = max(0, end_va - start_va)
    for ins in md.disasm(data[off:off + span], start_va):
        if ins.mnemonic != "call":
            continue
        ops = ins.op_str
        slot = None
        if ops.startswith("dword ptr [0x") and ops.endswith("]"):
            slot = int(ops[len("dword ptr ["):-1], 16)
        elif re.fullmatch(r"0x[0-9a-f]+", ops):
            toff = off_of(int(ops, 16) - image_base)
            if toff is not None and data[toff:toff + 2] == b"\xff\x25":
                slot = struct.unpack_from("<I", data, toff + 2)[0]
        if slot in slots and slots[slot][0] == "MSVBVM60.DLL":
            out.append(slot)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Measure whether a native decode reproduces a listing's call order.")
    ap.add_argument("--exe", required=True, help="a native VB6 build (work on a copy)")
    ap.add_argument("--listings", required=True, help="decompiler listings carrying 'VA headers")
    ap.add_argument("--dll", default=None,
                    help="the msvbvm60.dll this build was compiled against, for ordinal names")
    ap.add_argument("--sample", type=int, default=40, help="listing files to measure (default 40)")
    ap.add_argument("--body-cap", type=lambda v: int(v, 0), default=DEFAULT_BODY_CAP)
    args = ap.parse_args(argv)

    try:
        import capstone
    except ImportError:
        print("error: capstone is not installed (pip install 'vb6decompiler[asm]')", file=sys.stderr)
        return 2

    t0 = time.perf_counter()
    slots, image_base, off_of, data = import_slots(args.exe)
    vb_slots = {va: v for va, v in slots.items() if v[0] == "MSVBVM60.DLL"}
    ordinals = sum(1 for _d, n, _o in vb_slots.values() if n is None)
    print(f"# import table: {len(slots)} slots, {len(vb_slots)} MSVBVM60 "
          f"({len(vb_slots) - ordinals} by name + {ordinals} by ordinal)")

    ordinal_names: dict[int, str] = {}
    if args.dll:
        ordinal_names = {o: n for n, o in pe.read(args.dll).exports if n}
        print(f"# {os.path.basename(args.dll)}: {len(ordinal_names)} named exports")

    files = sorted(f for f in os.listdir(args.listings)
                   if f.lower().endswith((".frm", ".bas", ".cls")))[:args.sample]
    seqs, order, thunk_calls = listing_slots([os.path.join(args.listings, f) for f in files],
                                             data, image_base, off_of)
    print(f"# {len(files)} listing files, {len(seqs)} procedures, "
          f"{sum(len(v) for v in seqs.values())} listing call sites, "
          f"{thunk_calls} direct calls resolved through a jmp-thunk")

    by_file: dict[str, list[int]] = collections.defaultdict(list)
    for va, fname in order.items():
        by_file[fname].append(va)
    bounds = {}
    for vas in by_file.values():
        vas.sort()
        for i, va in enumerate(vas):
            bounds[va] = vas[i + 1] if i + 1 < len(vas) else va + args.body_cap
            if bounds[va] - va > args.body_cap:
                bounds[va] = va + args.body_cap

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    t = time.perf_counter()
    same = same_prefix = listing_more = decode_more = other = 0
    sites = 0
    for va, want in seqs.items():
        got = decode_slots(md, va, bounds[va], data, image_base, vb_slots, off_of)
        sites += len(got)
        if got == want:
            same += 1
        elif want == got[:len(want)]:
            same_prefix += 1          # decode carries extra calls after the listing's last
        elif got == want[:len(got)]:
            listing_more += 1         # the range stopped before the listing's last call
        elif len(got) > len(want):
            decode_more += 1
        else:
            other += 1
    dt = time.perf_counter() - t
    n = len(seqs)
    print(f"# decoded {sites} call sites in {dt:.1f}s ({dt / max(n, 1) * 1000:.2f} ms/procedure)")
    print(f"# identical ordered sequence: {same} of {n}")
    print(f"# identical then extra calls at the end: {same_prefix} of {n}")
    print(f"# range ended early (listing continues): {listing_more} of {n}")
    print(f"# extra calls mid-sequence: {decode_more} of {n}")
    print(f"# neither is a prefix of the other: {other} of {n}")
    if ordinal_names:
        used = {s for va in seqs for s in decode_slots(md, va, bounds[va], data, image_base, vb_slots, off_of)
                if vb_slots[s][1] is None}
        resolvable = sum(1 for s in used if vb_slots[s][2] in ordinal_names)
        print(f"# ordinal slots used: {len(used)} distinct, {resolvable} nameable from this DLL")
    print(f"# total {time.perf_counter() - t0:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
