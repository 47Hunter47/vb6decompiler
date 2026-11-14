#!/usr/bin/env python3
"""Decompile a VB6 executable with Ghidra/PyGhidra, supplying bounds and names.

Why: a generic decompiler knows nothing about VB6. It finds no procedure
boundaries in a Visual Basic build, resolves no COM dispatch targets, and never
prints the text of a string literal — it prints `DAT_<addr>`, `PTR_DAT_<addr>`
or `PTR_PTR_<addr>` depending on how deep the indirection is. What it does
provide, and no VB6-specific tool here provides, is rebuilt control flow:
`if`/`else`/`while` instead of `GoTo loc_`. So the division of labour is:
this repository supplies addresses, names and literal text; Ghidra supplies
structure.  See docs/tool-matrix.md for the measured comparison.

Traps that cost probing time, all resolved here (see docs/pitfalls.md,
"Running a second-opinion decompiler"):

* Ghidra 12.x requires the JDK level its own `Ghidra/application.properties`
  declares (`application.java.min`). A correct-looking `JAVA_HOME` pointing at
  an older JDK fails inside `support/LaunchSupport.jar` with
  `unsupported java version`, exit 1. Read the requirement from the file.
* `pyghidra.start()` must run before any `from ghidra... import ...` (JPype
  import hook). Importing Ghidra classes at module level breaks plain import.
* `FlatProgramAPI` has no `getAddress` (that was a `GhidraScript` helper): use
  `getAddressFactory().getAddress("0x16a2170")`. `FlatProgramAPI.disassemble(a)`
  decodes a single instruction; for a range use
  `DisassembleCommand(address_set, None, True).applyTo(prog, monitor)`.
* `DecompResults` has no `depFailed()`: use `decompileCompleted()`,
  `failedToStart()`, `isCancelled()`.
* `MemoryMap` has no `getBlockCount()`: use `len(mem.getBlocks())`.
  `LanguageID` is read with `getLanguageID().getIdAsString()`, not `getID()`.
* `createLabel` / `setPlateComment` do not change the emitted pseudo-C (they
  were tried with and without a wrapping transaction: the symbol table shows
  them, the decompiler text does not). Names are therefore applied to the
  decompiler text, keeping the `DAT_`/`PTR_` prefix that carries the
  indirection degree.
* Two failure families need two different fixes: `process: timeout` responds to
  a longer timeout; `Flow exceeded maximum allowable instructions` and
  `Response buffer size exceeded` are `DecompileOptions` ceilings, not time.
  Print the defaults with `--print-options` before raising them, and run a
  plateau test (same target set at two ceiling values) before paying for a
  higher ceiling: identical solved sets mean the ceiling is not binding.
* Ghidra 12 runs the decompiler in a separate `decompile` process whose working
  set is not bounded by `-Xmx` or `JAVA_TOOL_OPTIONS`. Worker heap settings do
  not cap it.
* A Ghidra project carries file locks: parallel workers need one project
  directory each, built from scratch (importing a ~100 MB class EXE with
  auto-analysis off takes seconds).

Targets come from a CSV with a `va` column (and optional `name`); the address is
the identity, names are cosmetic here.  Literals for an optional naming pass come
from a CSV with `va,addr,text` columns (`is_sql` is copied through when present).

Output file shape: `<sanitised name>__<va>.c`, which `scripts/pseudoc_inventory.py`
and `scripts/literal_visibility.py` read.

Usage (Ghidra and JDK live outside this repository; nothing is uploaded):

    export JAVA_HOME=/path/to/jdk
    export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.2_PUBLIC
    python scripts/ghidra_bridge.py program.exe --targets targets.csv \
        --literals literals.csv --out out/pseudoc --timeout 900 \
        --max-payload-mb 128 --max-instructions 20000000
"""
from __future__ import annotations

import argparse
import collections
import csv
import os
import re
import subprocess
import sys

PROGRESS_EVERY = 25
METIN_MIN = 10
NAME_TEXT_LEN = 28
CEILING_KEYS = ("maxPayloadMBytes", "maxInstructions", "defaultTimeout")
# Ghidra names a constant after its indirection degree; the address sits at the
# token tail, so the name is inserted between the prefix and the address.
TOKEN_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*?)_?([0-9a-f]{8})\b")


def jdk_requirement(ghidra_dir: str) -> int | None:
    """Return the JDK feature level Ghidra demands, read from its own file."""
    yol = os.path.join(ghidra_dir, "Ghidra", "application.properties")
    try:
        satirlar = open(yol, encoding="utf-8", errors="replace").read().splitlines()
    except OSError:
        return None
    for satir in satirlar:
        satir = satir.strip()
        if satir.startswith("application.java.min="):
            try:
                return int(satir.split("=", 1)[1])
            except ValueError:
                return None
    return None


def safe_name(ad: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", ad).strip("_") or "proc"


def oku_csv(yol: str, kolonlar: tuple[str, ...]) -> list[dict]:
    with open(yol, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    eksik = [k for k in kolonlar if rows and k not in rows[0]]
    if eksik:
        raise SystemExit("%s: missing column(s) %s" % (yol, ", ".join(eksik)))
    return rows


def targets_from(yol: str) -> list[tuple[int, str]]:
    hedefler = []
    for r in oku_csv(yol, ("va",)):
        va = int(r["va"].replace("0x", "").replace("0X", ""), 16)
        ad = (r.get("name") or "").strip() or "Proc_%X" % va
        hedefler.append((va, ad))
    return hedefler


def literals_from(yol: str | None) -> dict[int, list[dict]]:
    harita = collections.defaultdict(list)
    if not yol:
        return harita
    for r in oku_csv(yol, ("va", "addr", "text")):
        harita[int(r["va"].replace("0x", ""), 16)].append(
            {"addr": int(r["addr"].replace("0x", ""), 16), "text": r["text"],
             "sql": (r.get("is_sql") or "").strip()})
    return harita


def name_tokens(metin: str, harita: dict[int, str]) -> str:
    """Insert a short literal name before the address at each token tail.

    Two guards: a token whose address is not ours is left alone (Ghidra also
    emits `FUN_x` and data symbols we never catalogued), and a token whose text
    Ghidra already inlined is not doubled.
    """
    def cevir(m):
        on_ek, adres = m.group(1), m.group(2)
        ad = harita.get(int(adres, 16))
        if not ad:
            return m.group(0)
        taban = "DAT" if not on_ek else on_ek
        return "%s_%s_%s" % (taban, ad, adres)
    return TOKEN_RE.sub(cevir, metin)


def literal_names(litler: list[dict]) -> dict[int, str]:
    adlar = {}
    for lit in litler:
        parca = " ".join(lit["text"].split())[:NAME_TEXT_LEN]
        if len(parca) >= METIN_MIN:
            adlar.setdefault(lit["addr"], re.sub(r"[^A-Za-z0-9]+", "_", parca).strip("_").lower())
    return adlar


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("exe", help="VB6 executable to decompile")
    ap.add_argument("--targets", required=True, help="CSV with a va column, optional name column")
    ap.add_argument("--literals", help="optional CSV: va,addr,text[,is_sql] used to name literal tokens")
    ap.add_argument("--out", required=True, help="directory for one .c file per procedure")
    ap.add_argument("--summary", help="default: <out>/ghidra_summary.csv")
    ap.add_argument("--project", help="Ghidra project directory (default: <out>/_ghidra_proj)")
    ap.add_argument("--ghidra", default=os.environ.get("GHIDRA_INSTALL_DIR"),
                    help="Ghidra install dir (default: GHIDRA_INSTALL_DIR)")
    ap.add_argument("--java-home", default=os.environ.get("JAVA_HOME"))
    ap.add_argument("--limit", type=int, default=0, help="decompile at most N targets")
    ap.add_argument("--timeout", type=int, default=300, help="per-function timeout, seconds")
    ap.add_argument("--max-payload-mb", type=int, help="override DecompileOptions payload ceiling")
    ap.add_argument("--max-instructions", type=int, help="override DecompileOptions instruction ceiling")
    ap.add_argument("--print-options", action="store_true", help="show Ghidra defaults and exit")
    ap.add_argument("--overwrite", action="store_true", help="re-decompile existing output files")
    args = ap.parse_args(argv)

    if not args.ghidra:
        raise SystemExit("GHIDRA_INSTALL_DIR is not set and --ghidra was not given")
    gerek = jdk_requirement(args.ghidra)
    launch = os.path.join(args.ghidra, "support", "LaunchSupport.jar")
    java = args.java_home or "java"
    cmd = [os.path.join(java, "bin", "java") if args.java_home else "java",
           "-jar", launch, args.ghidra, "-jdk_home", "-save"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
    except OSError as e:
        raise SystemExit("cannot run LaunchSupport (%s): %s" % (" ".join(cmd), e))
    if res.returncode != 0:
        raise SystemExit("LaunchSupport rejected the JDK (need feature level %s per "
                         "application.properties): %s"
                         % (gerek, (res.stdout + res.stderr).strip()[:300]))

    import pyghidra  # noqa: E402  (needs start() before Ghidra imports)

    pyghidra.start(verbose=False, use_modules=True, offscreen=True)
    from ghidra.app.cmd.disassemble import DisassembleCommand  # noqa: E402
    from ghidra.app.decompiler import DecompileOptions, DecompInterface  # noqa: E402
    from ghidra.program.flatapi import FlatProgramAPI  # noqa: E402
    from ghidra.program.model.address import AddressSet  # noqa: E402
    from pyghidra import open_program, transaction  # noqa: E402

    hedefler = targets_from(args.targets)
    if args.limit:
        hedefler = hedefler[:args.limit]
    lit_harita = literals_from(args.literals)

    proje = args.project or os.path.join(args.out, "_ghidra_proj")
    os.makedirs(proje, exist_ok=True)
    os.makedirs(args.out, exist_ok=True)
    with open_program(args.exe, project_location=proje, project_name="vb6d",
                      update=True, analyze=False) as prog:
        api = FlatProgramAPI(prog)
        dfi = DecompInterface()
        opt = DecompileOptions()
        varsayilan = {k: getattr(opt, "get" + k[0].upper() + k[1:])() for k in CEILING_KEYS}
        print("Ghidra defaults: maxPayloadMBytes=%s maxInstructions=%s defaultTimeout=%s"
              % (varsayilan["maxPayloadMBytes"], varsayilan["maxInstructions"],
                 varsayilan["defaultTimeout"]))
        print("language=%s blocks=%d" % (prog.getLanguage().getLanguageID().getIdAsString(),
                                         len(prog.getMemory().getBlocks())))
        if args.print_options:
            return 0
        if args.max_payload_mb:
            opt.setMaxPayloadMBytes(args.max_payload_mb)
        if args.max_instructions:
            opt.setMaxInstructions(args.max_instructions)
        opt.setAnalyzeForLoops(True)
        dfi.setOptions(opt)
        dfi.openProgram(prog)

        ozet_yol = args.summary or os.path.join(args.out, "ghidra_summary.csv")
        cozulen = atlanan = 0
        toplam_sn = 0.0
        zaman = __import__("time").monotonic
        for i, (va, ad) in enumerate(hedefler, 1):
            adres = api.getAddressFactory().getAddress("0x%08x" % va)
            fonk = api.getFunctionAt(adres)
            if fonk is None:
                with transaction(prog, "vb6d bounds"):
                    api.createFunction(adres, safe_name(ad))
                fonk = api.getFunctionAt(adres)
            if fonk is None:
                atlanan += 1
                print("SKIP %s %08x: cannot create function" % (ad, va), flush=True)
                continue
            if not fonk.getBody().isEmpty():
                aralik = AddressSet(fonk.getBody().getStartAddress(),
                                    fonk.getBody().getEndAddress())
                DisassembleCommand(aralik, None, True).applyTo(prog, None)
            bas = zaman()
            sonuc = dfi.decompileFunction(fonk, args.timeout, None)
            sn = zaman() - bas
            if not sonuc.decompileCompleted():
                atlanan += 1
                sebep = sonuc.getErrorMessage() or (
                    "failed to start" if sonuc.failedToStart() else "cancelled")
                kind = "ceiling" if ("exceeded maximum allowable instructions" in sebep
                                     or "Response buffer size exceeded" in sebep) else "timeout"
                print("SKIP %s %08x (%s): %s" % (ad, va, kind, sebep[:160]), flush=True)
                continue
            cozulen += 1
            toplam_sn += sn
            govde = sonuc.getDecompiledFunction().getC()
            adlar = literal_names(lit_harita.get(va, []))
            if adlar:
                govde = name_tokens(govde, adlar)
            yol = os.path.join(args.out, "%s__%08x.c" % (safe_name(ad), va))
            if args.overwrite or not os.path.exists(yol):
                open(yol, "w", encoding="utf-8").write(govde)
            say = collections.Counter(
                sozcuk for sozcuk in re.findall(r"\b(if|else|while|for|goto)\b", govde))
            satir = govde.count("\n") + 1
            print("OK %s %08x sn=%.1f lines=%d if=%d while=%d for=%d goto=%d"
                  % (ad, va, sn, satir, say["if"], say["while"], say["for"], say["goto"]),
                  flush=True)
            if i % PROGRESS_EVERY == 0:
                print("PROGRESS %d/%d seconds=%.0f" % (i, len(hedefler), toplam_sn), flush=True)

        with open(ozet_yol, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["targets", "solved", "skipped", "seconds_solved", "out_dir"])
            w.writerow([len(hedefler), cozulen, atlanan, "%.1f" % toplam_sn, args.out])
        print("SUMMARY solved=%d skipped=%d of %d targets, %.1f s of decompiler time -> %s"
              % (cozulen, atlanan, len(hedefler), toplam_sn, ozet_yol))
    return 0


if __name__ == "__main__":
    sys.exit(main())
