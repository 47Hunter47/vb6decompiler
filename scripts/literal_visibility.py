#!/usr/bin/env python3
"""Measure whether a decompiler actually surfaces a program's string literals.

Why: judging a decompiler by eye gets this wrong twice, in opposite directions.

* Ghidra refers to unresolved data as `DAT_00a2d94c` — no `0x` prefix. Searching
  for `0x00a2d94c` finds nothing and invites the false verdict "this engine does
  not see the strings".
* When the data is printable and null-terminated, Ghidra hides the address
  entirely and inlines the text into the statement. An address-only count then
  finds nothing and produces the same false verdict from the other side.

So visibility is measured as *address token OR inlined text*, per literal, and
reported with its denominator.  Absence is reported as absence: a literal that
is never referenced in a procedure body is not a tool failure — the procedure
may simply not use it.

Pattern trap (this bug inflates the count): in
`(?<![0-9a-f])(?:0x)?AAA|BBB|CCC(?![0-9a-f])` the lookbehind applies only to the
first alternative and the lookahead only to the last one, so the middle
alternatives match without their boundaries.  The alternation must be wrapped:
`(?:AAA|BBB|CCC)`.  One alternative per search (this tool searches each literal
separately) avoids the trap outright.

Input shape: one file per procedure, named `<label>__<va>.c` (what
`scripts/ghidra_bridge.py` writes), plus a literals CSV with `va,addr,text`
columns and an optional `is_sql` column.

Usage:

    python scripts/literal_visibility.py --corpus out/pseudoc \
        --literals out/literals.csv --out out/visibility.csv
"""
from __future__ import annotations

import argparse
import csv
import os
import re
import sys

METIN_MIN = 10
TEXT_WINDOW = 16
ADRES_RE_TPL = r"(?<![0-9a-f])(?:0x)?%08x(?![0-9a-f])"


def normalize(metin: str) -> str:
    return " ".join(metin.lower().replace("\\", "").split())


def read_rows(yol: str, kolonlar: tuple[str, ...]) -> list[dict]:
    with open(yol, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    eksik = [k for k in kolonlar if rows and k not in rows[0]]
    if eksik:
        raise SystemExit("%s: missing column(s) %s" % (yol, ", ".join(eksik)))
    return rows


def corpus_files(dizin: str) -> dict[str, str]:
    """Map procedure VA -> file, keeping the larger file when one VA was run twice."""
    secili: dict[str, tuple[int, str]] = {}
    for kok, _, adlar in os.walk(dizin):
        for ad in adlar:
            if not ad.endswith(".c") or "__" not in ad:
                continue
            va = ad[:-2].rsplit("__", 1)[1]
            if not re.fullmatch(r"[0-9a-fA-F]{1,8}", va):
                continue
            va = va.lower()
            yol = os.path.join(kok, ad)
            anahtar = (os.path.getsize(yol), yol)
            if va not in secili or anahtar > secili[va]:
                secili[va] = anahtar
    return {va: boyut_yol[1] for va, boyut_yol in secili.items()}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--corpus", required=True, help="directory of <label>__<va>.c files")
    ap.add_argument("--literals", required=True, help="CSV: va,addr,text[,is_sql]")
    ap.add_argument("--out", required=True, help="per-literal visibility CSV")
    ap.add_argument("--cut-marker", help="cut the body at this marker string: a driver often "
                                         "appends its own comment block listing every literal "
                                         "address, and that block would make all of them visible "
                                         "even when the code never references them")
    args = ap.parse_args(argv)

    dosyalar = corpus_files(args.corpus)
    if not dosyalar:
        raise SystemExit("no <label>__<va>.c files under %s" % args.corpus)

    govde = {}
    for va, yol in dosyalar.items():
        metin = open(yol, encoding="utf-8", errors="replace").read()
        if args.cut_marker:
            kesim = metin.find(args.cut_marker)
            if kesim > 0:
                metin = metin[:kesim]
        govde[va] = (metin, normalize(metin))

    satirlar = []
    for r in read_rows(args.literals, ("va", "addr", "text")):
        va = r["va"].replace("0x", "").lower().lstrip("0")
        anahtar = next((k for k in govde if k.lstrip("0") == va), None)
        if anahtar is None:
            continue
        ham, kucuk = govde[anahtar]
        adres = int(r["addr"].replace("0x", ""), 16)
        m = re.search(ADRES_RE_TPL % adres, ham.lower())
        adres_i = m.start() if m else None
        parca = " ".join(r["text"].lower().split())[:TEXT_WINDOW]
        metin_i = kucuk.find(parca) if len(parca) >= METIN_MIN else -1
        if metin_i >= 0 and (adres_i is None or metin_i < adres_i):
            gorunur, nasil, indeks = True, "text", metin_i
        elif adres_i is not None:
            gorunur, nasil, indeks = True, "address", adres_i
        else:
            gorunur, nasil, indeks = False, "", ""
        satirlar.append({"va": "%08x" % int("0" + va, 16), "file": os.path.basename(dosyalar[anahtar]),
                         "addr": "%08x" % adres, "visible": int(gorunur), "how": nasil,
                         "at_index": indeks, "is_sql": (r.get("is_sql") or "").strip(),
                         "text": " ".join(r["text"].split())[:160]})

    with open(args.out, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["va", "file", "addr", "visible", "how",
                                          "at_index", "is_sql", "text"])
        w.writeheader()
        w.writerows(satirlar)

    g = sum(s["visible"] for s in satirlar)
    sql_t = sum(1 for s in satirlar if s["is_sql"] == "1")
    sql_g = sum(1 for s in satirlar if s["is_sql"] == "1" and s["visible"])
    adres_g = sum(1 for s in satirlar if s["visible"] and s["how"] == "address")
    metin_g = sum(1 for s in satirlar if s["visible"] and s["how"] == "text")
    print("visible=%d of %d literals (address-first=%d, text-first=%d)" % (g, len(satirlar), adres_g, metin_g))
    print("SQL-flagged: visible=%d of %d" % (sql_g, sql_t))
    print("procedures with decompiled output=%d, literals with no procedure file=%d"
          % (len(dosyalar), sum(1 for r in read_rows(args.literals, ("va", "addr", "text"))
                                if r["va"].replace("0x", "").lower().lstrip("0")
                                not in {k.lstrip("0") for k in govde})))
    print("out=%s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
