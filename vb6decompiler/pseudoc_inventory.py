#!/usr/bin/env python3
"""Harvest inventories from decompiler pseudo-C (Ghidra output, one file per procedure).

Why: a decompiler's pseudo-C is the only place that shows, for one procedure,
*the order things happen in*.  Our own static inventories know which literals a
procedure touches and which procedures a call edge connects, but only the
emitted body says which SQL fragment is concatenated before which one, which
line made a call, and which branch decision was taken.  These CSVs turn that
ordering into data instead of prose:

* `<prefix>_order.csv`       literals in the order they appear in the body
                             (this is what lets a split SQL statement be stitched
                             in the right sequence — no other source orders it)
* `<prefix>_vtable.csv`      `(*DAT_<obj>)[slot]` indirect calls: object address + slot
* `<prefix>_calls.csv`       ordered call edges with line numbers; `__vba*` runtime
                             helpers are aggregated because they are noise at line level
* `<prefix>_conditions.csv`  branch conditions that reference a parameter or a named
                             constant (the generic decompiler resolves branches a VB6
                             tool leaves as `GoTo loc_`)
* `<prefix>_globals.csv`     census of unnamed `DAT_x` globals by procedure frequency:
                             the run-time trace shortlist, since no static name table
                             exists for these in a VB6 build

Two traps are baked in:

* The same procedure may exist twice on disk (a raw run and a renamed re-run).
  Everything here deduplicates **by address**, keeping the larger file, because
  the same body counted twice inflates every number.
* Parenthesised conditions are closed by counting depth, not with a lazy regex:
  `if (__vbaStrCmp(x, "a)b") == 0)` closes early for a regex and silently loses
  the rest of the condition.

Input shape matches `scripts/ghidra_bridge.py` output: `<label>__<va>.c`.

Usage:

    python scripts/pseudoc_inventory.py --corpus out/pseudoc --out-dir out \\
        --literals out/literals.csv --global-literals out/all_literals.csv
"""
from __future__ import annotations

import argparse
import collections
import csv
import os
import re
import sys

KOLON_SIRA = ["va", "label", "sira", "addr", "text", "is_sql", "source"]
KOLON_VT = ["va", "label", "satir_no", "object_addr", "slot"]
KOLON_CAGRI = ["va", "label", "kind", "target", "count", "first_satir_no"]
KOLON_KOSUL = ["va", "label", "satir_no", "kind", "condition", "params", "constants"]
KOLON_PARAM = ["va", "label", "satir_no", "kind", "target", "note"]
KOLON_GLOBAL = ["addr", "procedures", "first_seen"]
METIN_MIN = 10
TEXT_WINDOW = 16
ADRES_RE_TPL = r"(?<![0-9a-f])(?:0x)?%08x(?![0-9a-f])"
VTABLE_RE = re.compile(r"\(\*DAT_([0-9a-f]{8})\)\[\s*(0x[0-9a-f]+|\d+)\s*\]")
VBA_RE = re.compile(r"__vba[A-Za-z0-9_]+\s*\(")
FUN_RE = re.compile(r"\bFUN_[0-9a-f]{8}\b")
DAT_RE = re.compile(r"\bDAT_([0-9a-f]{8})", re.IGNORECASE)
CALL_RE = re.compile(r"(?<![A-Za-z0-9_])(FUN_[0-9a-f]{8}|[A-Za-z_][A-Za-z0-9_]{3,})\(")
NAMED_RE = re.compile(r"\b(?:PTR_)*(sql|str)_([a-z0-9_]+?)_([0-9a-f]{8})\b")
PARAM_RE = re.compile(r"\bparam_(\d+)\b")
KOSUL_ADLARI = ("} else if (", "else if (", "if (", "while (")


def norm(adres) -> str:
    """One representation for addresses: lowercase hex, no leading zeros.

    Cards store ints, CSVs store hex strings; comparing a decimal string against
    a hex one silently produces zero matches, which is the worst kind of failure
    in a harvester.
    """
    if isinstance(adres, int):
        return "%08x" % adres
    return str(adres).replace("0x", "").strip().lower().lstrip("0")


def kanon(adres) -> str:
    """Canonical 8-hex-digit form for output columns (joining uses norm())."""
    return "%08x" % int(str(adres).replace("0x", ""), 16)


def read_rows(yol, kolonlar):
    with open(yol, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    eksik = [k for k in kolonlar if rows and k not in rows[0]]
    if eksik:
        raise SystemExit("%s: missing column(s) %s" % (yol, ", ".join(eksik)))
    return rows


def dedup(dizin):
    secili = {}
    for kok, _, adlar in os.walk(dizin):
        for ad in adlar:
            if not ad.endswith(".c") or "__" not in ad:
                continue
            va = ad[:-2].rsplit("__", 1)[1]
            if not re.fullmatch(r"[0-9a-fA-F]{1,8}", va):
                continue
            label = ad[:-2].rsplit("__", 1)[0]
            yol = os.path.join(kok, ad)
            anahtar = (os.path.getsize(yol), yol)
            if va not in secili or anahtar > secili[va][0]:
                secili[va] = (anahtar, label, yol)
    return {va: (lab, yol) for va, (_, lab, yol) in secili.items()}


def close_paren(sat, bas):
    """Index of the parenthesis closing the one at ``bas``, ignoring quoted text.

    Depth counting alone is not enough: a string literal may contain a closing
    parenthesis (`__vbaStrCmp(x, "a)b")`) and ends the scan early, which silently
    truncates the condition.  Escape sequences are skipped so an inner quote does
    not open/close a phantom string.
    """
    derinlik = 0
    tirnak = False
    i = bas
    while i < len(sat):
        c = sat[i]
        if tirnak:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                tirnak = False
        elif c == '"':
            tirnak = True
        elif c == "(":
            derinlik += 1
        elif c == ")":
            derinlik -= 1
            if derinlik == 0:
                return i
        i += 1
    return -1


def conditions(lines, va, label):
    satirlar, parametreler = [], []
    for no, sat in enumerate(lines, 1):
        sire = sat.strip()
        on_ek = next((k for k in KOSUL_ADLARI if sire.startswith(k)), None)
        if on_ek:
            bit = close_paren(sire, len(on_ek) - 1)
            if bit > 0:
                ic = sire[len(on_ek):bit]
                sabit = list(dict.fromkeys(NAMED_RE.findall(ic)))
                par = list(dict.fromkeys(PARAM_RE.findall(ic)))
                if sabit or par:
                    kind = "while" if on_ek.startswith("while") else (
                        "else_if" if "else" in on_ek else "if")
                    satirlar.append({"va": va, "label": label, "satir_no": no, "kind": kind,
                                     "condition": " ".join(ic.split())[:160],
                                     "params": ",".join(par),
                                     "constants": ",".join("%s_%s_%s" % x for x in sabit)})
        par = list(dict.fromkeys(PARAM_RE.findall(sire)))
        sabit = list(dict.fromkeys(NAMED_RE.findall(sire)))
        if par and sabit:
            for p in par:
                for t, metin, adres in sabit:
                    parametreler.append({"va": va, "label": label, "satir_no": no,
                                         "kind": ("concat" if "__vbaStrCat" in sire
                                                  else "compare" if ("==" in sire or "!=" in sire)
                                                  else "other"),
                                         "target": "param_%s" % p,
                                         "note": "%s_%s_%s" % (t, metin, adres)})
    return satirlar, parametreler


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--corpus", required=True, help="directory of <label>__<va>.c files")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--prefix", default="pseudoc")
    ap.add_argument("--literals", help="optional CSV: va,addr,text[,is_sql] (per-procedure cards)")
    ap.add_argument("--global-literals", help="optional CSV: addr,text[,is_sql] (whole-program literal map)")
    ap.add_argument("--cut-marker", help="if set, the body ends at this marker string "
                                         "(a driver may append its own inventory comment)")
    args = ap.parse_args(argv)

    os.makedirs(args.out_dir, exist_ok=True)
    kartlar = collections.defaultdict(list)
    if args.literals:
        for r in read_rows(args.literals, ("va", "addr", "text")):
            kartlar[norm(r["va"])].append({"addr": norm(r["addr"]), "text": r["text"],
                                           "is_sql": (r.get("is_sql") or "").strip()})
    kuresel = {}
    if args.global_literals:
        for r in read_rows(args.global_literals, ("addr", "text")):
            kuresel.setdefault(norm(r["addr"]), (r["text"], (r.get("is_sql") or "").strip()))

    sira, vt, cagri, kosul, param = [], [], [], [], []
    global_adres = collections.defaultdict(set)
    govde_var = 0
    for va, (label, yol) in sorted(dedup(args.corpus).items()):
        ham = open(yol, encoding="utf-8", errors="replace").read()
        if args.cut_marker:
            kesim = ham.find(args.cut_marker)
            if kesim > 0:
                ham = ham[:kesim]
        govde_var += 1
        alt = ham.split("\n")
        kucuk = " ".join(ham.lower().replace("\\", "").split())
        # va comes from a filename (`016a2170`), cards from a CSV (`16a2170`):
        # every lookup goes through norm() or the join silently matches nothing.
        kart_va = norm(va)
        bilinen = {norm(l["addr"]) for l in kartlar.get(kart_va, [])}

        for lit in kartlar.get(kart_va, []):
            a = lit["addr"]
            m = re.search(ADRES_RE_TPL % int(a, 16), ham.lower())
            adres_i = m.start() if m else None
            parca = " ".join(lit["text"].lower().split())[:TEXT_WINDOW]
            metin_i = kucuk.find(parca) if len(parca) >= METIN_MIN else -1
            if adres_i is None and metin_i < 0:
                continue
            if metin_i >= 0 and (adres_i is None or metin_i < adres_i):
                yer, kaynak = metin_i, "text"
            else:
                yer, kaynak = adres_i, "address"
            sira.append({"va": va, "label": label, "sira": yer, "addr": kanon(a),
                         "text": " ".join(lit["text"].split())[:160],
                         "is_sql": lit["is_sql"], "source": kaynak})
        # sorted: set iteration order varies between runs, and these rows feed the
        # order table and the census — an unstable sequence makes runs incomparable.
        for a in sorted({x.lower() for x in DAT_RE.findall(ham)}):
            if a in bilinen:
                continue
            # Census: every global this body touches that this procedure's own
            # literals cannot name — that is the run-time trace shortlist.
            global_adres[a].add(label)
            k = kuresel.get(norm(a))
            if not k:
                continue
            m = re.search(r"\bDAT_%s\b" % a, ham, re.IGNORECASE)
            if m:
                sira.append({"va": va, "label": label, "sira": m.start(), "addr": kanon(a),
                             "text": " ".join(k[0].split())[:160], "is_sql": k[1],
                             "source": "global_map"})

        # Calls are aggregated per (procedure, callee) and keep the first line: a
        # hot helper called 40 times is 40 rows of noise otherwise, and ordering is
        # still readable from first_satir_no.
        sayan = collections.OrderedDict()
        for no, sat in enumerate(alt, 1):
            for obj, slot in VTABLE_RE.findall(sat):
                vt.append({"va": va, "label": label, "satir_no": no, "object_addr": obj,
                           "slot": slot if str(slot).startswith("0x") else "0x%x" % int(slot)})
            for hedef in FUN_RE.findall(sat):
                anahtar = ("internal_unnamed", hedef)
                kayit = sayan.setdefault(anahtar, [0, no])
                kayit[0] += 1
            for sozcu in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]{3,})\s*\(", sat):
                if sozcu.startswith("__vba") or FUN_RE.match(sozcu):
                    continue
                anahtar = ("named", sozcu)
                kayit = sayan.setdefault(anahtar, [0, no])
                kayit[0] += 1
        vba = collections.Counter()
        for sat in alt:
            for eslesme in VBA_RE.findall(sat):
                vba[eslesme.strip(" (")] += 1
        for (tur, hedef), (adet, ilk) in sayan.items():
            cagri.append({"va": va, "label": label, "kind": tur, "target": hedef,
                          "count": adet, "first_satir_no": ilk})
        for hedef, adet in sorted(vba.items()):
            cagri.append({"va": va, "label": label, "kind": "vba_runtime", "target": hedef,
                          "count": adet, "first_satir_no": ""})
        k, p = conditions(alt, va, label)
        kosul += k
        param += p

    ciktilar = [("order", KOLON_SIRA, sira), ("vtable", KOLON_VT, vt),
                ("calls", KOLON_CAGRI, cagri), ("conditions", KOLON_KOSUL, kosul),
                ("params", KOLON_PARAM, param),
                ("globals", KOLON_GLOBAL,
                 [{"addr": kanon(a), "procedures": len(k),
                   "first_seen": ";".join(sorted(k)[:5])}
                  for a, k in sorted(global_adres.items(),
                                     key=lambda x: (-len(x[1]), x[0]))])]
    for ad, kolonlar, kayitlar in ciktilar:
        yol = os.path.join(args.out_dir, "%s_%s.csv" % (args.prefix, ad))
        with open(yol, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=kolonlar)
            w.writeheader()
            w.writerows(kayitlar)
        print("%s_%s.csv rows=%d" % (args.prefix, ad, len(kayitlar)))
    print("procedures=%d literals_ordered=%d (of %d procedures with output)"
          % (govde_var, len(sira), govde_var))
    sql_s = sum(1 for r in sira if r["is_sql"] == "1")
    print("SQL-flagged order rows=%d; conditions=%d (param-bound=%d, constant-bound=%d)"
          % (sql_s, len(kosul), sum(1 for r in kosul if r["params"]),
             sum(1 for r in kosul if r["constants"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
