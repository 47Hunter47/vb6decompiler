"""Per-procedure evidence, one JSON object per line — not recovered source code.

Why this exists
---------------
A lost-source application can be re-specified from what a compiled build still
proves, but only if the evidence is *per procedure*: a reader (or another tool)
re-implementing one screen needs that screen's literals in the order they were used,
the SQL statements that closed around them, and the name hints that came from a
decompiler — not a 400,000-row CSV that mixes every procedure together.

What a record may claim, and what it may not
--------------------------------------------
* ``va`` is the only identity. Names repeat inside a form (one measured target had
  267 bodies all called ``FisButton_Click``), so :func:`procs.merge_listing_names`
  returns every name a listing gave an address; ``name_hint`` carries them with
  ``"kind": "hint"`` and a reader must not treat one as the procedure's real name.
* ``literals`` are in listing order. That order is the listing's, which approximates
  program order — see the trap in :mod:`vb6decompiler.sqlstitch`.
* ``sql`` keeps ``CLOSED`` apart from every open bucket (``OPEN_QUOTE``,
  ``DANGLING``, ``ESCAPE``, ``MULTI``, ``STUCK``). An open statement is a fragment
  that needs a run-time value; it is reported as open, never completed by a guess.
* Nothing here is source code and nothing here is compilable. This module reads
  evidence the other stages already produced and writes it down; it does not decode
  instructions (:mod:`vb6decompiler.dossier` has no instruction decoder at all).

Output shape: JSONL
-------------------
One line per procedure, written as the run progresses, because one JSON array of
~34k procedures (or one file per procedure) is unwieldy for both a human and a
streaming consumer. ``--out`` names the file; without it the records go to stdout
and the summary goes to stderr, like every other stage.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import TextIO

from . import literals as literals_mod
from . import procs, runtime_table, sqlstitch
from .encoding import DEFAULT_CODEPAGE

#: Default output name when ``--out`` is not given and the caller wants a file.
DEFAULT_OUT_NAME = "dossier.jsonl"

#: Longest literal kept in a record. Longer than this and it is a blob, not a literal;
#: the count still includes it, the text is replaced by a marker so a record stays small.
MAX_LITERAL_CHARS = literals_mod.MAX_CHARS

#: Cap on SQL candidates per procedure. A long chain of fragments can generate hundreds
#: of nested prefixes; closed statements and the longest fragments are kept first, and
#: the truncation is visible in ``counts["sql_truncated"]``.
MAX_SQL_PER_PROC = 32

#: Inventory CSV kinds produced by ``scripts/pseudoc_inventory.py``. Only these are
#: merged, and each row is grouped by its ``va`` column.
INVENTORY_KINDS = ("order", "vtable", "calls", "conditions")

#: Inventory call rows that name a runtime helper (``__vbaFoo``/``rtcBar``) are the
#: only ones :mod:`vb6decompiler.runtime_table` annotates; a Win32 API call is not its
#: business.
RUNTIME_CALL_KIND = "vba_runtime"


@dataclass
class ProcedureDossier:
    """Everything the toolkit can prove about one procedure. One JSONL line."""

    va: str
    object_name: str | None = None
    name_hint: dict | None = None
    literals: list[dict] = field(default_factory=list)
    sql: list[dict] = field(default_factory=list)
    inventory: dict | None = None
    #: Runtime helpers this procedure calls, with what the export table says about
    #: each. Only filled when the inventory carried call rows (see RUNTIME_CALL_KIND).
    runtime_calls: list[dict] | None = None

    @property
    def counts(self) -> dict:
        """Counts that always agree with the lists they describe."""
        closed = sum(1 for s in self.sql if s["closed"])
        return {
            "literals": len(self.literals),
            "sql_closed": closed,
            "sql_open": len(self.sql) - closed,
            "sql_truncated": self._sql_truncated,
        }

    _sql_truncated: bool = False

    def as_dict(self) -> dict:
        out = {
            "va": self.va,
            "object_name": self.object_name,
            "name_hint": self.name_hint,
            "literals": self.literals,
            "sql": self.sql,
            "counts": self.counts,
        }
        if self.inventory is not None:
            out["inventory"] = self.inventory
        if self.runtime_calls is not None:
            out["runtime_calls"] = self.runtime_calls
        return out


@dataclass
class DossierReport:
    """What a run accounted for. Denominators, so a summary can be read as evidence."""

    procedures: int = 0
    with_literal: int = 0
    with_closed_sql: int = 0
    runtime_calls: int = 0
    runtime_calls_described: int = 0
    failed: list[tuple[str, str]] = field(default_factory=list)
    encoding: str = DEFAULT_CODEPAGE

    def lines(self) -> list[str]:
        """The ``#`` summary lines, each with its denominator."""
        out = [
            f"# {self.procedures} procedures, decoded as {self.encoding}",
            f"# procedures with >=1 literal: {self.with_literal} of {self.procedures}",
            f"# procedures with >=1 closed SQL statement: {self.with_closed_sql} of {self.procedures}",
        ]
        if self.runtime_calls:
            out.append(
                f"# runtime calls described: {self.runtime_calls_described} of "
                f"{self.runtime_calls} (descriptions are a third party's unverified notes)"
            )
        if self.failed:
            out.append(f"# failed: {len(self.failed)} of {self.procedures}")
            out.extend(f"#   failed {va}: {msg}" for va, msg in self.failed[:10])
        return out


# ---------------------------------------------------------------------------
# input: what the other stages already produced
# ---------------------------------------------------------------------------


def _objects_by_va(listing_dir: str, encoding: str) -> dict[int, str]:
    """VA -> object file name, from the same listings :func:`literals.scan_listings` reads.

    Reuses :func:`procs.parse_listing` rather than re-parsing: two regexes for one
    format drift apart, and the listing header is the only place the object name lives.
    """
    out: dict[int, str] = {}
    for root, _dirs, files in os.walk(listing_dir):
        for name in sorted(files):
            if not name.lower().endswith((".frm", ".bas", ".cls")):
                continue
            try:
                obj, names = procs.parse_listing(os.path.join(root, name), encoding=encoding)
            except OSError:
                continue
            for va in names:
                out.setdefault(va, obj)
    return out


def load_inventory(path: str) -> dict[int, dict[str, list[dict]]]:
    """``{va: {kind: [row, ...]}}`` from a ``pseudoc_inventory.py`` output directory.

    Accepts the directory the script writes (``<prefix>_order.csv`` etc.) or one such
    CSV. Rows keep their own columns: an indirect call whose object address is a
    ``DAT_x`` token stays that token, because a statically unresolvable target must not
    be turned into a guessed one.
    """
    import csv

    files: list[tuple[str, str]] = []
    if os.path.isdir(path):
        for name in sorted(os.listdir(path)):
            if not name.lower().endswith(".csv"):
                continue
            kind = name.rsplit(".", 1)[0].rsplit("_", 1)[-1]
            if kind in INVENTORY_KINDS:
                files.append((os.path.join(path, name), kind))
    elif path.lower().endswith(".csv"):
        kind = path.rsplit(".", 1)[0].rsplit("_", 1)[-1]
        files.append((path, kind if kind in INVENTORY_KINDS else "order"))
    else:
        raise ValueError(f"{os.path.basename(path)}: not a directory of inventory CSVs or a CSV")

    out: dict[int, dict[str, list[dict]]] = {}
    for file_path, kind in files:
        with open(file_path, encoding="utf-8-sig", newline="") as fh:
            for row in csv.DictReader(fh):
                raw = (row.get("va") or "").strip()
                if not raw:
                    continue
                try:
                    va = int(raw.replace("0x", ""), 16)
                except ValueError:
                    continue
                out.setdefault(va, {}).setdefault(kind, []).append(row)
    return out


def runtime_call_rows(inventory: dict | None, report: DossierReport) -> list[dict] | None:
    """Annotate the runtime helpers one procedure calls; ``None`` when it calls none.

    ``inventory`` is one procedure's ``{kind: [row, ...]}`` block. Name and ordinal
    come from the export table of the DLL the table was generated against; ``category``
    and ``description`` are a third party's reverse-engineering notes, so ``source``
    says ``unverified`` and a reader must not take them as measured.

    A target spelled ``ord_598`` is an import by ordinal alone, and
    ``runtime_table.describe`` resolves it against that one DLL build: the record's
    ``source`` names the build, because the same ordinal elsewhere is another
    function. An ordinal the build does not export by name keeps ``name: "ord_598"``
    and nulls — it is reported as unnamed, not guessed.
    """
    rows: list[dict] = []
    for row in (inventory or {}).get("calls", []):
        if row.get("kind") != RUNTIME_CALL_KIND:
            continue
        token = (row.get("target") or "").strip()
        call = runtime_table.describe(token) if token else None
        rows.append({
            "name": call.name if call else token,
            "count": row.get("count"),
            "ordinal": call.ordinal if call else None,
            "category": call.category if call else None,
            "description": call.description if call else None,
            "source": call.source if call else None,
        })
        if call is not None and call.description:
            report.runtime_calls_described += 1
    report.runtime_calls += len(rows)
    return rows or None


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------


def _sql_candidates(chain: list[literals_mod.Literal],
                    max_more: int = sqlstitch.MAX_MORE) -> tuple[list[dict], bool]:
    """SQL rows for one procedure: longest candidate per statement text, closed first.

    A chain produces one candidate per start per length, so the nested prefixes have to
    collapse: the longest text wins for a given normalised key, closed statements sort
    before open ones, and the list is capped so one 200-literal procedure cannot
    dominate a record.
    """
    best: dict[str, sqlstitch.Candidate] = {}
    for start in range(len(chain)):
        for cand in sqlstitch.stitch(chain, start, max_more=max_more):
            key = sqlstitch.key(cand.text)
            if key in best and len(best[key].text) >= len(cand.text):
                continue
            best[key] = cand
    ordered = sorted(best.values(), key=lambda c: (not c.closed, -len(c.text), c.text))
    truncated = len(ordered) > MAX_SQL_PER_PROC
    rows = [
        {
            "text": c.text,
            "status": c.status,
            "closed": c.closed,
            "parts": c.parts,
            "reason": c.reason,
            "tables": c.tables,
        }
        for c in ordered[:MAX_SQL_PER_PROC]
    ]
    return rows, truncated


def iter_dossiers(listing_dir: str, encoding: str = DEFAULT_CODEPAGE,
                  inventory: dict[int, dict[str, list[dict]]] | None = None,
                  report: DossierReport | None = None) -> Iterator[ProcedureDossier]:
    """Yield one dossier per procedure, ordered by VA; a failing one is counted.

    Streaming is the point: the caller writes each record as it arrives, so a 34k
    procedure build never sits in memory as a list of dataclasses.
    """
    report = report if report is not None else DossierReport(encoding=encoding)
    report.encoding = encoding
    all_literals = literals_mod.scan_listings(listing_dir, encoding=encoding)
    names = procs.merge_listing_names(listing_dir, encoding=encoding)
    objects = _objects_by_va(listing_dir, encoding)

    by_proc: dict[int, list[literals_mod.Literal]] = {}
    for lit in all_literals:
        if lit.proc_va is None:
            continue
        by_proc.setdefault(lit.proc_va, []).append(lit)

    for va in sorted(set(by_proc) | set(names)):
        # Counted before the work: the denominator is every procedure the run met, so
        # "X of Y" stays readable when part of Y failed.
        report.procedures += 1
        try:
            dossier = ProcedureDossier(va=f"{va:X}", object_name=objects.get(va))
            hints = names.get(va) or []
            if hints:
                dossier.name_hint = {"kind": "hint", "names": hints}
            chain = by_proc.get(va, [])
            dossier.literals = [
                {
                    "va": f"{lit.va:X}",
                    "text": lit.text if len(lit.text) <= MAX_LITERAL_CHARS
                    else lit.text[:MAX_LITERAL_CHARS],
                    "encoding": lit.encoding,
                }
                for lit in chain
            ]
            dossier.sql, dossier._sql_truncated = _sql_candidates(chain)
            if inventory is not None:
                merged = inventory.get(va)
                if merged:
                    dossier.inventory = merged
                    dossier.runtime_calls = runtime_call_rows(merged, report)
        except Exception as exc:  # one bad procedure must not end the run
            report.failed.append((f"{va:X}", f"{type(exc).__name__}: {exc}"))
            continue
        if dossier.literals:
            report.with_literal += 1
        if dossier.counts["sql_closed"]:
            report.with_closed_sql += 1
        yield dossier


def stream(listing_dir: str, out: TextIO, encoding: str = DEFAULT_CODEPAGE,
           inventory_path: str | None = None) -> DossierReport:
    """Write every dossier to ``out`` as JSONL and return what the run accounted for."""
    inventory = load_inventory(inventory_path) if inventory_path else None
    report = DossierReport(encoding=encoding)
    out.writelines(json.dumps(dossier.as_dict(), ensure_ascii=False) + "\n" for dossier in iter_dossiers(listing_dir, encoding=encoding, inventory=inventory,
                                 report=report))
    return report


def summary(report: DossierReport) -> dict:
    """The report as a dict, so a caller can assert the same numbers the CLI prints."""
    return {
        "procedures": report.procedures,
        "with_literal": report.with_literal,
        "with_closed_sql": report.with_closed_sql,
        "runtime_calls": report.runtime_calls,
        "runtime_calls_described": report.runtime_calls_described,
        "failed": len(report.failed),
    }


def main(argv: list[str] | None = None) -> int:
    """``python -m vb6decompiler.dossier <listing dir> [--out FILE] [--encoding CP]``."""
    import argparse

    parser = argparse.ArgumentParser(description="Per-procedure evidence, one JSON object per line.")
    parser.add_argument("listings", help="directory of decompiler listings")
    parser.add_argument("--out", default=None, help=f"write here instead of stdout ({DEFAULT_OUT_NAME})")
    parser.add_argument("--encoding", default=None, help="code page of the listing text")
    parser.add_argument("--inventory", default=None,
                        help="pseudoc_inventory.py output directory (or one of its CSVs)")
    args = parser.parse_args(argv)
    if not os.path.isdir(args.listings):
        print(f"error: {args.listings}: not a directory", file=sys.stderr)
        return 2
    handle = open(args.out, "w", encoding="utf-8", newline="\n") if args.out else sys.stdout
    try:
        report = stream(args.listings, handle, encoding=args.encoding or DEFAULT_CODEPAGE,
                        inventory_path=args.inventory)
    finally:
        if args.out:
            handle.close()
    for line in report.lines():
        print(line, file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = [
    "DEFAULT_OUT_NAME",
    "INVENTORY_KINDS",
    "MAX_LITERAL_CHARS",
    "MAX_SQL_PER_PROC",
    "DossierReport",
    "ProcedureDossier",
    "iter_dossiers",
    "load_inventory",
    "main",
    "runtime_call_rows",
    "stream",
    "summary",
]
