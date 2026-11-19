"""xref: read a dossier file back as a question-shaped index.

``vb6d dossier`` answers "what does this procedure contain"; an agent usually
starts from the other side — "which procedures touch this string / this SQL".
The dossier JSONL already holds every fact needed for that direction; this
just inverts it, so the answer is one command instead of jq gymnastics.

Three output shapes (all on stdout, one JSON document):
* default: a per-procedure rollup (owner, hint, counts) — small enough to
  stream;
* ``--literal SUBSTR`` / ``--sql SUBSTR``: the search direction — matching
  entries with the procedures that own them (case-insensitive substring;
  matching is on the recovered text, never on a guess);
* ``--full``: both directions at once (large on real builds — the dossier of
  the reference build carries 441,607 literal mentions).

Lineage is carried through: procedure VA, owner object, literal VAs and SQL
text VAs come straight from the dossier records; xref invents nothing and
relabels nothing.
"""
from __future__ import annotations

import json
from typing import TextIO


def _usable(rec: object) -> str | None:
    """Rejection reason for one parsed dossier line, or None when xref can read it.

    The shared gate lives in :mod:`vb6decompiler.records`; xref opts into every
    nested structure it indexes (literals, sql, counts). A valid JSON document is
    not a dossier record: a shape mismatch is REJECTED and counted, never coerced
    into looking fine.
    """
    from . import records

    return records.reject_reason(rec, literals=True, sql=True, counts=True)


def _procedures(fh: TextIO) -> tuple[list[dict], list[str]]:
    """Parse dossier records into (procedure rollups, bad-line notes).

    A dossier written without ``--inventory`` simply has no inventory field;
    nothing here requires one. Lines that fail JSON parsing or record shape
    are counted and named (line + reason) — one corrupt line must not void
    the file, and one crash must not be needed to notice it (same policy as
    the dossier builder).
    """
    procs, bad = [], []
    for n, line in enumerate(fh, 1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            bad.append(f"line {n}: not JSON")
            continue
        reason = _usable(rec)
        if reason is not None:
            bad.append(f"line {n}: {reason}")
            continue
        hint = rec.get("name_hint") or {}
        procs.append({
            "va": rec.get("va"),
            "object_name": rec.get("object_name"),
            "hints": hint.get("names") or [],
            "counts": rec.get("counts") or {},
            "literals": rec.get("literals") or [],
            "sql": rec.get("sql") or [],
        })
    return procs, bad


def _owner(p: dict) -> dict:
    return {"va": p["va"], "object_name": p["object_name"], "hints": p["hints"]}


def rollup(procs: list[dict]) -> dict:
    rows = [{"va": p["va"], "object_name": p["object_name"], "hints": p["hints"],
             "counts": p["counts"]} for p in procs]
    rows.sort(key=lambda r: (-(r["counts"].get("literals", 0)), (r["va"] or "")))
    return {"procedures": rows}


def search(procs: list[dict], needle: str, field: str) -> dict:
    """Case-insensitive substring search over literal or SQL text entries."""
    needle_fold = needle.casefold()
    hits = []
    for p in procs:
        for e in p[field]:
            text = (e.get("text") or "")
            if needle_fold in text.casefold():
                hits.append({"entry": e, "owner": _owner(p)})
                break  # one hit per (procedure, field); owners are the answer
    key = "literals" if field == "literals" else "sql"
    return {key: hits}


def full(procs: list[dict]) -> dict:
    lit: dict[str, list] = {}
    sql: dict[str, list] = {}
    for p in procs:
        for e in p["literals"]:
            lit.setdefault(e.get("va") or "", []).append(_owner(p))
        for s in p["sql"]:
            sql.setdefault(s.get("text_va") or "", []).append(_owner(p))
    return {
        "procedures": rollup(procs)["procedures"],
        "literal_to_procedures": [{"literal_va": k, "procedures": v} for k, v in
                                  sorted(lit.items(), key=lambda kv: -len(kv[1]))],
        "sql_to_procedures": [{"sql_va": k, "procedures": v} for k, v in
                              sorted(sql.items(), key=lambda kv: -len(kv[1]))],
    }
