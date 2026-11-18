"""Per-procedure operation outline: call counts read through the runtime table.

Input is ``edges.jsonl`` (see :mod:`vb6decompiler.edges`); every hit on the
VB6 runtime is bucketed by the runtime table's own ``category`` — a third
party's reverse-engineering notes marked unverified, so the output field is
named for that marker and stderr repeats the word. Runtime names the table
does not categorize, and hits on other DLLs, get counts and no
interpretation: a category is never invented here, and late-bound counts
stay counts because nothing here can say what they were.
"""
from __future__ import annotations

from . import runtime_table

#: hits on this dll (case-insensitive) go through the runtime table
RUNTIME_DLL = "MSVBVM60.DLL"


def outline_row(edge: dict) -> dict:
    """The outline for one edges row: categories where known, counts elsewhere."""
    ops: dict[str, int] = {}
    unknown: dict[str, int] = {}
    api: dict[str, int] = {}
    for src in ("calls_imported", "calls_thunks"):
        for name, count in (edge.get(src) or {}).items():
            dll, _, tail = name.partition("!")
            if dll.upper() == RUNTIME_DLL:
                call = runtime_table.describe(tail)
                if call is not None and call.category:
                    ops[call.category] = ops.get(call.category, 0) + count
                else:
                    unknown[name] = unknown.get(name, 0) + count
            else:
                api[name] = api.get(name, 0) + count
    r: dict = {"va": edge["va"], "object_name": edge.get("object_name"),
               "names": edge.get("names", []),
               "unverified_operations": ops, "api_calls": api}
    if unknown:
        r["runtime_unlisted"] = unknown
    late = edge.get("calls_late_bound")
    if late:
        r["late_bound_calls"] = late  # a count, not a claim: nothing here names them
    return r
