"""One dossier JSONL record, validated for the fields a reader actually consumes.

:mod:`vb6decompiler.dossier` is the writer; ``xref``, ``edges`` and
``decode --procs`` are readers. They used to validate different subsets, so a
record one accepted could make its sibling fail halfway through a batch. This is
the shared gate: :func:`reject_reason` returns a short reason for a
``# line n:`` note, or ``None`` when the field types are those the dossier
format defines. It is not a schema framework — only the documented fields.

Address rule: the dossier writes bare uppercase hex (``401000``). Python's
``int(value, 16)`` also accepts ``0x`` prefixes, signs, underscores and
surrounding whitespace, none of which is the documented format, so the gate
checks the string shape before converting.
"""
from __future__ import annotations

import re

_HEX_RE = re.compile(r"[0-9A-Fa-f]{1,16}\Z")


def hex_va(value: object) -> int | None:
    """The address a documented hex string spells, or ``None`` if it is not one."""
    if isinstance(value, str) and _HEX_RE.fullmatch(value):
        return int(value, 16)
    return None


def reject_reason(rec: object, *, literals: bool = False, sql: bool = False,
                  counts: bool = False) -> str | None:
    """Why a consumer cannot read this record, or ``None`` when it can.

    ``literals``/``sql``/``counts`` opt into the nested structures a particular
    consumer reads; ``va``, ``object_name`` and ``name_hint`` are checked
    always, because every consumer reads at least those.
    """
    if not isinstance(rec, dict):
        return "record is not a JSON object"
    va = rec.get("va")
    if not isinstance(va, str) or not va:
        return "no va"
    if hex_va(va) is None:
        return f"va {va!r} is not a hex address"
    name = rec.get("object_name")
    if name is not None and not isinstance(name, str):
        return "object_name is not a string or null"
    hint = rec.get("name_hint")
    if hint is not None and not isinstance(hint, dict):
        return "name_hint is not an object"
    names = (hint or {}).get("names")
    if names is not None and not (isinstance(names, list)
                                  and all(isinstance(x, str) for x in names)):
        return "name_hint.names is not a list of strings"
    if counts:
        values = rec.get("counts")
        if values is not None and not (isinstance(values, dict)
                                       and all(isinstance(v, int) for v in values.values())):
            return "counts is not an object of integers"
    if literals:
        entries = rec.get("literals")
        if entries is not None:
            if not isinstance(entries, list):
                return "literals is not a list"
            for entry in entries:
                if not isinstance(entry, dict):
                    return "literals has a non-object entry"
                if hex_va(entry.get("va")) is None:
                    return f"literals entry va {entry.get('va')!r} is not a hex address"
                if not isinstance(entry.get("text"), str):
                    return "literals entry text is not a string"
    if sql:
        entries = rec.get("sql")
        if entries is not None:
            if not isinstance(entries, list):
                return "sql is not a list"
            for entry in entries:
                if not isinstance(entry, dict):
                    return "sql has a non-object entry"
                if not isinstance(entry.get("text"), str):
                    return "sql entry has a non-string text/text_va"
                text_va = entry.get("text_va", "")
                if not isinstance(text_va, str) or (text_va and hex_va(text_va) is None):
                    return "sql entry has a non-string text/text_va"
    return None
