"""What an ``MSVBVM60`` export is called — and, where a source says so, what it does.

A dossier reader meets ``call ds:__vbaVarLateMemCallSt`` and the name explains
nothing. This module answers that one question from
``data/runtime_calls.json``, generated against a real runtime DLL by
``scripts/gen_runtime_table.py`` (msvbvm60.dll 6.00.9848, export table read with
:mod:`vb6decompiler.pe`).

Trust, split by field:

* ``ordinal`` and the presence of ``name`` were measured from that DLL's export
  table. Ordinals belong to one build; a different msvbvm60 build may number them
  differently, so this table never claims otherwise.
* ``category`` and ``description`` are a third party's reverse-engineering notes
  (Apache-2.0 ``visualbasic`` crate). Their ``source`` says ``unverified``, and a
  caller that prints them must print that word with them.

An unknown name, a deleted data file or a corrupt one answers ``None`` — this is an
annotation, never a reason for the run to fail.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

#: Package-relative path of the generated table; must ship in the wheel.
DATA_FILE = "data/runtime_calls.json"

#: Marker inside ``RuntimeCall.source`` for text no test here has verified.
UNVERIFIED = "unverified"


@dataclass(frozen=True)
class RuntimeCall:
    """One exported runtime helper, as far as the table can speak for it."""

    name: str
    ordinal: int
    category: str | None
    description: str | None
    source: str

    @property
    def is_verified(self) -> bool:
        """``False`` when any field came from an unverified third-party note."""
        return UNVERIFIED not in self.source


@lru_cache(maxsize=1)
def _entries() -> dict[str, dict]:
    """The table, read once. Any problem yields an empty table, not an exception."""
    try:
        raw = resources.files("vb6decompiler").joinpath(DATA_FILE).read_text(encoding="utf-8")
        entries = json.loads(raw)["entries"]
        return entries if isinstance(entries, dict) else {}
    except (OSError, ValueError, KeyError, TypeError):
        return {}


def describe_runtime_call(name: str) -> RuntimeCall | None:
    """The table's record for ``name``, or ``None`` when it has nothing to say."""
    entry = _entries().get(name)
    if not isinstance(entry, dict):
        return None
    try:
        return RuntimeCall(
            name=name,
            ordinal=int(entry["ordinal"]),
            category=entry.get("category"),
            description=entry.get("description"),
            source=str(entry.get("source") or "export-table"),
        )
    except (KeyError, TypeError, ValueError):
        return None
