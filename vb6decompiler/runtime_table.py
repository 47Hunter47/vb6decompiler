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

**An ordinal is not a name.** A build can import a helper by ordinal alone
(``call ds:[0x401060]`` where the IAT slot was filled from ``ordinal 598``); then
the pseudo-C a decompiler prints carries no name at all, and a consumer sees
``ord_598``. Resolving that ordinal to a name is possible *only* for the build in
``data/runtime_calls.json`` — the DLL is identified by file version and sha256, and
:func:`describe_runtime_ordinal` returns ``None`` for an ordinal this build does
not export. The ``source`` of such a call says ``export-table ord`` plus the build,
so a reader can see the name is only valid for that DLL. Two-thirds of that DLL's
exports are ordinal-only and have no name to give (the table records how many) —
those stay unnamed instead of being guessed.
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


def count() -> int:
    """How many helpers the table carries. ``0`` means it did not load.

    The loaders above answer ``None``/a sentinel for a missing or corrupt file so
    that no annotation can fail a run; ``doctor`` needs the other answer.
    """
    return len(_entries())


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


#: How a nameless import is spelled by the pseudo-C harvest: ``ord_598``.
ORDINAL_PREFIX = "ord_"


@lru_cache(maxsize=1)
def _by_ordinal() -> dict[int, str]:
    """ordinal -> name, inverted from the same table (one build's numbering)."""
    out: dict[int, str] = {}
    for name, entry in _entries().items():
        if isinstance(entry, dict) and isinstance(entry.get("ordinal"), int):
            out.setdefault(entry["ordinal"], name)
    return out


@lru_cache(maxsize=1)
def table_dll() -> str:
    """The DLL the table speaks for, as ``name`` version (sha256 prefix).

    A name resolved from an ordinal is only valid for this build, so callers that
    print one print this beside it.
    """
    try:
        raw = resources.files("vb6decompiler").joinpath(DATA_FILE).read_text(encoding="utf-8")
        info = json.loads(raw)["dll"]
        # Windows renders [6, 0, 98, 48] as "6.00.9848"; keep that spelling so a
        # reader can match the string to Explorer's file properties.
        major, minor, build_hi, build_lo = info["file_version"]
        version = f"{major}.{minor:02d}.{build_hi}{build_lo:02d}"
        digest = str(info.get("sha256") or "")[:8]
        return f"msvbvm60.dll {version}" + (f" (sha256 {digest})" if digest else "")
    except (OSError, ValueError, KeyError, TypeError):
        return "msvbvm60.dll (unknown build)"


def describe_runtime_ordinal(ordinal: int) -> RuntimeCall | None:
    """The record for a helper imported by ``ordinal`` alone, or ``None``.

    ``None`` is the honest answer for an ordinal this build does not export by
    name: 1,276 of its exports are ordinal-only, so there is no name to report and
    none is invented. The ``source`` names the build, because the same ordinal in
    another ``msvbvm60.dll`` is a different function.
    """
    name = _by_ordinal().get(int(ordinal))
    if name is None:
        return None
    call = describe_runtime_call(name)
    if call is None:
        return None
    # The name is measured; keep whatever third-party marker the entry carries.
    provenance = call.source.replace("export-table; ", "", 1)
    return RuntimeCall(
        name=call.name,
        ordinal=call.ordinal,
        category=call.category,
        description=call.description,
        source=f"export-table ord — {table_dll()}" + (f"; {provenance}" if provenance else ""),
    )


def describe(token: str) -> RuntimeCall | None:
    """A record for ``rtcMsgBox`` or ``ord_598``; ``None`` when the table is silent.

    One entry point for both spellings because a consumer gets whichever the
    decompiler printed, and a caller should not have to know which is which.
    """
    text = (token or "").strip()
    if not text:
        return None
    if text.startswith(ORDINAL_PREFIX):
        tail = text[len(ORDINAL_PREFIX):]
        if tail.isdigit():
            return describe_runtime_ordinal(int(tail))
        return None
    return describe_runtime_call(text)
