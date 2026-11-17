"""Unit tests for the runtime-call table.

The table is generated from one build of msvbvm60.dll, so most of what can be
asserted without that DLL is a *shape* invariant: measured ordinals, and the rule
that any text taken from a third party carries the `unverified` marker.
"""

from __future__ import annotations

import json
import os

import pytest

from vb6decompiler import runtime_table

#: Names the sources that started this table cared about. Reported, not required:
#: the table follows the DLL, and a name the DLL does not export cannot be in it.
PRIORITY_NAMES = (
    "__vbaCheckTypeVar",
    "__vbaStrCompVar",
    "__vbaVarLateMemCallSt",
    "__vbaLateIdStAd",
    "__vbaUI1I2",
    "__vbaUI1I4",
    "__vbaNextEachCollVar",
    "__vbaVarIndexLoad",
    "__vbaI2Var",
)


def _entries() -> dict:
    return runtime_table._entries()


def test_table_and_lookup_agree_on_a_name_the_runtime_exports():
    entries = _entries()
    assert entries, "generated table is missing or empty"
    name = "__vbaFreeStr"
    call = runtime_table.describe_runtime_call(name)
    assert call is not None
    assert call.name == name
    assert call.ordinal == entries[name]["ordinal"]
    assert isinstance(call.ordinal, int) and call.ordinal > 0


def test_unknown_name_is_none_not_an_error():
    assert runtime_table.describe_runtime_call("__vbaNoSuchHelper") is None


def test_third_party_text_is_always_marked_unverified():
    for name, entry in _entries().items():
        assert isinstance(entry["ordinal"], int) and entry["ordinal"] > 0, name
        if entry.get("description"):
            assert runtime_table.UNVERIFIED in entry["source"], name
            assert entry.get("category"), name
        else:
            assert entry["source"] == "export-table", name


def test_a_missing_data_file_is_none_not_a_crash(monkeypatch, tmp_path):
    # A fresh empty directory stands in for the package: the file is not there.
    monkeypatch.setattr(runtime_table.resources, "files", lambda _package: tmp_path)
    runtime_table._entries.cache_clear()
    try:
        assert runtime_table.describe_runtime_call("__vbaFreeStr") is None
    finally:
        runtime_table._entries.cache_clear()


def test_a_corrupt_data_file_is_none_not_a_crash(monkeypatch, tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "runtime_calls.json").write_text("{ not json", encoding="utf-8")
    monkeypatch.setattr(runtime_table.resources, "files", lambda _package: tmp_path)
    runtime_table._entries.cache_clear()
    try:
        assert runtime_table.describe_runtime_call("__vbaFreeStr") is None
    finally:
        runtime_table._entries.cache_clear()


def test_priority_name_coverage_is_reported(capsys):
    entries = _entries()
    present = [n for n in PRIORITY_NAMES if n in entries]
    missing = [n for n in PRIORITY_NAMES if n not in entries]
    print(f"priority names in the table: {len(present)} of {len(PRIORITY_NAMES)}")
    if missing:
        print("not exported by the build this table came from: " + ", ".join(missing))
    # A missing name is a finding, not a failure; a present one must be well formed.
    for name in present:
        call = runtime_table.describe_runtime_call(name)
        assert call is not None and call.ordinal > 0


@pytest.mark.skipif(not os.environ.get("VB6D_MSVBVM60"),
                    reason="set VB6D_MSVBVM60 to a msvbvm60.dll to re-check the table")
def test_table_still_matches_the_local_dll():
    from vb6decompiler import pe

    exports = {n: o for n, o in pe.read(os.environ["VB6D_MSVBVM60"]).exports if n}
    entries = _entries()
    wrong = {n: (e["ordinal"], exports.get(n)) for n, e in entries.items()
             if exports.get(n) != e["ordinal"]}
    assert not wrong, f"{len(wrong)} of {len(entries)} ordinals drifted: {list(wrong)[:5]}"
