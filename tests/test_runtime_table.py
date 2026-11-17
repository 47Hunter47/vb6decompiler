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


# ------------------------------------------------------------- dossier integration
CALLS_CSV = (
    "va,label,kind,target,count,first_satir_no\n"
    "401000,FUN_401000,vba_runtime,__vbaFreeStr,3,\n"
    "401000,FUN_401000,vba_runtime,__vbaUI1I4,1,\n"
    "401000,FUN_401000,vba_runtime,__vbaNotAThing,1,\n"
    "401000,FUN_401000,api,Kernel32.GetTickCount,2,\n"
)
CALLER_LISTING = (
    "VERSION 5.00\n"
    "Private Sub cmdGo_Click()  '401000\n"
    '    mov eax, 42C3A0h ; "SELECT 1"\n'
    "End Sub\n"
)


def _dossier_run(tmp_path, with_inventory: bool):
    from vb6decompiler import dossier

    listings = tmp_path / "listings"
    listings.mkdir()
    (listings / "fDemo.frm").write_bytes(CALLER_LISTING.encode("cp1254"))
    kwargs = {}
    if with_inventory:
        inv = tmp_path / "inv"
        inv.mkdir()
        (inv / "p_calls.csv").write_text(CALLS_CSV, encoding="utf-8")
        kwargs["inventory_path"] = str(inv)
    import io
    buf = io.StringIO()
    report = dossier.stream(str(listings), buf, **kwargs)
    rows = [json.loads(line) for line in buf.getvalue().splitlines() if line.strip()]
    return rows, report


def test_dossier_annotates_runtime_calls_and_leaves_api_calls_alone(tmp_path):
    rows, report = _dossier_run(tmp_path, with_inventory=True)
    calls = rows[0]["runtime_calls"]
    assert [c["name"] for c in calls] == ["__vbaFreeStr", "__vbaUI1I4", "__vbaNotAThing"]
    assert calls[0]["ordinal"] > 0 and runtime_table.UNVERIFIED in calls[0]["source"]
    # A name the table does not know keeps its row with nulls, never a guessed ordinal.
    assert calls[2] == {"name": "__vbaNotAThing", "count": "1", "ordinal": None,
                        "category": None, "description": None, "source": None}
    assert report.runtime_calls == 3
    assert report.runtime_calls_described == 2
    assert "runtime calls described: 2 of 3" in "\n".join(report.lines())


def test_dossier_without_call_rows_prints_no_runtime_line(tmp_path):
    rows, report = _dossier_run(tmp_path, with_inventory=False)
    assert "runtime_calls" not in rows[0]
    assert report.runtime_calls == 0
    assert "runtime calls" not in "\n".join(report.lines())


# ------------------------------------------------------------------- packaging
def test_the_data_file_is_inside_the_built_wheel(tmp_path):
    """A table that exists in the checkout but not in the wheel is invisible on PyPI."""
    import subprocess
    import sys
    import zipfile
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    out = tmp_path / "wheel"
    # Isolation on purpose: CI's runtime environment has no setuptools, so the build
    # backend has to come from the wheel that pip fetches for the build.
    built = subprocess.run(
        [sys.executable, "-m", "pip", "wheel", str(root), "--no-deps",
         "-w", str(out), "-q"],
        capture_output=True, text=True,
    )
    assert built.returncode == 0, built.stderr[-800:]
    wheels = sorted(out.glob("*.whl"))
    assert len(wheels) == 1, f"expected one wheel, got {wheels}"
    assert "vb6decompiler/data/runtime_calls.json" in zipfile.ZipFile(wheels[0]).namelist()


# --------------------------------------------------------------------- ordinal imports
# A build can import a helper by ordinal alone; the decompiler then prints `ord_598`.
# Resolving it is only legitimate against the DLL build the table was generated from,
# which is why the resolved record names that build.
def test_an_ordinal_resolves_to_this_build_s_export_name():
    call = runtime_table.describe_runtime_ordinal(598)
    assert call is not None
    assert call.name and call.ordinal == 598
    assert call.source.startswith("export-table ord")
    assert runtime_table.table_dll() in call.source  # the name is valid for that build only


def test_an_ordinal_this_build_does_not_name_answers_none():
    # 1276 exports of that DLL are ordinal-only: no name exists, and none is invented.
    assert runtime_table.describe_runtime_ordinal(712) is None
    assert runtime_table.describe_runtime_ordinal(999999) is None


def test_both_spellings_go_through_one_entry_point():
    by_name = runtime_table.describe("rtcMsgBox")
    by_ordinal = runtime_table.describe(f"ord_{by_name.ordinal}")
    assert by_ordinal is not None and by_ordinal.name == by_name.name
    assert runtime_table.describe("ord_notanumber") is None
    assert runtime_table.describe("") is None
    assert runtime_table.describe("rtcNoSuchHelper") is None


def test_ordinals_are_unique_so_the_inverse_is_unambiguous():
    # A duplicate ordinal would make ordinal -> name a coin toss.
    entries = runtime_table._entries()
    ordinals = [e["ordinal"] for e in entries.values() if isinstance(e, dict)]
    assert len(ordinals) == len(set(ordinals))
    assert len(runtime_table._by_ordinal()) == len(ordinals)


def test_the_table_names_the_dll_it_speaks_for():
    # Without this, an ordinal-derived name cannot be attributed to a build.
    assert runtime_table.table_dll().startswith("msvbvm60.dll ")
    assert "sha256" in runtime_table.table_dll()


def test_a_dossier_annotates_an_ordinal_only_call(tmp_path):
    from vb6decompiler import dossier

    inv = {"calls": [{"va": "401000", "kind": "vba_runtime", "target": "ord_598", "count": "2"},
                     {"va": "401000", "kind": "vba_runtime", "target": "ord_712", "count": "1"},
                     {"va": "401000", "kind": "vba_runtime", "target": "rtcMsgBox", "count": "4"}]}
    report = dossier.DossierReport()
    rows = dossier.runtime_call_rows(inv, report)
    assert [r["name"] for r in rows] == [runtime_table.describe_runtime_ordinal(598).name, "ord_712", "rtcMsgBox"]
    assert rows[0]["ordinal"] == 598 and "export-table ord" in rows[0]["source"]
    # An ordinal with no name keeps its spelling and carries no invented fields.
    assert rows[1]["ordinal"] is None and rows[1]["description"] is None
    assert report.runtime_calls == 3
