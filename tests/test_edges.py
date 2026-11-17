"""The edges aggregator over a synthetic image + a synthetic dossier.

Needs the decode engine: same isolation as the other capstone tests.
"""
import json

import pytest

from _mini_pe import mini_pe

CODE = bytes.fromhex("FF25B4104000" + "00" * 10
                      + "E8EBFFFFFF" + "E80C000000" + "E8DDFFFFFF" + "FF15B0104000"
                      + "C3" + "C3")
# A thunk (jmp [slot B]) sits at 0x401000, BELOW the listed population that
# starts at 0x401010.  Body A (0x401010, rets 0x401025) calls the thunk,
# calls body B at 0x401026, calls 0x400FFC (no bytes anywhere), and calls
# import slot A directly.  The dossier population deliberately starts at A.


@pytest.fixture()
def fixture(tmp_path):
    pytest.importorskip("capstone")
    exe = tmp_path / "two.exe"
    exe.write_bytes(mini_pe(code=CODE, imports=True))
    procs = tmp_path / "dossier.jsonl"
    procs.write_text(
        '{"va": "401010", "object_name": "fA", "name_hint": {"names": ["Proc_1"]}}\n'
        '{"va": "401026", "object_name": "fB", "name_hint": {"names": ["Proc_2"]}}\n',
        encoding="utf-8")
    return exe, procs


def test_collect_aggregates_one_row_per_procedure(fixture):
    from vb6decompiler import edges

    exe, procs = fixture
    rows, bad, totals = edges.collect(str(exe), str(procs))
    assert bad == 0
    assert [r["va"] for r in rows] == ["401010", "401026"]
    a, b = rows
    assert a["ended"] == "ret"
    assert a["calls_imported"] == {"kernel32!ProcA": 1}
    assert a["calls_procedures"] == {"401026": 1}
    assert a["calls_thunks"] == {"kernel32!ProcB": 1}  # two-hop jmp [slot]
    assert a["calls_late_bound"] == 0
    # 0x400FFC: no bytes, not a thunk, no object table in this synthetic
    # image -> stays a counted unnamed hit (a result, not a shrug)
    assert a["calls_other"] == {"400FFC": 1}
    assert "calls_objects" not in a
    assert b["ended"] == "ret" and b["instructions"] == 1
    assert b.get("range_capped") is True  # the last range has no next VA
    assert totals == {"calls": 4, "named": 1, "thunk_named": 1, "edges": 1,
                      "late_bound": 0, "uncensus": 1, "obj_named": 0}


def test_edges_cli_writes_jsonl_and_counts(fixture, tmp_path, capsys):
    from vb6decompiler import cli

    exe, procs = fixture
    out = tmp_path / "edges.jsonl"
    code = cli.main(["edges", str(exe), "--dossier", str(procs), "--out", str(out)])
    _o, err = capsys.readouterr()
    assert code == 0
    lines = out.read_text(encoding="utf-8").splitlines()
    rows = [json.loads(x) for x in lines]
    assert len(rows) == 2 and rows[0]["calls_procedures"] == {"401026": 1}
    assert "2 procedures" in err
    assert "1 named via import thunks" in err
    capsys.readouterr()
    assert cli.main(["edges", str(exe), "--dossier", str(tmp_path / "nope.jsonl")]) == 2
