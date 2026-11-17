"""The edges aggregator over a synthetic image + a synthetic dossier.

Needs the decode engine: same isolation as the other capstone tests.
"""
import json

import pytest

from _mini_pe import mini_pe

CODE = bytes.fromhex("E80A000000" + "FF15B0104000" + "C3" + "000000" + "C3")


@pytest.fixture()
def fixture(tmp_path):
    pytest.importorskip("capstone")
    exe = tmp_path / "two.exe"
    exe.write_bytes(mini_pe(code=CODE, imports=True))
    procs = tmp_path / "dossier.jsonl"
    procs.write_text(
        '{"va": "401000", "object_name": "fA", "name_hint": {"names": ["Proc_1"]}}\n'
        '{"va": "40100F", "object_name": "fB", "name_hint": {"names": ["Proc_2"]}}\n',
        encoding="utf-8")
    return exe, procs


def test_collect_aggregates_one_row_per_procedure(fixture):
    from vb6decompiler import edges

    exe, procs = fixture
    rows, bad, totals = edges.collect(str(exe), str(procs))
    assert bad == 0
    assert [r["va"] for r in rows] == ["401000", "40100F"]
    a, b = rows
    assert a["ended"] == "ret"
    assert a["calls_imported"] == {"kernel32!ProcA": 1}
    assert a["calls_procedures"] == {"40100F": 1}
    assert a["calls_late_bound"] == 0
    assert b["ended"] == "ret" and b["instructions"] == 1
    assert b.get("range_capped") is True  # the last range has no next VA
    assert totals == {"calls": 2, "named": 1, "edges": 1, "late_bound": 0, "uncensus": 0}
    # body A ends at its ret; the padding between A and B is never decoded,
    # and B's own single ret closes the last (capped) range


def test_edges_cli_writes_jsonl_and_counts(fixture, tmp_path, capsys):
    from vb6decompiler import cli

    exe, procs = fixture
    out = tmp_path / "edges.jsonl"
    code = cli.main(["edges", str(exe), "--dossier", str(procs), "--out", str(out)])
    _o, err = capsys.readouterr()
    assert code == 0
    lines = out.read_text(encoding="utf-8").splitlines()
    rows = [json.loads(x) for x in lines]
    assert len(rows) == 2 and rows[0]["calls_procedures"] == {"40100F": 1}
    assert "2 procedures" in err
    capsys.readouterr()
    assert cli.main(["edges", str(exe), "--dossier", str(tmp_path / "nope.jsonl")]) == 2
