"""The edges aggregator over a synthetic image + a synthetic dossier.

Needs the decode engine: same isolation as the other capstone tests.
"""
import json

import pytest

from _mini_pe import mini_pe

CODE = bytes.fromhex("FF25B4104000" + "00" * 10
                      + "E8EBFFFFFF" + "E811000000" + "B890104000" + "E8D8FFFFFF"
                      + "FF15B0104000" + "C3" + "C3")
# A thunk (jmp [slot B]) sits at 0x401000, BELOW the listed population that
# starts at 0x401010.  Body A (0x401010, rets 0x40102A) calls the thunk,
# calls body B at 0x40102B, loads the literal at 0x401090 (mov eax, imm32),
# calls 0x400FFC (no bytes anywhere), and calls import slot A directly.
# The dossier population deliberately starts at A; its literal table names
# 0x401090 ("MERHABA").


@pytest.fixture()
def fixture(tmp_path):
    pytest.importorskip("capstone")
    exe = tmp_path / "two.exe"
    exe.write_bytes(mini_pe(code=CODE, imports=True))
    procs = tmp_path / "dossier.jsonl"
    procs.write_text(
        '{"va": "401010", "object_name": "fA", "name_hint": {"names": ["Proc_1"]},'
        ' "literals": [{"va": "401090", "text": "MERHABA", "encoding": "utf16"}]}\n'
        '{"va": "40102B", "object_name": "fB", "name_hint": {"names": ["Proc_2"]}}\n',
        encoding="utf-8")
    return exe, procs


def test_collect_aggregates_one_row_per_procedure(fixture):
    from vb6decompiler import edges

    exe, procs = fixture
    rows, bad, totals = edges.collect(str(exe), str(procs))
    assert bad == 0
    assert [r["va"] for r in rows] == ["401010", "40102B"]
    a, b = rows
    assert a["ended"] == "ret"
    assert a["calls_imported"] == {"kernel32!ProcA": 1}
    assert a["calls_procedures"] == {"40102B": 1}
    assert a["calls_thunks"] == {"kernel32!ProcB": 1}  # two-hop jmp [slot]
    assert a["calls_late_bound"] == 0
    # 0x400FFC: no bytes, not a thunk, no object table in this synthetic
    # image -> stays a counted unnamed hit (a result, not a shrug)
    assert a["calls_other"] == {"400FFC": 1}
    assert "calls_objects" not in a
    assert "events" not in a  # default stays slim
    assert b["ended"] == "ret" and b["instructions"] == 1
    assert b.get("range_capped") is True  # the last range has no next VA
    assert totals == {"calls": 4, "named": 1, "thunk_named": 1, "edges": 1,
                      "late_bound": 0, "uncensus": 1, "obj_named": 0,
                      "events": 0, "literal_events": 0}


def test_events_flag_streams_named_events_in_program_order(fixture):
    from vb6decompiler import edges

    exe, procs = fixture
    rows, _bad, totals = edges.collect(str(exe), str(procs), events=True)
    a, b = rows
    evts = a["events"]
    assert [e["va"] for e in evts] == ["401010", "401015", "40101A", "401024"]
    assert evts[0]["name"] == "kernel32!ProcB"  # thunk hop names the call
    assert evts[1]["name"] == "proc:40102B"  # range floor, marked as such
    assert evts[2]["text"] == "MERHABA"  # the immediate IS a known literal
    assert evts[3]["name"] == "kernel32!ProcA"
    assert b["events"] == []  # absence inside, padding never
    assert totals["events"] == 4 and totals["literal_events"] == 1


def test_edges_cli_writes_jsonl_and_counts(fixture, tmp_path, capsys):
    from vb6decompiler import cli

    exe, procs = fixture
    out = tmp_path / "edges.jsonl"
    code = cli.main(["edges", str(exe), "--dossier", str(procs), "--out", str(out)])
    _o, err = capsys.readouterr()
    assert code == 0
    lines = out.read_text(encoding="utf-8").splitlines()
    rows = [json.loads(x) for x in lines]
    assert len(rows) == 2 and rows[0]["calls_procedures"] == {"40102B": 1}
    assert "2 procedures" in err
    assert "1 named via import thunks" in err
    assert "events" not in err
    capsys.readouterr()
    out2 = tmp_path / "edges2.jsonl"
    assert cli.main(["edges", str(exe), "--dossier", str(procs), "--out", str(out2),
                     "--events"]) == 0
    _o, err2 = capsys.readouterr()
    assert "events on: 4 named events, 1 literal loads" in err2
    r0 = json.loads(out2.read_text(encoding="utf-8").splitlines()[0])
    assert len(r0["events"]) == 4
    assert cli.main(["edges", str(exe), "--dossier", str(tmp_path / "nope.jsonl")]) == 2
