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


# --------------------------------------------------------------------------- lane failure reporting
# The object-table lane used to catch Exception and pretend the naming simply
# was not there - which was honest for "not a VB6 build" and a black hole for
# everything else. The expected error stays silent; anything else says so.
def test_a_fault_in_the_naming_lane_says_so_and_the_run_completes(fixture, monkeypatch, capsys):
    from vb6decompiler import edges, procs

    exe, dossier = fixture

    def boom(path, encoding=None):
        raise RuntimeError("planted fault")

    monkeypatch.setattr(procs, "read", boom)
    rows, _bad, _totals = edges.collect(str(exe), str(dossier))
    _out, err = capsys.readouterr()
    assert "object-table lane unavailable: RuntimeError" in err
    assert rows, "the edge rows do not depend on the naming lane"


def test_the_expected_not_a_vb6_build_stays_silent(fixture, monkeypatch, capsys):
    from vb6decompiler import edges, procs

    exe, dossier = fixture

    def not_vb6(path, encoding=None):
        raise procs.VBError("x.exe: no 'VB5!' header (not a VB5/VB6 build)")

    monkeypatch.setattr(procs, "read", not_vb6)
    rows, _bad, _totals = edges.collect(str(exe), str(dossier))
    _out, err = capsys.readouterr()
    assert err == "", f"absence of an object table is a result, not news: {err!r}"
    assert rows


# --------------------------------------------------------------------------- range attribution
# One policy for both consumers (review item C): procedure i covers
# [vas[i], vas[i+1]), the LAST one covers [vas[-1], vas[-1] + LAST_RANGE_CAP)
# — the window edges actually decodes. A bare bisect answered "nearest start
# below", silently labelling a target past the capped last range as that
# procedure's call. Bounds below are the fixture's own arithmetic:
# last start 401080 + cap 0x10000 = 411100.
def test_owner_index_is_range_containment_not_nearest_start():
    from vb6decompiler.edges import LAST_RANGE_CAP, owner_index

    vas = [0x401000, 0x401100, 0x402000]  # last start 402000, capped at 412000
    assert owner_index(vas, 0x401000) == 0                    # exactly a start
    assert owner_index(vas, 0x4010FF) == 0                    # inside a normal range
    assert owner_index(vas, 0x401100) == 1                    # exactly the NEXT start
    assert owner_index(vas, 0x400FF8) is None                 # before the first start
    assert owner_index(vas, 0x402000 + LAST_RANGE_CAP - 1) == 2   # last byte inside the cap
    assert owner_index(vas, 0x402000 + LAST_RANGE_CAP) is None    # exactly the boundary
    assert owner_index(vas, 0x412001) is None                 # past the final boundary
    assert owner_index([], 0x401000) is None
    dup = [0x401000, 0x401000, 0x401100]
    assert owner_index(dup, 0x401000) == 1                    # equal starts: the later record, deterministically


def _bounds_fixture(tmp_path):
    """A synthetic image whose calls hit every attribution boundary (probed)."""
    pytest.importorskip("capstone")
    from _mini_pe import mini_pe

    def call(target, at):
        return b"\xe8" + (target - (at + 5)).to_bytes(4, "little", signed=True)

    code = bytearray(b"\x90" * 0x90)
    for at, tgt in [(0x401010, 0x401015), (0x401015, 0x401050), (0x40101A, 0x401060),
                    (0x40101F, 0x401005), (0x401024, 0x411080), (0x401029, 0x41107F),
                    (0x40102E, 0x421100)]:
        code[at - 0x401000:at - 0x401000 + 5] = call(tgt, at)
    code[0x33] = 0xC3  # modA's ret
    code[0x50:0x55] = call(0x401085, 0x401050)  # modDup's body: into modZ's range
    code[0x55] = 0xC3
    code[0x80:0x85] = call(0x41107E, 0x401080)  # modZ's body: inside its own capped range
    code[0x85] = 0xC3
    exe = tmp_path / "bounds.exe"
    exe.write_bytes(mini_pe(code=bytes(code)))
    dos = tmp_path / "dossier.jsonl"
    dos.write_text(
        '{"va": "401080", "object_name": "modZ", "name_hint": {"names": ["ProcZ"]}}\n'
        '{"va": "401050", "object_name": "modB", "name_hint": {"names": ["ProcB"]}}\n'
        '{"va": "401010", "object_name": "modA", "name_hint": {"names": ["ProcA"]}}\n'
        '{"va": "401050", "object_name": "modDup", "literals": []}\n',
        encoding="utf-8")  # deliberately unsorted, with a duplicate start
    return exe, dos


def test_calls_outside_every_range_stay_unattributed(tmp_path):
    from vb6decompiler import edges

    exe, dos = _bounds_fixture(tmp_path)
    rows, bad, totals = edges.collect(str(exe), str(dos))
    assert bad == 0
    by = {(r["va"], r["object_name"]): r for r in rows}
    a = by[("401010", "modA")]
    assert a["calls_procedures"] == {"401010": 1, "401050": 2, "401080": 1}
    # 401005 is below every start; 411080 and 421100 are past the capped last
    # range (401080 + 0x10000 = 411100). They count as unnamed hits, never as
    # the nearest procedure's calls.
    assert a["calls_other"] == {"401005": 1, "411080": 1, "421100": 1}
    z = by[("401080", "modZ")]
    assert z["calls_procedures"] == {"401080": 1}  # 41107E is inside its own capped window
    assert z["range_capped"] is True
    # an equal start empties the EARLIER record's range: [401050, 401050)
    assert by[("401050", "modB")]["instructions"] == 0
    assert by[("401050", "modDup")]["calls_procedures"] == {"401080": 1}
    assert totals["edges"] == 6 and totals["uncensus"] == 3


def test_decode_procs_and_edges_agree_on_every_target(tmp_path, capsys):
    """Same dossier, same policy: what edges attributes, decode attributes."""
    import json

    from vb6decompiler import cli, edges

    exe, dos = _bounds_fixture(tmp_path)
    rows, _bad, _totals = edges.collect(str(exe), str(dos))
    edges_map = {r["va"]: r["calls_procedures"] for r in rows}
    assert edges_map["401010"] == {"401010": 1, "401050": 2, "401080": 1}
    code = cli.main(["decode", str(exe), "--va", "401010", "--procs", str(dos), "--json"])
    assert code == 0
    out, err = capsys.readouterr()
    assert "4 land on known procedures" in err  # the 3 unnamed hits stayed unnamed
    calls = [r for r in json.loads(out)["rows"] if r["mnemonic"].startswith("call")]
    landed = [r for r in calls if "target_proc" in r]
    missed = [r for r in calls if "target_proc" not in r]
    assert sorted(r["target_va"] for r in landed) == ["401015", "401050", "401060", "41107F"]
    assert sorted(r["target_va"] for r in missed) == ["401005", "411080", "421100"]


def test_dossier_rejections_name_their_line(fixture, capsys):
    from vb6decompiler import edges

    exe, procs = fixture
    procs.write_text(
        procs.read_text(encoding="utf-8")
        + "not json\n[]\n" + '{"va": "nothex"}\n',
        encoding="utf-8")
    rows, bad, _totals = edges.collect(str(exe), str(procs))
    assert bad == 3
    assert [r["va"] for r in rows] == ["401010", "40102B"]  # good lines unaffected
    _o, err = capsys.readouterr()
    assert "line 3: not JSON" in err
    assert "line 4: record is not a JSON object" in err
    assert "line 5: va 'nothex' is not a hex address" in err


# --------------------------------------------------------------------------- nested record shapes
# Review 0.5.7 item F: top-level validation passed records whose nested fields the
# consumer then choked on. edges and decode --procs now share one gate
# (vb6decompiler/records.py); a malformed record is counted and the batch goes on.
NESTED_BAD = [
    "not json",                                              # 3
    "[1, 2]",                                                # 4
    '"a bare scalar"',                                       # 5
    '{"object_name": "x"}',                                  # 6 no va
    '{"va": "zzz"}',                                         # 7 not hex
    '{"va": "0x401000"}',                                    # 8 int() would have accepted it
    '{"va": "401A00", "name_hint": "invalid"}',              # 9
    '{"va": "401A01", "name_hint": {"names": 42}}',          # 10
    '{"va": "401A02", "literals": 42}',                      # 11
    '{"va": "401A03", "literals": [7]}',                     # 12
    '{"va": "401A04", "literals": [{"va": "zz", "text": "t"}]}',   # 13
    '{"va": "401A05", "literals": [{"va": "401090", "text": 5}]}',  # 14
]
# decode reads only the procedure identity, so the four literal-shaped rejections
# above are usable for it — the gate is per consumer, not per file.
DECODE_REJECTS = 8


def test_edges_rejects_bad_nested_records_and_keeps_going(fixture, capsys):
    from vb6decompiler import edges

    exe, procs = fixture
    good_after = '{"va": "401040", "object_name": "modLate", "name_hint": {"names": ["ProcLate"]}}\n'
    procs.write_text(procs.read_text(encoding="utf-8") + "\n".join(NESTED_BAD) + "\n" + good_after,
                     encoding="utf-8")
    rows, bad, _totals = edges.collect(str(exe), str(procs))
    assert bad == len(NESTED_BAD)
    assert [r["va"] for r in rows] == ["401010", "40102B", "401040"]  # valid before and after
    _o, err = capsys.readouterr()
    assert "line 8: va '0x401000' is not a hex address" in err
    assert "line 11: literals is not a list" in err
    assert "line 13: literals entry va 'zz' is not a hex address" in err
    assert "line 14: literals entry text is not a string" in err


def test_decode_procs_uses_the_same_gate(fixture, capsys):
    from vb6decompiler import cli

    exe, procs = fixture
    procs.write_text(procs.read_text(encoding="utf-8") + "\n".join(NESTED_BAD) + "\n",
                     encoding="utf-8")
    code = cli.main(["decode", str(exe), "--va", "401010", "--procs", str(procs), "--json"])
    out, err = capsys.readouterr()
    assert code == 0, err
    assert f"# warning: {DECODE_REJECTS} unreadable lines skipped" in err
    assert json.loads(out)["rows"]


def test_collect_reuses_one_engine_and_changes_nothing(fixture, monkeypatch):
    """Review 0.5.7 item I: ~98 us of engine construction against a ~177 us decode."""
    from vb6decompiler import blob, edges, x86

    exe, procs = fixture
    calls = {"n": 0}
    real = x86.engine

    def counted():
        calls["n"] += 1
        return real()

    monkeypatch.setattr(x86, "engine", counted)
    rows, _bad, _totals = edges.collect(str(exe), str(procs), events=True)
    assert calls["n"] == 1, "one engine per pass, not one per body and thunk"
    # and the rows are what a fresh engine per body produces
    data, sections = blob.load_sections(str(exe))
    for row, va, end in zip(rows, [0x401010, 0x40102B],
                            [0x40102B, 0x40102B + edges.LAST_RANGE_CAP]):
        sec = next(s for s in sections if s.virtual_address <= va < s.virtual_address + s.span)
        delta = va - sec.virtual_address
        window = data[sec.raw_pointer + delta: sec.raw_pointer + delta + min(sec.raw_size - delta, end - va)]
        alone = x86.decode(window, va, limit=10**9)
        assert (row["instructions"], row["ended"]) == (alone["instructions"], alone["ended"])
