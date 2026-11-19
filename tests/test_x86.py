"""The optional engine boundary: named refusal, honest endings, real decode.

Engine-needing tests skip without capstone installed — same isolation as the
Ghidra-facing suites, so the default suite stays core-only.
"""
import json
import sys

import pytest
from _mini_pe import mini_pe

from vb6decompiler import x86

PROLOGUE = bytes.fromhex("558BEC83C4F8535657E800000000C3")


def test_missing_engine_is_a_named_refusal(monkeypatch):
    monkeypatch.setitem(sys.modules, "capstone", None)  # forces ImportError on import
    with pytest.raises(x86.EngineUnavailable) as exc:
        x86.decode(b"\x90", 0x401000)
    assert "vb6decompiler[asm]" in str(exc.value)


def test_decode_stops_at_ret_and_labels_ending():
    pytest.importorskip("capstone")
    r = x86.decode(PROLOGUE, 0x401000)
    assert r["rows"][0]["mnemonic"] == "push" and r["rows"][0]["operands"] == "ebp"
    assert r["rows"][-1]["mnemonic"] == "ret"
    assert r["ended"] == "ret" and r["consumed_bytes"] == len(PROLOGUE)
    assert r["rows"][6]["mnemonic"] == "call"  # the e8 target is the next byte here


def test_limit_is_reported_not_silent():
    pytest.importorskip("capstone")
    r = x86.decode(bytes([0x90]) * 40, 0x401000, limit=5)
    assert r["instructions"] == 5 and r["ended"] == "limit"


def test_a_supplied_engine_decodes_identically():
    """Review 0.5.7 item I: reuse must not change a single field."""
    pytest.importorskip("capstone")
    md = x86.engine()
    assert x86.decode(PROLOGUE, 0x401000, engine=md) == x86.decode(PROLOGUE, 0x401000)
    # the engine is stateless between calls: a second range on the same engine
    # gives the same answer a fresh one would
    other = bytes.fromhex("B801000000C3")
    assert x86.decode(other, 0x402000, engine=md) == x86.decode(other, 0x402000)


def test_garbage_names_where_it_stopped():
    pytest.importorskip("capstone")
    # 0F 26 is not an encoding this 32-bit engine can express (measured: it
    # refuses from the very byte), so the stop address must be named, not implied
    r = x86.decode(bytes([0x0F, 0x26, 0x00, 0x00, 0x00]), 0x401000)
    assert r["ended"] == "garbage" and r["instructions"] == 0
    assert r["stopped_at_va"] == "401000"


def test_exhausted_is_never_reported_as_ret():
    pytest.importorskip("capstone")
    body = bytes.fromhex("558BEC8B450850")  # push ebp / frame / mov eax,[ebp+8] / push eax — no ret
    r = x86.decode(body, 0x401000)
    assert r["ended"] == "exhausted" and r["consumed_bytes"] == len(body)


def test_cli_decode_on_synthetic_image(tmp_path, capsys):
    pytest.importorskip("capstone")
    from vb6decompiler import cli

    exe = tmp_path / "fake.exe"
    exe.write_bytes(mini_pe(code=PROLOGUE))
    code = cli.main(["decode", str(exe), "--va", "401000", "--json"])
    out, err = capsys.readouterr()
    assert code == 0
    d = json.loads(out)
    assert d["ended"] == "ret" and d["rows"][-1]["mnemonic"] == "ret"
    assert '"va": "0x' not in out and '"bytes": "0x' not in out  # our hex fields stay bare; operand text is the engine's own rendering
    assert "ended: ret" in err
    # a VA outside every mapped section is the exit-2 contract, not a traceback
    code = cli.main(["decode", str(exe), "--va", "900000", "--json"])
    capsys.readouterr()
    assert code == 2


def test_end_va_stops_the_dump_at_the_boundary(tmp_path, capsys):
    pytest.importorskip("capstone")
    from vb6decompiler import cli

    exe = tmp_path / "two.exe"
    exe.write_bytes(mini_pe(code=PROLOGUE + PROLOGUE))  # two back-to-back bodies
    code = cli.main(["decode", str(exe), "--va", "401000", "--end-va", "40100F", "--json"])
    out, _err = capsys.readouterr()
    assert code == 0
    d = json.loads(out)
    assert d["ended"] == "ret" and d["instructions"] == 8  # first body only
    # cut the range just before its ret: the dump must not run into the next body
    code = cli.main(["decode", str(exe), "--va", "401000", "--end-va", "40100E", "--json"])
    out, _err = capsys.readouterr()
    assert code == 0
    d = json.loads(out)
    assert d["ended"] == "exhausted" and d["rows"][-1]["mnemonic"] == "call"
    capsys.readouterr()
    assert cli.main(["decode", str(exe), "--va", "401000", "--end-va", "401000", "--json"]) == 2


def test_import_named_calls_get_named_targets(tmp_path, capsys):
    pytest.importorskip("capstone")
    from vb6decompiler import cli

    exe = tmp_path / "imp.exe"
    # three call [slot] instructions then ret: slots 4010B0/4010B4 are ProcA/ProcB
    # in the fixture IAT, 4010B8 is the terminator slot (no name behind it)
    code = bytes.fromhex("FF15B0104000" + "FF15B4104000" + "FF15B8104000" + "C3")
    exe.write_bytes(mini_pe(code=code, imports=True))
    code = cli.main(["decode", str(exe), "--va", "401000", "--json"])
    out, err = capsys.readouterr()
    assert code == 0
    d = json.loads(out)
    rows = d["rows"]
    assert rows[0]["target"] == "kernel32!ProcA" and rows[0]["target_va"] == "4010B0"
    assert rows[1]["target"] == "kernel32!ProcB"
    assert "target" not in rows[2] and rows[2]["target_va"] == "4010B8"
    assert d["ended"] == "ret"
    assert "calls: 2 of 3 named via import table" in err


def test_procs_file_attributes_internal_targets(tmp_path, capsys):
    pytest.importorskip("capstone")
    from vb6decompiler import cli

    exe = tmp_path / "two.exe"
    # body A calls the VA where body B starts (E8 rel to 0x40100F), then rets
    exe.write_bytes(mini_pe(code=bytes.fromhex("E80A000000C3")))
    procs = tmp_path / "dossier.jsonl"
    procs.write_text(
        'not-json-at-all\n'
        '{"va": "401000", "object_name": "fA", "name_hint": {"names": ["Proc_1"]}}\n'
        '{"va": "40100F", "object_name": "fB", "name_hint": {"names": ["Proc_2"]}}\n',
        encoding="utf-8")
    code = cli.main(["decode", str(exe), "--va", "401000", "--procs", str(procs), "--json"])
    out, err = capsys.readouterr()
    assert code == 0
    d = json.loads(out)
    row = d["rows"][0]
    assert row["target_va"] == "40100F"
    assert row["target_proc"]["object_name"] == "fB"  # bisect: the range that holds it
    assert row["target_proc"]["names"] == ["Proc_2"]
    assert "1 unreadable lines skipped" in err
    assert "line 1: not JSON" in err  # the skip names its line (review item G)
    assert "1 land on known procedures" in err
