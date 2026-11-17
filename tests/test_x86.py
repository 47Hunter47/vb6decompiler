"""The optional engine boundary: named refusal, honest endings, real decode.

Engine-needing tests skip without capstone installed — same isolation as the
Ghidra-facing suites, so the default suite stays core-only.
"""
import json
import sys

import pytest

from vb6decompiler import x86
from _mini_pe import mini_pe

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
