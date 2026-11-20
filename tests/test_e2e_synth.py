"""Every stage, end to end, on one synthetic build — no target binary needed.

SYNTHETIC: the build comes from :mod:`synth_vb6` and is labelled so everywhere.
Its numbers are not measurements of a real program. What these tests are for:
until now nothing exercised a stage on a *whole* build (the unit tests build one
structure each), so a stage that only worked on the one binary in the author's
hands stayed green.

One build is made per session and every stage reads it, because the point is
that they agree with each other: the ``.frm`` geometry must equal the blob's,
the listing's procedure VAs must be the object table's entries, and the call
inside the code must be attributed to a procedure the dossier knows.
"""

from __future__ import annotations

import csv
import io
import json
import os

import pytest
import synth_vb6

from vb6decompiler import cli


def _capstone() -> bool:
    try:
        import capstone  # noqa: F401
    except ImportError:
        return False
    return True


needs_engine = pytest.mark.skipif(not _capstone(), reason="capstone ([asm] extra) not installed")


@pytest.fixture(scope="module")
def target(tmp_path_factory):
    root = tmp_path_factory.mktemp("synth")
    return synth_vb6.build(root)


def _run(argv, capsys):
    code = cli.main(argv)
    out, err = capsys.readouterr()
    return code, out, err


def _csv(out: str) -> list[dict]:
    return list(csv.DictReader(io.StringIO(out)))


def _jsonl(path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


# --------------------------------------------------------------------------- pe
def test_pe_sees_one_vb6_image(target, capsys):
    code, out, err = _run(["pe", str(target.exe)], capsys)
    assert code == 0
    rows = _csv(out)
    assert len(rows) == 1
    assert rows[0]["bits"] == "32"
    assert rows[0]["image_base"] == "0x400000"
    assert rows[0]["vb6"] == "True"
    assert rows[0]["import_dlls"] == "1"
    assert "# 1 images, 1 import a VB6 runtime, 0 unreadable" in err


# --------------------------------------------------------------------------- procs
def test_procs_reads_two_objects_and_four_entries(target, capsys):
    code, out, _ = _run(["procs", str(target.exe)], capsys)
    assert code == 0
    facts = dict(line.split("\t") for line in out.splitlines() if "\t" in line)
    assert facts["name"] == "prjSynth"
    assert (facts["objects"], facts["methods"], facts["unique_entries"]) == ("2", "4", "4")
    # A slot only counts as an entry when the bytes there are the VB6 prologue.
    assert facts["methods_without_address"] == "0"
    assert "modSynth01" in out and "fSynth01" in out


# --------------------------------------------------------------------------- literals
def test_literals_finds_every_bstr_and_keeps_the_non_ascii_one(target, capsys):
    code, out, _ = _run(["literals", str(target.exe)], capsys)
    assert code == 0
    rows = _csv(out)
    bstr = [r for r in rows if r["bstr"] == "yes"]
    # Four literals in the build; the ASCII names around them are not BSTRs, and
    # ``bstr=yes`` is the length-prefix check that separates a literal from a
    # coincidental run of UTF-16 (§2 of docs/formats.md).
    assert len(bstr) == 4
    texts = {r["text"] for r in bstr}
    assert "Kayıt bulunamadı" in texts
    assert all(r["encoding"] == "utf16" for r in bstr)


# --------------------------------------------------------------------------- stitch
def test_stitch_closes_the_chain_and_leaves_the_open_one_open(target, capsys):
    code, out, err = _run(["stitch", str(target.listings)], capsys)
    assert code == 0
    rows = _csv(out)
    closed = [r for r in rows if r["status"] == "CLOSED"]
    assert len(closed) == 1
    assert closed[0]["sql"] == "SELECT OrderNo FROM tOrder WHERE DepDate = 'E1' AND Kind = 'A'"
    assert closed[0]["parts"] == "2"
    # The other chain ends where the program concatenates a value: no trace, no
    # claim. synthesise a pass here and the stage would be lying.
    assert "# {'candidates': 1, 'closed': 1" in err


# --------------------------------------------------------------------------- frm
def test_frm_parses_the_design_block(target, capsys):
    code, out, err = _run(["frm", str(target.frms)], capsys)
    assert code == 0
    assert "fSynth01" in out
    assert "(6000, 3000)" in out and "controls=3" in out
    assert "# 1 files: 1 parsed, 0 without a design block, 0 failed" in err


# --------------------------------------------------------------------------- blob
def test_blob_matches_the_frm_geometry_it_was_built_from(target, capsys):
    code, out, _ = _run(["blob", str(target.exe), "--validate", "--frm-dir", str(target.frms)],
                        capsys)
    assert code == 0
    report = json.loads(out)
    assert report["blob_count"] == 1 and report["truth_forms"] == 1
    # Same numbers as the design text: 3 controls, client size read correctly.
    assert (report["controls_matched"], report["controls_total"]) == (3, 3)
    assert report["form_rate"] == 100.0


# --------------------------------------------------------------------------- dossier
def test_dossier_has_one_row_per_procedure_with_the_table_entries(target, capsys):
    out_path = target.root / "dossier.jsonl"
    code, _, err = _run(["dossier", "--listings", str(target.listings), "--out", str(out_path)],
                        capsys)
    assert code == 0
    rows = _jsonl(out_path)
    assert len(rows) == 4
    assert {r["va"] for r in rows} == {f"{va:X}" for va in target.entries.values()}
    assert sorted(r["object_name"] for r in rows) == [
        "fSynth01", "fSynth01", "modSynth01", "modSynth01"]
    assert "# procedures with >=1 closed SQL statement: 1 of 4" in err


# --------------------------------------------------------------------------- decode / edges
@needs_engine
def test_decode_shows_the_call_and_edges_attributes_it(target, capsys):
    va = target.entries["Main"]
    code, out, err = _run(["decode", str(target.exe), "--va", f"{va:X}", "--limit", "8"], capsys)
    assert code == 0
    assert "call " in out
    assert "calls: 0 of 1 named via import table" in err

    dossier = target.root / "edges-dossier.jsonl"
    edges = target.root / "edges.jsonl"
    assert _run(["dossier", "--listings", str(target.listings), "--out", str(dossier)],
                capsys)[0] == 0
    code, _, err = _run(["edges", str(target.exe), "--dossier", str(dossier), "--out", str(edges)],
                        capsys)
    assert code == 0
    rows = {r["va"]: r for r in _jsonl(edges)}
    assert len(rows) == 4
    caller = rows[f"{va:X}"]
    # The callee is a dossier procedure, so the edge is named, not guessed.
    assert caller["calls_procedures"] == {f"{target.entries['Helper']:X}": 1}
    assert all(r["calls_late_bound"] == 0 for r in rows.values())


@needs_engine
def test_outline_reads_the_edges_file(target, capsys):
    dossier = target.root / "outline-dossier.jsonl"
    edges = target.root / "outline-edges.jsonl"
    outline = target.root / "outline.jsonl"
    assert _run(["dossier", "--listings", str(target.listings), "--out", str(dossier)],
                capsys)[0] == 0
    assert _run(["edges", str(target.exe), "--dossier", str(dossier), "--out", str(edges)],
                capsys)[0] == 0
    code, _, _ = _run(["outline", str(edges), "--out", str(outline)], capsys)
    assert code == 0
    rows = _jsonl(outline)
    assert len(rows) == 4
    # No runtime calls in the synthetic code, so every bucket stays empty rather
    # than being counted as "unknown operations".
    assert all(r["api_calls"] == {} for r in rows)


def test_the_build_is_written_once_and_stays_put(target):
    assert os.path.getsize(target.exe) > 0
    assert sorted(p.name for p in target.listings.iterdir()) == ["fSynth01.frm", "modSynth01.bas"]
    assert [p.name for p in target.frms.iterdir()] == ["fSynth01.frm"]
