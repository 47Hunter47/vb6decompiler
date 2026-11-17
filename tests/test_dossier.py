"""`vb6d dossier`: what a per-procedure record may claim, and what it must not.

Every fixture here is synthetic decompiler text in the shape `docs/formats.md` §4
describes, so the suite runs with no VB6 binary. The invariants matter more than the
example values: a record whose `counts` disagree with its own lists would make every
number the README publishes unfalsifiable.
"""

from __future__ import annotations

import io
import json
import os

import pytest

from vb6decompiler import cli, dossier

#: Two procedures: one whose fragments stitch into a closed statement, one that stays
#: open inside a quote, and a third whose only literal is a plain UI message.
LISTING = "\n".join([
    "VERSION 5.00",
    "Private Sub cmdGo_Click()  '401000",
    '    mov eax, 42C3A0h ; "SELECT * FROM tOrder WHERE Id = "',
    '    mov eax, 42C3B0h ; "7"',
    '    mov eax, 42C3C0h ; "Kayıt bulunamadı"',
    "End Sub",
    "",
    "Private Sub cmdDel_Click()  '402000",
    '    mov eax, 42C400h ; "DELETE FROM tLine WHERE Id = \'"',
    "End Sub",
    "",
    "Private Sub Form_Load()  '403000",
    '    mov eax, 42C500h ; "Hazır"',
    "End Sub",
    "",
]) + "\n"


@pytest.fixture()
def listings(tmp_path):
    path = tmp_path / "fDemo.frm"
    path.write_bytes(LISTING.encode("cp1254"))
    return str(tmp_path)


def _stream(listings_dir, **kwargs) -> tuple[list[dict], dossier.DossierReport]:
    buf = io.StringIO()
    report = dossier.stream(listings_dir, buf, **kwargs)
    rows = [json.loads(line) for line in buf.getvalue().splitlines() if line.strip()]
    return rows, report


def test_one_record_per_procedure_keyed_by_address(listings):
    rows, report = _stream(listings)
    assert [r["va"] for r in rows] == ["401000", "402000", "403000"]
    assert report.procedures == 3
    # The object name comes from the file, the procedure name from the header comment,
    # and the name is labelled a hint because names repeat within one form.
    assert rows[0]["object_name"] == "fDemo"
    assert rows[0]["name_hint"] == {"kind": "hint", "names": ["cmdGo_Click"]}


def test_literal_order_is_the_listing_order(listings):
    rows, _report = _stream(listings)
    assert [l["text"] for l in rows[0]["literals"]] == [
        "SELECT * FROM tOrder WHERE Id = ", "7", "Kayıt bulunamadı",
    ]


def test_a_closed_statement_is_closed_and_an_open_one_stays_open(listings):
    rows, _report = _stream(listings)
    go = [s for s in rows[0]["sql"] if s["text"].startswith("SELECT * FROM tOrder")]
    assert go and go[0]["closed"] is True and go[0]["status"] == "CLOSED"
    dele = [s for s in rows[1]["sql"] if s["text"].startswith("DELETE")]
    assert dele and dele[0]["closed"] is False and dele[0]["status"] == "OPEN_QUOTE"


def test_counts_agree_with_the_lists_they_describe(listings):
    # The invariant behind every number the docs quote: no count may be maintained by
    # hand next to a list it describes.
    rows, report = _stream(listings)
    for row in rows:
        counts = row["counts"]
        assert counts["literals"] == len(row["literals"])
        assert counts["sql_closed"] == sum(1 for s in row["sql"] if s["closed"])
        assert counts["sql_open"] == sum(1 for s in row["sql"] if not s["closed"])
    assert report.with_literal == sum(1 for r in rows if r["literals"])
    assert report.with_closed_sql == sum(1 for r in rows if r["counts"]["sql_closed"])
    assert dossier.summary(report) == {
        "procedures": 3,
        "with_literal": 3,
        "with_closed_sql": 1,
        "runtime_calls": 0,
        "runtime_calls_described": 0,
        "failed": 0,
    }


def test_summary_lines_carry_their_denominators(listings):
    _rows, report = _stream(listings)
    text = "\n".join(report.lines())
    assert "procedures with >=1 literal: 3 of 3" in text
    assert "procedures with >=1 closed SQL statement: 1 of 3" in text
    assert "failed" not in text  # a clean run does not print a zero-failure line


def test_one_failing_procedure_is_counted_and_the_run_continues(listings, monkeypatch):
    real = dossier._sql_candidates

    def boom(chain, max_more=dossier.sqlstitch.MAX_MORE):
        if chain and chain[0].proc_va == 0x401000:
            raise RuntimeError("synthetic failure")
        return real(chain, max_more=max_more)

    monkeypatch.setattr(dossier, "_sql_candidates", boom)
    rows, report = _stream(listings)
    assert [r["va"] for r in rows] == ["402000", "403000"]  # the other two survived
    assert report.procedures == 3  # the denominator still counts the failed one
    assert report.failed == [("401000", "RuntimeError: synthetic failure")]
    assert "failed: 1 of 3" in "\n".join(report.lines())


# --------------------------------------------------------------------- inventory merge
VTable = "va,label,satir_no,object_addr,slot\n"
VTABLE_ROWS = VTable + "401000,FUN_401000,12,DAT_0040a000,3\n"


def test_inventory_is_merged_only_where_it_exists(listings, tmp_path):
    inv = tmp_path / "inv"
    inv.mkdir()
    (inv / "p_vtable.csv").write_text(VTABLE_ROWS, encoding="utf-8")
    base, _ = _stream(listings)
    merged, _ = _stream(listings, inventory_path=str(inv))
    assert "inventory" not in base[0]  # no inventory: the base record is unchanged
    assert base[0] == {k: v for k, v in merged[0].items() if k != "inventory"}
    assert merged[0]["inventory"]["vtable"][0]["slot"] == "3"
    assert "inventory" not in merged[1]  # a procedure with no row keeps its base form


def test_an_unresolvable_object_call_is_never_given_a_guessed_target(listings, tmp_path):
    inv = tmp_path / "inv"
    inv.mkdir()
    (inv / "p_vtable.csv").write_text(VTABLE_ROWS, encoding="utf-8")
    rows, _ = _stream(listings, inventory_path=str(inv))
    call = rows[0]["inventory"]["vtable"][0]
    # The object address is a `DAT_x` token in the pseudo-C: it must survive verbatim,
    # not be turned into a function VA because one happens to look plausible.
    assert call["object_addr"] == "DAT_0040a000"


def test_a_non_inventory_path_is_an_error_not_a_silent_skip(tmp_path):
    with pytest.raises(ValueError, match="not a directory"):
        dossier.load_inventory(str(tmp_path / "notes.txt"))


# --------------------------------------------------------------------- CLI
def test_cli_writes_jsonl_and_reports_on_stderr(listings, tmp_path, capsys):
    out = tmp_path / "out.jsonl"
    code = cli.main(["dossier", "--listings", listings, "--out", str(out)])
    captured = capsys.readouterr()
    assert code == 0
    assert captured.out == ""  # records went to the file, not interleaved with logs
    assert "# encoding: cp1254 (default)" in captured.err
    assert "procedures with >=1 literal: 3 of 3" in captured.err
    assert len(out.read_text(encoding="utf-8").splitlines()) == 3


def test_cli_defaults_to_a_file_inside_the_listing_directory(listings):
    assert cli.main(["dossier", "--listings", listings]) == 0
    produced = os.path.join(listings, dossier.DEFAULT_OUT_NAME)
    assert os.path.isfile(produced)
    assert len(open(produced, encoding="utf-8").read().splitlines()) == 3


def test_cli_on_a_missing_directory_exits_two(capsys, tmp_path):
    code = cli.main(["dossier", "--listings", str(tmp_path / "gone")])
    _out, err = capsys.readouterr()
    assert code == 2
    assert "error:" in err and "Traceback" not in err
