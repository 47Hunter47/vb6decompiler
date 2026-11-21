"""The per-object specification: what it claims, what it refuses to claim.

Two properties matter more than formatting, and both are tested with hostile input:
text from the build (control names, captions, messages, object names) must not be
able to inject Markdown or HTML, and a missing input must be *named* in the file
rather than silently producing an empty section that reads like a measurement.
"""

from __future__ import annotations

import json

import pytest
import synth_vb6

from vb6decompiler import cli, spec

HOSTILE = "<script>alert('x')</script> | a\\b `c` *d* _e_ [f]"
NON_ASCII = "Kayıt bulunamadı — şğİı"


# --------------------------------------------------------------------------- escaping
def test_markdown_text_neutralises_html_tables_and_emphasis():
    out = spec.markdown_text(HOSTILE)
    assert "<" not in out and ">" not in out
    assert "|" not in out.replace("\\|", "")      # every pipe carries its escape
    assert "`" not in out.replace("\\`", "")
    assert "\\*" in out and "\\_" in out and "\\[" in out


def test_markdown_text_keeps_one_physical_line():
    out = spec.markdown_text("a\nb\r\nc\td\u2028e")
    assert "\n" not in out and "\r" not in out and "\t" not in out
    assert "\\n" in out and "\\u2028" in out


def test_markdown_text_leaves_letters_alone():
    assert spec.markdown_text(NON_ASCII) == NON_ASCII


# --------------------------------------------------------------------------- file names
def test_a_reserved_windows_name_is_repaired_not_written(tmp_path):
    taken: set[str] = set()
    name, why = spec.safe_file_name("CON", taken, "0")
    assert name.lower() != "con.md"
    assert why and "reserved" in why


def test_a_path_escape_cannot_climb_out_of_the_output_directory(tmp_path):
    taken: set[str] = set()
    name, why = spec.safe_file_name("..\\..\\etc\\passwd", taken, "1")
    assert "/" not in name and "\\" not in name
    # The invariant that matters: the name resolves inside the output directory.
    assert (tmp_path / name).resolve().parent == tmp_path.resolve()
    assert why


def test_an_over_long_name_is_truncated_and_says_so():
    name, why = spec.safe_file_name("X" * 300, set(), "2")
    assert len(name) <= 100 + len(".md")
    assert why and "truncat" in why


def test_two_objects_with_one_name_get_distinct_files():
    taken: set[str] = set()
    first, _ = spec.safe_file_name("fDemo", taken, "0")
    second, why = spec.safe_file_name("fDemo", taken, "1")
    assert first != second
    assert why and "taken" in why


def test_the_index_name_is_never_taken_by_an_object():
    taken = {"index.md"}
    name, _ = spec.safe_file_name("index", taken, "0")
    assert name.lower() != "index.md"


# --------------------------------------------------------------------------- claims
def _row(va="4013B0", obj="modA", sql=(), literals=(), names=()):
    return {"va": va, "object_name": obj,
            "name_hint": {"kind": "hint", "names": list(names)} if names else None,
            "literals": [{"va": "401000", "text": t, "encoding": "listing"} for t in literals],
            "sql": list(sql)}


def _sql(text, status="CLOSED"):
    return {"text": text, "status": status, "closed": status == "CLOSED", "parts": 1,
            "reason": "", "tables": ["tOrder"]}


def test_a_kind_without_an_object_table_is_named_as_unknown():
    report = spec.build([_row()])
    [obj] = report.objects
    assert obj.kind == "unknown"
    assert "no object table supplied" in obj.kind_source
    assert any("object table" in note for note in report.notes)


def test_a_supplied_kind_names_its_source():
    report = spec.build([_row()], kinds={"modA": ("module", "object table (vb6d procs)")})
    assert report.objects[0].kind == "module"
    assert "object table" in report.objects[0].kind_source


def test_a_missing_design_is_a_named_absence_not_an_empty_table():
    text = spec.render_object(spec.build([_row()]).objects[0])
    assert "No design recovered" in text
    assert "no .frm directory supplied" in text


def test_a_form_with_no_design_block_in_the_directory_says_which_one():
    report = spec.build([_row(obj="fMissing")], design={})
    assert "no .frm design block for fMissing" in report.objects[0].design_reason


def test_an_open_statement_is_listed_as_a_gap_and_its_text_is_not_printed():
    secret = "SELECT * FROM tOrder WHERE Id = '7KAYIT"
    report = spec.build([_row(sql=[_sql(secret, status="OPEN_QUOTE")])])
    text = spec.render_object(report.objects[0])
    assert "not closed" in text
    assert secret not in text
    assert "open SQL: 1 of 1 statements" in text


def test_runtime_categories_are_printed_with_the_unverified_word():
    report = spec.build([_row()], outline={"4013B0": {
        "va": "4013B0", "unverified_operations": {"string": 2},
        "runtime_unlisted": {"__vbaFreeVar": 1}, "api_calls": {"kernel32!RtlMoveMemory": 3}}})
    text = spec.render_object(report.objects[0])
    assert "unverified" in text
    assert "kernel32!RtlMoveMemory x3" in text
    # The name is escaped for Markdown (its underscores) but reads the same once
    # rendered - which is what matters for a reader of the file.
    assert "vbaFreeVar x1" in text
    assert "does not categorize: 1" in text


def test_a_missing_outline_is_named():
    assert any("outline" in note for note in spec.build([_row()]).notes)


def test_a_schema_cross_check_names_the_tables_it_cannot_place():
    row = _sql("SELECT a FROM tOther")
    row["tables"] = ["tOther"]
    report = spec.build([_row(sql=[row])], known_tables={"torder"})
    assert any("tOther" in note and "absent from the schema" in note for note in report.notes)


def test_an_object_with_a_partial_statement_says_its_tables_are_a_lower_bound():
    report = spec.build([_row(sql=[_sql("SELECT a FROM tOrder")])], partial={"modA": 1})
    text = spec.render_object(report.objects[0])
    assert "partial: 1 of 1" in text and "lower bound" in text


def test_messages_are_text_that_reads_like_one_not_sql():
    report = spec.build([_row(literals=["Kayıt bulunamadı", "SELECT a FROM tOrder"],
                              sql=[_sql("SELECT a FROM tOrder")])])
    [message] = report.objects[0].procedures[0].messages
    assert message == "Kayıt bulunamadı"


def test_every_file_ends_with_the_gaps_section():
    for name, text in spec.files(spec.build([_row()])):
        assert text.endswith("\n")
        if name != "index.md":
            assert "## Gaps" in text


# --------------------------------------------------------------------------- end to end
@pytest.fixture()
def dossier(tmp_path):
    target = synth_vb6.build(tmp_path / "synth")
    path = tmp_path / "synth" / "dossier.jsonl"
    assert cli.main(["dossier", "--listings", str(target.listings), "--out", str(path)]) == 0
    return target, path


def test_cli_writes_one_file_per_object_plus_an_index(dossier, tmp_path, capsys):
    target, path = dossier
    capsys.readouterr()
    out = tmp_path / "spec"
    code = cli.main(["spec", str(path), "--exe", str(target.exe), "--frm", str(target.frms),
                     "--out", str(out)])
    assert code == 0
    names = sorted(p.name for p in out.iterdir())
    assert names == ["fSynth01.md", "index.md", "modSynth01.md"]
    index = (out / "index.md").read_text(encoding="utf-8")
    assert "2 objects, 4 procedures" in index
    assert "| form |" in index and "| module |" in index
    # The design section is the .frm text's three controls, geometry included.
    form_text = (out / "fSynth01.md").read_text(encoding="utf-8")
    assert form_text.count("| VB.") == 3
    assert "120, 240, 1455, 315" in form_text
    assert "Source: .frm design text" in form_text


def test_cli_reports_the_one_closed_statement_and_the_three_open_ones(dossier, tmp_path, capsys):
    _, path = dossier
    capsys.readouterr()
    out = tmp_path / "spec"
    assert cli.main(["spec", str(path), "--out", str(out)]) == 0
    _, err = capsys.readouterr()
    assert "1 closed of 4 statements" in err


def test_a_manifest_is_written_beside_the_directory(dossier, tmp_path, capsys):
    _, path = dossier
    capsys.readouterr()
    out = tmp_path / "spec"
    assert cli.main(["spec", str(path), "--out", str(out)]) == 0
    body = json.loads((tmp_path / "spec.manifest.json").read_text(encoding="utf-8"))
    assert body["command"] == "spec" and body["records"]["objects"] == 2


def test_a_missing_dossier_is_exit_2(tmp_path, capsys):
    code = cli.main(["spec", str(tmp_path / "gone.jsonl"), "--out", str(tmp_path / "o")])
    _, err = capsys.readouterr()
    assert code == 2
    assert err.startswith("error: ")


def test_an_out_path_that_is_a_file_is_exit_2(dossier, tmp_path, capsys):
    _, path = dossier
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    capsys.readouterr()
    code = cli.main(["spec", str(path), "--out", str(blocker)])
    assert code == 2
    assert "not a directory" in capsys.readouterr()[1]


def test_hostile_names_never_reach_a_file_name(dossier, tmp_path, capsys):
    _, path = dossier
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    rows.append({"va": "401700", "object_name": "../../CON", "name_hint": None,
                 "literals": [], "sql": [], "counts": {}})
    poisoned = tmp_path / "poisoned.jsonl"
    poisoned.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
                        encoding="utf-8")
    out = tmp_path / "spec"
    capsys.readouterr()
    assert cli.main(["spec", str(poisoned), "--out", str(out)]) == 0
    for written in out.iterdir():
        assert "/" not in written.name and "\\" not in written.name
        assert written.resolve().parent == out.resolve()
