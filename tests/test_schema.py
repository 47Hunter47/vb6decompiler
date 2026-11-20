"""The SQL tokenizer and the data model it feeds.

The stage's whole value is that it does not guess: a construct outside the handled
dialect must be *reported*, and a column must be attributed only when the statement
itself says which table it belongs to. Most of these tests exist to hold that line
- the parser is easy to make generous, and a generous parser invents relationships
between tables that the binary never proved.
"""

from __future__ import annotations

import json

import pytest
import synth_vb6

from vb6decompiler import cli, schema


# --------------------------------------------------------------------------- tokenizer
def test_bracketed_names_and_date_literals_are_tokens_not_text():
    tokens = schema.tokenize("SELECT [Order No] FROM [t Order] WHERE d = #1/2/2020#")
    assert [t.bare for t in tokens if t.kind == "ident"][:2] == ["SELECT", "Order No"]
    dates = [t.bare for t in tokens if t.kind == "string"]
    assert dates == ["1/2/2020"]


def test_a_doubled_quote_inside_a_string_stays_one_token():
    tokens = schema.tokenize("SELECT * FROM t WHERE a = 'rock''n''roll'")
    assert [t.bare for t in tokens if t.kind == "string"] == ["rock'n'roll"]


def test_a_bare_identifier_may_carry_the_builds_own_letters():
    """Measured on the reference corpus: 104 of 107 unparsed statements failed on a
    letter, not on a construct - Jet accepts unquoted Turkish names, and an
    ASCII-only identifier rule turned them into 'unexpected character'."""
    parsed = schema.parse("SELECT ÁrKod, Müşteri FROM tCari WHERE Şehir = 'İzmir'")
    assert parsed.tables == ["tCari"]
    assert {(c.table, c.name) for c in parsed.columns} == {
        ("tCari", "ÁrKod"), ("tCari", "Müşteri"), ("tCari", "Şehir")}


def test_parameter_markers_are_counted():
    assert schema.parse("SELECT a FROM t WHERE b = ? AND c = ?").params == 2


@pytest.mark.parametrize("text,reason", [
    ("SELECT 'unterminated FROM t", "unterminated string"),
    ("SELECT [unterminated FROM t", "unterminated quoted identifier"),
    ("SELECT a FROM t WHERE d = #2020", "unterminated date literal"),
    ("SELECT a FROM (t", "unbalanced parentheses"),
    ("SELECT a) FROM t", "unbalanced parentheses"),
    ("SELECT a FROM t WHERE x = ~", "unexpected character"),
    ("", "empty statement"),
])
def test_anything_outside_the_dialect_is_a_named_error(text, reason):
    with pytest.raises(schema.SQLSyntax) as exc:
        schema.parse(text)
    assert reason in str(exc.value)


# --------------------------------------------------------------------------- verbs and tables
@pytest.mark.parametrize("text,kind,tables", [
    ("SELECT a FROM tOrder", "select", ["tOrder"]),
    ("INSERT INTO tAudit (a) VALUES (1)", "insert", ["tAudit"]),
    ("UPDATE tOrder SET a = 1", "update", ["tOrder"]),
    ("DELETE FROM tLine WHERE a = 1", "delete", ["tLine"]),
    ("SELECT a FROM tOrder o JOIN tLine l ON l.o = o.o", "select", ["tOrder", "tLine"]),
    ("SELECT a FROM tOrder, tLine", "select", ["tOrder", "tLine"]),
    ("SELECT a FROM dbo.tOrder", "select", ["dbo.tOrder"]),
    ("EXEC dbo.spThing", "other", []),
])
def test_kind_and_tables(text, kind, tables):
    parsed = schema.parse(text)
    assert (parsed.kind, parsed.tables) == (kind, tables)


def test_insert_column_list_is_not_read_as_a_subquery():
    """Measured bug: handing the '(' to the table reader lost the table entirely."""
    parsed = schema.parse("INSERT INTO tAudit (AuditCode, AuditMsg) VALUES (?, 'x')")
    assert parsed.tables == ["tAudit"]
    assert [(c.table, c.name) for c in parsed.columns] == [
        ("tAudit", "AuditCode"), ("tAudit", "AuditMsg")]
    assert "subquery in FROM, not descended" not in parsed.notes


def test_an_insert_without_a_column_list_says_the_columns_are_unknown():
    parsed = schema.parse("INSERT INTO tAudit VALUES (1, 'x')")
    assert parsed.columns == []
    assert any("without a column list" in note for note in parsed.notes)


def test_star_is_recorded_as_a_star_not_as_a_column_name():
    assert [(c.table, c.name) for c in schema.parse("SELECT * FROM tOrder").columns] == [
        ("tOrder", "*")]
    assert [(c.table, c.name) for c in schema.parse(
        "SELECT o.* FROM tOrder o, tLine l").columns] == [("tOrder", "*")]


# --------------------------------------------------------------------------- columns
def test_a_single_table_statement_attributes_its_unqualified_columns():
    parsed = schema.parse("SELECT OrderNo, DepDate FROM tOrder WHERE Id = ?")
    assert {(c.table, c.name) for c in parsed.columns} == {
        ("tOrder", "OrderNo"), ("tOrder", "DepDate"), ("tOrder", "Id")}


def test_an_alias_resolves_through_the_statements_own_from_list():
    parsed = schema.parse(
        "SELECT o.OrderNo, l.DetailCode FROM tOrder o JOIN tLine l ON l.OrderNo = o.OrderNo")
    # The ON predicate is mined too, so l.OrderNo appears as well as o.OrderNo:
    # both are named explicitly and both resolve through the alias map.
    assert {(c.table, c.name) for c in parsed.columns} == {
        ("tOrder", "OrderNo"), ("tLine", "DetailCode"), ("tLine", "OrderNo")}


def test_a_two_table_statement_leaves_unqualified_columns_unattributed():
    """The statement cannot say which table an unqualified name is; say so."""
    parsed = schema.parse("SELECT OrderNo FROM tOrder, tLine WHERE Kind = 'A'")
    assert any("not attributed" in note for note in parsed.notes)
    unqualified = [c for c in parsed.columns if c.table is None]
    assert unqualified and all(c.name for c in unqualified)


def test_a_qualifier_the_statement_never_defined_stays_unattributed():
    parsed = schema.parse("SELECT z.OrderNo FROM tOrder o")
    column = next(c for c in parsed.columns if c.name == "OrderNo")
    assert column.table is None


def test_a_three_part_name_is_schema_table_column():
    parsed = schema.parse("SELECT dbo.tOrder.OrderNo FROM dbo.tOrder")
    assert (parsed.columns[0].table, parsed.columns[0].name) == ("dbo.tOrder", "OrderNo")


def test_an_expression_is_an_expression_not_its_first_word():
    parsed = schema.parse("SELECT COUNT(*), ISNULL(Sum(Qty),0) AS Q FROM tLine")
    assert parsed.columns == []
    assert parsed.notes.count("expression in select list") == 2


def test_update_targets_come_from_the_set_clause_only():
    parsed = schema.parse("UPDATE tOrder SET DepDate = #1/2/2020#, Kind = 'A' WHERE Id = ?")
    assert {(c.table, c.name) for c in parsed.columns} == {
        ("tOrder", "DepDate"), ("tOrder", "Kind"), ("tOrder", "Id")}


def test_a_subquery_is_noted_and_never_descended():
    parsed = schema.parse("SELECT a FROM t WHERE a IN (SELECT b FROM u)")
    assert parsed.tables == ["t"]
    assert any("not descended" in note for note in parsed.notes)
    # 'u' is the subquery's table and must not appear as this statement's table.
    assert "u" not in parsed.tables


# --------------------------------------------------------------------------- the report
def _row(va="4013B0", obj="modA", sql=()):
    return {"va": va, "object_name": obj, "sql": list(sql)}


def _sql(text, status="CLOSED", tables=()):
    return {"text": text, "status": status, "closed": status == "CLOSED",
            "parts": 1, "reason": "", "tables": list(tables)}


def test_the_counts_must_add_up():
    report = schema.build([
        _row(sql=[_sql("SELECT a FROM tOrder"), _sql("SELECT 'x", status="OPEN_QUOTE")]),
        _row(va="401400", sql=[_sql("SELECT a FROM (t")]),
    ])
    counts = report.counts()
    assert counts == {"statements": 3, "closed": 2, "parsed": 1, "unparsed": 1, "open": 1}
    assert report.invariants() == []


def test_an_invariant_break_is_printed_not_hidden():
    report = schema.build([_row(sql=[_sql("SELECT a FROM t")])])
    report.statements += 1          # a corrupted total must be visible
    assert report.invariants()


def test_open_statements_are_gaps_not_parsed_statements():
    report = schema.build([_row(sql=[_sql("SELECT a FROM tOrder WHERE b = '", status="OPEN_QUOTE")])])
    assert report.parsed == 0 and len(report.open) == 1
    assert report.open[0].status == "OPEN_QUOTE"
    assert "tOrder" not in report.tables


def test_crud_letters_and_readers_writers():
    report = schema.build([_row(obj="fMain", sql=[
        _sql("SELECT a FROM tOrder"),
        _sql("UPDATE tOrder SET a = 1"),
        _sql("INSERT INTO tLine (a) VALUES (1)"),
        _sql("DELETE FROM tLine WHERE a = 1"),
    ])])
    assert report.crud[("fMain", "tOrder")] == {"C": 0, "R": 1, "U": 1, "D": 0}
    assert report.crud[("fMain", "tLine")] == {"C": 1, "R": 0, "U": 0, "D": 1}
    assert report.tables["tOrder"]["readers"] == ["fMain"]
    assert report.tables["tOrder"]["writers"] == ["fMain"]
    assert report.tables["tLine"]["readers"] == []


def test_a_hint_that_disagrees_with_the_tokenizer_is_recorded():
    report = schema.build([_row(sql=[_sql("SELECT a FROM tOrder", tables=["tLine"])])])
    assert len(report.disagree) == 1
    assert "tLine" in report.disagree[0][1] and "tOrder" in report.disagree[0][1]


def test_an_unattributed_column_is_collected_under_its_own_name():
    report = schema.build([_row(sql=[_sql("SELECT OrderNo FROM tOrder, tLine")])])
    assert "OrderNo" in report.tables["(unattributed)"]["columns"]


def test_ordering_is_deterministic_and_the_text_never_appears():
    rows = [_row(va="401400", sql=[_sql("SELECT 'x", status="OPEN_QUOTE")]),
            _row(va="4013B0", sql=[_sql("SELECT a FROM (t")]),
            _row(va="401500", sql=[_sql("SELECT a FROM tOrder")])]
    first = schema.as_json(schema.build(rows))
    second = schema.as_json(schema.build(list(reversed(rows))))
    assert first == second
    assert "SELECT" not in first          # table and column names only
    assert [s["va"] for s in json.loads(first)["unparsed"]] == ["4013B0"]


def test_markdown_reports_every_denominator():
    report = schema.build([
        _row(sql=[_sql("SELECT a FROM tOrder"), _sql("SELECT b FROM (x")]),
        _row(va="401400", sql=[_sql("SELECT c FROM y WHERE d = '", status="OPEN_QUOTE")]),
    ])
    md = schema.as_markdown(report)
    assert "2 closed of 3 statements" in md
    assert "## Unparsed (1 of 2 closed)" in md
    assert "## Open statements (1 of 3)" in md
    assert "| `tOrder` |" in md


# --------------------------------------------------------------------------- wiring
def _run(argv, capsys):
    code = cli.main(argv)
    out, err = capsys.readouterr()
    return code, out, err


@pytest.fixture()
def dossier(tmp_path):
    root = tmp_path / "synth"
    target = synth_vb6.build(root)
    path = root / "dossier.jsonl"
    assert cli.main(["dossier", "--listings", str(target.listings), "--out", str(path)]) == 0
    return path


def test_cli_prints_the_model_and_a_counted_summary(dossier, capsys):
    capsys.readouterr()
    code, out, err = _run(["schema", str(dossier)], capsys)
    assert code == 0
    assert out.startswith("# Data model")
    # The synthetic target's one closed statement is a SELECT over tOrder.
    assert "| `tOrder` |" in out
    # The synthetic build carries one CLOSED statement and three it could not
    # close (a listing chain ends where a value is concatenated at run time).
    assert "1 parsed + 0 unparsed + 3 open = 4 of 4 statements" in err


def test_cli_json_is_parseable(dossier, capsys):
    capsys.readouterr()
    code, out, _ = _run(["schema", str(dossier), "--format", "json"], capsys)
    assert code == 0
    body = json.loads(out)
    assert body["counts"]["parsed"] == 1
    assert "tOrder" in body["tables"]


def test_out_writes_the_file_and_a_manifest(dossier, tmp_path, capsys):
    capsys.readouterr()
    out = tmp_path / "model.md"
    code, _, err = _run(["schema", str(dossier), "--out", str(out)], capsys)
    assert code == 0
    assert out.read_text(encoding="utf-8").startswith("# Data model")
    assert (tmp_path / "model.md.manifest.json").exists()
    assert "# wrote" in err


def test_a_missing_dossier_is_exit_2(tmp_path, capsys):
    code, out, err = _run(["schema", str(tmp_path / "gone.jsonl")], capsys)
    assert code == 2 and out == ""
    assert err.startswith("error: ")


def test_out_may_not_overwrite_the_dossier(dossier, capsys):
    capsys.readouterr()
    code, _, err = _run(["schema", str(dossier), "--out", str(dossier)], capsys)
    assert code == 2
    assert "error: " in err
    assert dossier.read_text(encoding="utf-8")  # the input is intact
