"""`vb6d unknowns`: count the markers, print none of the text.

The stage exists so a stranger can report "here is how much my build leaves
unknown" without shipping the build's own SQL and names. These tests hold that
promise with hostile and non-ASCII input, because the leak this stage could cause
is the exact thing it was written to avoid.

Every marker kind is exercised from the field names the emitters really write
(``dossier`` ``sql[].status``, ``edges`` ``calls_late_bound``, ``outline``
``unverified_operations``/``runtime_unlisted``), so the vocabulary cannot drift
away from the emitters without a test failing.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from vb6decompiler import cli, unknowns

HOSTILE = "<script>alert('x')</script>\nrock'n'roll"
NON_ASCII = "Kayıt bulunamadı — şğİı"


def _write(tmp_path, name, rows):
    path = tmp_path / name
    if name.endswith(".json"):
        path.write_text(json.dumps(rows), encoding="utf-8")
    else:
        path.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
                        encoding="utf-8")
    return path


def _dossier_row(va="4013B0", sql=()):
    return {"va": va, "object_name": "modSynth01", "name_hint": None, "counts": {},
            "literals": [], "sql": list(sql)}


def _sql(status, text=HOSTILE):
    return {"text": text, "status": status, "closed": status == "CLOSED", "parts": 1,
            "reason": "x", "tables": []}


# --------------------------------------------------------------------------- markers
def test_a_closed_statement_is_not_a_marker():
    assert unknowns.markers(_dossier_row(sql=[_sql("CLOSED")])) == []


@pytest.mark.parametrize("status", ["OPEN_QUOTE", "OPEN_PAREN", "DANGLING", "ESCAPE", "STUCK", "MULTI"])
def test_every_unclosed_status_the_dossier_emits_is_counted(status):
    marker, = unknowns.markers(_dossier_row(sql=[_sql(status)]))
    assert marker.kind == f"sql:{status}"
    assert marker.va == 0x4013B0
    assert marker.payload == ("text", HOSTILE)


def test_edges_late_bound_calls_are_counted_not_named():
    marker, = unknowns.markers({"va": "401360", "calls_late_bound": 3,
                                "calls_imported": {"__vbaStrCopy": 2}})
    assert marker.kind == "call:late-bound"
    assert marker.payload == ("count", 3)


def test_outline_unverified_and_uncategorized_are_separate_kinds():
    row = {"va": "401360", "unverified_operations": {"string": 2, "variant": 1},
           "runtime_unlisted": {"__vbaFreeVar": 4}, "api_calls": {}}
    kinds = {m.kind: m.payload for m in unknowns.markers(row)}
    assert kinds == {"call:unverified-operation": ("count", 3),
                     "call:uncategorized-runtime": ("count", 4)}


def test_a_kind_the_stage_could_not_name_is_counted():
    marker, = unknowns.markers({"va": "401000", "kind": "unknown"})
    assert marker.kind == "kind-unknown:kind"


def test_an_empty_marker_map_is_not_a_marker():
    assert unknowns.markers({"va": "401360", "unverified_operations": {},
                             "runtime_unlisted": {}, "calls_late_bound": 0}) == []


# --------------------------------------------------------------------------- privacy
def test_the_text_is_hashed_and_never_printed(tmp_path):
    path = _write(tmp_path, "d.jsonl", [_dossier_row(sql=[_sql("OPEN_QUOTE")])])
    report = unknowns.collect([str(path)])
    text = unknowns.as_text(report)
    as_json = unknowns.as_json(report)
    for rendered in (text, as_json, "\n".join(report.lines())):
        assert "script" not in rendered and "alert" not in rendered and "rock" not in rendered
    [row] = report.rows()
    expected = hashlib.sha256(HOSTILE.encode()).hexdigest()[:8]
    assert row["sample"] == f"len={len(HOSTILE)} sha256:{expected}"


def test_a_non_ascii_text_is_length_and_hash_only(tmp_path):
    path = _write(tmp_path, "d.jsonl", [_dossier_row(sql=[_sql("ESCAPE", NON_ASCII)])])
    report = unknowns.collect([str(path)])
    rendered = unknowns.as_text(report) + unknowns.as_json(report)
    assert "Kayıt" not in rendered
    assert report.sample["sql:ESCAPE"] == (len(NON_ASCII),
                                           hashlib.sha256(NON_ASCII.encode()).hexdigest()[:8])


def test_the_report_carries_no_paths(tmp_path):
    path = _write(tmp_path, "d.jsonl", [_dossier_row(sql=[_sql("STUCK")])])
    report = unknowns.collect([str(path)])
    assert str(tmp_path) not in unknowns.as_json(report)


# --------------------------------------------------------------------------- counting
def test_offsets_are_bucketed_by_page_not_by_address(tmp_path):
    rows = [_dossier_row(va="4013B0", sql=[_sql("OPEN_QUOTE")]),
            _dossier_row(va="4013C8", sql=[_sql("OPEN_QUOTE")]),
            _dossier_row(va="402005", sql=[_sql("OPEN_QUOTE")])]
    path = _write(tmp_path, "d.jsonl", rows)
    report = unknowns.collect([str(path)])
    assert report.per_kind["sql:OPEN_QUOTE"] == 3
    assert report.buckets["sql:OPEN_QUOTE"] == {"0x401000": 2, "0x402000": 1}


def test_every_number_carries_its_denominator(tmp_path):
    path = _write(tmp_path, "d.jsonl", [_dossier_row(sql=[_sql("STUCK")]), _dossier_row()])
    report = unknowns.collect([str(path)])
    assert "# 2 records read, 1 unknown markers in 1 kinds" in report.lines()[0]


def test_several_files_are_added_together(tmp_path):
    a = _write(tmp_path, "a.jsonl", [_dossier_row(sql=[_sql("STUCK")])])
    b = _write(tmp_path, "b.jsonl", [{"va": "401360", "calls_late_bound": 1}])
    report = unknowns.collect([str(a), str(b)])
    assert report.records == 2 and report.total == 2


def test_a_json_array_and_a_csv_are_accepted(tmp_path):
    array = _write(tmp_path, "d.json", [_dossier_row(sql=[_sql("STUCK")])])
    assert unknowns.collect([str(array)]).total == 1

    csv_path = tmp_path / "f.csv"
    csv_path.write_text("va,kind\n401000,unknown\n", encoding="utf-8")
    assert unknowns.collect([str(csv_path)]).total == 1


def test_an_unreadable_file_is_named_and_the_rest_still_counts(tmp_path):
    good = _write(tmp_path, "d.jsonl", [_dossier_row(sql=[_sql("STUCK")])])
    bad = tmp_path / "bad.jsonl"
    bad.write_text("{not json}\n", encoding="utf-8")
    report = unknowns.collect([str(bad), str(good)])
    assert report.total == 1 and report.records == 1
    assert [p for p, _ in report.unreadable] == [str(bad)]
    assert any("unreadable bad.jsonl" in line for line in report.lines())


def test_an_empty_file_reads_as_nothing_rather_than_a_failure(tmp_path):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    report = unknowns.collect([str(empty)])
    assert report.records == 0 and report.total == 0


def test_ordering_is_deterministic(tmp_path):
    rows = [_dossier_row(sql=[_sql("STUCK")]), _dossier_row(sql=[_sql("ESCAPE")]),
            {"va": "401360", "calls_late_bound": 1}]
    path = _write(tmp_path, "d.jsonl", rows)
    first = unknowns.as_text(unknowns.collect([str(path)]))
    second = unknowns.as_text(unknowns.collect([str(path)]))
    assert first == second
    kinds = [line.split(",")[0] for line in first.strip().splitlines()[1:]]
    assert kinds == sorted(kinds)


# --------------------------------------------------------------------------- wiring
def _run(argv, capsys):
    code = cli.main(argv)
    out, err = capsys.readouterr()
    return code, out, err


def test_cli_prints_the_table_and_a_summary(tmp_path, capsys):
    path = _write(tmp_path, "d.jsonl", [_dossier_row(sql=[_sql("OPEN_QUOTE")])])
    code, out, err = _run(["unknowns", str(path)], capsys)
    assert code == 0
    assert out.startswith("kind,count,")
    assert "sql:OPEN_QUOTE" in out
    assert "# 1 records read, 1 unknown markers" in err


def test_cli_json_is_parseable(tmp_path, capsys):
    path = _write(tmp_path, "d.jsonl", [_dossier_row(sql=[_sql("STUCK")])])
    code, out, _ = _run(["unknowns", str(path), "--json"], capsys)
    assert code == 0
    body = json.loads(out)
    assert body["records"] == 1 and body["kinds"]["sql:STUCK"]["count"] == 1


def test_a_missing_path_is_exit_2_not_an_empty_report(tmp_path, capsys):
    code, out, err = _run(["unknowns", str(tmp_path / "gone.jsonl")], capsys)
    assert code == 2
    assert out == ""
    assert err.startswith("error: ")
