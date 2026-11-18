"""The outline reader over synthetic edges rows - no engine, no exe needed."""
import json

from vb6decompiler import runtime_table


def write_edges(path, rows, extra_line=""):
    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
        if extra_line:
            fh.write(extra_line + "\n")


def test_outline_buckets_categories_api_and_unknown(tmp_path):
    from vb6decompiler import outline

    cat = runtime_table.describe("__vbaStrCat")  # expected value from the table itself
    assert cat is not None and cat.category
    edges = tmp_path / "edges.jsonl"
    write_edges(edges, [
        {"va": "15A20C0", "object_name": "fX", "names": ["Proc_1"], "ended": "ret",
         "instructions": 5,
         "calls_imported": {"MSVBVM60.DLL!__vbaStrCat": 2,
                            "kernel32!lstrcpynA": 1,
                            "MSVBVM60.DLL!__vbaTotallyMadeUp": 1},
         "calls_procedures": {"15A3000": 3}, "calls_late_bound": 7},
        {"va": "1", "object_name": "fY", "names": [], "ended": "ret",
         "instructions": 1, "calls_imported": {}, "calls_procedures": {}},
    ])
    rows = [outline.outline_row(json.loads(x)) for x in edges.read_text(encoding="utf-8").splitlines()]
    a, b = rows
    assert a["unverified_operations"] == {cat.category: 2}
    assert a["api_calls"] == {"kernel32!lstrcpynA": 1}
    assert a["runtime_unlisted"] == {"MSVBVM60.DLL!__vbaTotallyMadeUp": 1}
    assert a["late_bound_calls"] == 7
    assert b["unverified_operations"] == {} and "runtime_unlisted" not in b
    assert "late_bound_calls" not in b


def test_outline_cli(tmp_path, capsys):
    from vb6decompiler import cli

    edges = tmp_path / "edges.jsonl"
    write_edges(edges, [{"va": "1", "object_name": "f", "names": [], "ended": "ret",
                         "instructions": 1,
                         "calls_imported": {"MSVBVM60.DLL!__vbaStrCat": 2},
                         "calls_procedures": {}}], extra_line="not-a-json-line")
    out = tmp_path / "outline.jsonl"
    code = cli.main(["outline", str(edges), "--out", str(out)])
    _o, err = capsys.readouterr()
    assert code == 0
    rows = [json.loads(x) for x in out.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 1 and sum(rows[0]["unverified_operations"].values()) == 2
    assert "unverified" in err
    assert "1 unreadable lines skipped" in err
    assert cli.main(["outline", str(tmp_path / "nope.jsonl")]) == 2


def test_outline_names_every_unusable_line(tmp_path, capsys):
    from vb6decompiler import cli

    edges = tmp_path / "edges.jsonl"
    write_edges(
        edges,
        [{"va": "1", "object_name": "f", "names": [], "ended": "ret",
          "instructions": 1, "calls_imported": {}, "calls_procedures": {}}],
        extra_line="not json\n[]\n"
                   + '{"object_name": "no-va"}\n{"va": "zz", "calls_imported": {}}\n'
                   + '{"va": "2", "object_name": "g", "names": [], "ended": "ret",'
                   + '"instructions": 1, "calls_imported": [1], "calls_procedures": {}}')
    out = tmp_path / "outline.jsonl"
    code = cli.main(["outline", str(edges), "--out", str(out)])
    _o, err = capsys.readouterr()
    assert code == 0
    assert len(out.read_text(encoding="utf-8").splitlines()) == 1
    assert "line 2: not JSON" in err
    assert "line 3: record is not a JSON object" in err
    assert "line 4: edges row has no va" in err
    assert "line 5: va 'zz' is not a hex address" in err
    assert "line 6: edges row has malformed fields" in err
    assert "5 unreadable lines skipped" in err
