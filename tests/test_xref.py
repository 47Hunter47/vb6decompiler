"""vb6d xref: the dossier file read from the other side.

Synthetic dossier records only — xref consumes the JSONL shape, not the
listings, and invents nothing beyond inverting what the dossier wrote.
"""
import json

from vb6decompiler import xref


def _rec(va, obj, hints, literals, sql=()):
    lits = [{"va": v, "text": t, "encoding": "cp1252"} for v, t in literals]
    return json.dumps({
        "va": va, "object_name": obj,
        "name_hint": {"kind": "hint", "names": hints} if hints else None,
        "literals": lits,
        "sql": [{"text": t, "closed": True, "proc_va": va, "text_va": tv} for t, tv in sql],
        "counts": {"literals": len(lits), "sql_closed": len(sql), "sql_open": 0,
                   "sql_truncated": False},
    })


def _file(tmp_path, lines):
    path = tmp_path / "dossier.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_rollup_and_search_and_invert(tmp_path):
    p = _file(tmp_path, [
        _rec("401000", "fDemo012", ["Command1_Click"], [("410000", "SELECT * FROM tCustomer"),
                                                        ("410050", "Ad Soyad")]),
        _rec("402000", "modGenel", [], [("410050", "Ad Soyad")],
             sql=[("SELECT * FROM tCustomer", "410000")]),
        "not json at all",
    ])
    with open(p, encoding="utf-8") as fh:
        procs, bad = xref._procedures(fh)
    assert len(procs) == 2 and len(bad) == 1

    rolled = xref.rollup(procs)["procedures"]
    assert rolled[0]["va"] == "401000"  # more literal mentions first
    assert rolled[0]["hints"] == ["Command1_Click"]

    hit = xref.search(procs, "ad soyad", "literals")  # case-insensitive on purpose
    assert [h["owner"]["object_name"] for h in hit["literals"]] == ["fDemo012", "modGenel"]

    sq = xref.search(procs, "tCustomer", "sql")
    # fDemo012 mentions the statement only as a raw literal here; its sql list is
    # empty in this fixture, so only the procedure with a real SQL entry hits.
    assert [h["owner"]["object_name"] for h in sq["sql"]] == ["modGenel"]

    full = xref.full(procs)
    owners = {row["literal_va"]: [p["object_name"] for p in row["procedures"]]
              for row in full["literal_to_procedures"]}
    assert owners["410050"] == ["fDemo012", "modGenel"]  # shared literal found by both
    assert full["sql_to_procedures"][0]["sql_va"] == "410000"


def test_xref_cli_shapes_are_parseable_json(tmp_path, capsys):
    from vb6decompiler import cli

    def run(argv):
        code = cli.main(argv)
        out, err = capsys.readouterr()
        return code, out, err

    p = _file(tmp_path, [_rec("401000", "fDemo012", [], [("410000", "SELECT x")])])
    code, out, err = run(["xref", str(p)])
    assert code == 0
    assert json.loads(out)["tool"] == "vb6d xref"
    assert "# 1 procedures" in err
    code, out, _err = run(["xref", str(p), "--literal", "SELECT"])
    assert code == 0 and len(json.loads(out)["literals"]) == 1
    # missing input file is the exit-2 contract, not a traceback
    code, out, err = run(["xref", str(tmp_path / "absent.jsonl")])
    assert code == 2


def test_malformed_lines_are_named_and_counted_not_fatal(tmp_path):
    # valid JSON is not automatically a dossier record: xref counts, names
    # (line + reason) and keeps reading (review item G).
    p = _file(tmp_path, [
        _rec("401000", "fDemo012", [], [("410000", "SELECT 1")]),
        "not json at all",
        "[]",
        '"a bare string"',
        '{"literals": []}',
        '{"va": "z-z", "literals": []}',
        '{"va": "403000", "name_hint": 7}',
        '{"va": "404000", "name_hint": {"names": "Main"}}',
        '{"va": "405000", "literals": "oops"}',
        '{"va": "406000", "literals": [7]}',
        '{"va": "407000", "sql": [{"text": 7, "text_va": "410000"}]}',
        '{"va": "408000", "counts": {"literals": "3"}}',
        '{"va": "408100", "literals": [{"va": "zz", "text": "t"}]}',
        _rec("409000", "fOk", [], [("410010", "OK")]),
    ])
    with open(p, encoding="utf-8") as fh:
        procs, bad = xref._procedures(fh)
    assert [r["va"] for r in procs] == ["401000", "409000"]
    assert [note.split(":")[0] for note in bad] == [f"line {n}" for n in range(2, 14)]
    reasons = " ".join(bad)
    for word in ("not JSON", "not a JSON object", "no va", "hex address",
                 "name_hint is not an object", "list of strings", "literals",
                 "counts", "text/text_va"):
        assert word in reasons
    rows = xref.full(procs)["literal_to_procedures"]
    assert sorted(r["literal_va"] for r in rows) == ["410000", "410010"]
