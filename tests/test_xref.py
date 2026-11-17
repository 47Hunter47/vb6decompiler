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
        _rec("401000", "fDemo902", ["Command1_Click"], [("410000", "SELECT * FROM tDemoCustomer"),
                                                        ("410050", "Ad Soyad")]),
        _rec("402000", "modGenel", [], [("410050", "Ad Soyad")],
             sql=[("SELECT * FROM tDemoCustomer", "410000")]),
        "not json at all",
    ])
    with open(p, encoding="utf-8") as fh:
        procs, bad = xref._procedures(fh)
    assert len(procs) == 2 and len(bad) == 1

    rolled = xref.rollup(procs)["procedures"]
    assert rolled[0]["va"] == "401000"  # more literal mentions first
    assert rolled[0]["hints"] == ["Command1_Click"]

    hit = xref.search(procs, "ad soyad", "literals")  # case-insensitive on purpose
    assert [h["owner"]["object_name"] for h in hit["literals"]] == ["fDemo902", "modGenel"]

    sq = xref.search(procs, "tDemoCustomer", "sql")
    # fDemo902 mentions the statement only as a raw literal here; its sql list is
    # empty in this fixture, so only the procedure with a real SQL entry hits.
    assert [h["owner"]["object_name"] for h in sq["sql"]] == ["modGenel"]

    full = xref.full(procs)
    owners = {row["literal_va"]: [p["object_name"] for p in row["procedures"]]
              for row in full["literal_to_procedures"]}
    assert owners["410050"] == ["fDemo902", "modGenel"]  # shared literal found by both
    assert full["sql_to_procedures"][0]["sql_va"] == "410000"


def test_xref_cli_shapes_are_parseable_json(tmp_path, capsys):
    from vb6decompiler import cli

    def run(argv):
        code = cli.main(argv)
        out, err = capsys.readouterr()
        return code, out, err

    p = _file(tmp_path, [_rec("401000", "fDemo902", [], [("410000", "SELECT x")])])
    code, out, err = run(["xref", str(p)])
    assert code == 0
    assert json.loads(out)["tool"] == "vb6d xref"
    assert "# 1 procedures" in err
    code, out, _err = run(["xref", str(p), "--literal", "SELECT"])
    assert code == 0 and len(json.loads(out)["literals"]) == 1
    # missing input file is the exit-2 contract, not a traceback
    code, out, err = run(["xref", str(tmp_path / "absent.jsonl")])
    assert code == 2
