"""The call graph: slices, and the edges it refuses to invent.

`edges` reports three kinds of call: one attributed to a listed procedure (a VA),
one named through the import table, and a late-bound count with no target at all.
The first two become nodes. The third becomes a single labelled `unresolved` node
per procedure — never an arrow to a guess, because a drawn edge is a claim and the
whole point of this toolkit is that claims carry evidence.
"""

from __future__ import annotations

import pytest
import synth_vb6

from vb6decompiler import cli, graph


def _row(va, names=(), obj="modA", procs=None, imports=None, late=0):
    return {"va": va, "object_name": obj, "names": list(names), "ended": "ret",
            "instructions": 5, "calls_procedures": procs or {},
            "calls_imported": imports or {}, "calls_late_bound": late}


ROWS = [
    _row("401000", ["Main"], procs={"401200": 2}, imports={"MSVBVM60!__vbaStrCopy": 1}, late=3),
    _row("401200", ["Helper"], procs={"401300": 1}),
    _row("401300", ["Deep"], procs={"401900": 1}),          # 401900 outside the dossier
    _row("402000", ["cmdOk_Click"], obj="fForm1"),
]


# --------------------------------------------------------------------------- assembly
def test_node_kinds_and_counts():
    g = graph.whole_graph(ROWS)
    counts = g.counts()
    assert counts["procedures"] == 5        # four listed + the VA outside the dossier
    assert counts["imports"] == 1
    assert counts["unresolved"] == 1
    # 401000 -> 401200 x2, -> import x1, -> unresolved x3; 401200 -> 401300; 401300 -> 401900
    assert counts["edges"] == 2 + 1 + 3 + 1 + 1


def test_a_target_outside_the_dossier_is_kept_and_labelled_by_its_va():
    g = graph.whole_graph(ROWS)
    node = g.nodes["401900"]
    assert "outside the dossier" in node.label
    assert node.kind == graph.PROCEDURE


def test_a_late_bound_call_becomes_one_unresolved_node_not_an_edge_to_a_guess():
    g = graph.whole_graph(ROWS)
    targets = [dst for (src, dst) in g.edges if src == "401000"]
    unresolved = [t for t in targets if t.startswith("unresolved:")]
    assert unresolved == ["unresolved:401000"]
    assert g.edges[("401000", "unresolved:401000")] == 3
    # Nothing was invented: every other target is a VA or an import the file named.
    assert set(targets) == {"401200", "import:MSVBVM60!__vbaStrCopy", "unresolved:401000"}


def test_the_label_prefers_the_object_and_the_first_name_hint():
    g = graph.whole_graph(ROWS)
    assert g.nodes["401000"].label == "modA.Main"
    unnamed = graph.whole_graph([_row("401500", [])])
    assert unnamed.nodes["401500"].label == "modA.401500"


# --------------------------------------------------------------------------- slicing
def test_a_slice_follows_one_direction_to_the_requested_depth():
    g = graph.whole_graph(ROWS)
    one = graph.slice_graph(g, "401000", 1)
    assert set(one.nodes) == {"401000", "401200", "import:MSVBVM60!__vbaStrCopy",
                              "unresolved:401000"}
    two = graph.slice_graph(g, "401000", 2)
    assert "401300" in two.nodes and "401900" not in two.nodes


def test_an_object_name_selects_every_procedure_of_that_object():
    g = graph.whole_graph(ROWS)
    sliced = graph.slice_graph(g, "modA", 0)
    assert set(sliced.nodes) == {"401000", "401200", "401300"}
    assert sliced.roots == ["401000", "401200", "401300"]


def test_the_reverse_direction_finds_callers():
    g = graph.whole_graph(ROWS)
    callers = graph.slice_graph(g, "401300", 1, direction="in")
    assert set(callers.nodes) == {"401300", "401200"}


def test_a_start_that_matches_nothing_raises_rather_than_drawing_an_empty_graph():
    g = graph.whole_graph(ROWS)
    with pytest.raises(graph.GraphError):
        graph.slice_graph(g, "nope", 1)
    with pytest.raises(graph.GraphError):
        graph.slice_graph(g, "DEADBEEF", 1)


def test_an_edges_file_that_is_not_one_is_refused():
    with pytest.raises(graph.GraphError):
        graph._normalise_va("dll!Func")


# --------------------------------------------------------------------------- rendering
def test_dot_escapes_a_hostile_label():
    g = graph.Graph()
    g.add_node(graph.Node("1", 'a"b\\c\nd'))
    g.add_node(graph.Node("2", "x"))
    g.add_edge("1", "2")
    dot = graph.as_dot(g)
    assert '\\"' in dot and "\\\\" in dot
    assert dot.count("\n") >= 4
    assert dot.startswith("digraph calls {") and dot.rstrip().endswith("}")


def test_mermaid_neutralises_brackets_and_quotes_in_a_label():
    g = graph.Graph()
    g.add_node(graph.Node("1", 'a["b"]|c'))
    text = graph.as_mermaid(g)
    label = text.split("\n")[1]
    assert '["' not in label[3:] or label.count('"') == 2


def test_both_formats_mark_imports_and_unresolved_nodes_differently():
    g = graph.whole_graph(ROWS)
    dot = graph.as_dot(g)
    assert "shape=ellipse" in dot and "shape=octagon" in dot
    mermaid = graph.as_mermaid(g)
    assert '(["' in mermaid and "{{" in mermaid


def test_the_summary_carries_both_numbers():
    g = graph.whole_graph(ROWS)
    sliced = graph.slice_graph(g, "401000", 1)
    line = graph.compare(sliced, g)
    # Two of the five nodes in the slice are procedures: the root and one callee.
    assert "2 of 5 procedures" in line


def test_ordering_is_deterministic():
    g = graph.whole_graph(ROWS)
    assert graph.as_dot(g) == graph.as_dot(graph.whole_graph(list(reversed(ROWS))))


def test_an_unreadable_line_is_skipped_not_fatal(tmp_path):
    path = tmp_path / "e.jsonl"
    path.write_text('{"va": "401000", "calls_procedures": {}}\nnot json\n\n'
                    '{"no_va": 1}\n', encoding="utf-8")
    rows = graph.rows_from(str(path))
    assert [r["va"] for r in rows] == ["401000"]


# --------------------------------------------------------------------------- wiring
@pytest.fixture()
def edges(tmp_path):
    target = synth_vb6.build(tmp_path / "synth")
    dossier = tmp_path / "synth" / "d.jsonl"
    path = tmp_path / "synth" / "e.jsonl"
    assert cli.main(["dossier", "--listings", str(target.listings), "--out", str(dossier)]) == 0
    assert cli.main(["edges", str(target.exe), "--dossier", str(dossier), "--out", str(path)]) == 0
    return target, path


def test_cli_draws_a_slice_and_says_what_it_is(edges, capsys):
    _, path = edges
    capsys.readouterr()
    code = cli.main(["graph", str(path), "--from", "modSynth01", "--depth", "1"])
    out, err = capsys.readouterr()
    assert code == 0
    assert out.startswith("digraph calls {")
    assert "modSynth01.Main" in out and "modSynth01.Helper" in out
    # Both modSynth01 procedures are roots and Helper is Main's only callee, so the
    # slice is exactly those two of the build's four.
    assert "2 of 4 procedures" in err


def test_cli_mermaid_and_out_write_a_manifest(edges, tmp_path, capsys):
    _, path = edges
    capsys.readouterr()
    out = tmp_path / "g.mmd"
    code = cli.main(["graph", str(path), "--format", "mermaid", "--all", "--out", str(out)])
    assert code == 0
    assert out.read_text(encoding="utf-8").startswith("flowchart LR")
    assert (tmp_path / "g.mmd.manifest.json").exists()
    assert "warning" in capsys.readouterr()[1]


def test_cli_without_a_start_or_all_is_exit_2(edges, capsys):
    _, path = edges
    capsys.readouterr()
    assert cli.main(["graph", str(path)]) == 2
    assert "nothing to draw" in capsys.readouterr()[1]


def test_cli_depth_without_from_is_exit_2(edges, capsys):
    _, path = edges
    capsys.readouterr()
    assert cli.main(["graph", str(path), "--depth", "1"]) == 2
    assert "--depth needs --from" in capsys.readouterr()[1]


def test_cli_a_bad_start_is_exit_2_not_a_traceback(edges, capsys):
    _, path = edges
    capsys.readouterr()
    assert cli.main(["graph", str(path), "--from", "nope"]) == 2
    assert "no object by that name" in capsys.readouterr()[1]


def test_cli_out_may_not_overwrite_the_edges_file(edges, capsys):
    _, path = edges
    capsys.readouterr()
    assert cli.main(["graph", str(path), "--all", "--out", str(path)]) == 2
    assert path.read_text(encoding="utf-8").strip()


def test_cli_all_warns_about_size(edges, capsys):
    _, path = edges
    capsys.readouterr()
    assert cli.main(["graph", str(path), "--all"]) == 0
    assert "the picture is as large as the program" in capsys.readouterr()[1]
