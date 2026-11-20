"""A call graph you can slice: DOT or Mermaid, around one procedure or one form.

A whole-program graph of 34,000 procedures is unreadable, so this stage's default
is a *slice*: start at a procedure (by VA) or an object (by name) and follow the
edges out to a given depth, or in, or both. ``--all`` exists and prints the size
first, because sometimes the whole picture is the question.

The rule that shapes the output: **an edge exists only where the evidence names a
target.** ``edges`` writes ``calls_procedures`` (a VA it attributed), ``calls_imported``
(a runtime helper, named through the import table) and ``calls_late_bound`` (a count
with no target at all). The first two become nodes; the third becomes one clearly
labelled ``unresolved`` node per procedure, never an edge to a guessed target — a
graph that invents an arrow is worse than one that shows a gap.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field

#: Node kinds, spelled in the output so a reader can filter.
PROCEDURE, IMPORT, UNRESOLVED = "proc", "import", "unresolved"


class GraphError(ValueError):
    """The request cannot be answered from the edges file (not a syntax problem)."""


@dataclass(frozen=True)
class Node:
    id: str
    label: str
    kind: str = PROCEDURE


@dataclass
class Graph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: dict[tuple[str, str], int] = field(default_factory=lambda: defaultdict(int))
    #: Procedures the slice started at, so a renderer can mark them.
    roots: list[str] = field(default_factory=list)

    def add_node(self, node: Node) -> None:
        self.nodes.setdefault(node.id, node)

    def add_edge(self, src: str, dst: str) -> None:
        self.edges[(src, dst)] += 1

    def counts(self) -> dict:
        return {
            "nodes": len(self.nodes),
            "edges": sum(self.edges.values()),
            "procedures": sum(1 for n in self.nodes.values() if n.kind == PROCEDURE),
            "imports": sum(1 for n in self.nodes.values() if n.kind == IMPORT),
            "unresolved": sum(1 for n in self.nodes.values() if n.kind == UNRESOLVED),
        }


# ---------------------------------------------------------------------------
# Reading the edges file
# ---------------------------------------------------------------------------
def rows_from(path: str) -> list[dict]:
    """Every readable row; an unreadable line is skipped and counted by the caller.

    A partially written edges file is normal after an interrupted run, and one bad
    line must not cost the graph: the count is reported instead.
    """
    out = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict) and isinstance(row.get("va"), str):
                out.append(row)
    return out


def _label(row: dict) -> str:
    """A procedure's label: its object and the first name hint it carries."""
    name = (row.get("names") or [None])[0]
    obj = row.get("object_name") or ""
    if name:
        return f"{obj}.{name}" if obj else str(name)
    # No name hint: the VA is the identity, and the object still says where it is.
    va = row.get("va", "?")
    return f"{obj}.{va}" if obj else str(va)


def whole_graph(rows: list[dict]) -> Graph:
    graph = Graph()
    by_va: dict[str, dict] = {}
    for row in rows:
        va = row["va"].upper()
        by_va[va] = row
        graph.add_node(Node(va, _label(row), PROCEDURE))
    for va, row in by_va.items():
        for target, count in (row.get("calls_procedures") or {}).items():
            key = str(target).upper()
            if key not in by_va:
                # A VA the dossier never listed: keep it, labelled as itself. It is
                # evidence of a call, and calling it unknown-by-name is not the same
                # as calling the edge unknown.
                graph.add_node(Node(key, f"VA {key} (outside the dossier)", PROCEDURE))
            for _ in range(int(count) if isinstance(count, int) else 1):
                graph.add_edge(va, key)
        for name, count in (row.get("calls_imported") or {}).items():
            node_id = f"import:{name}"
            graph.add_node(Node(node_id, str(name), IMPORT))
            for _ in range(int(count) if isinstance(count, int) else 1):
                graph.add_edge(va, node_id)
        late = row.get("calls_late_bound")
        if isinstance(late, int) and late > 0:
            node_id = f"unresolved:{va}"
            graph.add_node(Node(node_id, "unresolved (late-bound)", UNRESOLVED))
            for _ in range(late):
                graph.add_edge(va, node_id)
    return graph


def _normalise_va(text: str) -> str:
    raw = text.strip().upper()
    raw = raw.removeprefix("0X")
    if not re.fullmatch(r"[0-9A-F]{4,16}", raw):
        raise GraphError(f"--from {text!r}: not a VA (pass bare hex, e.g. 4013B0) or an object name")
    return raw


def slice_graph(graph: Graph, start: str, depth: int, *, direction: str = "out") -> Graph:
    """Everything within ``depth`` hops of ``start``, in one direction.

    ``start`` is a VA or an object name; an object name selects every procedure of
    that object, which is what "show me this form's calls" means. A start that
    matches nothing raises: an empty graph would read as "this object calls nothing".
    """
    roots = _roots(graph, start)
    keep: set[str] = set(roots)

    steps = max(depth, 0)
    if direction in ("out", "both"):
        frontier = set(roots)
        for _ in range(steps):
            frontier = {dst for (src, dst) in graph.edges if src in frontier} - keep
            if not frontier:
                break
            keep |= frontier
    if direction in ("in", "both"):
        frontier = set(roots)
        for _ in range(steps):
            frontier = {src for (src, dst) in graph.edges if dst in frontier} - keep
            if not frontier:
                break
            keep |= frontier

    out_graph = Graph(roots=list(roots))
    for node_id in sorted(keep):
        if node_id in graph.nodes:
            out_graph.add_node(graph.nodes[node_id])
    for (src, dst), count in graph.edges.items():
        if src in out_graph.nodes and dst in out_graph.nodes:
            out_graph.edges[(src, dst)] = count
    return out_graph


def _roots(graph: Graph, start: str) -> list[str]:
    """The procedures a ``--from`` argument selects, or :class:`GraphError`."""
    try:
        va = _normalise_va(start)
    except GraphError:
        va = None
    if va is not None:
        if va not in graph.nodes:
            raise GraphError(f"--from {start!r}: no procedure with that VA in the edges file")
        return [va]
    wanted = start.strip().lower()
    found = sorted(n.id for n in graph.nodes.values()
                   if n.kind == PROCEDURE and n.label.lower().split(".")[0] == wanted)
    if not found:
        raise GraphError(f"--from {start!r}: no object by that name in the edges file")
    return found


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
def _dot_id(node_id: str) -> str:
    return "n_" + re.sub(r"[^0-9A-Za-z_]", "_", node_id)


def _dot_quote(text: str) -> str:
    """DOT string escaping: a quote ends the string, a backslash ends the line."""
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def as_dot(graph: Graph) -> str:
    out = ["digraph calls {", "  rankdir=LR;", "  node [shape=box, fontname=\"Helvetica\"];"]
    for node in sorted(graph.nodes.values(), key=lambda n: n.id):
        attrs = []
        if node.kind == IMPORT:
            attrs.append('shape=ellipse,style=dashed')
        elif node.kind == UNRESOLVED:
            attrs.append('shape=octagon,style=dashed,color=firebrick')
        if node.id in graph.roots:
            attrs.append('penwidth=2,color=navy')
        suffix = (", " + ", ".join(attrs)) if attrs else ""
        out.append(f"  {_dot_id(node.id)} [label={_dot_quote(node.label)}{suffix}];")
    for (src, dst), count in sorted(graph.edges.items()):
        label = f' [label="{count}"]' if count > 1 else ""
        out.append(f"  {_dot_id(src)} -> {_dot_id(dst)}{label};")
    out.append("}")
    return "\n".join(out) + "\n"


def _mermaid_id(node_id: str) -> str:
    return "n" + re.sub(r"[^0-9A-Za-z]", "_", node_id)


def _mermaid_text(text: str) -> str:
    """Mermaid labels break on quotes, brackets and pipes; neutralise them."""
    return re.sub(r'["\[\]{}()|<>]', lambda m: {"<": "#lt;", ">": "#gt;"}.get(m.group(0), "_"), text)


def as_mermaid(graph: Graph) -> str:
    out = ["flowchart LR"]
    for node in sorted(graph.nodes.values(), key=lambda n: n.id):
        label = _mermaid_text(node.label)
        if node.kind == IMPORT:
            out.append(f'  {_mermaid_id(node.id)}(["{label}"])')
        elif node.kind == UNRESOLVED:
            # Mermaid's hexagon: {{text}}. The label is already neutralised above,
            # so it cannot close the shape early.
            out.append(f"  {_mermaid_id(node.id)}{{{{{label}}}}}")
        else:
            out.append(f'  {_mermaid_id(node.id)}["{label}"]')
    for (src, dst), count in sorted(graph.edges.items()):
        arrow = f"-->|{count}|" if count > 1 else "-->"
        out.append(f"  {_mermaid_id(src)} {arrow} {_mermaid_id(dst)}")
    return "\n".join(out) + "\n"


def compare(drawn: Graph, whole: Graph) -> str:
    """The one line a reader needs: what this file is, against what exists.

    Both numbers, never a percentage alone: "2 of 4 procedures" says a slice was
    asked for, while "50%" could equally be a graph that lost half its rows.
    """
    d, w = drawn.counts(), whole.counts()
    return (f"{d['procedures']} of {w['procedures']} procedures, "
            f"{d['edges']} of {w['edges']} edges")


def summary(graph: Graph) -> str:
    counts = graph.counts()
    return (f"# {counts['procedures']} procedures, {counts['imports']} imported helpers, "
            f"{counts['unresolved']} unresolved nodes; {counts['edges']} edges")
