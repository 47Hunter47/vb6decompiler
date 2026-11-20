"""One Markdown specification per object, built from evidence the stages already wrote.

The product of a lost-source recovery is not source: it is a specification a
developer can rebuild from. This module assembles that per object — the design
(when the ``.frm`` text exists), the messages and captions the procedures carry,
the SQL they issue and the tables it touches, and the runtime helpers their code
calls — with every fact naming the stage it came from.

Three rules, all of them the project's:

* **Every fact carries its source.** Kind comes from the object table or it says
  it was not supplied; design comes from ``.frm`` text or it says the stage was
  not run; a runtime category is printed with the word ``unverified`` because the
  table that names it is a third party's notes.
* **Gaps are listed, not smoothed over.** Open SQL, controls with no recovered
  geometry, runtime helpers the table does not categorize: each is a line in the
  same file, with its denominator.
* **Text from the build is untrusted.** Names, captions and messages go through
  :func:`markdown_text` (which neutralises HTML, table cells and line breaks), and
  file names go through :func:`safe_file_name`, which reuses the Windows rules of
  :mod:`vb6decompiler.projectwrite` instead of inventing a second set.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .projectwrite import safe_stem

if TYPE_CHECKING:                      # the parser is only needed for its type here
    from .frm import Form

#: A literal that reads like something a user sees, rather than SQL.
_MESSAGE_HINT = re.compile(r"[A-Za-zÇĞİÖŞÜçğıöşü]{3,}[\s.!?:]")
#: Longest name a generated file may carry, matching projectwrite's own bound.
INDEX_NAME = "index.md"


def markdown_text(value) -> str:
    """Untrusted text as one inert Markdown line.

    HTML is neutralised (``<`` is what starts a tag in Markdown), table separators
    and emphasis characters are escaped, and anything a reader could not see -
    CR/LF, tab, the Unicode line separators - becomes a visible escape. Letters
    stay readable, Turkish included.
    """
    out = []
    for ch in str(value):
        if ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"):
            out.append(f"\\u{ord(ch):04x}")
        elif ch in "<>&":
            out.append({"<": "&lt;", ">": "&gt;", "&": "&amp;"}[ch])
        elif ch in "|`*_[]":
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def safe_file_name(name: str, taken: set[str], index: str) -> tuple[str, str | None]:
    """``(file name, repair reason)`` for one object, reusing projectwrite's rules.

    Windows device names, illegal characters and over-long names are decided in
    one place (:func:`projectwrite.safe_stem`); this adds only what a directory of
    Markdown files needs — a unique stem and the ``.md`` suffix.
    """
    stem, why = safe_stem(name)
    if stem is None:
        stem, why = f"object_{index}", "no usable characters in the object name"
    elif why and "reserved" in why:
        # safe_stem reports the reservation and hands back the name unchanged: the
        # caller decides, because only it knows what else is claimable here.
        stem = f"object_{index}"
    candidate = f"{stem}.md"
    n = 1
    while candidate.lower() in taken:
        candidate = f"{stem}_{n}.md"
        n += 1
        why = why or "name already taken in this directory"
    taken.add(candidate.lower())
    return candidate, why


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------
@dataclass
class Procedure:
    va: str
    names: list[str] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)
    sql: list[dict] = field(default_factory=list)
    runtime: dict = field(default_factory=dict)
    runtime_unlisted: dict = field(default_factory=dict)
    unverified_ops: dict = field(default_factory=dict)

    @property
    def closed(self) -> int:
        return sum(1 for row in self.sql if row.get("closed"))

    @property
    def open(self) -> int:
        return len(self.sql) - self.closed


@dataclass
class ObjectSpec:
    name: str
    kind: str
    kind_source: str
    procedures: list[Procedure] = field(default_factory=list)
    design: Form | None = None           # the parsed .frm design block, when supplied
    design_source: str = "not supplied"
    design_reason: str = ""
    file_name: str = ""
    name_repair: str | None = None

    @property
    def statements(self) -> int:
        return sum(len(p.sql) for p in self.procedures)

    @property
    def closed(self) -> int:
        return sum(p.closed for p in self.procedures)

    def gaps(self) -> list[str]:
        out = []
        open_sql = self.statements - self.closed
        if open_sql:
            out.append(f"open SQL: {open_sql} of {self.statements} statements need a run-time "
                       f"value (a trace closes them, nothing here did)")
        if self.design is None:
            out.append(f"design: {self.design_reason or 'not supplied'}")
        else:
            missing = [c for c in self.design.controls if c.bounds is None]
            if missing:
                out.append(f"geometry: {len(missing)} of {len(self.design.controls)} controls "
                           f"carry no complete rectangle")
            unknown = [c for c in self.design.controls if not c.type]
            if unknown:
                out.append(f"control type: {len(unknown)} of {len(self.design.controls)} "
                           f"controls name no type")
        unlisted = sum(sum(p.runtime_unlisted.values()) for p in self.procedures)
        if unlisted:
            out.append(f"runtime helpers the table does not categorize: {unlisted}")
        ops = sum(sum(p.unverified_ops.values()) for p in self.procedures)
        if ops:
            out.append(f"runtime calls carrying a third party's unverified note: {ops}")
        return out


@dataclass
class SpecReport:
    objects: list[ObjectSpec] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def counts(self) -> dict:
        return {
            "objects": len(self.objects),
            "procedures": sum(len(o.procedures) for o in self.objects),
            "statements": sum(o.statements for o in self.objects),
            "closed": sum(o.closed for o in self.objects),
            "files": len(self.objects) + 1,
        }


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------
def _messages(literals: list[dict], sql_texts: set[str]) -> list[str]:
    """Literals that read like something a user sees, never a SQL fragment."""
    out = []
    for literal in literals:
        text = literal.get("text")
        if not isinstance(text, str) or not text.strip() or text in sql_texts:
            continue
        if literal.get("encoding") == "listing" and _MESSAGE_HINT.search(text):
            out.append(text)
    return out


def build(records: list[dict], *, kinds: dict[str, tuple[str, str]] | None = None,
          design: dict[str, Form] | None = None,
          design_reason: str = "", outline: dict[str, dict] | None = None,
          known_tables: set[str] | None = None) -> SpecReport:
    """Assemble the report. Every optional input leaves a named absence behind.

    ``kinds`` maps an object name to ``(kind, source)``; ``design`` maps a
    lowercased form name to a parsed ``.frm``; ``outline`` maps a procedure VA to
    its outline row. Missing inputs are not errors — the file says what was not
    supplied, which is the difference between "no controls" and "no design stage".
    """
    report = SpecReport()
    by_object: dict[str, ObjectSpec] = {}
    for record in records:
        name = str(record.get("object_name") or "").strip() or "(unnamed object)"
        spec = by_object.get(name)
        if spec is None:
            kind, source = (kinds or {}).get(name, ("unknown", "no object table supplied"))
            spec = ObjectSpec(name=name, kind=kind, kind_source=source)
            by_object[name] = spec
        va = str(record.get("va") or "")
        proc = Procedure(va=va, names=list((record.get("name_hint") or {}).get("names") or []))
        sql_rows = [row for row in (record.get("sql") or []) if isinstance(row, dict)]
        proc.sql = sql_rows
        sql_texts = {str(row["text"]) for row in sql_rows if isinstance(row.get("text"), str)}
        proc.messages = _messages(list(record.get("literals") or []), sql_texts)
        row = (outline or {}).get(va.upper()) or (outline or {}).get(va)
        if isinstance(row, dict):
            proc.runtime = dict(row.get("api_calls") or {})
            proc.unverified_ops = dict(row.get("unverified_operations") or {})
            proc.runtime_unlisted = dict(row.get("runtime_unlisted") or {})
        spec.procedures.append(proc)

    if not kinds:
        report.notes.append("object kinds: no object table supplied (--exe), every kind reads 'unknown'")
    if design is None:
        design_reason = design_reason or "no .frm directory supplied (--frm)"
        report.notes.append(f"design: {design_reason}")
    if outline is None:
        report.notes.append("runtime calls: no outline file supplied (--outline)")
    if known_tables is not None:
        named: dict[str, str] = {}       # lower -> as written, so the note is readable
        for obj_spec in by_object.values():
            for proc in obj_spec.procedures:
                for row in proc.sql:
                    for table in row.get("tables") or []:
                        if isinstance(table, str):
                            named.setdefault(table.lower(), table)
        missing = sorted(named[name] for name in named.keys() - known_tables)
        if missing:
            report.notes.append(
                f"tables named by statements but absent from the schema: "
                f"{len(missing)} ({', '.join(markdown_text(t) for t in missing)}) - the schema "
                f"only models CLOSED statements, so an open one can name more")

    taken: set[str] = {INDEX_NAME.lower()}
    for index, (name, spec) in enumerate(sorted(by_object.items(), key=lambda kv: kv[0].lower())):
        form = (design or {}).get(name.lower())
        if form is not None:
            spec.design = form
            spec.design_source = ".frm design text (vb6d frm)"
        elif design is not None:
            spec.design_reason = f"no .frm design block for {markdown_text(name)} in the directory given"
        else:
            spec.design_reason = design_reason
        spec.file_name, spec.name_repair = safe_file_name(name, taken, str(index))
        spec.procedures.sort(key=lambda p: p.va)
        report.objects.append(spec)
    report.objects.sort(key=lambda o: o.file_name.lower())
    return report


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
def _control_row(control) -> str:
    bounds = control.bounds
    geometry = (f"{bounds[0]}, {bounds[1]}, {bounds[2]}, {bounds[3]}" if bounds
                else "unknown")
    caption_prop = control.prop("Caption")
    caption = markdown_text(caption_prop.value) if caption_prop is not None else "-"
    visible_prop = control.prop("Visible")
    visible = ("absent (VB6 omits the default)" if visible_prop is None
               else markdown_text(visible_prop.raw or visible_prop.value))
    index_prop = control.prop("Index")
    array_index = markdown_text(index_prop.raw or index_prop.value) if index_prop else "-"
    kind = markdown_text(control.type) if control.type else "unknown"
    return (f"| {markdown_text(control.name)} | {kind} | {caption} | {geometry} | "
            f"{visible} | {array_index} |")


def render_object(spec: ObjectSpec) -> str:
    out = [f"# {markdown_text(spec.name)}", "",
           f"- kind: **{markdown_text(spec.kind)}** (source: {markdown_text(spec.kind_source)})",
           f"- procedures: {len(spec.procedures)}",
           f"- SQL statements: {spec.closed} closed of {spec.statements}"]
    if spec.name_repair:
        out.append(f"- file name: `{spec.file_name}` ({markdown_text(spec.name_repair)})")
    out.append("")

    out.append("## Design")
    out.append("")
    if spec.design is None:
        out.append(f"No design recovered: {markdown_text(spec.design_reason or 'not supplied')}.")
    else:
        out.append(f"Source: {markdown_text(spec.design_source)}.")
        out.append("")
        out.append(f"Controls: {len(spec.design.controls)}.")
        out.append("")
        out.append("| Control | Type | Caption | Left, Top, Width, Height (twips) | Visible | Array index |")
        out.append("|---|---|---|---|---|---|")
        for control in spec.design.controls:
            out.append(_control_row(control))
        if getattr(spec.design, "complete", True) is False:
            out.append("")
            out.append("**The design block had no closing `End`:** the controls above are what "
                       "was recovered before the cut.")
    out.append("")

    out.append("## Procedures")
    out.append("")
    if not spec.procedures:
        out.append("None recorded.")
    for proc in spec.procedures:
        out.append(f"### `{proc.va}`")
        out.append("")
        if proc.names:
            hints = ", ".join(markdown_text(n) for n in proc.names)
            out.append(f"- name hints: {hints} (a decompiler's guess, not the designer's name)")
        out.append(f"- SQL: {proc.closed} closed of {len(proc.sql)}")
        if proc.messages:
            out.append(f"- text that reads as a message or a caption ({len(proc.messages)}):")
            for message in proc.messages:
                out.append(f"  - {markdown_text(message)}")
        for row in proc.sql:
            status = markdown_text(row.get("status") or "?")
            tables = row.get("tables") or []
            where = f" tables: {', '.join(markdown_text(t) for t in tables)}" if tables else ""
            if row.get("closed"):
                out.append(f"- CLOSED (`{status}`){where}: {markdown_text(row.get('text') or '')}")
            else:
                out.append(f"- not closed (`{status}`){where}: the text is a fragment, "
                           f"so it is not printed as a statement")
        if proc.runtime or proc.runtime_unlisted:
            named = ", ".join(f"{markdown_text(k)} x{v}" for k, v in sorted(proc.runtime.items()))
            out.append(f"- runtime helpers called, by category (third-party notes, unverified): "
                       f"{named or 'none categorized'}")
            if proc.runtime_unlisted:
                out.append("  - the table does not categorize: "
                           + ", ".join(f"{markdown_text(k)} x{v}"
                                       for k, v in sorted(proc.runtime_unlisted.items())))
        out.append("")

    gaps = spec.gaps()
    out.append("## Gaps")
    out.append("")
    out.extend(f"- {gap}" for gap in gaps) if gaps else out.append("None.")
    return "\n".join(out) + "\n"


def render_index(report: SpecReport) -> str:
    counts = report.counts()
    out = ["# Specification", "",
           (f"{counts['objects']} objects, {counts['procedures']} procedures, "
            f"{counts['closed']} closed of {counts['statements']} SQL statements."), "",
           "| Object | Kind | Procedures | SQL closed | File |",
           "|---|---|---|---|---|"]
    for spec in report.objects:
        out.append(f"| {markdown_text(spec.name)} | {markdown_text(spec.kind)} | "
                   f"{len(spec.procedures)} | {spec.closed} of {spec.statements} | "
                   f"[{spec.file_name}]({spec.file_name}) |")
    if report.notes:
        out.append("")
        out.append("## What was not supplied")
        out.append("")
        out.extend(f"- {markdown_text(note)}" for note in report.notes)
    out.append("")
    out.append("Every fact above names the stage it came from; a gap is a gap, not a guess.")
    return "\n".join(out) + "\n"


def files(report: SpecReport) -> list[tuple[str, str]]:
    """``(file name, text)`` for the whole report, index first."""
    out = [(INDEX_NAME, render_index(report))]
    out.extend((spec.file_name, render_object(spec)) for spec in report.objects)
    return out

