"""A data model read out of the closed SQL statements a build carries.

The point of recovering a lost source is a rewrite, and the SQL is the most
reliable evidence in the binary: it is plain text. So the useful artefact is not
34,000 statements but a model — which tables exist, which columns are named, who
reads and who writes them.

Two rules decide everything below:

* **Nothing is guessed.** A construct the tokenizer does not recognise is
  reported with its reason instead of being coerced into a table or a column.
  ``*`` is recorded as a star; a qualifier whose alias the statement never
  defined stays unattributed; an expression is an expression, not the column
  its text happens to start with.
* **Every count has a denominator.** Statements in = parsed + unparsed + open, and
  the report prints that sum so a reader can check it. Open statements (built at
  run time) are listed as gaps and never parsed: their text is a fragment.

The dialect handled is the one these programs actually use — Jet/Access through
RDO and SQL Server through OLE DB: ``[bracketed names]``, ``#date#`` literals,
``?`` parameter markers, ``&`` concatenation. That is a subset on purpose; a
statement outside it is unparsed, not approximated.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field

#: Statement verbs that decide the CRUD letter. Anything else is ``other``.
KINDS = {
    "select": "R",
    "insert": "C",
    "update": "U",
    "delete": "D",
}
#: Words that end a FROM list.
FROM_END = {
    "where", "group", "order", "having", "union", "on", "using", "into", "values",
    "set", "when", "then", "else", "end", "as", "join", "inner", "left", "right",
    "full", "cross", "outer", "select",
}
#: Join noise that carries no table name of its own.
JOIN_NOISE = {"inner", "left", "right", "full", "cross", "outer", "join"}
#: How much of an unparsed statement the report keeps: a hash can be compared
#: between two runs, the text itself may not be ours to publish.
SHA_CHARS = 12


class SQLSyntax(ValueError):
    """The statement is outside the dialect this tokenizer handles."""


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Token:
    kind: str        # ident, string, number, param, op, punct
    text: str
    bare: str = ""   # identifiers: the name without its brackets/quotes
    quoted: bool = False


#: Bare identifiers carry the build's own letters. Jet accepts unquoted non-ASCII
#: names, and a Turkish-named column is the common case in these programs: an
#: ASCII-only rule rejected 104 of 107 unparsed statements on the reference
#: listing corpus, every one of them for a letter rather than a construct.
_IDENT_START = re.compile(r"[^\W\d]|[@#]")
_IDENT_BODY = re.compile(r"[\w$@#]*")
_NUMBER = re.compile(r"[0-9]+(?:\.[0-9]+)?")
_OPS = ("<>", "<=", ">=", "!=", "=", "<", ">", "+", "-", "*", "/", "&", "|", "!")


def tokenize(text: str) -> list[Token]:
    """Split one statement. Raises :class:`SQLSyntax` on anything unbalanced.

    Deliberately small: a token this function cannot name means the statement is
    outside the handled dialect, and saying so is more useful than a guess.
    """
    out: list[Token] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch in " \t\r\n":
            i += 1
            continue
        if ch == "'":                                   # string, '' escapes a quote
            j = i + 1
            buf = []
            while j < n:
                if text[j] == "'":
                    if j + 1 < n and text[j + 1] == "'":
                        buf.append("'")
                        j += 2
                        continue
                    break
                buf.append(text[j])
                j += 1
            if j >= n:
                raise SQLSyntax("unterminated string")
            out.append(Token("string", text[i:j + 1], "".join(buf)))
            i = j + 1
            continue
        if ch == "[" or ch == '"':                       # quoted identifier
            close = "]" if ch == "[" else '"'
            j = text.find(close, i + 1)
            if j < 0:
                raise SQLSyntax("unterminated quoted identifier")
            name = text[i + 1:j]
            if not name:
                raise SQLSyntax("empty quoted identifier")
            out.append(Token("ident", text[i:j + 1], name, quoted=True))
            i = j + 1
            continue
        if ch == "#":                                    # Jet date literal
            j = text.find("#", i + 1)
            if j < 0:
                raise SQLSyntax("unterminated date literal")
            out.append(Token("string", text[i:j + 1], text[i + 1:j]))
            i = j + 1
            continue
        if ch == "?":
            out.append(Token("param", ch))
            i += 1
            continue
        if ch.isdigit():
            m = _NUMBER.match(text, i)
            assert m is not None
            out.append(Token("number", m.group(0)))
            i = m.end()
            continue
        if _IDENT_START.match(ch):
            m = _IDENT_BODY.match(text, i + 1)
            assert m is not None
            name = text[i:m.end()]
            out.append(Token("ident", name, name))
            i = m.end()
            continue
        for op in _OPS:
            if text.startswith(op, i):
                out.append(Token("op", op))
                i += len(op)
                break
        else:
            if ch in "(),.;:":
                out.append(Token("punct", ch))
                i += 1
            else:
                raise SQLSyntax(f"unexpected character {ch!r}")
    if not out:
        raise SQLSyntax("empty statement")
    return out


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Column:
    """A column the statement names, and the table it was attributed to."""

    table: str | None
    name: str


@dataclass
class Parsed:
    kind: str
    tables: list[str] = field(default_factory=list)
    columns: list[Column] = field(default_factory=list)
    params: int = 0
    #: Everything the parser had to leave unresolved, in the statement's own terms.
    notes: list[str] = field(default_factory=list)


def _word(tok: Token) -> str:
    return (tok.bare or tok.text).lower()


def _depth_change(tok: Token) -> int:
    return 1 if tok.text == "(" else -1 if tok.text == ")" else 0


def _split_top(tokens: list[Token], sep: str = ",") -> list[list[Token]]:
    """Split on ``sep`` at paren depth 0."""
    parts: list[list[Token]] = []
    current: list[Token] = []
    depth = 0
    for tok in tokens:
        depth += _depth_change(tok)
        if depth == 0 and tok.text == sep and tok.kind == "punct":
            parts.append(current)
            current = []
            continue
        current.append(tok)
    if current:
        parts.append(current)
    return parts


def _table_list(tokens: list[Token]) -> tuple[list[tuple[str, str | None]], int]:
    """``(table, alias)`` pairs from the tokens after FROM/UPDATE/INTO/DELETE.

    Stops at the first clause keyword. A parenthesised item (a subquery) is
    counted and skipped, never descended into.
    """
    out: list[tuple[str, str | None]] = []
    i, n = 0, len(tokens)
    while i < n:
        tok = tokens[i]
        word = _word(tok)
        if tok.kind == "punct" and tok.text == "(":
            depth, j = 1, i + 1
            while j < n and depth:
                depth += _depth_change(tokens[j])
                j += 1
            out.append(("<subquery>", None))
            i = j
            continue
        if tok.kind == "ident" and word in JOIN_NOISE:
            i += 1
            continue
        if tok.kind == "ident" and word == "on":
            depth, j = 0, i + 1
            while j < n:
                depth += _depth_change(tokens[j])
                if depth == 0 and tokens[j].kind == "ident" and _word(tokens[j]) in FROM_END:
                    break
                if depth == 0 and tokens[j].kind == "punct" and tokens[j].text == ",":
                    break
                j += 1
            i = j
            continue
        if tok.kind == "ident" and word in FROM_END:
            break
        if tok.kind == "ident" and word not in JOIN_NOISE:
            name = tok.bare or tok.text
            canonical = f"{name}.{tokens[i + 2].bare}" if (
                i + 2 < n and tokens[i + 1].text == "." and tokens[i + 2].kind == "ident") else name
            step = 3 if canonical != name else 1
            alias = None
            k = i + step
            if k < n and tokens[k].kind == "ident" and _word(tokens[k]) == "as":
                k += 1
            if k < n and tokens[k].kind == "ident" and _word(tokens[k]) not in FROM_END:
                alias = tokens[k].bare or tokens[k].text
                k += 1
            out.append((canonical, alias))
            i = k
            continue
        i += 1
    return out, i


def _qualified(tokens: list[Token], aliases: dict[str, str], tables: list[str]) -> Column:
    """Turn one select-list / assignment token run into a column, or a note."""
    if len(tokens) == 1 and tokens[0].kind == "op" and tokens[0].text == "*":
        return Column(tables[0] if len(tables) == 1 else None, "*")
    if (len(tokens) == 3 and tokens[0].kind == "ident" and tokens[1].text == "."
            and tokens[2].kind == "op" and tokens[2].text == "*"):
        return Column(_attribute(tokens[0].bare, "*", aliases, tables, qualified=True), "*")
    # A three-part name is schema.table.column (SQL Server): the first two parts
    # are the table, which is how such a name is written when an alias is absent.
    if (len(tokens) == 5 and tokens[1].text == "." and tokens[3].text == "."
            and all(t.kind == "ident" for t in (tokens[0], tokens[2], tokens[4]))):
        table = f"{tokens[0].bare}.{tokens[2].bare}"
        return Column(table, tokens[4].bare)
    names = [t for t in tokens if t.kind == "ident"]
    if not names:
        return Column(None, "")
    head = names[0]
    if len(tokens) == 1:
        return Column(_attribute(head.bare, head.bare, aliases, tables), head.bare)
    if len(tokens) == 3 and tokens[1].text == "." and tokens[2].kind == "ident":
        owner = _attribute(tokens[0].bare, tokens[2].bare, aliases, tables, qualified=True)
        return Column(owner, tokens[2].bare)
    return Column(None, "")           # an expression: not a named column


def _attribute(qualifier: str, name: str, aliases: dict[str, str], tables: list[str],
               qualified: bool = False) -> str | None:
    """Which table a column belongs to — only when the statement says so.

    A qualifier resolves through the statement's own alias map. With exactly one
    table in the statement an *unqualified* column is that table's (the statement
    cannot be read any other way); with two or more it stays unattributed. A
    qualifier that resolved to nothing is never handed the only table: that was a
    measured wrong answer — ``SELECT z.OrderNo FROM tOrder o`` invented
    ``tOrder.OrderNo`` although ``z`` names nothing in the statement.
    """
    if qualifier.lower() in aliases:
        return aliases[qualifier.lower()]
    for table in tables:
        if table.lower() == qualifier.lower():
            return table
    if len(tables) == 1 and not qualified:
        return tables[0]
    return None


def parse(text: str) -> Parsed:
    """One closed SQL statement into kinds, tables and named columns."""
    tokens = tokenize(text)
    depth = 0
    for tok in tokens:                     # a top-level ';' inside one candidate is a join bug
        depth += _depth_change(tok)
        if depth < 0:
            raise SQLSyntax("unbalanced parentheses")
    if depth:
        raise SQLSyntax("unbalanced parentheses")

    while tokens and tokens[0].kind == "punct" and tokens[0].text == "(":
        tokens = tokens[1:]
    if not tokens or tokens[0].kind != "ident":
        raise SQLSyntax("statement does not begin with a verb")
    verb = _word(tokens[0])
    parsed = Parsed(kind=verb if verb in KINDS else "other")
    if verb not in KINDS:
        parsed.notes.append(f"verb not modelled: {tokens[0].bare}")
        return parsed

    body = tokens[1:]
    if verb == "select":
        _parse_select(parsed, body)
    elif verb == "insert":
        _parse_insert(parsed, body)
    elif verb == "update":
        _parse_update(parsed, body)
    else:
        _parse_delete(parsed, body)
    parsed.params = sum(1 for t in tokens if t.kind == "param")
    nested_verb = any(t.kind == "ident" and _word(t) in KINDS for t in _inside_parens(tokens))
    if nested_verb and not any("subquery" in note for note in parsed.notes):
        parsed.notes.append("subquery in a predicate, not descended")
    return parsed


def _inside_parens(tokens: list[Token]) -> list[Token]:
    """The tokens that sit inside at least one pair of parentheses."""
    out, depth = [], 0
    for tok in tokens:
        depth += _depth_change(tok)
        if depth > 0:
            out.append(tok)
    return out


def _alias_map(refs: list[tuple[str, str | None]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for table, alias in refs:
        if alias:
            out[alias.lower()] = table
        out[table.rsplit(".", 1)[-1].lower()] = table
    return out


def _finish_tables(parsed: Parsed, refs: list[tuple[str, str | None]]) -> list[str]:
    tables = []
    for table, _alias in refs:
        if table == "<subquery>":
            parsed.notes.append("subquery in FROM, not descended")
            continue
        if table not in tables:
            tables.append(table)
    parsed.tables = tables
    if len(tables) > 1:
        parsed.notes.append("multi-table statement: unqualified columns are not attributed")
    return tables


def _parse_select(parsed: Parsed, body: list[Token]) -> None:
    depth, from_at = 0, None
    for i, tok in enumerate(body):
        depth += _depth_change(tok)
        if depth == 0 and tok.kind == "ident" and _word(tok) in ("from", "into"):
            from_at = i
            if _word(tok) == "into":
                parsed.notes.append("SELECT INTO creates a table: write target unknown to this stage")
            break
    if from_at is None:
        parsed.notes.append("no FROM clause: tables unknown")
        parsed.columns = _select_columns(body, {}, [], parsed.notes)
        return
    select_list = body[:from_at]
    refs, _end = _table_list(body[from_at + 1:])
    tables = _finish_tables(parsed, refs)
    columns = _select_columns(select_list, _alias_map(refs), tables, parsed.notes)
    columns += _predicate_columns(body, _alias_map(refs), tables)
    parsed.columns = columns


def _predicate_columns(tokens: list[Token], aliases: dict[str, str],
                       tables: list[str]) -> list[Column]:
    """Columns named in a WHERE/ON predicate at the statement's own depth.

    Only the statement's own level is read: descending into a subquery would
    attribute the inner query's columns to the outer table list, which is exactly
    the kind of quiet wrong answer this stage must not produce.
    """
    out: list[Column] = []
    depth = 0
    seen_clause = False
    i, n = 0, len(tokens)
    while i < n:
        tok = tokens[i]
        if depth == 0 and tok.kind == "ident" and _word(tok) in ("where", "on"):
            seen_clause = True
            i += 1
            continue
        if depth == 0 and tok.kind == "ident" and _word(tok) in (
                "group", "order", "having", "union", "select"):
            seen_clause = False
        if seen_clause and depth == 0 and tok.kind == "ident":
            word = _word(tok)
            if word not in FROM_END and word not in ("and", "or", "not", "is", "null", "in",
                                                     "like", "between", "exists", "true", "false"):
                if (i + 2 < n and tokens[i + 1].text == "." and tokens[i + 2].kind == "ident"):
                    table = _attribute(tok.bare, tokens[i + 2].bare, aliases, tables, qualified=True)
                    out.append(Column(table, tokens[i + 2].bare))
                    i += 3
                    continue
                if not (i + 1 < n and tokens[i + 1].text == "("):
                    out.append(Column(_attribute(tok.bare, tok.bare, aliases, tables), tok.bare))
        depth += _depth_change(tok)
        i += 1
    return out


def _select_columns(tokens: list[Token], aliases: dict[str, str], tables: list[str],
                    notes: list[str]) -> list[Column]:
    out: list[Column] = []
    # SELECT [DISTINCT|ALL|TOP n] ...
    while tokens and tokens[0].kind == "ident" and _word(tokens[0]) in ("distinct", "all", "top"):
        if _word(tokens[0]) == "top":
            tokens = tokens[2:] if len(tokens) > 1 and tokens[1].kind == "number" else tokens[1:]
        else:
            tokens = tokens[1:]
    for item in _split_top(tokens):
        # drop a trailing "AS alias" or a bare alias
        if len(item) >= 3 and item[-2].kind == "ident" and _word(item[-2]) == "as":
            item = item[:-2]
        elif len(item) >= 2 and item[-1].kind == "ident" and item[-2].kind not in ("punct", "op"):
            item = item[:-1]
        column = _qualified(item, aliases, tables)
        if column.name:
            out.append(column)
        elif item:
            # COUNT(*), ISNULL(a,0), a + b: named things inside an expression are
            # not the column the select list produces, so the list item is
            # counted as an expression and its text is not attributed.
            notes.append("expression in select list")
    return out


def _parse_insert(parsed: Parsed, body: list[Token]) -> None:
    if body and body[0].kind == "ident" and _word(body[0]) == "into":
        body = body[1:]
    # INSERT INTO t (a, b): the '(' right after the table opens the COLUMN list.
    # Handing it to the table reader would count it as a subquery and lose the
    # table entirely (measured while writing these tests).
    stop = next((i for i, t in enumerate(body) if t.kind == "punct" and t.text == "("), len(body))
    refs, _consumed = _table_list(body[:stop])
    tables = _finish_tables(parsed, refs)
    rest = body[stop:]
    columns: list[Column] = []
    # VALUES (…) is the value list; only a '(' that is NOT preceded by VALUES
    # names columns.
    column_list = bool(rest and rest[0].kind == "punct" and rest[0].text == "("
                       and not (stop > 0 and _word(body[stop - 1]) == "values"))
    if column_list:
        depth, end = 1, 1
        while end < len(rest) and depth:
            depth += _depth_change(rest[end])
            end += 1
        for item in _split_top(rest[1:end - 1]):
            names = [t for t in item if t.kind == "ident"]
            if len(names) == 1 and len(item) == 1:
                columns.append(Column(tables[0] if len(tables) == 1 else None, names[0].bare))
            else:
                parsed.notes.append("insert column list holds an expression")
    else:
        parsed.notes.append("insert without a column list: the stored columns are unknown")
    parsed.columns = columns


def _parse_update(parsed: Parsed, body: list[Token]) -> None:
    refs, consumed = _table_list(body)
    tables = _finish_tables(parsed, refs)
    rest = body[consumed:]
    if not rest or rest[0].kind != "ident" or _word(rest[0]) != "set":
        parsed.notes.append("update without a SET clause")
        return
    depth, end = 0, len(rest)
    for i, tok in enumerate(rest[1:], 1):
        depth += _depth_change(tok)
        if depth == 0 and tok.kind == "ident" and _word(tok) in ("where", "from"):
            end = i
            break
    columns: list[Column] = []
    aliases = _alias_map(refs)
    for item in _split_top(rest[1:end]):
        if len(item) >= 3 and item[1].kind == "op" and item[1].text == "=":
            target = item[0]
            if target.kind == "ident":
                table = _attribute(target.bare, target.bare, aliases, tables)
                columns.append(Column(table, target.bare))
            else:
                parsed.notes.append("set target is not a plain column")
    parsed.columns = columns + _predicate_columns(rest[end:], aliases, tables)


def _parse_delete(parsed: Parsed, body: list[Token]) -> None:
    if body and body[0].kind == "ident" and _word(body[0]) == "from":
        body = body[1:]
    refs, _consumed = _table_list(body)
    tables = _finish_tables(parsed, refs)
    parsed.columns = _predicate_columns(body, _alias_map(refs), tables)


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
@dataclass
class Statement:
    va: str
    object_name: str
    status: str
    sha: str
    parsed: Parsed | None = None
    reason: str = ""

    @property
    def closed(self) -> bool:
        return self.status == "CLOSED"


@dataclass
class Report:
    statements: int = 0
    closed: int = 0
    parsed: int = 0
    unparsed: list[Statement] = field(default_factory=list)
    open: list[Statement] = field(default_factory=list)
    tables: dict[str, dict] = field(default_factory=dict)
    crud: dict[tuple[str, str], dict] = field(default_factory=dict)
    disagree: list[tuple[str, str]] = field(default_factory=list)
    conflicts: list[tuple[str, str]] = field(default_factory=list)

    def invariants(self) -> list[str]:
        """Self-checks printed with the report: a wrong total must be visible."""
        out = []
        total = self.parsed + len(self.unparsed) + len(self.open)
        if total != self.statements:
            out.append(f"MISMATCH: parsed {self.parsed} + unparsed {len(self.unparsed)} + "
                       f"open {len(self.open)} = {total}, statements in {self.statements}")
        return out

    def counts(self) -> dict:
        return {
            "statements": self.statements,
            "closed": self.closed,
            "parsed": self.parsed,
            "unparsed": len(self.unparsed),
            "open": len(self.open),
        }


def _iter_sql(records: list[dict]):
    for record in records:
        va = record.get("va") or ""
        obj = record.get("object_name") or ""
        for row in record.get("sql") or []:
            if not isinstance(row, dict):
                continue
            text = row.get("text")
            if not isinstance(text, str):
                continue
            yield va, obj, row, text


def build(records: list[dict]) -> Report:
    """The model, from dossier records already in memory."""
    report = Report()
    for va, obj, row, text in _iter_sql(records):
        report.statements += 1
        stmt = Statement(va=va, object_name=obj, status=str(row.get("status") or ""),
                         sha=hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:SHA_CHARS])
        if not row.get("closed"):
            report.open.append(stmt)
            continue
        report.closed += 1
        try:
            stmt.parsed = parse(text)
        except SQLSyntax as exc:
            stmt.reason = str(exc)
            report.unparsed.append(stmt)
            continue
        report.parsed += 1
        _record(report, stmt, row)
    _order(report)
    return report


def _record(report: Report, stmt: Statement, row: dict) -> None:
    parsed = stmt.parsed
    assert parsed is not None
    letters = KINDS.get(parsed.kind)
    hint_names = [t for t in (row.get("tables") or []) if isinstance(t, str)]
    if hint_names and {t.lower() for t in hint_names} != {t.lower() for t in parsed.tables}:
        report.disagree.append(
            (stmt.sha, f"sqlstitch hints {sorted(hint_names)} vs tokenizer {sorted(parsed.tables)}"))

    for table in parsed.tables:
        info = report.tables.setdefault(table, {"columns": set(), "readers": set(), "writers": set()})
        if letters == "R":
            info["readers"].add(stmt.object_name)
        elif letters:
            info["writers"].add(stmt.object_name)
        for column in parsed.columns:
            if column.table == table and column.name:
                info["columns"].add(column.name)
    for column in parsed.columns:
        if column.table is None and column.name:
            report.tables.setdefault("(unattributed)", {"columns": set(), "readers": set(),
                                                        "writers": set()})["columns"].add(column.name)
    if letters:
        for table in parsed.tables:
            cell = report.crud.setdefault((stmt.object_name, table),
                                          {"C": 0, "R": 0, "U": 0, "D": 0})
            cell[letters] += 1


def _order(report: Report) -> None:
    """Deterministic order everywhere: two runs must produce the same bytes."""
    report.unparsed.sort(key=lambda s: (s.va, s.sha))
    report.open.sort(key=lambda s: (s.va, s.sha))
    report.disagree.sort()
    for info in report.tables.values():
        for key in ("columns", "readers", "writers"):
            info[key] = sorted(info[key], key=str.lower)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def as_json(report: Report) -> str:
    return json.dumps({
        "counts": report.counts(),
        "invariants": report.invariants(),
        "tables": {name: {"columns": info["columns"],
                          "readers": info["readers"],
                          "writers": info["writers"]}
                   for name, info in sorted(report.tables.items())},
        "crud": [{"object": obj, "table": table, **counts}
                 for (obj, table), counts in sorted(report.crud.items())],
        "unparsed": [{"va": s.va, "object": s.object_name, "sha256": s.sha, "reason": s.reason}
                     for s in report.unparsed],
        "open": [{"va": s.va, "object": s.object_name, "status": s.status, "sha256": s.sha}
                 for s in report.open],
        "disagreements": [{"sha256": sha, "detail": detail} for sha, detail in report.disagree],
    }, indent=2, ensure_ascii=False)


def as_markdown(report: Report) -> str:
    counts = report.counts()
    out = ["# Data model", "",
           (f"{counts['closed']} closed of {counts['statements']} statements, "
            f"{counts['parsed']} parsed, {counts['unparsed']} unparsed, "
            f"{counts['open']} open (built at run time, listed as gaps, never parsed)."), ""]
    for line in report.invariants():
        out.append(f"**{line}**")
    out.append("")
    out.append("## Tables")
    out.append("")
    out.append("| Table | Columns seen | Read by | Written by |")
    out.append("|---|---|---|---|")
    for name, info in sorted(report.tables.items()):
        columns = ", ".join(f"`{c}`" for c in info["columns"]) or "-"
        out.append(f"| `{name}` | {columns} | {len(info['readers'])} | {len(info['writers'])} |")
    out.append("")
    out.append("## CRUD by object")
    out.append("")
    out.append("| Object | Table | C | R | U | D |")
    out.append("|---|---|---|---|---|---|")
    for (obj, table), cell in sorted(report.crud.items()):
        out.append(f"| {obj or '-'} | `{table}` | {cell['C']} | {cell['R']} | {cell['U']} | {cell['D']} |")
    out.append("")
    out.append(f"## Unparsed ({len(report.unparsed)} of {counts['closed']} closed)")
    out.append("")
    if not report.unparsed:
        out.append("None: every closed statement fell inside the handled dialect.")
    for stmt in report.unparsed:
        out.append(f"- `{stmt.va}` {stmt.object_name or '-'} — {stmt.reason} (sha256:{stmt.sha})")
    out.append("")
    out.append(f"## Open statements ({len(report.open)} of {counts['statements']})")
    out.append("")
    if not report.open:
        out.append("None.")
    for stmt in report.open:
        out.append(f"- `{stmt.va}` {stmt.object_name or '-'} {stmt.status} (sha256:{stmt.sha})")
    if report.disagree:
        out.append("")
        out.append(f"## Table hints that disagree ({len(report.disagree)})")
        out.append("")
        out.append("`sqlstitch` already names tables from the text; the tokenizer re-derives them. "
                   "A disagreement is evidence about one of the two, not something to average.")
        for sha, detail in report.disagree:
            out.append(f"- sha256:{sha} — {detail}")
    return "\n".join(out) + "\n"
