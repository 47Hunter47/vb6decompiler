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
#: Words that can never name a table. One list, so a keyword in a table position is
#: refused by name instead of becoming a table called ``FROM`` (measured).
RESERVED = frozenset({
    "add", "all", "alter", "and", "any", "as", "asc", "begin", "between", "by",
    "case", "check", "column", "commit", "constraint", "create", "cross", "default",
    "delete", "desc", "distinct", "drop", "else", "end", "except", "exec", "execute",
    "exists", "false", "foreign", "from", "full", "group", "having", "if", "in",
    "index", "inner", "insert", "intersect", "into", "is", "join", "key", "left",
    "like", "not", "null", "on", "or", "order", "outer", "primary", "references",
    "right", "rollback", "select", "set", "some", "table", "then", "top", "true",
    "union", "unique", "update", "using", "values", "view", "when", "where", "with",
})
#: Words that end a table list at the statement's own depth.
TABLE_END = frozenset({"where", "group", "order", "having", "union", "intersect",
                       "except", "using", "into", "values", "set", "select", "on"})
#: Join noise that carries no table name of its own.
JOIN_NOISE = frozenset({"inner", "left", "right", "full", "cross", "outer", "join"})
#: Nesting past this is reported as partial instead of recursing without a bound.
MAX_DEPTH = 32
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
#: A Jet date literal -- the only thing ``#...#`` means outside a table position.
_DATE_LITERAL = re.compile(
    r"#\s*[0-9]{1,4}[/-][0-9]{1,2}[/-][0-9]{1,4}"
    r"(?:[ T][0-9]{1,2}:[0-9]{2}(?::[0-9]{2})?(?:\s*[AP]M)?)?\s*#", re.IGNORECASE)
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
        # Comments carry no tokens. Inside a quoted string or identifier they are
        # text, which is why this check sits after the quote readers below never
        # see them -- see the string/identifier branches for that.
        if text.startswith("--", i):
            j = text.find("\n", i)
            i = n if j < 0 else j + 1
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                raise SQLSyntax("unterminated block comment")
            i = j + 2
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
        if ch == "#":                                    # Jet date literal, or a temp table
            m = _DATE_LITERAL.match(text, i)
            if m is not None:
                out.append(Token("string", m.group(0), m.group(0)[1:-1]))
                i = m.end()
                continue
            # No date pair: ``#tmp`` after INTO/FROM/JOIN/UPDATE is a temp table name.
            # A leading digit is a date literal that lost its '#', not a table.
            if i + 1 < n and text[i + 1].isdigit():
                raise SQLSyntax("unterminated date literal")
            m = _IDENT_BODY.match(text, i + 1)
            assert m is not None
            name = text[i:m.end()]
            out.append(Token("ident", name, name))
            i = m.end()
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
    #: Every base table named, reads first: the list columns are attributed against.
    tables: list[str] = field(default_factory=list)
    columns: list[Column] = field(default_factory=list)
    params: int = 0
    #: Everything the parser had to leave unresolved, in the statement's own terms.
    notes: list[str] = field(default_factory=list)
    #: Tables this statement reads, and ``(table, letter)`` writes it performs.
    reads: list[str] = field(default_factory=list)
    writes: list[tuple[str, str]] = field(default_factory=list)
    #: Non-empty when only part of the statement was understood: the reason, kept
    #: with the tables that were found instead of dropping the statement.
    partial: str = ""


def _word(tok: Token) -> str:
    return (tok.bare or tok.text).lower()


def _kw(tok: Token) -> str:
    """The lowercase word of an unquoted identifier, or ``''`` for anything else.

    A quoted name is never a keyword: ``[Order]`` is a table even though ``order``
    is one, which is why every keyword test here reads through this function.
    """
    return _word(tok) if tok.kind == "ident" and not tok.quoted else ""


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


def _group_end(tokens: list[Token], start: int) -> int:
    """Index one past the ``)`` that closes ``tokens[start] == '('``."""
    depth, j = 1, start + 1
    while j < len(tokens) and depth:
        depth += _depth_change(tokens[j])
        j += 1
    if depth:
        raise SQLSyntax("unbalanced parentheses")
    return j


def _top_at(tokens: list[Token], word: str) -> int | None:
    """Index of the first top-level ``word``, or ``None``."""
    depth = 0
    for i, tok in enumerate(tokens):
        if depth == 0 and _kw(tok) == word:
            return i
        depth += _depth_change(tok)
    return None


def _table_list(tokens: list[Token], *, cte: frozenset[str] = frozenset()
                ) -> tuple[list[tuple[str, str | None]], int]:
    """``(table, alias)`` pairs from the tokens after FROM/UPDATE/INTO/DELETE.

    Stops at the first clause keyword. A parenthesised item is a derived table: it
    is recorded as ``<derived>`` and its own statement is read by :func:`_descend`,
    never by inventing a table name for it. A keyword where a name belongs is a
    named error, not a table called ``FROM`` (that was a measured wrong answer).
    """
    out: list[tuple[str, str | None]] = []
    i, n = 0, len(tokens)
    expect_name = True
    while i < n:
        tok = tokens[i]
        word = _kw(tok)
        if tok.kind == "punct" and tok.text == "(":
            i = _group_end(tokens, i)
            k = i
            if k < n and _kw(tokens[k]) == "as":
                k += 1
            alias = None
            if k < n and tokens[k].kind == "ident" and _kw(tokens[k]) not in RESERVED:
                alias = tokens[k].bare or tokens[k].text
                k += 1
            out.append(("<derived>", alias))
            i, expect_name = k, False
            continue
        if tok.kind == "punct" and tok.text == ",":
            i, expect_name = i + 1, True
            continue
        if word in JOIN_NOISE:
            i, expect_name = i + 1, True
            continue
        if word == "on":
            # skip the ON predicate up to the next join, clause or comma
            depth, j = 0, i + 1
            while j < n:
                depth += _depth_change(tokens[j])
                if depth == 0 and tokens[j].kind == "ident" and (
                        _kw(tokens[j]) in TABLE_END or _kw(tokens[j]) in JOIN_NOISE):
                    break
                if depth == 0 and tokens[j].kind == "punct" and tokens[j].text == ",":
                    break
                j += 1
            i, expect_name = j, False
            continue
        if word in TABLE_END:
            if expect_name:
                raise SQLSyntax("expected a table name, found a keyword")
            break
        if tok.kind != "ident":
            raise SQLSyntax("expected a table name, found a non-name token")
        if word in RESERVED:
            raise SQLSyntax("expected a table name, found a keyword")
        name = tok.bare or tok.text
        step = 1
        if (i + 2 < n and tokens[i + 1].text == "." and tokens[i + 2].kind == "ident"
                and not tokens[i + 2].quoted):
            name = f"{name}.{tokens[i + 2].bare}"
            step = 3
        k = i + step
        if k < n and _kw(tokens[k]) == "as":
            k += 1
        alias = None
        if k < n and tokens[k].kind == "ident" and _kw(tokens[k]) not in RESERVED:
            alias = tokens[k].bare or tokens[k].text
            k += 1
        # A CTE name is a query, not a base table: the body's tables are the reads.
        if name.rsplit(".", 1)[-1].lower() not in cte:
            out.append((name, alias))
        i, expect_name = k, False
    if expect_name and out:
        # a dangling JOIN/comma is an incomplete statement, not a table called nothing
        raise SQLSyntax("expected a table name, found the end of the statement")
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


def _add_read(parsed: Parsed, name: str) -> None:
    if name and name != "<derived>" and name not in parsed.reads:
        parsed.reads.append(name)


def _add_write(parsed: Parsed, name: str, letter: str) -> None:
    if name and name != "<derived>" and all(t != name for t, _letter in parsed.writes):
        parsed.writes.append((name, letter))


def _names(parsed: Parsed) -> list[str]:
    out = list(parsed.reads)
    for name, _letter in parsed.writes:
        if name not in out:
            out.append(name)
    return out


def _seal(parsed: Parsed) -> None:
    """Finish a statement's own tables and the note a multi-table statement needs."""
    parsed.tables = _names(parsed)
    if len(parsed.tables) > 1 and not any("not attributed" in note for note in parsed.notes):
        parsed.notes.append("multi-table statement: unqualified columns are not attributed")


def _alias_map(refs: list[tuple[str, str | None]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for table, alias in refs:
        if table == "<derived>":
            continue
        if alias:
            out[alias.lower()] = table
        out[table.rsplit(".", 1)[-1].lower()] = table
    return out


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
    parsed = _statement(tokens)
    parsed.params = sum(1 for t in tokens if t.kind == "param")
    return parsed


def _statement(tokens: list[Token], depth: int = 0,
               *, cte: frozenset[str] = frozenset()) -> Parsed:
    """One statement (or one nested statement) into its model."""
    while tokens and tokens[0].kind == "punct" and tokens[0].text == "(":
        tokens = tokens[1:]
    if not tokens or tokens[0].kind != "ident":
        raise SQLSyntax("statement does not begin with a verb")
    verb = _kw(tokens[0]) or _word(tokens[0])
    if verb == "with":
        parsed = _parse_with(tokens[1:], depth)
        _seal(parsed)
        return parsed
    if verb not in KINDS:
        # Understood statements are modelled; anything else is kept as partial with
        # its reason rather than counted as parsed (EXEC, DDL, ...).
        parsed = Parsed(kind="other", partial=f"verb not modelled: {tokens[0].bare}")
        _seal(parsed)
        return parsed
    parsed = Parsed(kind=verb)
    body = tokens[1:]
    if verb == "select":
        _parse_select(parsed, body, depth, cte)
    elif verb == "insert":
        _parse_insert(parsed, body, depth, cte)
    elif verb == "update":
        _parse_update(parsed, body, depth, cte)
    else:
        _parse_delete(parsed, body, depth, cte)
    _descend(parsed, tokens, depth)
    _seal(parsed)
    return parsed


def _merge(dst: Parsed, src: Parsed) -> None:
    """Fold a nested statement's tables and columns into the statement that holds it."""
    for name in src.reads:
        _add_read(dst, name)
    for name, letter in src.writes:
        _add_write(dst, name, letter)
    dst.columns.extend(src.columns)
    if src.partial and not dst.partial:
        dst.partial = src.partial


def _descend(parsed: Parsed, tokens: list[Token], depth: int) -> None:
    """Read every nested statement inside parentheses, recursively.

    Subselects after IN/EXISTS/ANY/ALL, scalar subselects and derived tables are
    read tables of the same statement; the outer statement keeps its own tables.
    """
    if depth >= MAX_DEPTH:
        parsed.partial = parsed.partial or "nesting too deep"
        return
    i, n = 0, len(tokens)
    while i < n:
        tok = tokens[i]
        if tok.kind == "punct" and tok.text == "(":
            end = _group_end(tokens, i)
            inner = tokens[i + 1:end - 1]
            first = _kw(inner[0]) if inner else ""
            if first in ("select", "with"):
                try:
                    sub = _statement(inner, depth + 1)
                except SQLSyntax as exc:
                    parsed.partial = parsed.partial or f"nested statement not parsed: {exc}"
                else:
                    _merge(parsed, sub)
            elif inner:
                _descend(parsed, inner, depth + 1)
            i = end
            continue
        i += 1


def _split_compounds(body: list[Token]) -> list[list[Token]]:
    """The branches of a UNION/INTERSECT/EXCEPT at the statement's own depth."""
    parts: list[list[Token]] = []
    current: list[Token] = []
    depth, i, n = 0, 0, len(body)
    while i < n:
        tok = body[i]
        depth += _depth_change(tok)
        if depth == 0 and _kw(tok) in ("union", "intersect", "except"):
            parts.append(current)
            current = []
            i += 1
            while i < n and _kw(body[i]) in ("all", "distinct"):
                i += 1
            if i < n and _kw(body[i]) == "select":
                i += 1
            continue
        current.append(tok)
        i += 1
    parts.append(current)
    return parts


def _parse_select(parsed: Parsed, body: list[Token], depth: int,
                  cte: frozenset[str]) -> None:
    if depth >= MAX_DEPTH:
        parsed.partial = parsed.partial or "nesting too deep"
        return
    for branch in _split_compounds(body):
        _select_branch(parsed, branch, cte)


def _select_branch(parsed: Parsed, tokens: list[Token], cte: frozenset[str]) -> None:
    into_at = _top_at(tokens, "into")
    from_at = _top_at(tokens, "from")
    starts = [at for at in (into_at, from_at) if at is not None]
    head = min(starts) if starts else len(tokens)
    select_list = tokens[:head]
    if into_at is not None and (from_at is None or into_at < from_at):
        target = tokens[into_at + 1] if into_at + 1 < len(tokens) else None
        if target is not None and target.kind == "ident" and _kw(target) not in RESERVED:
            _add_write(parsed, target.bare or target.text, "C")
        else:
            parsed.partial = parsed.partial or "SELECT INTO target is not a plain name"
    if from_at is None:
        parsed.notes.append("no FROM clause: tables unknown")
        parsed.columns += _select_columns(select_list, {}, _names(parsed), parsed.notes)
        return
    refs, _consumed = _table_list(tokens[from_at + 1:], cte=cte)
    for name, _alias in refs:
        _add_read(parsed, name)
    # A derived table's own columns belong to the subquery, not to this level: with
    # one in the FROM list no unqualified column can be attributed here.
    derived = any(name == "<derived>" for name, _alias in refs)
    tables = [] if derived else list(parsed.reads)
    aliases = _alias_map(refs)
    parsed.columns += _select_columns(select_list, aliases, tables, parsed.notes)
    parsed.columns += _predicate_columns(tokens[from_at + 1:], aliases, tables)


def _predicate_columns(tokens: list[Token], aliases: dict[str, str],
                       tables: list[str]) -> list[Column]:
    """Columns named in a WHERE/ON predicate at the statement's own depth.

    Only the statement's own level is read: a subquery's columns belong to its own
    statement, which :func:`_descend` reads separately, so attributing them to the
    outer table list is exactly the quiet wrong answer this stage must not produce.
    """
    out: list[Column] = []
    depth = 0
    seen_clause = False
    i, n = 0, len(tokens)
    while i < n:
        tok = tokens[i]
        word = _kw(tok)
        if depth == 0 and word in ("where", "on"):
            seen_clause = True
            i += 1
            continue
        if depth == 0 and word in ("group", "order", "having", "union", "select"):
            seen_clause = False
        if seen_clause and depth == 0 and tok.kind == "ident":
            name = _word(tok)
            if name not in RESERVED and name not in (
                    "and", "or", "not", "is", "null", "in", "like", "between", "exists",
                    "true", "false", "any", "some", "all"):
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


def _parse_insert(parsed: Parsed, body: list[Token], depth: int,
                  cte: frozenset[str]) -> None:
    if body and _kw(body[0]) == "into":
        body = body[1:]
    # INSERT INTO t (a, b): the '(' right after the table opens the COLUMN list.
    # Handing it to the table reader would count it as a subquery and lose the
    # table entirely (measured while writing these tests).
    stop = next((i for i, t in enumerate(body) if t.kind == "punct" and t.text == "("), len(body))
    refs, consumed = _table_list(body[:stop], cte=cte)
    if not refs:
        raise SQLSyntax("INSERT without a table name")
    target = refs[0][0]
    _add_write(parsed, target, "C")
    for name, _alias in refs[1:]:
        _add_read(parsed, name)
    rest = body[consumed:]
    if rest and _kw(rest[0]) == "select":
        # INSERT INTO t SELECT ... : t is the write, the SELECT's tables are reads.
        _parse_select(parsed, rest[1:], depth + 1, cte)
        return
    tables = _names(parsed)
    # VALUES (…) is the value list; only a '(' that is NOT preceded by VALUES
    # names columns.
    column_list = bool(rest and rest[0].kind == "punct" and rest[0].text == "("
                       and not (stop > 0 and _kw(body[stop - 1]) == "values"))
    if column_list:
        end = _group_end(rest, 0)
        for item in _split_top(rest[1:end - 1]):
            names = [t for t in item if t.kind == "ident"]
            if len(names) == 1 and len(item) == 1:
                parsed.columns.append(Column(target if len(tables) == 1 else None,
                                             names[0].bare))
            else:
                parsed.notes.append("insert column list holds an expression")
        rest = rest[end:]
    else:
        parsed.notes.append("insert without a column list: the stored columns are unknown")
    select_at = next((j for j, t in enumerate(rest) if _kw(t) == "select"), None)
    if select_at is not None:
        _parse_select(parsed, rest[select_at + 1:], depth + 1, cte)


def _parse_update(parsed: Parsed, body: list[Token], depth: int,
                  cte: frozenset[str]) -> None:
    refs, consumed = _table_list(body, cte=cte)
    if not refs:
        raise SQLSyntax("UPDATE without a table name")
    target = refs[0][0]
    rest = body[consumed:]
    if not rest or _kw(rest[0]) != "set":
        parsed.partial = parsed.partial or "update without a SET clause"
        _add_write(parsed, target, "U")
        return
    # the SET list ends at a top-level WHERE or FROM
    depth_, end, term = 0, len(rest), ""
    for i, tok in enumerate(rest[1:], 1):
        depth_ += _depth_change(tok)
        if depth_ == 0 and _kw(tok) in ("where", "from"):
            end, term = i, _kw(tok)
            break
    after = rest[end:]
    extra: list[tuple[str, str | None]] = []
    if term == "from":
        # UPDATE t SET ... FROM t JOIN u ...: the FROM list is what the target is
        # matched through, and naming an alias there is how the target is written.
        extra, used = _table_list(after[1:], cte=cte)
        after = after[1 + used:]
    aliases = _alias_map(extra)
    resolved = aliases.get(target.rsplit(".", 1)[-1].lower(), target)
    _add_write(parsed, resolved, "U")
    for name, _alias in extra:
        if name != "<derived>" and name.lower() != resolved.lower():
            _add_read(parsed, name)
    tables = _names(parsed)
    for item in _split_top(rest[1:end]):
        if len(item) >= 3 and item[1].kind == "op" and item[1].text == "=":
            head = item[0]
            if head.kind == "ident":
                table = _attribute(head.bare, head.bare, aliases, tables)
                parsed.columns.append(Column(table, head.bare))
            else:
                parsed.notes.append("set target is not a plain column")
    parsed.columns += _predicate_columns(after, aliases, tables)


def _parse_delete(parsed: Parsed, body: list[Token], depth: int,
                  cte: frozenset[str]) -> None:
    if body and _kw(body[0]) in ("from", "into"):
        body = body[1:]
    refs, _consumed = _table_list(body, cte=cte)
    if not refs:
        raise SQLSyntax("DELETE without a table name")
    target = refs[0][0]
    _add_write(parsed, target, "D")
    for name, _alias in refs[1:]:
        _add_read(parsed, name)
    tables = _names(parsed)
    parsed.columns += _predicate_columns(body, _alias_map(refs), tables)


def _parse_with(tokens: list[Token], depth: int) -> Parsed:
    """``WITH name AS (SELECT ...) [, ...] <statement>``.

    The CTE name is a query, never a base table: only the tables inside the body
    become reads of the main statement.
    """
    names: list[str] = []
    bodies: list[list[Token]] = []
    i, n = 0, len(tokens)
    while i < n:
        tok = tokens[i]
        if tok.kind != "ident":
            raise SQLSyntax("WITH without a CTE name")
        names.append((tok.bare or tok.text).lower())
        i += 1
        if i < n and tokens[i].kind == "punct" and tokens[i].text == "(":
            i = _group_end(tokens, i)                 # the CTE's column list
        if i >= n or _kw(tokens[i]) != "as":
            raise SQLSyntax("WITH: expected AS after the CTE name")
        i += 1
        if i >= n or tokens[i].kind != "punct" or tokens[i].text != "(":
            raise SQLSyntax("WITH: expected a parenthesised CTE body")
        end = _group_end(tokens, i)
        bodies.append(tokens[i + 1:end - 1])
        i = end
        if i < n and tokens[i].kind == "punct" and tokens[i].text == ",":
            i += 1
            continue
        break
    if i >= n:
        raise SQLSyntax("WITH without a statement")
    if depth >= MAX_DEPTH:
        return Parsed(kind="other", partial="nesting too deep")
    parsed = _statement(tokens[i:], depth + 1, cte=frozenset(names))
    for body in bodies:
        try:
            sub = _statement(body, depth + 1, cte=frozenset(names))
        except SQLSyntax as exc:
            parsed.partial = parsed.partial or f"CTE body not parsed: {exc}"
            continue
        _merge(parsed, sub)
    return parsed
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
    partial: list[Statement] = field(default_factory=list)
    unparsed: list[Statement] = field(default_factory=list)
    open: list[Statement] = field(default_factory=list)
    tables: dict[str, dict] = field(default_factory=dict)
    crud: dict[tuple[str, str], dict] = field(default_factory=dict)
    disagree: list[tuple[str, str]] = field(default_factory=list)
    conflicts: list[tuple[str, str]] = field(default_factory=list)

    @property
    def partial_objects(self) -> set[str]:
        """Objects that own a partially read statement: their lists are lower bounds."""
        return {s.object_name for s in self.partial}

    def invariants(self) -> list[str]:
        """Self-checks printed with the report: a wrong total must be visible."""
        out = []
        total = self.parsed + len(self.partial) + len(self.unparsed) + len(self.open)
        if total != self.statements:
            out.append(f"MISMATCH: parsed {self.parsed} + partial {len(self.partial)} + "
                       f"unparsed {len(self.unparsed)} + open {len(self.open)} = {total}, "
                       f"statements in {self.statements}")
        return out

    def counts(self) -> dict:
        return {
            "statements": self.statements,
            "closed": self.closed,
            "parsed": self.parsed,
            "partial": len(self.partial),
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
        # A statement only part of which was understood is not a parsed statement:
        # it keeps the tables that were found and its reason, in its own bucket.
        if stmt.parsed.partial:
            stmt.reason = stmt.parsed.partial
            report.partial.append(stmt)
        else:
            report.parsed += 1
        _record(report, stmt, row)
    _order(report)
    return report


def _record(report: Report, stmt: Statement, row: dict) -> None:
    parsed = stmt.parsed
    assert parsed is not None
    hint_names = [t for t in (row.get("tables") or []) if isinstance(t, str)]
    if hint_names and {t.lower() for t in hint_names} != {t.lower() for t in parsed.tables}:
        report.disagree.append(
            (stmt.sha, f"sqlstitch hints {sorted(hint_names)} vs tokenizer {sorted(parsed.tables)}"))

    def info_for(table: str) -> dict:
        return report.tables.setdefault(table, {"columns": set(), "readers": set(),
                                                "writers": set()})

    for table in parsed.reads:
        info_for(table)["readers"].add(stmt.object_name)
    for table, _letter in parsed.writes:
        info_for(table)["writers"].add(stmt.object_name)
    for table in parsed.tables:
        if table.startswith("#"):        # a temp table, named by the tokenizer
            info_for(table)["temp"] = True
    for column in parsed.columns:
        if column.table and column.name:
            info_for(column.table)["columns"].add(column.name)
        elif column.name:
            info_for("(unattributed)")["columns"].add(column.name)
    for table in parsed.reads:
        cell = report.crud.setdefault((stmt.object_name, table),
                                      {"C": 0, "R": 0, "U": 0, "D": 0})
        cell["R"] += 1
    for table, letter in parsed.writes:
        cell = report.crud.setdefault((stmt.object_name, table),
                                      {"C": 0, "R": 0, "U": 0, "D": 0})
        cell[letter] += 1


def _order(report: Report) -> None:
    """Deterministic order everywhere: two runs must produce the same bytes."""
    report.partial.sort(key=lambda s: (s.va, s.sha))
    report.unparsed.sort(key=lambda s: (s.va, s.sha))
    report.open.sort(key=lambda s: (s.va, s.sha))
    report.disagree.sort()
    for info in report.tables.values():
        for key in ("columns", "readers", "writers"):
            info[key] = sorted(info[key], key=str.lower)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def _lower_bound(report: Report, objects) -> bool:
    return any(obj in report.partial_objects for obj in objects)


def as_json(report: Report) -> str:
    tables = {}
    for name, info in sorted(report.tables.items()):
        entry = {"columns": info["columns"], "readers": info["readers"],
                 "writers": info["writers"]}
        if info.get("temp"):
            entry["temp"] = True
        if _lower_bound(report, list(info["readers"]) + list(info["writers"])):
            entry["lower_bound"] = True
        tables[name] = entry
    crud = []
    for (obj, table), counts in sorted(report.crud.items()):
        row = {"object": obj, "table": table, **counts}
        if obj in report.partial_objects:
            row["lower_bound"] = True
        crud.append(row)
    return json.dumps({
        "counts": report.counts(),
        "invariants": report.invariants(),
        "tables": tables,
        "crud": crud,
        "unparsed": [{"va": s.va, "object": s.object_name, "sha256": s.sha, "reason": s.reason}
                     for s in report.unparsed],
        "partial": [{"va": s.va, "object": s.object_name, "sha256": s.sha, "reason": s.reason,
                     "tables": s.parsed.tables if s.parsed else []} for s in report.partial],
        "open": [{"va": s.va, "object": s.object_name, "status": s.status, "sha256": s.sha}
                 for s in report.open],
        "disagreements": [{"sha256": sha, "detail": detail} for sha, detail in report.disagree],
    }, indent=2, ensure_ascii=False)


def as_markdown(report: Report) -> str:
    counts = report.counts()
    out = ["# Data model", "",
           (f"{counts['closed']} closed of {counts['statements']} statements, "
            f"{counts['parsed']} parsed, {counts['partial']} partial, "
            f"{counts['unparsed']} unparsed, "
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
        lower = _lower_bound(report, list(info["readers"]) + list(info["writers"]))
        mark = " (lower bound)" if lower else ""
        temp = " (temp)" if info.get("temp") else ""
        out.append(f"| `{name}`{temp} | {columns} | {len(info['readers'])}{mark} | "
                   f"{len(info['writers'])}{mark} |")
    out.append("")
    out.append("## CRUD by object")
    out.append("")
    out.append("| Object | Table | C | R | U | D |")
    out.append("|---|---|---|---|---|---|")
    for (obj, table), cell in sorted(report.crud.items()):
        mark = " (lower bound)" if obj in report.partial_objects else ""
        out.append(f"| {obj or '-'}{mark} | `{table}` | {cell['C']} | {cell['R']} | "
                   f"{cell['U']} | {cell['D']} |")
    out.append("")
    out.append(f"## Partial ({len(report.partial)} of {counts['closed']} closed)")
    out.append("")
    if not report.partial:
        out.append("None: every closed statement was either parsed or refused.")
    for stmt in report.partial:
        tables = ", ".join(f"`{t}`" for t in (stmt.parsed.tables if stmt.parsed else [])) or "-"
        out.append(f"- `{stmt.va}` {stmt.object_name or '-'} — {stmt.reason}; tables found: "
                   f"{tables} (sha256:{stmt.sha})")
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
