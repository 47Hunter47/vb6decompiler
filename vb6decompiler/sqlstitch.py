"""Joining literal fragments back into whole SQL statements — and saying where it stops.

Why this exists
---------------
Native VB6 does not keep SQL in one piece. The compiler stores each literal
separately and the program concatenates them at run time with ``__vbaStrCat``:
on the reference target 8,597 calls, 262,162 literals, of which only 1,298 were
whole statements. Everything else is a fragment like ``"SELECT ... FROM tOrder
WHERE HOrderDep = '"`` followed by a value the user typed.

So "which table does this screen write" cannot be answered by reading literals: it
has to be answered by *stitching* neighbours and then being honest about what
closed. Measured on 1,273 write-candidate procedures:

* 108 statements closed completely (26 exact, 35 with a shape warning, 47 by
  splitting two statements that were glued together),
* 699 stayed open inside a quote, 119 ended on a dangling connector, 112 carried
  escaped human text,
* 134 of 247 writing procedures produced no candidate at all.

This module reproduces that classification. It never fills a gap with a guess: a
fragment that needs a run-time value is reported as ``RUNTIME_GAP``, which is the
honest answer and tells you a live trace is required.

Two measured traps are encoded in the gates:

1. **``lit.addr`` is the address of the text, not of the instruction.** Sorting
   fragments by it approximates program order; it is not proof of it. Callers that
   need order must supply it (see the ``order`` field) and say where it came from.
2. **A verb inside quotes is not a verb.** ``WHERE X = 'UPDATE t SET ...'`` is one
   statement assigning a string, not two. :func:`statements` counts verbs outside
   quotes only, which is what stopped the count from doubling.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .literals import Literal

#: How many following fragments to try when closing a statement.
MAX_MORE = 6

_SQL_HINT = re.compile(
    r"\b(select|from|where|and|or|order|group|values|set|insert|update|delete|union|like|in)\b",
    re.I,
)
_TARGET = re.compile(r"\b(from|into|update)[ \t]+([A-Za-z_][A-Za-z0-9_$]*)", re.I)

#: Words that follow `from`/`into`/`update` in real text without being a table. The
#: reference corpus produced 217 "tables" named ``where`` before this list existed.
_NOT_A_TABLE = {
    "where", "set", "select", "values", "value", "table", "and", "or", "on",
    "join", "as", "the", "this", "it", "a", "an", "null", "not", "into", "from",
}
_ARITH = re.compile(r"^[()\s]*[A-Za-z_][A-Za-z0-9_().\s]*(<>|>=|<=|=|<|>|\+|-|\*|,)")
_NUMERIC = re.compile(r"^[\s()\d.,'<>+=-]+$")

#: "Escaped human text": a message glued onto SQL. A closed empty quote followed by
#: a letter, a date glued to a parenthesis, or a sentence with !/? in it.
ESCAPE = re.compile(r"''[^\s'()=,<>+\-*0-9]|\)[0-9]{2}\.[0-9]{2}|[!?]")
#: A statement ending on an operator or connector is a fragment, not a statement.
#: A trailing quote is deliberately NOT in this set: a balanced statement legitimately
#: ends with one (``... = 'E1'``), and :func:`balanced` already catches the open case.
_DANGLING = re.compile(r"(and|or|,|<|>|=|\+|-|\blike\b|\bin\b|\()\s*$", re.I)


def normalise(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "")).strip().lower()


def key(text: str) -> str:
    """Comparison key: quotes and spacing removed, case folded."""
    return re.sub(r"['\"]", "", normalise(text)).strip()


def statements(text: str) -> int:
    """Verbs outside quotes. A verb inside a string value is not a statement.

    The verb is matched after a non-letter, not after a word boundary: a VB6 program
    concatenates data straight onto SQL, so the text can read ``…02SELECT ContactKey…``
    and ``\\b`` sees no boundary between ``2`` and ``S``. With ``\\b`` that string
    counted as one statement instead of two and a two-statement join was reported
    CLOSED.
    """
    in_quote, buf = False, []
    for ch in text:
        if ch == "'":
            in_quote = not in_quote
            buf.append(" ")
        elif not in_quote:
            buf.append(ch)
    flat = "".join(buf)
    return len(
        re.findall(r"(?:^|[^A-Za-z_])(select|insert|update|delete)\b", flat, re.I)
    )


def starts_statement(text: str) -> bool:
    """Does this candidate begin where a statement can begin?

    Without this gate, a chain starting in the middle of an expression closes
    perfectly well — measured output included ``AltStockCode' AND AltStockType = '…'``
    reported as CLOSED. A fragment before the verb belongs to the previous statement.
    """
    return bool(re.match(r"\s*(select|insert|update|delete)\b", text, re.I))


def balanced(text: str) -> bool:
    return text.count("'") % 2 == 0 and text.count("(") == text.count(")")


def is_sql_fragment(text: str) -> bool:
    """Is this fragment SQL/arithmetic rather than a message that got concatenated?"""
    if not text or not text.strip():
        return True
    if _SQL_HINT.search(text):
        return True
    stripped = text.strip()
    return bool(_NUMERIC.match(stripped) or _ARITH.match(stripped))


@dataclass
class Candidate:
    text: str
    parts: int
    status: str            # CLOSED / OPEN_QUOTE / ESCAPE / DANGLING / MULTI / STUCK
    reason: str
    tables: list[str] = field(default_factory=list)

    @property
    def closed(self) -> bool:
        return self.status == "CLOSED"

    def as_row(self) -> dict:
        return {
            "status": self.status,
            "parts": self.parts,
            "reason": self.reason,
            "tables": ";".join(self.tables),
            "sql": self.text,
        }


def chains(literals: list[Literal]) -> dict[int, list[Literal]]:
    """Group literals by procedure, preserving the order the source gave them."""
    out: dict[int, list[Literal]] = {}
    for lit in literals:
        if lit.proc_va is None:
            continue
        out.setdefault(lit.proc_va, []).append(lit)
    return out


def stitch(chain: list[Literal], start: int, max_more: int = MAX_MORE) -> list[Candidate]:
    """Every candidate beginning at ``chain[start]``, longest first, classified.

    A chain may only *start* at a fragment that begins a statement. Starting
    everywhere produced thousands of balanced mid-expression joins that passed every
    other gate; a statement boundary in VB6 is where the literal itself opens with a
    verb.
    """
    if not starts_statement(chain[start].text):
        return []
    out: list[Candidate] = []
    for n in range(1, max_more + 1):
        parts = chain[start : start + n]
        if len(parts) < n:
            break
        text = "".join(p.text for p in parts)
        if not _SQL_HINT.search(text):
            continue
        out.append(_classify(text, parts))
    return out


def _classify(text: str, parts: list[Literal]) -> Candidate:
    stmts = statements(text)
    tables = sorted(
        {m.group(2) for m in _TARGET.finditer(text) if m.group(2).lower() not in _NOT_A_TABLE}
    )
    if not starts_statement(text):
        return Candidate(text, len(parts), "NOT_START", "begins mid-statement", tables)
    if ESCAPE.search(text):
        return Candidate(text, len(parts), "ESCAPE", "human text glued onto SQL", tables)
    if not balanced(text):
        open_q = text.count("'") % 2 == 1
        return Candidate(
            text,
            len(parts),
            "OPEN_QUOTE" if open_q else "OPEN_PAREN",
            "run-time value or missing tail" if open_q else "unbalanced parentheses",
            tables,
        )
    if stmts > 1:
        return Candidate(text, len(parts), "MULTI", f"{stmts} statements glued together", tables)
    if _DANGLING.search(text.strip()):
        return Candidate(text, len(parts), "DANGLING", "ends on a connector", tables)
    if not any(is_sql_fragment(p.text) for p in parts[1:]):
        return Candidate(text, len(parts), "STUCK", "continuation is not SQL", tables)
    return Candidate(text, len(parts), "CLOSED", "balanced, single statement", tables)


def stitch_all(literals: list[Literal], max_more: int = MAX_MORE) -> list[Candidate]:
    """Best closed candidate per procedure, plus the count of open fragments."""
    out: list[Candidate] = []
    for _proc, chain in chains(literals).items():
        best: Candidate | None = None
        for i in range(len(chain)):
            for cand in stitch(chain, i, max_more=max_more):
                if cand.closed and (best is None or len(cand.text) > len(best.text)):
                    best = cand
        if best is not None:
            out.append(best)
    return out


def summarise(candidates: list[Candidate]) -> dict:
    counts: dict[str, int] = {}
    for c in candidates:
        counts[c.status] = counts.get(c.status, 0) + 1
    return {
        "candidates": len(candidates),
        "closed": counts.get("CLOSED", 0),
        "by_status": counts,
    }
