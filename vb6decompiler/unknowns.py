"""``vb6d unknowns`` — what the stages could not resolve, safe to paste in an issue.

The evidence rules of this project say an unknown construct is reported as unknown
rather than guessed. That leaves a reader holding a row file full of such markers
with no way to ask "how much is unknown, and where?" without shipping the target's
own text to whoever is reading.

So this stage reads the row files the stages already wrote (``dossier``, ``edges``,
``outline``) and reports the markers as numbers:

* per marker kind, a count and the share of records it came from ("X of Y");
* where it sits, as a VA bucket (``VA >> 12`` — the page, not the address);
* for any text the marker carried, only its length and the first 8 hex digits of
  its SHA-256, so the same string can be recognised across two reports without
  being readable.

Never printed: the SQL, a name, a table, a path, or any byte of the input. The
marker vocabulary is exactly what the emitters write (see each kind below), not an
inference about what "unknown" might mean somewhere else.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import sys
from dataclasses import dataclass, field

from .errors import ExpectedValueError

#: ``dossier`` SQL statuses other than ``CLOSED``: a statement the stage refused to
#: call complete. The status itself is the marker; the text is never printed.
SQL_STATUSES = ("OPEN_QUOTE", "OPEN_PAREN", "DANGLING", "ESCAPE", "STUCK", "MULTI", "NOT_START")
#: How many characters of the hash a reader needs to compare two reports.
SHA_PREFIX = 8
#: ``VA >> 12`` groups markers by their 4 KiB page; a whole address is too narrow
#: to compare between builds and a section name would be a guess.
BUCKET_SHIFT = 12


@dataclass
class Marker:
    kind: str
    va: int | None = None
    #: ``("count", n)`` for a tally, ``("text", s)`` for a string that must be hashed.
    payload: tuple[str, object] | None = None


@dataclass
class Report:
    records: int = 0
    per_kind: dict[str, int] = field(default_factory=dict)
    buckets: dict[str, dict[str, int]] = field(default_factory=dict)
    sample: dict[str, tuple[int, str] | int] = field(default_factory=dict)
    unreadable: list[tuple[str, str]] = field(default_factory=list)

    @property
    def total(self) -> int:
        return sum(self.per_kind.values())

    def add(self, marker: Marker) -> None:
        self.per_kind[marker.kind] = self.per_kind.get(marker.kind, 0) + 1
        if marker.va is not None:
            page = f"0x{marker.va >> BUCKET_SHIFT:X}000"
            bucket = self.buckets.setdefault(marker.kind, {})
            bucket[page] = bucket.get(page, 0) + 1
        if marker.payload and marker.kind not in self.sample:
            self.sample[marker.kind] = _sample(marker.payload)

    def rows(self) -> list[dict[str, str]]:
        out = []
        for kind in sorted(self.per_kind):
            buckets = self.buckets.get(kind, {})
            top = sorted(buckets.items(), key=lambda kv: (-kv[1], kv[0]))[:4]
            sample = self.sample.get(kind, "")
            out.append({
                "kind": kind,
                "count": str(self.per_kind[kind]),
                "page buckets (top 4)": " ".join(f"{page}:{n}" for page, n in top),
                "sample": (f"len={sample[0]} sha256:{sample[1]}" if isinstance(sample, tuple)
                           else f"count={sample}"),
            })
        return out

    def lines(self) -> list[str]:
        """The ``#`` summary, every number with its denominator."""
        out = [f"# {self.records} records read, {self.total} unknown markers in {len(self.per_kind)} kinds"]
        for path, reason in self.unreadable:
            out.append(f"# unreadable {os.path.basename(path)}: {reason}")
        return out


def _sample(payload: tuple[str, object]) -> tuple[int, str] | int:
    kind, value = payload
    if kind == "count":
        # The emitters put an int here; anything else is a record we do not trust.
        return value if isinstance(value, int) else 0
    text = value if isinstance(value, str) else str(value)
    return len(text), hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:SHA_PREFIX]


def _va(record: dict) -> int | None:
    for key in ("va", "text_va", "proc_va"):
        raw = record.get(key)
        if isinstance(raw, str) and raw:
            try:
                return int(raw, 16)
            except ValueError:
                continue
    return None


def markers(record: dict) -> list[Marker]:
    """Every marker this record carries, by the field names the emitters write."""
    out: list[Marker] = []
    va = _va(record)

    for row in record.get("sql") or []:
        if not isinstance(row, dict):
            continue
        status = row.get("status")
        if status in SQL_STATUSES:
            out.append(Marker(f"sql:{status}", va, ("text", row.get("text") or "")))

    late = record.get("calls_late_bound")
    if isinstance(late, int) and late > 0:
        out.append(Marker("call:late-bound", va, ("count", late)))

    unverified = record.get("unverified_operations")
    if isinstance(unverified, dict) and unverified:
        total = sum(v for v in unverified.values() if isinstance(v, int))
        out.append(Marker("call:unverified-operation", va, ("count", total)))

    unlisted = record.get("runtime_unlisted")
    if isinstance(unlisted, dict) and unlisted:
        total = sum(v for v in unlisted.values() if isinstance(v, int))
        out.append(Marker("call:uncategorized-runtime", va, ("count", total)))

    # A stage that had to name a kind it does not know writes the word itself
    # (``frm``: KIND_UNKNOWN). The value is a vocabulary word, not target text.
    for key in ("kind", "type"):
        if record.get(key) == "unknown":
            out.append(Marker(f"kind-unknown:{key}", va))
    return out


def _records(path: str) -> list[dict]:
    """Records of one row file: JSONL, a JSON array, or CSV."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        if path.lower().endswith(".csv"):
            return list(csv.DictReader(fh))
        text = fh.read()
    stripped = text.lstrip()
    if stripped.startswith("["):
        loaded = json.loads(stripped)
        if not isinstance(loaded, list):
            raise ExpectedValueError(f"{path}: expected a JSON array of records")
        return [r for r in loaded if isinstance(r, dict)]
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ExpectedValueError(f"{path}: line {n}: not JSON ({exc.msg})") from exc
        if isinstance(row, dict):
            out.append(row)
    return out


def collect(paths: list[str]) -> Report:
    """Read every file, counting markers. An unreadable file is named, not fatal.

    One bad file must not stop a report meant for a bug submission: the reader
    needs to see which input was skipped as much as the counts.
    """
    report = Report()
    for path in paths:
        try:
            records = _records(path)
        except (OSError, ExpectedValueError, json.JSONDecodeError) as exc:
            report.unreadable.append((path, str(exc)))
            continue
        for record in records:
            report.records += 1
            for marker in markers(record):
                report.add(marker)
    return report


def as_text(report: Report) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=["kind", "count", "page buckets (top 4)", "sample"],
                            lineterminator="\n")
    writer.writeheader()
    writer.writerows(report.rows())
    return buffer.getvalue()


def as_json(report: Report) -> str:
    kinds = {}
    for kind, n in sorted(report.per_kind.items()):
        sample = report.sample.get(kind)
        kinds[kind] = {
            "count": n,
            "page_buckets": report.buckets.get(kind, {}),
            # A text sample is (length, hash prefix); a tally sample is the number.
            "sample": list(sample) if isinstance(sample, tuple) else sample,
        }
    return json.dumps({
        "records": report.records,
        "markers": report.total,
        "kinds": kinds,
        "unreadable": [{"name": os.path.basename(p), "reason": r} for p, r in report.unreadable],
    }, indent=2)


def warn(message: str) -> None:
    print(message, file=sys.stderr)
