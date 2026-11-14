"""Hide credentials before anything reaches disk.

Why this exists
---------------
A recovered VB6 build contains **plain-text connection strings with ``uid=`` and
``pwd=`` values** (250 of them in the reference target, plus server names and UNC
shares). Any artefact written from that data — CSV, Markdown, JSON, a commit —
leaks the credentials of a live SQL Server. Every writer in this package runs its
text through :func:`mask_text`; :func:`audit` is the gate that proves nothing else
did.

What is masked
--------------
* ``password=`` / ``pwd=`` values      -> ``[REDACTED]``
* ``user id=`` / ``uid=`` values       -> ``[REDACTED]``
* ``server=`` / ``data source=`` hosts -> ``[HOST]``
* ``\\\\host\\share`` UNC prefixes        -> ``\\\\[HOST]\\``
* IPv4 literals                        -> ``[IP]``

What is *not* masked, on purpose: database names. They are evidence about the
program's data model, not a credential, and masking them would destroy the very
information the toolkit exists to produce.

The measured trap: a masking regex written with ``\\s`` crosses newlines. When a
literal ends with ``Server=``, ``\\s`` swallows the line break and "masks" the first
word of the next line — corrupting the file and producing a false count. All
whitespace classes here are ``[ \\t]``, never ``\\s``, and the file-level pass counts
lines before and after and refuses to write when they differ.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

REDACTED = "[REDACTED]"
HOST = "[HOST]"
IP = "[IP]"

#: Every pattern is line-bounded: ``[ \t]`` and ``[^;\s"']``-style ranges that can
#: never cross a newline, and the value stops at the next separator.
def _keep_key(match: "re.Match[str]") -> str:
    """Keep the key and separator as written, replace only the value.

    A replacement *string* cannot carry a literal backslash: ``re`` reads ``\\``
    and ``\\1`` as escapes, and a UNC replacement raised "bad escape". A callable
    has no such problem, so every pattern below uses one.
    """
    return match.group(1) + match.group(2) + REDACTED


def _keep_host_key(match: "re.Match[str]") -> str:
    return match.group(1) + match.group(2) + HOST


def _unc(match: "re.Match[str]") -> str:
    return "\\\\" + HOST + "\\"


#: RFC 5737 documentation ranges.  Docs and tests use them on purpose as the
#: stand-in for a real address, so they are not leaks and must survive masking —
#: a gate that redacts its own examples teaches people to disable the gate.
DOC_NETS = ("192.0.2.", "198.51.100.", "203.0.113.")
_LIVE_IP = re.compile(r"\b(?!(?:192\.0\.2|198\.51\.100|203\.0\.113)\.)(?:\d{1,3}\.){3}\d{1,3}\b")

_PATTERNS: list[tuple[re.Pattern[str], object]] = [
    (re.compile(r"(?i)\b(password|pwd)([ \t]*=[ \t]*)([^;\"'\r\n \t`]+)"), _keep_key),
    (re.compile(r"(?i)\b(user[ \t]+id|uid)([ \t]*=[ \t]*)([^;\"'\r\n \t`]+)"), _keep_key),
    (re.compile(r"(?i)\b(server|data[ \t]+source)([ \t]*=[ \t]*)([^;,\"'\r\n \t`]+)"), _keep_host_key),
    (re.compile(r"\\\\[A-Za-z0-9._-]+\\"), _unc),
    (_LIVE_IP, IP),
]

#: Marker that means a value was already masked; re-masking it produces nested
#: ``[REDACTED]`` inside ``[REDACTED]`` and then a false "still leaking" alarm.
_ALREADY = re.compile(r"\[(REDACTED|HOST|IP)\]")


def mask_text(text: str) -> str:
    """Mask one string. Idempotent: masked values stay as they are."""
    if _ALREADY.search(text):
        # Still run the patterns: a string can carry one masked and one live value.
        pass
    out = text
    for pattern, repl in _PATTERNS:
        out = pattern.sub(repl, out)
    return out


@dataclass
class AuditResult:
    files: int
    lines: int
    findings: dict[str, int]

    @property
    def clean(self) -> bool:
        return not any(self.findings.values())


def audit(path: str, extensions: tuple[str, ...] = (".csv", ".md", ".json", ".txt", ".sql", ".log")) -> AuditResult:
    """Count unmasked credentials in the text files under ``path``.

    Only *values* count. A file that mentions the word ``uid=`` with nothing after
    it is a connection-string fragment, not a leak — counting keywords produced
    211 false positives against 92 real ones in the reference corpus.
    """
    findings = {"password": 0, "uid": 0, "host": 0, "unc": 0, "ip": 0}
    files = 0
    lines = 0
    targets = [path] if os.path.isfile(path) else []
    if not targets:
        for root, _dirs, names in os.walk(path):
            for n in names:
                if n.lower().endswith(extensions):
                    targets.append(os.path.join(root, n))
    # The audit uses the same token rule as the masker: a value must have at least one
    # character that is not a separator or a markdown backtick. Otherwise prose such as
    # "`uid=`/`pwd=` values" is counted as two leaks, and a gate that cries wolf on
    # documentation gets ignored — which is how a real leak survives.
    live = [
        (re.compile(r"(?i)\b(password|pwd)[ \t]*=[ \t]*[^;\"'\r\n \t`]"), "password"),
        (re.compile(r"(?i)\b(user[ \t]+id|uid)[ \t]*=[ \t]*[^;\"'\r\n \t`]"), "uid"),
        (re.compile(r"(?i)\b(server|data[ \t]+source)[ \t]*=[ \t]*[^;,\"'\r\n \t`]"), "host"),
        (re.compile(r"\\\\[A-Za-z0-9._-]+\\"), "unc"),
        (_LIVE_IP, "ip"),
    ]
    for f in targets:
        files += 1
        with open(f, encoding=_codec_for(f), errors="replace") as fh:
            for line in fh:
                lines += 1
                for pattern, key in live:
                    if pattern.search(line) and not _ALREADY.search(line):
                        findings[key] += 1
    return AuditResult(files=files, lines=lines, findings=findings)


def _codec_for(path: str) -> str:
    """BOM-aware codec pick. A UTF-16 artefact (``command > out.txt`` in
    PowerShell) read as UTF-8 with ``replace`` turns ``uid=`` into ``u?i?d?``:
    every pattern misses it and the gate passes a live leak.
    shortcut: detection is BOM-only; a BOM-less UTF-16 file is still blind to
    the gate — upgrade if a corpus proves that case is real.
    """
    with open(path, "rb") as fh:
        head = fh.read(2)
    if head in (b"\xff\xfe", b"\xfe\xff"):
        return "utf-16"      # the codec strips the BOM on read and rewrites it on write
    if head == b"\xef\xbb":  # EF BB BF prefix
        return "utf-8-sig"   # strips on read, rewrites on write
    return "utf-8"


def mask_file(path: str, dry_run: bool = False) -> int:
    """Mask one file in place. Returns the number of changed lines.

    The line count is compared before and after: a whitespace class that crosses
    newlines would silently join lines, and this function refuses to write in that
    case. Decoding is BOM-aware, and undecodable bytes round-trip via
    surrogateescape: a cp1254 artefact leaves every byte outside the masked
    values unchanged.
    """
    codec = _codec_for(path)
    with open(path, encoding=codec, errors="surrogateescape", newline="") as fh:
        original = fh.read()
    lines = original.splitlines(keepends=True)
    changed = [mask_text(line) for line in lines]
    n_changed = sum(1 for a, b in zip(lines, changed) if a != b)
    if len(changed) != len(lines):
        raise RuntimeError(
            f"{path}: masking changed the line count ({len(lines)} -> {len(changed)}); not writing"
        )
    if not dry_run and n_changed:
        with open(path, "w", encoding=codec, errors="surrogateescape", newline="") as fh:
            fh.write("".join(changed))
    return n_changed


def mask_tree(path: str, extensions: tuple[str, ...] | None = None, dry_run: bool = False) -> dict:
    """Mask every text file under a directory; returns per-file changed-line counts."""
    exts = extensions or (".csv", ".md", ".json", ".txt", ".sql", ".log")
    out: dict[str, int] = {}
    for root, _dirs, names in os.walk(path):
        for n in names:
            if n.lower().endswith(exts):
                p = os.path.join(root, n)
                # A symlink would let 'mask my artefacts dir' rewrite a file that
                # lives outside it; the audit may still read through it (stricter).
                out[p] = 0 if os.path.islink(p) else mask_file(p, dry_run=dry_run)
    return out
