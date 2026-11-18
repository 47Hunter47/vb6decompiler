"""Exception marker: whose fault is it, the caller's or the toolkit's.

The CLI exit-code contract (AGENTS.md) sorts every failure into two buckets:
unusable input or a wrong invocation (exit 2, one line on stderr) and
unexpected internal or operational trouble (exit 3). An exception says it
belongs to the first by inheriting :class:`ExpectedInput`; everything else —
a bug, an unwritable output, a mask that refuses to write — is not the
caller's file or flag to fix and exits 3.
"""


class ExpectedInput(Exception):
    """This failure is the caller's to fix: a bad path, a bad file, a bad flag value."""


class ExpectedValueError(ExpectedInput, ValueError):
    """An input problem callers already catch as ``ValueError``.

    Callers and tests that assert the old base type (``blob``'s decoding,
    ``encoding`` refusals, the inventory-path check) keep working: the marker
    rides alongside ValueError instead of replacing it.
    """
