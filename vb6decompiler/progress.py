"""A progress line on stderr, and the rule for when it may appear.

A long stage that prints nothing for a minute looks hung, but a progress line in a
piped run corrupts a report someone is parsing with a script. So: only when stderr is
a terminal, only every few seconds, and always with both numbers (``12000 of 34000``)
so the line means the same thing whether it is the first or the last.
"""

from __future__ import annotations

import sys
import time

#: Seconds between two progress lines. Long enough to stay out of the way, short
#: enough that a hung stage is distinguishable from a slow one.
INTERVAL = 5.0


def enabled(stream=None) -> bool:
    """A progress line is only for a human watching; never for a pipe or a file."""
    stream = stream or sys.stderr
    try:
        return bool(stream.isatty())
    except (AttributeError, OSError):
        return False


class Progress:
    """Report "done of total" at most every :data:`INTERVAL` seconds.

    The first tick always prints: a stage that has started and says so is
    distinguishable from one that is hung, and that is the whole reason the line
    exists. After that, one line per interval.

    ``force`` exists for tests and for a stage that knows it is slow: it ignores the
    tty check but not the interval, so the output stays readable either way.
    """

    def __init__(self, label: str, total: int, *, stream=None, force: bool = False,
                 interval: float = INTERVAL) -> None:
        self.label = label
        self.total = total
        self.stream = stream
        self.interval = interval
        self.active = force or enabled(stream)
        self.started = time.monotonic()
        self._last = self.started - interval   # so the first tick prints at once

    def tick(self, done: int, *, final: bool = False) -> None:
        """Announce progress; the last call should pass ``final=True``."""
        now = time.monotonic()
        if not self.active:
            return
        if not final and now - self._last < self.interval:
            return
        self._last = now
        elapsed = now - self.started
        print(f"# {self.label}: {done} of {self.total} ({elapsed:.1f}s)", file=self.stream or sys.stderr)
