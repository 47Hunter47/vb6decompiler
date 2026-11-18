"""Reading an image once and sharing the buffer, plus an mmap path where it pays.

Why this exists
---------------
Every parser in this package needs the *whole* file in random-access form: a 111 MB
executable is read by :mod:`pe`, then again by :mod:`procs`, and inside a single
stage some functions read it twice (``datareport.read_designs`` called
``find_designs``, which opened the same file again; ``vb6d procs --validate`` read it
once for the header chain and once for the prologue check). Each of those is a full
copy of the file in memory — measured on a 111 MB file, ``read()`` peaks at 116 MB and
takes 0.08 s, so a stage that reads twice pays it twice.

:func:`image` maps the file instead of copying it, and :func:`buffer` says how to use
it: the returned object supports slicing, ``len()``, ``find()`` and
``struct.unpack_from`` — everything the parsers do with a ``bytes`` — while the data
stays in the OS page cache.

Two limits are deliberate:

* **A mapped file must be closed**, or Windows keeps it locked (no rename, no delete)
  until the interpreter collects it. Callers use ``with image(path) as data:``, and
  the context manager closes the mapping on every path out, including exceptions.
* **A buffer that escapes the function cannot be a mapping.** ``blob.load_sections``
  returns the bytes to its callers; ``frm.parse_bytes`` splits the raw text with
  ``bytes.split``, which a mapping does not implement. Those sites keep ``fh.read()``
  and say so at the call site — a mapping there would either leak or break.

So the rule for a new call site: map it only when the buffer is used *inside* the
function and only through slicing, ``len``, ``find`` and ``struct.unpack_from``.
"""

from __future__ import annotations

import mmap
import os
from contextlib import contextmanager
from typing import Iterator

#: Files smaller than this are not worth a system call pair: the copy is cheaper than
#: the mapping setup. Measured cross-over on this machine: a 4 MB mapping wins by a
#: hair, below it the sizes are inside the noise, so the constant is a floor and not a
#: tuned value.
MMAP_MIN_BYTES = 4 * 1024 * 1024


class InputError(OSError):
    """The path the caller handed us is not there.

    An OSError subclass so the ``except OSError`` handlers built along the way
    (edges, outline) keep catching it; the CLI's named-error contract turns it
    into exit 2 with one line.
    """


def require(path: str) -> None:
    """Reject a missing input up front — a walk of a path that does not exist
    returns zero files and used to read as "0 images, exit 0".

    The message carries the path exactly as the caller typed it (not resolved,
    not made absolute): that is the string the stranger recognises as their own
    argument. Every reader entry point calls this before touching the path.
    """
    if not os.path.exists(path):
        raise InputError(f"{path}: no such file or directory")


@contextmanager
def image(path: str) -> Iterator[bytes | mmap.mmap]:
    """Yield the file's bytes for read-only random access; never leaves it open.

    Falls back to ``fh.read()`` for an empty file (``mmap`` refuses those) and for a
    file the OS will not map (some network shares) — the parser then gets the same
    ``bytes`` it always got, so a mapping failure is a performance detail, not a
    different result.
    """
    require(path)
    with open(path, "rb") as fh:
        size = os.fstat(fh.fileno()).st_size
        if size < MMAP_MIN_BYTES:
            yield fh.read()
            return
        try:
            handle = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        except (OSError, ValueError):
            fh.seek(0)
            yield fh.read()
            return
        try:
            yield handle
        finally:
            handle.close()
