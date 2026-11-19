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
import tempfile
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from typing import TextIO

from .errors import ExpectedInput

#: Files smaller than this are not worth a system call pair: the copy is cheaper than
#: the mapping setup. Measured cross-over on this machine: a 4 MB mapping wins by a
#: hair, below it the sizes are inside the noise, so the constant is a floor and not a
#: tuned value.
MMAP_MIN_BYTES = 4 * 1024 * 1024


class InputError(ExpectedInput, OSError):
    """The path the caller handed us is not there, usable, or safe to write onto.

    An OSError subclass so the ``except OSError`` handlers built along the way
    (edges, outline) keep catching it; the ``ExpectedInput`` marker says the CLI
    contract's caller-side bucket (exit 2, one line) is its home.
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


# --------------------------------------------------------------------------- output safety
def same_path(a: str, b: str) -> bool:
    """True when two paths name the same file.

    Spelling first (abspath + normcase, Windows case folding) because it answers
    for a destination that does not exist yet. Existing paths are then compared by
    filesystem identity — ``samefile`` catches a symlink or hard-link alias, and
    ``realpath`` catches a symlinked parent directory. An identity lookup that
    fails (a path we may read but not stat) is not an error: the spelling answer
    stands, so an optional check never turns a valid output into a crash.
    """
    if os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b)):
        return True
    try:
        if os.path.exists(a) and os.path.exists(b):
            return os.path.samefile(a, b)
    except OSError:
        pass
    return os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(b))


def refuse_overwrite_inputs(out: str, inputs: Iterable[str]) -> None:
    """An output may not be one of the files the run consumes: say so BEFORE opening.

    For a directory scan the caller passes the files actually consumed — checking
    only the directory name would miss an ``--out`` set to one of the very listing
    files being read (or to the executable the pass is decoding).
    """
    for path in inputs:
        if same_path(out, path):
            raise InputError(
                f"{out}: output path is one of the input files ({path}); refusing to overwrite")


#: Prefix/suffix of the unique temporary file :func:`atomic_out` creates in the
#: destination's directory. The name is random (``tempfile.mkstemp``): two writers
#: never share it, and no pre-existing path is opened or truncated.
TMP_PREFIX = ".vb6d-"
TMP_SUFFIX = ".tmp"


@contextmanager
def atomic_out(path: str, newline: str | None = None) -> Iterator[TextIO]:
    """A UTF-8 text writer on a unique sibling temp file, moved onto ``path`` only on a clean exit.

    Opening the destination directly truncates it immediately, so a failure in the
    middle of writing used to replace a usable file with half of a new one (and a
    refused run left an empty file behind). The temp file sits in the destination's
    own directory so ``os.replace`` stays on one volume, where it is atomic; on any
    failure the temp is removed and the previous output is untouched.

    The temp name comes from ``mkstemp`` (exclusive create, unpredictable): a fixed
    ``<path>.vb6d-tmp`` let two concurrent runs truncate each other's buffer and let a
    planted symlink redirect the write. Each invocation removes only the file it
    created itself, and closes it before ``os.replace`` — Windows refuses to replace
    a file that still has an open handle.
    """
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=TMP_PREFIX, suffix=TMP_SUFFIX, dir=directory)
    try:
        fh = os.fdopen(fd, "w", encoding="utf-8", newline=newline)
    except BaseException:
        os.close(fd)  # fdopen did not take ownership; Windows would refuse the cleanup below
        raise
    moved = False
    try:
        with fh:
            yield fh
        os.replace(tmp, path)
        moved = True
    finally:
        if not moved:
            try:
                os.remove(tmp)
            except FileNotFoundError:  # a caller moved it itself; nothing to clean
                pass
