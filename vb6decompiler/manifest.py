"""A manifest beside every file a stage writes: what produced it, from what.

The outputs of this tool are shared — pasted into an issue, attached to a report,
diffed between two builds — and a row file on its own cannot say which build,
which code page or which tool version produced it. The manifest answers that in a
few fields and never changes the artefact it describes: it is a separate
``<out>.manifest.json`` next to the file.

Two rules it follows, both about privacy:

* input paths are reduced to file names unless ``--manifest-paths`` is given,
  because a manifest is as likely to be shared as the output beside it;
* a hash is streamed, so a 100 MB target costs memory the same as a 1 KB file.

Nothing here is guessed: an input that cannot be read is recorded with the reason
instead of a size, and the manifest itself is written on a best-effort basis —
a stage that produced its output must not fail because a side file could not be
written. (The stage's own exit code still reports a real failure.)
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
from datetime import UTC, datetime

#: Suffix appended to the output path; ``report.jsonl`` -> ``report.jsonl.manifest.json``.
SUFFIX = ".manifest.json"
#: Read size for the streamed hash: large enough that a 100 MB file is 100 reads.
CHUNK = 1 << 20


def now() -> datetime:
    """UTC, because two machines' local clocks cannot be compared."""
    return datetime.now(UTC)


def _stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def _sha256_dir(path: str) -> tuple[str, int]:
    """Hash of a directory's *content*: name, size and hash of every file, in order.

    A listing directory has no bytes of its own to hash, and hashing only the tree
    listing would let an edited file keep the same fingerprint.
    """
    digest = hashlib.sha256()
    count = 0
    for root, dirs, files in os.walk(path):
        dirs.sort()
        for name in sorted(files):
            full = os.path.join(root, name)
            rel = os.path.relpath(full, path).replace(os.sep, "/")
            try:
                size = os.path.getsize(full)
                file_hash = _sha256_file(full)
            except OSError as exc:
                # The digest names the failure by type, not by number: a numeric
                # error code is on the hygiene denylist, and this hash only needs
                # to change when the tree does.
                digest.update(f"{rel}\0error:{type(exc).__name__}\0".encode())
                continue
            digest.update(f"{rel}\0{size}\0{file_hash}\0".encode())
            count += 1
    return digest.hexdigest(), count


def describe_input(path: str, *, full_paths: bool = False) -> dict:
    """One input as the manifest records it."""
    row: dict = {"name": path if full_paths else os.path.basename(os.path.normpath(path))}
    if full_paths:
        row["path"] = os.path.abspath(path)
    try:
        if os.path.isdir(path):
            row["kind"] = "directory"
            row["sha256"], row["files"] = _sha256_dir(path)
        else:
            row["kind"] = "file"
            row["size"] = os.path.getsize(path)
            row["sha256"] = _sha256_file(path)
    except OSError as exc:
        # A missing input is the stage's business to report; here it is named.
        row["kind"] = "unreadable"
        row["reason"] = f"{type(exc).__name__}: {exc.strerror or exc}"
    return row


def build(*, command: str, output: str, inputs, encoding: tuple[str, str] | None,
          started: datetime, records: dict | None = None,
          full_paths: bool = False) -> dict:
    """The manifest body for one run."""
    finished = now()
    from . import cli  # imported here: cli owns the version string, and imports this

    return {
        "tool": cli.version_line(),
        "command": command,
        "output": output if full_paths else os.path.basename(os.path.normpath(output)),
        "inputs": [describe_input(p, full_paths=full_paths) for p in inputs],
        "encoding": ({"codec": encoding[0], "source": encoding[1]} if encoding else None),
        "runtime": {"python": platform.python_version(), "implementation": platform.python_implementation()},
        "started": _stamp(started),
        "finished": _stamp(finished),
        "records": records or {},
    }


def path_for(output: str) -> str:
    return output + SUFFIX


def write(output: str, *, skip: bool = False, **fields) -> str | None:
    """Write ``<output>.manifest.json``; returns the path, or ``None`` if it failed.

    Called after the artefact exists, so a failure here leaves the artefact intact
    and reports itself on stderr instead of turning a finished run into an error.

    ``skip`` (``--no-manifest``) removes a manifest an earlier run left beside the
    same output: it would describe the new artefact with the old input's hash, and
    a wrong statement about provenance is worse than none.
    """
    if not output:
        return None
    target = path_for(output)
    if skip:
        try:
            os.unlink(target)
        except FileNotFoundError:
            return None
        except OSError as exc:
            print(f"# stale manifest kept, {target}: {exc.strerror or exc}", file=sys.stderr)
        return None
    try:
        with open(target, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(build(output=output, **fields), fh, indent=2, sort_keys=False)
            fh.write("\n")
    except OSError as exc:
        print(f"# manifest not written: {target}: {exc.strerror or exc}", file=sys.stderr)
        return None
    return target
