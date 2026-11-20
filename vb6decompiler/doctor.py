"""``vb6d doctor`` — can this machine run the toolkit, and what is switched off?

The question a newcomer asks first is "why did my first command fail", and the
answer is usually the environment, not the file: an old interpreter, a missing
optional engine, a data file that did not survive packaging, a `VB6D_*` variable
pointing at a moved directory. This module answers that without touching the
network and without an input file, in one line per check, so the output can be
pasted into an issue.

Exit codes (see ``AGENTS.md``): ``0`` nothing to report, ``1`` warnings only,
``2`` a check failed — the environment cannot run the toolkit.

Nothing here guesses: a check that cannot tell reports the reason it cannot.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from dataclasses import asdict, dataclass

from . import encoding, runtime_table
from .errors import ExpectedValueError

#: The interpreter the package declares in ``pyproject.toml``.
MIN_PYTHON = (3, 11)
#: Free space below this is worth a warning before a 100 MB target is read.
LOW_DISK = 1 << 30
#: Path-valued variables the stages and the test suite read.
ENV_PATHS = (
    "VB6D_TARGET",
    "VB6D_LISTINGS",
    "VB6D_FRM_DIR",
    "VB6D_REPORT_DIR",
    "VB6D_MSVBVM60",
    "VB6D_SCRUB_DENYLIST",
)

OK, WARN, FAIL = "ok", "warn", "fail"


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    message: str


def _python() -> Check:
    version = ".".join(str(part) for part in sys.version_info[:3])
    needed = ".".join(str(part) for part in MIN_PYTHON)
    if sys.version_info[:2] >= MIN_PYTHON:
        return Check("python", OK, f"{version} (needs {needed} or newer)")
    return Check("python", FAIL, f"{version} is older than {needed} (pyproject requires-python)")


def _engine() -> Check:
    try:
        import capstone
    except ImportError:
        return Check(
            "capstone",
            WARN,
            "not installed - 'decode' and 'edges' are disabled; "
            'pip install "vb6decompiler[asm]" enables them',
        )
    except OSError as exc:  # present on disk but unusable: not the same as missing
        return Check("capstone", FAIL, f"installed but not importable: {exc.strerror or exc}")
    version = getattr(capstone, "__version__", "")
    return Check("capstone", OK, f"{version} - 'decode' and 'edges' are available".lstrip())


def _runtime_table() -> Check:
    loaded = runtime_table.count()
    if loaded:
        return Check("runtime table", OK, f"{loaded} helpers from {runtime_table.table_dll()}")
    return Check(
        "runtime table",
        FAIL,
        "data file missing or unreadable (reinstall the package); "
        "'outline' would report every runtime call as uncategorized",
    )


def _encoding() -> Check:
    try:
        codec, source = encoding.choice(None, None)
    except ExpectedValueError as exc:  # VB6D_ENCODING holds something that is not a code page
        return Check("encoding", FAIL, f"{encoding.ENV_VAR}: {exc}")
    return Check("encoding", OK, f"{codec} ({source})")


def _env_paths() -> Check:
    set_vars = [(name, os.environ[name]) for name in ENV_PATHS if os.environ.get(name)]
    if not set_vars:
        return Check("environment variables", OK, "no VB6D_* path variable is set")
    missing = [(name, value) for name, value in set_vars if not os.path.exists(value)]
    if missing:
        names = ", ".join(f"{name}={value}" for name, value in missing)
        return Check("environment variables", WARN, f"set but pointing at nothing: {names}")
    return Check("environment variables", OK, f"{len(set_vars)} path variable(s) resolve")


def _temp() -> Check:
    directory = tempfile.gettempdir()
    try:
        handle, path = tempfile.mkstemp(prefix="vb6d-doctor-", dir=directory)
        os.close(handle)
        os.unlink(path)
    except OSError as exc:
        return Check("temp directory", FAIL, f"{directory}: {exc.strerror or exc}")
    return Check("temp directory", OK, f"{directory} is writable")


def _disk(directory: str) -> Check:
    target = directory if os.path.isdir(directory) else os.getcwd()
    try:
        free = shutil.disk_usage(target).free
    except OSError as exc:
        return Check("disk space", WARN, f"{target}: {exc.strerror or exc}")
    gib = free / (1 << 30)
    if free < LOW_DISK:
        return Check("disk space", WARN, f"{gib:.1f} GiB free under {target} (a 100 MB target needs room to write)")
    return Check("disk space", OK, f"{gib:.1f} GiB free under {target}")


def run(directory: str | None = None) -> list[Check]:
    """Every check, in the order a newcomer needs them."""
    return [
        _python(),
        _engine(),
        _runtime_table(),
        _encoding(),
        _env_paths(),
        _temp(),
        _disk(directory or os.getcwd()),
    ]


def exit_code(checks: list[Check]) -> int:
    if any(c.status == FAIL for c in checks):
        return 2
    if any(c.status == WARN for c in checks):
        return 1
    return 0


def summarise(checks: list[Check]) -> str:
    counts = {status: sum(1 for c in checks if c.status == status) for status in (OK, WARN, FAIL)}
    return f"# doctor: {counts[OK]} ok, {counts[WARN]} warn, {counts[FAIL]} fail"


def as_json(checks: list[Check]) -> str:
    return json.dumps([asdict(c) for c in checks], indent=2)
