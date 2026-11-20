"""One workspace file instead of seven environment variables and a dozen flags.

The stages already read their inputs from the command line, from ``VB6D_*``
variables and (for the code page) from the build's own header. That is three ways to
say the same thing, and a recovery run says it a dozen times. ``vb6d.toml`` is the
fourth and last: a file, because a run is repeatable only if its inputs are written
down somewhere.

Precedence, from strongest to weakest — the order the toolkit already had, with the
file inserted where a project's own settings belong:

    flag  >  VB6D_* environment variable  >  vb6d.toml  >  header LCID  >  default

Two rules keep the file honest:

* **Unknown keys are refused, not ignored.** A misspelled ``listing_dir`` that is
  silently skipped produces a run that looks configured and reads nothing.
* **``init`` writes placeholders only.** No real target name, no host, no path from
  the machine that generated it: the template is meant to be committed.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field

#: The file searched for, in this order, starting at the current directory and
#: walking up. A run inside ``out/`` still finds the project's file.
FILE_NAME = "vb6d.toml"
#: Keys of the one table this version understands. A new key is a schema change and
#: lands with the stage that needs it.
KNOWN_KEYS = {
    "target", "listings", "frm_dir", "report_dir", "output",
    "encoding", "workers", "progress",
}


class ConfigError(ValueError):
    """The file is not usable: unknown key, wrong type, unreadable."""


@dataclass
class Config:
    path: str | None = None
    target: str | None = None
    listings: str | None = None
    frm_dir: str | None = None
    report_dir: str | None = None
    output: str | None = None
    encoding: str | None = None
    workers: int | None = None
    progress: bool | None = None
    #: Keys that were present but empty: a placeholder the user has not filled in.
    placeholders: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()
                if k not in ("path", "placeholders") and v is not None}

    def get(self, key: str) -> object:
        return getattr(self, key, None)


#: What ``init`` writes. Every value is a placeholder: a template that names a real
#: build would carry someone's environment into a committed file.
TEMPLATE = """\
# vb6d workspace - fill in what your build needs, delete the rest.
#
#   vb6d doctor                       # check the machine before the first run
#   vb6d run --config vb6d.toml       # every stage, in dependency order
#
# Paths may be relative to this file. Command-line flags beat these values, and
# a VB6D_* environment variable beats them too.
#
# On Windows write paths with forward slashes ("C:/build/app.exe") or in single
# quotes ('C:/build/app.exe'): inside a double-quoted TOML string a backslash
# starts an escape, so a Windows path written plainly will not parse.

# target    = "<path to the compiled .exe>"
# listings  = "<directory of decompiler listings: .frm, .bas, .cls>"
# frm_dir   = "<directory of .frm design text>"
# report_dir= "<install directory holding rpt*.dll>"
# output    = "out"

# encoding  = "cp1254"   # default: the build's header LCID, else cp1254
# workers   = 4          # per-file stages on N threads; 1 = sequential
# progress  = true       # a stderr progress line on long stages
"""


def find(start: str | None = None) -> str | None:
    """The nearest ``vb6d.toml`` at or above ``start`` (default: the cwd)."""
    here = os.path.abspath(start or os.getcwd())
    while True:
        candidate = os.path.join(here, FILE_NAME)
        if os.path.isfile(candidate):
            return candidate
        parent = os.path.dirname(here)
        if parent == here:
            return None
        here = parent


def load(path: str) -> Config:
    """Read one file. Every problem names the file and the key.

    ``tomllib`` is the standard library from 3.11, which is the floor this package
    declares — no dependency is added for a config file.
    """
    try:
        with open(path, "rb") as fh:
            raw = tomllib.load(fh)
    except OSError as exc:
        raise ConfigError(f"{path}: cannot read ({exc.strerror or exc})") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: not valid TOML ({exc})") from exc

    # A file may carry [vb6d] or the keys at top level; both are one table here.
    table = raw.get("vb6d", raw)
    if not isinstance(table, dict):
        raise ConfigError(f"{path}: [vb6d] must be a table")
    unknown = sorted(set(table) - KNOWN_KEYS)
    if unknown:
        raise ConfigError(
            f"{path}: unknown key(s) {', '.join(unknown)}; known: {', '.join(sorted(KNOWN_KEYS))}")

    cfg = Config(path=path)
    base = os.path.dirname(os.path.abspath(path))
    for key in ("target", "listings", "frm_dir", "report_dir", "output", "encoding"):
        value = table.get(key)
        if value is None:
            continue
        if not isinstance(value, str):
            raise ConfigError(f"{path}: {key} must be a string, not {type(value).__name__}")
        if not value.strip():
            cfg.placeholders.append(key)
            continue
        # Relative paths are relative to the file, so a workspace can be moved or
        # committed and still mean the same thing.
        if key != "encoding" and not os.path.isabs(value):
            value = os.path.normpath(os.path.join(base, value))
        setattr(cfg, key, value)
    workers = table.get("workers")
    if workers is not None:
        if not isinstance(workers, int) or isinstance(workers, bool) or workers < 1:
            raise ConfigError(f"{path}: workers must be a positive integer")
        cfg.workers = workers
    progress = table.get("progress")
    if progress is not None:
        if not isinstance(progress, bool):
            raise ConfigError(f"{path}: progress must be true or false")
        cfg.progress = progress
    return cfg


def write_template(directory: str) -> str:
    """Write ``vb6d.toml`` into ``directory``; refuse to overwrite one."""
    path = os.path.join(directory, FILE_NAME)
    if os.path.exists(path):
        raise ConfigError(f"{path}: already exists (delete it or pass another directory)")
    os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(TEMPLATE)
    return path


def resolve(*, config_path: str | None = None, search: bool = True) -> Config:
    """The config a command should use: ``--config`` path, else the nearest file.

    No file is not an error — every stage still works from flags and environment
    variables, which is what a one-off run wants. The returned object simply has
    ``path is None`` so a caller can say which source it used.
    """
    path = config_path or (find() if search else None)
    if path is None:
        return Config()
    if not os.path.isfile(path):
        raise ConfigError(f"{path}: no such file")
    return load(path)
