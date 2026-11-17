"""vb6decompiler — evidence-based recovery of native-compiled VB6 programs.

Every module here has one job and prints what it could not do. The package never
guesses a name, a string or a table: it either reads it from the file or it says
"unknown" and counts it.
"""
from __future__ import annotations

# The version lives in pyproject.toml only (docs/RULES.md, "single-version rule"): a
# constant here drifted to 0.1.0 while the package shipped 0.2.x, so it was removed
# rather than duplicated. `importlib.metadata.version("vb6decompiler")` reads the real one.
__all__ = [
    "blob", "datareport", "dossier", "encoding", "frm", "literals", "mask", "pe",
    "procs", "sqlstitch",
]
