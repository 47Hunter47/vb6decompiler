"""vb6decompiler — evidence-based recovery of native-compiled VB6 programs.

Every module here has one job and prints what it could not do. The package never
guesses a name, a string or a table: it either reads it from the file or it says
"unknown" and counts it.
"""
from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["pe", "procs", "literals", "sqlstitch", "frm", "blob", "datareport", "mask"]
