"""Kept so `python scripts/frx_icon.py ...` keeps working.

The implementation moved into the package (`vb6decompiler.frx_icon`) so a pip
install can run it too: `python -m vb6decompiler.frx_icon ...`. This shim exists
because the command is quoted in older notes and in `docs/`; it does nothing else.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vb6decompiler.frx_icon import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
