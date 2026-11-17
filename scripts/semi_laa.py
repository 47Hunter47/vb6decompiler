"""Kept so `python scripts/semi_laa.py ...` keeps working.

The implementation moved into the package (`vb6decompiler.semi_laa`);
`python -m vb6decompiler.semi_laa ...` does the same thing.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vb6decompiler.semi_laa import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
