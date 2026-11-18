"""Kept so `python scripts/literal_visibility.py ...` keeps working.

The implementation moved into the package (`vb6decompiler.literal_visibility`);
`python -m vb6decompiler.literal_visibility ...` does the same thing.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vb6decompiler.literal_visibility import main

if __name__ == "__main__":
    raise SystemExit(main())
