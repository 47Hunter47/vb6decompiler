"""Kept so `python scripts/pseudoc_inventory.py ...` keeps working.

The implementation moved into the package (`vb6decompiler.pseudoc_inventory`);
`python -m vb6decompiler.pseudoc_inventory ...` does the same thing. Needed by
pip users because `vb6d dossier --inventory` consumes this script's CSVs.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vb6decompiler.pseudoc_inventory import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
