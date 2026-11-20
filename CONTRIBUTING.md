# Contributing

This toolkit's only product is a claim someone can check. Everything below follows
from that: a change is worth merging when a reader can rerun it and get the same
answer, and a change that makes a claim softer without saying so is a regression.

`AGENTS.md` is the rule book and `docs/RULES.md` the technical contract. They win
over this file; if they disagree with it, they are right and this file needs a fix.

## The gate

Every commit that touches tracked files must pass, in this order:

```bash
python -m compileall -q vb6decompiler tests
python -m pytest -q
vb6d mask . --dry-run
ruff check && mypy vb6decompiler
```

Run them one at a time and read each exit code. Do not chain them with `&&` inside a
script that reports "OK" regardless: a gate that only *prints* is not a gate, and
this repository has been burned by exactly that.

`vb6d mask . --dry-run` is not decoration — it is what catches a credential or a host
name that crept into generated output.

## Stand-ins only

Code, tests, docs, fixtures and commit messages use stand-in names: `fDemo011`,
`tOrder`, `mDemo`. Never a real customer name, table, form, host, address or account
from any program this toolkit was used on. A real target's identifiers belong in
private notes, not here.

The hygiene test enforces this from a private list the maintainer keeps outside the
repository:

```bash
VB6D_SCRUB_DENYLIST=/path/to/private/denylist.txt python -m pytest tests/test_hygiene.py -q
```

Without that variable the check skips, so a local green run proves less than a run
with it set. Two traps, both hit before:

* the test scans **every tracked byte**, so a string in a new test can trip it;
* it also checks the *shape* of things — a UNC path or a private address range in a
  fixture counts, even when the host is invented. Write the fixture differently
  instead of asking the scanner for an exception.

## Identity

Commits are made as the project identity only. Never commit as a person's private
name or address, and never rewrite history to fix an identity: that is the
maintainer's call, and it needs a backup and a plan.

## One task, one commit

Keep the diff to the task. Refactors, "while I am here" fixes and new features go
into their own commit or into a note — a mixed diff cannot be reviewed and cannot be
reverted.

Measured numbers in a docstring or a CHANGELOG entry must be numbers you produced by
running the command on this machine, with the input named. "Should be faster" and
"probably fixes" are not results.

## Tests

* A new stage or flag needs a test that would fail without it.
* Text that comes out of a binary is untrusted: escaping gets a test with hostile
  input (`<script>`, a path escape, a 300-character name, a newline).
* A test that only passes on one platform is a platform claim. Case-folding is the
  usual trap, because it belongs to the filesystem rather than the OS: Windows and
  macOS fold case (and `os.path.normcase` only carries the *spelling* rule on the
  first of them), while most Linux filesystems do not. Ask the filesystem, not
  `os.name`.
* Fix a broken test by making it state the truth; do not widen the assertion until
  it passes.

## Publishing

A push to `master` that touches `vb6decompiler/**`, `pyproject.toml` or
`third_party/**` publishes to PyPI and cannot be undone. Version bumps and tags are
the maintainer's, and the workflow creates the tag: never create one by hand, never
force-push, never rewrite history.
