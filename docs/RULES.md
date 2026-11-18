# Rules for anyone (human or agent) working in this repo

This is a tool repository, not a project log. Counts, dates and open items about
any *target* program do not belong here; they belong in the private notes of the
project that uses these tools.

## What belongs here

* Reusable code: parsers, harvesters, validators.
* Rules that survived contact with a real target: "do not do X, measured Y".
* Tests that reproduce a measurement, including on real files.

## Non-negotiable rules

1. **No invented output.** Every number in a docstring, README or test message is
   either produced by code in this repo or explicitly labelled as a guess. If you
   cannot run it, say you cannot.
2. **A parser without a validation gate is not finished.** Anything that reads a
   binary or vendor blob ships with a `--validate` path that compares against a
   ground truth (usually the `.frm` text shipped with the same program) and
   prints coverage, not "OK".
3. **Report the denominator.** "24,967 controls matched" is meaningless without
   "of 24,967". "20 % covered" needs "of 34,159".
4. **Absence is not proof.** A missing string, function or table means the tool
   did not find it. Write it that way, in code comments and in output text.
5. **Never store secrets.** Connection strings, `uid=`/`pwd=` values, server names
   and UNC paths are masked by `vb6decompiler/mask.py` before any artefact is
   written. Database *names* are not secrets.
6. **Do not put target-specific paths in code.** Every entry point takes a path.
   Defaults are `None`; examples live in `docs/`.
7. **Keep the measured constants with their explanation.** Regexes and thresholds
   in this repo were derived from real files; if one looks arbitrary, the comment
   above it says what it was calibrated against. Do not "clean up" them.

## Repo hygiene

8. **Docs, tests and examples use stand-ins.** Addresses come from RFC 5737
   (`192.0.2.0/24`), hosts are `fileserv`/`example`, schema and screen names are
   placeholders (`tOrder`, `fDemo011`), and no person or company is named. This
   tool was built against one program; nothing in the repo may require knowing
   that program's name, host, database, tables, screens or controls to be usable.
   `tests/test_hygiene.py` checks the shapes (private addressing, UNC shares
   naming a real host, e-mail, home paths); `VB6D_SCRUB_DENYLIST` — a private
   file, one name per line — also checks the names of whoever's program was read.
9. **`vb6d mask` covers generated artefacts** (`.csv`, `.md`, `.json`, `.txt`,
   `.sql`, `.log`). It is not a repo-wide scrub: source and test text are guarded
   by the hygiene test instead.

## Style

* English in code, docs and commit messages (the repo is public-facing).
* Text speaks in code pages, not nationalities: "a build compiled on a CP1254
  machine", never "a Turkish build". This is a universal toolkit; a nationality
  word reads as "built for that people". Exceptions where the page itself is the
  measurement: LCID table comments, CHANGELOG history, and fixture data (captions
  are evidence — re-derive before replacing them).
* Text inside a target's own data is preserved byte-for-byte; ANSI text is decoded with
  the code page the run resolved (`vb6decompiler/encoding.py`), UTF-16LE as such, never
  with a lossy guess.
* Prefer stdlib. `pefile` and `capstone` are the only optional third-party
  dependencies and each is confined to one module.
* `capstone` in the library/CLI enters only through the `asm` extra and only
  inside `x86.py`; core commands and the default test suite must work without
  it (engine-needing tests skip when it is absent). A missing engine is a
  named refusal with the install hint, never an import traceback.
* Tests: `pytest -q`. Real-target tests are opt-in through four environment
  variables — `VB6D_TARGET`, `VB6D_LISTINGS`, `VB6D_FRM_DIR`, `VB6D_REPORT_DIR` —
  and skip when unset.
* The structure reference is `docs/formats.md`. If you discover an offset or grammar
  that is not in it, add it there with the measurement, not in a code comment that
  nobody reads.

## Testing and agent packaging

* Verify test counts with two reads: `pytest -q --collect-only` (what exists)
  and `pytest -q -o console_output_style=count` (what ran; skipped counts are
  reported separately). A "green" run that collected zero tests proves nothing.
* Version numbers live only in `pyproject.toml`. The agent-packaging copy at
  `.agents/skills/vb6decompiler/SKILL.md` is the single skill file — plugin
  manifests point at it and carry no version; a second copy drifts.
* The `vb6d` console shim can go stale after a package rename
  (`ModuleNotFoundError`). Repair with the canonical interpreter:
  `pip install -e .` rebuilds the entry points.

## Releasing

A push to `master` that touches release-relevant files (`vb6decompiler/**`,
`pyproject.toml`, `third_party/**`) ships a release: CI bumps the patch version,
commits and tags it, and publishes to PyPI through trusted publishing (no token
in the repository). Docs-only pushes do not publish — the README on the PyPI
page updates with the next code release. A push that raises `version` in
`pyproject.toml` itself ships that exact version — that is the manual path for a
minor or major release. Do not upload by hand: the runner owns the version
sequence, and re-uploading a version the runner already burned just fails.

GitHub skips every workflow for a commit whose message contains a literal skip
marker (`[skip ci]` and friends) — quoting the marker inside a sentence, e.g.
when describing the pipeline, suppresses CI for that push. The release pipeline
uses the marker deliberately for its own bump commit; do not put it in your
commit messages.

## Before you finish

```
pytest -q
vb6d mask .          # must report zero unmasked credentials
```
