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
* Turkish text inside a target's own data is preserved byte-for-byte; decode as
  CP1254 or UTF-16LE, never with a lossy guess.
* Prefer stdlib. `pefile` and `capstone` are the only optional third-party
  dependencies and each is confined to one module.
* Tests: `pytest -q`. Real-target tests are opt-in through four environment
  variables — `VB6D_TARGET`, `VB6D_LISTINGS`, `VB6D_FRM_DIR`, `VB6D_REPORT_DIR` —
  and skip when unset.
* The structure reference is `docs/formats.md`. If you discover an offset or grammar
  that is not in it, add it there with the measurement, not in a code comment that
  nobody reads.

## Before you finish

```
pytest -q
vb6d mask .          # must report zero unmasked credentials
```
