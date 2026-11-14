# AGENTS.md — rule book for this repository

`docs/RULES.md` holds the technical rules (what may be claimed, measured structures,
tool limits). This file is the rule book for anyone — human or agent — editing or
running this repository. It is a set of rules, not a log: project state, open items
and test results live elsewhere.

## Running the tool (the contract an agent needs)

* Shape: `vb6d <stage> <path> [flags]`; every stage answers `vb6d <stage> --help`.
* stdout carries record lines only when you strip comments: footnotes, summaries
  and error messages are `#`-prefixed — on stderr for every stage except `mask`,
  and `procs` writes one `#` count line to stdout. Discard `#` lines when
  parsing. `--json` exists for `pe`, `procs`, `stitch`, `frm`, `blob` and
  `datareport`; `literals` is CSV-only by design because its row count is six
  figures and JSON indentation only bloats it.
* Exit codes: `0` = the run completed whatever it found (a missing thing is a
  result — report it, do not retry); `1` = mask audit found live values (the
  artefacts are not publishable); `2` = unusable input or a wrong invocation
  (one line on stderr, no traceback; `VB6D_DEBUG=1` re-raises for bug reports).
* Both streams are reconfigured to UTF-8; a character the console cannot encode
  becomes a visible escape, never a silent drop.
* Trust semantics before repeating a number: unknown constructs are reported as
  unknown, never guessed (`docs/formats.md` §7); closed SQL is a lower bound;
  decompiler-supplied names are hints. `docs/pipeline.md` states what each stage
  may claim and what it must not.
* Before publishing anything a run produced: `vb6d mask <out_dir> --dry-run`;
  non-zero means sanitise first.
* Stage order, tips and expected failure shapes: README, "Using it well".

## Rules

1. **Evidence, not guessing.** Every number in docs, tests or commit messages comes
   from a command that can be re-run. If you could not measure it, say so and label
   it an assumption.
2. **A parser never invents structure.** An un-calibrated grammar is a missing
   feature, not a guess: report the unknown as unknown (`docs/formats.md` §7)
   instead of emitting plausible records.
3. **Report denominators.** "24,967 of 24,967 controls matched", not "100 %". A
   count without its total is not evidence.
4. **Standard library only.** `pefile` and `capstone` are optional dev-time second
   opinions. No other third-party dependency, no vendored binaries.
5. **The tool is generic.** It must not know or imply a specific program. Paths come
   from the caller or from the `VB6D_*` variables.
6. **Public text is written for a stranger.** English, plain, reproducible steps. No
   machine names, personal paths, internal hosts, account names or chat ids.

## Do

- Run the gate before committing:
  `python -m compileall -q vb6decompiler tests`, then `pytest -q` (no target
  variables exported), then `vb6d mask . --dry-run`.
- When you have a real VB6 build, run the target-variable suite as well: export
  `VB6D_TARGET`, `VB6D_LISTINGS`, `VB6D_FRM_DIR`, `VB6D_REPORT_DIR` and run
  `pytest -q` — nothing may skip.
- Add an invariant test with every measurement you publish. A claim without a test
  rots.
- Keep code Python 3.11 compatible (this project's interpreter): no syntax that
  only exists in newer releases.
- Mask generated artefacts (`vb6d mask <dir>`) before committing or publishing them.
  A non-zero `vb6d mask . --dry-run` exit means "not publishable yet".
- Keep the CLI shape `vb6d <stage> <path> [flags]`; prefer a flag alias over renaming
  a flag people already use.

## Don't

- **No target identity in this repository, ever**: no product, company or person
  names; no host names, database names, accounts, credentials, private IP addresses,
  UNC shares, install paths or personal home paths. Docs and tests use placeholder
  hosts (`example`, `fileserv`) and RFC 5737 documentation addresses
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). `tests/test_hygiene.py`
  enforces this — if it fails, fix the content, not the test.
- Do not commit the owner's own list of names to keep out. It lives outside the
  repository and is read through `VB6D_SCRUB_DENYLIST`.
- Do not commit decompiler output, listing dumps, or artefacts produced by a
  licensed third-party tool. Re-derive what you need here, or describe it without
  pasting it.
- Do not simplify away validation, error handling, permission checks or resource
  cleanup. Narrowing scope is allowed; narrowing safety is not.
- Do not rewrite public git history, change repository visibility, or force-push
  without the owner's explicit approval.
- Do not add a dependency, a new stage, or a speculative abstraction because it
  might be useful later.
