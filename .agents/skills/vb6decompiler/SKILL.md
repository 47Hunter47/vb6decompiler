---
name: vb6decompiler
description: Recover what a native-compiled Visual Basic 6 program actually does when its source is lost: prologue-verified procedure table, BSTR/UTF-16 literal and SQL harvest, SQL statement stitching, .frm design text, binary form geometry, DataReport layouts, credential mask before publishing. Use when the target is a VB6 native executable or report DLL (MSVBVM60). Skip for P-Code builds, for projects that still have their source, and for non-VB6 binaries.
---

# vb6decompiler

`vb6d` reads what generic disassemblers do not: VB6 keeps strings as
length-prefixed `BSTR`s inside `.text`, enters procedures through a fixed runtime
prologue, serialises form designs into the executable as binary property blobs,
and stores report layouts in separate VB6 DLLs. Every claim the tool makes is a
measurement a command reproduces; un-calibrated constructs are reported as
unknown, never guessed.

## Set up once

```
pip install vb6decompiler
```

Point the tool at your target; nothing is baked in:

```bash
export VB6D_TARGET=/opt/app/App.exe
export VB6D_LISTINGS=/work/decompile
export VB6D_FRM_DIR=/work/decompile
export VB6D_REPORT_DIR=/opt/app
```

## Pipeline — run in order, each stage says whether the next is worth running

```
vb6d pe          <install dir>        what the install is made of
vb6d procs       <app.exe> --validate objects, method counts, prologue-verified entry points
vb6d literals   <app.exe>            UTF-16LE BSTR literals with addresses (CSV)
vb6d stitch     <listing dir>        fragments joined into statements; open stays open
vb6d frm         <listing dir>       controls, geometry, arrays, SSTab pages
vb6d blob        <app.exe> --validate --frm-dir <frm dir>   geometry for forms with no .frm
vb6d datareport <install dir>        report sections from the report DLLs (and the exe)
vb6d mask       <out dir> --dry-run  credential audit before publishing anything
```

`procs` alone carries no addresses or names; they appear only after
`--names <listing dir>` merges a decompiler listing.

A second-opinion engine over that same validated list: `scripts/ghidra_bridge.py`
(run), `scripts/literal_visibility.py` (measure), `scripts/pseudoc_inventory.py`
(harvest: literal order, object+slot, ordered calls, branch conditions, the
unnamed-global census). What it cannot resolve is not a tool gap either: an
indirect call through an object global and an unnamed `DAT_x` are run-time facts,
so their answer is a trace, not a longer decompiler run.

## The contract, so you parse it right

- Discard `#`-prefixed lines before parsing stdout: footnotes, summaries and
  counts are comments. `--json` exists for `pe`, `procs`, `stitch`, `frm`,
  `blob` and `datareport`; `literals` is CSV by design.
- Exit codes: `0` = completed, whatever it found — a missing thing is a result,
  report it, do not retry; `1` = mask audit says not publishable; `2` = unusable
  input (one line on stderr, no traceback; `VB6D_DEBUG=1` re-raises for a bug
  report).
- Report every count with its denominator. Closed SQL is a lower bound:
  `OPEN_QUOTE` means a run-time value is missing and no smarter regex closes it.
- Procedure names do not exist in a native build: treat names as hints and
  prologue-verified addresses as the better fact.

## Traps that cost other people days

- A scanner reporting zero SQL on a VB6 binary may simply not read UTF-16LE.
- Three-state flags (`Visible`, `Locked`) have defaults that look like explicit
  values; `docs/pitfalls.md` lists each with its measurement.
- Trust blob geometry only as far as `--validate` calibration holds, per form.
- A P-Code build is outside calibration: if `procs --validate` finds no real
  prologues, suspect a P-Code compile before blaming the tool.
- Run `vb6d mask <out dir> --dry-run` before publishing run output; non-zero
  means sanitise first, not retry quietly.
- A generic decompiler prints `DAT_<addr>`, never the string, and may inline the
  text instead — "I searched for 0x… and found nothing" is not a verdict. Measure
  with `scripts/literal_visibility.py`, and cut the body with `--cut-marker` if the
  driver appended its own literal dump, which otherwise makes everything visible.

What each stage may claim and must never be used to claim: `docs/pipeline.md`.
Structures and grammars: `docs/formats.md`. Editing rules for the repository:
`AGENTS.md`.
