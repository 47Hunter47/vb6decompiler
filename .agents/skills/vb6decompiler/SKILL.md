---
name: vb6decompiler
description: Recover what a native-compiled Visual Basic 6 program actually does when its source is lost: prologue-verified procedure table, BSTR/UTF-16 literal and SQL harvest, SQL statement stitching, .frm design text, binary form geometry, DataReport layouts, per-procedure evidence dossiers, credential mask before publishing. Use when the target is a VB6 native executable or report DLL (MSVBVM60). Skip for P-Code builds, for projects that still have their source, and for non-VB6 binaries.
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

Optional, when the question needs them: `VB6D_ENCODING` (code page of the text —
see "Text and code pages"), `VB6D_MSVBVM60` (re-check the shipped runtime call
table against your own DLL), `VB6D_SCRUB_DENYLIST` (names that must never appear
in published artefacts).

## Pipeline — run in order, each stage says whether the next is worth running

```
vb6d pe          <install dir>        what the install is made of
vb6d procs       <app.exe> --validate objects, method counts, prologue-verified entry points
vb6d literals    <app.exe>            UTF-16LE BSTR literals with addresses (CSV)
vb6d stitch      <listing dir>        fragments joined into statements; open stays open
vb6d frm         <listing dir>        controls, geometry, arrays, SSTab pages
vb6d blob        <app.exe> --validate --frm-dir <frm dir>   geometry for forms with no .frm
vb6d datareport  <install dir>        report sections from the report DLLs (and the exe)
vb6d dossier     --listings <dir>     one JSON object per procedure: literals in order,
                                      SQL closed vs open, name hints, runtime calls
vb6d xref        <dossier.jsonl>      read the dossier back: which procedures mention a
                                      string or SQL fragment (--literal/--sql SUBSTR),
                                      rollup ordered by literal count, --full double index
vb6d decode      <app.exe> --va HEX   instruction dump [asm]: bytes, mnemonic, operands,
                                      an explicit `ended` field; call targets named from
                                      the file's import table; --end-va limits to one body;
                                      --procs <dossier.jsonl> attributes in-image targets
vb6d edges       <app.exe> --dossier <dossier.jsonl>
                                      one pass over every procedure range -> edges.jsonl:
                                      imported / thunk / procedure-range / object / other +
                                      late-bound counts; --events adds the ordered stream
vb6d outline     <edges.jsonl>        operations outline via the runtime table:
                                      unverified_operations, api_calls, runtime_unlisted
vb6d project     <app.exe>            project skeleton: .vbp + design-record placeholder
                                      files + recovery-report.json (structure, not source)
vb6d mask        <out dir> --dry-run  credential audit before publishing anything
```

`decode` and `edges` need the `[asm]` extra (`pip install "vb6decompiler[asm]"`); without
the engine they exit `2` with an install hint, never a traceback. `outline` reads
`edges.jsonl` with no engine. `edges --events` is opt-in and large; event text is raw, so
an events file goes through `mask` before it leaves the machine.

`procs` alone carries no addresses or names; they appear only after
`--names <listing dir>` merges a decompiler listing.

`dossier` is the stage for *re-specifying* a lost application rather than reading
one screen: per procedure VA it collects what the other stages proved. It is
evidence, not source — nothing in it is compilable VB6. `--inventory <dir>`
merges the pseudo-C harvest below, by VA.

Helpers that ship in the package, so a pip install has them (a checkout also runs
them as `python scripts/<name>.py`):

```
python -m vb6decompiler.pseudoc_inventory    literal order, object+slot, ordered calls,
                                             branch conditions, unnamed-global census
python -m vb6decompiler.literal_visibility   what a decompiler output actually shows
python -m vb6decompiler.frx_icon             standalone .ico per form, from the .frx
python -m vb6decompiler.semi_laa             set the Large Address Aware bit on a copy
```

The two that need something else stay in `scripts/`: `ghidra_bridge.py` (a local
Ghidra install plus `pip install pyghidra`) and `win32_gui_probe.py` (a Windows
GUI).

An indirect call through an object global, and an unnamed `DAT_x`, are run-time
facts: the answer is a trace, not a longer decompiler run.

## The contract, so you parse it right

- Discard `#`-prefixed lines before parsing stdout: footnotes, summaries and
  counts are comments. `--json` exists for `pe`, `procs`, `stitch`, `frm`, `blob`
  and `datareport`; `dossier` writes JSONL; `literals` is CSV by design.
- Exit codes: `0` = completed, whatever it found — a missing thing is a result,
  report it, do not retry; `1` = mask audit says not publishable; `2` = unusable
  input (one line on stderr, no traceback; `VB6D_DEBUG=1` re-raises for a bug
  report).
- Report every count with its denominator. Closed SQL is a lower bound:
  `OPEN_QUOTE` means a run-time value is missing and no smarter regex closes it.
- Procedure names do not exist in a native build: treat names as hints and
  prologue-verified addresses as the better fact. `dossier` labels them `hint` for
  that reason.
- A runtime call *description* in a dossier is a third party's note marked
  `unverified`. Only the name and ordinal were read from an export table, and an
  ordinal belongs to one runtime build.

## Text and code pages

VB6 stores text in the ANSI code page of the machine that **compiled** the
project. The order is `--encoding CODEPAGE` > `VB6D_ENCODING` > the build's header
LCID > `cp1254`, and every text-decoding stage prints its choice once on stderr as
`# encoding: cp1251 (lcid)`.

- The header LCID records the *developer's* language, not the compiler's code
  page; they usually agree and occasionally do not, which is why a flag outranks
  it.
- Only single-byte ANSI pages are accepted (CP874, CP1250–CP1258). A double-byte
  page (CP932/936/949/950) or UTF-8 exits `2`: the parsers map a character offset
  back onto the byte it came from, and that identity is false for a
  variable-width encoding.
- Captions showing `U+FFFD` after decoding mean the code page is wrong, not that
  the file is damaged; `vb6d frm` counts them for exactly that reason.

## Traps that cost other people days

- A scanner reporting zero SQL on a VB6 binary may simply not read UTF-16LE.
- Three-state flags (`Visible`, `Locked`) have defaults that look like explicit
  values; `docs/pitfalls.md` lists each with its measurement.
- Trust blob geometry only as far as `--validate` calibration holds, per form.
- A P-Code build is outside calibration. `procs --validate` says "0 of N entries
  start with a native prologue; this build may be P-Code (not verified)" when
  that is what it measured — a suspicion, never a detection, because no P-Code
  build has been measured here.
- Run `vb6d mask <out dir> --dry-run` before publishing run output; non-zero
  means sanitise first, not retry quietly.
- A generic decompiler prints `DAT_<addr>`, never the string, and may inline the
  text instead — "I searched for 0x… and found nothing" is not a verdict. Measure
  with `python -m vb6decompiler.literal_visibility`, and cut the body with
  `--cut-marker` if the driver appended its own literal dump, which otherwise
  makes everything visible.
- A procedure's byte range runs to the next method-table entry, so it can contain
  a helper that has no entry of its own. Anything derived from a range says "seen
  in this range", not "belongs to this procedure".

What each stage may claim and must never be used to claim: `docs/pipeline.md`.
Structures and grammars: `docs/formats.md`. Editing rules for the repository:
`AGENTS.md`.
