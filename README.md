# vb6decompiler

Recovering what a native-compiled VB6 program actually does, with evidence.

Commercial VB6 decompilers stop at one of two walls: they give you forms without
code, or code without the semantics that make it portable. This toolkit was built
while recovering a large native-compiled VB6 application (111 MB, ~34,000
procedures) whose source was lost. Every claim below is a measurement, and every
measurement has a command that reproduces it.

The point is not another disassembler. VB6 is not plain x86 at the level that
matters: strings are length-prefixed `BSTR`s stored inside `.text`, procedures are
entered through a fixed runtime prologue, most calls go through `MSVBVM60` vtable
dispatch, forms are serialised into the executable as binary property blobs, and
reports live in separate VB6 DLLs as `DataReport` blobs. Off-the-shelf tools read
none of that. These modules do.

Nothing here points at the program it was developed against: no target name, no
host, no database name, no account, no credential, no absolute install path.
**You supply every path.**

## What it does

| Stage | Command | Evidence it produces |
|---|---|---|
| PE surface of an install | `vb6d pe <dir>` | imports, exports, VB6 runtime dependency, ActiveX/COM classification |
| Procedure inventory | `vb6d procs <exe>` | object table: objects and method counts, entry points verified by prologue |
| String / SQL harvest | `vb6d literals <exe or listing dir>` | `BSTR` (UTF-16LE) literals the ASCII scanners miss, with code addresses |
| SQL reconstruction | `vb6d stitch <dir or listing>` | fragments joined into whole statements, with explicit "not provable statically" buckets |
| Form design | `vb6d frm <dir>` | controls, geometry, `Visible`, control arrays, `SSTab` pages from `.frm` text |
| Form geometry from binary | `vb6d blob <exe> --validate` | geometry for forms that have no `.frm`, calibrated against `.frm` ground truth |
| DataReport layout | `vb6d datareport <dll or dir>` | report sections, controls, captions recovered from the runtime blobs |
| Form icons from `.frx` | `scripts/frx_icon.py <frx dir> <out> [--validate <frm dir>]` | standalone `.ico` per form, extracted from the leading ICON record without the executable; coverage cross-checked against `.frm` Icon references |
| Second-opinion decompiler run | `scripts/ghidra_bridge.py --ghidra <dir> --bin <exe> --targets <csv> --out <dir>` | one pseudo-C file per procedure: our bounds and names, engine ceilings as flags, the JDK requirement read from the install before anything is imported |
| Literal visibility check | `scripts/literal_visibility.py --corpus <dir> --literals <csv> --out <csv>` | measured visible / catalogued per procedure — an address token (`DAT_`, `PTR_PTR_`) **or** inlined text counts, with a denominator instead of a hunch |
| Pseudo-C inventories | `scripts/pseudoc_inventory.py --corpus <dir> --out-dir <dir>` | literal order, indirect-call object+slot, ordered calls with line numbers, branch conditions, unnamed-global census |
| Credential gate | `vb6d mask <dir>` | files rewritten in place: connection strings redacted, then an audit counting what is still live |

The `scripts/` helpers are in the repository, not in the pip install — take a checkout
for those. The three Ghidra-side helpers additionally expect a **local** Ghidra install
and `pip install pyghidra`; the library and the `vb6d` CLI stay standard-library only.

## You fill these in

Every entry point takes a path; nothing is baked in. Real-target tests read five
variables and skip when they are unset.

| Variable | What you put in it |
|---|---|
| `VB6D_TARGET` | your VB6 executable, e.g. `D:/App/App.exe` or `/opt/app/App.exe` |
| `VB6D_LISTINGS` | a directory of decompiler output: listing text carrying `'VA` address comments (the shape `docs/formats.md` §4 reads), plus `.frm` and `.frx` files |
| `VB6D_FRM_DIR` | a directory holding `.frm` design text — ground truth for `--validate` |
| `VB6D_REPORT_DIR` | the install directory holding the report DLLs |
| `VB6D_SCRUB_DENYLIST` | optional: a private file, one name per line — names you refuse to publish. The hygiene test fails if any of them appears in this repository. |

Set them for one command, or export them for a session:

```bash
# bash / zsh
export VB6D_TARGET="/opt/app/App.exe"
export VB6D_LISTINGS="$HOME/work/decompile"
export VB6D_FRM_DIR="$HOME/work/decompile"
export VB6D_REPORT_DIR="/opt/app"
```

```powershell
# PowerShell
$env:VB6D_TARGET     = "D:/App/App.exe"
$env:VB6D_LISTINGS   = "D:/work/decompile"
$env:VB6D_FRM_DIR    = "D:/work/decompile"
$env:VB6D_REPORT_DIR = "D:/App"
```

## Why not an existing tool

Measured on the same target (`docs/tool-matrix.md` has the full table, including
how each number was obtained):

* **Semi-VB-Decompiler** — the only free tool that recovers procedure *bodies*. It
  is single-threaded, overflows its `Integer` procedure counter above 32,767
  procedures (`Error 6`), needs a PE `LAA` bit patch to use more than 2 GB, and
  writes one event name for every body in a form. Bodies are pseudo-source
  (`var_64`, `arg_C`), not compilable code.
* **VBReFormer** — forms and structure, expression bodies withheld without a
  licence; cannot even accept the 111 MB executable (transport limit).
* **Ghidra / Rizin / IDA** — no VB6 knowledge: no `BSTR` literals, no procedure
  table, no form blobs, no `DataReport` blobs.
* **Generic RE engines** — correct for C/C++/Rust/Go, blind to VB6 layout. One such
  engine found 6,875 functions of 34,159 (20 %, stopped at its own instruction cap)
  and 59 strings with zero SQL, because its string scanner does not read UTF-16LE
  literals.

None of these is wrong; they are aimed at C/C++/Rust/Go binaries. The gap this
repository fills is VB6-specific structure, and it fills it with reproducible
counts rather than vendor percentages.

## Install

```
pip install vb6decompiler
```

Or work from a checkout:

```
git clone <this repo> && cd vb6decompiler
python -m pip install -e .
```

Python 3.11+. **Nothing outside the standard library is required** — every parser
here is hand-written, which is the point (a library wrapper would hide the layout).
`pefile` and `capstone` are optional and used only as a second opinion while
developing:

```
python -m pip install -e ".[pe,asm]"
```

## Coding agents

The repository ships as a plugin for coding agents as well as a pip package, so
an agent can drive `vb6d` without a tutorial:

```
claude plugin marketplace add 47Hunter47/vb6decompiler
claude plugin install vb6decompiler@vb6decompiler
```

One skill lives at `.agents/skills/vb6decompiler/SKILL.md` — the location both
Claude Code and Codex read — and says when the tool applies, how to parse its
output and which traps to avoid; the plugin manifests point at that single copy.
Agents editing the repository itself follow `AGENTS.md`.

## Quick start

```
vb6d pe            <install dir>                 # what is this install made of
vb6d procs         <app.exe>                     # object table: objects, method counts
vb6d procs         <app.exe> --validate          # are the entry points real prologues
vb6d procs         <app.exe> --names <listing dir> # attach decompiler names/addresses
vb6d literals      <app.exe>                     # BSTR/UTF-16 literals with addresses
vb6d literals      <listing dir> --sql-only      # literals a decompiler listing produced
vb6d stitch        <listing dir>                 # join fragments, classify what stayed open
vb6d frm           <listing dir>                 # .frm controls, geometry, arrays, SSTab
vb6d blob          <app.exe> --validate --frm-dir <frm dir>
vb6d datareport    <install dir>                 # report layouts from the report DLLs
vb6d mask          .                             # mask credentials in your artefacts
vb6d mask          . --dry-run                   # report only; exit 1 if anything is live
```

Exit codes: 0 = completed, whatever it found; 1 = mask audit not clean; 2 =
unusable input (one line on stderr, no traceback — set `VB6D_DEBUG=1` for the
traceback when reporting a bug).

What the reference build (111 MB, 802 forms) produced while this toolkit was
developed, so you can tell at a glance whether your own numbers look sane:

| Stage | Result |
|---|---|
| object table | 834 objects, 34,415 methods, 0.4 s |
| literals from the image | 167,564 in 4.6 s (6,171 with a SQL verb) |
| literals from a listing | 441,607 in 12,480 procedures |
| statements | 10,691 starts → 8,745 closed in 4,109 procedures, 494 tables |
| `.frm` design | 369 forms, 30,000 controls, 126 forms with control arrays |
| form blobs | 801 blobs, 24,967/24,967 controls (100 %), 367/369 forms |
| DataReports | 437 layouts (413 in report DLLs + 24 embedded in the executable) |

A different program legitimately gives different numbers. The tests assert
invariants and lower bounds, not these totals.

## Using it well

Run the stages in pipeline order; each one tells you whether the next is worth
running. `docs/pipeline.md` states what every stage may claim and what it must
never be used to claim.

1. `vb6d pe <install dir>` first. It costs seconds and says what you have: which
   binaries carry VB6 code, which are redistributables, where the report DLLs are.
2. `vb6d procs`, then `--validate` before trusting anything downstream. Method
   counts are cheap; entry points proven by their runtime prologue are evidence.
   Addresses and names only exist once a decompiler listing is merged in with
   `--names`.
3. `vb6d literals` on the executable gives UTF-16 text with addresses; on a
   listing it gives procedure ownership, and that ownership is what makes
   `vb6d stitch` possible at all.
4. `vb6d stitch` reports what stayed open as open. The gap buckets are not noise:
   `OPEN_QUOTE` means a run-time value is missing, and no smarter regex closes
   it.
5. `vb6d frm` reads the design text; `vb6d blob --validate` calibrates the binary
   reader against it. Trust blob geometry for forms that have no `.frm` exactly
   as far as that calibration holds.
6. Count embedded reports when you run `vb6d datareport`. A scan limited to
   `rpt*.dll` misses 24 of the 437 layouts the reference build carries inside its
   own executable.
7. `vb6d mask . --dry-run` before sharing anything you produced. A non-zero exit
   means the artefacts are not publishable, not that you should retry quietly.

Things that cost days to learn:

* Procedure names do not exist in a native build. A decompiler's names are
  guesses and `.frm` event names repeat; treat every name as a hint and every
  prologue-verified address as the better fact.
* If a string scanner reports zero SQL on a VB6 binary, ask whether it reads
  UTF-16LE at all. One engine reported 59 strings and zero SQL on a build that
  holds 167,564 `BSTR` literals, 6,171 of them with a SQL verb.
* Compare shapes, not totals: literals per procedure, closed versus open
  statements, controls per form. Totals scale with the program; the tests assert
  invariants for the same reason.
* When a free decompiler refuses a large executable, run `scripts/semi_laa.py`
  on a copy. The Large Address Aware bit is a property of the file, not of the
  tool's competence.
* Three-state flags such as `Visible` and `Locked` have defaults that look like
  explicit values, and `docs/pitfalls.md` lists that class of trap with the
  measurement that proved each one.

## Honest limits

* Procedure **names** are not recoverable from a native build; only addresses and
  the names a decompiler guessed.
* Bodies recovered by a third-party decompiler are pseudo-source. Expression-level
  fidelity does not exist in any free tool measured here.
* SQL that is built at run time (concatenated from variables) cannot be closed
  statically. `vb6d stitch` reports those gaps as gaps instead of guessing.
* An indirect call through an object global (`(*DAT_x)[slot]`) has no statically
  resolvable target either: the bytes stored at such a global are 0 or a small
  non-address token, never a vtable pointer, and a VB6 symbol record carries no
  name for the global. `scripts/pseudoc_inventory.py` counts them and ranks them
  for a run-time trace; nothing in this repo closes them statically.
* Geometry recovered from the binary is calibrated, not exact for forms that
  changed after the `.frm` in hand was written; `--validate` says so per form.
* The toolkit is calibrated on native-compiled builds; a P-Code build is outside
  that calibration and was not tested here. If `vb6d procs --validate` reports no
  real prologues in your build, suspect a P-Code compile before suspecting the
  toolkit.
* The parsers know the grammar of the reference build. Another program ships
  different controls, property sets and report sections, so expect more `unknown`
  lines than the reference numbers show. An un-calibrated construct is reported as
  unknown, never guessed (`docs/formats.md` §7), and no stage drops a file
  silently: failures are counted and named.

## Layout

```
vb6decompiler/     the library (one module per stage, stdlib only except pefile/capstone)
scripts/          standalone helpers (semi_laa.py: set the LAA bit on a copy;
                  frx_icon.py: extract the leading ICON record of a .frx;
                  win32_gui_probe.py: drive vendor GUI tools headlessly when the
                  measurement only exists in a window; ghidra_bridge.py + 
                  literal_visibility.py + pseudoc_inventory.py: run a generic
                  decompiler over a validated procedure list, measure what its
                  output actually shows, and harvest order/slot/call inventories)
tests/            unit tests + target tests that skip unless VB6D_TARGET is set
docs/             formats.md (structures), pitfalls.md (traps), tool-matrix.md,
                  pipeline.md (stages and what each may claim), RULES.md
.agents/skills/   the vb6decompiler skill — what a coding agent installs
.claude-plugin/   Claude Code plugin + marketplace manifests (skills point at it)
.codex-plugin/    Codex plugin manifest (same single skill copy)
```

Run the tests:

```
pip install -e ".[dev]"
pytest -q                                            # unit tests, no target needed
VB6D_TARGET="C:/path/App.exe" pytest -q              # + real-target invariants
VB6D_LISTINGS="C:/path/decompile" pytest -q          # + listing/stitching tests
VB6D_FRM_DIR="C:/path/decompile" pytest -q           # + blob calibration
VB6D_REPORT_DIR="C:/path/install" pytest -q          # + DataReport parsing
VB6D_SCRUB_DENYLIST="C:/path/names.txt" pytest -q    # + scan for your target own names
```

The hygiene test needs no target: it looks for private addresses, home paths, e-mail and
UNC shares, and it adds a name scan only when you point `VB6D_SCRUB_DENYLIST` at a list
kept **outside** the repository (the names are yours, they do not belong in public).

`docs/formats.md` is the structure reference: every offset, every grammar, and the
fields that look documented but are not what they claim (`lpMethods` in a native
build, `lpGuiTable`). `docs/pitfalls.md` is the second most useful file: it lists
the traps that cost days (double-`Integer` overflow, `OriginalFirstThunk` vs
`FirstThunk`, CP1254 vs UTF-16, `Visible` defaults, blob property sorting) with the
measurement that
proved each one.

## Licence

MIT. See `LICENSE`.
