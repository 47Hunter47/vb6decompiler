# The pipeline, and what each stage is allowed to claim

A native VB6 program is recovered in layers. Each layer below states what it
produces, what it costs, and what it must never be used to claim. The counts are
from one real target (111 MB, 32-bit, 802 forms, 834 objects) so that the shape of
the problem is visible; they are not a promise about another program.

```
   binary ──► PE surface ──► object table ──► literals ──► statements
                  │              │              │              │
                  ▼              ▼              ▼              ▼
             dependencies   forms/modules   UI text, SQL   table writes
                  │              │
                  ▼              ▼
            form blobs ──► geometry for forms with no .frm
                  │
                  ▼
             report DLLs ──► DataReport layout
```

## 0. Inventory

`vb6d pe <install dir>` — which files are VB6, which are C++/ATL, which are system
DLLs shipped alongside. On the reference install: 36 binaries, 9 with VB6 code
(the executable, 8 report DLLs), 1 C++/ATL component, the rest redistributables.

*Costs:* seconds. *Claim it supports:* the executable imports one DLL
(`MSVBVM60`) and reaches the database through COM, so the import table describes
the runtime, not the program. An image whose section table claims bytes past
EOF gets `truncated: true` in its row: the headers of such a file parse, every
lookup past EOF returns nothing, and without the flag a cut-off VB6 build is
indistinguishable from a clean foreign file.

## 1. Object table

`vb6d procs <exe>` — the `VB5!` header chain: every form, module and class with its
method count. Reference: **834 objects / 34,415 declared methods** in 0.4 s.

*Does not give addresses* in a native build (see `pitfalls.md` §7). Addresses come
from a decompiler listing's `'VA` comments; `vb6d procs <exe> --names <listing dir>`
**counts** the listing's unique VAs (reference: 34,159, 208 of them also verifiable
directly as prologues) — the per-procedure name hints themselves are written by
`vb6d dossier` (§3b).
The gap between 34,415 declared and 34,159 found is designer-only members and
methods with no body — it is reported, not hidden.

*Claim it supports:* "this program has N forms and M methods". *Not:* "these are
all its entry points" — that needs the listing.

## 2. Literals

`vb6d literals <exe>` — every `BSTR` in the image. Reference: **167,564 literals in
4.6 s**, of which **6,171** carry a SQL verb and **257** are occurrences of a table
name that a generic ASCII scanner reported zero times.

From a listing: `vb6d literals <listing dir>` — 262k fragments with procedure
ownership, which is what makes stitching possible.

*Claim it supports:* "this text exists in this build at this address". *Not:* "this
query is executed" — a literal can be dead, and much SQL is assembled at run time.

## 3. Statements

`vb6d stitch <listing dir>` — join neighbouring fragments in a procedure and
classify. Every candidate row carries the owning procedure's listing VA
(`proc_va`) and the first fragment's address (`text_va`), so a published result
can be traced back to the build; both are empty when ownership is unknown.
Input is a listing directory: without a listing no literal carries a
procedure, so a bare executable yields no candidates — the stage says so on
stderr instead of failing silently (`literals <exe>` is the stage for binary
text). Reference measurement on the full listing corpus (**441,607 literals in
12,480 procedures**):

| Figure | Value |
|---|---|
| statement starts (a literal that opens with a verb) | **10,691** |
| starts that closed into a whole statement | **8,745**, in **4,109** procedures |
| tables named by those statements | **494** |
| most named | `tWorkOrder` 1,489 · `tItem` 687 · `tMaterial` 474 · `tInvoice` 426 · `tContact` 374 |

Why the remaining 1,946 starts did not close — this is the honest part, and each
reason names what would be needed:

| Reason | Count | What it needs |
|---|---|---|
| `OPEN_QUOTE` | 564 | a run-time value; only a live trace of the TDS traffic closes it |
| `STUCK` | 404 | a different neighbour; the continuation is not SQL |
| `ESCAPE` | 393 | reading: human text glued onto SQL |
| `MULTI` | 370 | splitting two statements that share one literal |
| `DANGLING` | 125 | one more fragment, or a trace |
| `OPEN_PAREN` | 90 | tail missing |

Statuses mean exactly this:

| Status | Meaning | What it needs |
|---|---|---|
| `CLOSED` | balanced, one statement, no glued message | nothing |
| `OPEN_QUOTE` | a value is concatenated at run time | a live trace of the TDS traffic |
| `OPEN_PAREN` | tail missing | a live trace |
| `MULTI` | two statements in one string | split, then re-evaluate |
| `DANGLING` | ends on a connector | another fragment, or a trace |
| `ESCAPE` | human text glued on | manual reading |
| `STUCK` | continuation is not SQL | different neighbour |

Numbers above were measured on 0.2.x. 0.3.0 corrected one classification: a whole
statement stored as a single literal no longer reports `STUCK` (it was asking about a
continuation that does not exist), so `CLOSED` on the same corpus is **higher** and the
`STUCK` row is **lower** than shown. Re-measure with `vb6d stitch` before quoting either.

*Claim it supports:* "these statements are complete". *Not:* "these are the
program's queries" — the closed set is a lower bound, always.

## 3b. Procedure dossiers

`vb6d dossier --listings <dir> [--out FILE] [--inventory DIR]` — everything the
stages above proved about **one procedure**, written as one JSON object per line
(JSONL): the literal texts in listing order, the SQL candidates with `CLOSED` kept
apart from every open bucket, the name hints with `"kind": "hint"`, and — when a
`python -m vb6decompiler.pseudoc_inventory` output directory is supplied — that procedure's
pseudo-C order, indirect calls, call list and branch conditions, merged by VA.

*Claim it supports:* "this is the evidence collected for procedure `X`".
*Not:* "this is procedure `X`'s source". Nothing in the record is compilable VB6,
no instruction is decoded, and a name in `name_hint` is whatever a decompiler
printed next to that address. Statically unresolvable object calls
(`(*DAT_x)[slot]`) keep their `DAT_x` token: the dossier never invents a target.
The summary prints "procedures with >=1 literal: X of Y" and
"procedures with >=1 closed SQL statement: X of Y", with Y counted before any
per-procedure failure, so the denominators survive a partial run.

**`vb6d decode <exe> --va HEX [--end-va HEX]` — milestone D's first layer, the
raw dump (needs the `[asm]` extra)** — it hands the engine only the section's
bytes on disk from that VA (clamped, and clamped again at `--end-va` when given)
and the result says how the decode ended: `ret` (the stream returned),
`limit` (the instruction cap hit), `exhausted` (every byte decoded, no `ret`
inside — for a procedure range that is the documented `body_bounds` gap
surfacing, not an error), `garbage` (with `stopped_at_va`, the first byte the
engine cannot express) or `no-bytes`. It claims instruction addresses, bytes,
mnemonics and operands only: nothing here is VB6 syntax, and the operands'
`0x…` immediates are the engine's own rendering (quoted text), while the
dump's own address fields stay bare uppercase hex. Each call whose target is
statically reachable is annotated against the file's own import table:
`target_va`, plus `target` as `dll!name` when the VA is an import slot —
bound import tables (VB6-era binders put live addresses in the slots) are
named through the ILT at the matching index, and `ordN` slots of the VB6
runtime are resolved via the shipped call table. Late-bound `call [reg+disp]`
targets stay unannotated because nothing static can name them, and the
stderr line states how many of the calls were named. With `--procs
<dossier.jsonl>` an in-image target that is not an import slot gets
`target_proc`: the dossier procedure whose reported range holds it —
attribution of a range, never a claim of identity. Missing engine: named
refusal, exit 2, install hint.

`vb6d edges <exe> --dossier <file>` is the same pass done once for the whole
corpus instead of one procedure at a time: it decodes every dossier range in
a single process and writes `edges.jsonl`, one row per procedure (even a
procedure with no decodable call gets a row — absence is a result). Each row
carries `calls_imported` (`dll!name` → count), `calls_procedures` (the owning
range's VA → count), `calls_late_bound`, and `ended`; the last range in the
file has no next VA, so it reads under a fixed cap and says
`range_capped: true`. The claim stays the range kind: these are calls *seen
in the range*, not assertions about who calls whom, and a fourth total —
targets below the first listed procedure VA — counts hits on code the
listings never enumerated (helpers with no entry of their own), which is
where a call graph's edges into unnamed territory become visible instead of
silent.

**Call order is measurable without a decompiler** — as a measurement, not a stage.
`scripts/t35_import_call_spike.py` decodes each procedure's own byte range with
capstone, resolves every call through the import address table (including a direct
call to a `jmp [slot]` thunk), and prints how often that order matches what a
decompiler listing says for the same procedure. On the reference build the answer is
"always the same calls in the same order, sometimes with extra calls at the end of
the range" — the extra ones are the documented `procs.body_bounds` gap: a range runs
to the next method-table entry and can contain a helper that has no entry of its own.
So if this is ever wired into a dossier, the field must read "calls seen in this
procedure's range", never "this procedure calls". The script needs capstone
(`pip install "vb6decompiler[asm]"`) and reports the DLL build behind any ordinal it
names.

When the inventory carried `vba_runtime` call rows, each record also gains
`runtime_calls`: the `MSVBVM60` helper name and its ordinal, read from the export
table of the DLL in `vb6decompiler/data/runtime_calls.json`, plus a category and
description that are a third party's notes and keep `"source": "unverified"` for
exactly that reason. An ordinal belongs to one runtime build; a different
`msvbvm60.dll` may number the same helper differently, so the table never presents an
ordinal as a fact about your build (`VB6D_MSVBVM60` re-checks it against yours).

A call the build imports **by ordinal alone** reaches the inventory spelled
`ord_598`, with no name at all. The dossier resolves it against that one DLL build
and marks the row `"source": "export-table ord — msvbvm60.dll <version> (sha256 …)"`,
so a reader can see the name is only valid for that build. An ordinal the build does
not export by name stays `ord_598` with null fields: reported unnamed, never guessed.

**Reading the dossier backwards: `vb6d xref <dossier.jsonl>`.** The dossier
answers "what is in this procedure"; questions usually start from the other
side — "which procedures touch this string / this SQL". xref inverts what the
dossier already wrote, so the answer is one command, not jq gymnastics:

* default: a procedure rollup ordered by literal mentions — who to look at first;
* `--literal SUBSTR` / `--sql SUBSTR`: the search direction — matches recovered
  text (case-insensitive) and answers with the owning procedure (VA, owner
  object, name hint); matching is on recovered text only, never on a guess;
* `--full`: both inverted indexes at once (literal VA → procedures, SQL text
  VA → procedures) — large output at reference-build sizes, hence opt-in.

A corrupt line in the dossier is counted on stderr and skipped, never a reason
to void the file — the builder's policy carried through.

## 3c. Project skeleton

`vb6d project <exe> [--out DIR]` writes a reconstructed project **directory**:
the object table's modules/classes/forms, one placeholder file per object, and
`recovery-report.json`. Structure is what this proves; text is not.

* `.vbp` listing order: VB6 compiles in `.vbp` order, so the object-table order
  is the closest evidence of the original sequence — labelled *inferred* in the
  report, never asserted as proven.
* Junk quarantine: native method entries usually decode to garbage (reference
  build: 626 readable entries, exactly **1** passes an identifier check). Only
  passing names reach the stubs, and a pass is recorded as shape evidence, not
  truth. `Startup=` is written only when a module has a readable `Main`; the
  reference build has none, so the line is a comment and the report lists it
  under gaps.
* `Type=Exe` is the file's only *assumption*, and it is carried as one in the
  report: the application type is not modelled from the object table.
* DataReport objects are runtime-only: counted in the report, never `.vbp`
  entries or files; their layouts are `vb6d datareport`'s job.
* Design records: form stubs embed the blob-recovered design in comment form —
  record offset and size (the binary stream stays in the exe, fetchable at that
  offset), the form extent, one line per control with type, caption, geometry,
  SSTab page or titles, and visibility only where the marker was read. A form
  with no parseable record is named in the gaps, never silently skipped.
* Reference-build measurement: 810 `.vbp` entries, 812 files written
  (802 forms / 7 modules / 1 class, plus `.vbp` + report), 801 of 802 forms
  designed (the one gap is a `.frm` named in the report),
  55,814 controls across design blocks, 625 of 626 method names
  quarantined as provable junk, startup unrecovered,
  full run on the 111 MB build in about 28 s. The exe is never
  touched; output lands in a sibling `<exe-name>_project` directory.

## 4. Forms

`vb6d frm <listing dir>` — `.frm` design blocks: controls, geometry in twips,
`Visible`/`Locked` in three states, control arrays, `SSTab` pages from nesting.
Reference: **802 files → 369 design blocks, 433 code-only stubs (listed, not
skipped), 0 failures**; 30,000 controls, 24,970 of them with written
Left/Top/Width/Height; **126 forms with control arrays, 1,165 groups / 14,268
elements** (49 groups with a non-contiguous `Index`); `SSTab`: 14 controls, 1,266
nested children, **0 page captions written** — those live in the `.frx` blob, so
pages are reported empty rather than guessed.

Extract: `vb6d blob <exe> --json` lists the forms with the geometry its record
parser already recovers — every control as name, type, caption, position, size,
array index, tri-state `Visible`, tab page.

`vb6d blob <exe> --validate --frm-dir <listing dir>` — geometry for the forms that
have **no** `.frm`. Reference: 801 blobs, **24,967/24,967 controls matched
(100 %)**, 367/369 forms fully matched (99.46 %), client size **368/368**,
`SSTab` members **1,258/1,258**, `Visible` **254/432 matched with 0 false
positives** (a class with no calibrated marker is left unknown, never guessed).
Two forms did not match and are named: one rebuilt after the design text (`formRec01`,
28 extra array elements in the compiled form), one with no blob at all (`modMain` is a
module, not a form).

*Claim it supports:* "these are the controls and their positions". *Not:* "this is
what a control does" — behaviour is not in the design or the blob.

## 5. Reports

`vb6d datareport <install dir>` — `DataReport` layouts from the report DLLs.
Reference: **437 designs** = 413 in the eight `rpt*.dll` files (94 + 80 + 68 + 56 +
54 + 33 + 18 + 10) **plus 24 embedded in the executable itself**. The 24 are not a
parser artefact: the VB6 object table independently reports exactly 24 objects of
type `0x1018083` (`datareport`), so a scan limited to `rpt*.dll` misses a whole
class of reports that ship inside the EXE.

Layout is sections, controls, captions and (partially) geometry; the data binding
(`DataField`) is assigned by class code and is **not** in the blob.

*Claim it supports:* "this report has these boxes in these sections". *Not:* "this
report computes this total" — the arithmetic lives in the DLL's compiled code.

## 6. What remains, always

* **Names.** Not recoverable from a native build. A decompiler's names are guesses;
  a listing's names are the designer's event names, which repeat.
* **Expression-level code.** Free lifters give register-level pseudo-source.
  Reconstructing VB semantics (`Variant`, `BSTR`, `On Error`, late binding) is
  research, not a build step.
* **Run-time flows.** Which control sends which value to which SQL parameter is
  only visible in a trace. A trace tool that hooks the VB6 runtime's string and
  socket functions is the honest next stage; static analysis stops at the boundary
  and this toolkit reports it as a boundary.
