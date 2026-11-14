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
the runtime, not the program.

## 1. Object table

`vb6d procs <exe>` — the `VB5!` header chain: every form, module and class with its
method count. Reference: **834 objects / 34,415 declared methods** in 0.4 s.

*Does not give addresses* in a native build (see `pitfalls.md` §7). Addresses come
from a decompiler listing's `'VA` comments: `vb6d procs <exe> --names <listing dir>`
merges them (reference: 34,159 unique VAs, 208 of them also verifiable directly).
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
classify. Reference measurement on the full listing corpus (**441,607 literals in
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

*Claim it supports:* "these statements are complete". *Not:* "these are the
program's queries" — the closed set is a lower bound, always.

## 4. Forms

`vb6d frm <listing dir>` — `.frm` design blocks: controls, geometry in twips,
`Visible`/`Locked` in three states, control arrays, `SSTab` pages from nesting.
Reference: **802 files → 369 design blocks, 433 code-only stubs (listed, not
skipped), 0 failures**; 30,000 controls, 24,970 of them with written
Left/Top/Width/Height; **126 forms with control arrays, 1,165 groups / 14,268
elements** (49 groups with a non-contiguous `Index`); `SSTab`: 14 controls, 1,266
nested children, **0 page captions written** — those live in the `.frx` blob, so
pages are reported empty rather than guessed.

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
