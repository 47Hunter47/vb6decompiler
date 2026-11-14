# What each tool actually did

Every row below was measured on the same file: a **111 MB, 32-bit, native-compiled
VB6 ERP executable** with a lost source tree, plus its 8 VB6 report DLLs. Nothing
here is a vendor claim; where a tool published a figure, the figure is quoted with
the reason it does not apply.

## Summary

| Tool | Forms | Procedure bodies | String literals | Form blobs | DataReports | Verdict |
|---|---|---|---|---|---|---|
| **Semi-VB-Decompiler** (OSS lifter) | 790 `.frm` | 30,898 bodies, all pseudo-source | via listing comments | no | no | the only free source of bodies; single-threaded; overflows at 32,767 procedures |
| **VBReFormer** (free tier) | structure + forms | withheld | partial | no | `.dsr` names only | cannot accept the 111 MB file at all |
| **Ghidra / Rizin / IDA** | no | yes (generic) | ASCII only | no | no | no VB6 structure; no `BSTR`, no form blobs |
| **Craft Anything 0.2.0** | no | 6,875 of 34,159 (20 %) | **59**, zero SQL | no | no | generic engine, correct for C/Rust/Go, blind to VB6 layout |
| **this toolkit** | 801 blobs + 790 `.frm` | 34,159 entries (listings) / 34,415 declared | 167,564 from the image | 801 | 437 designs | narrow, and it says where it stops |
| **VB Decompiler 26.6 Lite** (DotFix, free tier) | visual forms yes | **no** — Lite excludes code decompilation by design | disassembly only | no | no | engine accepts the 111 MB file; produced nothing the OSS toolchain had not already produced (details below) |

## Craft Anything 0.2.0 — full measurement

Run on the real target with `--deep`, a project folder, and its own release build
(`craft-anything-0.2.0-windows-x64-portable.zip`, SHA-256 verified against
`SHA256SUMS.txt`). Commands, verbatim:

```
craft-anything-cli doctor
craft-anything-cli --deep --project target.cany triage  TARGET.exe
craft-anything-cli --deep --project target.cany native-functions-list TARGET.exe --limit 5000
craft-anything-cli --deep --project target.cany native-strings-browse   TARGET.exe
craft-anything-cli --deep --project target.cany native-strings-find     TARGET.exe --pattern tOrder
craft-anything-cli --deep --project target.cany native-function-pseudocode TARGET.exe --function 0x163C730
```

| Measurement | Result | What it means |
|---|---|---|
| `triage` | PE, x86 32-bit, imports `MSVBVM60.DLL`, `stripped: true`, DLL list = 1 | correct, and identical to `vb6d pe` |
| `native-functions-list` | **6,875** functions; limitations: `instruction_limit` ("stopped after 6,000,000 instructions"), `functions_truncated` | its own output says the list is incomplete |
| overlap with the 34,159 VAs a decompiler listing gives | 6,865 shared, **10 not in our set**, 27,294 missing | 20.1 % coverage; the 10 extras are worth a look, not worth a workflow |
| sampled 200 procedures it missed | **199 start with `55 8B EC`** (the VB6 prologue) | they are real code, not padding |
| `native-strings-browse` | **59** strings, all from `.rsrc`, e.g. `"\nG#h\`"` | it scans data sections; this build keeps literals in `.text` |
| `native-strings-find --pattern tOrder` | **0** | the file contains that text **260 times** as UTF-16LE |
| `native-function-pseudocode 0x163C730` | register-level pseudo-C (`edi = 0; eax = *(uint32_t*)(…)`), `__vba*` helpers resolved | better than nothing for helpers, but not VB6 expression-level, and no `BSTR` text |

Why the string result matters: the executable has a 4 KB `.data` and a 106 MB
`.text`, and VB6 stores literals as UTF-16LE `BSTR`s inside `.text`. A scanner that
reads "data sections for ASCII" reports a fraction of a percent of the program's
text and none of its SQL.

What Craft Anything is genuinely good at, from the same run: `doctor` is honest
about missing engines, the evidence records carry confidence and limitation codes,
and the CLI/MCP split is a good pattern. Its `runtime_ui_*` (UI Automation) tools
are the one area that could matter for VB6 — driving a running app — but they were
verified upstream only against a WinForms window, and VB6 exposes controls through
an MSAA bridge whose `InvokePattern` behaviour is unproven.

## Semi-VB-Decompiler

* 790 `.frm` + 779 `.frx` + `.vbp` out of 802 declared objects.
* 30,898 `Sub/Function` bodies, **0 empty** in a completed run — but every body is
  pseudo-source: `var_64`, `arg_C`, `global_06DE02D4`. No names, no comments, no
  locals.
* Every body in a form is labelled with **one** event name (267 bodies called
  `FisButton_Click` in one form). Identity is the address in the trailing comment,
  never the name.
* Known ceilings, measured: `Error 6: Overflow` above 32,767 procedures (an
  `Integer` counter; patch to `Long` and rebuild), a ~2 GB address-space cap (the
  VB6 linker never sets `IMAGE_FILE_LARGE_ADDRESS_AWARE`; `scripts/semi_laa.py`
  flips the bit on a copy), single-threaded (CPU minutes == wall minutes), and an
  output folder that stays empty for ~13 CPU hours before writing everything at
  once.
* It **cannot** give you the procedure table, form geometry, or report layouts.

## VBReFormer

* Free tier returns forms, control names, handlers and SQL strings; expression
  bodies are `withheld` without a licence. Comments and private/local names never
  come back, at any tier.
* The reference executable is rejected by the vendor service (`transport_failed`,
  HTTP 413) — over 100 MB is out of scope. `>100 MB` cannot be worked around by
  waiting longer.
* Report layouts: `.vbp` manifests in its export name 413 `Designer=` entries but
  the export contains **0** `.frm` and **0** `Form=` — the form layer lives only in
  the executable.

## Generic RE suites

Ghidra, Rizin and IDA read the PE and disassemble it correctly, and are useful *as a
second opinion on one function*. None of them knows that:

* `MSVBVM60.DLL`'s 276 imports are the entire API surface (everything else is COM
  through vtable dispatch, so 131,460 call sites have no static target),
* a `BSTR` is length-prefixed UTF-16LE with no terminator,
* form definitions are serialised blobs with class-specific property tables,
* reports are `DataReport` blobs in sibling DLLs.

Using one on a VB6 target yields no names and no strings; what Ghidra *does* rebuild
is control flow, and that is measured below. Rizin and IDA were not run on this
target, so the row above is a capability statement for them, not a measurement.

### Ghidra 12.2 on the reference binary (measured: 1,395 procedures)

Local pilot: JDK 25 + Ghidra 12.2 + PyGhidra, auto-analysis off, procedure bounds and
names supplied by this toolkit's own inventory. Nothing leaves the machine.

* **1,369 of 1,395 targeted procedures decompiled** (26 failed) in two parallel
  workers: 5 h 43 min wall time, 13,107 s of decompiler time, average 9.6 s per
  solved procedure.
* Output: **626,845 pseudo-C lines** across 252 objects/modules — `if` 50,602,
  `else` 2,540, `while` 810, `goto` 2,747. That is **4.38 gotos per 1,000 lines
  against 35.1 per 1,000** for the same class of bodies from the VB6 front end:
  where the front end emits `GoTo loc_`, Ghidra rebuilds the branch.
* `for` loops: **0** across the whole corpus even with `setAnalyzeForLoops(True)`.
  Cause not established.
* Ceiling defaults are the lever, not the timeout: `maxPayloadMBytes=50`,
  `maxInstructions=100000`, default 30 s. Raising them to 128 MB / 20 M
  instructions turned the same 39-target set from 31/39 into 36/39; raising only
  the timeout to 900 s did not fix those failures.
* The scripts shipped in this repo were re-run over the same pseudo-C and reproduce
  the inventories exactly — 1,593 indirect-call slots, 167 branch conditions, 25
  parameter-bound rows, 2,254 unnamed globals — and the order/call tables differ
  only by definition (the SQL flag is whatever the caller's literal CSV says; call
  rows are aggregated per callee and keep the first line number).
* Literal visibility (address token **or** embedded text) over campaign slices:
  **1,816 / 3,099 (59 %)**; SQL-flagged literals **221 / 255 (87 %)** for procedures
  our graph attributes literals to. Ghidra prints `DAT_<addr>`, `PTR_DAT_<addr>`,
  `PTR_PTR_<addr>` and never the string itself; label/plate-comment APIs inside
  Ghidra were tried and produced no change in pseudo-C, so the text is attached at
  the text level while keeping the indirection prefix.
* Ghidra's own contribution to the click-chain gap is thin: of 1,062 chain
  procedures, only 281 have any literal attribution in our graph and none are
  SQL-flagged, and the call to the SQL-carrying helper is usually a vtable slot,
  which is not mapped to a procedure anywhere in our data. Ordered call edges in
  the recovered handlers match 60 chain handlers directly.
* Failure tail: 26 procedures — timeouts on the two largest modules and
  9 form-event handlers, 4 payload-ceiling cases, 1 `memory range beyond end of address
  space`. The tail dominates wall time (81 % of one worker slice), so extrapolating
  to all 34,159 procedures was not attempted.
* Ghidra 12.x requires **JDK 25** (`application.java.min=25`); JDK 17 and 21 are rejected by `LaunchSupport`.
* Driver side, in this repo: `scripts/ghidra_bridge.py` runs it over a `vb6d procs` target list,
  `scripts/literal_visibility.py` measures what its output actually shows, `scripts/pseudoc_inventory.py`
  harvests the inventories. The trap list is `docs/pitfalls.md`, "Running a second-opinion decompiler".
  rejected by `LaunchSupport`.

## VB Decompiler 26.6 Lite and VBScanner (DotFix / recovery-product family)

Measured locally in one headless session on the reference binary. Nothing here is a
vendor claim; vendor-scope statements quote the vendor's own Lite-scope page.

* Installer `vb_decompiler_lite.zip` (17.4 MB): Authenticode status `Valid`, signer
  `DotFix Software` (individual entrepreneur, Tula, RU). Silent install works.
* The engine **accepts the 111 MB file**: the app reaches ~316 MB private memory and
  populates its Project / Designer / Disassembler / HEX tabs from a command-line
  file argument — the transport failure above is a service-size limit, not a
  format limit.
* Lite's scope is disassembly plus form visuals by design ("code decompilation is
  not included" — vendor scope page), which is exactly the layer this toolkit and
  Semi already export. Re-running Lite produced **no new facts**.
* The app phones home to the vendor host over TLS at start-up. When that route is
  unavailable the start-up modal never resolves and the process exits — a headless
  run in a restricted network must expect this (measured twice).
* Registration facts, all measured on the same (genuine, signed) executable, which
  is also the binary a purchased key unlocks — there is no separate Pro download:
  the file is **packed** (`.text` virtual 8,648,472 bytes, raw 3,128,832, entropy
  7.94); a full-file scan finds **no** plaintext `registration`, `license` or
  `serial` string; it ships its own `libeay32/ssleay32` (in-process HTTPS); an
  unregistered install leaves **no** registry key and **no** license file anywhere.
  A keygen route must unpack ~8 MB of code before it can even find the check — and
  the vendor sells name-bound 1-PC activation, so the check may be server-side.
  No community keygen or crack release was found for this product line.
* UI Automation is unusable against this app from a console session:
  `ControlFromHandle` on the main window hangs (measured in both a service session
  and the interactive session), and `GetMenuItemInfoW` fails from a 64-bit caller
  against the 32-bit target. Reading its registration dialog needs a real
  interactive session with a human.
* `VBScanner` (the recovery product's free companion scanner; VB6, 65,536-byte
  executable) was driven to completion: folder set via `WM_SETTEXT`, buttons and
  checkboxes via centre-point mouse messages, scan produced a 10-row list — but the
  rows' text is unreadable from outside (`LVM_GETITEMTEXTW` returns 0 of the
  requested characters; UI A exposes the list as an empty pane): VB6 `ListView`
  is custom-drawn here. Its classification role duplicates `vb6d pe` on the same
  folder, so its verdict adds nothing; recorded as a measured-null row, not skipped.
