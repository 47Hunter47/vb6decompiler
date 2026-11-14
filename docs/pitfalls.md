# Traps that cost days

Each entry is a measurement, not advice. The numbers come from a 111 MB native VB6
build (32-bit, 802 forms, 834 declared objects) unless stated otherwise. They are
kept here because every one of them produced a *plausible wrong answer* first.

## Reading the binary

**1. `.data` is not where VB6 puts strings.**
`.text` 106 MB, `.data` 4 KB, `.rsrc` 8 KB. A scanner limited to data sections
reported 59 strings (all `.rsrc` noise) and zero of the 260 occurrences of a table
name that the file really contains. Scan every executable section.

**2. A `BSTR` is not a C string.**
4-byte byte-length prefix, UTF-16LE text, then a NUL. No ASCII, no terminator
convention. Check the prefix (`declared == 2 × chars`) — that check is what
separates a literal from a coincidence.

**3. Turkish letters break the "high byte is zero" rule.**
`ş`, `ğ`, `İ` are UTF-16 code units above 0x7F. A rule that requires `data[i+1] == 0`
splits any string carrying them into pieces and silently loses the SQL around it. Decode
the pair as a code unit and test the character.

**4. Decode both alignments.**
A literal does not have to start on a 2-byte boundary; one odd-length neighbour
shifts everything after it. Two passes (offset 0 and 1) cost 5 seconds on 111 MB.

**5. Walk both thunk arrays.**
In an import descriptor, `OriginalFirstThunk` and `FirstThunk` are different
ranges. Naming only one left every `call dword ptr [0x40xxxx]` anonymous: named
call sites went from ~135k to ~267k when both were walked.

**6. Do not hand-roll the export table.**
A hand-written reader reported `NumberOfFunctions ≈ 761,000` for a 1 MB OCX. The
same file via `pefile` had 4 exports. Bound the count, and compare against a
trusted reader before believing an export list.

**7. The VB6 header gives counts, not addresses.**
`VB5!` → `ProjectInfo` → `ObjectTable` yields 834 objects and 34,415 declared
methods in 0.4 s. In this build the `ObjectInfo` block's documented `lpMethods`
slot holds small integers (0x4, 0x7), not entry points: accepting them produced
208 "procedures" of which 0 started with `55 8B EC`. Verify a prologue before
calling a pointer a procedure.

**8. `fObjectType` is not a small enum.**
Measured values in one build: `0x18001` module, `0x18083` form, `0x118003` class,
`0x1018083` DataReport. A bit-mask guess mislabels all of them; print unknown
values as hex.

**9. The String literal is loaded with `mov` far more often than `push`.**
A scanner matching `push <addr> ; "text"` missed **170,645** literals — 170,555 of
them were `mov`. Match any instruction's trailing `; "…"` comment.

**9a. In a listing, match the procedure header before filtering for comments.**
`Private Sub FisButton_Click() '15F6040` contains no `;`, so a "skip lines without
a literal comment" filter placed above the header match discards every header. The
literals still parse — 441,607 of them — and every one has `proc_va = None`, so
stitching produces zero chains and the run looks like "this corpus has no SQL".
Check headers first, then filter.

**10. `lit.addr` is the address of the text, not of the instruction.**
Sorting fragments by it approximates program order and is not proof of order.
Statement order needs a control-flow pass (capstone) or a live trace.

## Reconstructing statements

**11. A verb inside quotes is not a verb.**
`WHERE X = 'UPDATE t SET …'` is one statement assigning a string. Counting verbs
without tracking quote state doubled the statement count and produced "61 closed
statements" of which 35 were two glued together.

**11a. `\b` misses a verb that follows a digit.**
VB6 concatenates data straight onto SQL, so the text reads `…ProcA1001SELECT
ContactKey…`. Between `2` and `S` there is no word boundary, so `\bselect\b` finds only
the *second* SELECT and a two-statement join is reported CLOSED. Match after
`[^A-Za-z_]`, not after `\b`. Measured: 1 statement reported where there were 2.

**11b. A join may only start where a statement can start.**
Stitching from every fragment produces thousands of perfectly balanced
mid-expression joins (`AltStockCode' AND AltStockType = '…'`) that pass every other
gate. Require the *first* fragment to open with SELECT/INSERT/UPDATE/DELETE. This
one gate changed 4,629 "closed" candidates into 8,745 real statements out of
10,691 honest starts.

**11c. A word after `from`/`into`/`update` is not always a table.**
217 of the reference corpus's "tables" were named `where`. Keep a keyword deny-list
and print it, rather than letting it into the table inventory.

**12. Glued statements are the normal failure, not the exception.**
`update tOrder$ set HOrderDep = Null WHERE … = '00.00.0000' update tOrder$ set
HOrderTerm = Null …` is two statements in one string. Splitting them and evaluating
each separately kept 47 correct statements that a whole-string check rejected.

**13. An open quote usually means a run-time value, not a missing literal.**
699 of 1,273 candidates ended inside a quote. Those need a trace; filling them in
is fabrication. Report `RUNTIME_GAP` and move on.

**14. Human text glued to SQL looks like SQL.**
`'…'Not found!`, `)01.01.2026`, `!?` inside a fragment. Without an escape detector
these enter the inventory and later appear as "recovered queries".

## Forms

**15. `.frm` writes only non-default properties.**
A `TextBox` with no `Locked` line is editable; no `Visible` line means visible.
Measured on 6,278 text boxes: 353 `Locked=-1`, 97 `Locked=0`, **5,828 with no line
at all**. Count three states (true / false / absent), never two.

**16. Nothing is data-bound at design time.**
`DataField` / `DataSource` / `DataBound` appear in **zero** controls. The field ↔
table mapping must come from the SQL in the code, not from control properties.

**17. Control names do not identify columns.**
Of 424 input controls, 6 (1.4 %) had a name equal to a column name; every one of
those was a `Label`. Names are positional (`txtCode1..8`, `Column1..n`, `Marker1..n`).
`Tag` carries flags (`"R"`), not column names (540 tags, 0 matches).

**18. Control arrays must be grouped by (type, name, Index).**
Merging `Sutun1..Sutun12` into one control destroys the grid layout and the
per-cell handler wiring.

**19. `SSTab` page membership comes from nesting, not from a property.**
A child control belongs to the tab it is declared inside; the tab's own `Tab = n`
only says which page is selected at design time. Measured on the reference
listing: 14 `SSTab` controls hold **1,266** nested children, and **0** files write
`TabCaption(n)` or `Tab =` — page captions are in the `.frx` blob, not the `.frm`.
Report pages as empty instead of inventing titles. In the compiled form the same
membership is recoverable: the blob parser matches **1,258/1,258** members with no
false positives.

## Form blobs (geometry without `.frm`)

**20. The blob is a serialised property tree, not a fixed struct.**
Record header `<size:int32><idx:uint8><namelen:uint16><name>0x00<class:uint8>`, then
`<pid:uint8><value>` pairs whose types depend on the class's property table. A
fixed-offset reader works on one form and fails on the next.

**21. Control arrays set bit 31 of the size field.**
`size | 0x80000000`, followed by `<idx:uint8><index:uint16>` before the name. Miss
it and the record length is nonsense and the whole rest of the blob desynchronises.

**22. Geometry is 4 × int16 with a class-specific property id, or 4 × int32 when a
coordinate exceeds 32767.**
One property, two encodings. The class→pid table must be calibrated against real
`.frm` text, and `--validate` must re-run that calibration on every release.

**23. One blob can hold several form objects.**
Class `0x0D` opens a new segment. Splitting on the first segment only gave one
form per blob and silently dropped the rest.

**24. Calibration is the only proof.**
Result on the reference target: 24,967/24,967 controls matched on type and
Left/Top/Width/Height (100 %), 367/369 forms fully matched (99.46 %), client size
368/368. The two mismatches are a form rebuilt after the `.frm` in hand and one
form with no blob at all (`modMain`) — both named in the output, not averaged away.
The client rect was the last thing to become exact: pid `0x35` is
`(ClientLeft, ClientTop, ClientWidth, ClientHeight)`, and reading it as a block
length followed by three values rejected every form whose client origin was large
(360/368) while looking entirely plausible.

## DataReport blobs (reports)

**25. DataReport strings are `len32 + UTF-16LE` — the form blob's `len16 + CP1254`
is wrong here.**
The two blob families look alike and are not alike.

**26. Scan byte-by-byte.**
A 4-byte stride loses alignment on every odd-length string, and after that every
"string" is read as an integer. This one silently produced a plausible-looking but
wrong control list.

**27. VB6 does not serialise properties equal to the default.**
So a record can be `(L, W, H, X)` — no `Top` — or `(L, H≈225, X, Y)` — no `Top`,
no `Width`. The `150..300` / `1..4` separators are measured heuristics, and inferred
values must be labelled `T_cikarim`, never presented as read values.

**28. Section ownership is positional.**
A control belongs to the last section record before it: `Section1`=Detail,
`Section2`=PageHeader, `Section3`=PageFooter. Gate: 100 % of data boxes
(`txt*`/`Text*`) must land in Detail.

**29. Join on `design|dll`, not on `design`.**
Six design names appear in two DLLs with different evidence; a name-keyed dict
silently overwrites one and keeps the other.

**30. `DataField` is not in the blob.**
It is assigned at run time from class code. Layout is blob ∪ code evidence; layout
alone is not a report spec.

## Secrets

**31. Connection strings are plain text in the binary.**
250 literal connection strings with `uid=`/`pwd=` in the reference build. Mask
before writing anything.

**32. A masking regex written with `\s` crosses newlines.**
When a literal ends with `Server=`, `\s` swallows the line break and masks the first
word of the next line — corrupting the artefact and producing a false count.
Counted 211 findings against 92 real ones. Use `[ \t]`, and compare line counts
before and after writing.

**33. Keyword presence is not a leak.**
Fragments like `;uid=` carry no value. Count *values*; otherwise every audit is
noise and nobody reads it.

## Working method

**34. A parser without a validation gate is not finished.**
Every binary or blob parser in this repository has a `--validate` that compares
against ground truth and prints coverage with its denominator.

**35. Absence is not proof.**
"0 strings" meant "the scanner looked in the wrong section". "Function not found"
meant "recursive descent stopped". Output text in this toolkit says which one it is.

## Driving vendor GUI tools headlessly

Vendor RE tools are usually GUI-only. These are the walls hit while driving two of
them (a Delphi/VCL decompiler and a VB6 scanner) from a console session; each one
cost a blind run before it was understood. `scripts/win32_gui_probe.py` encodes the
workarounds.

**36. Window-class search breaks on Delphi/VCL tools.** The class name is random per
process; search by title (`list --title ...`), never by class. A service-session run
also leaves every window `IsWindowVisible = False` — visible-in-name only; synthesis
targeted at station 0 goes nowhere, run the driver in the interactive session.

**37. VB6 OCX controls swallow `BM_CLICK`.** Buttons and checkboxes toggle on a
centre-point `WM_LBUTTONDOWN` + `WM_LBUTTONUP` pair (`SendMessage`), not on
`BM_CLICK`. And their `BM_GETCHECK` reads 0 whatever the control shows — checkbox
state is not externally readable; verify a tick **by its effect** (the list fills,
the scan starts), never by state.

**38. VB6 ListView rows are custom-drawn.** `LVM_GETITEMCOUNT` works,
`LVM_GETITEMTEXTW` returns 0 of the requested characters, and UI Automation reports
an empty pane. Treat row text as unreadable; count rows only, and pick tools whose
output has a machine-readable path.

**39. UI Automation hangs where lists are huge.** Connecting to a window whose panes
hold tens of thousands of virtualized items can hang the walk (measured: never
returned inside 3 minutes, twice). Raw messages with the target's own struct layout
are the reliable channel. For cross-process item text: `VirtualAllocEx` takes a
**handle** (mask needs `PROCESS_VM_OPERATION`) not a pid; `cchTextMax` counts
**WCHARs**, reserve twice the bytes; build the `LVITEM` with the **target's**
pointer size (a 64-bit driver against a 32-bit target uses 4-byte pointers, and
`pszText` must be 8-aligned there).

**40. Menu APIs are a cross-bitness trap.** `GetMenuItemInfoW` fails from a 64-bit
caller against a 32-bit target (returns false; the struct is the target's). Menus
are UIA's job (pitfall 39 makes that hard for this app class) — plan GUI dialog
reading as an interactive-session task, not a headless one.

**41. Enumeration callbacks must swallow their own exceptions.** One raise inside
one `EnumWindows`/`EnumChildWindows` callback aborts the whole sweep and the driver
concludes "no windows exist" — the classic blind run. And `GetWindowThreadProcessId`
lookup on `kernel32` fails in some ctypes setups; fall back, don't crash.

## Running a second-opinion decompiler (Ghidra / PyGhidra)

**42. The JDK requirement is written in the install, not in your memory.** Ghidra's
own `Ghidra/application.properties` carries `application.java.min=`; a JDK below it
makes `LaunchSupport` exit 1 with `unsupported java version` **after** JPype has been
imported, which reads as a Python bug. `scripts/ghidra_bridge.py` reads the file,
asks `LaunchSupport -jdk_home` to resolve a usable JDK, and refuses before importing
anything.

**43. Reflect before calling.** Measured API traps in one session: `FlatProgramAPI`
has no `getAddress` (use `toAddress`); a Sleigh language exposes
`getLanguageID().getIdAsString()`, not `getLanguage().getID()`; a memory map has no
`getBlockCount()` (use `len(getBlocks())`); `getFunctionAt` returns `None` for an
address that is a range start rather than a function boundary. Under JPype, a Java
`String` arrives as a Java object — convert explicitly. Dump `dir()` on the object you
are about to call; guessing costs a full program open per attempt.

**44. Turn auto-analysis off when you bring your own bounds.** Full analysis rewrites
the program and spends unbounded time inside functions you have already validated.
The inventories in this repo need only function bounds and names, and those come from
`vb6d procs` output (an entry is believed only when the three bytes there are
`55 8B EC`). Import, create one function per validated range, set its name, decompile.

**45. A generic engine never prints literal text.** It emits `DAT_00a46408`,
`PTR_DAT_…`, `PTR_PTR_DAT_…` and occasionally inlines the text instead — so a search
for `0x00a46408` finds nothing and the run gets reported as "the engine lost the
strings". Measured here: renaming **inside** the program (`createLabel`, plate
comments) changed the emitted pseudo-C **not at all**, so the names go onto the
emitted text instead (`--literals` in `scripts/ghidra_bridge.py`), and visibility is
measured with `scripts/literal_visibility.py` against both forms.

**46. A driver-appended comment block makes everything visible.** If the run appends
its own per-procedure literal dump to the emitted body, then every catalogued address
is present in the file, and a visibility measurement over the whole file reports 100%.
Cut at the marker (`--cut-marker`) and measure the body only.

**47. Ceilings buy bodies; timeouts buy wall clock.** Print the engine defaults with
`scripts/ghidra_bridge.py --print-options` (50 MB payload, 100,000 instructions, and
the engine's own per-function timeout) and raise them only after a plateau test on the
same subset — a ceiling raise that recovers nothing is pure memory risk. Every failed
procedure burns its whole timeout, so report **solved-only** and **total** seconds
separately or a run looks ten times slower than the decompiler actually was. Two
operational facts: the decompiler engine runs in its own process, so a JVM `-Xmx` does
not bound its peak memory, and killing the driver leaves the JVM host plus the engine
holding RAM — kill explicit pids. Ghidra locks its project, so concurrent workers need
one project directory each.
