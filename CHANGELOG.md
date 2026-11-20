# Changelog

Newest first. One section per released version; the numbers in a section are the ones
the workflow published, not drafts.

## 0.6.0

First-run trust. `vb6d doctor` answers the question a newcomer actually has — why
the first command failed — in one `ok`/`warn`/`fail` line per fact: the interpreter
against `requires-python`, capstone present or absent and which stages that
disables, the runtime table's size and the DLL build it speaks for, the code page
that would be chosen and where that choice came from, every path-valued `VB6D_*`
variable, a writable temp directory and free space under the output directory. No
input file and no network; `--json` for a script. Exit codes extend the contract
already in `AGENTS.md`: `0` nothing to report, `1` warnings only, `2` a check
failed.

Every stage that takes `--out` now writes `<out>.manifest.json` beside its output:
tool version, command, each input's name and SHA-256 (streamed in blocks, so a
100 MB target costs the memory a 1 KB file does, and a directory is hashed over its
files' names, sizes and hashes), the code page and its source, Python version, UTC
start and end, and the run's record counts. The artefact itself stays
byte-identical. Input paths are file names by default because a manifest is shared
like the output beside it; `--manifest-paths` records absolute paths and
`--no-manifest` skips the file — removing a stale one, since it would describe the
new artefact with the old input's hash.

`vb6d unknowns <outputs...>` turns the markers the stages already wrote into
numbers that are safe to paste into an issue: a count with its record denominator
per kind, the VA page buckets the markers sit in, and for any text only its length
and the first 8 hex digits of its SHA-256. The kinds are the emitters' own field
names — an unclosed `sql[].status`, `calls_late_bound`, `unverified_operations`,
`runtime_unlisted`, a kind spelled `unknown` — never an inference about what
"unknown" might mean elsewhere.

Testing no longer needs a real build. `tests/synth_vb6.py` constructs one
**synthetic** VB6-like target — every byte layout taken from `docs/formats.md` —
and `tests/test_e2e_synth.py` runs `pe`, `procs`, `literals`, `stitch`, `frm`,
`blob`, `dossier` and, when capstone is present, `decode`, `edges` and `outline`
on it, asserting exact counts and lines. It proves the stages agree with each other
(the listing's procedure VAs are the object table's entries, the form blob's
geometry is the design text's), never that they are right about a real program;
`docs/pipeline.md` §7 says so where it shows how to build one.

Two behaviour corrections. `frm` on a file instead of a scan directory now exits 2
and names the path as typed: it used to raise `NotADirectoryError` into exit 3
("internal error") for an invocation whose only problem was the argument, and
`frm --recursive <file>` was worse — `os.walk` over a file yields nothing, so it
printed `0 files` and exited 0 like an empty success. And `sqlstitch` no longer
reports a candidate `CLOSED` when a later fragment opens with a statement verb
after the previous fragment ended on a completed value: the verb scan matches a
verb only after a non-letter (so data glued to a digit counts as a second
statement), which meant a verb glued letter-to-letter — `…Dim w` + `SELECT …` —
hid inside the last word. On the reference listing corpus the candidate count was
unchanged at 60,794 while 842 of the 5,122 candidates that had claimed `CLOSED`
became `MULTI` with its own reason, and the procedures holding a closed statement
went from 1,842 to 1,839. `AGENTS.md` also stops claiming error lines are
`#`-prefixed.

## 0.5.8

Reliability and data-safety pass. Every writer now creates its buffer with
`tempfile.mkstemp`, so two runs cannot share a temporary file and a planted
symlink at the old fixed `<out>.vb6d-tmp` path is neither followed nor
truncated. `project` generates into a staging directory beside the destination,
verifies the `.vbp` references and the report against what it wrote, and only
then promotes it — the previous directory is renamed aside and restored if
promotion fails; `--force` now replaces the whole directory (stale generated
files cannot survive), and an output that is a symlink, a regular file or a
directory holding the source executable is refused. Executable-derived text in
generated comments (object, procedure, control and page names, captions, the
exe path) goes through one escaper: CR/LF, TAB, NUL and the Unicode line
separators become visible escapes, printable text stays readable. Windows
device names are detected by their first dot-segment, so `CON.backup` and a
project named `CON` no longer become `CON.bak`-shaped paths, and over-long
names are truncated deterministically with the reason recorded.

`dossier --out` is now checked against the inventory CSVs it consumes as well
as the listings, with symlink and hard-link aliases resolved through
`samefile`. `edges` and `decode --procs` share one record gate
(`records.py`): a malformed nested field is counted with its line number
instead of crashing the batch, and addresses must be bare hex rather than
whatever `int(x, 16)` accepts. `decode` reports a bad `--va`/`--end-va` or a
non-positive `--limit`/`--window` as exit 2, a missing `--procs` file as exit
2, and `edges` maps a missing `[asm]` engine to exit 2 with the install hint
and no output file. `project`'s design scan catches only the image's own
errors; a programming fault is no longer reported as an empty design.
Capstone engines are built once per `edges` run: measured on 20,000 short
bodies, 3.74 s → 1.23 s (engine construction was 98 µs against a 38 µs
decode), with identical rows. `ReferenceCount=0` is named as a reconstruction
assumption in the `.vbp` comment and the recovery report, since the reference
table is not modelled. Suite: 376 collected, 15 skipped.

## 0.5.7

Documentation only. `stitch_all` promised "the count of open fragments" in its
docstring and never returned one; it now says what it returns and points at
`stitch`/`summarise` for a closure census — with the denominator beside it.

## 0.5.6

`sqlstitch` promised a `RUNTIME_GAP` status in its docstring and never produced
one, so a value the program concatenated at run time could close as a statement.
Two boundaries did it: an unterminated quote followed by a bare quote (a value
rendered as an empty string) and an unterminated quote followed by a field name
that is quoted later. Both passed every existing gate — balanced, one verb, no
dangling connector — and were reported CLOSED, which the text could not support.
The new gate reads the fragment boundary instead of the joined text, and keeps the
case that must stay closed: a long stored literal the listing split across
fragments still ends with its closing quote and is not a gap. Re-measured on the
same corpus, candidate census unchanged: CLOSED 20,693 → 5,122, RUNTIME_GAP
0 → 26,067, OPEN_QUOTE 22,836 → 12,785; best-closed-per-procedure 4,423 → 1,842,
and the 755 texts that appear only afterwards were verified to have been CLOSED
candidates in the previous run as well — a longer bogus join had been hiding them.
Suite: 319 passed, 15 skipped of 334 collected.

## 0.5.5

The second external review series. Operational failures now exit 3 —
`internal error: <type>: <msg>` on stderr — so a toolkit bug or an unwritable
output is told apart from unusable input (exit 2), and `VB6D_DEBUG=1` still
re-raises for bug reports. `procs --names` is labelled for what it is: a
coverage count that attaches no name to a procedure record; per-procedure name
hints come from `vb6d dossier`. The DataReport gap now names what the writer
did not rebuild — the designer files a real `.vbp` would list (`.dsr` text,
`.dsx` resource) — instead of asserting a runtime-only verdict the object
table never gave. No stage opens an output that names a consumed input, and
outputs are written atomically, so an interrupted run leaves neither a
half-written file nor a `.vb6d-tmp` behind. Unusable JSONL input lines
identify themselves by line number, kind and reason. Call targets are
attributed by range containment, not by the nearest start below a target; a
method named `Main` is no longer evidence for `Startup=`; unknown object types
land in the recovery report instead of a KeyError; `frm --json` carries the
parsed form, not only its census; `dossier` keeps a SQL candidate's text
address so `xref --full` indexes real statements. `--force` for the project
writer is documented, and the pipeline's stale startup claim was corrected.
The 0/1/2/3 contract is written into AGENTS.md, README and the agent skill.
Suite: 331 tests, green on 3.11–3.14; two path-spelling tests that quietly
assumed a Windows filesystem were made platform-aware.

## 0.5.4

Closes the sibling of the 0.5.3 rename: the same fixture text still carried four
more column names from the program this tool was built against, in `pitfalls.md`,
`tests/test_core.py` and one `sqlstitch.py` docstring. They are now ordinary
stand-ins; no measured count changed.

## 0.5.3

Public docs and tests now use only stand-ins for target screen, table and column
names, so the repository reads the same to someone who has never seen the program
it was developed against. Duplicated tool comments are gone from a dozen lines,
and a hygiene test keeps them from returning. The dev tools are pinned to the
release line they were tested on (`ruff` 0.17, `mypy` 2.4), so a newer release
cannot turn CI red without a code change. `edges` and `outline` report an
unusable input with the same `error:` prefix as every other command. `dossier`
refuses a `--listings` directory that holds no listing file, instead of writing
an empty dossier and exiting 0.

## 0.5.2

A version-only bump after the workflow file was renamed `release.yml`; the package
is identical to 0.5.1.

## 0.5.1

A forced history update of master left GitHub marking this publish workflow
"deleted". A `workflow_dispatch` trigger is added so the manual release path
survives, and raising `version` re-registers the file through a real release.
Package code is identical to 0.5.0; only the CI wiring changed.

## 0.5.0

Every command now treats a path it cannot use as an error: a missing file or
directory, or a single file named on the command line that is unreadable or not a
PE image, exits 2 with one line on stderr naming the path exactly as typed. A
mistyped name no longer reads as "0 images, exit 0", and raw parser text like
"unpack_from requires a buffer" no longer reaches a stranger without a file name.
Reading a whole directory keeps counting unreadable files, because finding them is
that survey's job. The object-table lane in `vb6d edges` reports unexpected faults
on stderr instead of staying silent about everything (`vb6d dossier` already named
where it writes, and the docs now say so too). `vb6d blob` validates headers
through the same PE parser as every other stage, so a PE-shaped stub fails
explicitly instead of reporting zero forms. `ruff` and `mypy` joined the dev extra
and the tests workflow as a review baseline, configured to the state the code is
in with every ignore individually justified; the package therefore does not yet
ship a `py.typed` marker. The README was restructured for honesty: two claims now
name exactly the tiers measured in `docs/tool-matrix.md` (free/Lite editions and
generic engines - paid editions were never measured), the long evidence cells
moved verbatim to `docs/commands.md`, and a quick start joined the intro. CI runs
the suite on 3.11 through 3.14 with the engine extra, fails when the x86 or edges
lanes skip, and checks that the wheel carries the runtime call table; publishing
is now limited to pushes that touch release-relevant files, so docs-only pushes
no longer spend a version.

## 0.4.26

* **`edges --events` — the ordered event stream (milestone D's eighth
  layer):** each procedure row may carry `events`, an ordered array of the
  things whose identity is already known — a named call (its label from the
  import table, the thunk hop, the range floor marked `proc:…`, or an
  object-table hit) and a `push/mov/lea` of an immediate that IS a dossier
  literal (its text carried). Nothing unnamed or late-bound pads the
  stream; unnamed traffic stays in the counts, and the default output of
  `edges` stays byte-for-byte slim without the flag. Measured on the full
  reference corpus (5m6s with the flag): 33,776 of 34,159 procedures have
  at least one event; **2,375,908 events = 1,934,388 named calls + 441,520
  literal loads** — and the call-event total equals exactly the sum of the
  three named call lanes (1,897,375 + 9,980 + 27,033; the 79 unnamed stay
  out), an internal-consistency check the file proves on itself. A stream
  reads like a statement trace: `__vbaStrCy`, `rtcRate`, the literal
  `00000000000000000#`, `__vbaVarDup`, `__vbaFreeVarList` in the order the
  body lists them. The flag costs 148 MB of JSONL on this corpus and the
  literal texts are raw — a stream file headed anywhere public passes the
  mask gate first, like every other output of this tool.

## 0.4.25

* **`vb6d outline <edges.jsonl>` — an operation outline, marker-first
  (milestone D's seventh layer):** the edges file read through the runtime
  table with no engine at all: each procedure's runtime hits are bucketed by
  the table's own `category`, and because those categories are a third
  party's reverse-engineering notes marked unverified, the output field
  carries the marker in its name — `unverified_operations` — and stderr
  repeats the word; a consumer cannot read a category without being told
  what it is. Names the table does not categorize stay names
  (`runtime_unlisted`), hits on other dlls are counted without
  interpretation (`api_calls`), late-bound counts pass through as counts,
  and no category is invented. Measured on the full reference corpus (2 s,
  engine untouched): **1,882,740 of 1,907,355 runtime hits (98.7%) land in a
  category**; the 24,615 left are ordinal-only imports and names the notes
  do not describe, kept as names. Ranking: `free` 548,835, `object` 399,969,
  `error` 363,145, `string` 323,374, `late` 95,441 — the shape of a VB6
  program (object lifetimes, error plumbing, string work) readable from
  counts alone; the file's program calls the runtime and nothing else (0
  hits on other dlls), which is itself a finding. An outline is an outline:
  per-procedure runtime fingerprints, not statements of what the source said.

## 0.4.24

* **`edges` names compiler thunks — the unnamed pile collapses (milestone
  D's sixth layer):** a call target below the listed population whose own
  first instruction is `jmp [import slot]` is a compiler thunk, resolved two
  hops and reported as `calls_thunks` (`dll!name` → count); the object
  table's function entries are also consulted (`calls_objects`, object names
  only), and what remains is `calls_other`, a per-target-VA count. Measured
  on the full reference corpus (unchanged 4m40s pass): of the 10,059
  previously-unnamed hits, **9,980 are thunks** — five of them account for
  nearly all of it: `__vbaChkstk` 7,479 (the stack-probe helper),
  `_adj_fdiv_m32` 1,434, `_adj_fdiv_m64` 634, `_adj_fdivr_m64` 413,
  `_adj_fdiv_r` 20 — the classic VB6 FPU-patch cluster, sitting right next
  to the entry-point trampoline where the listings never enumerated. The
  still-unnamed lane shrank to **79 hits across 11 target VAs** (a region
  near `ACDD38` whose entries are not slot jumps); `calls_objects` measures
  zero on a compiled exe because native builds keep method entry addresses
  empty by design — documented in `procs.py`, now stated in the docs too.
  The 34,159 / 34,159 ret-in-range result held on the rerun.

## 0.4.23

* **`vb6d edges <exe> --dossier <file>` — the call graph, produced once
  (milestone D's fifth layer):** one process decodes every dossier range
  instead of launching per-procedure, writing `edges.jsonl` with one row per
  procedure — `calls_imported` (`dll!name` → count), `calls_procedures`
  (owning range VA → count: attribution, never identity), `calls_late_bound`,
  `ended`; a procedure that makes no decodable call still gets a row, and
  the file's last range reads under a fixed cap and says `range_capped`.
  Measured on the full reference corpus (34,159 procedures, 4m59s including
  the dossier rebuild): **34,159 / 34,159 ranges end on a `ret` inside the
  range — zero garbage, zero exhausted across the whole population**, which
  is the body-bounds claim now proven corpus-wide, not by 402 samples.
  Totals: 1.897M import-named calls (top: `__vbaHresultCheckObj` 319.979,
  `__vbaNew2` 217.851), 27.033 edges attributed to listed procedures — one
  `modApiFuncs` helper holds **17.197 inbound calls** across the program —
  1.791M late-bound (obj-call `[reg+disp]`, unnameable statically), and
  10.059 targets below the first listed procedure VA: the helper region the
  listings never enumerated, counted instead of footnoted.

## 0.4.22

* **`decode --procs <dossier.jsonl>` — call edges, honestly attributed
  (milestone D's fourth layer):** an in-image call target that is not an
  import slot gets `target_proc` — the dossier procedure whose *reported
  range* holds the target (VA + object name + listing name hints). This is
  range attribution, never an identity claim. Measured on the reference
  build (300-procedure sample): 212 edges attributed to known procedures —
  including hot shared helpers like one `modApiFuncs` procedure called 151
  times across the sample — while 277 targets land **below the first listed
  procedure VA**, a helper region near the entry point the listings never
  enumerated:
  the documented "helpers with no entry of their own" gap, now visible as a
  named measurement instead of a footnote. Corrupt dossier lines are
  counted and skipped, same as the dossier builder itself.

## 0.4.21

* **`decode` names its call targets (milestone D's third layer):** every call
  whose target is statically reachable is annotated from the file's own
  import table — `target_va`, plus `target` as `dll!name` when the VA is an
  import slot. Two VB6-era import quirks had to be handled to get there
  (measured on the real build): the binder leaves `FirstThunk` zero with the
  live table at the OFT offset, and the live slots are *bound* (they hold
  load-time addresses), so slot names are paired by index from the ILT;
  `ordN` slots of the VB6 runtime are resolved through the shipped call
  table, and anything still unknown prints `ordN` or `?` instead of a guess.
  Late-bound `call [reg+disp]` stays unannotated — nothing static can name
  it — and the stderr line now reports how many of the calls were named.
  Measured: on a 402-procedure sample of the reference build, 22,911 calls
  (including 49 through `jmp [slot]` thunks) arrive named — the runtime
  helper census the dossier already reports, now seen from the code side —
  while 23,668 stay late-bound by nature and 316 are internal calls.
  `pe.Import.slots` carries the slot map; `pe.import_names()` renders it.

## 0.4.20

* **`decode` honest boundaries — milestone D's second layer:** `--end-va HEX`
  clamps the dump to one body (the neighbouring procedure VAs the dossier
  already lists make the range exactly one body), and the ending taxonomy got
  sharpened: `exhausted` (every byte decoded, no `ret` in range) is now told
  apart from `garbage` (the engine stopped mid-stream; `stopped_at_va` names
  the first byte it cannot express), and neither is ever reported as `ret`.
  Measured on the real build: 402 procedures sampled across the whole VA
  space (stride over all 34,159 dossier procedure VAs), each bounded by its
  own range, all 402 decoded `push ebp … ret` — median 169 instructions
  (range 4 to 32,341), zero garbage, zero run-overs. The body bounds the
  listings report are real body bounds, so the semantics layer will not have
  to guess them.

## 0.4.19

* **`vb6d decode <exe> --va HEX` — milestone D's first layer:** a raw x86
  instruction dump starting at any VA the earlier stages already report
  (dossier, xref, object table). Each row carries the VA, the instruction
  bytes, the mnemonic and the operands, and the result declares how it ended
  (`ret`, `limit`, `undecodable`, `no-bytes`), so silence is never mistaken
  for completeness. Runs on capstone through the existing optional `[asm]`
  extra — core installs stay standard-library only, and a missing engine
  refuses with exit 2 and the install hint instead of a traceback; RULES.md
  gained the matching confinement line. The wheel (capstone 5.0.7) was
  measured on this machine; its bindings render operands as `op_str` and need
  `detail=True`, pinned in `x86.py`, and the upstream license ships in
  `third_party/capstone/`. Measured on the real build: three dossier
  procedure VAs each start their decode at a `push ebp` prologue, two end at
  `ret` (226 and 373 instructions), one reports the instruction limit, and a
  control VA inside a data pool reports `undecodable` from its first row.
  No VB6 semantics claimed yet — that is what this layer is for.

## 0.4.18

* **Consistency fix:** `vb6d project` report JSON now writes addresses as bare
  uppercase hex (`"996671"`), matching the convention every other command
  already followed (`dossier`, `literals`, `stitch`). Only human comment lines
  in the stub files keep the `0x` prefix. A test now pins the rule so a future
  field cannot drift back to `0x…` in machine output.

## 0.4.17

* **`vb6d xref`: the dossier read backwards** — the questions agents actually
  start from ("which procedures touch this string / this SQL") become one
  command over the dossier file instead of jq gymnastics. Default: a procedure
  rollup ordered by literal mentions; `--literal/--sql SUBSTR`: case-insensitive
  search over recovered text answering with owning procedures (VA, owner
  object, name hints); `--full`: both inverted indexes (large, opt-in).
  Measured on the reference corpus: 34,159 procedures with 441,607 literal
  mentions, rollup in 2 s (9.1 MB of JSON); `--literal SELECT` returns 4,435
  owning procedures; a string absent from the build returns an empty result
  and exit 0. A corrupt dossier line is counted on stderr and skipped, never
  a reason to void the file.

## 0.4.16

* **`vb6d project` design records:** form stubs now embed a comment-form design
  reconstruction from the exe's form-data blobs — record offset and size (the
  binary stream itself stays in the exe), the form extent, and one line per
  recovered control: name, array index, type, caption, geometry, SSTab page or
  page titles, and visibility where the marker was read (silent stays unknown).
  The report carries per-form record evidence; a form with no parseable record
  is named in the gaps. Reference build: 801 of 802 forms designed
  (the one gap is a `.frm` named in the report), 55,814 controls across stubs,
  full run on the 111 MB build in about 28 s.

## 0.4.15

* **Documentation only:** pitfalls entry 11 — the method-entry name column of a
  native object table is junk decodes (1 plausible of 626 on the reference build).

## 0.4.14

* **Documentation only:** changelog section order restored.

## 0.4.13

* **Documentation only:** changelog attribution fix — 0.4.11 was the back-fill
  release; the project skeleton shipped in 0.4.12.

## 0.4.12

* **`vb6d project <exe>`: reconstructed project skeleton** — a `.vbp` listing
  the object table's modules, classes and forms in table order (labelled
  inferred: VB6 compiles in `.vbp` order), one placeholder file per object
  carrying a banner of its provenance, and a `recovery-report.json` that
  separates confirmed fields, inferred fields, gaps and the file's single
  assumption (`Type=Exe`). Measured on the reference build: 810 `.vbp` entries,
  812 files written, exactly 1 of 626 readable method names passing an
  identifier check (625 quarantined as junk decodes), startup unrecovered.
  No source text is invented; the exe itself is never touched.

## 0.4.11

* **Documentation only:** changelog back-fill for 0.4.9–0.4.10.

## 0.4.10

* **Documentation only:** changelog catch-up for 0.4.4–0.4.8.

## 0.4.9

* **`vb6d --version` prints the tool version on one line and exits 0**, so an
  agent saving stage output can record which version produced it. The version
  is read from the installed distribution — pyproject.toml remains its only
  home (docs/RULES.md) — and a bare checkout says plainly that it has no
  metadata to answer with.

## 0.4.8

* **`pe` flags images whose sections claim bytes past EOF** (`truncated: true`
  in every row). The headers of a cut file parse, every lookup past EOF quietly
  returns nothing, and the row looked identical to a clean foreign file: on the
  reference build, 111 MB cut to 100 KB reported `vb6=False` and "0 unreadable"
  while the whole file reports `vb6=True`. Full images and a 27 MB foreign
  binary keep the flag false (0 false positives on the images at hand).

## 0.4.7

* **`blob --json` carries the per-control geometry its parser already
  recovers**: caption, position, size, control-array index, the tri-state
  `Visible` and the SSTab tab page for every control, plus the form's client
  offset. Measured on the reference build: 801 forms, 55,814 detail controls
  (29,965 with an array index, 17,048 with a caption, 1,593 on a tab page, 489
  with a resolved `Visible`). Text and CSV rows keep their old per-form shape
  — a pinned test asserts the header.

## 0.4.6

* **`procs --names` documentation now tells the truth: the flag counts, it does
  not attach.** The flag help, README and pipeline.md §1 said names were
  attached or merged; `cmd_procs` records one count (`names_from_listing`), and
  the native object table exposes no method addresses on the reference build
  (0 unique entries), so there is nothing per-procedure to attach to. The
  per-procedure name hints have always been `dossier`'s (§3b), and the help now
  says where to find them. Behavior unchanged; wording corrected.

## 0.4.5

* **`stitch` on a bare executable says why the run is empty.** Literals
  harvested from a binary carry no procedure ownership (`proc_va` is only known
  from a listing header), so chaining had nothing to group and the stage
  returned an empty result with nothing on stderr — readable as "this build has
  no SQL" when nothing had been attempted. The cause is stated on stderr, the
  right input named, and the exit stays 0; unusable input still costs exit 2
  because the scan runs before the announcement. README and pipeline.md §3
  corrected to match: `stitch` takes a listing directory.
* Test-only helper `tests/_mini_pe.py` builds a synthetic 32-bit PE inside the
  tests — including a truncated variant that no binary fixture can express.

## 0.4.4

* **Stitched SQL statements now name where they came from.** A `stitch`
  candidate used to name tables but carried no address, so a CLOSED statement
  could not be relocated to the build it was stitched from. Rows now carry the
  owning procedure's listing VA (`proc_va`) and the first fragment's text
  address (`text_va`), in the same empty-when-unknown form literals.py uses.
  Measured on the reference listing corpus: 4,423 of 4,423 closed rows carry
  both.

## 0.4.3

* **A measured answer on the question the roadmap left open: can a native decode
  give a procedure's runtime-call order?** `scripts/t35_import_call_spike.py` decodes
  each procedure's own byte range with capstone, resolves every call through the
  import address table (direct `call [slot]` and `call rel32` to a `jmp [slot]`
  thunk), and compares that order against the same procedures in a decompiler
  listing. It ships as a measurement, not a stage: it prints agreement per procedure
  and never emits a call graph.
* **What it found, so nobody has to re-run it to learn the shape:** on the reference
  build, 1,750 procedures in 40 listing files gave 1,451 identical ordered sequences
  and 299 identical-then-extra, with 0 that ended early and 0 with a different call or
  a different order. The 299 are the documented `procs.body_bounds` gap — a range runs
  to the next method-table entry and can contain a helper with no entry of its own —
  so any field derived from it must say "calls seen in this range", never "this
  procedure calls".
* **Two traps the measurement itself hit, now pinned by tests:** a listing prints a
  direct call to a runtime thunk as `call 00516100h` with no slot, and skipping those
  made 102 procedures look like a decoder disagreement; and an ordinal-imported call
  has no name in the binary at all (`ord_598`), which is why the script reports the
  DLL build behind any ordinal it names. Cost 3.5 ms per procedure.
* **The extractors are unit-tested without a binary or capstone.** The listing parser
  keeps order, skips late-bound `call [eax+4]`, follows a thunk to its slot and refuses
  a thunk outside the image — the four ways this had to be right.

## 0.4.2

* **A runtime helper imported by ordinal alone can now be named.** A build may fill
  an IAT slot from `ordinal 598` and never mention the name, so the pseudo-C a
  decompiler prints reads `ord_598` and a dossier could say nothing about it. The
  shipped table already held one ordinal per name, so the reverse lookup costs no new
  data: `runtime_table.describe_runtime_ordinal()` and `describe()` resolve
  `ord_598` → its export name, and the dossier uses them.
* **The resolved name carries the build it came from.** An ordinal is a position in
  one DLL's export table, so the row's `source` reads
  `export-table ord — msvbvm60.dll <version> (sha256 …)`. An ordinal that build does
  not export by name stays `ord_598` with null fields — reported unnamed, never
  guessed.
* **The agent skill describes the tool as it is.** `.agents/skills/` is the single
  copy every plugin manifest points at, and it still described the pre-dossier
  pipeline: it now lists `vb6d dossier`, the code-page rule
  (`--encoding` > `VB6D_ENCODING` > header LCID > `cp1254`) and the in-package
  helper commands, and it no longer sends a reader to `scripts/literal_visibility.py`
  or `scripts/pseudoc_inventory.py` for work the package does itself.

## 0.4.1

* **One read per file instead of two or three.** `vb6decompiler/fileio.py` maps an
  image (`mmap`) when the file is at least 4 MB and reads it otherwise, and the
  parsers that only ever slice it now share that one buffer: `datareport.find_designs`
  used to open the same DLL a second time (`read_designs` already had it) and
  `procs.prologue_report` read a file `procs.read` had just read. Measured on a
  111 MB image: `read()` peaks at 116 MB and takes 0.08 s, so every removed read is
  116 MB of allocation and 0.08 s gone. Results are byte-identical — compared against
  0.4.0 on a synthetic PE through both paths, and pinned by `tests/test_fileio.py`.
* **A mapping is closed on every path out**, including an exception: on Windows an
  open mapping keeps the file locked. A file the OS refuses to map falls back to a
  plain read, so a mapping failure changes speed, never output.
* **Four helpers moved into the package**: `frx_icon`, `literal_visibility`,
  `pseudoc_inventory` and `semi_laa` are now `python -m vb6decompiler.<name>`, so a
  pip install can run them — `pseudoc_inventory` matters most because `vb6d dossier
  --inventory` consumes its CSVs. `scripts/<name>.py` stays as a shim, so every
  command quoted in older notes still runs;  `ghidra_bridge.py` (needs a Ghidra
  install) and `win32_gui_probe.py` (needs a Windows GUI) stay in `scripts/`.

## 0.4.0

* **`vb6d dossier` names the runtime helpers a procedure calls.** When the merged
  pseudo-C inventory carries `vba_runtime` call rows, each record gains a
  `runtime_calls` list: helper name, ordinal, category, description and where each
  field came from. A run without such rows produces exactly the records 0.3.0
  produced, and the summary line appears only when calls were seen
  (`# runtime calls described: X of Y`).
* **The table is generated from the DLL, not copied from a web page.**
  `scripts/gen_runtime_table.py` reads the export table of a local `msvbvm60.dll` with
  this repository's own PE reader and writes `vb6decompiler/data/runtime_calls.json`:
  the named exports of that build, keyed by name, with the ordinal read from the same
  file. Ordinal-only exports are left out because they have no name to key on.
* **Descriptions are third-party notes and are labelled as such.** The category and
  description text comes from the Apache-2.0 `visualbasic` crate's export table,
  credited in `THIRD_PARTY_NOTICES.md`. Its ordinal column was checked against a local
  DLL first and disagreed on every row it has (602 of 602, each off by exactly 99), so
  ordinals are re-read from the DLL. Names the crate does not list keep a null
  description instead of an invented one, and every printed description carries
  `unverified` in `source`.
* **The data file has to survive packaging.** Package data is declared, and a test
  builds the wheel and asserts `vb6decompiler/data/runtime_calls.json` is inside it.
* **New: `docs/references.md`.** What was read for background — the runtime, P-Code,
  the `VB5!` header — and what each page is good for. No numbers are taken from it.

## 0.3.0

* **Code page awareness.** Text used to be decoded as CP1254 by name, which is right
  for a Turkish build and silently wrong for every other one. The code page is now
  chosen in this order: `--encoding CODEPAGE` on the stage, else `VB6D_ENCODING`,
  else the LCID in the build's `VB5!` header, else CP1254. Every stage that decodes
  text prints the choice once on stderr, e.g. `# encoding: cp1251 (lcid)`. Only
  single-byte ANSI code pages are accepted; a double-byte page (CP932/936/949/950)
  or UTF-8 exits 2 with one line, because the parsers map a character offset back
  onto the byte it came from.
* **A `VB5!` header's LCID is a hint, not the answer.** It records the developer's
  IDE language; the bytes follow the code page of the machine that compiled the
  project. `--encoding` outranks it for exactly that reason.
* **P-Code is named instead of failing silently.** `vb6d procs --validate` prints
  "0 of N entries start with a native prologue; this build may be P-Code (not
  verified)" when that is what it measured. No P-Code binary was available to
  measure, so this is a suspicion and the wording says so (`docs/formats.md` §8
  lists the fields to compare once a sample exists).
* **New stage: `vb6d dossier --listings <dir>`.** One JSON object per procedure
  (JSONL): literals in listing order, SQL candidates with `CLOSED` kept apart from
  the open buckets, name hints labelled as hints, and an optional
  `scripts/pseudoc_inventory.py` directory merged by VA. It collects evidence for
  re-specifying a lost-source program; it does not recover source code.
* **Correction in `vb6d stitch`:** a whole statement stored as a single literal was
  reported `STUCK` ("continuation is not SQL") because the guard tested `parts[1:]`
  of a one-part candidate. Such a statement now closes when it starts with a verb,
  is balanced and is not dangling. Closed counts on a real corpus are therefore
  **higher** than 0.2.x reported for the same input.
