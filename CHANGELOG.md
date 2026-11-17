# Changelog

Newest first. One section per released version; the numbers in a section are the ones
the workflow published, not drafts.

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
  (`mBGS.frm` is the named gap), 55,814 controls across stubs, full run on the
  111 MB build in about 28 s.

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
