# Changelog

Newest first. One section per released version; the numbers in a section are the ones
the workflow published, not drafts.

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
