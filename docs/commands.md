# Stage by stage

Long descriptions moved out of the README table **verbatim**; each README
row links here. The commands column stays in the README unchanged.

## SQL reconstruction

fragments joined into whole statements, with explicit "not provable statically" buckets; binary text belongs to `vb6d literals`

## Per-procedure evidence

one JSON object per procedure: its literals in order, its SQL with closed/open kept apart, name hints, plus an optional pseudo-C inventory merged by VA — evidence for re-specification, not source

## Form icons from `.frx`

standalone `.ico` per form, extracted from the leading ICON record without the executable; coverage cross-checked against `.frm` Icon references

## Second-opinion decompiler run

one pseudo-C file per procedure: our bounds and names, engine ceilings as flags, the JDK requirement read from the install before anything is imported

## Literal visibility check

measured visible / catalogued per procedure — an address token (`DAT_`, `PTR_PTR_`) **or** inlined text counts, with a denominator instead of a hunch

## Pseudo-C inventories

literal order, indirect-call object+slot, ordered calls with line numbers, branch conditions, unnamed-global census

## Runtime call order check

whether a native decode reproduces each procedure's `MSVBVM60` call order; reports agreement per procedure, not a guessed call graph

## Cross-reference query

the dossier read backwards: which procedures touch a string or SQL fragment (case-insensitive), or a procedure rollup ordered by literal count

## x86 raw decode

instruction dump from a VA each earlier stage already reported: bytes, mnemonic, operands, an explicit `ended` field (ret / limit / exhausted / garbage + stop address), call targets named via the file's own import table (`target` = `dll!name`, `target_va`; late-bound `[reg+disp]` stays unnamed), and with `--procs` procedure attribution of in-image targets (`target_proc` = the dossier procedure whose reported range holds the target) — no VB6 semantics claimed yet

## Program call edges

one process pass over every dossier range: `edges.jsonl`, one row per procedure — `calls_imported` (`dll!name` → count), `calls_thunks` (targets that are `jmp [import slot]` thunks, named via the slot), `calls_procedures` (owner range-VA → count, range attribution not identity), `calls_objects` (hits on object-table function entries, named by object only), `calls_other` (unnamed hits, target VA → count), `calls_late_bound`, `ended`; `--events` adds an ordered per-procedure `events` stream (named calls + loads of immediates that are dossier literals — only events with a name or text make it in); stderr totals split named / thunk-named / attributed / late-bound / object-named / still-unnamed

## Operation outline

the edges file read through the runtime table: per procedure `unverified_operations` (runtime category → count; the categories are a third party's reverse-engineering notes, the field is named for the marker and stderr repeats it), `api_calls` (other dlls, counted not interpreted), `runtime_unlisted` (names the table does not categorize) — and never an invented category

## Project skeleton

structure, not source: `.vbp` with the object table's modules/classes/forms in table order, one placeholder file per object — forms carry their recovered design record (offset, extent, per-control lines) in comment form — and a `recovery-report.json` separating confirmed / inferred / missing — nothing invented. Default output is a sibling `<exe-name>_project` directory; an existing non-empty one is refused unless `--force`, which **replaces the whole directory** (stale files and unrelated files included) with a project generated in a staging directory beside it and promoted only when complete — a failed run leaves the previous project intact. `ReferenceCount=0` is a placeholder assumption, named in the report; the reference table is not modelled

## Environment check

`vb6d doctor` — one `ok` / `warn` / `fail` line per environment fact a first run depends on: Python against `requires-python`, capstone present or absent and which stages that disables, the runtime table's size and the DLL build it speaks for, the code page that would be chosen **and where that choice came from** (flag / env / header LCID / default), every path-valued `VB6D_*` variable resolved or reported, a writable temp directory, and free space under the output directory. No input file, no network. `--json` for a script; `--dir` to point the disk check at an output directory. Exit `0` nothing to report, `1` warnings only (an absent optional extra is one), `2` a check failed — the environment cannot run the toolkit, so it is not the file's fault. Nothing is asserted that could not be measured: a check that cannot tell says why.

## Run manifest

every stage that takes `--out` (`project`, `dossier`, `edges`, `outline`) also writes `<out>.manifest.json` beside its output — tool version, command, each input's name and SHA-256 (streamed, so a 100 MB target costs the memory a 1 KB file does; a directory is hashed over its file names, sizes and hashes), the code page and its source, Python version, UTC start and end, record counts. The artefact stays byte-identical. Input paths are reduced to file names by default because the manifest travels with the output; `--manifest-paths` records absolute paths instead; `--no-manifest` skips the file and removes a manifest an earlier run left beside the same output (it would describe the new artefact with the old input's hash)

## Unknown summary

`vb6d unknowns <outputs...>` — the markers the stages wrote, as numbers safe to paste into an issue: per kind a count with its record denominator, the VA page buckets the markers sit in (`VA >> 12`: a page compares between builds where an address does not), and for any text only its length and the first 8 hex digits of its SHA-256. Reads the row files `dossier`, `edges` and `outline` already wrote (JSONL, a JSON array or CSV). Marker kinds are the emitters' own field names — `sql[].status` other than `CLOSED`, `calls_late_bound`, `unverified_operations`, `runtime_unlisted`, a kind spelled `unknown` — never an inference. No SQL, name, table, path or byte of the target is printed; `--json` prints the same numbers as an object. An unreadable file is named and the rest still counts; a missing path is exit 2 and prints no table, because an empty report reads as "nothing is unknown"

## Data model from the SQL

`vb6d schema <dossier.jsonl> [--format md|json] [--out F]` — the closed statements read as a model instead of a list: per table the columns named explicitly plus who reads and who writes it, a CRUD matrix per (object, table), the statements that could not be parsed with their reason, and the open ones counted as gaps. The tokenizer handles the dialect these programs use — `[bracketed names]`, `#date#` literals, `''` escapes, `?` markers, `schema.table.column` — and refuses the rest by name rather than approximating it. Nothing is guessed: `*` is recorded as a star, an expression in a select list stays an expression, a qualifier the statement never defined stays unattributed, and an unqualified column is given to a table only when the statement names exactly one. Statements in = parsed + unparsed + open, printed with the report so the sum can be checked; a hint that disagrees with `sqlstitch`'s own table list is listed, not averaged

## Specification per object

`vb6d spec <dossier.jsonl> [--exe E] [--frm DIR] [--outline F] [--schema S] --out DIR` — `index.md` plus one Markdown file per object. Each file carries the object's kind **and the stage it came from**, the design table when `.frm` text is supplied (control, type, caption, twips geometry, `Visible`, array index), and per procedure its VA, name hints, the text that reads as a message, its SQL with closed and open kept apart, and the runtime-call categories with their `unverified` marker. The Gaps section lists what is missing with its denominator: open SQL, controls with no recovered rectangle, runtime helpers the table does not categorize. A missing input is named in the file (`no .frm directory supplied`) instead of leaving a section that reads like a measurement. Text from the build goes through one Markdown escaper and file names through `projectwrite`'s Windows-safe rules, so a caption or an object name cannot change where a file lands

## Form mockups

`vb6d frm <dir> --format html --out DIR [--exe E] [--scale N]` — a static page per form plus an index: known control types drawn as the plain HTML element that reads like them, anything else a labelled placeholder box with its own type name. `--exe` adds forms that exist only as binary blobs and cross-checks the `.frm` geometry against them per form. Three facts are printed on every page because a picture invites belief: the twips→pixel factor **and that it is assumed** (15 twips/px is the classic 96 dpi value; nothing measured it for a given build, and `docs/formats.md` states no factor), the geometry source, and whether a blob existed to cross-check. No script and no external resource exist in the output, and a CSP meta also forbids them, so it is safe to open from `file://`

## Call graph

`vb6d graph <edges.jsonl> [--from NAME_OR_VA] [--depth N] [--direction out|in|both] [--format dot|mermaid] [--out F]` — a slice by default: a whole-program graph of tens of thousands of procedures is unreadable, so `--all` exists, warns about the size, and is the only way to get everything. An edge appears only where the evidence names a target: `calls_procedures` and `calls_imported` become nodes, `calls_late_bound` becomes one labelled `unresolved` node per procedure rather than an arrow to a guess, and a call to a VA the dossier never listed keeps its VA as the label. A `--from` that matches nothing is exit 2 — an empty drawing would read as "this calls nothing". The stderr line carries both numbers (`2 of 4 procedures, 1 of 1 edges`), never a percentage

## Workspace file and one-command run

`vb6d init [--dir D]` writes a `vb6d.toml` of commented placeholders — no target name, no host, no path from the machine that generated it, because the file is meant to be committed. `vb6d run [--from STAGE] [--only a,b] [--jobs N] [--force-stage]` runs the stages in dependency order from that config, writing each stage's output under its own directory (`pe/`, `frm/`, `dossier/`, `schema/`, …) with that stage's manifest. Precedence is `flag > VB6D_* variable > vb6d.toml > the build's header LCID > default`; an unknown key in the file is refused rather than ignored, since a misspelled `listing_dir` would otherwise configure nothing and complain about nothing.

Three properties of `run` are load-bearing. **One failure does not cancel the rest:** each stage's own exit code is the verdict, the independent stages keep going, and stages that needed a failed one are reported `skipped: <stage> failed`. **"up to date" is a claim with evidence:** it appears only when the manifest beside an output records the same input hashes (and, for a run, the same paths) and the same tool version, so `--force-stage` is for the case where you want the pass repeated, not for suspicion. **The table names every stage** with status, seconds and its note, and the exit code follows the contract: `0` when nothing failed, `3` when a stage did.

`--jobs N` runs the stages of one dependency wave in parallel; results are collected in plan order, so two runs print the same table. Per-file parsing is parallel too: `vb6d frm --jobs 4` parses N files on threads and assembles the report in file order — the counts and the order are identical to the sequential path, which is what the test asserts. `--exe` on `frm --format html` cross-checks geometry against the executable's own form blobs.

A progress line (`# frm: 120 of 800 (4.3s)`) appears on long stages only when stderr is a terminal: a stage that writes into a pipe someone is parsing stays silent, and the first line always prints so a hung stage is distinguishable from a slow one.

## Synthetic demo and the benchmark

`vb6d demo --out DIR` writes the synthetic build and prints the commands to run on it. It is SYNTHETIC and says so: every number it produces is about the builder, never about VB6. The builder lives in the source tree (`tests/synth_vb6.py`), so the command works from a clone and explains itself when the package was installed from a wheel.

`python scripts/bench_synth.py --target-mb 100 --jobs 1 4` scales that build and times each stage, printing seconds and peak memory. Not part of the package and never imported by it; peak memory reads the OS counters and prints `n/a` where the platform will not say. Read the numbers as "this machine, this builder" — a real target's timing is yours to measure.

## Offline explorer

`vb6d explore <run output dir> --out DIR [--chunk-bytes N]` — a static site over what `vb6d run` wrote: an overview, a searchable procedures page, the tables the closed SQL names (with the CRUD matrix and the statements that could not be parsed), and a forms page that links to the mockups the `frm` stage built. It works from `file://` on a machine with no server and no network: no `fetch`, no external file, no library.

Two rules make it safe rather than merely convenient. **No untrusted text becomes markup:** the embedded JSON escapes `<`, `>` and `&` as JSON unicode escapes, so a caption or a SQL string containing a closing `script` tag cannot end the block it sits in, and the page's own script writes through `textContent`, so a string is never parsed as HTML. **Only one script runs:** the CSP carries a per-file nonce, so the page allows exactly the script it was built with and nothing else.

What it embeds is a bounded slice, and the page says so: the procedure labels, the closed SQL text, the message-like literals and the table and column names. The full literal list stays in `dossier.jsonl` — embedding 441k literals of a real build would make a page nobody can open. Data is split into blocks of at most `--chunk-bytes` (2 MiB by default) and the stderr summary quotes the block count and the largest block, so a slow page has a number attached to it.
