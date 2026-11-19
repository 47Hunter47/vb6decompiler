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

