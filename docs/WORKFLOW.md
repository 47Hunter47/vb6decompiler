# From a lost-source executable to a rewrite specification

One screen per step. Every command below is real; the target is the **synthetic**
build, so the whole workflow can be followed without a VB6 program at hand. Where a
step's numbers would come from your build, the text says so — none of the figures here
are measurements of a real program.

Each step names what it produces and what it may *not* be used to claim. That second
half is the point: this toolkit's output is evidence, and evidence that is read as
more than it is becomes a wrong rewrite.

---

## 0. Check the machine

```bash
vb6d doctor
```

One `ok`/`warn`/`fail` line per fact a first run depends on: interpreter, optional
engine, runtime table, the code page that will be chosen and where that choice came
from, `VB6D_*` paths, temp directory, free space. Exit `0` clean, `1` warnings only,
`2` a check failed.

*Why first:* a first failure is usually the environment, not the file. An absent
capstone extra, for instance, disables `decode` and `edges` — and a run without them
still completes, which is exactly the kind of silence worth catching at the start.

---

## 1. Name the inputs once

```bash
vb6d init --dir work
# edit work/vb6d.toml: target, listings, frm_dir, output
```

`init` writes commented placeholders only — no path from your machine, no target name —
because the file is meant to be committed next to your notes. Unknown keys are refused,
so a typo cannot configure nothing and complain about nothing.

*What it is not:* a lock file. Flags still beat it, and `VB6D_*` variables beat it too.

---

## 2. Run the passes

```bash
vb6d run --config work/vb6d.toml
```

Stages in dependency order, each into its own directory with its own manifest, and a
table at the end: status, seconds, note. A stage that fails does not cancel the others;
anything depending on it is reported `skipped: <stage> failed`.

```
stage      status        time  records                            note
pe         ok            0.1s  -                                  
...
dossier    ok            0.2s  -
schema     ok            0.0s  -
```

Run it a second time and the stages that already produced their output say `up to
date`: the manifest beside each output has to match the input hashes and the tool
version, or the stage runs again. `--force-stage` is for when you *want* the pass
repeated.

---

## 3. Read the surface

```bash
vb6d pe "<exe>"        # is it VB6 at all, and what does it import
vb6d procs "<exe>"     # objects and method counts; entries only where a prologue verified
```

*Claim it supports:* "this is a native VB6 build with N objects". *Not:* "these are the
procedure addresses" — in a native build the object table usually does not carry them,
and the ones it names are verified by a prologue rather than trusted.

---

## 4. Harvest the text

```bash
vb6d literals "<exe>" > literals.csv
vb6d stitch "<listings dir>"
```

`literals` finds `BSTR`s (UTF-16LE, length-prefixed) that an ASCII scanner misses;
`stitch` joins neighbouring fragments into statements and classifies what did not
close: `OPEN_QUOTE` needs a run-time value, `MULTI` is two statements in one string,
`ESCAPE` is human text glued on.

*Claim it supports:* "these statements are complete". *Not:* "these are the program's
queries" — the closed set is a lower bound, always.

---

## 5. See the forms

```bash
vb6d frm "<frm dir>" --format html --out out/frm --exe "<exe>"
```

One page per form: boxes at the recovered geometry, unknown control types as dashed
placeholders with their own type name, and the `.frm` geometry cross-checked against
the executable's own form blob where both exist. Every page prints the twips-to-pixel
factor **and says it is assumed** (15 twips/px is the classic 96 dpi value; nothing
measures it per build), so `--scale` is there when your forms look wrong.

*Claim it supports:* "this form had these controls at these positions". *Not:* "this is
the UI" — behaviour, data binding and the VB6 layout engine are not modelled.

---

## 6. Build the data model

```bash
vb6d schema out/dossier/dossier.jsonl --format md --out out/schema.md
```

Per table: the columns named explicitly, who reads and who writes it, and a CRUD matrix
by object. Plus the statements that could not be parsed, with a reason and a hash, and
the open ones counted as gaps.

*Claim it supports:* "these tables and columns are named by closed SQL, by these
objects". *Not:* "this is the schema" — a column is attributed to a table only when the
statement said which table, and `*` stays a star.

---

## 7. Write the specification

```bash
vb6d spec out/dossier/dossier.jsonl --exe "<exe>" --frm "<frm dir>" \
    --outline out/outline/outline.jsonl --out out/spec
```

`index.md` plus one file per object: kind *and the stage that supplied it*, the design
table, and per procedure its VA, name hints, message-like text, SQL, runtime-call
categories and a Gaps section with denominators. Anything not supplied is named in the
file ("no .frm directory supplied") instead of leaving a section that reads like a
measurement.

This is the deliverable of a lost-source recovery: not source, but something a
developer can rebuild from, with every fact traceable to a stage.

---

## 8. Explore it

```bash
vb6d explore out --out out/explore
```

A static site: searchable procedures, the tables, and the form mockups. Opens from
`file://` — no server, no network — because the data is embedded in the pages and the
CSP allows exactly the script each page carries.

*What it embeds:* labels, closed SQL, message-like literals, table and column names.
The full literal list stays in `dossier.jsonl`, and the page says so.

---

## 9. Before you publish anything

```bash
vb6d mask out --dry-run
```

Non-zero means a credential-shaped or host-shaped string is in the outputs. Sanitise,
then rerun. Do this before pasting a `dossier.jsonl` into a ticket, and prefer
`vb6d unknowns` (counts, page buckets and hash prefixes) when what you need is to
report a gap rather than to share the data.

---

## Where this workflow stops

* **Names.** A native build does not carry them. A decompiler's names are guesses; a
  listing's names are designer event names, which repeat.
* **Expression-level code.** Reconstructing VB semantics (`Variant`, late binding,
  `On Error`) from native code is research, not a parse.
* **Run-time flows.** Which control sends which value to which parameter is visible in
  a trace, not in the file. Open SQL needs that trace, and the toolkit reports it as a
  boundary rather than filling it in.
