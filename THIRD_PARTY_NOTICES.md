# Third-party notices

This repository ships one artifact derived from someone else's work. Everything
else here was measured from the target files themselves.

## `vb6decompiler/data/runtime_calls.json` — category and description fields

* Source: the `visualbasic` crate, version 0.2.1, file `data/msvbvm60_exports.csv`
  (<https://docs.rs/crate/visualbasic/0.2.1/source/data/msvbvm60_exports.csv>),
  project <https://github.com/BinFlip/visualbasic-rs>.
* Author: Johann Kempter.
* License: Apache License 2.0. Full text: <https://www.apache.org/licenses/LICENSE-2.0>.
* Used: the `category` and `notes` columns, as the `category` and `description`
  values of the generated table. `notes` is otherwise verbatim except that runs of
  backslashes become `/` (a doubled backslash in a note reads as a UNC share to this
  repo's own `mask` audit, which would then rewrite the shipped file). They are one
  reverser's reading of `MSVBVM60.DLL` and are marked `unverified` in every entry's
  `source` field and in every output line that prints them.
* Changed: the `ordinal` column was **not** used. Those ordinals disagree with the
  export table of `msvbvm60.dll` 6.00.9848 for all 602 rows (each off by +99), so
  `scripts/gen_runtime_table.py` reads names and ordinals from the DLL itself.
* Names the DLL exports but the CSV does not list (33 of 635) carry
  `description: null` rather than invented text.

Regenerate with:

```
python scripts/gen_runtime_table.py --dll <path to msvbvm60.dll> \
    --csv <path to msvbvm60_exports.csv>
```
