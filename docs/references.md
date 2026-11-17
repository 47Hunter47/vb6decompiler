# Where the background came from

Nothing on this page is a source of numbers for this tool. Every offset, count and
grammar in `docs/formats.md` was measured from real builds here; the pages below are
what was read to know *what to look for*, and what a reader can go to for context
this repository does not cover.

## Runtime exports

* **`visualbasic` crate 0.2.1** — <https://github.com/BinFlip/visualbasic-rs>
  An Apache-2.0 Rust crate that parses VB6 binaries. Its
  [`data/msvbvm60_exports.csv`](https://docs.rs/crate/visualbasic/0.2.1/source/data/msvbvm60_exports.csv)
  maps each `MSVBVM60` export to a calling convention, parameter list and a short
  reverse-engineering note. Those notes are all the `description` field of
  `vb6decompiler/data/runtime_calls.json` consists of, and they stay marked
  `unverified`. Its ordinal column was checked against the local DLL and did not
  match, so names and ordinals are read from the DLL instead — see
  `THIRD_PARTY_NOTICES.md` and `scripts/gen_runtime_table.py`.

## P-Code and the runtime in general

* **Marion Marschalek, "Not old enough to be forgotten: the new chic of Visual
  Basic 6", Virus Bulletin, July 2014** —
  <https://www.virusbulletin.com/uploads/pdf/magazine/2014/vb201407-VB6.pdf>
  Why VB6 binaries look the way they do: the runtime DLL the entry point hands the
  application structure to, the byte-code interpreter behind P-Code, and what a
  native build's calls into the runtime resolve to.

* **David Zimmer, "VB6 P-Code Obfuscation", Gen Digital / Avast, 2021** —
  <https://www.gendigital.com/blog/insights/research/vb6-p-code-obfuscation>
  Where the names of P-Code handlers come from (debug symbols leaked with a handful
  of runtimes) and what happens when the byte stream itself is tampered with. Only
  relevant to the P-Code warning `vb6d procs --validate` prints.

* **Andrea Geddon, "Visual Basic Reversed — A decompiling approach"** —
  <https://sandsprite.com/vb-reversing/files/VISUAL%20BASIC%20REVERSED.pdf>
  A step-by-step walkthrough of the same header an entry point points at: signature,
  language DLL, project/dialog/external tables, and why VB arithmetic goes through
  `VARIANT` helpers. Useful as a second reading of `docs/formats.md` §3–4.

* **"The truth about P-Code", Visual Basic 6.0 — Superior Source Code, 2015** —
  <https://vb6awards.blogspot.com/2015/06/the-truth-about-p-code.html>
  One decompiler author's explanation of the P-Code/native split and of why the
  two need different recovery strategies. An opinion piece: its estimates are not
  measurements and are not used here.

## Commercial tools that handle VB5/6

Listed because a reader looking for a ready-made tool should know they exist. No
claim is made here about what any of them recovers.

* **VBReFormer** — <https://www.decompiler-vb.net/>
* **VB Decompiler** — <https://www.vb-decompiler.org/>
