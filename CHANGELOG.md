# Changelog

Newest first. One section per released version; the numbers in a section are the ones
the workflow published, not drafts.

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
