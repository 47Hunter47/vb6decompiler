"""Command line entry point: one subcommand per stage, JSON or CSV on stdout.

Every subcommand prints what it measured and what it could not do. Exit code is 0
when the run completed, whatever it found — a missing thing is a result, not a
failure. An unusable input (not a PE, no ``VB5!`` header, missing file) exits 2
with one line on stderr; ``VB6D_DEBUG=1`` keeps the traceback for bug reports.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys


def _emit(rows, as_json: bool, fields: list[str] | None = None) -> None:
    if as_json:
        print(json.dumps(rows, ensure_ascii=False, indent=2, default=str))
        return
    if isinstance(rows, dict):
        for k, v in rows.items():
            print(f"{k}\t{v}")
        return
    if not rows:
        return
    if isinstance(rows[0], dict):
        cols = fields or list(rows[0].keys())
        w = csv.DictWriter(sys.stdout, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)
    else:
        for r in rows:
            print(r)


def _announce(codec: str, source: str) -> None:
    """Say which code page this run decoded with, once, on stderr.

    stderr and not stdout: stdout carries record lines only (AGENTS.md), and a
    ``#`` line there would have to be stripped by every caller that parses output.
    """
    from . import encoding

    print(encoding.summary_line(codec, source), file=sys.stderr)


def cmd_pe(args) -> int:
    from . import pe

    rows = pe.scan_directory(args.path, recursive=args.recursive)
    _emit(rows, args.json)
    if not args.json:
        vb6 = [r for r in rows if r.get("vb6")]
        errs = [r for r in rows if r.get("error")]
        print(f"# {len(rows)} images, {len(vb6)} import a VB6 runtime, {len(errs)} unreadable", file=sys.stderr)
    return 0


def cmd_procs(args) -> int:
    from . import encoding, procs

    explicit = args.encoding or encoding.env_codepage()
    project = procs.read(args.exe, encoding=explicit)
    # procs.read resolves explicit > header LCID > default; the only label it cannot
    # know is that the value came from the shell rather than the command line.
    source = "env" if (not args.encoding and encoding.env_codepage()) else project.encoding_source
    _announce(project.encoding, source)
    stats = project.stats()
    if args.names:
        names = procs.merge_listing_names(args.names)
        stats["names_from_listing"] = len(names)
    hint = None
    if args.validate:
        stats["prologue"] = procs.prologue_report(args.exe, project)
        hint = procs.pcode_hint(project)
    if args.json:
        _emit(
            {
                "stats": stats,
                "objects": [
                    {
                        "index": o.index,
                        "name": o.name,
                        "type": o.object_type,
                        "methods": o.method_count,
                    }
                    for o in project.objects
                ],
            },
            True,
        )
    else:
        for k, v in stats.items():
            print(f"{k}\t{v}")
        print(f"\n# {len(project.objects)} objects")
        for o in project.objects[: args.limit]:
            print(f"  [{o.index:4d}] {o.name:<24} {o.object_type:<12} methods={o.method_count}")
    if hint:
        print(hint, file=sys.stderr)
    return 0


def cmd_project(args) -> int:
    from . import encoding, procs, projectwrite

    explicit = args.encoding or encoding.env_codepage()
    project = procs.read(args.exe, encoding=explicit)
    source = "env" if (not args.encoding and encoding.env_codepage()) else project.encoding_source
    _announce(project.encoding, source)
    out_dir = args.out or projectwrite.default_out_dir(args.exe)
    report = projectwrite.write_project(project, out_dir)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    counts = report["counts"]
    print(f"# {counts['vbp_entries']} placeholder files + {projectwrite.DEFAULT_REPORT_NAME} -> {out_dir}",
          file=sys.stderr)
    return 0


def cmd_literals(args) -> int:
    from . import encoding, literals

    src = args.source
    if os.path.isdir(src):
        codec, source = encoding.choice(args.encoding, None)
        _announce(codec, source)
        lits = literals.scan_listings(src, encoding=codec)
    else:
        # The binary pass matches 0x20-0x7E only, so no code page is chosen here and
        # none is reported: BSTR literals are UTF-16 and are decoded by the format.
        lits = literals.scan_binary(src, min_chars=args.min_chars)
    if args.sql_only:
        lits = [l for l in lits if l.is_sql]
    _emit([l.as_row() for l in lits], False)
    print(f"# {len(lits)} literals", file=sys.stderr)
    return 0


def cmd_stitch(args) -> int:
    from . import encoding, literals, sqlstitch

    src = args.source
    if os.path.isdir(src):
        codec, source = encoding.choice(args.encoding, None)
        _announce(codec, source)
        lits = literals.scan_listings(src, encoding=codec)
    else:
        # The scan runs before the announcement so unusable input still costs
        # exit 2. shortcut: the scan only buys its seconds back as an empty
        # result on huge images; upgrade to a header probe if that ever matters.
        lits = literals.scan_binary(src)
        print("# binary input: no procedure ownership outside a listing, so chaining can only yield nothing — point stitch at a listing directory (binary text: vb6d literals <exe>)", file=sys.stderr)
    cands = sqlstitch.stitch_all(lits, max_more=args.max_more)
    rows = [c.as_row() for c in cands]
    _emit(rows, args.json)
    if not args.json:
        print(f"# {sqlstitch.summarise(cands)}", file=sys.stderr)
    return 0


def cmd_frm(args) -> int:
    from . import encoding, frm

    codec, source = encoding.choice(args.encoding, None)
    _announce(codec, source)
    res = frm.scan_directory(args.path, recursive=args.recursive, encoding=codec)
    if args.json:
        _emit(
            {
                "files_seen": res.files_seen,
                "forms": [
                    {
                        "name": f.name,
                        "type": f.type,
                        "controls": len(f.controls),
                        "client_size_twips": f.client_size,
                        "warnings": len(f.warnings),
                    }
                    for f in res.forms
                ],
                "no_design_block": res.no_design,
                "failures": res.failures,
            },
            True,
        )
        return 0
    for f in res.forms:
        size = f.client_size
        print(f"{f.name}	{size if size else 'unknown'}	controls={len(f.controls)}")
    print(
        f"# {res.files_seen} files: {len(res.forms)} parsed, "
        f"{len(res.no_design)} without a design block, {len(res.failures)} failed",
        file=sys.stderr,
    )
    return 0


def cmd_blob(args) -> int:
    from dataclasses import asdict

    from . import blob

    codec, source = blob.codec_for(args.exe, args.encoding)
    _announce(codec, source)
    if args.validate:
        report = blob.validate(args.exe, frm_dir=args.frm_dir, encoding=codec)
        payload = asdict(report)
        payload["field_diffs"] = dict(report.field_diffs)
        payload["control_rate"] = round(report.control_rate, 2)
        payload["form_rate"] = round(report.form_rate, 2)
        _emit(payload, True)
        print(report.summary(), file=sys.stderr)
        return 0
    forms = blob.extract_forms(args.exe, encoding=codec)
    if args.json:
        # CSV rows are per-form; the per-control detail belongs to --json only,
        # because its row count is in the ten-thousands on a real build.
        _emit(
            [
                {
                    "name": f.name,
                    "controls": len(f.controls),
                    "width": f.width,
                    "height": f.height,
                    "client_left": f.client_left,
                    "client_top": f.client_top,
                    "controls_detail": [
                        {k: getattr(c, k) for k in
                         ("name", "type", "caption", "left", "top", "width",
                          "height", "index", "visible", "tab_page", "pages")}
                        for c in f.controls
                    ],
                }
                for f in forms
            ],
            True,
        )
    else:
        _emit(
            [
                {"name": f.name, "controls": len(f.controls), "width": f.width, "height": f.height}
                for f in forms
            ],
            False,
        )
    print(f"# {len(forms)} forms from form-data blobs", file=sys.stderr)
    return 0


def cmd_datareport(args) -> int:
    from . import datareport

    files = datareport.iter_files([args.path]) if os.path.isdir(args.path) else [args.path]
    designs = datareport.read_paths(files)
    if args.json:
        _emit({"summary": datareport.summary(designs), "designs": [d.as_dict() for d in designs]}, True)
        return 0
    for d in designs:
        print(f"{os.path.basename(d.path)}	{d.name}	records={len(d.records)}	sections={len(d.sections)}	controls={len(d.controls)}")
    for k, v in datareport.summary(designs).items():
        print(f"# {k}	{v}", file=sys.stderr)
    return 0


def cmd_dossier(args) -> int:
    from . import dossier, encoding

    # A typo'd listing directory would produce an empty, perfectly valid JSONL file;
    # os.stat turns that into the exit-2 contract instead of a silent no-op.
    os.stat(args.listings)
    codec, source = encoding.choice(args.encoding, None)
    _announce(codec, source)
    out_path = args.out or os.path.join(args.listings, dossier.DEFAULT_OUT_NAME)
    with open(out_path, "w", encoding="utf-8", newline="") as fh:
        report = dossier.stream(args.listings, fh, encoding=codec,
                                inventory_path=args.inventory)
    for line in report.lines():
        print(line, file=sys.stderr)
    print(f"# wrote {out_path}", file=sys.stderr)
    return 0


def cmd_xref(args) -> int:
    from . import xref

    os.stat(args.dossier)
    with open(args.dossier, encoding="utf-8") as fh:
        procs, bad = xref._procedures(fh)
    for note in bad:
        print(f"# {note}", file=sys.stderr)
    if args.literal:
        shape = xref.search(procs, args.literal, "literals")
        kind = f"literal search {args.literal!r}"
    elif args.sql:
        shape = xref.search(procs, args.sql, "sql")
        kind = f"sql search {args.sql!r}"
    elif args.full:
        shape = xref.full(procs)
        kind = "full index"
    else:
        shape = xref.rollup(procs)
        kind = "procedure rollup"
    print(json.dumps({"tool": "vb6d xref", **shape}, ensure_ascii=False, indent=2))
    mentions = sum(len(p["literals"]) for p in procs)
    print(f"# {len(procs)} procedures, {mentions} literal mentions; {kind}", file=sys.stderr)
    return 0


def cmd_mask(args) -> int:
    from . import mask

    # A gate aimed at a typo'd or missing path found nothing because it looked at
    # nothing; exiting 0 there would make every CI run of this gate meaningless.
    os.stat(args.path)
    result = mask.mask_tree(args.path, dry_run=args.dry_run)
    changed = {k: v for k, v in result.items() if v}
    print(f"# {len(result)} files scanned, {len(changed)} changed, {sum(changed.values())} lines")
    audit = mask.audit(args.path)
    print(f"# audit: files={audit.files} lines={audit.lines} findings={audit.findings} clean={audit.clean}")
    # --dry-run skips the *write*, not the check: a gate that exits 0 in dry-run can
    # never fail in CI, which is how a real leak would sail through.
    return 0 if audit.clean else 1


def _version_line() -> str:
    from importlib.metadata import PackageNotFoundError, version

    try:
        return f"vb6d {version('vb6decompiler')}"
    except PackageNotFoundError:
        return "vb6d (version unknown: bare source checkout, not installed)"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vb6d",
        description="Evidence-based recovery of native-compiled VB6 programs.",
    )
    # An agent needs to pin the tool that produced a result file. The version
    # lives in pyproject.toml only (docs/RULES.md), so it is read from the
    # installed distribution; a bare source checkout has no metadata to ask.
    p.add_argument("--version", action="version", version=_version_line(),
                   help="print the package version and exit")
    sub = p.add_subparsers(dest="command", required=True)

    q = sub.add_parser("pe", help="PE surface of a file or install directory")
    q.add_argument("path")
    q.add_argument("--recursive", action="store_true")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_pe)

    q = sub.add_parser("procs", help="VB6 object table: objects, method counts, addresses")
    q.add_argument("exe")
    q.add_argument("--names", metavar="LISTING_DIR", help="count unique procedure VAs found in a decompiler listing (per-procedure names: vb6d dossier)")
    q.add_argument("--validate", action="store_true", help="check that entries are real prologues")
    q.add_argument("--limit", type=int, default=40)
    q.add_argument("--json", action="store_true")
    q.add_argument("--encoding", metavar="CODEPAGE", default=None,
                    help="code page of the decoded text (default: header LCID, else cp1254; env VB6D_ENCODING)")
    q.set_defaults(func=cmd_procs)

    q = sub.add_parser("project", help="project skeleton: .vbp + placeholder files + recovery report")
    q.add_argument("exe")
    q.add_argument("--out", metavar="DIR", default=None,
                   help="output directory (default: <exe-name>_project beside the exe; never the exe itself)")
    q.add_argument("--json", action="store_true",
                   help="print the recovery report as JSON on stdout (files are written either way)")
    q.add_argument("--encoding", metavar="CODEPAGE", default=None,
                    help="code page of the decoded text (default: header LCID, else cp1254; env VB6D_ENCODING)")
    q.set_defaults(func=cmd_project)

    q = sub.add_parser("literals", help="BSTR/UTF-16 and ASCII literals, with addresses")
    q.add_argument("source", help="an .exe/.dll, or a directory of decompiler listings")
    q.add_argument("--min-chars", type=int, default=4)
    q.add_argument("--sql-only", action="store_true")
    q.add_argument("--encoding", metavar="CODEPAGE", default=None,
                    help="code page of the decoded text (default: header LCID, else cp1254; env VB6D_ENCODING)")
    q.set_defaults(func=cmd_literals)

    q = sub.add_parser("stitch", help="join SQL fragments and classify what did not close")
    q.add_argument("source")
    q.add_argument("--max-more", type=int, default=6)
    q.add_argument("--json", action="store_true")
    q.add_argument("--encoding", metavar="CODEPAGE", default=None,
                    help="code page of the decoded text (default: header LCID, else cp1254; env VB6D_ENCODING)")
    q.set_defaults(func=cmd_stitch)

    q = sub.add_parser("frm", help="parse .frm design blocks")
    q.add_argument("path")
    q.add_argument("--recursive", action="store_true")
    q.add_argument("--json", action="store_true")
    q.add_argument("--encoding", metavar="CODEPAGE", default=None,
                    help="code page of the decoded text (default: header LCID, else cp1254; env VB6D_ENCODING)")
    q.set_defaults(func=cmd_frm)

    q = sub.add_parser("blob", help="form geometry from the executable's form-data blobs")
    q.add_argument("exe")
    q.add_argument("--validate", action="store_true")
    q.add_argument("--frm-dir", help="ground-truth .frm directory for --validate")
    q.add_argument("--json", action="store_true")
    q.add_argument("--encoding", metavar="CODEPAGE", default=None,
                    help="code page of the decoded text (default: header LCID, else cp1254; env VB6D_ENCODING)")
    q.set_defaults(func=cmd_blob)

    q = sub.add_parser("datareport", help="DataReport layouts from report DLLs")
    q.add_argument("path", help="a DLL, or the install directory holding rpt*.dll")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_datareport)

    q = sub.add_parser("dossier", help="per-procedure evidence file, one JSON object per line")
    q.add_argument("--listings", required=True, metavar="DIR",
                   help="directory of decompiler listings (the same input as 'literals'/'stitch')")
    q.add_argument("--out", default=None, help="JSONL output path (default: DIR/dossier.jsonl)")
    q.add_argument("--inventory", default=None,
                   help="pseudoc_inventory.py output directory to merge by procedure VA")
    q.add_argument("--encoding", metavar="CODEPAGE", default=None,
                   help="code page of the listing text (default: cp1254; env VB6D_ENCODING)")
    q.set_defaults(func=cmd_dossier)

    q = sub.add_parser("xref", help="query a dossier file from the other side: which procedures touch X")
    q.add_argument("dossier", help="a dossier JSONL file (the output of 'vb6d dossier')")
    shape = q.add_mutually_exclusive_group()
    shape.add_argument("--literal", metavar="SUBSTR",
                       help="literal entries whose text contains SUBSTR (case-insensitive), with owning procedures")
    shape.add_argument("--sql", metavar="SUBSTR",
                       help="SQL entries whose text contains SUBSTR (case-insensitive), with owning procedures")
    shape.add_argument("--full", action="store_true",
                       help="both inverted indexes at once (large on real builds; default is the procedure rollup)")
    q.set_defaults(func=cmd_xref)

    q = sub.add_parser("mask", help="mask credentials in generated artefacts and audit the result")
    q.add_argument("path")
    q.add_argument("--dry-run", action="store_true")
    q.set_defaults(func=cmd_mask)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    # A stranger pipes output to a file on a cp1252 console; literals recovered
    # from UTF-16 are not encodable there. Cosmetic only: never changes exit codes.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, OSError):
            pass
    try:
        return args.func(args)
    except Exception as exc:
        # Named errors (VBError, PEError, FrmError) already carry their path and
        # cause; one line keeps a stranger's first crash readable, not a wall of
        # traceback. VB6D_DEBUG restores the full traceback for bug reports.
        if os.environ.get("VB6D_DEBUG"):
            raise
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
