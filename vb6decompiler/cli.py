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
    from . import procs

    project = procs.read(args.exe)
    stats = project.stats()
    if args.names:
        names = procs.merge_listing_names(args.names)
        stats["names_from_listing"] = len(names)
    if args.validate:
        stats["prologue"] = procs.prologue_report(args.exe, project)
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
    return 0


def cmd_literals(args) -> int:
    from . import literals

    src = args.source
    if os.path.isdir(src):
        lits = literals.scan_listings(src)
    else:
        lits = literals.scan_binary(src, min_chars=args.min_chars)
    if args.sql_only:
        lits = [l for l in lits if l.is_sql]
    _emit([l.as_row() for l in lits], False)
    print(f"# {len(lits)} literals", file=sys.stderr)
    return 0


def cmd_stitch(args) -> int:
    from . import literals, sqlstitch

    src = args.source
    lits = literals.scan_listings(src) if os.path.isdir(src) else literals.scan_binary(src)
    cands = sqlstitch.stitch_all(lits, max_more=args.max_more)
    rows = [c.as_row() for c in cands]
    _emit(rows, args.json)
    if not args.json:
        print(f"# {sqlstitch.summarise(cands)}", file=sys.stderr)
    return 0


def cmd_frm(args) -> int:
    from . import frm

    res = frm.scan_directory(args.path, recursive=args.recursive)
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

    if args.validate:
        report = blob.validate(args.exe, frm_dir=args.frm_dir)
        payload = asdict(report)
        payload["field_diffs"] = dict(report.field_diffs)
        payload["control_rate"] = round(report.control_rate, 2)
        payload["form_rate"] = round(report.form_rate, 2)
        _emit(payload, True)
        print(report.summary(), file=sys.stderr)
        return 0
    forms = blob.extract_forms(args.exe)
    _emit(
        [
            {
                "name": f.name,
                "controls": len(f.controls),
                "width": f.width,
                "height": f.height,
            }
            for f in forms
        ],
        args.json,
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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vb6d",
        description="Evidence-based recovery of native-compiled VB6 programs.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    q = sub.add_parser("pe", help="PE surface of a file or install directory")
    q.add_argument("path")
    q.add_argument("--recursive", action="store_true")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_pe)

    q = sub.add_parser("procs", help="VB6 object table: objects, method counts, addresses")
    q.add_argument("exe")
    q.add_argument("--names", metavar="LISTING_DIR", help="attach names from a decompiler listing")
    q.add_argument("--validate", action="store_true", help="check that entries are real prologues")
    q.add_argument("--limit", type=int, default=40)
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_procs)

    q = sub.add_parser("literals", help="BSTR/UTF-16 and ASCII literals, with addresses")
    q.add_argument("source", help="an .exe/.dll, or a directory of decompiler listings")
    q.add_argument("--min-chars", type=int, default=4)
    q.add_argument("--sql-only", action="store_true")
    q.set_defaults(func=cmd_literals)

    q = sub.add_parser("stitch", help="join SQL fragments and classify what did not close")
    q.add_argument("source")
    q.add_argument("--max-more", type=int, default=6)
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_stitch)

    q = sub.add_parser("frm", help="parse .frm design blocks")
    q.add_argument("path")
    q.add_argument("--recursive", action="store_true")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_frm)

    q = sub.add_parser("blob", help="form geometry from the executable's form-data blobs")
    q.add_argument("exe")
    q.add_argument("--validate", action="store_true")
    q.add_argument("--frm-dir", help="ground-truth .frm directory for --validate")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_blob)

    q = sub.add_parser("datareport", help="DataReport layouts from report DLLs")
    q.add_argument("path", help="a DLL, or the install directory holding rpt*.dll")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_datareport)

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
