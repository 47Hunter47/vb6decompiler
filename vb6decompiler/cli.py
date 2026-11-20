"""Command line entry point: one subcommand per stage, JSON or CSV on stdout.

Every subcommand prints what it measured and what it could not do. Exit code is 0
when the run completed, whatever it found — a missing thing is a result, not a
failure. An unusable input or a wrong invocation (not a PE, no ``VB5!`` header,
missing file) exits 2 with one line on stderr; a failure the toolkit cannot blame
on the caller's input exits 3 with the exception type, so an agent can tell a bug
report from its own typo. ``VB6D_DEBUG=1`` keeps the traceback for bug reports.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys

from .errors import ExpectedInput


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
    from . import encoding, manifest, procs, projectwrite

    started = manifest.now()

    explicit = args.encoding or encoding.env_codepage()
    project = procs.read(args.exe, encoding=explicit)
    source = "env" if (not args.encoding and encoding.env_codepage()) else project.encoding_source
    _announce(project.encoding, source)
    out_dir = args.out or projectwrite.default_out_dir(args.exe)
    report = projectwrite.write_project(project, out_dir, force=args.force)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    counts = report["counts"]
    print(f"# {counts['vbp_entries']} placeholder files + {projectwrite.DEFAULT_REPORT_NAME} -> {out_dir}",
          file=sys.stderr)
    # Beside the directory, not inside it: the tree is the recovered project and a
    # file of ours in it would be read as a source object.
    written = manifest.write(out_dir, skip=args.no_manifest, command="project",
                             inputs=[args.exe], encoding=(project.encoding, source),
                             started=started, records=counts, full_paths=args.manifest_paths)
    if written:
        print(f"# manifest: {written}", file=sys.stderr)
    return 0


def cmd_decode(args) -> int:
    from . import blob, fileio, pe, records, x86

    # Bad flags are the caller's invocation, not a toolkit fault: exit 2 with one
    # line (int(x, 16) would also have taken "0x", signs and underscores).
    va = records.hex_va(args.va)
    if va is None:
        raise fileio.InputError(f"--va {args.va!r}: not a bare hex address")
    if args.limit <= 0:
        raise fileio.InputError(f"--limit {args.limit}: must be a positive count")
    if args.window <= 0:
        raise fileio.InputError(f"--window {args.window}: must be a positive byte count")
    end = None
    if args.end_va is not None:
        end = records.hex_va(args.end_va)
        if end is None:
            raise fileio.InputError(f"--end-va {args.end_va!r}: not a bare hex address")
    data, sections = blob.load_sections(args.exe)
    window = b""
    for sec in sections:
        if sec.virtual_address <= va < sec.virtual_address + sec.span:
            delta = va - sec.virtual_address
            if delta < sec.raw_size:  # a virtual-only section holds no bytes here
                # clamp to what this section actually has on disk; the result's
                # ``ended`` field then honestly says where decoding stopped, so
                # no exact-length read is needed the way blob.py's read_va wants
                window = data[sec.raw_pointer + delta:
                              sec.raw_pointer + delta + min(args.window, sec.raw_size - delta)]
            break
    if not window:
        raise fileio.InputError(f"no file bytes mapped at VA {args.va.upper()} "
                                "(outside every section or past its raw data)")
    if end is not None:
        if end <= va:
            raise fileio.InputError("--end-va must be above --va")
        window = window[: end - va]  # the range's own end: nothing past it is decoded
    try:
        result = x86.decode(window, va, limit=args.limit)
    except x86.EngineUnavailable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    # name call targets against this file's own import table; late-bound
    # [reg+disp] calls stay unannotated because nothing here can name them
    iat = pe.import_names(pe.read(args.exe))
    vas, owners = [], []
    if args.procs:
        from . import fileio, records
        from .edges import owner_index

        fileio.require(args.procs)  # a missing explicit input is exit 2, not a crash
        bad = 0
        with open(args.procs, encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                try:
                    d = json.loads(line)
                except ValueError:
                    bad += 1  # builder policy from dossier: count, skip, keep going
                    print(f"# line {n}: not JSON", file=sys.stderr)
                    continue
                reason = records.reject_reason(d)
                if reason is not None:
                    bad += 1
                    print(f"# line {n}: {reason}", file=sys.stderr)
                    continue
                proc_va = records.hex_va(d["va"])
                if proc_va is None:  # unreachable: reject_reason turned that shape away
                    continue
                vas.append(proc_va)
                owners.append(d)
        order = sorted(range(len(vas)), key=vas.__getitem__)
        vas = [vas[i] for i in order]
        owners = [owners[i] for i in order]
        if bad:
            print(f"# warning: {bad} unreadable lines skipped in {args.procs}", file=sys.stderr)
    named = calls = landed = 0
    for row in result["rows"]:
        if not row["mnemonic"].startswith("call"):
            continue
        calls += 1
        t = x86.call_target(row["operands"])
        if t is None:
            continue
        row["target_va"] = f"{t:X}"
        name = iat.get(t)
        if name:
            row["target"] = name
            named += 1
        elif args.procs:
            # attribution, not identity: the target lands inside the range a
            # listing reported for that procedure (t35's standing warning);
            # the SAME policy edges uses, cap on the last range included
            i = owner_index(vas, t)
            if i is not None:
                o = owners[i]
                row["target_proc"] = {"va": f"{vas[i]:X}",
                                      "object_name": o.get("object_name"),
                                      "names": (o.get("name_hint") or {}).get("names") or []}
                landed += 1
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        for r in result["rows"]:
            line = f"{r['va']}  {r['bytes']:<18} {r['mnemonic']} {r['operands']}".rstrip()
            if "target" in r:
                line += f"  -> {r['target']}"
            elif "target_proc" in r:
                tp = r["target_proc"]
                line += f"  -> proc {tp['va']} ({tp['object_name']})"
            print(line)
    stop = f", stopped at {result['stopped_at_va']}" if "stopped_at_va" in result else ""
    extra = f", {landed} land on known procedures" if args.procs else ""
    print(f"# {result['instructions']} instructions, {result['consumed_bytes']} bytes, "
          f"ended: {result['ended']}{stop}; calls: {named} of {calls} named via import table{extra}",
          file=sys.stderr)
    return 0


def cmd_edges(args) -> int:
    from . import edges, fileio, manifest, x86

    started = manifest.now()

    out = args.out or os.path.join(os.path.dirname(os.path.abspath(args.dossier)), "edges.jsonl")
    # a typo'd dossier is unusable input, not an empty edge set: name it
    # with the path as typed before collect() opens anything
    fileio.require(args.dossier)
    # writing onto either input file would destroy it after a five-minute pass:
    # refuse before collect() opens the image
    fileio.refuse_overwrite_inputs(out, [args.dossier, args.exe])
    try:
        rows, bad, totals = edges.collect(args.exe, args.dossier, events=args.events)
    except x86.EngineUnavailable as exc:
        # same contract as decode: the optional extra is missing, so this is
        # unusable capability (exit 2) with the install hint, and no output file
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if bad:
        print(f"# warning: {bad} unreadable lines skipped in {args.dossier}", file=sys.stderr)
    with fileio.atomic_out(out) as fh:
        fh.writelines(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)
    ev = f"; events on: {totals['events']} named events, {totals['literal_events']} literal loads" if args.events else ""
    print(f"# {len(rows)} procedures -> {out}; totals: {totals['named']} named via imports, "
          f"{totals['thunk_named']} named via import thunks, "
          f"{totals['edges']} attributed to listed procedures, {totals['late_bound']} late-bound, "
          f"{totals['obj_named']} on object-table functions of known objects, "
          f"{totals['uncensus']} still unnamed{ev}", file=sys.stderr)
    written = manifest.write(out, skip=args.no_manifest, command="edges",
                             inputs=[args.exe, args.dossier], encoding=None, started=started,
                             records={"procedures": len(rows), "unreadable_lines": bad, **totals},
                             full_paths=args.manifest_paths)
    if written:
        print(f"# manifest: {written}", file=sys.stderr)
    return 0


def cmd_graph(args) -> int:
    from . import fileio, graph, manifest

    started = manifest.now()
    fileio.require(args.edges)
    rows = graph.rows_from(args.edges)
    if not rows:
        raise fileio.InputError(f"{args.edges}: no readable edges row (is this 'vb6d edges' output?)")
    whole = graph.whole_graph(rows)
    if args.from_ or args.depth is not None:
        start = args.from_
        if start is None:
            raise fileio.InputError("--depth needs --from: a slice has to start somewhere")
        depth = 2 if args.depth is None else args.depth
        try:
            drawn = graph.slice_graph(whole, start, depth, direction=args.direction)
        except graph.GraphError as exc:
            raise fileio.InputError(str(exc)) from exc
        kind = f"slice from {start} ({args.direction}, depth {depth})"
    elif args.all:
        drawn = whole
        kind = "the whole graph"
        print(f"# warning: --all on {len(rows)} procedures - the picture is as large as the "
              f"program; prefer --from with --depth", file=sys.stderr)
    else:
        raise fileio.InputError("nothing to draw: pass --from NAME_OR_VA (with --depth) or --all")

    body = graph.as_dot(drawn) if args.format == "dot" else graph.as_mermaid(drawn)
    if args.out:
        fileio.refuse_overwrite_inputs(args.out, [args.edges])
        with fileio.atomic_out(args.out, newline="") as fh:
            fh.write(body)
        print(f"# wrote {args.out}", file=sys.stderr)
        written = manifest.write(args.out, skip=args.no_manifest, command="graph",
                                 inputs=[args.edges], encoding=None, started=started,
                                 records={**drawn.counts(), "rows_read": len(rows)},
                                 full_paths=args.manifest_paths)
        if written:
            print(f"# manifest: {written}", file=sys.stderr)
    else:
        print(body, end="")
    print(f"# {kind}: {graph.compare(drawn, whole)}; {drawn.counts()['imports']} imported "
          f"helpers, {drawn.counts()['unresolved']} unresolved nodes", file=sys.stderr)
    return 0


def cmd_outline(args) -> int:
    from . import fileio, manifest, outline

    started = manifest.now()

    out = args.out or os.path.join(os.path.dirname(os.path.abspath(args.edges)), "outline.jsonl")
    fileio.require(args.edges)  # same contract: the path as typed, one line, exit 2
    fileio.refuse_overwrite_inputs(out, [args.edges])  # truncating the input would empty it mid-read
    fh = open(args.edges, encoding="utf-8")
    rows = categorized = unlisted = api = bad = 0
    with fh, fileio.atomic_out(out) as sink:
        for n, line in enumerate(fh, 1):
            try:
                edge = json.loads(line)
            except ValueError:
                bad += 1  # dossier policy again: count, skip, keep going
                print(f"# line {n}: not JSON", file=sys.stderr)
                continue
            if not isinstance(edge, dict):
                bad += 1
                print(f"# line {n}: record is not a JSON object", file=sys.stderr)
                continue
            va = edge.get("va")
            if not isinstance(va, str) or not va:
                bad += 1
                print(f"# line {n}: edges row has no va", file=sys.stderr)
                continue
            try:
                int(va, 16)
            except ValueError:
                bad += 1
                print(f"# line {n}: va {va!r} is not a hex address", file=sys.stderr)
                continue
            try:
                r = outline.outline_row(edge)
            except (ValueError, KeyError, TypeError, AttributeError):
                bad += 1
                print(f"# line {n}: edges row has malformed fields", file=sys.stderr)
                continue
            sink.write(json.dumps(r, ensure_ascii=False) + "\n")
            rows += 1
            categorized += sum(r["unverified_operations"].values())
            unlisted += sum(r.get("runtime_unlisted", {}).values())
            api += sum(r["api_calls"].values())
    if bad:
        print(f"# warning: {bad} unreadable lines skipped in {args.edges}", file=sys.stderr)
    print(f"# {rows} procedures -> {out}; {categorized} runtime hits bucketed by "
          f"category (third-party notes - unverified), {unlisted} runtime hits the table "
          f"does not categorize, {api} hits on other dlls", file=sys.stderr)
    written = manifest.write(out, skip=args.no_manifest, command="outline",
                             inputs=[args.edges], encoding=None, started=started,
                             records={"procedures": rows, "unreadable_lines": bad,
                                      "categorized_calls": categorized,
                                      "uncategorized_calls": unlisted,
                                      "external_calls": api},
                             full_paths=args.manifest_paths)
    if written:
        print(f"# manifest: {written}", file=sys.stderr)
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


def _html_views(forms, blob_exe: str | None) -> tuple[list, list]:
    """``(views, notes)`` for the HTML mode: .frm geometry, cross-checked with blobs.

    The two sources are read by different parsers and stored differently (``.frm``
    geometry lives in each control's properties, blob geometry is flat fields), so
    the comparison happens here on the numbers themselves. A form that only the
    blob knows still gets a page: dropping it would hide recovered evidence.
    """
    from . import blob as blob_mod
    from . import htmlview

    views: dict[str, htmlview.FormView] = {}
    for form in forms:
        boxes = []
        for control in form.controls:
            bounds = control.bounds
            caption = control.prop("Caption")
            visible = control.prop("Visible")
            index = control.prop("Index")
            boxes.append(htmlview.Box(
                name=control.name, type=control.type,
                caption=str(caption.value) if caption is not None else None,
                left=bounds[0] if bounds else None, top=bounds[1] if bounds else None,
                width=bounds[2] if bounds else None, height=bounds[3] if bounds else None,
                visible=bool(visible.value) if visible is not None else None,
                index=int(index.value) if index is not None and isinstance(index.value, int) else None,
                parent=control.parent))
        size = form.client_size
        views[form.name.lower()] = htmlview.FormView(
            name=form.name, source=".frm design text", width=size[0] if size else None,
            height=size[1] if size else None, boxes=boxes)

    notes: list[str] = []
    if blob_exe:
        blobs = blob_mod.iter_form_blobs(blob_exe)
        codec = blob_mod.codec_for(blob_exe)[0]
        for blob in blobs:
            parsed = blob_mod.extract_form(blob, encoding=codec)
            if parsed is None:
                continue
            key = parsed.name.lower()
            view = views.get(key)
            if view is None:
                views[key] = htmlview.FormView(
                    name=parsed.name, source="binary form blob",
                    width=parsed.width, height=parsed.height,
                    boxes=[htmlview.Box(name=c.name, type=c.type, caption=c.caption,
                                        left=c.left, top=c.top, width=c.width, height=c.height,
                                        visible=c.visible, index=c.index) for c in parsed.controls],
                    notes=[("no .frm design block for this form: the geometry above comes from "
                            "the executable's own form-data blob")])
                continue
            blob_boxes = {c.name.lower(): (c.type, c.left, c.top, c.width, c.height)
                          for c in parsed.controls}
            agree = sum(1 for box in view.boxes
                        if (box.type, box.left, box.top, box.width, box.height)
                        == blob_boxes.get(box.name.lower()))
            view.crosscheck = (agree, len(view.boxes))
            if agree != len(view.boxes):
                notes.append(f"{view.name}: {agree} of {len(view.boxes)} controls agree with the "
                             f"blob (a form rebuilt after the .frm in hand is the known cause)")
        notes.insert(0, f"{len(blobs)} form blobs read from the executable and used to cross-check")
    return list(views.values()), notes


def cmd_frm(args) -> int:
    from . import encoding, frm

    codec, source = encoding.choice(args.encoding, None)
    _announce(codec, source)
    res = frm.scan_directory(args.path, recursive=args.recursive, encoding=codec)
    if args.format == "html" or args.html:
        return _frm_html(args, res)
    if args.json:
        _emit(
            {
                "files_seen": res.files_seen,
                "forms": [
                    {
                        "name": f.name,
                        "type": f.type,
                        "controls": len(f.controls),  # count; details ride in "detail"
                        "client_size_twips": f.client_size,
                        "warnings": len(f.warnings),
                        "detail": frm.form_json(f),
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


def _frm_html(args, res) -> int:
    from . import fileio, htmlview, manifest, spec

    if not args.out:
        raise fileio.InputError("--format html needs --out DIR")
    started = manifest.now()
    views, notes = _html_views(res.forms, args.exe)
    if not views:
        raise fileio.InputError(f"{args.path}: no form to draw ({res.files_seen} files seen)")
    # ``args.scale or default`` would turn an explicit 0 into the default and hide a
    # flag value the user has to fix; --scale is checked, not coerced.
    scale = htmlview.TWIPS_PER_PX if args.scale is None else args.scale
    if scale <= 0:
        raise fileio.InputError(f"--scale {scale}: must be a positive number of twips per pixel")
    out_dir = args.out
    if os.path.exists(out_dir) and not os.path.isdir(out_dir):
        raise fileio.InputError(f"{out_dir}: exists and is not a directory")
    os.makedirs(out_dir, exist_ok=True)

    # File names reuse the spec stage's Windows-safe helper: a form name comes out
    # of the build and decides nothing about where a file lands.
    taken: set[str] = {"index.html"}
    links: dict[str, str] = {}
    written = 0
    for index, view in enumerate(sorted(views, key=lambda v: v.name.lower())):
        name, _why = spec.safe_file_name(view.name, taken, str(index), suffix=".html")
        target = os.path.join(out_dir, name)
        fileio.refuse_overwrite_inputs(target, [args.path, args.exe])
        with fileio.atomic_out(target, newline="") as fh:
            fh.write(htmlview.render_form(view, scale=scale))
        links[view.name] = name
        written += 1
    index_path = os.path.join(out_dir, "index.html")
    with fileio.atomic_out(index_path, newline="") as fh:
        fh.write(htmlview.render_index(sorted(views, key=lambda v: v.name.lower()),
                                       scale=scale, links=links))
    print(htmlview.summary(views), file=sys.stderr)
    for note in notes:
        print(f"# {note}", file=sys.stderr)
    print(f"# {written + 1} pages -> {out_dir} ({scale} twips/px, assumed 96 dpi)", file=sys.stderr)
    print(f"# {res.files_seen} files: {len(res.forms)} parsed, {len(res.no_design)} without a "
          f"design block, {len(res.failures)} failed", file=sys.stderr)
    man = manifest.write(out_dir, skip=args.no_manifest, command="frm --format html",
                         inputs=[p for p in (args.path, args.exe) if p], encoding=(res.encoding, "flag"),
                         started=started,
                         records={"forms": len(views), "pages": written + 1, "scale_twips_per_px": scale},
                         full_paths=args.manifest_paths)
    if man:
        print(f"# manifest: {man}", file=sys.stderr)
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
    from . import dossier, encoding, fileio, literals, manifest

    started = manifest.now()

    # A typo'd listing directory would produce an empty, perfectly valid JSONL file;
    # fileio.require turns that into the exit-2 contract instead of a silent no-op.
    fileio.require(args.listings)
    # The same mistake one level down: a directory that exists but holds no listing
    # file cannot produce a dossier, and an empty output file would read as success.
    if next(literals.listing_files(args.listings), None) is None:
        raise fileio.InputError(f"{args.listings}: no listing files found")
    codec, source = encoding.choice(args.encoding, None)
    _announce(codec, source)
    out_path = args.out or os.path.join(args.listings, dossier.DEFAULT_OUT_NAME)
    # an --out set to one of the listing files being consumed would eat the
    # listing, and one set to an --inventory CSV would eat an input the same way:
    # compare against the files actually read, not just the directory names
    consumed = list(literals.listing_files(args.listings))
    if args.inventory:
        consumed += dossier.inventory_files(args.inventory)
    fileio.refuse_overwrite_inputs(out_path, consumed)
    with fileio.atomic_out(out_path, newline="") as fh:
        report = dossier.stream(args.listings, fh, encoding=codec,
                                inventory_path=args.inventory)
    for line in report.lines():
        print(line, file=sys.stderr)
    print(f"# wrote {out_path}", file=sys.stderr)
    written = manifest.write(
        out_path, skip=args.no_manifest, command="dossier",
        inputs=[args.listings] + ([args.inventory] if args.inventory else []),
        encoding=(codec, source), started=started,
        records={"procedures": report.procedures, "with_literal": report.with_literal,
                 "with_closed_sql": report.with_closed_sql, "failed": len(report.failed)},
        full_paths=args.manifest_paths)
    if written:
        print(f"# manifest: {written}", file=sys.stderr)
    return 0


def cmd_xref(args) -> int:
    from . import fileio, xref

    fileio.require(args.dossier)  # missing input: one line naming the path, exit 2
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
    from . import fileio, mask

    # A gate aimed at a typo'd or missing path found nothing because it looked at
    # nothing; exiting 0 there would make every CI run of this gate meaningless.
    fileio.require(args.path)
    result = mask.mask_tree(args.path, dry_run=args.dry_run)
    changed = {k: v for k, v in result.items() if v}
    print(f"# {len(result)} files scanned, {len(changed)} changed, {sum(changed.values())} lines")
    audit = mask.audit(args.path)
    print(f"# audit: files={audit.files} lines={audit.lines} findings={audit.findings} clean={audit.clean}")
    # --dry-run skips the *write*, not the check: a gate that exits 0 in dry-run can
    # never fail in CI, which is how a real leak would sail through.
    return 0 if audit.clean else 1


def cmd_spec(args) -> int:
    from . import fileio, manifest, procs, spec, unknowns

    started = manifest.now()
    fileio.require(args.dossier)
    try:
        records = unknowns._records(args.dossier)
    except unknowns.ExpectedValueError as exc:
        raise fileio.InputError(str(exc)) from exc

    kinds: dict[str, tuple[str, str]] = {}
    if args.exe:
        project = procs.read(args.exe, encoding=args.encoding)
        kinds = {o.name: (o.object_type, "object table (vb6d procs)") for o in project.objects}

    design: dict[str, frm_mod.Form] = {}
    design_reason = "no .frm directory supplied (--frm)"
    if args.frm:
        from . import encoding as encoding_mod
        from . import frm as frm_mod
        codec, source = encoding_mod.choice(args.encoding, None)
        scan = frm_mod.scan_directory(args.frm, encoding=codec)
        design = {form.name.lower(): form for form in scan.forms}
        design_reason = (f"{len(design)} design blocks of {scan.files_seen} files read as "
                         f"{codec} ({source}); {len(scan.no_design)} carry no design block, "
                         f"{len(scan.failures)} failed")

    outline: dict[str, dict] | None = None
    if args.outline:
        fileio.require(args.outline)
        outline = {}
        for record in unknowns._records(args.outline):
            va = record.get("va")
            if isinstance(va, str):
                outline[va.upper()] = record

    known_tables: set[str] | None = None
    if args.schema:
        fileio.require(args.schema)
        try:
            with open(args.schema, encoding="utf-8") as fh:
                known_tables = {name.lower() for name in (json.load(fh).get("tables") or {})}
        except (OSError, ValueError) as exc:
            raise fileio.InputError(f"{args.schema}: not a schema JSON ({exc})") from exc

    report = spec.build(records, kinds=kinds or None, design=design or None,
                        design_reason=design_reason, outline=outline,
                        known_tables=known_tables)
    written = spec.files(report)
    out_dir = args.out
    if os.path.exists(out_dir) and not os.path.isdir(out_dir):
        raise fileio.InputError(f"{out_dir}: exists and is not a directory")
    os.makedirs(out_dir, exist_ok=True)
    for name, body in written:
        target = os.path.join(out_dir, name)
        consumed = [p for p in (args.dossier, args.exe, args.frm, args.outline, args.schema) if p]
        fileio.refuse_overwrite_inputs(target, consumed)
        with fileio.atomic_out(target, newline="") as fh:
            fh.write(body)
    counts = report.counts()
    print(f"# {counts['files']} files for {counts['objects']} objects, "
          f"{counts['procedures']} procedures, {counts['closed']} closed of "
          f"{counts['statements']} statements -> {out_dir}", file=sys.stderr)
    for note in report.notes:
        print(f"# {note}", file=sys.stderr)
    man = manifest.write(out_dir, skip=args.no_manifest, command="spec",
                         inputs=[args.dossier] + [p for p in (args.exe, args.frm, args.outline) if p],
                         encoding=None, started=started, records=counts,
                         full_paths=args.manifest_paths)
    if man:
        print(f"# manifest: {man}", file=sys.stderr)
    return 0


def cmd_schema(args) -> int:
    from . import fileio, manifest, schema, unknowns

    started = manifest.now()
    fileio.require(args.dossier)
    try:
        records = unknowns._records(args.dossier)
    except unknowns.ExpectedValueError as exc:
        raise fileio.InputError(str(exc)) from exc
    report = schema.build(records)
    body = schema.as_json(report) if args.format == "json" else schema.as_markdown(report)
    if args.out:
        fileio.refuse_overwrite_inputs(args.out, [args.dossier])
        with fileio.atomic_out(args.out, newline="") as fh:
            fh.write(body)
        print(f"# wrote {args.out}", file=sys.stderr)
        written = manifest.write(args.out, skip=args.no_manifest, command="schema",
                                 inputs=[args.dossier], encoding=None, started=started,
                                 records=report.counts(), full_paths=args.manifest_paths)
        if written:
            print(f"# manifest: {written}", file=sys.stderr)
    else:
        print(body, end="")
    counts = report.counts()
    print(f"# {counts['parsed']} parsed + {counts['unparsed']} unparsed + {counts['open']} open "
          f"= {counts['parsed'] + counts['unparsed'] + counts['open']} of {counts['statements']} "
          f"statements; {len(report.tables)} tables", file=sys.stderr)
    for line in report.invariants():
        print(f"# {line}", file=sys.stderr)
    return 0


def cmd_unknowns(args) -> int:
    from . import fileio, unknowns

    # A typo'd path here would print an empty table and exit 0, which reads as
    # "nothing is unknown" - the opposite of what the stage is asked.
    for path in args.outputs:
        fileio.require(path)
    report = unknowns.collect(args.outputs)
    print(unknowns.as_json(report) if args.json else unknowns.as_text(report), end="")
    for line in report.lines():
        print(line, file=sys.stderr)
    # Unreadable inputs are named and counted; the counts that remain are still
    # evidence, so this is a completed run (exit 0), not a failure.
    return 0


def cmd_doctor(args) -> int:
    from . import doctor

    checks = doctor.run(args.dir)
    if args.json:
        print(doctor.as_json(checks))
    else:
        for c in checks:
            print(f"{c.status:<5} {c.name:<22} {c.message}")
    print(doctor.summarise(checks), file=sys.stderr)
    return doctor.exit_code(checks)


def version_line() -> str:
    from importlib.metadata import PackageNotFoundError, version

    try:
        return f"vb6d {version('vb6decompiler')}"
    except PackageNotFoundError:
        return "vb6d (version unknown: bare source checkout, not installed)"


def _manifest_flags(parser) -> None:
    """The two switches every ``--out`` stage shares (see :mod:`vb6decompiler.manifest`)."""
    parser.add_argument("--no-manifest", action="store_true",
                        help="do not write <out>.manifest.json beside the output")
    parser.add_argument("--manifest-paths", action="store_true",
                        help="record full input paths in the manifest (default: file names only, "
                             "because the manifest is shared like the output)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vb6d",
        description="Evidence-based recovery of native-compiled VB6 programs.",
    )
    # An agent needs to pin the tool that produced a result file. The version
    # lives in pyproject.toml only (docs/RULES.md), so it is read from the
    # installed distribution; a bare source checkout has no metadata to ask.
    p.add_argument("--version", action="version", version=version_line(),
                   help="print the package version and exit")
    sub = p.add_subparsers(dest="command", required=True)

    q = sub.add_parser("pe", help="PE surface of a file or install directory")
    q.add_argument("path")
    q.add_argument("--recursive", action="store_true")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_pe)

    q = sub.add_parser("procs", help="VB6 object table: objects, method counts, addresses")
    q.add_argument("exe")
    q.add_argument("--names", metavar="LISTING_DIR",
                   help="count unique procedure VAs found in a decompiler listing "
                        "(a coverage count: no name is attached to a procedure; "
                        "per-procedure hints: vb6d dossier)")
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
    _manifest_flags(q)
    q.add_argument("--force", action="store_true",
                   help="replace an existing output directory's ENTIRE contents (including "
                        "unrelated files) with the newly generated project")
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
    q.add_argument("--format", choices=("html",), default=None,
                   help="'html' writes a static view (one page per form plus index.html) to --out")
    q.add_argument("--html", action="store_true", help=argparse.SUPPRESS)  # old spelling, same mode
    q.add_argument("--out", metavar="DIR", help="output directory for --format html")
    q.add_argument("--exe", help="the build, to cross-check the .frm geometry against form blobs "
                                 "and to draw forms that have no .frm at all")
    q.add_argument("--scale", type=int, default=None,
                   help="twips per pixel for --format html (default 15, the classic 96 dpi factor; "
                        "it is assumed, not measured, and every page prints it)")
    _manifest_flags(q)
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
    _manifest_flags(q)
    q.add_argument("--inventory", default=None,
                   help="pseudoc_inventory.py output directory to merge by procedure VA")
    q.add_argument("--encoding", metavar="CODEPAGE", default=None,
                   help="code page of the listing text (default: cp1254; env VB6D_ENCODING)")
    q.set_defaults(func=cmd_dossier)

    dc = sub.add_parser("decode", help="dump x86 instructions from a VA (needs the [asm] extra)")
    dc.add_argument("exe", help="VB6 executable to read the bytes from")
    dc.add_argument("--va", required=True, help="virtual address to start at, hex (a VA the dossier or xref already reported)")
    dc.add_argument("--end-va", help="stop at this VA, hex (a neighbouring procedure VA makes the range exactly one body)")
    dc.add_argument("--limit", type=int, default=200, help="max instructions (default 200)")
    dc.add_argument("--window", type=int, default=16384, help="bytes of section data handed to the engine (default 16384)")
    dc.add_argument("--json", action="store_true", help="machine-readable dump including how the decode ended")
    dc.add_argument("--procs", help="a dossier JSONL (vb6d dossier output): in-image call targets are attributed to the procedure whose reported range holds them")
    dc.set_defaults(func=cmd_decode)

    ed = sub.add_parser("edges", help="one pass over a dossier's ranges: per-procedure call edges (needs the [asm] extra)")
    ed.add_argument("exe")
    ed.add_argument("--dossier", required=True, help="JSONL produced by vb6d dossier")
    ed.add_argument("--out", help="output JSONL (default: edges.jsonl next to the dossier file)")
    _manifest_flags(ed)
    ed.add_argument("--events", action="store_true", help="add ordered per-procedure event streams: named calls + loads of immediates that are dossier literals")
    ed.set_defaults(func=cmd_edges)

    ovl = sub.add_parser("outline", help="read an edges file through the runtime table: per-procedure operation counts (no engine needed)")
    ovl.add_argument("edges", help="JSONL produced by vb6d edges")
    ovl.add_argument("--out", help="output JSONL (default: outline.jsonl next to the edges file)")
    _manifest_flags(ovl)
    ovl.set_defaults(func=cmd_outline)

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

    q = sub.add_parser(
        "spec",
        help="one Markdown specification per object, every fact naming its source",
    )
    q.add_argument("dossier", help="JSONL produced by vb6d dossier")
    q.add_argument("--exe", help="the build, for object kinds (object table)")
    q.add_argument("--frm", help="directory of .frm design text, for the design section")
    q.add_argument("--outline", help="outline JSONL, for the runtime-call categories per procedure")
    q.add_argument("--schema", help="schema JSON from 'vb6d schema --format json' (accepted, not needed: "
                                    "the tables come from the dossier's own sql rows)")
    q.add_argument("--encoding", help="code page of the .frm text (default: cp1254; env VB6D_ENCODING)")
    q.add_argument("--out", metavar="DIR", required=True, help="output directory")
    _manifest_flags(q)
    q.set_defaults(func=cmd_spec)

    q = sub.add_parser(
        "schema",
        help="data model from the closed SQL: tables, named columns, who reads and writes",
    )
    q.add_argument("dossier", help="JSONL produced by vb6d dossier")
    q.add_argument("--format", choices=("md", "json"), default="md")
    q.add_argument("--out", help="output file (default: stdout)")
    _manifest_flags(q)
    q.set_defaults(func=cmd_schema)

    q = sub.add_parser(
        "graph",
        help="call graph around one procedure or object, as DOT or Mermaid",
    )
    q.add_argument("edges", help="JSONL produced by vb6d edges")
    q.add_argument("--format", choices=("dot", "mermaid"), default="dot")
    q.add_argument("--from", dest="from_", metavar="NAME_OR_VA",
                   help="procedure VA (bare hex) or object name to start from")
    q.add_argument("--depth", type=int, default=None,
                   help="hops to follow from --from (default 2)")
    q.add_argument("--direction", choices=("out", "in", "both"), default="out",
                   help="follow calls out of the start, into it, or both ways")
    q.add_argument("--all", action="store_true",
                   help="draw every procedure (warns: unreadable on a large program)")
    q.add_argument("--out", help="output file (default: stdout)")
    _manifest_flags(q)
    q.set_defaults(func=cmd_graph)

    q = sub.add_parser(
        "unknowns",
        help="count what the stages marked unknown, in a form safe to paste in an issue",
    )
    q.add_argument("outputs", nargs="+", metavar="output",
                   help="JSONL/JSON/CSV row files written by dossier, edges or outline")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_unknowns)

    q = sub.add_parser("doctor", help="is this machine able to run the toolkit? (one line per check)")
    q.add_argument("--json", action="store_true")
    q.add_argument("--dir", help="directory whose free space to report (default: the current one)")
    q.set_defaults(func=cmd_doctor)

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
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")  # type: ignore[union-attr]  # AttributeError is caught on the next line for stripped stdouts
        except (AttributeError, OSError):
            pass
    try:
        return args.func(args)
    except ExpectedInput as exc:
        # The caller's own problem — bad path, bad file, bad flag value. The named
        # errors (VBError, PEError, FrmError, InputError) already carry the path and
        # cause; one line keeps a stranger's first crash readable, not a wall of
        # traceback. VB6D_DEBUG restores the full traceback for bug reports.
        if os.environ.get("VB6D_DEBUG"):
            raise
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        # Not the caller's file or flag to fix: a toolkit bug or an operational
        # failure (unwritable output, a mask that refuses to write). A script
        # wrapping this CLI must tell that apart from its own bad input, so it
        # gets its own exit code with the exception type that names the bug.
        if os.environ.get("VB6D_DEBUG"):
            raise
        print(f"internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
