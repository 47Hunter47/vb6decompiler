"""Reconstructed project skeleton: structure from the object table, text from nowhere.

``vb6d project`` writes what the object table genuinely proves — the project
name, the list of standard modules, classes and forms, and their order — as a
directory of ``.vbp`` plus one placeholder file per object, alongside a
machine-readable ``recovery-report.json``.

Nothing invents source. Every generated file carries a banner naming its
evidence (object-table index) and its limits; the report separates confirmed
fields, inferred fields (with the reason), and gaps. In native builds the
method-entry area usually decodes to junk (verified on the reference build:
626 readable entries, exactly 1 passes an identifier check, 0 carry an address),
so member lists are NOT written into the stubs unless they pass that check —
and a passing check is evidence of shape, not of truth.

Names come from the executable and are not trusted: :func:`plan_files`
sanitizes them into single path components inside the output directory and
resolves case-insensitive duplicates; an unusable name gets an
``object_<index>`` placeholder while the original stays in the report.

Form stubs are not empty: the exe's form-data blobs contribute a comment-form
design record (offset, extent, one line per control). The binary stream itself
is deliberately left in the exe — the report names the offset, so verbatim
bytes are one read away from the input.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import unicodedata

from . import fileio
from .procs import VBProject

#: .vbp object-kind keyword for each object-table type we can name.
VBP_KIND = {"form": "Form", "module": "Module", "class": "Class"}
EXT = {"form": ".frm", "module": ".bas", "class": ".cls"}

#: DataReport objects get no file and no .vbp entry: the recovered artefact is
#: their compiled layout (`vb6d datareport`), and the designer files a real .vbp
#: would list — .dsr text plus .dsx resources — are not carried in the image.
#: Silence about them is "not reconstructed", never a runtime-only verdict.
NO_PROJECT_FILE = ("datareport",)

DEFAULT_REPORT_NAME = "recovery-report.json"

#: Characters Windows refuses in a file name plus everything a path component
#: must not contain: separators and colons (drive or UNC prefixes) become '_',
#: which is also what stops a '..' chain from climbing out of the directory.
_UNSAFE_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f\x7f]')

#: Device names Windows resolves regardless of extension (CON.bas is CON).
_RESERVED = {"con", "prn", "aux", "nul"} | {f"com{i}" for i in range(1, 10)} | {f"lpt{i}" for i in range(1, 10)}

#: Longest generated stem. Windows allows 255 characters per component but the
#: whole path is capped at 260, and the destination directory is the caller's;
#: 100 leaves room for one and keeps the file name readable when truncated.
MAX_STEM = 100


def _reserved_name(stem: str) -> bool:
    """True when Windows would read the first dot-segment as a device name.

    ``CON.bas`` and ``CON.backup.vbp`` are both the console device: the
    reservation survives every extension the writer appends.
    """
    return stem.split(".")[0].strip().lower() in _RESERVED


def _safe_stem(name: str | None) -> tuple[str | None, str | None]:
    """A single-path-component stem for an untrusted name: ``(stem, why)``.

    ``why`` says what had to be repaired (illegal characters, stripped dots,
    a reserved device name, an over-long name, nothing usable left); ``None``
    means the stem is usable as written. Transform, never invent: the original
    name is preserved in the recovery report, and the caller decides whether
    the repair needs a suffix or a placeholder.
    """
    s = _UNSAFE_RE.sub("_", str(name if name is not None else ""))
    if s != str(name if name is not None else ""):
        why = "illegal path characters replaced"
    else:
        why = None
    trimmed = s.strip(". ")
    if trimmed != s:
        why = (why + "; leading/trailing dots and spaces stripped") if why else \
              "leading/trailing dots and spaces stripped"
    s = trimmed
    if len(s) > MAX_STEM:
        s = s[:MAX_STEM].strip(". ")
        why = f"name longer than {MAX_STEM} characters truncated" + (f"; {why}" if why else "")
    if not s:
        return None, "no usable characters"
    if _reserved_name(s):
        base = s.split(".")[0]
        why = f"reserved Windows device name {base.upper()}" + (f"; {why}" if why else "")
    return s, why


def plan_files(project: VBProject) -> dict:
    """Decide every generated filename before anything is written.

    Collision policy, deterministic in table order: the first object claims the
    readable name; a name that is already claimed (case-insensitively — the
    rule the Windows filesystem enforces) or cannot be kept takes
    ``name_<index>``, then ``object_<index>``, which is unique per object. A
    placeholder invents nothing: the original name and the reason live in the
    report's evidence and ``name_mapping``. Objects whose type this writer
    cannot name are collected in ``unsupported`` — never mapped to a guessed
    extension, never dropped.
    """
    files: dict[int, dict] = {}
    taken: dict[str, int] = {}  # lower filename -> index of the claiming object
    unsupported: list[dict] = []
    for o in project.objects:
        if o.object_type in NO_PROJECT_FILE:
            continue  # deliberate non-entry: the report's datareport gap explains it
        if o.object_type not in EXT:
            unsupported.append({"object_index": o.index, "name": o.name,
                                "raw_type": f"{o.raw_type:X}"})
            continue
        stem, why = _safe_stem(o.name)
        if stem and o.object_type == "form":
            stem = stem.lower()  # real .vbp files list their forms in lower case
        cands = ([stem] if stem and why is None else []) \
            + ([f"{stem}_{o.index}"] if stem else []) + [f"object_{o.index:04d}"]
        base = cands[0] if cands else None
        chosen, i = None, 0
        while chosen is None:
            cand = cands[i] if i < len(cands) else f"object_{o.index:04d}_{i}"
            if cand.lower() not in taken and not _reserved_name(cand):
                chosen = cand
            i += 1
        reasons = [why] if why else []
        if base and chosen != base:
            first = taken.get(base.lower())
            reasons.append(f"case-insensitive duplicate of object {first}"
                           if first is not None else "duplicate generated name")
        entry: dict[str, object] = {"file": chosen + EXT[o.object_type], "kind": o.object_type}
        if chosen.startswith("object_") and not (stem or "").startswith("object_"):
            entry["placeholder"] = True
            reasons.append("name unusable, index placeholder assigned")
        if entry["kind"] != "form" and not chosen.isidentifier():
            reasons.append(f"stem is not a VB6 identifier; the .vbp identifier "
                           f"column uses object_{o.index:04d}")
        if reasons:
            entry["why"] = "; ".join(reasons)
        entry["stem"] = chosen  # the Module= line needs an identifier, see vbp_text
        files[o.index] = entry
        taken[chosen.lower()] = o.index

    vbp_stem, vbp_why = _safe_stem(project.project_name)
    if vbp_stem is None:
        vbp_stem, vbp_why = "project", f"project name unusable ({vbp_why})"
    elif _reserved_name(vbp_stem):
        # CON.vbp is the console device on Windows; the reservation does not care
        # about the extension, so the readable stem can never be used as a file.
        vbp_stem, vbp_why = "project", f"{vbp_why}; generated file named project.vbp"
    return {"vbp": {"file": vbp_stem + ".vbp", "why": vbp_why},
            "files": files, "unsupported": unsupported}


def _junk_names(names: list[str | None]) -> tuple[list[str], int]:
    """Split method-entry names into (plausible, provably-junk).

    A VB6 identifier is letters/digits/underscore, never a control character;
    native builds routinely decode the method-entry area through the image's
    code page and get hits like ``MZ\\x90``. Failing the shape check proves
    junk; passing it only proves shape. See module docstring.
    """
    plausible, junk = [], 0
    for name in names:
        if name is not None and name.isidentifier():
            plausible.append(name)
        else:
            junk += 1
    return plausible, junk


def _identifier(entry: dict, index: int) -> str:
    """The name a .vbp line can put where VB6 expects a project identifier.

    The file stem may hold characters no VB6 identifier accepts (dots, leading
    digits); the identifier column then gets the same placeholder the file
    fallback uses, matching the generated file one-to-one.
    """
    stem = entry["stem"]
    return stem if stem.isidentifier() else f"object_{index:04d}"


def vbp_text(project: VBProject, plan: dict | None = None) -> str:
    """Build the .vbp text. Object-table order is kept as the listing order:
    VB6 compiles in .vbp listing order, so the table order is the closest
    evidence of the original compile sequence (labelled inferred in the report).
    ``plan`` (see :func:`plan_files`) supplies the generated filenames.
    """
    plan = plan or plan_files(project)
    lines = [
        "; recovered by vb6d project from the executable's object table — not the",
        "; original .vbp. Entry list and order are confirmed structure; everything",
        "; the object table does not record (references, startup, Type, file dates)",
        "; is an assumption or a gap — see recovery-report.json.",
        f"; source executable: {_txt(project.path)}",
        f"; project identifier: {_txt(project.identifier)}  runtime: {project.runtime_build} revision {project.runtime_rev}",
        "Type=Exe",
        "ReferenceCount=0",
    ]
    entries = plan["files"]
    kinds = [entries[i]["kind"] for i in sorted(entries)]
    files = [f"BasicFiles={sum(1 for k in kinds if k == 'module')}",
             f"FormFiles={sum(1 for k in kinds if k == 'form')}",
             f"ClassFiles={sum(1 for k in kinds if k == 'class')}"]
    lines += files
    lines.append("; Startup= not recovered: the object table names methods but does not")
    lines.append("; record Sub-vs-Function, parameters, visibility, or the startup choice")
    for o in project.objects:
        entry = entries.get(o.index)
        if entry is None:
            continue
        if entry["kind"] == "form":
            lines.append(f"Form={entry['file']}")
        else:
            name = _identifier(entry, o.index)
            lines.append(f"{VBP_KIND[entry['kind']]}={name}; {entry['file']}")
    return "\r\n".join(lines) + "\r\n"


def _txt(value) -> str:
    """Represent untrusted, executable-derived text on one physical source line.

    Everything here comes out of the image (object names, control names and types,
    captions, page titles), so CR/LF — or U+2028, which some editors treat as a
    break — could start a new ``.frm`` line, and a control character could hide
    text. Escape what cannot be printed; letters stay readable (Turkish included),
    and the report keeps the original value unchanged.
    """
    out = []
    for ch in str(value):
        if ch == "\\":
            out.append("\\\\")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"):
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return "".join(out)


def _design_map(exe_path: str, encoding: str) -> dict[str, list] | None:
    """``name.lower() -> [(FormBlob, Form), ...]`` from the exe's form-data blobs.

    None means the scan itself failed (the writer then says so in the report
    instead of pretending the forms had no design). A name claimed by more than
    one record is deliberately left a list: the writer refuses to pick one and
    reports the ambiguity. The binary record stream is NOT copied out: it lives
    in the exe, and the report records its offset so anything needing verbatim
    bytes can fetch them from the input.
    """
    from . import blob
    try:
        data, _sections = blob.load_sections(exe_path)
    except Exception:
        return None
    out: dict[str, list] = {}
    for form_blob in blob.blobs_from(data):
        form = blob.extract_form(form_blob, encoding=encoding)
        if form is not None:
            out.setdefault(form.name.lower(), []).append((form_blob, form))
    return out


def _design_for(design: dict | None, name: str) -> tuple | None:
    """The one design record for a form name, or None when absent or ambiguous.

    Ambiguous (several blobs claim one lower-case name) is treated as no design
    on purpose: attaching an arbitrary record would attribute the wrong form's
    controls to this stub. The report names the ambiguity instead.
    """
    recs = (design or {}).get(name.lower()) or []
    return recs[0] if len(recs) == 1 else None


def _ambiguous(design: dict | None) -> list[str]:
    return sorted(k for k, recs in (design or {}).items() if len(recs) > 1)


def _design_lines(design: tuple) -> list[str]:
    form_blob, form = design
    lines = [
        "' Design record recovered from the executable (comment form, not .frm syntax):",
        f"'   record: {form_blob.size} bytes at file offset 0x{form_blob.offset:x}; the binary",
        "'   control stream itself was left in the exe (fetch it from the input at that offset).",
    ]
    if form.width is not None and form.height is not None:
        extra = ""
        if form.client_left is not None and form.client_top is not None:
            extra = f", client origin {form.client_left} x {form.client_top}"
        lines.append(f"'   form extent: {form.width} x {form.height}{extra}")
    for c in form.controls:
        parts = [f"control {_txt(c.name)}" + (f"({c.index})" if c.index is not None else ""),
                 f"type {_txt(c.type)}"]
        if c.caption is not None:
            parts.append(f"caption \"{_txt(c.caption)}\"")
        parts.append(f"L{c.left} T{c.top} W{c.width} H{c.height}")
        if c.tab_page is not None:
            parts.append(f"SSTab page {c.tab_page}")
        if c.pages:
            parts.append("pages: " + " | ".join(_txt(p) for p in c.pages))
        if c.visible is not None:
            parts.append(f"visible={'true' if c.visible else 'false'}")
        lines.append("'   " + "; ".join(parts))
    lines.append("'   controls with no visible-marker read are silent on visibility (unknown, never \"visible\").")
    return lines


def _stub(project: VBProject, o, plausible: list[str], design: tuple | None = None) -> str:
    kind = o.object_type
    lines = [
        "' vb6decompiler placeholder — generated by vb6d project, not source text.",
        f"' Confirmed: {_txt(kind)} name \"{_txt(o.name)}\" from the object table (index {o.index}).",
        f"' Declared procedures: {o.method_count}; verified addresses in the table: {len(o.method_addresses)} (native tables store no procedure VAs).",
    ]
    if plausible:
        lines.append("' Procedure names passing the identifier check (shape evidence only):")
        lines += [f"'   {_txt(n)}" for n in plausible]
    else:
        lines.append("' Procedure names: the readable method entries failed the identifier check (junk decodes); none written here.")
    if design is not None:
        lines += _design_lines(design)
    lines.append("' Code body was not recovered — see recovery-report.json and vb6d dossier.")
    return "\r\n".join(lines) + "\r\n"


def build_report(project: VBProject, exe_path: str, design: dict | None = None,
                 plan: dict | None = None) -> dict:
    """The machine-readable companion: provenance, confidence, gaps, assumptions."""
    plan = plan or plan_files(project)
    entries = plan["files"]
    all_names = [m.name for _, m in project.methods]
    plausible_total, junk_total = _junk_names(all_names)
    files = []
    for o in project.objects:
        entry = entries.get(o.index)
        if entry is None:
            continue  # unsupported types are reported under unsupported_objects
        plausible, junk = _junk_names([m.name for m in o.methods])
        rec = {
            "file": entry["file"],
            "kind": entry["kind"],
            "status": "placeholder",
            "evidence": {"source": "object table", "object_index": o.index,
                         "name": o.name, "raw_type": f"{o.raw_type:X}"},
            "methods_declared": o.method_count,
            "methods_with_verified_address": len(o.method_addresses),
            "names_shape_plausible": len(plausible),
            "names_provably_junk": junk,
        }
        if entry.get("placeholder"):
            rec["placeholder_name"] = True
        if entry.get("why"):
            rec["name_note"] = entry["why"]
        if entry["kind"] == "form":
            d = _design_for(design, o.name)
            rec["design"] = None if d is None else {
                "source": "exe form-data blob",
                "record_bytes": d[0].size,
                "record_offset": f"{d[0].offset:X}",
                "controls": len(d[1].controls),
                "note": "comment-form reconstruction; the binary stream stays in the exe",
            }
            if rec["design"]:
                rec["status"] = "placeholder + recovered design record"
        files.append(rec)
    if design is None:
        design_gap = {"item": "design records",
                      "why": "form-blob scan of the image failed; stubs carry no design and the count of parseable records is unknown"}
    else:
        missing = sorted(f["file"] for f in files
                         if f["kind"] == "form" and f["design"] is None)
        amb = _ambiguous(design)
        design_gap = {"item": "design records",
                      "why": f"{len(missing)} of the listed form objects have no parseable form-data record: {', '.join(missing) or 'none'}"}
        if amb:
            design_gap["why"] += (f"; {len(amb)} design-record names are claimed by several blobs "
                                  f"({', '.join(amb)}) — attached to no form rather than guessed")
    counts: dict[str, int] = {}
    for o in project.objects:
        counts[o.object_type] = counts.get(o.object_type, 0) + 1
    mapping = [{"generated": e["file"], "original": o.name, "why": e["why"]}
               for o in project.objects
               for e in [entries.get(o.index)] if e and e.get("why")]
    if plan["vbp"].get("why"):
        mapping.insert(0, {"generated": plan["vbp"]["file"],
                           "original": project.project_name, "why": plan["vbp"]["why"]})
    gaps = [
        {"item": "code bodies", "why": "native procedures are machine code; decompilation is a separate milestone (D)"},
        design_gap,
        {"item": "startup object", "why": "a readable 'Main' method name proves neither Sub-vs-Function, parameters, visibility, nor the startup designation; the object table records none of them"},
        {"item": "references", "why": "reference table not modelled; control usage recoverable separately from vb6d blob per-control types"},
        {"item": "procedure addresses", "why": "native object table carries none; addresses come from decompiler listings (vb6d dossier)"},
    ]
    if counts.get("datareport"):
        gaps.append({"item": "datareport objects", "why": (
            f"{counts['datareport']} DataReport objects: only their compiled layout is "
            "recoverable here (vb6d datareport reads it from the blob); the designer "
            "files a real .vbp would list (.dsr text, .dsx resource) are not carried "
            "in the image — no entry, no file, nothing claimed about the original "
            "project's source set")})
    if plan["unsupported"]:
        gaps.append({"item": "unsupported object types",
                     "why": f"{len(plan['unsupported'])} objects carry an object-table type this writer cannot name; "
                            "they are listed under unsupported_objects, got no file and no .vbp entry"})
    return {
        "tool": "vb6d project",
        "input": {
            "path": exe_path,
            "project_name": project.project_name,
            "project_description": project.project_description,
            "runtime": {"build": project.runtime_build, "revision": project.runtime_rev},
            "identifier": project.identifier,
            "encoding": {"codepage": project.encoding, "source": project.encoding_source},
        },
        "counts": {
            "objects": len(project.objects),
            "by_type": counts,
            "vbp_entries": len(entries),
            "method_entries_read": len(all_names),
            "method_names_shape_plausible": len(plausible_total),
            "method_names_provably_junk": junk_total,
            "methods_with_verified_address": sum(1 for _, m in project.methods if m.address is not None),
        },
        "vbp": {
            "file": plan["vbp"]["file"],
            "order_basis": "object-table order, kept because VB6 compiles in .vbp listing order (inferred, not proven)",
            "startup": "unrecovered",
        },
        "name_mapping": mapping,
        "files": files,
        "unsupported_objects": plan["unsupported"],
        "gaps": gaps,
        "assumptions": [
            {"item": "Type=Exe", "why": "input is a PE application image; ActiveX DLL/Control projects would need Type=Dll — application type is not modelled from the object table"},
        ],
    }


def default_out_dir(exe_path: str) -> str:
    base = os.path.splitext(exe_path)[0]
    return base + "_project"


#: Staging and backup directories are siblings of the destination, so promotion is
#: a rename on one volume; the dot prefix keeps them out of a plain listing.
STAGE_PREFIX = ".vb6d-stage-"
BACKUP_PREFIX = ".vb6d-backup-"


def _canonical(path: str) -> str:
    """Real path with Windows case folding: what a rename would actually resolve to."""
    return os.path.normcase(os.path.realpath(os.path.abspath(path)))


def _check_out_dir(out_dir: str, exe_path: str) -> None:
    """Refuse an output the writer may not replace. Checked before anything is created.

    Replacing the whole directory means the executable must not live inside it
    (a default ``<exe>_project`` never does), and a symlinked output would make
    the rename land somewhere the caller did not name. Canonical comparison so a
    ``..`` detour or a case spelling cannot fool the guard.
    """
    is_junction = getattr(os.path, "isjunction", lambda _p: False)
    if os.path.islink(out_dir) or is_junction(out_dir):
        raise fileio.InputError(f"{out_dir}: output path is a symlink; refusing to replace it")
    if os.path.isfile(out_dir):
        raise fileio.InputError(f"{out_dir}: output path is a file, not a project directory")
    real_out, real_exe = _canonical(out_dir), _canonical(exe_path)
    if real_exe == real_out or real_exe.startswith(real_out + os.sep):
        raise fileio.InputError(
            f"{out_dir}: output directory contains the source executable ({exe_path}); "
            "replacing it would delete the input")


def _write_tree(directory: str, project: VBProject, plan: dict, report: dict,
                design: dict | None) -> None:
    """Write the complete project into ``directory`` (a staging dir, never the destination)."""
    with open(os.path.join(directory, plan["vbp"]["file"]), "w", encoding="utf-8", newline="") as fh:
        fh.write(vbp_text(project, plan))
    for o in project.objects:
        entry = plan["files"].get(o.index)
        if entry is None:
            continue
        plausible, _ = _junk_names([m.name for m in o.methods])
        design_for_o = _design_for(design, o.name) if entry["kind"] == "form" else None
        with open(os.path.join(directory, entry["file"]), "w", encoding="utf-8", newline="") as fh:
            fh.write(_stub(project, o, plausible, design=design_for_o))
    with open(os.path.join(directory, DEFAULT_REPORT_NAME), "w", encoding="utf-8", newline="") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def _verify_tree(directory: str, plan: dict, report: dict) -> None:
    """Every .vbp reference and report entry names a file that exists, and nothing else.

    A generator bug (a name that escapes the directory, a file the report forgot)
    must surface here, while the previous destination is still intact — not as a
    half-described project on disk.
    """
    expected = {plan["vbp"]["file"], DEFAULT_REPORT_NAME} | {e["file"] for e in plan["files"].values()}
    for name in expected:
        if os.path.basename(name) != name:
            raise RuntimeError(f"generated filename escapes the output directory: {name!r}")
    on_disk = set(os.listdir(directory))
    if on_disk != expected:
        raise RuntimeError(f"generated tree does not match its report: "
                           f"missing {sorted(expected - on_disk)}, unexpected {sorted(on_disk - expected)}")
    reported = {f["file"] for f in report["files"]}
    if reported != {e["file"] for e in plan["files"].values()}:
        raise RuntimeError("recovery report and .vbp plan disagree on the generated files")


def _promote(staging: str, out_dir: str, force: bool) -> None:
    """Move the finished staging tree onto ``out_dir``, keeping a rollback copy.

    A directory swap is not atomic across platforms: the previous tree is renamed
    aside first, and restored if the new rename fails. Only ordinary failures are
    covered; a crash between the two renames leaves the backup beside the
    destination (never deleted before the new tree is in place).
    """
    parent = os.path.dirname(os.path.abspath(out_dir))
    backup = None
    if os.path.isdir(out_dir):
        if os.listdir(out_dir):
            if not force:
                raise fileio.InputError(
                    f"{out_dir}: output directory is not empty; "
                    "pass --force to replace its entire contents")
            # mkstemp-shaped unique name, released so the rename can take it
            backup = tempfile.mkdtemp(prefix=BACKUP_PREFIX, dir=parent)
            os.rmdir(backup)
            os.replace(out_dir, backup)
        else:
            os.rmdir(out_dir)  # Windows cannot rename onto an existing directory
    try:
        os.replace(staging, out_dir)
    except BaseException:
        if backup is not None:
            os.replace(backup, out_dir)  # restore; if this fails the backup still holds the tree
        raise
    if backup is not None:
        shutil.rmtree(backup, ignore_errors=True)


def write_project(project: VBProject, out_dir: str, force: bool = False) -> dict:
    """Write the skeleton directory and return the report.

    The executable itself is never touched (repo rule: copy, do not patch). The
    project is generated in a staging directory beside the destination and only
    promoted when it is complete and verified, so an exception mid-generation
    leaves the previous project exactly as it was. Without ``force`` a non-empty
    destination is refused; with ``force`` the whole directory is replaced —
    including unrelated files the user left there — so stale generated files
    cannot survive into the new project.
    """
    _check_out_dir(out_dir, project.path)
    plan = plan_files(project)
    if os.path.isdir(out_dir) and not force:
        existing = os.listdir(out_dir)
        if existing:
            raise fileio.InputError(
                f"{out_dir}: output directory is not empty ({len(existing)} files); "
                "pass --force to replace its entire contents")
    parent = os.path.dirname(os.path.abspath(out_dir))
    os.makedirs(parent, exist_ok=True)
    staging = tempfile.mkdtemp(prefix=STAGE_PREFIX, dir=parent)
    try:
        has_forms = any(e["kind"] == "form" for e in plan["files"].values())
        design = _design_map(project.path, project.encoding) if has_forms else {}
        report = build_report(project, project.path, design=design, plan=plan)
        _write_tree(staging, project, plan, report, design)
        _verify_tree(staging, plan, report)
        _promote(staging, out_dir, force)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return report
