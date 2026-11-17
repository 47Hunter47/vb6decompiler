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

Form stubs are not empty: the exe's form-data blobs contribute a comment-form
design record (offset, extent, one line per control). The binary stream itself
is deliberately left in the exe — the report names the offset, so verbatim
bytes are one read away from the input.
"""
from __future__ import annotations

import json
import os

from .procs import VBProject

#: .vbp object-kind keyword for each object-table type we can name.
VBP_KIND = {"form": "Form", "module": "Module", "class": "Class"}
EXT = {"form": ".frm", "module": ".bas", "class": ".cls"}

#: DataReport objects live only at runtime (the layout lives in the report DLL);
#: they are recorded in the report but never written as .vbp entries.
RUNTIME_ONLY = ("datareport",)

DEFAULT_REPORT_NAME = "recovery-report.json"


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


def vbp_text(project: VBProject) -> str:
    """Build the .vbp text. Object-table order is kept as the listing order:
    VB6 compiles in .vbp listing order, so the table order is the closest
    evidence of the original compile sequence (labelled inferred in the report).
    """
    lines = [
        "; recovered by vb6d project from the executable's object table — not the",
        "; original .vbp. Entry list and order are confirmed structure; everything",
        "; the object table does not record (references, startup, Type, file dates)",
        "; is an assumption or a gap — see recovery-report.json.",
        f"; source executable: {project.path}",
        f"; project identifier: {project.identifier}  runtime: {project.runtime_build} revision {project.runtime_rev}",
        "Type=Exe",
        f"ReferenceCount=0",
    ]
    listed = [o for o in project.objects if o.object_type not in RUNTIME_ONLY]
    files = [f"BasicFiles={sum(1 for o in listed if o.object_type == 'module')}",
             f"FormFiles={sum(1 for o in listed if o.object_type == 'form')}",
             f"ClassFiles={sum(1 for o in listed if o.object_type == 'class')}"]
    lines += files
    startup = _startup(project)
    if startup:
        lines.append(f"Startup={startup}")
    else:
        lines.append("; Startup= not recovered: no readable Sub Main in any standard module")
    for o in listed:
        ext = EXT[o.object_type]
        if o.object_type == "form":
            lines.append(f"{VBP_KIND[o.object_type]}={o.name.lower()}{ext}")
        else:
            lines.append(f"{VBP_KIND[o.object_type]}={o.name}; {o.name}{ext}")
    return "\r\n".join(lines) + "\r\n"


def _startup(project: VBProject) -> str | None:
    """Sub Main only when a module's readable name passes the identifier check."""
    for o in project.objects:
        if o.object_type != "module":
            continue
        plausible, _ = _junk_names([m.name for m in o.methods])
        if any(n.lower() == "main" for n in plausible):
            return "Sub Main"
    return None


def _txt(value) -> str:
    """Keep one design fact on one line: newlines/tabs in captions become escapes."""
    return str(value).replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")


def _design_map(exe_path: str, encoding: str) -> dict[str, tuple] | None:
    """``name.lower() -> (FormBlob, Form)`` from the exe's form-data blobs.

    None means the scan itself failed (the writer then says so in the report
    instead of pretending the forms had no design). The binary record stream is
    NOT copied out: it lives in the exe, and the report records its offset so
    anything needing verbatim bytes can fetch them from the input.
    """
    from . import blob
    try:
        data, _sections = blob.load_sections(exe_path)
    except Exception:
        return None
    out: dict[str, tuple] = {}
    for form_blob in blob.blobs_from(data):
        form = blob.extract_form(form_blob, encoding=encoding)
        if form is not None:
            out.setdefault(form.name.lower(), (form_blob, form))
    return out


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
        parts = [f"control {c.name}" + (f"({c.index})" if c.index is not None else ""),
                 f"type {c.type}"]
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
        f"' vb6decompiler placeholder — generated by vb6d project, not source text.",
        f"' Confirmed: {kind} name \"{o.name}\" from the object table (index {o.index}).",
        f"' Declared procedures: {o.method_count}; verified addresses in the table: {len(o.method_addresses)} (native tables store no procedure VAs).",
    ]
    if plausible:
        lines.append("' Procedure names passing the identifier check (shape evidence only):")
        lines += [f"'   {n}" for n in plausible]
    else:
        lines.append("' Procedure names: the readable method entries failed the identifier check (junk decodes); none written here.")
    if design is not None:
        lines += _design_lines(design)
    lines.append("' Code body was not recovered — see recovery-report.json and vb6d dossier.")
    return "\r\n".join(lines) + "\r\n"


def build_report(project: VBProject, exe_path: str, design: dict | None = None) -> dict:
    """The machine-readable companion: provenance, confidence, gaps, assumptions."""
    listed = [o for o in project.objects if o.object_type not in RUNTIME_ONLY]
    all_names = [m.name for _, m in project.methods]
    plausible_total, junk_total = _junk_names(all_names)
    files = []
    for o in listed:
        ext = EXT[o.object_type]
        plausible, junk = _junk_names([m.name for m in o.methods])
        entry = {
            "file": f"{o.name.lower() if o.object_type == 'form' else o.name}{ext}",
            "kind": o.object_type,
            "status": "placeholder",
            "evidence": {"source": "object table", "object_index": o.index,
                         "name": o.name, "raw_type": f"{o.raw_type:X}"},
            "methods_declared": o.method_count,
            "methods_with_verified_address": len(o.method_addresses),
            "names_shape_plausible": len(plausible),
            "names_provably_junk": junk,
        }
        if o.object_type == "form":
            d = design.get(o.name.lower()) if design else None
            entry["design"] = None if d is None else {
                "source": "exe form-data blob",
                "record_bytes": d[0].size,
                "record_offset": f"{d[0].offset:X}",
                "controls": len(d[1].controls),
                "note": "comment-form reconstruction; the binary stream stays in the exe",
            }
            if entry["design"]:
                entry["status"] = "placeholder + recovered design record"
        files.append(entry)
    if design is None:
        design_gap = {"item": "design records",
                      "why": "form-blob scan of the image failed; stubs carry no design and the count of parseable records is unknown"}
    else:
        missing = sorted(f["file"] for f in files
                         if f["kind"] == "form" and f["design"] is None)
        design_gap = {"item": "design records",
                      "why": f"{len(missing)} of the listed form objects have no parseable form-data record: {', '.join(missing) or 'none'}"}
    startup = _startup(project)
    counts = {t: sum(1 for o in project.objects if o.object_type == t)
              for t in ("form", "module", "class", "datareport")}
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
            "vbp_entries": len(listed),
            "method_entries_read": len(all_names),
            "method_names_shape_plausible": len(plausible_total),
            "method_names_provably_junk": junk_total,
            "methods_with_verified_address": sum(1 for _, m in project.methods if m.address is not None),
        },
        "vbp": {
            "file": f"{(project.project_name or 'project')}.vbp",
            "order_basis": "object-table order, kept because VB6 compiles in .vbp listing order (inferred, not proven)",
            "startup": startup or "unrecovered",
        },
        "files": files,
        "gaps": [
            {"item": "code bodies", "why": "native procedures are machine code; decompilation is a separate milestone (D)"},
            design_gap,
            {"item": "startup object", "why": "no readable Sub Main in any standard module" if not startup else "recovered"},
            {"item": "references", "why": "reference table not modelled; control usage recoverable separately from vb6d blob per-control types"},
            {"item": "procedure addresses", "why": "native object table carries none; addresses come from decompiler listings (vb6d dossier)"},
            {"item": "datareport objects", "why": f"{counts.get('datareport', 0)} runtime-only DataReport objects are not project files; layouts via vb6d datareport"},
        ],
        "assumptions": [
            {"item": "Type=Exe", "why": "input is a PE application image; ActiveX DLL/Control projects would need Type=Dll — application type is not modelled from the object table"},
        ],
    }


def default_out_dir(exe_path: str) -> str:
    base = os.path.splitext(exe_path)[0]
    return base + "_project"


def write_project(project: VBProject, out_dir: str) -> dict:
    """Write the skeleton directory and return the report (files are siblings;
    the executable itself is never touched — repo rule: copy, do not patch)."""
    os.makedirs(out_dir, exist_ok=True)
    has_forms = any(o.object_type == "form" for o in project.objects)
    design = _design_map(project.path, project.encoding) if has_forms else {}
    report = build_report(project, project.path, design=design)
    name = project.project_name or "project"
    with open(os.path.join(out_dir, f"{name}.vbp"), "w", encoding="utf-8", newline="") as fh:
        fh.write(vbp_text(project))
    for o in project.objects:
        if o.object_type in RUNTIME_ONLY:
            continue
        ext = EXT[o.object_type]
        plausible, _ = _junk_names([m.name for m in o.methods])
        design_for_o = design.get(o.name.lower()) if (design and o.object_type == "form") else None
        with open(os.path.join(out_dir, f"{o.name.lower() if o.object_type == 'form' else o.name}{ext}"),
                  "w", encoding="utf-8", newline="") as fh:
            fh.write(_stub(project, o, plausible, design=design_for_o))
    report_path = os.path.join(out_dir, DEFAULT_REPORT_NAME)
    with open(report_path, "w", encoding="utf-8", newline="") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    return report
