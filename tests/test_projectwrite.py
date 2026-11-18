"""vb6d project: structure recovery without inventing source.

Synthetic VBProject fixtures (no target exe needed): the writer only consumes
the procs model, so the tests hand it fabricated tables and check exactly what
lands on disk — including the junk-name quarantine that keeps ``MZ\\x90``-style
native decodes out of the stubs.
"""
import json
import os

import pytest

from vb6decompiler import fileio, projectwrite
from vb6decompiler.procs import Method, VBObject, VBProject


def make_project():
    objs = [
        VBObject(0, "modGenel", "module", 0x1000000, 2,
                 [Method(0, None, None, False, "Main"),
                  Method(1, None, None, False, "DoThings")]),
        VBObject(1, "Form1", "form", 0x118000A, 3,
                 [Method(0, 0x401000, 0x1000, True, "MZ\x90"),
                  Method(1, None, None, False, "Clicked")]),
        VBObject(2, "clsTablo", "class", 0x118003, 1,
                 [Method(0, None, None, False, "Helper")]),
        VBObject(3, "rptX", "datareport", 0x1018083, 1,
                 [Method(0, None, None, False, "Rep")]),
    ]
    return VBProject(path="sample.exe", image_base=0x400000, project_name="Sample",
                     project_description=None, runtime_build=6, runtime_rev=0,
                     form_count=1, object_count=4, compiled_count=4,
                     identifier="ABCD0001", objects=objs)


def test_vbp_lists_every_source_object_in_table_order():
    text = projectwrite.vbp_text(make_project())
    assert "Type=Exe" in text
    assert "Startup=Sub Main" not in text  # module 0's readable "Main" is a name, not evidence
    assert "; Startup= not recovered" in text
    assert "Module=modGenel; modGenel.bas" in text
    assert "Form=form1.frm" in text  # form file names are lower-case in real .vbp files
    assert "Class=clsTablo; clsTablo.cls" in text
    assert "rptX" not in text  # DataReport: no designer file was reconstructible, so no .vbp entry (item I)
    assert "BasicFiles=1" in text and "FormFiles=1" in text and "ClassFiles=1" in text
    assert text.index("modGenel") < text.index("form1") < text.index("clsTablo")  # table order kept


def test_startup_unrecovered_is_a_comment_not_a_guess():
    project = make_project()
    project.objects[0].methods[0].name = "NotMain"
    text = projectwrite.vbp_text(project)
    assert "; Startup= not recovered" in text
    assert "Startup=Sub Main" not in text
    report = projectwrite.build_report(project, "sample.exe")
    assert report["vbp"]["startup"] == "unrecovered"


def test_a_main_name_alone_never_becomes_startup(tmp_path):
    """Review item D: the Method record carries no signature, visibility or
    Sub-vs-Function; a perfect name therefore proves nothing about startup."""
    project = make_project()  # module 0 method 0 is a readable "Main"
    text = projectwrite.vbp_text(project)
    assert "Startup=Sub Main" not in text
    report = projectwrite.build_report(project, "sample.exe")
    assert report["vbp"]["startup"] == "unrecovered"
    gap = next(g for g in report["gaps"] if g["item"] == "startup object")
    assert "proves neither" in gap["why"]


def test_junk_names_are_quarantined_out_of_stubs():
    report = projectwrite.build_report(make_project(), "sample.exe")
    counts = report["counts"]
    assert counts["method_names_shape_plausible"] == 5  # Main, DoThings, Clicked, Helper, Rep
    assert counts["method_names_provably_junk"] == 1  # the MZ\x90 decode
    form = next(f for f in report["files"] if f["kind"] == "form")
    assert form["names_provably_junk"] == 1
    stub = projectwrite._stub(make_project(), make_project().objects[1],
                              ["Clicked"])
    assert "Confirmed: form name \"Form1\"" in stub
    assert "MZ" not in stub  # the junk decode never reaches the file
    assert "'   Clicked" in stub


def test_write_project_dir_and_report(tmp_path):
    project = make_project()
    out = tmp_path / "Sample_project"
    report = projectwrite.write_project(project, str(out))
    names = sorted(p.name for p in out.iterdir())
    assert names == ["Sample.vbp", "clsTablo.cls", "form1.frm", "modGenel.bas",
                     "recovery-report.json"]  # exactly the placeholder set; rptX gets no file
    on_disk = json.loads((out / "recovery-report.json").read_text(encoding="utf-8"))
    assert on_disk == json.loads(json.dumps(report))  # stdout report and file report agree
    assert on_disk["unsupported_objects"] == []  # rptX is a known kind with no rebuildable designer file, not an unnamed type
    assert on_disk["gaps"] and on_disk["assumptions"][0]["item"] == "Type=Exe"
    vbp = (out / "Sample.vbp").read_text(encoding="utf-8")
    assert vbp.startswith("; recovered by vb6d project")


def test_datareport_gap_names_the_designer_files_it_did_not_rebuild():
    """Review item I: recovered layout is not the designer file, and "no file for
    it" must never be phrased as if the evidence proved the object runtime-only."""
    report = projectwrite.build_report(make_project(), "sample.exe")
    gap = next(g for g in report["gaps"] if g["item"] == "datareport objects")
    assert "runtime-only" not in gap["why"]
    assert ".dsr" in gap["why"] and ".dsx" in gap["why"]  # names exactly what is missing
    assert report["counts"]["by_type"]["datareport"] == 1  # the object is recorded, not dropped
    assert "rptX" not in report["files"]  # and no designer file was faked for it


def _fake_design():
    from vb6decompiler.blob import Control, Form, FormBlob
    controls = [
        Control("Text1", "TextBox", "Müşteri Adı\nikinci satır", 100, 200, 300, 120),
        Control("CmdSave", "CommandButton", None, 0, 0, 960, 360,
                index=0, visible=False, tab_page=2),
    ]
    return {"form1": [(FormBlob(name="Form1", offset=0x500, size=0x1234, data=b""),
                       Form("Form1", controls, width=5000, height=4000,
                           client_left=0, client_top=0))]}


def test_design_blocks_land_in_form_stubs(tmp_path, monkeypatch):
    monkeypatch.setattr(projectwrite, "_design_map", lambda exe, encoding: _fake_design())
    out = tmp_path / "Sample_project"
    report = projectwrite.write_project(make_project(), str(out))
    stub = (out / "form1.frm").read_text(encoding="utf-8")
    assert "record: 4660 bytes at file offset 0x500" in stub
    assert 'caption "Müşteri Adı\\nikinci satır"' in stub  # newlines escape, stay on one line
    assert "L100 T200 W300 H120" in stub
    assert "CmdSave(0)" in stub and "visible=false" in stub and "SSTab page 2" in stub
    assert "form extent: 5000 x 4000, client origin 0 x 0" in stub
    form = next(f for f in report["files"] if f["kind"] == "form")
    assert form["status"] == "placeholder + recovered design record"
    assert form["design"]["controls"] == 2 and form["design"]["record_offset"] == "500"
    # JSON hex follows the repo-wide convention (bare uppercase, like dossier/
    # literals/stitch); the 0x prefix belongs in human comment lines only.
    assert '"0x' not in json.dumps(report)
    assert form["design"]["note"]  # the stream stays in the exe


def test_forms_without_a_record_say_so(tmp_path, monkeypatch):
    monkeypatch.setattr(projectwrite, "_design_map", lambda exe, encoding: {})
    out = tmp_path / "Sample_project"
    report = projectwrite.write_project(make_project(), str(out))
    assert "Design record" not in (out / "form1.frm").read_text(encoding="utf-8")
    form = next(f for f in report["files"] if f["kind"] == "form")
    assert form["design"] is None
    gap = next(g for g in report["gaps"] if g["item"] == "design records")
    assert gap["why"].startswith("1 of")


def test_failed_design_scan_is_reported_not_hidden(tmp_path, monkeypatch):
    monkeypatch.setattr(projectwrite, "_design_map", lambda exe, encoding: None)
    out = tmp_path / "Sample_project"
    report = projectwrite.write_project(make_project(), str(out))
    gap = next(g for g in report["gaps"] if g["item"] == "design records")
    assert "scan of the image failed" in gap["why"]


# --------------------------------------------------------------------------- name safety
# The object table's names come from an executable. Untrusted: a name can carry
# path separators, a drive prefix, a reserved device name, or a duplicate that
# only the Windows case-insensitive filesystem makes visible.
def _mkproj(objects, name="Proj"):
    return VBProject(path="sample.exe", image_base=0x400000, project_name=name,
                     project_description=None, runtime_build=6, runtime_rev=0,
                     form_count=1, object_count=len(objects), compiled_count=len(objects),
                     identifier="ABCD0001", objects=objects)


UNSAFE = [
    VBObject(0, "mod..\\evil", "module", 0x18001, 0),   # traversal-shaped name
    VBObject(1, "C:\\x", "module", 0x18001, 0),         # drive prefix
    VBObject(2, "CON", "module", 0x18001, 0),           # reserved device name
    VBObject(3, "...", "module", 0x18001, 0),           # dots only
    VBObject(4, "a", "module", 0x18001, 0),
    VBObject(5, "A", "module", 0x18001, 0),             # case-only duplicate
    VBObject(6, "Form1", "form", 0x18083, 0),
]


def test_unsafe_names_never_escape_or_collide(tmp_path):
    out = tmp_path / "o" / "proj"
    report = projectwrite.write_project(_mkproj(UNSAFE), str(out))
    assert sorted(os.listdir(tmp_path)) == ["o"]            # nothing landed beside the out dir
    assert sorted(os.listdir(tmp_path / "o")) == ["proj"]   # nothing escaped into the parent
    names = sorted(p.name for p in out.iterdir())
    # a mangled stem carries the object index: the name is safe, not original
    assert names == ["A_5.bas", "CON_2.bas", "C__x_1.bas", "Proj.vbp", "a.bas",
                     "form1.frm", "mod.._evil_0.bas", "object_0003.bas",
                     "recovery-report.json"]
    assert len({n.lower() for n in names}) == len(names)  # no case-insensitive collision
    mapping = {m["original"]: m["generated"] for m in report["name_mapping"]}
    assert mapping["mod..\\evil"] == "mod.._evil_0.bas"  # originals survive in the report
    assert mapping["CON"] == "CON_2.bas"
    placeholder = next(f for f in report["files"] if f["file"] == "object_0003.bas")
    assert placeholder["placeholder_name"] is True
    assert placeholder["evidence"]["name"] == "..."  # the placeholder names its source
    vbp = (out / "Proj.vbp").read_text(encoding="utf-8")
    for entry in report["files"]:  # every .vbp line points at a file that exists
        assert entry["file"] in vbp
        assert (out / entry["file"]).exists()
    assert "Module=object_0000; mod.._evil_0.bas" in vbp  # dots are no VB6 identifiers


def test_ambiguous_design_names_are_reported_not_assigned(tmp_path, monkeypatch):
    fake = _fake_design()["form1"]
    monkeypatch.setattr(projectwrite, "_design_map",
                        lambda exe, encoding: {"form1": fake + fake})
    out = tmp_path / "Sample_project"
    report = projectwrite.write_project(make_project(), str(out))
    assert "Design record" not in (out / "form1.frm").read_text(encoding="utf-8")
    gap = next(g for g in report["gaps"] if g["item"] == "design records")
    assert "claimed by several blobs" in gap["why"]


def test_unknown_object_types_are_reported_not_fatal(tmp_path):
    """Review item E: procs keeps unknown types as hex on purpose; the writer
    must keep them too — no guessed extension, no .vbp entry, no KeyError."""
    objs = [
        VBObject(0, "modMain", "module", 0x1000000, 1, [Method(0, None, None, False, "Go")]),
        VBObject(1, "Form1", "form", 0x118000A, 1, [Method(0, None, None, False, "Clicked")]),
        VBObject(2, "clsX", "class", 0x118003, 1, [Method(0, None, None, False, "Helper")]),
        VBObject(3, "oddOne", "0x123456", 0x123456, 2, []),
        VBObject(4, "oddTwo", "0xBEEF00", 0xBEEF00, 0, []),
    ]
    project = _mkproj(objs)
    out = tmp_path / "proj"
    report = projectwrite.write_project(project, str(out))
    assert sorted(p.name for p in out.iterdir()) == [
        "Proj.vbp", "clsX.cls", "form1.frm", "modMain.bas",
        "recovery-report.json"]  # form files lower-case, like real .vbp projects
    vbp = (out / "Proj.vbp").read_text(encoding="utf-8")
    assert "0x123456" not in vbp and "oddOne" not in vbp  # no guessed entries
    unsupported = report["unsupported_objects"]
    assert [(u["object_index"], u["name"], u["raw_type"]) for u in unsupported] == [
        (3, "oddOne", "123456"), (4, "oddTwo", "BEEF00")]  # preserved, raw types intact
    counts = report["counts"]
    assert counts["objects"] == 5  # everything found
    assert counts["vbp_entries"] == 3  # only what was rebuilt
    assert counts["by_type"].get("0x123456") == 1  # unknown type stays in the census
    gap = next(g for g in report["gaps"] if g["item"] == "unsupported object types")
    assert "2 objects" in gap["why"]


def test_an_unknown_type_alone_still_produces_a_project(tmp_path):
    """All-unknown is a result too: report with the whole census, zero entries."""
    project = _mkproj([VBObject(0, "onlyOdd", "0x123456", 0x123456, 1, [])])
    out = tmp_path / "proj"
    report = projectwrite.write_project(project, str(out))
    assert len(report["unsupported_objects"]) == 1
    assert report["counts"]["vbp_entries"] == 0
    assert (out / "recovery-report.json").exists()


def test_existing_output_dir_is_refused_unless_forced(tmp_path):
    out = tmp_path / "Sample_project"
    out.mkdir()
    keeper = out / "hand-edited.bas"
    keeper.write_text("' edited by hand\n", encoding="utf-8")
    with pytest.raises(fileio.InputError, match="--force"):
        projectwrite.write_project(make_project(), str(out))
    assert keeper.read_text(encoding="utf-8") == "' edited by hand\n"  # refused, not clobbered
    assert list(out.glob("*.vb6d-tmp")) == []
    projectwrite.write_project(make_project(), str(out), force=True)
    assert (out / "Sample.vbp").exists()
