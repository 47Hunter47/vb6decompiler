"""vb6d project: structure recovery without inventing source.

Synthetic VBProject fixtures (no target exe needed): the writer only consumes
the procs model, so the tests hand it fabricated tables and check exactly what
lands on disk — including the junk-name quarantine that keeps ``MZ\\x90``-style
native decodes out of the stubs.
"""
import json

from vb6decompiler import projectwrite
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
    assert "Startup=Sub Main" in text  # module 0 has a readable Main
    assert "Module=modGenel; modGenel.bas" in text
    assert "Form=form1.frm" in text  # form file names are lower-case in real .vbp files
    assert "Class=clsTablo; clsTablo.cls" in text
    assert "rptX" not in text  # runtime-only DataReport is never a project file
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
    assert on_disk["gaps"] and on_disk["assumptions"][0]["item"] == "Type=Exe"
    vbp = (out / "Sample.vbp").read_text(encoding="utf-8")
    assert vbp.startswith("; recovered by vb6d project")
