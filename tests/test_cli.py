"""The `vb6d` command line: wiring, exit codes and output shape.

No target binary is needed. The `.frm` fixtures and a temporary directory cover the
paths that can be exercised anywhere; the target-dependent commands
(`procs`, `blob`, `datareport`, `literals` against a real image) are covered by
`test_target.py` and skip without `VB6D_TARGET`.

What these tests are for: `cli.py` is the only module with no other caller, so a
broken subcommand is invisible until someone runs it by hand.
"""

from __future__ import annotations

import json
import os

import pytest

from vb6decompiler import cli, procs

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _run(argv, capsys):
    code = cli.main(argv)
    out, err = capsys.readouterr()
    return code, out, err


# --------------------------------------------------------------------------- wiring
def test_every_subcommand_is_wired_to_a_function():
    parser = cli.build_parser()
    # Introspect what argparse actually built: a subparser missing `func` dies with
    # AttributeError only when that one subcommand is used.
    actions = [a for a in parser._actions if hasattr(a, "choices") and isinstance(a.choices, dict)]
    assert actions, "no subparsers found"
    subs = actions[0].choices
    assert set(subs) == {"pe", "procs", "project", "literals", "stitch", "frm", "blob",
                         "datareport", "dossier", "decode", "edges", "outline", "xref", "mask",
                         "doctor", "unknowns", "schema", "spec", "graph"}
    for name, sub in subs.items():
        assert callable(sub.get_default("func")), f"{name} has no func"


def test_missing_subcommand_exits_nonzero():
    with pytest.raises(SystemExit) as exc:
        cli.main([])
    assert exc.value.code != 0


def test_version_is_one_word_on_stdout_and_exits_zero(capsys):
    # An agent pinning "which tool version produced this file" must get the
    # answer on stdout with exit 0 — not a help wall.
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    out, err = capsys.readouterr()
    assert out.startswith("vb6d ") and err == ""


# --------------------------------------------------------------------------- frm
def test_frm_prints_a_summary_with_its_denominator(capsys):
    code, out, err = _run(["frm", FIXTURES], capsys)
    assert code == 0
    # The denominator is not decoration: "369 parsed" means nothing without "of 802".
    assert "parsed" in err and "of" not in err.lower().split("parsed")[0]
    assert "files:" in err
    assert out.strip(), "no per-form lines printed"


def test_frm_json_is_machine_readable(capsys):
    code, out, _err = _run(["frm", FIXTURES, "--json"], capsys)
    assert code == 0
    payload = json.loads(out)
    assert payload["files_seen"] >= len(payload["forms"])
    assert all("controls" in f for f in payload["forms"])
    # A file with no design block is reported, not silently dropped.
    assert isinstance(payload["no_design_block"], list)


def test_frm_json_details_let_an_agent_read_a_form_without_reparsing(capsys):
    """Review item F: --json used to be counts only; the parser knows far more."""
    code, out, _err = _run(["frm", FIXTURES, "--json"], capsys)
    assert code == 0
    payload = json.loads(out)
    by = {f["name"]: f for f in payload["forms"]}
    # back-compat: "controls" stays the integer count; the list rides alongside
    assert all(isinstance(f["controls"], int) and
               f["controls"] == len(f["detail"]["controls"]) for f in payload["forms"])
    tab = by["fSynthTab"]["detail"]
    assert tab["complete"] is True and tab["incomplete_reason"] is None
    kids = {c["name"]: c for c in tab["controls"]}
    assert (kids["txtGeneral"]["parent"], kids["txtGeneral"]["depth"]) == ("SSTab1", 1)
    assert (kids["lblIc"]["parent"], kids["lblIc"]["depth"]) == ("fraDetail", 2)
    caps = [(p["param"], p["value"]) for p in kids["SSTab1"]["properties"]
            if p["name"] == "TabCaption"]
    assert caps == [(0, "General"), (1, "Detail"), (2, "Summary")]  # indexed props keep their index
    arr = by["fSynthArray"]["detail"]
    idxs = sorted(p["value"] for c in arr["controls"] if c["name"] == "txtAd"
                  for p in c["properties"] if p["name"] == "Index")
    assert idxs == [0, 1, 2]  # control-array members keep their written Index
    vis = next(p for p in next(c for c in arr["controls"] if c["name"] == "picKutu")["properties"]
               if p["name"] == "Visible")
    assert (vis["value"], vis["kind"], vis["comment"]) == (False, "bool", "False")
    assert [c["line"] for c in arr["controls"]] == sorted(c["line"] for c in arr["controls"])
    cap = next(p for p in arr["properties"] if p["name"] == "Caption")
    assert cap["value"] == "Settings' welcome note" and cap["raw"].startswith('"')
    kes = by["fKesik"]["detail"]
    assert kes["complete"] is False and "without closing End" in kes["incomplete_reason"]
    assert kes["warnings"][0]["line"] == 10  # warnings carry line numbers, not just counts


# --------------------------------------------------------------------------- mask
def test_mask_reports_zero_findings_and_exits_zero(tmp_path, capsys):
    (tmp_path / "notes.md").write_text("nothing secret here\n", encoding="utf-8")
    code, out, _err = _run(["mask", str(tmp_path)], capsys)
    assert code == 0
    assert "clean=True" in out


def test_mask_exits_one_when_a_secret_survives(tmp_path, capsys):
    # dry_run skips the write, so the value is still there afterwards: the audit must
    # say so and the exit code must be non-zero. A gate that always exits 0 is a
    # decoration, not a gate.
    leak = tmp_path / "leak.csv"
    leak.write_text("uid=sa;pwd=hunter2\n", encoding="utf-8")
    code, out, _err = _run(["mask", str(tmp_path), "--dry-run"], capsys)
    assert code == 1
    assert "clean=False" in out


def test_mask_dry_run_does_not_write(tmp_path):
    leak = tmp_path / "leak.csv"
    leak.write_text("uid=sa;pwd=hunter2\n", encoding="utf-8")
    cli.main(["mask", str(tmp_path), "--dry-run"])
    assert "hunter2" in leak.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- error boundary
# A stranger's first run hits a bad input (packed exe, wrong file, typo'd path).
# That must cost one readable line and exit 2, not a Python traceback.
def test_unusable_exe_is_one_line_on_stderr_not_a_traceback(tmp_path, capsys):
    junk = tmp_path / "junk.exe"
    junk.write_bytes(b"MZ\x90\x00garbage-not-a-real-image")
    code = cli.main(["procs", str(junk)])
    _out, err = capsys.readouterr()
    assert code == 2
    assert "error:" in err
    assert "Traceback" not in err


def test_missing_file_is_an_error_not_a_traceback(capsys):
    code = cli.main(["procs", os.path.join(FIXTURES, "nope.exe")])
    _out, err = capsys.readouterr()
    assert code == 2
    assert "error:" in err and "Traceback" not in err


def test_vb6d_debug_keeps_the_traceback(tmp_path, monkeypatch):
    junk = tmp_path / "junk.exe"
    junk.write_bytes(b"MZ\x90\x00garbage-not-a-real-image")
    monkeypatch.setenv("VB6D_DEBUG", "1")
    with pytest.raises(procs.VBError):  # measured: this junk file escapes as VBError
        cli.main(["procs", str(junk)])


def test_mask_on_a_missing_path_does_not_pass_vacuously(tmp_path, capsys):
    code = cli.main(["mask", str(tmp_path / "gone")])
    _out, err = capsys.readouterr()
    assert code == 2
    assert "error:" in err


# --------------------------------------------------------------------------- encoding
# Three paths the roadmap names: a code page the user typed, one the header supplied,
# and input that cannot be honoured (one line, exit 2, no traceback).
def test_encoding_flag_is_reported_once_on_stderr(capsys):
    code, _out, err = _run(["frm", FIXTURES, "--encoding", "cp1252"], capsys)
    assert code == 0
    lines = [l for l in err.splitlines() if l.startswith("# encoding:")]
    assert lines == ["# encoding: cp1252 (explicit)"], lines


def test_a_directory_input_reports_the_default_when_nothing_is_given(capsys):
    # A .frm directory has no header to ask; the default must name itself, not stay
    # silent, so a stranger can see why their captions look wrong.
    code, _out, err = _run(["frm", FIXTURES], capsys)
    assert code == 0
    assert "# encoding: cp1254 (default)" in err


def test_the_environment_variable_is_used_and_labelled(capsys, monkeypatch):
    monkeypatch.setenv("VB6D_ENCODING", "cp1250")
    code, _out, err = _run(["frm", FIXTURES], capsys)
    assert code == 0
    assert "# encoding: cp1250 (env)" in err


def test_a_typo_in_the_flag_is_one_line_and_exit_two(capsys):
    code = cli.main(["frm", FIXTURES, "--encoding", "cp9999"])
    out, err = capsys.readouterr()
    assert code == 2
    assert out == ""
    assert "unknown code page" in err and "Traceback" not in err


def test_a_multibyte_build_is_refused_before_any_output(capsys):
    # Accepting cp932 would keep working until the first non-ASCII byte, then return
    # offsets that no longer line up with the bytes. Refuse it up front.
    code = cli.main(["frm", FIXTURES, "--encoding", "cp932"])
    out, err = capsys.readouterr()
    assert code == 2
    assert out == ""
    assert "multi-byte" in err and "Traceback" not in err


# --------------------------------------------------------------------------- stitch provenance
def test_stitch_rows_carry_the_procedure_and_the_start_address(tmp_path, capsys):
    # A candidate that names no address cannot be traced back to the build it came
    # from. The listing header gave every chain these two numbers, so the stage must
    # pass them through instead of dropping them on the way to stdout.
    lst = tmp_path / "listings"
    lst.mkdir()
    (lst / "m.bas").write_text(
        "Private Sub Form_Load() '400010\n"
        "  00401000h ; \"SELECT * FROM tItem WHERE A = '\"\n"
        "  00401040h ; \"1'\"\n",
        encoding="cp1254",
    )
    code, out, _err = _run(["stitch", str(lst), "--json"], capsys)
    assert code == 0
    rows = json.loads(out)
    assert rows, "expected the closed candidate"
    assert rows[0]["proc_va"] == "400010"
    assert rows[0]["text_va"] == "401000"


def test_stitch_on_a_bare_binary_says_why_there_is_nothing(tmp_path, capsys):
    # A real (synthetic) PE: the old behaviour was a silent empty run, which read
    # as "this build has no SQL" when the actual cause was that a binary carries
    # no procedure ownership. The answer must be said, and the exit stays 0:
    # finding nothing is a result, unusable input is not (AGENTS.md contract).
    from _mini_pe import mini_pe

    exe = tmp_path / "tiny.exe"
    exe.write_bytes(mini_pe())
    code, out, err = _run(["stitch", str(exe), "--json"], capsys)
    assert code == 0
    assert json.loads(out) == []
    assert "no procedure ownership" in err
    # Garbage still costs exit 2 even though the binary answer is already known.
    junk = tmp_path / "junk.exe"
    junk.write_bytes(b"MZ\x90\x00garbage-not-a-real-image")
    assert cli.main(["stitch", str(junk)]) == 2


# --------------------------------------------------------------------------- blob detail
def test_blob_json_carries_per_control_geometry(tmp_path, capsys, monkeypatch):
    # blob.py recovers caption, position, size, array index and the tri-state
    # Visible per control; the summary-only JSON used to throw all of it away,
    # which made `blob --json` useless for the forms that have no .frm at all.
    from vb6decompiler import blob

    forms = [
        blob.Form(
            name="fSample", width=3270, height=1905, client_left=8, client_top=8,
            controls=[
                blob.Control(name="Text1", type="TextBox", caption="a",
                             left=100, top=200, width=300, height=60),
                blob.Control(name="Command1", type="CommandButton", caption=None,
                             left=100, top=300, width=300, height=120, index=2,
                             visible=False),
            ],
        )
    ]
    monkeypatch.setattr(blob, "extract_forms", lambda exe, encoding=None: forms)
    from _mini_pe import mini_pe
    exe = tmp_path / "fake.exe"
    exe.write_bytes(mini_pe())  # a real (if empty) image: codec_for parses the header
    code, out, _err = _run(["blob", str(exe), "--json"], capsys)
    assert code == 0
    forms_out = json.loads(out)
    (form,) = forms_out
    assert form["controls_detail"]
    text1, cmd = form["controls_detail"]
    assert (text1["left"], text1["top"], text1["width"], text1["height"]) == (100, 200, 300, 60)
    assert cmd["index"] == 2 and cmd["visible"] is False and cmd["caption"] is None
    # The text mode keeps its old per-form shape: a new column would break callers.
    code, out, _err = _run(["blob", str(exe)], capsys)
    assert out.splitlines()[0] == "name,controls,width,height"


def test_project_command_writes_skeleton_and_reports(tmp_path, capsys, monkeypatch):
    """The skeleton is provenance first: report on stdout, files beside a name
    that never touches the exe, and no progress text inside the JSON."""
    import dataclasses

    from _mini_pe import mini_pe
    from test_projectwrite import make_project

    from vb6decompiler import procs

    exe = tmp_path / "fake.exe"
    exe.write_bytes(mini_pe())
    project = dataclasses.replace(make_project(), path=str(exe))
    monkeypatch.setattr(procs, "read", lambda path, encoding=None: project)

    code, out, err = _run(["project", str(exe), "--out", str(tmp_path / "out"), "--json"], capsys)
    assert code == 0
    report = json.loads(out)  # stdout must be parseable on its own
    assert report["tool"] == "vb6d project"
    assert report["counts"]["vbp_entries"] == 3
    assert report["input"]["path"] == str(exe)
    assert (tmp_path / "out" / "Sample.vbp").exists()
    assert (tmp_path / "out" / "recovery-report.json").exists()
    assert "# 3 placeholder files" in err

    # Default output is a sibling directory named after the exe; stdout stays empty.
    code, out, _err = _run(["project", str(exe)], capsys)
    assert code == 0 and out == ""
    assert (tmp_path / "fake_project" / "Sample.vbp").exists()
