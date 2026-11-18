"""One input-error contract for every subcommand (the 0.4.31 review's fix).

A missing path or a file that is not a readable PE is unusable input for
every subcommand: exit 2, one line on stderr naming the file, stdout empty,
no traceback, and no ``unpack_from``/``struct`` internals in the text (the
AGENTS.md exit-code contract). A *directory* scan is different and stays as
it was: counting unreadable files is the point of a survey.

The output-side contract lives here too: an output that names a consumed
input is refused before anything opens, and a failed write leaves the
previous output byte-intact (review 0.5.x, items A2/A3).

The malformed files are built inside ``tmp_path`` so the test states the
input instead of storing binaries. ``rand.bin`` is random every run; the
assertions never pin which line a random 300-byte stub produces, only that
it names the file and stays free of parser internals.
"""
from __future__ import annotations

import os
import struct

import pytest

from vb6decompiler import cli, dossier

#: Every subcommand `vb6d --help` lists, in help order. test_cli.py pins the
#: same set against argparse; keep the two in step when a stage is added.
SUBCOMMANDS = ["pe", "procs", "project", "literals", "stitch", "frm", "blob",
               "datareport", "dossier", "decode", "edges", "outline", "xref", "mask"]

#: The subcommands whose positional input is a PE image.
PE_SUBCOMMANDS = ["pe", "procs", "project", "literals", "stitch", "blob",
                  "datareport", "decode", "edges"]

MALFORMED = ("empty.bin", "rand.bin", "mz.bin", "trunc_pe.bin")


def _argv(command, path):
    """The command's positional argument filled with `path` (plus the flags
    that are required to reach it)."""
    if command == "dossier":
        return ["dossier", "--listings", path]
    if command == "decode":
        return ["decode", path, "--va", "401000"]
    if command == "edges":
        return ["edges", path, "--dossier", path]
    return [command, path]


@pytest.fixture
def missing(tmp_path):
    """A path nobody created: str(), exactly as it would be typed."""
    return str(tmp_path / "gone.bin")


@pytest.fixture
def bad_files(tmp_path):
    """The four malformed inputs of the review, built in tmp_path."""
    (tmp_path / "empty.bin").write_bytes(b"")
    (tmp_path / "rand.bin").write_bytes(os.urandom(300))
    (tmp_path / "mz.bin").write_bytes(b"MZ")
    stub = bytearray(1024)
    stub[0:2] = b"MZ"
    struct.pack_into("<I", stub, 0x3C, 0x80)
    stub[0x80:0x84] = b"PE\0\0"  # signature, then an all-zero (junk) section table
    (tmp_path / "trunc_pe.bin").write_bytes(bytes(stub))
    return {name: str(tmp_path / name) for name in MALFORMED}


# --------------------------------------------------------------------------- missing path
@pytest.mark.parametrize("command", SUBCOMMANDS)
def test_missing_input_is_one_line_exit_two(command, missing, capsys):
    code = cli.main(_argv(command, missing))
    out, err = capsys.readouterr()
    assert code == 2, err
    assert "error:" in err
    assert os.path.basename(missing) in err
    assert "Traceback" not in err
    assert out == "", "nothing may reach stdout when the input is unusable"


def test_missing_path_is_reported_with_the_path_as_typed(missing, capsys):
    """The exact sentence the 0.4.31 review asked for, per subcommand."""
    expected = f"error: {missing}: no such file or directory\n"
    for command in SUBCOMMANDS:
        if command == "frm":  # frm announces the code page before scanning: two lines
            continue          # on stderr; the parametrized test above pins its contract
        capsys.readouterr()  # drain what the previous command printed
        code = cli.main(_argv(command, missing))
        _out, err = capsys.readouterr()
        assert code == 2, (command, err)
        assert err == expected, (command, err)


@pytest.mark.parametrize("command", SUBCOMMANDS)
def test_every_input_error_uses_the_same_prefix(command, missing, capsys):
    """One prefix for an unusable input, on every command: `error:`, never `# error:`
    (the `#` form marks a footnote, not a failure)."""
    cli.main(_argv(command, missing))
    _out, err = capsys.readouterr()
    lines = err.splitlines()
    first = next(line for line in lines if not line.startswith("#"))
    assert first.startswith("error: "), (command, err)
    assert not any(line.startswith("# error:") for line in lines), (command, err)


# --------------------------------------------------------------------------- malformed PE
@pytest.mark.parametrize("command", PE_SUBCOMMANDS)
@pytest.mark.parametrize("name", MALFORMED)
def test_malformed_pe_is_one_line_naming_the_file(command, name, bad_files, tmp_path, capsys):
    path = bad_files[name]
    if command == "edges":
        # a dossier that parses: the malformed image must be the error surfaced
        (tmp_path / "d.jsonl").write_text('{"va": "401000"}\n', encoding="utf-8")
        argv = ["edges", path, "--dossier", str(tmp_path / "d.jsonl")]
    else:
        argv = _argv(command, path)
    code = cli.main(argv)
    out, err = capsys.readouterr()
    assert code == 2, err
    assert name in err, err
    assert "Traceback" not in err
    assert "unpack_from" not in err and "struct.error" not in err
    assert out == "", "nothing may reach stdout when the input is unusable"


def test_truncated_header_reads_as_one_named_line(bad_files, capsys):
    """The review's exact replacement for the unpack_from leak: literals and
    datareport already validate through the PE parser, so the wrap in pe.py
    is what turns the internals into this sentence."""
    path = bad_files["mz.bin"]
    for command in ("literals", "datareport", "blob", "pe"):
        capsys.readouterr()
        code = cli.main([command, path])
        out, err = capsys.readouterr()
        assert code == 2, (command, err)
        assert err == "error: mz.bin: truncated or malformed PE header\n", (command, err)
        assert out == "", (command, out)


def test_pe_shaped_junk_names_its_own_wound(bad_files, capsys):
    """blob no longer answers a stub whose optional header is junk with
    '0 forms, exit 0': it reports the header problem, like every other reader."""
    code = cli.main(["blob", bad_files["trunc_pe.bin"]])
    out, err = capsys.readouterr()
    assert code == 2, err
    assert err == "error: trunc_pe.bin: unknown optional header magic 0x0\n", err
    assert out == ""


# --------------------------------------------------------------------------- the directory lane
def test_directory_scan_still_counts_unreadable_files(tmp_path, capsys):
    """Rule 10 unchanged: one bad file inside a directory is a counted result,
    not a failed run (the explicit-single-file contract above is the difference)."""
    from _mini_pe import mini_pe

    (tmp_path / "good.exe").write_bytes(mini_pe())
    (tmp_path / "broken.exe").write_bytes(b"not a PE file")
    code = cli.main(["pe", str(tmp_path)])
    out, err = capsys.readouterr()
    assert code == 0, err
    assert "1 unreadable" in err
    assert "broken.exe" in out  # the bad file is named in the rows, not swallowed


# --------------------------------------------------------------------------- dossier listings
def test_dossier_refuses_a_directory_with_no_listing_files(tmp_path, capsys):
    """A mistyped --listings path used to write an empty dossier and exit 0, which
    reads exactly like a run that found nothing."""
    out = tmp_path / "dossier.jsonl"
    code = cli.main(["dossier", "--listings", str(tmp_path), "--out", str(out)])
    _out, err = capsys.readouterr()
    assert code == 2, err
    assert err == f"error: {tmp_path}: no listing files found\n", err
    assert not out.exists(), "an error run must not leave an output file behind"


def test_dossier_with_a_listing_and_no_procedures_stays_a_result(tmp_path, capsys):
    """Listing files exist, so the run is a survey: zero procedures is the answer,
    and the file it wrote says so."""
    (tmp_path / "modDemo.bas").write_text('Attribute VB_Name = "modDemo"\n', encoding="utf-8")
    out = tmp_path / "dossier.jsonl"
    code = cli.main(["dossier", "--listings", str(tmp_path), "--out", str(out)])
    _out, err = capsys.readouterr()
    assert code == 0, err
    assert out.exists() and out.stat().st_size == 0
    assert "# 0 procedures" in err


# --------------------------------------------------------------------------- output/input collisions
# An output path that names a file the run consumes must be refused BEFORE it is
# opened: today open(path, "w") truncates the input and a five-minute pass ends
# by destroying its own dossier, listing or image (review 0.5.x, item A2).
def _listing_with_procedure(dir_path):
    (dir_path / "fDemo.bas").write_text(
        "Private Sub Form_Load() '401000\n"
        '  00401000h ; "SELECT * FROM tItem"\n', encoding="cp1254")
    return dir_path / "fDemo.bas"


def test_dossier_refuses_an_out_that_is_a_listing_file(tmp_path, capsys):
    listing = _listing_with_procedure(tmp_path)
    before = listing.read_bytes()
    code = cli.main(["dossier", "--listings", str(tmp_path), "--out", str(listing)])
    _out, err = capsys.readouterr()
    assert code == 2, err
    assert "output path is one of the input files" in err
    assert listing.read_bytes() == before, "the refused run must leave the listing byte-identical"
    assert list(tmp_path.glob("*.vb6d-tmp")) == []


def test_edges_refuses_an_out_that_is_the_exe_or_the_dossier(tmp_path, capsys):
    from _mini_pe import mini_pe

    exe = tmp_path / "app.exe"
    exe.write_bytes(mini_pe())
    dos = tmp_path / "dossier.jsonl"
    dos.write_text('{"va": "401000"}\n', encoding="utf-8")
    exe_bytes, dos_bytes = exe.read_bytes(), dos.read_bytes()
    for out in (str(exe), str(dos)):
        capsys.readouterr()
        code = cli.main(["edges", str(exe), "--dossier", str(dos), "--out", out])
        _o, err = capsys.readouterr()
        assert code == 2, err
        assert "output path is one of the input files" in err
    assert exe.read_bytes() == exe_bytes and dos.read_bytes() == dos_bytes
    assert list(tmp_path.glob("*.vb6d-tmp")) == []


def test_outline_refuses_an_out_that_is_its_edges_file(tmp_path, capsys):
    edges = tmp_path / "edges.jsonl"
    edges.write_text('{"va": "1", "calls_imported": {}}\n', encoding="utf-8")
    before = edges.read_bytes()
    code = cli.main(["outline", str(edges), "--out", str(edges)])
    _o, err = capsys.readouterr()
    assert code == 2, err
    assert "output path is one of the input files" in err
    assert edges.read_bytes() == before  # the old run read nothing and wrote nothing back
    assert list(tmp_path.glob("*.vb6d-tmp")) == []


def test_dossier_failure_keeps_the_previous_output_intact(tmp_path, capsys, monkeypatch):
    """A mid-write failure must not trade a usable file for half of a new one."""
    _listing_with_procedure(tmp_path)
    out = tmp_path / "dossier.jsonl"
    out.write_text("PRE-EXISTING OUTPUT\n", encoding="utf-8")
    real = dossier.iter_dossiers

    def flaky(listing_dir, **kw):
        yield next(real(listing_dir, **kw))
        raise OSError("planted write failure")

    monkeypatch.setattr(dossier, "iter_dossiers", flaky)
    code = cli.main(["dossier", "--listings", str(tmp_path), "--out", str(out)])
    _o, err = capsys.readouterr()
    assert code != 0, err
    assert out.read_text(encoding="utf-8") == "PRE-EXISTING OUTPUT\n"
    assert list(tmp_path.glob("*.vb6d-tmp")) == [], "a failed run leaves no temp file"


def test_dossier_rerun_replaces_its_own_previous_output(tmp_path, capsys):
    """Atomic replacement still overwrites the tool's own prior file on a clean run."""
    _listing_with_procedure(tmp_path)
    for _ in range(2):
        code = cli.main(["dossier", "--listings", str(tmp_path)])
    _o, err = capsys.readouterr()
    assert code == 0, err
    produced = tmp_path / "dossier.jsonl"
    assert len(produced.read_text(encoding="utf-8").splitlines()) == 1
    assert list(tmp_path.glob("*.vb6d-tmp")) == []


# --------------------------------------------------------------------------- exit 3: the toolkit's own failures
# Review item H1: a crash used to leave the same exit 2 that says "your input was
# unusable", so a script could not tell its own bad path from a bug in here.
# The marker vb6decompiler/errors.py::ExpectedInput separates the buckets:
# exit 2 = fix the file or the flag; exit 3 = the toolkit failed, file a bug.

def _plant(monkeypatch, name, exc):
    """Make main's dispatch raise `exc`: build_parser binds func on every main() call."""
    def boom(_args):
        raise exc

    monkeypatch.setattr(cli, name, boom)


def test_an_internal_fault_exits_3_and_names_its_type(monkeypatch, capsys):
    _plant(monkeypatch, "cmd_procs", RuntimeError("planted internal fault"))
    code = cli.main(["procs", "anything.exe"])
    out, err = capsys.readouterr()
    assert code == 3, err
    assert err == "internal error: RuntimeError: planted internal fault\n", err
    assert out == "" and "Traceback" not in err


def test_an_unwritable_output_exits_3_not_two(monkeypatch, capsys):
    """A write failure (a read-only destination) is not bad input: review H1 gave
    operational failures their own exit code so agents stop retrying with new flags."""
    _plant(monkeypatch, "cmd_dossier", PermissionError("read-only file system"))
    code = cli.main(["dossier", "--listings", "whatever"])
    out, err = capsys.readouterr()
    assert code == 3, err
    assert err == "internal error: PermissionError: read-only file system\n", err
    assert out == ""


def test_named_input_errors_stay_exit_two_with_one_line(monkeypatch, capsys):
    """The marker routes, it does not renumber: InputError and its siblings still get
    one `error:` line and exit 2."""
    from vb6decompiler import fileio

    _plant(monkeypatch, "cmd_procs", fileio.InputError("anything.exe: unreadable"))
    code = cli.main(["procs", "anything.exe"])
    out, err = capsys.readouterr()
    assert code == 2, err
    assert err == "error: anything.exe: unreadable\n", err
    assert out == ""


def test_vb6d_debug_reraises_the_internal_fault(monkeypatch):
    monkeypatch.setenv("VB6D_DEBUG", "1")
    _plant(monkeypatch, "cmd_procs", RuntimeError("planted internal fault"))
    with pytest.raises(RuntimeError, match="planted internal fault"):
        cli.main(["procs", "anything.exe"])


# --------------------------------------------------------------------------- procs --names wording (H2)
def test_procs_names_help_promises_a_coverage_count(capsys):
    """Review item H2: `procs --names` counts listing VAs; no name is attached to a
    native procedure record. The help line is the contract an agent reads first."""
    with pytest.raises(SystemExit) as exit_:
        cli.build_parser().parse_args(["procs", "--help"])
    assert exit_.value.code == 0
    out, _err = capsys.readouterr()
    flat = " ".join(out.split())  # argparse wraps help at the terminal width
    assert "coverage count" in flat and "no name is attached" in flat, out
