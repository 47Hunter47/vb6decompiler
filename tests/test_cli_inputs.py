"""One input-error contract for every subcommand (the 0.4.31 review's fix).

A missing path or a file that is not a readable PE is unusable input for
every subcommand: exit 2, one line on stderr naming the file, stdout empty,
no traceback, and no ``unpack_from``/``struct`` internals in the text (the
AGENTS.md exit-code contract). A *directory* scan is different and stays as
it was: counting unreadable files is the point of a survey.

The malformed files are built inside ``tmp_path`` so the test states the
input instead of storing binaries. ``rand.bin`` is random every run; the
assertions never pin which line a random 300-byte stub produces, only that
it names the file and stays free of parser internals.
"""
from __future__ import annotations

import os
import struct

import pytest

from vb6decompiler import cli

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
