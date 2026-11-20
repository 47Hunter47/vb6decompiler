"""Parallel parsing and the progress line: same output, and nothing in a pipe.

`--jobs` exists for one reason — a directory of 800 forms on a slow disk — so the test
that matters is that it changes nothing else: the same forms, the same order, the same
counts as the sequential path, and a failing file still recorded instead of aborting
its neighbours.

The progress line is the other half of that promise: a stage that prints into a pipe
someone is parsing must stay silent.
"""

from __future__ import annotations

import io

import synth_vb6

from vb6decompiler import cli, frm, progress


# --------------------------------------------------------------------------- jobs
def test_parallel_and_sequential_scans_agree(tmp_path):
    target = synth_vb6.build(tmp_path)
    files = frm.pick_files(str(target.frms))
    sequential = frm.scan_files(files, jobs=1, root=str(target.frms))
    parallel = frm.scan_files(files, jobs=4, root=str(target.frms))
    assert [f.name for f in sequential.forms] == [f.name for f in parallel.forms]
    assert (sequential.files_seen, len(sequential.forms), len(sequential.no_design),
            len(sequential.failures)) == (
        parallel.files_seen, len(parallel.forms), len(parallel.no_design),
        len(parallel.failures))


def test_a_hard_file_does_not_abort_its_neighbours(tmp_path):
    target = synth_vb6.build(tmp_path)
    broken = target.frms / "aaa_broken.frm"
    broken.write_text("VERSION 5.00\nBegin VB.Form fBroken\n", encoding="cp1254")  # no End
    files = frm.pick_files(str(target.frms))
    result = frm.scan_files(files, jobs=4, root=str(target.frms))
    # The synthetic form is still parsed; the cut one is recorded in its own bucket.
    assert any(f.name == "fSynth01" for f in result.forms)
    assert result.files_seen == len(files)
    assert len(result.forms) + len(result.no_design) + len(result.failures) == result.files_seen


def test_cli_jobs_keeps_the_text_output_identical(tmp_path, capsys):
    target = synth_vb6.build(tmp_path)
    capsys.readouterr()
    assert cli.main(["frm", str(target.frms)]) == 0
    sequential, _ = capsys.readouterr()
    assert cli.main(["frm", str(target.frms), "--jobs", "4"]) == 0
    parallel, _ = capsys.readouterr()
    assert sequential == parallel


# --------------------------------------------------------------------------- progress
def test_progress_is_silent_unless_stderr_is_a_terminal():
    stream = io.StringIO()          # not a tty
    bar = progress.Progress("frm", 10, stream=stream)
    assert not bar.active
    bar.tick(5, final=True)
    assert stream.getvalue() == ""


def test_forced_progress_carries_both_numbers_and_the_elapsed_time():
    stream = io.StringIO()
    bar = progress.Progress("frm", 10, stream=stream, force=True, interval=0)
    bar.tick(3)
    bar.tick(10, final=True)
    lines = stream.getvalue().splitlines()
    assert lines[0].startswith("# frm: 3 of 10 (") and lines[1].startswith("# frm: 10 of 10 (")


def test_the_interval_keeps_a_fast_stage_quiet_after_the_first_line():
    """The first tick prints (a started stage must look started); the rest wait."""
    stream = io.StringIO()
    bar = progress.Progress("frm", 100, stream=stream, force=True, interval=60)
    bar.tick(1)
    for done in range(2, 100):
        bar.tick(done)
    assert stream.getvalue().count(chr(10)) == 1
    bar.tick(100, final=True)
    assert "100 of 100" in stream.getvalue()
