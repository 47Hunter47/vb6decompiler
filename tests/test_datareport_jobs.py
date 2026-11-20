"""`datareport --jobs`: same report, read in parallel.

The property to hold is the one the sequential reader had for free: the output is a
function of the input list, not of the order the threads finished. And a broken file
must still raise — this is a reader, and a summary that quietly dropped a DLL would
misreport how many designs exist.
"""

from __future__ import annotations

import pytest

from vb6decompiler import cli, datareport, fileio


def _design(path: str, name: str) -> datareport.Design:
    return datareport.Design(name=name, path=path, class_name="DataReport", va=0x401000,
                             size=100, header_fields=(0, 0), records=())


def test_parallel_reads_keep_the_input_order(monkeypatch):
    order: list[str] = []

    def fake_read_designs(path: str):
        order.append(path)
        return [_design(path, f"d_{path}")]

    monkeypatch.setattr(datareport, "read_designs", fake_read_designs)
    paths = [f"rpt{i}.dll" for i in range(8)]
    designs = datareport.read_paths(paths, jobs=4)
    assert [d.name for d in designs] == [f"d_{p}" for p in paths]
    assert sorted(order) == sorted(paths)          # every file was read once


def test_jobs_one_and_jobs_n_agree(monkeypatch):
    def fake_read_designs(path: str):
        return [_design(path, f"a_{path}"), _design(path, f"b_{path}")]

    monkeypatch.setattr(datareport, "read_designs", fake_read_designs)
    paths = [f"rpt{i}.dll" for i in range(5)]
    assert ([d.name for d in datareport.read_paths(paths, jobs=1)]
            == [d.name for d in datareport.read_paths(paths, jobs=4)])


def test_a_broken_file_raises_in_both_modes(monkeypatch):
    """Hiding an unreadable DLL would make the summary lie about the design count."""
    def fake_read_designs(path: str):
        if path == "bad.dll":
            raise fileio.InputError("bad.dll: header did not parse")
        return [_design(path, path)]

    monkeypatch.setattr(datareport, "read_designs", fake_read_designs)
    for jobs in (1, 3):
        with pytest.raises(fileio.InputError):
            datareport.read_paths(["ok.dll", "bad.dll"], jobs=jobs)


def test_an_empty_list_is_an_empty_report():
    assert datareport.read_paths([], jobs=4) == []


def test_the_cli_flag_reaches_the_reader(tmp_path, monkeypatch):
    seen: dict = {}

    def fake_read_paths(paths, *, jobs=1):
        seen["jobs"] = jobs
        seen["paths"] = list(paths)
        return []

    monkeypatch.setattr(datareport, "read_paths", fake_read_paths)
    monkeypatch.setattr(datareport, "iter_files", lambda targets: ["a.dll", "b.dll"])
    assert cli.main(["datareport", str(tmp_path), "--jobs", "3"]) == 0
    assert seen["jobs"] == 3 and seen["paths"] == ["a.dll", "b.dll"]


def test_the_default_is_sequential(tmp_path, monkeypatch):
    seen: dict = {}

    def fake_read_paths(paths, *, jobs=1):
        seen["jobs"] = jobs
        return []

    monkeypatch.setattr(datareport, "read_paths", fake_read_paths)
    monkeypatch.setattr(datareport, "iter_files", lambda targets: ["a.dll"])
    assert cli.main(["datareport", str(tmp_path)]) == 0
    assert seen["jobs"] == 1


def test_a_workspace_run_hands_the_worker_count_to_the_per_file_stages(tmp_path):
    """4.3 asks for --jobs on the per-file stages; the config's workers must reach them."""
    from vb6decompiler import workspace

    cfg = workspace.Config(path=str(tmp_path / "vb6d.toml"), target="a.exe",
                           report_dir=str(tmp_path), frm_dir=str(tmp_path))
    stage = {"name": "datareport", "needs": [], "engine": False}
    assert cli._stage_argv(stage, cfg, str(tmp_path / "out"), 4)[-2:] == ["--jobs", "4"]
    assert "--jobs" not in cli._stage_argv(stage, cfg, str(tmp_path / "out"), 1)

    frm_stage = {"name": "frm", "needs": [], "engine": False}
    assert "--jobs" in cli._stage_argv(frm_stage, cfg, str(tmp_path / "out"), 3)
