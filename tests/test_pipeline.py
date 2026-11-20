"""`vb6d run`: dependency order, one failure is not a cancellation, resume on evidence.

The three claims this file has to hold, in the order they matter:

* a failed stage does not stop the independent ones, and the stages that needed it
  are reported ``skipped: <stage> failed`` — not quietly missing;
* "up to date" appears only when the manifest beside an output records the same
  input hashes and the same tool version;
* the table names every stage, and the exit code follows the contract (0 or 3).

The end-to-end tests drive the real CLI on the synthetic build, because the parts
that broke while writing this were exactly the joins: a missing output directory,
`frm` running in the wrong mode, and a dependent stage running on an input that a
failed stage never wrote.
"""

from __future__ import annotations

import json

import pytest
import synth_vb6

from vb6decompiler import cli, pipeline


# --------------------------------------------------------------------------- planning
def test_the_plan_is_dependency_order_not_alphabetical():
    order = pipeline.names()
    assert order[:3] == ["pe", "procs", "literals"]
    for stage in pipeline.STAGES:
        for need in stage["needs"]:
            assert order.index(need) < order.index(stage["name"]), stage["name"]


def test_only_selects_named_stages_and_refuses_unknown_ones():
    picked = pipeline.plan(only=["schema", "dossier"])
    assert [s["name"] for s in picked] == ["dossier", "schema"]   # plan order, not argv order
    with pytest.raises(ValueError) as exc:
        pipeline.plan(only=["decode"])
    assert "not driven by 'run'" in str(exc.value)


def test_from_drops_everything_before_the_stage():
    picked = [s["name"] for s in pipeline.plan(from_stage="dossier")]
    assert picked[0] == "dossier" and "pe" not in picked


def test_a_dropped_dependency_becomes_a_skip_with_the_reason():
    waves, skipped = pipeline.waves(pipeline.plan(only=["schema", "outline"]))
    assert waves == []
    assert {s["name"]: why for s, why in skipped} == {
        "schema": "needs dossier", "outline": "needs edges"}


def test_independent_stages_share_one_wave():
    waves, skipped = pipeline.waves(pipeline.plan(only=["pe", "procs", "dossier", "schema"]))
    assert not skipped
    assert [sorted(s["name"] for s in w) for w in waves] == [
        ["dossier", "pe", "procs"], ["schema"]]


def test_a_failed_dependency_blocks_only_its_dependents():
    assert pipeline.blocked({"name": "schema", "needs": ["dossier"]}, {"dossier"})
    assert pipeline.blocked({"name": "schema", "needs": ["dossier"]}, {"pe"}) is None
    assert pipeline.blocked({"name": "pe", "needs": []}, {"dossier"}) is None


# --------------------------------------------------------------------------- exit codes
def test_exit_code_is_zero_only_when_nothing_failed(capsys):
    ok = pipeline.StageRun(name="pe", status=pipeline.OK)
    bad = pipeline.StageRun(name="edges", status=pipeline.FAILED)
    assert pipeline.exit_code([ok, ok]) == 0
    assert pipeline.exit_code([ok, bad]) == 3
    err = capsys.readouterr()[1]
    assert "# failed: 1 of 2 stages (edges)" in err


def test_the_table_has_one_row_per_stage_in_the_given_order():
    rows = [pipeline.StageRun(name="pe", status=pipeline.OK, seconds=0.5),
            pipeline.StageRun(name="datareport", status=pipeline.SKIPPED, detail="not configured")]
    text = pipeline.table(rows)
    assert text.splitlines()[0].startswith("stage")
    assert "pe         ok" in text and "datareport skipped" in text
    assert "not configured" in text


# --------------------------------------------------------------------------- resume
def test_up_to_date_needs_a_manifest(tmp_path):
    output = tmp_path / "dossier.jsonl"
    output.write_text("{}\n", encoding="utf-8")
    fresh, why = pipeline.up_to_date(str(output), [], "vb6d 9.9.9")
    assert not fresh and "no manifest" in why


def test_up_to_date_compares_the_tool_version_and_the_input_hash(tmp_path):
    from vb6decompiler import manifest

    target = tmp_path / "app.exe"
    target.write_bytes(b"MZ")
    output = tmp_path / "dossier.jsonl"
    output.write_text("{}\n", encoding="utf-8")
    manifest.write(str(output), command="dossier", inputs=[str(target)], encoding=None,
                   started=manifest.now(), records={}, full_paths=True)

    assert pipeline.up_to_date(str(output), [str(target)], cli.version_line())[0]
    assert not pipeline.up_to_date(str(output), [str(target)], "vb6d 0.0.1")[0]

    target.write_bytes(b"MZ changed")
    fresh, why = pipeline.up_to_date(str(output), [str(target)], cli.version_line())
    assert not fresh and "changed" in why


# --------------------------------------------------------------------------- end to end
def _quiet(argv):
    import contextlib
    import io

    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture()
def workspace(tmp_path):
    target = synth_vb6.build(tmp_path / "build")
    ws = tmp_path / "ws"
    assert _quiet(["init", "--dir", str(ws)])[0] == 0
    cfg = ws / "vb6d.toml"
    cfg.write_text(
        f'target = "{target.exe.as_posix()}"\n'
        f'listings = "{target.listings.as_posix()}"\n'
        f'frm_dir = "{target.frms.as_posix()}"\n'
        "output = \"out\"\nworkers = 2\n", encoding="utf-8")
    return target, cfg, ws


def test_a_full_run_succeeds_and_writes_the_tree(workspace):
    _, cfg, ws = workspace
    code, _out, err = _quiet(["run", "--config", str(cfg)])
    assert code == 0, err
    out = ws / "out"
    # Every configured stage has something in its own directory.
    for stage in ("pe", "procs", "literals", "stitch", "frm", "blob", "dossier", "schema",
                  "edges", "outline"):
        assert (out / stage).is_dir(), stage
        assert any(p.is_file() for p in (out / stage).iterdir()), stage
    assert (out / "dossier" / "dossier.jsonl").exists()
    assert (out / "schema" / "schema.json").exists()
    assert (out / "frm" / "index.html").exists()      # the HTML view, not the text mode
    assert (out / "run.manifest.json").exists()


def test_the_table_names_every_stage_and_the_skipped_one_says_why(workspace):
    _, cfg, _ws = workspace
    code, _out, err = _quiet(["run", "--config", str(cfg)])
    assert code == 0
    table = err[err.find("stage "):]
    for stage in pipeline.names():
        assert stage in table
    assert "not configured" in table          # no report_dir in this workspace
    assert "# run manifest:" in err


def test_the_run_manifest_records_each_stage(workspace):
    _target, cfg, ws = workspace
    assert _quiet(["run", "--config", str(cfg)])[0] == 0
    body = json.loads((ws / "out" / "run.manifest.json").read_text(encoding="utf-8"))
    statuses = {row["name"]: row["status"] for row in body["stages"]}
    assert statuses["dossier"] == "ok"
    assert statuses["datareport"] == "skipped"
    assert body["workers"] == 2


def test_a_second_run_reuses_every_stage_it_can(workspace):
    """The resume claim: same inputs, same tool -> 'up to date', not another pass."""
    _target, cfg, _ws = workspace
    assert _quiet(["run", "--config", str(cfg)])[0] == 0
    code, _out, err = _quiet(["run", "--config", str(cfg)])
    assert code == 0
    table = err[err.find("stage "):]
    assert "up to date" in table
    # Everything that writes a manifest of its own should be reused; the stdout-only
    # stages are the exception and must say so by running again.
    assert table.count("up to date") >= 4


def test_force_stage_reruns_what_the_manifest_called_fresh(workspace):
    _target, cfg, _ws = workspace
    assert _quiet(["run", "--config", str(cfg)])[0] == 0
    code, _out, err = _quiet(["run", "--config", str(cfg), "--force-stage"])
    assert code == 0
    assert "up to date" not in err[err.find("stage "):]


def test_a_missing_input_fails_one_stage_and_skips_its_dependents(tmp_path):
    """The failure path that matters: the run continues, and nothing runs on nothing."""
    ws = tmp_path / "ws"
    assert _quiet(["init", "--dir", str(ws)])[0] == 0
    cfg = ws / "vb6d.toml"
    # No listings directory: dossier cannot run, so schema must not pretend to.
    cfg.write_text('listings = "nope"\noutput = "out"\n', encoding="utf-8")
    code, _out, err = _quiet(["run", "--config", str(cfg), "--only", "dossier,schema"])
    assert code == 3
    table = err[err.find("stage "):]
    assert "dossier    failed" in table
    assert "schema     skipped" in table and "dossier failed" in table
    assert "# failed: 1 of 2 stages (dossier)" in err


def test_no_workspace_is_exit_2_not_a_traceback(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    code, _out, err = _quiet(["run"])
    assert code == 2
    assert "no vb6d.toml found" in err


def test_an_unconfigured_stage_is_skipped_not_failed(tmp_path):
    ws = tmp_path / "ws"
    assert _quiet(["init", "--dir", str(ws)])[0] == 0
    cfg = ws / "vb6d.toml"
    cfg.write_text('output = "out"\n', encoding="utf-8")
    code, _out, err = _quiet(["run", "--config", str(cfg), "--only", "pe,blob"])
    assert code == 0
    table = err[err.find("stage "):]
    assert table.count("not configured") == 2


def test_init_refuses_to_clobber_an_existing_workspace(tmp_path):
    ws = tmp_path / "ws"
    assert _quiet(["init", "--dir", str(ws)])[0] == 0
    code, _out, err = _quiet(["init", "--dir", str(ws)])
    assert code == 2
    assert "already exists" in err
