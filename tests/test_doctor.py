"""`vb6d doctor`: the checks, and the exit code a CI step reads.

Each check is exercised with a monkeypatched environment rather than the real
machine, because "capstone is missing" and "the data file did not survive
packaging" are the failures this command exists to name, and neither can be
produced by asking the machine that has both.
"""

from __future__ import annotations

import json
import sys
import tempfile

from vb6decompiler import cli, doctor


def _status(checks, name):
    return next(c for c in checks if c.name == name)


# --------------------------------------------------------------------------- exit codes
def test_exit_code_is_the_worst_check():
    ok = doctor.Check("x", doctor.OK, "")
    warn = doctor.Check("y", doctor.WARN, "")
    fail = doctor.Check("z", doctor.FAIL, "")
    assert doctor.exit_code([ok, ok]) == 0
    assert doctor.exit_code([ok, warn]) == 1
    assert doctor.exit_code([warn, fail]) == 2


def test_a_clean_machine_exits_zero(monkeypatch, capsys):
    for name in doctor.ENV_PATHS:
        monkeypatch.delenv(name, raising=False)
    code, out, err = _run(["doctor"], capsys)
    assert code in (0, 1), err  # a machine without the [asm] extra is a warning, not a failure
    assert "# doctor: " in err
    assert "python" in out


def test_machine_warning_only_exits_one(monkeypatch, capsys):
    # ``sys.modules[name] = None`` makes the next ``import`` raise ImportError,
    # which is exactly the state of a machine without the optional extra.
    monkeypatch.setitem(sys.modules, "capstone", None)
    checks = doctor.run(tempfile.gettempdir())
    assert _status(checks, "capstone").status == doctor.WARN
    # Other checks may warn on this machine too; none may fail because of it.
    assert not any(c.status == doctor.FAIL for c in checks)


# --------------------------------------------------------------------------- individual checks
def test_missing_runtime_table_is_a_failure(monkeypatch):
    monkeypatch.setattr(doctor.runtime_table, "count", lambda: 0)
    check = doctor._runtime_table()
    assert check.status == doctor.FAIL
    assert "outline" in check.message


def test_an_unreadable_code_page_fails_the_encoding_check(monkeypatch):
    monkeypatch.setenv("VB6D_ENCODING", "not-a-codepage")
    check = doctor._encoding()
    assert check.status == doctor.FAIL
    assert "VB6D_ENCODING" in check.message


def test_the_encoding_check_names_where_the_choice_came_from(monkeypatch):
    monkeypatch.delenv("VB6D_ENCODING", raising=False)
    assert doctor._encoding().message.endswith("(default)")
    monkeypatch.setenv("VB6D_ENCODING", "cp1252")
    assert doctor._encoding().message == "cp1252 (env)"


def test_environment_paths_are_checked_not_trusted(monkeypatch, tmp_path):
    for name in doctor.ENV_PATHS:
        monkeypatch.delenv(name, raising=False)
    assert doctor._env_paths().status == doctor.OK

    monkeypatch.setenv("VB6D_LISTINGS", str(tmp_path))
    assert doctor._env_paths().status == doctor.OK

    monkeypatch.setenv("VB6D_TARGET", str(tmp_path / "gone.exe"))
    check = doctor._env_paths()
    assert check.status == doctor.WARN
    assert "VB6D_TARGET" in check.message


def test_an_unwritable_temp_directory_is_reported(monkeypatch):
    def boom(*_args, **_kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(doctor.tempfile, "mkstemp", boom)
    check = doctor._temp()
    assert check.status == doctor.FAIL
    assert "No space left on device" in check.message


def test_low_disk_space_warns_before_a_large_target(monkeypatch, tmp_path):
    monkeypatch.setattr(doctor, "LOW_DISK", 1 << 62)
    check = doctor._disk(str(tmp_path))
    assert check.status == doctor.WARN
    assert "GiB free" in check.message


def test_disk_check_falls_back_to_the_current_directory(tmp_path):
    check = doctor._disk(str(tmp_path / "missing"))
    assert str(tmp_path) not in check.message  # reports the directory it actually measured
    assert check.status in (doctor.OK, doctor.WARN)


# --------------------------------------------------------------------------- wiring
def _run(argv, capsys):
    code = cli.main(argv)
    out, err = capsys.readouterr()
    return code, out, err


def test_json_output_is_parseable_and_carries_every_check(monkeypatch, capsys):
    for name in doctor.ENV_PATHS:
        monkeypatch.delenv(name, raising=False)
    code, out, _ = _run(["doctor", "--json"], capsys)
    rows = json.loads(out)
    assert {r["name"] for r in rows} >= {"python", "capstone", "runtime table", "encoding",
                                        "temp directory", "disk space"}
    assert all(r["status"] in ("ok", "warn", "fail") for r in rows)
    assert [r["status"] for r in rows].count("fail") == (1 if code == 2 else 0)


def test_doctor_needs_no_input_file(monkeypatch, capsys):
    monkeypatch.chdir(tempfile.gettempdir())
    code, out, _ = _run(["doctor"], capsys)
    assert code in (0, 1)
    assert "python" in out
