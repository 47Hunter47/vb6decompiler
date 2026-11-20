"""The run manifest beside every output a stage writes.

The manifest is evidence: a row file pasted into an issue cannot say which build,
code page or tool version produced it. These tests hold the two promises that make
it safe to share — no full paths unless asked, and no change to the artefact — plus
the one that makes it honest: it must not survive a run that declined to write it.
"""

from __future__ import annotations

import hashlib
import json
import os

import pytest
import synth_vb6

from vb6decompiler import cli, manifest


@pytest.fixture()
def target(tmp_path):
    return synth_vb6.build(tmp_path)


def _dossier(target, out, *extra):
    return cli.main(["dossier", "--listings", str(target.listings), "--out", str(out), *extra])


def _read(out) -> dict:
    with open(manifest.path_for(str(out)), encoding="utf-8") as fh:
        return json.load(fh)


# --------------------------------------------------------------------------- shape
def test_manifest_lands_beside_the_output_and_names_the_run(target, capsys):
    out = target.root / "dossier.jsonl"
    assert _dossier(target, out) == 0
    capsys.readouterr()
    body = _read(out)
    assert body["command"] == "dossier"
    assert body["output"] == "dossier.jsonl"
    assert body["tool"].startswith("vb6d ")
    assert body["encoding"] == {"codec": "cp1254", "source": "default"}
    assert body["runtime"]["python"] == f"{os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}"
    assert body["records"]["procedures"] == 4
    # UTC, second precision, so two machines' clocks can be compared at all.
    assert body["started"].endswith("Z") and body["finished"].endswith("Z")
    assert body["started"] <= body["finished"]


def test_input_is_hashed_and_named_without_its_directory(target, capsys):
    out = target.root / "dossier.jsonl"
    assert _dossier(target, out) == 0
    capsys.readouterr()
    [row] = _read(out)["inputs"]
    assert row["kind"] == "directory"
    assert row["name"] == "listings"          # a shared manifest must not carry a user's path
    assert "path" not in row
    assert row["files"] == 2
    assert len(row["sha256"]) == 64


def test_manifest_paths_opt_in_to_full_paths(target, capsys):
    out = target.root / "dossier.jsonl"
    assert _dossier(target, out, "--manifest-paths") == 0
    capsys.readouterr()
    [row] = _read(out)["inputs"]
    assert row["path"] == os.path.abspath(str(target.listings))
    assert _read(out)["output"] == os.path.abspath(str(out))


# --------------------------------------------------------------------------- honesty
def test_no_manifest_removes_the_stale_one_it_would_falsify(target, capsys):
    out = target.root / "dossier.jsonl"
    assert _dossier(target, out) == 0
    assert os.path.exists(manifest.path_for(str(out)))
    capsys.readouterr()
    # Same output, different input: the old manifest would describe this file with
    # another input's hash, which is a false statement about provenance.
    other = synth_vb6.build(target.root / "second")
    assert _dossier(other, out, "--no-manifest") == 0
    assert not os.path.exists(manifest.path_for(str(out)))


def test_the_artefact_is_byte_identical_with_and_without_a_manifest(target, capsys):
    out = target.root / "dossier.jsonl"
    assert _dossier(target, out, "--no-manifest") == 0
    without = out.read_bytes()
    assert _dossier(target, out) == 0
    capsys.readouterr()
    assert out.read_bytes() == without


def test_a_directory_hash_changes_when_one_file_changes(tmp_path):
    directory = tmp_path / "listings"
    directory.mkdir()
    (directory / "a.bas").write_text("one\n", encoding="utf-8")
    first = manifest.describe_input(str(directory))["sha256"]
    (directory / "a.bas").write_text("two\n", encoding="utf-8")
    second = manifest.describe_input(str(directory))["sha256"]
    assert first != second


def test_a_missing_input_is_recorded_not_raised(tmp_path):
    row = manifest.describe_input(str(tmp_path / "gone.exe"))
    assert row["kind"] == "unreadable"
    assert "FileNotFoundError" in row["reason"]


def test_a_large_file_is_hashed_in_streams(tmp_path, monkeypatch):
    big = tmp_path / "big.bin"
    payload = os.urandom(3 << 20)
    big.write_bytes(payload)
    # Any single read bigger than the chunk size would mean the whole file was
    # loaded; the tool must behave on a 100 MB target the way it does here.
    monkeypatch.setattr(manifest, "CHUNK", 64 << 10)
    row = manifest.describe_input(str(big))
    assert row["sha256"] == hashlib.sha256(payload).hexdigest()
    assert row["size"] == len(payload)
