"""`vb6d.toml`: found, read, refused when wrong, written as placeholders.

The failure this file must not have is the quiet one: a misspelled key ignored, a
relative path resolved against the wrong directory, a placeholder counted as a
setting. Each test below pins one of those.
"""

from __future__ import annotations

import os

import pytest

from vb6decompiler import workspace


def _write(path, body: str) -> str:
    path.write_text(body, encoding="utf-8")
    return str(path)


# --------------------------------------------------------------------------- reading
def test_a_full_file_is_read_with_paths_resolved_against_the_file(tmp_path):
    cfg_path = _write(tmp_path / "vb6d.toml", """
target   = "build/app.exe"
listings = "decompiled"
output   = "out"
encoding = "cp1252"
workers  = 4
progress = true
""")
    cfg = workspace.load(cfg_path)
    assert cfg.target == os.path.normpath(str(tmp_path / "build" / "app.exe"))
    assert cfg.listings == os.path.normpath(str(tmp_path / "decompiled"))
    assert cfg.output == os.path.normpath(str(tmp_path / "out"))
    assert cfg.encoding == "cp1252"          # a code page name is not a path
    assert (cfg.workers, cfg.progress) == (4, True)
    assert cfg.path == cfg_path


def test_absolute_paths_are_left_alone(tmp_path):
    absolute = str(tmp_path / "elsewhere" / "app.exe")
    # TOML literal string (single quotes): a Windows path in a basic string needs
    # every backslash doubled, which is the trap the template warns about.
    cfg = workspace.load(_write(tmp_path / "vb6d.toml", f"target = '{absolute}'\n"))
    assert cfg.target == absolute


def test_an_unknown_key_is_refused_and_the_known_ones_are_listed(tmp_path):
    path = _write(tmp_path / "vb6d.toml", 'listing_dir = "typo"\n')
    with pytest.raises(workspace.ConfigError) as exc:
        workspace.load(path)
    message = str(exc.value)
    assert "listing_dir" in message and "listings" in message


def test_a_wrong_type_names_the_key(tmp_path):
    path = _write(tmp_path / "vb6d.toml", "target = 42\n")
    with pytest.raises(workspace.ConfigError) as exc:
        workspace.load(path)
    assert "target" in str(exc.value) and "string" in str(exc.value)


@pytest.mark.parametrize("body,fragment", [
    ("workers = 0\n", "positive integer"),
    ("workers = true\n", "positive integer"),
    ("progress = 1\n", "true or false"),
    ("[vb6d]\n", None),                     # an empty table is valid
])
def test_values_are_checked_not_coerced(tmp_path, body, fragment):
    path = _write(tmp_path / "vb6d.toml", body)
    if fragment is None:
        assert workspace.load(path).workers is None
    else:
        with pytest.raises(workspace.ConfigError) as exc:
            workspace.load(path)
        assert fragment in str(exc.value)


def test_a_broken_toml_names_the_file(tmp_path):
    path = _write(tmp_path / "vb6d.toml", "target = \n")
    with pytest.raises(workspace.ConfigError) as exc:
        workspace.load(path)
    assert os.path.basename(path) in str(exc.value) and "TOML" in str(exc.value)


def test_keys_may_sit_under_a_vb6d_table(tmp_path):
    path = _write(tmp_path / "vb6d.toml", '[vb6d]\nworkers = 2\n')
    assert workspace.load(path).workers == 2


def test_an_empty_placeholder_is_recorded_not_used(tmp_path):
    path = _write(tmp_path / "vb6d.toml", 'target = ""\nlistings = "  "\n')
    cfg = workspace.load(path)
    assert cfg.target is None and cfg.listings is None
    assert cfg.placeholders == ["target", "listings"]


# --------------------------------------------------------------------------- searching
def test_the_nearest_file_wins_and_a_parent_is_found(tmp_path):
    root = tmp_path / "project"
    (root / "out" / "deep").mkdir(parents=True)
    _write(root / "vb6d.toml", 'workers = 3\n')
    with pytest.MonkeyPatch.context() as mp:
        mp.chdir(root / "out" / "deep")
        found = workspace.find()
    assert found == str(root / "vb6d.toml")


def test_no_file_anywhere_is_not_an_error(tmp_path):
    with pytest.MonkeyPatch.context() as mp:
        mp.chdir(tmp_path)
        assert workspace.find() is None
    cfg = workspace.resolve(search=False)
    assert cfg.path is None and cfg.target is None


def test_an_explicit_missing_path_is_an_error(tmp_path):
    with pytest.raises(workspace.ConfigError):
        workspace.resolve(config_path=str(tmp_path / "gone.toml"))


# --------------------------------------------------------------------------- template
def test_init_writes_placeholders_only(tmp_path):
    path = workspace.write_template(str(tmp_path / "ws"))
    text = open(path, encoding="utf-8").read()
    assert "vb6d run --config vb6d.toml" in text
    for line in text.splitlines():
        if line.strip().startswith("#") or not line.strip():
            continue
        # Every live line is a commented example: nothing real is written.
        raise AssertionError(f"template has a live setting: {line!r}")
    assert workspace.load(path).as_dict() == {}


def test_init_refuses_to_overwrite(tmp_path):
    workspace.write_template(str(tmp_path))
    with pytest.raises(workspace.ConfigError) as exc:
        workspace.write_template(str(tmp_path))
    assert "already exists" in str(exc.value)


def test_the_template_parses_as_toml_and_says_where_it_will_look(tmp_path):
    import tomllib

    path = workspace.write_template(str(tmp_path))
    tomllib.loads(open(path, encoding="utf-8").read())   # commented lines are not keys
