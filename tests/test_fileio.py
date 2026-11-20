"""`fileio.image`: one buffer for a whole-file parse, mapped when it is worth it.

Three things must hold, or the mapping is a regression rather than a saving:
the buffer reads exactly like `bytes`, the mapping is closed on every exit, and a
file the OS refuses to map still parses (as plain `bytes`).
"""

from __future__ import annotations

import mmap
import os

import pytest

# Reuse the PE builder from the DataReport suite: the only synthetic PE in the tree.
from test_datareport import build_pe, design_record, event

from vb6decompiler import fileio


def test_a_small_file_is_read_not_mapped(tmp_path):
    # Below the threshold the mapping setup costs more than the copy; the caller must
    # see the same bytes either way.
    path = tmp_path / "small.bin"
    path.write_bytes(b"MZ" + bytes(range(64)))
    with fileio.image(str(path)) as data:
        assert isinstance(data, bytes)
        assert data[:2] == b"MZ"


def test_a_large_file_is_mapped_and_behaves_like_bytes(tmp_path):
    path = tmp_path / "large.bin"
    body = b"MZ" + bytes(range(256)) * ((fileio.MMAP_MIN_BYTES // 256) + 100)
    path.write_bytes(body)
    with fileio.image(str(path)) as data:
        # The mapping path really ran: this assertion is what makes the rest mean
        # something (a silent fallback would pass every content check).
        assert isinstance(data, mmap.mmap)
        assert len(data) == len(body)
        assert data[:2] == body[:2]
        assert data[-4:] == body[-4:]
        assert data.find(b"MZ") == 0
        assert data[1000:1010] == body[1000:1010]


def test_the_mapping_is_closed_when_the_block_ends(tmp_path):
    path = tmp_path / "large.bin"
    path.write_bytes(b"\x00" * (fileio.MMAP_MIN_BYTES + 1))
    with fileio.image(str(path)) as data:
        keep = data
    assert keep.closed  # Windows would keep the file locked otherwise


def test_the_mapping_is_closed_when_the_block_raises(tmp_path):
    path = tmp_path / "large.bin"
    path.write_bytes(b"\x00" * (fileio.MMAP_MIN_BYTES + 1))
    captured = {}
    with pytest.raises(RuntimeError), fileio.image(str(path)) as data:
        captured["m"] = data
        raise RuntimeError("parser blew up")
    assert captured["m"].closed


def test_an_empty_file_yields_empty_bytes(tmp_path):
    # mmap refuses a zero-length file; the parser must still get a buffer.
    path = tmp_path / "empty.bin"
    path.write_bytes(b"")
    with fileio.image(str(path)) as data:
        assert data == b""


def test_a_file_the_os_will_not_map_is_read_instead(tmp_path, monkeypatch):
    path = tmp_path / "large.bin"
    body = b"MZ" + b"\x00" * fileio.MMAP_MIN_BYTES
    path.write_bytes(body)

    def refuse(*_args, **_kwargs):
        raise OSError("cannot map this file")

    monkeypatch.setattr(fileio.mmap, "mmap", refuse)
    with fileio.image(str(path)) as data:
        assert isinstance(data, bytes)
        assert data[:2] == b"MZ" and len(data) == len(body)


# --------------------------------------------------------------------------- equivalence
def _design(path: str):
    from vb6decompiler import datareport

    designs = datareport.read_designs(path)
    assert len(designs) == 1
    d = designs[0]
    return (d.name, d.va, d.size, [(c.name, c.caption) for c in d.controls])


def test_a_mapped_file_parses_to_the_same_design_as_a_read_one(tmp_path):
    # Two identical PEs: one small (bytes path), one padded past the mapping
    # threshold (mmap path). Padding sits after the declared section, so nothing the
    # parser resolves moves — only the way the buffer is produced changes.
    record = design_record("rptZzz009", event("Section1", (227,))
                           + event("txt1", (10, 20, 30, 40), caption="Name"))
    image = build_pe(record)
    small = tmp_path / "rptSmall.dll"
    small.write_bytes(image)
    large = tmp_path / "rptLarge.dll"
    large.write_bytes(image + b"\x00" * (fileio.MMAP_MIN_BYTES + 1))
    assert os.path.getsize(large) > fileio.MMAP_MIN_BYTES

    assert _design(str(small)) == _design(str(large))
    assert _design(str(small))[0] == "rptZzz009"


# --------------------------------------------------------------------------- output safety
# Review 0.5.x items A2/A3: refuse to open an output that names a consumed
# input, and never let a failed write replace a good file with a partial one.
def test_same_path_spots_the_same_file_under_each_spelling(tmp_path):
    target = tmp_path / "Dir" / "App.exe"
    target.parent.mkdir()
    target.write_bytes(b"MZ")
    same = [
        str(target.parent.parent / "Dir" / "App.exe"),  # absolute detour
        str(target.parent) + os.sep + ".." + os.sep + "Dir" + os.sep + "App.exe",
    ]
    for other in same:
        assert fileio.same_path(str(target), other), other
    # Whether a case variant names the same file is a property of the VOLUME, not
    # of the platform: Windows and macOS (APFS) fold case, most Linux filesystems
    # do not, and ``normcase`` only carries the platform's spelling rule - on macOS
    # it is the identity while the volume still folds. Ask the filesystem.
    variant = str(target).upper()
    assert fileio.same_path(str(target), variant) == os.path.exists(variant)
    assert not fileio.same_path(str(target), str(target.parent / "other.exe"))
    assert not fileio.same_path(str(target.parent), str(target))  # a dir is not its file


def test_refuse_overwrite_inputs_names_the_input_before_anything_opens(tmp_path):
    listing = tmp_path / "fDemo.bas"
    listing.write_text("'x\n", encoding="utf-8")
    # a detour spelling of the very same file: identical on case-folding and
    # case-sensitive filesystems alike (a case spelling is only the same file on Windows)
    out = str(tmp_path / "sub" / os.sep.join(["..", "fDemo.bas"]))
    with pytest.raises(fileio.InputError, match="input files"):
        fileio.refuse_overwrite_inputs(out, [str(listing)])
    assert not list(tmp_path.glob(".vb6d-*.tmp"))  # the guard ran before the writer


def test_same_path_sees_through_symlink_and_hard_link_aliases(tmp_path):
    target = tmp_path / "real.csv"
    target.write_text("va\n", encoding="utf-8")
    link = tmp_path / "link.csv"
    hard = tmp_path / "hard.csv"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        link = None
    try:
        os.link(target, hard)
    except (OSError, NotImplementedError):
        hard = None
    for alias in (link, hard):
        if alias is not None:
            assert fileio.same_path(str(alias), str(target))
            assert fileio.same_path(str(target), str(alias))
    assert not fileio.same_path(str(target), str(tmp_path / "other.csv"))


def test_atomic_out_replaces_the_target_and_leaves_no_temp(tmp_path):
    out = tmp_path / "out.jsonl"
    out.write_text("OLD\n", encoding="utf-8")
    with fileio.atomic_out(str(out)) as fh:
        fh.write("NEW\n")
    assert out.read_text(encoding="utf-8") == "NEW\n"
    assert list(tmp_path.glob(".vb6d-*.tmp")) == []


def test_atomic_out_keeps_the_previous_file_when_the_block_fails(tmp_path):
    out = tmp_path / "out.jsonl"
    out.write_bytes(b"PRE-EXISTING\n")
    with pytest.raises(RuntimeError, match="planted"), fileio.atomic_out(str(out)) as fh:
        fh.write("half a new file\n")
        raise RuntimeError("planted")
    assert out.read_bytes() == b"PRE-EXISTING\n"
    assert list(tmp_path.glob(".vb6d-*.tmp")) == [], "a failed run must clean up its temp"


# --------------------------------------------------------------------------- unique temp names
# Review 0.5.7 item A: the temp path was deterministic (`<out>.vb6d-tmp`), so two
# writers shared a buffer, a pre-existing file with that name was truncated, and a
# symlink there redirected the write outside the destination.
def test_a_legacy_tmp_file_is_never_touched(tmp_path):
    out = tmp_path / "out.jsonl"
    legacy = tmp_path / (out.name + ".vb6d-tmp")
    legacy.write_bytes(b"someone else's buffer\n")
    with fileio.atomic_out(str(out)) as fh:
        fh.write("NEW\n")
    assert legacy.read_bytes() == b"someone else's buffer\n"
    assert out.read_text(encoding="utf-8") == "NEW\n"


def test_a_symlink_at_the_legacy_tmp_path_is_never_followed(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"must not change\n")
    legacy = tmp_path / "out.jsonl.vb6d-tmp"
    try:
        os.symlink(victim, legacy)
    except (OSError, NotImplementedError):
        pytest.skip("this filesystem/user cannot create symlinks")
    out = tmp_path / "out.jsonl"
    with fileio.atomic_out(str(out)) as fh:
        fh.write("NEW\n")
    assert victim.read_bytes() == b"must not change\n"
    assert os.path.islink(legacy)  # untouched, not replaced or removed


def test_two_concurrent_writers_use_different_temp_files(tmp_path, monkeypatch):
    import threading

    barrier = threading.Barrier(2)
    replaced: list[str] = []
    lock = threading.Lock()
    real_replace = fileio.os.replace

    def record(src, dst):
        with lock:
            replaced.append(os.path.basename(src))
        return real_replace(src, dst)

    monkeypatch.setattr(fileio.os, "replace", record)
    body = "".join(f"line {i}\n" for i in range(2000))
    errors: list[BaseException] = []

    def write(name: str) -> None:
        try:
            barrier.wait(timeout=10)
            with fileio.atomic_out(str(tmp_path / name)) as fh:
                fh.write(body)
        except (OSError, RuntimeError) as exc:  # surfaced by the assertion below
            errors.append(exc)

    threads = [threading.Thread(target=write, args=(n,)) for n in ("a.jsonl", "b.jsonl")]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert not errors, errors
    assert len(replaced) == 2 and len(set(replaced)) == 2, replaced
    for name in ("a.jsonl", "b.jsonl"):
        assert (tmp_path / name).read_text(encoding="utf-8") == body
    assert list(tmp_path.glob(".vb6d-*.tmp")) == []


def test_a_failed_writer_removes_only_its_own_temp(tmp_path):
    foreign = tmp_path / ".vb6d-foreign.tmp"
    foreign.write_bytes(b"another process\n")
    out = tmp_path / "out.jsonl"
    with pytest.raises(RuntimeError, match="planted"), fileio.atomic_out(str(out)) as fh:
        fh.write("half\n")
        raise RuntimeError("planted")
    assert foreign.read_bytes() == b"another process\n"
    assert not out.exists()
