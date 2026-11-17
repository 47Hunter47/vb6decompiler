"""`fileio.image`: one buffer for a whole-file parse, mapped when it is worth it.

Three things must hold, or the mapping is a regression rather than a saving:
the buffer reads exactly like `bytes`, the mapping is closed on every exit, and a
file the OS refuses to map still parses (as plain `bytes`).
"""

from __future__ import annotations

import mmap
import os

import pytest

from vb6decompiler import fileio

# Reuse the PE builder from the DataReport suite: the only synthetic PE in the tree.
from test_datareport import build_pe, design_record, event


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
    with pytest.raises(RuntimeError):
        with fileio.image(str(path)) as data:
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
