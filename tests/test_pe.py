"""The pe stage: surface summary rows and the truncation flag.

No target binary needed: the synthetic image from `_mini_pe` stands in. The
flag exists because a truncated file parses cleanly — the headers read, the
lookups past EOF return nothing — and without it the cut image looked like a
clean foreign file.
"""

from __future__ import annotations

import os

from _mini_pe import mini_pe

from vb6decompiler import pe


def test_a_whole_mini_image_is_not_truncated():
    # Guards the fixture itself: if this fails, the builder (not the parser) is wrong.
    img = pe._parse("m.exe", mini_pe())
    assert img.bits == 32 and img.sections[0].name == ".text"
    assert not img.truncated
    assert img.summary()["truncated"] is False


def test_a_section_claiming_bytes_past_eof_is_truncated():
    img = pe._parse("m.exe", mini_pe(truncated=True))
    assert img.truncated
    row = img.summary()
    assert row["truncated"] is True


def test_scan_directory_keeps_good_and_cut_images_apart(tmp_path):
    good = tmp_path / "good.exe"
    good.write_bytes(mini_pe())
    cut = tmp_path / "cut.exe"
    cut.write_bytes(mini_pe(truncated=True))
    rows = {os.path.basename(r["path"]): r for r in pe.scan_directory(str(tmp_path))}
    assert rows["good.exe"]["truncated"] is False
    assert rows["cut.exe"]["truncated"] is True
