"""Tests for the DataReport design reader.

Two layers:

* synthetic records built byte-by-byte in the measured grammar, so the traps that
  matter (``len32 + UTF-16LE`` strings, the odd-length alignment pad, sparse
  property arrays, positional section ownership, the record header that makes a
  class-name hit a design) are pinned without needing a target install;
* one real-target test, skipped unless ``VB6D_REPORT_DIR`` (a directory of compiled
  VB6 binaries) or ``VB6D_TARGET`` (one such file) is set. It asserts invariants and
  prints the measured coverage — it does not pin one program's totals, because a
  different program legitimately has different counts.
"""

from __future__ import annotations

import os
import struct

import pytest

from vb6decompiler import datareport as dr


# ---------------------------------------------------------------------------
# synthetic record builders (the measured grammar, written out by hand)
# ---------------------------------------------------------------------------


def string_event(text: str) -> bytes:
    """``len32 + UTF-16LE`` plus the ``00 00`` pad after an odd character count."""
    data = struct.pack("<I", len(text)) + text.encode("utf-16-le")
    if len(text) % 2 == 1:
        data += b"\x00\x00"
    return data


def event(text: str, ints: tuple[int, ...] = (), caption: str | None = None) -> bytes:
    """A name (or value) string followed by its int32 property array."""
    data = string_event(text) + b"".join(struct.pack("<I", v) for v in ints)
    if caption is not None:
        data += string_event(caption)
    return data


def design_record(name: str, body: bytes, pad_to: int = 0x200) -> bytes:
    """Wrap a property stream in the design record header this module locates.

    Layout: ``<size:int32> <idx:uint8> <namelen:uint16> <name> 0x00 0xFF
    <len16><class name> 0x00`` followed by ``body``.
    """
    if len(body) < pad_to:
        body = body + b"\x00" * (pad_to - len(body))
    class_name = dr.DATAREPORT_CLASS.encode("ascii")
    tail = (
        b"\x00"  # idx
        + struct.pack("<H", len(name))
        + name.encode("ascii")
        + b"\x00"
        + b"\xFF"
        + struct.pack("<H", len(class_name))
        + class_name
        + b"\x00"
        + body
    )
    return struct.pack("<I", len(tail)) + tail


def parse(name: str, body: bytes, path: str = "synthetic.dll") -> dr.Design:
    # No tail padding here: a trailing run of zero bytes would be read as the last
    # control's property array and shadow the geometry under test.
    blob = design_record(name, body, pad_to=0)
    head = dr.DesignHead(
        name=name,
        va=0x401000,
        size=struct.unpack_from("<I", blob, 0)[0],
        offset=0,
        header_fields=(0, 0),
    )
    return dr.parse_design(head, blob, path)


def build_pe(payload: bytes, section_va: int = 0x1000, image_base: int = 0x400000) -> bytes:
    """A one-section 32-bit PE image carrying ``payload`` in ``.text``."""
    raw_offset = 0x200
    head = bytearray(raw_offset)
    head[0:2] = b"MZ"
    struct.pack_into("<I", head, 0x3C, 0x40)
    head[0x40:0x44] = b"PE\x00\x00"
    coff = 0x44
    struct.pack_into("<HHIIIHH", head, coff, 0x14C, 1, 0, 0, 0, 224, 0x0102)
    opt = coff + 20
    struct.pack_into("<H", head, opt, 0x10B)          # PE32
    struct.pack_into("<I", head, opt + 16, 0x1000)    # entry point RVA
    struct.pack_into("<I", head, opt + 28, image_base)
    struct.pack_into("<I", head, opt + 92, 0)         # no data directories
    sec = opt + 224
    head[sec:sec + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", head, sec + 8, len(payload), section_va, len(payload), raw_offset)
    struct.pack_into("<I", head, sec + 36, 0x60000020)
    return bytes(head) + payload


# ---------------------------------------------------------------------------
# string events
# ---------------------------------------------------------------------------


def test_strings_are_len32_utf16le_and_odd_lengths_carry_a_pad():
    buf = string_event("abc") + string_event("Section1")
    events = list(dr.iter_string_events(buf))
    assert [text for _off, text, _end in events] == ["abc", "Section1"]
    # "abc" is three characters: 4 + 6 bytes of string, then the 2-byte pad.
    assert events[0][2] == 4 + 6 + 2
    assert events[1][0] == events[0][2]


def test_the_pad_does_not_swallow_the_next_event():
    """The pad is why the scan must be byte-by-byte, not on a 4-byte stride.

    With a 4-byte stride the pad of the odd-length string is read as the high half
    of the following length, so the event after it disappears.
    """
    odd = string_event("txt1") + b"".join(struct.pack("<I", v) for v in (1, 2, 3, 4))
    following = string_event("lblNext") + b"\x00" * 16
    buf = odd + following
    texts = [text for _o, text, _e in dr.iter_string_events(buf)]
    assert "lblNext" in texts


def test_form_grammar_finds_nothing_here():
    """A ``len16 + CP1254`` string (the form-blob grammar) is not a DataReport string."""
    buf = struct.pack("<H", 6) + b"txt123" + b"\x00" + b"\x00" * 32
    assert list(dr.iter_string_events(buf)) == []


# ---------------------------------------------------------------------------
# property arrays
# ---------------------------------------------------------------------------


def test_full_property_array_is_left_top_width_height():
    design = parse(
        "rptT1",
        event("Section1", (302,))
        + event("txt1", (500, 1200, 3000, 225), caption="Firma")
        + event("Section2", (1335,))
        + event("lblBaslik", (4713, 283, 5298, 225), caption="Baslik"),
    )
    txt, label = design.controls
    assert (txt.left, txt.top, txt.width, txt.height) == (500, 1200, 3000, 225)
    assert txt.geometry == "full"
    assert txt.top_inferred is False
    assert txt.caption == "Firma"
    assert label.section == "Section2" and label.section_role == "PageHeader"
    assert txt.section == "Section1" and txt.section_role == "Detail"


def test_sparse_layout_leaves_top_unknown_outside_detail():
    """``(L, W, H, X)``: Top was not serialised; nothing is invented for it."""
    design = parse(
        "rptT2",
        event("Section2", (1335,))
        + event("lblBaslik", (4713, 300, 225, 3), caption="Baslik"),
    )
    (label,) = design.controls
    assert label.geometry == "sparse_lwhx"
    assert (label.left, label.width, label.height) == (4713, 300, 225)
    assert label.top is None and label.top_inferred is False


def test_detail_top_is_inferred_only_from_the_design_itself():
    design = parse(
        "rptT3",
        event("Section1", (302,))
        + event("txt1", (100, 1200, 3000, 225), caption="Bir")   # complete record
        + event("txt2", (200, 2000, 225, 1), caption="Iki")      # (L, W, H, X)
        + event("Section2", (1335,))
        + event("lblBaslik", (4713, 300, 225, 1), caption="Baslik"),
    )
    txt1, txt2, label = design.controls
    assert (txt1.left, txt1.top) == (100, 1200)
    assert txt2.geometry == "sparse_lwhx"
    assert (txt2.left, txt2.width, txt2.height) == (200, 2000, 225)
    assert txt2.top == 1200 and txt2.top_inferred is True
    # The header control sits in another band: the Detail mode is not its evidence.
    assert label.top is None and label.top_inferred is False


def test_double_skip_layout_keeps_width_and_top_unknown():
    """``(L, H, X, Y)``: neither Top nor Width was serialised."""
    design = parse(
        "rptT4",
        event("Section1", (302,))
        + event("txt1", (100, 1200, 3000, 225), caption="Bir")
        + event("txt9", (40, 225, 1, 2), caption="Dokuz"),
    )
    _, skipped = design.controls
    assert skipped.geometry == "sparse_lh"
    assert skipped.left == 40 and skipped.height == 225
    assert skipped.width is None
    assert skipped.top == 1200 and skipped.top_inferred is True


def test_long_property_run_is_reported_not_guessed():
    design = parse("rptT5", event("Section1", (302,)) + event("txt1", tuple(range(1, 11))))
    (txt,) = design.controls
    assert txt.geometry == "unreliable"
    assert (txt.left, txt.top, txt.width, txt.height) == (None, None, None, None)


def test_short_property_run_is_partial():
    design = parse("rptT6", event("Section1", (302,)) + event("txt1", (5, 6)))
    (txt,) = design.controls
    assert txt.geometry == "partial"
    assert txt.left is None and txt.top is None


# ---------------------------------------------------------------------------
# captions, sections, orphan values
# ---------------------------------------------------------------------------


def test_caption_repeating_the_name_is_flagged_as_the_default():
    design = parse(
        "rptT7",
        event("Section2", (1335,))
        + event("txt1", (10, 20, 30, 40), caption="txt1")
        + event("txt2", (11, 21, 31, 41), caption="Customer Code"),
    )
    first, second = design.controls
    assert first.caption == "txt1" and first.caption_is_default is True
    assert second.caption == "Customer Code" and second.caption_is_default is False


def test_a_control_name_after_a_control_is_not_its_caption():
    design = parse(
        "rptT8",
        event("Section1", (302,))
        + event("txt1", (10, 20, 30, 40))
        + event("txt2", (11, 21, 31, 41), caption="Name"),
    )
    first, second = design.controls
    assert first.caption == ""
    assert second.caption == "Name"


def test_orphan_strings_are_kept_as_values():
    design = parse(
        "rptT9",
        event("Section3", (500,)) + event("Total") + event(": 1.234,56"),
    )
    assert [r.kind for r in design.records] == ["section", "value", "value"]
    assert design.records[1].name == "Total"
    assert design.values[1].name == ": 1.234,56"


def test_section_records_carry_their_own_height():
    design = parse(
        "rptT10",
        event("Section4", (120,)) + event("Section2", (1335,)) + event("Section1", (227,)),
    )
    assert design.section_heights() == {"Section4": 120, "Section2": 1335, "Section1": 227}
    assert [r.section_role for r in design.sections] == ["rptHeader", "PageHeader", "Detail"]


def test_controls_before_any_section_have_no_owner():
    design = parse("rptT11", event("lblErken", (1, 2, 3, 4), caption="x") + event("Section1", (227,)))
    first = design.controls[0]
    assert first.section == "" and first.section_role == ""
    assert first.section == "" and first.top == 2  # geometry is still read


# ---------------------------------------------------------------------------
# locating designs in a PE file
# ---------------------------------------------------------------------------


def test_read_designs_finds_one_design_with_its_name_and_extent(tmp_path):
    body = event("Section1", (227,)) + event("txt1", (10, 20, 30, 40), caption="Name")
    record = design_record("rptZzz001", body)
    path = tmp_path / "rptZzz.dll"
    path.write_bytes(build_pe(record))

    designs = dr.read_designs(str(path))
    assert [d.name for d in designs] == ["rptZzz001"]
    assert designs[0].va == 0x400000 + 0x1000
    assert designs[0].size == struct.unpack_from("<I", record, 0)[0]
    assert designs[0].controls[0].caption == "Name"


def test_a_bare_class_name_is_not_a_design(tmp_path):
    """The class name also occurs in the type-library region: two hits per DLL.

    Only a hit whose five header bytes agree is a design record; the others must be
    dropped instead of yielding a nameless design.
    """
    good = design_record("rptZzz002", event("Section1", (227,)))
    # A bare class-name string with no record header in front of it.
    bare = b"\x00\x00\x00\x00" + dr.DATAREPORT_CLASS.encode("ascii") + b"\x00\x00\x00\x00"
    path = tmp_path / "rptBoth.dll"
    path.write_bytes(build_pe(good + bare))

    designs = dr.read_designs(str(path))
    assert [d.name for d in designs] == ["rptZzz002"]
    assert len(dr._class_offsets(path.read_bytes())) == 2


def test_designs_are_not_collapsed_by_name(tmp_path):
    """Two files may hold a design of the same name with different content."""
    one = tmp_path / "rptA.dll"
    one.write_bytes(build_pe(design_record("rptSame01", event("Section1", (227,)))))
    two = tmp_path / "rptB.dll"
    two.write_bytes(
        build_pe(
            design_record(
                "rptSame01",
                event("Section1", (500,)) + event("txt1", (1, 2, 3, 4), caption="x"),
            )
        )
    )
    designs = dr.read_paths([str(one), str(two)])
    assert len(designs) == 2
    assert {d.key for d in designs} == {
        ("rpta.dll", "rptSame01"),
        ("rptb.dll", "rptSame01"),
    }
    assert {d.section_heights()["Section1"] for d in designs} == {227, 500}


def test_summary_reports_denominators():
    design = parse(
        "rptT12",
        event("Section1", (227,))
        + event("txt1", (10, 20, 30, 40), caption="Name")
        + event("txt2", (10, 300, 225, 1))
        + event("lblX", (10, 225, 1, 2)),
    )
    stats = dr.summary([design])
    assert stats["designs"] == 1
    assert stats["controls"] == 3
    assert stats["top_unknown"] == 0  # all three Detail records: mode 20 is used
    assert stats["width_unknown"] == 1
    assert stats["full_geometry"] == 1
    assert stats["geometry"] == {"full": 1, "sparse_lh": 1, "sparse_lwhx": 1}


# ---------------------------------------------------------------------------
# real target (skipped without an install)
# ---------------------------------------------------------------------------

_REPORT_DIR = os.environ.get("VB6D_REPORT_DIR")
if not _REPORT_DIR and os.environ.get("VB6D_TARGET"):
    _REPORT_DIR = os.path.dirname(os.environ["VB6D_TARGET"])

needs_reports = pytest.mark.skipif(not _REPORT_DIR, reason="VB6D_REPORT_DIR not set")


@needs_reports
def test_real_report_binaries_yield_consistent_designs():
    paths = dr.iter_files([_REPORT_DIR])
    designs = dr.read_paths(paths)
    assert designs, "no DataReport design found; check the directory"

    stats = dr.summary(designs)
    print(
        f"\ndesigns {stats['designs']} in {stats['files']} files"
        f"   records {stats['records']}"
        f" (sections {stats['sections']}, controls {stats['controls']},"
        f" values {stats['values']})"
        f"   full geometry {stats['full_geometry']}/{stats['controls']}"
        f"   Top unknown {stats['top_unknown']} (inferred {stats['top_inferred']},"
        f" and {stats['width_unknown']} records with no Width)"
    )

    # Every design must be self-consistent: records in file order and inside the
    # record extent that located them.
    for design in designs:
        offsets = [r.offset for r in design.records]
        assert offsets == sorted(offsets), design.name
        assert all(0 <= r.offset <= r.end <= design.size for r in design.records), design.name
        # A DataReport without a single section record was located wrongly.
        assert design.sections, design.name
        # Names are the anchor of the grammar: a control must satisfy the prefix rule.
        assert all(dr.CONTROL_NAME_RE.match(c.name) for c in design.controls), design.name

    # Coverage gates: some geometry must be stored, and the reader must not claim
    # full geometry for everything (that would mean it is inventing the sparse cases).
    assert stats["full_geometry"] > 0
    assert stats["full_geometry"] < stats["controls"]
    assert stats["designs_with_section"] == stats["designs"]
