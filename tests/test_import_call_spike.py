"""The call-order spike's two extractors, tested without a binary or capstone.

The spike itself needs an executable and capstone to answer its question, so what can
be asserted here is the part that has a right answer on its own: how a listing line
turns into a slot address, and how a direct call is followed to its `jmp [slot]`
thunk. Both were wrong once during the measurement (`call 00516100h` was skipped,
which made 102 of 1,750 procedures look like a decoder disagreement), which is why
they are pinned.
"""

from __future__ import annotations

import importlib.util
import os
import struct

SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")


def _load():
    spec = importlib.util.spec_from_file_location(
        "t35_spike", os.path.join(SCRIPTS, "t35_import_call_spike.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # capstone is imported inside main(), so this is free
    return module


spike = _load()

IMAGE_BASE = 0x400000


def _off_of(blob_size: int):
    """A VA->offset resolver for a buffer that starts at IMAGE_BASE."""
    def off_of(rva: int):
        return rva if 0 <= rva < blob_size else None
    return off_of


def _thunk_buffer(thunk_off: int, slot_va: int, size: int = 0x100) -> bytes:
    buf = bytearray(size)
    buf[thunk_off:thunk_off + 2] = b"\xff\x25"
    struct.pack_into("<I", buf, thunk_off + 2, slot_va)
    return bytes(buf)


# --------------------------------------------------------------------- thunk resolution
def test_a_direct_call_is_followed_through_its_jmp_thunk():
    buf = _thunk_buffer(0x40, 0x4010F4)
    assert spike.thunk_slot(IMAGE_BASE + 0x40, buf, IMAGE_BASE, _off_of(len(buf))) == 0x4010F4


def test_a_direct_call_that_is_not_a_thunk_resolves_to_nothing():
    # A normal `call rel32` to real code has no IAT slot behind it; inventing one
    # would attach a runtime name to an unrelated call.
    buf = bytes(0x100)
    assert spike.thunk_slot(IMAGE_BASE + 0x40, buf, IMAGE_BASE, _off_of(len(buf))) is None
    assert spike.thunk_slot(0x10, buf, IMAGE_BASE, _off_of(len(buf))) is None  # unmapped


# --------------------------------------------------------------------- listing extraction
LISTING = "\n".join([
    "Private Sub Demo()  '401000",
    "  loc_00401010: call [004010F4h] ; __vbaOnError",
    "  loc_00401020: call 00516100h ; __vbaChkstk",
    "  loc_00401030: call [eax+00000004h]",
    "  loc_00401040: call [004010A0h] ; __vbaHresultCheckObj",
    "End Sub",
    "",
    "Private Sub Next()  '402000",
    "  loc_00402010: call [004010A0h]",
    "End Sub",
    "",
])


def test_listing_slots_keeps_order_and_resolves_thunks(tmp_path):
    thunk_va = 0x516100
    buf = _thunk_buffer(thunk_va - IMAGE_BASE, 0x4011E4, size=0x200000)
    path = tmp_path / "fDemo.frm"
    path.write_text(LISTING, encoding="cp1254")

    seqs, order, thunk_calls = spike.listing_slots([str(path)], buf, IMAGE_BASE,
                                                   _off_of(len(buf)))
    # Order preserved, the late-bound `call [eax+4]` skipped (no static target), and
    # the direct call attributed to the slot behind its thunk — not dropped.
    assert seqs[0x401000] == [0x4010F4, 0x4011E4, 0x4010A0]
    assert seqs[0x402000] == [0x4010A0]
    assert thunk_calls == 1
    assert order[0x401000] == "fDemo.frm"


def test_a_thunk_outside_the_image_is_not_invented(tmp_path):
    # The direct call points past the buffer: it must not become a slot.
    buf = bytes(0x100)
    path = tmp_path / "fDemo.frm"
    path.write_text("Private Sub Demo()  '401000\n  call 00999999h\nEnd Sub\n", encoding="cp1254")
    seqs, _order, thunk_calls = spike.listing_slots([str(path)], buf, IMAGE_BASE,
                                                    _off_of(len(buf)))
    assert seqs[0x401000] == []
    assert thunk_calls == 0


def test_a_procedure_header_is_read_before_any_call_line(tmp_path):
    # The header carries no `call`, so a filter that skips "lines without call" first
    # loses the procedure and attributes its calls to the previous one.
    path = tmp_path / "fDemo.frm"
    path.write_text(LISTING, encoding="cp1254")
    buf = bytes(0x200000)
    seqs, _order, _thunks = spike.listing_slots([str(path)], buf, IMAGE_BASE,
                                                _off_of(len(buf)))
    assert set(seqs) == {0x401000, 0x402000}


def test_the_body_cap_is_named_and_not_zero():
    # A zero cap would silently measure nothing and report 100 % agreement.
    assert spike.DEFAULT_BODY_CAP > 0
