"""Tests for :mod:`vb6decompiler.blob`.

Two layers:

* Synthetic blobs assembled from the documented record grammar.  These pin the
  decoder's behaviour (geometry, control arrays, wide geometry, OCX class
  names, Visible marker, SSTab pages, blob discovery through a PE header) and
  run everywhere.
* A real-target check, skipped unless ``VB6D_TARGET`` (path to the ``.exe``)
  and ``VB6D_FRM_DIR`` (directory with the matching ``.frm`` text) are set.
  It asserts coverage thresholds rather than exact counts, because the counts
  belong to the target, not to this repo; the measured numbers are printed by
  ``validate()``.
"""
from __future__ import annotations

import os
import struct

import pytest

from vb6decompiler import blob


# --------------------------------------------------------------------------
# Synthetic blob builder (grammar only — no target bytes)
# --------------------------------------------------------------------------
def _s(text: str) -> bytes:
    """CP1254 string in blob form: ``<len16> bytes 0x00``."""
    raw = text.encode("cp1254")
    return struct.pack("<H", len(raw)) + raw + b"\x00"


def _u16(text: str) -> bytes:
    """UTF-16LE string in blob form: ``<bytelen16> bytes``."""
    raw = text.encode("utf-16-le")
    return struct.pack("<H", len(raw)) + raw


def _record(name: str, cls: int, body: bytes, *, index: int | None = None,
            idx_byte: int = 0) -> bytes:
    """One record as ``<size:int32> <idx:uint8> [<index:uint16>] <name> 0x00 ...``.

    ``cls`` is the class byte; ``0xFF`` means ``body`` starts with the OCX class
    name string.  The size field is patched to the real record length, which is
    what the scanner expects (and what lets a record be recognised at all).
    """
    if index is None:
        head = bytearray(b"\x00\x00\x00\x00" + bytes([idx_byte]))
    else:
        head = bytearray(b"\x00\x00\x00\x00" + bytes([idx_byte])
                         + struct.pack("<H", index))
    head += struct.pack("<H", len(name)) + name.encode("ascii") + b"\x00"
    head += bytes([cls])
    record = bytearray(head) + body
    struct.pack_into("<I", record, 0, len(record))
    if index is not None:
        # Bit 31 marks a control-array element.
        struct.pack_into("<I", record, 0, len(record) | 0x80000000)
    return bytes(record)


def _geom(pid: int, left: int, top: int, width: int, height: int,
          post: int = 0xFF) -> bytes:
    """16-bit geometry property plus the pid of the following property."""
    return (bytes([pid]) + struct.pack("<hhhh", left, top, width, height)
            + bytes([post]) + b"\x00")


def _geom32(pid: int, left: int, top: int, width: int, height: int,
            post: int = 0xFF) -> bytes:
    """32-bit geometry property: ``<pid> 0x00 0x80 <4 x int32>``."""
    return (bytes([pid, 0x00, 0x80]) + struct.pack("<iiii", left, top, width, height)
            + bytes([post]) + b"\x00")


def _cap(text: str) -> bytes:
    """Caption property: pid ``0x01`` + CP1254 string (first property slot)."""
    return b"\x01" + _s(text)


def _form_blob(name: str, controls: list[bytes], *,
               client: tuple[int, int] | None = (6000, 4000)) -> bytes:
    """Build a form record followed by its control records."""
    body = b""
    if client is not None:
        # Form-level client size: pid 0x35, block length 12, ClientTop, W, H.
        body += bytes([0x35]) + struct.pack("<I", 12) + struct.pack("<iii", 0, *client)
    # Trailing padding keeps the last property's window inside the blob, as it
    # always is in a real form (other properties follow the client size).
    return _record(name, 0x0D, body) + b"".join(controls) + b"\x00" * 16


def _parse(data: bytes, name: str = "fTest") -> blob.Form:
    form = blob.extract_form(blob.FormBlob(name=name, offset=0, size=len(data),
                                           data=data))
    assert form is not None
    return form


# --------------------------------------------------------------------------
# Geometry and record decoding
# --------------------------------------------------------------------------
def test_plain_control_geometry_and_caption():
    data = _form_blob("fTest", [
        _record("lblTitle", 0x01, _cap("Merhaba") + _geom(0x05, 120, 240, 3000, 315)),
    ])
    form = _parse(data)
    assert form.width == 6000 and form.height == 4000
    assert len(form.controls) == 1
    ctrl = form.controls[0]
    assert (ctrl.name, ctrl.type) == ("lblTitle", "VB.Label")
    assert ctrl.geometry() == (120, 240, 3000, 315)
    assert ctrl.caption == "Merhaba"
    assert ctrl.index is None


def test_control_array_index_from_header():
    data = _form_blob("fTest", [
        _record("cmdGo", 0x04, _geom(0x04, 0, 0, 1000, 400), index=7, idx_byte=7),
    ])
    ctrl = _parse(data).controls[0]
    assert ctrl.index == 7
    assert (ctrl.left, ctrl.width) == (0, 1000)


def test_wide_geometry_used_when_value_exceeds_int16():
    data = _form_blob("fTest", [
        _record("imgBig", 0x18, _geom32(0x03, 40000, 50000, 480, 480)),
    ])
    ctrl = _parse(data).controls[0]
    assert ctrl.type == "VB.Image"
    assert ctrl.geometry() == (40000, 50000, 480, 480)


def test_ocx_class_name_comes_from_record():
    body = _s("MSComctlLib.Slider") + _geom(0x03, 60, 90, 2400, 400)
    ctrl = _parse(_form_blob("fTest", [_record("sldOne", 0xFF, body)])).controls[0]
    assert ctrl.type == "MSComctlLib.Slider"
    assert ctrl.geometry() == (60, 90, 2400, 400)


def test_visible_marker_after_geometry_means_hidden():
    data = _form_blob("fTest", [
        # No marker after the geometry -> unknown (the blob only stores the
        # non-default value, so "unknown" is the honest answer).
        _record("txtA", 0x02, _geom(0x04, 10, 10, 1000, 300, post=0xFF)),
        # <pid 0x09, 0> immediately after the geometry -> Visible = False.
        _record("txtB", 0x02, _geom(0x04, 20, 20, 1000, 300, post=0x09)),
    ])
    txt_a, txt_b = _parse(data).controls
    assert txt_a.visible is None
    assert txt_b.visible is False


def test_class_without_geometry_is_not_emitted():
    # VB.Line has X1/Y1/X2/Y2 instead of Left/Top/Width/Height.
    data = _form_blob("fTest", [
        _record("linBorder", 0x17, _s("x") + _geom(0x03, 0, 0, 100, 100)),
        _record("lblKept", 0x01, _geom(0x05, 5, 5, 500, 100)),
    ])
    form = _parse(data)
    assert [c.name for c in form.controls] == ["lblKept"]


def test_form_client_size():
    data = _form_blob("fTest", [], client=(11145, 6045))
    form = _parse(data)
    assert (form.width, form.height) == (11145, 6045)


# --------------------------------------------------------------------------
# SSTab pages
# --------------------------------------------------------------------------
SIG = blob.SSTAB_SIGNATURES[0]


def _sstab_body() -> bytes:
    # Filler between a member name and the next signature mirrors real records,
    # where property bytes sit between them; the signature search window is
    # wider than the filler, so a short filler would read as a page title.
    body = _s("MSComctlLib.SSTab") + _geom(0x03, 60, 60, 6000, 3000, post=0xFF)
    body += _u16("Genel") + SIG + b"\x00" * 8
    body += _u16("txtAd") + b"\x00" * 64
    body += _u16("Liste") + SIG + b"\x00" * 8
    body += _u16("lstKalem") + b"\x00" * 64
    return body


def test_sstab_pages_and_membership():
    data = _form_blob("fTest", [
        _record("tabMain", 0xFF, _sstab_body()),
        _record("txtAd", 0x02, _geom(0x04, 100, 100, 2000, 300)),
        _record("lstKalem", 0x08, _geom(0x04, 100, 500, 2000, 900)),
    ])
    form = _parse(data)
    tab = next(c for c in form.controls if c.name == "tabMain")
    assert tab.pages == ("Genel", "Liste")
    pages = {c.name: c.tab_page for c in form.controls}
    assert pages["txtAd"] == 1
    assert pages["lstKalem"] == 2


# --------------------------------------------------------------------------
# Blob discovery through a minimal PE image
# --------------------------------------------------------------------------
def _minimal_pe(payload: bytes) -> bytes:
    """One-section PE file with ``payload`` in that section's raw data."""
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)

    coff = bytearray(20)
    struct.pack_into("<H", coff, 0, 0x014C)   # i386
    struct.pack_into("<H", coff, 2, 1)        # one section
    struct.pack_into("<H", coff, 16, 0xE0)    # optional header size

    opt = bytearray(0xE0)
    struct.pack_into("<I", opt, 28, 0x400000)  # ImageBase

    sec = bytearray(40)
    sec[0:8] = b".data\x00\x00\x00"
    struct.pack_into("<I", sec, 8, len(payload))   # VirtualSize
    struct.pack_into("<I", sec, 12, 0x1000)        # VirtualAddress
    struct.pack_into("<I", sec, 16, len(payload))  # SizeOfRawData
    struct.pack_into("<I", sec, 20, 0x200)         # PointerToRawData

    head = bytes(dos) + b"PE\x00\x00" + bytes(coff) + bytes(opt) + bytes(sec)
    assert len(head) <= 0x200
    return head + b"\x00" * (0x200 - len(head)) + payload


def test_find_form_records_and_iter_form_blobs(tmp_path):
    payload = b"\x00" * 32 + _form_blob("fAlpha", [
        _record("lblOne", 0x01, _geom(0x05, 15, 30, 1200, 240)),
    ]) + b"\x00" * 16
    exe = tmp_path / "synthetic.exe"
    exe.write_bytes(_minimal_pe(payload))

    records = blob.find_form_records(exe.read_bytes())
    assert [(r[2], r[3]) for r in records][0][0] == "fAlpha"

    blobs = blob.iter_form_blobs(str(exe))
    assert [b.name for b in blobs] == ["fAlpha"]
    form = blob.extract_form(blobs[0])
    assert form is not None and [c.name for c in form.controls] == ["lblOne"]


def test_load_sections_rejects_non_pe(tmp_path):
    junk = tmp_path / "nope.bin"
    junk.write_bytes(b"not a pe file at all" * 4)
    with pytest.raises(ValueError):
        blob.load_sections(str(junk))


# --------------------------------------------------------------------------
# Real target (opt-in)
# --------------------------------------------------------------------------
TARGET = os.environ.get("VB6D_TARGET")
FRM_DIR = os.environ.get("VB6D_FRM_DIR")


@pytest.mark.skipif(not TARGET, reason="set VB6D_TARGET to a VB6 .exe to run")
def test_real_target_has_form_blobs():
    blobs = blob.iter_form_blobs(TARGET)
    assert blobs, "no form blobs found — absence is not proof, check the parser"
    forms = [f for f in (blob.extract_form(b) for b in blobs) if f and f.controls]
    assert len(forms) > 0
    # Every emitted control must carry a type and positive size.
    for form in forms[:50]:
        for ctrl in form.controls:
            assert ctrl.type and ctrl.width > 0 and ctrl.height > 0


@pytest.mark.skipif(not (TARGET and FRM_DIR),
                    reason="set VB6D_TARGET and VB6D_FRM_DIR to measure coverage")
def test_real_target_coverage():
    report = blob.validate(TARGET, FRM_DIR)
    print(report.summary())
    assert report.truth_forms > 0
    # Thresholds, not exact counts: the counts belong to the target.
    assert report.control_rate >= 99.0
    assert report.form_rate >= 90.0
