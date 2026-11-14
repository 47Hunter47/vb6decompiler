"""Tests against a real VB6 build and install.

They skip unless ``VB6D_TARGET`` names a native VB6 executable. Optionally set
``VB6D_LISTINGS`` to a decompiler listing directory and ``VB6D_FRM_DIR`` to a
``.frm`` directory for the calibration tests.

The numbers asserted here are *lower bounds and invariants*, never a magic total:
a different program legitimately has different counts, and a test that pins one
program's totals would fail on the next target and teach the wrong lesson.
"""

from __future__ import annotations

import os
import re

import pytest

from vb6decompiler import literals, pe, procs

TARGET = os.environ.get("VB6D_TARGET")
LISTINGS = os.environ.get("VB6D_LISTINGS")
needs_target = pytest.mark.skipif(not TARGET, reason="VB6D_TARGET not set")
needs_listings = pytest.mark.skipif(not LISTINGS, reason="VB6D_LISTINGS not set")


@needs_target
def test_pe_reads_a_real_image():
    image = pe.read(TARGET)
    assert image.bits in (32, 64)
    assert image.imports, "a real VB6 executable imports at least its runtime"
    assert image.entry_point > image.image_base


@needs_target
def test_vb6_header_chain_gives_objects_and_methods():
    project = procs.read(TARGET)
    assert project.object_count == len(project.objects)
    assert project.project_name
    declared = sum(o.method_count for o in project.objects)
    assert declared > 0
    # Every object is typed; an unparsed type is reported as hex, never dropped.
    assert all(o.object_type for o in project.objects)


@needs_target
def test_addresses_are_only_reported_when_a_prologue_is_there():
    project = procs.read(TARGET)
    for _obj, method in project.methods_by_address():
        with open(TARGET, "rb") as fh:
            fh.seek(method.file_offset)
            assert fh.read(3) == procs.PROLOGUE


@needs_target
def test_binary_literals_include_utf16_runs():
    lits = literals.scan_binary(TARGET, include_cp1254=False)
    assert len(lits) > 1000, "a native build of any size has thousands of BSTRs"
    assert any(l.encoding == "utf16" and l.is_sql for l in lits)


@needs_listings
def test_listing_scan_recovers_procedure_literals():
    lits = literals.scan_listings(LISTINGS)
    assert lits
    assert all(l.proc_va for l in lits if l.source == "listing")
    assert any(l.is_sql for l in lits)


@needs_listings
def test_stitching_closes_some_statements_and_reports_the_rest():
    from vb6decompiler import sqlstitch

    lits = literals.scan_listings(LISTINGS)
    cands = sqlstitch.stitch_all(lits)
    stats = sqlstitch.summarise(cands)
    assert stats["candidates"] >= 0
    # A run that closes nothing is suspicious on a real corpus; if this ever fires,
    # look at the gates instead of lowering the bar.
    assert stats["closed"] > 0


@needs_target
@needs_listings
def test_frx_files_are_a_slice_of_the_executables_blob_region():
    """docs/formats.md §5: a ``.frx`` is a slice of the blob, not a second source.

    Each listing ``.frx`` must line up byte-for-byte with the same form's blob
    region in the executable.  If a long shared prefix ever stops being the normal
    case, the ``.frx`` really does hold independent data and §5 has to be
    re-measured rather than patched.
    """
    from vb6decompiler import blob

    regions = {b.name.lower(): b.data for b in blob.iter_form_blobs(TARGET)}
    compared = long_prefix = 0
    for name in sorted(os.listdir(LISTINGS)):
        if not name.lower().endswith(".frx"):
            continue
        region = regions.get(name[:-4].lower())
        if region is None:
            continue
        with open(os.path.join(LISTINGS, name), "rb") as fh:
            data = fh.read()
        at = region.find(data[:64])
        if at < 0:
            continue
        compared += 1
        shared = 0
        while (at + shared < len(region) and shared < len(data)
               and region[at + shared] == data[shared]):
            shared += 1
        if shared >= 4096:
            long_prefix += 1
    assert compared, "no listing .frx matched a form blob in the executable"
    assert long_prefix * 2 >= compared, (long_prefix, compared)


@needs_target
@needs_listings
def test_sstab_page_titles_come_from_the_blob_not_from_frm_text():
    """Decompiled ``.frm`` text drops ``TabCaption``; the blob keeps the titles."""
    from vb6decompiler import blob

    titles = {}
    for form in blob.extract_forms(TARGET):
        for control in form.controls:
            if (control.type or "").rsplit(".", 1)[-1] == "SSTab":
                titles.setdefault(form.name.lower(), []).extend(control.pages or [])
    assert titles, "no SSTab control in the executable"

    seen = 0
    dropped = 0
    for name in sorted(os.listdir(LISTINGS)):
        if not name.lower().endswith(".frm"):
            continue
        with open(os.path.join(LISTINGS, name), "rb") as fh:
            text = fh.read().decode("utf-8", "replace")
        if "SSTab" not in text:
            continue
        seen += 1
        if re.search(r"TabCaption\s*\(\s*\d+\s*\)", text):
            continue  # a real source tree keeps them; nothing to recover here
        dropped += 1
        # The design text cannot say which tabs exist; the blob can.  A form that
        # loses this is a form whose tabs are silently unknown.
        assert titles.get(name[:-4].lower()), name
    assert seen, "no SSTab form in the listings"
    # Only meaningful when the decompiler dropped the captions: that is when the
    # blob is the only source, and it must then carry them.
    if dropped:
        assert sum(len(v) for v in titles.values()) >= dropped
