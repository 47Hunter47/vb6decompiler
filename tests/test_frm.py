"""Tests for the ``.frm`` design-block parser.

Every test here states the measured reason it exists: the five traps in
``vb6decompiler/frm.py``'s module docstring each get a test that fails if someone
"simplifies" the parser back into a wrong-but-plausible shape.

The synthetic fixtures in ``tests/fixtures/`` are hand-written, not captured from
the target: they are small enough to enumerate by eye and they pin the grammar.
The last test compares against a real decompiled directory and skips unless
``VB6D_FRM_DIR`` is set — per ``docs/RULES.md`` §2, a parser over vendor text
ships with a coverage run, and that run needs a target path from the environment,
never a hardcoded one.
"""

from __future__ import annotations

import os

import pytest

from vb6decompiler import frm

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
FRM_DIR = os.environ.get("VB6D_FRM_DIR")
needs_frm_dir = pytest.mark.skipif(not FRM_DIR, reason="VB6D_FRM_DIR not set")


def fx(name: str) -> str:
    return os.path.join(FIXTURES, name)


@pytest.fixture(scope="module")
def array_form() -> frm.Form:
    return frm.parse_frm(fx("array_and_values.frm"))


@pytest.fixture(scope="module")
def tab_form() -> frm.Form:
    return frm.parse_frm(fx("sstab_pages.frm"))


# --------------------------------------------------------------------- trap 1: absence
def test_absent_boolean_is_not_false(array_form):
    """A missing `Visible`/`Locked` line is the VB6 default, never `False`.

    Measured: the target writes `Visible = 0 'False` 432 times and `Visible = -1`
    never, so "absent" carries almost all of the truth and folding it into
    `False` would hide thousands of visible controls.
    """
    free = array_form.control("txtSerbest")
    assert free.bool_prop("Locked") is None          # not written
    assert free.tri("Locked") == frm.ABSENT
    assert free.effective_bool("Locked", default=False) is False   # caller's default
    assert free.effective_bool("Locked", default=True) is True     # still the caller's


def test_tristate_counts_three_states(array_form):
    counts = frm.bool_tri_counts(array_form.controls, "Locked")
    assert counts == {frm.TRUE_EXPLICIT: 1, frm.FALSE_EXPLICIT: 1, frm.ABSENT: 6}
    # The three states always add up to the denominator the caller passed.
    assert sum(counts.values()) == len(array_form.controls)


def test_enumeration_zero_is_not_boolean_false(array_form):
    """`BorderStyle = 0 'None` and `Visible = 0 'False` are numerically identical.

    Only the VB6 type-hint comment separates them; a parser that reads every 0 as
    false turns "no border" into "hidden".
    """
    free = array_form.control("txtSerbest")
    assert free.prop("BorderStyle").value == 0
    assert free.prop("BorderStyle").comment == "None"
    assert free.tri("BorderStyle") == frm.ABSENT      # written, but not a boolean
    assert array_form.control("picKutu").tri("Visible") == frm.FALSE_EXPLICIT


# --------------------------------------------------------------------- trap 2: CP1254
def test_cp1254_text_is_decoded_and_raw_bytes_kept(array_form):
    """Turkish text must be CP1254, and the original bytes must stay reachable."""
    assert array_form.control("mnuCikis").caption == "Çıkış"
    # CP1254 bytes for Ç ı k ı ş, still wrapped in the quotes VB6 writes.
    assert array_form.control("mnuCikis").caption_bytes == b'"\xc7\xfdk\xfd\xfe"'
    # latin-1 would "succeed" here and produce mojibake; prove the two differ.
    assert b"\xc7\xfdk\xfd\xfe".decode("latin-1") != "Çıkış"


def test_apostrophe_inside_a_caption_is_not_a_comment(array_form):
    assert array_form.caption == "Settings' welcome note"


def test_decimal_comma_is_a_float(array_form):
    """VB6 writes `Size = 8,25` (authoring locale); it is one number, not a tuple."""
    assert array_form.control("picKutu").font["Size"] == 8.25
    assert isinstance(array_form.control("picKutu").font["Size"], float)


# --------------------------------------------------------------------- trap 3: twips
def test_geometry_is_twips_as_written(array_form):
    assert array_form.client_size == (6000, 3000)
    assert array_form.control("txtAd", 0).bounds == (100, 500, 1200, 300)


def test_pixel_conversion_is_opt_in_and_labelled(array_form):
    """15 twips/px is an assumption; nothing converts unless it is asked to."""
    c = array_form.control("txtAd", 0)
    assert c.bounds == (100, 500, 1200, 300)                  # twips, unchanged
    assert c.bounds_px() == (100 / 15, 500 / 15, 1200 / 15, 300 / 15)
    assert frm.TWIPS_PER_PX_ASSUMED == 15
    assert "assum" in frm.twips_to_px.__doc__.lower()          # documented as a guess


def test_partial_rectangle_is_none_not_zero():
    form = frm.parse_frm_text(
        "Begin VB.Form f\n"
        "  Begin VB.TextBox t\n"
        "    Left = 10\n"
        "    Top = 20\n"
        "  End\n"
        "End\n"
    )
    assert form.control("t").bounds is None      # Width/Height absent: no 0 fallback
    assert form.control("t").twips("Left") == 10


# --------------------------------------------------------------------- trap 4: arrays
def test_control_array_grouped_and_ordered_by_index(array_form):
    """One name + one type + `Index` is one control with many positions."""
    arrays = array_form.control_arrays()
    assert list(arrays) == [("TextBox", "txtAd")]
    assert [c.index for c in arrays[("TextBox", "txtAd")]] == [0, 1, 2]
    # ... and they are sorted even though the file writes Index 2 first.
    assert [c.bounds[1] for c in arrays[("TextBox", "txtAd")]] == [500, 800, 200]
    assert len(array_form.by_name("txtAd")) == 3     # not merged into one control


def test_scalar_controls_are_not_arrays(array_form):
    assert ("TextBox", "txtSerbest") not in array_form.control_arrays()


def test_index_gap_is_detectable():
    """A missing element is a real finding (the target has one form like this)."""
    form = frm.parse_frm_text(
        "Begin VB.Form f\n"
        "  Begin VB.TextBox a\n    Index = 0\n  End\n"
        "  Begin VB.TextBox a\n    Index = 5\n  End\n"
        "End\n"
    )
    members = form.control_arrays()[("TextBox", "a")]
    assert [c.index for c in members] == [0, 5]


def test_same_name_different_type_is_not_an_array():
    """`(type, name)` is the key: a TextBox and a Label sharing a name are two controls."""
    form = frm.parse_frm_text(
        "Begin VB.Form f\n"
        "  Begin VB.TextBox x\n    Index = 0\n  End\n"
        "  Begin VB.Label x\n    Caption = \"l\"\n  End\n"
        "End\n"
    )
    arrays = form.control_arrays()
    assert ("TextBox", "x") in arrays
    assert ("Label", "x") not in arrays
    assert [c.short_type for c in arrays[("TextBox", "x")]] == ["TextBox"]


# --------------------------------------------------------------------- trap 5: SSTab
def test_sstab_ownership_comes_from_nesting(tab_form):
    """A page child has no parent property; the Begin/End nesting is the only source."""
    sstab = tab_form.sstabs()[0]
    assert sstab.short_type == "SSTab"
    assert [c.name for c in tab_form.sstab_children("SSTab1")] == ["txtGeneral", "fraDetail"]
    assert tab_form.control("txtGeneral").parent == "SSTab1"
    # a grandchild still resolves to the tab control, not to the Frame
    assert tab_form.sstab_of(tab_form.control("lblIc")) == "SSTab1"


def test_sstab_pages_keep_their_captions_and_index(tab_form):
    """`TabCaption(n)` is indexed: keying by name alone would report one page."""
    sstab = tab_form.sstabs()[0]
    assert sstab.tab_pages() == [(0, "General"), (1, "Detail"), (2, "Summary")]
    assert sstab.selected_page == 1     # `Tab = 1`, the page shown in the designer


def test_sstab_without_page_properties_reports_no_pages():
    """No `TabCaption` means no pages *known*, not "one page".

    Measured: 0 of the 14 `SSTab` controls in the target write `Tab`/`TabCaption`
    — the page data lives in the `.frx` `OleObjectBlob` — so an empty list is the
    honest answer and a guessed page count would be invented data.
    """
    form = frm.parse_frm_text(
        "Begin VB.Form f\n"
        "  Begin TabDlg.SSTab SSTab1\n"
        "    Width = 10\n"
        "    Begin VB.TextBox t\n      Left = 1\n    End\n"
        "  End\n"
        "End\n"
    )
    sstab = form.sstabs()[0]
    assert sstab.tab_pages() == []
    assert sstab.selected_page is None
    assert [c.name for c in form.sstab_children("SSTab1")] == ["t"]


# --------------------------------------------------------------------- grammar edges
def test_line_has_no_bounds_and_derived_bounds_are_named_so(array_form):
    line = array_form.control("Line1")
    assert line.bounds is None                      # a Line has X1/Y1/X2/Y2 only
    assert line.line_coords == (10, 20, 10, 120)
    assert line.derived_bounds == (10, 20, 1, 100)  # 1 twip minimum, vertical line


def test_frx_reference_is_not_text_and_offsets_are_hex(array_form):
    """`"f.frx":10AA` is a binary offset; the target writes hex (measured: 1,626 refs)."""
    pic = array_form.control("picKutu").prop("Picture")
    assert pic.kind == frm.KIND_FRX
    assert pic.value == frm.FrxRef("fSynthArray.frx", 0x10AA, "10AA")
    assert array_form.control("picKutu").prop("Picture").value.offset == 4266


def test_hex_colour_is_an_integer(array_form):
    assert array_form.control("Line1").prop("BorderColor").value == 0xFFFFFF


def test_menu_nesting_and_caption(array_form):
    child = array_form.control("mnuCikis")
    assert child.short_type == "Menu"
    assert child.parent == "mnuDosya"
    assert array_form.control("mnuDosya").caption == "&Dosya"


def test_property_group_members_belong_to_the_control(array_form):
    font = array_form.control("picKutu").props
    assert "Font.Name" in font and font["Font.Name"].value == "Arial"
    assert array_form.control("picKutu").font == {"Name": "Arial", "Size": 8.25, "Weight": 700}


def test_code_after_the_design_block_is_ignored(array_form):
    """`Private Sub Form_Load()` and its body must not become properties."""
    assert "BeginNotAControl" not in {c.name for c in array_form.controls}
    assert array_form.warnings == []
    assert array_form.complete is True


def test_code_only_file_raises_instead_of_returning_an_empty_form():
    """A code-only stub is 434 of 802 files on the target; 0 controls is a lie for it."""
    with pytest.raises(frm.NoDesignBlock):
        frm.parse_frm(fx("code_only.frm"))


def test_truncated_design_block_is_flagged_with_a_reason():
    """One file on the target stops mid-control and continues into `Public ... As`."""
    form = frm.parse_frm(fx("truncated.frm"))
    assert form.complete is False
    assert len(form.controls) == 1                      # recovered, not thrown away
    assert "closing End" in form.incomplete_reason
    assert len(form.warnings) == 1                      # one finding, not 14k lines
    assert form.warnings[0].line == 10


def test_scan_directory_accounts_for_every_file():
    result = frm.scan_directory(FIXTURES)
    summary = frm.summarize(result)
    assert summary["files_seen"] == len(
        [n for n in os.listdir(FIXTURES) if n.lower().endswith(".frm")]
    )
    assert summary["files_parsed"] == 3                  # array, sstab, truncated
    assert summary["files_without_design_block"] == 1     # code_only.frm, named not skipped
    assert summary["parse_failures"] == 0
    assert summary["forms_incomplete"] == 1
    assert summary["files_parsed"] + summary["files_without_design_block"] \
        + summary["parse_failures"] == summary["files_seen"]
    # two groups: txtAd(0..2) in the array fixture, and the single Index=9
    # element recovered from the truncated file (an array with one surviving member)
    assert summary["control_array_groups"] == 2
    assert summary["controls_total"] == 13


def test_summary_text_reports_denominators():
    text = frm.format_summary(frm.summarize(frm.scan_directory(FIXTURES)))
    assert "3 parsed / 4 seen" in text
    assert "of 13" in text         # tri-state line carries its denominator


def test_summary_counts_sstab_pages_with_caption():
    """Counts come from `summarize`, which is what a caller would report."""
    result = frm.scan_directory(FIXTURES)
    summary = frm.summarize(result)
    assert summary["sstab_controls"] == 1
    assert summary["sstab_pages_with_caption"] == 3
    assert summary["sstab_selected_page_written"] == 1


# --------------------------------------------------------------------- real target
@needs_frm_dir
def test_real_frm_directory_parses_without_failures():
    """Invariants only — never a pinned total (another program has other counts)."""
    result = frm.scan_directory(FRM_DIR)
    summary = frm.summarize(result)

    assert summary["files_seen"] > 0
    assert summary["files_parsed"] > 0
    assert summary["parse_failures"] == 0, summary["parse_failure_details"]
    # every file is either parsed or explicitly counted as having no design block
    assert summary["files_parsed"] + summary["files_without_design_block"] \
        == summary["files_seen"]
    assert summary["controls_total"] > 0
    # CP1254 decoding of a Turkish target must not produce replacement characters
    assert summary["captions_containing_replacement_char"] == 0

    # Every control-array element carries an Index and groups are ordered.
    for form in result.forms:
        for key, members in form.control_arrays().items():
            indexes = [c.index for c in members if c.index is not None]
            assert indexes == sorted(indexes), (form.name, key)
            assert all(c.name == key[1] for c in members)

    # A form found with nesting raises a claim that must hold for its children.
    for form in result.forms:
        for sstab in form.sstabs():
            assert sstab.short_type == "SSTab"
            for child in form.sstab_children(sstab.name):
                assert child.parent == sstab.name

    print(frm.format_summary(summary))
