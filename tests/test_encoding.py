"""Code page selection: the order of the three sources and what must be refused.

The parsers map a character offset back onto the original bytes (``frm.py`` does it
on every raw value), so the single-byte property is not a style preference — it is a
correctness pre-condition. These tests therefore check the *resolved* table as well as
the function that reads it: a future row pointing at cp932 would pass every happy-path
test and corrupt offsets in production.
"""

from __future__ import annotations

import pytest

from vb6decompiler import encoding


# --------------------------------------------------------------------- source order
def test_explicit_wins_over_the_header():
    # A developer on a Turkish IDE can compile text in any code page; the flag is the
    # only input that comes from the person running the tool.
    assert encoding.resolve_encoding("cp1251", 0x041F) == ("cp1251", "explicit")


def test_lcid_is_used_when_no_explicit_codec():
    assert encoding.resolve_encoding(None, 0x0419) == ("cp1251", "lcid")


def test_default_when_neither_source_speaks():
    assert encoding.resolve_encoding(None, None) == (encoding.DEFAULT_CODEPAGE, "default")


def test_unknown_lcid_falls_back_to_the_default():
    # 0x042B (Armenian) has no ANSI default code page; measured probe returned none.
    assert encoding.codepage_for_lcid(0x042B) is None
    assert encoding.resolve_encoding(None, 0x042B) == (encoding.DEFAULT_CODEPAGE, "default")


def test_explicit_name_is_canonicalised():
    assert encoding.resolve_encoding("windows-1251", None) == ("cp1251", "explicit")


def test_the_three_measured_anchors():
    assert encoding.codepage_for_lcid(0x041F) == "cp1254"  # tr-TR
    assert encoding.codepage_for_lcid(0x0409) == "cp1252"  # en-US
    assert encoding.codepage_for_lcid(0x0419) == "cp1251"  # ru-RU


# --------------------------------------------------------------------- refusals
@pytest.mark.parametrize("lcid", [0x0411, 0x0804, 0x0412, 0x0404])
def test_a_multibyte_build_is_refused_by_name(lcid):
    with pytest.raises(ValueError, match="multi-byte"):
        encoding.resolve_encoding(None, lcid)


def test_multibyte_explicit_codec_is_refused():
    with pytest.raises(ValueError, match="multi-byte"):
        encoding.resolve_encoding("cp932", None)


def test_a_non_ansi_codec_is_refused():
    # UTF-8 is variable-width too, but it is not in the multi-byte set: it must still
    # be refused, with the supported list, not silently accepted.
    with pytest.raises(ValueError, match="supported"):
        encoding.resolve_encoding("utf-8", None)


def test_an_unknown_codec_name_is_one_readable_line():
    with pytest.raises(ValueError, match="unknown code page"):
        encoding.resolve_encoding("cp9999", None)


# --------------------------------------------------------------------- table invariants
def test_every_mapped_code_page_is_single_byte_or_a_named_refusal():
    for lcid, codec in encoding.LCID_TO_CODEPAGE.items():
        if codec in encoding.MULTIBYTE_CODEPAGES:
            with pytest.raises(ValueError, match="multi-byte"):
                encoding.resolve_encoding(None, lcid)
        else:
            encoding.validate_single_byte(codec)  # raises for anything not ANSI


def test_single_byte_pages_really_decode_one_byte_per_character():
    # The invariant the parsers depend on: 256 input bytes -> 256 characters, so a
    # character offset is a byte offset.
    for codec in sorted(encoding.SINGLE_BYTE_CODEPAGES):
        assert len(bytes(range(256)).decode(codec, "replace")) == 256, codec
