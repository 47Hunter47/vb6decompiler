"""Unit tests that need no target binary.

Target-dependent tests live in ``test_target.py`` and skip unless ``VB6D_TARGET``
points at a real VB6 build.
"""

from __future__ import annotations

import os
import struct

import pytest

from vb6decompiler import literals, mask, sqlstitch


# --------------------------------------------------------------------------- literals
def _lit(text: str, proc: int = 0x400010) -> literals.Literal:
    return literals.Literal(va=0x500000, text=text, encoding="listing", proc_va=proc)


def test_sql_flag_is_a_flag_not_a_verdict():
    assert _lit("SELECT * FROM tOrder WHERE HOrderDep = '").is_sql
    assert not _lit("Settings saved").is_sql


def test_merge_keys_on_address_not_text():
    a = literals.Literal(va=0x500000, text="SELECT 1", encoding="listing", proc_va=1)
    b = literals.Literal(va=0x500010, text="SELECT 1", encoding="listing", proc_va=1)
    # The same sentence at two addresses is two literals; keying by text hides one.
    assert len(literals.merge([a], [b])) == 2


def test_merge_deduplicates_identical_address_pairs():
    a = literals.Literal(va=0x500000, text="x", encoding="listing", proc_va=1)
    b = literals.Literal(va=0x500000, text="x", encoding="listing", proc_va=1)
    assert len(literals.merge([a], [b])) == 1


def test_listing_literal_regex_accepts_mov_not_only_push():
    line = 'loc_0164467E: mov edx, 00A3F970h ; "INSERT tAuditLog (AuditCode) VALUES "\n'
    m = literals.LISTING_LITERAL.search(line)
    assert m is not None and m.group(1) == "00A3F970"


def test_listing_proc_header_takes_the_trailing_va():
    line = "Private Sub FisButton_Click() '36FB300\n"
    m = literals.LISTING_PROC.match(line)
    assert m is not None and int(m.group(2), 16) == 0x36FB300


def test_turkish_letters_are_inside_a_literal():
    # A "high byte must be zero" rule would split this literal around 'ş'.
    raw = "Connection failed ş ğ İ".encode("utf-16-le")
    text = raw.decode("utf-16-le")
    assert literals._RUN.fullmatch(text) is not None


# --------------------------------------------------------------------------- sqlstitch
def test_listing_header_gives_literals_their_procedure():
    """Regression: a header has no ';', so it must be matched before that filter.

    Measured failure on a real corpus: 441,607 literals parsed, **0** with a
    procedure VA, and stitching then produced 0 candidates because every chain was
    empty.
    """
    import tempfile

    body = (
        "Private Sub FisButton_Click() '15F6040\n"
        'loc_015F6050: push 00A3F970h ; "SELECT HOrderNo FROM tOrder "\n'
        'loc_015F6058: mov edx, 00A3F980h ; "WHERE HOrderDep = "\n'
        "End Sub\n"
        "\n"
        "Private Sub IptalButton_Click() '15F6120\n"
        'loc_015F6130: push 00A3F990h ; "UPDATE tAuditLog SET AuditCode = 1"\n'
        "End Sub\n"
    )
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "fDemo011.frm"), "w", encoding="cp1254") as fh:
            fh.write(body)
        lits = literals.scan_listings(d)

    assert len(lits) == 3
    assert [l.proc_va for l in lits] == [0x15F6040, 0x15F6040, 0x15F6120]
    # ...and the chain therefore exists, which is what stitching needs.
    chains = sqlstitch.chains(lits)
    assert sorted(chains) == [0x15F6040, 0x15F6120]


def test_stitch_closes_across_two_fragments():
    a = literals.Literal(va=0xA3F970, text="SELECT HOrderNo FROM tOrder WHERE ", encoding="listing", proc_va=1)
    b = literals.Literal(va=0xA3F980, text="HOrderDep = 'E1'", encoding="listing", proc_va=1)
    cands = sqlstitch.stitch_all([a, b])
    assert len(cands) == 1
    assert cands[0].closed and cands[0].tables == ["tOrder"]


def test_balanced_single_statement_closes():
    chain = [
        _lit("SELECT HOrderNo FROM tOrder WHERE "),
        _lit("HOrderDep = 'E1'"),
    ]
    cands = sqlstitch.stitch(chain, 0)
    assert any(c.status == "CLOSED" and c.tables == ["tOrder"] for c in cands)


def test_open_quote_is_reported_not_guessed():
    chain = [_lit("SELECT * FROM tOrder WHERE HOrderDep = '")]
    (cand,) = sqlstitch.stitch(chain, 0)
    assert cand.status == "OPEN_QUOTE"
    assert not cand.closed


def test_verb_inside_quotes_is_not_a_second_statement():
    text = "UPDATE tAuditLog SET AuditMsg = 'UPDATE tOrder SET HOrderFlag = 0' WHERE AuditCode = 1"
    assert sqlstitch.statements(text) == 1


def test_two_glued_statements_are_counted_as_two():
    text = "UPDATE tWorkOrder SET HApproved = 1 WHERE HApproved = 0 DELETE FROM tAuditLog"
    assert sqlstitch.statements(text) == 2
    cand = sqlstitch._classify(text, [_lit(text)])
    assert cand.status == "MULTI"


def test_human_text_glued_onto_sql_is_flagged():
    cand = sqlstitch._classify("SELECT * FROM tItem WHERE ItemKey = ''Not found!", [_lit("x")])
    assert cand.status == "ESCAPE"


def test_dangling_connector_is_reported():
    cand = sqlstitch._classify(
        "SELECT * FROM tItem WHERE ItemKey = 'A' AND", [_lit("x")]
    )
    assert cand.status == "DANGLING"


def test_balance_requires_matching_parens():
    assert sqlstitch.balanced("SELECT (a) FROM t")
    assert not sqlstitch.balanced("SELECT (a FROM t")


# --------------------------------------------------------------------------- mask
def test_password_value_is_masked_and_key_kept():
    out = mask.mask_text("Provider=SQLOLEDB;uid=sa;pwd=S3cret!;database=ACME_PROD")
    assert "S3cret" not in out
    assert "ACME_PROD" in out  # database names are evidence, not a credential
    assert "uid=[REDACTED]" in out


def test_masking_is_idempotent():
    once = mask.mask_text("server=192.0.2.10;uid=sa;pwd=x")
    twice = mask.mask_text(once)
    assert once == twice


def test_unc_and_ip_are_masked():
    out = mask.mask_text(r"\\fileserv\data\appdata.mdb on 198.18.4.7")
    assert "fileserv" not in out and "198.18.4.7" not in out


def test_utf16_artifact_is_masked_and_the_bom_survives(tmp_path):
    # 'command > out.txt' in PowerShell writes UTF-16. Read as UTF-8 with
    # replace it is 'u?i?d?' and every pattern misses: the gate passed live
    # leaks before this test existed.
    body = "uid=sa;pwd=hunter2\nNotlar: \u011f\u015f\u0131\u00e7\u00fc listesi\n"
    p = tmp_path / "out.txt"
    p.write_bytes(b"\xff\xfe" + body.encode("utf-16-le"))
    assert mask.mask_file(str(p)) == 1
    raw = p.read_bytes()
    assert raw.startswith(b"\xff\xfe")  # still valid UTF-16 after the rewrite
    text = raw.decode("utf-16")
    assert "hunter2" not in text and "[REDACTED]" in text
    assert "\u011f\u015f\u0131\u00e7\u00fc" in text  # non-ASCII text survives the round trip


def test_audit_finds_a_utf16_leak(tmp_path):
    (tmp_path / "leak.txt").write_bytes(b"\xff\xfe" + "pwd=hunter2\n".encode("utf-16-le"))
    res = mask.audit(str(tmp_path))
    assert not res.clean and res.findings["password"] >= 1


def test_non_utf8_bytes_survive_masking_byte_for_byte(tmp_path):
    body = "uid=sa;pwd=hunter2\nNotlar: \u011f\u015f\u0131\u00e7\u00fc listesi\n"
    original = body.encode("cp1254")
    p = tmp_path / "old.txt"
    p.write_bytes(original)
    mask.mask_file(str(p))
    # Everything outside the masked values must be byte-identical: the old
    # decode-with-replace pass turned each Turkish byte into U+FFFD on write.
    expected = original.replace(b"uid=sa", b"uid=[REDACTED]").replace(b"pwd=hunter2", b"pwd=[REDACTED]")
    assert p.read_bytes() == expected


def test_mask_does_not_cross_lines(tmp_path):
    # A whitespace class that crosses newlines would eat the next line's first word.
    p = tmp_path / "a.csv"
    p.write_text("col\nServer=\nnext line stays\n", encoding="utf-8")
    before = p.read_text(encoding="utf-8").count("\n")
    mask.mask_file(str(p))
    after = p.read_text(encoding="utf-8").count("\n")
    assert before == after
    assert "next line stays" in p.read_text(encoding="utf-8")


def test_audit_counts_values_not_keywords(tmp_path):
    clean = tmp_path / "clean.csv"
    clean.write_text("note\n;uid=;\n", encoding="utf-8")  # key present, no value
    result = mask.audit(str(clean))
    assert result.findings["uid"] == 0
    assert result.clean


def test_audit_finds_a_live_value(tmp_path):
    leaky = tmp_path / "leaky.csv"
    leaky.write_text("conn\nuid=sa;pwd=hunter2\n", encoding="utf-8")
    result = mask.audit(str(leaky))
    assert not result.clean


def test_prose_about_keys_is_not_rewritten_or_counted(tmp_path):
    """A document that *describes* masking must survive its own gate.

    Measured failure: with an empty-match value pattern, "`uid=`/`pwd=`" became
    "`uid=[REDACTED]`/`pwd=[REDACTED]`" and the audit counted two leaks in a file
    that contains no secret at all.
    """
    doc = tmp_path / "notes.md"
    original = "Connection strings with `uid=`/`pwd=` values and `Server=` take care.\n"
    doc.write_text(original, encoding="utf-8")
    assert mask.mask_file(str(doc)) == 0
    assert doc.read_text(encoding="utf-8") == original
    assert mask.audit(str(doc)).clean


def test_concatenated_data_does_not_hide_a_second_statement():
    """`02SELECT` has no word boundary; `\b` counted two statements as one.

    Measured: a join reported CLOSED whose text was
    ``…ProcA1001SELECT ContactKey FROM tContact … SELECT * FROM tAlternate …``.
    """
    text = "ProcB2002SELECT ContactKey FROM tContact WHERE a = 1 SELECT * FROM tAlternate"
    assert sqlstitch.statements(text) == 2


def test_a_candidate_must_begin_where_a_statement_can_begin():
    chain = [
        _lit("AltStockCode' AND AltStockType = 'AltStockType' AND UnitCode = ''"),
    ]
    assert sqlstitch.stitch(chain, 0) == []
    assert not sqlstitch.starts_statement(chain[0].text)


def test_documentation_addresses_survive_masking():
    """RFC 5737 ranges are the stand-ins the docs use on purpose.

    Masking them would redact the repo's own examples, which teaches readers to
    switch the gate off.  A real private address must still be masked.
    """
    doc = mask.mask_text("host 192.0.2.10 alt 198.51.100.7 alt 203.0.113.9")
    assert "192.0.2.10" in doc and "198.51.100.7" in doc and "203.0.113.9" in doc
    # RFC 2544 benchmarking range: not private, not documentation, so it must be
    # masked like any live address.
    live = mask.mask_text("host 198.18.4.7 alt 198.19.5.8 alt 198.18.9.9")
    assert "198.18.4.7" not in live and "198.19.5.8" not in live and "198.18.9.9" not in live
    assert live.count(mask.IP) == 3
