"""The offline explorer: no network, no markup from untrusted text, every link resolves.

Three properties are tested here and each has been a real bug in tools like this:

* **An embedded string must not be able to end its own block.** ``</script>`` inside a
  caption is the classic way a JSON-in-script page becomes an XSS hole, so the JSON is
  escaped at the three characters that matter and the test injects exactly that.
* **Links must resolve on disk.** A site that only works with a server, or whose
  ``href`` points at a page the builder forgot to write, is a dead end for the reader
  who opened it from ``file://``.
* **A big build must be chunked, and the report must quote the real sizes.**
"""

from __future__ import annotations

import html.parser
import json
import os
import re

import synth_vb6

from vb6decompiler import cli, explore

HOSTILE = "<script>alert('x')</script>\" onload=\"evil()"
NON_ASCII = "Kayıt bulunamadı — şğİı"


class _Scan(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags: list[str] = []
        self.attrs: list[str] = []
        self.links: list[str] = []
        self.scripts = 0

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag.lower())
        if tag.lower() == "script":
            self.scripts += 1
        for key, value in attrs:
            self.attrs.append(key.lower())
            if key.lower() in ("href", "src", "action"):
                self.links.append(value or "")


def _scan(text: str) -> _Scan:
    parser = _Scan()
    parser.feed(text)
    return parser


def _source(tmp_path, procedures, *, tables=None, forms=None, partial=None):
    """A run directory built by hand, so the test controls every string in it."""
    root = tmp_path / "out"
    (root / "dossier").mkdir(parents=True)
    with open(root / "dossier" / "dossier.jsonl", "w", encoding="utf-8") as fh:
        fh.writelines(json.dumps(row, ensure_ascii=False) + "\n" for row in procedures)
    if tables is not None:
        (root / "schema").mkdir()
        (root / "schema" / "schema.json").write_text(
            json.dumps({"tables": tables, "crud": [], "unparsed": [],
                        "partial": partial or []}), encoding="utf-8")
    if forms:
        (root / "frm").mkdir()
        for name in forms:
            (root / "frm" / name).write_text("<html></html>", encoding="utf-8")
    return root


def _proc(va="4013B0", obj="modA", names=(), sql=(), literals=()):
    return {"va": va, "object_name": obj,
            "name_hint": {"kind": "hint", "names": list(names)} if names else None,
            "literals": [{"va": "401000", "text": t, "encoding": "listing"} for t in literals],
            "sql": [{"text": t, "status": s, "closed": s == "CLOSED", "tables": tabs,
                     "parts": 1, "reason": ""} for t, s, tabs in sql]}


# --------------------------------------------------------------------------- escaping
def test_a_hostile_string_cannot_end_its_json_block(tmp_path):
    src = explore.read_source(str(_source(
        tmp_path, [_proc(sql=[(f"SELECT a FROM t WHERE b = '{HOSTILE}", "CLOSED", ["t"])])])))
    page = explore.render_procedures(src, explore.chunks(explore.procedures_data(src)))
    # The page legitimately closes its own data block and its own script; what must
    # never happen is a *third* closer, i.e. one supplied by the hostile string.
    assert page.count("</script>") == 2
    blocks = re.findall(r'<script type="application/json"[^>]*>(.*?)</script>', page, re.DOTALL)
    assert blocks
    for block in blocks:
        assert json.loads(block)                     # still valid JSON
        assert "<" not in block and ">" not in block
    # And the hostile text is still in the data, as text: proof it was escaped, not dropped.
    assert "alert" in page
    scan = _scan(page)
    assert "script" in scan.tags                     # the page's own script only
    assert not [a for a in scan.attrs if a.startswith("on")]


def test_non_ascii_survives_readable(tmp_path):
    src = explore.read_source(str(_source(tmp_path, [_proc(literals=[NON_ASCII])])))
    data = explore.procedures_data(src)
    assert data[0]["messages"] == [NON_ASCII]
    page = explore.render_procedures(src, explore.chunks(data))
    assert "Kayıt bulunamadı" in page


def test_embed_escapes_exactly_the_three_characters():
    text = explore.embed({"a": "</script>", "b": "&", "c": "ünïcode"})
    assert "<" not in text and ">" not in text and "&" not in text
    assert "\\u003c" in text and "\\u0026" in text
    assert json.loads(text) == {"a": "</script>", "b": "&", "c": "ünïcode"}


# --------------------------------------------------------------------------- safety
def test_every_page_forbids_loading_anything(tmp_path):
    root = _source(tmp_path, [_proc()], tables={"tOrder": {"columns": ["a"]}},
                   forms=["fA.html"])
    built = explore.build(explore.read_source(str(root)), forms_prefix="../frm/")
    for name, body in built.files.items():
        assert "Content-Security-Policy" in body, name
        assert "default-src 'none'" in body and "connect-src 'none'" in body
        assert "nonce-" in body, name
        for link in _scan(body).links:
            assert not re.match(r"(?i)^(https?:)?//", link), (name, link)


def test_a_page_carries_no_external_resource(tmp_path):
    root = _source(tmp_path, [_proc()], forms=["fA.html"])
    built = explore.build(explore.read_source(str(root)), forms_prefix="../frm/")
    for name, body in built.files.items():
        scan = _scan(body)
        assert "img" not in scan.tags and "iframe" not in scan.tags, name
        assert all(not link.lower().endswith((".js", ".css")) for link in scan.links), name


# --------------------------------------------------------------------------- links
def test_internal_links_point_at_files_that_exist(tmp_path):
    root = _source(tmp_path, [_proc()], tables={"tOrder": {"columns": []}},
                   forms=["fA.html", "index.html"])
    out = root / "explore"
    out.mkdir()
    built = explore.build(explore.read_source(str(root)), forms_prefix="../frm/")
    for name, body in built.files.items():
        (out / name).write_text(body, encoding="utf-8")
    for name in built.files:
        for link in _scan((out / name).read_text(encoding="utf-8")).links:
            if re.match(r"(?i)^(https?:|mailto:|#)", link):
                continue
            target = (out / link).resolve()
            assert target.exists(), f"{name} -> {link} is a dead end"


# --------------------------------------------------------------------------- chunking
def test_chunks_respect_the_limit_and_stay_valid_json():
    rows = [{"va": f"{0x400000 + i:X}", "label": "x" * 40} for i in range(400)]
    blocks = explore.chunks(rows, limit=4096)
    assert len(blocks) > 1
    assert all(len(b.encode("utf-8")) <= 4096 for b in blocks)
    assert sum(len(json.loads(b)) for b in blocks) == 400


def test_one_item_larger_than_the_limit_gets_its_own_block():
    rows = [{"va": "1", "label": "s" * 5000}, {"va": "2", "label": "small"}]
    blocks = explore.chunks(rows, limit=1024)
    assert len(blocks) == 2
    assert json.loads(blocks[0])[0]["va"] == "1"


def test_the_summary_quotes_the_real_sizes():
    src = explore.Source(root="x")
    built = explore.build(src, limit=1024)
    line = built.summary(limit=1024)
    assert "pages;" in line and "embedded data blocks" in line
    assert "1024-byte limit" in line


# --------------------------------------------------------------------------- reading
def test_a_missing_stage_is_named_not_fatal(tmp_path):
    root = tmp_path / "empty"
    root.mkdir()
    src = explore.read_source(str(root))
    assert src.procedures == [] and src.missing
    assert any("dossier" in m for m in src.missing)


def test_calls_and_runtime_come_from_the_stage_that_measured_them(tmp_path):
    root = _source(tmp_path, [_proc(va="4013B0")])
    (root / "edges").mkdir()
    (root / "edges" / "edges.jsonl").write_text(json.dumps(
        {"va": "4013B0", "calls_procedures": {"401400": 2}, "calls_imported": {"k!F": 1},
         "calls_late_bound": 3}) + "\n", encoding="utf-8")
    (root / "outline").mkdir()
    (root / "outline" / "outline.jsonl").write_text(json.dumps(
        {"va": "4013B0", "unverified_operations": {"string": 2}, "api_calls": {}}) + "\n",
        encoding="utf-8")
    [row] = explore.procedures_data(explore.read_source(str(root)))
    assert row["calls_in"] == 2 and row["late_bound"] == 3
    assert row["runtime"] == {"string": 2}


def test_a_literal_that_is_sql_text_is_not_offered_as_a_message(tmp_path):
    sql = "SELECT a FROM tOrder"
    src = explore.read_source(str(_source(
        tmp_path, [_proc(sql=[(sql, "CLOSED", ["tOrder"])], literals=[sql, "Kayıt yok"])])))
    [row] = explore.procedures_data(src)
    assert row["messages"] == ["Kayıt yok"]


def test_counts_add_up(tmp_path):
    src = explore.read_source(str(_source(
        tmp_path, [_proc(sql=[("SELECT a FROM t", "CLOSED", ["t"])], literals=["Mesaj var"]),
                   _proc(va="401400")], tables={"t": {"columns": ["a", "b"]}}, forms=["f.html"])))
    counts = src.counts()
    assert counts["procedures"] == 2 and counts["with_sql"] == 1
    assert counts["statements"] == 1 and counts["tables"] == 1 and counts["columns"] == 2
    assert counts["forms"] == 1


# --------------------------------------------------------------------------- wiring
def _run(argv):
    import contextlib
    import io

    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


def test_cli_writes_the_site_and_reports_the_sizes(tmp_path):
    root = _source(tmp_path, [_proc(sql=[("SELECT a FROM tOrder", "CLOSED", ["tOrder"])])],
                   tables={"tOrder": {"columns": ["a"], "readers": ["modA"], "writers": []}},
                   forms=["fA.html"])
    code, _out, err = _run(["explore", str(root), "--out", str(root / "explore")])
    assert code == 0, err
    assert sorted(os.listdir(root / "explore")) == ["forms.html", "index.html",
                                                    "procedures.html", "tables.html"]
    assert "pages; 1 embedded data blocks" in err
    assert "not available" in err          # edges/outline were not in this directory
    assert (root / "explore.manifest.json").exists()


def test_cli_links_to_the_frm_pages_that_the_run_wrote(tmp_path):
    target = synth_vb6.build(tmp_path / "build")
    ws = tmp_path / "ws"
    assert _run(["init", "--dir", str(ws)])[0] == 0
    cfg = ws / "vb6d.toml"
    cfg.write_text(f'target = "{target.exe.as_posix()}"\n'
                   f'listings = "{target.listings.as_posix()}"\n'
                   f'frm_dir = "{target.frms.as_posix()}"\noutput = "out"\n', encoding="utf-8")
    assert _run(["run", "--config", str(cfg)])[0] == 0
    out = ws / "out" / "explore"
    code, _out, err = _run(["explore", str(ws / "out"), "--out", str(out)])
    assert code == 0, err
    links = [l for l in _scan((out / "forms.html").read_text(encoding="utf-8")).links
             if l.startswith("../frm/")]
    assert links, "the forms page must link to the mockups"
    for link in links:
        assert (out / link).resolve().exists(), link


def test_an_empty_directory_is_exit_2_not_an_empty_site(tmp_path):
    root = tmp_path / "empty"
    root.mkdir()
    code, _out, err = _run(["explore", str(root), "--out", str(tmp_path / "site")])
    assert code == 2
    assert "nothing to explore" in err


def test_a_missing_root_is_exit_2(tmp_path):
    code, _out, err = _run(["explore", str(tmp_path / "gone"), "--out", str(tmp_path / "s")])
    assert code == 2 and err.startswith("error: ")


def test_a_partial_statement_is_counted_and_the_lists_are_lower_bounds(tmp_path):
    root = _source(tmp_path, [_proc()], tables={"t": {"columns": ["a"]}},
                   partial=[{"va": "4013B0", "object": "modA", "tables": [],
                             "reason": "verb not modelled: EXEC", "sha256": "0123456789ab"}])
    src = explore.read_source(str(root))
    assert src.counts()["partial"] == 1
    page = explore.render_tables(src)
    assert "1 statements were only partly read" in page
    assert "Statements only partly read (1)" in page
