"""The HTML view: what it draws, and what it refuses to imply.

Two properties are load-bearing. First, a recovered form must be safe to open from
``file://`` on a machine that has never seen this tool — no script, no remote
resource, nothing that runs. Second, the page must not read as a pixel-exact
rendering: the twips→pixel factor is an assumption, so it is printed and it is
overridable, and every page names where its geometry came from.

The escaping tests use hostile text because a caption is untrusted: it comes out of
a binary that may have been built by anyone.
"""

from __future__ import annotations

import html.parser
import json
import re

import pytest
import synth_vb6

from vb6decompiler import cli, htmlview

HOSTILE = "<script>alert('x')</script>\" onload=\"evil()"
NON_ASCII = "Kayıt bulunamadı — şğİı"
CSP = "Content-Security-Policy"


class _Scan(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags: list[str] = []
        self.links: list[str] = []
        self.attributes: list[str] = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag.lower())
        for key, value in attrs:
            self.attributes.append(key.lower())
            if key.lower() in ("href", "src", "action"):
                self.links.append(value or "")


def _scan(text: str) -> _Scan:
    parser = _Scan()
    parser.feed(text)
    return parser


def _box(name="txtAd", type="VB.TextBox", **kw):
    return htmlview.Box(name=name, type=type, **kw)


# --------------------------------------------------------------------------- escaping
def test_a_hostile_caption_cannot_open_a_tag_or_an_attribute():
    page = htmlview.render_form(htmlview.FormView(
        name="fTest", source=".frm design text", width=6000, height=3000,
        boxes=[_box(caption=HOSTILE, left=0, top=0, width=100, height=100)]))
    scan = _scan(page)
    assert "script" not in scan.tags
    # The words may survive as escaped TEXT; what must never happen is that they
    # become an attribute the browser would act on.
    assert not [a for a in scan.attributes if a.startswith("on")]


def test_a_hostile_form_name_cannot_open_a_tag():
    page = htmlview.render_form(htmlview.FormView(
        name=HOSTILE, source=".frm design text", width=100, height=100, boxes=[]))
    assert "script" not in _scan(page).tags


def test_non_ascii_text_survives_readable():
    page = htmlview.render_form(htmlview.FormView(
        name="fTest", source=".frm design text", width=100, height=100,
        boxes=[_box(type="VB.Label", caption=NON_ASCII, left=0, top=0, width=100, height=20)]))
    assert NON_ASCII in page


def test_a_control_character_is_escaped_not_emitted():
    page = htmlview.render_form(htmlview.FormView(
        name="fTest", source=".frm design text", width=100, height=100,
        boxes=[_box(caption="a\x00b\u2028c", left=0, top=0, width=10, height=10)]))
    assert "\x00" not in page and "\u2028" not in page
    assert "\\u0000" in page


# --------------------------------------------------------------------------- safety
def test_no_page_carries_a_script_or_a_remote_resource():
    views = [htmlview.FormView(name="fA", source=".frm design text", width=6000, height=3000,
                               boxes=[_box(left=0, top=0, width=100, height=100)]),
             htmlview.FormView(name="fB", source="binary form blob", width=3000, height=2000,
                               boxes=[])]
    pages = [htmlview.render_form(v) for v in views]
    pages.append(htmlview.render_index(views, links={"fA": "fA.html", "fB": "fB.html"}))
    for page in pages:
        scan = _scan(page)
        assert "script" not in scan.tags
        assert CSP in page
        for link in scan.links:
            assert not re.match(r"(?i)^(https?:)?//", link), link


def test_the_policy_forbids_every_loading_context():
    for directive in ("default-src 'none'", "script-src 'none'", "connect-src 'none'",
                      "img-src 'none'"):
        assert directive in htmlview.CSP


# --------------------------------------------------------------------------- honesty
def test_every_page_states_the_scale_and_that_it_is_assumed():
    page = htmlview.render_form(htmlview.FormView(name="fA", source=".frm design text",
                                                 width=150, height=150, boxes=[]))
    assert "15 twips per pixel" in page
    assert "assumed" in page


def test_the_scale_is_overridable_and_then_printed_as_given():
    page = htmlview.render_form(
        htmlview.FormView(name="fA", source=".frm design text", width=300, height=300,
                          boxes=[_box(left=30, top=30, width=60, height=60)]), scale=30)
    assert "30 twips per pixel" in page
    assert "left:1.0px" in page          # 30 twips / 30 = 1 px


def test_every_page_names_its_geometry_source():
    a = htmlview.render_form(htmlview.FormView(name="fA", source=".frm design text",
                                               width=100, height=100, boxes=[]))
    b = htmlview.render_form(htmlview.FormView(name="fB", source="binary form blob",
                                               width=100, height=100, boxes=[]))
    assert ".frm design text" in a and "binary form blob" in b


def test_a_form_that_was_not_crosschecked_says_so():
    page = htmlview.render_form(htmlview.FormView(name="fA", source=".frm design text",
                                                  width=100, height=100, boxes=[]))
    assert "nothing cross-checked it" in page


def test_the_summary_counts_every_control_with_its_denominator():
    views = [htmlview.FormView(name="fA", source=".frm design text", boxes=[
        _box(type="VB.TextBox", left=0, top=0, width=10, height=10),
        _box(type="MSComctlLib.SSTab", left=0, top=0, width=10, height=10),
        _box(type="VB.Label"),                                     # no rectangle
    ])]
    line = htmlview.summary(views)
    assert "drawn as a known type: 1 of 3" in line
    assert "placeholders: 1" in line
    assert "no rectangle: 1" in line


def test_an_unknown_control_type_is_a_placeholder_that_names_its_type():
    page = htmlview.render_form(htmlview.FormView(
        name="fA", source=".frm design text", width=100, height=100,
        boxes=[_box(name="tab1", type="MSComctlLib.SSTab", left=0, top=0, width=10, height=10)]))
    assert "placeholder" in page
    assert "MSComctlLib.SSTab" in page


def test_a_control_with_no_rectangle_is_listed_not_placed():
    page = htmlview.render_form(htmlview.FormView(
        name="fA", source=".frm design text", width=100, height=100,
        boxes=[_box(name="lblGhost", type="VB.Label")]))
    assert "Controls with no recovered rectangle" in page
    assert "lblGhost" in page
    # Not placed: no absolutely positioned box was emitted for it.
    assert "left:0.0px" not in page


def test_a_hidden_control_is_dimmed_not_dropped():
    page = htmlview.render_form(htmlview.FormView(
        name="fA", source=".frm design text", width=100, height=100,
        boxes=[_box(name="txtHidden", left=0, top=0, width=10, height=10, visible=False)]))
    assert "opacity:.45" in page and "txtHidden" in page


# --------------------------------------------------------------------------- end to end
@pytest.fixture()
def target(tmp_path):
    return synth_vb6.build(tmp_path)


def test_cli_writes_one_page_per_form_plus_an_index_and_a_manifest(target, capsys):
    out = target.root / "html"
    capsys.readouterr()
    code = cli.main(["frm", str(target.frms), "--format", "html", "--out", str(out),
                     "--exe", str(target.exe)])
    assert code == 0
    assert sorted(p.name for p in out.iterdir()) == ["fSynth01.html", "index.html"]
    _, err = capsys.readouterr()
    assert "controls drawn as a known type: 3 of 3" in err
    assert "15 twips/px" in err
    body = json.loads((target.root / "html.manifest.json").read_text(encoding="utf-8"))
    assert body["command"] == "frm --format html"
    assert body["records"]["forms"] == 1


def test_the_generated_form_page_cross_checks_against_the_blob(target, capsys):
    out = target.root / "html"
    capsys.readouterr()
    assert cli.main(["frm", str(target.frms), "--format", "html", "--out", str(out),
                     "--exe", str(target.exe)]) == 0
    page = (out / "fSynth01.html").read_text(encoding="utf-8")
    # The synthetic blob carries the same three controls and the same rectangles.
    assert "3 of 3 controls agree with the binary form blob" in page
    assert page.count("position:absolute") or "left:8.0px" in page   # 120 twips / 15


def test_html_without_out_is_exit_2(target, capsys):
    capsys.readouterr()
    code = cli.main(["frm", str(target.frms), "--format", "html"])
    assert code == 2
    assert "--format html needs --out" in capsys.readouterr()[1]


def test_a_negative_scale_is_exit_2(target, tmp_path, capsys):
    capsys.readouterr()
    code = cli.main(["frm", str(target.frms), "--format", "html", "--out",
                     str(tmp_path / "o"), "--scale", "0"])
    assert code == 2
    assert "positive" in capsys.readouterr()[1]


def test_the_existing_modes_are_untouched(target, capsys):
    """The HTML mode was added, not swapped in: text and --json must not change."""
    capsys.readouterr()
    assert cli.main(["frm", str(target.frms)]) == 0
    text, _ = capsys.readouterr()
    assert text.startswith("fSynth01\t(6000, 3000)\tcontrols=3")

    assert cli.main(["frm", str(target.frms), "--json"]) == 0
    payload = json.loads(capsys.readouterr()[0])
    assert sorted(payload) == ["failures", "files_seen", "forms", "no_design_block"]
    assert payload["forms"][0]["controls"] == 3


def test_the_html_file_name_goes_through_the_safe_helper(tmp_path):
    """Defence in depth: frm's own parser only accepts identifier-shaped names and blob
    names are matched by a name pattern too — but the writer must not depend on that,
    because turning a name into a path is the writer's rule, not the parser's."""
    from vb6decompiler import spec

    taken: set[str] = {"index.html"}
    name, why = spec.safe_file_name("../../CON", taken, "0", suffix=".html")
    assert "/" not in name and "\\" not in name
    assert name.endswith(".html") and name.lower() != "con.html"
    assert (tmp_path / name).resolve().parent == tmp_path.resolve()
    assert why


def test_a_form_whose_name_does_not_parse_is_named_as_nothing_to_draw(tmp_path, capsys):
    frms = tmp_path / "hostile"
    frms.mkdir()
    (frms / "a.frm").write_text(
        'VERSION 5.00\nBegin VB.Form ../../CON\n   Caption  =   "x"\n'
        "   ClientHeight    =   600\n   ClientWidth     =   600\nEnd\n", encoding="cp1254")
    capsys.readouterr()
    code = cli.main(["frm", str(frms), "--format", "html", "--out", str(tmp_path / "pages")])
    assert code == 2
    assert "no form to draw" in capsys.readouterr()[1]


def test_html_without_exe_still_works(tmp_path, capsys):
    """Measured crash: --exe is optional, but a None in the consumed-input list reached
    os.path and came back as exit 3 (a toolkit bug) instead of drawing the page."""
    target = synth_vb6.build(tmp_path)
    out = tmp_path / "html"
    capsys.readouterr()
    code = cli.main(["frm", str(target.frms), "--format", "html", "--out", str(out)])
    assert code == 0
    assert (out / "fSynth01.html").exists()
    page = (out / "fSynth01.html").read_text(encoding="utf-8")
    assert "no binary form blob for this form was supplied" in page
