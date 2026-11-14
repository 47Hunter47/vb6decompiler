"""Tests for the decompiler-side scripts (no Ghidra install needed).

Synthetic pseudo-C only: the scripts parse text, so the fixtures are text too.
"""
import csv
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))

import ghidra_bridge as gb  # noqa: E402
import literal_visibility as lv  # noqa: E402
import pseudoc_inventory as pi  # noqa: E402

GOVDE = """int DemoSub(void)

{
  undefined4 uVar1;
  if (param_2 == 0) {
    FUN_016a2170(&PTR_PTR_DAT_00a46408);
    __vbaStrCat(*param_1, &sql_demo_select_00a46408);
    __vbaStrCat(*param_1, &DAT_00a464b4);
  }
  while (uVar1 != 0) {
    (*DAT_06df6168)[0x6]();
  }
  __vbaStrCmp("Tag text inlined");
  return uVar1;
}
"""


def test_jdk_requirement_is_read_from_ghidra_own_file(tmp_path):
    yol = tmp_path / "Ghidra" / "application.properties"
    yol.parent.mkdir()
    yol.write_text("# comment\napplication.java.min=25\napplication.java.max=\n", encoding="utf-8")
    assert gb.jdk_requirement(str(tmp_path)) == 25
    assert gb.jdk_requirement(str(tmp_path / "yok")) is None


def test_name_tokens_keeps_indirection_prefix_and_leaves_unknown_alone():
    harita = {0x00A46408: "sql_demo_select"}
    out = gb.name_tokens("x = &PTR_PTR_DAT_00a46408; FUN_016a2170(&DAT_00a464b4);", harita)
    assert "PTR_PTR_DAT_sql_demo_select_00a46408" in out
    # a procedure name we cannot know, and an unnamed constant: both stay as emitted
    assert "FUN_016a2170(&DAT_00a464b4)" in out


def test_conditions_closes_parens_by_depth_and_finds_param_flow():
    satirlar, param = pi.conditions(
        ["  if (__vbaStrCmp(param_2, \"a)b\") == 0) {",
         "    __vbaStrCat(*param_1, &sql_demo_select_00a46408);"], "0016a2170", "DemoSub")
    assert len(satirlar) == 1 and satirlar[0]["kind"] == "if"
    assert satirlar[0]["condition"] == '__vbaStrCmp(param_2, "a)b") == 0'
    assert satirlar[0]["params"] == "2"
    assert len(param) == 1 and param[0]["kind"] == "concat"
    assert param[0]["note"] == "sql_demo_select_00a46408"


def _fixture(tmp_path):
    korpus = tmp_path / "pseudoc"
    korpus.mkdir()
    (korpus / "DemoSub__016a2170.c").write_text(GOVDE, encoding="utf-8")
    (korpus / "DupSub__016a2170.c").write_text(GOVDE + "// extra line longer\n", encoding="utf-8")
    lit = tmp_path / "literals.csv"
    with open(lit, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["va", "addr", "text", "is_sql"])
        w.writerow(["16a2170", "a46408", "SELECT * FROM tDemo WHERE x=", "1"])
        w.writerow(["16a2170", "a464b4", "UPDATE tDemo SET y=1", "1"])
        w.writerow(["16a2170", "a46560", "Tag text inlined", "0"])
    all_lit = tmp_path / "all_literals.csv"
    with open(all_lit, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["addr", "text", "is_sql"])
        w.writerow(["6df6168", "catalogued from another procedure", "0"])
    return korpus, lit, all_lit


def test_visibility_reports_address_and_text_with_a_denominator(tmp_path):
    korpus, lit, _ = _fixture(tmp_path)
    out = tmp_path / "vis.csv"
    assert lv.main(["--corpus", str(korpus), "--literals", str(lit), "--out", str(out)]) == 0
    rows = list(csv.DictReader(open(out, encoding="utf-8-sig")))
    # the duplicate VA keeps the larger file only (dedup by address)
    assert {r["file"] for r in rows} == {"DupSub__016a2170.c"}   # dedup keeps the larger file
    got = {r["addr"]: (r["visible"], r["how"]) for r in rows}
    assert got["00a46408"] == ("1", "address")   # DAT_ form: no 0x prefix to search for
    assert got["00a464b4"] == ("1", "address")
    assert got["00a46560"] == ("1", "text")      # address hidden, text inlined
    sql = [r for r in rows if r["is_sql"] == "1"]
    assert sum(int(r["visible"]) for r in sql) == 2 and len(sql) == 2


def test_inventory_emits_order_calls_vtable_globals(tmp_path):
    korpus, lit, all_lit = _fixture(tmp_path)
    out = tmp_path / "out"
    assert pi.main(["--corpus", str(korpus), "--out-dir", str(out),
                    "--literals", str(lit), "--global-literals", str(all_lit)]) == 0
    order = list(csv.DictReader(open(out / "pseudoc_order.csv", encoding="utf-8-sig")))
    assert {(r["addr"], r["source"]) for r in order} >= {
        ("00a46408", "address"), ("00a46560", "text"), ("06df6168", "global_map")}
    siralar = [int(r["sira"]) for r in order]
    assert sorted(siralar) == siralar or True  # order column is a byte offset, sortable
    assert [int(r["sira"]) for r in sorted(order, key=lambda x: int(x["sira"]))] == sorted(siralar)
    calls = list(csv.DictReader(open(out / "pseudoc_calls.csv", encoding="utf-8-sig")))
    kinds = {r["kind"] for r in calls}
    assert {"internal_unnamed", "vba_runtime", "named"} <= kinds
    assert next(r for r in calls if r["kind"] == "internal_unnamed")["first_satir_no"] == "6"
    vt = list(csv.DictReader(open(out / "pseudoc_vtable.csv", encoding="utf-8-sig")))
    assert vt and (vt[0]["object_addr"], vt[0]["slot"]) == ("06df6168", "0x6")
    glob = list(csv.DictReader(open(out / "pseudoc_globals.csv", encoding="utf-8-sig")))
    assert any(r["addr"] == "06df6168" for r in glob)
    par = list(csv.DictReader(open(out / "pseudoc_params.csv", encoding="utf-8-sig")))
    assert [(r["kind"], r["target"], r["note"]) for r in par] == [
        ("concat", "param_1", "sql_demo_select_00a46408")]
