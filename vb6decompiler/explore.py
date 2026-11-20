"""An offline explorer over a ``vb6d run`` output directory.

The recovered material is a directory of row files, which is fine for a script and
useless for a person. This builds a static site over it: an index, one page per
subject (procedures, tables, forms) and a search box that works with no server, no
network and no library.

Three constraints decide the design, and each one is a claim the tests hold:

* **It must work from ``file://``.** So: no ``fetch``, no external resource, and the
  data is embedded in the page itself. A CSP with a per-file nonce allows exactly the
  one script that page carries and nothing else.
* **Untrusted text may not become markup.** Everything from the build — object names,
  captions, SQL, messages — is escaped twice: ``<`` in the embedded JSON is written as
  ``\\u003c`` so it cannot end the ``<script>`` block, and the JavaScript writes through
  ``textContent`` so a string can never be parsed as HTML.
* **A big build must stay usable.** Embedded data is split into blocks of at most
  ``CHUNK_BYTES``; the page reports how many blocks it carries and the largest one.

What it does *not* embed: the 441k literals of a real build. Search covers the
procedure labels, the closed SQL text, the message-like literals and the table and
column names — the things a person searches for — and the page says so.
"""

from __future__ import annotations

import json
import os
import re
import secrets
from dataclasses import dataclass, field

from . import htmlview

#: Largest embedded data block. A page may carry several; this is the unit the report
#: quotes, and the number a reader checks when a page feels slow.
CHUNK_BYTES = 2 * 1024 * 1024
#: Nothing here may load anything: no image, no font, no connection, no frame.
CSP_TEMPLATE = ("default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-{nonce}'; "
                "img-src 'none'; font-src 'none'; connect-src 'none'; frame-src 'none'; "
                "base-uri 'none'; form-action 'none'")

#: A literal that reads like something a user sees (the same rule the spec stage uses).
_MESSAGE_HINT = re.compile(r"[A-Za-zÇĞİÖŞÜçğıöşü]{3,}[\s.!?:]")


@dataclass
class Source:
    """What the explorer found in the output directory."""

    root: str
    procedures: list[dict] = field(default_factory=list)
    tables: dict = field(default_factory=dict)
    crud: list[dict] = field(default_factory=list)
    unparsed: list[dict] = field(default_factory=list)
    edges: dict[str, dict] = field(default_factory=dict)
    outline: dict[str, dict] = field(default_factory=dict)
    forms: list[str] = field(default_factory=list)
    read: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)

    def counts(self) -> dict:
        return {
            "procedures": len(self.procedures),
            "with_sql": sum(1 for p in self.procedures if p["sql"]),
            "statements": sum(len(p["sql"]) for p in self.procedures),
            "tables": len(self.tables),
            "columns": sum(len(t.get("columns") or []) for t in self.tables.values()),
            "crud_rows": len(self.crud),
            "forms": len(self.forms),
            "unparsed": len(self.unparsed),
        }


# ---------------------------------------------------------------------------
# Reading the run's artefacts
# ---------------------------------------------------------------------------
def _jsonl(path: str) -> list[dict]:
    out = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                out.append(row)
    return out


def _messages(literals: list[dict], sql_texts: set[str]) -> list[str]:
    """Texts a person would search for; a SQL fragment is not one of them."""
    out = []
    for literal in literals:
        text = literal.get("text")
        if not isinstance(text, str) or text in sql_texts:
            continue
        if _MESSAGE_HINT.search(text):
            out.append(text)
    return out


def read_source(root: str) -> Source:
    """Read whatever a run left behind. A missing stage is named, never fatal."""
    src = Source(root=os.path.abspath(root))

    dossier = os.path.join(root, "dossier", "dossier.jsonl")
    if os.path.isfile(dossier):
        src.read.append("dossier")
        for record in _jsonl(dossier):
            sql_rows = [row for row in (record.get("sql") or []) if isinstance(row, dict)]
            texts = {str(row["text"]) for row in sql_rows if isinstance(row.get("text"), str)}
            va = str(record.get("va") or "")
            src.procedures.append({
                "va": va,
                "object": str(record.get("object_name") or ""),
                "names": [str(n) for n in (record.get("name_hint") or {}).get("names") or []],
                "sql": [{"status": str(row.get("status") or ""),
                         "closed": bool(row.get("closed")),
                         "tables": [str(t) for t in row.get("tables") or []],
                         "text": str(row.get("text") or "")} for row in sql_rows],
                "messages": _messages(list(record.get("literals") or []), texts),
                "literals": len(record.get("literals") or []),
            })
    else:
        src.missing.append("dossier (no dossier/dossier.jsonl)")

    schema = os.path.join(root, "schema", "schema.json")
    if os.path.isfile(schema):
        src.read.append("schema")
        with open(schema, encoding="utf-8") as fh:
            body = json.load(fh)
        if isinstance(body, dict):
            src.tables = {str(k): v for k, v in (body.get("tables") or {}).items()
                          if isinstance(v, dict)}
            src.crud = [row for row in body.get("crud") or [] if isinstance(row, dict)]
            src.unparsed = [row for row in body.get("unparsed") or [] if isinstance(row, dict)]
    else:
        src.missing.append("schema (no schema/schema.json)")

    for name, folder, file in (("edges", "edges", "edges.jsonl"),
                               ("outline", "outline", "outline.jsonl")):
        path = os.path.join(root, folder, file)
        if os.path.isfile(path):
            src.read.append(name)
            for row in _jsonl(path):
                va = str(row.get("va") or "").upper()
                if va:
                    (src.edges if name == "edges" else src.outline)[va] = row
        else:
            src.missing.append(f"{name} (no {folder}/{file})")

    forms_dir = os.path.join(root, "frm")
    if os.path.isdir(forms_dir):
        src.read.append("frm")
        src.forms = sorted(p for p in os.listdir(forms_dir) if p.lower().endswith(".html"))
    else:
        src.missing.append("frm (no frm/ directory of mockups; run 'vb6d run' or "
                           "'vb6d frm --format html')")
    return src


# ---------------------------------------------------------------------------
# Embedding data safely
# ---------------------------------------------------------------------------
def embed(body) -> str:
    """JSON as HTML-safe text.

    ``json.dumps`` alone is not enough: a string containing ``</script>`` would end the
    block it sits in and everything after it becomes markup. Escaping the three
    characters that matter keeps the JSON valid (they are valid escapes) and the block
    unbreakable.
    """
    raw = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    return raw.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def chunks(items: list, limit: int = CHUNK_BYTES) -> list[str]:
    """Split a list into JSON blocks of at most ``limit`` bytes each."""
    out: list[str] = []
    current: list = []
    size = 2                                     # "[]"
    for item in items:
        piece = len(embed(item).encode("utf-8")) + 1
        if current and size + piece > limit:
            out.append(embed(current))
            current, size = [], 2
        current.append(item)
        size += piece
        if size >= limit:                        # one item larger than the limit
            out.append(embed(current))
            current, size = [], 2
    if current:
        out.append(embed(current))
    return out or ["[]"]


def _page(title: str, nonce: str, body: str, *, script: str = "", style: str = "") -> str:
    return "\n".join([
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        f'<meta http-equiv="Content-Security-Policy" content="{CSP_TEMPLATE.format(nonce=nonce)}">',
        f"<title>{htmlview.esc(title)}</title>",
        f"<style>{BASE_CSS}{style}</style>",
        "</head><body>",
        body,
        f'<script nonce="{nonce}">{script}</script>' if script else "",
        "</body></html>",
    ]) + "\n"


BASE_CSS = (
    "body{font:14px system-ui,sans-serif;margin:0;color:#111;background:#f6f6f7}"
    "nav{background:#1f2937;color:#fff;padding:8px 16px;font-size:13px}"
    "nav a{color:#cfe3ff;margin-right:14px;text-decoration:none}"
    "main{padding:16px 20px;max-width:1200px}"
    "h1{font-size:20px;margin:0 0 8px}h2{font-size:16px;margin:20px 0 6px}"
    "table{border-collapse:collapse;font-size:13px;background:#fff}"
    "td,th{border:1px solid #d6d6d6;padding:4px 8px;text-align:left;vertical-align:top}"
    "code{background:#eef;padding:0 3px;border-radius:3px;font-size:12px}"
    "input[type=search]{font:inherit;padding:6px 8px;width:min(520px,90%);border:1px solid #bbb}"
    ".muted{color:#666}.count{font-weight:600}"
    ".bad{color:#a11}.ok{color:#171}"
)


def _nav() -> str:
    return ('<nav><strong>vb6d explorer</strong> '
            '<a href="index.html">Overview</a><a href="procedures.html">Procedures</a>'
            '<a href="tables.html">Tables</a><a href="forms.html">Forms</a></nav>')


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
def render_index(src: Source) -> str:
    counts = src.counts()
    rows = "".join(
        f"<tr><th>{htmlview.esc(k)}</th><td class='count'>{v}</td></tr>"
        for k, v in counts.items())
    missing = "".join(f"<li>{htmlview.esc(m)}</li>" for m in src.missing)
    read = ", ".join(src.read) or "nothing"
    body = (_nav() + "<main><h1>Recovered program</h1>"
            f"<p class='muted'>Built from <code>{htmlview.esc(os.path.basename(src.root))}</code>; "
            f"stages read: {htmlview.esc(read)}.</p>"
            f"<table>{rows}</table>"
            + (f"<h2>Not available</h2><ul>{missing}</ul>" if missing else "")
            + "<h2>What this site is</h2>"
            "<p class='muted'>A static view of what the stages recovered: forms as "
            "mockups (a visual aid, not an equivalent UI), procedures with their SQL and "
            "messages, and the tables those statements name. Nothing here loads a script "
            "or a resource from anywhere but this page; search runs in the browser over "
            "the data embedded in each page. Closed SQL is a lower bound, and every "
            "count is the number a stage wrote, not an estimate.</p></main>")
    return _page("Recovered program", secrets.token_urlsafe(16), body)


def procedures_data(src: Source) -> list[dict]:
    """The searchable rows: label, VA, SQL, messages, tables, calls, runtime."""
    rows = []
    for proc in sorted(src.procedures, key=lambda p: (p["object"].lower(), p["va"])):
        va = proc["va"].upper()
        edge = src.edges.get(va) or {}
        outline = src.outline.get(va) or {}
        rows.append({
            "va": proc["va"],
            "label": (f"{proc['object']}.{proc['names'][0]}" if proc["names"]
                      else (proc["object"] or proc["va"])),
            "object": proc["object"],
            "sql": proc["sql"],
            "messages": proc["messages"],
            "literals": proc["literals"],
            # A call only counts where the evidence named a target: these are the
            # counts the edges stage wrote, not a guess about what it did not see.
            "calls_in": len(edge.get("calls_procedures") or {}) + len(edge.get("calls_imported") or {}),
            "late_bound": int(edge.get("calls_late_bound") or 0),
            "runtime": dict(outline.get("unverified_operations") or {}),
        })
    return rows


PROC_SCRIPT = """
const CHUNKS = [...document.querySelectorAll('script[type="application/json"]')]
  .map(s => JSON.parse(s.textContent));
const ROWS = CHUNKS.flat();
const q = document.getElementById('q');
const out = document.getElementById('out');
const stat = document.getElementById('stat');
function text(r) {
  return [r.label, r.va, r.object].concat(
    r.sql.map(s => s.text), r.messages, r.sql.flatMap(s => s.tables),
    Object.keys(r.runtime)).join(' ').toLowerCase();
}
const INDEX = ROWS.map(text);
function cell(tag, value, cls) {
  const el = document.createElement(tag);
  if (cls) el.className = cls;
  el.textContent = value == null ? '' : String(value);
  return el;
}
function render(hits) {
  out.replaceChildren();
  for (const r of hits) {
    const row = document.createElement('tr');
    row.append(cell('td', r.va), cell('td', r.label),
      cell('td', r.sql.length ? r.sql.filter(s => s.closed).length + '/' + r.sql.length : '-'),
      cell('td', new Set(r.sql.flatMap(s => s.tables)).size || '-'),
      cell('td', r.literals), cell('td', r.calls_in), cell('td', r.late_bound),
      cell('td', Object.keys(r.runtime).join(', '), 'muted'));
    out.append(row);
  }
  stat.textContent = hits.length + ' of ' + ROWS.length + ' procedures';
}
function search() {
  const needle = q.value.trim().toLowerCase();
  if (!needle) return render(ROWS);
  const words = needle.split(/\\s+/);
  const hits = [];
  for (let i = 0; i < ROWS.length; i++) {
    const hay = INDEX[i];
    let ok = true;
    for (const w of words) { if (!hay.includes(w)) { ok = false; break; } }
    if (ok) hits.push(ROWS[i]);
  }
  render(hits);
}
q.addEventListener('input', search);
render(ROWS);
"""


def render_procedures(src: Source, blocks: list[str]) -> str:
    nonce = secrets.token_urlsafe(16)
    data = "\n".join(
        f'<script type="application/json" nonce="{nonce}">{block}</script>' for block in blocks)
    body = (_nav() + "<main><h1>Procedures</h1>"
            "<p class='muted'>Every procedure the dossier recorded. Search covers the "
            "label, the VA, the closed SQL text, the message-like literals, the table "
            "names and the runtime categories; the full literal list stays in "
            "<code>dossier.jsonl</code>.</p>"
            "<p><input id=\"q\" type=\"search\" placeholder=\"search procedures, SQL, messages, tables\"> "
            "<span id=\"stat\" class=\"muted\"></span></p>"
            "<table><thead><tr><th>VA</th><th>Procedure</th><th>SQL closed/total</th>"
            "<th>Tables</th><th>Literals</th><th>Named calls</th><th>Late-bound</th>"
            "<th>Runtime categories (unverified)</th></tr></thead><tbody id=\"out\"></tbody></table>"
            "</main>")
    return _page("Procedures", nonce, data + body, script=PROC_SCRIPT)


def render_tables(src: Source) -> str:
    if not src.tables:
        body = (_nav() + "<main><h1>Tables</h1><p class='muted'>No schema in this output "
                "directory: run <code>vb6d schema</code> (or <code>vb6d run</code>) first.</p>"
                "</main>")
        return _page("Tables", secrets.token_urlsafe(16), body)
    rows = "".join(
        "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            htmlview.esc(name),
            htmlview.esc(", ".join(info.get("columns") or []) or "-"),
            len(info.get("readers") or []), len(info.get("writers") or []))
        for name, info in sorted(src.tables.items()))
    crud = "".join(
        "<tr><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"
        .format(htmlview.esc(str(row.get("object") or "-")), htmlview.esc(str(row.get("table"))),
                row.get("C", 0), row.get("R", 0), row.get("U", 0), row.get("D", 0))
        for row in sorted(src.crud, key=lambda r: (str(r.get("object")), str(r.get("table")))))
    unparsed = "".join(
        f"<li><code>{htmlview.esc(str(row.get('va')))}</code> "
        f"{htmlview.esc(str(row.get('object') or '-'))} — {htmlview.esc(str(row.get('reason')))}"
        f" <span class='muted'>sha256:{htmlview.esc(str(row.get('sha256')))}</span></li>"
        for row in src.unparsed)
    body = (_nav() + "<main><h1>Tables</h1>"
            "<p class='muted'>Tables and columns the closed SQL names. A column appears "
            "under a table only when the statement said which table it belongs to: with "
            "two tables in one statement an unqualified column stays unattributed.</p>"
            "<table><thead><tr><th>Table</th><th>Columns seen</th><th>Readers</th>"
            f"<th>Writers</th></tr></thead><tbody>{rows}</tbody></table>"
            f"<h2>CRUD by object</h2><table><thead><tr><th>Object</th><th>Table</th>"
            f"<th>C</th><th>R</th><th>U</th><th>D</th></tr></thead><tbody>{crud}</tbody></table>"
            + (f"<h2>Statements that could not be parsed ({len(src.unparsed)})</h2>"
               f"<ul>{unparsed}</ul>" if unparsed else "")
            + "</main>")
    return _page("Tables", secrets.token_urlsafe(16), body)


def render_forms(src: Source, prefix: str = "frm/") -> str:
    if not src.forms:
        body = (_nav() + "<main><h1>Forms</h1><p class='muted'>No form mockups in this "
                "output directory: run <code>vb6d frm --format html</code> (or "
                "<code>vb6d run</code>, which does it for you).</p></main>")
        return _page("Forms", secrets.token_urlsafe(16), body)
    items = "".join(
        f'<li><a href="{htmlview.esc(prefix)}{htmlview.esc(name)}">'
        f"{htmlview.esc(name[:-5])}</a></li>"
        for name in src.forms if name.lower() != "index.html")
    body = (_nav() + "<main><h1>Forms</h1>"
            "<p class='muted'>Each page is the static mockup the <code>frm</code> stage "
            "wrote: boxes at the recovered geometry, with the twips-to-pixel factor it "
            "assumed printed on the page.</p>"
            f"<ul>{items}</ul>"
            f'<p class="muted"><a href="{htmlview.esc(prefix)}index.html">All forms in one '
            f"table</a></p></main>")
    return _page("Forms", secrets.token_urlsafe(16), body)


# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------
@dataclass
class Built:
    files: dict[str, str] = field(default_factory=dict)
    blocks: list[int] = field(default_factory=list)

    def summary(self, limit: int = CHUNK_BYTES) -> str:
        largest = max(self.blocks) if self.blocks else 0
        return (f"# {len(self.files)} pages; {len(self.blocks)} embedded data blocks, "
                f"largest {largest} bytes of a {limit}-byte limit")


def build(src: Source, *, limit: int = CHUNK_BYTES, forms_prefix: str = "frm/") -> Built:
    rows = procedures_data(src)
    blocks = chunks(rows, limit=limit)
    built = Built()
    built.blocks = [len(b.encode("utf-8")) for b in blocks]
    built.files["index.html"] = render_index(src)
    built.files["procedures.html"] = render_procedures(src, blocks)
    built.files["tables.html"] = render_tables(src)
    built.files["forms.html"] = render_forms(src, forms_prefix)
    return built
