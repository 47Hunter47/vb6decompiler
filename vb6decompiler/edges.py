"""Program-level call edges: one pass over the dossier's ranges, aggregated.

Claims stay the range kind documented for decode — "calls seen in this
procedure's range", never "this procedure calls": a range can hold a helper
that has no listing entry of its own. One procedure per row even when it
makes no decodable call, because absence is a result the agent must be able
to see. Import-slot hits carry ``dll!name``; targets that are themselves
``jmp [import slot]`` thunks carry the slot's name two hops away; in-image
hits carry the dossier procedure whose range holds them; late-bound
``[reg+disp]`` calls are counted as late-bound and nothing else, because
nothing here can name them.
"""
from __future__ import annotations

import bisect
import json

from . import blob, pe, x86

# the last range in the file has no next VA to stop it: read up to this many
# bytes and mark the row capped; upgrade needs an image-end rule
LAST_RANGE_CAP = 0x10000


def collect(exe: str, dossier_path: str) -> tuple[list[dict], int, dict]:
    """Return (rows, unreadable_line_count, totals) for one dossier file."""
    procs: list[tuple[int, object, list]] = []
    bad = 0
    with open(dossier_path, encoding="utf-8") as fh:
        for line in fh:
            try:
                d = json.loads(line)
                va = int(d["va"], 16)
            except (ValueError, KeyError, TypeError):
                bad += 1  # same policy as the dossier builder: count, skip, go on
                continue
            procs.append((va, d.get("object_name"), (d.get("name_hint") or {}).get("names", [])))
    procs.sort(key=lambda p: p[0])
    vas = [p[0] for p in procs]

    data, sections = blob.load_sections(exe)
    imports = pe.import_names(pe.read(exe))
    # the object table names whole objects, and its function entries are plain
    # VAs - exact hits below the listed population can be attributed to their
    # object even though native entry names are junk (never quoted here).
    # A non-VB6 exe has no such table: edges still work, without the naming.
    objfunc: dict[int, str] = {}
    try:
        from . import procs as _procs

        proj = _procs.read(exe)
        for o, m in proj.methods_by_address():
            objfunc.setdefault(m.address, o.name)
    except Exception:
        objfunc = {}
    # native builds keep Method.address=None (measured and documented in
    # procs.py), so on a compiled exe objfunc stays empty - by design, not
    # by omission; builds that DO expose entry addresses get the naming.

    def window_for(va: int, end_va: int) -> bytes:
        for sec in sections:
            if sec.virtual_address <= va < sec.virtual_address + sec.span:
                delta = va - sec.virtual_address
                if delta >= sec.raw_size:
                    return b""
                take = min(sec.raw_size - delta, end_va - va)
                return data[sec.raw_pointer + delta: sec.raw_pointer + delta + take]
        return b""

    thunk_cache: dict[int, "str | None"] = {}

    def thunk_name(t: int):
        # two-hop: many call targets below the listed population are `jmp
        # [import slot]` thunks the compiler emitted outside every listing -
        # resolve the slot and the thunk gets the import's name
        if t not in thunk_cache:
            nm = None
            probe = x86.decode(window_for(t, t + 12), t, limit=1)
            if probe["rows"] and probe["rows"][0]["mnemonic"] == "jmp":
                t2 = x86.call_target(probe["rows"][0]["operands"])
                if t2 is not None:
                    nm = imports.get(t2)
            thunk_cache[t] = nm
        return thunk_cache[t]

    rows: list[dict] = []
    totals = {"calls": 0, "named": 0, "thunk_named": 0, "late_bound": 0, "edges": 0,
              "uncensus": 0, "obj_named": 0}
    for i, (va, obj, names) in enumerate(procs):
        capped = False
        if i + 1 < len(vas):
            end_va = vas[i + 1]
        else:
            end_va, capped = va + LAST_RANGE_CAP, True
        result = x86.decode(window_for(va, end_va), va, limit=10**9)
        imported: dict[str, int] = {}
        edges: dict[str, int] = {}
        thunks: dict[str, int] = {}
        other: dict[str, int] = {}
        objects: dict[str, int] = {}
        late = 0
        for row in result["rows"]:
            if not row["mnemonic"].startswith("call"):
                continue
            totals["calls"] += 1
            t = x86.call_target(row["operands"])
            if t is None:
                late += 1
                totals["late_bound"] += 1
                continue
            name = imports.get(t)
            if name:
                imported[name] = imported.get(name, 0) + 1
                totals["named"] += 1
                continue
            j = bisect.bisect_right(vas, t) - 1
            if j >= 0:
                key = f"{vas[j]:X}"
                edges[key] = edges.get(key, 0) + 1
                totals["edges"] += 1
            else:
                # below the listed population: a `jmp [import slot]` thunk is
                # identity, a bare count is not - try the two named hops first
                tn = thunk_name(t)
                if tn:
                    thunks[tn] = thunks.get(tn, 0) + 1
                    totals["thunk_named"] += 1
                else:
                    oname = objfunc.get(t)
                    if oname:
                        objects[oname] = objects.get(oname, 0) + 1
                        totals["obj_named"] += 1
                    else:
                        key = f"{t:X}"
                        other[key] = other.get(key, 0) + 1
                        totals["uncensus"] += 1
        r: dict = {"va": f"{va:X}", "object_name": obj, "names": names,
                   "ended": result["ended"], "instructions": result["instructions"],
                   "calls_imported": imported, "calls_procedures": edges,
                   "calls_late_bound": late}
        if thunks:
            r["calls_thunks"] = thunks
        if other:
            r["calls_other"] = other
        if objects:
            r["calls_objects"] = objects
        if capped:
            r["range_capped"] = True
        rows.append(r)
    return rows, bad, totals
