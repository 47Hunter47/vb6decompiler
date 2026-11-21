"""``vb6d run``: the stages in dependency order, one config, an honest table.

Two properties make such a command trustworthy, and both are structural here:

* **A failing stage does not cancel the others.** Stages that needed it are reported
  ``skipped: needs <stage>``, never quietly absent, and the final table names every
  stage's status.
* **"up to date" is a claim with evidence.** It means the manifest beside the output
  records the same input hashes and the same tool version; anything else reruns. A
  resume that guesses is worse than no resume.

The parallel groups are the stages with no edge between them. Results are collected
in plan order, so two runs print the same table even when threads finish out of order.
"""

from __future__ import annotations

import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from . import manifest

#: Dependency order. ``needs`` names the stages whose output this one consumes.
#: ``engine`` marks a stage that requires the optional capstone extra.
STAGES: list[dict] = [
    {"name": "pe", "needs": [], "engine": False},
    {"name": "procs", "needs": [], "engine": False},
    {"name": "literals", "needs": [], "engine": False},
    {"name": "stitch", "needs": [], "engine": False},
    {"name": "frm", "needs": [], "engine": False},
    {"name": "blob", "needs": [], "engine": False},
    {"name": "datareport", "needs": [], "engine": False},
    {"name": "dossier", "needs": [], "engine": False},
    {"name": "schema", "needs": ["dossier"], "engine": False},
    {"name": "edges", "needs": ["dossier"], "engine": True},
    {"name": "outline", "needs": ["edges"], "engine": False},
]

#: Stages this command does not drive: they need a human decision (which VA, which
#: project directory, which mask target) or are queries rather than passes.
MANUAL = ("decode", "xref", "project", "spec", "graph", "mask")

RUNNING, OK, FAILED, SKIPPED = "running", "ok", "failed", "skipped"

#: The two or three counts worth showing per stage, most useful first. Anything a
#: stage reports that is not named here still reaches its manifest.
RECORD_KEYS: dict[str, tuple[str, ...]] = {
    "pe": ("images", "vb6", "unreadable"),
    "procs": ("objects", "methods"),
    "literals": ("literals",),
    "stitch": ("candidates", "closed"),
    "frm": ("parsed", "failed", "pages"),
    "blob": ("forms",),
    "datareport": ("designs", "controls"),
    "dossier": ("procedures", "with_closed_sql", "failed"),
    "schema": ("parsed", "partial", "unparsed"),
    "edges": ("procedures", "edges", "late_bound"),
    "outline": ("procedures", "categorized_calls", "external_calls"),
}
#: A table cell is a glance, not a report: three counts, this many characters.
CELL_WIDTH = 40


def records_cell(name: str, records: dict) -> str:
    """``4 procedures`` or ``1 images, 1 vb6``: the counts a reader needs first."""
    keys = [key for key in RECORD_KEYS.get(name, ()) if key in records]
    keys = keys or list(records)[:3]
    return ", ".join(f"{records[key]} {key}" for key in keys[:3])[:CELL_WIDTH]


@dataclass
class StageRun:
    name: str
    status: str = RUNNING
    seconds: float = 0.0
    detail: str = ""
    records: dict = field(default_factory=dict)
    #: The stage's own exit code, kept so ``run`` can report the contract's reason
    #: rather than flattening every failure into one code.
    code: int = 0

    def row(self) -> str:
        seconds = f"{self.seconds:.1f}s" if self.status != SKIPPED else "-"
        counts = records_cell(self.name, self.records) or "-"
        return f"{self.name:<10} {self.status:<10} {seconds:>7}  {counts:<34} {self.detail}"


def names() -> list[str]:
    return [s["name"] for s in STAGES]


def plan(*, only: list[str] | None = None, from_stage: str | None = None) -> list[dict]:
    """The stages to run, in dependency order, after ``--only``/``--from``.

    ``--from`` keeps dependency order and drops everything before that stage; a
    dropped dependency then counts as a missing one, so the dependent stage is
    reported skipped rather than run against input that was never produced.
    """
    known = names()
    if only:
        unknown = [n for n in only if n not in known]
        if unknown:
            raise ValueError(f"--only {','.join(unknown)}: not driven by 'run'; choose from "
                             f"{','.join(known)}")
        return [s for s in STAGES if s["name"] in only]
    if from_stage:
        if from_stage not in known:
            raise ValueError(f"--from {from_stage}: not a stage 'run' drives "
                             f"({', '.join(known)})")
        return STAGES[known.index(from_stage):]
    return list(STAGES)


def waves(stages: list[dict]) -> tuple[list[list[dict]], list[tuple[dict, str]]]:
    """Split a plan into dependency waves; ``(waves, skipped)``.

    A stage whose dependency is not in the plan can never run, and it is reported
    with the name of what it needed — the whole difference between a resumed run and
    a run that silently half-executed.
    """
    out: list[list[dict]] = []
    done: set[str] = set()
    pending = list(stages)
    while pending:
        ready = [s for s in pending if all(d in done for d in s["needs"])]
        if not ready:
            break
        out.append(ready)
        done.update(s["name"] for s in ready)
        pending = [s for s in pending if s not in ready]
    skipped = [(s, f"needs {', '.join(d for d in s['needs'] if d not in done)}")
               for s in pending]
    return out, skipped


# ---------------------------------------------------------------------------
# Resuming
# ---------------------------------------------------------------------------
def _manifest_of(output: str) -> dict:
    try:
        with open(manifest.path_for(output), encoding="utf-8") as fh:
            body = json.load(fh)
    except (OSError, ValueError):
        return {}
    return body if isinstance(body, dict) else {}


def records_of(output: str) -> dict:
    """The counts a stage wrote into its own manifest: what a resumed run shows."""
    records = _manifest_of(output).get("records")
    return dict(records) if isinstance(records, dict) else {}


def up_to_date(output: str, inputs: list[str], tool: str) -> tuple[bool, str]:
    """Whether an existing output can be kept, and why not when it cannot.

    Only a manifest can answer, and only when the input hashes and the tool version
    still match: an output of unknown provenance is not evidence.
    """
    body = _manifest_of(output)
    if not body:
        return False, "no manifest beside the output"
    if body.get("tool") != tool:
        return False, f"written by {body.get('tool')}, this is {tool}"
    rows = [row for row in body.get("inputs") or [] if isinstance(row, dict)]
    # A manifest written with --manifest-paths names the files it read, so the check
    # re-hashes exactly those. Without paths only the count and the name set can be
    # compared, which is weaker but still catches a changed or missing input.
    named = [row for row in rows if row.get("path")]
    if named:
        for row in named:
            now = manifest.describe_input(str(row["path"]))
            if now.get("kind") == "unreadable":
                return False, f"{os.path.basename(str(row['path']))} is unreadable now"
            if str(now.get("sha256")) != str(row.get("sha256")):
                return False, f"{os.path.basename(str(row['path']))} changed"
        return True, "inputs unchanged"
    recorded = {str(row.get("sha256")) for row in rows if row.get("sha256")}
    current: set[str] = set()
    for path in inputs:
        now = manifest.describe_input(path)
        if now.get("kind") == "unreadable":
            return False, f"{os.path.basename(path)} is unreadable now"
        current.add(str(now.get("sha256")))
    if recorded != current:
        return False, "an input changed since this output was written"
    return True, "inputs unchanged"


# ---------------------------------------------------------------------------
# Running
# ---------------------------------------------------------------------------
#: Stages that print their records to stdout: a run captures them into a file, so
#: every stage in the output directory has something to resume from.
STDOUT_STAGES = ("pe", "procs", "literals", "stitch", "blob")


def run_stage(argv: list[str], capture: str | None = None) -> StageRun:
    """Run one stage in-process and keep the CLI's own exit code as the verdict.

    In-process, not a subprocess: the run shares one config, and eleven subprocesses
    would pay the import cost eleven times. ``cli.main`` is the same entry point a
    shell reaches, so the status is the contract's code and not an exception caught
    somewhere else.
    """
    from . import cli

    row = StageRun(name=argv[0])
    started = time.monotonic()
    # The stage's counts are what it prints; a stale entry from an earlier call must
    # not stand in for a run that failed before reaching its summary.
    cli.STAGE_RECORDS.pop(argv[0], None)
    if capture:
        import contextlib
        import io

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = cli.main(argv)
        try:
            with open(capture, "w", encoding="utf-8", newline="") as fh:
                fh.write(buffer.getvalue())
        except OSError as exc:      # a report we could not keep is still a report
            print(f"# could not write {capture}: {exc.strerror or exc}", file=sys.stderr)
            code = code or 3
    else:
        code = cli.main(argv)
    row.seconds = time.monotonic() - started
    row.status = OK if code == 0 else FAILED
    row.code = code
    row.records = dict(cli.STAGE_RECORDS.get(argv[0], {}))
    if code:
        row.detail = f"exit {code}"
    return row


def run_wave(wave: list[dict], argv_for, workers: int,
             capture_for=None) -> list[StageRun]:
    """One dependency wave, in parallel when it holds more than one stage.

    Results come back in wave order, so the printed table does not depend on which
    thread finished first.
    """
    capture_for = capture_for or (lambda stage: None)
    if len(wave) == 1 or workers <= 1:
        return [run_stage(argv_for(stage), capture_for(stage)) for stage in wave]
    with ThreadPoolExecutor(max_workers=min(workers, len(wave))) as pool:
        return list(pool.map(lambda stage: run_stage(argv_for(stage), capture_for(stage)), wave))


def blocked(stage: dict, failed: set[str]) -> str | None:
    """The reason this stage cannot run because something it needed failed."""
    hit = [d for d in stage["needs"] if d in failed]
    return f"skipped: {', '.join(hit)} failed" if hit else None


def table(rows: list[StageRun]) -> str:
    head = f"{'stage':<10} {'status':<10} {'time':>7}  {'records':<34} output"
    return head + "\n" + "\n".join(r.row() for r in rows)


def exit_code(rows: list[StageRun]) -> int:
    """The run's own code, taken from the worst failure it saw.

    ``AGENTS.md`` distinguishes the two kinds of trouble, and a run of eleven stages
    can hit both, so it reports the one the user has to act on first:

    * a stage that failed because of the input or an invocation (2) means the
      *workspace* is wrong — the same code a single stage would have returned;
    * a stage that failed because of the toolkit (3) means a bug or an unwritable
      output, and it wins over 2 because nothing downstream can be trusted;
    * a failure with any other code is treated as the toolkit's (3), since only 0-3
      are defined and an unexpected one is itself a defect.

    Flattening both into 3 was wrong: it told a user with a typo in the config that the
    toolkit had broken.
    """
    bad = [r for r in rows if r.status == FAILED]
    if not bad:
        return 0
    names = ", ".join(r.name for r in bad)
    print(f"# failed: {len(bad)} of {len(rows)} stages ({names})", file=sys.stderr)
    codes = {r.code for r in bad}
    if 3 in codes or any(c not in (2, 3) for c in codes):
        return 3
    return 2
