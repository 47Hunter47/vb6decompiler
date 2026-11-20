"""Scale the synthetic build up and time each stage: seconds and peak memory.

Not part of the package and never imported by it — this is a measuring tool, and its
output is only meaningful if you ran it. Whatever number it prints is about *this*
machine and *this* builder; a real target's timing is the reader's to measure.

    python scripts/bench_synth.py --target-mb 100 --jobs 1 4

Peak memory is read from the OS process counters, not guessed: ``ru_maxrss`` on POSIX
(bytes there, KiB on Linux) and ``GetProcessMemoryInfo`` on Windows.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TESTS = REPO / "tests"


def peak_memory() -> tuple[float, str]:
    """This process's high-water mark, in MiB, with the unit it came from."""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        class PMC(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                        ("PeakWorkingSetSize", ctypes.c_size_t),
                        ("WorkingSetSize", ctypes.c_size_t),
                        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                        ("PagefileUsage", ctypes.c_size_t),
                        ("PeakPagefileUsage", ctypes.c_size_t)]

        counters = PMC()
        counters.cb = ctypes.sizeof(PMC)
        handle = ctypes.windll.kernel32.GetCurrentProcess()  # type: ignore[attr-defined]
        ok = ctypes.windll.psapi.GetProcessMemoryInfo(  # type: ignore[attr-defined]
            handle, ctypes.byref(counters), counters.cb)
        if not ok:
            return -1.0, "unavailable"
        return counters.PeakWorkingSetSize / (1 << 20), "MiB (peak working set)"
    import resource

    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # ru_maxrss is KiB on Linux and bytes on macOS; dividing by the wrong factor is a
    # silent factor-of-1024 error, so the unit is decided by the platform's own rule.
    divisor = 1024 if sys.platform.startswith("linux") else (1 << 20)
    return raw / divisor, "MiB (ru_maxrss)"


def build(target_mb: int, root: Path) -> Path:
    """A build of roughly ``target_mb``: the synthetic image with padding literals."""
    sys.path.insert(0, str(TESTS))
    import synth_vb6

    target = synth_vb6.build(root)
    data = target.exe.read_bytes()
    # Growth is honest padding, not a second code path: the same image, with NUL
    # bytes appended inside the single section, which is what a bigger build looks
    # like to a reader that maps the file.
    want = max(target_mb, 1) * (1 << 20)
    if len(data) < want:
        data = data + bytes(want - len(data))
        target.exe.write_bytes(data)
    return target.exe


PEAK_MARK = "# peak-mib "


def stage(argv: list[str]) -> dict:
    """Run one stage in a child that reports its own high-water mark.

    The parent's peak is not the stage's: it never maps the target. The child prints
    its number as its last line, which the parent strips off before showing anything.
    """
    started = time.monotonic()
    result = subprocess.run([sys.executable, __file__, "--_child", *argv],
                            capture_output=True, text=True)
    seconds = time.monotonic() - started
    peak = -1.0
    for line in reversed(result.stdout.splitlines()):
        if line.startswith(PEAK_MARK):
            peak = float(line[len(PEAK_MARK):])
            break
    return {"argv": " ".join(argv), "rc": result.returncode, "seconds": seconds, "peak": peak}


def child(argv: list[str]) -> int:
    """One stage, then this process's own peak on the last line."""
    import contextlib
    import io

    from vb6decompiler import cli

    with contextlib.redirect_stdout(io.StringIO()):
        code = cli.main(argv)
    mib, unit = peak_memory()
    print(f"{PEAK_MARK}{mib:.1f}")
    if mib < 0:
        print(f"# peak memory is unavailable here ({unit}); the seconds above are measured",
              file=sys.stderr)
    return code


def main() -> int:
    if "--_child" in sys.argv:
        # Before argparse: the stage's own --out would otherwise be eaten by ours.
        return child([a for a in sys.argv[1:] if a != "--_child"])

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-mb", type=int, default=100)
    parser.add_argument("--jobs", type=int, nargs="+", default=[1])
    parser.add_argument("--out", default=str(REPO.parent / "bench_synth_out"))
    args = parser.parse_args()

    root = Path(args.out).resolve()
    root.mkdir(parents=True, exist_ok=True)
    exe = build(args.target_mb, root)
    print(f"# SYNTHETIC build: {exe} ({exe.stat().st_size / (1 << 20):.1f} MiB)")
    listings = root / "listings"

    cases = [["pe", str(exe)], ["procs", str(exe)], ["literals", str(exe)],
             ["blob", str(exe)], ["dossier", "--listings", str(listings),
                                  "--out", str(root / "dossier.jsonl")]]
    cases += [["frm", str(root / "frms"), "--format", "html", "--out",
               str(root / f"html_j{j}"), "--jobs", str(j)] for j in args.jobs]

    print(f"{'stage':<52} {'rc':>3} {'seconds':>9} {'peak MiB':>9}")
    for argv in cases:
        row = stage(argv)
        peak = f"{row['peak']:.1f}" if row["peak"] >= 0 else "n/a"
        print(f"{row['argv'][:52]:<52} {row['rc']:>3} {row['seconds']:>9.2f} {peak:>9}")
    print("# these numbers are about this machine and this builder; measure your own target")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
