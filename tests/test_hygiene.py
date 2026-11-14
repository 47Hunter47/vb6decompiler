"""Repo hygiene: no target identity, no private addressing, no personal data.

This repo is a tool.  Everything in it must be usable by someone who has never
heard of the program it was developed against, so the repo itself is checked for
the things that would betray that program or its owner:

* a private address (``10/8``, ``192.168/16``, ``172.16-31/12``) instead of a
  documentation address from ``192.0.2/24``, ``198.51.100/24``, ``203.0.113/24``
  (RFC 5737) or a name like ``fileserv``;
* a UNC share pointing at a real machine;
* an e-mail address or a personal home path;
* a person's or a company's name.

The deny-list is *not* stored here: it lives in the private notes of whichever
project uses these tools.  What this test can check without naming anyone is the
shape of the leak, so it is written as patterns.  Set ``VB6D_SCRUB_DENYLIST`` to a
file of literal names (one per line) to also ban the names of your own target.
"""

from __future__ import annotations

import os
import re
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# RFC 5737 documentation ranges and RFC 6761 example names: the legal stand-ins.
DOC_NETS = ("192.0.2.", "198.51.100.", "203.0.113.")
# Placeholder host names a doc may legitimately use.
DOC_HOSTS = ("example", "fileserv", "target", "host", "server", "db", "local")

PRIVATE_IP = re.compile(
    r"(?<![\d.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![\d.])"
)
UNC = re.compile(r"\\\\[A-Za-z0-9._-]+\\[A-Za-z0-9._-]+")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
HOME_PATH = re.compile(r"(?i)[a-z]:\\+users\\+|/home/[a-z0-9_.-]+/|/Users/[a-z0-9_.-]+/")


def _tracked_files() -> list[str]:
    out = subprocess.run(["git", "ls-files"], cwd=REPO, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    return out.stdout.split()


def _text(path: str) -> str | None:
    with open(os.path.join(REPO, path), "rb") as fh:
        raw = fh.read()
    if b"\x00" in raw[:4096]:
        return None  # binary fixture: nothing textual to leak
    for enc in ("utf-8", "cp1254"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def _denylist() -> list[str]:
    path = os.environ.get("VB6D_SCRUB_DENYLIST")
    if not path:
        return []
    with open(path, encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]


def test_tracked_files_are_read():
    assert _tracked_files(), "no tracked files"


def test_no_private_addresses():
    bad = []
    for name in _tracked_files():
        text = _text(name)
        if text is None:
            continue
        for line, value in ((l, m.group(0)) for l in text.splitlines() for m in PRIVATE_IP.finditer(l)):
            if not value.startswith(DOC_NETS):
                bad.append((name, value))
    assert not bad, f"private addresses in tracked files: {bad[:10]}"


def test_unc_shares_point_at_example_hosts():
    bad = []
    for name in _tracked_files():
        text = _text(name)
        if text is None:
            continue
        for m in UNC.finditer(text):
            host = m.group(0).split("\\\\")[1].lower()
            if not any(tok in host for tok in DOC_HOSTS):
                bad.append((name, m.group(0)))
    assert not bad, f"UNC path naming a real host: {bad[:10]}"


def test_no_email_or_home_path():
    bad = []
    for name in _tracked_files():
        text = _text(name)
        if text is None:
            continue
        for m in EMAIL.finditer(text):
            if "example" not in m.group(0):
                bad.append((name, m.group(0)))
        for m in HOME_PATH.finditer(text):
            bad.append((name, m.group(0)))
    assert not bad, f"personal e-mail or home path: {bad[:10]}"


def test_denylist_from_the_private_project_is_empty_here():
    """When a project uses these tools, its own names must not appear in them."""
    names = _denylist()
    if not names:
        pytest.skip("VB6D_SCRUB_DENYLIST not set")
    bad = []
    for name in _tracked_files():
        text = _text(name)
        if text is None:
            continue
        for token in names:
            if re.search(r"(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])" % re.escape(token), text, re.I):
                bad.append((name, token))
    assert not bad, f"project-specific names present in the tool repo: {bad[:10]}"
