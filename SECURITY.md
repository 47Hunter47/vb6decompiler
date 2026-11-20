# Security policy

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting** on this repository: the *Security*
tab, then *Report a vulnerability*. That opens a draft advisory only you and the
maintainer can see.

Please do not open a public issue for a security problem, and do not send a report
that contains the data you are reporting about.

## What counts as a security issue here

This is an offline analysis tool: it reads files you point it at and writes files you
name. The realistic problems are:

* **Text from a binary escaping its context** — a recovered name, caption or SQL
  string that becomes markup in the HTML views, a file name that decides a path, a
  shell-looking string that runs.
* **An output overwriting an input** — a stage writing onto a file it read, which
  destroys evidence as well as data.
* **The mask gate being bypassed** — `vb6d mask` reporting clean on an artefact that
  still carries a credential.

Everything here is designed against those, and each has tests. A report showing one of
them getting through is valuable.

## What is out of scope

* Running this tool on a binary you do not have the right to analyse.
* The accuracy of a recovery claim: a wrong-but-labelled number is a bug, and the
  issue tracker is the right place for it. "Unknown" and "open" are answers here, not
  failures.
* Anything that requires an attacker to already control the input files *and* the
  command line — at that point they can run the code directly.

## Supported versions

The latest release on PyPI is the supported one. Fixes go forward in a new patch
release; the published artefacts are never rewritten.
