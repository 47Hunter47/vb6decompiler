## What this pull request changes

<!-- One paragraph. If it fixes an issue, name the issue. -->

## Checklist

- [ ] `AGENTS.md` and `docs/RULES.md` read, and the docs for the command I touched
      updated in this same pull request.
- [ ] The gate passes, each step read individually: `compileall`, `pytest`,
      `vb6d mask . --dry-run`, `ruff check`, `mypy vb6decompiler`, and the hygiene
      test with a private denylist set.
- [ ] Only stand-in names (`fDemo011`, `tOrder`): no real customer, table, host, path,
      address or account, in code, tests, docs **or the commit message**.
- [ ] Every number in a docstring, doc or CHANGELOG entry was produced by running the
      command on a named input, not estimated.
- [ ] New text that comes out of a binary is escaped for where it lands, with a test
      using hostile input.
- [ ] A new stage or flag has a test that fails without it, and `test_cli`'s
      subcommand set is updated.
- [ ] No history rewrite, no hand-made tag, no force-push.
- [ ] If this touches `.github/`, the workflow invariants are intact: OIDC publishing,
      `environment: pypi`, the concurrency group, no `${{ }}` inside `run:`, no
      `pull_request_target`.

## How I verified it

<!-- Commands run and what they printed. "Tests pass" without the number is not a
verification. -->
