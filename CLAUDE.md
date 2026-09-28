<!--
SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH

SPDX-License-Identifier: GPL-3.0-or-later
-->

# Working in this repository

Notes for AI assistants. `README.md` covers what the repository is, how to set the workspace up
and how to build and test — read it first and do not duplicate it here.
`application/wisun_sniffer/CLAUDE.md` is the important one: it records what the firmware's code
cannot tell you, including which vendor documentation is wrong.

## Conventions that are easy to get wrong

- **The tool configuration is upstream Zephyr's, unmodified.** `.checkpatch.conf`,
  `.clang-format`, `.editorconfig`, `.gitlint`, `.ruff.toml` and `.yamllint` are verbatim copies
  from Zephyr 4.2.1 and are annotated as such in `REUSE.toml` rather than carrying an added header
  — so do not edit them to suit a change; change the code instead, or raise it upstream. The two
  exceptions are mechanical: `extra-path` in `.gitlint` and `--typedefsfile` in `.checkpatch.conf`
  name paths inside the zephyr tree and are repointed at `../zephyr/scripts/`.
- **C is indented with tabs at 100 columns**, like upstream, everywhere including `boards/`. Always
  finish with
  `clang-format --dry-run --Werror application/wisun_sniffer/src/*.c application/wisun_sniffer/src/*.h`
  and with `../zephyr/scripts/checkpatch.pl --no-tree -f` on what you touched; Zephyr's checkpatch
  is stricter than the one this tree started with and does *not* excuse `LEADING_SPACE`,
  `CODE_INDENT` or `BLOCK_COMMENT_STYLE`.
- Ruff exemptions go in `.ruff-excludes.toml`, which is ours and which `.ruff.toml` extends. Adding
  a line there to quiet a new script is the wrong direction; deleting one after a fix is the right
  one. `pyproject.toml` deliberately has no `[tool.ruff]` section, since `.ruff.toml` wins anyway.
- `reuse lint` must stay clean. A new license identifier needs its text in `LICENSES/`, and an
  identifier no file uses any more is a failure too, so delete it with the last file that used it.
- Markdown is checked with `rumdl`, spelling with `codespell`, YAML with `yamllint -c .yamllint`.
- Commit subjects are `<area>: <imperative>`, with sub-areas where they help:
  `application: wisun_sniffer: ...`, `boards: si4467_dongle: ...`, `doc: ...`. The body says *why*.
- Every commit needs a `Signed-off-by:` line: `.gitlint` is Zephyr's and enforces the DCO, so
  commit with `git commit -s` rather than plain `git commit`. That rule comes from
  `extra-path=../zephyr/scripts/gitlint`, so `--gitlint` needs a west workspace as much as the
  build checks do — gitlint exits with a config error rather than a violation when the directory is
  missing, which reads like a broken `.gitlint` and is not one.
- `scripts/run_checks.py --all --keep-going` runs all of the above in one go and is the quickest
  way to see where a change stands; `--list` names the individual checks. It deliberately hands
  `application/wisun_sniffer/src/ext/` to neither clang-format nor checkpatch, because those files
  are generated and vendor-derived and would drown the output in findings nobody may act on.
- **A new check needs a step in `.github/workflows/checks.yml` as well.** Both jobs name their
  checks one per step, so that GitHub says which one failed; neither discovers a check by itself,
  and one left out is silently never run in CI. Put it in the `firmware` job if it needs a Zephyr
  tree and in `tree` otherwise.
- The checkers are pinned in `pyproject.toml`'s `dev` group and locked in `uv.lock`, and
  `run_checks.py` looks in `.venv/bin` before `PATH`. So after `uv sync` the versions are the ones
  CI uses — including `clang-format`, where a version difference is a diff. Bumping one is a
  deliberate act with its own commit, not something to do in passing while fixing a finding.

## An unraisable warning is reported against the wrong test

`filterwarnings = ["error"]` in `pyproject.toml` turns a `ResourceWarning` into an error, but
pytest collects unraisable exceptions at the *next* test's setup rather than where the file was
leaked. So a leak in one module is reported as an `ERROR` in whatever runs after it — which, with
`scripts/tests` in `testpaths`, is often a test that has nothing to do with it. Read the
`ResourceWarning` traceback inside the `ExceptionGroup` for the file that was actually left open;
the test name on the `ERROR` line is only where the collection happened to land.

## Twister has to be scoped

```console
west twister -T wisun-sniffer/tests -T wisun-sniffer/application/wisun_sniffer -p native_sim
```

Not the repository root — building `application/mcuboot/` in place fails, for a reason explained in
its own `README.md`. This is a known and accepted wrinkle; do not try to "fix" it by deleting the
`sample.yaml` descriptor.
