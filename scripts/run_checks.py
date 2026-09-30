#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Run the style and correctness checks this repository gates commits on.

Checks are ordered cheapest first and, by default, stop at the first failure --
there is no value in spending minutes building the firmware to tell you about a
formatting problem that a two-second run of clang-format would have found.
`--keep-going` runs them all anyway.

The checks split in two. Those above `--gitlint` need nothing but this
repository and the tools it can reach; those from `--gitlint` down need the
Zephyr tree that `west update` puts beside it, and are skipped with a note when
it is missing rather than reported as failures, because an un-updated workspace
is an environment problem and not something a commit can fix.

    scripts/run_checks.py --all          everything
    scripts/run_checks.py --all --fix    everything, fixing what can be fixed
    scripts/run_checks.py --clang-format --ruff
    scripts/run_checks.py --list
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Generated and vendor-derived sources. They carry their own .clang-format with
# `DisableFormat: true` and are not written in Zephyr's style, so neither
# clang-format nor checkpatch has anything useful to say about them.
EXTERNAL = "application/wisun_sniffer/src/ext/"


class CheckError(Exception):
    """A check could not be run at all, as opposed to running and failing."""


def zephyr_base() -> Path | None:
    """Locate the Zephyr tree, or None if this workspace has not been updated."""
    env = os.environ.get("ZEPHYR_BASE")
    if env and (Path(env) / "scripts" / "checkpatch.pl").exists():
        return Path(env).resolve()

    # The T2 layout puts Zephyr beside the manifest repository, which is us.
    candidate = REPO.parent / "zephyr"
    if (candidate / "scripts" / "checkpatch.pl").exists():
        return candidate

    return None


def tool(name: str, package: str | None = None) -> list[str]:
    """Resolve a checker, as a command prefix to put arguments after.

    Only ruff and pytest are dependencies of this repository's own uv project;
    the rest are stand-alone tools that a developer may or may not have
    installed. Rather than demand that they all be on PATH, fall back to the
    `uv run --no-project --with <package>` form that README.md documents, which
    fetches the tool into a cached throw-away environment.
    """
    local = REPO / ".venv" / "bin" / name
    if local.exists():
        return [str(local)]

    found = shutil.which(name)
    if found is not None:
        return [found]

    uv = shutil.which("uv")
    if uv is None:
        raise CheckError(f"neither {name} nor uv found; install one of them")

    return [uv, "run", "--no-project", "--with", package or name, name]


def tracked(*suffixes: str, under: str | None = None, skip: str | None = None) -> list[str]:
    """List files git knows about, including new ones that are not staged yet.

    `--others --exclude-standard` is load-bearing rather than defensive: without
    it a brand-new file passes every check right up to the moment it is
    committed, which is the one moment the checks are meant to cover.
    """
    out = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=True,
    ).stdout

    paths = []
    for name in out.split("\0"):
        if not name:
            continue
        if suffixes and not name.endswith(suffixes):
            continue
        if under is not None and not name.startswith(under):
            continue
        if skip is not None and name.startswith(skip):
            continue
        if not (REPO / name).is_file():
            continue
        paths.append(name)

    return sorted(paths)


def run(cmd: Sequence[str], cwd: Path | None = None) -> tuple[int, str]:
    """Run a command, returning its status and its combined output.

    A command that is not installed becomes a CheckError rather than the
    traceback subprocess would otherwise raise: not every one of these comes
    through tool(), and `perl not found` is the whole of what the operator needs
    to read.
    """
    try:
        proc = subprocess.run(
            list(cmd),
            cwd=cwd or REPO,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        raise CheckError(f"{cmd[0]} not found") from None

    return proc.returncode, (proc.stdout + proc.stderr).strip()


@dataclass
class Result:
    ok: bool
    output: str = ""
    skipped: str = ""


@dataclass
class Check:
    name: str
    help: str
    run: Callable[[bool], Result]
    needs_zephyr: bool = False


def jobs() -> int:
    return max(1, min(16, os.cpu_count() or 4))


# --------------------------------------------------------------------------
# Zephyr-independent checks
# --------------------------------------------------------------------------


def check_clang_format(fix: bool) -> Result:
    files = tracked(".c", ".h", skip=EXTERNAL)
    if not files:
        return Result(True, "no C files")

    args = ["-i"] if fix else ["--dry-run", "--Werror"]
    code, out = run([*tool("clang-format"), "--style=file", *args, *files])
    return Result(code == 0, out)


def check_ruff(fix: bool) -> Result:
    args = ["check", "--fix"] if fix else ["check"]
    code, out = run([*tool("ruff"), *args, "."])
    return Result(code == 0, out)


def check_ruff_format(fix: bool) -> Result:
    args = ["format"] if fix else ["format", "--check"]
    code, out = run([*tool("ruff"), *args, "."])
    return Result(code == 0, out)


def check_gersemi(fix: bool) -> Result:
    files = tracked("CMakeLists.txt", ".cmake")
    if not files:
        return Result(True, "no CMake files")

    args = ["--in-place"] if fix else ["--check"]
    code, out = run([*tool("gersemi"), *args, *files])
    return Result(code == 0, out)


def check_yamllint(fix: bool) -> Result:
    files = tracked(".yml", ".yaml")
    if not files:
        return Result(True, "no YAML files")

    code, out = run([*tool("yamllint"), "-c", ".yamllint", *files])
    return Result(code == 0, out)


def check_codespell(fix: bool) -> Result:
    args = ["--write-changes"] if fix else []
    code, out = run([*tool("codespell"), *args, "."])
    return Result(code == 0, out)


def check_rumdl(fix: bool) -> Result:
    files = tracked(".md")
    if not files:
        return Result(True, "no Markdown files")

    args = ["check", "--fix"] if fix else ["check"]
    code, out = run([*tool("rumdl"), *args, *files])
    return Result(code == 0, out)


def check_reuse(fix: bool) -> Result:
    """Check that every file declares a copyright holder and a license.

    A license identifier that no file uses any more fails this too, so deleting
    the last file that used one means deleting its text from LICENSES/.
    """
    code, out = run([*tool("reuse"), "lint"])
    return Result(code == 0, out)


def check_pytest(fix: bool) -> Result:
    """Run the host-side capture script's tests.

    `testpaths` in pyproject.toml says which directory that is, so no path is
    passed here -- one place to change when a second suite appears.
    """
    pytest_bin = REPO / ".venv" / "bin" / "pytest"
    if not pytest_bin.exists():
        uv = shutil.which("uv")
        if uv is None:
            raise CheckError(f"no .venv in {REPO} and no uv to create one")
        cmd = [uv, "run", "pytest", "-q"]
    else:
        cmd = [str(pytest_bin), "-q"]

    code, out = run(cmd)
    # 5 is pytest's "no tests collected", which is not a failure here.
    return Result(code in (0, 5), out[-4000:])


# --------------------------------------------------------------------------
# Checks that need a Zephyr tree
# --------------------------------------------------------------------------


def check_gitlint(fix: bool) -> Result:
    """Check the message of HEAD against .gitlint, which is Zephyr's.

    This one is in this half of the file for a reason that is easy to miss: our
    .gitlint sets `extra-path=../zephyr/scripts/gitlint`, and gitlint refuses to
    start at all when that directory is absent. Those are the rules worth having
    -- SignedOffBy is the DCO check, TitleStartsWithSubsystem is the `<area>:`
    one -- so overriding extra-path to run without them would pass the commits
    this is meant to catch.
    """
    base = zephyr_base()
    assert base is not None

    code, _ = run(["git", "rev-parse", "--verify", "HEAD"])
    if code != 0:
        return Result(True, skipped="no commits yet")

    code, out = run([*tool("gitlint"), "--commit", "HEAD"])
    return Result(code == 0, out)


VALIDATE_SNIPPET = """
import logging
import sys
import pykwalify.core
import yaml

# Twister validates these with pykwalify, not jsonschema: the file under
# scripts/schemas/twister/ is a pykwalify schema that looks superficially like
# JSON Schema. See scripts/pylib/twister/scl.py in the Zephyr tree.
logging.getLogger("pykwalify.core").setLevel(logging.CRITICAL)

with open(sys.argv[1]) as handle:
    schema = yaml.safe_load(handle)

problems = []
for name in sys.argv[2:]:
    with open(name) as handle:
        data = yaml.safe_load(handle)
    try:
        pykwalify.core.Core(source_data=data, schema_data=schema).validate(raise_exception=True)
    except Exception as error:
        problems.append("%s: %s" % (name, error))

print("\\n".join(problems), end="")
sys.exit(1 if problems else 0)
"""


def workspace_python() -> str:
    """The interpreter the Zephyr-side checks run under.

    Not sys.executable and not this repository's venv: twister and the schema
    validation need Zephyr's own requirements -- pykwalify, colorama, pyelftools
    and the rest -- which live in the west workspace venv beside .west/.
    """
    candidate = REPO.parent / ".venv" / "bin" / "python"
    if candidate.exists():
        return str(candidate)

    return sys.executable


def python_with(modules: Sequence[str], packages: Sequence[str]) -> list[str]:
    """An interpreter that can import @p modules, as a command prefix.

    Zephyr keeps pykwalify in requirements-build-test.txt rather than in its
    base requirements, so the west workspace venv may or may not have it
    depending on which of them was installed. Probe rather than assume, and fall
    back to fetching @p packages through uv, the same way tool() does.
    """
    probe = "import " + ", ".join(modules)

    for candidate in (workspace_python(), sys.executable):
        if run([candidate, "-c", probe])[0] == 0:
            return [candidate]

    uv = shutil.which("uv")
    if uv is None:
        raise CheckError(f"no interpreter has {', '.join(modules)}, and no uv to fetch them")

    fetch = [arg for package in packages for arg in ("--with", package)]

    return [uv, "run", "--no-project", *fetch, "python"]


def check_app_yaml(fix: bool) -> Result:
    """Validate every scenario file against twister's own schema.

    Run in a subprocess rather than imported: this script runs under whatever
    python invoked it, which is not necessarily one that has pykwalify.
    """
    base = zephyr_base()
    assert base is not None
    schema = base / "scripts" / "schemas" / "twister" / "testsuite-schema.yaml"
    if not schema.exists():
        raise CheckError(f"twister schema not found at {schema}")

    files = [
        *tracked("sample.yaml", under="application/"),
        *tracked("testcase.yaml", under="tests/"),
    ]
    if not files:
        return Result(True, "no scenario files")

    python = python_with(("pykwalify.core", "yaml"), ("pykwalify", "pyyaml"))
    code, out = run([*python, "-c", VALIDATE_SNIPPET, str(schema), *files])
    return Result(code == 0, out)


def check_checkpatch(fix: bool) -> Result:
    """Run Zephyr's checkpatch over our C.

    Run with cwd at the top of this repository so checkpatch picks up our
    .checkpatch.conf, which is Zephyr's verbatim apart from --typedefsfile
    having been repointed into the Zephyr tree.
    """
    base = zephyr_base()
    assert base is not None

    files = tracked(".c", ".h", skip=EXTERNAL)
    if not files:
        return Result(True, "no C files")

    code, out = run(
        [
            "perl",
            str(base / "scripts" / "checkpatch.pl"),
            "--file",
            "--no-tree",
            "--quiet",
            *files,
        ],
    )
    return Result(code == 0, out)


def twister(*args: str) -> tuple[int, str]:
    """Run twister, through west where there is one.

    `west twister` is what README.md tells you to test with, and going through
    it is what puts Zephyr's own requirements -- pykwalify, pyelftools, ply and
    the rest -- on sys.path, because west runs the extension under the
    interpreter west itself was installed into. Invoking scripts/twister with an
    interpreter of our choosing only works if that one happens to have them
    already, which is not something this script can arrange; it is kept as a
    fallback for a workspace whose west is not on PATH.

    Paths stay relative to this repository either way: west does not change
    directory for an extension command.
    """
    base = zephyr_base()
    assert base is not None

    env = os.environ.copy()
    env.setdefault("ZEPHYR_BASE", str(base))

    west = shutil.which("west")
    if west is not None:
        cmd = [west, "twister", *args]
    else:
        cmd = [workspace_python(), str(base / "scripts" / "twister"), *args]

    proc = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True, env=env)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def check_ztest(fix: bool) -> Result:
    """Run the ztest suites on native_sim.

    Scoped to the two paths that twister can handle rather than the repository
    root: application/mcuboot/sample.yaml describes builds MCUboot can only
    perform from its own source directory, and twister fails trying to build
    that directory in place.
    """
    code, out = twister(
        "-T",
        "tests",
        "-T",
        "application/wisun_sniffer",
        "--platform",
        "native_sim",
        "-O",
        "twister-out.ztest",
        "--clobber-output",
        "-j",
        str(jobs()),
    )
    return Result(code == 0, out[-4000:])


def check_build(fix: bool) -> Result:
    """Build every variant the sniffer's sample.yaml declares, for the dongle."""
    code, out = twister(
        "-T",
        "application/wisun_sniffer",
        "--all",
        "--build-only",
        "-O",
        "twister-out.build",
        "--clobber-output",
        "-j",
        str(jobs()),
    )
    return Result(code == 0, out[-4000:])


CHECKS: list[Check] = [
    Check("clang-format", "C formatting, Zephyr's .clang-format", check_clang_format),
    Check("ruff", "Python linting", check_ruff),
    Check("ruff-format", "Python formatting", check_ruff_format),
    Check("gersemi", "CMake formatting", check_gersemi),
    Check("yamllint", "YAML linting", check_yamllint),
    Check("codespell", "spelling", check_codespell),
    Check("rumdl", "Markdown linting", check_rumdl),
    Check("reuse", "copyright and license declarations", check_reuse),
    Check("pytest", "host-side capture script tests", check_pytest),
    Check("gitlint", "commit message of HEAD", check_gitlint, True),
    Check("app-yaml", "scenario files against twister's schema", check_app_yaml, True),
    Check("checkpatch", "Zephyr's checkpatch.pl", check_checkpatch, True),
    Check("ztest", "ztest suites on native_sim", check_ztest, True),
    Check("build", "every declared firmware variant", check_build, True),
]


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--all", action="store_true", help="run every check")
    parser.add_argument("--fix", action="store_true", help="fix what can be fixed")
    parser.add_argument(
        "--keep-going",
        action="store_true",
        help="run every selected check even after one fails",
    )
    parser.add_argument("--list", action="store_true", help="list the checks and exit")
    for check in CHECKS:
        parser.add_argument(f"--{check.name}", action="store_true", help=check.help)

    args = parser.parse_args()

    if args.list:
        width = max(len(check.name) for check in CHECKS)
        for check in CHECKS:
            mark = " (needs a Zephyr tree)" if check.needs_zephyr else ""
            print(f"  --{check.name:<{width}}  {check.help}{mark}")
        return 0

    selected = [c for c in CHECKS if args.all or getattr(args, c.name.replace("-", "_"))]
    if not selected:
        parser.print_help()
        return 2

    have_zephyr = zephyr_base() is not None
    failed = False

    for check in selected:
        if check.needs_zephyr and not have_zephyr:
            print(f"[  --] {check.name}: no Zephyr tree; run `west update` first")
            continue

        try:
            result = check.run(args.fix)
        except CheckError as exc:
            print(f"[FAIL] {check.name}: {exc}")
            failed = True
            if not args.keep_going:
                return 1
            continue

        if result.skipped:
            print(f"[  --] {check.name}: {result.skipped}")
            continue

        if result.ok:
            print(f"[  ok] {check.name}")
            continue

        print(f"[FAIL] {check.name}")
        if result.output:
            print(result.output)
        failed = True
        if not args.keep_going:
            return 1

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
