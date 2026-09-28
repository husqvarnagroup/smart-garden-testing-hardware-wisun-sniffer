# SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for the file selection and check registry of scripts/run_checks.py.

The checks themselves are one-line wrappers around other people's tools and are
not worth testing; what is worth testing is which files they are handed, since a
silently empty or silently over-broad list is the failure mode that would let a
bad commit through without anything looking wrong.
"""

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "run_checks.py"


def load():
    """Import run_checks.py, which is a program rather than an installed module.

    It has to go into sys.modules before it is executed: the script uses
    `from __future__ import annotations`, and @dataclass resolves those string
    annotations by looking its own module up there.
    """
    spec = importlib.util.spec_from_file_location("run_checks", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def run_checks():
    return load()


@pytest.fixture
def listing(run_checks, monkeypatch, tmp_path):
    """Make tracked() see a fixed file list under a temporary repository."""

    def install(names):
        for name in names:
            path = tmp_path / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("")

        def fake_run(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, 0, stdout="\0".join(names) + "\0", stderr="")

        monkeypatch.setattr(run_checks, "REPO", tmp_path)
        monkeypatch.setattr(run_checks.subprocess, "run", fake_run)

    return install


FILES = [
    "application/wisun_sniffer/src/main.c",
    "application/wisun_sniffer/src/main.h",
    "application/wisun_sniffer/src/ext/si4467_regs.h",
    "application/wisun_sniffer/sample.yaml",
    "boards/gardena/dongle/board.c",
    "tests/application/wisun_sniffer/fec/testcase.yaml",
    "README.md",
]


def test_tracked_filters_by_suffix(run_checks, listing):
    listing(FILES)

    assert run_checks.tracked(".md") == ["README.md"]


def test_tracked_returns_everything_without_a_suffix(run_checks, listing):
    listing(FILES)

    assert run_checks.tracked() == sorted(FILES)


def test_tracked_filters_by_prefix(run_checks, listing):
    listing(FILES)

    assert run_checks.tracked(".yaml", under="tests/") == [
        "tests/application/wisun_sniffer/fec/testcase.yaml"
    ]


def test_tracked_skips_a_prefix(run_checks, listing):
    listing(FILES)

    assert run_checks.tracked(".c", ".h", skip=run_checks.EXTERNAL) == [
        "application/wisun_sniffer/src/main.c",
        "application/wisun_sniffer/src/main.h",
        "boards/gardena/dongle/board.c",
    ]


def test_tracked_keeps_external_sources_when_not_asked_to_skip(run_checks, listing):
    listing(FILES)

    assert "application/wisun_sniffer/src/ext/si4467_regs.h" in run_checks.tracked(".h")


def test_tracked_drops_names_that_are_not_files(run_checks, listing, tmp_path):
    """A deleted-but-still-cached path must not reach a tool as an argument."""
    listing(FILES)
    (tmp_path / "README.md").unlink()

    assert run_checks.tracked(".md") == []


def test_run_reports_a_missing_command_rather_than_raising(run_checks):
    with pytest.raises(run_checks.CheckError, match="not found"):
        run_checks.run(["definitely-not-a-program-that-exists"])


def test_python_with_prefers_an_interpreter_that_already_has_the_modules(run_checks, monkeypatch):
    monkeypatch.setattr(run_checks, "run", lambda cmd, cwd=None: (0, ""))

    assert run_checks.python_with(("yaml",), ("pyyaml",)) == [run_checks.workspace_python()]


def test_python_with_falls_back_to_uv_when_none_has_them(run_checks, monkeypatch):
    monkeypatch.setattr(run_checks, "run", lambda cmd, cwd=None: (1, "ModuleNotFoundError"))
    monkeypatch.setattr(run_checks.shutil, "which", lambda name: "/usr/bin/uv")

    assert run_checks.python_with(("pykwalify.core", "yaml"), ("pykwalify", "pyyaml")) == [
        "/usr/bin/uv",
        "run",
        "--no-project",
        "--with",
        "pykwalify",
        "--with",
        "pyyaml",
        "python",
    ]


def test_python_with_says_so_when_it_cannot_fetch_them(run_checks, monkeypatch):
    monkeypatch.setattr(run_checks, "run", lambda cmd, cwd=None: (1, "ModuleNotFoundError"))
    monkeypatch.setattr(run_checks.shutil, "which", lambda name: None)

    with pytest.raises(run_checks.CheckError, match="pykwalify.core"):
        run_checks.python_with(("pykwalify.core",), ("pykwalify",))


@pytest.fixture
def recorded(run_checks, monkeypatch):
    """Capture the command twister() builds instead of running it."""
    seen = []

    def fake_run(cmd, **kwargs):
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(run_checks.subprocess, "run", fake_run)
    monkeypatch.setattr(run_checks, "zephyr_base", lambda: Path("/w/zephyr"))

    return seen


def test_twister_goes_through_west_when_there_is_one(run_checks, monkeypatch, recorded):
    monkeypatch.setattr(run_checks.shutil, "which", lambda name: "/usr/local/bin/west")

    run_checks.twister("-T", "tests")

    assert recorded[0] == ["/usr/local/bin/west", "twister", "-T", "tests"]


def test_twister_falls_back_to_the_script_without_west(run_checks, monkeypatch, recorded):
    monkeypatch.setattr(run_checks.shutil, "which", lambda name: None)
    monkeypatch.setattr(run_checks, "workspace_python", lambda: "/w/.venv/bin/python")

    run_checks.twister("-T", "tests")

    assert recorded[0] == [
        "/w/.venv/bin/python",
        "/w/zephyr/scripts/twister",
        "-T",
        "tests",
    ]


def test_every_check_has_a_usable_option_name(run_checks):
    names = [check.name for check in run_checks.CHECKS]

    assert len(names) == len(set(names))
    assert all(name == name.lower() and " " not in name for name in names)


def test_zephyr_checks_come_last(run_checks):
    """The ordering the module docstring promises: cheap first, Zephyr last."""
    flags = [check.needs_zephyr for check in run_checks.CHECKS]

    assert flags == sorted(flags)
