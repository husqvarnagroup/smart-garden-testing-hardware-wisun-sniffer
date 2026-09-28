# SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH
# SPDX-License-Identifier: GPL-3.0-or-later

"""Shared fixtures for the capture script's tests.

The script under test is a program rather than a package -- Wireshark runs it through a symlink in
its extcap directory, which is why it is one file and stays one file -- so it is loaded here by
path rather than imported.
"""

import importlib.util
import os

import pytest

TOOLS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(TOOLS_DIR, "wisun_sniffer_capture.py")


def load_capture():
    """Load the capture script as a module of its own."""
    spec = importlib.util.spec_from_file_location("wisun_sniffer_capture", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


@pytest.fixture(scope="session")
def script_path():
    """Where the capture script is, for the tests that run it rather than import it."""
    return SCRIPT


@pytest.fixture
def capture():
    """The capture script, loaded afresh for each test.

    Freshly, because these tests reach into the module to stand something in for the clock or the
    serial port, and a module shared between them would carry one test's fakes into the next.
    """
    return load_capture()
