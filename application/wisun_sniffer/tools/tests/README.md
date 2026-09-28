<!--
SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH

SPDX-License-Identifier: GPL-3.0-or-later
-->

# Tests for the capture script

These cover `../wisun_sniffer_capture.py`, the host-side half of the sniffer. They need no dongle
and no Wireshark: ptys stand in for the dongle's two USB interfaces, fifos for the capture and
control pipes, and a fake clock for time.

From the repository root:

```console
uv run pytest
```

`pyproject.toml` points `testpaths` here, so no path has to be given, and `uv` installs `pytest`
and `pyserial` into `.venv/` on first use. `test_toolbar.py` needs ptys and fifos, so it is
skipped off Linux. It runs the script as a subprocess under the interpreter running pytest — not
under the `python3` its shebang would find — so `pyserial` has to be installed in that one, which
is what `uv run` arranges. Wireshark runs it under the shebang interpreter instead, so `pyserial`
has to be installed there too for a capture to work.

| File | Covers |
|---|---|
| `test_retime.py` | `Stream` — reading PCAP-NG blocks out of the capture port and rebasing their timestamps onto the host clock |
| `test_console.py` | talking to the firmware's shell — sending a command, telling an answer from a log line, and checking the PHY that came back is the one asked for |
| `test_toolbar.py` | the script as Wireshark runs it: the extcap control protocol, the toolbar, and stopping |

Every test here was written from a fault that reached a dongle, and each one fails against the
version of the script that had it. That is the bar for adding another: a test that has never failed
has not been shown to test anything.

**This is not a test of the firmware.** The C under `../../src/` is not exercised at all — the
shell in `test_toolbar.py` is a Python thread playing the part, so it tests our side of the
conversation only. The firmware is verified on hardware.

They are separate from the firmware's own tests under `tests/`, which run on `native_sim` through
twister. Run these by hand after changing the script.
