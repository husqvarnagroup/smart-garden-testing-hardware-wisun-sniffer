<!--
SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH

SPDX-License-Identifier: GPL-3.0-or-later
-->

# Wi-SUN Sniffer

A Zephyr firmware that receives Wi-SUN FAN frames with an Si4467 transceiver and streams them to
Wireshark as PCAP-NG, plus everything needed to build it: the dongle board it runs on and an
MCUboot configuration. The dongle is the only supported target.

![Wi-SUN traffic decoded live in Wireshark, with the capture toolbar above the packet
list](application/wisun_sniffer/doc/screenshots/wireshark.png)

`application/wisun_sniffer/README.md` explains the firmware itself — the PHY, capture, Wireshark
integration and the shell; this file covers the repository and the workspace around it.

## What is here

| Path                               | Contents                                                 |
|------------------------------------|----------------------------------------------------------|
| `application/wisun_sniffer/`       | The sniffer firmware and its host-side capture script    |
| `application/mcuboot/`             | MCUboot configuration for the dongle                     |
| `boards/gardena/si4467_dongle/`    | The `si4467_dongle/nrf52840` board: nRF52840 plus Si4467 |
| `dts/bindings/transceiver/`        | The `silabs,si4467` devicetree binding                   |
| `scripts/`                         | The check runner and its own tests                       |
| `tests/application/wisun_sniffer/` | Unit tests that run on `native_sim`                      |

## Setting up the workspace

This repository is the manifest repository of a west workspace. To set up the workspace, use the
following commands:

```console
mkdir -p ~/workspace/wisun-sniffer
cd ~/workspace/wisun-sniffer
git clone <this repository> wisun-sniffer
west init -l wisun-sniffer
west update
```

which gives:

```text
~/workspace/wisun-sniffer/     west workspace top
├── .west/
├── bootloader/mcuboot/
├── modules/
├── zephyr/
└── wisun-sniffer/             this repository
```

Building needs the Zephyr SDK and the Zephyr Python requirements; see the
[Zephyr getting started guide](https://docs.zephyrproject.org/latest/develop/getting_started/index.html).

## Building

Build & flash (using a debug probe):

```console
west build -p auto -b si4467_dongle/nrf52840 wisun-sniffer/application/wisun_sniffer
west flash
```

To build for MCUboot (for updating over USB DFU):

```console
west build -p auto -b si4467_dongle/nrf52840 wisun-sniffer/application/wisun_sniffer \
    -- -DEXTRA_CONF_FILE=overlays/si4467_dongle-mcuboot.conf
```

The bootloader itself is a separate, one-time build; see `application/mcuboot/README.md`.

## Testing

Two independent suites. The firmware's forward error correction is covered by a `ztest` that runs
on `native_sim`:

```console
west twister -T wisun-sniffer/tests -T wisun-sniffer/application/wisun_sniffer \
    -p native_sim --inline-logs
```

Scope twister to those two paths rather than the repository root — building `application/mcuboot/`
in place fails; see `application/mcuboot/README.md` for why.

The host-side capture script has its own tests, which need neither a dongle nor Wireshark. They
use [`uv`](https://docs.astral.sh/uv/) for the Python environment:

```console
cd wisun-sniffer
uv run pytest
uv run ruff check .
```

`uv` creates `.venv/` and installs `pyserial` and `pytest` on first use; nothing has to be installed
by hand. `application/wisun_sniffer/tools/tests/README.md` explains what each test file covers.

## Code style

Zephyr's conventions apply, without deviation: `.checkpatch.conf`, `.clang-format`,
`.editorconfig`, `.gitlint`, `.ruff.toml` and `.yamllint` are copied verbatim from Zephyr 4.2.1, so
C is indented with **tabs** at 100 columns and a commit subject is `<area>: <subject>`. Two lines
were repointed to name paths inside the zephyr tree: `extra-path` in `.gitlint` and
`--typedefsfile` in `.checkpatch.conf`.

`scripts/run_checks.py` runs every check over exactly the files git knows about — including ones
not yet staged, which a manual glob misses. `--list` names them, each also its own option:

```console
scripts/run_checks.py --list
scripts/run_checks.py --all --keep-going     # run them all, reporting at the end
scripts/run_checks.py --all --fix            # fix what can be fixed in place
```

The last five need the Zephyr tree beside this repository and are skipped without it; `--gitlint`
is one of those, since its sign-off rule lives in `../zephyr/scripts/gitlint`. `scripts/tests/`
covers the runner's own file selection, under `uv run pytest`.

```console
uv sync
```

installs every checker, `clang-format` included, at the `uv.lock` versions the script prefers over
`PATH` — the one that matters, since minor `clang-format` versions can format differently. Without
it, the script fetches what it needs on demand instead.

## Continuous integration

`.github/workflows/checks.yml` runs the same script rather than its own copy of the commands, one
check per step so that GitHub names the one that failed.
