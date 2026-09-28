<!--
SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH

SPDX-License-Identifier: GPL-3.0-or-later
-->

# Wi-SUN Sniffer

A Zephyr firmware that receives Wi-SUN FAN frames with an Si4467 transceiver and streams them to
Wireshark as PCAP-NG, plus everything needed to build it: the dongle board it runs on and an
MCUboot configuration. The dongle is the only supported target.

`application/wisun_sniffer/README.md` is the one to read for what the firmware does — the PHY it
speaks, how to capture, the Wireshark integration and the shell. This file covers the repository
and the workspace around it.

## What is here

| Path                               | Contents                                              |
|------------------------------------|-------------------------------------------------------|
| `application/wisun_sniffer/`       | The sniffer firmware and its host-side capture script |
| `application/mcuboot/`             | MCUboot configuration for the dongle                  |
| `boards/gardena/dongle/`           | The `dongle/nrf52840` board: nRF52840 plus Si4467     |
| `dts/bindings/transceiver/`        | The `silabs,si4467` devicetree binding                |
| `scripts/`                         | The check runner and its own tests                    |
| `tests/application/wisun_sniffer/` | Unit tests that run on `native_sim`                   |

## Setting up the workspace

This repository is the manifest repository of a west workspace. Zephyr and the modules it needs
are fetched next to it, not into it:

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
`west.yml` pins upstream Zephyr and imports only the modules this repository reaches, so
`west update` fetches four projects rather than fifty: Zephyr itself, `cmsis_6` and `hal_nordic`
for the nRF52840, and `mcuboot`.

## Building

All commands run from the workspace top (`~/workspace/wisun-sniffer`).

```console
west build -p auto -b dongle/nrf52840 wisun-sniffer/application/wisun_sniffer
west flash
```

That image starts at the reset vector and needs a debug probe. To build it to load through MCUboot
instead — which lets a dongle be updated over USB DFU, with no probe — add the overlay:

```console
west build -p auto -b dongle/nrf52840 wisun-sniffer/application/wisun_sniffer \
    -- -DEXTRA_CONF_FILE=overlays/dongle-mcuboot.conf
```

No signing key is needed, and there is none in this repository: the image gets an MCUboot header
and a SHA256 but no signature, and the bootloader is built with
`CONFIG_BOOT_SIGNATURE_TYPE_NONE`. Loading firmware onto a dongle already needs physical access to
its button. The bootloader itself is a separate, one-time build; see
`application/mcuboot/README.md`.

`application/*/sample.yaml` lists the build variants in Zephyr's usual form.

## Testing

Two independent suites. The firmware's forward error correction is covered by a `ztest` that runs
on `native_sim`:

```console
west twister -T wisun-sniffer/tests -T wisun-sniffer/application/wisun_sniffer \
    -p native_sim --inline-logs
```

Scope twister to those two paths rather than the repository root: `application/mcuboot/` holds a
`sample.yaml` describing builds that MCUboot can only perform from its own source directory, and
twister would fail trying to build it in place.

The host-side capture script has its own tests, which need neither a dongle nor Wireshark. They
use [`uv`](https://docs.astral.sh/uv/) for the Python environment:

```console
cd wisun-sniffer
uv run pytest
uv run ruff check .
```

`uv` creates `.venv/` and installs `pyserial` and `pytest` on first use; nothing has to be
installed by hand. `application/wisun_sniffer/tools/tests/README.md` says what each test file
covers.

## Code style

Zephyr's conventions apply, without deviation: `.checkpatch.conf`, `.clang-format`,
`.editorconfig`, `.gitlint`, `.ruff.toml` and `.yamllint` are copied verbatim from Zephyr 4.2.1, so
C is indented with **tabs** at 100 columns and a commit subject is `<area>: <subject>`. Two lines
had to be repointed because they name paths inside the zephyr tree: `extra-path` in `.gitlint` and
`--typedefsfile` in `.checkpatch.conf` now reach `../zephyr/scripts/`.

```console
clang-format --dry-run --Werror application/wisun_sniffer/src/*.c application/wisun_sniffer/src/*.h
../zephyr/scripts/checkpatch.pl --no-tree -f <files>
uv run --no-project --with ruff ruff check .
uv run --no-project --with yamllint yamllint -c .yamllint .
rumdl check .
codespell
reuse lint
```

`scripts/run_checks.py` runs those, and the rest of what a commit is expected to pass, over exactly
the files git knows about — including new ones that are not staged yet, which is the case a manual
glob quietly misses. `--list` names the checks, each of which is also its own option:

```console
scripts/run_checks.py --list
scripts/run_checks.py --all                  # stops at the first failure
scripts/run_checks.py --all --keep-going     # runs them all and reports at the end
scripts/run_checks.py --all --fix            # fixes what can be fixed in place
scripts/run_checks.py --clang-format --ruff  # just these two
```

Checks are ordered cheapest first, and the last four need the Zephyr tree beside this repository;
without it they are reported as skipped rather than failed. Tools that are neither on `PATH` nor in
`.venv/` are fetched on demand through `uv run --no-project --with`, so nothing has to be installed
by hand for the script to work. `scripts/tests/` covers its file selection, and runs with the rest
of the Python tests under `uv run pytest`.

`.ruff.toml` extends `.ruff-excludes.toml`, which is this repository's own and holds the per-file
rule exemptions — the same mechanism Zephyr uses for code that predates a rule. Fixing a finding
and deleting its line there is the intended direction.

`application/wisun_sniffer/src/ext/` holds generated and vendor-derived files. They have their own
`.clang-format` with `DisableFormat: true` and must not be reformatted or edited by hand. The
hand-aligned tables in `wisun_phy.c` sit in explicit `clang-format off` regions for the same
reason; their indentation is still tabs, only the column alignment is spaces.
