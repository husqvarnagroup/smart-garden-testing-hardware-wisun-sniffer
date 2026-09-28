<!--
SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH

SPDX-License-Identifier: GPL-3.0-or-later
-->

# MCUboot

Configuration fragments for the MCUboot bootloader on the dongle. **There is no application here
to build.** MCUboot derives its own source root from `APPLICATION_SOURCE_DIR`, so it can only be
built from `bootloader/mcuboot/boot/zephyr`; this directory holds the `EXTRA_CONF_FILE` and
`EXTRA_DTC_OVERLAY_FILE` arguments to hand it. The `sample.yaml` here documents the build but
cannot be run by twister in place, which is why the twister invocation in the top-level `README.md`
is scoped to `tests/` and `application/wisun_sniffer/`.

| File                                    | Contents                                                             |
|-----------------------------------------|----------------------------------------------------------------------|
| `conf/mcuboot.conf`                     | Not board specific: size optimisation, log level, no signature check |
| `boards/si4467_dongle_nrf52840.conf`    | Single slot, USB DFU on the user button                              |
| `boards/si4467_dongle_nrf52840.overlay` | `mcuboot-button0` / `mcuboot-led0` aliases for DFU mode              |

## Building

From the west workspace top:

```console
west build -p always -b si4467_dongle/nrf52840 bootloader/mcuboot/boot/zephyr -- \
    -DEXTRA_CONF_FILE="$PWD/wisun-sniffer/application/mcuboot/conf/mcuboot.conf;$PWD/wisun-sniffer/application/mcuboot/boards/si4467_dongle_nrf52840.conf" \
    -DEXTRA_DTC_OVERLAY_FILE="$PWD/wisun-sniffer/application/mcuboot/boards/si4467_dongle_nrf52840.overlay"
```

No key is needed, and there is none in this repository.
`CONFIG_BOOT_SIGNATURE_TYPE_NONE` is set: the dongle enters DFU mode only while its button is held
during reset, so loading firmware already needs physical access. `CONFIG_BOOT_VALIDATE_SLOT0` is
still on, so the image's SHA256 is checked before it is booted — a corrupt image is caught, an
unauthorised one is not. See `conf/mcuboot.conf` for what a product board would set instead.

**Use `EXTRA_DTC_OVERLAY_FILE`, never `DTC_OVERLAY_FILE`.** The latter *replaces* MCUboot's own
`boot/zephyr/app.overlay`, which is what chooses `zephyr,code-partition = &boot_partition`. Without
it the choice falls back to the board's `slot0_partition` and the bootloader links at 0x10000, on
top of where the application goes. Nothing reports this; the flash simply does not boot. After
building, confirm the image really starts at zero:

```console
arm-none-eabi-objdump -h build/zephyr/zephyr.elf | head -n 8
```

## Flashing

The bootloader is flashed once, with a debug probe:

```console
west flash
```

Afterwards the dongle takes application images through USB DFU: hold the user button while
resetting, and the application LED lights to say it is in DFU mode. The image to load is
`build/zephyr/zephyr.signed.confirmed.hex` from an application built with
`overlays/si4467_dongle-mcuboot.conf`, into the `image-0` partition at 0x10000. Zephyr calls that file
`.signed.` whether or not a key was used; here it carries a header and a SHA256 and no signature.
