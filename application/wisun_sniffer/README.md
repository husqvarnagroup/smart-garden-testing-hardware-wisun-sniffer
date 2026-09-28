<!--
SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH

SPDX-License-Identifier: GPL-3.0-or-later
-->

# Wi-SUN Sniffer

## Overview

Receives Wi-SUN FAN frames with the Si4467 transceiver on the dongle board and streams them to
Wireshark as PCAP-NG using the IEEE 802.15.4 TAP link type (DLT 283).

The Si4467 runs in EZRadioPRO boot mode with `GLOBAL_CONFIG:PROTOCOL` set to `IE154G`, which makes
the packet handler parse the PHY header itself: it picks the FCS length, enables or disables
de-whitening and receives the right number of bytes, all derived from the received PHR. A single
configuration therefore captures every valid PHR variant.

There is no radio driver under the application: the transceiver is driven directly from
`src/si4467_wisun.c`, over SPI and the nIRQ line.

## PHY

The PHY is selected at run time from the three numbers the standard names one with: a regulatory
domain, a ChanPlanID and a PhyModeID, plus a channel. Defaults come from Kconfig and boot as the EU
FAN profile:

| Parameter                  | Default                                  |
|----------------------------|------------------------------------------|
| Regulatory domain          | EU (3)                                   |
| ChanPlanID                 | 32 (`863_870_100`)                       |
| PhyModeID                  | 0x01 (legacy mode #1a)                   |
| Channel 0 center frequency | 863.1 MHz, 100 kHz channel spacing       |
| Modulation                 | 2-FSK, 50 ksym/s, modulation index 0.5   |
| Preamble / SFD             | 8 octets `0x55` / `0x904E`               |
| FCS                        | 4 octets (the PHR is honoured per frame) |

Every regulatory domain and channel plan of Wi-SUN PHY 2.03 tables 7 and 8 can be selected, and the
firmware refuses combinations the standard does not list. Of the operating modes only those with a
modulation index of 0.5 can be programmed — PhyModeID 0x01, 0x03 and 0x05, at 50, 100 and 150 ksym/s,
and their forward error correcting counterparts 0x11, 0x13 and 0x15. The OFDM modes are a different PHY
altogether.

A coded mode is the same signal on the air as the uncoded one it is numbered above: the same symbol
rate, the same modulation index, the same channel spacing. What differs is that the PHY header and
the payload are convolutionally encoded and interleaved, and that a different start-of-frame
delimiter announces them — there is no bit in the PHY header saying so, which is why a coded mode is
selected rather than detected. The transceiver cannot decode any of it, so the deinterleaver, the
Viterbi decoder and the PN9 de-whitener are in the firmware, in `src/si4467_fec.c`.

The transceiver tunes from 142 to 1050 MHz, so the non-EU domains program correctly, but the
dongle's matching network and antenna are designed for 863 to 876 MHz and reception outside that
range will be poor. Selecting such a plan logs a warning; ChanPlanID 112 and 113 (2.4 GHz) and 144
and 145 (779 MHz) fall outside the synthesiser altogether and are refused.

Only one WDS generated radio configuration is in the tree, for the default PHY. The rest is derived
from it at run time: the synthesiser is programmed from ChanCenterFreq0 and ChanSpacing, and the
modem's decimation, oversampling and deviation from the symbol rate. The derivation is described in
`src/si4467_wisun.c`; `wisun_sniffer phy` prints what it came to, including the receive bandwidth
that results.

## Building and running

From the west workspace top:

```console
west build -p auto -b dongle/nrf52840 wisun-sniffer/application/wisun_sniffer
west flash
```

That build starts at the reset vector and needs a debug probe. `sample.wisun_sniffer.mcuboot` in
`sample.yaml` builds the same firmware to load through MCUboot instead, which lets a dongle be
updated over USB DFU:

```console
west build -p auto -b dongle/nrf52840 wisun-sniffer/application/wisun_sniffer \
    -- -DEXTRA_CONF_FILE=overlays/dongle-mcuboot.conf
```

No key is needed. The image is unsigned: `CONFIG_MCUBOOT_GENERATE_UNSIGNED_IMAGE` asks `imgtool`
for the MCUboot header and the SHA256 that MCUboot needs, without a signature. The dongle's
MCUboot is built with `CONFIG_BOOT_SIGNATURE_TYPE_NONE` and would not check one anyway — updating
a dongle needs physical access to its button — though `CONFIG_BOOT_VALIDATE_SLOT0` means the
SHA256 is still verified before the image is booted.

The bootloader itself is built once from `application/mcuboot/`, which has its own `README.md`;
the application is then `build/zephyr/zephyr.signed.confirmed.hex`, into the `image-0` partition
at 0x10000. With MCUboot in place, holding the dongle button during reset enters USB DFU, which
replaces the firmware without a debug probe. This variant also turns on the `mcuboot` shell
command, which reports the version and state of the image that is running.

The dongle enumerates with two CDC ACM interfaces:

- interface `if00` — console, log and shell
- interface `if02` — binary PCAP-NG capture stream

## Device names (optional)

The two interfaces are numbered in enumeration order, so which `/dev/ttyACM*` is the console
depends on what else is plugged in. `/dev/serial/by-id/` is stable and is what the capture script
uses, but the names are long. These udev rules add short symlinks for working at the shell; nothing
in the firmware or in `tools/` depends on them, so they are entirely optional:

```text
# /etc/udev/rules.d/99-wisun-sniffer.rules
SUBSYSTEM=="tty", ATTRS{idVendor}=="1915", ATTRS{idProduct}=="b823", ENV{ID_USB_INTERFACE_NUM}=="00", SYMLINK+="tty-wisun-sniffer-console"
SUBSYSTEM=="tty", ATTRS{idVendor}=="1915", ATTRS{idProduct}=="b823", ENV{ID_USB_INTERFACE_NUM}=="02", SYMLINK+="tty-wisun-sniffer-pcapng"
```

They apply to a dongle plugged in afterwards, or to one already connected after:

```console
sudo udevadm control --reload
sudo udevadm trigger --subsystem-match=tty
```

which gives `/dev/tty-wisun-sniffer-console` and `/dev/tty-wisun-sniffer-pcapng` alongside the
`by-id` paths.

The product ID is the one this application sets in `boards/dongle_nrf52840.conf`
(`CONFIG_USB_DEVICE_PID=B823`); `1915` is Nordic's vendor ID, which the board keeps. The match is
therefore on the firmware rather than on a particular dongle: with two sniffer dongles connected
both would claim the same names, and only `/dev/serial/by-id/`, which carries the serial number,
tells them apart.

## Capturing

The capture interface carries a plain PCAP-NG stream: a section header block and an interface
description block, then one enhanced packet block per frame. Each frame is wrapped in an
IEEE 802.15.4 TAP header, followed by the PSDU and its FCS. The header describes how the frame was
received, which Wireshark shows as a pseudo-header above the dissected frame:

| TLV                  | Contents                                                                                                                                                   |
|----------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `FCS_TYPE`           | 16 or 32 bit CRC, taken from the PHY header of each frame                                                                                                  |
| `RSS`                | signal strength in dBm, latched when the sync word was detected                                                                                            |
| `BIT_RATE`           | bit rate of the PHY in use, 50000 bps by default                                                                                                           |
| `CHANNEL_ASSIGNMENT` | the channel being listened on, on channel page 9 (SUN)                                                                                                     |
| `PHY_ENCODING`       | band and modulation of the PHY in use; by default band 4 (863 MHz), type 1 (FSK-B), mode 8 (50 kb/s, 2-FSK, modulation index 0.5, 100 kHz channel spacing) |

Frames are buffered before they are written to USB, so that a host which stops reading for a moment
does not corrupt the capture. If the buffer fills, whole frames are left out rather than a block
being cut short: the stream stays well formed and a reader keeps its place, at the cost of a gap.
`wisun_sniffer stats` counts the frames lost that way, and
`CONFIG_WISUN_SNIFFER_CAPTURE_BUF_SIZE` sets how large a burst can be absorbed.

`tools/wisun_sniffer_capture.py` captures without Wireshark having to know anything about the
dongle. It needs `pyserial`:

```console
tools/wisun_sniffer_capture.py | wireshark -k -i -

# or through a named pipe, which it creates and then waits on
tools/wisun_sniffer_capture.py --fifo /tmp/wisun.pcapng &
wireshark -k -i /tmp/wisun.pcapng

# writing a file, on a PHY selected for the occasion
tools/wisun_sniffer_capture.py --chan-plan 33 --phy-mode 3 --channel 10 -w capture.pcapng
```

The script is not a convenience wrapper. A reader has to see the section header before it will
accept anything else, and it only looks for it once, when it opens the stream. The firmware writes
one when DTR goes up on the capture port, which is the only way it can tell that anything is
listening — and `cat` never raises DTR, so it is indistinguishable from no reader at all. The
script takes DTR low, holds it there long enough for the firmware to notice, and raises it again,
so a section begins even if the previous capture left the line up. It then starts forwarding at
that section header rather than wherever the transceiver happened to be, and rebases frame
timestamps from the device uptime onto the host clock (`--device-timestamps` leaves them alone; the
spacing between frames is the same either way).

When a capture names a PHY — from the command line, or from Wireshark's interface options — the
script programs it and then checks that the firmware really is on it, rather than taking silence for
agreement.

A dongle that has just been restarted is not listening yet when its device node appears, so a
capture started at that moment writes into a console that drops the command. The script asks again
rather than waiting longer, which is why starting a capture on a dongle that is still coming up
works rather than quietly capturing on the PHY it booted with. If it never answers, the capture
still runs and the reason is reported at the end.

A PHY that is not the one asked for is reported with both named:

```text
the firmware is listening to domain 3 ChanPlanID 32 PhyModeID 0x01 channel 0, not the
domain 3 ChanPlanID 32 PhyModeID 0x01 channel 15 it was asked for
```

Under Wireshark that arrives as "Error from extcap pipe: …" when the capture stops, which is the
only channel an extcap program has for saying something went wrong. The capture still runs, on
whatever PHY the dongle is actually on.

Rebasing adds one offset to every frame and nothing else, which is what keeps the spacing intact.
The offset is measured over the first half second of frames and then left alone for the rest of the
capture: a capture opens with the dongle draining whatever it staged while nothing was reading, so
the frames behind that backlog arrive late and the first estimates are the worst ones. Frames are
held back for that half second and written out together, so the first of them appears a moment
after it was captured; everything after that is written as it arrives.

For a quick look without it, `wisun_sniffer section` on the console begins a section on demand.
Start the reader first, then ask:

```console
cat /dev/tty-wisun-sniffer-pcapng > capture.pcapng &
# then, on the console interface
wisun_sniffer section
```

Everything from that header on is a well-formed capture. What matters is what precedes it: a
dongle that has been receiving with nothing attached has frames staged from before the reader
arrived, and they go into the file first, so it opens with the tail of an older section and
Wireshark refuses it. Reading a port that has just been drained — after a capture with the script,
or on a dongle that has not heard anything yet — gives a file that starts at the header and opens
cleanly. The script has no such constraint, because it looks for the header and starts there, and
it stays the way to take a capture that matters.

### The LEDs

Three of the dongle's LEDs say something, and they are driven by two different chips:

| LED         | Driven by                      | Lit when                                      |
|-------------|--------------------------------|-----------------------------------------------|
| Application | nRF52840 `led0`                | a capture tool has the capture port open      |
| RX          | Si4467 GPIO3, `VALID_PREAMBLE` | a frame is arriving                           |
| TX          | Si4467 GPIO2, `TX_STATE`       | never — this application has no transmit path |

The application LED follows the same DTR signal as everything else here, so it agrees with
`trace auto` and with the section header: lit means a reader is attached and frames are going out to
it, dark means they are being received and dropped on the floor. It is deliberately not a traffic
light — what is worth seeing from across the room is whether the dongle is being read at all, and a
light that flickers once per frame cannot say that. A reader that never raises DTR (`cat`, a shell
redirect, some USB-serial bridges) leaves it dark even while it is reading, for the same reason such
a reader needs `wisun_sniffer section`.

The RX and TX LEDs are wired to the transceiver rather than to the nRF52840, so they show what the
radio is doing rather than what the firmware thinks. They follow its state machine directly, which
costs the firmware nothing and cannot drift out of step with it.

The RX LED lights for the duration of each frame: `VALID_PREAMBLE` goes high when the demodulator
finds a preamble and stays high until the packet has been received, which is the longest-lived of
the signals marking a frame. At 50 kbit/s that is roughly 9 ms for a 48-octet frame and about a
third of a second for the largest a Wi-SUN PHY allows — visible, but on quiet air expect a flicker
rather than a glow. Starting at the preamble rather than at the sync word also means it flickers
occasionally on noise that trips preamble detection and never becomes a frame; `wisun_sniffer stats`
shows that as preamble detects without matching frames. The TX LED is configured for symmetry and
stays dark, there being nothing here that transmits.

The application LED only exists on dongles from hardware revision 0.4.0 onwards; on an earlier one
the pin is not connected and there is nothing to see. The RX and TX LEDs are on every revision.

## Capturing from Wireshark directly

The same script is Wireshark's extcap interface, which makes the dongle appear in its interface
list so that capturing needs neither a fifo nor a shell pipeline. Put it in your personal extcap
directory, which `tshark -G folders` reports as `Personal Extcap path`:

```console
mkdir -p ~/.local/lib/wireshark/extcap
ln -s "$PWD/tools/wisun_sniffer_capture.py" ~/.local/lib/wireshark/extcap/
```

The dongle then shows up as *Wi-SUN Sniffer Dongle `<serial>`*. Its interface options select the
PHY — regulatory domain, ChanPlanID, PhyModeID and channel — and choose whether frames carry device
or host timestamps. The whole PHY goes to the firmware in one command, which validates it and
reports on the console if it is not a combination the standard allows.

Capturing takes the same path either way; only how the options arrive differs.

### The toolbar

While a capture runs, Wireshark shows a *Wi-SUN sniffer* toolbar above the packet list (*View →
Interface Toolbars* if it is hidden). It offers the same settings again, this time without stopping
the capture — which is the point of it, because finding the channel a device is heard on means
trying them:

| Control                                | Effect                                                                            |
|----------------------------------------|-----------------------------------------------------------------------------------|
| Domain, ChanPlanID, PhyModeID, Channel | Reprogram the transceiver, one field at a time                                    |
| Device timestamps                      | Switch between the device uptime and the host clock, for frames from here on      |
| Statistics                             | Show the receive counters (the `stats` command below), and keep a copy in the log |
| Log                                    | What the capture has been asked to do and what came of it                         |
| Help                                   | This documentation                                                                |

The firmware settles the rest of the PHY around whichever field was changed, because most of the
combinations on the way from one PHY to another are not allowed: selecting ChanPlanID 33 also moves
the operating mode to PhyModeID 0x03, since 33 will not run the mode 32 was using. The toolbar is then
set from what the dongle reports, so it shows what was really chosen rather than what was asked
for. A PHY the firmware will not take at all is reported in a dialog naming the part that is wrong
— a reserved ChanPlanID, a pairing the regulatory domain does not allow — and the toolbar goes back
to the PHY still in use.

Everything a control does happens on a thread of its own, so a change never interrupts the capture;
frames received on the previous PHY may still arrive just after one.

Wireshark keeps toolbar settings from one capture to the next, but the capture that starts is the
one the interface options describe: the toolbar is set from them when it appears, so it always
shows what the dongle was actually told to do.

## Shell

The console interface offers `wisun_sniffer` commands for bring-up and diagnosis. Numbers are read
the way C reads them — plain decimal, `0x` for hex — and an argument that is not a number, or is too
large for what it selects, is refused with a message rather than quietly turned into something else.
A PHY that is not one the standard lists is refused the same way, naming the part that is wrong
rather than reporting an errno and leaving the reason in the log:

```console
$ wisun_sniffer plan 99
cannot listen to domain 3, ChanPlanID 99, PhyModeID 0x01: ChanPlanID 99 is reserved
```

| Command                                    | Purpose                                                                                                                                                              |
|--------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `version`                                  | Application version, the commit it was built from, the board and the Zephyr version                                                                                  |
| `info`                                     | Transceiver part and firmware revision, and the PHY                                                                                                                  |
| `phy [domain plan mode [channel [force]]]` | Show the PHY being listened to, or set all of it at once                                                                                                             |
| `domain [name\|code]`                      | Show or set the regulatory domain, or list them all                                                                                                                  |
| `plan [ChanPlanID]`                        | Show or set the channel plan, or list the domain's plans                                                                                                             |
| `mode [PhyModeID]`                         | Show or set the operating mode, or list the plan's modes                                                                                                             |
| `channel [n [force]]`                      | Show or set the channel to listen on. A channel the plan does not have is refused, since nothing keeping to the standard transmits there; `force` tunes to it anyway |
| `stats [reset]`                            | Receive counters, from preamble detects to bad FCS, plus the frames dropped from the capture stream; `reset` starts them again from zero                             |
| `rssi [channel] [repeat]`                  | Measure the current RSSI, to check the frequency setup                                                                                                               |
| `inject [count]`                           | Feed a canned frame into the capture stream, so the Wireshark path can be tested without a transmitter                                                               |
| `section`                                  | Begin a new PCAP-NG section, for a reader that cannot raise DTR                                                                                                      |
| `trace [off\|on\|auto]`                    | Whether a line is logged for each frame received. `auto`, the default, stops while a capture tool is attached                                                        |
| `raw [0\|1]`                               | Print every octet drained from the FIFO instead of interpreting it, to tell a demodulation problem apart from a packet handler misconfiguration                      |
| `prop <group> <start> [count]`             | Read transceiver properties                                                                                                                                          |
| `setprop <group> <index> <value>`          | Write a transceiver property                                                                                                                                         |

### Frames on the console

Each frame received is announced on the console, which is what bring-up is done with:

```text
[00:04:12.881,225] <inf> wisun_sniffer: RX ch=0 len=48 rssi=-43 dBm fcs=4B/ok wht=1 afc=0
```

It stops as soon as a capture tool attaches, because by then the frames are in front of you in
Wireshark and the line is only traffic on the interface that also carries the shell — the one thing
here that scales with how busy the air is. `trace on` keeps it during a capture, `trace off` stops
it altogether, and `trace` on its own says which of the three is in force and what that currently
means.

It is a log message, so `log enable wrn wisun_sniffer` silences it as well; the separate command
exists because the log level cannot express "unless somebody is capturing", and levelling the
module off would take the PHY and capture messages with it. `raw` output is unaffected by either:
it is printed rather than logged, since a raw dump is longer than the log buffer will carry.
