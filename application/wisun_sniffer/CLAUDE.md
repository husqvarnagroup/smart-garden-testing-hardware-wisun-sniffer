<!--
SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH

SPDX-License-Identifier: GPL-3.0-or-later
-->

# Working on `wisun_sniffer`

Notes for AI assistants. `README.md` covers what the application is, the PHY it is configured
for, how to build it and what the shell offers — read it first and do not duplicate it here. This
file records what the code cannot tell you: which vendor documentation is wrong, how to prove a
change actually works against real traffic, and what is still broken.

## What must not be edited

`src/ext/` holds files this application did not write and must not change:

- `radio_config_wisun.h` is WDS output. It has its own `.clang-format` with `DisableFormat: true`
  and a `REUSE.toml` annotation. If the PHY needs to change, ask for a regenerated file.
- `si4467_regs.h` (command opcodes and property groups) and `si4467_patch.h` (the errata blob) came
  from an earlier Si4467 driver and are read-only artefacts. The register header only enumerates the
  property indices *that* driver needed, which is why `si4467_wisun.c` defines the rest itself
  rather than extending it.

Repository-wide conventions are in the top-level `CLAUDE.md`. The short version: the formatting
configuration is upstream Zephyr's, so C is **tabs at 100 columns**, and both
`clang-format --dry-run --Werror application/wisun_sniffer/src/*.c application/wisun_sniffer/src/*.h`
and `../../zephyr/scripts/checkpatch.pl --no-tree -f` have to be clean on what you touched.

The hand-aligned tables in `wisun_phy.c` are inside `clang-format off` regions on purpose — their
columns carry meaning that reflowing destroys. The indentation in them is still tabs; only the
alignment after the brace is spaces.

## The two build configurations

`sample.yaml` lists `sample.wisun_sniffer`, which starts at the reset vector, and
`sample.wisun_sniffer.mcuboot`, which adds `overlays/dongle-mcuboot.conf` and loads through
MCUboot. The firmware is identical; only where it is linked and how it gets onto the dongle
differ. Develop against the plain one — it flashes with one command — and check the MCUboot
variant builds before touching `prj.conf`, `boards/dongle_nrf52840.conf` or the overlay.

Two things about the MCUboot build are not obvious:

- **`CONFIG_MCUBOOT_SIGNATURE_KEY_FILE=""` and `CONFIG_MCUBOOT_GENERATE_UNSIGNED_IMAGE=y` go
  together, and the second is the one that matters.** An empty key on its own means "sign it
  yourself" and produces no image at all. What MCUboot needs in front of the firmware is the
  header and the SHA256, and those are `imgtool`'s work rather than the key's — the resulting
  `zephyr.signed.confirmed.hex` differs from a signed one only by the absent `KEYHASH` and
  `ECDSASIG` TLVs. Do not reintroduce a key to "fix" signing: no bootloader here verifies one.
- The overlay has to enable `CONFIG_FLASH` and `CONFIG_FLASH_MAP` itself. This application keeps
  nothing in flash, so unlike applications with settings storage it does not get them for free,
  and the image manager behind `CONFIG_MCUBOOT_SHELL` would silently fail its dependencies.

The bootloader is built separately, from `application/mcuboot/`, whose `README.md` has the
commands. It uses `EXTRA_DTC_OVERLAY_FILE` rather than `DTC_OVERLAY_FILE` on purpose: the latter
*replaces* `bootloader/mcuboot/boot/zephyr/app.overlay` instead of adding to it, so the chosen
`zephyr,code-partition` falls back to the board's `slot0_partition` and MCUboot links at 0x10000
on top of the application. Confirm any bootloader image spans 0x0 before flashing it.

## The Si4467 configuration, and where the documentation lies

The chip runs in EZRadioPRO boot mode with `GLOBAL_CONFIG:PROTOCOL = IE154G`
(`si4467_wisun.c:56`), so the packet handler parses the PHY header itself. That answers the
"boot in 802.15.4 mode" question: the *dedicated* 802.15.4 boot mode gives no packet-level access
and needs a Silabs MAC stack, whereas `IE154G` in the PRO boot mode fully supports the 802.15.4g
PHY (datasheet §9.3).

Four settings deviate from what WDS emits. **Every one of them stops frames arriving entirely, and
three contradict the API reference.** They are all in `si4467_configure_packet_handler()` and
`si4467_start_rx()`. Do not "clean them up" back to the vendor values.

| Setting | Value | Why |
|---|---|---|
| `PKT_CONFIG1` `BIT_ORDER` | `LSBIT_FIRST` | 802.15.4g sends the low-order bit of every octet first, in the PHY header as much as in the PSDU. The API reference claims `IE154G` overrides this bit. **It does not.** Left at MSB-first the PHR reads back bit-reversed (`10 62` instead of `08 46`), so the radio derives a wrong length and never sees that the PSDU is whitened. |
| `START_RX` `RXINVALID_STATE` | `READY` | Was `RX`, which makes the chip silently restart on a failed CRC. `PACKET_RX` never fires and the frame vanishes without a trace. |
| `PKT_LEN_ADJUST` | `4` | `IE154G` sizes the PSDU field as "length from the PHR **minus** the FCS" and keeps the FCS octets for its own CRC engine, so they never reach the host. Wireshark needs them. AN633 §10.10's worked examples show the same stripping; the API reference's claim that the FCS reaches the FIFO is simply wrong. |
| `PKT_CRC_CONFIG` | `0x00` | Nominally "no CRC engine", but `IE154G` overrides it and the engine runs anyway — seeded with all zeroes where IEEE 802.15.4 uses all ones, so it **rejects good frames**. Its verdict is ignored; `check_fcs()` (`si4467_wisun.c:716`) does it in software. |

Consequences worth keeping in mind:

- A frame is complete on `PACKET_RX` **or** `CRC_ERROR`. Both are handled; a sniffer must report
  damaged frames rather than hide them.
- `ALT_CRC_ERROR` is deliberately not used. `IE154G` runs the 16- and 32-bit engines in parallel,
  so on a 4-octet FCS the 16-bit engine reaches its meaningless verdict two octets early. Treating
  it as end-of-frame declares good frames corrupt.
- SPI reply framing is `[dummy][CTS][response…]` — CTS is at **index 1** (`CTS_DUMMY_OCTETS`,
  `si4467_wisun.c:114`). MISO idles high, so reading index 0 appears to work and silently shifts
  every response by one octet.
- `RX_FIFO_THRESHOLD` is 16, well below the 64-octet FIFO, so a false sync detect is recognised
  within a few milliseconds and a real frame arriving just after it is still caught.

## Deriving a PHY instead of generating one

Only one WDS radio configuration is in the tree, for EU ChanPlanID 32 with PhyModeID 0x01. Every other
PHY is computed at run time in `si4467_wisun_set_phy()`. The reason it works is that the receive
chain is defined in units of its own sample rate: a fixed divide-by-eight after the A/D converters,
then a polyphase pre-decimator, then two CIC stages, and what comes out clocks the channel filter,
the bit clock recovery loop and the AFC alike. **Halve the total decimation and the filter
bandwidth doubles while the oversampling per symbol, the loop gains and the filter coefficients all
stay exactly as they were.** So twice the symbol rate at twice the deviation needs no new
coefficients — only half the decimation.

This is not a guess. It was checked against a second WDS configuration for the same crystal at
100 ksym/s — which is not in this tree — and the two differ in exactly the properties computed here.
`pick_decimation()` and the formulas around it reproduce both byte for byte:

| | wisun (50 ksym/s) | the 100 ksym/s reference |
|---|---|---|
| `DECIMATION_CFG1` / `CFG0` | `0x20` / `0x20` | `0x10` / `0x20` |
| `BCR_OSR` | `0x0041` | `0x0041` |
| `BCR_NCO_OFFSET` | `0x07E07E` | `0x07E07E` |
| `AFC_WAIT` | `0x12` | `0x23` |

The argument only holds while the **modulation index stays at 0.5**, since that is what fixes the
deviation as a fraction of the sample rate — WDS does change `AFC_GAIN` when it differs. That is
why `wisun_phy.c` marks only PhyModeID 0x01, 0x03 and 0x05 as programmable.

Two traps in this area:

- `MODEM_CLKGEN_BAND:SY_SEL` must stay set. The published `FREQ_CONTROL_INTE`/`FRAC` formula
  assumes the divide-by-two prescaler; clearing the bit puts the receiver on a different frequency
  and **not one frame arrives**, with no other symptom.
- `FREQ_CONTROL_FRAC` runs from 2^19 to 2^20, so the integer part comes out one lower than the
  ratio suggests. `INTE = (ratio << 19) >> 19 - 1`, not `floor(ratio)`.

PhyModeID 0x05 is derived but has never been received: no border router here is configured for it, and
its decimation cannot reach the usual oversampling of 8.125, so it runs at 10.875 with a receive
bandwidth about 1.8x wider than the signal needs.

## Forward error correction, and how far it has got

Wi-SUN PHY 2.03 numbers a coded PhyModeID `0x10` above its uncoded counterpart, so 1, 3 and 5 have
FEC variants 0x11, 0x13 and 0x15. **The transceiver cannot decode them.** The datasheet says so in
as many words (§9.3.6): it can tell the host whether FEC was used and nothing more. Everything past
the demodulator is therefore ours, in `si4467_fec.c`.

What that file does, and the order it has to do it in, is the one thing worth getting right.
A transmitter whitens the PSDU, puts the unwhitened PHR in front of it, encodes *that whole block*,
appends tail and padding, and interleaves the result (IEEE 802.15.4-2020 §19.3.2, figure 19-7). So
whitening lives **inside** the coded block, and de-whitening belongs after the Viterbi decoder,
over the PSDU alone. The transceiver's own de-whitener has to be off — left on it would be undoing
PN9 over convolutional code symbols.

The interleaver block is 16 bits wide, which is exactly the PHY header. That is not a coincidence
to be admired but the thing that makes a coded frame receivable: the first block decodes to the
PHR on its own, the PHR gives the PSDU length, and `wisun_fec_coded_len()` turns that into the true
on-air length. **The length in a coded PHR is the length before encoding — about half what
arrives** — which is why `PKT_LEN_FIELD_SOURCE` framing cannot be used and `INFINITE_LEN` is.

Three things were measured rather than read, and are not in any document:

- **The sync word register holds the SFD bit-reversed per octet.** The WDS configuration loads
  `09 72` for an SFD the standard prints as `0x904E`, because the PHY sends the low-order bit of an
  octet first. The coded SFD `0x6F4E` therefore goes in as `F6 72`. Read `prop 0x11 0x00 10` on a
  working dongle before trusting any change here.
- **`SYNC_CONFIG2`/`SYNC_BITS2` accept writes and survive a PHY change**, so dual sync word can be
  configured. Whether it *works* is another matter: the API reference tags every value of
  `INFO_FLAGS:SYNC_TRIGGER` — the only way to ask which sync word matched — as "Feature Available:
  revC2A", and the errata's own column headings call this part **Si4467-A2A**. The dongle reports
  `Si4467 rev 2 (ROM 6)`. Assume `SYNC_TRIGGER` is unavailable until someone demonstrates
  otherwise, which is why a coded PHY here listens for the coded SFD *only* rather than both.
- **`INFO_FLAGS` is the ninth octet of the `GET_MODEM_STATUS` reply**, one past what
  `si4467_get_modem_status()` reads today.

**None of the receive path has been run against a coded transmitter.** `si4467_fec.c` is verified
only on `native_sim` (`tests/application/wisun_sniffer/fec/`): PN9 against the thirty bits §16.2.3
prints, and the decoder against a reference encoder written separately from it, including a sweep
that flips every bit of a frame in turn. That says the mathematics is right; it says nothing about
the transceiver.

### What the air has confirmed, and what is still stuck

**The coded SFD is right, and the traffic really is coded.** Measured on the border router's own
network (it reports ChanPlanID 33, PhyModeID 0x13, `allowed_channel: 0` — channel 0, not 10):

| Sync word | Preamble detects | Sync detects |
|---|---|---|
| `F6 72`, the coded SFD `0x6F4E` | ~22 | ~22 |
| `09 72`, the uncoded SFD `0x904E` | 29 | **0** |

Nothing matches the uncoded SFD and nearly every preamble matches the coded one, which settles
both the SFD value and the per-octet bit reversal far better than reading a table does.

**Two things had to be right before a single octet arrived**, and both looked like they should not
have mattered:

- **`START_RX:RX_LEN` must state the length on a coded PHY.** It is left at zero for IE154G because
  the PHY header supplies the length. In generic mode zero is a *zero length packet*, not an
  invitation to work it out: the sync word matched, and then no FIFO interrupt ever arrived, no
  packet completed, and nothing was ever drained. `INFINITE_LEN` behaved the same way and was
  abandoned for a fixed field size.
- **A raw dump must be logged, not printed.** `dump_raw()` builds one `printk()` line, and at 512
  octets that is over 1024 characters against a `CONFIG_LOG_BUFFER_SIZE` of 1024, so the whole line
  is dropped. Every raw dump of a coded frame vanished this way until it became a
  `LOG_HEXDUMP_INF`. The existing comment about this hazard is about the uncoded path; it applies
  twice as hard here, because a coded frame is twice as long.

  **Beware of diagnosing this one too quickly, though.** Later, whole hex dump chunks and the
  summary lines between them went missing at a capture size of 1024 octets, and that was put down
  to the same buffer. It was never isolated, and there was a `picocom` open on the console at the
  time: two readers on one tty split the stream between them, so a script silently misses whatever
  the other reader took first, which looks exactly like a dropped log message. The capture size was
  reduced to 512 on the strength of that reasoning. Nothing depends on it -- a live coded reception
  is bounded by the frame's own length, not by this -- but the cause is unproven, and **the first
  thing to check when console output goes missing is `fuser` on the port**, not the log
  configuration.

**The capture path is calibrated and correct.** This was settled by borrowing an oracle. With the
network temporarily switched to its uncoded mode, the same frames were received twice: once through
the ordinary IE154G path, which decodes them and checks their FCS, and once through the coded
path's raw capture with the sync word overridden to the uncoded SFD. The frame's own octets appear
in the raw capture at **bit offset zero, least significant bit first**, five to ten times above the
noise floor of every other bit order and offset. So the capture begins where the frame begins, the
bits are in the order `si4467_fec.c` assumes, and the packet handler is not transforming the stream
in generic mode. Borrow that oracle again before doubting any of it.

**The whitening is applied after the coding, and only to the PSDU's code symbols.** That is the
shape of a coded frame, measured by decoding real traffic:

| Part | Encoded | Interleaved | Whitened |
|---|---|---|---|
| SHR (preamble, coded SFD `0x6F4E`) | no | no | no |
| PHY header, 16 bits — the first interleaver block exactly | yes | yes | **no** |
| PSDU | yes | yes | **yes**, PN9 from its seed at the first PSDU code symbol |

Receiving is therefore: descramble everything past the first four coded octets, deinterleave,
Viterbi decode. What falls out is the header followed by the PSDU **already in plaintext** — there
is no second de-whitening, and applying one destroys the frame.

**This is what the standard says, and the measurement only looked like a contradiction because
the clauses were read out of order.** IEEE 802.15.4-2020 19.3.2 is the *reference modulator* — a
transmit-side data flow — and the steps follow its numbering: 19.3.5 the coding, 19.3.6 the
interleaving, then 19.4 the whitening. 19.4 defers to 16.2.3, which starts the generator at "the
first bit of the PSDU"; in a coded frame that is the PSDU's first code symbol, and the header ahead
of it is left alone. Both halves of what was measured are in the text.

The trap is that "whitening covers the PSDU, never the header" is easy to carry over from the
uncoded PHY, where it means the PSDU's own octets. A decoder built on that reading recovers
nothing at all: it hands whitened symbols to a Viterbi decoder, which cannot tell them from noise,
and every search run against it comes back empty for the right reason and the wrong cause.

**The PHY header is sent most significant bit first, the rest of the frame least significant bit
first.** The RAIL documentation says so and it is load-bearing here: read the header's decoded bits
the way the PSDU's are read and it comes out as `0x1071` rather than `0x088e`.
`wisun_fec_decode_phr()` returns it as a value for that reason — there is no octet order to hand
back that would not be a trap.

**A clean link decodes with no bit errors at all.** The path metric is zero for every complete
capture, which is what two devices on a bench should give and what the uncoded path already
showed. A metric of "nearly zero" is not success here; it means something in the chain is slightly
wrong. The first version of this decode sat at five symbol errors per frame, all of them inside
the first interleaver block, which is exactly how the unwhitened header gave itself away.

### Receiving coded frames, and what a good run looks like

The decoder is in the receive path, so a coded frame reaches the same callback an uncoded one does
and goes to Wireshark the same way. Measured against the border router on EU ChanPlanID 33,
PhyModeID 0x13, channel 0, with `ping` driving the traffic:

```text
preamble detect : 22
sync detect     : 19
frames          : 18      bad FCS / bad PHR / timeouts : all 0
RX ch=0 len=169 rssi=-47 dBm fcs=4B/ok wht=1
RX ch=0 len=142 rssi=-55 dBm fcs=4B/ok wht=1
```

Same bar as the uncoded PHY: **every sync detect should become a frame**, and the lengths should be
the ones the uncoded mode shows for the same traffic — 169, 142, 135, 78, 57 and 56 here.

The whole path was walked as well, not just the counters. `tools/wisun_sniffer_capture.py
--chan-plan 33 --phy-mode 0x13 --channel 0 -w <file>` gives a capture whose blocks are one section
header, one interface description and one enhanced packet per frame, link type 283, with every
octet of the file accounted for by the walk and each frame's PSDU the one the console reported.

**A coded frame that needs any corrections at all is a warning sign on a bench.** The decoder
reports how many code symbols it had to overrule, and on a link this short a real frame needs none.
Symbols carrying no frame cost about a quarter of themselves, so the receive path discards anything
over an eighth and counts it as a bad PHY header rather than reporting it. That guard exists
because a frame did get through once with a length of 509 and a 2 octet FCS, which nothing on this
network sends: a 16 bit CRC accepts noise one time in 65536, and the length field alone cannot tell
you it was never a frame. The correction count can.

### Catching the reply, and the two things that stopped it

A frame with the acknowledgment request bit set is followed by one, and **an acknowledgment's
sync detect lands 2.7 to 3.9 ms after the end of the frame it answers** — measured off the device
timestamps in a capture, which are latched at sync detect and so are the real air spacing. Its own
preamble accounts for much of that, so the receiver has perhaps two milliseconds to be listening
again. Everything below is about spending less than that.

Both faults here looked like the same symptom — a frame reported and its acknowledgment missing —
and neither was what it looked like.

- **The end of a coded frame does not arrive on an interrupt.** The FIFO raises one when it crosses
  `RX_FIFO_THRESHOLD`, and a coded length is almost never a multiple of sixteen, so the last few
  octets sit there until the silence after the frame has been demodulated into the FIFO too: up to
  1.3 ms of air time, spent deaf, in exactly the window the reply arrives in. `drain_tail()` polls
  them out once the PHY header has given the length. **Bound that poll by air time, not by a count
  of polls** — sized as a count it came to just under eight octets' worth, and the frames leaving
  exactly that much outstanding gave up a moment before their last octets landed, which is how the
  169 octet half of a ping exchange lost its acknowledgment while the 142 octet half kept one.
- **The decoder needs one more buffer than the job queue can hold.** A frame taken off the queue is
  no longer on it but is still being read, so what is alive at once is the queue's capacity plus
  the one in flight. With the two equal, the receive thread's next slot is the one the decoder is
  part way through, and four frames in twenty milliseconds — a ping and its acknowledgment —
  overwrites one mid-decode.

That second one is worth recognising by its signature, because it does not present as a race.
The frame still decodes, to something, and is thrown out by the correction guard above: **64
corrections in the 864 code bits of a 50 octet acknowledgment received at −53 dBm.** A tenth of
the symbols wrong at a signal strength where a clean link needs none is not an aerial problem and
should not be chased as one; noise would be nearer a quarter, and a real fault in the decode chain
would not spare the frames around it.

The bar after both: ten rounds of `status` on the DUT saw the status message and its
acknowledgment every time, and ten rounds of `ping` from the border router saw all four frames in
nine of them, with no warning logged in a further fifteen rounds. What is left is rare enough to
be traffic rather than firmware — the one bad round carried background frames on top of the
exchange, so it was six frames deep, not four.

**Read the whole console before concluding anything about a missing frame.** Both of these were
diagnosed from `<wrn>` lines that a filtered view had been dropping; the counters said only that a
sync detect had not become a frame, which is true of every cause and distinguishes none of them.
`bad length` and `bad PHR` each cover several paths, and the log line says which.

### How it was found, and what to do if it needs doing again

Two searches ran before this, and the second one is the technique worth keeping.

The first asked the FCS whether a frame had been recovered, over every orientation of the decoder.
It answered no several thousand times, which says nothing about *why*. The second asked the Viterbi
path metric instead: a true codeword decodes with a metric near zero, random data near 0.25, and
neither answer needs the frame to be aligned or the whitening to be guessed right first. That
turned "no" into a number that could be searched against, and the search space was then large
enough to include the PN9 phase — 511 values, one of which dropped every capture from 0.25 to
0.0056 at once.

**Use the path metric, not the FCS, when nothing decodes.** The FCS is the right oracle once a
frame is nearly right and the wrong one while it is still entirely wrong.

The rest of the negative result stands and is still worth not repeating: with the whitening left
on, no generator polynomial pair, neither trellis, no interleaver permutation in the affine family
and no bit offset produces structure, because none of them can.

**Generating traffic.** Do not wait for the network to say something. The border router console
takes `ping <ipv6 address>`, and its neighbour is in `wisun` output; pinging it while the sniffer
listens turns a twenty minute wait into a repeatable experiment. The DUT on
`/dev/tty-efr32dk-000440313485` reports the same PHY but only echoes `status` without transmitting.

**A dongle usually does not come back on its own after `west flash`, when the tree is being worked
on from a VM.** Flashing resets the dongle, the reset drops it off the USB bus, and a passed-through
device does not re-attach itself to the guest — putting it back is an action on the host, not in
here. Ask for it and carry on; it is not a fault and there is nothing to investigate.

In particular it is not the firmware. Halt the target over SWD after one of these and the program
counter is in `arch_cpu_idle` with `CFSR` and `HFSR` both zero, which is a healthy dongle idling
with nobody listening. Do not read anything into a console that disappears mid-session either, and
do not go looking for a fault in the receive path because the counters stopped moving.

**Ask `lsusb` whether it is there, not `/dev/serial/by-id/`.** The symlinks outlive the device: they
are still listed after the dongle has gone, and opening one then fails with `ENODEV` rather than
`ENOENT`, which reads like a permissions or driver problem and is neither. The dongle can also sit
on the bus for a few seconds after `west flash` before dropping off, so a check run straight after
flashing can pass and the run that follows it still find nothing —
`lsusb | grep 1915:b823` immediately before the run is the one that means anything.

## Verifying a change

Never claim a receive-path change works without running it against the border router. The
counters lie less than the console does. There are two, on different PHYs:

```console
# Border router 1 - Silicon Labs J-Link OB, EU ChanPlanID 32 PhyModeID 0x01, channel 0 only
wisun ping fd12:3456::6ea0:42ff:febd:e61e
# Border router 2 - Silicon Labs J-Link Pro OB Border Router, EU ChanPlanID 33 PhyModeID 0x03,
# channel 10 only (865.100 MHz)
wisun ping fd12:3456::3a39:8fff:fe99:8226

wisun get wisun                 # phy_mode_id, chan_plan_id, allowed_channels, neighbours
```

Match the sniffer to whichever one you are testing against with a single command, which is also
what the extcap script sends:

```console
wisun_sniffer phy 3 32 0x01 0   # border router 1
wisun_sniffer phy 3 33 0x03 10  # border router 2
```

The dongle exposes two CDC ACM interfaces: `-if00` is console/log/shell, `-if02` is the binary
PCAP-NG stream. Address them through `/dev/serial/by-id/usb-Gardena_Wi-SUN_Sniffer_Dongle_*`,
never `/dev/ttyACM<n>` — the numbering moves when devices re-enumerate.

Flashing goes through an Olimex programmer. If `west flash` fails with `LIBUSB_ERROR_ACCESS`, the
shell's process group lacks `plugdev`; wrap the command as `sg plugdev -c '<script>'` rather than
restarting the session.

The counters answer a question about one run, so start it from a known point:
`wisun_sniffer stats reset` zeroes them and the capture drop counter without a reboot, which would
take the selected PHY with it.

A healthy run against a few pings looks like this — **every sync detect should become a frame**:

```text
preamble detect : 44      RX ch=0 len=154 rssi=-46 dBm fcs=4B/ok wht=1 afc=-12
sync detect     : 42
frames          : 42      bad FCS / bad PHR / bad length / fifo errors / timeouts : all 0
capture drops   : 0
```

`capture drops` counts frames left out of the PCAP-NG stream because the host was not reading fast
enough. It should stay at zero for live traffic; anything else means the capture has holes in it,
even though the stream itself is still well formed.

`wisun_sniffer inject` pushes a real captured frame with a valid FCS through the TAP and PCAP-NG
encoders, so the whole Wireshark path can be checked with no transmitter in range. Validate
captures with `capinfos` and `tshark -V`, not by eye: link type must be 283, every frame must
report `FCS: … (Correct)`, and there must be no malformed blocks.

## Debugging reception, when frames do not arrive

`wisun_sniffer raw 1` stops interpreting frames and prints every octet drained from the FIFO as
one hex line (`dump_raw()`, `si4467_wisun.c:1163`). That separates "the demodulator is wrong" from
"the packet handler is misconfigured", which the counters alone cannot.

The technique that actually solved this bring-up: capture raw octets, then **brute-force the
transform space offline using the FCS as an oracle** — per-octet bit reversal, bit offsets 0–7,
PN9 de-whitening on or off, CRC-32 and CRC-16 — over every plausible frame length, and report any
combination whose trailing octets match the computed CRC. A single hit is conclusive; the one that
decoded here contained the ASCII string `Wi-SUN Network` and the border router's EUI-64.

Two details that must be right for that to work:

- **PN9** (IEEE 802.15.4-2020 §16.2.3): the emitted bit is the feedback term `b0 ^ b5`, *not* a
  register bit, which is what makes the sequence start `0000 1111 0111 …` from an all-ones seed.
  Check any implementation against the 30 bits the standard prints before trusting it.
- **FCS-32** is the ordinary Ethernet CRC-32 (reflected, seeded and inverted with all ones),
  transmitted least-significant octet first. FCS-16 is ITU-T CRC-16 seeded with zeroes.

Known-good reference values for regression checks: the border router is
`f0:44:d3:ff:fe:24:3d:b1`, the router node `6c:a0:42:ff:fe:bd:e6:1e`, PAN ID `0x73cf`. A PHR of
`08 46` decodes as 4-octet FCS, whitening on, 70-octet PSDU.

## The per-frame line on the console

`on_frame()` logs one line per frame. It used to `printk()` it, which was wrong three times over:
it ran in the **receive thread** and waited on the console from there, so the one output here that
scales with traffic held up the transceiver to produce it; `printk()` has no module or level, so it
could not be levelled or turned off; and it was not a log line, so the capture script's
`CONSOLE_LOG_LINE` filter did not recognise it and only happened not to mistake it for something.
`LOG_INF` fixes all three — deferred logging packages the message and returns, and
`CONFIG_LOG_MODE_OVERFLOW` drops the oldest message under load rather than blocking a thread that
has a 64 octet FIFO behind it.

**`wisun_sniffer trace` is deliberately not the log level.** The level cannot say "unless somebody
is capturing", and turning the module down to `wrn` would take the PHY and capture messages with
it, which are the ones worth keeping. `auto` — the default — logs frames only while
`pcapng_host_attached()` is false, so the console goes quiet for the duration of a Wireshark
capture and comes back when DTR drops.

`dump_raw()` stays a `printk()`, and that is not an oversight: a raw dump is up to 1024 characters
of hex and `CONFIG_LOG_BUFFER_SIZE` is 1024, so as a log message it would be dropped exactly when
it is wanted. It is off by default and only reached through `raw 1`.

## The three LEDs, and the two chips that drive them

The dongle's LEDs are not all the nRF52840's to drive, and which chip owns one decides where its
code lives:

| LED | Owner | Code | Meaning |
|---|---|---|---|
| Application | nRF52840, `DT_ALIAS(led0)` = `gpio1` pin 2 | `led.c` | a capture tool holds the capture port |
| RX | Si4467 GPIO3 | `si4467_configure_gpios()` | a frame is arriving |
| TX | Si4467 GPIO2 | `si4467_configure_gpios()` | nothing — there is no transmit path |

`VALID_PREAMBLE` (24) and `TX_STATE` (32) are hardware functions of the transceiver's state machine,
so the firmware writes them once at bring-up and never thinks about them again: no interrupt, no
work per frame, and nothing that can disagree with what the radio is actually doing. Every other pin
in that `GPIO_PIN_CFG` is `DONOTHING` (0), which the API reference defines as "behavior of this pin
is not modified" — that is what makes it safe to send while nIRQ and SDO are carrying the receive
interrupt and the SPI read data. **`DONOTHING` does not cover drive strength**, which `GEN_CONFIG`
applies to every output pin at once; `MED_LOW` is what earlier firmware has always used on this
board, which is why it is what this one sends.

**`VALID_PREAMBLE` is the longest a frame can hold the LED**, which is why it is the mode chosen.
It goes high at preamble detection and low once the packet is received, so it spans preamble, PHY
header and PSDU: about 9 ms for a 48-octet frame at 50 kbit/s, 328 ms for the largest PSDU the PHY
allows. `SYNC_WORD_DETECT` (26) ends at the same point but begins 8 octets later, so it can only
ever be shorter — it is the stricter choice, since `VALID_PREAMBLE` also flickers on a preamble that
never reaches a sync word. `RX_STATE` (33) is longer still but useless here: this application sits
in receive permanently, so it would be a light that is always on.

The call sits after `si4467_apply_radio_config()`. The WDS blob carries a `GPIO_PIN_CFG` of its own
(all `DONOTHING`), which `si4467_apply_radio_config()` skips along with `POWER_UP`. Only a reset or
`POWER_UP` clears the pin configuration, and neither happens after bring-up, so the LEDs survive
every PHY change.

Unlike `led_init()`, a failure here is fatal. That is not an inconsistency: `GPIO_PIN_CFG` is an SPI
command, so it does not fail because a pin is absent, it fails because the transceiver stopped
answering — and then there is nothing to sniff with either.

## The application LED, and why `pcapng.c` does not drive it

`led.c` owns the application LED (`DT_ALIAS(led0)`, `gpio1` pin 2), lit while a capture tool holds
the capture port. The DTR poll in `pcapng.c` is the only place that knows when that changes, so it
would have been one line to set the pin from `monitor()` — and that is the wrong line. The stream
writer has no business knowing which pins the board has; the next board it is built for may have
none. Instead `monitor()` calls `attach_cb` on **both edges**, `main.c` registers
`on_host_attached()`, and the LED stays a board concern in a file that does nothing else.

Two ordering details matter. `host_attached` is assigned **before** the callback runs, so a callback
that asks `pcapng_host_attached()` cannot be told something different from what it was just passed.
And `main()` registers the callback **before** `pcapng_init()`, which is what starts the poll — the
registration only writes a static, so doing it first costs nothing and cannot miss the first attach.

The LED is an attach indicator, not a traffic indicator, and should stay one: a light that blinks
per frame cannot answer the question worth answering from across the room, which is whether anything
is reading the dongle at all. `led_ready` makes a board without the pin quiet rather than logging a
GPIO failure every quarter second, and a failed `led_init()` is a warning in `main()` rather than a
return — an indicator that cannot be lit is no reason to leave the dongle deaf.

## Writing to the capture UART, and the two ways it corrupts the stream

PCAP-NG has no marker to resynchronise on. A reader that loses its place in the middle of a block
takes the following octets for a block header, and every block after that is garbage — so **losing
a whole frame is vastly better than writing a partial block**. Two separate hazards make a naive
write do exactly the wrong thing, and `pcapng.c` is shaped around both. Do not simplify it back to
writing straight to the UART.

1. **`uart_poll_out()` discards silently.** The capture UART has no flow control, so once the CDC
   ACM ring buffer fills it drops octets mid-block and returns as if it had written them.
2. **The CDC ACM driver frees buffer space before the data has been sent.** `tx_work_handler()`
   hands `usb_transfer()` a pointer into its own ring buffer and calls `ring_buf_get_finish()`
   immediately, so the space is advertised as free while the host still has not been sent it.
   Writing into it splices old and new content together.

The design that satisfies both: frames are staged in an application owned ring buffer
(`CONFIG_WISUN_SNIFFER_CAPTURE_BUF_SIZE`), and `reserve()` claims room for the **complete** block
before any of it is written, so a block is either staged whole or dropped whole. A dedicated thread
drains it, and it waits for `uart_irq_tx_ready()` to go non-zero before each write.

That wait is an **interlock, not a measure of free space** — the distinction matters, because
treating it as free space is what starved an earlier version of this code to 115 octets in 20
seconds. `tx_ready` is clear for exactly as long as a transfer is in flight, which is precisely the
window in which hazard 2 bites. `uart_fifo_fill()` is used rather than `uart_poll_out()` because it
reports how much it accepted, so the remainder can be retried.

Verify any change here by flooding the stream and walking the result block by block; the drops
must be accounted for exactly. `wisun_sniffer inject 500` overruns the buffer several times over:

```text
offered 502 = 500 injected + 2 received while attached
capture drops 399, so 103 blocks should be in the stream
13076 of 13076 octets consumed
  EPB=103, IDB=1, SHB=1            <- one section per capture, never more
```

Every octet must be consumed by the walk, and `EPB + capture drops` must equal the frames offered.
A capture that merely *opens* in Wireshark proves nothing: corruption shows up only after the
buffer has wrapped under sustained load.

## The capture script

`tools/wisun_sniffer_capture.py` is the only host-side tool, and it has two front ends: a command
line, and the extcap protocol Wireshark drives it with (`--extcap-interfaces`, `--extcap-config`,
`--extcap-dlts`, `--capture --fifo`). They meet at `capture()` and share everything below it, so a
change to the capture path cannot fix one and break the other. It is not a convenience wrapper:
`cat` gets a usable stream only with `wisun_sniffer section` and only on a port with no backlog
behind it (see "Open problems"), so there is no simpler path this could be replaced by.

Keep it one file. Splitting the extcap half out again means importing a sibling module from a
script Wireshark runs through a symlink, where `sys.path[0]` is the extcap directory rather than
`tools/` — that needs a `dirname(realpath(__file__))` shim and silently breaks if anyone copies the
script instead of symlinking it.

Test the Wireshark side by driving it the way Wireshark does, not by importing it and calling
functions. `WIRESHARK_EXTCAP_DIR=<dir> tshark -i wisun-<serial>` runs the real thing through a
symlink in `<dir>` without installing anything, and stopping tshark goes through the same
`extcap_request_stop()` as the GUI's stop button. `--capture` is the only mode that tolerates
unknown options, because Wireshark passes some this interface does not use; everywhere else a typo
is an error.

### The tests, and what they do not cover

`tools/tests/` holds pytest tests for the capture script — `python -m pytest
application/wisun_sniffer/tools/tests/`, no dongle needed. **They test the script, not the
firmware.** `test_toolbar.py` looks like an integration test of the whole sniffer, but the shell it
talks to is a Python thread playing the part, so it exercises our side of the conversation only.
The ~3700 lines of C under `src/` have no automated coverage; they are verified on hardware.

That is not an accident of effort. The script is the part nobody exercises on a bench, and all
three faults it has shipped — spacing compression, a log line accepted as a shell reply, a command
sent before the shell was reading — were found by a person noticing something odd rather than by
running it. Each is now a test that fails against the version that had the fault, which is the bar
for adding another: **a test that has never failed has not been shown to test anything.**

They run under `uv`, from the repository root: `uv run pytest`. `pyproject.toml` points
`testpaths` at them, so no path has to be typed. They are kept next to the script rather than
under `tests/` because the script is the application's own, and `tests/` is for firmware that
runs on `native_sim`.

If firmware coverage is ever wanted, `wisun_phy.c`'s plan and frequency derivation, `tap.c`'s TLV
encoder and `pcapng.c`'s block writer are pure functions and would suit ztest on `native_sim`.
`si4467_wisun.c` would not — it is SPI transactions and interrupt timing.

### The console carries the log as well as the shell

Every shell command the script runs is read back off an interface the firmware also logs to, so a
reply can arrive with log messages spliced through it, or consist of nothing else. `console_reply()`
strips them, and **everything that decides whether a command was answered must go through it**.

This is not hypothetical. `console_command(..., expect="channel")` used to test `expect in text`
against the raw text, and a dongle that has just restarted flushes a deferred startup log
(`CONFIG_LOG_PROCESS_THREAD_STARTUP_DELAY_MS=4000`) containing:

```text
<inf> wisun_sniffer: listening in EU on ChanPlanID 32, PhyModeID 0x01, channel 0 (863.100 MHz)
```

That line alone satisfied the wait. `console_complaint()` then found nothing, because it had always
skipped log lines — the code knew log output was noise in one place and forgot it in the other — so
`set_phy()` reported success on the strength of a line the shell never printed, and the capture ran
on whatever PHY the dongle happened to boot with.

`set_phy()` therefore **verifies rather than assumes**: the absence of a complaint only says the
firmware did not object to what it was told, which is weaker than the firmware listening to it. The
check parses the PHY out of the command's own reply — `wisun_sniffer phy a b c d` prints the PHY it
ended on — so it costs no second round trip, and it cannot be satisfied by a log line, because
`parse_phy()` anchors its patterns at the start of a line and log lines start with a timestamp.

### A dongle can be reached before it is listening

The device node appears when USB enumerates, which is well before the shell is reading. A capture
started right after a restart therefore writes its command into a console that drops it, and the
reply that comes back is the boot banner and the startup log that had been waiting in the transmit
buffer — **with no echo of the command in it**, which is the tell: the shell echoes what it
receives, so no echo means the shell never saw it. That is what this looked like in the field:

```text
uart:~$ *** Booting Zephyr OS build v4.2.1-52-gd7e8b3f6434f ***
uart:~$ [00:00:00.001,861] <inf> wisun_sniffer: Wi-SUN sniffer 0.0.1 on dongle/nrf52840
…
uart:~$ uart:~$
```

Nothing in the stream announces when the shell arrives, so `console_command()` simply **asks again**
(`CONSOLE_ATTEMPTS`). This is safe only because every command here is repeatable — they set the PHY
to a stated value or read something back — so a duplicate that does land costs nothing. Do not add
a command to this path for which that is untrue without revisiting the loop.

A longer single timeout would not have worked: the command was lost, not slow, and waiting longer
for an answer to something nobody received just delays the same failure. The first attempt also
serves to drain the backlog, which is why the second one usually succeeds.

`console_summary()` keeps the resulting error message to the last thing the shell said instead of
the whole boot log — under extcap this message ends up in a Wireshark dialog, where several hundred
octets of startup log help nobody, and `*** Booting Zephyr OS ***` says why on its own.

**Wireshark is not the place to look when interface options seem not to arrive.** Measured against
tshark 4.6.6 with a probe extcap under `WIRESHARK_EXTCAP_DIR`: it puts *every* argument on the
`--capture` command line every time — the declared defaults when nothing is saved, the saved
preference values otherwise. Mixed case and dashes in the interface name are not a problem either;
`wisun-6EE8F75F43BA56F1` becomes the preference key `extcap.wisun_6ee8f75f43ba56f1.channel` and is
applied. So `selected_phy()` never returns `None` under `--capture`, and a PHY that did not take
effect is ours to explain. (The GUI options dialog can supply its own argument table rather than
going through the preferences, and that path has not been measured.)

### Rebasing timestamps without distorting them

`Stream` adds one offset to every frame and changes nothing else, because **the spacing between
frames is the measurement** — it is what a sniffer is for, and the device latched each timestamp at
sync detect, so it is right. Anything that varies the offset across a capture rewrites that
measurement.

An earlier version did exactly that. It kept the smallest `now - device_us` seen so far, which is a
sound estimator of the offset and the wrong thing to apply live: every improvement moves later
frames earlier relative to the ones already written, so gaps come out short. It was worst where it
mattered most. A capture opens with the dongle draining what it staged while nothing was reading,
so the frames behind that backlog arrive late through a pipe still catching up, the early bounds
are the most inflated, and the compression lands on the densest traffic. Reproduced in the harness:
100 ms spacing came out as 50 ms, and one uneven case turned a 992 µs gap into **minus 389 ms**.

The fix is to estimate for `WARMUP_SECONDS` and then stop. Frames that arrive during the warm-up
are held and written together once the offset is fixed, so no frame is ever written with an offset
that later changes. Two consequences to keep in mind when touching this: `feed()` must be called
even when the port read times out, or the held frames wait for traffic that may not come, and
`close()` must run at the end of a capture, or a capture shorter than the warm-up writes nothing.
`test_retime.py` drives the real class with a fake clock and covers both, plus the two spacing
cases above.

### How a capture is stopped, and why it used to hang

Wireshark's stop button runs `extcap_request_stop()`: it sends the extcap program **SIGTERM**, then
gives it `EXTCAP_CLEANUP_TIMEOUT` — **30 seconds** — before SIGKILL. Nothing about a capture ends
until that returns, so a script that does not answer the signal is a Wireshark that ignores the
stop button and then stalls for half a minute on the way out. That is the whole explanation for
"Wireshark hangs when closing"; the number to recognise is 30 seconds.

**A Python program can only answer a signal between calls.** The handler runs, and then Python
retries the interrupted call (PEP 475) — so anything that blocks indefinitely swallows SIGTERM and
ctrl-c alike. Two calls in this script did:

- `open(fifo, "wb")`, which waits for the reader. Reproduced directly: ctrl-c leaves it waiting for
  ever.
- `write()` into a fifo the reader has stopped draining. Reproduced with a 4 KiB fifo nobody reads:
  the process sat in `anon_pipe_write` and survived SIGTERM until it was killed.

A third way to hang needs no blocked call at all: when the reader closes the fifo, a script that
only finds out on its next write can wait minutes for one on a quiet channel.

`Sink` answers all three. It keeps the fifo non-blocking and waits for room with `poll()`, so every
wait is one that a stop request gets out of; `open_fifo()` opens with `O_NONBLOCK`, which fails
with `ENXIO` until a reader is there, turning the wait into a loop that can be given up on; and
`reader_gone()` polls for `POLLERR`, which the writing end of a pipe reports as soon as the reading
end closes, with nothing having to be written. A capture written to a file gets none of this and
needs none of it.

The numbers to regress against, measured in the GUI: the extcap program is gone 0.2 to 0.3 s after
`Requesting stop`, and closing Wireshark while it is capturing takes about half a second from the
click to the process exiting.

**Stderr is an error channel, not a log.** Wireshark keeps everything an extcap program writes
there and, when the capture closes, shows it to the user as
`capture_input_closed(): Error from extcap pipe: …` — an error box at the end of every capture,
whatever the text said. Progress therefore goes through `log()`, which says nothing once `--capture`
sets `quiet`; only `warn()` writes to stderr under Wireshark, and what it writes is meant to become
the capture's error. Anything the toolbar causes has somewhere better to go — see below.

### The toolbar controls

`Toolbar` serves the controls Wireshark shows above the packet list. Five things about that
protocol are not visible from this end of it and are easy to get wrong:

- **The controls are declared in `--extcap-interfaces`, not in `--extcap-config`.** Wireshark parses
  them once, out of the interface list, and builds one toolbar shared by every interface the program
  offers (`extcap_parse_interfaces()`). Declared in the config output they are silently ignored: no
  toolbar, no error. A `value` sentence has to come after the `control` it belongs to, and a
  `{validation=…}` regex may contain braces but never `}{`, which is where the tokeniser splits.
- **The two pipe arguments are named from Wireshark's end.** `--extcap-control-in` is the one it
  *writes* and this script reads; extcap.c passes its own `control_in` as our `--extcap-control-out`.
- **A message is `T`, a 24-bit big-endian length covering the two octets that follow it, the control
  number and the command.** Payloads are text, except a checkbox, which is one octet.
- **Wireshark opens its end from the thread its window runs on** and blocks there until this script
  has opened the other end, so the read end is opened first and before anything that can wait. Only
  the GUI passes the pipes at all: tshark parses the same declarations and then never sends a
  message, which is why `controls` is optional.
- **Everything before `CMD_INITIALIZED` is the toolbar repeating what it was left set to at the end
  of some earlier capture**, which has nothing to do with this one. It is ignored, and the toolbar is
  then set from the interface options that this capture really started with.

Two controls that look like obvious additions are deliberately absent: a `restore` button, which
Wireshark disables while capturing, and anything on `role=control` for use between captures, which
it also disables. Control buttons only work during a capture; a `help` button only appears if the
`extcap` sentence carries a `{help=…}`.

**A toolbar changes one field at a time, so it must use the shell's per-field commands** —
`wisun_sniffer plan 33`, not `wisun_sniffer phy 3 33 0x03 7`. This is the opposite of what a capture
does at its start, and both are right. In EU, ChanPlanID 32 runs PhyModeID 0x01 and ChanPlanID 33 runs
3 or 5, so on the way from one to the other *every* order is refused: plan first is refused because
33 will not run mode 0x01, mode first because 32 will not run mode 0x03. Measured on the dongle — from
the toolbar those two PHYs were unreachable until this changed. The per-field commands keep what
they can and move the rest to something that works, so `plan 33` brings mode 3 with it.

The consequence is that **the answer is not what was asked for, and the PHY has to be read back**
(`read_phy()`), then published to the toolbar so it shows what the firmware settled on. Selecting
ChanPlanID 33 moves the operating mode to PhyModeID 0x03 and can move the channel with it; whatever
the firmware did is what the toolbar has to show.

The firmware now refuses what it used to accept quietly — an argument that is not a number, one too
large for the field, and a channel the plan does not have (`wisun_sniffer channel 300` once landed
on channel 44). Those come back through `set_phy_field()` as ordinary refusals and end up in the
toolbar's warning dialog, so there is nothing extra to do about them here.

It matters that the refusal says something. **A dialog is the only thing the person at the toolbar
sees**, so a refusal that only names an errno is a dead end — the log it points at is on a USB
interface the GUI never shows. That is why `wisun_phy_select()` writes its reason into a buffer the
caller passes rather than into the log: the shell prints it, the dialog carries it, and
`wisun_phy_init()` — the one caller with no shell behind it — logs it instead.

Failures from a control go into the toolbar's log and a dialog (`_failed()`), never to stderr: they
answer something the user just clicked, and stderr would instead end the capture with an error box.

The whole of it runs on one daemon thread, and that is load-bearing. Answering a control takes a
round trip to the shell on the other USB interface — up to two seconds if the firmware refuses —
which is far too long to stop draining the capture port for, and the thread must never keep the
process alive at the end of a capture. `Settings` is the only thing the two threads share.

Test it without a dongle by playing Wireshark's side: ptys for the two CDC ACM interfaces, fifos
for the capture pipe and the two control pipes, a thread answering the console the way the shell
would, and the control protocol written out byte for byte. `tshark -D` with `WIRESHARK_EXTCAP_DIR`
set checks the declarations against the real parser — but only prove that by breaking one on
purpose first, because a rejected sentence is reported as `invalid type … in CONTROL sentence` on
stdout and nothing else changes.

Two things to know when reproducing any of this:

- `pgrep -f wisun_sniffer_capture.py` matches the shell running the test as well as the script,
  which makes a dead process look alive. Write the pattern as `[w]isun_sniffer_capture.py`.
- `--log-level debug --log-file <path>` is how the GUI tells you what it is doing;
  `Requesting stop PID` and `Closing spawned PID` bracket the part that used to hang. Driving the
  GUI needs `DISPLAY=:0` and the `XAUTHORITY` from the running session (read it out of
  `/proc/$(pgrep -u "$USER" plasmashell)/environ`), and `-a duration:<n>` stops a capture the same
  way the stop button does. `WIRESHARK_EXTCAP_DIR` is honoured by tshark but **not** by the GUI,
  which only looks in the personal and global extcap directories.

What it does, all of which a capture needs and none of which can be done in firmware:

- It **stops promptly however the capture ends** — see above.
- It **starts forwarding at a section header** rather than wherever the transceiver happened to be,
  which is what makes attaching mid-stream work at all.
- It **rebases timestamps onto the host clock**. The firmware counts microseconds since boot, so
  without this Wireshark dates every frame to 1970. Only the offset is changed, so the spacing
  between frames stays exactly as the device measured it. The offset is the *smallest* value of
  `now - device_timestamp` seen so far, not the first one: a capture begins with whatever the
  dongle buffered while nothing was reading, and anchoring to one of those stale frames dated a
  whole capture 28 seconds into the future when it was measured.
- It **toggles DTR**, which is how the firmware notices a reader: the line is taken low, held there
  for longer than the firmware's 250 ms sampling interval, and only then raised, because the rising
  edge is what starts a section. Merely opening the port is not enough — pyserial raises DTR on
  open, so a capture started straight after another one can find the line already high, and then
  waits forever for a section header that is never written.
- It **opens its output before the port**, so that the section begins when a reader is really
  there. For a fifo that means blocking until Wireshark opens the other end. Frames the dongle
  buffered while nothing was attached arrive ahead of the section header and are discarded with it.
- It **selects the PHY in one command**, `wisun_sniffer phy <domain> <plan> <mode> <channel>`, when
  a whole PHY is known — which is how a capture starts. Sending those fields one at a time does not
  work: the firmware validates after each, and a channel plan is rarely valid alongside the
  operating mode selected before it.
- It **serves the toolbar**, which is how the PHY is changed without stopping the capture, and
  which changes one field at a time — see below, because that needs the opposite approach.

**Talking to the shell has three traps, all of which were silent.** `console_command()` handles
them; do not simplify it.

1. **The prompt ends `uart:~$ \x1b[m`.** It is written in colour, so a reply never ends in `$` until
   the escape sequences are taken out of it (`ANSI_ESCAPE`). Before this was noticed, the
   termination check could not match, and every `set_phy()` at the start of every capture sat out
   its full two-second timeout and then reported success without having read anything.
2. **A command that is never answered is not agreement.** The reply is the only evidence that
   anything was programmed, so a timeout is returned as an error rather than as a short reply.
3. **The console carries the log as well as the shell.** A reply can contain minutes of `<inf>`
   lines that arrived since it was last read, so `console_complaint()` skips anything the logging
   subsystem wrote and returns the one line the shell refused on — which is also all that goes in
   an error message.

`Stream.feed()` must reassemble blocks across arbitrary chunk boundaries, so verify changes to it
offline: prepend random junk to a known-good capture, feed it in randomly sized pieces, and require
the output to equal the original byte for byte over a few hundred trials.

Installation is a host-side change outside this repository, so **only do it if asked**. The target
is the `Personal Extcap path` from `tshark -G folders`, which is `~/.local/lib/wireshark/extcap`
and *not* the `~/.config/wireshark/extcap` that older notes suggest.

## Open problems

**DTR is still the only signal the capture port carries.** The section header is written on the
rising edge and never repeated, so a tool that does not toggle the line — `cat` was measured not to
— gets no header of its own accord. `wisun_sniffer section` is the way in for those, and it is a
shell command rather than a repeat on a timer for a reason: the repeat that used to exist only ever
half worked, because whatever the transceiver was mid-way through sending still preceded the
header, and it left every capture opening with a run of stale empty sections.

The command does not make the port `cat`-clean in every case, and should not be described as
though it does. It puts a decodable section into the stream from that point on, but a backlog
staged while nothing was attached still precedes it, in `tx_ring` and in up to
`CONFIG_USB_CDC_ACM_RINGBUF_SIZE` of the CDC ACM driver's own buffer, and `cat` writes from byte
zero, so the file begins with the tail of an older section and Wireshark refuses it. Making that
case work would mean not staging frames at all while unattached, which needs a software notion of
"attached" that a reader with no DTR can never clear — a real design decision, not a tidy-up. It
has not been taken.

**Frames captured before a capture starts are thrown away, deliberately.** Whatever the dongle
staged while nothing was attached is flushed when a reader turns up, ahead of the new section
header, and the scripts discard everything before that header. It is the same mechanism that keeps
frames from a previously selected PHY out of a capture.

## Measurement notes

RSSI is latched at sync detect, so it describes the frame rather than what follows it. The
datasheet specifies accuracy only from **−110 to −90 dBm**; above that the reading compresses. A
20 dB attenuator on the antenna moved a −48 dBm signal to −67.5 dBm (correct) but a −13 dBm signal
to −46.5 dBm, because −13 dBm was already in AGC compression. Keep strong transmitters attenuated
if the numbers need to mean anything.

## Reference documentation

In `doc/`: `WiSUN_PHY_2.03.pdf` (channel plans, operating modes), `WiSUN_FAN_1.1.pdf`,
`IEEE802.15.4-2020.pdf` (PPDU §19.2, PHR figure 19-4, mode-switch PHR §19.2.5, whitening §16.2.3,
band/modulation/mode tables 7-21, 7-23, 7-25), `Wireshark_ieee802154_tap.pdf` (TAP header and
TLVs, DLT 283), and under `doc/si4467/`: the datasheet, AN633 (programming guide, §10.10 for the
802.15.4g project and §10.18 for long-packet reception) and the API reference under
`EZRadioPRO_REVC2/Si4467/revA2A/` — authoritative for property bit layouts, but see above for
where its prose about `IE154G` cannot be trusted.
