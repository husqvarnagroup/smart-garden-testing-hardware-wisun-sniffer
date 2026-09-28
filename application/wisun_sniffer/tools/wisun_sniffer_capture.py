#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Capture from the Wi-SUN sniffer dongle, from a command line or from Wireshark.

Opens the dongle's capture interface, tells the firmware a reader has attached by toggling DTR,
and writes the PCAP-NG stream to a fifo, a file or standard output. Piping the capture port with
"cat" cannot do any of that: it never raises DTR, so the firmware cannot tell it apart from no
reader at all, and it starts forwarding wherever the transceiver happened to be rather than at a
section header.

    ./wisun_sniffer_capture.py | wireshark -k -i -
    ./wisun_sniffer_capture.py --fifo /tmp/wisun.pcapng   # then: wireshark -k -i the same fifo
    ./wisun_sniffer_capture.py --phy-mode 3 --chan-plan 33 --channel 10 -w capture.pcapng
    ./wisun_sniffer_capture.py --phy-mode 0x13 --chan-plan 33 --channel 0 -w coded.pcapng

The same script is Wireshark's extcap interface, which makes the dongle appear in its interface
list: Wireshark calls it to enumerate interfaces, to ask what link type and options they offer, and
finally to capture into a fifo it creates. It also puts a toolbar above the packet list, from which
the PHY can be changed without restarting the capture. Both front ends take exactly the same
capture path. See README.md for how to install it.
"""

import argparse
import errno
import glob
import os
import re
import select
import signal
import stat
import struct
import sys
import threading
import time

VERSION = "1.0"

# Where the Help button goes: this application's own directory, whose README describes the dongle,
# the PHY it is set up for and this script, rather than the top of the repository.
HELP_URL = (
    "https://dev.azure.com/HQV-Gardena/SG-Embedded/_git/sg-zephyr-firmware"
    "?path=/application/wisun_sniffer"
)

# The dongle exposes the console on the first CDC ACM interface and the capture stream on the
# second, both under the same USB serial number.
BY_ID = "/dev/serial/by-id"
DEVICE_PREFIX = "usb-Gardena_Wi-SUN_Sniffer_Dongle_"
CONSOLE_SUFFIX = "-if00"
CAPTURE_SUFFIX = "-if02"

DLT_IEEE802_15_4_TAP = 283

BLOCK_TYPE_EPB = 0x00000006
SHB_MAGIC = b"\x0a\x0d\x0d\x0a"

# Nothing the firmware emits comes anywhere near this; it only bounds the damage from a length
# field read out of octets that turn out not to be a block header at all.
MAX_BLOCK_LEN = 65536

# How long the offset between the device clock and the host clock is estimated for before it is
# fixed for the rest of the capture. Frames are held back for this long, once the first one
# arrives, so that they can all be written with the same offset.
#
# It has to outlast the catch-up at the start of a capture, where frames reach us late through a
# pipe still draining what the dongle staged while nothing was reading, and it is what a capture
# waits before its first frame appears. Measured drains here finish inside 100 ms.
WARMUP_SECONDS = 0.5

# The PHY the firmware boots with, used for whichever parts of a PHY selection are left out.
DEFAULT_PHY = (3, 32, 1, 0)

# Wi-SUN PHY 2.03 table 8, for the Wireshark interface options. The firmware holds the same tables
# and is the one that decides whether a combination is valid, so these are only here to be selected
# from.
REGULATORY_DOMAINS = [
    (0, "WW - 2400-2483.5 MHz"),
    (1, "NA - 902-928 MHz"),
    (2, "JP - 920-928 MHz"),
    (3, "EU - 863-876 MHz"),
    (4, "CN - 470-510 and 920.5-924.5 MHz"),
    (5, "IN - 865-868 MHz"),
    (6, "MX - 902-928 MHz"),
    (7, "BZ - 902-928 MHz"),
    (8, "AU/NZ - 915-928 MHz"),
    (9, "KR - 917-923.5 MHz"),
    (10, "PH - 915-918 MHz"),
    (11, "MY - 919-923 MHz"),
    (12, "HK - 920-925 MHz"),
    (13, "SG - 866-869 and 920-925 MHz"),
    (14, "TH - 920-925 MHz"),
    (15, "VN - 920-925 MHz"),
]

# Wi-SUN PHY 2.03 tables 11 and 19, restricted to the modes the firmware can program.
#
# A PhyModeID is a PhyType in its high nibble and a PhyMode in its low one, so each mode has a
# forward error correcting variant numbered 16 above it. The two are the same signal on the air and
# differ only in how the frame is built, but a receiver has to be told which to expect: the coded
# frames announce themselves with a different start-of-frame delimiter, and a sniffer listening for
# the wrong one hears nothing at all.
PHY_MODES = [
    (0x01, "0x01 (#1a) - 50 ksym/s, modulation index 0.5"),
    (0x03, "0x03 (#2a) - 100 ksym/s, modulation index 0.5"),
    (0x05, "0x05 (#3) - 150 ksym/s, modulation index 0.5"),
    (0x11, "0x11 (#1a with FEC) - 50 ksym/s, modulation index 0.5"),
    (0x13, "0x13 (#2a with FEC) - 100 ksym/s, modulation index 0.5"),
    (0x15, "0x15 (#3 with FEC) - 150 ksym/s, modulation index 0.5"),
]


def phy_mode_text(value):
    """A PhyModeID as hex, which is the only form it reads as one thing rather than two.

    The high nibble is the PhyType and the low one the PhyMode, so 0x13 is mode 3 with FEC at a
    glance while 19 is a number that has to be divided first.
    """
    return f"0x{value:02x}"


def parse_int(text):
    """A number the way the firmware's shell reads one: hex when it says so, decimal otherwise.

    Not int(text, 0) throughout, because that rejects a leading zero -- and the channel control
    accepts one, so a channel typed as 007 would stop working.
    """
    return int(text, 0) if text.lower().startswith("0x") else int(text)


# What each part of the PHY means, said once for the interface options dialog and the toolbar
# alike: they offer the same four fields, and two descriptions of them would soon disagree.
TOOLTIP_DOMAIN = (
    "Decides which channel plans and operating modes may be combined. The dongle's front end is "
    "designed for 863-876 MHz, so only EU is really within its reach."
)
TOOLTIP_CHAN_PLAN = (
    "Fixes where channel zero sits and how far apart the channels are. In EU: 32 is 863.1 MHz "
    "with 100 kHz spacing, 33 the same start with 200 kHz, 34 and 35 the 870-876 MHz band, 36 and "
    "37 all of 863-876 MHz."
)
TOOLTIP_PHY_MODE = (
    "Fixes the symbol rate, and whether frames are forward error corrected. Only the modes with a "
    "modulation index of 0.5 can be programmed. ChanPlanID 32 goes with mode 0x01, ChanPlanID 33 "
    "with 0x03 and 0x05, and each has a FEC variant with 0x10 added to it. A node using FEC is not "
    "heard "
    "on the uncoded mode, or the other way round, so this has to match what the network runs."
)
TOOLTIP_CHANNEL = (
    "Channel number within the channel plan. With ChanPlanID 32 the centre frequency is "
    "863.1 MHz + channel * 100 kHz."
)
TOOLTIP_DEVICE_TIMESTAMPS = (
    "The dongle has no clock and counts from boot. With this frames are dated from 1970 instead "
    "of from the host clock, though the spacing between them is right either way."
)

stop_requested = False

# Set while Wireshark is driving, which turns anything on stderr into a capture error.
quiet = False


def log(message):
    """Say what is going on, to a person at a command line.

    Stdout carries the extcap protocol or the capture itself, so this can only go to stderr -- and
    stderr means something else entirely when Wireshark is driving. It collects everything an
    extcap program writes there and shows it when the capture closes, as "Error from extcap pipe:
    ...", whatever it says. Progress reported that way ends every capture with an error box, so
    under Wireshark this keeps quiet and only warn() speaks.
    """
    if not quiet:
        write_stderr(message)


def warn(message):
    """Report something that went wrong, which under Wireshark becomes the capture's error."""
    write_stderr(message)


def write_stderr(message):
    """Writing has to be allowed to fail: Wireshark closes the pipe when it is done with us, and a
    broken pipe here would end the capture with a traceback and a failure exit status."""
    try:
        print(f"{os.path.basename(sys.argv[0])}: {message}", file=sys.stderr, flush=True)
    except OSError:
        pass


def request_stop():
    """Ask the forwarding loop to return at the next opportunity."""
    global stop_requested

    stop_requested = True


# ------------------------------------------------------------------------------------------- #
# Device discovery                                                                             #
# ------------------------------------------------------------------------------------------- #


def find_dongles():
    """Return the serial number of every attached dongle, in a stable order."""
    pattern = os.path.join(BY_ID, f"{DEVICE_PREFIX}*{CAPTURE_SUFFIX}")
    serials = []

    for path in sorted(glob.glob(pattern)):
        name = os.path.basename(path)
        serials.append(name[len(DEVICE_PREFIX) : -len(CAPTURE_SUFFIX)])

    return serials


def device_path(serial, suffix):
    return os.path.join(BY_ID, f"{DEVICE_PREFIX}{serial}{suffix}")


def interface_value(serial):
    return f"wisun-{serial}"


def serial_from_interface(value):
    """Recover the USB serial number from the interface name Wireshark passes back."""
    if not value or not value.startswith("wisun-"):
        raise SystemExit(f"not a Wi-SUN sniffer interface: {value!r}")

    return value[len("wisun-") :]


def pick_dongle(requested):
    """Choose which dongle to capture from, insisting on being told when it is ambiguous."""
    serials = find_dongles()

    if requested:
        if requested not in serials:
            raise SystemExit(
                f"no dongle with serial number {requested}; found: {serials or 'none'}"
            )
        return requested

    if not serials:
        raise SystemExit(f"no Wi-SUN sniffer dongle under {BY_ID}; is one plugged in?")

    if len(serials) > 1:
        raise SystemExit(f"several dongles are attached, select one with --serial: {serials}")

    return serials[0]


# ------------------------------------------------------------------------------------------- #
# Serial port                                                                                  #
# ------------------------------------------------------------------------------------------- #

# What the shell says when it will not do what it was asked. Used both to notice that it has
# finished answering and to decide what the answer was.
CONSOLE_COMPLAINT = re.compile(r"error|failed|cannot|unknown|not found|has no|must be", re.I)

# A line the logging subsystem wrote rather than the shell. Both go to the console, and a log line
# that happens to carry one of the words above is not an answer to anything.
CONSOLE_LOG_LINE = re.compile(r"\[\d\d:\d\d:\d\d\.\d+,\d+\] <\w+>")

# The shell writes to a terminal and dresses its prompt and its editing in colour and cursor
# movement, none of which is text. Its prompt really ends "uart:~$ \x1b[m", so a reply is not even
# recognisable as finished until this is taken out of it.
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# The end of everything the shell has to say.
CONSOLE_PROMPT = "$"

# How many times a shell command is sent before it is given up on. A dongle can be opened before it
# is listening -- the device node appears when USB enumerates, and a console opened right after a
# restart delivers the boot banner and the startup log that were waiting in the transmit buffer
# before it carries anything the shell reads. One attempt lands in that gap and is simply lost, so
# what a capture starting at the wrong moment needs is another go, not a longer wait.
CONSOLE_ATTEMPTS = 3

# How long DTR is held low before it is raised again. The firmware samples the line every 250 ms
# and starts a section on the rising edge, so the low period has to outlast one sampling interval:
# a reader that attaches while the line still looks high from the previous one is never noticed,
# and waits for a section header that will not come.
DTR_SETTLE_SECONDS = 0.5


def import_serial():
    try:
        import serial
    except ImportError:
        raise SystemExit(
            "this needs pyserial; install it with 'pip install pyserial' (for the Wireshark "
            "interface, into the Python that Wireshark runs extcap scripts with)"
        )

    return serial


def open_port(path, timeout=0.2):
    """Open a CDC ACM interface. DTR is raised, as pyserial does by default."""
    serial = import_serial()

    try:
        return serial.Serial(path, 115200, timeout=timeout)
    except OSError as err:
        raise SystemExit(f"cannot open {path}: {err}")


def open_capture_port(path, timeout=0.2):
    """Open the capture interface and announce the reader with a clean DTR edge.

    DTR is how the firmware notices that something is listening: it starts a fresh PCAP-NG section
    when the line goes up. Opening the port is not enough on its own, because the line may still be
    up from a previous capture, so it is deliberately taken low first and held there long enough
    for the firmware to sample it.
    """
    serial = import_serial()

    port = serial.Serial()
    port.port = path
    port.baudrate = 115200
    port.timeout = timeout
    # Applied when the port is opened, so the line is never raised in between.
    port.dtr = False

    try:
        port.open()
    except OSError as err:
        raise SystemExit(f"cannot open {path}: {err}")

    time.sleep(DTR_SETTLE_SECONDS)

    # Whatever arrived while the firmware thought nobody was there belongs to the previous section.
    port.reset_input_buffer()
    port.dtr = True

    return port


def console_command(serial_number, command, expect, timeout=2.0, attempts=CONSOLE_ATTEMPTS):
    """Run a shell command on the console interface. Returns (reply, error), one of them None.

    The reply comes back as text, with the terminal control sequences the shell decorates it with
    taken out. The shell has answered when its prompt is back and it has either printed what was
    asked for or said why it would not. The prompt alone would not do, because the shell echoes the
    command as it receives it and the echo already ends in one.

    A command whose answer never arrives is an error rather than a short reply: there is nothing to
    read it for, and a firmware that says nothing would otherwise look exactly like one that agreed.

    It is asked more than once because a dongle can be reached before it is listening. The device
    node appears when USB enumerates, which is well before the shell is reading, so a capture
    started right after a restart writes into a console that drops it -- the reply then holds the
    boot banner and the startup log but no echo of the command, the shell never having seen it.
    Nothing in the stream says when the shell arrives, so the command is simply repeated until it
    is answered. Every command here is one that can be repeated harmlessly: they set the PHY to a
    stated value or read something back, so a duplicate that does arrive costs nothing.
    """
    path = device_path(serial_number, CONSOLE_SUFFIX)
    if not os.path.exists(path):
        return None, f"no console interface at {path}"

    text = ""

    with open_port(path) as console:
        for _ in range(attempts):
            # Whatever is already in the buffer belongs to the boot, to the log, or to an attempt
            # that went unanswered, and matching against any of it would answer the wrong question.
            console.reset_input_buffer()
            console.write(f"{command}\r\n".encode())
            console.flush()

            deadline = time.monotonic() + timeout
            reply = bytearray()
            text = ""

            while time.monotonic() < deadline:
                reply.extend(console.read(256))
                text = ANSI_ESCAPE.sub("", reply.decode(errors="replace"))
                said = console_reply(text)

                if text.rstrip().endswith(CONSOLE_PROMPT) and (
                    expect in said or CONSOLE_COMPLAINT.search(said) is not None
                ):
                    return text, None

    return None, (
        f"the firmware did not answer '{command}' in {attempts} attempts of {timeout:g} s"
        f"; the console said {console_summary(text)}"
    )


def console_summary(text):
    """How to describe a console that did not answer, without quoting a whole boot log at anyone.

    The last thing the shell said, which is the part worth seeing: on the failure this exists for it
    is the boot banner, and "*** Booting Zephyr OS ***" says why the command went unanswered more
    plainly than the several hundred octets of startup log around it would.
    """
    # The shell re-prints its prompt after every log message, so most lines carry one; what matters
    # is whatever follows the last of them.
    said = [line.rsplit(CONSOLE_PROMPT, 1)[-1].strip() for line in console_reply(text).splitlines()]
    said = [line for line in said if line]

    if said:
        return repr(said[-1])

    if CONSOLE_LOG_LINE.search(text):
        return "nothing but log output, so the dongle had only just started"

    return "nothing at all"


def console_reply(text):
    """What the shell itself said, with the firmware's log lines taken out.

    The console carries the log as well as the shell, so anything read back from it can have log
    messages spliced through it -- and they are not answers to anything. Matching against them is
    how a command that was never executed comes to look as though it was: a dongle that has just
    restarted flushes a startup log holding "listening in EU on ChanPlanID 32, PhyModeID 0x01,
    channel 0", which satisfies a caller waiting to see the word "channel" before the shell has
    said anything at all.
    """
    return "\n".join(line for line in text.splitlines() if not CONSOLE_LOG_LINE.search(line))


def console_complaint(text):
    """The line the shell refused something on, if it refused anything.

    Only the line, because the rest of a reply is whatever the firmware had to say since it was
    last read, which can be minutes of it and belongs in nobody's error message.
    """
    for line in console_reply(text).splitlines():
        if CONSOLE_COMPLAINT.search(line):
            return line.strip()

    return None


def parse_phy(text):
    """The PHY out of what the shell prints about one, or None if that is not what this is."""
    phy = []

    for pattern in (
        r"^domain\s*:.*?\((\d+)\)",
        r"^chan plan\s*:\s*(\d+)",
        r"^phy mode\s*:\s*(0x[0-9a-fA-F]+|\d+)",
        r"^channel\s*:\s*(\d+)",
    ):
        match = re.search(pattern, text, re.M)
        if match is None:
            return None

        phy.append(parse_int(match.group(1)))

    return phy


def read_phy(serial_number):
    """Ask the firmware what it is listening to. Returns (phy, error), one of them None."""
    text, error = console_command(serial_number, "wisun_sniffer phy", expect="channel")
    if error:
        return None, error

    phy = parse_phy(text)
    if phy is None:
        return None, f"cannot make out the PHY from '{text.strip()}'"

    return phy, None


def set_phy_field(serial_number, field, value):
    """Change one part of the PHY, and let the firmware settle the rest of it around that.

    This is the only way a toolbar can move from one PHY to another, because it changes one field
    at a time and most of the combinations on the way are invalid: in EU, ChanPlanID 33 does not go
    with PhyModeID 0x01 and ChanPlanID 32 does not go with PhyModeID 0x03, so whichever of the two
    is set first is refused on its own. The shell's per-field commands exist for exactly this. Each
    keeps as much of the current PHY as the new field allows and moves what is left to something
    that works -- a channel plan that will not run the operating mode in use takes the first one it
    will run.

    So the answer is not what was asked for, and the caller has to read the PHY back rather than
    assume it. Returns what went wrong, or None.
    """
    command = f"wisun_sniffer {field} {value}"
    text, error = console_command(serial_number, command, expect="channel")

    if error:
        return error

    complaint = console_complaint(text)
    if complaint:
        return f"the firmware refused '{command}': {complaint}"

    return None


def set_phy(serial_number, domain, chan_plan, phy_mode, channel):
    """Tell the firmware which Wi-SUN PHY to listen to. Returns what went wrong, or None.

    A whole PHY is named at once, which is what makes it different from set_phy_field() above: this
    one says exactly what to listen to and is refused if that is not a combination the standard
    allows, rather than settling for the nearest thing that works. It is how a capture starts,
    where the whole PHY is known and nothing should be quietly substituted for it.

    The reply is read back rather than assumed. The command prints the PHY the firmware ended up on,
    so the answer to "did it work" is already in front of us, and checking it costs nothing: the
    absence of a complaint only says the firmware did not object to what it was told, which is a
    weaker thing than the firmware now listening to it.
    """
    wanted = [domain, chan_plan, phy_mode, channel]
    command = f"wisun_sniffer phy {domain} {chan_plan} {phy_mode_text(phy_mode)} {channel}"
    text, error = console_command(serial_number, command, expect="channel")

    if error:
        return f"{error}, leaving the PHY alone"

    complaint = console_complaint(text)
    if complaint:
        return f"the firmware refused '{command}': {complaint}"

    actual = parse_phy(text)
    if actual is None:
        return f"'{command}' was not answered with a PHY: {console_reply(text).strip()!r}"

    if actual != wanted:
        return (
            f"the firmware is listening to domain {actual[0]} ChanPlanID {actual[1]} "
            f"PhyModeID {phy_mode_text(actual[2])} channel {actual[3]}, not "
            f"the domain {wanted[0]} ChanPlanID {wanted[1]} "
            f"PhyModeID {phy_mode_text(wanted[2])} channel {wanted[3]} it was asked for"
        )

    return None


# ------------------------------------------------------------------------------------------- #
# Capture output                                                                               #
# ------------------------------------------------------------------------------------------- #

# How long to wait for room in the fifo before looking at whether the capture is being stopped.
WRITE_POLL_MS = 200

POLL_ERRORS = select.POLLERR | select.POLLHUP | select.POLLNVAL


class Sink:
    """Where the capture goes, and how it notices that nobody is reading it any more.

    Wireshark ends a capture by taking away the process that reads the fifo, sending the extcap
    program SIGTERM and then giving it thirty seconds to exit before killing it. Both of those have
    to be answered, or the stop button does nothing and Wireshark stalls for that half minute.

    Noticing the reader has gone cannot wait until there is something to write, because on a quiet
    channel there may be no next frame for minutes. Poll reports POLLERR on the writing end of a
    pipe or fifo as soon as the reading end closes, with nothing having to be written to it, so the
    far end is watched directly.

    Answering the signal means never being inside a call that ignores it. A write to a fifo the
    reader has stopped draining blocks, and a blocked write cannot be interrupted -- Python runs
    the signal handler and then retries the call -- so the fifo is kept non-blocking and waiting
    for room is done with poll, which can be given up on. A capture written to a file needs none of
    this: its reader cannot go away and its writes cannot block.
    """

    def __init__(self, fd, close_fd=True):
        self.fd = fd
        self.close_fd = close_fd
        self.poller = None

        # Only a pipe or a fifo has a reader that can leave and a write that can block. A file or a
        # terminal is written as it always was, not least because making a terminal non-blocking
        # would leave it that way for the shell that lent it to us.
        if not stat.S_ISFIFO(os.fstat(fd).st_mode):
            return

        os.set_blocking(fd, False)
        self.poller = select.poll()
        self.poller.register(fd, select.POLLOUT)

    def reader_gone(self):
        """Whether whoever reads this has closed their end, asked without writing anything."""
        if self.poller is None:
            return False

        return any(events & POLL_ERRORS for _, events in self.poller.poll(0))

    def write(self, data):
        """Write a block whole, waiting for room only as long as the capture is still wanted."""
        view = memoryview(data)

        while view:
            if self.poller and not self._wait_writable():
                # The reader has gone or the capture is stopping; the rest of the block has
                # nowhere useful to go. Whoever is reading has to resynchronise anyway.
                return

            try:
                written = os.write(self.fd, view)
            except BlockingIOError:
                continue

            view = view[written:]

    def close(self):
        if self.close_fd:
            os.close(self.fd)
        elif self.poller:
            # Hand the pipe back the way it was lent to us.
            os.set_blocking(self.fd, True)

    def _wait_writable(self):
        while not stop_requested:
            for _, events in self.poller.poll(WRITE_POLL_MS):
                if events & POLL_ERRORS:
                    return False
                if events & select.POLLOUT:
                    return True

        return False


# ------------------------------------------------------------------------------------------- #
# PCAP-NG stream                                                                               #
# ------------------------------------------------------------------------------------------- #


class Settings:
    """What a running capture can still be told to do differently.

    The PHY and how frames are timestamped are chosen before a capture starts, from the command
    line or from Wireshark's interface options, but the toolbar can change either of them while it
    runs. Both are kept here so that whoever changes them and whoever acts on them do not have to
    know about each other: the toolbar thread writes, the forwarding loop reads, and neither reads
    a half-written value because each field is written whole.
    """

    def __init__(self, phy, host_timestamps=True):
        self.phy = list(phy)
        self.host_timestamps = host_timestamps


class Stream:
    """Forwards whole PCAP-NG blocks, starting at a section header.

    The firmware writes continuously, so a reader attaching at an arbitrary moment can land in the
    middle of a block. Everything before the first section header is therefore discarded, and from
    then on blocks are only passed on once they have arrived complete.
    """

    def __init__(self, out, settings):
        self.out = out
        self.settings = settings
        self.buf = bytearray()
        self.synced = False
        self.offset_us = None
        self.bound_us = None
        self.warmup_until = None
        self.held = []
        self.blocks = 0
        self.packets = 0

    def feed(self, data=b""):
        self.buf.extend(data)

        # Even an empty feed has to get here: it is what releases the held blocks when the warm-up
        # ends during a lull, rather than leaving them until the next frame turns up.
        self._release()

        if not self.synced and not self._sync():
            return

        while len(self.buf) >= 12:
            block_type, block_len = struct.unpack_from("<II", self.buf, 0)

            if block_len < 12 or block_len % 4 or block_len > MAX_BLOCK_LEN:
                warn(f"implausible block length {block_len}, looking for the next section")
                self.synced = False
                del self.buf[:4]
                if not self._sync():
                    return
                continue

            if len(self.buf) < block_len:
                return

            block = bytes(self.buf[:block_len])
            del self.buf[:block_len]

            if block_type == BLOCK_TYPE_EPB:
                self.packets += 1

            self._emit(block, block_type)

    def _sync(self):
        """Drop everything before the first section header. Returns whether one was found."""
        start = self.buf.find(SHB_MAGIC)
        if start < 0:
            # Keep the tail, in case it holds the beginning of the magic.
            del self.buf[: max(0, len(self.buf) - (len(SHB_MAGIC) - 1))]
            return False

        if start:
            log(f"skipped {start} octets to reach the start of a section")

        del self.buf[:start]
        self.synced = True

        return True

    def _write(self, block):
        self.out.write(block)
        self.blocks += 1

    def _emit(self, block, block_type):
        """Write a block out, or hold it back while the clock offset is still being estimated."""
        if not self.settings.host_timestamps:
            # Held blocks were captured while host timestamps were still wanted, so they keep them.
            self._release(force=True)
            self._write(block)
            return

        if self.offset_us is not None:
            self._write(self._retime(block) if block_type == BLOCK_TYPE_EPB else block)
            return

        if block_type == BLOCK_TYPE_EPB:
            self._observe(block)
            if self.warmup_until is None:
                self.warmup_until = time.monotonic() + WARMUP_SECONDS

        if self.warmup_until is None:
            # The section header and interface description, which carry no timestamp to correct.
            self._write(block)
            return

        self.held.append(block)
        self._release()

    def _observe(self, block):
        """Take one estimate of the offset between the device clock and the host clock.

        A frame can only reach us after it was captured, so "now minus the device timestamp" is an
        upper bound on that offset, and the smallest bound seen is the best estimate of it.
        """
        high, low = struct.unpack_from("<II", block, 12)
        bound = int(time.time() * 1_000_000) - ((high << 32) | low)

        if self.bound_us is None or bound < self.bound_us:
            self.bound_us = bound

    def _release(self, force=False):
        """Fix the offset once the warm-up is over, and write out everything held back for it."""
        if self.offset_us is not None or self.warmup_until is None:
            return

        if not force and time.monotonic() < self.warmup_until:
            return

        self.offset_us = self.bound_us
        held, self.held = self.held, []

        for block in held:
            block_type = struct.unpack_from("<I", block, 0)[0]
            self._write(self._retime(block) if block_type == BLOCK_TYPE_EPB else block)

    def close(self):
        """Write out anything still held back. A capture can end during the warm-up."""
        self._release(force=True)

    def _retime(self, block):
        """Rebase a frame's timestamp from device uptime onto the host clock.

        The firmware counts microseconds since it booted, which Wireshark would otherwise display
        as a date in 1970. One offset is added to every frame, so the spacing between them stays
        exactly as the device measured it.

        That the offset is a single number is the whole point, and it used to not be. The estimate
        was refined as better bounds arrived, which sounds harmless and is not: lowering it moves
        every later frame earlier relative to the ones already written out, so the spacing between
        frames came out shorter than the device measured. A capture opens with the dongle draining
        whatever it staged while nothing was reading, and the frames behind that backlog reach us
        late through a pipe that is still catching up, so the early bounds are the worst ones and
        the correction was largest exactly where the traffic was densest.

        Estimating for a moment and then leaving it alone gets both halves right: the bound has
        stopped improving by the end of the warm-up, and nothing after it distorts spacing.
        """
        high, low = struct.unpack_from("<II", block, 12)
        stamp = ((high << 32) | low) + self.offset_us
        patched = bytearray(block)
        struct.pack_into("<II", patched, 12, stamp >> 32, stamp & 0xFFFFFFFF)

        return bytes(patched)


def forward(port, out, settings):
    """Pump the capture port into @p out until stopped, and report what got through."""
    stream = Stream(out, settings)

    try:
        while not stop_requested:
            if out.reader_gone():
                log("the reader closed the capture")
                break

            # Fed even when the read timed out, so the warm-up can end in a lull rather than
            # waiting for the next frame to push the held ones out.
            stream.feed(port.read(4096))
    except (BrokenPipeError, OSError) as err:
        # The reader going away is the normal way a capture ends.
        if getattr(err, "errno", None) not in (errno.EPIPE, errno.EBADF, None):
            warn(f"capture stopped: {err}")

    try:
        stream.close()
    except (BrokenPipeError, OSError):
        # Nothing to be done about a reader that has already gone; the counts below are still true.
        pass

    return stream


# ------------------------------------------------------------------------------------------- #
# Wireshark toolbar controls                                                                   #
# ------------------------------------------------------------------------------------------- #

# The controls, in the order they are shown. Every message names one of them by number, so these
# are part of the protocol rather than a local convenience.
CONTROL_DOMAIN = 0
CONTROL_CHAN_PLAN = 1
CONTROL_PHY_MODE = 2
CONTROL_CHANNEL = 3
CONTROL_DEVICE_TIMESTAMPS = 4
CONTROL_STATISTICS = 5
CONTROL_LOG = 6
CONTROL_HELP = 7

# For the messages that address the window rather than a control: the status bar and the dialogs.
CONTROL_NONE = 255

# Which part of the PHY each of the four PHY controls stands for: where it sits in Settings.phy,
# the shell command that changes it, and what to call it in a message.
PHY_CONTROLS = {
    CONTROL_DOMAIN: (0, "domain", "regulatory domain"),
    CONTROL_CHAN_PLAN: (1, "plan", "ChanPlanID"),
    CONTROL_PHY_MODE: (2, "mode", "PhyModeID"),
    CONTROL_CHANNEL: (3, "channel", "channel"),
}

# What a message asks for. Wireshark sends SET when a control is used and INITIALIZED once the
# toolbar is ready; the rest are only ever sent the other way.
CMD_INITIALIZED = 0
CMD_SET = 1
CMD_ADD = 2
CMD_REMOVE = 3
CMD_ENABLE = 4
CMD_DISABLE = 5
CMD_STATUSBAR = 6
CMD_INFORMATION = 7
CMD_WARNING = 8
CMD_ERROR = 9

# Every message starts with this octet, then a 24-bit big-endian length covering the control
# number, the command and the payload.
CONTROL_INDICATION = ord("T")
CONTROL_HEADER_LEN = 6

# Wireshark will not send more than this in one message, so a longer one means the place in the
# stream has been lost rather than that something very large is on its way.
CONTROL_MAX_PAYLOAD = 65535

# How long to wait for a control message before looking at whether the capture is being stopped.
CONTROL_POLL_MS = 200

# How long to keep trying to open the pipe back to Wireshark before deciding there is no toolbar.
CONTROL_OPEN_TIMEOUT = 10.0


def extcap_controls():
    """Declare the toolbar Wireshark shows above the packet list while this interface captures.

    These belong to the interface list and not to the interface options: Wireshark reads them once,
    out of --extcap-interfaces, and builds a single toolbar that every dongle this script offers
    then shares. Each value sentence has to follow the control it belongs to.

    The toolbar offers the same PHY as the options dialog because that is the point of it: which
    channel something can be heard on is found by trying them, and stopping the capture to try the
    next one loses whatever arrives in between.
    """
    print(
        f"control {{number={CONTROL_DOMAIN}}}{{type=selector}}{{display=Domain}}"
        f"{{tooltip={TOOLTIP_DOMAIN}}}"
    )
    for code, name in REGULATORY_DOMAINS:
        default = "{default=true}" if code == DEFAULT_PHY[0] else ""
        print(f"value {{control={CONTROL_DOMAIN}}}{{value={code}}}{{display={name}}}{default}")

    print(
        f"control {{number={CONTROL_CHAN_PLAN}}}{{type=string}}{{display=ChanPlanID}}"
        f"{{default={DEFAULT_PHY[1]}}}{{validation=^[0-9]{{1,3}}$}}{{required=true}}"
        f"{{tooltip={TOOLTIP_CHAN_PLAN}}}"
    )

    print(
        f"control {{number={CONTROL_PHY_MODE}}}{{type=selector}}{{display=PhyModeID}}"
        f"{{tooltip={TOOLTIP_PHY_MODE}}}"
    )
    for value, name in PHY_MODES:
        default = "{default=true}" if value == DEFAULT_PHY[2] else ""
        print(
            f"value {{control={CONTROL_PHY_MODE}}}{{value={phy_mode_text(value)}}}"
            f"{{display={name}}}{default}"
        )

    print(
        f"control {{number={CONTROL_CHANNEL}}}{{type=string}}{{display=Channel}}"
        f"{{default={DEFAULT_PHY[3]}}}{{validation=^[0-9]{{1,3}}$}}{{required=true}}"
        f"{{tooltip={TOOLTIP_CHANNEL}}}"
    )

    print(
        f"control {{number={CONTROL_DEVICE_TIMESTAMPS}}}{{type=boolean}}"
        f"{{display=Device timestamps}}{{default=false}}{{tooltip={TOOLTIP_DEVICE_TIMESTAMPS}}}"
    )

    print(
        f"control {{number={CONTROL_STATISTICS}}}{{type=button}}{{display=Statistics}}"
        "{tooltip=Show the dongle's receive counters. Every sync detect should have become a "
        "frame; anything counted as dropped is a frame the dongle received but left out of the "
        "capture because the host was not reading fast enough.}"
    )
    print(
        f"control {{number={CONTROL_LOG}}}{{type=button}}{{role=logger}}{{display=Log}}"
        "{tooltip=Show what the capture has been asked to do and what came of it}"
    )
    print(
        f"control {{number={CONTROL_HELP}}}{{type=button}}{{role=help}}{{display=Help}}"
        "{tooltip=Open the documentation for this sniffer}"
    )


class Toolbar:
    """The controls above the packet list, and what using one does.

    Wireshark hands out two pipes for these: one it writes control messages to, one it reads them
    from. Everything to do with them happens on a thread of its own, because none of it can be done
    between two reads of the capture port. Opening either pipe waits for Wireshark to open the
    other end, messages arrive whenever somebody clicks something, and answering one takes a round
    trip to the firmware's shell -- which is far too long to stop draining the capture port for.
    The forwarding loop therefore never touches any of this. The two threads meet at the Settings
    object and nowhere else, and only this thread writes to Wireshark.

    It is a daemon thread: a capture has to end promptly however it was ended, and not wait for a
    message on a pipe that Wireshark has already stopped writing to.
    """

    def __init__(self, control_in, control_out, serial_number, settings):
        self.control_in = control_in
        self.control_out = control_out
        self.serial_number = serial_number
        self.settings = settings
        self.out_fd = None
        self.initialized = False

    def start(self):
        """Begin serving the toolbar, and return at once whether or not there proves to be one."""
        threading.Thread(target=self._run, name="toolbar", daemon=True).start()

    def _run(self):
        # The reading end is opened first, and without blocking, because Wireshark opens the other
        # end of it from the thread its window runs on and waits there until this one is open.
        try:
            fd = os.open(self.control_in, os.O_RDONLY | os.O_NONBLOCK)
        except OSError as err:
            log(f"no toolbar: cannot read control messages from {self.control_in}: {err}")
            return

        try:
            self.out_fd = self._open_out()
            if self.out_fd is None:
                return

            self._log(f"capturing from {self.serial_number}")
            self._read_loop(fd)
        except OSError as err:
            log(f"the toolbar stopped: {err}")
        finally:
            os.close(fd)
            if self.out_fd is not None:
                os.close(self.out_fd)
                self.out_fd = None

    def _open_out(self):
        """Open the pipe back to Wireshark, which only takes if it is already listening on it.

        Opening it without blocking fails with ENXIO until then, which turns the wait into a loop
        that a stop request gets out of -- and one that gives up, since a Wireshark that never
        opens its end is a capture that is not going to have a toolbar.
        """
        deadline = time.monotonic() + CONTROL_OPEN_TIMEOUT

        while not stop_requested and time.monotonic() < deadline:
            try:
                return os.open(self.control_out, os.O_WRONLY | os.O_NONBLOCK)
            except OSError as err:
                if err.errno != errno.ENXIO:
                    raise

                time.sleep(0.05)

        log(f"no toolbar: nothing is reading {self.control_out}")

        return None

    def _read_loop(self, fd):
        """Take messages from Wireshark until it stops sending them or the capture ends."""
        poller = select.poll()
        poller.register(fd, select.POLLIN)
        buf = bytearray()

        while not stop_requested:
            for _, events in poller.poll(CONTROL_POLL_MS):
                if events & select.POLLIN:
                    data = os.read(fd, 4096)
                    if not data:
                        # Wireshark closes this when the capture stops; there is nothing more to
                        # come, but the capture itself ends the way it always does.
                        return

                    buf.extend(data)
                    if not self._dispatch(buf):
                        return
                elif events & POLL_ERRORS:
                    return

    def _dispatch(self, buf):
        """Hand on every complete message in @p buf. Returns whether the pipe still makes sense."""
        while len(buf) >= CONTROL_HEADER_LEN:
            if buf[0] != CONTROL_INDICATION:
                log("lost the place in the control messages, giving up on the toolbar")
                return False

            length = int.from_bytes(buf[1:4], "big")
            if length < 2 or length > CONTROL_MAX_PAYLOAD + 2:
                log(f"implausible control message length {length}, giving up on the toolbar")
                return False

            if len(buf) < 4 + length:
                return True

            number, command = buf[4], buf[5]
            payload = bytes(buf[CONTROL_HEADER_LEN : 4 + length])
            del buf[: 4 + length]

            self._handle(number, command, payload)

        return True

    def _handle(self, number, command, payload):
        if command == CMD_INITIALIZED:
            # Anything before this is the toolbar repeating what it was left set to at the end of
            # some earlier capture. This one was configured in the interface options dialog and the
            # PHY has already been programmed from it, so the toolbar is corrected rather than
            # obeyed: from here on it shows what the dongle is really doing.
            self.initialized = True
            self._publish()
            return

        if not self.initialized or command != CMD_SET:
            return

        if number in PHY_CONTROLS:
            self._change_phy(number, payload)
        elif number == CONTROL_DEVICE_TIMESTAMPS:
            self._change_timestamps(payload)
        elif number == CONTROL_STATISTICS:
            self._report_statistics()

    def _change_phy(self, number, payload):
        """Reprogram the transceiver for one field of the PHY, and say what became of the rest."""
        index, field, name = PHY_CONTROLS[number]
        text = payload.decode(errors="replace").strip()

        try:
            value = parse_int(text)
        except ValueError:
            value = -1

        if not 0 <= value <= 255:
            self._failed(f"{name} has to be a number from 0 to 255, not {text!r}")
            return

        if value == self.settings.phy[index]:
            return

        error = set_phy_field(self.serial_number, field, value)
        if error:
            # The toolbar goes back to the PHY that is still in use: the firmware validates a
            # combination before it programs any of it, so a refusal changes nothing.
            self._publish_phy()
            self._failed(error)
            return

        # What the firmware settled on, which is not necessarily what was asked for: a channel plan
        # takes an operating mode it can run with, and a channel out of range is one it can reach.
        phy, error = read_phy(self.serial_number)
        if error:
            self._failed(f"the PHY was changed but cannot be read back: {error}")
            return

        self.settings.phy = phy
        self._publish_phy()

        domain, plan, mode, channel = phy
        self._announce(
            f"{name} set to {value}: listening in domain {domain} on ChanPlanID {plan}, "
            f"PhyModeID {phy_mode_text(mode)}, channel {channel}"
        )

    def _change_timestamps(self, payload):
        """Switch between device and host timestamps, which a checkbox states as one octet."""
        device = len(payload) > 0 and payload[0] != 0

        if device == (not self.settings.host_timestamps):
            return

        self.settings.host_timestamps = not device
        self._announce(
            "timestamping frames with the device uptime, from 1970"
            if device
            else "timestamping frames with the host clock"
        )

    def _report_statistics(self):
        """Show the firmware's receive counters, which is what the button was pressed for.

        This is the one control that cannot answer immediately -- it takes a round trip to the
        shell on the dongle's other USB interface -- so the button goes dead while it runs rather
        than looking as though the click was missed.
        """
        self._send(CONTROL_STATISTICS, CMD_DISABLE)

        try:
            text, error = console_command(
                self.serial_number, "wisun_sniffer stats", expect="capture drops"
            )
            if error:
                self._failed(f"cannot read the counters: {error}")
                return

            # The shell echoes what it was sent and prints its prompt around the answer; the
            # counters are the lines that are a name and a number.
            counters = [line.strip() for line in text.splitlines() if " : " in line]

            self._show(f"Wi-SUN sniffer {self.serial_number}\n\n" + "\n".join(counters))
        finally:
            self._send(CONTROL_STATISTICS, CMD_ENABLE)

    def _publish(self):
        """Set every control to what this capture is actually doing.

        The PHY is read off the dongle rather than repeated back from the interface options: those
        are what the firmware was asked for at the start of the capture, and if it did not take
        them the toolbar would be the last place that should say so.
        """
        phy, error = read_phy(self.serial_number)
        if phy:
            self.settings.phy = phy
        else:
            self._log(f"cannot read the PHY back, showing what was asked for: {error}")

        self._publish_phy()
        self._send(
            CONTROL_DEVICE_TIMESTAMPS,
            CMD_SET,
            b"\x00" if self.settings.host_timestamps else b"\x01",
        )

    def _publish_phy(self):
        for number, (index, _, _) in PHY_CONTROLS.items():
            value = self.settings.phy[index]
            text = phy_mode_text(value) if number == CONTROL_PHY_MODE else str(value)

            # A selector shows nothing at all unless what is sent back is one of the values it was
            # declared with, so the PhyModeID has to go back in the form it went out in.
            self._send(number, CMD_SET, text)

    def _announce(self, message):
        """Report something that went as asked: in the log, and along the bottom of the window."""
        self._log(message)
        self._send(CONTROL_NONE, CMD_STATUSBAR, message)

    def _show(self, message):
        """Put an answer in front of whoever asked for it, and keep a copy in the log.

        A dialog, because this answers a button that was pressed to see something: the log is a
        record of the capture rather than somewhere to look things up, and it takes another click
        to open.
        """
        self._log(message)
        self._send(CONTROL_NONE, CMD_INFORMATION, message)

    def _failed(self, message):
        """Report something that did not, in a dialog, since it answers something just clicked.

        Not on stderr: Wireshark keeps that until the capture ends and then presents it as the
        reason it ended, and a channel number the firmware would not take ends nothing.
        """
        self._log(message)
        self._send(CONTROL_NONE, CMD_WARNING, message)

    def _log(self, message):
        """Add a line to the log that the toolbar's Log button opens."""
        self._send(CONTROL_LOG, CMD_ADD, f"{time.strftime('%H:%M:%S')}  {message}\n")

    def _send(self, number, command, payload=b""):
        """Send one control message, giving up on the message rather than on the capture."""
        if self.out_fd is None:
            return

        if isinstance(payload, str):
            payload = payload.encode()

        payload = payload[:CONTROL_MAX_PAYLOAD]
        header = struct.pack(">BBHBB", CONTROL_INDICATION, 0, len(payload) + 2, number, command)

        try:
            os.write(self.out_fd, header + payload)
        except OSError as err:
            # Wireshark stops reading this when the capture stops, which is not worth reporting.
            log(f"a toolbar message went nowhere: {err}")


# ------------------------------------------------------------------------------------------- #
# Capture                                                                                      #
# ------------------------------------------------------------------------------------------- #


def open_fifo(fifo):
    """Wait for a reader to open @p fifo, in a way that can be given up on.

    Opening a fifo for writing waits for the reader, which is exactly the moment the capture
    should start -- but a blocking open cannot be interrupted: the signal handler runs, then
    Python retries the call, so ctrl-c and Wireshark abandoning the capture would both leave the
    script waiting for a reader that is never coming. Opening without blocking fails with ENXIO
    until a reader is there, which turns the wait into a loop that can be told to stop.
    """
    while not stop_requested:
        try:
            return os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        except OSError as err:
            if err.errno != errno.ENXIO:
                raise SystemExit(f"cannot open the capture fifo {fifo}: {err}")

            time.sleep(0.1)

    log("stopped before a reader opened the fifo")
    raise SystemExit(0)


def open_output(fifo, path):
    """Open wherever the capture is to go, which for a fifo waits for the reader to turn up."""
    if fifo:
        if not os.path.exists(fifo):
            os.mkfifo(fifo, 0o600)
        elif not stat.S_ISFIFO(os.stat(fifo).st_mode):
            raise SystemExit(f"{fifo} exists and is not a fifo")

        log(f"waiting for a reader: wireshark -k -i {fifo}")

        return Sink(open_fifo(fifo))

    if path:
        return Sink(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644))

    return Sink(sys.stdout.fileno(), close_fd=False)


def capture(serial_number, fifo, path, phy, host_timestamps, controls=None):
    """Select the PHY if asked to, then forward the stream until stopped."""
    capture_path = device_path(serial_number, CAPTURE_SUFFIX)
    if not os.path.exists(capture_path):
        raise SystemExit(f"no capture interface at {capture_path}; is the dongle plugged in?")

    if phy:
        log("setting the PHY to domain {} plan {} mode {} channel {}".format(*phy))
        error = set_phy(serial_number, *phy)
        if error:
            warn(error)

    settings = Settings(phy or DEFAULT_PHY, host_timestamps=host_timestamps)

    if controls:
        # Before the output is opened, because that waits for Wireshark to open the other end of
        # the capture fifo while Wireshark's window is itself waiting to be let into the control
        # pipes. Only this end of them is under our control, so it is opened first.
        control_in, control_out = controls
        Toolbar(control_in, control_out, serial_number, settings).start()

    # The output is opened before the port, so that the firmware is told a reader has attached at
    # the moment one really has: the fresh section then starts ahead of the first frame the reader
    # will see, rather than behind whatever the dongle had buffered while it was waiting.
    out = open_output(fifo, path)
    port = open_capture_port(capture_path)

    log(f"capturing from {serial_number}, stop with ctrl-c")

    try:
        stream = forward(port, out, settings)
    finally:
        port.close()
        try:
            out.close()
        except OSError:
            pass

    log(f"forwarded {stream.packets} frames in {stream.blocks} blocks")


# ------------------------------------------------------------------------------------------- #
# extcap protocol                                                                              #
# ------------------------------------------------------------------------------------------- #


def extcap_interfaces():
    print(f"extcap {{version={VERSION}}}{{help={HELP_URL}}}{{display=Wi-SUN sniffer}}")

    for serial_number in find_dongles():
        print(
            f"interface {{value={interface_value(serial_number)}}}"
            f"{{display=Wi-SUN Sniffer Dongle {serial_number}}}"
        )

    extcap_controls()


def extcap_dlts():
    print(
        f"dlt {{number={DLT_IEEE802_15_4_TAP}}}{{name=IEEE802_15_4_TAP}}"
        f"{{display=IEEE 802.15.4 with TAP pseudo-header}}"
    )


def extcap_config():
    """Describe the interface options, which are the PHY plus how frames are timestamped.

    The numbers here have to line up with the command line below: Wireshark passes each option back
    as the "call" string it is declared with. These are what a capture starts with; the toolbar
    declared above offers the same four PHY fields again, for changing while it runs.
    """
    print(
        f"arg {{number=0}}{{call=--domain}}{{display=Regulatory domain}}{{type=selector}}"
        f"{{default={DEFAULT_PHY[0]}}}{{tooltip={TOOLTIP_DOMAIN}}}"
    )
    for code, name in REGULATORY_DOMAINS:
        print(f"value {{arg=0}}{{value={code}}}{{display={name}}}")

    print(
        f"arg {{number=1}}{{call=--chan-plan}}{{display=ChanPlanID}}{{type=integer}}"
        f"{{range=0,255}}{{default={DEFAULT_PHY[1]}}}{{tooltip={TOOLTIP_CHAN_PLAN}}}"
    )
    print(
        f"arg {{number=2}}{{call=--phy-mode}}{{display=PhyModeID}}{{type=selector}}"
        f"{{default={phy_mode_text(DEFAULT_PHY[2])}}}{{tooltip={TOOLTIP_PHY_MODE}}}"
    )
    for value, name in PHY_MODES:
        print(f"value {{arg=2}}{{value={phy_mode_text(value)}}}{{display={name}}}")

    print(
        f"arg {{number=3}}{{call=--channel}}{{display=Channel}}{{type=integer}}{{range=0,255}}"
        f"{{default={DEFAULT_PHY[3]}}}{{tooltip={TOOLTIP_CHANNEL}}}"
    )
    print(
        f"arg {{number=4}}{{call=--device-timestamps}}"
        f"{{display=Timestamp frames with the device uptime}}{{type=boolflag}}{{default=false}}"
        f"{{tooltip={TOOLTIP_DEVICE_TIMESTAMPS}}}"
    )


# ------------------------------------------------------------------------------------------- #
# Command line                                                                                 #
# ------------------------------------------------------------------------------------------- #


def build_parser():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--list", action="store_true", help="list the attached dongles and exit")
    parser.add_argument("--serial", help="capture from the dongle with this USB serial number")

    output = parser.add_mutually_exclusive_group()
    output.add_argument(
        "--fifo",
        metavar="PATH",
        help="write to this named pipe, creating it if needed, and wait for a reader to open it",
    )
    output.add_argument("-w", "--write", metavar="PATH", help="write to this file")

    phy = parser.add_argument_group(
        "Wi-SUN PHY",
        "Selecting any part of the PHY sends the whole of it to the firmware, which is the only "
        f"way it can validate the combination. Parts left out fall back to {DEFAULT_PHY}, the PHY "
        "the firmware boots with. Give none of these to capture on whatever it is already on.",
    )
    phy.add_argument("--domain", type=int, help="regulatory domain, e.g. 3 for EU")
    phy.add_argument("--chan-plan", type=int, help="ChanPlanID, e.g. 32 for 863.1 MHz / 100 kHz")
    phy.add_argument(
        "--phy-mode",
        type=parse_int,
        help="PhyModeID in hex: 0x01, 0x03 or 0x05, or 0x11, 0x13 or 0x15 with FEC",
    )
    phy.add_argument("--channel", type=int, help="channel number within the channel plan")

    parser.add_argument(
        "--device-timestamps",
        action="store_true",
        help="timestamp frames with the device uptime instead of the host clock, which dates them "
        "from 1970 but leaves the numbers exactly as the dongle measured them",
    )

    # What Wireshark calls this script with. They are hidden from --help because they are of no use
    # at a command line: everything they do has a plainer spelling above.
    extcap = parser.add_argument_group("Wireshark")
    for flag in ("--extcap-interfaces", "--extcap-dlts", "--extcap-config", "--capture"):
        extcap.add_argument(flag, action="store_true", help=argparse.SUPPRESS)
    extcap.add_argument("--extcap-version", nargs="?", help=argparse.SUPPRESS)
    extcap.add_argument("--extcap-interface", help=argparse.SUPPRESS)
    # Named from Wireshark's end of them: control-in is the pipe it writes and this script reads.
    extcap.add_argument("--extcap-control-in", metavar="PIPE", help=argparse.SUPPRESS)
    extcap.add_argument("--extcap-control-out", metavar="PIPE", help=argparse.SUPPRESS)

    return parser


def selected_phy(args):
    """The PHY to program, or None to leave the firmware on whatever it is already using."""
    selection = (args.domain, args.chan_plan, args.phy_mode, args.channel)

    if all(part is None for part in selection):
        return None

    return tuple(
        fallback if part is None else part for part, fallback in zip(selection, DEFAULT_PHY)
    )


def main():
    global quiet

    parser = build_parser()

    # Wireshark passes options this interface does not use, such as a capture filter, and rejecting
    # those would fail the capture. A command line typo still has to be reported, so anything left
    # over is only tolerated when Wireshark is the caller.
    args, unused = parser.parse_known_args()
    controls = None

    if args.extcap_interfaces:
        extcap_interfaces()
        return 0

    if args.extcap_dlts:
        extcap_dlts()
        return 0

    if args.extcap_config:
        extcap_config()
        return 0

    if args.list:
        for serial_number in find_dongles():
            print(serial_number)
        return 0

    if args.capture:
        # Wireshark makes the fifo itself and always states the whole PHY, so open_output() finds
        # the fifo already there and selected_phy() never has to fall back. It also shows whatever
        # reaches stderr as the reason the capture ended, so from here on only warn() writes there.
        quiet = True

        if not args.fifo:
            raise SystemExit("--capture needs --fifo")
        serial_number = serial_from_interface(args.extcap_interface)

        # Only passed when there is a toolbar to serve, which means the Wireshark window: tshark
        # parses the same control declarations and then leaves both of these out.
        if args.extcap_control_in and args.extcap_control_out:
            controls = (args.extcap_control_in, args.extcap_control_out)
    else:
        if unused:
            parser.error(f"unrecognised arguments: {' '.join(unused)}")
        serial_number = pick_dongle(args.serial)

    capture(
        serial_number,
        args.fifo,
        args.write,
        selected_phy(args),
        host_timestamps=not args.device_timestamps,
        controls=controls,
    )

    return 0


def handle_stop(signum, frame):
    del signum, frame
    request_stop()


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, handle_stop)
    signal.signal(signal.SIGINT, handle_stop)
    sys.exit(main())
