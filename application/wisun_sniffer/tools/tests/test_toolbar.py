# SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH
# SPDX-License-Identifier: GPL-3.0-or-later

"""Drive the toolbar controls the way the Wireshark window does.

The script runs as a real subprocess, because the toolbar is a protocol between two programs and
testing our half of it by calling functions would not exercise the half that goes wrong. Ptys stand
in for the two CDC ACM interfaces, fifos for the capture pipe and the two control pipes, and a
thread answers the console the way the firmware's shell would -- including refusing the PHY
combinations the standard does not allow, which is what makes changing one field at a time
interesting.

Wireshark's side is played out byte for byte: its reader thread opens the pipe the extcap writes,
its window thread opens the pipe the extcap reads, and INITIALIZED goes out once both are up.

These tests share one capture and run in the order they are written. That is deliberate rather than
lazy: each step leaves the dongle on a PHY the next one starts from, which is the sequence a person
at the toolbar produces, and it is where the interesting faults live.
"""

import errno
import os
import select
import signal
import struct
import subprocess
import sys
import threading
import time

import pytest

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="needs ptys and fifos")

SERIAL = "TEST01"

# Control numbers, which have to match the ones the script declares to Wireshark.
CTRL_DOMAIN, CTRL_PLAN, CTRL_MODE, CTRL_CHANNEL = 0, 1, 2, 3
CTRL_TIMESTAMPS, CTRL_STATS, CTRL_LOG = 4, 5, 6
CTRL_NONE = 255

CMD_INITIALIZED, CMD_SET, CMD_ADD = 0, 1, 2
CMD_ENABLE, CMD_DISABLE, CMD_STATUSBAR = 4, 5, 6
CMD_INFORMATION, CMD_WARNING = 7, 8

# What the firmware allows. In EU, ChanPlanID 32 runs PhyModeID 1 and 33 runs 3 or 5, so neither
# can be set first on its own -- the per-field commands exist exactly for that.
MODES_FOR_PLAN = {32: [1], 33: [3, 5]}


def sandbox(script, directory):
    """Copy @p script with the two things a pty cannot provide patched out.

    Both replacements are asserted, so that renaming either in the script fails the test loudly
    rather than leaving it quietly exercising the unpatched original.
    """
    with open(script, encoding="utf-8") as handle:
        source = handle.read()
    byid = os.path.join(directory, "byid")

    source, count = _replace(source, 'BY_ID = "/dev/serial/by-id"', f'BY_ID = "{byid}"')
    assert count == 1, "BY_ID is not where this test expects it"

    # A pty has no modem control lines, so raising and lowering DTR raises OSError. On a dongle
    # this is what asks the firmware for a new section, and there is no firmware here to ask.
    for line in ("    port.dtr = True\n", "    port.dtr = False\n"):
        source, count = _replace(
            source, line, f"    try:\n    {line}    except OSError:\n        pass\n"
        )
        assert count == 1, f"{line.strip()} is not where this test expects it"

    path = os.path.join(directory, "wisun_sniffer_capture.py")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(source)
    os.chmod(path, 0o755)

    return path


def _replace(text, old, new):
    return text.replace(old, new), text.count(old)


class Firmware:
    """The dongle: a shell that answers on one pty and a capture stream written to the other."""

    def __init__(self):
        self.console_m, self.console_s = os.openpty()
        self.capture_m, self.capture_s = os.openpty()
        self.commands = []
        self.refuse = threading.Event()
        self.phy = [3, 32, 1, 0]
        self._stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _phy_block(self):
        return (
            f"domain    : EU ({self.phy[0]}), 863-876 MHz\r\n"
            f"chan plan : {self.phy[1]} (863_870_100), 100 kHz spacing, 69 channels\r\n"
            f"phy mode  : 0x{self.phy[2]:02x} (#1a), 50000 symbols/s, "
            f"modulation index 0.50\r\n"
            f"channel   : {self.phy[3]} (863.100 MHz)"
        )

    @staticmethod
    def _refused(domain, plan, mode):
        return (
            f"cannot listen to domain {domain}, ChanPlanID {plan}, PhyModeID {mode}: "
            f"-22 (the log says which part is wrong)"
        )

    def _answer(self, command):
        # Numbers are read with int(..., 0) throughout, because the firmware reads them the way C
        # does -- "0x13" as readily as "19" -- and a shell that only took decimal would accept
        # things the real one accepts while refusing things it does not.
        parts = command.split()

        if command == "wisun_sniffer phy":
            return self._phy_block()

        if command.startswith("wisun_sniffer phy "):
            # The whole PHY at once, refused unless the combination is one the standard allows.
            domain, plan, mode, channel = (int(part, 0) for part in parts[2:])
            if self.refuse.is_set() or mode not in MODES_FOR_PLAN.get(plan, []):
                return self._refused(domain, plan, mode)

            self.phy[:] = [domain, plan, mode, channel]
            return self._phy_block()

        if len(parts) > 2 and parts[1] in ("domain", "plan", "mode", "channel"):
            # One field, with the firmware settling the rest around it.
            index = ["domain", "plan", "mode", "channel"].index(parts[1])
            wanted = list(self.phy)
            wanted[index] = int(parts[2], 0)

            if index == 1 and wanted[2] not in MODES_FOR_PLAN.get(wanted[1], []):
                wanted[2] = (MODES_FOR_PLAN.get(wanted[1]) or [wanted[2]])[0]

            if self.refuse.is_set() or wanted[2] not in MODES_FOR_PLAN.get(wanted[1], []):
                return self._refused(*wanted[:3])

            self.phy[:] = wanted
            return self._phy_block()

        if command.startswith("wisun_sniffer stats"):
            return (
                "preamble detect : 44\r\nsync detect     : 42\r\nframes          : 42\r\n"
                "bad FCS         : 0\r\nbad PHR         : 0\r\nbad length      : 0\r\n"
                "fifo errors     : 0\r\ntimeouts        : 0\r\ncapture drops   : 0"
            )

        return f"{command}: command not found"

    def _serve(self):
        line = b""

        while not self._stop.is_set():
            readable, _, _ = select.select([self.console_m], [], [], 0.2)
            if not readable:
                continue

            try:
                line += os.read(self.console_m, 4096)
            except OSError:
                return

            if not line.endswith(b"\n") and not line.endswith(b"\r"):
                continue

            command = line.decode(errors="replace").strip()
            line = b""

            if not command:
                continue

            self.commands.append(command)
            os.write(self.console_m, f"\r\n{self._answer(command)}\r\nuart:~$ ".encode())

    def transmit(self, data):
        """Push capture-stream octets at the script, as the dongle's capture interface would."""
        os.write(self.capture_m, data)

    def stop(self):
        self._stop.set()


def _open_for_writing(path, child, timeout=10.0):
    """Open the pipe the extcap reads, giving up if it is never going to read it.

    A blocking open waits for a reader that will never come if the script exited on its way there
    -- with no pyserial in the interpreter running it, say -- and the test then hangs with nothing
    to say why. Opening without blocking fails with ENXIO until the reader is there instead, which
    turns the wait into a loop that can watch the child and report what became of it.
    """
    deadline = time.monotonic() + timeout

    while True:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
            # Only the open had to avoid blocking; writes are small and want the simpler failure.
            os.set_blocking(fd, True)

            return fd
        except OSError as err:
            if err.errno != errno.ENXIO:
                raise

        if child.poll() is not None:
            said = child.stderr.read().decode(errors="replace").strip()
            raise AssertionError(
                f"the capture script exited with {child.returncode} instead of "
                f"reading {path}: {said or 'it said nothing'}"
            )

        if time.monotonic() > deadline:
            raise AssertionError(f"the capture script did not open {path} within {timeout} s")

        time.sleep(0.02)


class Wireshark:
    """The window: writes control messages to the extcap and reads the ones it sends back."""

    def __init__(self, control_in, control_out, child):
        self.received = []
        self._lock = threading.Lock()
        threading.Thread(target=self._read, args=(control_out,), daemon=True).start()

        # The window thread's own open, which waits for the extcap to read the other end.
        self._out = _open_for_writing(control_in, child)

    def _read(self, path):
        fd = os.open(path, os.O_RDONLY)
        buf = bytearray()

        while True:
            data = os.read(fd, 4096)
            if not data:
                os.close(fd)
                return

            buf.extend(data)
            while len(buf) >= 6:
                assert buf[0] == ord("T"), f"bad control indication {buf[0]:#x}"
                length = int.from_bytes(buf[1:4], "big")
                if len(buf) < 4 + length:
                    break

                message = (buf[4], buf[5], bytes(buf[6 : 4 + length]))
                del buf[: 4 + length]
                with self._lock:
                    self.received.append(message)

    def send(self, number, command, payload=b""):
        if isinstance(payload, str):
            payload = payload.encode()

        os.write(
            self._out,
            struct.pack(">BBHBB", ord("T"), 0, len(payload) + 2, number, command) + payload,
        )

    def wait_for(self, predicate, what, timeout=5.0):
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            with self._lock:
                found = [message for message in self.received if predicate(message)]
            if found:
                return found
            time.sleep(0.02)

        raise AssertionError(f"timed out waiting for {what}; got {self.received}")

    def forget(self):
        with self._lock:
            self.received.clear()

    def values(self, *numbers):
        """The latest value published for each of @p numbers, as text."""
        with self._lock:
            return {n: p.decode() for n, c, p in self.received if c == CMD_SET and n in numbers}

    def payloads(self, number, command):
        with self._lock:
            return [p.decode() for n, c, p in self.received if n == number and c == command]

    def close(self):
        os.close(self._out)


class Session:
    """One capture, with the dongle and the window either side of it."""

    def __init__(self, script, directory):
        self.firmware = Firmware()
        self.captured = bytearray()

        byid = os.path.join(directory, "byid")
        os.makedirs(byid)
        for suffix, slave in (("if00", self.firmware.console_s), ("if02", self.firmware.capture_s)):
            os.symlink(
                os.ttyname(slave),
                os.path.join(byid, f"usb-Gardena_Wi-SUN_Sniffer_Dongle_{SERIAL}-{suffix}"),
            )

        self.fifo = os.path.join(directory, "fifo")
        control_in = os.path.join(directory, "control-in")
        control_out = os.path.join(directory, "control-out")
        for path in (self.fifo, control_in, control_out):
            os.mkfifo(path, 0o600)

        # Run by the interpreter running the tests rather than by the script's own shebang: the
        # one thing the script needs that the standard library does not provide is pyserial, and
        # the interpreter it was installed into is this one, not whichever python3 is on PATH.
        self.child = subprocess.Popen(
            [
                sys.executable,
                sandbox(script, directory),
                "--extcap-interface",
                f"wisun-{SERIAL}",
                "--capture",
                "--fifo",
                self.fifo,
                "--domain",
                "3",
                "--chan-plan",
                "32",
                "--phy-mode",
                "1",
                "--channel",
                "0",
                "--extcap-control-in",
                control_in,
                "--extcap-control-out",
                control_out,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        threading.Thread(target=self._drain, daemon=True).start()
        self.wireshark = Wireshark(control_in, control_out, self.child)

    def _drain(self):
        """What dumpcap does with the capture fifo."""
        fd = os.open(self.fifo, os.O_RDONLY)

        while True:
            readable, _, _ = select.select([fd], [], [], 0.1)
            if readable:
                data = os.read(fd, 65536)
                if not data:
                    os.close(fd)
                    return
                self.captured.extend(data)

    def timestamps(self):
        """The timestamp of every packet block that reached the fifo."""
        stamps = []
        offset = 0

        while offset + 12 <= len(self.captured):
            block_type, block_len = struct.unpack_from("<II", self.captured, offset)
            if block_len < 12:
                break
            if block_type == 6:
                high, low = struct.unpack_from("<II", self.captured, offset + 12)
                stamps.append((high << 32) | low)
            offset += block_len

        return stamps


def section_header():
    shb = b"\x0a\x0d\x0d\x0a" + (28).to_bytes(4, "little") + b"\x4d\x3c\x2b\x1a"
    shb += (1).to_bytes(2, "little") + (0).to_bytes(2, "little")
    shb += (0xFFFFFFFFFFFFFFFF).to_bytes(8, "little") + (28).to_bytes(4, "little")

    idb = (1).to_bytes(4, "little") + (20).to_bytes(4, "little")
    idb += (283).to_bytes(2, "little") + (0).to_bytes(2, "little")
    idb += (2112).to_bytes(4, "little") + (20).to_bytes(4, "little")

    return shb + idb


def packet(uptime_us):
    data = bytes(range(16))
    body = (0).to_bytes(4, "little")
    body += (uptime_us >> 32).to_bytes(4, "little") + (uptime_us & 0xFFFFFFFF).to_bytes(4, "little")
    body += len(data).to_bytes(4, "little") + len(data).to_bytes(4, "little") + data
    total = 12 + len(body)

    return (
        (6).to_bytes(4, "little") + total.to_bytes(4, "little") + body + total.to_bytes(4, "little")
    )


@pytest.fixture(scope="module")
def session(script_path, tmp_path_factory):
    """One capture for the whole module; the tests below walk it through a sequence."""
    started = Session(script_path, str(tmp_path_factory.mktemp("toolbar")))

    yield started

    started.firmware.stop()
    if started.child.poll() is None:
        started.child.kill()
        started.child.wait(timeout=10)

    # Popen with stdout=PIPE and stderr=PIPE hands two pipes to the caller to close. Left to the
    # garbage collector they raise ResourceWarning, which `filterwarnings = ["error"]` turns into
    # an error -- reported against whichever test happens to run next, since that is when pytest
    # collects unraisable exceptions.
    for pipe in (started.child.stdout, started.child.stderr):
        pipe.close()


def test_a_value_sent_before_initialized_is_ignored(session):
    """The toolbar repeats what it was left set to at the end of an earlier capture.

    This one was configured in the interface options dialog and the PHY has already been programmed
    from that, so the toolbar is corrected rather than obeyed.
    """
    session.wireshark.send(CTRL_CHANNEL, CMD_SET, "99")
    time.sleep(0.3)

    assert "wisun_sniffer phy 3 32 1 99" not in session.firmware.commands


def test_initialized_publishes_what_the_capture_is_really_doing(session):
    session.wireshark.send(0, CMD_INITIALIZED)
    published = session.wireshark.wait_for(
        lambda m: m[0] == CTRL_TIMESTAMPS and m[1] == CMD_SET, "the published timestamp mode"
    )

    assert session.wireshark.values(CTRL_DOMAIN, CTRL_PLAN, CTRL_MODE, CTRL_CHANNEL) == {
        CTRL_DOMAIN: "3",
        CTRL_PLAN: "32",
        CTRL_MODE: "0x01",
        CTRL_CHANNEL: "0",
    }
    assert session.firmware.commands.count("wisun_sniffer phy") == 1, (
        "the PHY is read off the dongle rather than repeated back from the command line"
    )
    assert published[0][2] == b"\x00", "host timestamps are published as an unticked box"


def test_a_channel_change_reprograms_the_transceiver(session):
    session.wireshark.forget()
    session.wireshark.send(CTRL_CHANNEL, CMD_SET, "7")
    session.wireshark.wait_for(
        lambda m: m[0] == CTRL_NONE and m[1] == CMD_STATUSBAR,
        "a status bar message about the channel",
    )

    assert "wisun_sniffer channel 7" in session.firmware.commands, "the field's own command is used"

    status = session.wireshark.payloads(CTRL_NONE, CMD_STATUSBAR)[0]
    assert "channel set to 7" in status


def test_a_plan_brings_a_mode_it_can_run_and_the_toolbar_is_told(session):
    """ChanPlanID 33 will not run PhyModeID 1, so the firmware moves the mode as well."""
    session.wireshark.forget()
    session.wireshark.send(CTRL_PLAN, CMD_SET, "33")
    session.wireshark.wait_for(
        lambda m: m[0] == CTRL_NONE and m[1] == CMD_STATUSBAR, "a status bar message about the plan"
    )

    assert session.wireshark.values(CTRL_DOMAIN, CTRL_PLAN, CTRL_MODE, CTRL_CHANNEL) == {
        CTRL_DOMAIN: "3",
        CTRL_PLAN: "33",
        CTRL_MODE: "0x03",
        CTRL_CHANNEL: "7",
    }, "the toolbar shows what the firmware settled on, not what was asked for"


def test_a_refused_phy_is_put_back_in_the_toolbar_too(session):
    """The firmware validates a combination before programming any of it, so a refusal changes
    nothing -- and the toolbar must not be left showing something the dongle is not doing."""
    session.wireshark.forget()
    session.firmware.refuse.set()

    session.wireshark.send(CTRL_MODE, CMD_SET, "5")
    warning = session.wireshark.wait_for(
        lambda m: m[0] == CTRL_NONE and m[1] == CMD_WARNING, "a warning dialog"
    )

    assert session.wireshark.values(CTRL_DOMAIN, CTRL_PLAN, CTRL_MODE, CTRL_CHANNEL) == {
        CTRL_DOMAIN: "3",
        CTRL_PLAN: "33",
        CTRL_MODE: "0x03",
        CTRL_CHANNEL: "7",
    }
    assert "refused" in warning[0][2].decode()

    session.firmware.refuse.clear()


def test_setting_a_control_to_what_it_already_is_does_nothing(session):
    before = len(session.firmware.commands)

    session.wireshark.send(CTRL_PLAN, CMD_SET, "33")
    time.sleep(0.3)

    assert len(session.firmware.commands) == before


def test_an_out_of_range_channel_never_reaches_the_firmware(session):
    session.wireshark.forget()
    before = len(session.firmware.commands)

    session.wireshark.send(CTRL_CHANNEL, CMD_SET, "300")
    session.wireshark.wait_for(
        lambda m: m[0] == CTRL_NONE and m[1] == CMD_WARNING, "a warning about the range"
    )

    assert len(session.firmware.commands) == before


def test_the_statistics_button_logs_and_gives_itself_back(session):
    session.wireshark.forget()
    session.wireshark.send(CTRL_STATS, CMD_SET)
    session.wireshark.wait_for(
        lambda m: m[0] == CTRL_STATS and m[1] == CMD_ENABLE,
        "the statistics button being enabled again",
    )

    order = [c for n, c, _ in session.wireshark.received if n == CTRL_STATS]
    assert order == [CMD_DISABLE, CMD_ENABLE], "disabled while it runs, enabled after"

    logged = "".join(session.wireshark.payloads(CTRL_LOG, CMD_ADD))
    assert "sync detect     : 42" in logged
    assert "uart:~$" not in logged and "wisun_sniffer stats" not in logged, (
        "the echo and the prompt are kept out of the log"
    )

    shown = session.wireshark.payloads(CTRL_NONE, CMD_INFORMATION)
    assert len(shown) == 1 and "sync detect     : 42" in shown[0], (
        "and shown straight away, not only in the log"
    )


def test_the_timestamp_box_changes_what_reaches_the_capture(session):
    """Ticked, frames keep the device uptime; unticked, they are rebased onto the host clock."""
    session.firmware.transmit(section_header())
    time.sleep(0.4)
    session.firmware.transmit(packet(1_000_000))
    time.sleep(0.4)

    session.wireshark.forget()
    session.wireshark.send(CTRL_TIMESTAMPS, CMD_SET, b"\x01")
    session.wireshark.wait_for(
        lambda m: m[0] == CTRL_NONE and m[1] == CMD_STATUSBAR,
        "a status message about the timestamps",
    )

    session.firmware.transmit(packet(2_000_000))
    time.sleep(0.4)

    stamps = session.timestamps()
    assert len(stamps) == 2, "both frames got through"
    assert stamps[0] > 1_600_000_000_000_000, "the first carries a host timestamp"
    assert stamps[1] == 2_000_000, "the second carries the device uptime"


def test_stopping_works_with_a_toolbar_in_the_picture(session):
    """Wireshark gives an extcap thirty seconds after SIGTERM before killing it, and stalls for
    that long if it is not answered. A control message in flight must not get in the way."""
    session.wireshark.send(CTRL_CHANNEL, CMD_SET, "8")
    session.wireshark.close()

    started = time.monotonic()
    session.child.send_signal(signal.SIGTERM)

    try:
        session.child.wait(timeout=30)
    except subprocess.TimeoutExpired:
        session.child.kill()
        raise AssertionError("the script was still running 30 s after SIGTERM")

    assert time.monotonic() - started < 2.0

    err = session.child.stderr.read().decode(errors="replace").strip()
    out = session.child.stdout.read().decode(errors="replace").strip()

    assert err == "", "Wireshark shows anything on stderr as the reason the capture ended"
    assert out == "", "stdout is the capture stream when there is no fifo"
