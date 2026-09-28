# SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH
# SPDX-License-Identifier: GPL-3.0-or-later

"""Check how the script talks to the firmware's shell, and what it believes about the answers.

Two faults let a capture start on a PHY nobody asked for without saying so, and both are covered
here. console_command() accepted a firmware log line as the answer to a shell command, so a dongle
that had just restarted appeared to agree with everything. And set_phy() treated "the firmware did
not complain" as "the firmware did what it was told", which is a weaker thing.

A third fault was what those two were hiding: a command sent before the shell was reading is lost
outright, and one attempt is not enough. The console output in LOST below is what that looked like
on the dongle, kept as it came off it.
"""

import pytest

PROMPT = "uart:~$ "

# What "wisun_sniffer phy 3 32 1 15" prints when it worked.
PHY_15 = """\
domain    : EU (3), 863-876 MHz
chan plan : 32 (863_870_100), 100 kHz spacing, 69 channels
phy mode  : 0x01 (1a), 50000 symbols/s, modulation index 0.50
channel   : 15 (864.600 MHz)
modem     : sample rate 500000 Hz, RX bandwidth 83 kHz, oversampling 10.000
"""

PHY_0 = PHY_15.replace("channel   : 15 (864.600 MHz)", "channel   : 0 (863.100 MHz)")

# The deferred startup log of a dongle that has just come up. Note that it contains the word
# "channel", which is what a caller waiting for the PHY is looking for.
STARTUP_LOG = """\
[00:00:04.001,220] <inf> wisun_sniffer: Wi-SUN sniffer 0.0.1 on dongle/nrf52840
[00:00:04.001,281] <inf> si4467_wisun: transceiver ready
[00:00:04.002,502] <inf> wisun_sniffer: listening in EU on ChanPlanID 32, PhyModeID 1, \
channel 0 (863.100 MHz)
"""

# What the console really produced when a capture was started on a dongle that was still coming up:
# the boot banner, the startup log with a prompt re-printed after every line, and -- the tell -- no
# echo of the command. The shell echoes what it receives, so no echo means it never arrived.
LOST = """\
uart:~$ *** Booting Zephyr OS build v4.2.1-52-gd7e8b3f6434f ***
uart:~$ [00:00:00.001,861] <inf> wisun_sniffer: Wi-SUN sniffer 0.0.1 on dongle/nrf52840
uart:~$ [00:00:00.090,087] <inf> si4467_wisun: transceiver ready
uart:~$ [00:00:00.092,864] <inf> wisun_sniffer: listening in EU on ChanPlanID 32, PhyModeID 1, \
channel 0 (863.100 MHz)
uart:~$ uart:~$ """

ANSWERED = f"wisun_sniffer phy 3 32 1 15\n{PHY_15}{PROMPT}"


def answering(capture, reply):
    """Stand in for console_command() with one that answers @p reply, as the real one would."""

    def fake(serial_number, command, expect, timeout=2.0, attempts=None):
        del serial_number, command, expect, timeout, attempts
        return reply, None

    capture.console_command = fake


class FakePort:
    """Enough of a serial port for console_command(): hands out canned text a read at a time."""

    def __init__(self, chunks=()):
        self.chunks = list(chunks)
        self.written = b""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def reset_input_buffer(self):
        """Nothing to discard: the canned chunks stand for what arrives after the command."""

    def write(self, data):
        self.written += data

    def flush(self):
        pass

    def read(self, size):
        del size

        return self.chunks.pop(0).encode() if self.chunks else b""


class RetryPort(FakePort):
    """A console that ignores what is written to it until @p answer_on, then answers."""

    def __init__(self, answer_on):
        super().__init__()
        self.answer_on = answer_on
        self.attempt = 0

    def write(self, data):
        del data
        self.attempt += 1
        self.chunks = [ANSWERED if self.attempt >= self.answer_on else LOST, ""]


@pytest.fixture
def console(capture):
    """Puts a fake port behind console_command(), and hands the test the port it will use."""
    port = FakePort()
    capture.device_path = lambda serial, suffix: "/dev/null"
    capture.os.path.exists = lambda path: True
    capture.open_port = lambda path, timeout=0.2: port

    def use(replacement):
        capture.open_port = lambda path, timeout=0.2: replacement
        return replacement

    use.port = port

    return use


# ------------------------------------------------------------------------------------------- #
# set_phy() checks what it is told                                                             #
# ------------------------------------------------------------------------------------------- #


def test_a_matching_reply_is_accepted(capture):
    answering(capture, ANSWERED)

    assert capture.set_phy("X", 3, 32, 1, 15) is None


def test_a_phy_that_is_not_the_one_asked_for_is_reported(capture):
    """The reply says channel 0 where 15 was asked for, which used to pass in silence."""
    answering(capture, f"wisun_sniffer phy 3 32 1 15\n{PHY_0}{PROMPT}")

    error = capture.set_phy("X", 3, 32, 1, 15)

    assert error is not None
    assert "channel 0" in error and "channel 15" in error, "both PHYs belong in the message"


def test_a_startup_log_is_not_mistaken_for_a_reply(capture):
    """The reported case: the dongle restarted, so the only thing that came back was its log."""
    answering(capture, f"{STARTUP_LOG}{PROMPT}")

    assert capture.set_phy("X", 3, 32, 1, 15) is not None


def test_a_refusal_is_reported_as_a_refusal(capture):
    """Not as a mismatch: what the firmware objected to is more use than what it ended up on."""
    answering(
        capture,
        f"wisun_sniffer phy 3 99 1 15\ncannot listen to domain 3, ChanPlanID 99, "
        f"PhyModeID 1: ChanPlanID 99 is reserved\n{PROMPT}",
    )

    error = capture.set_phy("X", 3, 99, 1, 15)

    assert error is not None
    assert "refused" in error and "reserved" in error


# ------------------------------------------------------------------------------------------- #
# The log is not the shell                                                                     #
# ------------------------------------------------------------------------------------------- #


def test_log_lines_are_stripped_from_a_reply(capture):
    said = capture.console_reply(f"{STARTUP_LOG}channel   : 15 (864.600 MHz)\n{PROMPT}")

    assert "channel   : 15" in said
    assert "channel 0" not in said


def test_an_error_in_the_log_is_not_a_complaint_about_the_command(capture):
    log = f"[00:00:04.001,220] <err> si4467_wisun: FIFO overflow, frame dropped\n{PROMPT}"

    assert capture.console_complaint(log) is None


def test_a_real_complaint_is_still_found(capture):
    assert capture.console_complaint(f"cannot listen to domain 3\n{PROMPT}") is not None


def test_a_log_line_does_not_answer_a_command(capture, console):
    """The log holds the word being waited for, and the real answer never comes."""
    console(FakePort([f"{STARTUP_LOG}{PROMPT}", ""]))

    _, error = capture.console_command(
        "X", "wisun_sniffer phy 3 32 1 15", expect="channel", timeout=0.1, attempts=1
    )

    assert error is not None


def test_the_real_answer_is_recognised_behind_a_log_burst(capture, console):
    """Stripping the log must not throw away an answer that arrived after it."""
    console(FakePort([STARTUP_LOG, f"{PHY_15}{PROMPT}"]))

    text, error = capture.console_command(
        "X", "wisun_sniffer phy 3 32 1 15", expect="channel", timeout=1.0
    )

    assert error is None
    assert capture.parse_phy(text) == [3, 32, 1, 15]


# ------------------------------------------------------------------------------------------- #
# A command sent before the shell was listening                                                #
# ------------------------------------------------------------------------------------------- #


def test_a_lost_command_is_sent_again(capture, console):
    port = console(RetryPort(answer_on=2))

    text, error = capture.console_command(
        "X", "wisun_sniffer phy 3 32 1 15", expect="channel", timeout=0.1
    )

    assert error is None
    assert capture.parse_phy(text) == [3, 32, 1, 15]
    assert port.attempt == 2, "and not asked more times than it had to be"


def test_a_console_that_never_answers_is_given_up_on(capture, console):
    port = console(RetryPort(answer_on=99))

    _, error = capture.console_command(
        "X", "wisun_sniffer phy 3 32 1 15", expect="channel", timeout=0.1
    )

    assert error is not None
    assert port.attempt == capture.CONSOLE_ATTEMPTS


def test_the_message_says_why_rather_than_quoting_the_boot_log(capture, console):
    """This message ends up in a Wireshark dialog, where a whole startup log helps nobody."""
    console(RetryPort(answer_on=99))

    _, error = capture.console_command(
        "X", "wisun_sniffer phy 3 32 1 15", expect="channel", timeout=0.1
    )

    assert "Booting Zephyr" in error, "the one line that explains it"
    assert "863.100 MHz" not in error, "but not the log around it"
    assert "\n" not in error


def test_a_silent_console_is_described_as_silent(capture, console):
    """Rather than as an empty quotation, which reads like a bug in the script."""
    console(FakePort())

    _, error = capture.console_command("X", "wisun_sniffer phy", expect="channel", timeout=0.1)

    assert "nothing at all" in error
