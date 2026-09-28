# SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH
# SPDX-License-Identifier: GPL-3.0-or-later

"""Check that Stream preserves the spacing the device measured between frames.

The spacing is the measurement -- it is what a sniffer is for, and the dongle latches each
timestamp at sync detect, so it is right when it leaves the dongle. Rebasing onto the host clock
must therefore add one offset to every frame and change nothing else.

An earlier version took the offset to be the smallest "now - device_us" seen so far. That bound
keeps shrinking while a capture opens, because the first frames come from the backlog the dongle
staged while nothing was reading and so arrive late; every improvement moved later frames earlier
relative to the ones already written, and 100 ms of spacing came out as 50 ms. These tests drive
the real Stream with a controlled clock so that arrival pattern can be reproduced exactly.
"""

import struct

import pytest


class FakeClock:
    """Stands in for the time module, advanced by the test rather than by waiting."""

    def __init__(self):
        self.now = 1_700_000_000.0

    def time(self):
        return self.now

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds

    def advance(self, seconds):
        self.now += seconds


class Sink:
    """Collects what the stream writes, and decodes the timestamps back out of it."""

    def __init__(self, capture):
        self.capture = capture
        self.blocks = []

    def write(self, block):
        self.blocks.append(block)

    def stamps(self):
        """The timestamp of every packet block written, in microseconds."""
        out = []

        for block in self.blocks:
            if struct.unpack_from("<I", block, 0)[0] == self.capture.BLOCK_TYPE_EPB:
                high, low = struct.unpack_from("<II", block, 12)
                out.append((high << 32) | low)

        return out


def section_header(capture):
    """A section header block, which is what Stream syncs on. Only the magic matters here."""
    body = capture.SHB_MAGIC + struct.pack("<I", 28) + struct.pack("<I", 0x1A2B3C4D)
    body += struct.pack("<HH", 1, 0) + struct.pack("<q", -1) + struct.pack("<I", 28)
    assert len(body) == 28

    return body


def packet(capture, device_us):
    """An enhanced packet block stamped @p device_us, carrying four octets."""
    block = struct.pack("<II", capture.BLOCK_TYPE_EPB, 36)
    block += struct.pack("<I", 0)
    block += struct.pack("<II", device_us >> 32, device_us & 0xFFFFFFFF)
    block += struct.pack("<II", 4, 4) + b"\xde\xad\xbe\xef" + struct.pack("<I", 36)
    assert len(block) == 36

    return block


def run(capture, arrivals, host_timestamps=True):
    """Feed frames and return the timestamps written out, in microseconds.

    @p arrivals is a list of (device_us, delay_s): when the dongle stamped the frame, and how long
    it took to reach the host. The capture is then closed, which is what releases anything still
    being held back for the warm-up.
    """
    clock = FakeClock()
    capture.time = clock

    sink = Sink(capture)
    stream = capture.Stream(
        sink, capture.Settings(capture.DEFAULT_PHY, host_timestamps=host_timestamps)
    )
    stream.feed(section_header(capture))

    start = clock.now
    for device_us, delay in arrivals:
        # The host clock reads "when it was captured, plus how long it took to get here".
        clock.now = start + device_us / 1_000_000 + delay
        stream.feed(packet(capture, device_us))

    clock.advance(10.0)
    stream.close()

    return sink.stamps()


def test_spacing_survives_the_catch_up(capture):
    """The case that was broken: a capture opening with the pipe catching up.

    The first frames are half a second late and the delay decays away, while the dongle spaced them
    100 ms apart. Every gap must still be 100 ms.
    """
    spacing_us = 100_000
    arrivals = [(i * spacing_us, max(0.0, 0.5 - i * 0.05)) for i in range(20)]

    stamps = run(capture, arrivals)
    gaps = [b - a for a, b in zip(stamps, stamps[1:])]

    assert len(stamps) == 20
    assert set(gaps) == {spacing_us}


def test_uneven_spacing_is_preserved_exactly(capture):
    """Real traffic is not evenly spaced, and the uneven case is where the error showed worst.

    Before the fix a 992 us gap here came out as minus 389 ms -- the frames were written out of
    order relative to each other.
    """
    device = [0, 7, 999, 1_000_000, 1_000_050, 3_500_000]
    arrivals = [(us, 0.4 if i < 2 else 0.01) for i, us in enumerate(device)]

    stamps = run(capture, arrivals)

    wanted = [b - a for a, b in zip(device, device[1:])]
    assert [b - a for a, b in zip(stamps, stamps[1:])] == wanted


def test_frames_land_near_the_host_clock(capture):
    """Preserving the spacing is not enough on its own: the offset has to be plausible too."""
    stamps = run(capture, [(i * 100_000, 0.02) for i in range(10)])

    assert abs(stamps[0] / 1_000_000 - 1_700_000_000.0) < 1.0


def test_a_capture_ending_in_the_warm_up_still_writes_what_it_held(capture):
    """Frames held back for the warm-up must not be lost when the capture stops inside it."""
    clock = FakeClock()
    capture.time = clock

    sink = Sink(capture)
    stream = capture.Stream(sink, capture.Settings(capture.DEFAULT_PHY, host_timestamps=True))
    stream.feed(section_header(capture))
    stream.feed(packet(capture, 1000))

    assert sink.stamps() == [], "the frame should still be held back this early"

    stream.close()

    assert len(sink.stamps()) == 1


@pytest.mark.parametrize("device_us", [[0, 250_000, 1_250_000]])
def test_device_timestamps_are_passed_through_untouched(capture, device_us):
    """--device-timestamps means what it says: no offset, whatever one would have been measured."""
    stamps = run(capture, [(us, 0.0) for us in device_us], host_timestamps=False)

    assert stamps == device_us
