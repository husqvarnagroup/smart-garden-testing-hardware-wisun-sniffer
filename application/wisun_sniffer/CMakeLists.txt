# SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH
# SPDX-License-Identifier: GPL-3.0-or-later

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE} PATHS ../../../zephyr NO_DEFAULT_PATH)

project(wisun_sniffer)

target_sources(
    app
    PRIVATE
        src/led.c
        src/main.c
        src/pcapng.c
        src/si4467_fec.c
        src/si4467_wisun.c
        src/tap.c
        src/wisun_phy.c
)

# The Viterbi decoder is the only thing here with an inner loop that runs thousands of times per
# frame, and the application is otherwise built for size. Speed for this one file, because what it
# decides is whether a frame is decoded before the next one has filled the receive FIFO -- and an
# acknowledgment follows the frame it answers by well under a millisecond.
set_source_files_properties(
    src/si4467_fec.c
    PROPERTIES
        COMPILE_OPTIONS
            "-O2"
)
