# SPDX-FileCopyrightText: Copyright (c) 2023 GARDENA GmbH
# SPDX-License-Identifier: GPL-3.0-or-later

# Support/use OpenOCD per default
include(${ZEPHYR_BASE}/boards/common/openocd.board.cmake)

# Support J-Link
board_runner_args(jlink "--device=nRF52840_xxAA" "--speed=8000")
include(${ZEPHYR_BASE}/boards/common/jlink.board.cmake)
