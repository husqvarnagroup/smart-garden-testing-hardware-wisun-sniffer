# SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH
# SPDX-License-Identifier: GPL-3.0-or-later

cmake_minimum_required(VERSION 3.13.1)

project(tests-wisun_sniffer_fec)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE} PATHS ../../../../../zephyr NO_DEFAULT_PATH)

set(APP_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../../application/wisun_sniffer/src)

target_sources(
    app
    PRIVATE
        src/test_fec.c
        ${APP_SRC_DIR}/si4467_fec.c
)

target_include_directories(app PRIVATE ${APP_SRC_DIR})
