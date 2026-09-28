/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * @file
 *
 * @brief IEEE 802.15.4 TAP header, the metadata Wireshark reads alongside each frame.
 *
 * Every captured frame is presented as a TAP packet: a short header, a series of type-length-value
 * fields describing how the frame was received, and then the PHY payload itself. See "IEEE 802.15.4
 * TAP Link Type Specification" version 1.0 in doc/.
 */

#ifndef WISUN_SNIFFER_TAP_H_
#define WISUN_SNIFFER_TAP_H_

#include "si4467_wisun.h"

#include <stddef.h>
#include <stdint.h>

/** Enough for the TAP header and every TLV this application emits. */
#define TAP_HEADER_MAX_LEN 64

/**
 * @brief Build the TAP header and TLVs describing @p frame.
 *
 * The PHY payload is not copied; it follows the header in the capture stream.
 *
 * @param buf  Destination, at least @ref TAP_HEADER_MAX_LEN octets.
 * @param frame Frame to describe.
 *
 * @return Number of octets written to @p buf.
 */
size_t tap_build_header(uint8_t *buf, const struct wisun_frame *frame);

#endif /* WISUN_SNIFFER_TAP_H_ */
