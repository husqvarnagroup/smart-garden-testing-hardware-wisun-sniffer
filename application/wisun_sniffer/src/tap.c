/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "tap.h"

#include "wisun_phy.h"

#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/util.h>

#include <string.h>

/** TAP TLV types (specification section 3). */
#define TAP_TLV_FCS_TYPE           0
#define TAP_TLV_RSS                1
#define TAP_TLV_BIT_RATE           2
#define TAP_TLV_CHANNEL_ASSIGNMENT 3
#define TAP_TLV_PHY_ENCODING       4

/** FCS Type TLV values. */
#define TAP_FCS_TYPE_NONE   0
#define TAP_FCS_TYPE_CRC_16 1
#define TAP_FCS_TYPE_CRC_32 2

/*
 * The PHY is described to Wireshark exactly as it has been selected, so switching the channel plan
 * or the operating mode changes what the pseudo-header says as well as what the transceiver is
 * listening to. Only the channel travels with the frame; the rest is read from the current
 * selection, which cannot change while a frame is being handled because reception is stopped while
 * the transceiver is reprogrammed.
 */

/** Channel page nine, the one the SUN PHYs live on (IEEE 802.15.4-2020 10.1.2). */
#define PHY_CHANNEL_PAGE 9

/** FSK-B, modulation scheme encoding 1 (table 7-23). */
#define PHY_TYPE 1

/** The version of the TAP format this application writes. */
#define TAP_VERSION 0

/** Header: version, padding and the 16 bit length of the header and its TLVs. */
#define TAP_HEADER_LEN 4

/** @brief Append one TLV, padding its value out to a 32 bit boundary as the format requires. */
static size_t put_tlv(uint8_t *buf, uint16_t type, const void *value, uint16_t len)
{
	const size_t padded = ROUND_UP(len, 4);

	sys_put_le16(type, &buf[0]);
	sys_put_le16(len, &buf[2]);
	memcpy(&buf[4], value, len);
	memset(&buf[4 + len], 0, padded - len);

	return 4 + padded;
}

size_t tap_build_header(uint8_t *buf, const struct wisun_frame *frame)
{
	const struct wisun_phy_config *phy = wisun_phy_current();
	const uint8_t fcs_type = (frame->fcs_len == 2) ? TAP_FCS_TYPE_CRC_16 : TAP_FCS_TYPE_CRC_32;
	const float rss_dbm = (float)frame->rssi_dbm;
	uint8_t value[4];
	size_t len = TAP_HEADER_LEN;

	/*
	 * Tell Wireshark which FCS the frame carries so that it validates the octets at the end of
	 * the PHY payload rather than dissecting them as data. Wi-SUN FAN always uses a 32 bit FCS,
	 * but the PHY header carries the choice per frame, so it is taken from there.
	 */
	len += put_tlv(&buf[len], TAP_TLV_FCS_TYPE, &fcs_type, sizeof(fcs_type));

	/*
	 * Signal strength, as an IEEE-754 float. The transceiver latches it when it detects the
	 * sync word, so it describes this frame rather than whatever the receiver hears afterwards.
	 * Copied rather than cast: this is a little-endian target, so the octets are already in TAP
	 * order.
	 */
	memcpy(value, &rss_dbm, sizeof(rss_dbm));
	len += put_tlv(&buf[len], TAP_TLV_RSS, value, sizeof(rss_dbm));

	/* Two level FSK, so one symbol per bit and the symbol rate is the bit rate. */
	sys_put_le32(phy->mode->symbol_rate, value);
	len += put_tlv(&buf[len], TAP_TLV_BIT_RATE, value, sizeof(uint32_t));

	sys_put_le16(frame->channel, value);
	value[2] = PHY_CHANNEL_PAGE;
	len += put_tlv(&buf[len], TAP_TLV_CHANNEL_ASSIGNMENT, value, 3);

	/*
	 * The rate mode encoding names a bit rate, a modulation index and a channel spacing
	 * together, so a combination the standard does not list has none. Leaving the TLV out then
	 * is better than making a value up: Wireshark simply shows no PHY encoding rather than a
	 * wrong one.
	 */
	{
		const uint8_t phy_mode = wisun_phy_tap_mode(phy->plan, phy->mode);

		if (phy_mode != 0xFF) {
			value[0] = wisun_phy_tap_band(phy->plan);
			value[1] = PHY_TYPE;
			value[2] = phy_mode;
			len += put_tlv(&buf[len], TAP_TLV_PHY_ENCODING, value, 3);
		}
	}

	buf[0] = TAP_VERSION;
	buf[1] = 0; /* Padding */
	sys_put_le16((uint16_t)len, &buf[2]);

	return len;
}
