/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * @file
 *
 * @brief The Wi-SUN PHY as the standard describes it, and the one currently being listened to.
 *
 * A Wi-SUN PHY is named by three numbers: a regulatory domain, a ChanPlanID and a PhyModeID. The
 * domain says which combinations of the other two are allowed in a region, the ChanPlanID fixes the
 * centre frequency of channel zero and the channel spacing, and the PhyModeID fixes the symbol rate
 * and the modulation index. Together with a channel number they determine everything the
 * transceiver and the capture format need to know, so this is what the shell and the extcap
 * interface let you select.
 *
 * The tables come from Wi-SUN PHY 2.03: table 7 for the channel plans, table 8 for the regulatory
 * domains and table 11 for the operating modes.
 */

#ifndef WISUN_SNIFFER_WISUN_PHY_H_
#define WISUN_SNIFFER_WISUN_PHY_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** A regulatory channel plan; Wi-SUN PHY 2.03 table 7. */
struct wisun_chan_plan {
	/** ChanPlanID. */
	uint8_t id;
	/** ChanPlanName, which also names the frequency band, e.g. "863_870_100". */
	const char *name;
	/** ChanCenterFreq0, the centre frequency of channel zero. */
	uint32_t freq0_khz;
	/** ChanSpacing. */
	uint32_t spacing_khz;
	/** Upper edge of the frequency band, used to work out how many channels the plan spans. */
	uint32_t band_hi_khz;
};

/** A PHY operating mode; Wi-SUN PHY 2.03 table 11. */
struct wisun_phy_mode {
	/** PhyModeID. */
	uint8_t id;
	/** Legacy PHY mode name, e.g. "#1a". A mode and its FEC variant share one. */
	const char *legacy;
	/** Symbols per second. Two level FSK, so this is also the bit rate. */
	uint32_t symbol_rate;
	/** Modulation index, scaled by 100. */
	uint16_t mod_index_x100;
	/**
	 * Whether the mode applies forward error correction, which the transceiver cannot undo and
	 * si4467_fec.c therefore does in software.
	 */
	bool fec;
	/**
	 * Whether this application can program the transceiver for the mode; see wisun_phy.c for
	 * what decides it.
	 */
	bool supported;
};

/** One row of a regulatory domain: a channel plan and the operating modes allowed with it. */
struct wisun_domain_plan {
	uint8_t plan_id;
	/**
	 * Bit @c n set means PhyMode @c n is allowed, with or without FEC. OFDM modes are not
	 * represented.
	 *
	 * Only the low nibble of a PhyModeID is recorded, because Wi-SUN PHY 2.03 pairs every mode
	 * with its FEC variant rather than listing them separately -- table 8 writes ChanPlanID
	 * 33's entry as 0x03/0x13 -- and annex B says any mode "may additionally support" FEC. Ask
	 * @ref wisun_phy_mode_allowed rather than testing a bit here, so that a PhyModeID with its
	 * FEC nibble set finds the row its uncoded counterpart put there.
	 */
	uint16_t mode_mask;
};

/** A regulatory domain; Wi-SUN PHY 2.03 table 8. */
struct wisun_reg_domain {
	/** The code carried in the Wi-SUN header, e.g. 3 for EU. */
	uint8_t code;
	const char *name;
	/** The frequency bands the domain covers, for display. */
	const char *bands;
	const struct wisun_domain_plan *plans;
	uint8_t num_plans;
};

/** Everything that has been selected, and what the transceiver was programmed with. */
struct wisun_phy_config {
	const struct wisun_reg_domain *domain;
	const struct wisun_chan_plan *plan;
	const struct wisun_phy_mode *mode;
	uint8_t channel;
};

/** @brief Look a regulatory domain up by its code, or NULL if there is no such domain. */
const struct wisun_reg_domain *wisun_phy_domain(uint8_t code);

/** @brief Look a channel plan up by its ChanPlanID, or NULL if the plan is reserved. */
const struct wisun_chan_plan *wisun_phy_plan(uint8_t id);

/** @brief Look an operating mode up by its PhyModeID, or NULL if there is no such mode. */
const struct wisun_phy_mode *wisun_phy_mode(uint8_t id);

/** @brief Iterate the tables, for the shell to list what can be selected. */
const struct wisun_reg_domain *wisun_phy_domain_at(size_t index);
const struct wisun_phy_mode *wisun_phy_mode_at(size_t index);

/** @brief Whether @p domain allows @p plan_id, and with which operating modes. */
const struct wisun_domain_plan *wisun_phy_domain_plan(const struct wisun_reg_domain *domain,
						      uint8_t plan_id);

/**
 * @brief Whether @p entry allows PhyModeID @p phy_mode_id.
 *
 * A PhyModeID is a PhyType in its high nibble and a PhyMode in its low one, and the channel plan
 * tables record only the latter; see @ref wisun_domain_plan::mode_mask.
 */
bool wisun_phy_mode_allowed(const struct wisun_domain_plan *entry, uint8_t phy_mode_id);

/** @brief Centre frequency of @p channel within @p plan. */
uint32_t wisun_phy_channel_khz(const struct wisun_chan_plan *plan, uint8_t channel);

/** @brief How many channels @p plan spans before its ChanMask is applied. */
uint16_t wisun_phy_num_channels(const struct wisun_chan_plan *plan);

/** @brief Peak frequency deviation of @p mode, which follows from its symbol rate. */
uint32_t wisun_phy_deviation_hz(const struct wisun_phy_mode *mode);

/**
 * @brief Frequency band identifier for @p plan; IEEE 802.15.4-2020 table 7-21.
 *
 * Part of the description handed to Wireshark in the TAP header.
 */
uint8_t wisun_phy_tap_band(const struct wisun_chan_plan *plan);

/**
 * @brief FSK-B rate mode for @p plan and @p mode; IEEE 802.15.4-2020 table 7-25.
 *
 * The encoding names a bit rate, a modulation index and a channel spacing together, so it depends
 * on the channel plan as much as on the operating mode. Returns 0xff when the combination has no
 * encoding, which happens for plans whose spacing the standard does not pair with the mode.
 */
uint8_t wisun_phy_tap_mode(const struct wisun_chan_plan *plan, const struct wisun_phy_mode *mode);

/**
 * @brief Room a caller should give @ref wisun_phy_select for the reason it refused a PHY.
 *
 * Enough for the longest of them; a longer one would be truncated rather than lost.
 */
#define WISUN_PHY_REASON_LEN 96

/**
 * @brief Select a PHY and program the transceiver for it.
 *
 * Reception is stopped for the duration and restarted afterwards if it was running. On failure the
 * previous selection is left in place, except where @p reason says reception has stopped.
 *
 * @param domain_code regulatory domain to listen in; Wi-SUN PHY 2.03 table 8.
 * @param plan_id     ChanPlanID, which fixes channel zero and the channel spacing; table 7.
 * @param phy_mode_id PhyModeID, which fixes the symbol rate and the modulation index; table 11.
 * @param channel     channel number within @p plan_id.
 * @param reason      filled with why the PHY was refused, or left alone on success. May be NULL
 *                    where a refusal is expected and the caller means to try something else.
 * @param reason_len  size of @p reason, normally @ref WISUN_PHY_REASON_LEN.
 *
 * @return 0 on success, -EINVAL if the combination is not a valid Wi-SUN PHY, -ENOTSUP if the
 *         transceiver cannot be programmed for it, or a negative errno from the transceiver.
 */
int wisun_phy_select(uint8_t domain_code, uint8_t plan_id, uint8_t phy_mode_id, uint8_t channel,
		     char *reason, size_t reason_len);

/**
 * @brief Switch to @p channel within the channel plan already selected.
 *
 * Cheaper than @ref wisun_phy_select, which reprograms the whole PHY.
 */
int wisun_phy_set_channel(uint8_t channel);

/** @brief The PHY currently being listened to. Never returns null members. */
const struct wisun_phy_config *wisun_phy_current(void);

/**
 * @brief Apply the configured defaults and start receiving.
 *
 * Called once at start-up, after the transceiver has been brought up.
 */
int wisun_phy_init(void);

#endif /* WISUN_SNIFFER_WISUN_PHY_H_ */
