/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "wisun_phy.h"

#include "si4467_wisun.h"

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>

#include <errno.h>
#include <stdarg.h>

LOG_MODULE_REGISTER(wisun_phy, LOG_LEVEL_INF);

#define MODE(id) BIT(id)

/*
 * Wi-SUN PHY 2.03 table 7. The band the plan belongs to is part of its name; only the upper edge is
 * kept separately, because it is what decides how many channels the plan has.
 */
/* clang-format off */
static const struct wisun_chan_plan chan_plans[] = {
	{  1, "902_928_200",   902200,  200,  928000},
	{  2, "902_928_400",   902400,  400,  928000},
	{  3, "902_928_600",   902600,  600,  928000},
	{  4, "902_928_800",   902800,  800,  928000},
	{  5, "902_928_1200",  903200, 1200,  928000},
	{ 21, "920_928_200",   920600,  200,  928000},
	{ 22, "920_928_400",   920900,  400,  928000},
	{ 23, "920_928_600",   920800,  600,  928000},
	{ 24, "920_928_800",   921100,  800,  928000},
	{ 32, "863_870_100",   863100,  100,  870000},
	{ 33, "863_870_200",   863100,  200,  870000},
	{ 34, "870_876_100",   870100,  100,  876000},
	{ 35, "870_876_200",   870200,  200,  876000},
	{ 36, "863_876_100",   863100,  100,  876000},
	{ 37, "863_876_200",   863100,  200,  876000},
	{ 39, "865_868_100",   865100,  100,  868000},
	{ 40, "865_868_200",   865100,  200,  868000},
	{ 41, "866_869_100",   866100,  100,  869000},
	{ 42, "866_869_200",   866100,  200,  869000},
	{ 43, "866_869_400",   866300,  400,  869000},
	{ 48, "915_928_200",   915200,  200,  928000},
	{ 49, "915_928_400",   915400,  400,  928000},
	{ 64, "920_925_200",   920200,  200,  925000},
	{ 65, "920_925_400",   920400,  400,  925000},
	{ 80, "919_923_200",   919200,  200,  923000},
	{ 81, "919_923_400",   919200,  400,  923000},
	{ 96, "917_923_200",   917100,  200,  923000},
	{ 97, "917_923_400",   917300,  400,  923000},
	{112, "2400_2483_200", 2400200, 200, 2483500},
	{113, "2400_2483_400", 2400400, 400, 2483500},
	{128, "920_925_250",   920625,  250,  925000},
	{144, "779_787_200",   779200,  200,  787000},
	{145, "779_787_400",   779400,  400,  787000},
	{160, "470_510_200",   470200,  200,  510000},
};
/* clang-format on */

/*
 * Wi-SUN PHY 2.03 table 11, and the FEC variants of table 19. The OFDM modes are a different PHY
 * altogether and are not here.
 *
 * A PhyModeID is a PhyType in its high nibble and a PhyMode in its low one, so the FEC variant of
 * a mode is numbered 0x10 above it and is otherwise the same signal: same symbol rate, same
 * modulation index, same channel spacing. Only the framing differs, and only after the
 * demodulator, which is why an FEC row needs nothing of si4467_wisun_set_phy() that its uncoded
 * counterpart did not.
 *
 * The supported flag marks the modes this application can program the transceiver for. They all
 * have a modulation index of 0.5, which is what the rest of the modem configuration was derived
 * for; see si4467_wisun_set_phy(). The transceiver cannot decode FEC at all, so the coded rows are
 * supported on the strength of si4467_fec.c doing it in software instead.
 */
/* clang-format off */
static const struct wisun_phy_mode phy_modes[] = {
	{0x01, "#1a",  50000,  50, false, true},
	{0x02, "#1b",  50000, 100, false, false},
	{0x03, "#2a", 100000,  50, false, true},
	{0x04, "#2b", 100000, 100, false, false},
	{0x05, "#3",  150000,  50, false, true},
	{0x06, "#4a", 200000,  50, false, false},
	{0x07, "#4b", 200000, 100, false, false},
	{0x08, "#5",  300000,  50, false, false},
	{0x11, "#1a",  50000,  50, true,  true},
	{0x12, "#1b",  50000, 100, true,  false},
	{0x13, "#2a", 100000,  50, true,  true},
	{0x14, "#2b", 100000, 100, true,  false},
	{0x15, "#3",  150000,  50, true,  true},
	{0x16, "#4a", 200000,  50, true,  false},
	{0x17, "#4b", 200000, 100, true,  false},
	{0x18, "#5",  300000,  50, true,  false},
};
/* clang-format on */

/* Wi-SUN PHY 2.03 table 8, one entry per (regulatory domain, ChanPlanID) pair. */
static const struct wisun_domain_plan ww_plans[] = {
	{112, MODE(2) | MODE(3)},
	{113, MODE(5) | MODE(6) | MODE(8)},
};
/* clang-format off */
static const struct wisun_domain_plan na_plans[] = {
	{1, MODE(2) | MODE(3)},
	{2, MODE(5) | MODE(6)},
	{3, MODE(8)},
	{4, 0},
	{5, 0},
};
/* clang-format on */
static const struct wisun_domain_plan jp_plans[] = {
	{21, MODE(2)},
	{22, MODE(4) | MODE(5)},
	{23, MODE(7) | MODE(8)},
	{24, 0},
};
/* clang-format off */
static const struct wisun_domain_plan eu_plans[] = {
	{32, MODE(1)},
	{33, MODE(3) | MODE(5)},
	{34, MODE(1)},
	{35, MODE(3) | MODE(5)},
	{36, MODE(1)},
	{37, MODE(3) | MODE(5)},
};
/* clang-format on */
static const struct wisun_domain_plan cn_plans[] = {
	{128, MODE(2) | MODE(3) | MODE(5)},
	{160, MODE(2) | MODE(3) | MODE(5)},
};
static const struct wisun_domain_plan in_plans[] = {
	{39, MODE(1)},
	{40, MODE(3) | MODE(5)},
};
static const struct wisun_domain_plan mx_plans[] = {
	{1, MODE(2) | MODE(3)},
	{2, MODE(5) | MODE(6) | MODE(8)},
};
/* clang-format off */
static const struct wisun_domain_plan bz_plans[] = {
	{1, MODE(2) | MODE(3)},
	{2, MODE(5) | MODE(6)},
	{3, MODE(8)},
	{4, 0},
	{5, 0},
};
/* clang-format on */
static const struct wisun_domain_plan au_plans[] = {
	{48, MODE(2) | MODE(3)},
	{49, MODE(5) | MODE(6) | MODE(8)},
};
static const struct wisun_domain_plan kr_plans[] = {
	{96, MODE(2) | MODE(3)},
	{97, MODE(5) | MODE(6) | MODE(8)},
};
static const struct wisun_domain_plan my_plans[] = {
	{80, MODE(2) | MODE(3)},
	{81, MODE(5) | MODE(6) | MODE(8)},
};
/* clang-format off */
static const struct wisun_domain_plan sg_plans[] = {
	{41, MODE(1)},
	{42, MODE(3) | MODE(5)},
	{43, MODE(6) | MODE(8)},
	{64, MODE(2) | MODE(3)},
	{65, MODE(5) | MODE(6) | MODE(8)},
};
/* clang-format on */
static const struct wisun_domain_plan asia_925_plans[] = {
	{64, MODE(2) | MODE(3)},
	{65, MODE(5) | MODE(6) | MODE(8)},
};

static const struct wisun_reg_domain reg_domains[] = {
	{0x00, "WW", "2400-2483.5 MHz", ww_plans, ARRAY_SIZE(ww_plans)},
	{0x01, "NA", "902-928 MHz", na_plans, ARRAY_SIZE(na_plans)},
	{0x02, "JP", "920-928 MHz", jp_plans, ARRAY_SIZE(jp_plans)},
	{0x03, "EU", "863-876 MHz", eu_plans, ARRAY_SIZE(eu_plans)},
	{0x04, "CN", "470-510 and 920.5-924.5 MHz", cn_plans, ARRAY_SIZE(cn_plans)},
	{0x05, "IN", "865-868 MHz", in_plans, ARRAY_SIZE(in_plans)},
	{0x06, "MX", "902-928 MHz", mx_plans, ARRAY_SIZE(mx_plans)},
	{0x07, "BZ", "902-928 MHz", bz_plans, ARRAY_SIZE(bz_plans)},
	{0x08, "AU/NZ", "915-928 MHz", au_plans, ARRAY_SIZE(au_plans)},
	{0x09, "KR", "917-923.5 MHz", kr_plans, ARRAY_SIZE(kr_plans)},
	{0x0A, "PH", "915-918 MHz", au_plans, ARRAY_SIZE(au_plans)},
	{0x0B, "MY", "919-923 MHz", my_plans, ARRAY_SIZE(my_plans)},
	{0x0C, "HK", "920-925 MHz", asia_925_plans, ARRAY_SIZE(asia_925_plans)},
	{0x0D, "SG", "866-869 and 920-925 MHz", sg_plans, ARRAY_SIZE(sg_plans)},
	{0x0E, "TH", "920-925 MHz", asia_925_plans, ARRAY_SIZE(asia_925_plans)},
	{0x0F, "VN", "920-925 MHz", asia_925_plans, ARRAY_SIZE(asia_925_plans)},
};

/**
 * The PHY the WDS configuration in the tree describes, and the one everything falls back to: EU,
 * ChanPlanID 32, PhyModeID 1. Nothing else is guaranteed to be in the tables above.
 */
#define FALLBACK_DOMAIN 0x03
#define FALLBACK_PLAN   32
#define FALLBACK_MODE   1

/**
 * The band the dongle's front end is designed for. The transceiver tunes from 142 to 1050 MHz, so
 * the other regulatory domains can be programmed and are offered, but the matching network and the
 * antenna are not theirs and reception outside this range will be poor.
 */
#define FRONT_END_LO_KHZ 863000
#define FRONT_END_HI_KHZ 876000

/** The PHY currently selected, and being received on. */
static struct wisun_phy_config current;

const struct wisun_reg_domain *wisun_phy_domain(uint8_t code)
{
	for (size_t i = 0; i < ARRAY_SIZE(reg_domains); i++) {
		if (reg_domains[i].code == code) {
			return &reg_domains[i];
		}
	}

	return NULL;
}

const struct wisun_chan_plan *wisun_phy_plan(uint8_t id)
{
	for (size_t i = 0; i < ARRAY_SIZE(chan_plans); i++) {
		if (chan_plans[i].id == id) {
			return &chan_plans[i];
		}
	}

	return NULL;
}

const struct wisun_phy_mode *wisun_phy_mode(uint8_t id)
{
	for (size_t i = 0; i < ARRAY_SIZE(phy_modes); i++) {
		if (phy_modes[i].id == id) {
			return &phy_modes[i];
		}
	}

	return NULL;
}

const struct wisun_reg_domain *wisun_phy_domain_at(size_t index)
{
	return (index < ARRAY_SIZE(reg_domains)) ? &reg_domains[index] : NULL;
}

const struct wisun_phy_mode *wisun_phy_mode_at(size_t index)
{
	return (index < ARRAY_SIZE(phy_modes)) ? &phy_modes[index] : NULL;
}

const struct wisun_domain_plan *wisun_phy_domain_plan(const struct wisun_reg_domain *domain,
						      uint8_t plan_id)
{
	for (uint8_t i = 0; i < domain->num_plans; i++) {
		if (domain->plans[i].plan_id == plan_id) {
			return &domain->plans[i];
		}
	}

	return NULL;
}

bool wisun_phy_mode_allowed(const struct wisun_domain_plan *entry, uint8_t phy_mode_id)
{
	/* The tables record the PhyMode alone, a mode and its FEC variant sharing the one entry. */
	return (entry->mode_mask & MODE(phy_mode_id & 0x0F)) != 0;
}

uint32_t wisun_phy_channel_khz(const struct wisun_chan_plan *plan, uint8_t channel)
{
	return plan->freq0_khz + (uint32_t)channel * plan->spacing_khz;
}

uint16_t wisun_phy_num_channels(const struct wisun_chan_plan *plan)
{
	/* The last channel has to sit strictly below the upper band edge. */
	return (uint16_t)((plan->band_hi_khz - plan->freq0_khz - 1) / plan->spacing_khz + 1);
}

uint32_t wisun_phy_deviation_hz(const struct wisun_phy_mode *mode)
{
	/* Modulation index h = 2 * deviation / symbol rate. */
	return mode->symbol_rate * mode->mod_index_x100 / 200;
}

uint8_t wisun_phy_tap_band(const struct wisun_chan_plan *plan)
{
	static const struct {
		uint32_t lo_khz;
		uint32_t hi_khz;
		uint8_t band;
	} bands[] = {
		{470000, 510000, 2},   /* 470 MHz */
		{779000, 787000, 3},   /* 780 MHz */
		{863000, 865999, 4},   /* 863 MHz */
		{866000, 869999, 14},  /* 866 MHz */
		{870000, 876000, 15},  /* 870 MHz */
		{902000, 914999, 6},   /* 901 MHz */
		{915000, 916999, 7},   /* 915 MHz */
		{917000, 919999, 8},   /* 917 MHz */
		{920000, 928000, 9},   /* 920 MHz */
		{2400000, 2483500, 13} /* 2450 MHz */
	};

	for (size_t i = 0; i < ARRAY_SIZE(bands); i++) {
		if (plan->freq0_khz >= bands[i].lo_khz && plan->freq0_khz <= bands[i].hi_khz) {
			return bands[i].band;
		}
	}

	return 0;
}

uint8_t wisun_phy_tap_mode(const struct wisun_chan_plan *plan, const struct wisun_phy_mode *mode)
{
	/*
	 * IEEE 802.15.4-2020 table 7-25. Each encoding names a bit rate, a modulation index and a
	 * channel spacing at once, which is why the channel plan takes part in the lookup. The four
	 * level entries are left out: this application only receives 2-FSK.
	 *
	 * A coded PhyModeID and its uncoded counterpart return the same encoding -- 0x03 and 0x13
	 * are both row 7 -- and that is right, not a gap to be filled. Table 7-25 has no FEC
	 * dimension, and neither has the TAP format it feeds: its TLVs carry no coding field and no
	 * vendor range, so there is nothing to put one in short of inventing a Mode value, which
	 * would dissect as a reserved mode and say something false rather than nothing. Nothing is
	 * lost by it either. The PhyModeID names the coding, a capture is one PHY throughout, and
	 * the sniffer reports the PhyModeID it was told to listen on.
	 */
	static const struct {
		uint32_t symbol_rate;
		uint16_t mod_index_x100;
		uint32_t spacing_khz;
		uint8_t tap_mode;
	} encodings[] = {
		{50000, 100, 200, 0}, {100000, 100, 400, 1}, {150000, 50, 400, 2},
		{200000, 50, 400, 3}, {200000, 100, 600, 5}, {100000, 50, 200, 7},
		{50000, 50, 100, 8},  {150000, 50, 200, 9},  {300000, 50, 400, 10},
	};

	for (size_t i = 0; i < ARRAY_SIZE(encodings); i++) {
		if (encodings[i].symbol_rate == mode->symbol_rate &&
		    encodings[i].mod_index_x100 == mode->mod_index_x100 &&
		    encodings[i].spacing_khz == plan->spacing_khz) {
			return encodings[i].tap_mode;
		}
	}

	return 0xFF;
}

const struct wisun_phy_config *wisun_phy_current(void)
{
	/*
	 * Nothing has been selected yet if the transceiver failed to come up. Describe the PHY this
	 * application was built for rather than hand out null pointers, so that the shell and the
	 * capture format always have something coherent to report.
	 */
	if (current.plan == NULL) {
		current.domain = wisun_phy_domain(FALLBACK_DOMAIN);
		current.plan = wisun_phy_plan(FALLBACK_PLAN);
		current.mode = wisun_phy_mode(FALLBACK_MODE);
	}

	return &current;
}

/**
 * @brief Record why a PHY was refused, for whoever asked for it.
 *
 * The reason used to go to the log only, which left the shell -- and the Wireshark toolbar behind
 * it -- with nothing to show but an errno and a pointer at a log the user often cannot see. It is
 * written here and reported by the caller, so each refusal is stated once, in the place the request
 * came from.
 */
static void explain(char *reason, size_t reason_len, const char *fmt, ...)
{
	va_list args;

	if (reason == NULL) {
		return;
	}

	va_start(args, fmt);
	vsnprintk(reason, reason_len, fmt, args);
	va_end(args);
}

int wisun_phy_select(uint8_t domain_code, uint8_t plan_id, uint8_t phy_mode_id, uint8_t channel,
		     char *reason, size_t reason_len)
{
	const struct wisun_reg_domain *domain = wisun_phy_domain(domain_code);
	const struct wisun_chan_plan *plan = wisun_phy_plan(plan_id);
	const struct wisun_phy_mode *mode = wisun_phy_mode(phy_mode_id);
	const struct wisun_domain_plan *entry;
	struct si4467_wisun_phy radio;
	int ret;

	if (domain == NULL) {
		explain(reason, reason_len, "no regulatory domain with code %u", domain_code);
		return -EINVAL;
	}

	if (plan == NULL) {
		explain(reason, reason_len, "ChanPlanID %u is reserved", plan_id);
		return -EINVAL;
	}

	if (mode == NULL) {
		explain(reason, reason_len, "no operating mode with PhyModeID 0x%02x", phy_mode_id);
		return -EINVAL;
	}

	entry = wisun_phy_domain_plan(domain, plan_id);
	if (entry == NULL) {
		explain(reason, reason_len, "regulatory domain %s does not use ChanPlanID %u",
			domain->name, plan_id);
		return -EINVAL;
	}

	if (!wisun_phy_mode_allowed(entry, phy_mode_id)) {
		explain(reason, reason_len,
			"regulatory domain %s does not pair PhyModeID 0x%02x with ChanPlanID %u",
			domain->name, phy_mode_id, plan_id);
		return -EINVAL;
	}

	if (!mode->supported) {
		explain(reason, reason_len, "PhyModeID 0x%02x (%s) is not supported by this build",
			mode->id, mode->legacy);
		return -ENOTSUP;
	}

	/*
	 * Asked here as well as inside si4467_wisun_set_phy(), which reaches the same verdict but
	 * can only return an errno for it: this is where the plan that chose the frequency is
	 * known, and so where the refusal can name it. ChanPlanID 112, 113, 144 and 145 are the
	 * ones this catches.
	 */
	if (!si4467_wisun_can_tune(plan->freq0_khz)) {
		explain(reason, reason_len,
			"ChanPlanID %u (%s) is at %u.%03u MHz, which the transceiver cannot tune "
			"to",
			plan->id, plan->name, plan->freq0_khz / 1000, plan->freq0_khz % 1000);
		return -ENOTSUP;
	}

	if (plan->freq0_khz < FRONT_END_LO_KHZ || plan->band_hi_khz > FRONT_END_HI_KHZ) {
		LOG_WRN("ChanPlanID %u (%s) is outside the %u to %u kHz the dongle's front end is "
			"designed for; the transceiver will tune there but hear very little",
			plan->id, plan->name, FRONT_END_LO_KHZ, FRONT_END_HI_KHZ);
	}

	radio.center_freq0_khz = plan->freq0_khz;
	radio.chan_spacing_khz = plan->spacing_khz;
	radio.symbol_rate = mode->symbol_rate;
	radio.deviation_hz = wisun_phy_deviation_hz(mode);
	radio.fec = mode->fec;

	ret = si4467_wisun_set_phy(&radio);
	if (ret) {
		/*
		 * Only record the selection once the transceiver has taken it, so that what a
		 * capture says about a frame is always what the radio was programmed with.
		 * Reception stays stopped until a PHY that works has been asked for.
		 *
		 * Everything the tables can object to has been ruled out above, so this is the
		 * transceiver itself failing -- an SPI transfer or a state change -- and the log is
		 * where the detail of that belongs.
		 */
		explain(reason, reason_len,
			"the transceiver was not reprogrammed (%d); reception is stopped, see the "
			"log",
			ret);
		return ret;
	}

	current.domain = domain;
	current.plan = plan;
	current.mode = mode;
	current.channel = channel;

	if (channel >= wisun_phy_num_channels(plan)) {
		LOG_WRN("channel %u is beyond the %u channels of ChanPlanID %u", channel,
			wisun_phy_num_channels(plan), plan->id);
	}

	return si4467_wisun_start(channel);
}

int wisun_phy_set_channel(uint8_t channel)
{
	const struct wisun_phy_config *phy = wisun_phy_current();
	int ret;

	if (channel >= wisun_phy_num_channels(phy->plan)) {
		LOG_WRN("channel %u is beyond the %u channels of ChanPlanID %u", channel,
			wisun_phy_num_channels(phy->plan), phy->plan->id);
	}

	ret = si4467_wisun_set_channel(channel);
	if (ret) {
		return ret;
	}

	current.channel = channel;

	return 0;
}

int wisun_phy_init(void)
{
	/*
	 * Nobody is at a shell this early, so this is the one caller that reports to the log. The
	 * buffer is static rather than automatic because this runs on the 1 kB main stack, below
	 * the transceiver bring-up, and it is called exactly once from one thread.
	 */
	static char reason[WISUN_PHY_REASON_LEN] = "";
	int ret = wisun_phy_select(CONFIG_WISUN_SNIFFER_DEFAULT_REGULATORY_DOMAIN,
				   CONFIG_WISUN_SNIFFER_DEFAULT_CHAN_PLAN_ID,
				   CONFIG_WISUN_SNIFFER_DEFAULT_PHY_MODE_ID,
				   CONFIG_WISUN_SNIFFER_DEFAULT_CHANNEL, reason, sizeof(reason));

	if (ret) {
		LOG_WRN("the configured PHY cannot be used (%s), falling back to EU ChanPlanID %u "
			"PhyModeID 0x%02x",
			reason, FALLBACK_PLAN, FALLBACK_MODE);
		ret = wisun_phy_select(FALLBACK_DOMAIN, FALLBACK_PLAN, FALLBACK_MODE,
				       CONFIG_WISUN_SNIFFER_DEFAULT_CHANNEL, reason,
				       sizeof(reason));
		if (ret) {
			LOG_ERR("the fallback PHY cannot be used either: %s", reason);
		}
	}

	return ret;
}
