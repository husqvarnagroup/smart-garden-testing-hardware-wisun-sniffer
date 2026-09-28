/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "led.h"
#include "pcapng.h"
#include "si4467_wisun.h"
#include "tap.h"
#include "wisun_phy.h"

#include <app_version.h>

#include <zephyr/device.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/shell/shell.h>
#include <zephyr/version.h>

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

LOG_MODULE_REGISTER(wisun_sniffer, LOG_LEVEL_INF);

/** @brief Centre frequency of @p channel in the channel plan currently selected. */
static uint32_t channel_to_khz(uint8_t channel)
{
	return wisun_phy_channel_khz(wisun_phy_current()->plan, channel);
}

/** @brief When a line is logged for each received frame; see @ref cmd_trace. */
enum frame_trace {
	TRACE_OFF,
	TRACE_ON,
	TRACE_AUTO,
};

static const char *const trace_names[] = {
	[TRACE_OFF] = "off",
	[TRACE_ON] = "on",
	[TRACE_AUTO] = "auto",
};

/**
 * Whether each frame is announced on the console.
 *
 * Auto by default: the line is what bring-up is done with, but once a capture tool is reading the
 * other interface the frames are in front of the user already, in Wireshark, and all this adds is
 * traffic on the interface that carries the shell.
 */
static enum frame_trace trace_mode = TRACE_AUTO;

/** @brief Whether this frame should be announced, under the mode currently set. */
static bool trace_wanted(void)
{
	switch (trace_mode) {
	case TRACE_ON:
		return true;
	case TRACE_AUTO:
		return !pcapng_host_attached();
	default:
		return false;
	}
}

/**
 * @brief Light the LED for as long as a capture tool is reading the stream.
 *
 * The same signal the frame trace follows, so the LED agrees with the console about when a capture
 * is running. It is deliberately not a traffic indicator: what one wants to see across the room is
 * whether the dongle is being read at all, and a light that flickers per frame cannot say that.
 */
static void on_host_attached(bool attached)
{
	led_set_capture_active(attached);
}

static void on_frame(const struct wisun_frame *frame, void *user_data)
{
	uint8_t tap_header[TAP_HEADER_MAX_LEN];
	size_t tap_header_len;

	ARG_UNUSED(user_data);

	/*
	 * Logged, not printed: printk() runs synchronously in this (receive) thread and would block
	 * the transceiver on console I/O, and has no level to filter by.
	 */
	if (trace_wanted()) {
		LOG_INF("RX ch=%u len=%u rssi=%d dBm fcs=%uB/%s wht=%u afc=%d", frame->channel,
			frame->psdu_len, frame->rssi_dbm, frame->fcs_len,
			frame->fcs_ok ? "ok" : "bad", frame->whitened, frame->afc_offset);
	}

	tap_header_len = tap_build_header(tap_header, frame);
	pcapng_write_packet(frame->timestamp_us, tap_header, tap_header_len, frame->psdu,
			    frame->psdu_len);
}

/* ------------------------------------------------------------------------------------------- */
/* Shell                                                                                        */
/* ------------------------------------------------------------------------------------------- */

/**
 * @brief Largest repeat count a command will accept.
 *
 * Anything above this is a mistyped number rather than an intention, and every one of these
 * commands holds the shell for the whole run.
 */
#define MAX_REPEAT 65535U

/**
 * @brief Read a shell argument as a number from 0 to @p max.
 *
 * strtoul() reports neither text that is not a number -- it returns 0 for "abc" -- nor a value too
 * large for the field it is going into, and the casts to uint8_t that these commands need turn 300
 * into 44. Both used to be accepted in silence, so a typo moved the receiver to a channel nobody
 * asked for and was reported as success.
 *
 * @param sh     shell to say why on, when the argument cannot be used.
 * @param what   what the argument is, for the message if it is not usable.
 * @param text   the argument as the shell received it.
 * @param max    largest acceptable value, which is what the destination field can hold.
 * @param value  set only if the argument is usable.
 *
 * @return true if @p value was set, false after saying why not.
 */
static bool parse_number(const struct shell *sh, const char *what, const char *text,
			 unsigned long max, unsigned long *value)
{
	char *end;
	unsigned long parsed = strtoul(text, &end, 0);

	/*
	 * Nothing was consumed, or something that is not part of a number followed it. A minus sign
	 * is caught here rather than by the range check below, which strtoul() would otherwise
	 * reach with the value wrapped round to something enormous and report as merely too large.
	 */
	if (end == text || *end != '\0' || text[0] == '-') {
		shell_error(sh, "%s: '%s' is not a number", what, text);
		return false;
	}

	/* Covers overflow as well: strtoul() saturates at ULONG_MAX, which is above every max here.
	 */
	if (parsed > max) {
		shell_error(sh, "%s: %s is out of range, the largest is %lu", what, text, max);
		return false;
	}

	*value = parsed;

	return true;
}

/**
 * @brief Read an optional trailing keyword such as "reset" or "force".
 *
 * @return true if @p text is @p keyword, false after saying that it is not.
 */
static bool parse_keyword(const struct shell *sh, const char *text, const char *keyword)
{
	if (strcmp(text, keyword) != 0) {
		shell_error(sh, "no such argument: %s (the only one is '%s')", text, keyword);
		return false;
	}

	return true;
}

/**
 * @brief Check @p channel against the channels @p plan actually has.
 *
 * A channel beyond the plan is a frequency nothing keeping to the standard transmits on, so it is
 * refused rather than tuned to — but the transceiver can reach it, and looking there is a
 * legitimate thing to want, hence @p force.
 *
 * @return true if the channel may be used, false after saying why not.
 */
static bool check_channel(const struct shell *sh, const struct wisun_chan_plan *plan,
			  uint8_t channel, bool force)
{
	const uint16_t channels = wisun_phy_num_channels(plan);

	if (channel < channels) {
		return true;
	}

	if (!force) {
		shell_error(sh,
			    "channel %u is beyond the %u channels of ChanPlanID %u; add 'force' to "
			    "listen there anyway",
			    channel, channels, plan->id);
		return false;
	}

	shell_warn(sh,
		   "channel %u is beyond the %u channels of ChanPlanID %u, so nothing that keeps "
		   "to the plan transmits there",
		   channel, channels, plan->id);

	return true;
}

/** @brief Print the PHY being listened to, in the terms the standard names it with. */
static void print_phy(const struct shell *sh)
{
	const struct wisun_phy_config *phy = wisun_phy_current();
	const struct si4467_wisun_phy_actual *actual = si4467_wisun_get_phy_actual();
	const uint32_t khz = channel_to_khz(phy->channel);

	shell_print(sh, "domain    : %s (%u), %s", phy->domain->name, phy->domain->code,
		    phy->domain->bands);
	shell_print(sh, "chan plan : %u (%s), %u kHz spacing, %u channels", phy->plan->id,
		    phy->plan->name, phy->plan->spacing_khz, wisun_phy_num_channels(phy->plan));
	shell_print(sh, "phy mode  : 0x%02x (%s%s), %u symbols/s, modulation index %u.%02u",
		    phy->mode->id, phy->mode->legacy, phy->mode->fec ? " with FEC" : "",
		    phy->mode->symbol_rate, phy->mode->mod_index_x100 / 100,
		    phy->mode->mod_index_x100 % 100);
	shell_print(sh, "channel   : %u (%u.%03u MHz)", phy->channel, khz / 1000, khz % 1000);
	shell_print(sh, "modem     : sample rate %u Hz, RX bandwidth %u kHz, oversampling %u.%03u",
		    actual->sample_rate_hz, actual->rx_bandwidth_hz / 1000, actual->osr_x8 / 8,
		    (actual->osr_x8 % 8) * 125);
}

/*
 * `git describe` over this application's release tags, which CMakeLists.txt limits it to. Falls
 * back to the bare commit (plus "-dirty") until the first release/wisun_sniffer- tag exists.
 */
#if defined(APP_BUILD_VERSION) && !IS_EMPTY(APP_BUILD_VERSION)
#define BUILD_STRING STRINGIFY(APP_BUILD_VERSION)
#else
#define BUILD_STRING "not built from a git checkout"
#endif

/** @brief Say which build this is; the startup log line says the same but has usually scrolled
 * away by the time anyone wants it again.
 */
static int cmd_version(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	shell_print(sh, "version   : %s", APP_VERSION_STRING);
	shell_print(sh, "build     : %s", BUILD_STRING);
	shell_print(sh, "board     : %s", CONFIG_BOARD_TARGET);
	shell_print(sh, "zephyr    : %s", KERNEL_VERSION_STRING);

	return 0;
}

static int cmd_info(const struct shell *sh, size_t argc, char **argv)
{
	struct si4467_wisun_part_info info;
	int ret;

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	ret = si4467_wisun_get_part_info(&info);
	if (ret) {
		shell_error(sh, "failed to read chip information: %d", ret);
		return ret;
	}

	shell_print(sh, "part      : Si%04x rev %u (ROM %u, build %u, id %u, customer %u)",
		    info.part, info.chiprev, info.romid, info.pbuild, info.id, info.customer);
	shell_print(sh, "firmware  : %u.%u.%u, patch 0x%04x, func %u", info.rev_ext,
		    info.rev_branch, info.rev_int, info.patch, info.func);
	print_phy(sh);

	return 0;
}

/** @brief Reprogram for a new domain, channel plan or operating mode, keeping the rest. */
static int select_phy(const struct shell *sh, uint8_t domain, uint8_t plan, uint8_t mode,
		      uint8_t channel)
{
	char reason[WISUN_PHY_REASON_LEN] = "";
	int ret = wisun_phy_select(domain, plan, mode, channel, reason, sizeof(reason));

	if (ret) {
		shell_error(sh, "cannot listen to domain %u, ChanPlanID %u, PhyModeID 0x%02x: %s",
			    domain, plan, mode, reason);
		return ret;
	}

	print_phy(sh);

	return 0;
}

static int cmd_phy(const struct shell *sh, size_t argc, char **argv)
{
	const struct wisun_phy_config *phy = wisun_phy_current();
	const struct wisun_chan_plan *wanted;
	unsigned long domain;
	unsigned long plan;
	unsigned long mode;
	unsigned long channel = phy->channel;

	if (argc < 4) {
		print_phy(sh);
		return 0;
	}

	if (!parse_number(sh, "domain", argv[1], UINT8_MAX, &domain) ||
	    !parse_number(sh, "ChanPlanID", argv[2], UINT8_MAX, &plan) ||
	    !parse_number(sh, "PhyModeID", argv[3], UINT8_MAX, &mode) ||
	    (argc > 4 && !parse_number(sh, "channel", argv[4], UINT8_MAX, &channel)) ||
	    (argc > 5 && !parse_keyword(sh, argv[5], "force"))) {
		return -EINVAL;
	}

	/*
	 * Against the plan being asked for, not the one in use. An unknown plan is left to
	 * wisun_phy_select() below, which is what knows why it cannot be used.
	 */
	wanted = wisun_phy_plan((uint8_t)plan);
	if (wanted != NULL && !check_channel(sh, wanted, (uint8_t)channel, argc > 5)) {
		return -EINVAL;
	}

	/*
	 * Setting all of it at once, rather than one command per field, so that a caller can name a
	 * PHY that shares neither its channel plan nor its operating mode with the current one. The
	 * individual commands each keep the rest of the selection and would refuse such a step.
	 */
	return select_phy(sh, (uint8_t)domain, (uint8_t)plan, (uint8_t)mode, (uint8_t)channel);
}

static int cmd_domain(const struct shell *sh, size_t argc, char **argv)
{
	const struct wisun_phy_config *phy = wisun_phy_current();
	const struct wisun_reg_domain *domain = NULL;

	if (argc < 2) {
		shell_print(sh, "domain: %s (%u), %s", phy->domain->name, phy->domain->code,
			    phy->domain->bands);
		shell_print(sh, "available:");

		for (size_t i = 0; (domain = wisun_phy_domain_at(i)) != NULL; i++) {
			shell_print(sh, "  %2u  %-6s %s", domain->code, domain->name,
				    domain->bands);
		}

		return 0;
	}

	if (isdigit((unsigned char)argv[1][0])) {
		unsigned long code;

		if (!parse_number(sh, "domain", argv[1], UINT8_MAX, &code)) {
			return -EINVAL;
		}

		domain = wisun_phy_domain((uint8_t)code);
	} else {
		for (size_t i = 0; (domain = wisun_phy_domain_at(i)) != NULL; i++) {
			if (strcasecmp(domain->name, argv[1]) == 0) {
				break;
			}
		}
	}

	if (domain == NULL) {
		shell_error(sh, "no regulatory domain called %s", argv[1]);
		return -EINVAL;
	}

	/*
	 * Keep the channel plan and operating mode in use if the new domain allows that pairing. No
	 * reason is asked for: being turned down here is an ordinary outcome that the loop below
	 * then deals with, and reporting it would describe a PHY nobody asked for.
	 */
	if (wisun_phy_domain_plan(domain, phy->plan->id) != NULL &&
	    wisun_phy_select(domain->code, phy->plan->id, phy->mode->id, phy->channel, NULL, 0) ==
		    0) {
		print_phy(sh);
		return 0;
	}

	/* Otherwise move to the first combination the domain offers that can be programmed. */
	for (uint8_t i = 0; i < domain->num_plans; i++) {
		const struct wisun_domain_plan *entry = &domain->plans[i];
		const struct wisun_phy_mode *mode;

		for (size_t j = 0; (mode = wisun_phy_mode_at(j)) != NULL; j++) {
			if (wisun_phy_mode_allowed(entry, mode->id) && mode->supported) {
				return select_phy(sh, domain->code, entry->plan_id, mode->id, 0);
			}
		}
	}

	shell_error(sh, "regulatory domain %s has no operating mode this build can program",
		    domain->name);

	return -ENOTSUP;
}

static int cmd_plan(const struct shell *sh, size_t argc, char **argv)
{
	const struct wisun_phy_config *phy = wisun_phy_current();
	unsigned long value;
	uint8_t plan_id;
	uint8_t mode_id;

	if (argc < 2) {
		shell_print(sh, "chan plan: %u (%s), %u.%03u MHz + n * %u kHz, %u channels",
			    phy->plan->id, phy->plan->name, phy->plan->freq0_khz / 1000,
			    phy->plan->freq0_khz % 1000, phy->plan->spacing_khz,
			    wisun_phy_num_channels(phy->plan));
		shell_print(sh, "available in %s:", phy->domain->name);

		for (uint8_t i = 0; i < phy->domain->num_plans; i++) {
			const struct wisun_domain_plan *entry = &phy->domain->plans[i];
			const struct wisun_chan_plan *plan = wisun_phy_plan(entry->plan_id);
			const struct wisun_phy_mode *mode;
			char modes[48] = "";
			size_t pos = 0;

			for (size_t j = 0; (mode = wisun_phy_mode_at(j)) != NULL; j++) {
				if (wisun_phy_mode_allowed(entry, mode->id)) {
					pos += snprintk(&modes[pos], sizeof(modes) - pos, " 0x%02x",
							mode->id);
				}
			}

			shell_print(sh, "  %3u  %-13s %4u kHz  %3u ch  PhyModeID%s", plan->id,
				    plan->name, plan->spacing_khz, wisun_phy_num_channels(plan),
				    (pos > 0) ? modes : " none (OFDM only)");
		}

		return 0;
	}

	if (!parse_number(sh, "ChanPlanID", argv[1], UINT8_MAX, &value)) {
		return -EINVAL;
	}

	plan_id = (uint8_t)value;
	mode_id = phy->mode->id;

	/* Keep the operating mode if the new plan allows it, otherwise take its first usable one.
	 */
	{
		const struct wisun_domain_plan *entry = wisun_phy_domain_plan(phy->domain, plan_id);

		if (entry != NULL && !wisun_phy_mode_allowed(entry, mode_id)) {
			const struct wisun_phy_mode *mode;

			for (size_t i = 0; (mode = wisun_phy_mode_at(i)) != NULL; i++) {
				if (wisun_phy_mode_allowed(entry, mode->id) && mode->supported) {
					mode_id = mode->id;
					break;
				}
			}
		}
	}

	return select_phy(sh, phy->domain->code, plan_id, mode_id, phy->channel);
}

static int cmd_mode(const struct shell *sh, size_t argc, char **argv)
{
	const struct wisun_phy_config *phy = wisun_phy_current();
	const struct wisun_domain_plan *entry;
	const struct wisun_phy_mode *mode;
	unsigned long value;

	if (argc < 2) {
		shell_print(sh, "phy mode: 0x%02x (%s%s), %u symbols/s, modulation index %u.%02u",
			    phy->mode->id, phy->mode->legacy, phy->mode->fec ? " with FEC" : "",
			    phy->mode->symbol_rate, phy->mode->mod_index_x100 / 100,
			    phy->mode->mod_index_x100 % 100);

		entry = wisun_phy_domain_plan(phy->domain, phy->plan->id);
		shell_print(sh, "available with ChanPlanID %u:", phy->plan->id);

		for (size_t i = 0; (mode = wisun_phy_mode_at(i)) != NULL; i++) {
			if (entry == NULL || !wisun_phy_mode_allowed(entry, mode->id)) {
				continue;
			}

			shell_print(sh,
				    "  0x%02x  %-4s%-9s %6u symbols/s  modulation index %u.%02u%s",
				    mode->id, mode->legacy, mode->fec ? " with FEC" : "",
				    mode->symbol_rate, mode->mod_index_x100 / 100,
				    mode->mod_index_x100 % 100,
				    mode->supported ? "" : "  (not programmable)");
		}

		return 0;
	}

	if (!parse_number(sh, "PhyModeID", argv[1], UINT8_MAX, &value)) {
		return -EINVAL;
	}

	return select_phy(sh, phy->domain->code, phy->plan->id, (uint8_t)value, phy->channel);
}

static int cmd_stats(const struct shell *sh, size_t argc, char **argv)
{
	const struct si4467_wisun_stats *stats;

	if (argc > 1) {
		if (!parse_keyword(sh, argv[1], "reset")) {
			return -EINVAL;
		}

		si4467_wisun_reset_stats();
		pcapng_reset_dropped();
		shell_print(sh, "counters reset");

		return 0;
	}

	stats = si4467_wisun_get_stats();

	shell_print(sh, "preamble detect : %u", stats->preamble_detect);
	shell_print(sh, "sync detect     : %u", stats->sync_detect);
	shell_print(sh, "frames          : %u", stats->frames);
	shell_print(sh, "bad FCS         : %u", stats->fcs_error);
	shell_print(sh, "bad PHR         : %u", stats->bad_phr);
	shell_print(sh, "bad length      : %u", stats->bad_length);
	shell_print(sh, "fifo errors     : %u", stats->fifo_error);
	shell_print(sh, "timeouts        : %u", stats->timeout);
	shell_print(sh, "capture drops   : %u", pcapng_get_dropped());

	return 0;
}

/**
 * @brief Show or set whether a line is logged for each received frame.
 *
 * Separate from the log level: turning the module off would silence the PHY and capture messages
 * too, and the level has no way to say "only when nobody is capturing".
 */
static int cmd_trace(const struct shell *sh, size_t argc, char **argv)
{
	if (argc > 1) {
		size_t i;

		for (i = 0; i < ARRAY_SIZE(trace_names); i++) {
			if (strcmp(argv[1], trace_names[i]) == 0) {
				trace_mode = (enum frame_trace)i;
				break;
			}
		}

		if (i == ARRAY_SIZE(trace_names)) {
			shell_error(sh, "no such setting: %s (one of %s, %s, %s)", argv[1],
				    trace_names[TRACE_OFF], trace_names[TRACE_ON],
				    trace_names[TRACE_AUTO]);
			return -EINVAL;
		}
	}

	shell_print(sh, "trace: %s, so frames are %s logged%s", trace_names[trace_mode],
		    trace_wanted() ? "being" : "not being",
		    (trace_mode == TRACE_AUTO)
			    ? (pcapng_host_attached() ? " (a capture tool is attached)"
						      : " (no capture tool is attached)")
			    : "");

	return 0;
}

static int cmd_rssi(const struct shell *sh, size_t argc, char **argv)
{
	unsigned long channel = wisun_phy_current()->channel;
	unsigned long repeat = 1;
	int ret;

	if (argc > 1 && !parse_number(sh, "channel", argv[1], UINT8_MAX, &channel)) {
		return -EINVAL;
	}
	if (argc > 2 && !parse_number(sh, "repeat", argv[2], MAX_REPEAT, &repeat)) {
		return -EINVAL;
	}

	for (unsigned long i = 0; i < repeat; i++) {
		int16_t rssi_dbm;

		ret = si4467_wisun_measure_rssi((uint8_t)channel, &rssi_dbm);
		if (ret) {
			shell_error(sh, "failed to measure RSSI: %d", ret);
			return ret;
		}

		shell_print(sh, "channel %lu (%u.%03u MHz): %d dBm", channel,
			    channel_to_khz((uint8_t)channel) / 1000,
			    channel_to_khz((uint8_t)channel) % 1000, rssi_dbm);

		if (i + 1 < repeat) {
			k_msleep(100);
		}
	}

	return 0;
}

static int cmd_channel(const struct shell *sh, size_t argc, char **argv)
{
	const struct wisun_phy_config *phy = wisun_phy_current();
	unsigned long value;
	uint8_t channel;
	int ret;

	if (argc < 2) {
		shell_print(sh, "channel %u of %u (%u.%03u MHz)", phy->channel,
			    wisun_phy_num_channels(phy->plan), channel_to_khz(phy->channel) / 1000,
			    channel_to_khz(phy->channel) % 1000);
		return 0;
	}

	if (!parse_number(sh, "channel", argv[1], UINT8_MAX, &value) ||
	    (argc > 2 && !parse_keyword(sh, argv[2], "force"))) {
		return -EINVAL;
	}

	channel = (uint8_t)value;

	if (!check_channel(sh, phy->plan, channel, argc > 2)) {
		return -EINVAL;
	}

	ret = wisun_phy_set_channel(channel);
	if (ret) {
		shell_error(sh, "failed to switch to channel %u: %d", channel, ret);
		return ret;
	}

	shell_print(sh, "listening on channel %u (%u.%03u MHz)", channel,
		    channel_to_khz(channel) / 1000, channel_to_khz(channel) % 1000);

	return 0;
}

static int cmd_raw(const struct shell *sh, size_t argc, char **argv)
{
	unsigned long value;

	if (argc > 1) {
		if (!parse_number(sh, "raw", argv[1], 1, &value)) {
			return -EINVAL;
		}

		si4467_wisun_set_raw(value != 0);
	}

	shell_print(sh, "raw capture %s", si4467_wisun_get_raw() ? "on" : "off");

	return 0;
}

/**
 * A Wi-SUN FAN enhanced acknowledgment captured off the air, kept verbatim including its FCS.
 *
 * Used by "wisun_sniffer inject" to exercise the whole capture path without needing a transmitter
 * nearby: because it is a real frame with a valid FCS, a capture tool has to dissect it as one and
 * show the FCS as good.
 */
static const uint8_t sample_psdu[] = {
	0x4a, 0xee, 0x2c, 0xb1, 0x3d, 0x24, 0xfe, 0xff, 0xd3, 0x44, 0xf0, 0x1e,
	0xe6, 0xbd, 0xfe, 0xff, 0x42, 0xa0, 0x6c, 0x0e, 0xbb, 0xa0, 0x24, 0x00,
	0x01, 0x05, 0x15, 0x01, 0x05, 0x1a, 0x64, 0x33, 0x02, 0x15, 0x04, 0x79,
	0x55, 0x3d, 0x68, 0x49, 0x78, 0xca, 0xdd, 0x42, 0xc9, 0x8e, 0x74, 0x44,
};

static int cmd_inject(const struct shell *sh, size_t argc, char **argv)
{
	static struct wisun_frame frame;
	unsigned long count = 1;

	if (argc > 1 && !parse_number(sh, "count", argv[1], MAX_REPEAT, &count)) {
		return -EINVAL;
	}

	frame.psdu_len = sizeof(sample_psdu);
	frame.fcs_len = 4;
	frame.fcs_ok = true;
	frame.whitened = true;
	frame.rssi_dbm = -43;
	frame.channel = wisun_phy_current()->channel;
	memcpy(frame.phr, (const uint8_t[]){0x08, 0x30}, sizeof(frame.phr));
	memcpy(frame.psdu, sample_psdu, sizeof(sample_psdu));

	for (unsigned long i = 0; i < count; i++) {
		frame.timestamp_us = k_ticks_to_us_floor64(k_uptime_ticks());
		on_frame(&frame, NULL);
	}

	shell_print(sh, "injected %lu frame(s) of %zu octets", count, sizeof(sample_psdu));

	return 0;
}

/**
 * @brief Begin a new PCAP-NG section, for a reader that cannot raise DTR (`cat`, a shell redirect,
 * some USB-serial bridges). See pcapng.c's @c host_attached for why DTR is the only such signal.
 */
static int cmd_section(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	if (!pcapng_write_section_header()) {
		shell_error(
			sh,
			"no room in the capture buffer: start the reader before asking for this");
		return -ENOBUFS;
	}

	shell_print(sh, "new PCAP-NG section written to the capture stream");

	return 0;
}

static int cmd_prop(const struct shell *sh, size_t argc, char **argv)
{
	uint8_t values[16];
	unsigned long group, start;
	unsigned long count = 1;
	int ret;

	if (!parse_number(sh, "group", argv[1], UINT8_MAX, &group) ||
	    !parse_number(sh, "start", argv[2], UINT8_MAX, &start) ||
	    (argc > 3 && !parse_number(sh, "count", argv[3], sizeof(values), &count))) {
		return -EINVAL;
	}

	if (count == 0) {
		shell_error(sh, "count must be between 1 and %zu", sizeof(values));
		return -EINVAL;
	}

	ret = si4467_wisun_get_properties((uint8_t)group, (uint8_t)start, (uint8_t)count, values);
	if (ret) {
		shell_error(sh, "failed to read properties: %d", ret);
		return ret;
	}

	for (unsigned long i = 0; i < count; i++) {
		shell_print(sh, "%02lx:%02lx = 0x%02x", group, start + i, values[i]);
	}

	return 0;
}

static int cmd_setprop(const struct shell *sh, size_t argc, char **argv)
{
	unsigned long group, index, value;
	int ret;

	ARG_UNUSED(argc);

	if (!parse_number(sh, "group", argv[1], UINT8_MAX, &group) ||
	    !parse_number(sh, "index", argv[2], UINT8_MAX, &index) ||
	    !parse_number(sh, "value", argv[3], UINT8_MAX, &value)) {
		return -EINVAL;
	}

	ret = si4467_wisun_set_property_raw((uint8_t)group, (uint8_t)index, (uint8_t)value);
	if (ret) {
		shell_error(sh, "failed to write property: %d", ret);
		return ret;
	}

	shell_print(sh, "%02lx:%02lx = 0x%02lx", group, index, value);

	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(
	wisun_sniffer_cmds,
	SHELL_CMD_ARG(version, NULL, "Print the firmware version", cmd_version, 1, 0),
	SHELL_CMD_ARG(info, NULL, "Print transceiver information", cmd_info, 1, 0),
	SHELL_CMD_ARG(prop, NULL, "<group> <start> [count] Read transceiver properties", cmd_prop,
		      3, 1),
	SHELL_CMD_ARG(setprop, NULL, "<group> <index> <value> Write a transceiver property",
		      cmd_setprop, 4, 0),
	SHELL_CMD_ARG(stats, NULL,
		      "[reset] Print the receive statistics, or start them again from zero",
		      cmd_stats, 1, 1),
	SHELL_CMD_ARG(rssi, NULL, "<channel> [repeat] Measure RSSI on a channel", cmd_rssi, 1, 2),
	SHELL_CMD_ARG(
		phy, NULL,
		"[domain plan mode [channel [force]]] Show or set the whole Wi-SUN PHY at once",
		cmd_phy, 1, 5),
	SHELL_CMD_ARG(domain, NULL, "[name|code] Show or set the regulatory domain", cmd_domain, 1,
		      1),
	SHELL_CMD_ARG(plan, NULL, "[ChanPlanID] Show or set the channel plan", cmd_plan, 1, 1),
	SHELL_CMD_ARG(mode, NULL, "[PhyModeID] Show or set the PHY operating mode", cmd_mode, 1, 1),
	SHELL_CMD_ARG(channel, NULL,
		      "[channel [force]] Show or set the channel to listen on; 'force' allows one "
		      "outside the channel plan",
		      cmd_channel, 1, 2),
	SHELL_CMD_ARG(
		trace, NULL,
		"[off|on|auto] Show or set whether each received frame is logged; 'auto' stops "
		"while a capture tool is attached",
		cmd_trace, 1, 1),
	SHELL_CMD_ARG(raw, NULL, "[0|1] Show or set raw capture mode", cmd_raw, 1, 1),
	SHELL_CMD_ARG(inject, NULL, "[count] Feed a canned frame into the capture stream",
		      cmd_inject, 1, 1),
	SHELL_CMD_ARG(section, NULL,
		      "Begin a new PCAP-NG section, for a reader that cannot raise DTR",
		      cmd_section, 1, 0),
	SHELL_SUBCMD_SET_END);

SHELL_CMD_REGISTER(wisun_sniffer, &wisun_sniffer_cmds, "Wi-SUN sniffer commands", NULL);

/* ------------------------------------------------------------------------------------------- */

int main(void)
{
	const struct wisun_phy_config *phy;
	uint32_t khz;
	int ret;

	LOG_INF("Wi-SUN sniffer %s on %s", APP_VERSION_STRING, CONFIG_BOARD_TARGET);

	ret = led_init();
	if (ret) {
		/* An indicator that cannot be lit is no reason to leave the dongle deaf. */
		LOG_WRN("the application LED is unavailable: %d", ret);
	}

	/* Before the poll it feeds is started, so that the first attach is not missed. */
	pcapng_set_attach_callback(on_host_attached);

	ret = pcapng_init();
	if (ret) {
		LOG_ERR("capture stream setup failed: %d", ret);
		return ret;
	}

	ret = si4467_wisun_init();
	if (ret) {
		LOG_ERR("transceiver bring-up failed: %d", ret);
		return ret;
	}

	si4467_wisun_set_rx_callback(on_frame, NULL);

	ret = wisun_phy_init();
	if (ret) {
		LOG_ERR("failed to start receiving: %d", ret);
		return ret;
	}

	phy = wisun_phy_current();
	khz = channel_to_khz(phy->channel);

	LOG_INF("listening in %s on ChanPlanID %u, PhyModeID 0x%02x, channel %u (%u.%03u MHz)",
		phy->domain->name, phy->plan->id, phy->mode->id, phy->channel, khz / 1000,
		khz % 1000);

	return 0;
}
