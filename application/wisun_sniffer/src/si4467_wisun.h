/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * @file
 *
 * @brief Si4467 transceiver, configured to receive Wi-SUN FAN frames.
 *
 * The transceiver runs in EZRadioPRO boot mode with GLOBAL_CONFIG:PROTOCOL set to IE154G, so the
 * packet handler parses the PHY header on its own: it derives the frame length, picks the FCS
 * length and enables or disables de-whitening per frame. Frames therefore arrive here ready to
 * use, with no software de-whitening or bit reordering needed.
 *
 * The FCS is the one thing the radio does not get right. Its CRC engine cannot be switched off
 * under IE154G and seeds itself with all zeroes where IEEE 802.15.4 uses all ones, so it rejects
 * good frames; it also keeps the FCS octets out of the FIFO unless PKT_LEN_ADJUST asks for them.
 * The driver therefore asks for them, ignores the radio's verdict and checks the FCS in software,
 * which lets the complete PSDU reach Wireshark. Frames that fail are still reported: a sniffer
 * must never hide them.
 */

#ifndef WISUN_SNIFFER_SI4467_WISUN_H_
#define WISUN_SNIFFER_SI4467_WISUN_H_

#include <stdbool.h>
#include <stdint.h>

/**
 * Largest PSDU an IEEE 802.15.4 SUN PHY can carry, in octets, including the FCS. This is the value
 * the packet handler is configured with (PKT_RX_FIELD_2_LENGTH).
 */
#define WISUN_MAX_PSDU_LEN 2047

/**
 * A received Wi-SUN frame, as handed to the RX callback.
 *
 * The members are ordered widest first so that the structure has no padding holes in it; see the
 * pahole check in the pipeline.
 */
struct wisun_frame {
	/** Uptime when the frame's sync word was detected. */
	uint64_t timestamp_us;
	/** PSDU length in octets, including the FCS. Taken from the PHR. */
	uint16_t psdu_len;
	/** RSSI latched at sync detect. */
	int16_t rssi_dbm;
	/**
	 * Carrier offset the AFC measured for this frame, in the transceiver's own units. A value
	 * far from zero means the receiver and the transmitter disagree about the channel centre
	 * frequency, which shows up as frames that decode but fail their FCS.
	 */
	int16_t afc_offset;
	/** PHY header exactly as received (2 octets). */
	uint8_t phr[2];
	/** FCS length in octets, 2 or 4. Taken from the PHR FCS Type bit. */
	uint8_t fcs_len;
	/** Channel the frame was received on. */
	uint8_t channel;
	/** Whether the FCS at the end of @ref psdu matches the frame. */
	bool fcs_ok;
	/** Whether the transmitter whitened the PSDU (the radio has already undone it). */
	bool whitened;
	/** PSDU including FCS. Only the first @ref psdu_len octets are valid. */
	uint8_t psdu[WISUN_MAX_PSDU_LEN];
};

/** Counters for bring-up and diagnostics; see the `wisun_sniffer stats` shell command. */
struct si4467_wisun_stats {
	uint32_t preamble_detect;
	uint32_t sync_detect;
	uint32_t frames;
	/** Frames included in @ref frames whose FCS did not match. */
	uint32_t fcs_error;
	/** PHY header could not belong to a Wi-SUN FAN frame, so the frame was abandoned early. */
	uint32_t bad_phr;
	/** PHR reported a length of zero or more than @ref WISUN_MAX_PSDU_LEN. */
	uint32_t bad_length;
	/** RX FIFO overflowed, i.e. we did not drain it fast enough. */
	uint32_t fifo_error;
	/** Reception started but did not complete within the watchdog period. */
	uint32_t timeout;
};

/**
 * The PHY to receive: where channel zero sits, how far apart the channels are, and how the symbols
 * are modulated. All of it follows from a Wi-SUN ChanPlanID and PhyModeID; see wisun_phy.h.
 */
struct si4467_wisun_phy {
	/** Centre frequency of channel zero (ChanCenterFreq0). */
	uint32_t center_freq0_khz;
	/** Distance between channels (ChanSpacing). */
	uint32_t chan_spacing_khz;
	/** Symbols per second. Two level FSK, so this is also the bit rate. */
	uint32_t symbol_rate;
	/** Peak frequency deviation. */
	uint32_t deviation_hz;
	/**
	 * Whether frames on this PHY are convolutionally coded.
	 *
	 * Nothing about the modulation changes with it -- a coded mode has the same symbol rate and
	 * modulation index as its uncoded counterpart -- so the synthesiser and the modem are
	 * programmed identically either way. What changes is everything after the demodulator:
	 * which sync word marks the start of a frame, and whether the packet handler may be trusted
	 * to find the end of one. See si4467_configure_packet_handler().
	 */
	bool fec;
};

/**
 * What the transceiver ended up being programmed with. The numbers it can express are quantised,
 * and the receive bandwidth in particular is only indirectly selectable, so this is worth showing.
 */
struct si4467_wisun_phy_actual {
	/** Centre frequency of channel zero the synthesiser was programmed to. */
	uint32_t center_freq0_hz;
	/** Channel step the synthesiser was programmed with. */
	uint32_t chan_spacing_hz;
	/** Sample rate at the channel filter, which is what sets its bandwidth. */
	uint32_t sample_rate_hz;
	/** Bandwidth of the wide channel filter at that sample rate. */
	uint32_t rx_bandwidth_hz;
	/** Bit clock recovery oversampling rate, scaled by eight as the transceiver expresses it.
	 */
	uint16_t osr_x8;
};

/**
 * Chip identification, as returned by the PART_INFO and FUNC_INFO commands. The members are
 * ordered widest first rather than in the order the commands report them, so that the structure
 * has no padding holes in it.
 */
struct si4467_wisun_part_info {
	uint16_t part;
	uint16_t id;
	uint16_t patch;
	uint8_t chiprev;
	uint8_t pbuild;
	uint8_t customer;
	uint8_t romid;
	uint8_t rev_ext;
	uint8_t rev_branch;
	uint8_t rev_int;
	uint8_t func;
};

/**
 * @brief Called for every received frame.
 *
 * Runs in the RX thread, not in interrupt context. @p frame is only valid for the duration of the
 * call.
 */
typedef void (*si4467_wisun_rx_cb_t)(const struct wisun_frame *frame, void *user_data);

/**
 * @brief Reset, patch, power up and configure the transceiver.
 *
 * Does not start reception; call @ref si4467_wisun_start for that.
 *
 * @return 0 on success, negative errno otherwise.
 */
int si4467_wisun_init(void);

/** @brief Register the callback invoked for each received frame. */
void si4467_wisun_set_rx_callback(si4467_wisun_rx_cb_t cb, void *user_data);

/**
 * @brief Program the transceiver for @p phy.
 *
 * Reception stops for the duration; call @ref si4467_wisun_start afterwards. The configuration
 * loaded at start-up is a fixed one generated by WDS, and this recomputes the parts of it that
 * depend on the PHY: the synthesiser, and the modem's decimation, oversampling and deviation.
 *
 * @return 0 on success, -ENOTSUP if the frequency or the symbol rate is outside what the
 *         transceiver can be programmed for, or a negative errno.
 */
int si4467_wisun_set_phy(const struct si4467_wisun_phy *phy);

/**
 * @brief Whether the synthesiser can reach @p freq_khz.
 *
 * @ref si4467_wisun_set_phy asks this of itself and refuses a PHY it cannot tune to, but all it can
 * hand back is an errno, and all it knows to log is a frequency. Asking beforehand lets a caller
 * that knows which channel plan chose that frequency turn the plan down by name.
 */
bool si4467_wisun_can_tune(uint32_t freq_khz);

/** @brief What @ref si4467_wisun_set_phy actually programmed. */
const struct si4467_wisun_phy_actual *si4467_wisun_get_phy_actual(void);

/**
 * @brief Start receiving on @p channel.
 *
 * The centre frequency follows from the PHY set with @ref si4467_wisun_set_phy.
 */
int si4467_wisun_start(uint8_t channel);

/** @brief Stop receiving and return the transceiver to its ready state. */
int si4467_wisun_stop(void);

/**
 * @brief Switch to @p channel, restarting reception if it is currently running.
 */
int si4467_wisun_set_channel(uint8_t channel);

/** @brief Channel currently configured. */
uint8_t si4467_wisun_get_channel(void);

/** @brief Read chip identification. */
int si4467_wisun_get_part_info(struct si4467_wisun_part_info *info);

/**
 * @brief Measure the current RSSI on @p channel.
 *
 * Interrupts reception for the duration of the measurement. Intended for checking that the
 * frequency configuration is sane, not for continuous monitoring.
 */
int si4467_wisun_measure_rssi(uint8_t channel, int16_t *rssi_dbm);

/**
 * @brief Turn raw capture mode on or off.
 *
 * In raw mode the receive path makes no attempt to interpret a frame: every octet drained from the
 * FIFO is printed to the console as a hex line, and nothing is discarded for an implausible PHY
 * header. This is a bring-up aid — it tells a demodulation problem apart from a packet handler
 * misconfiguration, which the frame counters on their own cannot.
 */
void si4467_wisun_set_raw(bool raw);

/** @brief Whether raw capture mode is on. */
bool si4467_wisun_get_raw(void);

/** @brief Access the diagnostic counters. */
const struct si4467_wisun_stats *si4467_wisun_get_stats(void);

/**
 * @brief Zero the diagnostic counters.
 *
 * The counters only mean anything against a known starting point: whether every sync detect became
 * a frame is a question about one run, not about everything since the dongle was plugged in. This
 * gives that starting point without a reset, which would take the selected PHY with it.
 */
void si4467_wisun_reset_stats(void);

/**
 * @brief Read @p count consecutive properties starting at @p group : @p start.
 *
 * Intended for checking what the transceiver actually ended up configured with, which is the
 * quickest way to tell a wrong configuration apart from a reception problem.
 */
int si4467_wisun_get_properties(uint8_t group, uint8_t start, uint8_t count, uint8_t *values);

/**
 * @brief Write a single transceiver property.
 *
 * The counterpart of @ref si4467_wisun_get_properties, for trying a setting out against live
 * traffic before committing it to the configuration in the driver.
 */
int si4467_wisun_set_property_raw(uint8_t group, uint8_t index, uint8_t value);

#endif /* WISUN_SNIFFER_SI4467_WISUN_H_ */
