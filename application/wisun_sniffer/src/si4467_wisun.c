/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "si4467_fec.h"
#include "si4467_wisun.h"

/*
 * Command opcodes and property group numbers come from the register header, as does the errata
 * patch blob. Both are vendor-derived artefacts kept under src/ext/ and are not edited here. The
 * register header only enumerates the property indices the driver it came from needed, so the ones
 * used here are defined below.
 */
#include "ext/radio_config_wisun.h"
#include "ext/si4467_patch.h"
#include "ext/si4467_regs.h"

#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/spi.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/byteorder.h>

#include <string.h>

LOG_MODULE_REGISTER(si4467_wisun, LOG_LEVEL_INF);

#define SI4467_NODE DT_NODELABEL(si4467)

static const struct spi_dt_spec si4467_spi =
	SPI_DT_SPEC_GET(SI4467_NODE, SPI_WORD_SET(8) | SPI_TRANSFER_MSB | SPI_OP_MODE_MASTER, 0);
static const struct gpio_dt_spec si4467_sdn = GPIO_DT_SPEC_GET(SI4467_NODE, sdn_gpios);
static const struct gpio_dt_spec si4467_nirq = GPIO_DT_SPEC_GET(SI4467_NODE, nirq_gpios);

/** Determined with a signal generator; see the board devicetree. */
#define RX_RSSI_OFFSET_DB DT_PROP_OR(SI4467_NODE, rx_rssi_offset, 0)
/** Crystal load capacitance trim, board specific. WDS cannot know this value. */
#define XTAL_TUNE_VALUE   DT_PROP_OR(SI4467_NODE, xtal_capacitor_tune_value, 42)

/* Property addresses used below, as (group, index) pairs. */
#define PROP_GLOBAL_XO_TUNE       SI4467_PROPERTY_GROUP_GLOBAL, 0x00
#define PROP_GLOBAL_CONFIG        SI4467_PROPERTY_GROUP_GLOBAL, 0x03
#define PROP_INT_CTL_ENABLE       SI4467_PROPERTY_GROUP_INT_CTL, 0x00
#define PROP_MODEM_DATA_RATE      SI4467_PROPERTY_GROUP_MODEM, 0x03
#define PROP_MODEM_TX_NCO_MODE    SI4467_PROPERTY_GROUP_MODEM, 0x06
#define PROP_MODEM_FREQ_DEV       SI4467_PROPERTY_GROUP_MODEM, 0x0A
#define PROP_MODEM_DECIMATION_CFG SI4467_PROPERTY_GROUP_MODEM, 0x1E
#define PROP_MODEM_BCR            SI4467_PROPERTY_GROUP_MODEM, 0x22
#define PROP_MODEM_AFC_WAIT       SI4467_PROPERTY_GROUP_MODEM, 0x2D
#define PROP_MODEM_RSSI_CONTROL   SI4467_PROPERTY_GROUP_MODEM, 0x4C
#define PROP_MODEM_CLKGEN_BAND    SI4467_PROPERTY_GROUP_MODEM, 0x51
#define PROP_PKT_LEN              SI4467_PROPERTY_GROUP_PKT, 0x08
#define PROP_PKT_RX_THRESHOLD     SI4467_PROPERTY_GROUP_PKT, 0x0C
#define PROP_FREQ_CONTROL_INTE    SI4467_PROPERTY_GROUP_FREQ_CONTROL, 0x00

/**
 * GLOBAL_CONFIG with PROTOCOL set to IE154G: fast sequencer, split FIFOs, and automatic 802.15.4g
 * PHY header parsing.
 *
 * This is the exact value WDS emits for its 802.15.4g project. Note that the API reference says
 * bit 6 "should always be written to 1" while WDS leaves it clear here; if reception ever turns
 * out to be unreliable, 0x62 is the variant worth trying.
 */
#define GLOBAL_CONFIG_IE154G 0x22

/**
 * The same, with PROTOCOL back to generic, which is what a coded PHY has to run in.
 *
 * Every service IE154G provides is derived from the PHY header, and on a coded frame the header is
 * not there to be read: it is inside the convolutional code, half a decode away. Left on, the
 * packet handler would sooner or later find something header shaped in the code symbols and then
 * de-whiten, size and end the frame on it. Generic is not a fallback here, it is the only setting
 * that describes what is arriving -- an undelimited stream of bits that means nothing until
 * si4467_fec.c has been over it.
 */
#define GLOBAL_CONFIG_GENERIC 0x20

/**
 * The start-of-frame delimiters of IEEE 802.15.4-2020 tables 19-2 and 19-3, for 2-FSK with
 * phySunFskSfd = 0, which is the pair Wi-SUN PHY 2.03 6.1.2 selects between.
 *
 * Whether a frame is coded is not in the PHY header -- there is no bit for it -- so the SFD is the
 * only thing that says so, and a receiver has to commit to one or the other before the frame
 * starts. That is why a coded PhyModeID is a separate selection here rather than something noticed
 * per frame.
 *
 * Each octet is bit reversed against the way the standard prints the pattern, because the PHY
 * sends the low order bit of an octet first and the sync word register is matched against the
 * order the bits arrive in. The uncoded pair below is 0x904E written that way, and it is what the
 * WDS configuration already loads -- which is the check that the reversal is right.
 */
#define SFD_UNCODED_FIRST 0x09
#define SFD_CODED_FIRST   0xF6
#define SFD_SECOND        0x72

/** PKT_LEN as IE154G needs it: a two octet big endian length, kept in the FIFO, sizing field 2. */
#define PKT_LEN_FROM_PHR 0x3A

/**
 * PKT_LEN for a coded frame: no length field at all, so the field lengths alone decide.
 *
 * The length in a coded frame's PHY header counts the octets the frame had before it was encoded,
 * so it is about half the number that actually arrive; handing it to the packet handler would end
 * every frame halfway through. The field is therefore given a fixed size instead, and the
 * reception ends when that many code symbols have arrived.
 *
 * INFINITE_LEN looks like the better fit for a frame whose length is not yet known, and was tried
 * first. On air it gave sync detects and then silence: no FIFO interrupt ever followed, so nothing
 * was ever drained. A fixed length keeps the packet handler on the path it is used to -- it counts
 * octets and raises PACKET_RX -- and a capture of a known size is all the raw mode needs.
 */
#define PKT_LEN_FIXED 0x00

/* Packet handler interrupt bits (GET_INT_STATUS PH_PEND). */
#define PH_INT_RX_FIFO_ALMOST_FULL BIT(0)
#define PH_INT_CRC_ERROR           BIT(3)
#define PH_INT_PACKET_RX           BIT(4)

/* Modem interrupt bits (GET_INT_STATUS MODEM_PEND). */
#define MODEM_INT_SYNC_DETECT     BIT(0)
#define MODEM_INT_PREAMBLE_DETECT BIT(1)
#define MODEM_INT_INVALID_SYNC    BIT(5)

/* Chip interrupt bits (GET_INT_STATUS CHIP_PEND). */
#define CHIP_INT_CMD_ERROR                     BIT(3)
#define CHIP_INT_FIFO_UNDERFLOW_OVERFLOW_ERROR BIT(5)

/* FIFO_INFO argument bits. */
#define FIFO_INFO_RESET_TX BIT(0)
#define FIFO_INFO_RESET_RX BIT(1)

/*
 * GPIO_PIN_CFG pin functions. DONOTHING is the one value that leaves a pin as it is, rather than
 * being a function in its own right, which is what makes it safe for the pins this application
 * depends on but does not want to redefine.
 */
#define GPIO_CFG_DONOTHING      0
#define GPIO_CFG_VALID_PREAMBLE 24
#define GPIO_CFG_TX_STATE       32

/** Drive strength for all of the pins above, in bits 6:5 of the GEN_CONFIG argument. */
#define GPIO_CFG_DRV_STRENGTH_MED_LOW (2 << 5)

/* START_RX / CHANGE_STATE operating states. */
#define STATE_NOCHANGE 0
#define STATE_SLEEP    1
#define STATE_READY    3
#define STATE_RX       8

/**
 * RSSI is latched at sync word detect, so the reported value belongs to the frame rather than to
 * whatever the receiver happens to hear afterwards. WDS leaves latching disabled.
 */
#define MODEM_RSSI_CONTROL_LATCH_SYNC 0x02

/**
 * Drain the RX FIFO once this many octets are in it.
 *
 * Deliberately well below the 64 octet FIFO. A 16 bit sync word matches noise every second or so,
 * and such a false detect starts a reception that only ends when the watchdog fires. Draining
 * early means the bogus PHY header is recognised within a few milliseconds and the receiver is
 * restarted, so a real frame arriving shortly after a false detect is still caught.
 */
#define RX_FIFO_THRESHOLD 16

/**
 * How long to wait between looks at the FIFO while polling out the end of a coded frame.
 *
 * An octet is 80 us of air time at 100 kbit/s and 160 us at 50, so this looks a few times per
 * octet however the PHY is configured. It bounds how late the end of a frame can be noticed,
 * which is what decides whether the receiver is listening again before a reply arrives.
 */
#define TAIL_POLL_US 25

/**
 * How long a reception may take before it is abandoned, as a multiple of the time a maximum length
 * frame needs on the air. At 50 kbps that is 2047 octets in ~330 ms, so the watchdog fires at
 * ~660 ms; at higher symbol rates it scales down with the frame duration.
 */
#define RX_WATCHDOG_FACTOR 2

/** Cap on how much of a reception attempt raw capture mode prints; see @ref dump_raw. */
#define RAW_DUMP_MAX_OCTETS 512

/**
 * How many coded octets to take off a coded PHY before ending the reception.
 *
 * On a coded PHY nothing in the transceiver knows where a frame ends: the length in the PHY header
 * is inside the convolutional code, and describes the frame before it was encoded in any case. The
 * field is therefore given this fixed size and the reception ends when it has been filled.
 *
 * Until the decoder is in the receive path this is a fixed count rather than the frame's real
 * length: it is what @c raw 1 needs to get code symbols off the air and onto a host, which is what
 * has to happen before the decoder can be trusted against anything real. It matches
 * @ref RAW_DUMP_MAX_OCTETS so that a dump is never truncated, and at rate 1/2 it spans a frame of
 * about 250 octets.
 */
#define CODED_CAPTURE_OCTETS 512

/**
 * Longest coded frame the PHY can produce, which is what a coded reception is collected into.
 *
 * @ref wisun_fec_coded_len of the largest PSDU, give or take the rounding it does. The receive
 * field is sized to this as well, so the transceiver never decides a frame is over on its own --
 * the decode does, as soon as the PHY header says how long the frame really is.
 */
#define MAX_CODED_LEN WISUN_FEC_MAX_CODED_OCTETS

/*
 * PHY header fields, as a 16-bit value; IEEE 802.15.4-2020 figure 19-4. decode_phr() takes the
 * same fields out of the two octets the uncoded path receives; a coded frame's header arrives
 * most significant bit first, so it is carried as a value instead.
 */
#define WISUN_PHR_LENGTH_MASK 0x07FFU
#define WISUN_PHR_WHITENED    0x0800U
#define WISUN_PHR_FCS_TYPE    0x1000U
/** Mode Switch and the two reserved bits, all of which a data frame leaves clear. */
#define WISUN_PHR_RESERVED    0xE000U

#define CTS_TIMEOUT_MS 100
#define MAX_CMD_ARGS   16
#define MAX_CMD_RESP   16

/*
 * Reply framing for commands that carry a CTS: the first octet clocked back is a dummy (it is
 * shifted out while the READ_CMD_BUFF opcode is still going in), the second is CTS, and the
 * response follows. Note that MISO idles high, so mistaking the dummy for CTS silently shifts
 * every response by one octet rather than failing outright.
 */
#define CTS_DUMMY_OCTETS 2

/** Ready-to-send SPI command buffers; only touched while holding spi_lock. */
static uint8_t cmd_tx_buf[1 + MAX_CMD_ARGS];
static uint8_t cts_tx_buf[CTS_DUMMY_OCTETS + MAX_CMD_RESP];
static uint8_t cts_rx_buf[CTS_DUMMY_OCTETS + MAX_CMD_RESP];

static K_MUTEX_DEFINE(spi_lock);

enum {
	EVENT_NIRQ = BIT(0),
	EVENT_STOP = BIT(1),
};

static K_EVENT_DEFINE(rx_events);

/**
 * How many received frames may be waiting on the decoder at once.
 *
 * This is the depth of burst the receive path can absorb without dropping anything, and a burst is
 * what this network produces: a ping and its acknowledgments are four frames in twenty
 * milliseconds, and background traffic lands on top of that. Four deep leaves room for the busiest
 * exchange seen here and the frames either side of it.
 */
#define CODED_JOB_QUEUE_DEPTH 4

/**
 * One more buffer than the queue can hold, and that is the whole reason for the number.
 *
 * A frame the decoder has taken off the queue is no longer on it but is still being read, so the
 * frames alive at once are the queue's capacity plus the one in flight. With as many buffers as
 * the queue is deep, the slot the receive thread moves to next is the one the decoder is part way
 * through, and a burst overwrites a frame mid-decode. It does not look like a race afterwards: the
 * frame decodes to something, just with far too many corrections, and is discarded as an
 * implausible header at a signal strength where nothing should be wrong at all.
 */
#define CODED_SLOTS (CODED_JOB_QUEUE_DEPTH + 1)

/**
 * A coded frame as it arrives, and what it decodes to.
 *
 * Separate from @ref rx_frame because a coded frame is about twice the size of the frame it
 * carries, and because nothing in it means anything until si4467_fec.c has been over it.
 */
static uint8_t coded_frame[CODED_SLOTS][MAX_CODED_LEN];
static uint8_t decoded_frame[WISUN_MAX_PSDU_LEN + 2 * sizeof(uint16_t)];

/** Which one the receive thread is filling; the decoder has whichever it was handed. */
static uint8_t coded_slot;

/** The frame the decoder builds, which is its own and not the one reception is assembling into. */
static struct wisun_frame coded_out;

/**
 * Everything about a coded frame except its octets, handed to the decoder with them.
 *
 * Decoding a frame costs milliseconds -- measured at eight for a long one -- and an acknowledgment
 * follows the frame it answers by less than one, so it cannot be done on the thread that has to be
 * back listening by then. What travels here is what the receive thread knew at the time and will
 * have overwritten by the time the decoder runs.
 */
struct coded_job {
	uint64_t timestamp_us;
	size_t len;
	uint16_t phr;
	int16_t rssi_dbm;
	int16_t afc_offset;
	uint8_t slot;
	uint8_t channel;
};

K_MSGQ_DEFINE(coded_jobs, sizeof(struct coded_job), CODED_JOB_QUEUE_DEPTH, 4);

/**
 * Held while a frame is reported and the counters that go with it are moved.
 *
 * Two threads can reach that: the receive thread for an uncoded frame and the decoder for a coded
 * one. A single PHY is one or the other, so they do not normally both have frames to hand on --
 * but changing from a coded PHY to an uncoded one while the decoder still has work queued is
 * exactly a moment when they do, and the capture stream has no room for two writers.
 */
K_MUTEX_DEFINE(report_lock);

static struct {
	struct gpio_callback nirq_cb;
	si4467_wisun_rx_cb_t rx_cb;
	void *rx_cb_user_data;
	struct si4467_wisun_stats stats;
	struct si4467_wisun_phy_actual actual;
	/** How long one reception may take, derived from the symbol rate. */
	uint32_t watchdog_ms;
	/** How long one octet occupies the air, derived from the symbol rate; see drain_tail(). */
	uint32_t octet_us;
	uint8_t channel;
	bool receiving;
	bool running;
	/**
	 * Whether the selected PHY is convolutionally coded, in which case the transceiver is
	 * streaming undelimited code symbols rather than parsed frames; see
	 * @ref si4467_configure_framing.
	 */
	bool fec;
	/** Print every octet drained from the FIFO instead of interpreting it; see @ref dump_raw.
	 */
	bool raw;
} ctx;

/** The frame being assembled, plus the one handed to the callback. Owned by the RX thread. */
static struct wisun_frame rx_frame;

/* ------------------------------------------------------------------------------------------- */
/* SPI transport                                                                                */
/* ------------------------------------------------------------------------------------------- */

static int spi_xfer(const uint8_t *tx, uint8_t *rx, size_t len)
{
	const struct spi_buf tx_buf = {.buf = (uint8_t *)tx, .len = len};
	const struct spi_buf_set tx_set = {.buffers = &tx_buf, .count = 1};
	const struct spi_buf rx_buf = {.buf = rx, .len = len};
	const struct spi_buf_set rx_set = {.buffers = &rx_buf, .count = 1};

	return spi_transceive_dt(&si4467_spi, &tx_set, rx ? &rx_set : NULL);
}

/**
 * @brief Poll READ_CMD_BUFF until the chip reports CTS, then read @p resp_len response octets.
 *
 * The CTS octet and the response must be read within a single chip select assertion, which is why
 * this is one transfer rather than a poll followed by a read.
 */
static int si4467_wait_cts(uint8_t *resp, size_t resp_len)
{
	const int64_t deadline = k_uptime_get() + CTS_TIMEOUT_MS;

	__ASSERT_NO_MSG(resp_len <= MAX_CMD_RESP);

	/* Typical time to a valid CTS is 20 us; the maximum is unspecified. */
	k_busy_wait(20);

	do {
		const size_t len = CTS_DUMMY_OCTETS + resp_len;
		int ret;

		memset(cts_tx_buf, 0, len);
		cts_tx_buf[0] = COMMAND_READ_CMD_BUFF;

		ret = spi_xfer(cts_tx_buf, cts_rx_buf, len);
		if (ret) {
			LOG_ERR("SPI transfer failed while polling CTS: %d", ret);
			return ret;
		}

		if (cts_rx_buf[1] == 0xFF) {
			if (resp_len) {
				memcpy(resp, &cts_rx_buf[CTS_DUMMY_OCTETS], resp_len);
			}
			return 0;
		}

		k_yield();
	} while (k_uptime_get() < deadline);

	LOG_ERR("timed out waiting for CTS");
	return -ETIMEDOUT;
}

/**
 * @brief Issue a command and optionally collect its response.
 *
 * Waits for CTS both before sending (the chip must be idle to accept a command) and after, so that
 * callers never have to think about command timing.
 */
static int si4467_cmd(uint8_t opcode, const uint8_t *args, size_t args_len, uint8_t *resp,
		      size_t resp_len)
{
	int ret;

	__ASSERT_NO_MSG(args_len <= MAX_CMD_ARGS);

	k_mutex_lock(&spi_lock, K_FOREVER);

	ret = si4467_wait_cts(NULL, 0);
	if (ret) {
		goto out;
	}

	cmd_tx_buf[0] = opcode;
	if (args_len) {
		memcpy(&cmd_tx_buf[1], args, args_len);
	}

	ret = spi_xfer(cmd_tx_buf, NULL, 1 + args_len);
	if (ret) {
		LOG_ERR("failed to send command 0x%02x: %d", opcode, ret);
		goto out;
	}

	ret = si4467_wait_cts(resp, resp_len);
	if (ret) {
		LOG_ERR("no CTS after command 0x%02x", opcode);
	}

out:
	k_mutex_unlock(&spi_lock);
	return ret;
}

/** @brief Read @p len octets from the RX FIFO. This command has no CTS handshake. */
static int si4467_read_rx_fifo(uint8_t *buf, size_t len)
{
	const uint8_t opcode = COMMAND_READ_RX_FIFO;
	const struct spi_buf tx_bufs[] = {{.buf = (uint8_t *)&opcode, .len = 1}};
	const struct spi_buf_set tx_set = {.buffers = tx_bufs, .count = 1};
	const struct spi_buf rx_bufs[] = {{.buf = NULL, .len = 1}, {.buf = buf, .len = len}};
	const struct spi_buf_set rx_set = {.buffers = rx_bufs, .count = 2};
	int ret;

	k_mutex_lock(&spi_lock, K_FOREVER);
	ret = spi_transceive_dt(&si4467_spi, &tx_set, &rx_set);
	k_mutex_unlock(&spi_lock);

	if (ret) {
		LOG_ERR("failed to read %zu octets from RX FIFO: %d", len, ret);
	}

	return ret;
}

static int si4467_set_property(uint8_t group, uint8_t index, uint8_t value)
{
	const uint8_t args[] = {group, 1, index, value};

	return si4467_cmd(COMMAND_SET_PROPERTY, args, sizeof(args), NULL, 0);
}

/** @brief Write up to 12 consecutive properties in one command. */
static int si4467_set_properties(uint8_t group, uint8_t start, const uint8_t *values, uint8_t count)
{
	uint8_t args[3 + 12];

	if (count == 0 || count > 12) {
		return -EINVAL;
	}

	args[0] = group;
	args[1] = count;
	args[2] = start;
	memcpy(&args[3], values, count);

	return si4467_cmd(COMMAND_SET_PROPERTY, args, 3 + count, NULL, 0);
}

int si4467_wisun_get_properties(uint8_t group, uint8_t start, uint8_t count, uint8_t *values)
{
	const uint8_t args[] = {group, count, start};

	if (count == 0 || count > MAX_CMD_RESP) {
		return -EINVAL;
	}

	return si4467_cmd(COMMAND_GET_PROPERTY, args, sizeof(args), values, count);
}

/* ------------------------------------------------------------------------------------------- */
/* Chip commands                                                                                */
/* ------------------------------------------------------------------------------------------- */

/**
 * @brief Read the RX FIFO fill level.
 *
 * @param reset_rx  Discard whatever is currently in the RX FIFO.
 * @param count     Set to the number of octets available, may be NULL when resetting.
 */
static int si4467_fifo_info(bool reset_rx, uint8_t *count)
{
	const uint8_t args[] = {reset_rx ? FIFO_INFO_RESET_RX : 0};
	uint8_t resp[2];
	int ret;

	ret = si4467_cmd(COMMAND_FIFO_INFO, args, sizeof(args), resp, sizeof(resp));
	if (ret) {
		return ret;
	}

	if (count) {
		*count = resp[0];
	}

	return 0;
}

/** @brief Read and clear all pending interrupts. */
static int si4467_get_int_status(uint8_t *ph_pend, uint8_t *modem_pend, uint8_t *chip_pend)
{
	/* Clear every latched interrupt we are told about. */
	const uint8_t args[] = {0x00, 0x00, 0x00};
	uint8_t resp[8];
	int ret;

	ret = si4467_cmd(COMMAND_GET_INT_STATUS, args, sizeof(args), resp, sizeof(resp));
	if (ret) {
		return ret;
	}

	*ph_pend = resp[2];
	*modem_pend = resp[4];
	*chip_pend = resp[6];

	return 0;
}

/**
 * @brief Convert a raw RSSI register reading to dBm.
 *
 * This is valid with a MODEM_RSSI_COMP of 0x40.
 */
static int16_t rssi_raw_to_dbm(uint8_t raw)
{
	return (int16_t)raw / 2 - 0x40 - 70 - RX_RSSI_OFFSET_DB;
}

/**
 * @brief Read the modem status, including current and latched RSSI.
 *
 * @param clear_pending  Clear the latched modem interrupts as a side effect.
 * @param curr_rssi      Where to put the RSSI as it is right now, raw register units. May be NULL.
 * @param latch_rssi     Where to put the RSSI latched at sync detect, raw units. May be NULL.
 * @param afc_offset     Where to put the AFC frequency offset. May be NULL.
 *
 * @return 0 on success, negative errno otherwise.
 */
static int si4467_get_modem_status(bool clear_pending, uint8_t *curr_rssi, uint8_t *latch_rssi,
				   int16_t *afc_offset)
{
	const uint8_t args[] = {clear_pending ? 0x00 : 0xFF};
	uint8_t resp[8];
	int ret;

	ret = si4467_cmd(COMMAND_GET_MODEM_STATUS, args, sizeof(args), resp, sizeof(resp));
	if (ret) {
		return ret;
	}

	if (curr_rssi) {
		*curr_rssi = resp[2];
	}
	if (latch_rssi) {
		*latch_rssi = resp[3];
	}
	if (afc_offset) {
		*afc_offset = (int16_t)sys_get_be16(&resp[6]);
	}

	return 0;
}

static int si4467_change_state(uint8_t state)
{
	const uint8_t args[] = {state};

	return si4467_cmd(COMMAND_CHANGE_STATE, args, sizeof(args), NULL, 0);
}

/**
 * @brief Enter RX on @p channel.
 *
 * RX_LEN is left at zero: with GLOBAL_CONFIG:PROTOCOL set to IE154G the packet handler derives the
 * frame length from the received PHY header, so we must not constrain it here.
 */
static int si4467_start_rx(uint8_t channel)
{
	/*
	 * RX_LEN stands in for PKT_FIELD_1_LENGTH. Under IE154G it is left at zero because the
	 * packet handler takes the length from the PHY header, but a coded PHY has no header it can
	 * read, and zero there is a zero length packet rather than "decide for yourself": the sync
	 * word matched and then nothing was ever drained. State the length instead.
	 */
	const uint16_t rx_len = ctx.fec ? CODED_CAPTURE_OCTETS : 0;
	const uint8_t args[] = {
		channel, /* CHANNEL */
		0x00,    /* CONDITION: start immediately */
		(uint8_t)(rx_len >> 8),
		(uint8_t)(rx_len & 0xFF), /* RX_LEN */
		STATE_RX,                 /* RXTIMEOUT_STATE: keep listening */
		STATE_READY, /* RXVALID_STATE: stop so the FIFO can be drained safely */
		/*
		 * RXINVALID_STATE. A sniffer must report damaged frames rather than hide them, so
		 * this is not RX: re-entering RX here would make the radio discard the frame and
		 * start over without ever raising PACKET_RX, and the frame would vanish silently.
		 */
		STATE_READY,
	};

	return si4467_cmd(COMMAND_START_RX, args, sizeof(args), NULL, 0);
}

/* ------------------------------------------------------------------------------------------- */
/* Bring-up                                                                                     */
/* ------------------------------------------------------------------------------------------- */

/** @brief Pulse SDN to force a power-on reset, leaving the chip in its bootloader. */
static int si4467_reset(void)
{
	int ret;

	ret = gpio_pin_set_dt(&si4467_sdn, 1);
	if (ret) {
		LOG_ERR("failed to assert SDN: %d", ret);
		return ret;
	}

	k_msleep(10);

	ret = gpio_pin_set_dt(&si4467_sdn, 0);
	if (ret) {
		LOG_ERR("failed to release SDN: %d", ret);
		return ret;
	}

	/* The datasheet allows up to 6 ms for the power-on reset to complete. */
	k_msleep(20);

	return 0;
}

/**
 * @brief Upload the errata patch.
 *
 * Must happen while the chip is still in its bootloader, i.e. between reset and POWER_UP. Per
 * AN633 a CTS has to be collected after every line.
 */
static int si4467_apply_patch(void)
{
	static const uint8_t patch[][8] = SI4467_PATCH_DATA_ARRAY;

	LOG_DBG("applying errata patch (%zu lines)", ARRAY_SIZE(patch));

	for (size_t i = 0; i < ARRAY_SIZE(patch); i++) {
		int ret = si4467_cmd(patch[i][0], &patch[i][1], 7, NULL, 0);

		if (ret) {
			LOG_ERR("failed to apply patch line %zu/%zu: %d", i, ARRAY_SIZE(patch),
				ret);
			return ret;
		}
	}

	return 0;
}

/**
 * @brief Boot the main application image in EZRadioPRO mode, with the patch applied.
 *
 * The dedicated 802.15.4 boot mode is deliberately not used: it only accepts 802.15.4 traffic
 * through a Silicon Labs MAC stack and offers no packet level access, which rules out sniffing.
 * EZRadioPRO mode supports the 802.15.4g PHY in full (datasheet section 9.3).
 */
static int si4467_power_up(void)
{
	const uint32_t xtal_hz = DT_PROP(SI4467_NODE, xtal_frequency);
	const uint8_t args[] = {
		0x01 | BIT(7),          /* BOOT_OPTIONS: main application image, apply patch */
		0x00,                   /* XTAL_OPTIONS: crystal, not TCXO */
		(xtal_hz >> 24) & 0xFF, /* XO_FREQ */
		(xtal_hz >> 16) & 0xFF,
		(xtal_hz >> 8) & 0xFF,
		(xtal_hz >> 0) & 0xFF,
	};

	return si4467_cmd(COMMAND_POWER_UP, args, sizeof(args), NULL, 0);
}

/**
 * @brief Apply the WDS generated configuration.
 *
 * The array holds length prefixed commands. POWER_UP and GPIO_PIN_CFG entries are skipped, because
 * this application issues both itself: its own POWER_UP because WDS does not know about the errata
 * patch, and its own GPIO_PIN_CFG because WDS does not know what the board wired the pins to. See
 * si4467_power_up() and si4467_configure_gpios().
 */
static int si4467_apply_radio_config(void)
{
	static const uint8_t config[] = RADIO_CONFIGURATION_DATA_ARRAY;
	size_t i = 0;

	while (i < sizeof(config) && config[i] != 0) {
		const uint8_t len = config[i];
		const uint8_t opcode = config[i + 1];
		int ret;

		if (len < 1 || i + 1 + len > sizeof(config)) {
			LOG_ERR("malformed radio configuration at offset %zu", i);
			return -EINVAL;
		}

		if (opcode != COMMAND_POWER_UP && opcode != COMMAND_GPIO_PIN_CFG) {
			ret = si4467_cmd(opcode, &config[i + 2], len - 1, NULL, 0);
			if (ret) {
				LOG_ERR("radio configuration command 0x%02x failed: %d", opcode,
					ret);
				return ret;
			}
		}

		i += len + 1;
	}

	return 0;
}

/**
 * @brief Point the transceiver's GPIO2 and GPIO3 at the TX and RX indicator LEDs.
 *
 * The two LEDs beside the USB connector are wired to the transceiver rather than to the nRF52840,
 * so it is the only thing that can light them. Both modes follow the transceiver's own state
 * machine, which costs the firmware nothing: no interrupt, no work per frame, and nothing to get
 * out of step with what the radio is actually doing.
 *
 * VALID_PREAMBLE is the longest lived of the signals that mark a frame arriving. It goes high when
 * the demodulator finds a preamble and stays high until the packet has been received, so it covers
 * the preamble, the PHY header and the whole PSDU -- about 9 ms for a 48 octet frame at 50 kbit/s,
 * and a third of a second for the largest a Wi-SUN PHY allows. SYNC_WORD_DETECT ends at the same
 * point but starts 8 octets later, so it can only ever be shorter.
 *
 * The cost of starting that early is that the LED also flickers on a preamble that never reaches a
 * sync word, which is noise rather than a frame; the signal drops again at the sync word timeout.
 * SYNC_WORD_DETECT (26) is the stricter choice if that ever becomes distracting.
 *
 * TX_STATE stays dark, there being no transmit path at all.
 *
 * Every other pin is left as DONOTHING, the mode that changes nothing: nIRQ and SDO carry the
 * receive interrupt and the SPI read data that the rest of this file depends on, and GPIO0 and
 * GPIO1 are brought out to nRF52840 pins that nothing here drives or reads.
 *
 * The one thing DONOTHING does not cover is drive strength, which GEN_CONFIG applies to every
 * output pin at once, nIRQ and SDO included. MED_LOW is enough for both the LEDs and a 10 MHz SPI
 * read.
 */
static int si4467_configure_gpios(void)
{
	static const uint8_t args[] = {
		GPIO_CFG_DONOTHING,      /* GPIO0, unused */
		GPIO_CFG_DONOTHING,      /* GPIO1, unused */
		GPIO_CFG_TX_STATE,       /* GPIO2, TX LED */
		GPIO_CFG_VALID_PREAMBLE, /* GPIO3, RX LED */
		GPIO_CFG_DONOTHING,      /* nIRQ, the receive interrupt */
		GPIO_CFG_DONOTHING,      /* SDO, SPI read data */
		GPIO_CFG_DRV_STRENGTH_MED_LOW,
	};

	return si4467_cmd(COMMAND_GPIO_PIN_CFG, args, sizeof(args), NULL, 0);
}

/**
 * @brief Configure the packet handler for the IEEE 802.15.4g PHY.
 *
 * WDS can only express the 12.5 kHz deviation this PHY needs from an "empty framework" project,
 * which emits generic packet handling. These are the settings its 802.15.4g project would have
 * produced, so the radio parses the PHY header itself.
 */
static int si4467_configure_packet_handler(void)
{
	int ret;

	/*
	 * Index 0x00 onwards:
	 *   PKT_CRC_CONFIG     0x00  no CRC engine. The API reference says so for IE154G: "PHR and
	 *                            FCS will be put in the FIFO for the host to retrieve and
	 *                            check. Therefore, CRC shouldn't be enabled." It is also what
	 *                            a sniffer needs, since a frame that fails the check has to
	 *                            reach Wireshark rather than be dropped. WDS emits 0x57 here
	 *                            (CRC-32 with an all zeroes seed, CRC-16 alternative), which
	 *                            fails on every Wi-SUN frame anyway: IEEE 802.15.4 seeds its
	 *                            FCS-32 with all ones.
	 *   PKT_WHT_POLY       0x0108, PKT_WHT_SEED 0x010F, PKT_WHT_BIT_NUM 0x07
	 *                            the PN9 whitener the standard mandates; the empty framework
	 *                            defaults to 0xFFFF/0x20, which would garble every PSDU
	 *   PKT_CONFIG1        0x83  PH_FIELD_SPLIT, so RX fields are configured independently,
	 *                            plus BIT_ORDER = LSBIT_FIRST. IEEE 802.15.4g sends the low
	 *                            order bit of every octet first, in the PHY header as much as
	 *                            in the PSDU. The API reference claims IE154G overrides this
	 *                            bit, but it does not: left at MSBIT_FIRST the header reads
	 *                            back bit reversed, so the radio parses a wrong length and
	 *                            misses that the PSDU is whitened, and no frame ever completes.
	 *   PKT_CONFIG2        0x80
	 *   PKT_LEN            0x3A  two octet length field, kept IN_FIFO, applied to field 2
	 *   PKT_LEN_FIELD_SOURCE 0x01 the length comes from field 1, i.e. the PHR
	 *   PKT_LEN_ADJUST     0x04  IE154G sizes the PSDU field as "length from the PHR minus the
	 *                            FCS", keeping the FCS octets for its own CRC engine, so
	 *                            without this they never reach the host. Wireshark has to see
	 *                            them, and the engine's verdict is worthless anyway: it seeds
	 *                            the CRC with all zeroes while IEEE 802.15.4 uses all ones, so
	 *                            it rejects perfectly good frames. The FCS is checked in
	 *                            software instead, see check_fcs().
	 *
	 *                            On a frame with a 2 octet FCS this reads two octets of noise
	 *                            past the end; the PHY header says how long the frame really
	 *                            is, so the surplus is simply ignored.
	 *   PKT_TX_THRESHOLD   0x30  unused, this application never transmits
	 */
	static const uint8_t pkt_common[] = {0x00, 0x01, 0x08, 0x01, 0x0F, 0x07,
					     0x83, 0x80, 0x3A, 0x01, 0x04, 0x30};

	/*
	 * Index 0x0C onwards: RX FIFO threshold, then the TX field definitions. The TX fields are
	 * set to mirror the RX ones purely for consistency.
	 */
	static const uint8_t pkt_fields[] = {RX_FIFO_THRESHOLD,
					     0x00,
					     0x02, /* FIELD_1_LENGTH: the 2 octet PHR */
					     0x04, /* FIELD_1_CONFIG: PN_START, no whitening */
					     0xC0, /* FIELD_1_CRC_CONFIG */
					     0x07,
					     0xFF, /* FIELD_2_LENGTH: maximum PSDU */
					     0x00,
					     0x00, /* FIELD_2_CONFIG / CRC_CONFIG */
					     0x00,
					     0x00,
					     0x00};

	/*
	 * Index 0x21 onwards: the RX field definitions that PH_FIELD_SPLIT enables.
	 * Field 1 is the PHY header; field 2 is the PSDU including its FCS.
	 */
	static const uint8_t pkt_rx_fields[] = {0x00, 0x02, 0x04, 0xC0, 0x07, 0xFF, 0x00, 0x00};

	ret = si4467_set_properties(SI4467_PROPERTY_GROUP_PKT, 0x00, pkt_common,
				    sizeof(pkt_common));
	if (ret) {
		return ret;
	}

	ret = si4467_set_properties(SI4467_PROPERTY_GROUP_PKT, 0x0C, pkt_fields,
				    sizeof(pkt_fields));
	if (ret) {
		return ret;
	}

	return si4467_set_properties(SI4467_PROPERTY_GROUP_PKT, 0x21, pkt_rx_fields,
				     sizeof(pkt_rx_fields));
}

/**
 * @brief Point the packet handler at a coded or an uncoded PHY.
 *
 * Everything that differs between the two lives here, and all of it is downstream of the
 * demodulator: which sync word starts a frame, whether the PHY header may be used to size and
 * de-whiten it, and whether the transceiver is allowed to decide a frame has ended. The
 * synthesiser and the modem are not touched, because a coded mode carries the same symbol rate and
 * modulation index as its uncoded counterpart and so is the same signal on the air.
 *
 * Called for every PHY selection rather than once at bring-up, since the choice follows the
 * PhyModeID.
 */
static int si4467_configure_framing(bool fec)
{
	/*
	 * RX field 1 is the two octet PHY header on an uncoded PHY, with field 2 sized from it. On
	 * a coded one there is nothing to split: field 1 is as long as the field length allows,
	 * carries no whitening and no CRC, and a fixed size, since nothing on the air says where a
	 * coded frame ends.
	 */
	static const uint8_t rx_fields_uncoded[] = {0x00, 0x02, 0x04, 0xC0, 0x07, 0xFF, 0x00, 0x00};
	static const uint8_t rx_fields_coded[] = {CODED_CAPTURE_OCTETS >> 8,
						  CODED_CAPTURE_OCTETS & 0xFF,
						  0x00,
						  0x00,
						  0x00,
						  0x00,
						  0x00,
						  0x00};
	const uint8_t sync[] = {fec ? SFD_CODED_FIRST : SFD_UNCODED_FIRST, SFD_SECOND};
	int ret;

	ret = si4467_set_property(PROP_GLOBAL_CONFIG,
				  fec ? GLOBAL_CONFIG_GENERIC : GLOBAL_CONFIG_IE154G);
	if (ret) {
		return ret;
	}

	ret = si4467_set_properties(SI4467_PROPERTY_GROUP_SYNC, 0x01, sync, sizeof(sync));
	if (ret) {
		return ret;
	}

	ret = si4467_set_property(PROP_PKT_LEN, fec ? PKT_LEN_FIXED : PKT_LEN_FROM_PHR);
	if (ret) {
		return ret;
	}

	return si4467_set_properties(SI4467_PROPERTY_GROUP_PKT, 0x21,
				     fec ? rx_fields_coded : rx_fields_uncoded,
				     fec ? sizeof(rx_fields_coded) : sizeof(rx_fields_uncoded));
}

/**
 * @brief Fix up the settings WDS cannot know or got wrong for this application.
 */
static int si4467_apply_overrides(void)
{
	int ret;

	/* Crystal trim is a property of the board, not of the PHY. */
	ret = si4467_set_property(PROP_GLOBAL_XO_TUNE, XTAL_TUNE_VALUE);
	if (ret) {
		return ret;
	}

	/*
	 * Turn on automatic PHY header parsing. Without it the radio has no idea how long a frame
	 * is, which FCS it carries or whether it is whitened.
	 */
	ret = si4467_set_property(PROP_GLOBAL_CONFIG, GLOBAL_CONFIG_IE154G);
	if (ret) {
		return ret;
	}

	ret = si4467_configure_packet_handler();
	if (ret) {
		return ret;
	}

	/* Without this the latched RSSI always reads zero and frames get no signal strength. */
	ret = si4467_set_property(PROP_MODEM_RSSI_CONTROL, MODEM_RSSI_CONTROL_LATCH_SYNC);
	if (ret) {
		return ret;
	}

	ret = si4467_set_property(PROP_PKT_RX_THRESHOLD, RX_FIFO_THRESHOLD);
	if (ret) {
		return ret;
	}

	/*
	 * Enable exactly the interrupts the receive path acts on. Preamble detect is not needed
	 * functionally but makes it possible to tell "the modem hears nothing" apart from "the
	 * modem hears something but the sync word does not match" during bring-up.
	 */
	{
		const uint8_t args[] = {
			SI4467_PROPERTY_GROUP_INT_CTL,
			4,
			0x00,
			0x07, /* INT_CTL_ENABLE: packet handler, modem and chip groups */
			PH_INT_RX_FIFO_ALMOST_FULL | PH_INT_PACKET_RX | PH_INT_CRC_ERROR,
			MODEM_INT_SYNC_DETECT | MODEM_INT_PREAMBLE_DETECT | MODEM_INT_INVALID_SYNC,
			CHIP_INT_CMD_ERROR | CHIP_INT_FIFO_UNDERFLOW_OVERFLOW_ERROR,
		};

		ret = si4467_cmd(COMMAND_SET_PROPERTY, args, sizeof(args), NULL, 0);
		if (ret) {
			return ret;
		}
	}

	return 0;
}

/* ------------------------------------------------------------------------------------------- */
/* PHY programming                                                                              */
/* ------------------------------------------------------------------------------------------- */

/*
 * The WDS configuration applied at start-up describes one PHY: ChanPlanID 32 with PhyModeID 1, so
 * 863.1 MHz, 100 kHz channels, 50 ksym/s and 12.5 kHz deviation. Everything else this application
 * can be told to listen to is reached by recomputing the handful of properties that differ.
 *
 * That is possible because the receive chain is defined almost entirely in units of its own sample
 * rate. The high-speed samples from the A/D converters go through a fixed divide-by-eight, then a
 * polyphase pre-decimator, then two cascaded CIC stages, and what comes out clocks the channel
 * filter, the bit clock recovery loop and the AFC. Halve the total decimation and every one of them
 * runs twice as fast: the filter bandwidth doubles, the oversampling rate per symbol is unchanged,
 * and the same filter coefficients still apply. So a PHY at twice the symbol rate and twice the
 * deviation needs no new coefficients, only half the decimation.
 *
 * This was checked against two independent WDS outputs for this crystal: the one this application
 * ships with (50 ksym/s) and a second one at 100 ksym/s, which is not in this tree. The two differ
 * in exactly the properties computed here, and the values below reproduce both.
 *
 * The argument only holds while the modulation index stays the same, since that is what fixes the
 * deviation as a fraction of the sample rate. wisun_phy.c therefore only offers the modes with a
 * modulation index of 0.5.
 */

/** Crystal the transceiver runs from. Every derivation below is relative to it. */
#define XTAL_HZ DT_PROP(SI4467_NODE, xtal_frequency)

/** Fixed decimation between the A/D converters and the programmable decimators. */
#define ADC_DECIMATION 8

/**
 * The sample rate the WDS configuration runs the channel filter at, and the bandwidth of the wide
 * filter at that rate (both from the header WDS generated). Used to report the bandwidth that
 * results from a different sample rate.
 */
#define WDS_SAMPLE_RATE_HZ  406250
#define WDS_RX_BANDWIDTH_HZ 99200

/**
 * Bounds on the bit clock recovery oversampling rate. The API reference gives 8 to 12 as the usable
 * range; WDS lands on 8.125 whenever the decimators allow it, so that is what is aimed for.
 */
#define OSR_X8_MIN    64
#define OSR_X8_MAX    96
#define OSR_X8_TARGET 65

/** MODEM_CLKGEN_BAND:SY_SEL, the high performance synthesiser prescaler. */
#define MODEM_CLKGEN_SY_SEL BIT(3)

/** MODEM_TX_NCO_MODE:TXOSR enumeration for 20x oversampling, which is what WDS emits. */
#define TX_NCO_OSR_ENUM_20 2
#define TX_NCO_OSR         20

/** @brief Look up the synthesiser output divider for @p freq_hz; datasheet section 5.1. */
static int lookup_synth_band(uint32_t freq_hz, uint8_t *band, uint8_t *outdiv)
{
	static const struct {
		uint32_t lo_hz;
		uint32_t hi_hz;
		uint8_t band;
		uint8_t outdiv;
	} bands[] = {
		{850000000, 1050000000, 0, 4},
		{350000000, 525000000, 2, 8},
		{283000000, 350000000, 3, 12},
		{142000000, 175000000, 5, 24},
	};

	for (size_t i = 0; i < ARRAY_SIZE(bands); i++) {
		if (freq_hz >= bands[i].lo_hz && freq_hz <= bands[i].hi_hz) {
			*band = bands[i].band;
			*outdiv = bands[i].outdiv;
			return 0;
		}
	}

	return -ENOTSUP;
}

/**
 * @brief Program the synthesiser for a channel plan.
 *
 * The PLL is programmed with an integer and a 19 bit fraction of the divided VCO frequency, plus
 * the step one channel is worth, so that START_RX can be given a plain channel number.
 */
static int si4467_program_frequency(const struct si4467_wisun_phy *phy, uint8_t band,
				    uint8_t outdiv)
{
	const uint64_t pll_hz = 2ULL * XTAL_HZ;
	const uint64_t freq0_hz = (uint64_t)phy->center_freq0_khz * 1000;
	const uint64_t spacing_hz = (uint64_t)phy->chan_spacing_khz * 1000;
	uint64_t inte_frac;
	uint32_t step;
	uint8_t inte;
	uint32_t frac;
	uint8_t values[6];
	int ret;

	/*
	 * The published formula is f = (INTE + FRAC / 2^19) * 2 * fxtal / outdiv with FRAC in
	 * [2^19, 2^20), which is why the integer part comes out one lower than the ratio suggests.
	 */
	inte_frac = ((freq0_hz << 19) * outdiv + pll_hz / 2) / pll_hz;
	inte = (uint8_t)((inte_frac >> 19) - 1);
	frac = (uint32_t)(inte_frac - ((uint64_t)inte << 19));

	step = (uint32_t)(((spacing_hz << 19) * outdiv + pll_hz / 2) / pll_hz);
	if (step > UINT16_MAX) {
		LOG_ERR("channel spacing of %u kHz is too large for the synthesiser",
			phy->chan_spacing_khz);
		return -ENOTSUP;
	}

	/*
	 * SY_SEL selects the high performance prescaler. It has to stay set: the formula above is
	 * only valid with a divide-by-two prescaler, so clearing it silently puts the receiver on a
	 * different frequency altogether.
	 */
	ret = si4467_set_property(PROP_MODEM_CLKGEN_BAND, MODEM_CLKGEN_SY_SEL | band);
	if (ret) {
		return ret;
	}

	values[0] = inte;
	values[1] = (uint8_t)(frac >> 16);
	values[2] = (uint8_t)(frac >> 8);
	values[3] = (uint8_t)frac;
	values[4] = (uint8_t)(step >> 8);
	values[5] = (uint8_t)step;

	ret = si4467_set_properties(PROP_FREQ_CONTROL_INTE, values, sizeof(values));
	if (ret) {
		return ret;
	}

	/* Report what the quantised values actually come to rather than what was asked for. */
	ctx.actual.center_freq0_hz =
		(uint32_t)((inte_frac * pll_hz + ((uint64_t)outdiv << 19) / 2) /
			   ((uint64_t)outdiv << 19));
	ctx.actual.chan_spacing_hz =
		(uint32_t)(((uint64_t)step * pll_hz + ((uint64_t)outdiv << 19) / 2) /
			   ((uint64_t)outdiv << 19));

	return 0;
}

/**
 * @brief Choose the decimation that puts the oversampling rate closest to what WDS aims for.
 *
 * The polyphase pre-decimator is tried at two before three and before being bypassed, which is the
 * order WDS picks in; that keeps the same filtering ahead of the CIC stages wherever possible.
 */
static int pick_decimation(uint32_t symbol_rate, uint8_t *dwn, uint8_t *ndec)
{
	/* Divide by two first: it is what WDS uses for every rate that allows it. */
	static const uint8_t dwn_ratios[] = {2, 3, 1};
	uint32_t best_error = UINT32_MAX;
	int ret = -ENOTSUP;

	for (size_t i = 0; i < ARRAY_SIZE(dwn_ratios); i++) {
		for (uint8_t n = 0; n <= 6; n++) {
			const uint32_t decimation = ADC_DECIMATION * dwn_ratios[i] * (1U << n);
			const uint32_t osr_x8 =
				(uint32_t)((8ULL * XTAL_HZ +
					    (uint64_t)decimation * symbol_rate / 2) /
					   ((uint64_t)decimation * symbol_rate));
			uint32_t error;

			if (osr_x8 < OSR_X8_MIN || osr_x8 > OSR_X8_MAX) {
				continue;
			}

			error = (osr_x8 > OSR_X8_TARGET) ? osr_x8 - OSR_X8_TARGET
							 : OSR_X8_TARGET - osr_x8;
			if (error < best_error) {
				best_error = error;
				*dwn = dwn_ratios[i];
				*ndec = n;
				ret = 0;
			}
		}
	}

	return ret;
}

/** @brief Program the modem for a symbol rate and deviation. */
static int si4467_program_modem(const struct si4467_wisun_phy *phy, uint8_t outdiv)
{
	uint8_t dwn, ndec;
	uint32_t decimation, sample_rate, osr_x8, nco_offset, data_rate, freq_dev, tx_nco_mode;
	uint8_t shwait, lgwait;
	uint8_t values[5];
	int ret;

	ret = pick_decimation(phy->symbol_rate, &dwn, &ndec);
	if (ret) {
		LOG_ERR("no decimation gives a usable oversampling rate at %u symbols/s",
			phy->symbol_rate);
		return ret;
	}

	decimation = ADC_DECIMATION * dwn * (1U << ndec);
	sample_rate = (XTAL_HZ + decimation / 2) / decimation;
	osr_x8 = (uint32_t)((8ULL * XTAL_HZ + (uint64_t)decimation * phy->symbol_rate / 2) /
			    ((uint64_t)decimation * phy->symbol_rate));

	/*
	 * The bit clock recovery NCO accumulates this offset once per oversampling tick and emits a
	 * pulse when it overflows, so it holds the symbol rate as a fraction of the sample rate. It
	 * is a 16 bit integer with 6 fractional bits, hence the 2^22.
	 */
	nco_offset = (uint32_t)(((uint64_t)phy->symbol_rate * (1ULL << 22) + sample_rate / 2) /
				sample_rate);

	{
		/*
		 * The decimator ratios are 2^NDEC1 and 2^NDEC2 in cascade; splitting the exponent
		 * across the two fields is what lets the total exceed eight.
		 */
		const uint8_t ndec1 = MIN(ndec, 3);
		const uint8_t ndec2 = ndec - ndec1;

		values[0] = (uint8_t)((ndec2 << 6) | (ndec1 << 4));

		/*
		 * DECIMATION_CFG0 bit 5 bypasses the divide-by-three pre-decimator and bit 4 the
		 * divide-by-two one; exactly one of them must be in circuit unless both are
		 * bypassed. The remaining bits stay at what WDS emitted, which is all zeroes.
		 */
		values[1] = (dwn == 2) ? BIT(5) : (dwn == 3) ? BIT(4) : (BIT(5) | BIT(4));
		values[2] = 0x00; /* DECIMATION_CFG2 */

		ret = si4467_set_properties(PROP_MODEM_DECIMATION_CFG, values, 3);
		if (ret) {
			return ret;
		}
	}

	values[0] = (uint8_t)(osr_x8 >> 8);
	values[1] = (uint8_t)osr_x8;
	values[2] = (uint8_t)(nco_offset >> 16);
	values[3] = (uint8_t)(nco_offset >> 8);
	values[4] = (uint8_t)nco_offset;

	ret = si4467_set_properties(PROP_MODEM_BCR, values, 5);
	if (ret) {
		return ret;
	}

	/*
	 * The AFC settling periods are counted in symbols, so a faster PHY needs more of them to
	 * give the synthesiser the same amount of real time. One step per 50 ksym/s reproduces both
	 * of the WDS configurations this was checked against.
	 */
	shwait = (uint8_t)CLAMP((phy->symbol_rate + 25000) / 50000, 1, 15);
	lgwait = (uint8_t)MIN(shwait + 1, 15);

	ret = si4467_set_property(PROP_MODEM_AFC_WAIT, (uint8_t)((shwait << 4) | lgwait));
	if (ret) {
		return ret;
	}

	/*
	 * The transmit side is never used by this application, but leaving it describing a
	 * different PHY than the receiver would be a trap for anyone reading the properties back.
	 */
	data_rate = phy->symbol_rate * TX_NCO_OSR;
	tx_nco_mode = ((uint32_t)TX_NCO_OSR_ENUM_20 << 26) | XTAL_HZ;
	freq_dev = (uint32_t)(((uint64_t)phy->deviation_hz * (1ULL << 19) * outdiv +
			       (uint64_t)XTAL_HZ) /
			      (2ULL * XTAL_HZ));

	values[0] = (uint8_t)(data_rate >> 16);
	values[1] = (uint8_t)(data_rate >> 8);
	values[2] = (uint8_t)data_rate;

	ret = si4467_set_properties(PROP_MODEM_DATA_RATE, values, 3);
	if (ret) {
		return ret;
	}

	values[0] = (uint8_t)(tx_nco_mode >> 24);
	values[1] = (uint8_t)(tx_nco_mode >> 16);
	values[2] = (uint8_t)(tx_nco_mode >> 8);
	values[3] = (uint8_t)tx_nco_mode;

	ret = si4467_set_properties(PROP_MODEM_TX_NCO_MODE, values, 4);
	if (ret) {
		return ret;
	}

	values[0] = (uint8_t)(freq_dev >> 16);
	values[1] = (uint8_t)(freq_dev >> 8);
	values[2] = (uint8_t)freq_dev;

	ret = si4467_set_properties(PROP_MODEM_FREQ_DEV, values, 3);
	if (ret) {
		return ret;
	}

	ctx.actual.sample_rate_hz = sample_rate;
	ctx.actual.rx_bandwidth_hz =
		(uint32_t)((uint64_t)WDS_RX_BANDWIDTH_HZ * sample_rate / WDS_SAMPLE_RATE_HZ);
	ctx.actual.osr_x8 = (uint16_t)osr_x8;

	return 0;
}

bool si4467_wisun_can_tune(uint32_t freq_khz)
{
	uint8_t band, outdiv;

	return lookup_synth_band(freq_khz * 1000, &band, &outdiv) == 0;
}

int si4467_wisun_set_phy(const struct si4467_wisun_phy *phy)
{
	const uint32_t freq0_hz = phy->center_freq0_khz * 1000;
	uint8_t band, outdiv;
	int ret;

	if (phy->symbol_rate == 0) {
		return -EINVAL;
	}

	ret = lookup_synth_band(freq0_hz, &band, &outdiv);
	if (ret) {
		LOG_ERR("%u kHz is outside the bands the transceiver can tune to",
			phy->center_freq0_khz);
		return ret;
	}

	/*
	 * Whatever is still queued belongs to the PHY being left, and reporting it against the new
	 * one would put a frame in the capture that was never received on it. A frame already being
	 * decoded is not reached by this and still reports; it is one frame, and stopping to wait
	 * for it would hold up the shell command that asked for the change.
	 */
	k_msgq_purge(&coded_jobs);

	/* Properties are only safe to write outside receive mode. */
	ctx.receiving = false;
	ret = si4467_change_state(STATE_READY);
	if (ret) {
		return ret;
	}

	ret = si4467_program_frequency(phy, band, outdiv);
	if (ret) {
		return ret;
	}

	ret = si4467_program_modem(phy, outdiv);
	if (ret) {
		return ret;
	}

	ret = si4467_configure_framing(phy->fec);
	if (ret) {
		return ret;
	}

	ctx.fec = phy->fec;

	/*
	 * A coded frame carries two channel bits for every bit of the frame it is, so it occupies
	 * the air for twice as long and the watchdog has to allow for that. Without it the longest
	 * frames on a coded PHY would be abandoned as timeouts at about the halfway point.
	 */
	ctx.watchdog_ms = RX_WATCHDOG_FACTOR * (WISUN_MAX_PSDU_LEN + sizeof(rx_frame.phr)) * 8 *
			  1000 / phy->symbol_rate * (phy->fec ? 2 : 1);

	/* 80 us at 100 kbit/s, 160 at 50. An octet of a coded frame is an octet on the air. */
	ctx.octet_us = 8 * 1000000 / phy->symbol_rate;

	{
		/* Rounded to kHz: the synthesiser is quantised to about 25 Hz, which is only noise
		 * here.
		 */
		const uint32_t freq0_khz = (ctx.actual.center_freq0_hz + 500) / 1000;

		LOG_INF("PHY: channel 0 at %u.%03u MHz, %u kHz spacing, %u symbols/s, %u Hz "
			"deviation "
			"(sample rate %u Hz, RX bandwidth %u kHz, oversampling %u.%03u)",
			freq0_khz / 1000, freq0_khz % 1000,
			(ctx.actual.chan_spacing_hz + 500) / 1000, phy->symbol_rate,
			phy->deviation_hz, ctx.actual.sample_rate_hz,
			ctx.actual.rx_bandwidth_hz / 1000, ctx.actual.osr_x8 / 8,
			(ctx.actual.osr_x8 % 8) * 125);
	}

	return 0;
}

const struct si4467_wisun_phy_actual *si4467_wisun_get_phy_actual(void)
{
	return &ctx.actual;
}

/* ------------------------------------------------------------------------------------------- */
/* Receive path                                                                                 */
/* ------------------------------------------------------------------------------------------- */

static void nirq_handler(const struct device *port, struct gpio_callback *cb, gpio_port_pins_t pins)
{
	ARG_UNUSED(port);
	ARG_UNUSED(cb);
	ARG_UNUSED(pins);

	k_event_post(&rx_events, EVENT_NIRQ);
}

/**
 * @brief Check whether the PHY header can belong to a Wi-SUN FAN frame.
 *
 * In the octet order the FIFO delivers, bit 7 is the Mode Switch field and bits 6 and 5 are
 * reserved, so all three must be zero (IEEE 802.15.4-2020 figure 19-4, Wi-SUN PHY 2.03 section
 * 6.1.3). A FAN frame therefore always starts with an octet in the range 0x00 to 0x1f.
 */
static bool phr_plausible(const uint8_t phr[2])
{
	const uint16_t len = ((phr[0] & 0x07) << 8) | phr[1];
	const uint8_t fcs_len = (phr[0] & 0x10) ? 2 : 4;

	return (phr[0] & 0xE0) == 0 && len >= fcs_len && len <= WISUN_MAX_PSDU_LEN;
}

/**
 * @brief Verify a frame's FCS.
 *
 * IEEE 802.15.4-2020 section 7.2.10: FCS-32 is the IEEE 802.3 CRC (seeded and inverted with all
 * ones), FCS-16 is ITU-T CRC-16 seeded with zeroes. Both are computed least significant bit first
 * over the MAC frame and transmitted least significant octet first.
 */
static bool check_fcs(const uint8_t *psdu, uint16_t psdu_len, uint8_t fcs_len)
{
	const uint16_t body_len = psdu_len - fcs_len;
	uint32_t crc = (fcs_len == 4) ? 0xFFFFFFFFU : 0U;
	uint32_t received = 0;

	for (uint16_t i = 0; i < body_len; i++) {
		crc ^= psdu[i];

		for (uint8_t bit = 0; bit < 8; bit++) {
			const uint32_t poly = (fcs_len == 4) ? 0xEDB88320U : 0x8408U;

			crc = (crc & 1) ? (crc >> 1) ^ poly : crc >> 1;
		}
	}

	if (fcs_len == 4) {
		crc ^= 0xFFFFFFFFU;
	}

	for (uint8_t i = 0; i < fcs_len; i++) {
		received |= (uint32_t)psdu[body_len + i] << (8 * i);
	}

	return received == crc;
}

/** @brief Parse the two PHY header octets into @ref rx_frame. */
static bool decode_phr(struct wisun_frame *frame)
{
	uint16_t psdu_len;

	/*
	 * IEEE 802.15.4-2020 figure 19-4. With PROTOCOL set to IE154G the packet handler has
	 * already acted on these fields; we decode them again only to describe the frame to
	 * Wireshark.
	 */
	psdu_len = ((frame->phr[0] & 0x07) << 8) | frame->phr[1];
	frame->fcs_len = (frame->phr[0] & 0x10) ? 2 : 4;
	frame->whitened = (frame->phr[0] & 0x08) != 0;

	if (psdu_len < frame->fcs_len || psdu_len > WISUN_MAX_PSDU_LEN) {
		return false;
	}

	frame->psdu_len = psdu_len;

	return true;
}

/**
 * @brief Print everything drained from the FIFO for one reception attempt, as one hex line.
 *
 * Only used in raw mode, where the frame is not interpreted at all. Printing it in a single line
 * makes it straightforward to paste into a decoder on the host, which is what this mode is for:
 * telling a demodulation problem apart from a packet handler misconfiguration.
 */
static void dump_raw(const char *reason, size_t received)
{
	/*
	 * Assembled in one buffer and printed with a single call: the shell redraws its prompt
	 * between printk() calls, which would otherwise slice the line into unusable fragments.
	 */
	static char line[3 * RAW_DUMP_MAX_OCTETS + 1];
	size_t pos = 0;

	received = MIN(received, RAW_DUMP_MAX_OCTETS);

	for (size_t i = 0; i < received; i++) {
		const uint8_t octet = (i < sizeof(rx_frame.phr))
					      ? rx_frame.phr[i]
					      : rx_frame.psdu[i - sizeof(rx_frame.phr)];

		pos += snprintk(&line[pos], sizeof(line) - pos, "%02x", octet);
	}

	line[pos] = '\0';

	printk("RAW %s rssi=%d n=%zu %s\n", reason, rx_frame.rssi_dbm, received, line);
}

/** @brief Restart reception after a frame or an error. */
static void restart_rx(void)
{
	ctx.receiving = false;

	(void)si4467_fifo_info(true, NULL);
	if (si4467_start_rx(ctx.channel)) {
		LOG_ERR("failed to re-enter RX");
	}
}

/** @brief Drain @p count octets out of the RX FIFO into the coded frame being assembled. */
static int collect_coded(size_t *received, size_t count)
{
	while (count > 0) {
		size_t chunk;
		int ret;

		if (*received >= MAX_CODED_LEN) {
			return -EMSGSIZE;
		}

		chunk = MIN(count, MAX_CODED_LEN - *received);

		ret = si4467_read_rx_fifo(&coded_frame[coded_slot][*received], chunk);
		if (ret) {
			return ret;
		}

		*received += chunk;
		count -= chunk;
	}

	return 0;
}

/**
 * @brief Poll the last octets of a coded frame out of the RX FIFO.
 *
 * The end of a coded frame does not arrive on an interrupt. The FIFO raises one when it crosses
 * RX_FIFO_THRESHOLD, and a coded length is almost never a multiple of that, so the remainder sits
 * there until enough of the silence after the frame has been demodulated to push the FIFO over the
 * line again -- up to sixteen octets, which is 1.3 ms of air time at 100 kbit/s.
 *
 * That time is spent deaf, and it is spent in exactly the window a reply arrives in: measured on
 * this network, an acknowledgment's sync detect follows the end of the frame it answers by 2.7 ms,
 * and its own preamble accounts for much of that. It was enough to miss the acknowledgment of
 * every 198 octet frame sent here while catching the shorter ones, which is what a margin this
 * narrow looks like from outside. Polling costs a handful of SPI reads and gives the octets up as
 * soon as they land.
 *
 * The wait is bounded by the air time of what is still outstanding, doubled, so a reception that
 * stops part-way through returns here rather than holding the thread; the watchdog then counts it.
 * That allowance has to come from the symbol rate rather than from a count of polls: sized as a
 * count it was just under the air time of eight octets, so the frames whose coded length left
 * exactly that much outstanding -- the 169 octet half of a ping exchange here -- gave up a moment
 * before their last octets landed and fell back to waiting for the interrupt, which is the whole
 * cost this exists to avoid. Their acknowledgments went missing while shorter frames' arrived.
 */
static void drain_tail(size_t *received, size_t target)
{
	const size_t outstanding = target - *received;
	const k_timepoint_t limit = sys_timepoint_calc(K_USEC(2 * outstanding * ctx.octet_us));

	while (*received < target && !sys_timepoint_expired(limit)) {
		uint8_t available;

		if (si4467_fifo_info(false, &available)) {
			return;
		}

		if (available == 0) {
			k_busy_wait(TAIL_POLL_US);
			continue;
		}

		if (*received + available > target) {
			available = (uint8_t)(target - *received);
		}

		if (collect_coded(received, available)) {
			return;
		}
	}
}

/**
 * @brief Drain @p count octets out of the RX FIFO into the frame being assembled.
 *
 * The first two octets of a frame are the PHY header, which the packet handler leaves in the FIFO
 * because PKT_LEN:IN_FIFO is set.
 */
static int collect(size_t *received, size_t count)
{
	while (count > 0) {
		size_t chunk;
		int ret;

		if (*received < sizeof(rx_frame.phr)) {
			chunk = MIN(count, sizeof(rx_frame.phr) - *received);
			ret = si4467_read_rx_fifo(&rx_frame.phr[*received], chunk);
		} else {
			const size_t offset = *received - sizeof(rx_frame.phr);

			if (offset >= WISUN_MAX_PSDU_LEN) {
				return -EMSGSIZE;
			}

			chunk = MIN(count, WISUN_MAX_PSDU_LEN - offset);
			ret = si4467_read_rx_fifo(&rx_frame.psdu[offset], chunk);
		}

		if (ret) {
			return ret;
		}

		*received += chunk;
		count -= chunk;
	}

	return 0;
}

static void handle_sync_detect(void)
{
	uint8_t latched_rssi = 0;

	ctx.stats.sync_detect++;

	rx_frame.timestamp_us = k_ticks_to_us_floor64(k_uptime_ticks());
	rx_frame.channel = ctx.channel;

	/*
	 * Read the RSSI that was latched at sync detect. Do not clear the modem interrupts here:
	 * they were already collected by GET_INT_STATUS.
	 */
	if (si4467_get_modem_status(false, NULL, &latched_rssi, &rx_frame.afc_offset) == 0) {
		rx_frame.rssi_dbm = rssi_raw_to_dbm(latched_rssi);
	} else {
		rx_frame.rssi_dbm = 0;
	}

	LOG_DBG("sync detect, rssi %d dBm", rx_frame.rssi_dbm);

	ctx.receiving = true;
}

static void rx_thread_fn(void *p1, void *p2, void *p3)
{
	size_t received = 0;
	/** Coded octets this frame will occupy, once its PHY header has said; zero until then. */
	size_t coded_target = 0;
	bool phr_checked = false;
	int64_t rx_deadline = 0;

	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	while (true) {
		uint8_t ph_pend, modem_pend, chip_pend;
		uint32_t events;
		uint8_t available = 0;
		uint8_t complete;

		events = k_event_wait(&rx_events, EVENT_NIRQ | EVENT_STOP, false,
				      ctx.receiving ? K_MSEC(50) : K_FOREVER);
		k_event_clear(&rx_events, events);

		if (events & EVENT_STOP) {
			return;
		}

		/*
		 * The watchdog is consulted on every pass rather than only when the wait timed out.
		 * It used to sit inside the timeout branch, which was enough while the transceiver
		 * only ever interrupted for a frame it was going to finish: a stalled reception
		 * went quiet, the wait expired, and the deadline was read. A coded PHY breaks that.
		 * It streams, so the interrupts never stop, so the wait never expires and the
		 * deadline was never reached -- a reception that went wrong there could run for
		 * ever without being counted.
		 */
		if (ctx.receiving && k_uptime_get() > rx_deadline) {
			if (ctx.raw) {
				dump_raw("timeout", received);
			}

			LOG_WRN("frame did not complete within %u ms "
				"(%zu octets drained, PHR %02x %02x, rssi %d dBm)",
				ctx.watchdog_ms, received, rx_frame.phr[0], rx_frame.phr[1],
				rx_frame.rssi_dbm);
			LOG_HEXDUMP_DBG(rx_frame.psdu, MIN(received, 32), "partial PSDU");
			ctx.stats.timeout++;
			received = 0;
			restart_rx();
			continue;
		}

		if (events == 0) {
			continue;
		}

		if (si4467_get_int_status(&ph_pend, &modem_pend, &chip_pend)) {
			continue;
		}

		LOG_DBG("nIRQ: ph=%02x modem=%02x chip=%02x", ph_pend, modem_pend, chip_pend);

		if (chip_pend & CHIP_INT_CMD_ERROR) {
			LOG_ERR("transceiver reported a command error");
		}

		if (chip_pend & CHIP_INT_FIFO_UNDERFLOW_OVERFLOW_ERROR) {
			LOG_WRN("RX FIFO overflow, frame lost");
			ctx.stats.fifo_error++;
			received = 0;
			restart_rx();
			continue;
		}

		if (modem_pend & MODEM_INT_PREAMBLE_DETECT) {
			ctx.stats.preamble_detect++;
		}

		if (modem_pend & MODEM_INT_SYNC_DETECT) {
			received = 0;
			phr_checked = false;
			coded_target = 0;
			rx_deadline = k_uptime_get() + ctx.watchdog_ms;
			handle_sync_detect();
		}

		/*
		 * A frame ends either with the FCS accepted (PACKET_RX) or rejected (CRC_ERROR).
		 * Both mean the whole frame is in the FIFO and reception has stopped, and both have
		 * to be reported: dropping the damaged ones would hide exactly the frames a sniffer
		 * exists to show.
		 *
		 * ALT_CRC_ERROR is deliberately not one of them. IE154G runs the 16 and 32 bit CRC
		 * engines side by side, so on a frame with a 4 octet FCS the 16 bit engine reaches
		 * its (meaningless) verdict two octets early. Ending the frame there declares a
		 * perfectly good frame corrupt and throws away the PACKET_RX that follows 320 us
		 * later.
		 */
		complete = ph_pend & (PH_INT_PACKET_RX | PH_INT_CRC_ERROR);

		if (ph_pend & (PH_INT_RX_FIFO_ALMOST_FULL | PH_INT_PACKET_RX | PH_INT_CRC_ERROR)) {
			if (si4467_fifo_info(false, &available)) {
				continue;
			}

			/*
			 * A coded frame goes into its own buffer and stops at the length its PHY
			 * header announced -- or, with nothing yet to announce it, at the raw
			 * capture size. Left to run it would fill the buffer and be thrown away as
			 * over-long, which is how a stream nothing ends looks from here.
			 */
			if (ctx.fec) {
				const size_t limit = (coded_target != 0) ? coded_target
						     : (ctx.raw)         ? CODED_CAPTURE_OCTETS
									 : (size_t)MAX_CODED_LEN;

				if (received + available > limit) {
					available = (uint8_t)(limit - received);
				}

				if (collect_coded(&received, available)) {
					LOG_WRN("coded frame exceeded the buffer");
					ctx.stats.bad_length++;
					received = 0;
					restart_rx();
					continue;
				}
			} else if (collect(&received, available)) {
				LOG_WRN("frame exceeded the maximum PSDU length");
				ctx.stats.bad_length++;
				received = 0;
				restart_rx();
				continue;
			}

			/*
			 * The PHY header is the first interleaver block, and it is the one part of
			 * a coded frame that is not whitened, so it decodes straight out of what
			 * has arrived. Its length is what says when to stop; without it there would
			 * be nothing to wait for.
			 */
			if (ctx.fec && coded_target == 0 &&
			    received >= WISUN_FEC_BLOCK_CODED_OCTETS) {
				uint16_t phr;

				if (wisun_fec_decode_phr(coded_frame[coded_slot], &phr) == 0) {
					const uint16_t psdu_len = phr & WISUN_PHR_LENGTH_MASK;

					/*
					 * Asking early is worth it and costs nothing, but it is
					 * only an attempt: the first octets out of the FIFO after a
					 * sync detect do not always start the frame, and a header
					 * read from them decodes to the same wrong value every
					 * time. So a header that is not a frame is not held against
					 * the reception -- collection simply carries on and asks
					 * again with more of it in hand. A reception that never
					 * produces one stops at the capture size below and is
					 * counted there.
					 */
					if ((phr & WISUN_PHR_RESERVED) == 0 &&
					    psdu_len > sizeof(uint32_t) &&
					    psdu_len <= WISUN_MAX_PSDU_LEN) {
						coded_target = wisun_fec_coded_len(psdu_len);
						rx_frame.phr[0] = (uint8_t)(phr >> 8);
						rx_frame.phr[1] = (uint8_t)phr;
					}
				}
			}

			/*
			 * Reject an implausible header as soon as it is complete. Waiting for the
			 * watchdog instead would block reception for the whole frame duration the
			 * corrupt length field implies, which can be several hundred milliseconds.
			 */
			if (!ctx.raw && !ctx.fec && !phr_checked &&
			    received >= sizeof(rx_frame.phr)) {
				phr_checked = true;

				if (!phr_plausible(rx_frame.phr)) {
					LOG_WRN("discarding implausible PHR %02x %02x "
						"(rssi %d dBm, %zu octets drained)",
						rx_frame.phr[0], rx_frame.phr[1], rx_frame.rssi_dbm,
						received);
					LOG_HEXDUMP_WRN(rx_frame.psdu,
							MIN(received - sizeof(rx_frame.phr), 32),
							"octets after the PHR");
					ctx.stats.bad_phr++;
					received = 0;
					restart_rx();
					continue;
				}
			}
		}

		/*
		 * Once the length is known the rest of the frame is a wait for a known number of
		 * octets, and waiting for it on interrupts costs more than the reply that follows
		 * it allows. See drain_tail().
		 */
		if (ctx.fec && ctx.receiving && coded_target != 0 && received < coded_target) {
			drain_tail(&received, coded_target);
		}

		/*
		 * A coded reception ends here, because nothing in the transceiver knows where a
		 * coded frame stops: the length in its PHY header counts the frame before it was
		 * encoded, and the receive field is sized so that the radio never reaches the end
		 * on its own.
		 */
		if (ctx.fec && ctx.receiving && received > 0 &&
		    received >=
			    ((coded_target != 0) ? coded_target : (size_t)CODED_CAPTURE_OCTETS)) {
			const size_t coded_len = coded_target;
			const size_t captured = received;

			ctx.receiving = false;
			(void)si4467_change_state(STATE_READY);

			/*
			 * Listening again before the frame is decoded rather than after it.
			 * Decoding is much the slowest thing here, and an acknowledgment follows
			 * the frame it answers by well under a millisecond, so a receiver that
			 * spends that time decoding is deaf for exactly the window the reply
			 * arrives in. The octets stay put: this thread is the only one that touches
			 * them, so the next frame cannot overwrite them until the decode below has
			 * returned.
			 */
			received = 0;
			coded_target = 0;
			restart_rx();

			if (ctx.raw) {
				LOG_INF("coded capture: %zu octets, rssi %d dBm", captured,
					rx_frame.rssi_dbm);

				/*
				 * In chunks: one hex dump of a whole capture is a single log
				 * message larger than CONFIG_LOG_BUFFER_SIZE, and would be
				 * discarded exactly like the printk line it replaced.
				 */
				for (size_t off = 0; off < captured; off += 256) {
					LOG_HEXDUMP_INF(&coded_frame[coded_slot][off],
							MIN((size_t)256, captured - off), "coded");
				}
			} else if (coded_len == 0) {
				/* Reached the cap without a header to explain it, so there was no
				 * frame here.
				 */
				ctx.stats.bad_phr++;
			} else {
				const struct coded_job job = {
					.timestamp_us = rx_frame.timestamp_us,
					.len = coded_len,
					.phr = sys_get_be16(rx_frame.phr),
					.rssi_dbm = rx_frame.rssi_dbm,
					.afc_offset = rx_frame.afc_offset,
					.slot = coded_slot,
					.channel = rx_frame.channel,
				};

				if (k_msgq_put(&coded_jobs, &job, K_NO_WAIT) != 0) {
					/*
					 * The decoder is still on the one before last. Better a
					 * counted loss here than a reception spent waiting for it.
					 */
					LOG_WRN("dropped a coded frame the decoder had no room "
						"for");
					ctx.stats.bad_length++;
				} else {
					/* The decoder now owns that buffer, so collection moves to
					 * the next.
					 */
					coded_slot = (uint8_t)((coded_slot + 1) % CODED_SLOTS);
				}
			}

			continue;
		}

		if (complete) {
			ctx.receiving = false;

			if (ctx.raw) {
				dump_raw((ph_pend & PH_INT_PACKET_RX) ? "packet" : "crc-error",
					 received);
				received = 0;
				restart_rx();
				continue;
			}

			if (received < sizeof(rx_frame.phr)) {
				LOG_WRN("frame shorter than the PHY header");
				ctx.stats.bad_length++;
			} else if (!decode_phr(&rx_frame)) {
				LOG_WRN("implausible PHY header %02x %02x", rx_frame.phr[0],
					rx_frame.phr[1]);
				ctx.stats.bad_length++;
			} else {
				const size_t psdu_received = received - sizeof(rx_frame.phr);

				if (psdu_received < rx_frame.psdu_len) {
					LOG_WRN("truncated frame: PHR says %u octets, got %zu",
						rx_frame.psdu_len, psdu_received);
					rx_frame.psdu_len = psdu_received;
				}

				rx_frame.fcs_ok = rx_frame.psdu_len > rx_frame.fcs_len &&
						  check_fcs(rx_frame.psdu, rx_frame.psdu_len,
							    rx_frame.fcs_len);

				k_mutex_lock(&report_lock, K_FOREVER);

				ctx.stats.frames++;
				if (!rx_frame.fcs_ok) {
					ctx.stats.fcs_error++;
				}

				if (ctx.rx_cb) {
					ctx.rx_cb(&rx_frame, ctx.rx_cb_user_data);
				}

				k_mutex_unlock(&report_lock);
			}

			received = 0;
			restart_rx();
		}

		/*
		 * nIRQ is level triggered: the transceiver holds it asserted until every pending
		 * interrupt has been read out. If it asserted a new interrupt while we were
		 * servicing this one, there is no fresh edge for the GPIO controller to report, so
		 * check the line and re-arm ourselves.
		 */
		if (gpio_pin_get_dt(&si4467_nirq) == 1) {
			k_event_post(&rx_events, EVENT_NIRQ);
		}
	}
}

/**
 * @brief Turn collected code symbols into frames, off the thread that has to keep listening.
 *
 * Preemptible and below the receive thread, which is cooperative, so a frame arriving always
 * interrupts a decode rather than waiting behind one. That is the whole point of the split: the
 * decode of a long frame takes about eight milliseconds, the receive FIFO holds about five
 * milliseconds of air time, and an acknowledgment arrives inside one.
 */
static void decode_thread_fn(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	while (true) {
		struct coded_job job;
		size_t decoded_len;
		size_t corrections = 0;

		/*
		 * A wait here ends without a job when the queue is purged, which is how a PHY
		 * change discards work queued for the PHY being left (si4467_wisun_set_phy()).
		 * Zephyr keeps one wait queue per message queue for readers and writers alike, so
		 * k_msgq_purge() unpends this thread along with any blocked writer and hands it
		 * -ENOMSG. Taking that for a job reads an uninitialised slot and length off the
		 * stack and descrambles through whatever they point at, which panics the kernel
		 * with nothing left to read: the fault handler clears CFSR before it prints, so the
		 * halt arrives with no fault status behind it.
		 */
		if (k_msgq_get(&coded_jobs, &job, K_FOREVER) != 0) {
			continue;
		}

		/*
		 * The whitening comes off the code symbols first and stops short of the PHY header,
		 * which is not whitened; see si4467_fec.h for the order and why it is not the one
		 * the standard's clause on whitening reads like.
		 */
		wisun_fec_descramble(coded_frame[job.slot], job.len, WISUN_FEC_UNSCRAMBLED_OCTETS);

		if (wisun_fec_decode(coded_frame[job.slot], job.len, decoded_frame,
				     sizeof(decoded_frame), &decoded_len, &corrections)) {
			LOG_WRN("a coded frame of %zu octets would not decode", job.len);
			ctx.stats.bad_length++;
			continue;
		}

		if (corrections > job.len / 4) {
			/*
			 * Far more than a frame needs and far less than noise costs: a real one on
			 * this bench decodes with none at all, while symbols carrying no frame run
			 * to about a quarter of themselves. Something whose header happened to look
			 * like a length lands here rather than being reported as a frame.
			 */
			LOG_WRN("discarding %zu coded octets the decoder disagreed with %zu times "
				"(rssi %d "
				"dBm)",
				job.len, corrections, job.rssi_dbm);
			ctx.stats.bad_phr++;
			continue;
		}

		coded_out.timestamp_us = job.timestamp_us;
		coded_out.rssi_dbm = job.rssi_dbm;
		coded_out.afc_offset = job.afc_offset;
		coded_out.channel = job.channel;
		coded_out.psdu_len = job.phr & WISUN_PHR_LENGTH_MASK;
		coded_out.fcs_len = (job.phr & WISUN_PHR_FCS_TYPE) ? 2 : 4;
		coded_out.whitened = (job.phr & WISUN_PHR_WHITENED) != 0;
		coded_out.phr[0] = (uint8_t)(job.phr >> 8);
		coded_out.phr[1] = (uint8_t)job.phr;

		/* Past the two octets the PHY header occupies, and already plaintext. */
		memcpy(coded_out.psdu, &decoded_frame[sizeof(uint16_t)], coded_out.psdu_len);

		coded_out.fcs_ok = coded_out.psdu_len > coded_out.fcs_len &&
				   check_fcs(coded_out.psdu, coded_out.psdu_len, coded_out.fcs_len);

		k_mutex_lock(&report_lock, K_FOREVER);

		ctx.stats.frames++;
		if (!coded_out.fcs_ok) {
			ctx.stats.fcs_error++;
		}

		if (ctx.rx_cb) {
			ctx.rx_cb(&coded_out, ctx.rx_cb_user_data);
		}

		k_mutex_unlock(&report_lock);
	}
}

static K_THREAD_STACK_DEFINE(rx_thread_stack, 3072);
static struct k_thread rx_thread;
/*
 * As much as the receive thread gets. The decode itself needs very little -- its working set is
 * static -- but this thread goes on to build a TAP header and hand the frame to the capture
 * stream, which is the same call chain the receive thread makes and has to be given the same room
 * for it.
 *
 * Neither figure is measured, and that is the point of the margin: this is a diagnostic tool where
 * an overflow costs a debugging session and the memory costs nothing. An earlier note here blamed
 * a kernel halt on a stack that was too small. It was not -- the halt was a message queue purge
 * waking this thread with no job for it -- and raising the stack never fixed it.
 */
static K_THREAD_STACK_DEFINE(decode_thread_stack, 3072);
static struct k_thread decode_thread;

/* ------------------------------------------------------------------------------------------- */
/* Public API                                                                                   */
/* ------------------------------------------------------------------------------------------- */

int si4467_wisun_init(void)
{
	int ret;

	if (!spi_is_ready_dt(&si4467_spi)) {
		LOG_ERR("SPI bus is not ready");
		return -ENODEV;
	}

	if (!gpio_is_ready_dt(&si4467_sdn) || !gpio_is_ready_dt(&si4467_nirq)) {
		LOG_ERR("transceiver GPIOs are not ready");
		return -ENODEV;
	}

	ret = gpio_pin_configure_dt(&si4467_sdn, GPIO_OUTPUT_ACTIVE);
	if (ret) {
		LOG_ERR("failed to configure SDN: %d", ret);
		return ret;
	}

	ret = gpio_pin_configure_dt(&si4467_nirq, GPIO_INPUT);
	if (ret) {
		LOG_ERR("failed to configure nIRQ: %d", ret);
		return ret;
	}

	ret = si4467_reset();
	if (ret) {
		return ret;
	}

	ret = si4467_apply_patch();
	if (ret) {
		return ret;
	}

	ret = si4467_power_up();
	if (ret) {
		LOG_ERR("POWER_UP failed: %d", ret);
		return ret;
	}

	ret = si4467_apply_radio_config();
	if (ret) {
		return ret;
	}

	/*
	 * After the configuration blob, which carries a GPIO_PIN_CFG of its own that is skipped.
	 * Only a reset or POWER_UP clears this, and neither happens again after bring-up, so the
	 * LEDs keep working across every PHY change.
	 *
	 * Fatal, unlike the LED on the nRF52840 side: this is an SPI command, so it does not fail
	 * because a pin is missing, it fails because the transceiver stopped answering -- in which
	 * case there is nothing to sniff with either.
	 */
	ret = si4467_configure_gpios();
	if (ret) {
		LOG_ERR("failed to configure the transceiver GPIOs: %d", ret);
		return ret;
	}

	ret = si4467_apply_overrides();
	if (ret) {
		return ret;
	}

	gpio_init_callback(&ctx.nirq_cb, nirq_handler, BIT(si4467_nirq.pin));
	ret = gpio_add_callback_dt(&si4467_nirq, &ctx.nirq_cb);
	if (ret) {
		LOG_ERR("failed to register the nIRQ callback: %d", ret);
		return ret;
	}

	ret = gpio_pin_interrupt_configure_dt(&si4467_nirq, GPIO_INT_EDGE_TO_ACTIVE);
	if (ret) {
		LOG_ERR("failed to enable the nIRQ interrupt: %d", ret);
		return ret;
	}

	ctx.channel = CONFIG_WISUN_SNIFFER_DEFAULT_CHANNEL;

	k_thread_create(&rx_thread, rx_thread_stack, K_THREAD_STACK_SIZEOF(rx_thread_stack),
			rx_thread_fn, NULL, NULL, NULL, K_PRIO_COOP(7), 0, K_NO_WAIT);
	k_thread_name_set(&rx_thread, "si4467_rx");

	k_thread_create(&decode_thread, decode_thread_stack,
			K_THREAD_STACK_SIZEOF(decode_thread_stack), decode_thread_fn, NULL, NULL,
			NULL, K_PRIO_PREEMPT(7), 0, K_NO_WAIT);
	k_thread_name_set(&decode_thread, "si4467_fec");

	LOG_INF("transceiver ready");

	return 0;
}

void si4467_wisun_set_rx_callback(si4467_wisun_rx_cb_t cb, void *user_data)
{
	ctx.rx_cb = cb;
	ctx.rx_cb_user_data = user_data;
}

int si4467_wisun_start(uint8_t channel)
{
	int ret;

	ctx.channel = channel;

	ret = si4467_fifo_info(true, NULL);
	if (ret) {
		return ret;
	}

	ret = si4467_start_rx(channel);
	if (ret) {
		LOG_ERR("failed to enter RX on channel %u: %d", channel, ret);
		return ret;
	}

	ctx.running = true;
	LOG_INF("receiving on channel %u", channel);

	return 0;
}

int si4467_wisun_stop(void)
{
	int ret = si4467_change_state(STATE_READY);

	ctx.running = false;
	ctx.receiving = false;

	return ret;
}

int si4467_wisun_set_channel(uint8_t channel)
{
	if (!ctx.running) {
		ctx.channel = channel;
		return 0;
	}

	return si4467_wisun_start(channel);
}

uint8_t si4467_wisun_get_channel(void)
{
	return ctx.channel;
}

int si4467_wisun_get_part_info(struct si4467_wisun_part_info *info)
{
	uint8_t part[8];
	uint8_t func[6];
	int ret;

	ret = si4467_cmd(COMMAND_PART_INFO, NULL, 0, part, sizeof(part));
	if (ret) {
		return ret;
	}

	ret = si4467_cmd(COMMAND_FUNC_INFO, NULL, 0, func, sizeof(func));
	if (ret) {
		return ret;
	}

	info->chiprev = part[0];
	info->part = sys_get_be16(&part[1]);
	info->pbuild = part[3];
	info->id = sys_get_be16(&part[4]);
	info->customer = part[6];
	info->romid = part[7];

	info->rev_ext = func[0];
	info->rev_branch = func[1];
	info->rev_int = func[2];
	info->patch = sys_get_be16(&func[3]);
	info->func = func[5];

	return 0;
}

int si4467_wisun_measure_rssi(uint8_t channel, int16_t *rssi_dbm)
{
	uint8_t curr_rssi = 0;
	int ret;

	ret = si4467_start_rx(channel);
	if (ret) {
		return ret;
	}

	/* Give the AGC time to settle before sampling. */
	k_msleep(2);

	ret = si4467_get_modem_status(false, &curr_rssi, NULL, NULL);
	if (ret) {
		return ret;
	}

	*rssi_dbm = rssi_raw_to_dbm(curr_rssi);

	/* Put the receiver back where it was. */
	if (ctx.running) {
		(void)si4467_start_rx(ctx.channel);
	} else {
		(void)si4467_change_state(STATE_READY);
	}

	return 0;
}

void si4467_wisun_set_raw(bool raw)
{
	ctx.raw = raw;
}

bool si4467_wisun_get_raw(void)
{
	return ctx.raw;
}

const struct si4467_wisun_stats *si4467_wisun_get_stats(void)
{
	return &ctx.stats;
}

void si4467_wisun_reset_stats(void)
{
	/*
	 * The receive thread is the only other writer and each counter is a word it increments on
	 * its own, so the most a reset arriving mid-frame can cost is one increment. Stopping
	 * reception to close that window would lose whole frames to save a count.
	 */
	memset(&ctx.stats, 0, sizeof(ctx.stats));
}

int si4467_wisun_set_property_raw(uint8_t group, uint8_t index, uint8_t value)
{
	return si4467_set_property(group, index, value);
}
