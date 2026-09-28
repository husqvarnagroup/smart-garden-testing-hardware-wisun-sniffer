/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "pcapng.h"

#include "si4467_wisun.h"

#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/ring_buffer.h>

#include <string.h>

LOG_MODULE_REGISTER(pcapng, LOG_LEVEL_INF);

/*
 * Binary capture data goes here, so it has to be a different UART than the console: the board puts
 * console, logging and shell on cdc_acm_uart0, boards/si4467_dongle_nrf52840.overlay adds
 * cdc_acm_uart1 for capture.
 */
static const struct device *const capture_uart = DEVICE_DT_GET(DT_CHOSEN(zephyr_sniffer_uart));

/* Block types (PCAP-NG specification section 4). */
#define BLOCK_TYPE_SHB 0x0A0D0D0AU
#define BLOCK_TYPE_IDB 0x00000001U
#define BLOCK_TYPE_EPB 0x00000006U

/** Lets a reader work out the byte order the writer used. */
#define BYTE_ORDER_MAGIC 0x1A2B3C4DU

/** DLT_IEEE802_15_4_TAP, the link type this application produces. */
#define LINKTYPE_IEEE802_15_4_TAP 283

/** Longest packet we can produce: the maximum PSDU plus a generous TAP header. */
#define SNAPLEN (WISUN_MAX_PSDU_LEN + 64)

/* Option codes shared by all blocks. */
#define OPT_ENDOFOPT       0
/* Section header block options. */
#define OPT_SHB_HARDWARE   2
#define OPT_SHB_OS         3
#define OPT_SHB_USERAPPL   4
/* Interface description block options. */
#define OPT_IF_NAME        2
#define OPT_IF_DESCRIPTION 3
#define OPT_IF_TSRESOL     9

/** Timestamps are microseconds, so if_tsresol is 10^-6. */
#define IF_TSRESOL_MICROSECONDS 6

/**
 * Enough for the section header and interface description blocks with all their options -- the
 * largest thing built here, since a packet block only buffers its own header -- with room to
 * spare for longer option strings. put_bytes() silently drops anything past this, which would
 * leave a short section header in the stream.
 */
#define BLOCK_BUF_SIZE 512

/**
 * Whether a capture tool has raised DTR on the capture port.
 *
 * This is how a reader announces itself, and the only such signal the port carries. The tools in
 * tools/ take the line low before they raise it, so that the edge below is seen even when the
 * previous capture left it high.
 */
static bool host_attached;

/** Told about both edges of the above; see @ref pcapng_set_attach_callback. */
static pcapng_attach_cb_t attach_cb;

/** Serialises whole blocks: the frame path and the monitor below both write to the stream. */
static K_MUTEX_DEFINE(stream_lock);

/* ------------------------------------------------------------------------------------------- */
/* Output staging                                                                               */
/* ------------------------------------------------------------------------------------------- */

/**
 * Staging buffer between the frame path and the USB stack.
 *
 * The capture UART cannot be written directly without risking a corrupt stream. It has no flow
 * control, so uart_poll_out() discards octets once the CDC ACM ring buffer is full, and a block
 * that is cut short is far worse than a block that never arrives: PCAP-NG has no marker to
 * resynchronise on, so a reader that loses its place reads the following octets as a block header
 * and everything after that is garbage.
 *
 * Buffering here makes the whole block the unit that gets dropped. Space for a complete block is
 * claimed before any of it is written, so a block reaches the stream either intact or not at all.
 */
static uint8_t tx_buf[CONFIG_WISUN_SNIFFER_CAPTURE_BUF_SIZE];
static struct ring_buf tx_ring;

/** Wakes the drain thread when a block has been staged. */
static K_SEM_DEFINE(tx_pending, 0, 1);

/** Frames dropped because the staging buffer was full, reported by "wisun_sniffer stats". */
static uint32_t dropped;

/**
 * @brief Claim space for a whole block, so it is never written in part.
 *
 * Call with stream_lock held, before the first emit() of a block -- once reserved, space cannot
 * disappear again (only the drain thread consumes the buffer), so every emit() that follows is
 * guaranteed to fit.
 *
 * @return true if the block can be written, false if it has to be dropped.
 */
static bool reserve(size_t len)
{
	return ring_buf_space_get(&tx_ring) >= len;
}

static void emit(const uint8_t *data, size_t len)
{
	const uint32_t wrote = ring_buf_put(&tx_ring, data, len);

	__ASSERT(wrote == len, "PCAP-NG block truncated despite reserve()");
	ARG_UNUSED(wrote);

	k_sem_give(&tx_pending);
}

/** How long to wait for the USB transfer in flight to finish before looking again. */
#define TX_BUSY_POLL K_MSEC(1)

/**
 * @brief Move staged octets into the USB stack.
 *
 * Two details of the CDC ACM driver dictate the shape of this loop.
 *
 * It is written with uart_fifo_fill() rather than uart_poll_out(), because that reports how much it
 * accepted instead of discarding the rest, which is what lets the remainder be retried. The UART
 * API expects it to be called from an interrupt handler, but for CDC ACM it is a plain buffered
 * write guarded by irq_lock(), exactly like the driver's own poll_out, so a thread is safe here.
 *
 * It also waits for uart_irq_tx_ready(), which stays at zero for as long as a USB transfer is in
 * flight. That wait is not for free space, and treating it as a measure of free space is what
 * starved an earlier version of this loop. It is an interlock: the driver hands the transfer a
 * pointer into its own ring buffer and then immediately marks that space free, so writing while a
 * transfer is in flight overwrites octets the host has not been sent yet. That corrupts the stream
 * in the worst possible way, splicing part of one block into the middle of another.
 */
static void tx_thread_fn(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	while (true) {
		uint8_t *data;
		uint32_t claimed;
		int space;
		int wrote;

		if (ring_buf_is_empty(&tx_ring)) {
			k_sem_take(&tx_pending, K_FOREVER);
			continue;
		}

		space = uart_irq_tx_ready(capture_uart);
		if (space <= 0) {
			k_sleep(TX_BUSY_POLL);
			continue;
		}

		claimed = ring_buf_get_claim(&tx_ring, &data, (uint32_t)space);
		wrote = uart_fifo_fill(capture_uart, data, (int)claimed);
		ring_buf_get_finish(&tx_ring, wrote > 0 ? (uint32_t)wrote : 0);
	}
}

/*
 * The drain thread only moves octets from the ring buffer to the UART FIFO, so needs little --
 * but gets a kilobyte anyway: nothing here is measured, and a stack overflow in the one thread
 * that keeps the capture stream moving would look like a hung dongle, not a crash.
 */
static K_THREAD_STACK_DEFINE(tx_thread_stack, 1024);
static struct k_thread tx_thread;

/**
 * Serialises a block into a buffer so that its total length, which PCAP-NG stores both before and
 * after the block body, can be filled in once the body is complete.
 */
struct block {
	uint8_t data[BLOCK_BUF_SIZE];
	/** Octets used so far, which may span several blocks built back to back. */
	size_t len;
	/** Where the block currently being built starts. */
	size_t start;
};

static void put_bytes(struct block *b, const void *src, size_t len)
{
	if (len == 0) {
		return;
	}

	if (b->len + len > sizeof(b->data)) {
		/* Only reachable by editing the fixed blocks below, so a build time concern. */
		__ASSERT(false, "PCAP-NG block does not fit in %zu octets", sizeof(b->data));
		return;
	}

	memcpy(&b->data[b->len], src, len);
	b->len += len;
}

static void put_u16(struct block *b, uint16_t value)
{
	uint8_t raw[sizeof(value)];

	sys_put_le16(value, raw);
	put_bytes(b, raw, sizeof(raw));
}

static void put_u32(struct block *b, uint32_t value)
{
	uint8_t raw[sizeof(value)];

	sys_put_le32(value, raw);
	put_bytes(b, raw, sizeof(raw));
}

static void put_u64(struct block *b, uint64_t value)
{
	uint8_t raw[sizeof(value)];

	sys_put_le64(value, raw);
	put_bytes(b, raw, sizeof(raw));
}

/** @brief Pad the block out to the next 32 bit boundary, as every PCAP-NG field must be. */
static void put_padding(struct block *b)
{
	static const uint8_t zeroes[3] = {0};
	const size_t pad = (4 - (b->len % 4)) % 4;

	put_bytes(b, zeroes, pad);
}

static void put_option(struct block *b, uint16_t code, const void *value, uint16_t len)
{
	put_u16(b, code);
	put_u16(b, len);
	put_bytes(b, value, len);
	put_padding(b);
}

static void put_string_option(struct block *b, uint16_t code, const char *value)
{
	put_option(b, code, value, (uint16_t)strlen(value));
}

static void begin_block(struct block *b, uint32_t type)
{
	b->start = b->len;
	put_u32(b, type);
	put_u32(b, 0); /* Block total length, filled in by end_block(). */
}

/**
 * @brief Close a block by writing its total length, which appears both in the header and trailer.
 */
static void end_block(struct block *b)
{
	uint32_t block_len;

	put_option(b, OPT_ENDOFOPT, NULL, 0);
	put_u32(b, 0); /* Placeholder for the trailing copy of the total length. */

	block_len = (uint32_t)(b->len - b->start);
	sys_put_le32(block_len, &b->data[b->start + 4]);
	sys_put_le32(block_len, &b->data[b->len - 4]);
}

bool pcapng_write_section_header(void)
{
	static struct block b;
	bool written;

	k_mutex_lock(&stream_lock, K_FOREVER);

	/* Both blocks are built together so that they reach the stream as one piece or not at all.
	 */
	b.len = 0;

	begin_block(&b, BLOCK_TYPE_SHB);
	put_u32(&b, BYTE_ORDER_MAGIC);
	put_u16(&b, 1); /* Major version */
	put_u16(&b, 0); /* Minor version */
	/*
	 * Section length is unknown: this is a live stream, so how long it turns out to be depends
	 * on when the capture is stopped.
	 */
	put_u64(&b, UINT64_MAX);
	put_string_option(&b, OPT_SHB_HARDWARE, "GARDENA si4467_dongle/nrf52840 with Si4467");
	put_string_option(&b, OPT_SHB_OS, "Zephyr");
	put_string_option(&b, OPT_SHB_USERAPPL, "wisun_sniffer");
	end_block(&b);

	begin_block(&b, BLOCK_TYPE_IDB);
	put_u16(&b, LINKTYPE_IEEE802_15_4_TAP);
	put_u16(&b, 0); /* Reserved */
	put_u32(&b, SNAPLEN);
	put_string_option(&b, OPT_IF_NAME, "wisun0");
	put_string_option(&b, OPT_IF_DESCRIPTION, "Wi-SUN FAN EU ChanPlanID 32 PhyModeID 1");
	put_option(&b, OPT_IF_TSRESOL, &(uint8_t){IF_TSRESOL_MICROSECONDS}, 1);
	end_block(&b);

	/*
	 * Both blocks are reserved as one piece as well: an interface description that arrives
	 * without its section header, or the other way round, leaves a reader unable to decode
	 * anything.
	 */
	written = reserve(b.len);
	if (written) {
		emit(b.data, b.len);
	}

	k_mutex_unlock(&stream_lock);

	return written;
}

void pcapng_write_packet(uint64_t timestamp_us, const uint8_t *header, size_t header_len,
			 const uint8_t *payload, size_t payload_len)
{
	static const uint8_t zeroes[3] = {0};
	const size_t packet_len = header_len + payload_len;
	const size_t padding = (4 - (packet_len % 4)) % 4;
	/* Block header and trailer: type, length, interface, timestamp, two lengths, length again.
	 */
	const uint32_t block_len = 32 + (uint32_t)(packet_len + padding);
	struct block b;

	k_mutex_lock(&stream_lock, K_FOREVER);

	/*
	 * Drop the whole frame if it does not fit. A capture that is missing a frame still decodes;
	 * one containing half a block does not, and cannot be recovered from either.
	 */
	if (!reserve(block_len)) {
		dropped++;
		k_mutex_unlock(&stream_lock);
		return;
	}

	b.len = 0;
	begin_block(&b, BLOCK_TYPE_EPB);
	put_u32(&b, 0);                              /* Interface ID, the only interface */
	put_u32(&b, (uint32_t)(timestamp_us >> 32)); /* Timestamp, high half */
	put_u32(&b, (uint32_t)timestamp_us);         /* Timestamp, low half */
	put_u32(&b, (uint32_t)packet_len);           /* Captured length, we never truncate */
	put_u32(&b, (uint32_t)packet_len);           /* Original length */
	sys_put_le32(block_len, &b.data[4]);

	emit(b.data, b.len);
	emit(header, header_len);
	emit(payload, payload_len);
	emit(zeroes, padding);

	/* The trailing copy of the block total length. */
	b.len = 0;
	put_u32(&b, block_len);
	emit(b.data, b.len);

	k_mutex_unlock(&stream_lock);
}

/* ------------------------------------------------------------------------------------------- */
/* Host attach detection                                                                        */
/* ------------------------------------------------------------------------------------------- */

/**
 * How often the capture port is checked -- imperceptible against a person pressing a button, and
 * also how long a reader must hold DTR low for the following edge to register, which is why
 * tools/wisun_sniffer_capture.py holds it low for twice as long.
 */
#define MONITOR_INTERVAL K_MSEC(250)

static void monitor(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(monitor_work, monitor);

/**
 * @brief Start a section whenever a capture tool attaches.
 *
 * A reader has to see a section header and an interface description before it will accept any
 * packet, and it looks for them once, when it opens the stream. Writing them on the rising edge of
 * DTR is what puts them there in time; the tools in tools/ raise it as their last step before they
 * start reading, and discard whatever precedes the header.
 */
static void monitor(struct k_work *work)
{
	uint32_t dtr = 0;
	bool attached = false;

	ARG_UNUSED(work);

	if (uart_line_ctrl_get(capture_uart, UART_LINE_CTRL_DTR, &dtr) == 0) {
		attached = dtr != 0;
	}

	if (attached != host_attached) {
		if (attached) {
			LOG_INF("capture tool attached, starting a new PCAP-NG section");

			if (!pcapng_write_section_header()) {
				LOG_WRN("no room for the section header; the reader will see "
					"nothing it can decode");
			}
		}

		/* Before the callback, so that it and pcapng_host_attached() cannot disagree. */
		host_attached = attached;

		if (attach_cb != NULL) {
			attach_cb(attached);
		}
	}

	k_work_reschedule(&monitor_work, MONITOR_INTERVAL);
}

void pcapng_set_attach_callback(pcapng_attach_cb_t cb)
{
	attach_cb = cb;
}

bool pcapng_host_attached(void)
{
	/*
	 * Read without the lock. It is a single word written by the monitor work item and read by
	 * the receive thread, and the answer is one poll interval stale in any case, so a lock
	 * would buy nothing but the illusion of precision.
	 */
	return host_attached;
}

uint32_t pcapng_get_dropped(void)
{
	return dropped;
}

void pcapng_reset_dropped(void)
{
	/*
	 * Under the lock the counter is incremented with, so a frame being dropped right now counts
	 * against the old total or against the new one, and cannot fall between them.
	 */
	k_mutex_lock(&stream_lock, K_FOREVER);
	dropped = 0;
	k_mutex_unlock(&stream_lock);
}

int pcapng_init(void)
{
	if (!device_is_ready(capture_uart)) {
		LOG_ERR("capture UART %s is not ready", capture_uart->name);
		return -ENODEV;
	}

	ring_buf_init(&tx_ring, sizeof(tx_buf), tx_buf);

	/*
	 * No callback is registered: this only makes the driver report its transmit ready state
	 * through uart_irq_tx_ready(), which the drain thread waits on. See tx_thread_fn().
	 */
	uart_irq_tx_enable(capture_uart);

	/*
	 * Preemptible, and so below the cooperative receive thread: draining the buffer must never
	 * delay servicing the transceiver, which has only a 64 octet FIFO to fall back on.
	 */
	k_thread_create(&tx_thread, tx_thread_stack, K_THREAD_STACK_SIZEOF(tx_thread_stack),
			tx_thread_fn, NULL, NULL, NULL, K_PRIO_PREEMPT(7), 0, K_NO_WAIT);
	k_thread_name_set(&tx_thread, "pcapng_tx");

	k_work_reschedule(&monitor_work, MONITOR_INTERVAL);

	return 0;
}
