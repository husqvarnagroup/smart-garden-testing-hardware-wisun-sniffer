/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * @file
 *
 * @brief PCAP-NG capture stream, written to the capture UART.
 *
 * Produces a live PCAP-NG stream that Wireshark can read straight from a pipe, using link type
 * 283 (DLT_IEEE802_15_4_TAP). The stream is a section header block and an interface description
 * block followed by one enhanced packet block per frame. Every block is little-endian and padded
 * to a 32 bit boundary.
 */

#ifndef WISUN_SNIFFER_PCAPNG_H_
#define WISUN_SNIFFER_PCAPNG_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Claim the capture UART and start watching for a capture tool attaching to it.
 *
 * @return 0 on success, negative errno otherwise.
 */
int pcapng_init(void);

/**
 * @brief Emit the section header and interface description blocks.
 *
 * Called automatically whenever a capture tool opens the capture port, so that a host attaching
 * long after boot sees a well-formed section rather than a packet block out of nowhere. A reader
 * that cannot raise DTR can ask for one from the shell instead.
 *
 * @return true if both blocks reached the stream, false if the staging buffer had no room for
 *         them, which means nothing is draining the capture port.
 */
bool pcapng_write_section_header(void);

/**
 * @brief Emit one enhanced packet block.
 *
 * The packet data is written from two pieces so that the frame does not have to be copied into a
 * contiguous buffer first.
 *
 * @param timestamp_us Capture time, in microseconds since boot.
 * @param header IEEE 802.15.4 TAP header and its TLVs.
 * @param header_len Length of @p header, in bytes.
 * @param payload PHY payload, following the TAP header.
 * @param payload_len Length of @p payload, in bytes.
 */
void pcapng_write_packet(uint64_t timestamp_us, const uint8_t *header, size_t header_len,
			 const uint8_t *payload, size_t payload_len);

/**
 * @brief Whether a capture tool is reading the capture port.
 *
 * True from the moment DTR is seen up until it goes down again. Polled, so it can be up to one
 * poll interval out of date, which is why nothing that must be exact should rest on it.
 */
bool pcapng_host_attached(void);

/**
 * @brief Called when a capture tool attaches to the capture port, or lets go of it.
 *
 * Runs on the system work queue, from the same poll that decides to start a new section, and only
 * when the answer changes. @ref pcapng_host_attached already reports @p attached by the time this
 * is called.
 *
 * @param attached true when a reader has just raised DTR, false when it has dropped it.
 */
typedef void (*pcapng_attach_cb_t)(bool attached);

/**
 * @brief Register a function to be told when a capture tool comes and goes.
 *
 * Keeps whatever the dongle does about it -- lighting an LED, quietening the console -- out of the
 * stream writer, which has no business knowing about either.
 *
 * @param cb Called on each change, or NULL to stop being called.
 */
void pcapng_set_attach_callback(pcapng_attach_cb_t cb);

/**
 * @brief Number of frames left out of the stream because the capture host was not keeping up.
 *
 * A frame is dropped whole rather than written in part, so the stream stays decodable; this counter
 * is the only way to tell that anything is missing from it.
 */
uint32_t pcapng_get_dropped(void);

/**
 * @brief Zero the dropped frame counter.
 *
 * Belongs with the receive counters in si4467_wisun.h: the two are read together and only mean
 * anything from the same starting point.
 */
void pcapng_reset_dropped(void);

#endif /* WISUN_SNIFFER_PCAPNG_H_ */
