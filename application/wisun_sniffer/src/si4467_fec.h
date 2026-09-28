/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * @file
 *
 * @brief Undoing the forward error correction of a SUN FSK frame, in software.
 *
 * The transceiver has no convolutional decoder -- its datasheet says so outright (section 9.3.6:
 * it can tell the host whether FEC was used, and nothing more) -- so everything a coded frame
 * needs after the demodulator is done here.
 *
 * A transmitter builds a coded frame in this order, established by decoding real traffic rather
 * than from the standard: the PHR and PSDU are convolutionally encoded and interleaved, and the
 * whitening is then applied to the code symbols -- but only to those of the PSDU. The encoded PHY
 * header, which is exactly the first interleaver block, is left alone.
 *
 * Receiving runs that backwards: descramble everything past that first block, deinterleave, Viterbi
 * decode, and what falls out is the PHY header followed by the PSDU with nothing left to undo.
 *
 * This is what IEEE 802.15.4-2020 describes, once its clauses are read in the order they are
 * numbered. 19.3.2 is the *reference modulator*, a transmit-side data flow, and the steps follow
 * it: 19.3.5 the coding, 19.3.6 the interleaving, and only then 19.4 the whitening. 16.2.3, which
 * 19.4 defers to, starts the generator at "the first bit of the PSDU" -- in a coded frame, the
 * PSDU's first code symbol, which is where it is started here.
 *
 * It is worth stating because the opposite order is an easy thing to come away with, and a decoder
 * built that way recovers nothing at all: it hands whitened symbols to the Viterbi decoder, which
 * cannot tell them from noise. The transceiver's own de-whitener has to stay off regardless, since
 * it would run over a different span than the transmitter's did.
 *
 * Nothing here talks to the transceiver, which is what lets it be tested on native_sim.
 */

#ifndef WISUN_SNIFFER_SI4467_FEC_H_
#define WISUN_SNIFFER_SI4467_FEC_H_

#include <stddef.h>
#include <stdint.h>

/**
 * Information bits one interleaver block carries; IEEE 802.15.4-2020 19.3.6.
 *
 * It is 16, which is exactly the width of the PHY header. That is what makes a coded frame
 * receivable at all without buffering the largest one the PHY allows: the first block decodes to
 * the PHR, the PHR gives the PSDU length, and the length says how much more to collect.
 */
#define WISUN_FEC_BLOCK_BITS 16

/** Coded bits one interleaver block occupies on air. The code has rate 1/2, so twice the above. */
#define WISUN_FEC_BLOCK_CODED_BITS (WISUN_FEC_BLOCK_BITS * 2)

/** Coded octets one interleaver block occupies on air. */
#define WISUN_FEC_BLOCK_CODED_OCTETS (WISUN_FEC_BLOCK_CODED_BITS / 8)

/**
 * Coded octets at the head of a frame that carry no whitening: the encoded PHY header.
 *
 * The header occupies the first interleaver block exactly, so the whitening begins on the block
 * boundary after it and the generator starts from its seed there.
 */
#define WISUN_FEC_UNSCRAMBLED_OCTETS WISUN_FEC_BLOCK_CODED_OCTETS

/**
 * Capacity for the longest coded frame, with headroom above it.
 *
 * @ref wisun_fec_coded_len of the largest PSDU -- 2047 octets -- is 4100, so a legal frame never
 * needs more than that and anything longer is not one. The extra is deliberate all the same: this
 * is the bound on a buffer the receive path fills straight from the air, and the cost of carrying
 * a quarter of a kilobyte nobody uses is nothing next to having to be sure the arithmetic above is
 * exact. Over-running it is handled rather than fatal either way -- collection stops at the bound
 * and the reception is counted as over-long.
 *
 * The decoder also keeps one octet of survivor decisions per information bit, so this sizes that
 * array too, and the receive path sizes the buffers it collects into to match.
 */
#define WISUN_FEC_MAX_CODED_OCTETS 4352

/**
 * @brief Undo the PN9 whitening of a coded frame, in place.
 *
 * IEEE 802.15.4-2020 16.2.3. The generator is x^9 + x^5 + 1 seeded with all ones, and the bit it
 * contributes is the feedback term itself rather than a register bit -- which is what makes the
 * sequence open 0000 1111 0111 rather than with the seed. Check any reimplementation against
 * those bits before trusting it.
 *
 * Applied to the code symbols, before anything else: on this PHY the whitening is the last thing
 * the transmitter does, so it is the first thing a receiver undoes.
 *
 * @param data  Octets to descramble, least significant bit of each first.
 * @param len   Length of @p data in octets.
 * @param skip  Octets at the front to leave alone before the generator starts;
 *              @ref WISUN_FEC_UNSCRAMBLED_OCTETS for a frame, zero for the bare sequence.
 */
void wisun_fec_descramble(uint8_t *data, size_t len, size_t skip);

/**
 * @brief How many coded octets a frame occupies on air.
 *
 * Counts the PHR, the PSDU, the three tail bits that return the encoder to the zero state and the
 * padding that rounds the block up to whole interleaver blocks, then doubles it for the code rate.
 * This is what tells the receive path when a coded frame has been collected in full; the length in
 * the PHR describes the frame before it was encoded and is about half of it.
 *
 * @param psdu_len  PSDU length in octets, including the FCS, as the PHR states it.
 *
 * @return Coded length in octets.
 */
size_t wisun_fec_coded_len(uint16_t psdu_len);

/**
 * @brief Decode the PHY header out of the first interleaver block.
 *
 * Enough of a coded frame to learn how long the rest of it is. The convolutional code runs on
 * past the end of the block, so this cannot be a terminated decode; it traces back from the best
 * path instead, which for a code with three memory elements has settled long before the 16 bits
 * are out.
 *
 * The header is the one field a SUN FSK transmitter sends most significant bit first, the rest of
 * the frame going out least significant bit first, so it is returned as a value rather than as
 * octets -- there is no octet order to hand back that would not be a trap.
 *
 * @param coded  First @ref WISUN_FEC_BLOCK_CODED_OCTETS octets of the frame, already descrambled.
 * @param phr    Filled with the decoded PHY header; IEEE 802.15.4-2020 figure 19-4.
 *
 * @return 0 on success, negative errno otherwise.
 */
int wisun_fec_decode_phr(const uint8_t *coded, uint16_t *phr);

/**
 * @brief Decode a complete coded frame.
 *
 * Deinterleaves and Viterbi decodes, leaving the encoded PHY header's two octets followed by the
 * PSDU, which is already plaintext -- the whitening came off the code symbols before this ran.
 * Read the header with @ref wisun_fec_decode_phr rather than from @p out, whose first two octets
 * hold its bits in the opposite order.
 *
 * @param coded        Coded frame as received, @ref wisun_fec_coded_len octets of it.
 * @param coded_len    Length of @p coded in octets.
 * @param out          Filled with the PHR and then the PSDU.
 * @param out_len      Room in @p out, in octets.
 * @param decoded_len  Set to the number of octets written to @p out.
 * @param corrections  Set to the code symbols the decoder had to disagree with, or NULL. On a
 *                     link that is merely short of signal this is small; on one that is not
 *                     carrying a coded frame at all it is about a quarter of the symbols, which
 *                     is the cheapest way to tell a damaged frame from something that was never
 *                     a frame. Both bench links measured here decode at zero.
 *
 * @return 0 on success, -EINVAL if @p coded_len is not a whole number of interleaver blocks,
 *         -ENOSPC if @p out is too small.
 */
int wisun_fec_decode(const uint8_t *coded, size_t coded_len, uint8_t *out, size_t out_len,
		     size_t *decoded_len, size_t *corrections);

#endif /* WISUN_SNIFFER_SI4467_FEC_H_ */
