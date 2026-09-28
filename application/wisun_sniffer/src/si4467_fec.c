/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "si4467_fec.h"

#include <errno.h>
#include <string.h>

/**
 * The code has three memory elements, so the trellis has eight states; IEEE 802.15.4-2020 19.3.5.
 * A state holds the three bits that went in before the current one, most recent first:
 * bit 2 is b(i-1), bit 1 is b(i-2), bit 0 is b(i-3).
 */
#define NUM_STATES 8

/**
 * How far back a survivor is followed before its oldest bit is believed.
 *
 * The usual rule of thumb is five constraint lengths, which is 20 bits here. Thirty-two is the
 * next whole interleaver block above that, which costs nothing and keeps the window aligned with
 * the blocks being fed in.
 */
#define TRACEBACK_DEPTH 32

/** Worse than any reachable path metric, so an unreachable state never wins a comparison. */
#define METRIC_MAX UINT16_MAX

/**
 * @brief One step of the PN9 generator; IEEE 802.15.4-2020 16.2.3.
 *
 * The bit that comes out is the feedback term, not a bit of the register. Getting that wrong
 * still produces a plausible looking pseudo-random sequence, just not this one.
 */
static uint8_t pn9_next(uint16_t *state)
{
	uint8_t out = (uint8_t)((*state ^ (*state >> 5)) & 1);

	*state = (uint16_t)((*state >> 1) | ((uint16_t)out << 8));

	return out;
}

void wisun_fec_descramble(uint8_t *data, size_t len, size_t skip)
{
	uint16_t state = 0x1FF;

	for (size_t i = skip; i < len; i++) {
		uint8_t mask = 0;

		for (uint8_t bit = 0; bit < 8; bit++) {
			mask |= (uint8_t)(pn9_next(&state) << bit);
		}

		data[i] ^= mask;
	}
}

size_t wisun_fec_coded_len(uint16_t psdu_len)
{
	/*
	 * The encoder runs over the PHR and the PSDU together, then three tail bits return it to
	 * the zero state, then padding rounds the result up to whole interleaver blocks. The
	 * standard states the padding as 5 or 13 bits depending on whether the octet count so far
	 * is odd, which is the same as saying tail and padding together occupy one whole octet or
	 * two.
	 */
	size_t octets = (size_t)psdu_len + sizeof(uint16_t);
	size_t info_bits = (octets + ((octets % 2 == 1) ? 1 : 2)) * 8;

	/* Rate 1/2, so twice the bits, and they are counted here in octets. */
	return info_bits / 4;
}

/** @brief Bit @p index of a received stream, which arrives least significant bit of an octet first.
 */
static uint8_t coded_bit(const uint8_t *coded, size_t index)
{
	return (uint8_t)((coded[index / 8] >> (index % 8)) & 1);
}

/**
 * @brief Undo the interleaving of one block, recovering its sixteen code symbols in order.
 *
 * IEEE 802.15.4-2020 19.3.6 permutes whole code symbols rather than single bits, writing
 * q(p)(k) = a(p)(t) with t = 15 - 4*(k mod 4) - floor(k/4). Reading that backwards is all this is:
 * the symbol received k-th belongs at position t.
 *
 * @param coded    Coded frame as received.
 * @param block    Which interleaver block to undo, counting from zero.
 * @param symbols  Filled with the block's symbols in transmission order, two bits each: bit 1 is
 *                 the first of the pair on air, bit 0 the second.
 */
static void deinterleave(const uint8_t *coded, size_t block, uint8_t *symbols)
{
	size_t base = block * WISUN_FEC_BLOCK_CODED_BITS;

	for (size_t k = 0; k < WISUN_FEC_BLOCK_BITS; k++) {
		size_t t = 15 - 4 * (k % 4) - (k / 4);
		uint8_t first = coded_bit(coded, base + 2 * k);
		uint8_t second = coded_bit(coded, base + 2 * k + 1);

		symbols[t] = (uint8_t)((first << 1) | second);
	}
}

/**
 * @brief The pair of bits the encoder emits leaving @p state on input @p input.
 *
 * IEEE 802.15.4-2020 19.3.5, the non-recursive non-systematic code. Both outputs are the
 * complement of a sum, which is easy to drop when reading the figure and produces a decoder that
 * inverts every bit it recovers.
 */
static uint8_t encode_symbol(uint8_t state, uint8_t input)
{
	uint8_t m1 = (uint8_t)((state >> 2) & 1);
	uint8_t m2 = (uint8_t)((state >> 1) & 1);
	uint8_t m3 = (uint8_t)(state & 1);
	uint8_t u1 = (uint8_t)(!(input ^ m2 ^ m3));
	uint8_t u0 = (uint8_t)(!(input ^ m1 ^ m2 ^ m3));

	return (uint8_t)((u1 << 1) | u0);
}

/**
 * Which of a state's two predecessors its survivor came from, one octet per stage: bit @c s is the
 * decision for state @c s.
 *
 * A whole frame's worth, because the traceback then runs once from the end rather than once per
 * bit. Following a survivor 32 stages back for every one of a frame's several thousand bits is
 * what made decoding take tens of milliseconds, which is longer than the gap before the
 * acknowledgment that answers the frame.
 */
static uint8_t decisions[WISUN_FEC_MAX_CODED_OCTETS * 4];

/**
 * @brief Run the trellis over @p blocks of code symbols, filling @ref decisions.
 *
 * @param coded   Coded frame, descrambled.
 * @param blocks  Interleaver blocks to process.
 * @param metric  Set to the cost of the surviving path.
 *
 * @return The state that path ends in.
 */
static uint8_t forward(const uint8_t *coded, size_t blocks, uint16_t *metric)
{
	/*
	 * The two output bits of every branch, worked out once and indexed by state and input.
	 * There are only sixteen, and deriving them per symbol was a measurable part of the cost.
	 */
	uint8_t expected[NUM_STATES * 2];
	uint16_t buffer[2][NUM_STATES];
	uint16_t *cost = buffer[0];
	uint16_t *next = buffer[1];
	uint8_t best = 0;
	size_t stage = 0;

	for (uint8_t s = 0; s < NUM_STATES; s++) {
		expected[s * 2] = encode_symbol(s, 0);
		expected[s * 2 + 1] = encode_symbol(s, 1);

		/*
		 * The encoder starts in the zero state. A penalty rather than an impossible value,
		 * so that the loop below needs no test for one: it is far more than a frame of this
		 * length can accumulate honestly, and small enough that adding to it cannot
		 * overflow.
		 */
		cost[s] = (s == 0) ? 0 : 1000;
	}

	for (size_t block = 0; block < blocks; block++) {
		uint8_t symbols[WISUN_FEC_BLOCK_BITS];

		deinterleave(coded, block, symbols);

		for (size_t i = 0; i < WISUN_FEC_BLOCK_BITS; i++) {
			const uint8_t symbol = symbols[i];
			uint16_t *swap;
			uint8_t decision = 0;

			/*
			 * Add, compare, select, once per state rather than once per branch. Every
			 * state has exactly two predecessors -- they differ only in the bit that is
			 * about to fall out of the register -- so both can be reached without
			 * searching for them, and the decision is which of the two won.
			 */
			for (uint8_t n = 0; n < NUM_STATES; n++) {
				const uint8_t input = (uint8_t)((n >> 2) & 1);
				const uint8_t low = (uint8_t)((n & 0x03) << 1);
				const uint8_t wrong0 =
					(uint8_t)(expected[low * 2 + input] ^ symbol);
				const uint8_t wrong1 =
					(uint8_t)(expected[(low + 1) * 2 + input] ^ symbol);
				const uint16_t from0 =
					(uint16_t)(cost[low] + ((wrong0 >> 1) & 1) + (wrong0 & 1));
				const uint16_t from1 =
					(uint16_t)(cost[low + 1] + ((wrong1 >> 1) & 1) +
						   (wrong1 & 1));

				if (from1 < from0) {
					next[n] = from1;
					decision |= (uint8_t)(1U << n);
				} else {
					next[n] = from0;
				}
			}

			/* Swapped rather than copied: the same sixteen octets, moved by two
			 * pointers.
			 */
			swap = cost;
			cost = next;
			next = swap;

			decisions[stage++] = decision;
		}
	}

	for (uint8_t s = 1; s < NUM_STATES; s++) {
		if (cost[s] < cost[best]) {
			best = s;
		}
	}

	*metric = cost[best];

	return best;
}

/**
 * @brief Walk the survivors back from @p state, writing the bits they were made of.
 *
 * Once, from the end of the frame to the start, which is what the whole of @ref decisions is kept
 * for. @p out is written least significant bit of each octet first and must arrive zeroed.
 *
 * The last few bits are the encoder's tail and padding rather than the frame, and the state the
 * padding left it in is not known, so those are wrong and are meant to be: nothing reads past the
 * PHY header and PSDU.
 */
static void traceback(size_t stages, uint8_t state, uint8_t *out)
{
	for (size_t i = stages; i-- > 0;) {
		/* Bit 2 of a state is the input that moved the encoder into it. */
		out[i / 8] |= (uint8_t)(((state >> 2) & 1) << (i % 8));
		state = (uint8_t)(((state & 0x03) << 1) | ((decisions[i] >> state) & 1));
	}
}

int wisun_fec_decode_phr(const uint8_t *coded, uint16_t *phr)
{
	uint8_t bits[WISUN_FEC_BLOCK_BITS / 8] = {0};
	uint16_t metric;
	uint8_t state;

	/*
	 * The frame runs on past this block, so there is no terminated state to start from and the
	 * best path stands in for one. With three memory elements the survivors have long since
	 * merged, so these are the same sixteen bits the full decode reaches; the header is only
	 * being read early to learn how much more of the frame to collect.
	 */
	state = forward(coded, 1, &metric);
	traceback(WISUN_FEC_BLOCK_BITS, state, bits);

	/* Most significant bit first, which is how the header alone is sent. */
	*phr = 0;

	for (size_t i = 0; i < WISUN_FEC_BLOCK_BITS; i++) {
		*phr = (uint16_t)((*phr << 1) | ((bits[i / 8] >> (i % 8)) & 1));
	}

	return 0;
}

int wisun_fec_decode(const uint8_t *coded, size_t coded_len, uint8_t *out, size_t out_len,
		     size_t *decoded_len, size_t *corrections)
{
	const size_t blocks = coded_len / WISUN_FEC_BLOCK_CODED_OCTETS;
	const size_t stages = blocks * WISUN_FEC_BLOCK_BITS;
	uint16_t metric;
	uint8_t state;

	if (coded_len == 0 || coded_len % WISUN_FEC_BLOCK_CODED_OCTETS != 0) {
		return -EINVAL;
	}

	if (coded_len > WISUN_FEC_MAX_CODED_OCTETS) {
		return -EMSGSIZE;
	}

	if (out_len < stages / 8) {
		return -ENOSPC;
	}

	memset(out, 0, stages / 8);

	state = forward(coded, blocks, &metric);
	traceback(stages, state, out);

	*decoded_len = stages / 8;

	if (corrections != NULL) {
		/* The survivor's metric is the number of received bits the decoder overruled. */
		*corrections = metric;
	}

	return 0;
}
