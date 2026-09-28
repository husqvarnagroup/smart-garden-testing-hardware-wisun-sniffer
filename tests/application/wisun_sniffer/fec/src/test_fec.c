/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 GARDENA GmbH
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * @file
 *
 * @brief Tests for the software side of SUN FSK forward error correction.
 *
 * The standard prints no worked example of a coded frame, so most of what is below is checked by
 * encoding against the same clauses the decoder was written from and requiring the pair to agree.
 * That would catch nothing on its own if both sides shared a misreading, so the two pieces the
 * standard does state outright are checked against it directly: the thirty PN9 bits of 16.2.3, and
 * the requirement that the code correct errors rather than merely carry bits through.
 *
 * @ref reference_encode is deliberately a separate implementation from si4467_fec.c rather than a
 * shared helper -- a round trip through one body of code proves only that it is self-consistent.
 */

#include "si4467_fec.h"

#include <zephyr/sys/byteorder.h>
#include <zephyr/ztest.h>

#include <string.h>

/** Longest PSDU these tests build a frame around. */
#define TEST_MAX_PSDU 40

/** Room for the coded form of the largest frame here, comfortably over @ref wisun_fec_coded_len. */
#define TEST_CODED_MAX 256

/** @brief The pair of bits the encoder emits; IEEE 802.15.4-2020 19.3.5. */
static uint8_t reference_symbol(uint8_t state, uint8_t input)
{
	uint8_t m1 = (state >> 2) & 1;
	uint8_t m2 = (state >> 1) & 1;
	uint8_t m3 = state & 1;

	return (uint8_t)(((!(input ^ m2 ^ m3)) << 1) | (!(input ^ m1 ^ m2 ^ m3)));
}

/**
 * @brief Build the coded form of @p info, the way a transmitter would.
 *
 * Encodes the PHR and PSDU as one block, appends the three tail bits and the padding, interleaves
 * each block of sixteen code symbols, and writes the result least significant bit of each octet
 * first.
 *
 * @return Length of @p out in octets.
 */
static size_t reference_encode(const uint8_t *info, size_t info_len, uint8_t *out)
{
	/* 19.3.5: five bits of padding after an odd octet count, thirteen after an even one. */
	size_t pad = (info_len % 2 == 1) ? 5 : 13;
	size_t num_bits = info_len * 8 + 3 + pad;
	size_t blocks = num_bits / WISUN_FEC_BLOCK_BITS;
	uint8_t symbols[(TEST_MAX_PSDU + 4) * 8 + 16];
	uint8_t state = 0;
	size_t bit = 0;

	zassert_true(num_bits <= ARRAY_SIZE(symbols), "test buffer too small");

	for (size_t i = 0; i < num_bits; i++) {
		/* Everything past the PHR and PSDU is tail and padding, which are zero here. */
		uint8_t b = (i < info_len * 8) ? ((info[i / 8] >> (i % 8)) & 1) : 0;

		symbols[i] = reference_symbol(state, b);
		state = (uint8_t)((b << 2) | ((state >> 1) & 0x03));
	}

	memset(out, 0, blocks * WISUN_FEC_BLOCK_CODED_OCTETS);

	for (size_t p = 0; p < blocks; p++) {
		for (size_t k = 0; k < WISUN_FEC_BLOCK_BITS; k++) {
			/* 19.3.6: the symbol sent k-th is the one at t in the block. */
			size_t t = 15 - 4 * (k % 4) - (k / 4);
			uint8_t symbol = symbols[p * WISUN_FEC_BLOCK_BITS + t];

			out[bit / 8] |= (uint8_t)(((symbol >> 1) & 1) << (bit % 8));
			bit++;
			out[bit / 8] |= (uint8_t)((symbol & 1) << (bit % 8));
			bit++;
		}
	}

	return blocks * WISUN_FEC_BLOCK_CODED_OCTETS;
}

/** @brief Fill @p info with something that is not symmetric under any of the transforms here. */
static void fill_info(uint8_t *info, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		info[i] = (uint8_t)(i * 53 + 3);
	}
}

/**
 * @brief Whether @p psdu ends in a correct 4 octet FCS.
 *
 * IEEE 802.15.4's FCS-32 is the ordinary Ethernet CRC-32 -- reflected, seeded and inverted with
 * all ones -- sent least significant octet first. Written out here rather than shared with the
 * driver so that a frame taken off the air is checked against the standard rather than against
 * this application's opinion of it.
 */
static bool check_fcs(const uint8_t *psdu, uint16_t len)
{
	uint32_t crc = 0xFFFFFFFFu;
	uint32_t want;

	for (size_t i = 0; i + sizeof(uint32_t) < len; i++) {
		crc ^= psdu[i];

		for (int bit = 0; bit < 8; bit++) {
			crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(crc & 1)));
		}
	}

	crc = ~crc;
	want = sys_get_le32(&psdu[len - sizeof(uint32_t)]);

	return crc == want;
}

/** @brief Find @p needle in @p hay, or NULL. */
static const uint8_t *memmem_bytes(const uint8_t *hay, size_t hay_len, const uint8_t *needle,
				   size_t needle_len)
{
	if (needle_len > hay_len) {
		return NULL;
	}

	for (size_t i = 0; i + needle_len <= hay_len; i++) {
		if (memcmp(&hay[i], needle, needle_len) == 0) {
			return &hay[i];
		}
	}

	return NULL;
}

ZTEST_SUITE(wisun_fec, NULL, NULL, NULL, NULL, NULL);

/**
 * The one place the standard prints the sequence itself, so the one check that can fail when the
 * generator is subtly wrong. De-whitening an all-zero buffer leaves the sequence behind.
 */
ZTEST(wisun_fec, test_pn9_matches_the_standard)
{
	static const char *expected = "000011110111000010110011011011";
	uint8_t buf[4] = {0};

	wisun_fec_descramble(buf, sizeof(buf), 0);

	for (size_t n = 0; n < strlen(expected); n++) {
		uint8_t got = (buf[n / 8] >> (n % 8)) & 1;

		zassert_equal(got, expected[n] - '0', "PN9 bit %zu is %u, the standard prints %c",
			      n, got, expected[n]);
	}
}

ZTEST(wisun_fec, test_pn9_undoes_itself)
{
	uint8_t data[24];
	uint8_t original[24];

	fill_info(data, sizeof(data));
	memcpy(original, data, sizeof(original));

	wisun_fec_descramble(data, sizeof(data), 0);
	zassert_true(memcmp(data, original, sizeof(data)) != 0, "whitening changed nothing");

	wisun_fec_descramble(data, sizeof(data), 0);
	zassert_mem_equal(data, original, sizeof(data), "whitening twice did not restore the data");
}

/**
 * The coded length is what tells the receive path when a frame has arrived in full, and it cannot
 * be read off the PHR -- the length there describes the frame before it was encoded.
 */
ZTEST(wisun_fec, test_coded_length_matches_an_encoded_frame)
{
	for (uint16_t psdu_len = 1; psdu_len <= TEST_MAX_PSDU; psdu_len++) {
		uint8_t info[TEST_MAX_PSDU + 2];
		uint8_t coded[TEST_CODED_MAX];
		size_t info_len = psdu_len + 2;

		fill_info(info, info_len);

		zassert_equal(
			wisun_fec_coded_len(psdu_len), reference_encode(info, info_len, coded),
			"coded length disagrees with an encoded frame at PSDU length %u", psdu_len);
	}
}

ZTEST(wisun_fec, test_decodes_an_undamaged_frame)
{
	for (uint16_t psdu_len = 1; psdu_len <= TEST_MAX_PSDU; psdu_len++) {
		uint8_t info[TEST_MAX_PSDU + 2];
		uint8_t coded[TEST_CODED_MAX];
		uint8_t out[TEST_CODED_MAX];
		size_t info_len = psdu_len + 2;
		size_t coded_len;
		size_t decoded_len;

		fill_info(info, info_len);
		coded_len = reference_encode(info, info_len, coded);

		zassert_ok(wisun_fec_decode(coded, coded_len, out, sizeof(out), &decoded_len, NULL),
			   "decode refused a well formed frame at PSDU length %u", psdu_len);
		zassert_true(decoded_len >= info_len, "decode returned only %zu octets",
			     decoded_len);
		zassert_mem_equal(out, info, info_len,
				  "frame did not survive a round trip at PSDU length %u", psdu_len);
	}
}

/**
 * Reading the PHY header out of the first block is what makes a coded frame receivable without
 * buffering the largest one the PHY allows, so it has to agree with the full decode.
 */
ZTEST(wisun_fec, test_decodes_the_phr_from_the_first_block)
{
	for (uint16_t psdu_len = 1; psdu_len <= TEST_MAX_PSDU; psdu_len++) {
		uint8_t info[TEST_MAX_PSDU + 2];
		uint8_t coded[TEST_CODED_MAX];
		size_t info_len = psdu_len + 2;
		uint16_t expected = 0;
		uint16_t phr;

		fill_info(info, info_len);
		reference_encode(info, info_len, coded);

		/* The header is the one field sent most significant bit first; see si4467_fec.h. */
		for (size_t i = 0; i < WISUN_FEC_BLOCK_BITS; i++) {
			expected = (uint16_t)((expected << 1) | ((info[i / 8] >> (i % 8)) & 1));
		}

		zassert_ok(wisun_fec_decode_phr(coded, &phr), "PHR decode failed at PSDU length %u",
			   psdu_len);
		zassert_equal(phr, expected,
			      "PHR from the first block is %04x, expected %04x at PSDU "
			      "length %u",
			      phr, expected, psdu_len);
	}
}

/**
 * The point of the code. A decoder that merely undid the encoding would pass every test above and
 * fail this one, which is the difference between carrying the bits and correcting them.
 */
ZTEST(wisun_fec, test_corrects_any_single_bit_error)
{
	uint8_t info[22];
	uint8_t coded[TEST_CODED_MAX];
	size_t coded_len;

	fill_info(info, sizeof(info));
	coded_len = reference_encode(info, sizeof(info), coded);

	for (size_t bit = 0; bit < coded_len * 8; bit++) {
		uint8_t damaged[TEST_CODED_MAX];
		uint8_t out[TEST_CODED_MAX];
		size_t decoded_len;

		memcpy(damaged, coded, coded_len);
		damaged[bit / 8] ^= (uint8_t)(1U << (bit % 8));

		zassert_ok(
			wisun_fec_decode(damaged, coded_len, out, sizeof(out), &decoded_len, NULL),
			"decode refused a frame with bit %zu flipped", bit);
		zassert_mem_equal(out, info, sizeof(info), "bit %zu flipped was not corrected",
				  bit);
	}
}

/** Two errors far enough apart that the decoder recovers between them. */
ZTEST(wisun_fec, test_corrects_separated_double_bit_errors)
{
	uint8_t info[22];
	uint8_t coded[TEST_CODED_MAX];
	size_t coded_len;

	fill_info(info, sizeof(info));
	coded_len = reference_encode(info, sizeof(info), coded);

	for (size_t first = 0; first + 40 < coded_len * 8; first += 17) {
		uint8_t damaged[TEST_CODED_MAX];
		uint8_t out[TEST_CODED_MAX];
		size_t second = first + 40;
		size_t decoded_len;

		memcpy(damaged, coded, coded_len);
		damaged[first / 8] ^= (uint8_t)(1U << (first % 8));
		damaged[second / 8] ^= (uint8_t)(1U << (second % 8));

		zassert_ok(
			wisun_fec_decode(damaged, coded_len, out, sizeof(out), &decoded_len, NULL),
			"decode refused a frame with bits %zu and %zu flipped", first, second);
		zassert_mem_equal(out, info, sizeof(info), "bits %zu and %zu were not corrected",
				  first, second);
	}
}

ZTEST(wisun_fec, test_refuses_a_length_that_is_not_whole_blocks)
{
	uint8_t coded[TEST_CODED_MAX] = {0};
	uint8_t out[TEST_CODED_MAX];
	size_t decoded_len;

	zassert_equal(wisun_fec_decode(coded, 0, out, sizeof(out), &decoded_len, NULL), -EINVAL,
		      "an empty frame was accepted");
	zassert_equal(wisun_fec_decode(coded, WISUN_FEC_BLOCK_CODED_OCTETS + 1, out, sizeof(out),
				       &decoded_len, NULL),
		      -EINVAL, "a partial interleaver block was accepted");
}

ZTEST(wisun_fec, test_refuses_an_output_buffer_that_is_too_small)
{
	uint8_t coded[TEST_CODED_MAX] = {0};
	uint8_t out[1];
	size_t decoded_len;

	zassert_equal(wisun_fec_decode(coded, sizeof(coded), out, sizeof(out), &decoded_len, NULL),
		      -ENOSPC, "decode wrote into a buffer it had been told was too small");
}

/**
 * A frame taken off the air, which is the only test here that knows what a real transmitter does
 * rather than what this file's own encoder does. It is what established the order the chain runs
 * in: the whitening covers the code symbols and comes off first, and what the decoder then
 * produces needs no further de-whitening.
 *
 * Captured at -55 dBm on EU ChanPlanID 33, PhyModeID 0x13, channel 0. Its FCS is the proof: a
 * wrong deinterleaver, trellis, phase or bit order does not produce a frame whose CRC-32 checks.
 */
ZTEST(wisun_fec, test_decodes_a_captured_frame)
{
	static const uint8_t captured[] = {
		0xc1, 0xc1, 0xd6, 0xc0, 0x15, 0x17, 0x71, 0xeb, 0xdd, 0x96, 0x21, 0x36, 0xc2, 0x16,
		0xe3, 0x47, 0x34, 0xd4, 0xfa, 0x55, 0x41, 0xe9, 0x13, 0x49, 0xf5, 0x9e, 0xc0, 0x50,
		0xa6, 0x35, 0xdb, 0x91, 0x70, 0x0f, 0x26, 0xf2, 0x0f, 0xff, 0x08, 0xf6, 0xa1, 0xdb,
		0x05, 0x84, 0xa1, 0x79, 0x80, 0x3d, 0xd8, 0x73, 0xef, 0xdf, 0xd5, 0x15, 0x22, 0xe0,
		0xc7, 0x01, 0x86, 0xcd, 0x17, 0x98, 0xcb, 0x56, 0x73, 0x19, 0x39, 0x8e, 0x87, 0x78,
		0x99, 0x44, 0x1a, 0xf9, 0x73, 0x48, 0xea, 0xbd, 0x7c, 0x32, 0xa1, 0xb1, 0x88, 0x39,
		0xe1, 0xb2, 0x7c, 0xa8, 0xb5, 0xf4, 0x31, 0x3b, 0xe4, 0x98, 0x16, 0x74, 0xa5, 0x21,
		0xf7, 0x91, 0x9e, 0x83, 0x29, 0x2c, 0x98, 0x84, 0x21, 0xf9, 0xc8, 0xb3, 0x7a, 0x1c,
		0x78, 0x33, 0xfb, 0x8b, 0x46, 0xbe, 0x95, 0xc5, 0x5d, 0x77, 0xab, 0x54, 0x77, 0xd1,
		0x81, 0xa9, 0x7b, 0xaf, 0x1e, 0x86, 0xe0, 0x18, 0xe4, 0x7d, 0xe1, 0x7f, 0x73, 0x33,
		0xc8, 0x5c, 0x1b, 0xa7, 0xcf, 0x21, 0xfd, 0xc0, 0xeb, 0xb1, 0x61, 0x8d, 0x0f, 0xac,
		0x48, 0x13, 0xfa, 0x29, 0x2b, 0xae, 0x84, 0x8e, 0x17, 0x30, 0x8b, 0xe7, 0xb0, 0x18,
		0x19, 0x9f, 0x8f, 0xef, 0x5e, 0x4d, 0x3e, 0xc9, 0xe7, 0x3e, 0xe3, 0x01, 0x5c, 0xde,
		0x23, 0xd4, 0x91, 0xaa, 0xf3, 0x81, 0x7a, 0x3e, 0xdb, 0x5f, 0x54, 0x61, 0x12, 0xcd,
		0x58, 0x71, 0x30, 0x0b, 0x45, 0x1d, 0xdb, 0x58, 0x6f, 0xa2, 0x02, 0xb2, 0xe1, 0x8e,
		0xac, 0x0a, 0x81, 0xce, 0x01, 0xbe, 0x4e, 0x85, 0xe8, 0xe5, 0xa7, 0x93, 0xaf, 0x7f,
		0xff, 0xfb, 0x6a, 0xf7, 0x09, 0xff, 0x2e, 0x97, 0xf8, 0xb2, 0xf5, 0x3f, 0xf4, 0x24,
		0x7f, 0x6c, 0xd1, 0xbb, 0xec, 0x6a, 0x91, 0x27, 0xa8, 0xf3, 0xab, 0x4b, 0x79, 0x92,
		0x3c, 0x55, 0x1a, 0x4f, 0x81, 0x94, 0x34, 0xd7, 0x1e, 0x4d, 0xe6, 0xeb, 0x35, 0x5f,
		0x2f, 0xce, 0x5d, 0x62, 0xeb, 0x8d, 0x2b, 0xc4, 0x75, 0xea, 0x71, 0x03, 0x89, 0x4f,
		0xbe, 0x21, 0x6a, 0xc1, 0x27, 0x10, 0x40, 0x54, 0x7b, 0x2c, 0x9a, 0x73, 0xb5, 0x77,
		0xf8, 0x06, 0x17, 0x72, 0x79, 0x6c, 0x91, 0x28, 0x2b, 0xa9, 0x81, 0xc1, 0xb6, 0xc2,
		0x42, 0x1a, 0x4a, 0x64, 0xe7, 0xd5, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0xe4, 0x60, 0x80, 0x83, 0x99, 0x89, 0x01, 0x66, 0x80, 0x07, 0x80, 0x10, 0x01,
		0x30, 0x26, 0x3e, 0x04, 0x64, 0x00, 0x01, 0x0e, 0x80, 0x10, 0x00, 0x02, 0x01, 0x10,
		0x80, 0x80, 0x60, 0x02, 0x18, 0x0c, 0x00, 0xc1, 0x10, 0xe3, 0x47, 0x04, 0x24, 0x00,
		0x24, 0x01, 0x12, 0x01, 0x00, 0xc3, 0x83, 0x84, 0x80, 0x00, 0x22, 0x7e, 0x3e, 0x90,
		0x19, 0x0c, 0xc2, 0x83, 0x04, 0x00, 0x80, 0x80, 0x13, 0x00, 0x00, 0x00, 0x00, 0xc0,
		0x00, 0x80, 0x33, 0x40, 0x00, 0x9c, 0x03, 0x04, 0x00, 0x40, 0x00, 0xfc, 0x00, 0x00,
		0xc0, 0x99, 0x30, 0x46, 0x66, 0x00, 0x10, 0xe3, 0x91, 0x00, 0x00, 0x43, 0x90, 0x20,
		0x40, 0x92, 0x91, 0x01, 0x81, 0x60, 0x9c, 0x80, 0x10, 0x18, 0x80, 0x11, 0x82, 0x33,
		0x01, 0xf0, 0x00, 0xe0, 0x00, 0x38, 0x46, 0x12, 0x12, 0x4e, 0x12, 0x38, 0x38, 0x91,
		0x10, 0xe3, 0xb1, 0x2b, 0xa3, 0x29, 0xd4, 0x01, 0xe3, 0xce, 0xca, 0x6f, 0x6d, 0x53,
		0x79, 0xe5, 0xb3, 0x39, 0xcb, 0x22, 0x46, 0xb7, 0xf2, 0x25, 0x78, 0x94, 0x7a, 0x49,
		0x65, 0x3e, 0x27, 0x9d, 0x28, 0xd3, 0xfb, 0x1f, 0xab, 0xb3, 0x66, 0x75, 0x61, 0x4f,
		0x9f, 0x53, 0xe2, 0xe3, 0xe7, 0x5f, 0xfb, 0x47, 0x5a, 0xe0, 0xd5, 0x78, 0x7e, 0xe8,
		0xc2, 0x33, 0x20, 0xf7, 0x63, 0x56, 0xb8, 0xfb,
	};
	uint8_t coded[sizeof(captured)];
	uint8_t out[sizeof(captured)];
	/* The neighbour's EUI-64, as the MAC header carries it. */
	static const uint8_t neighbour[] = {0x01, 0x22, 0xff, 0xfe, 0xff, 0x55, 0x67, 0x44};
	size_t decoded_len;
	size_t corrections;
	uint16_t phr;
	uint16_t psdu_len;
	const uint8_t *psdu;

	memcpy(coded, captured, sizeof(captured));
	wisun_fec_descramble(coded, sizeof(coded), WISUN_FEC_UNSCRAMBLED_OCTETS);

	zassert_ok(wisun_fec_decode_phr(coded, &phr),
		   "the captured frame's PHY header was refused");
	zassert_equal(phr, 0x088e, "PHY header is %04x, the frame was captured carrying 088e", phr);

	psdu_len = phr & 0x07FF;
	zassert_true(wisun_fec_coded_len(psdu_len) <= sizeof(captured),
		     "the capture is too short for the frame its header describes");

	zassert_ok(wisun_fec_decode(coded, wisun_fec_coded_len(psdu_len), out, sizeof(out),
				    &decoded_len, &corrections),
		   "a captured frame was refused");
	zassert_equal(
		corrections, 0,
		"a frame captured off a bench link needed %zu corrections; on a link this short "
		"a real frame needs none, and anything else is the chain being subtly wrong",
		corrections);

	psdu = &out[sizeof(uint16_t)];
	zassert_true(check_fcs(psdu, psdu_len), "the captured frame's FCS did not check out");
	zassert_not_null(memmem_bytes(psdu, psdu_len, neighbour, sizeof(neighbour)),
			 "the neighbour's address is not where it should be in the decoded frame");
}
