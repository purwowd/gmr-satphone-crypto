/*
 * Standalone keystream generator for GMR-1 A5/1 (A5-GMR-1).
 *
 * Purpose: provide an independent (C) implementation to cross-check the
 * Python port. This is based on Osmocom osmo-gmr/src/l1/a5.c logic, but made
 * self-contained (no external Osmocom headers/libraries).
 *
 * Output: keystream bits as ASCII '0'/'1' on stdout.
 *
 * Build:
 *   cc -O2 -Wall -Wextra -o osmo_gmr_keystream osmo_gmr1_a5_standalone.c
 *
 * Run:
 *   ./osmo_gmr_keystream --kc 0123456789abcdef --fn 0x1a2b3 --nbits 208
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t parity32(uint32_t x)
{
	x ^= x >> 16;
	x ^= x >> 8;
	x ^= x >> 4;
	x &= 0xf;
	return (0x6996 >> x) & 1;
}

static uint32_t majority(uint32_t v1, uint32_t v2, uint32_t v3)
{
	return (!!v1 + !!v2 + !!v3) >= 2;
}

static uint32_t clock_lfsr(uint32_t r, uint32_t mask, uint32_t taps)
{
	return ((r << 1) & mask) | parity32(r & taps);
}

#define A51_R1_LEN 19
#define A51_R2_LEN 22
#define A51_R3_LEN 23
#define A51_R4_LEN 17

#define A51_R1_MASK ((1u<<A51_R1_LEN)-1)
#define A51_R2_MASK ((1u<<A51_R2_LEN)-1)
#define A51_R3_MASK ((1u<<A51_R3_LEN)-1)
#define A51_R4_MASK ((1u<<A51_R4_LEN)-1)

#define A51_R1_TAPS 0x072000u
#define A51_R2_TAPS 0x311000u
#define A51_R3_TAPS 0x660000u
#define A51_R4_TAPS 0x013100u

static inline uint32_t BIT(int n) { return 1u << n; }

static void a5_set_bits(uint32_t r[4])
{
	r[0] |= 1;
	r[1] |= 1;
	r[2] |= 1;
	r[3] |= 1;
}

static void a5_clock_force(uint32_t r[4])
{
	r[0] = clock_lfsr(r[0], A51_R1_MASK, A51_R1_TAPS);
	r[1] = clock_lfsr(r[1], A51_R2_MASK, A51_R2_TAPS);
	r[2] = clock_lfsr(r[2], A51_R3_MASK, A51_R3_TAPS);
	r[3] = clock_lfsr(r[3], A51_R4_MASK, A51_R4_TAPS);
}

static void a5_clock(uint32_t r[4])
{
	int cb0 = !!(r[3] & BIT(15));
	int cb1 = !!(r[3] & BIT(6));
	int cb2 = !!(r[3] & BIT(1));
	int m = (cb0 + cb1 + cb2) >= 2;

	if (cb0 == m) r[0] = clock_lfsr(r[0], A51_R1_MASK, A51_R1_TAPS);
	if (cb1 == m) r[1] = clock_lfsr(r[1], A51_R2_MASK, A51_R2_TAPS);
	if (cb2 == m) r[2] = clock_lfsr(r[2], A51_R3_MASK, A51_R3_TAPS);
	r[3] = clock_lfsr(r[3], A51_R4_MASK, A51_R4_TAPS);
}

static uint8_t a5_output(uint32_t r[4])
{
	uint32_t m0 = majority(r[0] & BIT(1), r[0] & BIT(6), r[0] & BIT(15));
	uint32_t m1 = majority(r[1] & BIT(3), r[1] & BIT(8), r[1] & BIT(14));
	uint32_t m2 = majority(r[2] & BIT(4), r[2] & BIT(15), r[2] & BIT(19));

	m0 ^= !!(r[0] & BIT(11));
	m1 ^= !!(r[1] & BIT(1));
	m2 ^= !!(r[2] & BIT(0));

	return (uint8_t)(m0 ^ m1 ^ m2);
}

static int hex2bytes(const char *hex, uint8_t out[8])
{
	size_t n = strlen(hex);
	if (n != 16) return -1;
	for (size_t i = 0; i < 8; i++) {
		char tmp[3] = { hex[i*2], hex[i*2+1], 0 };
		char *end = NULL;
		long v = strtol(tmp, &end, 16);
		if (!end || *end) return -1;
		out[i] = (uint8_t)v;
	}
	return 0;
}

static void mix_frame_into_key(const uint8_t key[8], uint32_t fn, uint8_t lkey[8])
{
	for (int i = 0; i < 8; i++)
		lkey[i] = key[i ^ 1];

	lkey[6] ^= (fn & 0x0000f) << 4;
	lkey[3] ^= (fn & 0x00030) << 2;
	lkey[1] ^= (fn & 0x007c0) >> 3;
	lkey[0] ^= (fn & 0x0f800) >> 11;
	lkey[0] ^= (fn & 0x70000) >> 11;
}

static void gmr1_a5_1_bits(const uint8_t key[8], uint32_t fn, int nbits, uint8_t *out_bits)
{
	uint32_t r[4] = {0,0,0,0};
	uint8_t lkey[8];
	mix_frame_into_key(key, fn, lkey);

	for (int i = 0; i < 64; i++) {
		int byte_idx = i >> 3;
		int bit_idx = 7 - (i & 7);
		uint32_t b = (lkey[byte_idx] >> bit_idx) & 1;
		a5_clock_force(r);
		r[0] ^= b; r[1] ^= b; r[2] ^= b; r[3] ^= b;
	}

	a5_set_bits(r);

	for (int i = 0; i < 250; i++)
		a5_clock(r);

	for (int i = 0; i < nbits; i++) {
		a5_clock(r);
		out_bits[i] = a5_output(r);
	}
}

static void usage(const char *p)
{
	fprintf(stderr, "Usage: %s --kc <16hex> --fn <int|0x..> --nbits <n>\n", p);
}

int main(int argc, char **argv)
{
	const char *kc_hex = NULL;
	const char *fn_s = NULL;
	const char *nbits_s = NULL;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--kc") && i+1 < argc) kc_hex = argv[++i];
		else if (!strcmp(argv[i], "--fn") && i+1 < argc) fn_s = argv[++i];
		else if (!strcmp(argv[i], "--nbits") && i+1 < argc) nbits_s = argv[++i];
		else { usage(argv[0]); return 2; }
	}

	if (!kc_hex || !fn_s || !nbits_s) { usage(argv[0]); return 2; }

	uint8_t kc[8];
	if (hex2bytes(kc_hex, kc)) { fprintf(stderr, "Bad --kc\n"); return 2; }

	char *end = NULL;
	uint32_t fn = (uint32_t)strtoul(fn_s, &end, 0);
	if (!end || *end) { fprintf(stderr, "Bad --fn\n"); return 2; }

	int nbits = (int)strtol(nbits_s, &end, 10);
	if (!end || *end || nbits < 0) { fprintf(stderr, "Bad --nbits\n"); return 2; }

	uint8_t *bits = (uint8_t*)calloc((size_t)nbits ? (size_t)nbits : 1, 1);
	if (!bits) { fprintf(stderr, "OOM\n"); return 1; }

	gmr1_a5_1_bits(kc, fn, nbits, bits);
	for (int i = 0; i < nbits; i++)
		putchar(bits[i] ? '1' : '0');
	putchar('\n');

	free(bits);
	return 0;
}

