#ifndef API_INTERNAL_H
#define API_INTERNAL_H

#include "common.h"
#include "conversion.h"

// Empty inputs may be passed as NULL; the internal functions always get a valid pointer
#define API_BYTES(p) ((p) != NULL ? (p) : (const uint8_t *)"")

// Copies len bytes to out, after checking the capacity in *out_len
cc_status_t api_output(uint8_t *out, size_t *out_len, const void *data, size_t len);
// Writes the minimal big-endian encoding of n (one zero byte for 0)
cc_status_t api_output_mpz(uint8_t *out, size_t *out_len, const mpz_t n);
// Writes two integers (a signature or a ciphertext pair), checking both capacities first
cc_status_t api_output_mpz_pair(uint8_t *a, size_t *a_len, const mpz_t x, uint8_t *b, size_t *b_len, const mpz_t y);
// Sets n from big-endian bytes (an empty input is 0)
void api_input_mpz(mpz_t n, const uint8_t *in, size_t in_len);

cc_status_t api_sec_level(cc_sec_level_t level, sec_level_t *internal);
cc_status_t api_hash(cc_hash_t hash, hash_func_t *internal);
// Curve type (ec_t) and identifier as used by init_curve
cc_status_t api_curve(cc_curve_t curve, int *type, unsigned char *id);

#endif
