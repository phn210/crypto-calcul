#ifndef RNG_H
#define RNG_H

#include "common.h"

CC_NODISCARD cc_status_t get_random_seed(unsigned int *seed);
CC_NODISCARD cc_status_t rng_init(gmp_randstate_t state);
void rng_init_with_seed(gmp_randstate_t state, unsigned int seed);
void rand_int_b(mpz_t result, gmp_randstate_t state, unsigned long bits);
// Uniform in [0, n); n must be positive
CC_NODISCARD cc_status_t rand_int_m(mpz_t result, gmp_randstate_t state, const mpz_t n);
// Uniform in [1, n); n must be greater than 1
CC_NODISCARD cc_status_t rand_int_nonzero(mpz_t result, gmp_randstate_t state, const mpz_t n);
void rand_bytes(char *buf, gmp_randstate_t state, unsigned int byte_len);

#endif
