#ifndef RNG_H
#define RNG_H

#include "common.h"

unsigned int get_random_seed();
void rng_init(gmp_randstate_t state);
void rng_init_with_seed(gmp_randstate_t state, unsigned int seed);
void rand_int_b(mpz_t result, gmp_randstate_t state, unsigned long bits);
void rand_int_m(mpz_t result, gmp_randstate_t state, const mpz_t n);
void rand_bytes(char *buf, gmp_randstate_t state, unsigned int byte_len);

#endif