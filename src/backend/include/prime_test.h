#ifndef PRIME_TEST_H
#define PRIME_TEST_H

#include "common.h"

int primality_test(mpz_t n, gmp_randstate_t state, int t, PRIMALITY_TEST test);

#endif