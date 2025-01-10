#ifndef PRIME_TEST_H
#define PRIME_TEST_H

#include "common.h"

typedef enum prime_test
{
    GMP_TEST,
    FERMAT_TEST,
    MILLER_RABIN_TEST
} prime_test_t;

int primality_test(mpz_t n, gmp_randstate_t state, int t, prime_test_t test);

#endif