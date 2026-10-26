#ifndef PRIME_TEST_H
#define PRIME_TEST_H

#include "common.h"

typedef enum prime_test
{
    GMP_TEST,
    FERMAT_TEST,
    MILLER_RABIN_TEST
} prime_test_t;

// Sets *is_prime to 1 if n is (probably) prime, 0 otherwise; t is the number of rounds
CC_NODISCARD cc_status_t primality_test(const mpz_t n, gmp_randstate_t state, int t, prime_test_t test, int *is_prime);

#endif