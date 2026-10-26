#ifndef PRIME_GEN_H
#define PRIME_GEN_H

#include "common.h"
#include "prime_test.h"

// Random prime of b bits: k small primes are used for trial division before running t rounds of the test
CC_NODISCARD cc_status_t gen_prime_b(mpz_t n, gmp_randstate_t state, int b, int k, int t, prime_test_t test);
// Random prime below m (m > 2)
CC_NODISCARD cc_status_t gen_prime_m(mpz_t n, gmp_randstate_t state, const mpz_t m, int k, int t, prime_test_t test);

#endif
