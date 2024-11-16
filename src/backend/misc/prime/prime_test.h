#include "common.h"

#define GMP_TEST 0
#define FERMAT_TEST 1
#define MILLER_RABIN_TEST 2

int primality_test(mpz_t n, gmp_randstate_t state, int t, PRIMALITY_TEST test);