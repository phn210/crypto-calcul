#include "common.h"
#include "prime_test.h"

void gen_prime_b(mpz_t n, gmp_randstate_t state, int b, int k, int t, PRIMALITY_TEST test);
void gen_prime_m(mpz_t n, gmp_randstate_t state, mpz_t m, int k, int t, PRIMALITY_TEST test);