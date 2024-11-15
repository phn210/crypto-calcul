#include <stdio.h>
#include <stdlib.h>
#include "prime_test.h"
#include "prime_gen.h"
#include "rng.h"

int main()
{
    printf("\n===================== PRIME TEST =====================\n\n");

    gmp_randstate_t state;
    rng_init(state);

    mpz_t prime;
    mpz_init(prime);

    int b = 128; // Number of bits for the prime number
    int k = 20;  // Number of small primes
    int t = 25;  // Number of iterations for the primality test

    // Generate a prime number
    gen_prime(prime, state, b, k, t, MILLER_RABIN_TEST);
    gmp_printf("Generated prime: %Zd\n", prime);

    // Test the generated prime using different methods
    int is_prime_fermat = primality_test(prime, state, t, FERMAT_TEST);
    int is_prime_miller_rabin = primality_test(prime, state, t, MILLER_RABIN_TEST);
    int is_prime_gmp = primality_test(prime, state, t, GMP_TEST);

    printf("Fermat test: %s\n", is_prime_fermat ? "Prime" : "Composite");
    printf("Miller-Rabin test: %s\n", is_prime_miller_rabin ? "Prime" : "Composite");
    printf("GMP test: %s\n", is_prime_gmp ? "Prime" : "Composite");

    mpz_clear(prime);
    gmp_randclear(state);
    return 0;
}