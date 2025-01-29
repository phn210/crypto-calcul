#include "prime_test.h"
#include "prime_gen.h"
#include "rng.h"

int main()
{
    printf("\n===================== PRIME TEST =====================\n\n");

    gmp_randstate_t state;
    rng_init(state);

    mpz_t prime, mod;
    mpz_inits(prime, mod, NULL);

    int b = 512; // Number of bits for the prime number
    int k = 100; // Number of small primes
    int t = 25;  // Number of iterations for the primality test

    // Generate a prime number
    gen_prime_b(prime, state, b, k, t, MILLER_RABIN_TEST);
    // gmp_printf("Generated prime: %Zd\n", prime);

    // Test the generated prime using different methods
    int is_prime_fermat = primality_test(prime, state, t, FERMAT_TEST);
    int is_prime_miller_rabin = primality_test(prime, state, t, MILLER_RABIN_TEST);
    int is_prime_gmp = primality_test(prime, state, t, GMP_TEST);

    printf("[0] Fermat test:\t");
    if (is_prime_fermat > 0)
        printf("PASSED\n");
    else
        printf("FAILED\n");

    printf("[1] Miller-Rabin test:\t");
    if (is_prime_miller_rabin > 0)
        printf("PASSED\n");
    else
        printf("FAILED\n");

    printf("[2] GMP test:\t\t");
    if (is_prime_gmp > 0)
        printf("PASSED\n");
    else
        printf("FAILED\n");

    // Generate a prime number
    mpz_set_ui(mod, INT64_MAX);
    gen_prime_m(prime, state, mod, k, t, MILLER_RABIN_TEST);
    // gmp_printf("Generated prime: %Zd\n", prime);

    // Test the generated prime using different methods
    is_prime_fermat = primality_test(prime, state, t, FERMAT_TEST);
    is_prime_miller_rabin = primality_test(prime, state, t, MILLER_RABIN_TEST);
    is_prime_gmp = primality_test(prime, state, t, GMP_TEST);

    printf("[3] Fermat test:\t");
    if (is_prime_fermat > 0)
        printf("PASSED\n");
    else
        printf("FAILED\n");

    printf("[4] Miller-Rabin test:\t");
    if (is_prime_miller_rabin > 0)
        printf("PASSED\n");
    else
        printf("FAILED\n");

    printf("[5] GMP test:\t\t");
    if (is_prime_gmp > 0)
        printf("PASSED\n");
    else
        printf("FAILED\n");

    mpz_clears(prime, mod, NULL);
    gmp_randclear(state);
    return 0;
}