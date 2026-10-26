#include "prime_test.h"
#include "prime_gen.h"
#include "rng.h"

static const char *result(cc_status_t status, int is_prime)
{
    return status == CC_OK && is_prime ? "PASSED" : "FAILED";
}

static void test_generated_prime(int index, const mpz_t prime, gmp_randstate_t state, int t)
{
    const char *names[] = {"Fermat test:\t", "Miller-Rabin test:", "GMP test:\t"};
    prime_test_t tests[] = {FERMAT_TEST, MILLER_RABIN_TEST, GMP_TEST};

    for (int i = 0; i < 3; i++)
    {
        int is_prime = 0;
        cc_status_t status = primality_test(prime, state, t, tests[i], &is_prime);
        printf("[%d] %s\t%s\n", index + i, names[i], result(status, is_prime));
    }
}

int main()
{
    printf("\n===================== PRIME TEST =====================\n\n");

    gmp_randstate_t state;
    if (rng_init(state) != CC_OK)
    {
        printf("RNG init:\t\tFAILED\n");
        return 1;
    }

    mpz_t prime, mod;
    mpz_inits(prime, mod, NULL);

    int b = 512; // Number of bits for the prime number
    int k = 100; // Number of small primes
    int t = 25;  // Number of iterations for the primality test

    cc_status_t status = gen_prime_b(prime, state, b, k, t, MILLER_RABIN_TEST);
    if (status != CC_OK || mpz_sizeinbase(prime, 2) < (size_t)b)
        printf("gen_prime_b:\t\tFAILED\n");
    test_generated_prime(0, prime, state, t);

    mpz_set_ui(mod, INT64_MAX);
    status = gen_prime_m(prime, state, mod, k, t, MILLER_RABIN_TEST);
    if (status != CC_OK || mpz_cmp(prime, mod) >= 0)
        printf("gen_prime_m:\t\tFAILED\n");
    test_generated_prime(3, prime, state, t);

    // Edge cases that used to crash or loop: small n, small modulus, bad parameters
    int is_prime = 0, passed = 1;
    for (unsigned long n = 0; n < 8; n++)
    {
        mpz_set_ui(prime, n);
        passed &= primality_test(prime, state, t, FERMAT_TEST, &is_prime) == CC_OK &&
                  is_prime == (n == 2 || n == 3 || n == 5 || n == 7);
    }
    mpz_set_ui(mod, 3);
    passed &= gen_prime_m(prime, state, mod, k, t, MILLER_RABIN_TEST) == CC_OK && mpz_cmp_ui(prime, 2) == 0;
    mpz_set_ui(mod, 0);
    passed &= gen_prime_m(prime, state, mod, k, t, MILLER_RABIN_TEST) == CC_ERR_INVALID_ARG;
    passed &= gen_prime_b(prime, state, b, 0, t, MILLER_RABIN_TEST) == CC_ERR_INVALID_ARG;
    passed &= primality_test(prime, state, t, (prime_test_t)42, &is_prime) == CC_ERR_INVALID_ARG;
    printf("[6] Edge cases:\t\t%s\n", passed ? "PASSED" : "FAILED");

    mpz_clears(prime, mod, NULL);
    gmp_randclear(state);
    return 0;
}
