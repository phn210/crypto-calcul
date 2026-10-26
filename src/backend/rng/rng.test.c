#include "rng.h"

int main()
{
    printf("\n===================== RNG TEST =====================\n\n");

    gmp_randstate_t state;
    mpz_t result, n;
    char buf[32];

    // Initialize random state
    if (rng_init(state) != CC_OK)
    {
        printf("RNG:\tFAILED\n");
        return 1;
    }
    int passed = 1;

    // Test rand_int_b
    mpz_init(result);
    rand_int_b(result, state, 1024);
    // gmp_printf("Random 1024-bit integer: %Zd\n", result);
    mpz_clear(result);

    // Test rand_int_m
    mpz_init_set_str(n, "100000000000000000000000000000000000000", 10);
    mpz_init(result);
    passed &= rand_int_m(result, state, n) == CC_OK && mpz_cmp(result, n) < 0;

    // A zero modulus is rejected instead of dividing by zero
    mpz_set_ui(n, 0);
    passed &= rand_int_m(result, state, n) == CC_ERR_INVALID_ARG;
    mpz_clear(result);
    mpz_clear(n);

    // Test rand_bytes
    rand_bytes(buf, state, sizeof(buf));
    // printf("Random bytes: ");
    // for (int i = 0; i < sizeof(buf); i++)
    // {
    //     printf("%02x", (unsigned char)buf[i]);
    // }
    // printf("\n");

    printf("RNG:\t%s\n", passed ? "PASSED" : "FAILED");

    // Clear random state
    gmp_randclear(state);

    return 0;
}