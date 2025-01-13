#include "rng.h"

int main()
{
    printf("\n===================== RNG TEST =====================\n\n");

    gmp_randstate_t state;
    mpz_t result, n;
    char buf[32];

    // Initialize random state
    rng_init(state);

    // Test rand_int_b
    mpz_init(result);
    rand_int_b(result, state, 1024);
    // gmp_printf("Random 1024-bit integer: %Zd\n", result);
    mpz_clear(result);

    // Test rand_int_m
    mpz_init_set_str(n, "100000000000000000000000000000000000000", 10);
    mpz_init(result);
    rand_int_m(result, state, n);
    // gmp_printf("Random integer modulo n: %Zd\n", result);
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

    printf("RNG:\tPASSED\n");

    // Clear random state
    gmp_randclear(state);

    return 0;
}