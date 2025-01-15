#include "rng.h"

#define RAND_SOURCE "/dev/urandom"

unsigned int get_random_seed()
{
    unsigned long int rand_src;
#ifdef WINDOWS_H
    while (!RtlGenRandom(&rand_src, sizeof(unsigned int)))
    {
    };
#else
    FILE *fp = fopen(RAND_SOURCE, "rb");
    fread(&rand_src, sizeof(unsigned int), 1, fp);
    fclose(fp);
#endif
    return rand_src;
}

void rng_init(gmp_randstate_t state)
{
    gmp_randinit_default(state);
    gmp_randseed_ui(state, get_random_seed());
}

void rng_init_with_seed(gmp_randstate_t state, unsigned int seed)
{
    gmp_randinit_default(state);
    gmp_randseed_ui(state, seed);
}

void rand_int_b(mpz_t result, gmp_randstate_t state, unsigned long bits)
{
    mpz_urandomb(result, state, bits);
}

void rand_int_m(mpz_t result, gmp_randstate_t state, const mpz_t n)
{
    mpz_urandomm(result, state, n);
}

void rand_bytes(char *buf, gmp_randstate_t state, unsigned int byte_len)
{
    mpz_t r;
    mpz_init(r);
    mpz_urandomb(r, state, byte_len * 8);
    mpz_export(buf, NULL, 1, 1, 0, 0, r);
    mpz_clear(r);
}