#include "rng.h"

#define RAND_SOURCE "/dev/urandom"

cc_status_t get_random_seed(unsigned int *seed)
{
#ifdef WINDOWS_H
    if (!RtlGenRandom(seed, sizeof(*seed)))
        return CC_ERR_RNG;
#else
    FILE *fp = fopen(RAND_SOURCE, "rb");
    if (fp == NULL)
        return CC_ERR_RNG;
    size_t read = fread(seed, sizeof(*seed), 1, fp);
    fclose(fp);
    if (read != 1)
        return CC_ERR_RNG;
#endif
    return CC_OK;
}

cc_status_t rng_init(gmp_randstate_t state)
{
    unsigned int seed;
    CC_TRY(get_random_seed(&seed));
    rng_init_with_seed(state, seed);
    return CC_OK;
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

cc_status_t rand_int_m(mpz_t result, gmp_randstate_t state, const mpz_t n)
{
    if (mpz_sgn(n) <= 0)
        return CC_ERR_INVALID_ARG;
    mpz_urandomm(result, state, n);
    return CC_OK;
}

cc_status_t rand_int_nonzero(mpz_t result, gmp_randstate_t state, const mpz_t n)
{
    if (mpz_cmp_ui(n, 1) <= 0)
        return CC_ERR_INVALID_ARG;
    mpz_t bound;
    mpz_init(bound);
    mpz_sub_ui(bound, n, 1);
    mpz_urandomm(result, state, bound);
    mpz_add_ui(result, result, 1);
    mpz_clear(bound);
    return CC_OK;
}

void rand_bytes(char *buf, gmp_randstate_t state, unsigned int byte_len)
{
    mpz_t r;
    mpz_init(r);
    mpz_urandomb(r, state, byte_len * 8);

    // mpz_export skips leading zero bytes, so right-align the output
    size_t count = (mpz_sizeinbase(r, 2) + 7) / 8;
    if (mpz_sgn(r) == 0)
        count = 0;
    memset(buf, 0, byte_len - count);
    mpz_export(buf + byte_len - count, NULL, 1, 1, 0, 0, r);
    mpz_clear(r);
}
