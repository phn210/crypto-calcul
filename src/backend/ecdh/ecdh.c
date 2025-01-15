#include "ecdh.h"
#include "conversion.h"
#include "rng.h"

void gen_secret(mpz_t s, const public_params_t *pp)
{
    gmp_randstate_t state;
    rng_init(state);
    rand_int_m(s, state, pp->curve.r);
    gmp_randclear(state);
}

void gen_public(mpz_t p, const mpz_t s, const public_params_t *pp)
{
    point_t P;
    init_point(&P);
    size_t point_len = 2 * pp->curve.efs;
    unsigned char *buf = (unsigned char *)malloc(point_len);
    if (buf == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    generator(&P, pp->curve);
    mul(&P, P, s, pp->curve);
    point_to_bytes(buf, P, pp->curve);
    bytes_to_bigint(p, buf, point_len, BIG);
    point_from_bytes(&P, buf, pp->curve);

    free(buf);
    free_point(&P);
}

void compute_shared_secret(mpz_t shared_secret, const mpz_t s, const mpz_t p, const public_params_t *pp)
{
    point_t P;
    init_point(&P);
    size_t point_len = 2 * pp->curve.efs;
    unsigned char *buf = (unsigned char *)malloc(point_len);
    if (buf == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    size_t p_len;
    bigint_to_bytes(buf, &p_len, p, BIG);
    point_from_bytes(&P, buf, pp->curve);
    mul(&P, P, s, pp->curve);

    point_to_bytes(buf, P, pp->curve);
    bytes_to_bigint(shared_secret, buf, point_len, BIG);
    mpz_mod(shared_secret, shared_secret, pp->curve.r);

    free(buf);
    free_point(&P);
}
