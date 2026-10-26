#include "ecdh.h"
#include "conversion.h"
#include "rng.h"

static int valid_secret(const mpz_t s, const public_params_t *pp)
{
    return mpz_sgn(s) > 0 && mpz_cmp(s, pp->curve.r) < 0;
}

cc_status_t ecdh_gen_secret(mpz_t s, const public_params_t *pp)
{
    gmp_randstate_t state;
    CC_TRY(rng_init(state));
    cc_status_t status = rand_int_nonzero(s, state, pp->curve.r);
    gmp_randclear(state);
    return status;
}

// result = integer encoding of point P
static cc_status_t point_to_integer(mpz_t result, const point_t P, const public_params_t *pp)
{
    size_t len = point_size(pp->curve);
    unsigned char *buf = malloc(len);
    if (buf == NULL)
        return CC_ERR_NOMEM;

    cc_status_t status = point_to_bytes(buf, P, pp->curve);
    if (status == CC_OK)
        bytes_to_bigint(result, buf, len, BIG);

    free(buf);
    return status;
}

cc_status_t ecdh_gen_public(mpz_t p, const mpz_t s, const public_params_t *pp)
{
    if (!valid_secret(s, pp))
        return CC_ERR_INVALID_INPUT;

    point_t P;
    init_point(&P);
    generator(&P, pp->curve);
    mul(&P, P, s, pp->curve);
    cc_status_t status = point_to_integer(p, P, pp);
    free_point(&P);
    return status;
}

cc_status_t ecdh_compute_shared_secret(mpz_t shared_secret, const mpz_t s, const mpz_t p, const public_params_t *pp)
{
    if (!valid_secret(s, pp))
        return CC_ERR_INVALID_INPUT;

    size_t len = point_size(pp->curve);
    unsigned char *buf = malloc(len);
    if (buf == NULL)
        return CC_ERR_NOMEM;

    point_t P;
    init_point(&P);

    // The peer value must encode a valid point
    cc_status_t status = bigint_to_bytes_fixed(buf, len, p);
    if (status == CC_OK)
    {
        point_from_bytes(&P, buf, pp->curve);
        if (!is_valid_point(P, pp->curve))
            status = CC_ERR_INVALID_INPUT;
    }
    if (status == CC_OK)
    {
        mul(&P, P, s, pp->curve);
        if (is_infinity(P, pp->curve))
            status = CC_ERR_INVALID_INPUT;
    }
    if (status == CC_OK)
        status = point_to_integer(shared_secret, P, pp);
    if (status == CC_OK)
        mpz_mod(shared_secret, shared_secret, pp->curve.r);

    free(buf);
    free_point(&P);
    return status;
}
