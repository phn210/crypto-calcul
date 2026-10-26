#include "dh.h"
#include "rng.h"

// x in [1, p - 1)
static int in_exponent_range(const mpz_t x, const public_params_t *pp)
{
    mpz_t bound;
    mpz_init(bound);
    mpz_sub_ui(bound, pp->p, 1);
    int ok = mpz_sgn(x) > 0 && mpz_cmp(x, bound) < 0;
    mpz_clear(bound);
    return ok;
}

cc_status_t dh_gen_secret(mpz_t s, const public_params_t *pp)
{
    gmp_randstate_t state;
    CC_TRY(rng_init(state));

    mpz_t bound;
    mpz_init(bound);
    mpz_sub_ui(bound, pp->p, 1);
    cc_status_t status = rand_int_nonzero(s, state, bound);

    mpz_clear(bound);
    gmp_randclear(state);
    return status;
}

cc_status_t dh_gen_public(mpz_t p, const mpz_t secret, const public_params_t *pp)
{
    if (!in_exponent_range(secret, pp))
        return CC_ERR_INVALID_INPUT;
    mpz_powm(p, pp->g, secret, pp->p);
    return CC_OK;
}

cc_status_t dh_compute_shared_secret(mpz_t shared_secret, const mpz_t s, const mpz_t p, const public_params_t *pp)
{
    // Peer value must be in [2, p - 2]
    mpz_t upper;
    mpz_init(upper);
    mpz_sub_ui(upper, pp->p, 2);
    int valid = mpz_cmp_ui(p, 2) >= 0 && mpz_cmp(p, upper) <= 0;
    mpz_clear(upper);

    if (!valid || !in_exponent_range(s, pp))
        return CC_ERR_INVALID_INPUT;
    mpz_powm(shared_secret, p, s, pp->p);
    return CC_OK;
}
