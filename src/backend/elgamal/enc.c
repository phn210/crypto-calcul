#include "conversion.h"
#include "elgamal.h"
#include "rng.h"

cc_status_t elgamal_setup(public_params_t *pp, sec_level_t level)
{
    const char *p, *g;
    switch (level)
    {
    case L0:
        pp->p_bits = L0_P_BITS;
        p = L0_P;
        g = L0_G;
        break;
    case L1:
        pp->p_bits = L1_P_BITS;
        p = L1_P;
        g = L1_G;
        break;
    default:
        return CC_ERR_INVALID_ARG;
    }

    mpz_init_set_str(pp->p, p, 16);
    mpz_init_set_str(pp->g, g, 16);
    return CC_OK;
}

void elgamal_free_params(public_params_t *pp)
{
    mpz_clears(pp->p, pp->g, NULL);
}

cc_status_t elgamal_keygen(priv_key_t *sk, pub_key_t *pk, const public_params_t *pp)
{
    gmp_randstate_t state;
    CC_TRY(rng_init(state));
    mpz_inits(sk->x, pk->y, NULL);

    // x in [1, p - 1), y = g^x mod p
    mpz_t bound;
    mpz_init(bound);
    mpz_sub_ui(bound, pp->p, 1);
    cc_status_t status = rand_int_nonzero(sk->x, state, bound);
    if (status == CC_OK)
        mpz_powm(pk->y, pp->g, sk->x, pp->p);
    else
        elgamal_free_keys(sk, pk);

    mpz_clear(bound);
    gmp_randclear(state);
    return status;
}

void elgamal_free_keys(priv_key_t *sk, pub_key_t *pk)
{
    mpz_clears(sk->x, pk->y, NULL);
}

cc_status_t elgamal_encrypt(mpz_t c1, mpz_t c2, const mpz_t m, const pub_key_t *pk, const public_params_t *pp)
{
    if (mpz_sgn(m) < 0 || mpz_cmp(m, pp->p) >= 0)
        return CC_ERR_MSG_TOO_LONG;

    gmp_randstate_t state;
    CC_TRY(rng_init(state));

    // c1 = g^k, c2 = m * y^k with k in [1, p - 1)
    mpz_t k, bound;
    mpz_inits(k, bound, NULL);
    mpz_sub_ui(bound, pp->p, 1);
    cc_status_t status = rand_int_nonzero(k, state, bound);
    if (status == CC_OK)
    {
        mpz_powm(c1, pp->g, k, pp->p);
        mpz_powm(c2, pk->y, k, pp->p);
        mpz_mul(c2, c2, m);
        mpz_mod(c2, c2, pp->p);
    }

    mpz_clears(k, bound, NULL);
    gmp_randclear(state);
    return status;
}

cc_status_t elgamal_decrypt(mpz_t m, const mpz_t c1, const mpz_t c2, const priv_key_t *sk, const public_params_t *pp)
{
    if (mpz_sgn(c1) <= 0 || mpz_cmp(c1, pp->p) >= 0 || mpz_sgn(c2) < 0 || mpz_cmp(c2, pp->p) >= 0)
        return CC_ERR_INVALID_INPUT;

    // m = c2 * (c1^x)^-1 mod p
    mpz_t s;
    mpz_init(s);
    mpz_powm(s, c1, sk->x, pp->p);
    int invertible = mpz_invert(s, s, pp->p);
    if (invertible)
    {
        mpz_mul(m, c2, s);
        mpz_mod(m, m, pp->p);
    }

    mpz_clear(s);
    return invertible ? CC_OK : CC_ERR_INVALID_INPUT;
}
