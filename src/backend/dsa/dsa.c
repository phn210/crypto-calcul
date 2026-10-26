#include "dsa.h"
#include "conversion.h"
#include "rng.h"
#include "sha2.h"
#include "sha3.h"

cc_status_t dsa_setup(public_params_t *pp, sec_level_t level, hash_func_t hash)
{
    const char *p, *q, *g;
    switch (level)
    {
    case L0:
        pp->p_bits = L0_L;
        pp->q_bits = L0_N;
        pp->md_len = 28;
        p = L0_P;
        q = L0_Q;
        g = L0_G;
        break;
    case L1:
        pp->p_bits = L1_L;
        pp->q_bits = L1_N;
        pp->md_len = 32;
        p = L1_P;
        q = L1_Q;
        g = L1_G;
        break;
    default:
        return CC_ERR_INVALID_ARG;
    }

    switch (hash)
    {
    case SHA2:
        pp->hash = &sha2;
        break;
    case SHA3:
        pp->hash = &sha3;
        break;
    default:
        return CC_ERR_INVALID_ARG;
    }

    mpz_init_set_str(pp->p, p, 16);
    mpz_init_set_str(pp->q, q, 16);
    mpz_init_set_str(pp->g, g, 16);
    return CC_OK;
}

void dsa_free_params(public_params_t *pp)
{
    mpz_clears(pp->p, pp->q, pp->g, NULL);
}

cc_status_t dsa_keygen(priv_key_t *sk, pub_key_t *pk, const public_params_t *pp)
{
    gmp_randstate_t state;
    CC_TRY(rng_init(state));
    mpz_inits(sk->x, pk->y, NULL);

    // x in [1, q), y = g^x mod p
    cc_status_t status = rand_int_nonzero(sk->x, state, pp->q);
    if (status == CC_OK)
        mpz_powm(pk->y, pp->g, sk->x, pp->p);
    else
        dsa_free_keys(sk, pk);

    gmp_randclear(state);
    return status;
}

void dsa_free_keys(priv_key_t *sk, pub_key_t *pk)
{
    mpz_clears(sk->x, pk->y, NULL);
}

static void dsa_hash(mpz_t hm, const unsigned char *m, size_t len, const public_params_t *pp)
{
    unsigned char md[32];
    pp->hash(m, len, md, pp->md_len);
    bytes_to_bigint(hm, md, pp->md_len, BIG);
}

cc_status_t dsa_sign(mpz_t r, mpz_t s, const unsigned char *m, size_t len, const priv_key_t *sk, const public_params_t *pp)
{
    gmp_randstate_t state;
    CC_TRY(rng_init(state));

    mpz_t hm, k, tmp;
    mpz_inits(hm, k, tmp, NULL);
    dsa_hash(hm, m, len, pp);

    // Retry with a new k in [1, q) in the unlikely case r = 0 or s = 0
    cc_status_t status;
    do
    {
        status = rand_int_nonzero(k, state, pp->q);
        if (status != CC_OK)
            break;

        // r = (g^k mod p) mod q
        mpz_powm(r, pp->g, k, pp->p);
        mpz_mod(r, r, pp->q);

        // s = k^-1 * (H(m) + x * r) mod q
        mpz_mul(tmp, sk->x, r);
        mpz_add(tmp, tmp, hm);
        mpz_invert(k, k, pp->q);
        mpz_mul(s, tmp, k);
        mpz_mod(s, s, pp->q);
    } while (mpz_sgn(r) == 0 || mpz_sgn(s) == 0);

    mpz_clears(hm, k, tmp, NULL);
    gmp_randclear(state);
    return status;
}

cc_status_t dsa_verify(const mpz_t r, const mpz_t s, const unsigned char *m, size_t len, const pub_key_t *pk, const public_params_t *pp)
{
    if (mpz_sgn(r) <= 0 || mpz_cmp(r, pp->q) >= 0 || mpz_sgn(s) <= 0 || mpz_cmp(s, pp->q) >= 0)
        return CC_ERR_VERIFY;

    mpz_t hm, w, u1, u2, v;
    mpz_inits(hm, w, u1, u2, v, NULL);
    dsa_hash(hm, m, len, pp);

    // v = (g^(H(m) * w) * y^(r * w) mod p) mod q, with w = s^-1 mod q
    mpz_invert(w, s, pp->q);
    mpz_mul(u1, hm, w);
    mpz_mod(u1, u1, pp->q);
    mpz_mul(u2, r, w);
    mpz_mod(u2, u2, pp->q);

    mpz_powm(u1, pp->g, u1, pp->p);
    mpz_powm(u2, pk->y, u2, pp->p);
    mpz_mul(v, u1, u2);
    mpz_mod(v, v, pp->p);
    mpz_mod(v, v, pp->q);

    int valid = mpz_cmp(v, r) == 0;
    mpz_clears(hm, w, u1, u2, v, NULL);
    return valid ? CC_OK : CC_ERR_VERIFY;
}
