#include "ecdsa.h"
#include "conversion.h"
#include "rng.h"

#define MAX_MD_LEN 64

cc_status_t ecdsa_setup(public_params_t *pp, ec_t curve_type, unsigned char curve_id)
{
    return init_curve(&pp->curve, curve_type, curve_id);
}

void ecdsa_free_params(public_params_t *pp)
{
    free_curve(&pp->curve);
}

cc_status_t ecdsa_keygen(priv_key_t *sk, pub_key_t *pk, const public_params_t *pp)
{
    gmp_randstate_t state;
    CC_TRY(rng_init(state));
    mpz_init(sk->d);
    init_point(&pk->Q);

    // d in [1, r), Q = dG
    cc_status_t status = rand_int_nonzero(sk->d, state, pp->curve.r);
    if (status == CC_OK)
    {
        generator(&pk->Q, pp->curve);
        mul(&pk->Q, pk->Q, sk->d, pp->curve);
    }
    else
        ecdsa_free_keys(sk, pk);

    gmp_randclear(state);
    return status;
}

void ecdsa_free_keys(priv_key_t *sk, pub_key_t *pk)
{
    mpz_clear(sk->d);
    free_point(&pk->Q);
}

// e = H(m), truncated to the bit length of the group order
static cc_status_t ecdsa_digest(mpz_t e, const unsigned char *m, size_t m_len, const public_params_t *pp, hash_func_t hash_function)
{
    void *(*hash)(const void *, size_t, void *, size_t);
    CC_TRY(ec_hash_function(hash_function, &hash));
    if (pp->curve.type == MONTGOMERY)
        return CC_ERR_UNSUPPORTED;

    unsigned char md[MAX_MD_LEN];
    size_t md_len = pp->curve.md_len;
    size_t n_len = mpz_sizeinbase(pp->curve.r, 2);

    hash(m, m_len, md, md_len);
    bytes_to_bigint(e, md, md_len, BIG);
    if (n_len < md_len * 8)
        mpz_tdiv_q_2exp(e, e, md_len * 8 - n_len);
    return CC_OK;
}

cc_status_t ecdsa_sign(mpz_t r, mpz_t s, const unsigned char *m, size_t m_len, const priv_key_t *sk, const public_params_t *pp, hash_func_t hash_function)
{
    mpz_t e, k, k_inv, tmp;
    mpz_inits(e, k, k_inv, tmp, NULL);

    cc_status_t status = ecdsa_digest(e, m, m_len, pp, hash_function);
    gmp_randstate_t state;
    if (status == CC_OK)
        status = rng_init(state);
    if (status != CC_OK)
    {
        mpz_clears(e, k, k_inv, tmp, NULL);
        return status;
    }

    point_t R;
    point_affine_t R_affine;
    init_point(&R);
    init_affine(&R_affine);

    do
    {
        // k in [1, r), R = kG
        status = rand_int_nonzero(k, state, pp->curve.r);
        if (status != CC_OK || !mpz_invert(k_inv, k, pp->curve.r))
            continue;
        generator(&R, pp->curve);
        mul(&R, R, k, pp->curve);
        to_affine(&R_affine, R, pp->curve);

        // r = R.x mod n, s = k^-1 * (e + d * r) mod n
        mpz_mod(r, R_affine.x, pp->curve.r);
        mpz_set(tmp, e);
        mpz_addmul(tmp, sk->d, r);
        mpz_mul(s, k_inv, tmp);
        mpz_mod(s, s, pp->curve.r);
    } while (status == CC_OK && (mpz_sgn(r) == 0 || mpz_sgn(s) == 0));

    gmp_randclear(state);
    mpz_clears(e, k, k_inv, tmp, NULL);
    free_point(&R);
    free_affine(&R_affine);
    return status;
}

cc_status_t ecdsa_verify(const mpz_t r, const mpz_t s, const unsigned char *m, size_t m_len, const pub_key_t *pk, const public_params_t *pp, hash_func_t hash_function)
{
    mpz_t e, s_inv, u, v, r1;
    mpz_inits(e, s_inv, u, v, r1, NULL);

    cc_status_t status = ecdsa_digest(e, m, m_len, pp, hash_function);
    if (status == CC_OK && (mpz_sgn(r) <= 0 || mpz_cmp(r, pp->curve.r) >= 0 || mpz_sgn(s) <= 0 || mpz_cmp(s, pp->curve.r) >= 0))
        status = CC_ERR_VERIFY;
    if (status != CC_OK)
    {
        mpz_clears(e, s_inv, u, v, r1, NULL);
        return status;
    }

    point_t G, R, Q;
    point_affine_t R_affine;
    init_point(&G);
    init_point(&R);
    init_point(&Q);
    init_affine(&R_affine);

    // R = u * G + v * Q with u = e / s and v = r / s mod n
    mpz_invert(s_inv, s, pp->curve.r);
    mpz_mul(u, e, s_inv);
    mpz_mod(u, u, pp->curve.r);
    mpz_mul(v, r, s_inv);
    mpz_mod(v, v, pp->curve.r);

    generator(&G, pp->curve);
    mul(&R, G, u, pp->curve);
    mul(&Q, pk->Q, v, pp->curve);
    status = add(&R, R, Q, pp->curve);

    if (status == CC_OK)
    {
        to_affine(&R_affine, R, pp->curve);
        mpz_mod(r1, R_affine.x, pp->curve.r);
        if (is_infinity(R, pp->curve) || mpz_cmp(r, r1) != 0)
            status = CC_ERR_VERIFY;
    }

    mpz_clears(e, s_inv, u, v, r1, NULL);
    free_point(&G);
    free_point(&R);
    free_point(&Q);
    free_affine(&R_affine);
    return status;
}
