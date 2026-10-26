#include "ecelgamal.h"
#include "conversion.h"
#include "rng.h"

#define MAX_MD_LEN 64

cc_status_t ecelgamal_sign(mpz_t s1, mpz_t s2, const unsigned char *m, size_t m_len, const priv_key_t *sk, const public_params_t *pp, hash_func_t hash_function)
{
    void *(*hash)(const void *, size_t, void *, size_t);
    CC_TRY(ec_hash_function(hash_function, &hash));
    if (pp->curve.type == MONTGOMERY)
        return CC_ERR_UNSUPPORTED;

    gmp_randstate_t state;
    CC_TRY(rng_init(state));

    mpz_t k, k_inv, h, tmp;
    point_t R;
    point_affine_t R_affine;
    unsigned char md[MAX_MD_LEN];
    mpz_inits(k, k_inv, h, tmp, NULL);
    init_point(&R);
    init_affine(&R_affine);

    // h = H(m)
    hash(m, m_len, md, pp->curve.md_len);
    bytes_to_bigint(h, md, pp->curve.md_len, BIG);

    cc_status_t status;
    int invertible;
    do
    {
        // R = kG with k in [1, r)
        status = rand_int_nonzero(k, state, pp->curve.r);
        if (status != CC_OK)
            break;
        generator(&R, pp->curve);
        mul(&R, R, k, pp->curve);
        to_affine(&R_affine, R, pp->curve);

        // s1 = R.x mod r
        mpz_mod(s1, R_affine.x, pp->curve.r);

        // s2 = (h + s1 * x) / k mod r
        mpz_set(tmp, h);
        mpz_addmul(tmp, s1, sk->x);
        mpz_mod(tmp, tmp, pp->curve.r);

        invertible = mpz_invert(k_inv, k, pp->curve.r);
        mpz_mul(s2, k_inv, tmp);
        mpz_mod(s2, s2, pp->curve.r);
    } while (mpz_sgn(s1) == 0 || mpz_sgn(s2) == 0 || invertible == 0);

    gmp_randclear(state);
    mpz_clears(k, k_inv, h, tmp, NULL);
    free_point(&R);
    free_affine(&R_affine);
    return status;
}

cc_status_t ecelgamal_verify(const mpz_t s1, const mpz_t s2, const unsigned char *m, size_t m_len, const pub_key_t *pk, const public_params_t *pp, hash_func_t hash_function)
{
    void *(*hash)(const void *, size_t, void *, size_t);
    CC_TRY(ec_hash_function(hash_function, &hash));
    if (pp->curve.type == MONTGOMERY)
        return CC_ERR_UNSUPPORTED;
    if (mpz_sgn(s1) <= 0 || mpz_cmp(s1, pp->curve.r) >= 0 || mpz_sgn(s2) <= 0 || mpz_cmp(s2, pp->curve.r) >= 0)
        return CC_ERR_VERIFY;

    mpz_t h, s2_inv, u1, u2, tmp;
    point_t R, P;
    point_affine_t R_affine;
    unsigned char md[MAX_MD_LEN];
    mpz_inits(h, s2_inv, u1, u2, tmp, NULL);
    init_point(&R);
    init_point(&P);
    init_affine(&R_affine);

    // h = H(m)
    hash(m, m_len, md, pp->curve.md_len);
    bytes_to_bigint(h, md, pp->curve.md_len, BIG);

    // u1 = h / s2 mod r, u2 = s1 / s2 mod r
    mpz_invert(s2_inv, s2, pp->curve.r);
    mpz_mul(u1, h, s2_inv);
    mpz_mod(u1, u1, pp->curve.r);
    mpz_mul(u2, s1, s2_inv);
    mpz_mod(u2, u2, pp->curve.r);

    // R = u1 * G + u2 * Y
    generator(&R, pp->curve);
    mul(&R, R, u1, pp->curve);
    mul(&P, pk->Y, u2, pp->curve);
    cc_status_t status = add(&R, R, P, pp->curve);
    if (status == CC_OK)
    {
        to_affine(&R_affine, R, pp->curve);
        mpz_mod(tmp, R_affine.x, pp->curve.r);
        if (is_infinity(R, pp->curve) || mpz_cmp(tmp, s1) != 0)
            status = CC_ERR_VERIFY;
    }

    free_point(&R);
    free_point(&P);
    free_affine(&R_affine);
    mpz_clears(h, s2_inv, u1, u2, tmp, NULL);
    return status;
}
