#include "elgamal.h"
#include "conversion.h"
#include "rng.h"
#include "sha2.h"

static cc_status_t elgamal_hash(mpz_t h, const unsigned char *m, size_t m_len, sec_level_t sec_level)
{
    unsigned char md[SHA256_DIGEST_SIZE];
    size_t hash_len;
    switch (sec_level)
    {
    case L0:
        hash_len = SHA224_DIGEST_SIZE;
        break;
    case L1:
        hash_len = SHA256_DIGEST_SIZE;
        break;
    default:
        return CC_ERR_INVALID_ARG;
    }

    sha2(m, m_len, md, hash_len);
    bytes_to_bigint(h, md, hash_len, BIG);
    return CC_OK;
}

cc_status_t elgamal_sign(mpz_t r, mpz_t s, const unsigned char *m, size_t m_len, const priv_key_t *sk, const public_params_t *pp, sec_level_t sec_level)
{
    mpz_t k, k_inv, h, p1, tmp;
    mpz_inits(k, k_inv, h, p1, tmp, NULL);

    cc_status_t status = elgamal_hash(h, m, m_len, sec_level);
    gmp_randstate_t state;
    if (status == CC_OK)
        status = rng_init(state);
    if (status == CC_OK)
    {
        mpz_sub_ui(p1, pp->p, 1);

        // k in [1, p - 1) and invertible mod p - 1
        int invertible = 0;
        while (status == CC_OK && !invertible)
        {
            status = rand_int_nonzero(k, state, p1);
            invertible = status == CC_OK && mpz_invert(k_inv, k, p1);
        }
        gmp_randclear(state);
    }
    if (status == CC_OK)
    {
        // r = g^k mod p
        mpz_powm(r, pp->g, k, pp->p);

        // s = k^-1 * (h - r * x) mod (p - 1)
        mpz_mul(tmp, r, sk->x);
        mpz_sub(tmp, h, tmp);
        mpz_mul(s, k_inv, tmp);
        mpz_mod(s, s, p1);
    }

    mpz_clears(k, k_inv, h, p1, tmp, NULL);
    return status;
}

cc_status_t elgamal_verify(const mpz_t r, const mpz_t s, const unsigned char *m, size_t m_len, const pub_key_t *pk, const public_params_t *pp, sec_level_t sec_level)
{
    mpz_t h, v1, v2, tmp;
    mpz_inits(h, v1, v2, tmp, NULL);

    cc_status_t status = elgamal_hash(h, m, m_len, sec_level);
    if (status == CC_OK)
    {
        // 0 < r < p and 0 <= s < p - 1, otherwise signatures can be forged
        mpz_sub_ui(tmp, pp->p, 1);
        if (mpz_sgn(r) <= 0 || mpz_cmp(r, pp->p) >= 0 || mpz_sgn(s) < 0 || mpz_cmp(s, tmp) >= 0)
            status = CC_ERR_VERIFY;
    }
    if (status == CC_OK)
    {
        // v1 = y^r * r^s mod p
        mpz_powm(v1, pk->y, r, pp->p);
        mpz_powm(tmp, r, s, pp->p);
        mpz_mul(v1, v1, tmp);
        mpz_mod(v1, v1, pp->p);

        // v2 = g^h mod p
        mpz_powm(v2, pp->g, h, pp->p);

        if (mpz_cmp(v1, v2) != 0)
            status = CC_ERR_VERIFY;
    }

    mpz_clears(h, v1, v2, tmp, NULL);
    return status;
}
