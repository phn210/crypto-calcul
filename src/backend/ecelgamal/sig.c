#include "ecelgamal.h"
#include "conversion.h"
#include "rng.h"
#include "sha2.h"
#include "sha3.h"

void crypto_sign(mpz_t s1, mpz_t s2, const unsigned char *m, size_t m_len, const priv_key_t *sk, const public_params_t *pp, hash_func_t hash_function)
{
    void *(*hash)(const void *, size_t, void *, size_t);
    size_t md_len = pp->curve.md_len;

    switch (hash_function)
    {
    case SHA2:
        hash = &sha2;
        break;
    case SHA3:
        hash = &sha3;
        break;
    default:
        fprintf(stderr, "Invalid hash function\n");
        exit(EXIT_FAILURE);
    }

    mpz_t k, k_inv, h, tmp;
    point_t R;
    point_affine_t tmp_affine;

    mpz_inits(k, k_inv, h, tmp, NULL);
    init_point(&R);
    init_affine(&tmp_affine);
    gmp_randstate_t state;
    rng_init(state);
    unsigned char *buf = (unsigned char *)malloc(md_len);
    if (buf == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    // h = H(m)
    hash(m, m_len, buf, md_len);
    bytes_to_bigint(h, buf, md_len, BIG);
    int invertible;
    do
    {
        // Generate random k
        rand_int_m(k, state, pp->curve.r);

        // R = k * G
        generator(&R, pp->curve);
        mul(&R, R, k, pp->curve);
        to_affine(&tmp_affine, R, pp->curve);
        from_affine(&R, tmp_affine, pp->curve);

        // s1 = R.x mod r
        mpz_mod(s1, R.x, pp->curve.r);

        // s2 = (h + s1 * x) / k mod r
        mpz_set(tmp, h);
        mpz_addmul(tmp, s1, sk->x);
        mpz_mod(tmp, tmp, pp->curve.r);

        invertible = mpz_invert(k_inv, k, pp->curve.r);
        mpz_mul(s2, k_inv, tmp);
        mpz_mod(s2, s2, pp->curve.r);

    } while (mpz_cmp_ui(s1, 0) == 0 || mpz_cmp_ui(s2, 0) == 0 || invertible == 0);

    mpz_clears(k, h, tmp, NULL);
    free_point(&R);
    free_affine(&tmp_affine);
    free(buf);
}

char crypto_verify(const mpz_t s1, const mpz_t s2, const unsigned char *m, size_t m_len, const pub_key_t *pk, const public_params_t *pp, hash_func_t hash_function)
{
    void *(*hash)(const void *, size_t, void *, size_t);
    size_t md_len = pp->curve.md_len;

    switch (hash_function)
    {
    case SHA2:
        hash = &sha2;
        break;
    case SHA3:
        hash = &sha3;
        break;
    default:
        fprintf(stderr, "Invalid hash function\n");
        exit(EXIT_FAILURE);
    }

    mpz_t h, s2_inv, u1, u2, tmp;
    point_t R, P;
    point_affine_t tmp_affine;

    mpz_inits(h, s2_inv, u1, u2, tmp, NULL);
    init_point(&R);
    init_point(&P);
    init_affine(&tmp_affine);
    unsigned char *buf = (unsigned char *)malloc(md_len);
    if (buf == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    // h = H(m)
    hash(m, m_len, buf, md_len);
    bytes_to_bigint(h, buf, md_len, BIG);

    // u1 = h / s2 mod r
    mpz_invert(s2_inv, s2, pp->curve.r);
    mpz_mul(u1, h, s2_inv);
    mpz_mod(u1, u1, pp->curve.r);

    // u2 = s1 / s2 mod r
    mpz_mul(u2, s1, s2_inv);
    mpz_mod(u2, u2, pp->curve.r);

    // R = u1 * G + u2 * Y
    generator(&R, pp->curve);
    mul(&R, R, u1, pp->curve);
    mul(&P, pk->Y, u2, pp->curve);
    add(&R, R, P, pp->curve);
    to_affine(&tmp_affine, R, pp->curve);
    from_affine(&R, tmp_affine, pp->curve);

    // tmp = R.x mod r
    mpz_mod(tmp, R.x, pp->curve.r);

    char result = mpz_cmp(tmp, s1) == 0;

    free_point(&R);
    free_point(&P);
    free(buf);
    mpz_clears(h, s2_inv, u1, u2, tmp, NULL);

    return result;
}