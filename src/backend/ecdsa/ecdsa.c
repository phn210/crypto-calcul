#include "ecdsa.h"
#include "conversion.h"
#include "rng.h"
#include "sha2.h"
#include "sha3.h"

void setup(public_params_t *pp, ec_t curve_type, unsigned char curve_id)
{
    init_curve(&pp->curve, curve_type, curve_id);
}

void keygen(priv_key_t *sk, pub_key_t *pk, const public_params_t *pp)
{
    mpz_init(sk->d);
    init_point(&pk->Q);
    generator(&pk->Q, pp->curve);

    gmp_randstate_t state;
    rng_init(state);

    mpz_urandomm(sk->d, state, pp->curve.r);
    mul(&pk->Q, pk->Q, sk->d, pp->curve);

    gmp_randclear(state);
}

void crypto_sign(mpz_t r, mpz_t s, const unsigned char *m, size_t m_len, const priv_key_t *sk, const public_params_t *pp, hash_func_t hash_function)
{
    void *(*hash)(const void *, size_t, void *, size_t);
    size_t md_len = pp->curve.md_len;
    size_t n_len = mpz_sizeinbase(pp->curve.r, 2);

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

    mpz_t e;
    point_t G, R;
    point_affine_t R_affine;
    mpz_init(e);
    init_point(&G);
    init_point(&R);
    init_affine(&R_affine);
    generator(&G, pp->curve);

    unsigned char *md = (unsigned char *)malloc(md_len);
    if (md == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    hash(m, m_len, md, md_len);

    bytes_to_bigint(e, md, md_len, BIG);
    if (n_len < md_len * 8)
    {
        mpz_tdiv_q_2exp(e, e, md_len * 8 - n_len);
    }

    gmp_randstate_t state;
    rng_init(state);

    do
    {
        mpz_t k, k_inv;
        mpz_inits(k, k_inv, NULL);

        int invertible;
        do
        {
            mpz_urandomm(k, state, pp->curve.r);
            invertible = mpz_invert(k_inv, k, pp->curve.r);
        } while (invertible == 0);

        mul(&R, G, k, pp->curve);
        to_affine(&R_affine, R, pp->curve);

        mpz_mod(r, R_affine.x, pp->curve.r);
        mpz_addmul(e, sk->d, r);
        mpz_mul(s, k_inv, e);
        mpz_mod(s, s, pp->curve.r);

        mpz_clears(k, k_inv, NULL);
    } while (mpz_sgn(r) == 0 || mpz_sgn(s) == 0);

    mpz_clear(e);
    free_point(&G);
    free_point(&R);
    free_affine(&R_affine);
    free(md);
    gmp_randclear(state);
}

int crypto_verify(const mpz_t r, const mpz_t s, const unsigned char *m, size_t m_len, const pub_key_t *pk, const public_params_t *pp, hash_func_t hash_function)
{
    void *(*hash)(const void *, size_t, void *, size_t);
    size_t md_len = pp->curve.md_len;
    size_t n_len = mpz_sizeinbase(pp->curve.r, 2);

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

    if (mpz_cmp(r, pp->curve.r) >= 0 || mpz_cmp(s, pp->curve.r) >= 0)
    {
        return 0;
    }

    mpz_t e, s_inv, u, v, r1;
    point_t G, R, Q;
    point_affine_t R_affine;
    mpz_inits(e, s_inv, u, v, r1, NULL);
    init_point(&G);
    init_point(&R);
    init_point(&Q);
    init_affine(&R_affine);
    generator(&G, pp->curve);

    unsigned char *md = (unsigned char *)malloc(md_len);
    if (md == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    hash(m, m_len, md, md_len);

    bytes_to_bigint(e, md, md_len, BIG);
    if (n_len < md_len * 8)
    {
        mpz_tdiv_q_2exp(e, e, md_len * 8 - n_len);
    }

    mpz_invert(s_inv, s, pp->curve.r);
    mpz_mul(u, e, s_inv);
    mpz_mod(u, u, pp->curve.r);
    mpz_mul(v, r, s_inv);
    mpz_mod(v, v, pp->curve.r);

    mul(&R, G, u, pp->curve);
    mul(&Q, pk->Q, v, pp->curve);
    add(&R, R, Q, pp->curve);

    if (is_infinity(R, pp->curve))
    {
        return 0;
    }

    to_affine(&R_affine, R, pp->curve);
    mpz_mod(r1, R_affine.x, pp->curve.r);

    int result = mpz_cmp(r, r1) == 0;

    mpz_clears(e, s_inv, u, v, r1, NULL);
    free_point(&G);
    free_point(&R);
    free_point(&Q);
    free_affine(&R_affine);
    free(md);

    return result;
}