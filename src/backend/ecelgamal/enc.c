#include "ecelgamal.h"
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
    mpz_init(sk->x);
    init_point(&pk->Y);
    generator(&pk->Y, pp->curve);

    gmp_randstate_t state;
    rng_init(state);

    rand_int_m(sk->x, state, pp->curve.r);
    mul(&pk->Y, pk->Y, sk->x, pp->curve);

    gmp_randclear(state);
}

void crypto_encrypt(mpz_t c1, mpz_t c2, const mpz_t m, const pub_key_t *pk, const public_params_t *pp, hash_func_t hash_function)
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

    mpz_t k;
    point_t C1, tmp;
    mpz_inits(k, NULL);
    init_point(&C1);
    init_point(&tmp);
    size_t m_len = count_bytes(m);
    size_t buf_len = 2 * pp->curve.efs;
    unsigned char *buf_point = (unsigned char *)malloc(buf_len);
    if (buf_point == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    // Generate random k
    gmp_randstate_t state;
    rng_init(state);
    rand_int_m(k, state, pp->curve.r);

    // C1 = k * G
    generator(&tmp, pp->curve);
    mpz_urandomm(k, state, pp->curve.r);
    mul(&C1, tmp, k, pp->curve);
    point_to_bytes(buf_point, C1, pp->curve);
    bytes_to_bigint(c1, buf_point, buf_len, BIG);

    unsigned char *buf_m = (unsigned char *)malloc(m_len);
    if (buf_m == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    bigint_to_bytes(buf_m, &m_len, m, BIG);

    // k * Y
    mul(&tmp, pk->Y, k, pp->curve);
    point_to_bytes(buf_point, tmp, pp->curve);

    unsigned char *h = (unsigned char *)malloc(md_len);
    if (h == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    hash(buf_point, buf_len, h, md_len);

    for (size_t i = 0; i < m_len; i++)
    {
        buf_m[i] = buf_m[i] ^ h[i];
    }
    bytes_to_bigint(c2, buf_m, m_len, BIG);

    gmp_randclear(state);
    mpz_clear(k);
    free_point(&C1);
    free_point(&tmp);
    free(buf_m);
    free(buf_point);
    free(h);
}

void crypto_decrypt(mpz_t m, const mpz_t c1, const mpz_t c2, const priv_key_t *sk, const public_params_t *pp, hash_func_t hash_function)
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

    point_t tmp;
    init_point(&tmp);
    size_t buf_len = 2 * pp->curve.efs;
    unsigned char *buf_point = (unsigned char *)malloc(buf_len);
    if (buf_point == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    bigint_to_bytes(buf_point, &buf_len, c1, BIG);
    point_from_bytes(&tmp, buf_point, pp->curve);
    mul(&tmp, tmp, sk->x, pp->curve);
    point_to_bytes(buf_point, tmp, pp->curve);

    unsigned char *h = (unsigned char *)malloc(md_len);
    if (h == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    hash(buf_point, buf_len, h, md_len);

    size_t m_len = count_bytes(c2);
    unsigned char *buf_m = (unsigned char *)malloc(m_len);
    if (buf_m == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    bigint_to_bytes(buf_m, &m_len, c2, BIG);

    for (size_t i = 0; i < m_len; i++)
    {
        buf_m[i] = buf_m[i] ^ h[i];
    }
    bytes_to_bigint(m, buf_m, m_len, BIG);

    free_point(&tmp);
    free(buf_m);
    free(buf_point);
    free(h);
}