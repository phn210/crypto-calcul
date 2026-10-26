#include "ecelgamal.h"
#include "rng.h"

#define MAX_MD_LEN 64

cc_status_t ecelgamal_setup(public_params_t *pp, ec_t curve_type, unsigned char curve_id)
{
    return init_curve(&pp->curve, curve_type, curve_id);
}

void ecelgamal_free_params(public_params_t *pp)
{
    free_curve(&pp->curve);
}

cc_status_t ecelgamal_keygen(priv_key_t *sk, pub_key_t *pk, const public_params_t *pp)
{
    gmp_randstate_t state;
    CC_TRY(rng_init(state));
    mpz_init(sk->x);
    init_point(&pk->Y);

    // x in [1, r), Y = xG
    cc_status_t status = rand_int_nonzero(sk->x, state, pp->curve.r);
    if (status == CC_OK)
    {
        generator(&pk->Y, pp->curve);
        mul(&pk->Y, pk->Y, sk->x, pp->curve);
    }
    else
        ecelgamal_free_keys(sk, pk);

    gmp_randclear(state);
    return status;
}

void ecelgamal_free_keys(priv_key_t *sk, pub_key_t *pk)
{
    mpz_clear(sk->x);
    free_point(&pk->Y);
}

// h = H(encoding of the shared point), curve.md_len bytes
static cc_status_t shared_mask(unsigned char *h, const point_t shared, const public_params_t *pp, void *(*hash)(const void *, size_t, void *, size_t))
{
    size_t len = point_size(pp->curve);
    unsigned char *buf = malloc(len);
    if (buf == NULL)
        return CC_ERR_NOMEM;

    cc_status_t status = point_to_bytes(buf, shared, pp->curve);
    if (status == CC_OK)
        hash(buf, len, h, pp->curve.md_len);

    free(buf);
    return status;
}

cc_status_t ecelgamal_encrypt(unsigned char *c1, unsigned char *c2, const unsigned char *m, size_t m_len,
                              const pub_key_t *pk, const public_params_t *pp, hash_func_t hash_function)
{
    void *(*hash)(const void *, size_t, void *, size_t);
    CC_TRY(ec_hash_function(hash_function, &hash));
    if (m_len > pp->curve.md_len)
        return CC_ERR_MSG_TOO_LONG;

    gmp_randstate_t state;
    CC_TRY(rng_init(state));

    mpz_t k;
    point_t C1, S;
    unsigned char h[MAX_MD_LEN];
    mpz_init(k);
    init_point(&C1);
    init_point(&S);

    // C1 = kG, S = kY with k in [1, r)
    cc_status_t status = rand_int_nonzero(k, state, pp->curve.r);
    if (status == CC_OK)
    {
        generator(&C1, pp->curve);
        mul(&C1, C1, k, pp->curve);
        status = point_to_bytes(c1, C1, pp->curve);
    }
    if (status == CC_OK)
    {
        mul(&S, pk->Y, k, pp->curve);
        status = shared_mask(h, S, pp, hash);
    }
    if (status == CC_OK)
    {
        for (size_t i = 0; i < m_len; i++)
            c2[i] = m[i] ^ h[i];
    }

    gmp_randclear(state);
    mpz_clear(k);
    free_point(&C1);
    free_point(&S);
    return status;
}

cc_status_t ecelgamal_decrypt(unsigned char *m, const unsigned char *c1, size_t c1_len, const unsigned char *c2, size_t c2_len,
                              const priv_key_t *sk, const public_params_t *pp, hash_func_t hash_function)
{
    void *(*hash)(const void *, size_t, void *, size_t);
    CC_TRY(ec_hash_function(hash_function, &hash));
    if (c1_len != point_size(pp->curve) || c2_len > pp->curve.md_len)
        return CC_ERR_INVALID_INPUT;

    point_t S;
    unsigned char h[MAX_MD_LEN];
    init_point(&S);

    // S = x * C1, with C1 a valid point
    cc_status_t status = CC_OK;
    point_from_bytes(&S, c1, pp->curve);
    if (!is_valid_point(S, pp->curve))
        status = CC_ERR_INVALID_INPUT;
    if (status == CC_OK)
    {
        mul(&S, S, sk->x, pp->curve);
        status = shared_mask(h, S, pp, hash);
    }
    if (status == CC_OK)
    {
        for (size_t i = 0; i < c2_len; i++)
            m[i] = c2[i] ^ h[i];
    }

    free_point(&S);
    return status;
}
