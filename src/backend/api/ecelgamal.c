#include "api_internal.h"
#include "ecdh.h"

struct cc_ecelgamal
{
    hash_func_t hash;
    public_params_t pp;
    priv_key_t sk;
    pub_key_t pk;
    int has_key;
};

static cc_status_t curve_params(cc_curve_t curve, public_params_t *pp)
{
    int type;
    unsigned char id;
    CC_TRY(api_curve(curve, &type, &id));
    return ecelgamal_setup(pp, (ec_t)type, id);
}

// Writes the encoding of a point (point_size bytes)
static cc_status_t output_point(uint8_t *out, size_t *out_len, const point_t p, const curve_t curve)
{
    if (out_len == NULL)
        return CC_ERR_INVALID_ARG;
    size_t len = point_size(curve), capacity = *out_len;
    *out_len = len;
    if (out == NULL || capacity < len)
        return CC_ERR_BUFFER_TOO_SMALL;
    return point_to_bytes(out, p, curve);
}

cc_status_t cc_ecelgamal_new(cc_ecelgamal_t **ctx, cc_curve_t curve, cc_hash_t hash)
{
    if (ctx == NULL)
        return CC_ERR_INVALID_ARG;
    *ctx = NULL;

    hash_func_t hash_function;
    CC_TRY(api_hash(hash, &hash_function));
    if (hash_function != SHA2 && hash_function != SHA3)
        return CC_ERR_INVALID_ARG;

    cc_ecelgamal_t *ecelgamal = calloc(1, sizeof(cc_ecelgamal_t));
    if (ecelgamal == NULL)
        return CC_ERR_NOMEM;

    cc_status_t status = curve_params(curve, &ecelgamal->pp);
    if (status != CC_OK)
    {
        free(ecelgamal);
        return status;
    }
    ecelgamal->hash = hash_function;
    *ctx = ecelgamal;
    return CC_OK;
}

void cc_ecelgamal_free(cc_ecelgamal_t *ctx)
{
    if (ctx == NULL)
        return;
    if (ctx->has_key)
        ecelgamal_free_keys(&ctx->sk, &ctx->pk);
    ecelgamal_free_params(&ctx->pp);
    free(ctx);
}

cc_status_t cc_ecelgamal_keygen(cc_ecelgamal_t *ctx)
{
    if (ctx == NULL)
        return CC_ERR_INVALID_ARG;
    if (ctx->has_key)
    {
        ecelgamal_free_keys(&ctx->sk, &ctx->pk);
        ctx->has_key = 0;
    }
    CC_TRY(ecelgamal_keygen(&ctx->sk, &ctx->pk, &ctx->pp));
    ctx->has_key = 1;
    return CC_OK;
}

static cc_status_t require_key(const cc_ecelgamal_t *ctx)
{
    if (ctx == NULL)
        return CC_ERR_INVALID_ARG;
    return ctx->has_key ? CC_OK : CC_ERR_NO_KEY;
}

cc_status_t cc_ecelgamal_get(const cc_ecelgamal_t *ctx, cc_ec_param_t param, uint8_t *out, size_t *out_len)
{
    CC_TRY(require_key(ctx));
    switch (param)
    {
    case CC_EC_PRIVATE:
        return api_output_mpz(out, out_len, ctx->sk.x);
    case CC_EC_PUBLIC:
        return output_point(out, out_len, ctx->pk.Y, ctx->pp.curve);
    }
    return CC_ERR_INVALID_ARG;
}

cc_status_t cc_ecelgamal_encrypt(cc_ecelgamal_t *ctx, const uint8_t *msg, size_t msg_len,
                                 uint8_t *c1, size_t *c1_len, uint8_t *c2, size_t *c2_len)
{
    CC_TRY(require_key(ctx));
    if ((msg == NULL && msg_len > 0) || c1_len == NULL || c2_len == NULL)
        return CC_ERR_INVALID_ARG;
    if (msg_len > ctx->pp.curve.md_len)
        return CC_ERR_MSG_TOO_LONG;

    size_t c1_capacity = *c1_len, c2_capacity = *c2_len;
    *c1_len = point_size(ctx->pp.curve);
    *c2_len = msg_len;
    if (c1 == NULL || (c2 == NULL && msg_len > 0) || c1_capacity < *c1_len || c2_capacity < *c2_len)
        return CC_ERR_BUFFER_TOO_SMALL;

    unsigned char empty;
    return ecelgamal_encrypt(c1, c2 != NULL ? c2 : &empty, API_BYTES(msg), msg_len, &ctx->pk, &ctx->pp, ctx->hash);
}

cc_status_t cc_ecelgamal_decrypt(cc_ecelgamal_t *ctx, const uint8_t *c1, size_t c1_len, const uint8_t *c2, size_t c2_len,
                                 uint8_t *out, size_t *out_len)
{
    CC_TRY(require_key(ctx));
    if (c1 == NULL || (c2 == NULL && c2_len > 0) || out_len == NULL)
        return CC_ERR_INVALID_ARG;

    size_t capacity = *out_len;
    *out_len = c2_len;
    if ((out == NULL && c2_len > 0) || capacity < c2_len)
        return CC_ERR_BUFFER_TOO_SMALL;

    unsigned char empty;
    return ecelgamal_decrypt(out != NULL ? out : &empty, c1, c1_len, API_BYTES(c2), c2_len, &ctx->sk, &ctx->pp, ctx->hash);
}

cc_status_t cc_ecelgamal_sign(cc_ecelgamal_t *ctx, const uint8_t *msg, size_t msg_len,
                              uint8_t *r, size_t *r_len, uint8_t *s, size_t *s_len)
{
    CC_TRY(require_key(ctx));
    if (msg == NULL && msg_len > 0)
        return CC_ERR_INVALID_ARG;

    mpz_t x1, x2;
    mpz_inits(x1, x2, NULL);
    cc_status_t status = ecelgamal_sign(x1, x2, API_BYTES(msg), msg_len, &ctx->sk, &ctx->pp, ctx->hash);
    if (status == CC_OK)
        status = api_output_mpz_pair(r, r_len, x1, s, s_len, x2);
    mpz_clears(x1, x2, NULL);
    return status;
}

cc_status_t cc_ecelgamal_verify(cc_ecelgamal_t *ctx, const uint8_t *msg, size_t msg_len,
                                const uint8_t *r, size_t r_len, const uint8_t *s, size_t s_len)
{
    CC_TRY(require_key(ctx));
    if ((msg == NULL && msg_len > 0) || (r == NULL && r_len > 0) || (s == NULL && s_len > 0))
        return CC_ERR_INVALID_ARG;

    mpz_t x1, x2;
    mpz_inits(x1, x2, NULL);
    api_input_mpz(x1, r, r_len);
    api_input_mpz(x2, s, s_len);
    cc_status_t status = ecelgamal_verify(x1, x2, API_BYTES(msg), msg_len, &ctx->pk, &ctx->pp, ctx->hash);
    mpz_clears(x1, x2, NULL);
    return status;
}

/* ------------------------------------------------------------------------- */
/* ECDH                                                                      */
/* ------------------------------------------------------------------------- */

cc_status_t cc_ecdh_generate_secret(cc_curve_t curve, uint8_t *secret, size_t *secret_len)
{
    public_params_t pp;
    CC_TRY(curve_params(curve, &pp));

    mpz_t x;
    mpz_init(x);
    cc_status_t status = ecdh_gen_secret(x, &pp);
    if (status == CC_OK)
        status = api_output_mpz(secret, secret_len, x);

    mpz_clear(x);
    ecelgamal_free_params(&pp);
    return status;
}

cc_status_t cc_ecdh_public(cc_curve_t curve, const uint8_t *secret, size_t secret_len,
                           uint8_t *pub, size_t *pub_len)
{
    if ((secret == NULL && secret_len > 0) || pub_len == NULL)
        return CC_ERR_INVALID_ARG;
    public_params_t pp;
    CC_TRY(curve_params(curve, &pp));

    // Public values are fixed-size point encodings
    size_t len = point_size(pp.curve), capacity = *pub_len;
    *pub_len = len;
    cc_status_t status = pub == NULL || capacity < len ? CC_ERR_BUFFER_TOO_SMALL : CC_OK;

    mpz_t x, y;
    mpz_inits(x, y, NULL);
    api_input_mpz(x, secret, secret_len);
    if (status == CC_OK)
        status = ecdh_gen_public(y, x, &pp);
    if (status == CC_OK)
        status = bigint_to_bytes_fixed(pub, len, y);

    mpz_clears(x, y, NULL);
    ecelgamal_free_params(&pp);
    return status;
}

cc_status_t cc_ecdh_shared_secret(cc_curve_t curve, const uint8_t *secret, size_t secret_len,
                                  const uint8_t *peer_pub, size_t peer_pub_len, uint8_t *shared, size_t *shared_len)
{
    if ((secret == NULL && secret_len > 0) || (peer_pub == NULL && peer_pub_len > 0))
        return CC_ERR_INVALID_ARG;
    public_params_t pp;
    CC_TRY(curve_params(curve, &pp));

    mpz_t x, y, z;
    mpz_inits(x, y, z, NULL);
    api_input_mpz(x, secret, secret_len);
    api_input_mpz(y, peer_pub, peer_pub_len);

    // The peer value must be a full-size point encoding
    cc_status_t status = peer_pub_len == point_size(pp.curve) ? CC_OK : CC_ERR_INVALID_INPUT;
    if (status == CC_OK)
        status = ecdh_compute_shared_secret(z, x, y, &pp);
    if (status == CC_OK)
        status = api_output_mpz(shared, shared_len, z);

    mpz_clears(x, y, z, NULL);
    ecelgamal_free_params(&pp);
    return status;
}
