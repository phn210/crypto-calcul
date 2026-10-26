#include "api_internal.h"
#include "ecdsa.h"

struct cc_ecdsa
{
    hash_func_t hash;
    public_params_t pp;
    priv_key_t sk;
    pub_key_t pk;
    int has_key;
};

cc_status_t cc_ecdsa_new(cc_ecdsa_t **ctx, cc_curve_t curve, cc_hash_t hash)
{
    if (ctx == NULL)
        return CC_ERR_INVALID_ARG;
    *ctx = NULL;

    int type;
    unsigned char id;
    hash_func_t hash_function;
    CC_TRY(api_curve(curve, &type, &id));
    CC_TRY(api_hash(hash, &hash_function));
    if (hash_function != SHA2 && hash_function != SHA3)
        return CC_ERR_INVALID_ARG;
    if (type == MONTGOMERY)
        return CC_ERR_UNSUPPORTED;

    cc_ecdsa_t *ecdsa = calloc(1, sizeof(cc_ecdsa_t));
    if (ecdsa == NULL)
        return CC_ERR_NOMEM;

    cc_status_t status = ecdsa_setup(&ecdsa->pp, (ec_t)type, id);
    if (status != CC_OK)
    {
        free(ecdsa);
        return status;
    }
    ecdsa->hash = hash_function;
    *ctx = ecdsa;
    return CC_OK;
}

void cc_ecdsa_free(cc_ecdsa_t *ctx)
{
    if (ctx == NULL)
        return;
    if (ctx->has_key)
        ecdsa_free_keys(&ctx->sk, &ctx->pk);
    ecdsa_free_params(&ctx->pp);
    free(ctx);
}

cc_status_t cc_ecdsa_keygen(cc_ecdsa_t *ctx)
{
    if (ctx == NULL)
        return CC_ERR_INVALID_ARG;
    if (ctx->has_key)
    {
        ecdsa_free_keys(&ctx->sk, &ctx->pk);
        ctx->has_key = 0;
    }
    CC_TRY(ecdsa_keygen(&ctx->sk, &ctx->pk, &ctx->pp));
    ctx->has_key = 1;
    return CC_OK;
}

static cc_status_t require_key(const cc_ecdsa_t *ctx)
{
    if (ctx == NULL)
        return CC_ERR_INVALID_ARG;
    return ctx->has_key ? CC_OK : CC_ERR_NO_KEY;
}

cc_status_t cc_ecdsa_get(const cc_ecdsa_t *ctx, cc_ec_param_t param, uint8_t *out, size_t *out_len)
{
    CC_TRY(require_key(ctx));
    switch (param)
    {
    case CC_EC_PRIVATE:
        return api_output_mpz(out, out_len, ctx->sk.d);
    case CC_EC_PUBLIC:
    {
        if (out_len == NULL)
            return CC_ERR_INVALID_ARG;
        size_t len = point_size(ctx->pp.curve), capacity = *out_len;
        *out_len = len;
        if (out == NULL || capacity < len)
            return CC_ERR_BUFFER_TOO_SMALL;
        return point_to_bytes(out, ctx->pk.Q, ctx->pp.curve);
    }
    }
    return CC_ERR_INVALID_ARG;
}

cc_status_t cc_ecdsa_sign(cc_ecdsa_t *ctx, const uint8_t *msg, size_t msg_len,
                          uint8_t *r, size_t *r_len, uint8_t *s, size_t *s_len)
{
    CC_TRY(require_key(ctx));
    if (msg == NULL && msg_len > 0)
        return CC_ERR_INVALID_ARG;

    mpz_t x1, x2;
    mpz_inits(x1, x2, NULL);
    cc_status_t status = ecdsa_sign(x1, x2, API_BYTES(msg), msg_len, &ctx->sk, &ctx->pp, ctx->hash);
    if (status == CC_OK)
        status = api_output_mpz_pair(r, r_len, x1, s, s_len, x2);
    mpz_clears(x1, x2, NULL);
    return status;
}

cc_status_t cc_ecdsa_verify(cc_ecdsa_t *ctx, const uint8_t *msg, size_t msg_len,
                            const uint8_t *r, size_t r_len, const uint8_t *s, size_t s_len)
{
    CC_TRY(require_key(ctx));
    if ((msg == NULL && msg_len > 0) || (r == NULL && r_len > 0) || (s == NULL && s_len > 0))
        return CC_ERR_INVALID_ARG;

    mpz_t x1, x2;
    mpz_inits(x1, x2, NULL);
    api_input_mpz(x1, r, r_len);
    api_input_mpz(x2, s, s_len);
    cc_status_t status = ecdsa_verify(x1, x2, API_BYTES(msg), msg_len, &ctx->pk, &ctx->pp, ctx->hash);
    mpz_clears(x1, x2, NULL);
    return status;
}
