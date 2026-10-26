#include "api_internal.h"
#include "dsa.h"

struct cc_dsa
{
    public_params_t pp;
    priv_key_t sk;
    pub_key_t pk;
    int has_key;
};

cc_status_t cc_dsa_new(cc_dsa_t **ctx, cc_sec_level_t level, cc_hash_t hash)
{
    if (ctx == NULL)
        return CC_ERR_INVALID_ARG;
    *ctx = NULL;

    sec_level_t sec_level;
    hash_func_t hash_function;
    CC_TRY(api_sec_level(level, &sec_level));
    CC_TRY(api_hash(hash, &hash_function));

    cc_dsa_t *dsa = calloc(1, sizeof(cc_dsa_t));
    if (dsa == NULL)
        return CC_ERR_NOMEM;

    cc_status_t status = dsa_setup(&dsa->pp, sec_level, hash_function);
    if (status != CC_OK)
    {
        free(dsa);
        return status;
    }
    *ctx = dsa;
    return CC_OK;
}

void cc_dsa_free(cc_dsa_t *ctx)
{
    if (ctx == NULL)
        return;
    if (ctx->has_key)
        dsa_free_keys(&ctx->sk, &ctx->pk);
    dsa_free_params(&ctx->pp);
    free(ctx);
}

cc_status_t cc_dsa_keygen(cc_dsa_t *ctx)
{
    if (ctx == NULL)
        return CC_ERR_INVALID_ARG;
    if (ctx->has_key)
    {
        dsa_free_keys(&ctx->sk, &ctx->pk);
        ctx->has_key = 0;
    }
    CC_TRY(dsa_keygen(&ctx->sk, &ctx->pk, &ctx->pp));
    ctx->has_key = 1;
    return CC_OK;
}

static cc_status_t require_key(const cc_dsa_t *ctx)
{
    if (ctx == NULL)
        return CC_ERR_INVALID_ARG;
    return ctx->has_key ? CC_OK : CC_ERR_NO_KEY;
}

cc_status_t cc_dsa_get(const cc_dsa_t *ctx, cc_dl_param_t param, uint8_t *out, size_t *out_len)
{
    if (ctx == NULL)
        return CC_ERR_INVALID_ARG;
    switch (param)
    {
    case CC_DL_P:
        return api_output_mpz(out, out_len, ctx->pp.p);
    case CC_DL_Q:
        return api_output_mpz(out, out_len, ctx->pp.q);
    case CC_DL_G:
        return api_output_mpz(out, out_len, ctx->pp.g);
    case CC_DL_X:
        CC_TRY(require_key(ctx));
        return api_output_mpz(out, out_len, ctx->sk.x);
    case CC_DL_Y:
        CC_TRY(require_key(ctx));
        return api_output_mpz(out, out_len, ctx->pk.y);
    }
    return CC_ERR_INVALID_ARG;
}

cc_status_t cc_dsa_sign(cc_dsa_t *ctx, const uint8_t *msg, size_t msg_len,
                        uint8_t *r, size_t *r_len, uint8_t *s, size_t *s_len)
{
    CC_TRY(require_key(ctx));
    if (msg == NULL && msg_len > 0)
        return CC_ERR_INVALID_ARG;

    mpz_t x1, x2;
    mpz_inits(x1, x2, NULL);
    cc_status_t status = dsa_sign(x1, x2, API_BYTES(msg), msg_len, &ctx->sk, &ctx->pp);
    if (status == CC_OK)
        status = api_output_mpz_pair(r, r_len, x1, s, s_len, x2);
    mpz_clears(x1, x2, NULL);
    return status;
}

cc_status_t cc_dsa_verify(cc_dsa_t *ctx, const uint8_t *msg, size_t msg_len,
                          const uint8_t *r, size_t r_len, const uint8_t *s, size_t s_len)
{
    CC_TRY(require_key(ctx));
    if ((msg == NULL && msg_len > 0) || (r == NULL && r_len > 0) || (s == NULL && s_len > 0))
        return CC_ERR_INVALID_ARG;

    mpz_t x1, x2;
    mpz_inits(x1, x2, NULL);
    api_input_mpz(x1, r, r_len);
    api_input_mpz(x2, s, s_len);
    cc_status_t status = dsa_verify(x1, x2, API_BYTES(msg), msg_len, &ctx->pk, &ctx->pp);
    mpz_clears(x1, x2, NULL);
    return status;
}
