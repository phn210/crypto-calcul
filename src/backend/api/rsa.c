#include "api_internal.h"
#include "rsa.h"

struct cc_rsa
{
    cc_rsa_scheme_t scheme;
    sec_level_t sec_level;
    rsa_algo_t algo;
    public_params_t pp;
    priv_key_t sk;
    pub_key_t pk;
    int has_key;
};

cc_status_t cc_rsa_new(cc_rsa_t **ctx, cc_sec_level_t level, cc_rsa_scheme_t scheme)
{
    if (ctx == NULL || (scheme != CC_RSA_TEXTBOOK && scheme != CC_RSA_PKCS1 && scheme != CC_RSA_OAEP_PSS))
        return CC_ERR_INVALID_ARG;
    *ctx = NULL;

    cc_rsa_t *rsa = calloc(1, sizeof(cc_rsa_t));
    if (rsa == NULL)
        return CC_ERR_NOMEM;

    cc_status_t status = api_sec_level(level, &rsa->sec_level);
    if (status == CC_OK)
        status = rsa_setup(&rsa->pp, rsa->sec_level);
    if (status != CC_OK)
    {
        free(rsa);
        return status;
    }

    rsa->scheme = scheme;
    rsa->algo = RSA_CRT;
    *ctx = rsa;
    return CC_OK;
}

void cc_rsa_free(cc_rsa_t *ctx)
{
    if (ctx == NULL)
        return;
    if (ctx->has_key)
        rsa_free_keys(&ctx->sk, &ctx->pk);
    rsa_free_params(&ctx->pp);
    free(ctx);
}

cc_status_t cc_rsa_keygen(cc_rsa_t *ctx)
{
    if (ctx == NULL)
        return CC_ERR_INVALID_ARG;
    if (ctx->has_key)
    {
        rsa_free_keys(&ctx->sk, &ctx->pk);
        ctx->has_key = 0;
    }
    CC_TRY(rsa_keygen(&ctx->sk, &ctx->pk, &ctx->pp));
    ctx->has_key = 1;
    return CC_OK;
}

cc_status_t cc_rsa_use_crt(cc_rsa_t *ctx, int use_crt)
{
    if (ctx == NULL)
        return CC_ERR_INVALID_ARG;
    ctx->algo = use_crt ? RSA_CRT : RSA_STANDARD;
    return CC_OK;
}

static cc_status_t require_key(const cc_rsa_t *ctx)
{
    if (ctx == NULL)
        return CC_ERR_INVALID_ARG;
    return ctx->has_key ? CC_OK : CC_ERR_NO_KEY;
}

cc_status_t cc_rsa_size(const cc_rsa_t *ctx, size_t *size)
{
    CC_TRY(require_key(ctx));
    if (size == NULL)
        return CC_ERR_INVALID_ARG;
    *size = rsa_modulus_size(ctx->pk.n);
    return CC_OK;
}

cc_status_t cc_rsa_get(const cc_rsa_t *ctx, cc_rsa_param_t param, uint8_t *out, size_t *out_len)
{
    CC_TRY(require_key(ctx));
    switch (param)
    {
    case CC_RSA_N:
        return api_output_mpz(out, out_len, ctx->pk.n);
    case CC_RSA_E:
        return api_output_mpz(out, out_len, ctx->pk.e);
    case CC_RSA_D:
        return api_output_mpz(out, out_len, ctx->sk.d);
    case CC_RSA_P:
        return api_output_mpz(out, out_len, ctx->sk.p);
    case CC_RSA_Q:
        return api_output_mpz(out, out_len, ctx->sk.q);
    case CC_RSA_DP:
        return api_output_mpz(out, out_len, ctx->sk.dp);
    case CC_RSA_DQ:
        return api_output_mpz(out, out_len, ctx->sk.dq);
    case CC_RSA_QINV:
        return api_output_mpz(out, out_len, ctx->sk.q_inv);
    }
    return CC_ERR_INVALID_ARG;
}

cc_status_t cc_rsa_encrypt(cc_rsa_t *ctx, const uint8_t *msg, size_t msg_len, uint8_t *out, size_t *out_len)
{
    CC_TRY(require_key(ctx));
    if (out_len == NULL || (msg == NULL && msg_len > 0))
        return CC_ERR_INVALID_ARG;
    msg = API_BYTES(msg);

    if (ctx->scheme == CC_RSA_TEXTBOOK)
    {
        mpz_t m, c;
        mpz_inits(m, c, NULL);
        api_input_mpz(m, msg, msg_len);
        cc_status_t status = rsa_encrypt(c, m, &ctx->pk);
        if (status == CC_OK)
            status = api_output_mpz(out, out_len, c);
        mpz_clears(m, c, NULL);
        return status;
    }

    size_t k = rsa_modulus_size(ctx->pk.n);
    size_t capacity = *out_len;
    *out_len = k;
    if (out == NULL || capacity < k)
        return CC_ERR_BUFFER_TOO_SMALL;
    if (ctx->scheme == CC_RSA_PKCS1)
        return rsa_encrypt_pkcs1(out, msg, msg_len, &ctx->pk);
    return rsa_encrypt_oaep(out, msg, msg_len, &ctx->pk, ctx->sec_level);
}

cc_status_t cc_rsa_decrypt(cc_rsa_t *ctx, const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len)
{
    CC_TRY(require_key(ctx));
    if (out_len == NULL || (in == NULL && in_len > 0))
        return CC_ERR_INVALID_ARG;
    in = API_BYTES(in);

    if (ctx->scheme == CC_RSA_TEXTBOOK)
    {
        mpz_t m, c;
        mpz_inits(m, c, NULL);
        api_input_mpz(c, in, in_len);
        cc_status_t status = rsa_decrypt(m, c, &ctx->sk, ctx->algo);
        if (status == CC_OK)
            status = api_output_mpz(out, out_len, m);
        mpz_clears(m, c, NULL);
        return status;
    }

    size_t k = rsa_modulus_size(ctx->pk.n), m_len = 0;
    unsigned char *m = malloc(k);
    if (m == NULL)
        return CC_ERR_NOMEM;

    cc_status_t status;
    if (ctx->scheme == CC_RSA_PKCS1)
        status = rsa_decrypt_pkcs1(m, &m_len, in, in_len, &ctx->sk, ctx->algo);
    else
        status = rsa_decrypt_oaep(m, &m_len, in, in_len, &ctx->sk, ctx->algo, ctx->sec_level);
    if (status == CC_OK)
        status = api_output(out, out_len, m, m_len);

    free(m);
    return status;
}

cc_status_t cc_rsa_sign(cc_rsa_t *ctx, const uint8_t *msg, size_t msg_len, uint8_t *sig, size_t *sig_len)
{
    CC_TRY(require_key(ctx));
    if (sig_len == NULL || (msg == NULL && msg_len > 0))
        return CC_ERR_INVALID_ARG;
    msg = API_BYTES(msg);

    if (ctx->scheme == CC_RSA_TEXTBOOK)
    {
        mpz_t m, s;
        mpz_inits(m, s, NULL);
        api_input_mpz(m, msg, msg_len);
        cc_status_t status = rsa_sign(s, m, &ctx->sk, ctx->algo);
        if (status == CC_OK)
            status = api_output_mpz(sig, sig_len, s);
        mpz_clears(m, s, NULL);
        return status;
    }

    size_t k = rsa_modulus_size(ctx->pk.n);
    size_t capacity = *sig_len;
    *sig_len = k;
    if (sig == NULL || capacity < k)
        return CC_ERR_BUFFER_TOO_SMALL;
    if (ctx->scheme == CC_RSA_PKCS1)
        return rsa_sign_pkcs1(sig, msg, msg_len, &ctx->sk, ctx->algo, ctx->sec_level);
    return rsa_sign_pss(sig, msg, msg_len, &ctx->sk, ctx->algo, ctx->sec_level);
}

cc_status_t cc_rsa_verify(cc_rsa_t *ctx, const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len)
{
    CC_TRY(require_key(ctx));
    if ((msg == NULL && msg_len > 0) || (sig == NULL && sig_len > 0))
        return CC_ERR_INVALID_ARG;
    msg = API_BYTES(msg);
    sig = API_BYTES(sig);

    if (ctx->scheme == CC_RSA_TEXTBOOK)
    {
        mpz_t m, s;
        mpz_inits(m, s, NULL);
        api_input_mpz(m, msg, msg_len);
        api_input_mpz(s, sig, sig_len);
        cc_status_t status = rsa_verify(m, s, &ctx->pk);
        mpz_clears(m, s, NULL);
        return status;
    }
    if (ctx->scheme == CC_RSA_PKCS1)
        return rsa_verify_pkcs1(msg, msg_len, sig, sig_len, &ctx->pk, ctx->sec_level);
    return rsa_verify_pss(msg, msg_len, sig, sig_len, &ctx->pk, ctx->sec_level);
}
