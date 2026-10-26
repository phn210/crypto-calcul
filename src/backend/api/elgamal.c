#include "api_internal.h"
#include "dh.h"

struct cc_elgamal
{
    sec_level_t sec_level;
    public_params_t pp;
    priv_key_t sk;
    pub_key_t pk;
    int has_key;
};

cc_status_t cc_elgamal_new(cc_elgamal_t **ctx, cc_sec_level_t level)
{
    if (ctx == NULL)
        return CC_ERR_INVALID_ARG;
    *ctx = NULL;

    cc_elgamal_t *elgamal = calloc(1, sizeof(cc_elgamal_t));
    if (elgamal == NULL)
        return CC_ERR_NOMEM;

    cc_status_t status = api_sec_level(level, &elgamal->sec_level);
    if (status == CC_OK)
        status = elgamal_setup(&elgamal->pp, elgamal->sec_level);
    if (status != CC_OK)
    {
        free(elgamal);
        return status;
    }
    *ctx = elgamal;
    return CC_OK;
}

void cc_elgamal_free(cc_elgamal_t *ctx)
{
    if (ctx == NULL)
        return;
    if (ctx->has_key)
        elgamal_free_keys(&ctx->sk, &ctx->pk);
    elgamal_free_params(&ctx->pp);
    free(ctx);
}

cc_status_t cc_elgamal_keygen(cc_elgamal_t *ctx)
{
    if (ctx == NULL)
        return CC_ERR_INVALID_ARG;
    if (ctx->has_key)
    {
        elgamal_free_keys(&ctx->sk, &ctx->pk);
        ctx->has_key = 0;
    }
    CC_TRY(elgamal_keygen(&ctx->sk, &ctx->pk, &ctx->pp));
    ctx->has_key = 1;
    return CC_OK;
}

static cc_status_t require_key(const cc_elgamal_t *ctx)
{
    if (ctx == NULL)
        return CC_ERR_INVALID_ARG;
    return ctx->has_key ? CC_OK : CC_ERR_NO_KEY;
}

cc_status_t cc_elgamal_get(const cc_elgamal_t *ctx, cc_dl_param_t param, uint8_t *out, size_t *out_len)
{
    if (ctx == NULL)
        return CC_ERR_INVALID_ARG;
    switch (param)
    {
    case CC_DL_P:
        return api_output_mpz(out, out_len, ctx->pp.p);
    case CC_DL_G:
        return api_output_mpz(out, out_len, ctx->pp.g);
    case CC_DL_X:
        CC_TRY(require_key(ctx));
        return api_output_mpz(out, out_len, ctx->sk.x);
    case CC_DL_Y:
        CC_TRY(require_key(ctx));
        return api_output_mpz(out, out_len, ctx->pk.y);
    case CC_DL_Q:
        return CC_ERR_UNSUPPORTED;
    }
    return CC_ERR_INVALID_ARG;
}

cc_status_t cc_elgamal_encrypt(cc_elgamal_t *ctx, const uint8_t *msg, size_t msg_len,
                               uint8_t *c1, size_t *c1_len, uint8_t *c2, size_t *c2_len)
{
    CC_TRY(require_key(ctx));
    if (msg == NULL && msg_len > 0)
        return CC_ERR_INVALID_ARG;

    mpz_t m, x1, x2;
    mpz_inits(m, x1, x2, NULL);
    api_input_mpz(m, msg, msg_len);
    cc_status_t status = elgamal_encrypt(x1, x2, m, &ctx->pk, &ctx->pp);
    if (status == CC_OK)
        status = api_output_mpz_pair(c1, c1_len, x1, c2, c2_len, x2);
    mpz_clears(m, x1, x2, NULL);
    return status;
}

cc_status_t cc_elgamal_decrypt(cc_elgamal_t *ctx, const uint8_t *c1, size_t c1_len, const uint8_t *c2, size_t c2_len,
                               uint8_t *out, size_t *out_len)
{
    CC_TRY(require_key(ctx));
    if ((c1 == NULL && c1_len > 0) || (c2 == NULL && c2_len > 0))
        return CC_ERR_INVALID_ARG;

    mpz_t m, x1, x2;
    mpz_inits(m, x1, x2, NULL);
    api_input_mpz(x1, c1, c1_len);
    api_input_mpz(x2, c2, c2_len);
    cc_status_t status = elgamal_decrypt(m, x1, x2, &ctx->sk, &ctx->pp);
    if (status == CC_OK)
        status = api_output_mpz(out, out_len, m);
    mpz_clears(m, x1, x2, NULL);
    return status;
}

cc_status_t cc_elgamal_sign(cc_elgamal_t *ctx, const uint8_t *msg, size_t msg_len,
                            uint8_t *r, size_t *r_len, uint8_t *s, size_t *s_len)
{
    CC_TRY(require_key(ctx));
    if (msg == NULL && msg_len > 0)
        return CC_ERR_INVALID_ARG;

    mpz_t x1, x2;
    mpz_inits(x1, x2, NULL);
    cc_status_t status = elgamal_sign(x1, x2, API_BYTES(msg), msg_len, &ctx->sk, &ctx->pp, ctx->sec_level);
    if (status == CC_OK)
        status = api_output_mpz_pair(r, r_len, x1, s, s_len, x2);
    mpz_clears(x1, x2, NULL);
    return status;
}

cc_status_t cc_elgamal_verify(cc_elgamal_t *ctx, const uint8_t *msg, size_t msg_len,
                              const uint8_t *r, size_t r_len, const uint8_t *s, size_t s_len)
{
    CC_TRY(require_key(ctx));
    if ((msg == NULL && msg_len > 0) || (r == NULL && r_len > 0) || (s == NULL && s_len > 0))
        return CC_ERR_INVALID_ARG;

    mpz_t x1, x2;
    mpz_inits(x1, x2, NULL);
    api_input_mpz(x1, r, r_len);
    api_input_mpz(x2, s, s_len);
    cc_status_t status = elgamal_verify(x1, x2, API_BYTES(msg), msg_len, &ctx->pk, &ctx->pp, ctx->sec_level);
    mpz_clears(x1, x2, NULL);
    return status;
}

/* ------------------------------------------------------------------------- */
/* Diffie-Hellman over the ElGamal groups                                    */
/* ------------------------------------------------------------------------- */

static cc_status_t dh_params(cc_sec_level_t level, public_params_t *pp)
{
    sec_level_t sec_level;
    CC_TRY(api_sec_level(level, &sec_level));
    return elgamal_setup(pp, sec_level);
}

cc_status_t cc_dh_generate_secret(cc_sec_level_t level, uint8_t *secret, size_t *secret_len)
{
    public_params_t pp;
    CC_TRY(dh_params(level, &pp));

    mpz_t x;
    mpz_init(x);
    cc_status_t status = dh_gen_secret(x, &pp);
    if (status == CC_OK)
        status = api_output_mpz(secret, secret_len, x);

    mpz_clear(x);
    elgamal_free_params(&pp);
    return status;
}

cc_status_t cc_dh_public(cc_sec_level_t level, const uint8_t *secret, size_t secret_len,
                         uint8_t *pub, size_t *pub_len)
{
    if (secret == NULL && secret_len > 0)
        return CC_ERR_INVALID_ARG;
    public_params_t pp;
    CC_TRY(dh_params(level, &pp));

    mpz_t x, y;
    mpz_inits(x, y, NULL);
    api_input_mpz(x, secret, secret_len);
    cc_status_t status = dh_gen_public(y, x, &pp);
    if (status == CC_OK)
        status = api_output_mpz(pub, pub_len, y);

    mpz_clears(x, y, NULL);
    elgamal_free_params(&pp);
    return status;
}

cc_status_t cc_dh_shared_secret(cc_sec_level_t level, const uint8_t *secret, size_t secret_len,
                                const uint8_t *peer_pub, size_t peer_pub_len, uint8_t *shared, size_t *shared_len)
{
    if ((secret == NULL && secret_len > 0) || (peer_pub == NULL && peer_pub_len > 0))
        return CC_ERR_INVALID_ARG;
    public_params_t pp;
    CC_TRY(dh_params(level, &pp));

    mpz_t x, y, z;
    mpz_inits(x, y, z, NULL);
    api_input_mpz(x, secret, secret_len);
    api_input_mpz(y, peer_pub, peer_pub_len);
    cc_status_t status = dh_compute_shared_secret(z, x, y, &pp);
    if (status == CC_OK)
        status = api_output_mpz(shared, shared_len, z);

    mpz_clears(x, y, z, NULL);
    elgamal_free_params(&pp);
    return status;
}
