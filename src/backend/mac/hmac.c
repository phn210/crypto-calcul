#include "hmac.h"
#include "file_io.h"
#include "md5.h"
#include "sha1.h"
#include "sha2.h"
#include "sha3.h"

// Block size b and output length l of the underlying hash
static cc_status_t hmac_params(sec_level_t sec_level, hash_func_t hash_function, size_t *b, size_t *l,
                               void *(**hash)(const void *, size_t, void *, size_t))
{
    static const size_t sha2_b[] = {64, 64, 128, 128};
    static const size_t sha3_b[] = {144, 136, 104, 72};
    static const size_t lengths[] = {28, 32, 48, 64};

    int level;
    switch (sec_level)
    {
    case L0:
        level = 0;
        break;
    case L1:
        level = 1;
        break;
    case L2:
        level = 2;
        break;
    case L3:
        level = 3;
        break;
    default:
        level = -1;
    }

    switch (hash_function)
    {
    case MD5:
        *b = 64;
        *l = 16;
        *hash = &md5;
        return CC_OK;
    case SHA1:
        *b = 64;
        *l = 20;
        *hash = &sha1;
        return CC_OK;
    case SHA2:
        if (level < 0)
            return CC_ERR_INVALID_ARG;
        *b = sha2_b[level];
        *l = lengths[level];
        *hash = &sha2;
        return CC_OK;
    case SHA3:
        if (level < 0)
            return CC_ERR_INVALID_ARG;
        *b = sha3_b[level];
        *l = lengths[level];
        *hash = &sha3;
        return CC_OK;
    default:
        return CC_ERR_INVALID_ARG;
    }
}

int ct_memcmp(const void *a, const void *b, size_t len)
{
    const unsigned char *x = a, *y = b;
    unsigned char diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= x[i] ^ y[i];
    return diff;
}

cc_status_t hmac_length(sec_level_t sec_level, hash_func_t hash_function, size_t *mac_len)
{
    size_t b;
    void *(*hash)(const void *, size_t, void *, size_t);
    return hmac_params(sec_level, hash_function, &b, mac_len, &hash);
}

cc_status_t hmac_init(hmac_ctx_t *ctx, const void *key, size_t key_len, sec_level_t sec_level, hash_func_t hash_function)
{
    CC_TRY(hmac_params(sec_level, hash_function, &ctx->b, &ctx->l, &ctx->hash));
    const size_t BLOCK_SIZE = ctx->b;

    ctx->key = calloc(BLOCK_SIZE, 1);
    ctx->i_key_pad = malloc(BLOCK_SIZE);
    ctx->o_key_pad = malloc(BLOCK_SIZE);
    ctx->out = malloc(ctx->l);
    if (ctx->key == NULL || ctx->i_key_pad == NULL || ctx->o_key_pad == NULL || ctx->out == NULL)
    {
        hmac_free(ctx);
        return CC_ERR_NOMEM;
    }

    if (key_len > BLOCK_SIZE)
    {
        ctx->hash(key, key_len, ctx->key, ctx->l);
    }
    else
    {
        memcpy(ctx->key, key, key_len);
    }
    for (size_t i = 0; i < BLOCK_SIZE; i++)
    {
        ctx->i_key_pad[i] = ctx->key[i] ^ 0x36;
        ctx->o_key_pad[i] = ctx->key[i] ^ 0x5c;
    }
    return CC_OK;
}

cc_status_t hmac_update(hmac_ctx_t *ctx, const void *data, size_t data_len)
{
    size_t inner_len = ctx->b + data_len;
    size_t outer_len = ctx->b + ctx->l;
    unsigned char *inner = malloc(inner_len);
    unsigned char *outer = malloc(outer_len);
    if (inner == NULL || outer == NULL)
    {
        free(inner);
        free(outer);
        return CC_ERR_NOMEM;
    }

    memcpy(inner, ctx->i_key_pad, ctx->b);
    memcpy(inner + ctx->b, data, data_len);
    memcpy(outer, ctx->o_key_pad, ctx->b);
    memcpy(outer + ctx->b, (unsigned char *)ctx->hash(inner, inner_len, inner, ctx->l), ctx->l);
    memcpy(ctx->out, ctx->hash(outer, outer_len, outer, ctx->l), ctx->l);

    free(inner);
    free(outer);
    return CC_OK;
}

void hmac_final(hmac_ctx_t *ctx, void *mac)
{
    memcpy(mac, ctx->out, ctx->l);
}

void hmac_free(hmac_ctx_t *ctx)
{
    free(ctx->key);
    free(ctx->i_key_pad);
    free(ctx->o_key_pad);
    free(ctx->out);
    ctx->key = ctx->i_key_pad = ctx->o_key_pad = ctx->out = NULL;
}

cc_status_t hmac(const void *key, size_t keysize, const void *data, size_t data_len,
                 void *mac, sec_level_t sec_level, hash_func_t hash_function)
{
    hmac_ctx_t ctx;
    CC_TRY(hmac_init(&ctx, key, keysize, sec_level, hash_function));
    cc_status_t status = hmac_update(&ctx, data, data_len);
    if (status == CC_OK)
        hmac_final(&ctx, mac);
    hmac_free(&ctx);
    return status;
}

cc_status_t hmac_verify(const void *key, size_t keysize, const void *data, size_t data_len,
                        const void *mac, size_t mac_len, sec_level_t sec_level, hash_func_t hash_function)
{
    size_t expected_len;
    CC_TRY(hmac_length(sec_level, hash_function, &expected_len));
    if (mac_len != expected_len)
        return CC_ERR_VERIFY;

    unsigned char mac_check[64];
    CC_TRY(hmac(key, keysize, data, data_len, mac_check, sec_level, hash_function));
    return ct_memcmp(mac, mac_check, mac_len) == 0 ? CC_OK : CC_ERR_VERIFY;
}

cc_status_t hmac_file(const char *filename, const void *key, size_t keysize,
                      void *mac, sec_level_t sec_level, hash_func_t hash_function)
{
    unsigned char *file_contents;
    size_t file_size;
    CC_TRY(read_file(filename, &file_contents, &file_size));

    cc_status_t status = hmac(key, keysize, file_contents, file_size, mac, sec_level, hash_function);
    free(file_contents);
    return status;
}

cc_status_t hmac_file_verify(const char *filename, const void *key, size_t keysize,
                             const void *mac, size_t mac_len, sec_level_t sec_level, hash_func_t hash_function)
{
    unsigned char *file_contents;
    size_t file_size;
    CC_TRY(read_file(filename, &file_contents, &file_size));

    cc_status_t status = hmac_verify(key, keysize, file_contents, file_size, mac, mac_len, sec_level, hash_function);
    free(file_contents);
    return status;
}
