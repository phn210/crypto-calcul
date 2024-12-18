#include "hmac.h"
#include "md5.h"
#include "sha_1.h"
#include "sha_2.h"
#include "sha_3.h"

void hmac_init(hmac_ctx_t *ctx, const void *key, size_t key_len, SECURITY_LEVEL sec_level, HASH_FUNCTION hash_function)
{
    switch (hash_function)
    {
    case MD5:
        ctx->b = 64;
        ctx->l = 16;
        // ctx->hash = ;
        break;

    case SHA1:
        ctx->b = 64;
        ctx->l = 20;
        // ctx->hash = ;
        break;

    case SHA2:
        switch (sec_level)
        {
        case L0:
            ctx->b = 64;
            ctx->l = 28;
            break;
        case L1:
            ctx->b = 64;
            ctx->l = 32;
            break;
        case L2:
            ctx->b = 128;
            ctx->l = 48;
            break;
        case L3:
            ctx->b = 128;
            ctx->l = 64;
            break;
        default:
            break;
        }
        // ctx->hash = ;
        break;

    case SHA3:
        switch (sec_level)
        {
        case L0:
            ctx->b = 144;
            ctx->l = 28;
            break;
        case L1:
            ctx->b = 136;
            ctx->l = 32;
            break;
        case L2:
            ctx->b = 104;
            ctx->l = 48;
            break;
        case L3:
            ctx->b = 72;
            ctx->l = 64;
            break;
        default:
            break;
        }
        ctx->hash = sha3;
        break;

    default:
        fprintf(stderr, "Invalid hash function\n");
        exit(EXIT_FAILURE);
    }
    const size_t BLOCK_SIZE = ctx->b;

    ctx->key = malloc(BLOCK_SIZE);
    ctx->i_key_pad = malloc(BLOCK_SIZE);
    ctx->o_key_pad = malloc(BLOCK_SIZE);
    ctx->out = malloc(ctx->l);
    memset(ctx->key, 0, BLOCK_SIZE);
    memset(ctx->i_key_pad, 0, BLOCK_SIZE);
    memset(ctx->o_key_pad, 0, BLOCK_SIZE);

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
}

void hmac_update(hmac_ctx_t *ctx, const void *data, size_t data_len)
{
    size_t inner_len = ctx->b + data_len;
    size_t outer_len = ctx->b + ctx->l;
    unsigned char *inner = malloc(inner_len);
    unsigned char *outer = malloc(outer_len);
    if (inner == NULL || outer == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }

    memcpy(inner, ctx->i_key_pad, ctx->b);
    memcpy(inner + ctx->b, data, data_len);
    memcpy(outer, ctx->o_key_pad, ctx->b);
    memcpy(outer + ctx->b, (unsigned char *)ctx->hash(inner, inner_len, inner, ctx->l), ctx->l);
    memcpy(ctx->out, ctx->hash(outer, outer_len, outer, ctx->l), ctx->l);
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
}

void *hmac(const void *key, size_t keysize, const void *data, size_t data_len,
           void *mac, SECURITY_LEVEL sec_level, HASH_FUNCTION hash_function)
{
    hmac_ctx_t ctx;
    hmac_init(&ctx, key, keysize, sec_level, hash_function);
    hmac_update(&ctx, data, data_len);
    hmac_final(&ctx, mac);
    hmac_free(&ctx);
    return mac;
}