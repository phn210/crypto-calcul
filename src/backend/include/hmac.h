#ifndef HMAC_H
#define HMAC_H

#include "common.h"

typedef struct hmac_ctx
{
    size_t b;
    size_t l;
    unsigned char *key;
    unsigned char *i_key_pad;
    unsigned char *o_key_pad;
    unsigned char *out;
    void *(*hash)(const void *, size_t, void *, size_t);
} hmac_ctx_t;

void hmac_init(hmac_ctx_t *ctx, const void *key, size_t key_len, SECURITY_LEVEL sec_level, HASH_FUNCTION hash_function);
void hmac_update(hmac_ctx_t *ctx, const void *data, size_t data_len);
void hmac_final(hmac_ctx_t *ctx, void *mac);
void hmac_free(hmac_ctx_t *ctx);

void *hmac(const void *key, size_t keysize, const void *data, size_t data_len,
           void *mac, SECURITY_LEVEL sec_level, HASH_FUNCTION hash_function);

#endif