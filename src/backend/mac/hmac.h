#ifndef HMAC_H
#define HMAC_H

#include "common.h"

typedef struct
{
    size_t b;
    size_t l;
    unsigned char *key;
    unsigned char *i_key_pad;
    unsigned char *o_key_pad;
    unsigned char *out;
    void *(*hash)(const void *, size_t, void *, int);
} hmac_ctx;

void hmac_init(hmac_ctx *ctx, void *key, const size_t key_len, SECURITY_LEVEL sec_level, HASH_FUNCTION hash_function);
void hmac_update(hmac_ctx *ctx, void *data, const size_t data_len);
void hmac_final(hmac_ctx *ctx, void *mac);
void hmac_free(hmac_ctx *ctx);

void *hmac(const void *key, const size_t keysize, const void *data, const size_t data_len,
           void *mac, SECURITY_LEVEL sec_level, HASH_FUNCTION hash_function);

#endif