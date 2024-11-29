#ifndef SHA1_H
#define SHA1_H

#include "common.h"

#define HASH_SIZE 20

typedef struct sha1_ctx
{
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[5];
} sha1_ctx_t;

typedef struct hash_node
{
    unsigned char hash[HASH_SIZE];
    struct hash_node *next;
} hash_node_t;

void sha1_transform(sha1_ctx_t *ctx, const void *data);
void sha1_init(sha1_ctx_t *ctx);
void sha1_update(sha1_ctx_t *ctx, const void *data, size_t len);
void sha1_final(sha1_ctx_t *ctx, void *md);

void *sha1(const void *data, size_t len, void *md, int md_len);

#endif